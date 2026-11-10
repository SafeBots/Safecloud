# Safecloud Access Control

This document describes the full rights management model for Safecloud — how content creators, publishers, and Jet operators establish and enforce access to encrypted streams.

For the pay-per-minute key derivation mechanics and attestation, see [PayPerMinute.md](PayPerMinute.md).

---

## Overview

Safecloud access control is built on three ideas:

1. **Encrypted content is inert without its key.** The Jet holds the stream's root key server-side and issues per-chunk derived keys only to authorized, optionally attested, paying clients. A publisher who loses their grant cannot play the content — not because access is blocked at the CDN edge, but because the decryption key is withheld.

2. **Rights are recorded on a cryptographic grant chain.** Grants, negotiations, counter-signatures, and revocations are written to an append-only Merkle chain of signed entries. Any party can verify the full rights history for a stream without trusting the Jet or any central authority.

3. **Embed origin is enforced at two levels.** The browser's `Origin` header provides the first (browser-enforced) gate; a publisher-signed session token provides the cryptographic gate. Unauthorized embeds see only an unencrypted teaser.

---

## Roles

### Content Creator / Author

Creates and owns the stream. The creator registers the stream's root key on the Jet, sets the access model and price floor, and issues signed grants to publishers. The creator's Qbix PRF identity key is the root of the stream's trust chain.

**Can do:** register streams, set access models, issue/revoke grants, set per-publisher price floors, set teaser policy, view earnings.

### Publisher / Website Owner

Embeds Safecloud streams on a website. The publisher registers one or more Ed25519 keypairs with the Jet (one per registered origin). The publisher's PHP or server-side backend signs short-lived viewer auth tokens at page load; the Safecloud player includes these tokens in key requests so the Jet can rate-limit per publisher without a backend call per viewer.

**Can do:** register origins, receive grants from creators, sign viewer session tokens, see rate limit headroom, see active viewer sessions.

### Jet Operator

Runs the Jet node. The operator configures fees, rate limits, the blessed build list for attestation, and can inspect the full grant chain. The Jet operator does not need to be trusted by creators or publishers for the grant chain itself — all entries are externally verifiable.

**Can do:** configure the Jet, view the grant chain, see all publishers and creators, set attestation policy, manage fee splits.

### Viewer

End user of an embedded player. The viewer pays for access (via OCP/EIP-712 micropayments) and receives per-chunk decryption keys. On an attested Safebox client, key destruction is enforced by the TEE; on an unattested client, it is enforced by the player contract (which an individual can break — that is accepted; distributing a patched client is blocked by attestation).

**Can do:** pay for access, hold per-chunk keys for the current rewind window, scrub within the rewind window, re-pay to scrub further back.

---

## Identity

All parties are identified by their **Qbix PRF signing keypair** — the same identity used elsewhere in the Qbix/Streams ecosystem. A key fingerprint is the hex-encoded SHA-256 of the compressed public key (or the last 4 bytes of that hash as a short display form, e.g. `0xA3F8…C2D1`).

Publishers additionally register one or more **Ed25519 keypairs**, one per origin, for signing viewer session tokens. These are separate from the publisher's Qbix PRF identity key; the Ed25519 key is specifically for high-volume per-viewer token signing (fast to verify offline).

The **Jet** does not issue or manage identity keys. It stores the public keys parties register and uses them to verify signatures on grant entries and viewer tokens.

---

## The Grant Chain

The grant chain is a **signed append-only log** stored on the Jet, publicly readable, and independently verifiable. It is not a blockchain — there is no consensus, no distributed state, and no token. It is a simple Merkle chain: each entry references the SHA-256 hash of the previous entry, so the chain is tamper-evident and any party can verify that an entry has not been altered or removed.

### Entry structure

```json
{
  "seq":       47,
  "type":      "grant | revoke | negotiate | accept",
  "rootCid":   "bafybeig3k2j4p…e7c1",
  "from":      "0xA3F8…C2D1",
  "to":        "0xB7E4…9F3A",
  "terms": {
    "minRatePerSecond": "0.0002",
    "maxViewersPerHour": 50,
    "rewindWindow":     120,
    "requireAttestation": false,
    "expiry":           "2027-01-01T00:00:00Z"
  },
  "prevHash":  "sha256:81920a1b…",
  "sig":       "<base64 signature by 'from'>",
  "counterSig": "<base64 signature by 'to'>"
}
```

`sig` is always required (signed by `from`). `counterSig` is required for `accept` entries (counter-signed by `to`). `revoke` entries carry only `from`'s signature.

Grant chain entries are **unencrypted** so any party — including viewers verifying that the site they are watching has a legitimate grant — can read and verify them.

### Chain verification

To verify that publisher P has a valid grant for stream S:

1. Fetch the chain entries for `rootCid = S`.
2. Find the most recent `accept` entry where `to = P.pubkey` and `terms.expiry > now`.
3. Verify that no subsequent `revoke` entry exists for the same `(rootCid, to)` pair.
4. Verify the `sig` (creator's signature over the `grant` entry) and `counterSig` (publisher's signature over the `accept` entry).
5. Verify the `prevHash` chain from genesis.

The Jet performs this check on every key request; external verifiers can do the same independently.

---

## Grant Lifecycle

### 1. Creator issues an open offer

The creator signs a `grant` entry with proposed terms and a `to` field set to the publisher's public key. The entry is appended to the chain with `seq` = next sequence number. Status: `sig` present, `counterSig` absent — the grant is not yet active.

### 2. Publisher counter-signs (accept)

The publisher verifies the terms and counter-signs. An `accept` entry is appended. Status: both `sig` and `counterSig` present — grant is active. The Jet begins issuing keys to this publisher's viewers for the stream.

### 3. Negotiation (optional)

Either party may append a `negotiate` entry proposing different terms. The other party may then accept, counter-propose, or ignore. Each `negotiate` entry is signed by its author. The chain records the full negotiation history.

### 4. Revocation

Either party may append a `revoke` entry. After revocation:
- The Jet stops issuing keys to the revoked publisher's viewers.
- Viewers who already hold keys for chunks within their rewind window can finish watching those chunks; no new keys are issued.
- The revoke entry is signed only by the revoking party; the other party's counter-signature is not required.

### 5. Expiry

Grants carry an `expiry` timestamp in `terms`. The Jet checks this on every key request. Expired grants are treated as revoked without a chain entry — the original grant's expiry is authoritative.

---

## Access Models

Stream creators set the access policy in the stream's `Safecloud.access` attribute. Viewers can inspect this attribute before paying (it is unencrypted in the stream manifest).

| Model | Key policy | Default rewind window | Viewer pays |
|---|---|---|---|
| `permanent` | `permanent` | 0 | Once |
| `session` | `session` | 0 | Per session |
| `pay-per-minute` | `rolling-rewind` | 120 s | Per minute watched |
| `pay-per-second` | `rolling-rewind` | 10 s | Per second watched |

See [PayPerMinute.md](PayPerMinute.md) for the full per-chunk HKDF key derivation and rolling-rewind enforcement details.

---

## Embed Origin Enforcement

Access to a publisher-gated stream requires two gates to pass:

### Gate 1 — Browser `Origin` header (fast, browser-enforced)

When a browser makes a cross-origin request to the Jet's `/Safecloud/key` endpoint, it sends an `Origin` header that the Jet checks against the publisher's registered origins. This gate is enforced by the browser's same-origin policy and cannot be forged by page JavaScript. It provides fast rejection of unauthorized embeds at zero cost.

### Gate 2 — Publisher-signed viewer auth token (cryptographic)

For publisher-gated streams, the key request must include a `publisherAuth` JWT-like token:

```json
{
  "publisher": "B7E4…9F3A",
  "userId":    "viewer-5519",
  "rootCid":   "bafybeig3k2j4p…e7c1",
  "nbf":  1746652800,
  "exp":  1746656400,
  "nonce":"a3f8c1d7"
}
```

The token is signed by the publisher's registered Ed25519 key and verified offline by the Jet (no backend call per viewer). The Jet rejects tokens with an unrecognized `publisher` fingerprint, an expired `exp`, or a `rootCid` for which the publisher has no active grant.

Rate limits are applied per `(publisher, userId)` pair so that one viewer cannot exhaust the publisher's global viewer budget.

### Teaser policy

Streams can expose the first N seconds of the stream with **unencrypted chunks** (or encrypted with the key embedded in the manifest). Any embed — authorized or not — can play this teaser. After N seconds, the player must present a valid `publisherAuth` token or display a paywall.

The teaser length is set by the creator per stream. Setting it to 0 disables the teaser entirely.

---

## Rate Limits

Rate limits are enforced by the Jet at several levels:

| Limit | Configured by | Applied to |
|---|---|---|
| Global key requests / minute | Jet operator | All clients on this Jet |
| Viewers per hour per grant | Creator (in grant terms) | Each publisher per stream |
| Key requests per (publisher, userId) | Jet config (default) | Individual viewer session |
| Root key store size | Jet operator | All streams on this Jet |

When a publisher approaches their viewer-per-hour cap, the Jet returns a `429 Too Many Requests` response with a `Retry-After` header. The player can display a "stream at capacity" message to the viewer.

---

## Price Floors and Negotiation

Creators set a `minRatePerSecond` price floor either globally or per publisher in the grant terms. The floor is enforced by the Jet at key-request time: if the payment envelope in a key request does not meet the minimum rate, the Jet returns `402 Payment Required`.

Publishers may propose a lower rate in a `negotiate` entry. The creator can accept (by counter-signing an `accept` entry with the new rate) or decline (by ignoring or counter-proposing). The active rate for a stream is always the rate in the most recent `accept` entry for that `(rootCid, publisher)` pair.

**Mode 1 — Safebux payment.** The viewer pays directly with their Safebux balance. Revenue is split at the Jet: the Jet infrastructure fee (configured by the operator, default 5%) is taken first; the remaining amount is split between the creator CVM address and the publisher CVM address per the grant terms.

**Mode 2 — Website-sponsored / credit-based.** The publisher absorbs the cost and issues a `publisherAuth` token to the viewer. The publisher pays the Jet in Safebux; the viewer may pay the publisher in website credits, subscriptions, or not at all (the publisher bears the cost as a business decision). The Jet only sees Safebux payments — the publisher's monetization model is opaque to it.

---

## API Reference

### Register a root key

**Socket.io:** `Safecloud/content/registerRootKey`
**HTTP:** `POST /Safecloud/registerRootKey`

```json
{
  "rootCid":    "bafybeig3k2j4p…e7c1",
  "rootKey":    "<base64, 32 bytes>",
  "accessModel": { "model": "pay-per-minute", "rewindWindow": 120, "ratePerSecond": "0.0002", "requireAttestation": true }
}
```

Only the stream's creator (authenticated via their Qbix PRF key) may register a root key.

### Request chunk keys

**HTTP:** `POST /Safecloud/key`

```json
{
  "rootCid":      "bafybeig3k2j4p…e7c1",
  "chunkIndices": [42, 43, 44],
  "paymentSig":   "<base64 OCP/EIP-712 envelope>",
  "publisherAuth": "<base64 publisher-signed viewer token>",
  "attestation":  "<base64 Safebox attestation token>"
}
```

`publisherAuth` is required for publisher-gated streams. `attestation` is required when the stream has `requireAttestation: true`.

**Responses:**

| Status | Meaning |
|---|---|
| `200` | `{ "keys": { "42": "<base64>", "43": "<base64>", "44": "<base64>" } }` |
| `400` | Missing required field |
| `402` | Payment insufficient or missing |
| `403` | Attestation failed or publisher not authorized |
| `404` | Stream not registered on this Jet |
| `429` | Rate limit exceeded |
| `500` | Internal error |

CORS: `Access-Control-Allow-Origin: *` — the client runs on any embedding origin.

### Register a publisher origin

**Socket.io:** `Safecloud/publisher/registerOrigin`
**HTTP:** `POST /Safecloud/registerOrigin`

```json
{
  "origin":  "streamhub.io",
  "pubkey":  "<base64 Ed25519 public key>"
}
```

The request must be signed by the publisher's Qbix PRF key to prove ownership of the publisher identity.

### Grant chain endpoints

| Endpoint | Description |
|---|---|
| `GET /Safecloud/chain` | Full grant chain, paginated |
| `GET /Safecloud/chain/:rootCid` | Entries for a specific stream |
| `POST /Safecloud/chain/grant` | Append a signed `grant` entry |
| `POST /Safecloud/chain/accept` | Append a signed `accept` entry |
| `POST /Safecloud/chain/negotiate` | Append a signed `negotiate` entry |
| `POST /Safecloud/chain/revoke` | Append a signed `revoke` entry |

---

## Security Notes

### What is enforced by design

- **Key confidentiality.** The stream root key never leaves the Jet. Clients receive only per-chunk HKDF-derived keys valid for the current rewind window (or the full stream for `permanent` model). A client cannot reconstruct the root key or any other chunk key from what it holds.

- **Grant immutability.** The Merkle chain structure makes it impossible to alter or remove a past entry without invalidating all subsequent hashes. Any party holding a snapshot of the chain can detect tampering.

- **Offline publisher auth.** Publisher-signed viewer tokens are verified cryptographically by the Jet with no backend round-trip per viewer. A publisher cannot forge tokens for a stream they do not hold a grant for (the grant check is separate).

- **Distributed client hack prevention.** Build attestation blocks distribution of patched Safebox clients that suppress key destruction. See [PayPerMinute.md](PayPerMinute.md) for the full trust chain.

### What is not enforced (and why that is acceptable)

- **Individual key extraction.** A single viewer using browser DevTools to read in-memory chunk keys is not prevented. This is the digital equivalent of screen capture and is accepted by design. The system goal is preventing *distribution* of a hacked client, not preventing every conceivable individual workaround.

- **Screen capture.** Not preventable with software DRM. Safecloud does not attempt this.

- **Publisher claiming false viewer counts.** The Jet enforces the `maxViewersPerHour` limit but cannot verify that a publisher has charged viewers accurately. The economic relationship between publisher and viewer is outside the Jet's scope.

### Threat model

| Threat | Mitigated? | How |
|---|---|---|
| Unauthorized embed playing full stream | Yes | Publisher grant + Origin check + publisherAuth token |
| Revoked publisher continuing to serve | Yes | Jet checks grant status on every key request |
| Client holding keys after rewind window | Partial | Attested clients: enforced by TEE. Unattested: player contract (individual bypass accepted) |
| Forged grant entry | Yes | Merkle chain + signature verification |
| Distributed patched client | Yes | Build attestation + blessed build list |
| Payment replay | Yes | OCP/EIP-712 envelopes carry `nbf`/`exp` |
| Root key theft from Jet memory | Partial | In-memory bounded map; production deployments should use an HSM or sealed secrets manager |

---

## Implementation Files

| File | Role |
|---|---|
| `classes/Safecloud/Access.js` | Parse access models, `isChunkExpired()` |
| `classes/Safecloud/KeyIssuance.js` | HKDF derivation, payment+attestation gate |
| `classes/Safecloud/Jets.js` | HTTP routes, `_rootKeyStore`, socket handlers |
| `classes/Safecloud/Attestation/` | TEE attestation stack (Nitro/GCP/Azure/OCI/SEV-SNP/TDX) |
| `tests/key_issuance.test.js` | 48 unit tests covering key derivation and all gates |
| `docs/PayPerMinute.md` | Per-chunk HKDF formula, rolling-rewind enforcement, attestation token format |
