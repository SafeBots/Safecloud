# Pay-Per-Minute Streaming & Attested Key Issuance

Safecloud supports a pay-per-minute (or pay-per-second) access model for
encrypted streams.  Content creators set a metered access policy on their
stream; a Jet issues decryption keys only for the portion of the stream the
viewer has paid for.  Attested Safebox clients let the Jet enforce key
destruction, closing the gap against *distributed* client hacks.

---

## Overview

Traditional DRM systems rely on CDN-level access control: once a client has
the decryption key, the DRM box tries (and usually fails) to prevent screen
capture.  Safecloud takes a different approach:

| Concern | Safecloud solution |
|---|---|
| "I want to pay only for what I watch" | Per-chunk key issuance, keys issued only for the current rewind window |
| "Creator wants revenue for rewatching" | Keys for expired chunks are not re-issued without a fresh payment |
| "What stops a hacked client from keeping keys?" | Nothing — individual hacking is accepted (like screen capture). **Distribution** of a hacked client is blocked by build attestation. |

The key insight: a patched client that suppresses key destruction has a
different binary hash than the official Safecloud build.  Jets consult a
*blessed build list*.  Any build not on that list cannot receive keys from
an attestation-requiring stream, so the hack can't be distributed at scale.

---

## Access Models

Stream creators set the access policy in the stream's `Safecloud.access`
attribute (a JSON string, unencrypted so viewers can inspect it before paying).

```json
{
  "model": "pay-per-minute",
  "rewindWindow": 120,
  "ratePerSecond": "0.0002",
  "keyPolicy": "rolling-rewind",
  "requireAttestation": true
}
```

### `model` (string)

| Value | Meaning |
|---|---|
| `"permanent"` | Pay once; keys kept forever. Default when no policy is set. |
| `"session"` | Keys valid until the player closes; rewatching requires re-payment. |
| `"pay-per-minute"` | Rolling-rewind window; keys destroyed outside the window. Default `rewindWindow`: 120 s. |
| `"pay-per-second"` | Same as `pay-per-minute` with finer granularity. Default `rewindWindow`: 10 s. |

### `rewindWindow` (seconds)

How far back a viewer can scrub without re-paying.  Keys for chunks outside
`currentPosition − rewindWindow` are not re-issued.

### `ratePerSecond` (string, wei/s)

Informational — the rate displayed to the viewer.  The actual payment is
verified against the OCP/EIP-712 envelope attached to each key request.

### `keyPolicy` (string)

| Value | Meaning |
|---|---|
| `"permanent"` | Issued once, never revoked. |
| `"session"` | Valid until player close. |
| `"rolling-rewind"` | Valid only for chunks within the rewind window. |

Defaults: `pay-per-*` models default to `rolling-rewind`; `session` defaults
to `session`; `permanent` defaults to `permanent`.

### `requireAttestation` (boolean, default `false`)

When `true`, the Jet rejects key requests that don't carry a valid Safebox
attestation token from a blessed build.  See **Attestation** below.

---

## Per-Chunk Key Derivation

For pay-per-minute streams the Jet holds the stream *root key* server-side.
It derives a separate key for each chunk on demand using HKDF-SHA256:

```
chunkKey_i = HKDF-SHA256(
    ikm  = rootKey,          // 32-byte master key, never leaves the Jet
    info = "safecloud.chunk.v1.<i>",
    len  = 32
)
```

**Security property:** `chunkKey_i` does not reveal `rootKey` or any
`chunkKey_j` (j ≠ i).  HKDF is a one-way PRF; this is the standard PRF
security assumption.

The root key is registered by the author at upload time via:
- **Socket.io:** `Safecloud/content/registerRootKey` `{ rootCid, rootKey (base64), accessModel? }`
- **HTTP:** `POST /Safecloud/registerRootKey` (same body)

The root key **never leaves the Jet**.  Clients receive only per-chunk keys.

---

## Key Request API

### `POST /Safecloud/key`

Request body:
```json
{
  "rootCid":      "bafybeig…",
  "chunkIndices": [42, 43, 44],
  "paymentSig":   "<base64 OCP/EIP-712 envelope>",
  "attestation":  "<base64 Safebox attestation token>"
}
```

`attestation` is optional unless the stream has `requireAttestation: true`.

#### Responses

| Status | Meaning |
|---|---|
| `200` | Keys issued. `{ "keys": { "42": "<base64>", "43": "<base64>", "44": "<base64>" } }` |
| `400` | Missing `rootCid` or `chunkIndices`. |
| `402` | Payment required or insufficient balance.  `PAYMENT-REQUIRED` response header carries requirements. |
| `403` | Attestation required or build hash not on blessed list. |
| `404` | `rootCid` not registered on this Jet. |
| `500` | Internal error. |

CORS: `Access-Control-Allow-Origin: *` — the client runs on any embedding origin.

---

## Rolling-Rewind Enforcement

The client player is responsible for key lifecycle:

1. **Issue** — `POST /Safecloud/key` for the next N chunks ahead of the
   playback position.
2. **Keep** — hold keys in memory for chunks within
   `[currentPosition − rewindWindow, currentPosition + lookahead]`.
3. **Destroy** — zero and delete keys for chunks that have fallen outside the
   rewind window.
4. **Re-issue** — if the user scrubs back past the window, `POST /Safecloud/key`
   again with a fresh payment signature.

The Jet does not track which chunks a client has already received keys for
(stateless design).  On an *attested* client the Jet can optionally verify
that the client's rolling window is legitimate; on an *unattested* client
the Jet issues keys for whatever chunks the payment covers, trusting the
client to destroy them.

---

## Attestation

### Why attestation matters for distributed hacks

A single user can always:
- Use browser DevTools to read in-memory chunk keys.
- Screen-capture the decrypted video.

This is accepted — it's the digital equivalent of holding a camera up to a
screen.  What attestation prevents is **distributing a modified Safecloud
client** that automatically retains all keys forever.  Such a client would
have a different Nix derivation hash than the official build.  Jets refuse
keys to any build not on the blessed list, so the hack has no effect at scale.

### Trust chain

```
TPM / Hardware root-of-trust
  └── Nix derivation hash (reproducible build)
        └── Safebox TEE attestation document
              └── Browser session key
                    └── POST /Safecloud/key { attestation: … }
                          └── Jet verifies hash ∈ blessedBuilds
```

### Attestation token format

Tokens are base64-encoded JSON:
```json
{
  "provider":  "nitro",
  "document":  "<base64 raw attestation document>"
}
```

Supported providers: `nitro` (AWS Nitro Enclaves), `gcp`, `azure`, `oci`,
`sev-snp`, `tdx` — the full set from `classes/Safecloud/Attestation/`.

The Jet extracts the `buildHash` claim from the verified document and checks
it against the `Safecloud.attestation.blessedBuilds` config array.  An empty
list means "any valid attestation accepted" (useful during development).

### Jet configuration

```json
{
  "Safecloud": {
    "attestation": {
      "blessedBuilds": [
        "aabbccdd1122334455…",
        "bbccdd1122334455aa…"
      ]
    }
  }
}
```

Each entry is the hex-encoded Nix derivation hash of a blessed Safecloud
build.  New builds are added to the list after auditor sign-off.

---

## Implementation Files

| File | Purpose |
|---|---|
| `classes/Safecloud/Access.js` | Parse and encode stream access models; `isChunkExpired()` for the rolling-window check |
| `classes/Safecloud/KeyIssuance.js` | `deriveChunkKey()` (HKDF), `issueKeys()` (payment+attestation gate), `verifyClientAttestation()` |
| `classes/Safecloud/Jets.js` | `POST /Safecloud/key` route; `_rootKeyStore`; `Safecloud/content/registerRootKey` socket handler |
| `classes/Safecloud/Attestation/` | Full TEE attestation stack (Nitro/GCP/Azure/OCI/SEV-SNP/TDX) |
| `tests/key_issuance.test.js` | 48 unit tests: HKDF, derivation, access model parsing, payment gate, attestation gate |

---

## Security Notes

- **Root key confidentiality**: the root key is never transmitted to clients.
  It lives only in `_rootKeyStore` (a bounded in-memory map on the Jet).
  Production deployments should back this store with an HSM or sealed secrets
  manager and re-register on Jet restart.

- **Payment replay**: OCP/EIP-712 envelopes carry `nbf`/`exp` fields; the Jet
  rejects expired envelopes.  A payment authorizes a time window, not an
  unlimited number of key requests.

- **Attestation replay**: tokens should carry a nonce or expiry.  The
  `AttestationVerifier` checks document freshness when the TEE provider
  includes a timestamp (Nitro, GCP).

- **Key derivation collisions**: HKDF-SHA256 output is 256 bits; collision
  probability across all chunk indices is negligible.

- **Acceptable individual hacking**: a user who extracts chunk keys from
  memory can decrypt the content they paid for.  This is not prevented by
  design — it's equivalent to screen capture and falls under fair use in most
  jurisdictions.  The system goal is preventing *distribution* of a hacked
  client, which attestation achieves.
