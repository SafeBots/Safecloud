# Safecloud — Inter-Node Communication Protocol

## Table of Contents

- [Overview](#overview)
- [Principles](#principles)
- [Shared conventions](#shared-conventions)
  - [Chain separation](#chain-separation)
  - [OCP wire format](#ocp-wire-format)
  - [Connection authentication and session key delegation](#connection-authentication-and-session-key-delegation)
  - [OCP Role A — access grants](#ocp-role-a--access-grants)
  - [OCP Role B — payment tokens](#ocp-role-b--payment-tokens)
  - [OCP key resolution and remote keys](#ocp-key-resolution-and-remote-keys)
  - [Batch HTTP request format](#batch-http-request-format)
  - [Error response envelope](#error-response-envelope)
  - [HTTP status codes](#http-status-codes)
  - [x402 compliance](#x402-compliance)
  - [Cache-Control on encrypted responses](#cache-control-on-encrypted-responses)
- [Edge 1 — Cloud ↔ Jets (HTTP + socket.io)](#edge-1--cloud--jets-http--socketio)
  - [Topology](#topology-1)
  - [PUT /Safecloud/cloud/subtree — upload chunks](#put-safesubtree--upload-chunks)
  - [GET /Safecloud/cloud/subtree/{rootCid}/{start}/{end} — fetch chunk range](#get-safesubtreerooticdstartend--fetch-chunk-range)
  - [GET /Safecloud/cloud/chunk/{cid} — single-chunk x402 fetch](#get-safechunkcid--single-chunk-x402-fetch)
  - [socket.io equivalents](#socketio-equivalents)
- [Edge 2 — Jets ↔ Jets (HTTP via Jets.Router / hyperswarm)](#edge-2--jets--jets-http-via-jetsrouter--hyperswarm)
  - [Topology](#topology-2)
  - [Peer discovery via hyperswarm](#peer-discovery-via-hyperswarm)
  - [Relay request: GET /Safecloud/cloud/relay/{rootCid}/{start}/{end}](#relay-request-get-saferelayrooticdstartend)
- [Edge 3 — Jets ↔ Ethereum Provider RPC](#edge-3--jets--ethereum-provider-rpc)
  - [Topology](#topology-3)
  - [Balance check (pre-screen only)](#balance-check-pre-screen-only)
- [Edge 4 — Jets ↔ Drops (socket.io, browser-hosted)](#edge-4--jets--drops-socketio-browser-hosted)
  - [Topology](#topology-4)
  - [Drop handshake and stake registration](#drop-handshake-and-stake-registration)
  - [Drop lifecycle events](#drop-lifecycle-events)
  - [Jet → Drop: chunk storage push](#jet--drop-chunk-storage-push)
  - [Jet → Drop: chunk retrieval pull](#jet--drop-chunk-retrieval-pull)
  - [Jet → Drop: proof-of-storage challenge](#jet--drop-proof-of-storage-challenge)
  - [Jet → Drop: slash notification](#jet--drop-slash-notification)
- [Edge 5 — Drops ↔ Ethereum / OpenClaiming contract](#edge-5--drops--ethereum--openclaiming-contract)
  - [Topology](#topology-5)
  - [Balance verification](#balance-verification)
  - [Payment claim execution](#payment-claim-execution)
- [Safebux economics](#safebux-economics)
  - [Zero-sum payment flows](#zero-sum-payment-flows)
  - [Stake and graduated lockup](#stake-and-graduated-lockup)
  - [Routing priority and stake](#routing-priority-and-stake)
- [Proof of Corruption](#proof-of-corruption)
  - [CoC wire format](#coc-wire-format)
  - [Decidability rule](#decidability-rule)
  - [Gossip and slash mechanics](#gossip-and-slash-mechanics)
- [Attack vectors](#attack-vectors)
  - [MITM relay: MalloryJet between Jet1 and Drop2](#mitm-relay-malloryjet-between-jet1-and-drop2)
  - [Can MalloryJet get an honest Drop2 slashed?](#can-malloryjet-get-an-honest-drop2-slashed)
  - [Fake CoC against a legitimate participant](#fake-coc-against-a-legitimate-participant)
  - [Sybil routing attack](#sybil-routing-attack-many-low-stake-drops)
  - [Payment withholding by a malicious Jet](#payment-withholding-by-a-malicious-jet)
- [Implementation notes](#implementation-notes)

---

## Overview

Safecloud is a decentralized encrypted storage network composed of four node
types:

```
  ┌────────┐        ┌──────┐        ┌──────┐
  │ Cloud  │◀──────▶│ Jets │◀──────▶│ Jets │  (peer network)
  │(browser│        │(Node)│        │(Node)│
  │ client)│        └──┬───┘        └──────┘
  └────────┘           │
                   ┌───┴───┐
                   │ Drops │  (browser tabs offering storage)
                   └───────┘
                       │
               OpenClaiming contract
               (Ethereum / EVM chain)
```

All five communication edges share a common set of conventions: the OCP
protocol for authorization and payment, x402-compatible HTTP error responses,
and a uniform JSON error envelope. This document specifies each edge
independently, as a complete protocol reference.

---

## Principles

The following principles underpin every design decision in this protocol. When
in doubt about how to handle a case not explicitly covered, apply these
principles in order.

**1. Three parallel trees from one root.**
Every stored file has three trees rooted at the same `rootCid`, all with the
same N-ary shape, all navigable by the same link path arrays:

- **Merkle tree** — built bottom up from ciphertext. Commits to every chunk in
  every track. Public and cacheable. Deduplication is automatic: same content
  → same CIDs → same tree nodes.
- **Encryption key tree** — built top down via chained `Q.Crypto.delegate` calls,
  one per link path segment. Cloud only. Jets never see it.
- **Access level tree** — built top down via chained `Q.Crypto.delegate` calls,
  same path segments, different label prefix. Carries Streams-compatible access
  levels (`readLevel`, `writeLevel`, `adminLevel`). Jets enforce this tree.

The Merkle and Prolly trees go up; the key derivation trees go down.
The Prolly tree is per-node inventory (which files a Jet/Drop holds), not per-file
structure — it is completely separate from the per-file Merkle tree.

**2. Separate derivation trees for encryption and access — deduplication without
disclosure.**
The encryption key tree and the access grant tree are derived from different
branches of the same root key. Two users with different access levels see the
same ciphertext (enabling CDN deduplication and public caching) but hold
different subtree keys (enabling fine-grained access control). Ciphertext can
be cached publicly and indefinitely; decryption keys are distributed only to
authorized holders via OCP Role A grants.

**3. HTTP for caching and transport.**
Wherever possible, chunk retrieval is expressed as standard HTTP GET requests
with `Cache-Control: public, max-age=31536000, immutable`. This means CDNs,
browsers, and proxies all participate in the caching layer for free. The
immutability of CIDs (content-addressed, deterministic) makes this Q.Safecloud.Client

**4. OCP for all protocol-level signing.**
Every protocol-level authorization, payment, proof, and identity claim is
expressed as an OpenClaiming Protocol (OCP) envelope. OCP claims are
self-describing, independently verifiable, and composable. There is no
out-of-band trust, no session state that cannot be expressed as a signed claim,
and no mechanism for participants to make protocol-level assertions that are not
signed by their own key. (Transport-layer mechanisms such as HTTP Bearer tokens
for Jet relay auth and x402 payment headers sit beneath this layer and are not
themselves OCP claims.)

**5. Pairwise micropayments off-chain; settle on-chain in batches.**
Participants do not post every micropayment to a blockchain. Instead they
accumulate signed OCP payment tokens off-chain and batch-settle periodically
via `OpenClaiming.paymentsExecute()`. This gives the protocol the economic
precision of per-chunk pricing without the gas cost of per-chunk on-chain
transactions. The OpenClaiming contract is the final arbiter; off-chain tokens
are just pre-authorized claims against it.

**6. Zero-sum economics.**
Every payment is balanced: Clouds pay Jets for routing, Jets pay Drops for
storage and retrieval, Jets pay peer Jets for relay. No participant earns
without providing corresponding value. No participant is expected to subsidize
another. The Jet's margin is the spread between what it charges Cloud and what
it pays Drops. This makes economic incentives and attack surfaces explicit.

**7. Smart contracts for composable payout rules.**
The OpenClaiming contract supports arbitrary recipient sets, line-based budget
isolation, and ERC-20 tokens. Applications can build commissions, revenue
splits, subscription models, and DAO-governed treasuries on top without
modifying the protocol. The contract is deployed at one canonical address on
all supported chains and is not upgradeable — the rules are fixed and auditable.

**8. EVM addresses as canonical identity.**
Every participant — Cloud payer, Jet, Drop — is identified by their EVM address
on BNB Chain (BSC, `eip155:56`). This address is the basis for stake
accumulation, Safebux earnings, and slashing. It is not optional or ephemeral.
A participant without an EVM address has no stake and no accountability, and
is treated accordingly by routing algorithms.

**9. Balance and line pre-screening with caching.**
Before accepting a payment token, every node (Jet or Drop) independently
queries the payer's on-chain balance and allowance. This check is cached in
memory (default 1 hour) to avoid RPC hammering. It is a pre-screen only — the
definitive check is on-chain at execution. Nodes that skip this check risk
serving without getting paid; nodes that cache too aggressively risk serving
depleted payers. The 1-hour TTL balances these risks.

**10. Everyone acts as themselves; anyone can stop doing business with anyone.**
There is no central authority that can force a participant to serve a request,
accept a payment, or trust a peer. Jets route to whichever Drops they trust.
Drops serve whichever Jets pay them. Clouds connect to whichever Jets they
have configured. If a participant is overpriced, unreliable, or corrupt, the
rational response is to route around them. Reputation is accumulated through
consistent honest behavior and reflected in stake.

**11. Everyone signs as themselves.**
No participant signs on behalf of another, and no participant accepts a claim
not signed by the key it names as issuer. Proxies, relays, and intermediaries
pass through signed claims verbatim — they do not re-sign. A Jet forwarding a
Cloud payment token to a Drop forwards the original Cloud-signed OCP envelope;
it does not re-sign it as itself.

**12. Trusted execution environment for dynamically loaded JS.**
Any participant running Safecloud logic in a browser (Drops, and optionally
Cloud clients) must trust the JavaScript they execute. This trust should be
grounded in one of:
- A verifiable attestation from SafeBox (hardware root of trust via AWS Nitro,
  TPM-measured AMI, deterministic build pipeline) at `safebox.org`
- A user agent that checks the JS bundle hash against M-of-N auditor keys the
  user trusts before executing it (analogous to PHAR signature verification, but
  applied to browser JS bundles)

Without such grounding, a malicious server can ship JS that non-interactively
signs fraudulent OCP claims using the Drop's delegated session keys, forging
a Proof of Corruption against the Drop and slashing its stake. The pristine
environment is not a nice-to-have — it is a protocol security requirement.

**13. Proof of Corruption: gossip, slash, and lottery.**
When a participant provably lies — by signing two OCP claims that contradict
each other without requiring any external context to verify the contradiction —
any honest node can construct a Proof of Corruption (CoC) OCP claim referencing
the contradictory evidence. CoCs are gossiped across the Jet network. Honest
nodes that have gossiped a CoC enter their EVM address into a future lottery:
when the corrupt actor's stake is eventually slashed on-chain, the slashed
amount is distributed to lottery winners. Lottery randomness comes from a
RANDAO-type source (BNB Chain block randomness or a verifiable random beacon).
This incentivizes active CoC participation rather than passive observation —
every node that gossips a valid CoC gains a chance at the slashed stake.

**14. OCP claims are self-contained by design.**
Every OCP claim that could serve as evidence in a CoC must include sufficient
context to be verified without external state. The protocol enforces this at
claim-creation time by requiring that challenge responses include the current
Prolly root, that Prolly diffs include the previous root, and that all claims
include timestamps. A CoC that requires external context to verify is invalid
and the claimant is penalized for filing it.

---

## Shared conventions

### Chain separation

Safecloud uses two distinct chain roles:

- **Identity, stake, and Safebux accounting:** BNB Chain (BSC, `eip155:56`).
  Every participant's canonical EVM address, their Safebux balance, and all
  stake/slash operations live on BSC. This is hardcoded in the v1 protocol.

- **OpenClaiming payment execution:** the chain specified in each payment
  token's `stm.chainId` and `stm.contract`. The OpenClaiming address is
  configured per chain in `Users.web3.contracts["Safecloud/openclaiming"]`
  and is a SIGNED field: the rail validates `stm.contract == address(this)`.
  In the **reference deployment all payment flows — Cloud → Jet and
  Jet → Drop — execute on BSC** (`eip155:56`), denominated in Safebux.

The multi-chain capability of the OpenClaiming contract is a protocol feature
reserved for future deployments. All examples in this document use
`eip155:56` (BSC).

---

### OCP wire format

The OpenClaiming Protocol (OCP) is used for both access authorization (Role A)
and micropayments (Role B) across all edges. OCP defines a general signed-claim
envelope:

```json
{
  "ocp": 1,
  "iss": "data:key/es256;base64,<SPKI-DER-base64>",
  "sub": "...",
  "stm": { ... },
  "key": ["data:key/es256;base64,...", "data:key/eip712,0x..."],
  "sig": ["<base64-r-s-64-bytes>", "<base64-r-s-v-65-bytes>"]
}
```

Fields:
- `ocp` — protocol version, always `1`
- `iss` — issuer key URI (see key resolution below)
- `sub` — subject (depends on claim type)
- `stm` — statement object (claim-type-specific fields)
- `key` — array of signer key URIs, sorted lexicographically
- `sig` — array of signatures parallel to `key[]`, sorted with `key[]`

Signatures for ES256 keys are 64-byte raw `r‖s` (IEEE P1363), base64-encoded.
Signatures for EIP-712 keys are 65-byte `r‖s‖v`, base64-encoded.

Canonicalization uses RFC 8785 / JCS (JSON Canonicalization Scheme): `sig`
is stripped before hashing, keys are sorted, and the canonical UTF-8 JSON
string is SHA-256 hashed for ES256 signing.

**Important:** The two Safecloud OCP roles both use the full OCP envelope, with
claim-type-specific fields in `stm`:
- **Role A (access grants):** `sub = "safecloud:subtree"`. `stm` contains
  `label`, `context`, `issuedTime`, `secretHash`, `parent`. Signed with a
  P-256 (ES256) key. The `secret` (subtreeKey) is never included.
- **Role B (payment tokens):** `sub = "safecloud:payment"`. `stm` contains the
  EIP-712 Payment struct fields. Signed with an EVM (secp256k1 / EIP-712) key.
  The `sig[]` entry is accepted directly by `OpenClaiming.paymentsExecute()`.

The general OCP envelope is the base format for all Safecloud signed objects.
An implementor should expect all grants and payment tokens to have the
`ocp`/`iss`/`sub`/`stm`/`key[]`/`sig[]` structure.

---

### Connection authentication and session key delegation

Every Drop and Jet must prove ownership of its canonical EVM address before
being trusted on the network. Rather than requiring interactive wallet
signatures for every OCP claim — which would be unusable in a browser Drop that
signs challenge responses and Prolly diffs continuously — Safecloud uses a
**one-time interactive delegation** via `Q.Crypto.delegate` to establish a
non-interactive session keypair.

**The delegation ceremony (one interactive wallet signature per session):**

```js
// 1. User connects their wallet (MetaMask, WalletConnect, etc.)
const walletAddress = await wallet.getAddress();

// 2. Q.Crypto.delegate derives a session keypair from one interactive sign.
//    The user signs an EIP-712 structured delegation claim:
const delegation = await Q.Crypto.delegate({
    label:   'safecloud.session',
    context: JSON.stringify({
        exp: Math.floor(Date.now() / 1000) + 30 * 86400  // 30-day session
    }),
    format:  ['ES256', 'EIP712']   // derive both a P-256 and a secp256k1 session key
});

// delegation produces an OCP claim signed by the wallet:
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<wallet-address>",
  "sub": "safecloud:session-delegation",
  "stm": {
    "sessionKeyES256":  "<base64 P-256 SPKI>",    // for challenge responses, diffs
    "sessionKeyEIP712": "0x<secp256k1 address>",  // for payment tokens, announcements
    "exp": 1702684800
  },
  "key": ["data:key/eip712,0x<wallet-address>"],
  "sig": ["<wallet EIP-712 sig>"]
}
```

Both session keys are derived deterministically from the wallet signature — no
random generation, no storage of raw private key material. The session keypair
is stored in IndexedDB as a non-extractable `CryptoKey` (Web Crypto API,
`extractable: false`). All subsequent Safecloud signing is non-interactive:

| Claim type | Signing key used |
|------------|-----------------|
| Challenge responses, Prolly diff announces | ES256 session key (fast, local) |
| Payment tokens, routing announcements | EIP-712 session key (on-chain compatible) |
| CoC evidence | EIP-712 session key |

The delegation claim itself is sent in `Safecloud/drop/register` (Edge 4) and in
`safecloud.jet.hello` (Edge 2) in place of the old `authPayload`/`authSignature`
fields. Any receiver can verify the session keys are legitimately delegated
from the canonical wallet address by checking the delegation claim's signature.

Session lifetime is controlled by `stm.exp` in the delegation claim. Default
is 30 days. On expiry the Drop or Jet re-runs the ceremony with one interactive
wallet signature.

**Jet↔Jet hello delegation — concrete typed data (v1).** Node Jets hold their
wallet key directly, so `safecloud.jet.hello` carries a self-issued delegation
signed over this exact EIP-712 structure (`classes/Safecloud/Router.js`; the
signer `_buildJetDelegation` and verifier `_verifyDelegation` must stay
byte-identical on both ends):

```
domain:  { name: "Safecloud", version: "1" }          // chain-agnostic session claim
types:   JetSessionDelegation {
           iss:              string                    // "data:key/eip712,0x<wallet>"
           sub:              string                    // "safecloud:session-delegation"
           sessionKeyEIP712: address                   // wallet address (self-delegation)
           noisePublicKey:   string                    // hex of hyperswarm Noise static key
           nbf:              uint256
           exp:              uint256                   // now + 30 days
         }
```

The verifier recovers the signer and requires it to equal the hello's
`evmAddress`, checks the `nbf`/`exp` window, and — critically — requires
`stm.noisePublicKey` to equal the Noise static public key of the connection
the hello arrived on. A delegation captured from one connection therefore
cannot be replayed over another (see Attacks.md 1.2). Receivers with the
platform OCP module present verify `ocp: 1` claims through
`Q.Crypto.OpenClaim.verify` first, so Drop-style platform-issued delegations
remain acceptable on this edge. Setting
`Safecloud.swarm.allowUnverifiedDelegations: true` (default `false`) restores
the pre-v1 lenient behaviour for development meshes.

---

### Pristine environment requirement and SafeBox attestation

**The threat:** Safecloud Drops hold real economic stake (Safebux) and sign
OCP claims non-interactively using their delegated session keys. If the
JavaScript environment serving the Drop application is compromised — even
subtly — a malicious server could:

- Exfiltrate session keys from IndexedDB and sign fraudulent claims
- Manufacture false challenge responses to frame a Drop for a CoC
- Sign Prolly diff announces claiming the Drop evicted chunks it still holds,
  then fail a challenge, triggering a slash against the Drop's own stake
- Silently modify payment token amounts or recipient addresses

The delegation ceremony's `extractable: false` mitigates key exfiltration via
JavaScript, but it does not help if the malicious code simply calls the
non-extractable key's `sign()` function directly on attacker-chosen payloads.
A pristine environment is therefore a hard requirement for Safecloud Drops.

**SafeBox:** The Safecloud browser application is served exclusively from
`safebox.org`, which runs on a SafeBox-attested infrastructure. SafeBox is a
system for serving web applications from AWS EC2 instances whose software stack
is:

1. **Built deterministically** — the AMI is produced by a public, reproducible
   build pipeline. Any party can clone the pipeline, build the AMI, and verify
   that the resulting image hash matches the published value byte-for-byte.

2. **TPM-measured at boot** — the running instance's PCR values (TPM Platform
   Configuration Registers) record every step of the boot sequence. These
   measurements are published in a signed AWS Nitro attestation document.

3. **Publicly attested** — SafeBox publishes the Nitro attestation document for
   every running instance. Users and auditors can verify: (a) the AMI hash
   matches the published deterministic build, (b) the TPM measurements match the
   expected boot sequence, (c) the instance is running the code it claims to run.

4. **Attested in OCP** — SafeBox's attestation is itself an OCP claim signed by
   the SafeBox operator key:

```json
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<SafeBox-operator-EVM>",
  "sub": "safecloud:environment-attestation",
  "stm": {
    "amiHash":       "<SHA-256 of AMI image>",
    "bundleHash":    "<SHA-256 of served JS bundle>",
    "nitroDocument": "<base64 AWS Nitro attestation>",
    "origin":        "https://safebox.org",
    "timestamp":     1700000000
  },
  "key": ["data:key/eip712,0x<SafeBox-operator-EVM>"],
  "sig": ["<SafeBox operator EIP-712 sig>"]
}
```

Clients and peer Jets can fetch the current attestation from
`https://safebox.org/.well-known/safecloud-attestation.json` and verify it
before trusting a Drop that claims to be running on SafeBox.

**The trust chain for a Drop's session keys:**

```
AWS Nitro (hardware root of trust)
  └─ TPM measurements (boot sequence verified)
       └─ SafeBox AMI (deterministic build, public pipeline)
            └─ safebox.org JS bundle (hash in attestation)
                 └─ Q.Crypto.delegate ceremony (non-extractable session key)
                      └─ Drop's OCP claims (challenge responses, diffs, payments)
```

Every signed claim a Drop makes is traceable back to hardware attestation.
An operator who wanted to frame a Drop for a CoC would need to either compromise
AWS Nitro itself, or get the Drop's user to run a non-attested environment —
which the protocol explicitly warns against.

**Fallback for non-SafeBox environments:** Drops may run outside `safebox.org`
(e.g. as a browser extension or Electron app) at reduced trust. Peer Jets may
choose to assign lower routing priority to Drops whose delegation claim was not
issued within a SafeBox-attested session. Jets can check this by verifying the
environment attestation was valid at the time of the delegation's `issuedTime`.

---

### OCP Role A — access grants

Role A grants are full OCP envelopes. The access-specific fields live in `stm`.

```json
{
  "ocp":  1,
  "iss":  "data:key/es256;base64,<issuer-SPKI-DER-base64>",
  "sub":  "safecloud:subtree",
  "stm":  {
    "label":      "safecloud.node.1",
    "context":    "{\"rootCid\":\"bafy...\",\"link\":[\"track\",\"data\",\"0\",\"1\"],\"readLevel\":23,\"exp\":0}",
    "issuedTime": 1700000000,
    "secretHash": "<hex-keccak256-of-subtreeKey>",
    "parent":     "<hex-of-issuing-public-key>"
  },
  "key":  ["data:key/es256;base64,<grantee-SPKI-DER-base64>"],
  "sig":  ["<base64 ECDSA-P256 r‖s 64 bytes>"]
}
```

Fields:
- `ocp` — always `1`
- `iss` — the granting party's key URI (content owner or sub-delegator)
- `sub` — always `"safecloud:subtree"` for access grants
- `stm.label` — access tier: `safecloud.read.*`, `safecloud.write.*`, `safecloud.admin.*`.
  The label is the last segment's HKDF label in the delegation chain:
  - Track level: `safecloud.track.data`, `safecloud.track.index`
  - Subtree level: `safecloud.node.0`, `safecloud.node.1`, etc.
  The full path is recorded in `stm.context.link`. Grants for different tracks
  and different subtree nodes are completely independent — a grantee may hold
  index-only access, a clip range only, or any combination.
- `stm.context` — JSON string: `{ rootCid, link, readLevel, writeLevel, adminLevel, exp }`
  where `link` is the path array to the granted subtree node,
  e.g. `["track","data","0","1"]` for a specific internal node,
  or `["track","index"]` for the index track.
  The access level fields mirror the Streams access level system.
- `stm.issuedTime` — Unix seconds; informational only, does not affect crypto
- `stm.secretHash` — `keccak256` of the subtreeKey bytes; lets the Jet verify the
  grant's stated access is internally consistent without seeing the key itself
- `stm.parent` — hex of the parent public key in the delegation chain (for sub-grants)
- `key[]` — the grantee's key URI (who may use this grant)
- `sig[]` — issuer's ECDSA-P256 signature over the canonical JSON of the full envelope
  (with `sig` stripped per RFC 8785)

**The `secret` field (the actual subtreeKey for decryption) is NEVER included
in the OCP envelope.** It travels separately in Cloud's local grant record and
is stripped before the grant is sent to a Jet.

Sub-delegation: a grantee with `safecloud.admin.*` may issue a new grant with
themselves as `iss`, reducing the range or level. The `stm.parent` field chains
back to the original issuer so the Jet can verify the delegation path.

Grant verification on the Jet checks link path coverage: for each requested
chunk, at least one grant must satisfy:
- `stm.context.link` is an ancestor-or-equal path of the chunk's position in the tree
- `stm.context.rootCid == rootCid` (on reads)
- `stm.context.readLevel >= required` (or writeLevel/adminLevel as appropriate)
- `exp` not exceeded
- Valid OCP signature verifying the delegation chain from `accessRoot`

---

### OCP Role B — payment tokens

Used to prove the bearer is paying for retrieval. These are full OCP envelopes
where `stm` contains the EIP-712 Payment struct fields, signed with an EVM
(secp256k1) key. Verification is on-chain-compatible via `ecrecover`.

```json
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<payer-EVM-address>",
  "sub": "safecloud:payment",
  "stm": {
    "payer":          "0x<EVM address>",
    "token":          "0x<ERC-20 address>",
    "recipientsHash": "0x<keccak256(abi.encode([address[]]))>",
    "max":            "10000",
    "line":           0,
    "nbf":            0,
    "exp":            0,
    "chainId":        "eip155:56",
    "contract":       "0x<OpenClaiming address from config>"
  },
  "key": ["data:key/eip712,0x<payer-EVM-address>"],
  "sig": ["<base64 65-byte EIP-712 r‖s‖v>"]
}
```

The `sig[]` entry is the EIP-712 signature over the Payment struct — the same
bytes accepted by `OpenClaiming.paymentsExecute()` on-chain. The OCP envelope
wraps it in a standard signed-claim format so it can be carried alongside Role
A grants in the same request payload.

- `stm.line = 0` uses the **default line**, which is always open with no
  contract-level cap. Off-chain systems (Jets, Drops) pre-screen the payer's
  ERC-20 balance/allowance independently (see Edge 3). The definitive check is
  on-chain at execution. Use `line >= 1` for budget-capped explicit lines
  opened via `lineOpen()`.
- `stm.recipientsHash` = `keccak256(abi.encode(recipients[]))` where
  `recipients` is the array of allowed recipient addresses committed at signing.
  **Who constructs tokens for whom:**
  - **Cloud → Jet:** Cloud constructs the token. `recipients = [jetEVMAddress]`.
    Cloud knows Jets (they are the configured endpoints). This is the only token
    Cloud ever signs.
  - **Jet → Drop:** The **Jet** constructs and signs the token for the Drop it
    selects to serve the request. `recipients = [dropEVMAddress]`. The Jet knows
    the Drop's EVM address from the Drop's handshake registration (see Edge 4).
    Cloud never constructs or signs tokens for individual Drops — it does not
    know which Drops exist.
- `stm.max = "0"` means unlimited per-claim ceiling
- `stm.exp = 0` means no expiry

**Cloud payer model:** Cloud clients do not go through the session delegation
ceremony — they do not connect to the network as a registered participant.
Their identity is simply the EVM address that signed the OCP Role B payment
token. Safecloud is agnostic about how that address is funded:

| Scenario | Who signs the Cloud → Jet payment token |
|----------|------------------------------------------|
| End-user with a browser wallet | User's own EVM address, signed interactively |
| Video platform / SaaS | Application server wallet, charged to users via credit card / subscription |
| DAO-funded content | A multisig treasury address |
| Developer testing | A funded test wallet |

The Jet does not care who the ultimate end-user is — only that the OCP payment
token carries a valid EIP-712 signature and the payer has sufficient Safebux
balance and allowance.

**Line 0 (DEFAULT_LINE) semantics:**
Line 0 is always open and requires no prior `lineOpen()` call. The contract
imposes no line-level cap — only the per-claim `stm.max` ceiling applies.
The `spent` counter at `lines[payer][0]` is still tracked to enforce that
ceiling across multiple executions of the same claim. Using line 0 effectively
grants the contract unlimited access up to the payer's ERC-20 allowance; use
explicit lines (≥ 1) for budget isolation. `lineAvailable()` for line 0 returns
the claim-level capacity only and does NOT reflect ERC-20 balance or allowance.

**Payment tokens are reusable, not one-shot.** The `Payment` struct has no
nonce. A token may be executed repeatedly against the same line until
`lines[payer][line].spent` reaches the claim `max` ceiling, or the token
expires. Off-chain systems that want single-use semantics must track used tokens
independently and reject duplicates.

**Token deduplication and replay:**

Drops SHOULD index accumulated payment tokens by a hash of their canonical JSON
form. Because tokens have no nonce, the same token may be executed multiple
times until `lines[payer][line].spent` reaches the `max` ceiling or the token
expires. A Drop may execute the same token for multiple chunk-serving sessions
(partial consumption) or treat it as fully consumed once `spent >= max`.
Applications requiring single-use semantics MUST enforce this off-chain by
tracking submitted tokens.

**Amount derivation:**

The `amount` passed to `paymentsExecute()` is the number of chunks served in a
session multiplied by the per-chunk price configured by the Jet
(`Q.Config.get(['Safe', 'pricing', 'perChunkWei'])`). This value must be ≤
`stm.max`. The same per-chunk price is published in x402 `PaymentRequirements`
as `maxAmountRequired` for external HTTP clients.

A single payment token may be redeemed in multiple `paymentsExecute()` calls,
so long as the cumulative redeemed amount does not exceed `stm.max`. Each call
increments `lines[payer][line].spent`; the token is exhausted when `spent`
reaches `max`.

**EIP-712 domain** used by all Safecloud payment tokens:
```json
{
  "name":              "OpenClaiming",
  "version":           "1",
  "chainId":           <uint256 from stm.chainId CAIP-2>,
  "verifyingContract": <OpenClaiming address from config>
}
```

**Signed struct** (8 fields; the `contract` field is validated
`== address(this)` by the rail):
```
Payment(address payer,address token,bytes32 recipientsHash,uint256 max,
        uint256 line,uint256 nbf,uint256 exp,address contract)
```
`recipientsHash` = `keccak256(abi.encode(address[]))` for plain payments,
or `keccak256(abi.encode(Policy))` for enforced splits — one signed field,
two non-colliding encodings.

---

### OCP key resolution and remote keys

OCP key URIs support three formats:

**Inline P-256 key:**
```
data:key/es256;base64,<SPKI-DER-base64>
```
Parsed inline; no network request. The SPKI DER bytes are the 27-byte P-256
prefix followed by the 65-byte uncompressed public key point.

**Ethereum address:**
```
data:key/eip712,0x<address>
```
Parsed inline. Verification delegates to EIP-712 `ecrecover`.

**URL-hosted key document:**
```
https://example.com/.well-known/safecloud-keys.json#path/to/key
```
Fetched via HTTPS on first use and cached in memory for 60 seconds
(`_urlTtl = 60000 ms`). The fragment is a `/`-separated path into the JSON
document. The resolved value may itself be a key URI (enabling indirection),
but cycles are detected and rejected.

Jets and Drops performing verification must support all three formats. The
60-second URL cache is applied per process, not shared across instances.

---

### Batch HTTP request format

`GET /Safecloud/cloud/subtree/{rootCid}` encodes all auth and payment
parameters in the URL query string so that responses can be cached by CDN
proxies and intermediate servers.

Query parameters:
- `link` — slash-separated link path, e.g. `track/data/0/1`. Defaults to `track/data` if omitted.
- `g` — `base64url(JSON.stringify(grants[]))` — OCP Role A grants (secret stripped)
- `p` — `base64url(JSON.stringify(payments[]))` — OCP Role B payment tokens
- `s` — `base64url(publisherId + "\t" + streamName)` — optional Streams check

**URL size limit:** The full URL must stay within ~2000 characters. For large grant
sets, split into multiple requests at different link paths and reassemble.

```
// Data track subtree nodes fetched separately:
GET /Safecloud/cloud/subtree/bafy...?link=track/data/0&g=<b64url>&p=<b64url>
GET /Safecloud/cloud/subtree/bafy...?link=track/data/1&g=<b64url>&p=<b64url>
// Index track:
GET /Safecloud/cloud/subtree/bafy...?link=track/index&g=<b64url>&p=<b64url>
```

`PUT /Safecloud/cloud/subtree` and all socket.io messages use JSON bodies; no size limit
applies to them.

`PUT /Safecloud/cloud/subtree` and all socket.io messages use JSON bodies; no size limit
applies to them.

---

### Error response envelope

Every non-2xx response from any Safecloud HTTP endpoint uses this envelope:

```json
{
  "error": {
    "code":    "<ErrorCode>",
    "message": "<human-readable string>",
    "details": { ... }
  }
}
```

`Content-Type: application/json` is always set on error responses.

**403 — access denied:**
```json
{
  "error": {
    "code":    "NotAuthorized",
    "message": "Grants do not cover all requested chunk indices",
    "details": {
      "unauthorized": [3, 4, 7],
      "grantIssues": [
        { "index": 3, "issue": "No grant covers this index" },
        { "index": 7, "issue": "Grant expired at 1700000000" }
      ]
    }
  }
}
```

`details.unauthorized` is the **complete list of absolute chunk indices**
within the requested range that were denied. The client may immediately
retry with a modified request excluding those indices.

**402 — payment required (OCP token present, balance insufficient):**
```json
{
  "error": {
    "code":    "PaymentRequired",
    "message": "Payer ERC-20 balance insufficient",
    "details": {
      "payer":    "0x...",
      "token":    "0xUSDCAddress",
      "required": "1000",
      "balance":  "500",
      "chainId":  "eip155:56"
    }
  }
}
```

**404 — content not found:**
```json
{
  "error": {
    "code":    "NotFound",
    "message": "rootCid not found in this Jet's index",
    "details": { "rootCid": "bafy...", "hint": "Try another Jet" }
  }
}
```

Socket.io ack errors use the same structure in the `err` argument:
```js
ack({ error: { code: 'NotAuthorized', message: '...', details: { unauthorized: [3,7] } } })
```

---

### HTTP status codes

| Code | Meaning | When used |
|------|---------|-----------|
| 200  | OK | Request succeeded; body is JSON or raw bytes |
| 206  | Partial Content | HTTP Range request on chunk fetch |
| 400  | Bad Request | Malformed payload or missing required fields |
| 402  | Payment Required | OCP payment missing or balance insufficient; x402-compatible |
| 403  | Forbidden | OCP grants missing, invalid, or insufficient range coverage |
| 404  | Not Found | rootCid or cid unknown to this Jet |
| 500  | Internal Server Error | Jet failed to contact Drops or unexpected error |

---

### x402 compliance

When a `GET /Safecloud/cloud/chunk/{cid}` request arrives **without a `PAYMENT-SIGNATURE`
header**, the Jet returns a fully x402 v2-compatible response so that external
clients (AI agents, CDN middleware, curl) can discover payment requirements and
retry automatically:

```
HTTP/1.1 402 Payment Required
PAYMENT-REQUIRED: <base64(JSON PaymentRequirements)>
Content-Type: application/json
```

`PaymentRequirements` JSON (x402 v2 spec):
```json
{
  "scheme":             "exact",
  "network":            "eip155:56",
  "maxAmountRequired":  "1000",
  "resource":           "https://jet.example.com/Safecloud/cloud/chunk/bafy...",
  "description":        "Safecloud chunk retrieval",
  "mimeType":           "application/octet-stream",
  "payTo":              "0xJetWalletAddress",
  "token":              "0xUSDCAddress",
  "extra":              { "name": "Safecloud", "version": "1" }
}
```

The client retries with a complete OCP Role B envelope serialised as base64:
```
PAYMENT-SIGNATURE: <base64(JSON OCP Role B envelope)>
```

The envelope must contain `stm.payer`, `stm.token`, `stm.recipientsHash`,
`stm.max`, `stm.line`, `stm.nbf`, `stm.exp`, `stm.chainId`, `stm.contract`,
and `sig[0]` (the 65-byte EIP-712 signature). The Jet passes the Payment struct
fields and the signature directly to `OpenClaiming.paymentsExecute()`. A bare
EIP-712 signature is not sufficient — the full Payment struct is required for
on-chain verification.

On success:
```
HTTP/1.1 200 OK
PAYMENT-RESPONSE: <base64(SettlementResponse)>
Cache-Control: public, max-age=31536000, immutable
```

**x402 applies to `GET /Safecloud/cloud/chunk/{cid}` only.** This is the raw single-chunk
endpoint for external clients who pay for ciphertext access and obtain
decryption keys through a separate channel (e.g. OCP Role A grant from the
content owner). No OCP Role A grant is required on this path.

**`GET /Safecloud/cloud/subtree` is NOT an x402 endpoint.** It requires OCP Role A grants.
If no grants are present, the Jet returns 403 (not 402 with x402 headers),
because the client needs to obtain a grant from the content owner — payment
alone is not sufficient to access a specific named subtree.

---

### Cache-Control on encrypted responses

Encrypted chunk responses are **safe to cache publicly** because:

1. The encryption key tree and the access grant tree are separate branches
   of the same root key (see Cloud.md §1.2). The ciphertext bytes are
   determined entirely by the encryption branch; the access grant tree
   produces authorization tokens that travel with requests but do not
   affect the stored bytes.

2. CIDs are content-addressed (CIDv1, sha2-256 of ciphertext + AAD). The
   same CID always corresponds to the same ciphertext bytes — immutable.

Therefore all successful chunk responses carry:
```
Cache-Control: public, max-age=31536000, immutable
```

This enables CDN deduplication across all users of the same content, even
though that content is encrypted. Two users with different access grants
requesting the same chunk receive the same cached ciphertext; only their
locally held subtreeKey (from their respective OCP Role A grants) differs.

---


---

## File tracks — data track and index track

Every Safecloud object has two independently encrypted and independently
grantable tracks. Tracks are top-level branches of the N-ary Merkle tree:

```
rootCid
├── track/data    ← N-ary subtree of encrypted content chunks (N=2 default)
│     ├── node/0  → node/0/0, node/0/1, ... → leaf CIDs
│     └── node/1  → ...
└── track/index   ← single encrypted index chunk (initSegment, chapters, codec)
```

**Data track** contains the file content itself, split into AES-256-GCM encrypted
chunks arranged in an N-ary Merkle tree (default N=2). For video, each chunk
contains one GOP aligned to a keyframe boundary, so any subtree node can be
decoded independently. Keys are derived by chaining `Q.Crypto.delegate` down the
link path: `encryptionRoot → track/data → node/0 → node/0/1 → ... → subtreeKey`.
Leaf chunk keys use `Q.Data.derive(subtreeKey, "safecloud.chunk.key.i")`.

**Index track** is a single encrypted chunk (found by navigating
`Merkle.getNode(rootCid, ["track","index"])` — no manifest field needed) whose
plaintext is a JSON object containing type-specific metadata. For video:

```json
{
  "initSegment":   "<base64 fMP4 ftyp+moov bytes>",
  "totalDuration": 852.852,
  "codec":         "avc1.64001f",
  "audioCodec":    "mp4a.40.2",
  "width":         1920,
  "height":        1080,
  "frameRate":     "30000/1001",
  "chapters": [
    { "pts": 0.000,  "dts": 0.000,  "label": null },
    { "pts": 6.006,  "dts": 6.006,  "label": null },
    ...
  ]
}
```

For other file types the index carries whatever makes sense (document outline,
track listing, dataset schema, etc.). The index is always small enough to fit in
a single chunk — a few KB even for a long video with many chapters.

**Why separate tracks:**

1. **Privacy.** Codec, resolution, duration, and chapter timestamps are
   sensitive metadata. Storing them encrypted prevents passive observers from
   learning anything about the content — not even how long a video is — without
   a valid grant.

2. **Teaser / preview access.** Granting only the index track lets a recipient
   see the table of contents, scrub a seek bar, and inspect metadata — without
   being able to decrypt any actual video frames or file content. Combined with
   thumbnail images in the index, this enables rich previews with zero plaintext
   leakage from the data track.

3. **Independent cacheability.** The index track CID is stable and small. CDNs
   and Drops can cache it independently of the data chunks.

4. **Extensibility.** Future forks can be added without changing the core
   protocol: `safecloud.track.thumbs` for thumbnail images,
   `safecloud.track.preview` for a low-resolution rendition,
   `safecloud.track.audit` for provenance / access log.

**Key derivation for tracks:**

Both tracks are derived from the same `encryptionRoot`, ensuring a single
`rootKey` gives access to everything. But they use different HKDF labels, so they can be granted independently.
The Merkle tree path mirrors the HKDF label — "Merkle trees going up,
key derivation trees going down" (§Principles):

```
encryptionRoot
├── Q.Crypto.delegate("safecloud.track.data.{S}.{E}", context)  → data subtreeKey
└── Q.Crypto.delegate("safecloud.track.index",        context)  → index key
```

**Manifest fields for tracks:**

```json
{
  "v":                       1,
  "rootCid":                 "bafy...",
  "treeN":                   2,
  "treeDepth":               5,
  "chunkCount":              143,
  "tracks":                  ["data","index"],
  "encryptionRootPublicKey": "...",
  "accessRootPublicKey":     "...",
  "bindingProof":            {...}
}
```

No `indexCid` field — the index track CID is found by navigating
`Merkle.getNode(rootCid, ["track","index"])`. The rootCid commits to it.
`treeN` and `treeDepth` describe the N-ary data track structure.
`chunkCount` is the total leaf count in the data track.
No codec, resolution, duration, or timestamp information appears in the manifest.

**Grant independence examples:**

```
Full access:
  grant("safecloud.track.data.0.143", rootCid)   → decrypt all video frames
  grant("safecloud.track.index",      rootCid)   → decrypt index (chapters, timestamps)

Preview / teaser:
  grant("safecloud.track.index", rootCid) only   → see chapters + seek bar, no video

Clip access:
  grant("safecloud.track.data.24.48", rootCid)   → only minutes 2-4
  grant("safecloud.track.index",      rootCid)   → full chapter list (shows what they're missing)
```

---

## Edge 1 — Cloud ↔ Jets (HTTP + socket.io)

### Topology

```
  Browser (Q.Safecloud.Client)
      │
      ├── socket.io /Safecloud/  (persistent, primary for browser clients)
      └── HTTPS             (batch GET cacheable by CDN; PUT for upload)
      │
  Node.js Jet server (classes/Safecloud/Jets.js)
```

Cloud connects to the Jet on its configured URL (`Q.Safecloud.Jets.url` or
`Q.nodeUrl()`). The socket.io namespace is `/Safecloud/`. Both transports share
identical verification and response logic.

---

### PUT /Safecloud/cloud/subtree — upload chunks

```
PUT /Safecloud/cloud/subtree
Content-Type: application/json

{
  "chunks": [
    {
      "cid":        "bafy...",
      "iv":         "<base64 12 bytes>",
      "ciphertext": "<base64>",
      "tag":        "<base64 16 bytes>",
      "size":       262144,
      "tags":       []
    }
  ],
  "link":        ["track", "data"],
  "grants":      [ <OCP Role A grant objects, secret stripped> ],
  "payments":    [ <OCP Role B payment token objects> ],
  "publisherId": "abc123",
  "streamName":  "Safecloud/files/xyz"
}
```

`link` identifies which subtree these chunks belong to, e.g. `["track","data"]` for the full data
track or `["track","index"]` for the index track. The Jet uses this to key the CID index and route
Merkle proofs correctly.

`publisherId` + `streamName` are optional. When present, the Jet checks the
caller's Streams `WRITE_LEVEL.post` (20) before proceeding — uploading chunks
requires write access, not read access.

**Success (200):**
```json
{ "results": [{ "cid": "bafy...", "stored": true }, ...] }
```

**Failure responses:** see error envelope above (403, 402, 500).

---

### GET /Safecloud/cloud/subtree/{rootCid} — fetch subtree by link path

```
GET /Safecloud/cloud/subtree/bafy...?link=track/data/0/1&g=<grants_b64url>&p=<payments_b64url>&s=<streamId_b64url>
```

- `link` — slash-separated link path, e.g. `track/data` (full data track) or `track/data/0/1` (specific subtree node). Defaults to `track/data` if omitted.
- `g`, `p`, `s` — `base64url(JSON.stringify(...))`. See Batch HTTP format above.

**Success (200):**
```json
{
  "chunks": [
    {
      "cid":        "bafy...",
      "iv":         "<base64 12 bytes>",
      "ciphertext": "<base64>",
      "tag":        "<base64 16 bytes>",
      "proof":      [{ "hex": "...", "side": "left" }, ...]
    },
    null
  ]
}
```

`null` entries mean the chunk is unavailable (no Drop has it). This is **not**
a 403 — it is a transient storage gap. Cloud retries or tries another Jet.

`proof` is a Merkle inclusion proof for each chunk against `manifest.rootCid`.
Cloud verifies each proof before decrypting.

---

### GET /Safecloud/cloud/chunk/{cid} — single-chunk x402 fetch

For external clients only (wget, AI agents, CDN origin pulls). Supports HTTP
`Range:` header for Safari `<video>` and CDN range requests.

```
GET /Safecloud/cloud/chunk/bafy...
Range: bytes=0-16383     (optional)
PAYMENT-SIGNATURE: <base64(JSON OCP Role B envelope)>   (required; else 402)
```

**Success (200 or 206):**
```
Content-Type: application/octet-stream
Cache-Control: public, max-age=31536000, immutable
PAYMENT-RESPONSE: <base64(SettlementResponse)>
Content-Range: bytes 0-16383/262160    (if Range: was sent)

<raw ciphertext bytes>
```

---

### socket.io equivalents

The socket.io events `Safecloud/subtree/put` and `Safecloud/subtree/get` carry the same
payload shapes as the HTTP endpoints and return results via ack callbacks.
See Jets.md Part 3 for the full socket event list. The key differences:

- Socket.io clients omit the `PAYMENT-SIGNATURE` header and instead include
  OCP payment tokens in the `payments[]` array of the event payload.
- Responses are delivered via ack: `ack(null, result)` or
  `ack({ error: { code, message, details } })`.
- There is no URL size limit; all parameters travel in the JSON payload.

---

## Edge 2 — Jets ↔ Jets (HTTP via Jets.Router / hyperswarm)

### Topology

```
  Jet A (Node.js)
      │
      ├── hyperswarm DHT  (peer discovery; topic = SHA-256("safecloud-jets"))
      └── HTTPS           (relay requests between Jet peers)
      │
  Jet B (Node.js)
```

Jet-to-Jet communication is managed by `Jets.Router` (see Jets.Router.md).
The default implementation uses **hyperswarm** for peer discovery. Full
specification is in `Jets.Router.md`; this section documents the relay
HTTP protocol only.

---

### Peer discovery via hyperswarm

Jets use hyperswarm v3 (`holepunchto/hyperswarm`) for peer discovery:

```js
const Hyperswarm = require('hyperswarm');
const crypto     = require('crypto');

const swarm = new Hyperswarm({ keyPair: jetKeypair });
const topic = crypto.createHash('sha256').update('safecloud-jets').digest();

// Jets announce as servers and look up peers as clients
const discovery = swarm.join(topic, { server: true, client: true });
await discovery.flushed();   // wait for DHT announce to propagate

swarm.on('connection', (conn, info) => {
    // conn is a Noise-encrypted duplex stream
    // info.publicKey is the peer's keypair public key
    // register peer Jet URL via HTTP handshake over conn
});
```

Each Jet announces its HTTPS URL and identity to newly connected peers via the
first message over the Noise-encrypted hyperswarm connection:
```json
{
  "type":       "safecloud.jet.hello",
  "url":        "https://jet.example.com",
  "version":    1,
  "evmAddress": "0x<Jet BSC address>",
  "delegation": { <OCP safecloud:session-delegation claim signed by Jet wallet> }
}
```

The receiving Jet verifies the delegation claim: the wallet signature is valid,
`stm.exp` has not passed, and `iss` matches the stated `evmAddress`. All
subsequent OCP claims from this Jet (routing announcements, availability events,
CoC gossip) are signed with the delegated session keys and are verifiable back
to `evmAddress` via this claim.

Jets are Node.js processes — they do not face the browser key-management
problem that Drops do. A Jet's wallet key may be loaded from an environment
variable or secrets manager at startup. The delegation ceremony is run once at
startup and the session keypair is held in process memory for the session
lifetime.

After the handshake, Jets relay HTTP requests directly over HTTPS — the
hyperswarm connection is used only for peer discovery, CoC gossip, and
availability event subscriptions, not data transfer.

---

### Relay request: GET /Safecloud/cloud/relay/{rootCid}

When Jet A cannot find local Drops for a rootCid range, it queries peer Jets
via `Jets.Router.relayGet()`, which sends:

```
GET /Safecloud/cloud/relay/bafy...?link=track/data/0/1&g=<grants_b64url>&p=<payments_b64url>
Authorization: Bearer <jet-to-jet-auth-token>
```

The `Authorization` token is a short-lived credential derived from the mutual
hyperswarm Noise session key established during peer discovery. The exact
derivation (HMAC input, TTL, rotation) is specified in `Jets.Router.md`.
The relay endpoint is not accessible without a valid token — it is not part
of the public API.

**Success (200):** Same response shape as `GET /Safecloud/cloud/subtree` above.

**If the peer Jet also has no coverage (404):** Jet A tries the next peer in
the routing table. After all peers are exhausted, the chunk slot is returned
as `null` to the original Cloud client.

---

## Edge 3 — Jets ↔ Ethereum Provider RPC

### Topology

```
  Jet (Node.js)
      │
      └── HTTPS JSON-RPC
      │
  EVM Provider  (e.g. BSC RPC, configured per chain)
```

This edge is read-only. Jets never submit transactions. They only pre-screen
payer balances to reject obviously invalid payment tokens before accepting
requests.

---

### Balance check (pre-screen only)

```js
// Config: Q.Config.get(['Safe', 'evm', 'provider', chainId], defaultRpcUrl)
// chainId: CAIP-2 string, e.g. 'eip155:56'

const provider = new ethers.JsonRpcProvider(rpcUrl);

// ERC-20 balance (token != address(0)):
const ERC20_ABI = ['function balanceOf(address) view returns (uint256)'];
const contract  = new ethers.Contract(tokenAddress, ERC20_ABI, provider);
const balance   = await contract.balanceOf(payerAddress);  // BigInt

// Native coin balance (token == address(0)):
const balance = await provider.getBalance(payerAddress);   // BigInt
```

Results are cached in memory per `(chainId, payer, token)` tuple.
Cache TTL: `Q.Config.get(['Safe', 'evm', 'balanceCacheTtlMs'], 3600000)` (1 hour default).

The 1-hour cache is intentional: balance checks are a pre-screen, not the
definitive gate (on-chain execution is). Short-lived token holders top up
rarely; a 1-hour window avoids hammering the RPC provider for every micropayment
request while still catching revoked allowances within a reasonable window.

If the payer's balance is less than the per-request cost (configured at
`Q.Config.get(['Safe', 'pricing', 'perChunkWei'], '1000')` multiplied by the
number of requested chunks): return 402 immediately without forwarding to Drops.
When `stm.max` on the payment token is `"0"` (unlimited claim ceiling), the
balance check still applies — the Jet checks whether the balance covers the
immediate request cost, not the ceiling. This pre-screen is not authoritative —
on-chain execution (handled by the Assets plugin) performs the definitive check.

**On-chain execution is NOT performed by Jets.** Jets forward accumulated
payment tokens to PHP via `POST /Q/node { 'Q/method': 'Safecloud/payment/collect' }`,
and PHP delegates to the Assets plugin which calls
`OpenClaiming.paymentsExecute()` at the address configured in
`Users.web3.contracts["Safecloud/openclaiming"]`.

---

## Edge 4 — Jets ↔ Drops (socket.io, browser-hosted)

### Topology

```
  Drop (browser tab, Q.Safecloud.Drops)
      │
      └── socket.io /Safecloud/  (Drop connects outbound to Jet)
      │
  Jet (Node.js, classes/Safecloud/Jets.js)
```

Drops connect outbound to the Jet using the standard `Q.Socket.connect('/Safecloud/',
url)` mechanism. The Jet does NOT connect to Drops — it pushes requests to
already-connected Drop sockets. Drops may be anonymous (`userId === null`).

All payloads on this edge are JSON. Binary ciphertext is base64-encoded for
socket.io transport.

---

### Drop handshake and stake registration

When a Drop connects to a Jet, it performs a structured handshake that
establishes its identity, inventory, and stake before the Jet will route any
requests to it.

**Canonical identity:** Every participant in the Safecloud network — both Jets
and Drops — has a canonical EVM address on BNB Chain (BSC, `chainId = eip155:56`).
This address is the basis for stake accounting, Safebux earnings, and Proof of
Corruption slashing. A Drop derives its EVM address from its wallet and
registers it during the handshake via the session delegation claim.

**Identity via `Q.Crypto.delegate`:** Every connecting Drop must include a
valid `safecloud:session-delegation` OCP claim in its registration. This claim
was produced by one interactive wallet signature during the Drop's session
startup (see Connection Authentication in Shared Conventions). It binds both an
ES256 session key (for challenge responses and Prolly diffs) and an EIP-712
session key (for payment tokens and routing announcements) to the Drop's
canonical wallet address. The Jet verifies the delegation claim on registration
and rejects any Drop whose claim is missing, expired, or has an invalid wallet
signature.

**Handshake sequence:**

```
Drop                              Jet
 │                                 │
 │── Safecloud/drop/register ──────────▶│  (EVM address, P-256 key, storage offer)
 │◀── ack { cold, minStake } ──────│  (Jet tells Drop if it needs to sync inventory)
 │                                 │
 │── Safecloud/drop/announce ──────────▶│  (Bloom filter if cold, or Prolly root if warm)
 │◀── ack ────────────────────────│
 │                                 │
 │  [Jet may issue spot challenges]│
 │◀── Safecloud/drop/challenge ─────────│  (verify Drop actually has claimed chunks)
 │── ack { proof } ───────────────▶│
 │                                 │
 │  [Jet now routes requests here] │
```

After the handshake, the Jet:
1. Records the Drop's EVM address and current Safebux stake (queried from chain)
2. Builds or reconciles its Prolly tree view of the Drop's inventory
3. Begins issuing `Safecloud/drop/get` and `Safecloud/drop/put` requests to this Drop
4. Constructs OCP Role B payment tokens addressed to `[dropEVMAddress]` when
   forwarding retrieval requests

**Stake check at registration:** The Jet queries the BSC chain for the Drop's
Safebux balance (`safebux.balanceOf(dropEVMAddress)`). Drops with zero or
negligible stake receive lower routing priority. A minimum stake threshold is
configurable: `Q.Config.get(['Safe', 'drop', 'minStakeSafebux'], '0')`. Drops
below threshold may still connect and accumulate stake before being routed to
at full capacity.

---

### Drop lifecycle events

**Register (Drop → Jet):**
```js
// event: 'Safecloud/drop/register'
{
  "dropId":     "drop-<Q.clientId()>",   // sessionStorage-stable
  "clientId":   "<Q.clientId()>",
  "evmAddress": "0x<BSC wallet address>", // canonical identity
  "delegation": {                         // OCP safecloud:session-delegation claim
    "ocp": 1,
    "iss": "data:key/eip712,0x<wallet>",
    "sub": "safecloud:session-delegation",
    "stm": {
      "sessionKeyES256":  "<base64 P-256 SPKI>",
      "sessionKeyEIP712": "0x<secp256k1 session address>",
      "exp": 1702684800
    },
    "key": ["data:key/eip712,0x<wallet>"],
    "sig": ["<wallet EIP-712 sig>"]
  },
  // Jet verifies: delegation.iss matches evmAddress, exp not passed,
  // wallet sig valid. Session keys in stm are then trusted for this Drop.
  "storage":    { "GB": 10 },
  "prollyRoot": "<hex>|null",
  "bloomFilter": "<base64>|null"
}
// ack: { "dropId": "drop-...", "cold": true|false, "minStake": "<Safebux wei>" }
```

**Announce (Drop → Jet):** Sent after every inventory change — new chunks stored,
chunks evicted, or IndexedDB wiped. Always includes a signed Prolly diff.

```js
// event: 'Safecloud/drop/announce'
{
  "dropId":      "...",
  "storage":     { "GB": 10 },
  "used":        1234567,          // bytes currently occupied
  "prevRoot":    "<hex>|null",     // previous announced root (null on first announce)
  "prollyRoot":  "<hex>|null",     // new root after applying diff
  "diff": [                        // set of changes since prevRoot
    { "cid": "bafy...", "added": true  },
    { "cid": "bafy...", "added": false }   // false = evicted
  ],
  "reason":      "eviction"|"stored"|"reset"|null,
  // "reset" means IndexedDB was wiped; prollyRoot and diff are both null.
  // Any root previously announced is now void.
  "signature":   "<base64 OCP P-256 sig over canonical JSON of this announce>"
}
// ack: null
```

**The Drop's Prolly diff log (stored in IndexedDB):**

Every announce is appended to a durable, append-only log in IndexedDB. Each
entry is:

```js
{
  seq:       Number,         // monotonically increasing sequence number
  timestamp: Number,         // Unix seconds
  prevRoot:  String|null,
  newRoot:   String|null,
  diff:      Array<{ cid: String, added: Boolean }>,
  reason:    String|null,
  signature: String          // P-256 OCP sig over canonical JSON of this entry
}
```

The log grows only on inventory changes, not on every request. A Drop with
100K chunks that evicts 10 CIDs adds one entry with 10 CIDs — the log is O(changes),
not O(data). The log is the forensic record for Proof of Corruption: a Jet
holding a sequence of signed announces and challenge results can construct a
CoC purely from these entries without any external context.

**IndexedDB wipe / reset:** If the Drop's IndexedDB is cleared (browser data
wipe, storage eviction), the Drop MUST immediately send an announce with
`reason: "reset"`, `prollyRoot: null`, `diff: null`. This is an honest signal
that all previous root commitments are void. The Jet treats the Drop as cold
and re-syncs via Bloom filter on the next non-null announce. A reset announce
is not slashable — "I lost everything" is not contradicted by any prior claim.
Failing to send a reset and instead sending a stale root IS slashable (the
subsequent challenge failure will contradict the claimed root).

**Verification:** On receiving an announce, the Jet:
1. Verifies the P-256 signature
2. Verifies `apply(prevRoot, diff) == prollyRoot` (i.e. the diff produces the
   stated root — the Drop cannot lie about what changed)
3. Updates its local Prolly store and routing table accordingly
4. Stores the signed announce entry for potential CoC use

**Protocol requirement:** A Drop MUST send an updated `Safecloud/drop/announce` with
its new Prolly root *before* evicting any chunks. A Drop that evicts chunks
without first re-announcing may have its old Prolly root used as evidence in a
valid CoC (the old root implies a CID the Drop can no longer prove it holds).
Honest Drops running the reference implementation satisfy this automatically.

**Disconnect (Drop → Jet):** Intentional shutdown.
```js
// event: 'Safecloud/drop/disconnect'
{ "dropId": "..." }
// ack: null
```
Clears `dropId` from sessionStorage. Unexpected disconnects are handled by
the Jet's grace-period sweep (default 60s TTL before eviction from `Q.Safecloud.Drops`).

**Claim payments (Drop → Jet):**
```js
// event: 'Safecloud/drop/claimPayments'
{
  "dropId":        "...",
  "paymentTokens": [ <OCP Role B tokens signed by Jet> ],
  "signature":     "<base64 OCP claim signed with Drop secp256k1 keypair>"
}
// ack: { "txHash": "0x...|null" }
```
The Jet signed these tokens with `recipients = [dropEVMAddress]` — the address
the Drop registered during handshake. The Drop passes `recipients = [dropEVMAddress]`
to `paymentsExecute()`, and the contract verifies the hash matches. Jets relay
this to PHP for on-chain execution via the Assets plugin.

---

### Jet → Drop: chunk storage push

```js
// event: 'Safecloud/drop/put'  (server pushes to Drop socket)
{
  "chunks": [
    { "cid": "bafy...", "iv": "<b64 12>", "ciphertext": "<b64>",
      "tag": "<b64 16>", "size": 262144, "tags": [] }
  ],
  "options": {}
}
// ack: { "results": [{ "cid": "bafy...", "stored": true }] }
```

The Drop stores chunks in IndexedDB keyed by CID. On failure (quota exceeded),
the Drop performs LRU eviction, appends an eviction announce entry to its log,
and retries. After successfully storing all chunks, the Drop sends a
`Safecloud/drop/announce` event with the updated `prollyRoot` and `diff` containing
the newly added CIDs. The Jet does not consider a chunk durably stored until it
receives the corresponding signed announce.

---

### Jet → Drop: chunk retrieval pull

```js
// event: 'Safecloud/drop/get'  (server pushes to Drop socket)
{
  "cids":         ["bafy...", "bafy..."],
  "options":      {},
  "paymentToken": { <OCP Role B token signed by Jet, recipients=[dropEVMAddress]> }|null
}
// ack: { "chunks": [{ "cid": "bafy...", "iv": "<b64>", "ciphertext": "<b64>", "tag": "<b64>" }|null] }
```

The `paymentToken` is constructed and signed by the **Jet** (not Cloud) using:
- `stm.payer = jetEVMAddress` — the Jet is paying the Drop from its earned income
- `stm.token = SAFEBUX_ADDRESS` — denominated in Safebux on BSC
- `stm.recipientsHash = keccak256(abi.encode([dropEVMAddress]))` — Drop's address
  as registered during handshake
- `stm.line = 0` — default line, always open

Before serving, the Drop independently verifies the payment token's payer
(Jet) balance via ethers.js against the BSC chain (same 1-hour cache). If the
Jet's Safebux balance is insufficient, the Drop may return `null` or choose to
serve and flag the Jet as a low-trust router.

---

### Jet → Drop: proof-of-storage challenge

Issued periodically by the Jet to verify Drops hold the chunks their latest
signed announce claims. The Jet samples CIDs from the Drop's current Prolly
root using a Poisson-scheduled timer (unpredictable cadence — Drops cannot
anticipate challenges to temporarily re-fetch chunks).

```js
// event: 'Safecloud/drop/challenge'
{ "cid": "bafy...", "nonce": "<hex random 32 bytes>" }

// ack — signed OCP claim (the signature is the CoC evidence if forged):
{
  "ocp": 1,
  "iss": "data:key/es256;base64,<Drop-P256-SPKI>",
  "sub": "safecloud:challenge-response",
  "stm": {
    "cid":       "bafy...",
    "nonce":     "<hex>",
    "prevRoot":  "<hex>",   // the Drop's current Prolly root at time of response
    "proof":     "<hex keccak256(cid ‖ nonce ‖ chunk_first_32_bytes)>"
    // Binding the first 32 bytes of actual chunk data proves possession
    // without sending the full chunk. Jet independently verifies against
    // its cached copy of the ciphertext or by spot-fetching.
  },
  "key": ["data:key/es256;base64,<Drop-P256-SPKI>"],
  "sig": ["<base64 P-256 r‖s>"]
}
```

The `prevRoot` field in the response is critical: it commits the Drop to a
specific Prolly root at the time of the challenge. Combined with the Drop's
signed announce log, this creates a chain of accountability.

**How the Prolly log makes challenges into CoC evidence:**

A well-formed CoC requires only two signed entries from the Drop's own history:

```
evidence[0]: announce { prevRoot: R1, newRoot: R2, diff: [] }
             // Drop signed: "I have exactly what R2 says I have, nothing changed"

evidence[1]: challenge-response { prevRoot: R2, cid: X, proof: <FAIL or absent> }
             // Drop signed: "my root is R2" but couldn't prove possession of X

```

If `X` is reachable from `R2` (verifiable by any node with the Prolly tree),
these two signed claims contradict each other without any external context.
The announce says X is present (R2 includes it, diff: [] means no eviction).
The challenge failure proves X is absent. Both are signed by the Drop's P-256
key. The contradiction is decidable from the evidence alone.

On challenge failure (timeout, missing proof, or invalid proof): the Jet stores
the failed challenge response alongside the most recent signed announce, forming
a candidate CoC, and notifies PHP via `POST /Q/node { 'Q/method': 'Safecloud/drop/slash' }`.

---

### Jet → Drop: slash notification

```js
// event: 'Safecloud/drop/slashed'   (no ack)
{ "reason": "Challenge failed: proof invalid" }
```

The Drop receives this after PHP confirms on-chain slashing. Drop behavior
on receipt is implementation-defined (typically: display warning, cease
offering storage).

---

## Edge 5 — Drops ↔ Ethereum / OpenClaiming contract

### Topology

```
  Drop (browser tab)
      │
      ├── ethers.js (browser)
      └── HTTPS JSON-RPC
      │
  EVM Provider  (same config as Jet: Safecloud/evm/provider/<chainId>)
      │
  OpenClaiming contract  (address from Users.web3.contracts config)
```

Drops interact with the EVM provider directly from the browser using
`ethers.js`. Two distinct interactions occur: balance verification (read-only,
same as Jets) and payment claim execution (write, triggered by Drop).

---

### Balance verification

Drops verify the Jet's Safebux balance on BSC before serving chunks in response
to `Safecloud/drop/get`. The payment token's `stm.payer` is the Jet's EVM address.

```js
// Browser ethers.js (CDN import or bundled):
// chainId for Safebux is always BSC: 'eip155:56'
const provider = new ethers.JsonRpcProvider(
    Q.Config.get(['Safe', 'evm', 'provider', 'eip155:56'], BSC_RPC_URL)
);
const contract = new ethers.Contract(SAFEBUX_ADDRESS, ERC20_ABI, provider);
const balance  = await contract.balanceOf(jetEVMAddress);
// Cache for 1 hour per (jetEVMAddress) — same TTL as Jet-side checks
```

A compromised Jet cannot bypass this check — the Drop independently reads
from BSC.

---

### Payment claim execution

**Accumulation lifecycle:** As the Drop serves chunks, it accumulates OCP Role B
payment tokens from the Jet (one token per `Safecloud/drop/get` session). Tokens are
stored in IndexedDB. When the accumulated unredeemed value exceeds
`Q.Config.get(['Safe', 'drop', 'claimThresholdSafebux'], '100000')`, or on user
request, the Drop initiates a claim.

**On-chain execution** (direct path, Drop has BNB for gas):

```js
// The Jet signed the token with recipients = [dropEVMAddress]
const recipients = [dropEVMAddress];

const signer   = new ethers.Wallet(dropSecp256k1PrivateKey, provider);
const contract = new ethers.Contract(
    OC_ADDRESS, // from Users.web3.contracts["Safecloud/openclaiming"]
    OC_ABI,
    signer
);

for (const token of accumulatedTokens) {
    await contract.paymentsExecute(
        {                               // Payment struct (Jet is payer)
            payer:          token.stm.payer,          // jetEVMAddress
            token:          token.stm.token,           // SAFEBUX_ADDRESS
            recipientsHash: token.stm.recipientsHash,  // keccak256([dropEVMAddress])
            max:            BigInt(token.stm.max),
            line:           BigInt(token.stm.line),    // 0 = DEFAULT_LINE
            nbf:            BigInt(token.stm.nbf),
            exp:            BigInt(token.stm.exp)
        },
        recipients,                     // [dropEVMAddress]
        ethers.getBytes(               // Jet's EIP-712 signature (from token.sig[0])
            Buffer.from(token.sig[0], 'base64')
        ),
        dropEVMAddress,                 // recipient = this Drop
        perChunkAmount,                 // chunks served × perChunkSafebux
        ethers.ZeroAddress             // direct ERC-20 transferFrom
    );
}
```

**Alternative path (relay via Jet, no gas needed):**
```js
// event: 'Safecloud/drop/claimPayments'
{
  "dropId":        "drop-...",
  "paymentTokens": accumulatedTokens,   // OCP Role B envelopes signed by Jet
  "signature":     "<base64 OCP claim signed with Drop secp256k1 keypair>"
}
```
The Jet forwards to PHP (`POST /Q/node { 'Q/method': 'Safecloud/payment/collect' }`),
which calls `paymentsExecute(payment, [dropEVMAddress], sig, dropEVMAddress, amount, address(0))`
via the Assets plugin. This path requires the Jet/PHP to cover BSC gas.

The Drop maintains two keypairs in IndexedDB:
- **P-256 (ES256):** For OCP Role A grant verification and proof-of-storage
  challenge signing. `publicKey` (SPKI) sent in `Safecloud/drop/register`.
- **secp256k1:** For on-chain transactions. EVM address derived as
  `last 20 bytes of keccak256(pubkey[1:])`. Sent as `evmAddress` in
  `Safecloud/drop/register`. This IS the Drop's canonical BSC address and is known
  to the Jet from the start — there is no reveal step.

---

## Safebux economics

### Zero-sum payment flows

Safecloud uses a two-layer zero-sum economy denominated in Safebux (an ERC-20
token on BNB Chain / BSC, `chainId = eip155:56`):

```
  Cloud client
      │  pays Jet in Safebux
      │  (OCP Role B, payer=cloudEVMAddress, recipients=[jetEVMAddress])
      ▼
  Jet
      │  pays Drop in Safebux
      │  (OCP Role B, payer=jetEVMAddress, recipients=[dropEVMAddress])
      ▼
  Drop
```

Cloud pays Jets for routing and retrieval. Jets pay Drops for storage and
serving. The Jet's income minus its Drop payments is its operating margin.
Neither Cloud nor Drops are aware of the other's existence in the payment
layer — Cloud only knows Jets, Drops only know Jets.

Jets must pre-approve the OpenClaiming contract to spend Safebux on their
behalf (`SAFEBUX.approve(OC_ADDRESS, allowance)`). No prior `lineOpen()` call
is required for the default line (`line = 0`) — it is always open by protocol.
Jets that want budget isolation (e.g. separate accounting per downstream Jet or
Drop pool) may open explicit lines (`line >= 1`) via `lineOpen(jetEVMAddress,
lineId, maxWei)`. Jets that run out of Safebux balance or allowance cannot pay
Drops and will lose Drop connectivity.

### Stake and graduated lockup

Claimed Safebux on-chain represents the actor's **stake** in the network. Stake
is the basis for routing priority (Jets prefer high-stake Drops) and is the
asset at risk in a Proof of Corruption slash.

**Graduated lockup:** Safebux is subject to a percentage-based vesting schedule
after claiming. For example, at 10%/day release rate:
- Day 0: 10% of claimed balance is immediately spendable
- Day 1: another 10% unlocks
- …
- Day 9: last tranche unlocks; full balance accessible

This prevents earn-and-run attacks: a malicious actor who earns Safebux and
then tries to transfer it all cannot fully drain their stake for approximately
the lockup period. The remaining locked balance is always slashable.

Transferring Safebux to another address does not reset the lockup — locked
tokens cannot be transferred. Only unlocked tokens are liquid. Therefore
long-standing participants always retain a residual locked stake proportional
to their recent earnings.

The exact lockup parameters (percentage per period, period length) are encoded
in the Safebux token contract on BSC and apply to all participants equally.

### Routing priority and stake

Jets use Safebux stake as one signal for Drop selection:

```js
// Jets.Router weight for a Drop:
weight = stakedSafebux * reliabilityScore * availableStorage
```

New Drops with zero stake start at low priority and gain priority as they
accumulate stake through honest service. This creates a natural Sybil cost:
spinning up many low-stake Drops provides little routing advantage, while a
single high-stake Drop earns more.

---

## Proof of Corruption

A Proof of Corruption (CoC) is a signed OCP claim asserting that a specific
network participant made two or more self-contradictory signed statements.
The CoC is the primary accountability mechanism in the Safecloud network.

### CoC wire format

A CoC is itself an OCP claim envelope:

```json
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<claimant-EVM-address>",
  "sub": "safecloud:corruption",
  "stm": {
    "subject":   "data:key/es256;base64,<corrupt-actor-P256-SPKI>",
    "subjectEVM":"0x<corrupt-actor-EVM-address>",
    "evidence":  [
      { <OCP claim 1, signed by subject> },
      { <OCP claim 2, signed by subject> }
    ],
    "reason":    "Challenge responses for same (cid, nonce) pair contradict each other"
  },
  "key": ["data:key/eip712,0x<claimant-EVM-address>"],
  "sig": ["<base64 65-byte EIP-712 r‖s‖v from claimant>"]
}
```

Fields:
- `stm.subject` — the OCP key URI of the accused (their P-256 signing key)
- `stm.subjectEVM` — the accused's canonical BSC address (for on-chain slashing)
- `stm.evidence` — array of two or more complete OCP claims, all signed by
  `stm.subject`, that are unambiguously mutually contradictory
- `stm.reason` — human-readable description of the contradiction

The claimant must sign the CoC with their own EVM key (`iss` = their address).
This binds the claimant's stake to the claim — if the CoC is adjudicated as
frivolous, the claimant is penalised.

### Decidability rule

A valid CoC must be **self-contained and decidable without external context.**
The evidence claims must contain sufficient information that any honest node,
running the same validation code, can determine the contradiction purely from
reading the evidence array.

Examples of valid contradictions:
- Two challenge responses for the same `(cid, nonce)` pair that produce
  different `proof` values
- A Drop's `Safecloud/drop/announce` claiming it has a certain Prolly root, and a
  subsequent challenge response proving it lacks a chunk that root implies

Examples of invalid CoCs (would result in claimant being penalised):
- Evidence that requires external state to interpret (e.g., "this chunk is
  wrong because the correct version is on some other server")
- Timing-based arguments without timestamped signed claims
- A single claim presented as contradictory with an assertion not signed by
  the subject

The protocol does not technically enforce decidability on-chain — it is enforced
by honest nodes refusing to forward or act on undecidable CoCs. The claimant
bears the risk: if their CoC is not clearly decidable, honest nodes will
classify it as frivolous and the claimant loses stake.

### Gossip and slash mechanics

**Gossip:** CoCs are broadcast between Jets over hyperswarm Noise connections
(not over the `/Safecloud/` socket.io namespace). Each Jet maintains a local CoC
store and forwards new CoCs to peer Jets. A CoC is accepted for gossip only if:
1. The claimant's Safebux stake is above the minimum threshold
   (`Q.Config.get(['Safe', 'coc', 'minClaimantStake'], '1000')`)
2. The evidence claims are all validly signed by the stated subject key
3. The CoC itself is validly signed by the claimant

Jets that receive a CoC run the decidability check locally. If it passes, they
add the subject's OCP key to their local "corrupt actors" list and deprioritize
or disconnect that actor.

**Slash on claim:** When a corrupt actor attempts to claim Safebux on-chain
by calling `paymentsExecute()`, the transaction is observable by all. If any
honest participant has a valid CoC for that actor's key, they may call the
on-chain slash function with the CoC evidence before the corrupt actor can
spend their claimed tokens.

The slash mechanism works because:
1. The corrupt actor registered their EVM address at handshake time
2. Their P-256 OCP key is bound to that address (registered on-chain or gossiped)
3. The CoC evidence contains self-signed contradictory claims by that key
4. Any observer can verify the contradiction and execute the slash

**Claimant stake at risk:** Filing a CoC consumes a small amount of claimant
stake as a spam-prevention deposit. If the CoC is deemed valid by the network
(honest nodes converge on the same verdict), the deposit is returned and the
subject is slashed. If the CoC is deemed frivolous (honest nodes running the
same code reject it), the claimant loses their deposit. The deposit size is
`Q.Config.get(['Safe', 'coc', 'depositStake'], '100')` Safebux.

---

## Attack vectors

This section catalogs known attack vectors in the Safecloud protocol, the harm
each can cause, and the protocol properties that limit or prevent them.

---

### MITM relay: MalloryJet between Jet1 and Drop2

```
Jet1 ──── MalloryDrop ──── MalloryJet ──── Drop2
```

Mallory operates a Drop connected to Jet1 and a separate Jet connected to
Drop2, relaying traffic between them in both directions.

**What Mallory can do:**

- **Economic theft.** Jet1 issues payment tokens addressed to MalloryDrop.
  MalloryJet issues its own (potentially zero or underpriced) tokens to Drop2.
  Drop2 does the work; Mallory extracts the margin. This is parasitic routing:
  Mallory adds latency and takes income without contributing storage.

- **Inventory surveillance.** By triggering a cold-sync ack, MalloryJet can
  induce Drop2 to send a full Bloom filter, revealing Drop2's complete stored
  inventory. This is an information leak, not a stake threat.

- **Latency inflation.** Adding a relay hop degrades Jet1's perceived response
  time for Drop2. Jets tracking `reliabilityScore` will eventually deprioritize
  MalloryDrop based on observed latency, providing organic mitigation.

**What Mallory cannot do:**

- **Impersonate Drop2 to Jet1.** MalloryDrop's `Safecloud/drop/register` must
  include a delegation claim signed by its own wallet private key. It cannot
  present `evmAddress = Drop2` without Drop2's wallet key — the EIP-712
  wallet signature in the delegation claim would fail verification.

- **Get Drop2's stake slashed.** This is analyzed in detail below.

**Mitigation:** DHT-based direct routing (Jets.Router) reduces relay
opportunities by allowing Jet1 to discover and connect to Drop2 directly.
Latency-based routing priority further discourages relay hops.

---

### Can MalloryJet get an honest Drop2 slashed?

This is the critical question. We walk through every message MalloryJet can
send to Drop2 and examine whether honest Drop2 responses could constitute a
CoC-worthy contradiction.

**Challenge-response (`Safecloud/drop/challenge`):**

MalloryJet sends `{ cid, nonce }`. Drop2 signs `keccak256(cid ‖ nonce)` with
its P-256 OCP key. The proof is a **deterministic pure function** of the input.
Given the same `(cid, nonce)`, Drop2 always produces the same proof.

For a CoC, Mallory would need two different proofs from Drop2 for the *same*
`(cid, nonce)`. This is impossible for an honest deterministic implementation.
Mallory can send the same pair to Drop2 a thousand times and get the same proof
every time — no contradiction.

MalloryJet could also challenge Drop2 for a CID Drop2 never stored. Drop2
responds with null/not-found. This is also not a contradiction — Drop2 never
claimed to hold that CID (as long as its Prolly root doesn't imply it).

**Verdict: challenge-response cannot be weaponized against an honest Drop.**

**Chunk push (`Safecloud/drop/put`) with garbage data:**

MalloryJet sends chunks with invalid ciphertext, wrong CIDs, or arbitrary
garbage. Drop2 stores them honestly and includes them in its Prolly root.

A later challenge for those CIDs will get a valid proof response — Drop2 has
the data. The proof only asserts possession, not data validity. Drop2 cannot
be slashed for honestly storing data it was given.

**Verdict: garbage chunk injection causes no CoC risk to Drop2.**

**Storage flooding to provoke LRU eviction — the one real vulnerability:**

MalloryJet fills Drop2's storage quota with garbage chunks. Drop2's LRU evicts
previously held legitimate chunks. Drop2's Prolly root previously announced to
the network implied those now-evicted CIDs were present. If Drop2 fails a
subsequent challenge for an evicted CID, the evidence looks like:

1. Drop2 signed `Safecloud/drop/announce` with Prolly root X (implying CID Y)
2. Drop2 failed challenge for CID Y

This is a *structurally valid* CoC — an honest node running the protocol would
see a contradiction between the announced inventory and the challenge failure.

However, this is a protocol artifact, not dishonesty: Drop2 held the chunk,
announced it honestly, and later evicted it under legitimate storage pressure
induced by Mallory.

**Mitigation (protocol requirement):** A Drop MUST send an updated
`Safecloud/drop/announce` with its new Prolly root *before* evicting any chunks.
This ensures the signed inventory commitment is always current. CoC validation
MUST require that the announce and the failed challenge are temporally
consistent — an announce that predates a storage-flood attack is not valid
evidence against a Drop that later updated its announce.

Additionally, the CoC decidability rule (self-contained, no external context)
makes timing-based attacks harder: a CoC built on an old announce and a recent
challenge failure would need to include the timestamps of both signed claims.
If the announce was updated between the two events, the CoC is invalid.

**Verdict: exploitable only if Drop2 evicts without re-announcing, or if CoC
validation does not require temporal consistency. Both are addressed by the
announce-before-evict requirement and the decidability rule.**

**False `Safecloud/drop/announce` ack:**

MalloryJet sends a false ack to Drop2's announce — for example, claiming
`cold: true` when the Jet has valid Prolly state, to force Drop2 to re-send
its Bloom filter. Drop2 sends more data than necessary. **Harm:** information
leak only. Drop2 signs nothing additional; no contradiction is possible.

**Verdict: no CoC risk. Information leak only (inventory disclosure).**

**Summary: an honest Drop2 cannot be slashed by MalloryJet, with one caveat**

| Attack | CoC risk to Drop2 | Mitigated by |
|--------|-------------------|--------------|
| Relay all traffic (MITM) | None | Delegation claim prevents identity theft |
| Repeated same challenge | None | Deterministic proof function |
| Challenge for missing CID | None | Not-found is not a contradiction |
| Garbage chunk injection | None | Proof-of-possession, not validity |
| Storage flood → LRU eviction | **Yes, if no re-announce** | Announce-before-evict requirement |
| False ack on announce | None (info leak only) | No signing required from Drop |

The single exploitable vector — storage flooding to force LRU eviction before
re-announcement — is closed by the protocol requirement that Drops MUST
re-announce before evicting. This requirement is enforced by honest Drops
running the reference implementation; a Drop that violates it exposes itself
to a valid (non-malicious) CoC.

---

### Fake CoC against a legitimate participant

Mallory files a CoC against Drop2 with fabricated evidence — either forged
signatures or cherry-picked real claims that do not actually contradict.

- **Forged signatures:** Cannot be created without Drop2's P-256 private key.
  Any honest node verifying the evidence will reject it, and Mallory loses
  her deposit.

- **Non-contradictory evidence:** The decidability rule requires the
  contradiction to be self-evident from the evidence alone. If honest nodes
  running the same code do not find a contradiction, the CoC is frivolous and
  Mallory is penalised.

The deposit requirement (`minClaimantStake`) means Mallory cannot spam CoCs
at zero cost. Each failed CoC costs her stake.

---

### Sybil routing attack (many low-stake Drops)

Mallory registers many Drops with zero or minimal stake, all routing through
a single MalloryJet. She aims to capture a large fraction of Jet1's routing
decisions.

**Mitigation:** Routing weight is `stakedSafebux × reliabilityScore ×
availableStorage`. Zero-stake Drops receive near-zero routing weight. To
capture significant routing share, Mallory must stake real Safebux across all
her Drops, which costs her proportionally and provides slashable collateral.

---

### Payment withholding by a malicious Jet

MalloryJet routes retrieval requests to Drop2 but issues payment tokens with
`stm.max = 0` (zero ceiling) or with a payer address that has zero Safebux
balance.

**Drop2's defense:** Before serving, Drop2 independently checks MalloryJet's
Safebux balance on BSC. If the balance is insufficient for the request cost,
Drop2 returns null or disconnects. Drop2 is never obligated to serve without
payment — it simply stops serving Mallory's Jet and the routing weight for that
Jet drops as its reliability score falls.

This is economic harm (Drop2 earns less) but not stake harm. Drop2 does not
sign anything that could be used against it.

---



**Safe plugin depends on Streams and Assets:**
The Jet server (`classes/Safecloud/Jets.js`) requires the Streams plugin for access
checks when `publisherId`/`streamName` are present in requests: `WRITE_LEVEL.post`
(20) for chunk uploads, `READ_LEVEL.content` (23) for chunk downloads. On-chain
payment execution is delegated to the Assets plugin (`Q.Assets.OpenClaim`) rather
than performed inline by Jets. These are implementation details of the Qbix/Q
framework integration and do not affect the wire protocol documented above.

**OCP is the only authorization mechanism across all edges.**
There is no session cookie, no API key, and no bearer token other than OCP
claims for content access. The Q auth capability token (`client.capability`)
is used only for the socket.io connection handshake (identifying which Q user
is connected, if any) and does not substitute for OCP Role A grants.

**Drops have a known canonical identity.**
Every Drop registers its BSC EVM address during the handshake. There is no
anonymity for registered Drops — the address is revealed upfront and is used
for payment routing, stake accounting, and CoC slashing. Session anonymity
(the Jet does not know which browser user owns a Drop) is preserved, but the
Drop's economic identity is fully public within the network.

**Safebux is on BNB Chain (BSC, eip155:56).** This chain is the default for
all participants. The Safebux ERC-20 address and the OpenClaiming address are
set in config (`Safecloud.safebux.address` and
`Users.web3.contracts["Safecloud/openclaiming"]`) after deployment.

**Jets.Router.md** covers the full specification for Jet-to-Jet discovery,
routing, and relay — including Kademlia XOR distance metrics, hyperswarm
integration details, the `Jets.Router` pluggable interface, and the CoC gossip
wire protocol between Jets.
