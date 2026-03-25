# Q.Safe.Jets — Implementation Design Document

## Table of Contents

- [Part 1 — Key Design Decisions](#part-1--key-design-decisions)
  - [1.1 Responsibilities: Jets client vs Jets server vs Cloud vs Drops](#11-responsibilities-jets-client-vs-jets-server-vs-cloud-vs-drops)
  - [1.2 Dual transport: socket.io AND HTTP](#12-dual-transport-socketio-and-http)
  - [1.3 HTTP response codes: 402, 403, and batch authorization](#13-http-response-codes-402-403-and-batch-authorization)
  - [1.4 OCP: two distinct roles — access grants and micropayments](#14-ocp-two-distinct-roles--access-grants-and-micropayments)
  - [1.5 Payment verification — ethers.js + RPC + Assets plugin delegation](#15-payment-verification--ethersjs--rpc--assets-plugin-delegation)
  - [1.6 Anonymous Drops — identity without Users accounts](#16-anonymous-drops--identity-without-users-accounts)
  - [1.7 Streams-based access control for Cloud users](#17-streams-based-access-control-for-cloud-users)
  - [1.8 The subtree interface — Jets.put / Jets.get](#18-the-subtree-interface--jetsput--jetsget)
  - [1.9 Prolly tree reconciliation](#19-prolly-tree-reconciliation)
  - [1.10 Bloom filter cold handshake](#110-bloom-filter-cold-handshake)
  - [1.11 Proof-of-storage challenges](#111-proof-of-storage-challenges)
  - [1.12 Drop micropayments and SafeBux claims](#112-drop-micropayments-and-safebux-claims)
  - [1.13 Jets.Router — pluggable Drop and Jet discovery](#113-jetsrouter--pluggable-drop-and-jet-discovery)
- [Part 2 — External interfaces called by Jets](#part-2--external-interfaces-called-by-jets)
  - [From Q.Safe.Cloud (client layer above Jets)](#from-qsafecloud-client-layer-above-jets)
  - [From Q.Safe.Drops (storage layer below Jets)](#from-qsafedrops-storage-layer-below-jets)
  - [Platform: Q.Socket.connect](#platform-qsocketconnect)
  - [Platform: ethers.js provider](#platform-ethersjs-provider)
  - [Platform: Q.Data.Prolly](#platform-qdataprolly)
  - [Platform: Q.Data.Bloom](#platform-qdatabloom)
  - [Platform: Q.Data.Merkle.proof](#platform-qdatamerkleproof)
  - [Platform: Q.Utils.validateCapability](#platform-qutilsvalidatecapability)
  - [Platform: Streams access control](#platform-streams-access-control)
  - [Platform: Q.Assets.OpenClaim (delegated, v2)](#platform-qassetopenclaim-delegated-v2)
- [Part 3 — Socket and HTTP event protocol](#part-3--socket-and-http-event-protocol)
  - [Data flow diagram: Cloud, Jets, Drops, OCP](#data-flow-diagram-cloud-jets-drops-ocp)
  - [OCP payload formats: grants vs payments](#ocp-payload-formats-grants-vs-payments)
  - [HTTP batch request format](#http-batch-request-format)
  - [HTTP error response format](#http-error-response-format)
  - [Cloud to Jet (socket.io and HTTP)](#cloud-to-jet-socketio-and-http)
  - [Drop to Jet (socket.io)](#drop-to-jet-socketio)
  - [Jet to Drop (socket.io push)](#jet-to-drop-socketio-push)
  - [PHP to Jet internal (POST /Q/node)](#php-to-jet-internal-post-qnode)
  - [HTTP range request interface](#http-range-request-interface)
  - [x402 payment headers](#x402-payment-headers)
- [Part 4 — Client: web/js/Safe/Jets.js](#part-4--client-webjssafejetsjs)
  - [Internal helpers (implement first)](#internal-helpers-implement-first)
  - [Public methods](#public-methods)
  - [Q.Safe.Jets Events](#qsafejets-events)
  - [Default Drop push handlers](#default-drop-push-handlers)
- [Part 5 — Server: classes/Safe/Jets.js](#part-5--server-classessafejetsjs)
  - [Internal helpers (implement first)](#internal-helpers-implement-first-1)
  - [Public methods](#public-methods-1)
  - [Safe Server Events](#safe-server-events)
- [Part 6 — Implementation Order](#part-6--implementation-order)
- [Part 7 — What is NOT in Jets](#part-7--what-is-not-in-jets)

---

This document is the authoritative spec for:
- `plugins/Safe/web/js/Safe/Jets.js` — browser socket client
- `plugins/Safe/classes/Safe/Jets.js` — Node.js Jet server (replaces `node/Safe.js`)

Read `Cloud.md` first for the Cloud layer that sits above Jets.

---

## Part 1 — Key Design Decisions

### 1.1 Responsibilities: Jets client vs Jets server vs Cloud vs Drops

**Jets client (`web/js/Safe/Jets.js`)** is responsible for:
- Maintaining the `/Safe` socket.io connection to the Jet server
- Exposing `Jets.put(subtree)` and `Jets.get(subtree)` for Cloud to call
- Managing Drop lifecycle: `dropRegister`, `dropAnnounce`, `dropDisconnect`
- Routing incoming Jet->Drop push events to `Q.Safe.Drops`
- Reconnection with exponential backoff + jitter
- Serialising/deserialising ArrayBuffers for socket.io transport (base64)

**Jets server (`classes/Safe/Jets.js`)** is responsible for:
- Accepting both socket.io and HTTP connections from Cloud clients
- Routing `Safe/subtree/put` to Drops via `Safe/drop/put`
- Routing `Safe/subtree/get` from Drops, attaching Merkle proofs, returning to Cloud
- Verifying OCP grants and x402 payment headers before serving any request
- Checking payer ERC-20 balances via ethers.js + RPC (cached N minutes)
- Managing the Drop registry: registration, reconnect, grace-period eviction
- Prolly tree reconciliation per Drop on reconnect
- Bloom filter cold handshake on first contact
- Maintaining the CID routing index (`rootCid -> ordered CID array`)
- Issuing proof-of-storage challenges to Drops
- Receiving PHP->Node internal messages
- Pluggable routing strategy (v1: round-robin; v2: DHT hook)

**Cloud** (`web/js/Safe/Cloud.js`): encrypts/decrypts; calls `Jets.put` and
`Jets.get`. Jets never sees plaintext.

**Drops** (`web/js/Safe/Drops.js`): stores and serves ciphertext in IndexedDB;
responds to Jet push events; maintains Prolly tree and Bloom filter.

---

### 1.2 Dual transport: socket.io AND HTTP

Jets exposes two transports for the same `put`/`get` operations:

**socket.io** (primary for browser Cloud clients and all Drops):
- Persistent connection; best for streaming and real-time prefetch
- Used by `Q.Safe.Cloud` in the browser
- All Drop lifecycle events use socket.io exclusively

**HTTP** (secondary; for compatibility with web proxies, CDNs, and x402):
- `PUT /Safe/subtree` — upload a subtree of chunks
- `GET /Safe/chunk/{cid}` — fetch a single chunk by CID (range-request support)
- `GET /Safe/subtree/{rootCid}/{start}/{end}` — fetch a chunk range
- Standard HTTP 206 Partial Content + `Content-Range` for range requests
- Standard HTTP 402 Payment Required (x402) when no payment header present
- Enables caching by web proxies and CDNs for public/shared content
- Enables wget/curl compatible access

The HTTP interface is served on the same port as socket.io (Express on top of
`Users.Socket.listen()`). Both transports share the same verification, routing,
and response logic — HTTP handlers are thin adapters over the same internal
functions used by socket.io handlers.

---

### 1.3 HTTP response codes: 402, 403, and batch authorization

Jets uses standard HTTP semantics precisely to remain compatible with web
proxies, CDNs, curl, and x402 clients:

**HTTP 402 Payment Required** — payment is missing or malformed. Returned when:
- An HTTP request arrives with no `PAYMENT-SIGNATURE` header (x402 trigger)
- An OCP payment token is present but the payer's ERC-20 balance is insufficient
- An OCP payment token is structurally malformed (bad signature, expired)

The body is a valid x402 v2 `PaymentRequirements` object, and the
`PAYMENT-REQUIRED` header carries its base64 encoding. Any x402-aware client
(Stripe, Cloudflare, AI agent) can parse and retry automatically.

**HTTP 403 Forbidden** — access is denied due to missing or insufficient OCP
authorization grant. Returned when:
- No OCP grants are provided for a subtree request
- The provided grants do not cover the full requested range
- The requester's Streams read level (see section 1.7) is below the required level
- A grant has expired or has an invalid signature

The 403 body is **always a structured JSON object** listing which chunk indices
the requester lacks access to, so the client can re-request in bulk without
the unauthorized items:

```json
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error":       "NotAuthorized",
  "unauthorized": [3, 4, 7, 8, 9],
  "reason":       "Grants do not cover indices [3,4,7,8,9] of range [0,10)"
}
```

The `unauthorized` array contains **absolute chunk indices** within the
requested range. The client can immediately retry with a modified request
that excludes those indices, or acquire additional grants for them.

For socket.io: the same logic applies via the ack callback:
```js
ack({ error: 'NotAuthorized', unauthorized: [3,4,7,8,9], reason: '...' })
```

**HTTP 200 / socket.io ack with partial results** — authorization passes but
some chunks are unavailable (no Drop has them). In this case the response
succeeds with `null` entries for missing chunks — NOT a 403. The client
distinguishes: 403 = access denied (fix your grants), null chunk = retry later.

**HTTP 404** — `rootCid` or `cid` unknown to this Jet (not in `_cidIndex`).
The client should try another Jet.

---

### 1.4 OCP: two distinct roles — access grants and micropayments

OCP is used in two **completely separate** ways in Jets, and they must not be
confused:

**Role A — Access authorization (grants):**
These are `Q.Crypto.delegate` proofs produced by Cloud's `grant()` method.
They prove the requester was given read/write/admin access to a specific chunk
range by the content owner. Jets checks these to decide whether to serve a
request at all. If a grant check fails → **HTTP 403**. This is analogous to
Streams' `readLevel` check but for encrypted chunk ranges.

```js
// grant shape (from Cloud.grant()):
{
  statement: { label: 'safecloud.read.content', context: '{"rootCid":...,"start":0,"end":100}', ... },
  proof:     { signature: String, publicKey: String }
}
```

**Role B — Micropayment tokens:**
These are EIP-712 `Payment` structs signed by the payer (content consumer),
authorizing a transfer of ERC-20 tokens to the Jet/Drop for serving the data.
They prove the requester is paying for the retrieval. If a payment check fails
→ **HTTP 402**. Jets delegates the actual on-chain execution to
`Q.Assets.OpenClaim` (see section 1.5 and Part 2 platform interfaces).

```js
// payment token shape (OCP Payment struct):
{
  payer:          '0x...',
  token:          '0xUSDCAddress',
  recipientsHash: '0x...',   // keccak256(abi.encode([jetAddress]))
  max:            '10000',
  line:           0,
  nbf:            0,
  exp:            0,
  signature:      '0x...'   // EIP-712 signed by payer
}
```

**How they coexist on a single request:**
A `subtree/get` request carries both:
- `grants[]` — proves the requester has access (Role A)
- `payments[]` — proves the requester is paying (Role B)

Jets checks Role A first (fast, no blockchain). If Role A passes but Role B
fails, Jets returns 402. If Role A fails, Jets returns 403. If both pass, Jets
serves the request and forwards the payment token to the serving Drop(s).

**x402 compatibility for external clients:**
External HTTP clients (wget, CDN proxies, AI agents) that don't have OCP grants
can still fetch raw ciphertext chunks by paying via x402. Jets accepts the
standard x402 `PAYMENT-SIGNATURE` header on `GET /Safe/chunk/{cid}` as an
alternative to OCP payment tokens. This path does NOT require a grant — it
uses payment alone. The served content is raw ciphertext; the external client
must independently obtain decryption keys.

---

### 1.5 Payment verification — ethers.js + RPC + Assets plugin delegation

**Phase 1 (balance pre-check, happens in Jets before serving):**

Before serving a request with a payment token, the Jet checks that the payer
holds sufficient ERC-20 balance via ethers.js + RPC. This is a lightweight
pre-screen to reject obviously invalid tokens without a blockchain round-trip:

```js
Q.Config.get(['Safe', 'evm', 'provider', chainId], defaultRpcUrl)
// chainId in CAIP-2 format: 'eip155:8453' (Base), etc.
```

`Safe._checkPayerBalance(payer, token, amount, chainId)`:
1. Check `_balanceCache[chainId][payer][token]`; return if fresh (TTL 5 min)
2. `token === address(0)`: `provider.getBalance(payer)` (native)
3. Otherwise: `contract.balanceOf(payer)` via minimal ERC-20 ABI
4. Cache result. Return `balance >= BigInt(amount)`

Cache TTL: `Q.Config.get(['Safe', 'evm', 'balanceCacheTtlMs'], 300000)`.

**Phase 2 (on-chain execution, delegated to Q.Assets.OpenClaim):**

Jets does NOT call `OpenClaiming.executePayment()` directly. That responsibility
belongs to the Assets plugin. Jets' role is:
1. Validate the payment token's signature and balance pre-check (above)
2. Forward the payment token to PHP via `Q/node` internal message
   `Safe/payment/collect` with the token and serving Drop's public key
3. PHP delegates to the Assets plugin (`Q.Assets.OpenClaim`) which calls
   `OpenClaiming.executePayment(payment, [dropAddress], signature, dropAddress, amount, address(0))`
   on the contract deployed at `0x99996a51cc950d9822D68b83fE1Ad97B32Cd9999`

This delegation means Jets has no Solidity dependencies and Assets plugin
remains the single place where on-chain OCP execution happens across the
whole Q platform.

**Drops also verify independently:** When a Drop receives a `Safe/drop/get`
with a `paymentToken`, it independently checks the payer's balance using the
same config path before serving. This prevents a compromised Jet from
forwarding invalid tokens.

**Balance checks are advisory, not atomic with on-chain execution.** The Jet's
pre-check and the Drop's pre-check are both snapshots — neither is atomic with
`paymentsExecute()`. A payer may pass both checks and then drain their balance
before the claim is submitted. Drops and Jets rely on economic reputation and
repeated interactions to mitigate payment failures: a payer whose claims
consistently fail is excluded from future service. The graduated SafeBux lockup
means payers always have residual slashable stake even if liquid balances are
drained.

---

### 1.6 Anonymous Drops — identity without Users accounts

Drops do not need user accounts. A browser tab connects to `/Safe` without
being logged in; `client.capability.userId` is null for anonymous connections.
The Jet accepts both authenticated and anonymous connections on `/Safe`.

**Drop identity is stable within a session** via `dropId` derived from
`Q.clientId()` (sessionStorage). Same tab + session = same `dropId` across
reconnects.

**Sybil resistance via stake weighting.** Anonymous Drops require no account,
so nothing prevents an attacker from registering many Drop identities. Sybil
mitigation is handled at the `Safe.Router` layer: Drop selection is weighted
by `stakedSafebux × reliability × availableStorage`. Zero-stake Drops receive
near-zero routing weight and earn nothing. Capturing significant routing share
requires proportional SafeBux stake across all Sybil Drops — the attack scales
linearly in cost with the share captured.

**Drop keypair for payments:** On first registration, a P-256 keypair is
generated locally and stored in IndexedDB (not sessionStorage — must survive
restarts). The `publicKey` is sent in `Safe/drop/register`. OCP payment tokens
use `keccak256(abi.encode([publicKey]))` as `recipientsHash`. The Drop reveals
its `publicKey` only at claim time.

---

### 1.7 Streams-based access control for Cloud users

While Drops are anonymous, Cloud users (people requesting content) may have
Q user accounts with Streams-based access levels. Jets uses the `Streams` plugin
access level system to enforce read permissions on content that has been
published to a Streams stream.

**How it works:**

When a user requests content via `Safe/subtree/get`, the request may include
a `streamId` (`publisherId + streamName`) alongside the OCP grants. If present,
Jets checks the requester's Streams read level for that stream:

```js
// Server-side check:
Streams.fetchOne(userId, publisherId, streamName, function(err, stream) {
    stream.testReadLevel('content', function(err, allowed) {
        if (!allowed) return ack({ error: 'NotAuthorized', ... });
        // proceed with grant verification
    });
});
```

Streams read levels map to Safe access tiers:

| Streams `READ_LEVEL` | Value | Safe meaning |
|----------------------|-------|--------------|
| `none`               | 0     | No access |
| `see`                | 10    | Can see the file exists (manifest public) |
| `content`            | 23    | Can fetch encrypted chunks (with OCP grant) |
| `max`                | 40    | Full access |

The Streams check is an **additional gate**, not a replacement for OCP grants.
A requester needs both: a valid Streams read level AND a valid OCP grant for the
chunk range. Either check failing returns 403.

**Admin-level for invites:** `Streams.ADMIN_LEVEL.invite` (level 20) is used
for sharing — a user with `invite` level can call `Cloud.grant()` and share
access to content they did not upload, up to their own access level. Jets
enforces this sub-delegation chain: it verifies that the grant's `proof.publicKey`
matches a key that has `invite`-level access on the corresponding stream.

**Anonymous Cloud users (no userId):** If `client.capability.userId` is null
and the request includes a `streamId`, the Streams check is skipped (anonymous
users have no stream membership). Access is then controlled solely by the OCP
grant. Anonymous access is appropriate for shared public content.

---

### 1.8 The subtree interface — Jets.put / Jets.get

Replaces the old `chunkPut`/`chunkGet` with a range-aware interface.

**`Jets.put(subtree, options, callback)`**
```js
subtree: {
  chunks: Array<{ cid, iv, ciphertext, tag, size, tags }>,
  start:  Number,
  end:    Number,
  grants: Array   // Q.Crypto.delegate proofs
}
options: { authorizations, payments, onProgress }
Returns: { results: Array<{ cid, stored: Boolean }> }
```

**`Jets.get(subtree, options, callback)`**
```js
subtree: {
  rootCid: String,
  start:   Number,
  end:     Number,
  grants:  Array
}
options: { authorizations, payments, onProgress }
Returns: { chunks: Array<{ cid, iv, ciphertext, tag, proof: Array }|null> }
```

Socket events: `Safe/subtree/put` and `Safe/subtree/get`.
HTTP equivalents: `PUT /Safe/subtree` and `GET /Safe/subtree/{rootCid}/{start}/{end}`.

Why subtree framing: one grant verification covers the whole range; Merkle proof
generation knows the file structure; Prolly-based routing can optimise per range;
progress reporting is natural.

---

### 1.9 Prolly tree reconciliation

On reconnect, the Drop sends its Prolly root. The Jet compares against its
stored root for that `dropId`:

- **Match:** no-op (O(1))
- **Jet root null (cold):** accept Drop's root; emit `dropColdSync`
- **Mismatch:** `Q.Data.Prolly.diff(jetRoot, dropRoot, store)` gives O(diff * log n) result;
  reassign affected chunks; emit `dropSync`

The Jet maintains an in-memory Prolly store per Drop (`_dropProllyStores`).
On Jet restart all roots reset; every reconnecting Drop triggers a cold sync.

---

### 1.10 Bloom filter cold handshake

On first contact (or after Jet restart), the Drop sends a Bloom filter of all
its stored CIDs in `Safe/drop/announce` (`bloomFilter` field). Compact:
~1.2 bytes/element at 1% false positive rate. A Drop with 100K chunks uses
~120KB for its filter. Cached in memory per Drop; re-sent on every cold reconnect.

---

### 1.11 Proof-of-storage challenges

The primary proof-of-storage mechanism is **anonymous paid spot-checks** —
`Safe/drop/get` requests issued by the Jet for randomly selected CIDs,
indistinguishable from real Cloud-originated retrieval requests. Each such
request includes a micropayment token (same as any other retrieval). The Drop
cannot tell a spot-check from legitimate traffic and must serve correctly
regardless.

**Why anonymous paid requests, not explicit signed challenges:**

The previous design (`proof = sign(keccak256(cid + nonce))`) proves only key
possession, not data possession. A malicious Drop could pass every challenge
by signing the hash without ever storing a single byte. This is a fundamental
design flaw — the system would become "proof of key ownership" not proof of
storage.

The correct approach is to ask the Drop to return the actual chunk. The Jet
then verifies data integrity using the CID as ground truth:
```js
SHA-256(returned_ciphertext || returned_tag) === requested_cid
```
This verification is self-contained — the CID is its own ground truth. The
Jet does not need to hold the chunk locally to verify it; it only needs the CID
(which it has in `_cidIndex`). A Drop returning garbage, a wrong chunk, or null
for a CID its Prolly root claims it holds fails this check immediately.

**Spot-check scheduling:** Poisson-distributed, unpredictable. The Jet
schedules spot-checks using a Poisson timer per connected Drop:
```js
// Mean interval: Q.Config.get(['Safe', 'drop', 'challengeIntervalMs'], 60000)
// CID sampled uniformly at random from the Drop's announced Prolly root
```

**The explicit `Safe/drop/challenge` event** is retained as a lightweight
direct ping for cases where the Jet needs to verify a specific CID without
routing it through the full `get` pipeline. It returns the actual chunk data
(not a hash-based proof). The Jet verifies via CID recomputation.

```js
// event: 'Safe/drop/challenge'  (Jet → Drop)
{ cid: String }          // no nonce — the chunk itself is the proof

// ack: (err, { cid, iv, ciphertext, tag } | null)
// null = Drop does not have the chunk
```

The nonce is removed. A nonce-based challenge (`sign(keccak256(cid+nonce))`)
proves nothing about data possession. The returned chunk bytes are the proof.

**Nonce uniqueness is irrelevant** in this model because the Drop does not
sign anything in response to a challenge — it simply returns the chunk or null.
Replay of a previous challenge response is impossible because there is no
signed proof to replay; only actual chunk bytes.

**Verification by the Jet:**
1. Compute `SHA-256(fromBase64(ciphertext) || fromBase64(tag))`
2. Compare to the requested `cid`
3. If mismatch: log failed spot-check against this Drop's reliability score
4. If null (Drop says it doesn't have it): check whether the Drop's current
   signed Prolly root implies it should — if yes, log failure

**What constitutes a slashable pattern:**
A single null or mismatched response is NOT slashable — transient errors,
recent evictions not yet announced, and network hiccups are all legitimate.
A slashable pattern requires **at least N=3 independent failed retrievals**
(default `Q.Config.get(['Safe', 'drop', 'minSlashFailures'], 3)`) within a
bounded time window (`Q.Config.get(['Safe', 'drop', 'slashWindowMs'], 3600000)`,
default 1 hour) with no corresponding eviction announce sent between the last
announce and the failures:
- Drop's signed announce claims its Prolly root implies CID X is present
- ≥ N `get` requests for CID X return null or CID-mismatched data
- No eviction announce was sent removing CID X within the slash window

The threshold N and time window must be consistent across all honest Jets —
otherwise different Jets may reach different slashing conclusions for the same
Drop, making CoC adjudication contentious. N=3 and 1 hour are the protocol
defaults; operators MUST NOT configure per-instance values that diverge from
network consensus.

**Spot-check coverage is probabilistic.** Uniform random sampling over the
Drop's Prolly root does not guarantee all CIDs are checked within any finite
period. A Drop that stores a popular subset of chunks and silently evicts the
rest may pass checks for some time — popular chunks are requested more often
and thus sampled more. The detection probability for a given missing CID
increases with the number of spot-checks issued. Over time, repeated sampling
converges toward full coverage verification. Future versions may use
weighted sampling (favour rarely-accessed CIDs) or burst audits to improve
detection speed for selective partial storage.

This pattern constitutes a self-contained CoC: signed announce (commitment to
CID X) + ≥ N failed serves within the window = contradiction without external
context. The Jet accumulates this evidence silently. The announce-before-evict
requirement (see Drops.md §1.4) ensures honest Drops never accidentally
produce this pattern.

On reaching the threshold: emit `dropChallengeFail`, notify PHP via
`POST /Q/node { 'Q/method': 'Safe/drop/slash' }` for stake slashing.

---

### 1.12 Drop micropayments and SafeBux claims

1. Cloud sends OCP payment token with each `Safe/subtree/get`.
   `recipientsHash = keccak256(abi.encode([dropPublicKey]))`.
2. Jet forwards token to serving Drop(s) in `Safe/drop/get` response.
3. Drop accumulates tokens in IndexedDB.
4. Drop sends `Safe/drop/claimPayments` with public key + tokens + signature.
5. Jet relays to PHP -> blockchain.

Drop reveals `publicKey` only at claim time (preimage of `recipientsHash`),
providing operation-time unlinkability.

---

### 1.13 Jets.Router — pluggable Drop and Jet discovery

All routing — both **Drop selection within a Jet** and **Jet-to-Jet discovery
and relay** — is delegated to a single replaceable `Jets.Router` object. The
full specification for Jets.Router (DHT, Kademlia, hypercore Swarm integration,
Jet peering protocol) lives in `Jets.Router.md` (separate document).

```js
// Default: round-robin drop selection, no Jet-to-Jet peering
Safe.Router = {
  // Select Drops to store CIDs. Returns Array<drop>.
  selectForPut: function (cids, options) { return Promise.resolve(drops); },
  // Select Drops to retrieve a CID. Returns Array<drop>.
  selectForGet: function (cid, options)  { return Promise.resolve(drops); },
  // Discover and relay to a peer Jet. Returns Promise<chunks>.
  // Called by Safe/subtree/get handler when no local Drops have the CIDs.
  relayGet:     function (subtree, options) { return Promise.resolve(null); }
};
```

Replace `Safe.Router` before calling `Safe.listen()` to plug in DHT routing.
The `dropId` maps to a DHT node ID via `SHA-256(dropId)` for XOR distance
calculations. Jet-to-Jet relay via `relayGet` is a v2 deliverable (stub returns
null). See `Jets.Router.md` for the full specification.

---

## Part 2 — External interfaces called by Jets

These are the bottom of the Jets dependency tree. Understand all of these
before implementing any Jets method.

---

### From Q.Safe.Cloud (client layer above Jets)

Jets does not call into Cloud. This section documents the **data shapes** Cloud
sends to Jets for reference.

**Chunk object** (in `Safe/subtree/put`):
```js
{ cid: String, iv: String, ciphertext: String, tag: String, size: Number, tags: Array }
// All strings are base64. cid is a CIDv1 string starting with 'bafy'.
```

**Grant object** (in `subtree.grants`):
```js
// The secret field is stripped before sending to Jets.
// Jets only uses statement, proof, start, end.
{
  statement: { label: String, context: String, issuedTime: Number, secretHash: String, parent: String },
  proof:     { signature: String, publicKey: String },  // both base64
  start:     Number,
  end:       Number
}
```

---

### From Q.Safe.Drops (storage layer below Jets)

Jets calls Drops only on the **server side** via socket.io push. The Jets client
wires these events to `Q.Safe.Drops` functions:

**`Q.Safe.Drops.put(chunks, options, callback)`**
```js
chunks:  Array<{ iv: String, data: ArrayBuffer, tags: Array }>
options: { authorizations, payments }
Returns: Promise<{ results: Array<{ cid, iv, size }|false> }>
Called by: onDropPut handler in Jets.js client
```

**`Q.Safe.Drops.get(cids, options, callback)`**
```js
cids:    Array<String>
options: { paymentToken: Object|null }
Returns: Promise<{ chunks: Array<{ cid, iv, data: ArrayBuffer }|null> }>
Called by: onDropGet handler in Jets.js client
```

**`Q.Safe.Drops.getProllyRoot(callback)`**
```js
Returns: Promise<String|null>   // hex Prolly root, or null if no chunks stored
Called by: dropRegister, dropAnnounce in Jets.js client
```

**`Q.Safe.Drops.getBloomFilter(callback)`**
```js
Returns: Promise<String|null>   // base64 serialised Bloom filter, or null
Called by: dropRegister (cold contact) in Jets.js client
```

---

### Platform: Q.Socket.connect

```js
Q.Socket.connect('/Safe', url, callback, options)
// Returns Q.Socket on success
// Used by Jets.connect()
// url: _jetUrl() = Q.Safe.Jets.url || Q.nodeUrl()
```

Follows the standard Q.Socket pattern used by Streams.js. On the server,
`Users.Socket.listen()` sets `client.capability` from the Q auth token;
for anonymous Drops, `client.capability.userId === null`.

---

### Platform: ethers.js provider

```js
// Server-side (Node.js)
var ethers   = require('ethers');
var provider = new ethers.JsonRpcProvider(rpcUrl);

// ERC-20 minimal ABI
var ERC20_ABI = ['function balanceOf(address) view returns (uint256)'];
var contract  = new ethers.Contract(tokenAddress, ERC20_ABI, provider);
contract.balanceOf(payerAddress)  // Promise<BigInt>

// Config path
Q.Config.get(['Safe', 'evm', 'provider', chainId], defaultRpcUrl)
// chainId: CAIP-2 string, e.g. 'eip155:8453' (Base mainnet)
```

---

### Platform: Q.Data.Prolly

```js
Q.Data.Prolly.diff(rootA, rootB, store, callback)
// Compares two Prolly trees over the same store.
// Returns: Array<{ cid: String, added: Boolean }>
// store: { get(hash) -> Promise<node>, put(hash, node) -> Promise }

Q.Data.Prolly.build(entries, store, callback)
// entries: Array<{ key, value }>
// Returns: hex root String
```

---

### Platform: Q.Data.Bloom

```js
Q.Data.Bloom.fromElements(elements)
// elements: Array<String>  (CID strings)
// Returns: { filter: ArrayBuffer, serialize() -> String (base64) }

Q.Data.Bloom.test(filter, element)
// Returns: Boolean  (may be false positive, never false negative)
// filter: deserialized from base64 received in announce
```

---

### Platform: Q.Data.Merkle.proof

```js
Q.Data.Merkle.proof(leaves, index)
// leaves: Array<String>  (ordered CID strings — same array used in Merkle.build)
// index:  Number         (absolute chunk index)
// Returns: Promise<Array<{ hex: String, side: 'left'|'right' }>>
```

Used by `Safe.buildMerkleProofs` to attach proofs to `get` responses. Requires
the original `leaves` array stored in `_cidIndex[rootCid]` when the file was
uploaded via `Safe/subtree/put`.

---

### Platform: Q.Utils.validateCapability

```js
Q.Utils.validateCapability(capability, scope)
// capability: client.capability (set by Q auth middleware on socket connect)
// scope: String, e.g. 'Safe/subtree/put'
// Returns: Boolean
// Anonymous Drops pass with userId === null
```

---

### Platform: Streams access control

Used server-side to check a Cloud user's read/admin level on a stream before
serving chunks. This is relevant when the content is associated with a Streams
stream (the request includes `publisherId` + `streamName`).

```js
// Server-side (Node.js)
var Streams = Q.require('Streams');

// Fetch stream with access check for the requesting user
Streams.fetchOne(userId, publisherId, streamName, function(err, stream) {
    if (err || !stream) { return forbidden(); }

    // Check read level (23 = content)
    stream.testReadLevel('content', function(err, allowed) {
        if (!allowed) { return forbidden(); }
        // proceed
    });

    // Check admin level for sharing/invite
    stream.testAdminLevel('invite', function(err, allowed) {
        // allowed = user may sub-delegate access up to their own level
    });
});

// Numeric levels (from Streams.READ_LEVEL / ADMIN_LEVEL):
// READ_LEVEL.content = 23   — can fetch encrypted chunk content
// ADMIN_LEVEL.invite = 20   — can share access with others
```

Called by `Safe.verifyStreamAccess(userId, publisherId, streamName, level)`
in the `Safe/subtree/get` handler. If `userId` is null (anonymous), this
check is skipped and access is controlled solely by OCP grants.

---

### Platform: Q.Assets.OpenClaim (delegated, v2)

Jets does NOT call the OpenClaiming contract directly. On-chain payment
execution is delegated to the Assets plugin via a PHP→Node internal message.
The full call chain is:

```
Jets (Node.js)
  -> POST /Q/node { 'Q/method': 'Safe/payment/collect', paymentToken, dropPublicKey }
  -> PHP Assets plugin (Q.Assets.OpenClaim)
  -> OpenClaiming.executePayment(payment, recipients, signature, recipient, amount, address(0))
     at 0x99996a51cc950d9822D68b83fE1Ad97B32Cd9999
```

The `recipients` array is `[dropAddress]` where `dropAddress` is derived from
the Drop's registered `publicKey`. The `recipient` is the same Drop address.

In v1, Jets only performs the balance pre-check (section 1.5) and forwards the
payment token to PHP. The Assets plugin call is a v2 deliverable. Jets' protocol
already carries all the information needed — the handoff point is documented
here so the implementer knows where Jets' responsibility ends.

---

---

## Part 3 — Socket and HTTP event protocol

All socket events on the `/Safe` namespace. Ack pattern: `ack(err, result)`.
HTTP and socket.io share identical verification and routing logic — HTTP
handlers are thin adapters over the same internal functions.

---

### Data flow diagram: Cloud, Jets, Drops, OCP

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │  BROWSER                                                              │
  │                                                                       │
  │  ┌──────────────┐  Jets.put(subtree)    ┌────────────────────────┐  │
  │  │              │  ─────────────────▶   │                        │  │
  │  │  Q.Safe      │  Jets.get(subtree)    │  Q.Safe.Jets (client)  │  │
  │  │  .Cloud      │  ◀─────────────────   │  socket.io /Safe       │  │
  │  │              │                       └───────────┬────────────┘  │
  │  │  (encrypts / │                                   │ push events   │
  │  │   decrypts)  │  ┌──────────────────────────┐    │               │
  │  │              │  │  Q.Safe.Drops (IndexedDB) │◀───┘               │
  │  └──────┬───────┘  │  store/serve ciphertext   │                   │
  │         │          │  Prolly tree + Bloom       │                   │
  │         │ OCP      └──────────────────────────┘                    │
  │         │ grants+payments                                            │
  └─────────┼────────────────────────────────────────────────────────────┘
            │ socket.io /Safe   OR   HTTPS batch GET/PUT
            ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  NODE.JS JET SERVER  (classes/Safe/Jets.js)                         │
  │                                                                      │
  │  ① verifySubtreeGrant (OCP Role A)   →  403 if any index denied    │
  │  ② verifyStreamAccess (Streams)      →  403 if readLevel too low   │
  │  ③ _checkPayerBalance (OCP Role B)   →  402 if balance low         │
  │  ④ Jets.Router.selectForGet/Put       →  choose Drops               │
  │  ⑤ callDrop (Safe/drop/put|get)       →  fan out to Drops           │
  │  ⑥ buildMerkleProofs (_cidIndex)      →  attach proofs to response  │
  │  ⑦ forward payment tokens → PHP → Assets → OpenClaiming contract   │
  │                                                                      │
  │  ┌─────────────────┐  Safe/drop/put    ┌─────────────────────────┐ │
  │  │ _cidIndex        │  Safe/drop/get ▶  │  Drop (browser tab)     │ │
  │  │ rootCid→[cids]  │  Safe/drop/       │  IndexedDB ciphertext   │ │
  │  │ _dropProllyStore│  challenge      ◀  │  Prolly tree + Bloom    │ │
  │  └─────────────────┘                   └─────────────────────────┘ │
  └─────────────────────────────────────────────────────────────────────┘
            │
            │ POST /Q/node (Safe/payment/collect)
            ▼
  ┌──────────────────────────┐
  │  PHP / Assets plugin     │
  │  Q.Assets.OpenClaim      │
  │  → OpenClaiming contract │
  │    at 0x99996a51...9999  │
  └──────────────────────────┘
```

**Key derivation note — why GET responses are CDN-cacheable:**

The encryption key tree and the access grant tree are **separate branches** of
the same root:

```
rootKey
  ├─ Q.Crypto.delegate('safecloud.encryption.root')
  │    └─ encryptionRoot
  │         └─ delegate('safecloud.subtree.S.E')
  │              └─ subtreeKey  ──→  chunkKey[i]  ──→  ciphertext
  │
  └─ Q.Crypto.delegate('safecloud.access.root')
       └─ accessRoot
            └─ delegate('safecloud.subtree.S.E', context)
                 └─ grant proof  ──→  OCP Role A token
```

The ciphertext bytes produced by a given `chunkKey` are **deterministic and
stable** — they depend only on the encryption key tree, not on who has access.
The access grant tree produces OCP authorization tokens that travel alongside
requests but do not affect the encrypted bytes.

This means a CDN proxy can cache `GET /Safe/chunk/{cid}` responses using the
CID as the cache key. The same ciphertext is served to every requester; only
clients who hold a valid OCP grant (and the matching subtreeKey) can decrypt it.
The Jet sets `Cache-Control: public, max-age=31536000, immutable` on chunk
responses since CIDs are content-addressed and never change.

---

### OCP payload formats: grants (Role A) vs payments (Role B)

**Grant — OCP Role A (access authorization):**

Produced by `Cloud.grant()`. Verified by `Safe.verifySubtreeGrant()` on the
Jet. Identifies which chunk range the bearer is authorized to access.

```js
// Carried in: subtree.grants[]  /  query param ?g=<base64url>
{
  // secret is STRIPPED before sending to Jets — it is for the grantee's
  // local decryption only and must never travel over the wire to a Jet.
  statement: {
    label:      String,  // 'safecloud.read.content' | 'safecloud.write.post' | ...
    context:    String,  // JSON string: {"rootCid":"bafy...","start":0,"end":100,"exp":0}
    issuedTime: Number,  // Unix seconds
    secretHash: String,  // hex keccak256 of the subtreeKey bytes (Jets verifies consistency)
    parent:     String   // hex of issuing public key
  },
  proof: {
    signature: String,   // base64 ECDSA-P256 sig over canonical JSON of statement
    publicKey: String    // base64 P-256 uncompressed public key (65 bytes)
  },
  start: Number,         // convenience copy of context.start
  end:   Number          // convenience copy of context.end
}
```

**Payment token — OCP Role B (micropayment):**

An EIP-712 `Payment` struct from the OpenClaiming contract, signed by the
payer. Verified by `Safe._checkPayerBalance()` + forwarded to PHP for on-chain
execution. Identifies who is paying, how much, and to which recipients.

```js
// Carried in: payments[]  /  query param ?p=<base64url>  /  PAYMENT-SIGNATURE header
{
  payment: {
    payer:          String,  // '0x...' EVM address of payer (content consumer)
    token:          String,  // '0x...' ERC-20 address, or address(0) for native coin
    recipientsHash: String,  // '0x...' = keccak256(abi.encode([jetAddress]))
                             //   for Drop payments: keccak256(abi.encode([dropAddress]))
    max:            String,  // claim-level ceiling in token base units, '0' = unlimited
    line:           Number,  // trustline bucket id (must be open on-chain via lineOpen())
    nbf:            Number,  // Unix timestamp not-before, 0 = no lower bound
    exp:            Number   // Unix timestamp expiry, 0 = no expiry
  },
  signature: String,         // '0x...' 65-byte EIP-712 ECDSA sig from payer
  chainId:   String          // CAIP-2: 'eip155:8453' (Base), 'eip155:1' (Ethereum), etc.
}
```

Both types may travel over socket.io as plain JSON fields, or over HTTP encoded
as `base64url(JSON.stringify(array))` in query parameters `?g=` and `?p=`.

---

### HTTP batch request format

GET requests encode all parameters in the URL to enable HTTP caching by CDN
proxies and intermediate servers. Because encrypted chunk bytes are
deterministic and content-addressed, any proxy can cache and deduplicate
responses across all requesters.

**`GET /Safe/subtree/{rootCid}/{start}/{end}`**

URL path carries `rootCid`, `start`, `end`. Query parameters carry auth/payment
data as `base64url(JSON.stringify(array))`:

```
GET /Safe/subtree/bafy.../0/10?g=<grants_b64url>&p=<payments_b64url>&s=<streamId_b64url>
```

- `g` — OCP grants array (Role A), `secret` field stripped
- `p` — OCP payment tokens array (Role B)
- `s` — `base64url(publisherId + "\t" + streamName)` — optional Streams check

**Size limit:** The total URL must fit within ~2000 characters to pass safely
through all proxies and browsers. If a subtree range requires more (large
grants array, multiple payment tokens), the client **splits into multiple
sequential requests** covering sub-ranges. A range of 3–5 chunks with a
single grant typically fits comfortably.

```
// Example: 10 chunks split into two 5-chunk requests
GET /Safe/subtree/bafy.../0/5?g=...&p=...   → chunks [0,5)
GET /Safe/subtree/bafy.../5/10?g=...&p=...  → chunks [5,10)
```

Cloud reassembles the chunk arrays in order before decryption.

**Cache-Control on successful responses:**
```
Cache-Control: public, max-age=31536000, immutable
Content-Type: application/json
```

**`PUT /Safe/subtree`** — body is always JSON; no URL size concern:
```json
{
  "chunks":      [{ "cid": "...", "iv": "...", "ciphertext": "...", "tag": "...", "size": 262144, "tags": [] }],
  "start":       0,
  "end":         10,
  "grants":      [{ "statement": {}, "proof": {}, "start": 0, "end": 10 }],
  "payments":    [{ "payment": {}, "signature": "0x...", "chainId": "eip155:8453" }],
  "publisherId": "abc123",
  "streamName":  "Safe/files/xyz"
}
```

**`GET /Safe/chunk/{cid}`** — single-chunk fetch (x402 path for external
clients). No grants required; guarded by `PAYMENT-SIGNATURE` header only.
Supports HTTP `Range:` header for Safari `<video>` and CDN range requests.
Response is raw ciphertext bytes (`Content-Type: application/octet-stream`).

---

### HTTP error response format

Every non-2xx HTTP response from Jets has a JSON body with this structure:

```json
{
  "error": {
    "code":    "NotAuthorized",
    "message": "Human-readable description of what went wrong",
    "details": { ... }
  }
}
```

The `details` object is **always structured to identify exactly which parts of
the batch failed**, so the client can immediately retry without the failing
items — no guessing, no re-requesting the whole batch.

**403 Forbidden — access denied (some or all indices):**
```json
{
  "error": {
    "code":    "NotAuthorized",
    "message": "Grants do not cover all requested chunk indices",
    "details": {
      "unauthorized": [3, 4, 7, 8, 9],
      "grantIssues": [
        { "index": 3, "issue": "No grant covers this index" },
        { "index": 4, "issue": "No grant covers this index" },
        { "index": 7, "issue": "Grant expired at 1700000000" }
      ]
    }
  }
}
```

The `unauthorized` array contains **absolute chunk indices** within the
requested range. The client re-requests only the permitted indices in the
same batch call. Indices absent from `unauthorized` were permitted and will
be served on a corrected request.

**402 Payment Required — OCP payment token present but balance insufficient:**
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
      "chainId":  "eip155:8453"
    }
  }
}
```

When the `PAYMENT-SIGNATURE` header is **absent entirely** (external HTTP
client), the response is x402-compatible (see x402 section below) with the
`PAYMENT-REQUIRED` header carrying `PaymentRequirements` JSON.

**404 Not Found — rootCid or cid unknown to this Jet:**
```json
{
  "error": {
    "code":    "NotFound",
    "message": "rootCid not found in this Jet's index",
    "details": {
      "rootCid": "bafy...",
      "hint":    "Try another Jet or wait for replication"
    }
  }
}
```

**Socket.io ack equivalents** — same structure in the `err` ack argument:
```js
// 403:
ack({ error: { code: 'NotAuthorized', message: '...', details: { unauthorized: [3,4], grantIssues: [...] } } })
// 402:
ack({ error: { code: 'PaymentRequired', message: '...', details: { ... } } })
```

---

### Cloud to Jet (socket.io and HTTP)

**`Safe/subtree/put`** (socket.io) / **`PUT /Safe/subtree`** (HTTP)
```js
// Request payload (socket) / body (HTTP):
{
  chunks:         Array<{ cid, iv, ciphertext, tag, size, tags }>,
  start:          Number,
  end:            Number,
  grants:         Array,          // OCP Role A: Q.Crypto.delegate proofs (secret stripped)
  payments:       Array,          // OCP Role B: EIP-712 Payment structs
  publisherId:    String|null,    // optional: Streams readLevel check
  streamName:     String|null
}

// Success ack / 200 body:
{ "results": [{ "cid": "bafy...", "stored": true }, ...] }

// Error acks / error bodies: see HTTP error response format above
```

**`Safe/subtree/get`** (socket.io) / **`GET /Safe/subtree/{rootCid}/{start}/{end}`** (HTTP)
```js
// Request payload (socket) / URL + query params (HTTP):
{
  rootCid:        String,
  start:          Number,
  end:            Number,
  grants:         Array,          // OCP Role A (secret stripped)
  payments:       Array,          // OCP Role B
  publisherId:    String|null,
  streamName:     String|null
}

// Success ack / 200 body:
{
  "chunks": [
    {
      "cid":        "bafy...",
      "iv":         "<base64 12 bytes>",
      "ciphertext": "<base64>",
      "tag":        "<base64 16 bytes>",
      "proof":      [{ "hex": "...", "side": "left" }, ...]
    },
    null    // null = unavailable (no Drop has it) — NOT a 403
  ]
}

// Error acks / error bodies: see HTTP error response format above
```

**`GET /Safe/chunk/{cid}`** (HTTP only)
```
Single-chunk fetch for external clients (x402 path).
Supports Range: header (206 Partial Content) for Safari/CDN.
No OCP grant required.
No payment:  → 402 + PAYMENT-REQUIRED header (x402 spec)
Bad payment: → 402 + JSON error body
Chunk missing from _cidIndex: → 404 + JSON error body
Success:     → 200 + ciphertext bytes + PAYMENT-RESPONSE header
             Cache-Control: public, max-age=31536000, immutable
```



---

### Drop to Jet (socket.io)

**`Safe/drop/register`**
```js
{
  dropId:      String,
  clientId:    String,
  publicKey:   String,           // base64 P-256
  storage:     { GB: Number },
  prollyRoot:  String|null,
  bloomFilter: String|null       // base64; included on first contact or after Jet restart
}
ack: (err, { dropId: String })
```

**`Safe/drop/announce`**
```js
{
  dropId:      String,
  storage:     { GB: Number },
  used:        Number,
  prollyRoot:  String|null,
  bloomFilter: String|null
}
ack: (err)
```

**`Safe/drop/disconnect`**
```js
{ dropId: String }
ack: (err)
```

**`Safe/drop/claimPayments`**
```js
{
  dropId:        String,
  publicKey:     String,         // reveals preimage of recipientsHash
  paymentTokens: Array,
  signature:     String          // base64 OCP claim signed with Drop keypair
}
ack: (err, { txHash: String|null })
```

---

### Jet to Drop (socket.io push)

**`Safe/drop/put`**
```js
{
  chunks:  Array<{ cid, iv, ciphertext, tag, size, tags }>,
  options: Object
}
ack: (err, { results: Array<{ cid, stored: Boolean }> })
```

**`Safe/drop/get`**
```js
{
  cids:         Array<String>,
  options:      Object,
  paymentToken: Object|null
}
ack: (err, { chunks: Array<{ cid, iv, ciphertext, tag }|null> })
```

**`Safe/drop/challenge`**
```js
// Jet → Drop: request a specific chunk as proof of storage
{ cid: String }
// No nonce — the chunk bytes are the proof, not a signature over a nonce.
// A nonce-based signed response proves only key possession, not data possession.

// Drop ack:
(err, { cid: String, iv: String, ciphertext: String, tag: String } | null)
// null = Drop does not have the chunk (not a slashable offense if eviction
// announce was already sent removing this CID from the Prolly root)
```

The Jet verifies: `SHA-256(fromBase64(ciphertext) || fromBase64(tag)) === cid`.
This is self-verifying from the CID alone — no local copy of the chunk needed.

**`Safe/drop/slashed`**
```js
{ reason: String }
// no ack
```

---

### PHP to Jet internal (POST /Q/node)

**`Safe/drop/slash`**
```js
{ 'Q/method': 'Safe/drop/slash', dropId: String, reason: String }
```

---

### HTTP range request interface

`GET /Safe/chunk/{cid}` supports HTTP Range as required by Safari `<video>`
and HTTP proxies. The Jet:
1. Fetches full ciphertext from a Drop (or memory cache)
2. Parses `Range: bytes=N-M` header
3. Returns 206 with `Content-Range: bytes N-M/total`

Ciphertext is opaque bytes to the Jet — no decryption needed for range serving.

---

### x402 payment headers

Used on the HTTP transport for `GET /Safe/chunk/{cid}` when no
`PAYMENT-SIGNATURE` header is present. Provides x402 v2-compatible payment
discovery for external clients (curl, AI agents, CDN middleware).

**402 response — no payment header present:**
```
HTTP/1.1 402 Payment Required
PAYMENT-REQUIRED: <base64(JSON PaymentRequirements)>
Content-Type: application/json
```

PaymentRequirements (x402 v2 spec):
```json
{
  "scheme":             "exact",
  "network":            "eip155:8453",
  "maxAmountRequired":  "1000",
  "resource":           "https://jet.example.com/Safe/chunk/bafy...",
  "description":        "Safecloud chunk retrieval",
  "mimeType":           "application/octet-stream",
  "payTo":              "0xJetWalletAddress",
  "token":              "0xUSDCAddress",
  "extra":              { "name": "SafeCloud", "version": "1" }
}
```

Price: `Q.Config.get(['Safe', 'pricing', 'perChunkWei'], '1000')`.
Wallet: `Q.Config.get(['Safe', 'wallet', 'address'])`.

**Retry with payment:**
```
GET /Safe/chunk/{cid}
PAYMENT-SIGNATURE: <base64(EIP-712 signed PaymentPayload)>
```

**Success:**
```
HTTP/1.1 200 OK
Cache-Control: public, max-age=31536000, immutable
PAYMENT-RESPONSE: <base64(SettlementResponse)>
Content-Type: application/octet-stream
[ciphertext bytes]
```

For socket.io clients, OCP payment token failures return the standard error
ack format (see HTTP error response format section above).



## Part 4 — Client: web/js/Safe/Jets.js

Implements `Q.Safe.Jets` in the browser. Supersedes `plugins/Safe/web/js/Safe/Jets.js`
stub, upgrading `chunkPut`/`chunkGet` to the subtree interface and adding
`dropClaimPayments`.

---

### Internal helpers (implement first)

**`_dropId()` -> String**
```
Calls: sessionStorage.getItem/setItem, Q.clientId()
Called by: dropRegister, dropAnnounce, dropDisconnect
```
Returns stable `dropId` for this session. Format: `'drop-' + Q.clientId()`.
Stored in `sessionStorage['Q.Safe.dropId']`. Cleared on intentional `dropDisconnect`.

---

**`_jetUrl()` -> String**
```
Calls: Q.Safe.Jets.url, Q.nodeUrl()
Called by: connect
```
Returns `Q.Safe.Jets.url` if set, else `Q.nodeUrl()`. Allows overriding for
multi-Jet deployments.

---

**`_ab2b64(buf)` -> String  /  `_b642ab(b64)` -> ArrayBuffer**
```
Calls: Uint8Array, btoa/atob
Called by: onDropPut handler, onDropGet handler
```
ArrayBuffer <-> base64 for socket.io transport. Used only for the binary `data`
field in `Q.Safe.Drops.put/get` calls — all other chunk fields are already
base64 strings as produced by Cloud.

---

**`_withSocket(fn)` -> void**
```
Calls: connect() (if no socket), _queue array
Called by: put, get, dropRegister, dropAnnounce, dropDisconnect, dropClaimPayments
```
Executes `fn(_socket)` immediately if connected, otherwise queues `fn` and
triggers `connect()`. Queue is drained in `connect`'s success callback.

---

**`_scheduleReconnect()` -> void**
```
Calls: setTimeout, Q.Safe.Jets.connect
Called by: socket 'disconnect' handler in connect
```
Exponential backoff +/-30% jitter. baseMs=500, maxMs=30000. Preserved from
existing stub.

---

### Public methods

**`Q.Safe.Jets.connect(callback)` -> Promise\<Q.Socket\>**
```
Calls: _jetUrl, Q.Socket.connect('/Safe', url, callback)
Called by: _withSocket, explicit callers
```
Connects to `/Safe` namespace. Idempotent. On success: sets `_socket`,
`_connected`, resets `_reconnectAttempt`, registers `Safe/drop/*` event
handlers, drains `_queue`, fires `onConnect`. On disconnect: clears state,
schedules reconnect, fires `onDisconnect`. If `_dropInfo` is set (Drop was
registered before disconnect), calls `dropRegister(_dropInfo)` after reconnect.

---

**`Q.Safe.Jets.put(subtree, options, callback)` -> Promise**
```
Calls: _withSocket -> qs.socket.emit('Safe/subtree/put', ...)
Called by: store.js (via Cloud)
```
Parameters:
```js
subtree: { chunks, start, end, grants }
options: { authorizations, payments, onProgress }
```
All chunk fields are already base64 strings from Cloud. Calls
`options.onProgress(stored, total)` per-chunk as acks arrive. If ack returns
`{ error: 'No Drops available' }`: retry once after 2s before propagating error.

---

**`Q.Safe.Jets.get(subtree, options, callback)` -> Promise**
```
Calls: _withSocket -> qs.socket.emit('Safe/subtree/get', ...)
Called by: fetch.js, _prefetchLoop.js (via Cloud)
```
Parameters:
```js
subtree: { rootCid, start, end, grants }
options: { authorizations, payments, onProgress }
```
Returns `{ chunks: Array<{ cid, iv, ciphertext, tag, proof }|null> }`. Null
entries are unavailable chunks — Cloud handles them as partial failure.

---

**`Q.Safe.Jets.dropRegister(info, callback)` -> Promise**
```
Calls: Q.Safe.Drops.getProllyRoot, Q.Safe.Drops.getBloomFilter (if no prollyRoot),
       _withSocket -> qs.socket.emit('Safe/drop/register', ...)
Called by: Q.Safe.Drops
```
Parameters: `{ publicKey: String (base64 P-256), storage: { GB } }`.
Fetches `prollyRoot` from `Q.Safe.Drops.getProllyRoot()`. If null, fetches
`bloomFilter`. Builds full payload with `dropId`, `clientId`. Stores as `_dropInfo`
for reconnect handler.

---

**`Q.Safe.Jets.dropAnnounce(info, callback)` -> Promise**
```
Calls: _withSocket -> qs.socket.emit('Safe/drop/announce', ...)
Called by: reshare.js, Q.Safe.Drops
```
Sends `{ storage, used, prollyRoot, bloomFilter }`. Called after `reshare()`
and after LRU eviction.

---

**`Q.Safe.Jets.dropDisconnect(callback)` -> Promise**
```
Calls: _withSocket -> qs.socket.emit('Safe/drop/disconnect', ...)
Called by: Q.Safe.Drops
```
Clears `dropId` from sessionStorage after successful ack.

---

**`Q.Safe.Jets.dropClaimPayments(payload, callback)` -> Promise**
```
Calls: _withSocket -> qs.socket.emit('Safe/drop/claimPayments', ...)
Called by: Q.Safe.Drops
```
Parameters:
```js
{
  publicKey:     String,   // base64 P-256 — reveals identity for claim
  paymentTokens: Array,    // accumulated OCP tokens from Safe/drop/get responses
  signature:     String    // base64 OCP claim signed with Drop keypair
}
```

---

### Q.Safe.Jets Events

```js
Q.Safe.Jets.onConnect       = new Q.Event()  // (Q.Socket) — on connect
Q.Safe.Jets.onDisconnect    = new Q.Event()  // () — on disconnect
Q.Safe.Jets.onDropPut       = new Q.Event()  // (payload, ack)
Q.Safe.Jets.onDropGet       = new Q.Event()  // (payload, ack)
Q.Safe.Jets.onDropChallenge = new Q.Event()  // (payload, ack)
Q.Safe.Jets.onDropSlashed   = new Q.Event()  // (payload)
```

---

### Default Drop push handlers

Wired at module load time (bottom of Jets.js). Preserve from existing stub:

**`onDropPut`**: deserialise chunk data base64->ArrayBuffer -> `Q.Safe.Drops.put` -> ack.
**`onDropGet`**: `Q.Safe.Drops.get` -> serialise ArrayBuffer->base64 -> ack.
**`onDropChallenge`**: `Q.Safe.Drops.get([cid])` → return chunk bytes directly.
Jet verifies `SHA-256(ciphertext || tag) === cid`. No nonce, no signing.
See Drops.md §5 `onDropChallenge` for the full handler pipeline.

---

## Part 5 — Server: classes/Safe/Jets.js

Follows `Streams.js` conventions: `Users.Socket.listen()`, `/Q/node` handler,
`Q.makeEventEmitter`. Supersedes `plugins/Safe/node/Safe.js`.

**Private state:**
```js
Safe.drops = {}           // dropId -> drop record (schema below)
var _socketToDropId = {}  // socketId -> dropId
var _dropProllyStores = {}// dropId -> { get, put } in-memory Prolly store
var _providers = {}       // chainId -> ethers.JsonRpcProvider
var _balanceCache = {}    // chainId -> payer -> token -> { balance, cachedAt }
var _cidIndex = {}        // rootCid -> Array<String> (ordered CIDs from put)
```

**Drop record schema:**
```js
{
  dropId:        String,
  socketId:      String,          // socket.io id (changes on reconnect)
  socket:        Object,          // socket.io client
  clientId:      String|null,
  userId:        String|null,     // null for anonymous
  publicKey:     String|null,     // base64 P-256
  storage:       { GB: Number },
  used:          Number,
  prollyRoot:    String|null,
  bloomFilter:   Object|null,     // deserialized Bloom filter in memory
  offlineSince:  Number|null,
  registeredAt:  Number,
  reconnectedAt: Number
}
```

---

### Internal helpers (implement first)

**`_storeForDrop(dropId)` -> { get, put }**
```
Calls: _dropProllyStores[dropId]
Called by: Safe._reconcileDropInventory
```
Returns or creates in-memory Prolly node store for a Drop. Plain object
`{ hash: node }` wrapped with promise-returning `get`/`put`.

---

**`Safe._evmProvider(chainId)` -> ethers.JsonRpcProvider**
```
Calls: Q.Config.get(['Safe', 'evm', 'provider', chainId]), ethers.JsonRpcProvider
Called by: Safe._checkPayerBalance
```
Lazy-initialises a provider. Cached in `_providers[chainId]`.

---

**`Safe._checkPayerBalance(payer, token, amount, chainId)` -> Promise\<Boolean\>**
```
Calls: Safe._evmProvider, _balanceCache, ethers Contract.balanceOf
Called by: Safe/subtree/put handler, Safe/subtree/get handler, x402 verify
```
1. Check `_balanceCache[chainId][payer][token]`; return if fresh.
2. `token === address(0)`: `provider.getBalance(payer)`.
   Otherwise: `contract.balanceOf(payer)` with `ERC20_ABI`.
3. Cache result. Return `balance >= BigInt(amount)`.
Cache TTL: `Q.Config.get(['Safe', 'evm', 'balanceCacheTtlMs'], 300000)`.

---

**`Safe.callDrop(drop, method, payload, timeoutMs)` -> Promise**
```
Calls: drop.socket.emit(method, payload, ack)
Called by: subtree/put handler, subtree/get handler, chunk/challenge handler
```
Emits a socket.io event to a Drop and awaits the ack. Rejects after
`timeoutMs` (default 10000ms). Caller falls back to another Drop on rejection.

---

**`Safe.selectDrops(cids, options)` -> Array\<drop\>**
```
Calls: Safe.drops, Safe.router (if set)
Called by: subtree/put handler, subtree/get handler
```
v1: filters online Drops (`offlineSince === null`), returns up to
`options.replication` (default 2) in round-robin order. Delegates to
`Safe.router.selectForPut(cids, options)` or `.selectForGet(cid, options)`
if `Safe.router` is set.

---

**`Safe.verifySubtreeGrant(grants, rootCid, start, end)` -> Object**
```
Calls: Date.now(), ECDSA verify (via Q.Utils or inline)
Called by: subtree/put handler, subtree/get handler
Returns: { ok: Boolean, unauthorized: Array<Number>, reason: String }
```
For each absolute chunk index `i` in `[start, end)`, checks that at least one
grant in `grants` covers it. A grant covers index `i` if:
1. `grant.statement.label` starts with `'safecloud.'`
2. `grant.statement.context` JSON: `context.start <= i < context.end`
3. If `rootCid` is provided (get path): `context.rootCid === rootCid`
4. `exp` not expired (if present)
5. ECDSA `grant.proof.signature` valid over canonical JSON of `grant.statement`
   using `grant.proof.publicKey`

Returns `{ ok: true }` if all indices are covered, or
`{ ok: false, unauthorized: [3,4,7], reason: 'Grants do not cover indices [3,4,7] of range [0,10)' }`
listing exactly which indices lack coverage. The caller uses this to build the
HTTP 403 / socket.io ack body.

On upload (`put`), `rootCid` is null because the Merkle root is not yet known.
The grants still constrain the range; the `rootCid` binding is only enforced
on `get`.

---

**`Safe.verifyStreamAccess(userId, publisherId, streamName, level, callback)` -> void**
```
Calls: Streams.fetchOne, stream.testReadLevel / stream.testAdminLevel
Called by: subtree/put handler, subtree/get handler (when publisherId+streamName present)
```
Checks that `userId` has at least `level` access on the stream
`publisherId/streamName`. Calls `callback(null, true)` if allowed,
`callback(null, false)` if denied, `callback(err)` on Streams error.

If `userId` is null (anonymous connection), calls `callback(null, true)`
immediately — anonymous Cloud users are not checked via Streams; their access
is controlled solely by OCP grants.

`level` is a Streams read or admin level string, e.g. `'content'` (23) for
read access or `'invite'` (20) for sharing. The mapping:
- `Safe/subtree/get`: checks `READ_LEVEL.content` (23)
- Sub-delegation validation: checks `ADMIN_LEVEL.invite` (20)

---

**`Safe.buildMerkleProofs(rootCid, cids)` -> Promise\<Array\>**
```
Calls: _cidIndex[rootCid], Q.Data.Merkle.proof(storedCids, i)
Called by: subtree/get handler
```
Retrieves the ordered CID array from `_cidIndex[rootCid]` (populated during
`Safe/subtree/put`). Calls `Q.Data.Merkle.proof(storedCids, absoluteIndex)`
for each requested chunk. If `_cidIndex[rootCid]` is missing (Jet restart):
returns null proofs — Cloud retries.

Jets SHOULD prioritize rebuilding `_cidIndex` before serving requests after a
restart (e.g. by requiring at least one `Safe/subtree/put` to repopulate the
index, or by persisting the index to disk). Serving without Merkle proofs is
a temporary fallback for restarts, not a steady-state mode — clients that
receive null proofs will retry on a Jet that has the index.

Returns `Array< Array<{ hex, side }> >`, one proof per requested chunk.

---

**`Safe._reconcileDropInventory(drop, prollyRoot)` -> void**
```
Calls: _storeForDrop, Q.Data.Prolly.diff, Safe.emit
Called by: Safe/drop/register handler, Safe/drop/announce handler
```
Compares Jet's stored root vs Drop's reported root. Emits `dropColdSync`
(no prior state), `dropSync` (diff result), or nothing (match). Updates
`drop.prollyRoot` on success.

---

**`Safe._attachBloomFilter(drop, bloomFilter)` -> void**
```
Calls: Q.Data.Bloom (deserialize base64), drop.bloomFilter =
Called by: Safe/drop/register handler, Safe/drop/announce handler
```
Deserialises the Bloom filter from base64 and stores in `drop.bloomFilter`
for use by `selectDrops` when probing which Drops likely have a specific CID.

---

**`Safe_request_handler(req, res, next)` -> void**
```
Calls: Safe.drops, Safe.emit
Called by: Express POST /Q/node
```
Handles PHP->Node messages. Currently handles `Safe/drop/slash`: finds Drop
record by `dropId`, emits `dropSlash` event, sends `Safe/drop/slashed` to
Drop's socket.

---

### Public methods

**`Safe.listen(options)` -> { internal, socket }**
```
Calls (in order):
  Q.listen()
  server.attached.express.post('/Q/node', Safe_request_handler)
  Q.Config.get (host, port, https)
  Users.Socket.listen({ host, port, https })
  socketServer.io.of('/Safe').on('connection', ...)
  app.get('/Safe/chunk/:cid', ...)
  app.get('/Safe/subtree/:rootCid/:start/:end', ...)
  app.put('/Safe/subtree', ...)
  setInterval (grace-period sweep, GRACE_MS)
  var Streams = Q.require('Streams')  (lazy, only when streamId present in request)
```

Entry point; mirrors `Streams.listen()`. Idempotent (returns cached result on
repeat calls).

**Socket.io `/Safe` connection handler registers:**
- `Safe/drop/register` — create or restore Drop record; Prolly reconciliation
- `Safe/drop/announce` — update stats; Prolly reconciliation; Bloom attach
- `Safe/drop/disconnect` — remove Drop record
- `Safe/drop/claimPayments` — relay to PHP
- `Safe/subtree/put`:
  1. `verifySubtreeGrant(grants, null, start, end)` — grants don't need rootCid on upload;
     if `{ ok: false }`: ack `{ error: 'NotAuthorized', unauthorized, reason }` (403)
  2. `verifyStreamAccess(userId, publisherId, streamName, 'content')` if present;
     if denied: ack `{ error: 'NotAuthorized', unauthorized: all, reason: 'Streams access denied' }`
  3. For each payment token: `_checkPayerBalance`; if insufficient:
     ack `{ error: 'PaymentRequired', reason: '...' }` (402 equivalent)
  4. Store CID array in `_cidIndex[rootCid]`
  5. `selectDrops(cids)` -> fan out `callDrop(Safe/drop/put)` in parallel
  6. Ack merged per-chunk results
- `Safe/subtree/get`:
  1. `verifySubtreeGrant(grants, rootCid, start, end)`; if `{ ok: false }`:
     ack `{ error: 'NotAuthorized', unauthorized, reason }` — structured for bulk re-request
  2. `verifyStreamAccess(userId, publisherId, streamName, 'content')` if present
  3. For each payment token: `_checkPayerBalance`; if insufficient:
     ack `{ error: 'PaymentRequired', reason: '...' }`
  4. `selectDrops([...cids])` -> `callDrop(Safe/drop/get)` with fallback
  5. `buildMerkleProofs(rootCid, fetchedCids)`
  6. Forward `paymentToken` to each serving Drop
  7. Ack `{ chunks: [...] }` — null entries for unavailable (not a 403)
- `Safe/chunk/challenge` — `selectDrops([cid])` -> `callDrop(Safe/drop/challenge)` ->
  verify `SHA-256(ciphertext||tag) === cid`; log failure to reliability score on mismatch/null
- `Safe/peer/connect` — v1 stub: log and ack null
- `disconnect` — mark `drop.offlineSince = Date.now()`, emit `dropOffline`

**HTTP routes:**
- `GET /Safe/chunk/:cid`:
  - No `PAYMENT-SIGNATURE` header → 402 with `PAYMENT-REQUIRED` (x402 spec)
  - Invalid signature / insufficient balance → 402
  - Chunk not found in `_cidIndex` → 404
  - On success: fetch from Drop, serve with Range support, `PAYMENT-RESPONSE` header
- `GET /Safe/subtree/:rootCid/:start/:end`:
  - Parse grants + payments from `X-OCP-Grants` / `X-OCP-Payments` headers (base64 JSON)
  - `verifySubtreeGrant` failure → 403 with JSON body `{ error, unauthorized, reason }`
  - `_checkPayerBalance` failure → 402 with x402 body
  - Success → same logic as socket get → JSON response body
- `PUT /Safe/subtree`:
  - Parse grants + payments from body JSON
  - Same 403/402 logic as socket put
  - Success → JSON response body `{ results }`

**Grace-period sweep:**
```js
var GRACE_MS = Q.Config.get(['Safe', 'drop', 'offlineGraceMs'], 60000);
setInterval(function () {
  var now = Date.now();
  for (var dropId in Safe.drops) {
    var drop = Safe.drops[dropId];
    if (drop.offlineSince && (now - drop.offlineSince) > GRACE_MS) {
      Safe.emit('dropDisconnect', drop);
      delete Safe.drops[dropId];
      delete _dropProllyStores[dropId];
    }
  }
}, GRACE_MS);
```

---

### Safe Server Events

```js
Safe.on('dropRegister',      function (drop) { })
Safe.on('dropReconnect',     function (drop) { })
Safe.on('dropAnnounce',      function (drop) { })
Safe.on('dropOffline',       function (drop) { })
Safe.on('dropDisconnect',    function (drop) { })
Safe.on('dropSync',          function (drop, changes) { })   // Prolly diff
Safe.on('dropColdSync',      function (drop, prollyRoot) { })
Safe.on('dropBloom',         function (drop, bloomFilter) { })
Safe.on('dropChallengeFail', function (drop, cid) { })
Safe.on('dropSlash',         function (drop, payload) { })
```

---

## Part 6 — Implementation Order

Each step only calls things already above it in this list.

**Server (classes/Safe/Jets.js):**

1. `_storeForDrop(dropId)` — pure in-memory store factory
2. `Safe._evmProvider(chainId)` — ethers.JsonRpcProvider lazy init
3. `Safe._checkPayerBalance(payer, token, amount, chainId)` — calls `_evmProvider`
4. `Safe.callDrop(drop, method, payload, timeoutMs)` — socket.io ack promise wrapper
5. `Safe.selectDrops(cids, options)` — v1 round-robin; delegates to `Safe.Router`
6. `Safe.verifySubtreeGrant(grants, rootCid, start, end)` — returns `{ ok, unauthorized, reason }`
7. `Safe.verifyStreamAccess(userId, publisherId, streamName, level, callback)` — calls Streams.fetchOne
8. `Safe.buildMerkleProofs(rootCid, cids)` — calls `Q.Data.Merkle.proof`
9. `Safe._reconcileDropInventory(drop, prollyRoot)` — calls `_storeForDrop`, `Q.Data.Prolly.diff`
10. `Safe._attachBloomFilter(drop, bloomFilter)` — calls `Q.Data.Bloom`
11. `Safe_request_handler(req, res, next)` — PHP->Node handler
12. `Safe.listen(options)` — wires all socket.io + HTTP handlers + grace sweep

**Client (web/js/Safe/Jets.js):**

13. `_dropId()` — sessionStorage stable ID
14. `_jetUrl()` — URL resolution
15. `_ab2b64(buf)` / `_b642ab(b64)` — serialisation helpers
16. `_withSocket(fn)` — queue-or-execute helper
17. `_scheduleReconnect()` — exponential backoff
18. `Q.Safe.Jets.connect(callback)` — Q.Socket.connect + event wiring + drain
19. `Q.Safe.Jets.put(subtree, options, callback)` — Safe/subtree/put emit
20. `Q.Safe.Jets.get(subtree, options, callback)` — Safe/subtree/get emit
21. `Q.Safe.Jets.dropRegister(info, callback)` — fetches Prolly root + Bloom -> register
22. `Q.Safe.Jets.dropAnnounce(info, callback)` — announce emit
23. `Q.Safe.Jets.dropDisconnect(callback)` — disconnect emit + sessionStorage clear
24. `Q.Safe.Jets.dropClaimPayments(payload, callback)` — claimPayments emit
25. Default `onDropPut` handler — wires to `Q.Safe.Drops.put`
26. Default `onDropGet` handler — wires to `Q.Safe.Drops.get`
27. Default `onDropChallenge` handler — returns chunk bytes; Jet verifies CID

---

## Part 7 — What is NOT in Jets

- Chunk encryption or decryption — Cloud only
- Capability production (`grant()`) — Cloud only
- Merkle tree construction — Cloud's `store()` builds it; Jets generates proofs
  from the stored CID index (`_cidIndex`)
- Key derivation — Cloud only
- Service worker management — Cloud only
- Prolly tree construction on the Drop side — `Q.Safe.Drops` only
- Bloom filter construction — `Q.Safe.Drops` only; Jets only receives and queries
- IndexedDB storage — Drops only
- On-chain OCP payment execution — Assets plugin only (`Q.Assets.OpenClaim`);
  Jets only pre-checks balances and forwards tokens to PHP for execution
- SafeBux ERC-20 contract interaction — PHP/blockchain layer; Jets only relays claims
- DHT peer discovery and Jet-to-Jet relay — pluggable via `Jets.Router`;
  full specification in `Jets.Router.md` (separate document)
- x402 facilitator role — Jets is the resource server, not the facilitator;
  it verifies payment signatures locally but does not relay to Coinbase CDP
- Stream management (creating/closing streams) — Streams plugin only;
  Jets only reads stream access levels for authorization checks
