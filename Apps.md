# Safecloud — Application Platform

## Table of Contents

- [Overview](#overview)
- [Terminology](#terminology)
- [V1 scope](#v1-scope)
- [Architecture](#architecture)
  - [The stack](#the-stack)
  - [Comparison to traditional hosting](#comparison-to-traditional-hosting)
- [SafecloudApps](#safecloudapps)
  - [What a SafecloudApp is](#what-a-safecloudapp-is)
  - [App manifest](#app-manifest)
  - [Sandboxing and metering](#sandboxing-and-metering)
  - [App registration](#app-registration)
  - [Host API](#host-api)
- [SafecloudEnvelope](#safecloudenvelope)
  - [Envelope format](#envelope-format)
  - [Well-known types](#well-known-types)
  - [App-defined types](#app-defined-types)
- [SafecloudReceipts and SafecloudChains](#safecloudreceipts-and-safecloudchains)
  - [Execution receipts](#execution-receipts)
  - [Hash chain structure](#hash-chain-structure)
  - [Verification and replay](#verification-and-replay)
  - [Composable handlers](#composable-handlers)
- [Authentication and access control](#authentication-and-access-control)
  - [OCP claims as authentication](#ocp-claims-as-authentication)
  - [Key release as access control](#key-release-as-access-control)
  - [Example handlers](#example-handlers)
- [SafecloudDB integration](#safeclouddb-integration)
  - [Tracks as application state](#tracks-as-application-state)
  - [Schema patterns](#schema-patterns)
- [Dynamic sites](#dynamic-sites)
  - [Route handling](#route-handling)
  - [Request-response cycle](#request-response-cycle)
  - [Session state](#session-state)
  - [Composable WASM modules](#composable-wasm-modules)
- [Metrics and analytics](#metrics-and-analytics)
  - [Privacy-preserving analytics](#privacy-preserving-analytics)
  - [Aggregation patterns](#aggregation-patterns)
- [Auto-scaling and economics](#auto-scaling-and-economics)
  - [Market-driven scaling](#market-driven-scaling)
  - [Compute pricing](#compute-pricing)
  - [Redundancy and availability](#redundancy-and-availability)
- [Safebox integration](#safebox-integration)
  - [Confidential compute](#confidential-compute)
  - [Trust model comparison](#trust-model-comparison)
- [Comparison to other platforms](#comparison-to-other-platforms)
  - [Locutus](#locutus)
  - [Autonomi / SAFE Network](#autonomi--safe-network)
  - [Cloudflare Workers](#cloudflare-workers)
- [Example applications](#example-applications)
  - [DMCA compliance](#dmca-compliance)
  - [Streaming with pay-per-view](#streaming-with-pay-per-view)
  - [Subscription service](#subscription-service)
  - [Social platform](#social-platform)
- [Triggers](#triggers)
  - [What triggers are](#what-triggers-are)
  - [Trigger format](#trigger-format)
  - [Condition types](#condition-types)
  - [How triggers execute](#how-triggers-execute)
  - [Trigger management](#trigger-management)
  - [Determinism and triggers](#determinism-and-triggers)
- [Outbound endpoints](#outbound-endpoints)
  - [The problem](#the-problem)
  - [Outbound endpoint registry](#outbound-endpoint-registry)
  - [Host API extension](#host-api-extension)
  - [Secrets management](#secrets-management)
  - [Determinism and outbound calls](#determinism-and-outbound-calls)
- [Rooms and E2E encrypted chat](#rooms-and-e2e-encrypted-chat)
  - [Chat as a SafecloudApp](#chat-as-a-safecloudapp)
  - [Room structure](#room-structure)
  - [Epoch-based key management](#epoch-based-key-management)
  - [Room handlers](#room-handlers)
  - [Message ordering and consistency](#message-ordering-and-consistency)
  - [Group size and performance](#group-size-and-performance)
  - [Offline message delivery](#offline-message-delivery)
  - [Interop with outbound endpoints](#interop-with-outbound-endpoints)
- [Attack vectors](#attack-vectors)

---

## Overview

Safecloud's storage layer (Drops) and coordination layer (Jets) already provide encrypted, content-addressed storage with micropayment-driven availability. This document describes how Jets become a general-purpose application platform by executing SafecloudApps — turning Safecloud from a storage network into a full compute + storage + auth stack with no traditional servers. See also [AdaptiveStreamer.md](AdaptiveStreamer.md) (adaptive drop selection, serving policy, micropayment ramping).

The core insight: Jets already manage key release. A SafecloudApp generalizes "who gets keys" into "who gets what, under what rules." Key release becomes one type of response among many. The Jet becomes a programmable server. The WASM defines the rules. The rules are content-addressed, auditable, and deterministic.

The result is a serverless application platform where:

- **Compute** is permissionless Jets running sandboxed WASM, paid per fuel consumed.
- **Storage** is permissionless Drops holding encrypted chunks, paid per byte stored and served.
- **State** is SafecloudDB — prolly trees stored as encrypted chunks on Drops, read and written by WASM.
- **Auth** is OCP claims — the same cryptographic delegation used everywhere else in the protocol.
- **Payments** are Safebux — the same micropayment rail used for storage.
- **Encryption** is the default. There is no plaintext mode. Access control is key release, enforced by WASM.

No servers to rent. No databases to manage. No deploy pipelines. Publish your WASM, define your SafecloudDB schema, ship a static frontend. Any Jet can serve your app. The network auto-scales because supply follows demand through Safebux pricing.

---

## Terminology

All Safecloud-specific concepts are prefixed with "Safecloud" to avoid ambiguity with generic terms:

| Term | What it is |
|---|---|
| **SafecloudApp** | A WASM application: a manifest of handlers + libraries at a content-addressed CID. |
| **SafecloudHandler** | An individual WASM function within an app that handles a specific request type and returns a SafecloudEnvelope. |
| **SafecloudEnvelope** | The standard typed response format returned by every handler execution, with a proof block. |
| **SafecloudReceipt** | An execution receipt recording what WASM ran, what inputs it saw, what output it produced, and what state it changed. Signed by the Jet. |
| **SafecloudChain** | An append-only hash chain of SafecloudReceipts, stored as a SafecloudDB track. Tamper-evident computation log. |
| **SafecloudDB** | The database layer. Prolly trees (SafecloudTree) stored as encrypted chunks (SafecloudStore) on Drops. Per-track HKDF-derived encryption keys. |
| **SafecloudTree** | The prolly tree implementation (~600 lines). Content-defined B-tree with Dolt-style boundary function. |
| **SafecloudStore** | The encrypt/chunk/store adapter (~30 lines). Encrypt → chunk → store → return CID. |

Terms that are NOT prefixed — they are either proper nouns or shared across layers:

| Term | What it is |
|---|---|
| **Drops** | Storage nodes. Hold encrypted chunks, paid per byte. |
| **Jets** | Coordination/compute nodes. Run SafecloudApps, manage key release, paid per fuel. |
| **Safebux** | The micropayment unit. Pays for storage, compute, and bandwidth. |
| **OCP** | Open Cryptographic Protocol. Delegation-based auth used throughout Safecloud. |
| **Safebox** | Confidential compute tier. TEE-based execution for workloads that need hardware attestation. |
| **Safenet** | The overlay network connecting Drops, Jets, and clients. |

---

## V1 scope

SafecloudApps in v1 are **handlers + SafecloudDB + SafecloudEnvelopes**. A handler receives a request, reads and writes SafecloudDB tracks, and returns a typed envelope. That is the full execution model.

Things that are explicitly **not** in SafecloudApps v1:

- **Workflows** (multi-step orchestration with branching, retries, and state machines).
- **Tools** (callable capabilities with schema validation and sandboxed side effects).
- **Capabilities** (fine-grained permission manifests for what a handler may access).
- **LLM inference** (running models inside WASM).
- **Credential management** (storing and releasing third-party secrets).
- **Governance** (multi-party approval for sensitive actions).

All of these exist in Safebox, which runs them on confidential hardware at full native speed. They may migrate to SafecloudApps in a future version, but v1 keeps the Jet execution model simple: request → WASM → envelope. Safebox and SafecloudApps share vocabulary (SafecloudEnvelope, SafecloudReceipt, SafecloudChain) so that receipts from both tiers are interoperable.

---

## Architecture

### The stack

```
┌─────────────────────────────────────────────┐
│  Static site (HTML/JS/CSS)                  │  UI + custom type handlers
│  Hosted on Safecloud or any CDN             │  Talks to Jets via SafecloudEnvelope
├─────────────────────────────────────────────┤
│  Standard client (JS)                       │  Transport, auth, well-known type dispatch
│  Q.Safecloud.Client in the browser          │  Handles key-release, pagination, errors
├─────────────────────────────────────────────┤
│  SafecloudApp WASM (at CIDs)                │  App logic, runs on Jets
│  Sandboxed, metered, deterministic          │  Reads/writes SafecloudDB, returns envelopes
├─────────────────────────────────────────────┤
│  SafecloudDB (prolly trees)                 │  Application state
│  Encrypted chunks on Drops                  │  Per-track HKDF-derived keys
├─────────────────────────────────────────────┤
│  Safecloud (chunks on Drops)                │  Encrypted storage
│  Content-addressed, replicated              │  Safebux-incentivized availability
├─────────────────────────────────────────────┤
│  OCP claims                                 │  Auth for everything
│  Safebux                                    │  Payment for everything
└─────────────────────────────────────────────┘
```

### Comparison to traditional hosting

| Traditional | Safecloud | Difference |
|---|---|---|
| EC2 / Lambda | Jets (SafecloudApp WASM) | Permissionless, market-priced, any operator |
| S3 | Drops (encrypted chunks) | Encrypted by default, content-addressed, replicated by incentive |
| RDS / DynamoDB | SafecloudDB (prolly trees) | Encrypted, version-controlled (every root CID is a snapshot), no admin access to plaintext |
| IAM | OCP claims | Cryptographic delegation, no central authority, works across operators |
| KMS | HKDF key trees + SafecloudApp handlers | Key hierarchy built into the data structure, handler-driven release |
| CloudFront | Drop network + clients as temporary CDN | Encrypted cache everywhere, viewers re-serve ciphertext |
| Auto Scaling | Safebux market pricing | Supply follows demand because serving is profitable |
| VPC / Security Groups | Encryption by default | No plaintext anywhere, no network perimeter to defend |
| Nitro Enclaves | Safebox TEEs | Available when confidential compute is needed, not required otherwise |
| CloudWatch | SafecloudChains + metrics WASM | Verifiable, tamper-evident, computed by the same platform |
| Route 53 / DNS | CID addressing | Works with DNS but doesn't require it |

---

## SafecloudApps

### What a SafecloudApp is

A SafecloudApp is a set of WASM handlers and reusable libraries, bundled in a manifest and stored on Safecloud at a content address (CID). Each handler defines the rules for a specific request type — key release, takedown processing, route handling, metrics aggregation. When a request arrives at a Jet, the Jet loads the relevant handler WASM, provides it with the request and access to SafecloudDB state, and executes it. The handler returns a typed SafecloudEnvelope. The Jet delivers the envelope to the caller.

The app CID is public. Anyone can download the WASM binaries, decompile them, and inspect the rules. This is the transparency property — the rules are not hidden in a server you can't inspect.

Because WASM is deterministic (no threads, no randomness, no system calls unless the host provides them), the same handler + the same inputs always produces the same output. This is the verifiability property — any party can replay a computation and confirm the result.

### App manifest

A SafecloudApp manifest declares its handlers and libraries:

```json
{
  "v": 1,
  "name": "dmca-compliance",
  "handlers": {
    "on_key_request":  "bafy...handler1",
    "on_takedown":     "bafy...handler2",
    "on_counter":      "bafy...handler3",
    "GET /status":     "bafy...handler4"
  },
  "libraries": [
    "bafy...auth-lib",
    "bafy...safebux-lib"
  ],
  "schema": {
    "tracks": ["takedowns", "counter-notices", "audit-log"]
  }
}
```

**Handlers** are named WASM entry points. Each handler CID points to a WASM binary that exports a single function. Handler names can be event-style (`on_key_request`, `on_takedown`) or route-style (`GET /status`, `POST /api/subscribe`). The Jet dispatches incoming requests to the matching handler.

**Libraries** are shared WASM modules that handlers can import. Auth checks, Safebux balance queries, common data transformations — anything reusable across handlers goes in a library. Libraries are content-addressed like everything else; updating a library means publishing a new CID and updating the manifest.

**Schema** declares which SafecloudDB tracks the app uses. This is informational (the host API doesn't enforce it in v1) but useful for tooling, documentation, and future capability restrictions.

### Sandboxing and metering

Jet operators run untrusted WASM from arbitrary publishers. Safety comes from the WASM sandbox model, which is battle-tested in production systems (Cloudflare Workers, Fastly Compute, Wasmtime):

- **Memory cap.** Each WASM instance gets a fixed memory limit (e.g. 16 MB). Attempts to grow beyond it trap the instance.
- **Fuel metering.** Each WASM instruction consumes fuel. When fuel runs out, execution halts. This prevents infinite loops and bounds computation cost. The Jet sets the fuel budget based on the Safebux payment attached to the request.
- **Wall-clock timeout.** A hard time limit on top of fuel, to catch edge cases where instruction count is low but elapsed time is high (e.g. the host API is slow).
- **No ambient authority.** The WASM module cannot access the filesystem, network, other modules' memory, or any system resource. It can only call the host API the Jet explicitly provides.
- **Determinism.** WASM has no sources of nondeterminism by default. The host API provides controlled inputs (request data, SafecloudDB reads, timestamps from the SafecloudChain). Same inputs, same outputs.

### App registration

A developer registers a SafecloudApp with a Jet:

```
POST /Safecloud/apps/register
{
  appCid:     "bafy...",         // the SafecloudApp manifest CID
  contentCid: "bafy...",         // content this app governs (optional)
  deposit:    1000               // Safebux deposit for compute costs
}
```

If `contentCid` is provided, the app governs key release and access to that specific content. If omitted, the app is a general application — it handles any request routed to it.

Multiple Jets can register the same app. The caller picks a Jet (or the client auto-selects based on latency, price, or reputation). Because the WASM is deterministic, all Jets produce the same result for the same inputs.

### Host API

The Jet exposes a narrow API to the WASM instance. This is the entire surface area — the WASM cannot do anything else. No WASI needed; the Jet injects these functions directly.

```
// Merkle tree operations (generalized storage)
fn tree_create(name: &str) -> TreeId
fn tree_append(tree: TreeId, value: &[u8]) -> (u64, Proof)    // append-only log
fn tree_get(tree: TreeId, index: u64) -> (Vec<u8>, Proof)     // read by index
fn tree_put(tree: TreeId, key: &[u8], value: &[u8]) -> Proof  // key-value write
fn tree_range(tree: TreeId, opts: RangeOpts) -> Iterator<(Vec<u8>, Vec<u8>)>
fn tree_delete(tree: TreeId, key: &[u8]) -> Proof
fn tree_root(tree: TreeId) -> Cid                              // current root hash
fn tree_checkpoint(tree: TreeId) -> Cid                        // flush state to Drops
fn tree_hydrate(root_cid: Cid) -> TreeId                       // load tree from Drops
fn tree_diff(cid_a: Cid, cid_b: Cid) -> Vec<Change>           // diff two checkpointed states

// Legacy KV aliases (operate on a default tree in KV mode)
fn safedb_get(track: &str, key: &[u8]) -> Option<Vec<u8>>
fn safedb_range(track: &str, gte: &[u8], lte: &[u8]) -> Iterator<(Vec<u8>, Vec<u8>)>
fn safedb_put(track: &str, key: &[u8], value: &[u8])
fn safedb_delete(track: &str, key: &[u8])

// Read request context
fn request_claim() -> Option<OCPClaim>    // caller's auth claim
fn request_params() -> Map<String, String> // request parameters
fn request_body() -> Vec<u8>              // request body

// Controlled inputs
fn now() -> u64                           // logical timestamp (chain position)
fn random_seed() -> [u8; 32]              // deterministic seed from request hash

// Return response
fn respond(envelope: SafecloudEnvelope)

// Call another handler (composable)
fn call(handler_cid: &str, input: &[u8]) -> SafecloudEnvelope
```

The `tree_*` functions are the primary storage API. Trees support two access patterns: append-only log (`tree_append` / `tree_get` by index) and key-value (`tree_put` / `tree_range` / `tree_delete`). Both produce Merkle proofs on every operation. Trees checkpoint transparently to Drops — the Jet maintains an in-memory cache with a write-ahead log (WAL) on local disk, flushing asynchronously to content-addressed storage. On Jet restart or failover, `tree_hydrate(rootCid)` reconstructs the tree from Drops. This makes all SafecloudApp state portable across Jets.

The `safedb_*` functions remain as aliases for backward compatibility. They operate on a default tree using the KV access pattern, with `track` as a namespace prefix on keys.

---

## SafecloudEnvelope

### Envelope format

Every response from a Jet handler execution is wrapped in a SafecloudEnvelope:

```json
{
  "v": 1,
  "type": "safecloud/key-release",
  "payload": { },
  "proof": {
    "jetId":      "...",
    "appCid":     "bafy...",
    "handlerCid": "bafy...",
    "stateRoot":  "bafy...",
    "receiptCid": "bafy...",
    "signature":  "..."
  }
}
```

The `proof` block commits the Jet to: "I ran this handler (`handlerCid`) from this app (`appCid`) against this SafecloudDB state (`stateRoot`), produced this result, and logged it as this receipt (`receiptCid`)." The signature covers the entire envelope. Anyone can verify it against the Jet's public key.

### Well-known types

The standard Safecloud client JS handles these types natively:

| Type | Client action |
|---|---|
| `safecloud/key-release` | Decrypt specified chunks using the provided keys |
| `safecloud/key-revoke` | Purge specified keys from memory |
| `safecloud/data` | Generic data response, passed to app handler |
| `safecloud/cursor` | Paginated result set; client can request next page |
| `safecloud/error` | Display error to user, with code and message |
| `safecloud/redirect` | Follow redirect to another Jet or handler |
| `text/html` | Render as page (dynamic site response) |
| `application/json` | Parse and pass to app handler |

### App-defined types

App developers register custom type handlers on the client:

```js
client.registerHandler('com.example/recommendation', function (envelope) {
    renderRecommendationCard(envelope.payload);
});
```

The type namespace follows reverse-domain convention. The standard client dispatches on the type string — well-known types are handled internally, everything else goes to registered handlers. Unrecognized types with no handler are logged and ignored.

---

## SafecloudReceipts and SafecloudChains

### Execution receipts

Every handler execution on a Jet produces a SafecloudReceipt:

```json
{
  "v": 1,
  "prevReceiptCid": "bafy...",
  "appCid":         "bafy...",
  "handlerCid":     "bafy...",
  "inputHash":      "sha256:...",
  "outputHash":     "sha256:...",
  "stateRootBefore": "bafy...",
  "stateRootAfter":  "bafy...",
  "fuelConsumed":   42000,
  "memoryPeak":     8388608,
  "jetId":          "...",
  "timestamp":      1697500000,
  "signature":      "..."
}
```

The receipt records what ran (`appCid`, `handlerCid`), what it saw (`inputHash`, `stateRootBefore`), what it produced (`outputHash`, `stateRootAfter`), and how much it cost (`fuelConsumed`, `memoryPeak`). The Jet signs it.

### Hash chain structure

SafecloudReceipts form a SafecloudChain: each receipt includes the CID of the previous receipt (`prevReceiptCid`). This produces an append-only, tamper-evident log of all computations a Jet has performed for a given app. Inserting, removing, or modifying a receipt breaks the chain.

The chain is stored as a SafecloudDB track (`receipts/{appCid}`). Anyone with read access to the track can walk the chain and verify its integrity.

### Verification and replay

To verify a Jet's claim:

1. Fetch the SafecloudReceipt from the SafecloudChain.
2. Fetch the handler WASM by its CID.
3. Fetch the SafecloudDB snapshot at `stateRootBefore`.
4. Reconstruct the input from the `inputHash` (the input is available in the request log or from the caller).
5. Run the WASM on the input against the SafecloudDB snapshot.
6. Compare: the output hash should match `outputHash`, and the resulting SafecloudDB state should match `stateRootAfter`.

If they don't match, the Jet lied. The receipt (signed by the Jet) is cryptographic proof of the lie — a Proof of Corruption, handled by the same slashing mechanism described in Protocol.md.

### Composable handlers

A SafecloudHandler can call another handler via `call()`. Each sub-call produces its own SafecloudReceipt. The parent receipt references the child receipts, forming a tree:

```
SafecloudReceipt: key-release handler
├── SafecloudReceipt: age-verify handler   → caller is 18+
├── SafecloudReceipt: payment handler      → caller paid 5 Safebux
└── SafecloudReceipt: geo-check handler    → caller in allowed jurisdiction
    → all passed → release keys for chunks 0-100
```

The full tree is verifiable. This is the same pattern as Safebox deterministic workflows — a chain of invocations with a verifiable trace — but running on commodity Jets with transparency instead of hardware attestation.

---

## Authentication and access control

### OCP claims as authentication

Every request to a Jet can carry an OCP claim — a cryptographically signed delegation from a key that has authority over some resource. The handler inspects the claim and decides what to do.

This is the same OCP infrastructure used throughout Safecloud (see Protocol.md). No new auth system. No usernames and passwords. No OAuth. The caller's key IS their identity, and their claim IS their permission.

### Key release as access control

Encryption is the access control mechanism. Data is always ciphertext. Access means receiving decryption keys. The handler decides whether to release keys based on the caller's claim and whatever rules the handler encodes.

This is stronger than traditional access control: there is no admin backdoor, no database dump, no "root access." A Drop operator stores ciphertext they cannot read. A Jet operator runs WASM that decides whether to release keys — but the keys themselves are managed by the HKDF tree and the OCP delegation chain, not stored in the Jet's memory. The Jet can release a derived key for a specific chunk range; it never holds the root key.

### Example handlers

**Pay-per-view streaming:**
```
on_key_request(claim, params):
  chunks = params.chunkRange
  cost = chunks.length * PRICE_PER_CHUNK
  if safebux.balance(claim.holder) < cost:
    return error("insufficient balance")
  safebux.charge(claim.holder, cost)
  return key_release(chunks)
```

**Subscription access:**
```
on_key_request(claim, params):
  sub = safedb_get("subscriptions", claim.holder)
  if !sub or sub.expires < now():
    return error("subscription expired")
  return key_release(params.chunkRange)
```

**DMCA-aware key release:**
```
on_key_request(claim, params):
  takedowns = safedb_range("takedowns", params.contentCid, params.contentCid)
  for td in takedowns:
    if td.status == "active":
      counter = safedb_get("counter-notices", td.id)
      if !counter or counter.deadline > now():
        return error("content unavailable due to takedown")
  // no active takedown
  return key_release(params.chunkRange)
```

**Admin dashboard:**
```
on_request(claim, params):
  if !verify_admin_claim(claim):
    return error("unauthorized")
  metrics = safedb_range("metrics/views", params.from, params.to)
  return data("application/json", aggregate(metrics))
```

---

## SafecloudDB integration

### Tracks as application state

A SafecloudHandler reads and writes SafecloudDB tracks. Each track is a prolly tree (SafecloudTree) with its own HKDF-derived encryption key, stored as encrypted chunks (SafecloudStore) on Drops. See Database.md for the full SafecloudDB design. The WASM host API provides get, range, put, and delete operations on tracks.

Tracks are the application's database tables. A DMCA app has `takedowns`, `counter-notices`, and `audit-log` tracks. A streaming service has `subscriptions`, `watch-history`, and `metrics` tracks. A social platform has `users`, `posts`, `follows`, and `notifications` tracks.

### Schema patterns

Common SafecloudDB key patterns for app state:

```
Track: users
  key: {publicKey}                → { displayName, created, ... }

Track: posts
  key: {timestamp}/{postId}       → { author, contentCid, ... }  (sorted by time)

Track: follows
  key: {follower}/{followed}      → { since }

Track: subscriptions
  key: {subscriberKey}            → { plan, expires, ... }

Track: takedowns
  key: {contentCid}/{takedownId}  → { claimant, reason, status, filed }

Track: receipts/{appCid}
  key: {timestamp}/{receiptCid}   → SafecloudReceipt
```

---

## Dynamic sites

### Route handling

Jets can serve dynamic pages on standard hostnames. An operator points a domain's DNS at their Jet (or a set of Jets behind a load balancer), and the Jet routes requests to the appropriate SafecloudHandler based on the hostname and path. From the browser's perspective, it's a normal website — HTTPS, cookies, HTML responses. The WASM backend is invisible to the user.

Multiple Jets can serve the same hostname. DNS round-robin, anycast, or a lightweight proxy distributes requests. Because the handler WASM is deterministic and the SafecloudDB state is shared, every Jet produces the same response for the same request. There is no primary server.

The request-response cycle mirrors HTTP:

```
Browser → Jet
  Jet loads route handler (by CID from SafecloudApp manifest)
  WASM receives: { method, path, params, claim, body }
  WASM reads SafecloudDB, applies logic
  WASM returns: { type: "text/html", payload: "<html>..." }
Jet → Browser
```

The WASM is the backend. SafecloudDB is the database. The Jet is the server. No PHP, no MySQL, no hosting provider.

### Request-response cycle

```json
// Input to WASM handler
{
  "method": "GET",
  "path":   "/posts/latest",
  "params": { "limit": "10" },
  "claim":  { "holder": "...", "type": "session", ... },
  "body":   null
}

// Output from WASM handler (wrapped in SafecloudEnvelope)
{
  "v": 1,
  "type": "text/html",
  "payload": "<!doctype html><html>...",
  "headers": {
    "cache-control": "private, max-age=60"
  }
}
```

### Session state

User sessions are SafecloudDB tracks keyed by session token. The handler issues a session token (a random value from the deterministic seed, hashed with the user's public key), writes session state to SafecloudDB, and returns it as a cookie or header. Subsequent requests include the token; the handler reads the session track to restore state.

Because SafecloudDB is replicated across Drops, session state is available from any Jet. There is no session affinity. The user can hit any Jet running the same app and get the same session.

### Composable WASM modules

A dynamic site can be composed from multiple handlers — one per feature or route group. The SafecloudApp manifest maps routes to handler CIDs:

```json
{
  "handlers": {
    "GET /login":     "bafy...auth",
    "POST /login":    "bafy...auth",
    "GET /posts/*":   "bafy...posts",
    "POST /posts":    "bafy...posts",
    "GET /profile/*": "bafy...profile",
    "GET /admin/*":   "bafy...admin"
  }
}
```

This is a plugin architecture. Install a feature by adding handler CIDs to the manifest. Remove it by publishing a new manifest without them. Update it by publishing new handler WASM and updating the CID. Each handler has its own SafecloudReceipts in the SafecloudChain.

---

## Metrics and analytics

### Privacy-preserving analytics

Jets process key-release requests. Each request is a data point — which content CID was requested, which chunk range, when, by whom (if authenticated). The Jet can aggregate these into SafecloudDB tracks without ever seeing the content itself. The content is encrypted; the Jet sees request patterns against opaque CIDs.

This gives content creators analytics without surveillance:

- **View counts.** How many key-release requests per CID per day.
- **Watch depth.** How many chunks were requested per session (proxy for how much of a video was watched).
- **Segment heatmaps.** Which chunk ranges get re-requested (the parts people rewatch or re-read).
- **Temporal patterns.** When content is consumed (time of day, day of week).
- **Unique viewers.** Count of distinct caller keys (or anonymous distinct sessions).

None of this requires seeing the plaintext content or tracking users across sites.

### Aggregation patterns

A metrics handler maintains aggregation tracks:

```
Track: metrics/views
  key: {contentCid}/{day}           → { count, uniqueCallers, totalChunks }

Track: metrics/segments
  key: {contentCid}/{chunkStart}    → { replayCount, avgWatchDepth }

Track: metrics/top
  key: {period}/{rank}              → { contentCid, score }

Track: metrics/featured
  key: {contentCid}                 → { featuredBy, since, position }
```

"Most watched this week" is a range scan on `metrics/top`. "Which part of this video do people rewatch" is a range scan on `metrics/segments`. "Featured content" is a track that an admin-claim holder can write to.

---

## Auto-scaling and economics

### Market-driven scaling

There are no auto-scaling groups, no capacity planning, no Kubernetes clusters. The market is the autoscaler:

- **Demand increases** → serving requests becomes more profitable → more Jets run the app → capacity rises.
- **Demand decreases** → serving becomes less profitable → Jets deprioritize the app → capacity falls.
- **Storage demand increases** → storing chunks pays more → more Drops replicate them → redundancy rises.

This is the same mechanism that makes Bitcoin mining scale with price. The difference is that the "work" is useful application logic, not hash grinding.

### Compute pricing

Jets meter WASM execution and charge Safebux:

- **Fuel consumed.** Each WASM instruction costs fuel. More complex handlers cost more. The Jet sets a price-per-fuel-unit.
- **Memory-seconds.** Peak memory × execution time. A handler that allocates 16 MB for 100 ms costs more than one that uses 1 MB for 10 ms.
- **SafecloudDB I/O.** Reads and writes to SafecloudDB tracks have a per-operation cost.
- **Bandwidth.** The SafecloudEnvelope size contributes to cost.

Jets compete on price. A Jet with cheaper hardware or better optimization can undercut competitors. Callers pick Jets based on price, latency, and reputation.

### Redundancy and availability

Content and state are replicated by the storage layer (Drops), not the compute layer (Jets). A Jet going offline doesn't lose any data — another Jet loads the same SafecloudApp WASM and the same SafecloudDB state and serves the same requests. The SafecloudDB root CID is the state — any Jet with access to the Drops can load it.

This is a fundamental advantage over traditional hosting: the compute layer is stateless and fungible. Any Jet can replace any other Jet instantly. There is no failover delay, no data migration, no DNS propagation. The content-addressing makes the substitution transparent.

---

## Safebox integration

### Confidential compute

A regular Jet runs WASM transparently — the Jet operator can observe the WASM's I/O (inputs, outputs, SafecloudDB reads/writes). For most applications this is fine: the rules are public, the data is encrypted, and the Jet only sees request metadata.

For applications that require confidential computation — where even the request metadata or the computation itself must be hidden from the operator — the Jet runs inside a Safebox (TEE). Hardware attestation proves the WASM ran unmodified inside the enclave. The operator cannot observe or tamper with the execution.

SafecloudApps can declare which handlers run on which tier. A streaming service might run its `on_key_request` handler on regular Jets (cheap, transparent) but declare its `on_recommend` handler as Safebox-only (user watch history stays confidential).

### Trust model comparison

| Property | Jet (transparent) | Safebox Jet (confidential) |
|---|---|---|
| Rules visible to operator | Yes (WASM is public) | No (enclave is sealed) |
| I/O visible to operator | Yes (request/response metadata) | No (all inside enclave) |
| Verifiable by client | Yes (replay WASM + SafecloudDB snapshot) | Yes (TEE attestation) |
| Hardware requirement | None (commodity server) | TEE-capable (Intel SGX, ARM TrustZone) |
| Cost | Lower | Higher |
| Use cases | Key release, DMCA, metrics, dynamic sites | Sealed auctions, private matching, secret key ops |
| Execution model | SafecloudApp handlers only | Handlers + workflows + tools + capabilities |

Both tiers produce SafecloudReceipts. A receipt from a Safebox Jet includes the TEE attestation alongside the WASM execution proof. The SafecloudChain format is the same — the trust anchor differs (transparency vs hardware).

---

## Comparison to other platforms

### Locutus

Locutus (formerly Freenet 2) has nodes decrypt and execute WASM contracts. Nodes see plaintext data during execution. Trust comes from the assumption that nodes are distributed and no single node controls the full picture.

Safecloud separates concerns: Jets execute SafecloudApp handlers but never see the content (it stays encrypted; Jets manage key release, not decryption). When confidential computation is needed, Safebox provides hardware-attested isolation. This gives stronger privacy guarantees than Locutus's trust-the-executing-node model, at the cost of requiring TEE hardware for the confidential tier.

### Autonomi / SAFE Network

Autonomi assigns storage responsibility to network-managed sections and uses datachains (append-only logs of section membership events) for forensic accountability. Safecloud uses market-based storage (Drops self-select) and content-addressing for integrity. Autonomi's datachains solve the "which group was responsible when data went missing" problem; Safecloud doesn't have this problem because storage responsibility is individual (each Drop) and content-addressing makes data integrity instantly verifiable (wrong data = wrong CID).

Safecloud's SafecloudChains serve a different purpose: they log WASM computation, not storage responsibility. They're closer to a blockchain's transaction log than to Autonomi's membership chain.

### Cloudflare Workers

Cloudflare Workers run WASM on Cloudflare's edge network. The sandboxing model is similar (V8 isolates with memory and CPU limits). The differences:

- **Permissionless vs permissioned.** Anyone can run a Safecloud Jet. Only Cloudflare runs Workers.
- **Encrypted by default vs opt-in.** Safecloud data is always encrypted. Workers data is plaintext unless the developer encrypts it.
- **Verifiable vs trusted.** SafecloudReceipts make computation verifiable. Workers computation is trusted (you trust Cloudflare).
- **Payment.** Safecloud uses Safebux micropayments. Workers uses a subscription/usage billing model tied to a Cloudflare account.

The developer experience is analogous: write a WASM module, deploy it, it runs on distributed infrastructure. Safecloud adds encryption, verifiability, and permissionless operation.

---

## Example applications

### DMCA compliance

A content platform operator publishes a SafecloudApp with DMCA handlers:

1. `on_takedown` — accepts takedown notices (authenticated by OCP claims from registered DMCA agents), writes takedown records to the `takedowns` SafecloudDB track.
2. `on_key_request` — checks for active takedowns before releasing keys. Stops releasing keys for taken-down content.
3. `on_counter` — accepts counter-notices (authenticated by the content owner's claim), starts a 10-14 day waiting period, resumes key release if no lawsuit notification arrives.
4. Every action is logged to the SafecloudChain for legal auditability.

No backend server. No database admin. The DMCA logic is WASM binaries at CIDs. Any Jet runs them. The SafecloudChain is the legal paper trail.

### Streaming with pay-per-view

A content creator publishes a SafecloudApp with a streaming handler:

1. `on_key_request` receives a key-release request for a chunk range.
2. Charges Safebux per chunk (shown to users as per-minute pricing).
3. Releases keys for paid chunks only.
4. Enforces a 120-second sliding window (keys expire, client must re-request for rewind beyond the window).
5. Aggregates viewing metrics to SafecloudDB tracks.

Viewers pay per second of actual viewing. Rewinding costs more. The creator earns Safebux. The Jet earns a percentage for compute. The Drops earn for storage and bandwidth. Everyone is paid by the same micropayment rail.

### Subscription service

A SafecloudApp with subscription handlers:

1. `on_key_request` checks the caller's subscription status in the `subscriptions` SafecloudDB track. Releases keys for all content if the subscription is active. Returns a payment-required error if expired.
2. `GET /signup` serves the signup flow as a dynamic page.
3. `POST /subscribe` processes payment and writes a subscription record.

### Social platform

A SafecloudApp composed of multiple handlers:

- **auth handlers** — signup, login (session tokens via SafecloudDB), profile management.
- **post handlers** — create, read, update, delete posts. Posts are encrypted content on Safecloud; metadata is in SafecloudDB.
- **social handlers** — follow/unfollow, friend requests, notifications.
- **feed handlers** — compute personalized feeds from follows and post metadata.
- **moderation handlers** — content flagging, admin actions, ban list.

Each handler group uses its own SafecloudDB tracks. All share a single SafecloudChain. The static frontend talks to the Jet. The entire platform runs on permissionless Jets and Drops with no traditional backend.

---

## Triggers

### What triggers are

A trigger is a rule stored in a SafecloudDB track that fires a handler when a condition is met. The handler that fires is the same kind of WASM handler described above — it receives a request, reads and writes SafecloudDB, and produces a SafecloudEnvelope. The difference is that the request comes from the system rather than a client.

Triggers let SafecloudApps react to events without the client polling. A subscription service can fire a handler when a subscription expires. A social platform can fire a handler when a post reaches a view threshold. A DMCA handler can fire when a takedown waiting period ends.

### Trigger format

Triggers are stored in the `triggers/{appCid}` SafecloudDB track:

```json
{
  "id":          "trg_abc123",
  "handlerCid":  "bafy...handler",
  "condition": {
    "type":    "schedule",
    "cron":    "0 * * * *"
  },
  "params":      { "action": "sweep-expired" },
  "enabled":     true,
  "createdBy":   "holder-public-key",
  "fuelBudget":  500000
}
```

### Condition types

| Condition type | Fires when | Example |
|---|---|---|
| `schedule` | Cron expression matches current time | Hourly sweeps, daily aggregation |
| `track-write` | A key is written to a specified track | New post → update feed index |
| `track-match` | A track value matches a predicate | `subscriptions/{key}.expires < now()` → send expiry notice |
| `chain-receipt` | A new receipt is added to a specified chain | Cross-app composition: app B reacts to app A's receipts |
| `threshold` | A numeric track value crosses a boundary | View count > 1000 → feature the content |

### How triggers execute

The Jet runs a trigger evaluator loop. On each tick (configurable, default 60 seconds for schedule triggers), the evaluator:

1. Scans the `triggers/{appCid}` track for enabled triggers whose conditions are met.
2. For each matching trigger, constructs a request with `method: "TRIGGER"`, the trigger's params as the request params, and the trigger record as the request body.
3. Executes the handler WASM in the same sandbox as any other handler invocation — same fuel metering, same memory limits, same SafecloudReceipt production.
4. If the handler calls `respond()`, the response is stored in a `trigger-results/{appCid}` track (clients can poll or subscribe to this track for trigger outcomes).
5. The trigger execution produces a SafecloudReceipt in the same SafecloudChain as client-initiated executions. There is no separate audit trail — triggers and client requests share one chain.

Track-write and track-match triggers fire synchronously within the same Jet tick that produced the write, before the write's SafecloudReceipt is finalized. This guarantees that a trigger's side effects are included in the same state transition. If the trigger handler fails, the original write still succeeds — the trigger failure is logged as a separate receipt.

### Trigger management

Triggers are managed through the same handler architecture. An app's manifest can include a `manage-triggers` handler that accepts requests to create, update, enable, disable, and delete triggers. This handler enforces whatever access control the app requires — only the app owner, only admin-claim holders, or open to all users.

The host API for triggers adds two functions:

```
// Schedule a trigger (from inside a handler)
fn trigger_set(trigger: TriggerRecord)
fn trigger_delete(trigger_id: &str)
```

These are sugar for `safedb_put("triggers/{appCid}", ...)` with validation — the Jet rejects malformed trigger records, cron expressions that fire more frequently than the Jet's minimum interval, and fuel budgets that exceed the Jet's per-trigger cap.

### Determinism and triggers

Schedule triggers present a determinism challenge: two Jets running the same app may evaluate the cron at slightly different wall-clock times. The resolution: the trigger evaluator snaps to the SafecloudChain's logical timestamp, not wall time. The chain's timestamp advances monotonically (each receipt's timestamp is the previous receipt's timestamp + 1). The cron evaluator uses this logical time. Two Jets with the same chain state evaluate the same set of triggers, producing the same receipts.

Track-write and track-match triggers are inherently deterministic — they fire from the same write, against the same state, producing the same result.

---

## Outbound endpoints

### The problem

The host API described above is deliberately narrow: the WASM can read and write SafecloudDB, read the request, and respond. It cannot make HTTP requests, open sockets, or reach external systems. This is by design — unrestricted network access would break determinism (two Jets hitting the same API at different times get different results) and create security risks (WASM making arbitrary requests from the Jet's IP).

But real applications need to talk to external systems. A payment handler needs to verify a charge with Stripe. A notification handler needs to send an email or push notification. A bridge handler needs to post to a Telegram channel or Discord webhook.

### Outbound endpoint registry

The solution: outbound endpoints are declared in the SafecloudApp manifest, not discovered at runtime. The app developer registers a set of external URLs that the app's handlers are allowed to contact, with schemas for the requests and responses.

```json
{
  "v": 1,
  "name": "my-app",
  "handlers": { ... },
  "outbound": {
    "stripe-charge": {
      "url":    "https://api.stripe.com/v1/charges",
      "method": "POST",
      "headers": { "Authorization": "Bearer {{secret:stripe_key}}" },
      "schema": {
        "request":  { "type": "object", "properties": { "amount": { "type": "integer" }, "currency": { "type": "string" } } },
        "response": { "type": "object", "properties": { "id": { "type": "string" }, "status": { "type": "string" } } }
      },
      "rateLimit": { "maxPerMinute": 60 }
    },
    "send-email": {
      "url":    "https://api.sendgrid.com/v3/mail/send",
      "method": "POST",
      "headers": { "Authorization": "Bearer {{secret:sendgrid_key}}" },
      "rateLimit": { "maxPerMinute": 100 }
    },
    "telegram-webhook": {
      "url":    "https://api.telegram.org/bot{{secret:tg_token}}/sendMessage",
      "method": "POST",
      "rateLimit": { "maxPerMinute": 30 }
    }
  }
}
```

### Host API extension

Two new host API functions for outbound calls:

```
// Make an outbound HTTP request to a declared endpoint
fn outbound_call(endpoint_name: &str, body: &[u8]) -> OutboundResult

// Check outbound result (for async patterns)
fn outbound_status(call_id: &str) -> OutboundStatus
```

`outbound_call` is synchronous from the WASM's perspective — the handler blocks until the external request completes or times out. The Jet enforces the declared rate limits, validates the request body against the endpoint's schema, and injects the configured headers (including secrets that the WASM never sees).

### Secrets management

Outbound endpoints reference secrets via `{{secret:name}}` placeholders in headers and URLs. Secrets are stored in a `secrets/{appCid}` SafecloudDB track, encrypted under the app owner's key. The Jet decrypts them at request time using a key-release flow: the app owner grants the Jet a derived key that can decrypt only the secrets track, not the app's other data. The WASM handler never sees the secret values — it calls `outbound_call("stripe-charge", body)` and the Jet handles authentication.

This is the same HKDF-derived key pattern used throughout Safecloud. The secret is encrypted at rest (in SafecloudDB on Drops), decrypted only by the Jet at the moment of the outbound call, and never exposed to the WASM sandbox.

### Determinism and outbound calls

Outbound calls break determinism: the external service may return different results at different times, or be unreachable. This is handled by recording the outbound call and its result in the SafecloudReceipt:

```json
{
  "outboundCalls": [
    {
      "endpoint": "stripe-charge",
      "requestHash": "sha256:...",
      "responseHash": "sha256:...",
      "statusCode": 200,
      "durationMs": 142
    }
  ]
}
```

During replay/verification, the verifier uses the recorded outbound responses rather than re-calling the external service. The receipt commits the Jet to the specific external response it received. If the Jet fabricates an outbound response, the mismatch is detectable: the response hash in the receipt won't match what the external service would have returned for that request. This is weaker than pure-WASM verification (the verifier must trust the recorded external response or re-call the service themselves), but it provides an auditable trace.

Handlers that require strict determinism should avoid outbound calls. Outbound-dependent handlers are marked as `non-deterministic` in their receipts, and clients can choose to trust only deterministic receipts for high-stakes operations.

---

## Rooms and E2E encrypted chat

### Design principles

The chat architecture is shaped by two constraints: (1) Jets see only ciphertext — they cannot read messages, identify senders, or correlate who talks to whom; (2) the Jet's role is minimal — it is a durable append-only log, not a message router. Real-time delivery happens peer-to-peer. Notifications go through a Safebox push gateway.

This is not a separate system bolted onto Safecloud. A room is a Merkle tree on a Jet. Messages are opaque blobs appended to the tree. The cryptographic protocol (bidirectional hash chains, per-message keys, epoch transitions) runs entirely on clients. The Jet provides ordering and persistence; clients provide encryption, decryption, and real-time delivery.

### Room as a Merkle tree

A room is a set of named trees on a Jet:

```
Tree: rooms/{roomId}/messages    (append-only log of ciphertext blobs)
Tree: rooms/{roomId}/state       (KV: encrypted epoch records, encrypted member list)
```

The `messages` tree is append-only. Each entry is an opaque encrypted blob. The Jet assigns a monotonic position index on append — position 42, 43, 44. This index is the canonical ordering. There is no wall-clock timestamp in the envelope; the blob's tree index is its logical time. Inside the encrypted payload, the sender may include a display timestamp visible only to members after decryption.

The `state` tree holds encrypted room metadata: epoch records (chain seeds encrypted per-member), the encrypted member list, and room configuration. The Jet stores this as opaque KV entries — it cannot read the membership list or determine who is in the room.

### What the Jet sees

The Jet knows: a tree ID received an append at a certain time, and the blob is N bytes (padded). The Jet does not know: who authored the blob (onion routing), what the blob contains (encryption), who the room's members are (encrypted state), or even that this tree is a "chat room" rather than a file index or application state — all trees look identical at the protocol level.

### Real-time delivery via WebRTC

When room members are online simultaneously, they establish a WebRTC mesh (data channels). Messages are encrypted under the room's current epoch key and sent directly between peers. Delivery is immediate — no Jet in the latency path.

The Jet acts as a TURN relay when NAT hole-punching fails. It relays encrypted DTLS traffic between peers without being able to read it.

For rooms with more than ~20 concurrent members, a full mesh is impractical. Large rooms can use a Safebox as a selective forwarding unit (SFU), attested not to log the forwarded traffic.

A rotating batch submitter (selected per round using shared epoch randomness invisible to the Jet) collects the last N messages and submits them to the Jet's tree for persistence. The Jet sees one submission from a rotating pubkey — it cannot determine which member authored which message in the batch.

### Persistence via onion-routed append

Every message is also appended to the room's tree on a Jet for durability and offline delivery. To prevent the destination Jet from learning who authored each message, the sender routes the encrypted blob through 2 intermediate Jets using onion routing:

1. Alice encrypts the message blob and wraps it in 2 onion layers.
2. Alice posts the outer layer to Jet A via HTTPS (looks like a normal chunk upload).
3. Jet A peels one layer, forwards to Jet B (looks like normal inter-Jet chunk replication).
4. Jet B peels the last layer, forwards to Jet C (the destination).
5. Jet C receives an opaque blob from another Jet — indistinguishable from replicated chunk traffic — and appends it to the room's tree.

No single Jet in the chain knows both the sender and the destination tree. The entry Jet knows Alice's IP but not where the blob is going. The destination Jet knows the tree but not who sent the blob. Collusion between entry and destination Jets would be needed to link sender to room — the same threat model as Tor, mitigated by the same approach (choose entry nodes carefully, add hops for higher anonymity).

### Epoch-based key management

Each room uses the bidirectional hash-chain epoch protocol described in Ecosystem.md. The forward chain provides forward secrecy; the backward chain provides post-compromise security.

The per-message key is `K_msg = HKDF(F_k || B_k || roomId || msgIndex)` where `F_k` and `B_k` are the k-th values of the forward and backward hash chains for the current epoch, `roomId` prevents cross-room key reuse, and `msgIndex` prevents within-message-index key reuse.

Epoch transitions occur on member join/leave and periodically (every N messages or T hours). New chain seeds are distributed to all current members, encrypted under each member's public key, and stored in the room's state tree. The Jet stores these as opaque KV entries.

For groups with more than ~100 members, a key tree (binary tree of HKDF derivations) reduces epoch-transition cost from O(n) to O(log n).

### Room handlers

The chat SafecloudApp has two categories of handlers:

**Tree handlers (run on the Jet):** These are minimal — the Jet's WASM handler for message submission just validates payment (Safebux), appends the opaque blob to the tree, and returns a proof. It does not check membership or epochs because it cannot read the blob or the encrypted state.

```json
{
  "handlers": {
    "submit-blob":      "bafy...submit",
    "get-range":        "bafy...query",
    "submit-state":     "bafy...state"
  }
}
```

**`submit-blob`**: Validates Safebux payment, calls `tree_append(messagesTree, blob)`, returns the position index and Merkle proof. The handler is deliberately simple — it appends and returns.

**`get-range`**: Returns a range of blobs by position index. Pagination via tree range queries. No access control at the Jet level — the blobs are encrypted, so anyone who fetches them still needs the epoch keys to read them.

**`submit-state`**: Updates the encrypted state tree (epoch records, member list). Used during epoch transitions and membership changes.

**Client-side logic:** All room management — creating rooms, inviting members, removing members, epoch transitions, key exchange — happens on the client. The client writes encrypted state updates to the Jet's state tree via `submit-state`. Other members sync the state tree to learn about membership changes and new epoch seeds.

### Offline delivery and failover

When a member comes online after being away, their client syncs the room's message tree from the last-seen position index: `tree_range(messagesTree, {gte: lastSeen})`. They also sync the state tree to pick up any epoch transitions that occurred while offline. New epoch seeds are encrypted under their public key in the state tree.

If a Jet goes down, any other Jet can pick up the room: `tree_hydrate(rootCid)` reconstructs the tree from Drops. Members reconnect to the new Jet and continue from the last checkpoint. Payment switches to the new Jet (Safebux). The room is portable because the state is in the tree on Drops, not on any particular Jet.

### Push notifications via Safebox gateway

Web Push requires VAPID keys. Letting every Jet hold VAPID keys and push endpoints creates a spam vector — a malicious or buggy Jet could push unlimited notifications with no recourse.

Notifications go through a Safebox push gateway: a TEE-attested service that holds the VAPID keys and user push subscriptions. When a new blob appears in a room's tree, the Jet submits a push request to the gateway with an OCP claim proving it hosts the room. The gateway verifies the claim, checks per-user rate limits, encrypts the notification payload under the user's `notify` key, signs with VAPID, and sends via Web Push.

The gateway is the only entity with push endpoints. Jet failover does not require new push subscriptions. Users configure rate limits per room via OCP claims ("at most 10 pushes per hour from room X"). The gateway enforces the policy.

This is also the integration point between Safecloud's pull model and Intercloud's push model. The Safebox push gateway can subscribe to Intercloud rails on behalf of users, receive push events from the event layer, and deliver notifications that reference Safecloud CIDs. The user's client pulls the referenced content when they want to see it. See Architecture.md for the full picture of how the pull and push layers compose.

### Interop with outbound endpoints

Chat rooms can be bridged to external platforms using the outbound endpoint system. A trigger fires on each new blob in the messages tree. The trigger handler calls `outbound_call("telegram-webhook", ...)` to post a notification. For a full bridge (forwarding decrypted plaintext), the bridge handler must hold a member key, making it a visible participant in the room. Bridged messages appear in the SafecloudChain as outbound-call receipts, maintaining the audit trail.

---

## SafecloudApp deployment

### Deployment interfaces

**CLI (`@safecloud/cli` via npm):** The primary developer tool. A `cli/` directory in the Safecloud repo containing `index.js` and `package.json`, installed via `npm install -g @safecloud/cli`. The CLI calls canonical Client.js methods — the same SDK that runs in the browser.

```
safecloud deploy ./my-app        # chunk directory, upload to Drops, register manifest
safecloud dev --handler ./h.wasm # local Jet emulator, test against mock requests
safecloud hash ./handler.wasm    # compute CID
safecloud manifest init          # generate manifest skeleton
safecloud manifest validate      # check manifest references valid CIDs
```

**Zip upload:** POST a zip file to the Jet's admin endpoint. The Jet unpacks, chunks, stores on Drops, and registers the manifest. For non-developers who want to host a static site.

**Web dashboard:** A SafecloudApp itself — static HTML+CSS+JS hosted on a Jet, calling the Client.js SDK. Drag-and-drop deploy UI, manifest editor, logs viewer.

### Access control via OCP Actions

App ownership and deployment use the OCP Actions Extension (https://openclaiming.org/ActionsExtension). The app manifest has an owner public key. Operations are authorized by OCP action claims:

- **Owner** (`iss` = owner key): can update handlers, change policies, transfer ownership, delete the app.
- **Deployer** (delegated via OCP `delegate` claim): can update handler CIDs and static asset CIDs. Cannot change ownership or policies.
- **Admin** (delegated): can change policies and manage deployer roles. Cannot transfer ownership.

Single owner by default. Multi-owner (M-of-N multisig) uses the Actions Extension's quorum mechanism — `minimum` and `fraction` fields enforce required approvals, with an optional `delay` before execution.

### Standard includes

Every SafecloudApp can load standard libraries from the hosting Jet:

```html
<script src="/@safecloud/client.js"></script>  <!-- encryption, key mgmt, Drops -->
<script src="/@safecloud/drop.js"></script>    <!-- content-addressed storage ops -->
<script src="/@safecloud/app.js"></script>     <!-- App.db.*, App.auth.*, App.ws.*, App.push.* -->
<link rel="stylesheet" href="/@safecloud/app.css">  <!-- reset, typography, responsive, dark mode -->
```

Pinned versions: `/@safecloud/client@2.8.js`. The Jet resolves these paths to the current release CIDs.

For embedding (e.g., the video player on a third-party site), the iframe accepts a `css` querystring parameter: `?css=https://example.com/brand.css` or `?css=inline:body{background:%23000}`. The app's loader injects the custom CSS after the default theme.

---

## Attack vectors

| Attack | Risk | Defense |
|---|---|---|
| **Malicious WASM** — handler with hidden behavior | 🟢 Low | WASM is content-addressed and public. Anyone can decompile and audit it. Users choose which apps to trust, like choosing which app to install. |
| **Jet lies about execution** — returns wrong result | 🟢 Low | SafecloudChain commits the Jet to its inputs and outputs. Client can replay and detect lies. Proof of Corruption triggers slashing. |
| **Jet censors requests** — refuses to serve | 🟡 Medium | Multiple Jets can run the same app. Caller switches to another Jet. Market competition discourages censorship. |
| **SafecloudChain tampering** — Jet modifies past receipts | 🟢 Low | Hash chain: modifying any receipt breaks the chain. Clients and other Jets can detect the break. |
| **Resource exhaustion** — WASM consumes excessive resources | 🟢 Low | Fuel metering + memory caps + wall-clock timeout. Jet halts execution when limits are exceeded. |
| **Tree state manipulation** — Jet writes incorrect state | 🟡 Medium | Merkle tree with root CID: every state transition produces a new root. Clients verify proofs. Replay against the tree from Drops detects inconsistency. |
| **Side-channel on Jet** — operator observes I/O patterns | 🟡 Medium | For transparent Jets: the Jet sees tree IDs and blob arrival times but not senders (onion routing) or content (encryption). For confidential workloads: Safebox Jets (TEE). |
| **App upgrade attack** — creator silently swaps WASM | 🟡 Medium | App CID is committed at registration. Changing the app means a new CID, visible to all users. Clients can pin an app CID and refuse upgrades. |
| **Fuel price manipulation** — Jet charges excessive Safebux | 🟢 Low | Market competition. Multiple Jets serve the same app. Callers pick the cheapest. Price gouging loses customers. |
| **Trigger abuse** — app registers triggers that fire excessively | 🟢 Low | Jet enforces minimum interval and per-trigger fuel budget. Trigger evaluator uses chain logical time, not wall clock. |
| **Outbound endpoint abuse** — WASM makes unauthorized external requests | 🟢 Low | Only declared endpoints in the manifest are reachable, with rate limits and schema validation enforced by the Jet. Secrets are never exposed to the sandbox. |
| **Outbound response fabrication** — Jet fakes an external service response | 🟡 Medium | Response hash is committed in the SafecloudReceipt. Verifier can re-call the service to check. Receipts are marked non-deterministic. |
| **Epoch key compromise** — attacker obtains current chain seeds | 🟡 Medium | Forward chain limits forward exposure; backward chain limits backward exposure. Next epoch transition rotates both chains. Periodic automatic transitions bound the exposure window. |
| **Garbage escrow** — sender escrows a fake key for media | 🟡 Medium | Detectable when threshold group decrypts — garbage key produces garbage plaintext. Detection is evidence of deliberate evasion. |
| **Modified chat client** — client skips scanning and escrow | 🟡 Medium | Text: unavoidable (same gap as Signal). Media: Jet rejects media messages without valid escrow ciphertext. |
| **Push notification spam** — malicious Jet floods user with notifications | 🟢 Low | Jets cannot push directly. Notifications go through a Safebox push gateway with OCP-verified rate limits. The gateway is the only entity with VAPID keys and push endpoints. |
| **Metadata correlation on chat** — Jet links senders to rooms | 🟢 Low | Onion routing (2 hops) prevents the destination Jet from knowing the sender. The Jet sees only blob arrival from another Jet, indistinguishable from chunk replication. |
