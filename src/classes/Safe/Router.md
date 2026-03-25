# Safe.Router — Implementation Design Document

## Table of Contents

- [Part 1 — Key Design Decisions](#part-1--key-design-decisions)
  - [1.1 Responsibilities: Safe.Router vs Safe.Jets](#11-responsibilities-saferouter-vs-safejets)
  - [1.2 The pairwise SafeBux marketplace](#12-the-pairwise-safebux-marketplace)
  - [1.3 Drops connecting to multiple Jets](#13-drops-connecting-to-multiple-jets)
  - [1.4 Hyperswarm for Jet peer discovery](#14-hyperswarm-for-jet-peer-discovery)
  - [1.5 Pairwise EVM identity and hello handshake](#15-pairwise-evm-identity-and-hello-handshake)
  - [1.6 Second-level Prolly tree — Jets syncing Drop inventories](#16-second-level-prolly-tree--jets-syncing-drop-inventories)
  - [1.7 Routing announcements — Drop co-signed, Jet-named](#17-routing-announcements--drop-co-signed-jet-named)
  - [1.8 Availability events — first/last Drop transitions](#18-availability-events--firstlast-drop-transitions)
  - [1.9 Pairwise topic subscriptions between Jets](#19-pairwise-topic-subscriptions-between-jets)
  - [1.10 Relay authentication — Noise-derived bearer tokens](#110-relay-authentication--noise-derived-bearer-tokens)
  - [1.11 Drop selection — weighted routing](#111-drop-selection--weighted-routing)
  - [1.12 Deduplication — CID-level and request coalescing](#112-deduplication--cid-level-and-request-coalescing)
  - [1.13 CoC gossip over hyperswarm](#113-coc-gossip-over-hyperswarm)
  - [1.14 Pluggable interface](#114-pluggable-interface)
- [Part 2 — External interfaces](#part-2--external-interfaces)
  - [hyperswarm v3](#hyperswarm-v3)
  - [Q.Data.Prolly (Jet-level tree)](#qdataprolly-jet-level-tree)
  - [ethers.js (balance pre-check)](#ethersjs-balance-pre-check)
  - [Safe.Jets internal state consumed by Router](#safejets-internal-state-consumed-by-router)
- [Part 3 — Wire formats](#part-3--wire-formats)
  - [safecloud.jet.hello](#safecloudjetheello)
  - [safecloud:routing-announcement (OCP)](#safecloudrouting-announcement-ocp)
  - [safecloud:drop-availability (OCP)](#safeclouddrop-availability-ocp)
  - [safecloud:corruption (CoC)](#safecloudcorruption-coc)
  - [Relay request: GET /Safe/relay/{rootCid}/{start}/{end}](#relay-request-get-saferelayrooticdstartend)
  - [Noise bearer token derivation](#noise-bearer-token-derivation)
- [Part 4 — Jet-level Prolly tree](#part-4--jet-level-prolly-tree)
  - [Structure and ordering](#structure-and-ordering)
  - [Maintenance lifecycle](#maintenance-lifecycle)
  - [Syncing between Jets](#syncing-between-jets)
- [Part 5 — Safe.Router public interface](#part-5--saferouter-public-interface)
  - [Safe.Router.selectForGet(cid, options)](#saferouterselectforgetcid-options)
  - [Safe.Router.selectForPut(cids, options)](#saferouterselectforputcids-options)
  - [Safe.Router.relayGet(subtree, options)](#saferouterrelaygetsubtree-options)
  - [Safe.Router.announce(rootCid, event)](#saferouterannounce-rootcid-event)
  - [Safe.Router.gossipCoC(coc)](#saferoutergossipcococ)
  - [Safe.Router.peerJets()](#saferouterpeernjets)
- [Part 6 — Implementation Order](#part-6--implementation-order)
- [Part 7 — What is NOT in Router.js](#part-7--what-is-not-in-routerjs)

---

This document is the authoritative spec for `plugins/Safe/classes/Safe/Router.js`
— the pluggable routing layer that `classes/Safe/Jets.js` delegates all Drop
selection, Jet-to-Jet peering, relay, and CoC gossip to via `Safe.Router.*`.

Read `Protocol.md` (Edge 2), `Jets.md`, and `Drops.md` first. The naming
convention throughout is `Safe.*` (server-side classes): `Safe.Jets`,
`Safe.Router`, `Safe.Drops`. The browser-side counterparts are
`Q.Safe.Jets` and `Q.Safe.Drops`.

---

## Part 1 — Key Design Decisions

### 1.1 Responsibilities: Safe.Router vs Safe.Jets

**Safe.Router** (`classes/Safe/Router.js`) is responsible for:
- Hyperswarm peer discovery (joining the `safecloud-jets` topic, handling connections)
- Pairwise Jet-to-Jet authentication via `safecloud.jet.hello` + session delegation
- Maintaining the second-level Prolly tree (union of all connected Drops' CIDs)
- Syncing the second-level Prolly tree with peer Jets
- Producing and verifying `safecloud:routing-announcement` OCP claims
  (Drop co-signed, Jet named — binds DHT announcements to actual inventory)
- Producing and verifying `safecloud:drop-availability` OCP claims
  (Jet-signed, gossiped on first/last Drop transitions)
- Pairwise topic subscriptions between Jets for availability events
- Selecting Drops for `put` and `get` requests (weighted by stake × reliability × storage)
- Relay fallback: `GET /Safe/relay/{rootCid}/{start}/{end}` to peer Jets
  (Jets pay each other for relay)
- CoC gossip over hyperswarm Noise connections
- Request coalescing and CID-level deduplication

**Safe.Jets** (`classes/Safe/Jets.js`) is responsible for:
- Accepting socket.io and HTTP connections from Cloud clients and Drops
- OCP Role A grant verification and Role B payment pre-screening
- Merkle proof attachment on `get` responses
- Chunk fan-out to Drops via socket.io push events
- Drop lifecycle management (`Safe.drops` state)
- PHP→Node internal messages

**The interface boundary:** Safe.Jets calls `Safe.Router.selectForGet(cid)`,
`selectForPut(cids)`, and `relayGet(subtree)` to get routing decisions. Jets
calls `Router.announce(rootCid, event)` when first/last Drop coverage changes.
Everything about peer discovery, inventory sync, and CoC propagation is Router's
concern. Safe.Jets never calls hyperswarm directly.

---

### 1.2 The pairwise SafeBux marketplace

SafeCloud is a **pairwise marketplace of zero-sum SafeBux transfers** for
services between peers. Every service rendered between adjacent nodes is
compensated with a micropayment, and every payment is balanced:

```
Safe.Cloud (browser)
    │  pays Jet in SafeBux
    │  OCP Role B, payer = cloudEVM, recipients = [jetEVM]
    ▼
Safe.Jets (Node.js) — Jet A
    │  pays Drop in SafeBux
    │  OCP Role B, payer = jetA_EVM, recipients = [dropEVM]
    ├──▶ Drop (browser IndexedDB)
    │
    │  pays peer Jet in SafeBux (for relay)
    │  OCP Role B, payer = jetA_EVM, recipients = [jetB_EVM]
    └──▶ Safe.Jets — Jet B
              │  pays Drop in SafeBux
              └──▶ Drop (browser IndexedDB)
```

Each arrow is an independent pairwise payment. Jet A earns from Cloud and
pays Drops and peer Jets. Jet B earns from Jet A's relay payment and pays
its own Drops. Drops earn from whichever Jets they serve.

**No participant is forced to transact with any other.** A Jet can refuse to
route requests from a Cloud client whose payment token has an insufficient
SafeBux balance. A Drop can refuse to serve a Jet whose balance check fails.
A Jet can refuse to relay for a peer Jet that consistently fails to pay. The
market enforces honest behavior without a central authority — if a participant
is overpriced, unreliable, or corrupt, counterparties simply route around them.

**Why this structure is zero-sum in SafeBux:** The total SafeBux in the
system does not change as it flows through the chain. Cloud loses SafeBux; Jets
gain some and lose some (their margin is the spread); Drops accumulate. The
only external entry point is SafeBux earned through honest storage service
accumulating on-chain via `paymentsExecute()`.

---

### 1.3 Drops connecting to multiple Jets

A Drop does not serve just one Jet. It connects to a small number of Jets
simultaneously (default `Q.Config.get(['Safe', 'drop', 'maxJets'], 3)`) using
`Q.Socket` connections — one persistent socket.io connection per Jet, each
to a different Jet URL discovered via the SafeCloud Jet directory or
configuration.

```
Drop (browser tab)
  ├── Q.Socket → Jet A  (registers, announces, serves chunks)
  ├── Q.Socket → Jet B  (registers, announces, serves chunks)
  └── Q.Socket → Jet C  (registers, announces, serves chunks)
```

**Each Jet-Drop pair is an independent bilateral relationship:**
- The Drop sends `Safe/drop/register` to each Jet separately
- Each Jet maintains its own Drop record and Prolly state for this Drop
- Payment tokens accumulate per-Jet (each Jet pays the Drop for chunks
  it routes through that Drop)
- The Drop's signed announce log is shared (same inventory), but the
  announce messages are sent independently to each Jet

**Why multiple Jets:** A Drop connected to only one Jet is a single point
of failure — if that Jet goes offline, the Drop earns nothing until it
reconnects. Multiple connections provide:
1. **Redundancy:** earnings continue even if one Jet is offline
2. **Load distribution:** multiple Jets can route requests concurrently
3. **Anonymity:** see below

**Anonymity of challenges:** When a Drop is connected to multiple Jets, a
spot-check request for a CID could have originated from:
- A Cloud client connected to Jet A
- A Cloud client connected to Jet B, whose request was relayed to Jet A
- Jet A itself issuing a silent spot-check
- Jet B itself issuing a spot-check via relay to Jet A

The Drop sees only "this Jet wants chunk X." It cannot determine the
ultimate origin. This anonymity is meaningful: a malicious actor who wants
to probe whether a specific Drop holds a specific CID cannot target it
directly — they can only see aggregate routing behavior from a Jet, which
pools requests from many sources.

---

### 1.4 Hyperswarm for Jet peer discovery

Jets use hyperswarm v3 (`holepunchto/hyperswarm`) for peer discovery on a
single well-known topic:

```js
const topic = crypto.createHash('sha256').update('safecloud-jets').digest();
swarm.join(topic, { server: true, client: true });
```

Every Jet announces as both server and client. When two Jets connect,
the transport is a Noise-encrypted duplex stream — all messages over that
connection are authenticated and encrypted at the transport layer.

**One hyperswarm connection per peer pair.** Router tracks live connections
in `_peers` keyed by `evmAddress` (not hyperswarm public key) because the
EVM address is the canonical identity. Duplicate connections (if hyperswarm
reconnects) are deduplicated on receipt of the `hello` message.

The hyperswarm connection is used only for:
- `safecloud.jet.hello` exchange and Prolly sync
- Availability event gossip (`safecloud:drop-availability`)
- Routing announcement gossip (`safecloud:routing-announcement`)
- CoC gossip (`safecloud.coc`)
- Pairwise subscription messages

Data transfer (actual chunk relay) goes over HTTPS — the Noise connection
is control plane only.

---

### 1.5 Pairwise EVM identity and hello handshake

Every Jet must prove ownership of its EVM address before any routing
information is trusted from it. The proof is the `safecloud.jet.hello`
message, sent immediately after hyperswarm connection establishment.

```
Jet A ──[hyperswarm Noise]──▶ Jet B
  │── safecloud.jet.hello ──▶  (url, evmAddress, delegation, secondLevelRoot)
  │◀── safecloud.jet.hello ─── (url, evmAddress, delegation, secondLevelRoot)
  │   [both verify delegation claims]
  │   [compare secondLevelRoot; initiate Prolly sync if different]
  │── safecloud.prolly.diff ──▶ (if roots differ)
  │◀── safecloud.prolly.diff.response
  │   [peer is now trusted for routing messages]
```

**What the delegation proves:** The `safecloud:session-delegation` OCP claim
in `hello.delegation` was signed by the Jet's wallet key. It binds an ES256
and EIP-712 session key to the wallet's EVM address. Once verified:
- All subsequent routing messages signed with those session keys are
  attributable to `hello.evmAddress`
- The EVM address can be queried on BSC for the Jet's SafeBux stake
- CoC evidence signed by those keys is attributable to that Jet

Jets are Node.js processes — no browser key management complexity. A Jet
loads its wallet key from an environment variable or secrets manager at
startup, runs the delegation ceremony once, and holds the session keypair
in process memory for the lifetime of the process.

**The `jetEVM` field, not `jetURL`:** A Jet's URL is mutable (domain migration,
load balancer changes). The EVM address is stable. Routing announcements and
availability claims reference `jetEVM`. Consumers resolve the current URL from
the most recent `safecloud.jet.hello` in their peer table.

---

### 1.6 Second-level Prolly tree — Jets syncing Drop inventories

Each Jet maintains a **second-level Prolly tree** over the union of all CIDs
held by its currently connected Drops. This gives peer Jets a compact
representation of what this Jet can serve.

**Structure:**
- Keys: CID strings, lexicographically ordered (same as Drop-level)
- Values: `dropEVMAddress` string — a **deterministic representative Drop**:
  the Drop whose EVM address sorts lowest (lexicographically) among all
  currently-connected Drops holding this CID
- Root: hex string

**Why not highest-stake Drop as the value:** Stake fluctuates continuously as
Drops earn SafeBux and as the graduated lockup releases tokens. Using the
highest-stake Drop as the canonical value would cause frequent value changes
that ripple through the Prolly tree, generating unnecessary root churn and
Jet-to-Jet sync traffic. The lowest-EVM-address representative is stable as
long as the set of Drops holding the CID doesn't change. Actual routing
decisions are stake-weighted via `_cidCoverage` and `selectForGet` — the
Prolly tree only records that coverage exists, not the current routing preference.

**Why CID as key with Drop as value, not a set:** Two Jets with identical
Drop inventories produce identical second-level roots — root comparison is
a reliable O(1) "same state" check. The value (Drop address) is a stable
coverage representative; it only changes when Drops join or leave, not when
stake fluctuates. A separate in-memory map `_cidCoverage[cid] = Set<dropId>`
tracks all Drops holding a CID for actual routing decisions.

**Why lexicographic CID ordering:** CIDs are content-addressed strings
(`bafy...`). Deterministic ordering means any two nodes building the same
tree from the same entries produce byte-identical roots, enabling root
comparison as a sync check.

**Syncing with peers:** On new peer connection, both sides exchange
`secondLevelRoot` in `hello`. If different, the connecting Jet sends a diff
request. Peer responds with the delta. This is O(diff) not O(total).

---

### 1.7 Routing announcements — Drop co-signed, Jet-named

A Jet announcing to the DHT that it can route requests for a `rootCid` must
carry proof that at least one Drop actually holds the content. A bare Jet
assertion has no accountability — the Jet could over-announce to attract
traffic it cannot serve.

The routing announcement is therefore a **jointly signed OCP claim**:

```json
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<Drop-EVM>",
  "sub": "safecloud:routing-announcement",
  "stm": {
    "rootCid":    "bafy...",
    "jetEVM":     "0x<Jet-BSC-address>",
    "prollyRoot": "<hex — Drop's current Prolly root>",
    "timestamp":  1700000000,
    "ttl":        300
  },
  "key": [
    "data:key/eip712,0x<Drop-EVM>",
    "data:key/eip712,0x<Jet-EVM>"
  ],
  "sig": [
    "<Drop EIP-712 r‖s‖v>",
    "<Jet EIP-712 r‖s‖v>"
  ]
}
```

Both sign the same canonical OCP envelope. The Drop signs first (via the
session EIP-712 key derived from `Q.Crypto.delegate`), sends back to the
Jet via a new `Safe/drop/signAnnouncement` event, and the Jet counter-signs
before broadcasting.

**Accountability:** If the Drop's `prollyRoot` does not contain `rootCid`,
the announcement is a lie attributable to the Drop's signed key — direct
CoC material. If the Jet routes to a Drop that fails to serve (no eviction
announce sent), it is attributable to the Jet's reliability record.

**TTL and withdrawal:** Announcements expire after `stm.ttl` seconds.
Jets refresh while the Drop remains connected. When the last Drop for a
`rootCid` disconnects, the Jet sends a withdrawal (`ttl: 0`). Consumers
discard expired announcements without needing an explicit withdrawal message.

---

### 1.8 Availability events — first/last Drop transitions

Router tracks `_cidCoverage[rootCid]` = count of connected Drops with that
rootCid. Transitions 0→1 and 1→0 trigger availability events gossiped to
subscribed peer Jets:

```json
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<Jet-EVM>",
  "sub": "safecloud:drop-availability",
  "stm": {
    "rootCid":    "bafy...",
    "event":      "available"|"unavailable",
    "jetEVM":     "0x<Jet-EVM>",
    "dropCount":  3,
    "prollyRoot": "<hex — Jet's second-level Prolly root>",
    "timestamp":  1700000000
  },
  "key": ["data:key/eip712,0x<Jet-EVM>"],
  "sig": ["<Jet EIP-712 r‖s‖v>"]
}
```

Signed by the Jet only — this is a routing-layer state notification, not a
storage commitment. `dropCount` is a quality signal: higher = more redundancy
= prefer this route.

**Why first/last only:** Sending an event for every individual Drop state
change would flood the network for popular content. The first/last model
sends exactly two events per file per availability epoch — one when it
becomes routable, one when it stops.

---

### 1.9 Pairwise topic subscriptions between Jets

Beyond DHT-wide announcements, Jets subscribe to specific peer Jets for
availability events on rootCids they care about. This is the pairwise
subscription layer — works without DHT, survives DHT partitions.

```json
{ "type": "safecloud.subscribe",   "rootCid": "bafy...", "ttl": 3600 }
{ "type": "safecloud.unsubscribe", "rootCid": "bafy..." }
```

`rootCid: null` means "subscribe to all availability events from this peer."
Subscriptions expire after `ttl` seconds; subscriber refreshes before expiry.

When a subscribed event fires, the publishing Jet sends the
`safecloud:drop-availability` OCP claim directly over the Noise connection
(in addition to any DHT broadcast). The subscriber updates its routing table
immediately — no polling required.

**Use case:** A Jet frequently routing requests for a specific file subscribes
to all known peers for that `rootCid`. It receives instant notification on
any peer availability change and can fail over without retrying stale routes.

---

### 1.10 Relay authentication — Noise-derived bearer tokens

Relay requests (`GET /Safe/relay/...`) are HTTPS and require authentication.
Both sides derive the same short-lived token from the Noise handshake shared
secret — no round-trip needed.

**Critical:** The token MUST be derived from the Noise handshake **shared
secret**, NOT from `conn.remotePublicKey`. The remote public key is public
information — anyone could compute the same HMAC from it, making the token
trivially forgeable. The shared secret is established during the Noise
handshake and is known only to the two connected parties.

```js
// Derive the shared secret from the Noise handshake.
// hyperswarm / noiseSecretStream exposes this as:
const sharedSecret = conn.handshakeHash;
// conn.handshakeHash is the 32-byte BLAKE2b hash of the full Noise
// handshake transcript — unique per connection, known only to both peers.
// Do NOT use conn.remotePublicKey (public) or conn.publicKey (local public key).

function deriveRelayToken(sharedSecret, localEVM, remoteEVM, windowSec) {
    const window = Math.floor(Date.now() / 1000 / windowSec);
    return crypto.createHmac('sha256',
            Buffer.concat([sharedSecret, Buffer.from('safecloud.relay.auth')]))
        .update(`${localEVM}:${remoteEVM}:${window}`)
        .digest('hex');
}
// windowSec = Q.Config.get(['Safe', 'relay', 'tokenWindowSec'], 300)
// Accepting Jet validates current window AND previous window (clock skew)
```

Both sides compute the same token independently because both hold the same
`handshakeHash` from the Noise session. The token is tied to this specific
connection — a captured token is useless to a third party who lacks the shared
secret, and is automatically invalidated when the Noise connection closes.

**Why Noise-derived, not wallet-signed:** The relay token proves "this
request came from the peer on this specific Noise connection" — exactly
what the Noise handshake hash represents. It is ephemeral and automatically
invalidated when the connection drops. No separate key management.

**Relay is a paid service.** The relaying Jet (Jet B) receives an OCP Role B
payment token from Jet A alongside the relay request, denominated in SafeBux.
`recipients = [jetB_EVM]`. Jet B verifies Jet A's SafeBux balance before
serving, the same way a Drop verifies a Jet's balance. The relay payment is
a first-class participant in the pairwise marketplace — Jet A earns from Cloud,
pays Drops directly for chunks they serve, and pays peer Jets for relay when
needed. The structure is symmetric at every hop.

**Relay payment non-atomicity:** The balance check at relay time is advisory,
not atomic with `paymentsExecute()`. Jet A may pass Jet B's balance pre-check
and then drain its balance before Jet B claims. At scale, this creates a
potential systematic free-riding attack: a Jet with a high but temporary
balance passes pre-checks across many peer Jets, drains funds, and never pays.

Jet B MUST mitigate this via layered defenses:
- **Safety margin:** `balance >= N × expected_relay_cost` (N = 2 default)
- **Per-peer credit limit:** Jet B tracks total unconfirmed relay value
  outstanding per peer Jet A. If `outstanding[jetA] > creditLimit`, Jet B
  requires on-chain confirmation of prior claims before serving new relay
  requests. `creditLimit = Q.Config.get(['Safe', 'relay', 'peerCreditLimitSafebux'], '10000')`
- **Stake threshold:** Jet B rejects relay from peer Jets whose SafeBux
  stake is below `Q.Config.get(['Safe', 'relay', 'minPeerStake'], '1000')`.
  Zero-stake Jets can neither relay nor earn relay payments.
- **Reliability degradation:** Failed payment claims permanently reduce the
  peer's `reliabilityScore`. Consistently underpaying peers are removed from
  the routing table. This creates lasting reputational consequences beyond any
  single episode.

Relay payment guarantees are ultimately economic, not cryptographic. The
graduated lockup (locked SafeBux cannot be transferred) means peer Jets
always have residual slashable stake even if they try to drain liquid balances.

---

### 1.11 Drop selection within a Jet — weighted routing

```js
weight(drop) = stakedSafebux(drop) * reliabilityScore(drop) * availableStorage(drop)
```

**`stakedSafebux`:** BSC `safebux.balanceOf(dropEVMAddress)`, cached 1 hour.
Zero stake → `weight = 0`. New Drops start at low priority; stake accumulates
through honest service.

**`reliabilityScore`:** In `[0, 1]`, exponential moving average:
- Initial: `0.5` (benefit of the doubt on first connection)
- Successful serve: `score = 0.9 * score + 0.1 * 1.0`
- Null response or timeout: `score = 0.9 * score + 0.1 * 0.0`
- Reconnect: `score = 0.25` (slight penalty for dropping offline)

**`availableStorage`:** `storage.GB - used_GB`, clamped to 0. Used for `put`
routing (prefer Drops with free space). For `get`, set to `1.0` (storage
availability doesn't affect ability to serve existing chunks).

**Probabilistic weighted selection:** Rather than always picking the
highest-weight Drop (concentrates load), Router uses weighted-random
selection among the top-N by weight (`N = 3` default). Load distributes
proportionally to weight while zero-weight Drops are never selected.

**Replication for put:** `replicationFactor` Drops selected
(`Q.Config.get(['Safe', 'put', 'replicationFactor'], 2)`), sent in parallel.
Success when `ceil(replicationFactor / 2)` acks received (simple quorum).

**Peer Jet trust bootstrap:** The same reliability principle applies to peer
Jets used for relay. Initial trust in a newly-connected peer Jet is limited —
stake proves economic commitment, but a new Jet can still misbehave initially.
Routing decisions for relay SHOULD weight peer Jets by observed reliability
over time, not just by stake. A peer Jet that is new (no observed history) is
treated like a new Drop: moderate initial `reliabilityScore` (`0.5`), building
toward full trust through successful relay completions. Jets that fail relay
requests, return inconsistent Prolly diffs, or have payment claim failures are
deprioritized progressively.

---

### 1.12 Deduplication — CID-level and request coalescing

**CID-level (storage):** The second-level Prolly tree maps one entry per
CID — `{ cid → highest-stake-Drop }`. This is the canonical routing target
for that CID; it does NOT imply that only one Drop holds it. Full coverage
is tracked separately in `_cidCoverage[cid] = Set<dropId>` for fallback
routing. When the preferred Drop returns null, Router consults `_cidCoverage`
for the next candidate before escalating to relay. Readers should not infer
from the Prolly tree structure that each CID has a single holder.

**Request coalescing (inflight):** If two Cloud clients request the same
CID simultaneously, Router issues one Drop request and broadcasts the result
to both callers:

```js
_inflight[cid] = Promise<chunk>   // set on first request, cleared on resolve/reject
```

Second and subsequent concurrent requests for the same CID await the same
promise. On resolution, all waiters receive the result simultaneously.
TTL: `Q.Config.get(['Safe', 'get', 'timeoutMs'], 10000)` ms.

**Coalescing timeout race:** Inflight coalescing is best-effort. If the
in-flight request times out, the promise rejects, the `_inflight[cid]` entry
is cleared, and any subsequent request reissues the Drop call independently.
Two requests may briefly overlap in the window between timeout and entry
clearance — this is acceptable (duplicate Drop reads for one CID) and
self-correcting. Coalescing is a performance optimisation, not a correctness
invariant.

**Why this matters in practice:** A popular video segment prefetched by
many simultaneous `_prefetchLoop` instances (from multiple Safe.Cloud viewers)
would otherwise hammer the same Drop with N identical reads for the same
IndexedDB key. Coalescing collapses N requests into one Drop read, N-fold
reduction in Drop load for popular content.

**Bloom filter pre-routing:** Before issuing a `Safe/drop/put` to a Drop,
Router checks the Drop's in-memory Bloom filter: if the filter says the Drop
likely already has the CID, the put is skipped for that Drop. This avoids
redundant network roundtrips for content the Drop already holds — the most
common case for popular files.

---

### 1.13 CoC gossip over hyperswarm

CoCs (Proofs of Corruption) travel over hyperswarm Noise connections — not
over socket.io. Each received CoC is validated before storing or forwarding.

**Acceptance criteria:**
1. CoC is validly signed by claimant's EVM key
2. Claimant's SafeBux stake ≥ `Q.Config.get(['Safe', 'coc', 'minClaimantStake'], '1000')`
3. All evidence claims are validly signed by the stated subject key
4. Not already seen (`SHA-256(canonicalJSON(coc))` not in `_cocStore`)
5. Claimant ≠ subject (no self-CoC)
6. **The contradiction MUST be objectively verifiable by any independent Jet
   using only the included evidence — no external state, no context beyond
   the `stm.evidence` array.** A CoC that requires external knowledge to
   evaluate is rejected as undecidable; the claimant loses their deposit.

**On receiving a valid CoC:**
1. Store in `_cocStore[cocHash]`
2. Forward to all connected peers with decremented `hopCount`
   (flood gossip, default `maxHops = 7`)
3. If subject is a connected Drop:
   - Add to `_corruptActors` set
   - Set `reliabilityScore(drop) = 0` (excluded from routing)
   - Emit `corruptActorDetected` event (Safe.Jets decides whether to disconnect)
4. If subject is a peer Jet:
   - Remove from routing table
   - Close Noise connection

**CoC wire envelope:**
```json
{
  "type":     "safecloud.coc",
  "hopCount": 7,
  "coc":      { <OCP safecloud:corruption claim> }
}
```

See Protocol.md § Proof of Corruption for full decidability rules, slash
mechanics, and the lottery model for distributing slashed stake.

---

### 1.14 Pluggable interface

`Safe.Router` is assigned on `Safe` before `Safe.listen()`:

```js
// Default (this file):
Safe.Router = require('./Router');

// Override with custom implementation (e.g. Kademlia DHT):
Safe.Router = require('./Router.Kademlia');
Safe.listen(options);
```

The interface contract:

```js
{
  init:          (options) => Promise<void>,
  selectForGet:  (cid,  options) => Promise<drop|null>,
  selectForPut:  (cids, options) => Promise<Array<drop>>,
  relayGet:      (subtree, options) => Promise<{chunks}|null>,
  announce:      (rootCid, event) => void,
  gossipCoC:     (coc) => void,
  peerJets:      () => Array<{ evmAddress, url, stake }>,
  // Lifecycle hooks called by Safe.Jets:
  onDropRegistered:   (drop, prollyRoot) => void,
  onDropAnnounce:     (drop, diff) => void,
  onDropDisconnected: (drop) => void
}
```

v1 default implementation (this file) provides: real hyperswarm discovery,
second-level Prolly tree, weighted Drop selection with reliability tracking,
Noise-authenticated relay with relay payments, and flood CoC gossip. Kademlia
XOR-distance routing is v2.

---

## Part 2 — External interfaces

---

### hyperswarm v3

```js
const Hyperswarm = require('hyperswarm');

// Stable keypair deterministically derived from Jet's EVM private key:
const noiseKeypair = deriveNoiseKeypair(evmPrivateKey);
const swarm = new Hyperswarm({ keyPair: noiseKeypair });

const topic = crypto.createHash('sha256').update('safecloud-jets').digest();
swarm.join(topic, { server: true, client: true });
await discovery.flushed();   // wait for DHT announce to propagate

swarm.on('connection', (conn, info) => {
    // conn: Noise-encrypted duplex stream
    // info.publicKey: peer's 32-byte Noise public key
    _onConnection(conn, info);
});
```

`deriveNoiseKeypair(evmPrivateKey)`:
```js
const seed = crypto.createHash('sha256')
    .update(Buffer.from(evmPrivateKey.slice(2), 'hex'))
    .update(Buffer.from('safecloud.noise'))
    .digest();
// seed → Ed25519 keypair (hyperswarm uses Ed25519 / Curve25519 internally)
return require('hypercore-crypto').keyPair(seed);
```

---

### Q.Data.Prolly (Jet-level tree)

```js
// Build from scratch (startup or cold sync):
Q.Data.Prolly.build(entries, store)
// entries: Array<{ key: cidString, value: dropEVMAddress }>

// Incremental updates:
Q.Data.Prolly.insert(root, { key: cid, value: dropEVM }, store)
Q.Data.Prolly.delete(root, cid, store)

// Diff for peer sync:
Q.Data.Prolly.diff(rootA, rootB, store)
// Returns: Array<{ key: cid, value: dropEVM|null, added: Boolean }>

// Coverage check:
Q.Data.Prolly.has(root, cid, store)
// Returns: Boolean
```

The in-memory Prolly store for the second-level tree: `_jetProllyStore`
— plain `{ hash: node }` object, same pattern as Drop-level.

---

### ethers.js (balance pre-check)

```js
// Query SafeBux balance for Drop or peer Jet (shared cache with Safe.Jets):
const balance = await _safebux.balanceOf(evmAddress);  // BigInt
// Cached 1 hour per evmAddress in _balanceCache (shared with Safe.Jets)
```

Uses the same provider instance and cache as `Safe.Jets._checkPayerBalance`.

---

### Safe.Jets internal state consumed by Router

Router reads (read-only):
```js
Safe.drops         // dropId → drop record
Safe._cidIndex     // rootCid → Array<cidString>
```

Router private state:
```js
_peers             // evmAddress → { conn, url, evmAddress, stake, secondLevelRoot }
_cidCoverage       // rootCid → Set<dropId>
_reliabilityScore  // dropId → Number [0,1]
_inflight          // cid → Promise<chunk>
_cocStore          // cocHash → CoC
_corruptActors     // Set<evmAddress>
_jetProllyStore    // hash → Prolly node (second-level)
_jetProllyRoot     // String|null
_subscriptions     // peerEVM → Set<rootCid>  (topics we've subscribed to them for)
_peerRoutes        // rootCid → Array<{ jetEVM, dropCount, latencyMs, lastSeen }>
_balanceCache      // evmAddress → { balance: BigInt, cachedAt: Number }
```

---

## Part 3 — Wire formats

All messages over hyperswarm Noise connections are length-prefixed JSON
(4-byte big-endian length + UTF-8 JSON). Handled by `_frameConn(conn)`.

---

### `safecloud.jet.hello`

Sent immediately after connection, before any other message. Both sides
send and await the peer's hello before proceeding.

```json
{
  "type":            "safecloud.jet.hello",
  "url":             "https://jet.example.com",
  "version":         1,
  "evmAddress":      "0x<Jet BSC address>",
  "delegation": {
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
  "secondLevelRoot": "<hex>|null"
}
```

**Verification:**
1. `delegation.iss` matches `evmAddress`
2. Wallet signature valid over canonical JSON (sig stripped)
3. `delegation.stm.exp` not passed
4. `version === 1`
5. Timestamp within 2× session lifetime of now

---

### `safecloud:routing-announcement` (OCP)

Jointly signed by Drop and Jet. Sent when Jet gains first Drop for a
`rootCid`, and refreshed every `ttl / 2` seconds while Drop remains connected.

```json
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<Drop-EVM>",
  "sub": "safecloud:routing-announcement",
  "stm": {
    "rootCid":    "bafy...",
    "jetEVM":     "0x<Jet-BSC-address>",
    "prollyRoot": "<hex>",
    "timestamp":  1700000000,
    "ttl":        300
  },
  "key": [
    "data:key/eip712,0x<Drop-EVM>",
    "data:key/eip712,0x<Jet-EVM>"
  ],
  "sig": [
    "<Drop EIP-712 r‖s‖v>",
    "<Jet EIP-712 r‖s‖v>"
  ]
}
```

**Construction:** Drop signs first (sends `Safe/drop/signAnnouncement` ack
to Jet with Drop's signature). Jet counter-signs. Both sign canonical JSON
with `sig` stripped (RFC 8785). Withdrawal: `stm.ttl = 0`.

**Verification:** Both sigs valid; `timestamp` within `now ± maxClockSkewSec * 2`;
`ttl > 0` (else withdrawal); `stm.prollyRoot` matches the most recent signed
announce the Jet has received from that Drop over its direct socket.io connection.

The verifying Jet does NOT recompute the Prolly root from scratch — it simply
compares the value in the announcement to the `newRoot` of the most recent
`Safe/drop/announce` entry it holds for that Drop. This is possible because
Drops send signed diff-log entries on every inventory change, so the Jet always
has the Drop's current root from their direct connection. A new peer Jet that
has never connected to this Drop directly cannot perform this check — it
must rely on the Drop's announcement signature and trust transitively.

**Routing announcements are probabilistic hints, not guarantees.** This is
an explicit design constraint, not a bug. A Jet receiving a routing announcement
from a peer Jet can verify the signatures but cannot independently verify that
the Drop's Prolly root is accurate at the moment of announcement. The
announcement's trustworthiness increases with:
- Direct observation: the receiving Jet has also connected to that Drop, OR
- Serve-based confirmation: the peer Jet has successfully served chunks from
  that Drop in recent requests (tracked via `_peerRoutes` reliability)

Peers MUST treat routing announcements as hints that reduce routing latency,
not as authoritative inventory proofs. The definitive proof of storage is a
successful serve — the Drop either returns the correct chunk bytes or it
doesn't. A Jet that announces false coverage will fail serve attempts, its
reliability score will degrade, and it will eventually be removed from routing
tables. This is the economic enforcement mechanism for announcement honesty:
false announcements waste the announcing Jet's relay payment budget without
earning corresponding income.

**Handshake implications:** If verification fails (stale root, invalid signature,
expired delegation), the connection is closed and the announcing Jet/Drop must
reconnect and re-register. See Protocol.md § Drop handshake and stake
registration for the full reconnect sequence. A peer Jet whose hello fails
verification is simply not added to the routing table — the initiating Jet
tries the next available peer.

---

### `safecloud:drop-availability` (OCP)

Jet-signed only. Gossiped when first/last Drop for a `rootCid` transitions.

```json
{
  "ocp": 1,
  "iss": "data:key/eip712,0x<Jet-EVM>",
  "sub": "safecloud:drop-availability",
  "stm": {
    "rootCid":    "bafy...",
    "event":      "available"|"unavailable",
    "jetEVM":     "0x<Jet-EVM>",
    "dropCount":  3,
    "prollyRoot": "<hex>",
    "timestamp":  1700000000
  },
  "key": ["data:key/eip712,0x<Jet-EVM>"],
  "sig": ["<Jet EIP-712 r‖s‖v>"]
}
```

---

### `safecloud:corruption` (CoC)

```json
{
  "type":     "safecloud.coc",
  "hopCount": 7,
  "coc": {
    "ocp": 1,
    "iss": "data:key/eip712,0x<claimant-EVM>",
    "sub": "safecloud:corruption",
    "stm": {
      "subject":    "data:key/es256;base64,<accused-P256-SPKI>",
      "subjectEVM": "0x<accused-EVM>",
      "evidence":   [ { <OCP claim 1> }, { <OCP claim 2> } ],
      "reason":     "Announce claimed rootCid present; repeated serves returned null"
    },
    "key": ["data:key/eip712,0x<claimant-EVM>"],
    "sig": ["<claimant EIP-712 r‖s‖v>"]
  }
}
```

---

### Relay request: GET /Safe/relay/{rootCid}/{start}/{end}

```
GET /Safe/relay/bafy.../0/10?g=<grants_b64url>&p=<payments_b64url>
Authorization: Bearer <Noise-derived token>
X-OCP-Payment: <base64(OCP Role B token, payer=jetA_EVM, recipients=[jetB_EVM])>
```

`X-OCP-Payment` carries the relay payment token from Jet A to Jet B —
part of the pairwise marketplace. Jet B verifies Jet A's SafeBux balance
before serving, exactly as Drops verify Jets.

**Responses:**
- `200` — chunks JSON, same shape as `GET /Safe/subtree`
- `401` — invalid/expired bearer token; Jet A re-derives and retries once
- `402` — Jet A's SafeBux balance insufficient for relay payment
- `403` — grant verification failed
- `404` — Jet B has no coverage for this range

---

### Noise bearer token derivation

```js
```js
// IMPORTANT: use conn.handshakeHash (shared secret), NOT conn.remotePublicKey.
// remotePublicKey is public — anyone can compute an HMAC from it, making the
// token forgeable. handshakeHash is the 32-byte BLAKE2b hash of the full
// Noise handshake transcript, known only to both connected parties.
//
// Stability note: conn.handshakeHash is specific to hyperswarm / noiseSecretStream.
// If migrating to a different Noise library, verify that it exposes a stable
// shared secret from the handshake transcript. The requirement is:
//   - derived from the Noise handshake (not from a public key)
//   - identical on both sides
//   - unavailable to third parties
// If the library does not expose handshakeHash, derive explicitly:
//   sharedSecret = HKDF(noise_session_keys, 'safecloud.relay.secret')
const sharedSecret = conn.handshakeHash;

function deriveRelayToken(sharedSecret, localEVM, remoteEVM, windowSec) {
    const window = Math.floor(Date.now() / 1000 / windowSec);
    return crypto.createHmac('sha256',
            Buffer.concat([sharedSecret, Buffer.from('safecloud.relay.auth')]))
        .update(`${localEVM}:${remoteEVM}:${window}`)
        .digest('hex');
}
// Accept current window AND previous window (clock skew + rotation boundary)
```

Both sides derive independently from the same `handshakeHash`. Forging the
token requires knowing the shared secret — infeasible without participating
in the Noise handshake.

---

## Part 4 — Jet-level Prolly tree

### Structure and ordering

Second-level Prolly tree: `{ cid → dropEVMAddress }`, CIDs ordered
lexicographically. The value is the **deterministic representative Drop** —
the Drop whose EVM address sorts lowest among those currently holding the CID.
`_cidCoverage[cid] = Set<dropId>` tracks all Drops holding it; routing
decisions use that set, weighted by stake and reliability.

Two Jets with identical Drop inventories produce identical roots. Root
comparison is O(1); only when roots differ is a diff needed.

---

### Maintenance lifecycle

**On Drop registration** (`onDropRegistered(drop, prollyRoot)`):
1. For each CID in Drop's inventory (read from `_cidIndex` or await first announce):
   - Insert `{ cid → dropEVM }` if no entry or Drop has higher stake than current
   - Add dropId to `_cidCoverage[cid]`
2. Recompute `_jetProllyRoot`
3. If any rootCid transitions from 0 to 1 Drop coverage: `announce(rootCid, 'available')`

**On Drop announce** (`onDropAnnounce(drop, diff)`):
1. For each `{ cid, added }` in diff:
   - `added: true` → insert into second-level tree; add to `_cidCoverage`
   - `added: false` → remove from `_cidCoverage`; if empty, delete from tree;
     if rootCid transitions to 0 coverage: `announce(rootCid, 'unavailable')`
2. Recompute `_jetProllyRoot`

**On Drop disconnect** (`onDropDisconnected(drop)`):
1. Remove all Drop's CIDs from `_cidCoverage`
2. For CIDs where `_cidCoverage` becomes empty: delete from tree;
   if rootCid transitions to 0: `announce(rootCid, 'unavailable')`
3. Recompute `_jetProllyRoot`

---

### Syncing between Jets

On new peer connection, after hello:

1. Compare `hello.secondLevelRoot` to `_jetProllyRoot`
2. Equal → no sync
3. Different → send:
   ```json
   { "type": "safecloud.prolly.diff", "myRoot": "<hex>" }
   ```
4. Peer responds:
   ```json
   { "type": "safecloud.prolly.diff.response",
     "diff": [ { "cid": "bafy...", "dropEVM": "0x...", "added": true } ] }
   ```
5. Router applies diff to `_peerRoutes` (not merged into local second-level tree —
   peer's Drops are external routes, tracked separately)

**Local vs external routing table:**
- `_jetProllyRoot` / `_jetProllyStore` — this Jet's connected Drops only
- `_peerRoutes[rootCid]` — peer Jets' coverage, for relay decisions

`relayGet` consults `_peerRoutes`; `selectForGet` consults `_jetProllyStore`.
The separation is clean: if local Drops have the CID, serve locally; if not,
relay to the peer with the best `_peerRoutes` entry.

---

## Part 5 — Safe.Router public interface

---

### `Safe.Router.selectForGet(cid, options)` → Promise\<drop|null\>

```
cid:     String
options: { exclude: Array<dropId> }
Returns: drop from Safe.drops, or null (triggers relayGet in Safe.Jets)
```

Checks `_inflight[cid]` first — if a request is already in flight, returns
a virtual drop object that resolves via the coalesced promise. Otherwise:
weighted-random selection among connected Drops with `cid` in their inventory
(per `_cidCoverage`), excluding `_corruptActors` and `options.exclude`.

---

### `Safe.Router.selectForPut(cids, options)` → Promise\<Array\<drop\>\>

```
cids:    Array<String>
options: { replicationFactor: Number }
Returns: Array<drop>
```

Selects `replicationFactor` Drops. Prefers available storage. Pre-filters
using each Drop's Bloom filter to skip Drops that likely already hold a CID.
Returns fewer than `replicationFactor` if not enough suitable Drops connected.

---

### `Safe.Router.relayGet(subtree, options)` → Promise\<{chunks}|null\>

```
subtree: { rootCid, start, end, grants }
options: { payments, exclude: Array<jetEVM> }
Returns: { chunks } or null
```

Selects best peer from `_peerRoutes[rootCid]` (lowest latency, highest
dropCount, not in `exclude`, not in `_corruptActors`). Issues HTTPS relay
request with Noise bearer token and relay payment token. On 401: re-derive
token and retry once. On 404 or failure: try next peer. Returns null when
all exhausted.

---

### `Safe.Router.announce(rootCid, event)` → void

```
rootCid: String
event:   'available'|'unavailable'
```

Constructs `safecloud:drop-availability` OCP claim signed with Jet's EIP-712
session key. Broadcasts over all Noise connections. Sends to pairwise
subscribers. For `available`: requests Drop co-signature (`Safe/drop/signAnnouncement`)
for the DHT routing announcement.

---

### `Safe.Router.gossipCoC(coc)` → void

Validates, deduplicates, stores in `_cocStore`, decrements `hopCount`, floods
to peers. Updates `_corruptActors` and reliability scores for known subjects.

---

### `Safe.Router.peerJets()` → Array\<{evmAddress, url, stake}\>

Snapshot of `_peers`. Used by Safe.Jets for monitoring and relay candidate
selection.

---

## Part 6 — Implementation Order

1. `_frameConn(conn)` — length-prefix framing for Noise streams
2. `deriveRelayToken(sharedSecret, localEVM, remoteEVM, windowSec)` — pure HMAC over Noise handshake hash
3. `_deriveNoiseKeypair(evmPrivateKey)` — deterministic from wallet key
4. `_verifyDelegation(hello)` — validates hello delegation claim
5. `_weightDrop(drop)` — `stakedSafebux * reliabilityScore * availableStorage`
6. `_weightedRandomSelect(drops, N)` — weighted-random selection
7. `_updateReliability(dropId, success)` — EMA update
8. `_applyPeerDiff(diff)` — update `_peerRoutes` from peer Prolly diff
9. `Safe.Router.onDropRegistered(drop, prollyRoot)` — merge Drop CIDs
10. `Safe.Router.onDropAnnounce(drop, diff)` — apply diff to second-level tree
11. `Safe.Router.onDropDisconnected(drop)` — remove Drop CIDs, fire events
12. `Safe.Router.selectForGet(cid, options)` — weighted select + coalescing
13. `Safe.Router.selectForPut(cids, options)` — weighted select + Bloom check
14. `Safe.Router.relayGet(subtree, options)` — Noise token + HTTPS + payment
15. `Safe.Router.announce(rootCid, event)` — sign OCP, flood peers
16. `Safe.Router.gossipCoC(coc)` — validate, deduplicate, flood
17. `Safe.Router.peerJets()` — snapshot
18. `_handleHello(conn, hello)` — verify delegation, init Prolly sync
19. `_handleAvailability(msg)` — update `_peerRoutes`
20. `_handleProllyDiff(conn, msg)` — respond to diff request
21. `_handleCoC(msg)` — validate + pass to gossipCoC
22. `_handleSubscribe(conn, msg)` — register pairwise subscription
23. `_onConnection(conn, info)` — top-level handler: sends hello, dispatches msgs
24. `Safe.Router.init(options)` — create hyperswarm, join topic, setup handlers;
    called by `Safe.listen()` before accepting connections

---

## Part 7 — What is NOT in Router.js

- **Chunk transfer** — Safe.Jets calls Drops directly via socket.io. Router
  selects the Drop; Jets does the calling.

- **OCP Role A grant verification** — Safe.Jets `verifySubtreeGrant()`.

- **OCP Role B payment verification** — Safe.Jets `_checkPayerBalance()`.

- **Merkle proof generation** — Safe.Jets `buildMerkleProofs()`.

- **Drop lifecycle records** — `Safe.drops` is owned by Safe.Jets. Router
  reads it but never creates, updates, or deletes Drop records.

- **PHP→Node internal messages** — Safe.Jets `Safe_request_handler`.

- **IndexedDB** — Router is Node.js server-side only.

- **On-chain payment execution** — Assets plugin via PHP bridge. Router only
  reads BSC balances for pre-screening (shared cache with Safe.Jets).

- **Kademlia / XOR-distance routing** — v2. The pluggable interface is
  designed so a Kademlia implementation is a drop-in replacement for
  `Safe.Router` without touching Safe.Jets.

- **Drop-to-Drop communication** — Drops do not communicate with each other.
  All inter-Drop coordination goes through Jets.

- **Safe.Cloud** — Router is entirely server-side. It has no knowledge of
  encryption, key derivation, or manifests. It routes opaque CIDs.
