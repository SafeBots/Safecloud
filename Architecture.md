# Architecture

Safecloud is one layer in a three-layer stack. Each layer has a distinct job, and the system works because the layers compose cleanly rather than because any single layer does everything.

## The three layers

**Safecloud — pull.** Content-addressed encrypted storage. Clients encrypt data locally, chunk it, and store the chunks on Drops (storage nodes). Retrieval is by CID (content identifier — the hash of the chunk). Jets (compute nodes) host Merkle trees that index and order content. Everything at rest is ciphertext; Drops and Jets never see plaintext. The gravity of this layer is toward permanence and retrieval: put something in, get it back later by hash.

**Intercloud — push.** Event propagation along rails. A publisher pushes a state change onto a stream. Watchers subscribe and receive updates. Epochs shuffle watcher assignments. Fork detection (not prevention) catches misbehavior; proof-of-corruption is self-contained evidence of a lie. The gravity of this layer is toward propagation and consensus: something happened, and everyone who cares finds out.

**Safebox — trust.** Attested compute in a TEE (Trusted Execution Environment). A Safebox can touch plaintext when necessary — scanning content, delivering notifications, running confidential workloads — and remote attestation proves it ran the code it claims to have run, without logging or exfiltrating data. The gravity of this layer is toward trust and confidentiality: do something sensitive, and prove you did it honestly.

## How the layers meet

The three layers form a loop:

1. Content enters Safecloud. A message, a video, a document, a trade intent. It is encrypted on the client, chunked, and stored on Drops. Its CID is the permanent handle.

2. The event propagates through Intercloud. The CID (and metadata about the event) flows along rails to subscribers — other users, services, safebots. Each subscriber is a watcher on the relevant stream.

3. Safebots in Safeboxes process the event. A content-moderation bot scans it. A curation bot ranks it. A collaborative-editing bot merges concurrent changes. These are Intercloud participants: they receive pushes, do trusted compute inside a TEE, and push results back onto rails.

4. The output of that pipeline — curated, tested, validated — becomes a notification pushed to the end user via a Safebox push gateway. The notification references content by CID. The user's client pulls the content from Safecloud, decrypts it locally, and displays it.

Pull and push are not competing models; they are two access patterns on the same data. Pull is "give me what I missed" — cold sync, catch-up, fetching content by hash. Push is "here's what's happening now" — real-time events, notifications, stream updates. The Merkle tree is the shared data structure that supports both.

## Three-tier WASM

WASM (WebAssembly) executes at three tiers, separated by what each tier can access:

### Tier 1 — Jet-side WASM

Runs on Jets. Operates on metadata, policies, trees, and ciphertext. Cannot see plaintext content (Jets only store and serve encrypted chunks). This is the SafecloudApps execution environment — the equivalent of Cloudflare Workers but decentralized.

**Host API:**

| Function | Purpose |
|---|---|
| `tree_create(name)` | Create a named Merkle tree |
| `tree_append(treeId, value)` | Append a value; returns index and proof |
| `tree_get(treeId, index)` | Read by index with Merkle proof |
| `tree_put(treeId, key, value)` | Key-value write with proof |
| `tree_range(treeId, opts)` | Range query over keys |
| `tree_root(treeId)` | Current root CID |
| `tree_checkpoint(treeId)` | Flush tree state to Drops |
| `tree_hydrate(rootCid)` | Load tree from Drops |
| `tree_diff(cidA, cidB)` | Diff two checkpointed tree states |
| `request_claim()` | Caller's OCP claim |
| `request_params()` | URL/query parameters |
| `request_body()` | Request body bytes |
| `respond(status, headers, body)` | Send HTTP response |
| `call(appCid, handler, params)` | Call another SafecloudApp handler |
| `outbound_call(endpoint, req)` | Call a declared external HTTP endpoint |
| `trigger_set(name, cron, handler)` | Schedule a recurring trigger |
| `trigger_delete(name)` | Remove a trigger |
| `now()` | Logical timestamp (chain position) |
| `random_seed()` | Deterministic randomness from chain state |

The `tree_*` functions replace the earlier `safedb_*` flat KV API. The KV operations (`safedb_get`, `safedb_put`, `safedb_range`, `safedb_delete`) remain as aliases — they operate on a default tree in KV mode. The tree API generalizes this to support append-only logs, Merkle-indexed collections, and arbitrary tree structures, all of which checkpoint transparently to Drops.

**Execution model:** Each handler invocation gets a fuel budget (default 10M instructions), a memory cap (16 MiB), and a max call depth of 8 for inter-app calls. Execution produces a SafecloudReceipt (input hash, output hash, fuel consumed, tree root before/after) chained into a SafecloudChain that commits the Jet to its computation history.

**Persistence:** Tree state lives in memory while active, with a write-ahead log (WAL) on local disk for crash recovery. The WAL flushes asynchronously to Drops as content-addressed chunks. On Jet restart or failover, any Jet can call `tree_hydrate(rootCid)` to reconstruct the tree from Drops and replay the WAL. This makes SafecloudApp state portable across Jets — the Jet is ephemeral compute; the data lives in the content-addressed store.

### Tier 2 — Client-side WASM

Runs on the end user's device (browser, mobile app, desktop). Operates on plaintext content after decryption. This is where content scanning, format detection, local AI inference, and media processing happen.

**Host API:**

| Function | Purpose |
|---|---|
| `content_bytes()` | The decrypted content |
| `content_meta()` | Metadata (MIME type, size, source CID) |
| `report(category, confidence, evidence)` | Flag content for review |
| `now()` | Wall-clock timestamp |
| `random_seed()` | Cryptographic random bytes |

**Lifecycle hooks:** `onBeforeEncrypt` (scan outgoing content before it enters Safecloud), `onAfterDecrypt` (scan incoming content after retrieval), `onMediaLoaded` (process media for display — thumbnails, format detection, metadata extraction).

Client-side WASM binaries are content-addressed by CID and pinned per release. The client downloads them from Drops and verifies the hash before execution. A content publisher can require specific scanner CIDs as a condition of access (e.g., "this room requires CSAM scanner v2.3 at CID bafy...").

### Tier 3 — Safebox WASM

Same execution environment as Tier 2 (client-side), but running inside a TEE with remote attestation. The Safebox proves to the caller that it ran the expected WASM binary on the expected input, without logging or exfiltrating data.

Use cases: content moderation at scale (a "chaperone" that scans content for a room without any room member needing to be online), threshold decryption for escrowed media keys, and the push notification gateway.

The attestation report includes: the WASM binary CID, the input hash, the output hash, and the TEE's platform certificate chain. A verifier can check that the Safebox ran the claimed code on the claimed input and produced the claimed output, without trusting the Safebox operator.

## Chat and messaging

Messaging has two layers, designed for different threat models.

### Layer 1 — Rooms (synchronous, real-time)

A room is a Merkle tree (append-only log) on a Jet. Members communicate via two channels:

**WebRTC mesh (real-time delivery):** When members are online simultaneously, they maintain peer-to-peer WebRTC data channels. Messages are encrypted under the room's current epoch key and sent directly between peers. The Jet acts as a TURN relay if hole-punching fails — it relays encrypted DTLS traffic without being able to read it.

**Onion-routed append (persistence and offline delivery):** Every message is also appended to the room's tree on a Jet for durability. To prevent the Jet from learning who authored each message, the sender routes the encrypted blob through 2 intermediate Jets (onion routing). Each hop peels one encryption layer and forwards to the next. The destination Jet receives an opaque blob from another Jet — indistinguishable from normal inter-Jet chunk replication — and appends it to the tree.

What the destination Jet sees: a tree ID (which tree to append to), the blob arrival time, and the blob size (padded). What it does not see: who sent the blob (onion routed), what is in the blob (encrypted), or even that this tree is a "chat room" rather than a file index or app state (all trees look identical at the protocol level).

**Ordering:** The Jet assigns a monotonic position index on append. This is the canonical order. There is no wall-clock timestamp in the envelope — the blob's tree index is its logical time. Inside the encrypted payload, the sender may include a display timestamp, visible only to members after decryption.

**Epoch-based key management:** Each room uses bidirectional hash chains for forward secrecy and post-compromise security. The per-message key is `K_msg = HKDF(F_k || B_k || roomId || msgIndex)`. Epoch transitions rotate both chains. Member join/leave triggers a transition. All key material is encrypted per-member and stored in the tree — the Jet sees only ciphertext.

**Failover:** If a Jet goes down, any other Jet can hydrate the room's tree from Drops (`tree_hydrate(rootCid)`), continue from the last checkpoint, and accept new appends. Members reconnect to the new Jet. The room is portable because the state is in the tree, not on any particular Jet. Payment is in Safebux.

### Layer 2 — Mailboxes (asynchronous, anonymous)

A Drop registers mailbox public keys with Jets. A sender submits an encrypted blob addressed to a recipient's mailbox pubkey. The Jet queues the blob; the recipient retrieves it later. Mailbox keys are derived independently from the Drop's root secret (`delegate("mailbox/0")`, `delegate("mailbox/1")`, etc.), so the Jet cannot link mailboxes belonging to the same Drop.

**Steganography:** A mailbox submission looks identical to a chunk PUT. A mailbox retrieval looks identical to a chunk GET. Same encryption, same padding (1024-byte boundaries), same transport. The Jet cannot distinguish messaging operations from storage operations. HTTP responses are padded to a fixed size (64 KB) regardless of whether the mailbox is empty or full.

**Timing resistance:** Constant-rate polling, cover traffic (encrypted random data sent to own mailboxes and decoy pubkeys), batched retrieval mixed with regular chunk fetches, jittered multi-Jet polling.

**Uses:** Discovery and initial contact (exchanging room invitations), offline fallback when WebRTC is unavailable, trading intents and settlements (Trading.md), and any communication that requires strong anonymity.

### Notifications — the Safebox push gateway

Web Push notifications require VAPID keys. If every Jet held its own VAPID key and push endpoints, a malicious or buggy Jet could spam users with no recourse.

The solution is a Safebox push gateway: a TEE-attested service that holds the VAPID keys and user push subscriptions. Jets do not push directly. Instead:

1. An event occurs (new message in a room, SafecloudApp trigger fires, Intercloud rail delivers an update).
2. The Jet (or the Intercloud rail) submits a push request to the Safebox gateway, with an OCP claim proving authorization.
3. The gateway verifies the claim, checks per-user rate limits, encrypts the notification payload under the user's `notify` key, signs with VAPID, and sends via Web Push (FCM/APNs/autopush).
4. The user's service worker decrypts and displays the notification.

The gateway is attested not to spam, not to log which notifications go to whom, and to enforce rate limits. It is the only entity with VAPID keys and push endpoints. Jet failover does not require new push subscriptions — the gateway is the stable push identity.

Users can configure rate limits per room or per app via OCP claims: "at most 10 pushes per hour from room X." The gateway enforces the policy.

This is also the integration point between Safecloud (pull) and Intercloud (push). The Safebox push gateway subscribes to Intercloud rails on behalf of users, receives push events from the event layer, and delivers notifications referencing Safecloud CIDs. The user's client pulls the content by CID when they want to see it.

## Data structures (SDK)

The `tree_*` host API is a low-level primitive. Five higher-level data structures compose trees to provide familiar abstractions, all with content-addressed storage, checkpoint/hydrate portability, and cryptographic diffs. They are part of the Safecloud SDK and run client-side (Tier 2) or inside SafecloudApps (Tier 1).

- **Directory** — static folder (IPFS/IPLD analog). KV tree of path → file manifest. Immutable snapshots addressed by root CID.
- **Feed** — append-only event log (Hypercore/Kafka analog). Subscribe for live tail. Checkpoint and restore.
- **Repo** — versioned directory (Git analog). Working tree + commit log + branches. Branch, checkout, merge (LWW or manual conflict resolution), diff.
- **Database** — indexed KV store (Dolt analog). Primary tree + per-field index trees + commit log. Query by index, commit/rollback/diff.
- **NameResolver** — mutable name → CID resolution (IPNS analog). Monotonic sequence number prevents rollback.

These structures compose: a deployment pipeline might use a Repo for source control, a Directory for each published snapshot, a NameResolver for the public URL, a Feed for the audit trail, and a Database for status tracking. See [DataStructures.md](DataStructures.md) for the full API.

## SafecloudApp deployment

SafecloudApps are WASM handlers registered on a Jet with a manifest. Deploying an app means: compile your handlers to WASM, upload the binaries to Drops (getting CIDs), write a manifest that maps HTTP routes to handler CIDs, and register the manifest with a Jet. Point a DNS record at the Jet and the app is live on a real domain, served to real browsers over HTTPS.

### Deployment interfaces

**CLI (`@safecloud/cli` via npm):** The primary developer tool. `safecloud deploy` chunks a directory, uploads to Drops, computes the manifest, and registers with a Jet. `safecloud dev` runs a local Jet emulator for testing WASM handlers against test requests. `safecloud hash` computes the CID for a file. The CLI calls the same canonical Client.js methods that run in the browser — it is a thin wrapper over the SDK.

**Zip upload:** POST a zip file to the Jet's admin endpoint. The Jet unpacks, chunks, stores on Drops, and registers. The simple path for non-developers who want to host a static site.

**Web dashboard:** A SafecloudApp itself — static HTML+CSS+JS hosted on a Jet, calling the Client.js SDK. Drag-and-drop deploy, manifest editor, logs viewer. Dogfooding: the management tool is a SafecloudApp.

### Access control via OCP Actions

App ownership and deployment authorization use the OCP Actions Extension (https://openclaiming.org/ActionsExtension). The app manifest has an owner (a public key). Operations on the app are authorized by OCP action claims:

- **Owner**: the key that signed the original manifest. Can update handlers, change policies, transfer ownership, delete the app.
- **Deployer**: owner signs an OCP `delegate` claim granting deploy rights. The deployer can update handler CIDs and static asset CIDs but cannot change ownership or policies.
- **Admin**: can change policies and manage deployer roles but cannot transfer ownership.

Single owner by default. Delegation via OCP claims. Multi-owner (M-of-N multisig on manifest updates) uses the Actions Extension's quorum mechanism — `minimum` and `fraction` fields enforce the required number of approvals, with an optional time delay before execution.

### Standard includes

Every SafecloudApp can load standard libraries from the hosting Jet at well-known paths:

- `/@safecloud/client.js` — encryption, key management, Drop interaction
- `/@safecloud/drop.js` — content-addressed storage operations
- `/@safecloud/app.js` — SafecloudApp convenience layer: `App.db.*` (tree operations), `App.auth.*` (OCP identity), `App.ws.*` (WebSocket to Jet rooms), `App.push.*` (notification subscriptions)
- `/@safecloud/app.css` — sensible defaults (reset, typography, responsive grid, dark mode)

Pinned versions available: `/@safecloud/client@2.8.js`. The Jet resolves these paths to the current release CIDs of each library.

For embedding (e.g., the video player on a third-party site), the iframe accepts a `css` querystring parameter for custom styling: `?css=https://example.com/brand.css` or inline CSS. The SafecloudApp's loader injects the custom CSS after the default theme.

## Comparison with related systems

### vs Cloudflare Workers

| Cloudflare | Safecloud |
|---|---|
| Workers (V8 isolates) | SafecloudApps (WASM on Jets) |
| KV | SafecloudDB (Merkle tree with KV mode) |
| Durable Objects | Tree state with WAL + checkpoint to Drops |
| Cron Triggers | `trigger_set` / `trigger_delete` |
| Service Bindings | `call(appCid, handler, params)` |
| `fetch()` | `outbound_call(endpoint, req)` |
| Auth (JWT/mTLS) | OCP claims |
| Custom domains | Point DNS to a Jet |
| R2 (object storage) | Drops (content-addressed, encrypted) |

The key difference: Cloudflare is centralized infrastructure. SafecloudApps run on any Jet, are portable via tree hydration, and all stored data is end-to-end encrypted. The developer experience is similar; the trust model is different.

### vs Pear / Hyperswarm

| Pear/Hyperswarm | Safecloud |
|---|---|
| Pure peer-to-peer | Peers + servers (Jets) |
| Hypercore (SLEEP feeds) | Merkle trees over content-addressed chunks |
| Hyperbee (B-tree on Hypercore) | SafecloudDB (KV mode on Merkle tree) |
| DHT hole-punching | Jets have public IPs; TURN for WebRTC |
| Custom runtime (Pear) | Standard browsers (HTTPS, WSS, WebRTC) |
| Noise protocol auth | OCP claims with delegation and multisig |
| No payment layer | Safebux micropayments |
| Peers see plaintext | End-to-end encryption; Jets see only ciphertext |
| Beaker Browser (`hyper://`) | Real DNS, real HTTPS, real browsers |

The key difference: Pear gives you peer-to-peer apps for people willing to run Pear. Safecloud gives you decentralized infrastructure for apps that run in standard browsers, with confidentiality, payments, and servers that solve the availability problem without becoming single points of trust.

### vs Signal

| Signal | Safecloud |
|---|---|
| Centralized servers (opaque) | Decentralized Jets (metadata-blind) |
| Sealed sender (server doesn't see sender) | Onion routing (Jet doesn't see sender) |
| Server sees recipient, timing | Jet sees tree ID and arrival time only |
| Server routes messages | Clients route via WebRTC; Jet is a durable log |
| No payment | Safebux |
| Single protocol | Rooms (sync) + mailboxes (async) + WebRTC (p2p) |
| Trust the server operator | Trust the TEE attestation (for notifications) |

The key difference: Signal's metadata protection depends on trusting Signal's servers. Safecloud's metadata protection is structural — the Jet cannot correlate senders and recipients because onion routing and steganographic mailboxes prevent it at the protocol level. Notifications are the one exception, handled by a Safebox push gateway with attestation.
