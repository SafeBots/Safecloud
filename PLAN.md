# Safecloud 4.1 Implementation Plan

## What 4.0 adds (vs 3.8)

| Thing | 3.8 | 4.0 |
|---|---|---|
| Encrypted streams | ✅ | ✅ |
| Rolling-rewind / forward secrecy | ✅ | ✅ |
| ControlPanel (admin SPA at `/Safecloud/admin/`) | ✅ | ✅ |
| Payment nonce replay protection (`used_nonces`) | ✅ | ✅ |
| Author cert model (OCP) | ❌ | ✅ `AuthorPanel.js`, `ocp.js`, `ocp.php` |
| DocStore — Y.js snapshot persistence | ❌ | ✅ `DocStore.js` |
| `/registerPublisher` self-registration | ✅ working | ❌ → 410 Gone |
| `author_certs` table in RightsManagement | ❌ | ✅ |

4.0 is a **breaking release**: publishers must obtain an author-signed cert via OCP rather than self-registering. Everything else is additive.

---

## What 4.1 adds

The 4.0 codebase implements delivery and cert issuance. 4.1 adds the **cryptographic messaging layer** (hash chains, deniable chat, group membership), **document/folder trees**, and **P2P WebRTC offload**. These build on each other in dependency order.

| Thing | 4.1 |
|---|---|
| Backward secrecy — B_k hash chains | ✅ planned |
| CID-based content addressing | ✅ planned |
| Document/folder trees | ✅ planned |
| P2P WebRTC mesh (stream + chat) | ✅ planned |
| Deniable chat / relative identity | ✅ planned |
| Non-interactive group membership | ✅ planned |
| Editor UI (doc, sheet, code) | ✅ planned |

---

## Implementation steps

### Step 1 — HashChain.js: bidirectional key derivation

**Files:** `web/js/Safecloud/HashChain.js` (new), modify `sw.js`, `stream.js`, `RightsManagement.js`

The current streaming key model is `capability token → HKDF master key → per-segment key`. That gives forward secrecy via rolling-rewind deletion, but no backward secrecy — if the current segment key is compromised, future segment keys are derivable.

Replace with the bidirectional construction from the patent:

```
F₀ = random(32 bytes)
F_k = SHA-256(F_{k-1})          // forward chain — revealing F_k hides F_0..F_{k-1}

B_n = random(32 bytes)
B_k = SHA-256(B_{k+1})          // backward chain — revealing B_k hides B_{k+1}..B_n

K_seg[k] = HKDF(F_k ‖ B_k, salt=streamId, info="seg-key-v2" ‖ k)
```

`HashChain.js` exports:
- `generateForwardChain(seed, n)` → `Uint8Array[]`
- `generateBackwardChain(seed, n)` → `Uint8Array[]`
- `deriveSegKey(F_k, B_k, streamId, k)` → `CryptoKey`
- Sparse checkpoint storage: store every 100th element, derive on demand (saves 99× memory on long streams)

**sw.js changes:** Replace current `K_seg` derivation with `HashChain.deriveSegKey(F_k, B_k, ...)`. Load `HashChain.js` via `importScripts`.

**RightsManagement.js changes:** `bootstrap_packages` table gains `forward_seed BLOB`, `backward_seed BLOB`, `chain_length INTEGER`. Bootstrap endpoint encrypts `{F_k..F_n, B_k..B_n}` to recipient pubkey for a late-joining participant starting at index k.

**Breaking:** segment key format changes — streams encrypted under 4.0 are incompatible. Version the bootstrap package (`chain_version: 2`).

---

### Step 2 — CIDStore: content-addressed storage

**Files:** `web/js/Safecloud/CIDStore.js` (new), `classes/Safecloud/CIDStore.js` (new), modify `RightsManagement.js`, `Jets.js`

A CID is `sha256(content)` encoded as hex. Content-addressing gives deduplication, structural sharing between document versions, and a foundation for Merkle folder trees.

**Server (`classes/Safecloud/CIDStore.js`):**
```js
// DB table: cids(cid TEXT PRIMARY KEY, data BLOB NOT NULL, size INTEGER, created INTEGER)
class CIDStore {
    put(data)          // → cid  (noop if already present)
    get(cid)           // → Buffer | null
    has(cid)           // → bool
    pin(cid, ownerId)  // prevent GC
    gc()               // remove unpinned CIDs older than TTL
}
```

**Jets routes:**
```
GET  /Safecloud/cid/:cid          → serve raw bytes, immutable cache headers
POST /Safecloud/cid               → body: raw bytes, returns {cid}
```

Access control: any holder of a valid stream token can PUT/GET CIDs associated with that stream. CIDs are capability-gated, not public.

**Client (`web/js/Safecloud/CIDStore.js`):** thin fetch wrapper + local `Map` cache for session deduplication.

---

### Step 3 — DocTree: document/folder trees

**Files:** `web/js/Safecloud/DocTree.js` (new), `classes/Safecloud/DocTree.js` (new), modify `Jets.js`

Folders are CID-addressed JSON objects:

```js
// Folder node (stored as a CID)
{ type: 'dir', entries: { 'readme.md': '<cid>', 'src': '<cid>' } }

// File node (stored as a CID)
{ type: 'file', encoding: 'utf8' | 'bytes', cid: '<content-cid>', name: 'readme.md' }
```

Changing one file changes its CID → changes the parent dir CID → changes the root CID. The root CID is a snapshot of the entire tree at a point in time — commit-like semantics for free.

**DocTree API (server):**
```
GET  /Safecloud/tree/:rootCid          → resolve folder listing
GET  /Safecloud/tree/:rootCid/*path    → resolve path within tree
POST /Safecloud/tree/commit            → {rootCid, patch: [{op, path, cid}]} → newRootCid
```

**Integration with DocStore (4.0):** DocStore snapshots reference a rootCid. Each Y.js save produces a new rootCid; DocStore records `(docId, version, rootCid)`. Rollback = point to an old rootCid.

---

### Step 4 — PeerMesh: WebRTC P2P for streams and chat

**Files:** `web/js/Safecloud/PeerMesh.js` (new), modify `sw.js`, `Jets.js`

Peers in the same stream room share encrypted segment ciphertexts directly. The server is bypassed for cache-warm segments. Because segments are pre-encrypted, peers share ciphertexts freely — only a holder of a valid capability token can decrypt.

**PeerMesh.js (runs in SW scope via importScripts):**
```js
class PeerMesh {
    constructor(streamId, signalingUrl) { ... }
    async connect()                         // open WebSocket to /Safecloud/peer?stream=X
    async fetchSegment(videoId, segIndex)   // try peers, timeout 150ms, null = miss
    announceHave(videoId, segIndex)         // broadcast to room after server fetch
    sendChat(encryptedMsg)                  // route chat ciphertext to all room peers
    onChat(callback)                        // receive chat ciphertexts
}
```

**sw.js change** — wrap segment fetch:
```js
var peerResult = await peerMesh.fetchSegment(videoId, segIndex);
var ciphertext = peerResult || await fetchFromServer(url);
peerMesh.announceHave(videoId, segIndex);  // let others know we have it
```

**Jets signaling endpoint** (`/Safecloud/peer?stream=X`, WebSocket):
```
join  → server records (streamId, peerId, ws)
relay → server forwards SDP offer/answer and ICE candidates between peers in same room
leave → server removes peer, notifies room
```

No segment bytes pass through the server. The signaling relay is ~60 lines of Jets code.

**Chat over data channels:** once WebRTC data channels are established between peers, the same connection carries encrypted chat messages. Message envelope: `{type: 'seg'|'chat'|'have'|'want', payload: Uint8Array}`. The server remains a fallback for peers not yet WebRTC-connected.

**Peer selection — continuous latency optimization:**

Hold exactly 2-3 connections at all times. Continuously probe new candidates in the background (passive — never interrupts existing connections). After ICE settles on each probe, measure end-to-end RTT via `getStats()` → `currentRoundTripTime`. If the probe beats the current worst connection by ≥10% (threshold prevents churn), swap it in and close the worst. Repeat forever — the mesh self-optimizes toward the lowest-latency neighborhood in the room.

```js
_maybeSwap(peerId, pc, rtt) {
    if (this.peers.size < this.maxPeers) {
        this.peers.set(peerId, { pc, dc: pc.createDataChannel('sc'), ewma: rtt });
        return;
    }
    const worst = [...this.peers.entries()].sort((a, b) => b[1].ewma - a[1].ewma)[0];
    if (rtt < worst[1].ewma * 0.9) {   // 10% improvement required to swap
        worst[1].pc.close();
        this.peers.delete(worst[0]);
        this.peers.set(peerId, { pc, dc: pc.createDataChannel('sc'), ewma: rtt });
    } else {
        pc.close();                     // discard probe, keep current mesh
    }
}
```

The signaling server feeds the probe queue continuously — not just at join time, but pushing new room candidates as they appear. The client decides what to keep. EWMA (`0.8 × prev + 0.2 × sample`) smooths RTT noise on live connections; the threshold for swapping chat connections can be relaxed (15-20%) since humans tolerate slightly more latency than the segment-fetch deadline requires.

**Gossip with 2-3 connections:** when a peer receives a segment or chat message, it sends `{type: 'have', key}` to all kept connections. Any peer without it replies `{type: 'want', key}` and receives the bytes. With RTT-selected (geographically close) connections, fan-out is fast and bounded.

**What needs to be built:**

1. `peer-mesh.js` — WebRTC data channel management, continuous background probing, EWMA RTT tracking, swap-on-improvement logic, have/want gossip protocol
2. SW patch — wrap the segment fetch in `PeerMesh.fetchFromPeer()` before hitting the server (100ms timeout for segments; chat has no timeout)
3. Jets signaling endpoint — `/Safecloud/peer?stream=X` WebSocket room relay that pushes new peer candidates continuously, not just at join (~50 lines)
4. Chat: once data channels exist, it's just another message type on them

---

### Step 5 — Deniable chat: relative identity + transcript simulability

**Files:** `web/js/Safecloud/Chat.js` (new), `classes/Safecloud/Chat.js` (new), modify `Jets.js`, `RightsManagement.js`

Implements the patent's core privacy property: no message ever contains a cryptographic binding to a sender identity. Any participant can forge any message. Transcripts are non-evidentiary.

**Key derivation (no identity keys):**
```js
token = crypto.getRandomValues(new Uint8Array(32))
K_conv = HKDF(device_key, salt=token, info="conversation.v1")

// Chains derived from K_conv, not from identity keys
forwardChain  = HashChain.generateForward(HKDF(K_conv, info="forward"), length)
backwardChain = HashChain.generateBackward(HKDF(K_conv, info="backward"), length)
```

**Message format (no signature, no sender field):**
```js
{
    ciphertext: AES-256-GCM(K_msg[k], plaintext, AAD={index: k, conversationId}),
    index: k,
    reveal: { F_k, B_k }   // participants reveal chain elements per-message
    // NO signature. NO sender. NO identity binding.
}
```

`reveal: {F_k, B_k}` lets any participant derive K_msg[k] and forge a message at that index — this is intentional. It makes transcripts non-evidentiary because any participant could have produced them.

**Within-conversation authentication (relative identity):** participants know a message came from "the other person in this conversation" because only they share K_conv. That's as strong as asymmetric authentication for practical purposes. It just doesn't extend to outsiders.

**Server role:** relay ciphertexts to conversation participants. Routes:
```
POST /Safecloud/chat/:convId/send     → store + relay ciphertext to participants
GET  /Safecloud/chat/:convId/since/:k → fetch messages from index k
```

Server never sees plaintext. Chat messages are delivered peer-to-peer (via PeerMesh, Step 4) when WebRTC is established, through the server when not.

**DB (RightsManagement.js):** new tables `conversations(conv_id, token_cid, created)` and `chat_messages(conv_id, msg_index, ciphertext, stored_at)`.

---

### Step 6 — Group membership: non-interactive, O(1) adds/removes

**Files:** modify `RightsManagement.js`, `Chat.js`, add `Epoch.js` (new)

Builds on the hash chain + conversation model from Step 5. Groups use epoch-based key management from the patent.

**Add member (O(1)):**
```js
// Give new member chains from their join index forward — no rekey for existing members
bootstrap = {
    epoch: currentEpoch,
    forwardChain: encrypt(newMemberPubKey, F[joinIndex..n]),
    backwardChain: encrypt(newMemberPubKey, B[joinIndex..n]),
    startIndex: joinIndex
}
```

The new member can decrypt messages from `joinIndex` onward. They cannot decrypt earlier messages — history privacy is automatic.

**Remove member (O(1)):** stop delivering ciphertexts to the removed member. They retain chains from their participation period (and can forge messages for that period — this is intentional, same as a person who was in a room can claim they said something they didn't). No rekey needed unless the threat model requires it.

**Epoch transition (O(N), only on governance change):** generate new chains, distribute to all current members. Triggered by: owner transfer, admin quorum decision, security event, or max epoch length reached (configurable, default 10,000 messages or 90 days).

**Governance model (start simple, extend later):**
```
epochs(epoch_id, conv_id, gov_hash, forward_seed, backward_seed, start_index, end_index, created, closed_at)
epoch_members(epoch_id, member_id, pubkey_hex, join_index, left_at)
```

Initial governance model: single owner (Telegram-style). DAO/quorum models from the patent are future extensions.

---

### Step 7 — Editor UI

**Files:** `web/js/editors/DocEditor.js` (new), `web/js/editors/SheetEditor.js` (new), `web/js/editors/CodeEditor.js` (new), modify `Jets.js`

DocStore (4.0) gives persistence. This step adds the UI layer.

**DocEditor.js** — ProseMirror wrapper wired to DocStore:
- Load Y.js doc from DocStore snapshot
- Mount ProseMirror with y-prosemirror binding for real-time collaboration
- Save: `DocStore.saveSnapshot(docId)` on idle timeout or manual save
- Conflict resolution: Y.js CRDT — concurrent edits merge automatically
- Served at `/Safecloud/editor/doc/:docId`

**SheetEditor.js** — lightweight grid editor:
- Simple 2D array backed by a Y.js Y.Array of Y.Arrays
- Cell formulas evaluated client-side (no server round-trip)
- DocStore for persistence
- Served at `/Safecloud/editor/sheet/:docId`

**CodeEditor.js** — CodeMirror 6 wrapper:
- Syntax highlighting via CodeMirror language packages
- Y.js binding via y-codemirror.next
- DocStore for persistence
- Served at `/Safecloud/editor/code/:docId`

**Jets routes:**
```
GET /Safecloud/editor/doc/:docId    → serve DocEditor SPA
GET /Safecloud/editor/sheet/:docId  → serve SheetEditor SPA
GET /Safecloud/editor/code/:docId   → serve CodeEditor SPA
```

Each editor SPA is a single self-contained HTML page Jets serves from `web/editors/`. Access-gated by capability token (same mechanism as streams).

---

## Dependency order

```
Step 1 (HashChain)  ──┬──▶ Step 5 (Deniable chat)
                      └──▶ Step 6 (Group membership)

Step 2 (CIDStore)   ──────▶ Step 3 (DocTree)
                              └──▶ Step 7 (Editor UI, full versioning)

Step 4 (PeerMesh)   ──────▶ Step 5 (chat over data channels)

Step 7 (Editor UI)  depends on Step 3 (DocTree) for folder navigation
                    depends on DocStore (4.0) for snapshot persistence
```

Steps 1, 2, and 4 are independent of each other and can be developed in parallel. Steps 3, 5, 6, 7 each depend on exactly one earlier step.

---

## File manifest

New files in 4.1:

```
web/js/Safecloud/HashChain.js
web/js/Safecloud/CIDStore.js
web/js/Safecloud/DocTree.js
web/js/Safecloud/PeerMesh.js
web/js/Safecloud/Chat.js
web/js/editors/DocEditor.html
web/js/editors/SheetEditor.html
web/js/editors/CodeEditor.html
classes/Safecloud/CIDStore.js
classes/Safecloud/DocTree.js
classes/Safecloud/Chat.js
classes/Safecloud/Epoch.js
```

Modified in 4.1:

```
web/js/Safecloud/sw.js                          (Step 1 key derivation, Step 4 PeerMesh)
web/js/methods/Safecloud/Client/stream.js       (Step 1 bootstrap)
classes/Safecloud/Jets.js                       (Steps 2, 3, 4, 5, 7 — new routes)
classes/Safecloud/RightsManagement.js           (Steps 1, 2, 5, 6 — new tables + handlers)
classes/Safecloud/DocStore.js                   (Step 3 — rootCid integration)
```

---

## Breaking changes in 4.1

- Segment key format changes (Step 1) — streams encrypted under 4.0 are incompatible. The bootstrap package gains `chain_version: 2`; 4.1 clients reject `chain_version: 1`. Old streams must be re-encrypted or served by a 4.0 instance.
- `/Safecloud/cid/` namespace is new — no conflicts.
- Chat and group membership routes are new — no conflicts.
- Editor routes are new — no conflicts.
