# Safecloud Plugin — LLM Coding Primer

Decentralized encrypted storage, compute, and communication network. Browser clients encrypt locally, Jet servers route ciphertext and execute WASM handlers, Drop nodes (browser tabs) store chunks in IndexedDB. Plaintext never leaves the client. HLS video streaming via service worker. Micropayments via ERC-20 tokens with EIP-712 signatures. E2E encrypted chat with per-message key escrow under threshold ElGamal. Identity managed via hash-chained keychains with dual-threshold recovery.

**Unified architecture:** Safecloud is one layer in a three-layer stack. **Safecloud = pull** (content-addressed encrypted storage, retrieval by CID). **Intercloud = push** (event propagation along rails, watchers, epoch shuffling, fork detection). **Safebox = trust** (attested TEE compute, push notification gateway, confidential workloads). Content enters Safecloud (encrypted chunks) → events propagate through Intercloud (rails) → safebots in Safeboxes process events (curation, testing, moderation) → results push to users via Safebox gateway → users pull content from Safecloud by CID, decrypt in player. See [Architecture.md](Architecture.md) for the full treatment.

**Companion docs** — this primer covers the API surface for code generation. For deeper treatment: [Architecture.md](Architecture.md) (unified triangle, three-tier WASM, tree API, chat model, deployment, comparisons), [README.md](README.md) (storage primitives, key hierarchy, OCP, micropayments), [Ecosystem.md](Ecosystem.md) (how all layers unify), [EpochProtocol.md](EpochProtocol.md) (bidirectional hash-chain implementation reference), [Apps.md](Apps.md) (WASM execution model, tree API, triggers, rooms with WebRTC+onion routing, deployment), [Flagging.md](Flagging.md) (content moderation, reputation, threshold escrow), [Attacks.md](Attacks.md) (threat model, 150+ attack entries), [AdaptiveStreamer.md](AdaptiveStreamer.md) (adaptive drop selection, serving policy, micropayment ramping).

## 1. Node Types
```
Cloud   — browser client: encrypts, decrypts, manifests, HLS streaming, client-side WASM scanning
Jets    — Node.js routing server: chunk routing, grant verification, payment check, WASM handler execution
Drops   — browser tabs: IndexedDB ciphertext storage, Prolly tree inventory, payment claiming
Router  — Jet-to-Jet: Hyperswarm discovery, weighted Drop selection, relay
```

## 2. Architecture Layers
```
┌─────────────────────────────────────────────────┐
│  Client applications (browser / native)         │
│  E2E encryption, WASM scanning, key management   │
├─────────────────────────────────────────────────┤
│  SafecloudApps (WASM on Jets)                   │
│  Handlers, triggers, route handlers             │
│  Deterministic, sandboxed, auditable            │
├─────────────────────────────────────────────────┤
│  SafecloudDB (prolly trees on Drops)            │
│  Per-track HKDF-derived encryption keys         │
│  Keychains, chat state, org roles, audit logs   │
├─────────────────────────────────────────────────┤
│  Safecloud storage (encrypted chunks on Drops)  │
│  Content-addressed, replicated, incentivized    │
├─────────────────────────────────────────────────┤
│  OCP (auth) + Safebux (payment)                 │
│  Cryptographic delegation, micropayments        │
└─────────────────────────────────────────────────┘
```

## 3. Client API (Browser-Side)
```javascript
// Store (encrypt + upload)
var result = await Q.Safecloud.Client.store(
    { data: blob, name: 'photo.jpg', type: 'image/jpeg' },
    { chunkSize: 256 * 1024 }
);
// Returns: { manifest, rootKey }
// Pipeline: rootKey → encryptionRoot → subtreeKey → chunkKey[i]/IV[i]
//   → AES-256-GCM encrypt → CID → Merkle root → Jets.put

// Fetch (download + verify + decrypt)
var blob = await Q.Safecloud.Client.fetch(manifest, { rootKey: rootKey });
// Merkle-verifies every chunk before decrypting

// Grant (produce a subtree capability for a grantee)
var capability = await Q.Safecloud.Client.grant(manifest, rootKey, {
    ranges: [{ start: 0, end: 10 }],
    readLevel: 40,
    exp: Math.floor(Date.now() / 1000) + 86400
});
// OCP delegation proof — same Q.Crypto.delegate used by keychains

// Reshare (grant + send to another user)
await Q.Safecloud.Client.reshare(manifest, rootKey, {
    userId: recipientUserId,
    readLevel: 30
});

// HLS Video Streaming
await Q.Safecloud.Client.play(videoId, videoElement, {
    manifest: manifest,
    capability: capability,
    versions: ['720p', '1080p']
});
// Service worker intercepts fetch to safecloud-hls.local/{videoId}/...

await Q.Safecloud.Client.pause(videoId);
await Q.Safecloud.Client.stream(videoId, { version: '1080p' });

// Upload / Download (thin wrappers)
await Q.Safecloud.Client.upload(fileInput.files[0]);
await Q.Safecloud.Client.download(manifest, { rootKey: rootKey });
```

## 4. Drops API (Browser Storage Nodes)
```javascript
await Q.Safecloud.Drops.init({
    maxStorage: 500 * 1024 * 1024,
    evmAddress: '0x...'
});

await Q.Safecloud.Drops.put(cid, ciphertext);
var chunk = await Q.Safecloud.Drops.get(cid);

await Q.Safecloud.Drops.announce('put');       // diff since last announce
await Q.Safecloud.Drops.claimPayments();       // redeem micropayment tokens

var bloom = await Q.Safecloud.Drops.getBloomFilter();
var root = await Q.Safecloud.Drops.getProllyRoot();
```

## 5. Jets API (Routing Server)
```javascript
// Server-side: start Jet
Q.Safecloud.Jets.listen({ port: 8443 });

// Client-side: connect browser to Jet
await Q.Safecloud.Jets.connect({ url: 'wss://jet.example.com' });

// Put/Get through Jet (routes to Drops)
await Q.Safecloud.Jets.put(rootCid, chunks, { payments: paymentTokens });
var result = await Q.Safecloud.Jets.get(rootCid, { start: 0, end: 5 });

// Drop lifecycle (server-side)
Q.Safecloud.Jets.callDrop(drop, 'Safe/drop/put', { cid, chunk });
Q.Safecloud.Jets.selectDrops(cids, opts);
Q.Safecloud.Jets.verifySubtreeGrant(grant, rootCid, chunkIndex);
Q.Safecloud.Jets.buildMerkleProofs(chunks, merkleRoot);
Q.Safecloud.Jets._checkPayerBalance(payer, token, amount, chainId);
```

## 6. Router (Pluggable Routing Layer)
```javascript
Q.Safecloud.Router = require('./Router.Kademlia');
Q.Safecloud.Jets.listen(options);

await Router.init(options);
var drop = await Router.selectForGet(cid, options);
var drops = await Router.selectForPut(cids, options);
var result = await Router.relayGet(subtree, options);
Router.announce(rootCid, 'available');
Router.gossipCoC(chainOfCustody);

Router.onDropRegistered(drop, prollyRoot);
Router.onDropAnnounce(drop, diff);
Router.onDropDisconnected(drop);

var peers = Router.peerJets();  // [{evmAddress, url, stake}]
```

## 7. Key Hierarchy (Storage)
```
rootKey (32 bytes, random or derived from videoKey+version)
  ├── encryptionRoot (HKDF) → P-256 keypair (in manifest)
  │     └── subtreeKey (HKDF per subtree)
  │           └── chunkKey[i] + chunkIV[i] (HKDF per chunk index)
  │                 → AES-256-GCM encrypt
  └── accessRoot (HKDF) → P-256 keypair (in manifest)
        └── OCP Role A grants (sign subtree access proofs)
```
This covers per-file storage keys. Identity keys live in keychains (§12). Chat keys use the epoch protocol (§11).

## 8. SafecloudApps — WASM Execution on Jets
```javascript
// App manifest (stored at content address)
{
  "name": "my-handler",
  "version": "1.0.0",
  "wasm": "bafybeig...",         // CID of the WASM binary
  "handlers": {
    "on-store":    { "type": "hook",    "trigger": "safecloud.store" },
    "send-media":  { "type": "hook",    "trigger": "room.send-media" },
    "daily-scan":  { "type": "trigger", "cron": "0 3 * * *" }
  },
  "permissions": ["db.read", "db.write", "net.fetch"],
  "limits": { "maxMemoryMB": 128, "maxCpuMs": 5000 }
}

// Host API available inside WASM handlers:
host.tree.create(name)               // create a named Merkle tree
host.tree.append(treeId, value)      // append to log; returns index + proof
host.tree.get(treeId, index)         // read by index with proof
host.tree.put(treeId, key, value)    // KV write with proof
host.tree.range(treeId, opts)        // range query over keys
host.tree.root(treeId)               // current root CID
host.tree.checkpoint(treeId)         // flush to Drops
host.tree.hydrate(rootCid)           // load tree from Drops
host.db.get(track, key)              // legacy KV alias (default tree)
host.db.put(track, key, value)       // legacy KV alias
host.db.list(track, prefix)          // legacy KV alias
host.crypto.verify(sig, msg, pk)     // signature verification
host.crypto.hkdf(ikm, salt, info, len)
host.envelope.emit(type, payload)    // produce a SafecloudEnvelope
host.net.fetch(url, options)         // outbound HTTP (registered endpoints only)

// SafecloudReceipt — tamper-evident execution record
{
  "handler": "bafybeig...",
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "db_reads": [...],
  "db_writes": [...],
  "prev_receipt": "sha256:...",  // hash chain
  "jet_signature": "..."
}
```
See [Apps.md](Apps.md) for triggers, outbound endpoints, and room handlers.

## 9. Rooms and E2E Encrypted Chat
```javascript
// Room = two Merkle trees on a Jet
// rooms/{roomId}/messages  — append-only log of encrypted blobs
// rooms/{roomId}/state     — KV: encrypted epoch records, encrypted member list

// What the Jet sees: tree ID, blob arrival time, blob size (padded)
// What it does NOT see: sender (onion routed), content (encrypted),
//   membership (encrypted state), or that this is a "chat room" (all trees identical)

// Real-time: WebRTC mesh between online members
// Persistence: 2-hop onion routing → destination Jet appends opaque blob
//   Alice → Jet A (peels layer) → Jet B (peels layer) → Jet C (appends to tree)
//   Indistinguishable from inter-Jet chunk replication

// Ordering: monotonic tree position index assigned by Jet on append
// No wall-clock timestamp in envelope — display timestamps inside encrypted payload

// Jet-side handler is minimal:
// "submit-blob" — validate Safebux, tree_append(messagesTree, blob), return proof
// "get-range"   — return blobs by position range
// "submit-state" — update encrypted state tree (epoch transitions, membership)

// All room management (create, invite, remove, epoch transition) is client-side
// Client writes encrypted state updates via submit-state
// Other members sync state tree to learn about changes

// Failover: tree_hydrate(rootCid) on any Jet, continue from last checkpoint
// Notifications: Safebox push gateway (holds VAPID keys, enforces rate limits)

// Per-message encryption (unchanged):
// K_msg = HKDF(F_k || B_k || roomId || msgIndex)
// Epoch transitions rotate both chains on member join/leave
```
See [Architecture.md](Architecture.md) for the full chat model, [EpochProtocol.md](EpochProtocol.md) for hash-chain implementation.

## 10. Content Safety — Three Layers
```
Layer 1: Client-side WASM scanning (Flagging.md §Layer 1)
  — Client scans plaintext before encryption with whitelisted WASM classifier (CID-pinned)
  — Proof-of-scan: deterministic ScanReport included in upload envelope
  — Jet verifies proof-of-scan exists (cannot verify content — no plaintext)
  — Whitelisted classifier hashes: client rejects unknown CIDs
  — Reputation system: shadowban gradient, stake-based flagging
  — Corroboration: multiple independent scanners required
  — Jury: deterministic jury selection, secret ballot, reputation consequences
  — Anti-griefing: false flaggers lose reputation and stake

Layer 2: Safebox chaperone scanning (Flagging.md §Layer 2)
  — Attested Safecloud client running in Safebox TEE
  — Attestation-gated room admission: OCP safebox_announce claim, verifyAnnounce()
  — Scoped grants: time-limited read-only access to specific CIDs
  — Retrospective scanning: catches content missed at upload or newly added to hash DBs
  — Tier 2 classifiers: Detoxify (420 MB), multilingual models, small LLMs (1-3B Q4_0)
  — Periodic re-attestation: fresh TPM quote every 600 seconds or ejection
  — Chaperone flag weight: attestation_multiplier = 1.5 (proves unmodified code)

Layer 3: E2E chat (Flagging.md §E2E chat content safety)
  — Bilateral client-side scanning: sender pre-encryption + recipient post-decryption
  — Batched chaperone delivery: flagged messages flushed every ~10 min, shuffled
  — Severity-tiered deniability: clean (full), light flag (no attribution), heavy flag (attributed)
  — Per-message key escrow: Enc(PK_threshold, K_msg) under threshold ElGamal
  — Proof of escrow: send-media handler requires valid escrow ciphertext
  — Threshold decryption: k-of-n DKG, no TEE required
  — Garbage escrow: detectable post-hoc (decryption produces garbage)
  — Honest gap: two cooperating bad actors bypass all mechanisms (same as Signal)

// Client-side scanning pseudocode:
async function scanBeforeSend(content, type) {
    if (type === 'image') {
        var hash = await pdqHash(content);
        if (await matchesBlocklist(hash)) return { flag: true, reason: 'pdq_match' };
    }
    if (type === 'text') {
        var score = await toxicityClassifier(content);
        if (score > THRESHOLD) return { flag: true, reason: 'toxicity' };
    }
    return { flag: false };
}

// Per-message key escrow (flagged messages only):
// escrow = ElGamal.encrypt(PK_threshold, K_msg)
// K_msg = HKDF(F_k || B_k) — one-way from epoch keys, so escrowing K_msg
// does NOT reveal chain seeds F_0 or B_0
```

## 11. Epoch Protocol — Bidirectional Hash Chains
```
Forward chain:   F_0 (random) → F_1 = H(F_0) → F_2 = H(F_1) → ...
Backward chain:  B_0 (random) → B_n = H^n(B_0), reveal B_k = H^{n-k}(B_0)
Per-message key: K_msg = HKDF(F_k || B_k)

Epoch transition (membership change):
  1. Generate new F_0', new B_0'
  2. Distribute to remaining/new members via public keys
  3. Record transition in SafecloudDB track
  4. Forward secrecy: removed member can't compute F_k for k > departure
  5. Backward secrecy: new member can't compute B_k for k < arrival

Scope table — same protocol, different parameters:
  Chat conversation — participants are chat members
  Keychain          — participants are device keys
  Organization role — participants are role holders
  Camera feed       — participants are authorized viewers
  Recovery          — participants are recovery attestors
```
See [EpochProtocol.md](EpochProtocol.md) for data structures, algorithms, invariants, failure modes.

## 12. Keychains — Identity Key Management
```javascript
// Keychain entry (single-writer hash-chained log, stored as SafecloudDB track)
{
  "op":        "rotate | add | revoke",
  "keyType":   "signing | encryption | threshold-share",
  "key":       "base64...",
  "prevHash":  "sha256:...",
  "recovery":  "base64...",
  "timestamp": 1697500000,
  "signature": "..."   // signed by owner, OCP Delegation typed data
}
// Track path: keychain/{pubkey-fingerprint}

// Fork detection: two entries with same prevHash = fork
// Detectable via gossip (any two readers comparing notes)
// Fork invalidates chain from fork point forward
// No blockchain required — inherent property of hash chains + gossip

// Recovery: dual-threshold
// BOTH required simultaneously:
//   M-of-N friend attestations (friends alone can't take over)
//   A-of-B cold personal keys (cold keys alone can't recover)
// Recovery is itself an epoch transition → new genesis, old chain tombstoned

// Delegation: Q.Crypto.delegate produces OCP grants recorded in keychain
// Same mechanism for: device auth, brand delegation, org role grants
```
See [Ecosystem.md §Keychains](Ecosystem.md#keychains), [README.md §22](README.md).

## 13. Organizations and Delegation
```
Organization = multi-participant hash chain
Each role = a SafecloudDB track with epoch-based membership

  org/acme/
    admin        ← hash chain, members: [alice, bob]
    finance      ← hash chain, members: [alice, carol]
    support      ← hash chain, members: [dave, eve, frank]
    board        ← hash chain, members: [alice, bob, carol]

Adding a member to "admin" = same operation as adding a member to a chat group
Removing a member = epoch transition, same as removing a chat member
Governance bottoms out at keychain level: root keychain + dual-threshold recovery

Delegation chain verification:
  delegate's key → authorized by brand's key → in brand's keychain → valid chain to genesis
```
See [Ecosystem.md §Organizations and DAOs](Ecosystem.md#organizations-and-daos).

## 14. Manifest (Public, No Secrets)
```javascript
{
    v: 1,
    rootCid: '...',
    encryptionRootPublicKey: '...',    // P-256 (65 bytes, uncompressed)
    accessRootPublicKey: '...',        // P-256 (65 bytes, uncompressed)
    bindingProof: '...',               // proves both keys + rootCid share one rootKey
    chunkCount: 42,
    chunkSize: 262144,                 // 256 KB default
    size: 10485760,
    name: 'photo.jpg'
}
// Manifest is safe to share publicly — no secrets, no plaintext
// bindingProof prevents key substitution attacks
```

## 15. HLS Service Worker
```javascript
// Service worker at Safecloud/sw.js intercepts:
//   https://safecloud-hls.local/{videoId}/master.m3u8
//   https://safecloud-hls.local/{videoId}/{version}/playlist.m3u8
//   https://safecloud-hls.local/{videoId}/{version}/seg-{N}.ts

// Populated by _prefetchLoop via postMessage:
//   { type: 'Q.Safecloud.Client.register', videoId, manifest, capability, versions }
//   { type: 'Q.Safecloud.Client.segment', videoId, version, segIndex, ciphertext, tag, iv }
//   { type: 'Q.Safecloud.Client.seek', videoId, segIndex }
//   { type: 'Q.Safecloud.Client.setVersion', videoId, version, manifest }
//   { type: 'Q.Safecloud.Client.stop', videoId }

// Decrypts segments on-the-fly, serves to <video> element as standard HLS
```

## 16. Server-Side Verification (Node.js)
```javascript
Q.Safecloud.Client.validateManifest(manifest);                      // → {ok, reason}
await Q.Safecloud.Client.verifyBindingProof(manifest);              // → Boolean
await Q.Safecloud.Client.verifyGrant(grant, rootCid, chunkIndex);   // → Boolean
Q.Safecloud.Drops.verifyAnnounce(announcePayload, publicKey);       // → Boolean
Q.Safecloud.Drops.verifyChallengeResponse(requestedCid, chunk);     // → Boolean
Q.Safecloud.Drops.shouldSlash(drop, failureLog);                    // → Boolean
```

## 17. Common Mistakes
| Wrong | Right |
|-------|-------|
| Storing rootKey on the server | rootKey stays client-side; server sees only manifest (no secrets) |
| Sending plaintext to Jets | Client encrypts before upload; Jets/Drops see only ciphertext |
| Skipping Merkle verification on fetch | Always verify — `Client.fetch` does this automatically |
| Hardcoding Jet URL | Use `Q.Safecloud.Jets.connect()` which handles reconnection |
| Ignoring bindingProof | Prevents key-substitution attacks; always include in manifest |
| Using `put` without payment tokens | Jets verify ERC-20 balance; include `payments` option |
| Not calling `Drops.announce()` after puts | Jets need inventory updates for routing; announce after batch puts |
| Serving sw.js without Service-Worker-Allowed header | HLS interception requires `Service-Worker-Allowed: /` header |
| Assuming Drops persist forever | Drops are browser tabs; data can disappear; redundancy via multiple Drops |
| Escrowing chain seeds instead of K_msg | Only escrow per-message key K_msg; HKDF one-way prevents seed leakage |
| Skipping proof-of-escrow for media | `send-media` handler requires valid escrow ciphertext; text messages pass without |
| Ignoring keychain fork signals | A fork means key theft or equivocation; invalidate from fork point forward |
| Assuming single-threshold recovery | Recovery requires BOTH friend attestations AND cold keys simultaneously |
| Paying Drops before verifying chunks | Always Merkle-verify, then sign settlement; intent token is unsigned |
| Sharing one watermark across all Drops | Each Drop gets its own watermark channel (line 1+) so slow Drops are not subsidized |
| Requesting chunks from a paused Drop | Check `_paused[dropId]` — a Drop that sent `Safecloud/drop/pause` must not receive requests |

## 18. Adaptive Drop Selection (Striped Downloads)

Large files are downloaded from multiple Drops in parallel. The client probes candidates by requesting the first chunk from all of them simultaneously, times each response, and classifies them into tiers: **Fast** (≥ 50% of best throughput), **Marginal** (≥ 10%), **Slow** (removed). Subsequent chunks go to Fast-tier Drops weighted by throughput. EMA tracking (`alpha = 0.3`, asymmetric failure decay) continuously re-ranks, catching mid-download degradation.

```javascript
// Enable adaptive selection
var blob = await Q.Safecloud.Client.fetch(manifest, cap, { adaptive: true });

// AdaptiveStreamer API (internal — used by fetch and _prefetchLoop)
var streamer = new Q.Safecloud.Client.AdaptiveStreamer(manifest, cap, opts);
await streamer.probe();                    // parallel first-chunk fetch
var drop = streamer.assignDrop();          // best available Drop
streamer.recordResult(dropId, true, bytes, elapsedMs);  // update EMA
streamer.shouldThrottle(dropId);           // true if unpaid > maxUnpaid
```

**Drop-side serving policy** — set at `Drops.init({ servingPolicy: { serveWhen: 'wifi-only' } })`. The Drop monitors `navigator.connection` and Battery API; sends `Safecloud/drop/pause` / `resume` to the Jet when its connection state violates or re-satisfies the policy. Router.js filters paused Drops from `selectForGet`/`selectForPut`.

**Micropayment ramping** — payment is split: unsigned intent on request, signed settlement after Merkle-verified receipt. Per-drop watermark channels (line 0 = Jet infra, line 1+ = per Drop). Max unpaid window: 1 (probe) → 3 (ramp-up) → 8 (steady) → 16 (trusted). See [AdaptiveStreamer.md](AdaptiveStreamer.md) for full algorithm.
