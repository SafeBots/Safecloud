# Q.Safecloud.Client — Implementation Design Document

## Table of Contents

- [Part 1 — Key Design Decisions](#part-1--key-design-decisions)
  - [1.1 Responsibilities: Cloud vs Jets vs Drops](#11-responsibilities-cloud-vs-jets-vs-drops)
  - [1.2 Three parallel trees from one root](#12-three-parallel-trees-from-one-root)
  - [1.3 N-ary Merkle tree — built bottom up](#13-n-ary-merkle-tree--built-bottom-up)
  - [1.4 Encryption key tree — built top down](#14-encryption-key-tree--built-top-down)
  - [1.5 Access level tree — built top down](#15-access-level-tree--built-top-down)
  - [1.6 Link paths — navigating all three trees](#16-link-paths--navigating-all-three-trees)
  - [1.7 Tracks — top-level branches](#17-tracks--top-level-branches)
  - [1.8 Prolly tree — inventory, not content](#18-prolly-tree--inventory-not-content)
  - [1.9 Bloom filter](#19-bloom-filter)
  - [1.10 Chunking and tree shape](#110-chunking-and-tree-shape)
  - [1.11 Binding proof](#111-binding-proof)
  - [1.12 Manifest](#112-manifest)
  - [1.13 Capability schema](#113-capability-schema)
  - [1.14 HLS, service worker, and player integration](#114-hls-service-worker-and-player-integration)
  - [1.15 Versioned trees — multiple renditions](#115-versioned-trees--multiple-renditions)
- [Part 2 — Jets, Drops and platform interface](#part-2--jets-drops-and-platform-interface)
- [Part 3 — _internal.js helpers](#part-3--_internaljs-helpers)
- [Part 4 — Ergonomic public API](#part-4--ergonomic-public-api)
- [Part 5 — Power API and internals](#part-5--power-api-and-internals)
- [Part 6 — Implementation Order](#part-6--implementation-order)
- [Part 7 — What is NOT in Cloud.js](#part-7--what-is-not-in-cloudjs)

---

## Part 1 — Key Design Decisions

### 1.1 Responsibilities: Cloud vs Jets vs Drops

**Q.Safecloud.Client** is responsible for:
- All key derivation (rootKey → tracks → subtree nodes → chunks)
- Encrypting plaintext before any data leaves the device
- Decrypting received ciphertext and verifying Merkle proofs
- Producing capabilities (delegation proofs) that authorize third parties
- Assembling and parsing the public manifest
- Requesting upload/download via `Jets.put()` / `Jets.get()`
- Setting up the HLS service worker for video playback

**Q.Safecloud.Jets** is responsible for:
- Enforcing the access level tree (OCP Role A verification)
- Routing encrypted chunks to/from Drops
- Prolly tree maintenance for inventory reconciliation
- Bloom filter cold-start with Drops
- Proof-of-storage challenges

**Q.Safecloud.Drops** is responsible for:
- Storing and serving encrypted chunks in IndexedDB by CID
- LRU eviction, proof-of-storage responses

**The key boundary rule:** Cloud never stores ciphertext. Jets never see
plaintext or encryption keys. Drops never see plaintext.

---

### 1.2 Three parallel trees from one root

Every stored file has three parallel trees all rooted at the same `rootCid`.
The same N-ary tree shape, and the same **link path** array navigates all three.
But they serve completely different purposes and are built in opposite directions.

```
MERKLE TREE (commitment — built bottom up from ciphertext)
  rootCid
    ├── track/data/...   ← hashes of encrypted chunk CIDs
    └── track/index      ← hash of encrypted index chunk CID

ENCRYPTION KEY TREE (privacy — built top down, Cloud only)
  encryptionRoot
    ├── delegate(["track","data",...])  → subtreeKey → chunkKey[i] / chunkIV[i]
    └── delegate(["track","index"])    → indexTrackKey

ACCESS LEVEL TREE (authorization — built top down, Jets enforce)
  accessRoot
    ├── delegate(["track","data",...])  → carries readLevel, writeLevel, adminLevel
    └── delegate(["track","index"])    → carries readLevel
```

**Merkle tree** is a commitment over ciphertext, built bottom up. Same chunks
anywhere → same CIDs → free deduplication. Jets and Drops operate purely on
CIDs — they never know the tree structure.

**Encryption key tree** is built top down via chained `Q.Crypto.delegate` calls,
one per path segment. Cloud holds this. Jets never see it. Delegating at any
internal node grants decryption access to all chunks below that node.

**Access level tree** is structurally identical to the encryption key tree, but
uses different label prefixes and carries Streams-compatible access levels
(`readLevel`, `writeLevel`, `adminLevel`) in the delegation context.
Jets verify the access tree before serving any ciphertext.
A Jet can enforce read access without being able to decrypt anything.

**Why separate encryption and access trees:** CDNs can cache ciphertext
publicly because the access tree is separate. Two users with different grants
receive identical ciphertext (same CID, same bytes) but hold different subtree
keys. Deduplication works across all users of the same content.

**Prolly tree** is per Jet/Drop, not per file. Records `rootCid → present`.
Used only for inventory comparison. Never mixed with file structure.

---

### 1.3 N-ary Merkle tree — built bottom up

The Merkle tree is N-ary (branching factor N, default 2).
It is built bottom up from leaf chunk CIDs.

**Structure for a binary tree, depth 3:**

```
Level 0 (leaves):  [cid0, cid1, cid2, cid3, cid4, cid5, cid6, cid7]
Level 1:           [H(cid0,cid1), H(cid2,cid3), H(cid4,cid5), H(cid6,cid7)]
Level 2:           [H(h01,h23),   H(h45,h67)]
Level 3 (root):    H(h0123, h4567)
```

Track nodes sit above the chunk leaves in the full file tree:

```
rootCid = H(trackDataNode, trackIndexNode)
  trackDataNode  = Merkle root over data chunk leaves
  trackIndexNode = Merkle root over index chunk leaf
```

**Domain separation:**
- Leaf: `SHA-256(0x00 || UTF8(cid))`
- Internal node: `SHA-256(0x01 || child_0 || child_1 || ... || child_{N-1})`

**Tree shape parameters:**
- `treeN` — branching factor (default 2). Stored in manifest.
- `treeDepth` — depth of the data track subtree. Stored in manifest.
- A binary tree of depth D covers up to `2^D` leaf chunks.
- For N=2, depth=5: 32 chunks per subtree = 32 × 256KB ≈ 8MB.

**`Q.Data.Merkle` additions needed for N-ary tree with tracks:**

```js
// Build N-ary tree from a structured track object
Q.Data.Merkle.buildTree(tracks, N)
// tracks = { data: [cid0..cidM], index: [cidIndex] }
// Builds track nodes, then root over track nodes.
// Returns: { rootCid, trackRoots: { data: String, index: String }, ... }

// Navigate to an internal node by link path
Q.Data.Merkle.getNode(rootCid, linkPath, store)
// linkPath = ["track","data","0","1"]
// Returns: node hash at that path

// Inclusion proof for a node at a path
Q.Data.Merkle.nodeProof(rootCid, linkPath, store)
// Returns: Array<{ hash: String, side: Number }>
```

---

### 1.4 Encryption key tree — built top down

Keys are derived by chaining `Q.Crypto.delegate` once per path segment,
top down from `encryptionRoot`.

**Full derivation chain example (binary tree, data track, path ["track","data","0","1"]):**

```
rootKey
  → delegate("safecloud.encryption.root", '{}')
      → encryptionRoot

encryptionRoot
  → delegate("safecloud.track.data", '{}')
      → trackDataKey

trackDataKey
  → delegate("safecloud.node.0", '{}')
      → subtreeKey_0

subtreeKey_0
  → delegate("safecloud.node.1", '{}')
      → subtreeKey_0_1     ← this is what a grantee receives

subtreeKey_0_1
  → derive("safecloud.chunk.key.0") → chunkKey[0] (relative index 0 within this subtree)
  → derive("safecloud.chunk.key.1") → chunkKey[1]
  → derive("safecloud.chunk.iv.0")  → chunkIV[0]
  → derive("safecloud.chunk.iv.1")  → chunkIV[1]
```

**Rule:** `Q.Crypto.delegate` is used for every path segment down to (and including)
the subtree node. `Q.Data.derive` is used only for leaf chunk key/IV derivation
(O(N) calls, proof never needed).

**Helper `_.deriveByPath(parentKey, linkPath, context)` → Promise<Object>:**

Chains `delegate` down the path. At each segment except the last, context is
`'{}'`. At the last segment (tip), context is the full grant context JSON string.

```js
// Upload time: no rootCid yet, context is minimal
_.deriveByPath(encryptionRoot, ["track","data","0","1"], '{}')

// Grant time: full context with rootCid and access levels
_.deriveByPath(encryptionRoot, ["track","data","0","1"],
  JSON.stringify({ rootCid, link: ["track","data","0","1"], readLevel: 23, exp: 0 }))
```

---

### 1.5 Access level tree — built top down

Structurally identical to §1.4 but:
- Derived from `accessRoot` (not `encryptionRoot`)
- Label prefix: `"safecloud.access.track.*"` and `"safecloud.access.node.*"`
- Context at grant tip: `{ rootCid, link, readLevel, writeLevel, adminLevel, exp }`

Jets verify this delegation chain before serving ciphertext.
The grantee presents the access tree proof; Jets check the access level meets
the required minimum. No encryption key is involved.

**Canonical derivation table:**

| Step | Function | Reason |
|------|----------|--------|
| `rootKey → encryptionRoot` | `Q.Crypto.delegate` | Once per operation |
| `rootKey → accessRoot` | `Q.Crypto.delegate` | Once per operation |
| `videoKey → versionRootKey` | `Q.Crypto.delegate` | Once per version |
| `*Root → track node` | `Q.Crypto.delegate` (path segment) | Delegation unit |
| `track → subtree node` | `Q.Crypto.delegate` (path segment) | Delegation unit |
| `subtreeKey → chunkKey[i]` | `Q.Data.derive` | O(N), never delegated |
| `subtreeKey → chunkIV[i]` | `Q.Data.derive` | O(N), never delegated |

---

### 1.6 Link paths — navigating all three trees

A **link path** is an array of string segments navigating from the file's
`rootCid` downward through the tree:

```js
["track", "data"]              // data track root
["track", "data", "0"]         // left child of data track root
["track", "data", "0", "1"]    // right child of left child
["track", "index"]             // index track
```

The same link path navigates:
- The **Merkle tree** — `Merkle.getNode(rootCid, linkPath, store)`
- The **encryption key tree** — `deriveByPath(encryptionRoot, linkPath, ctx)`
- The **access level tree** — `deriveByPath(accessRoot, linkPath, ctx)`

**Grants use link paths, not `{start, end}` ranges:**

```json
{
  "link":      ["track", "data", "0", "1"],
  "secret":    "<base64 subtreeKey at this node>",
  "statement": {
    "label":   "safecloud.node.1",
    "context": "{\"rootCid\":\"bafy...\",\"link\":[\"track\",\"data\",\"0\",\"1\"],\"readLevel\":23,\"exp\":0}",
    "issuedTime": 1700000000,
    "secretHash": "...",
    "parent": "..."
  },
  "proof": { ... }
}
```

**Non-contiguous access** — pass an array of grants:

```js
grants: [
  { link: ["track","data","0","1"], secret: "...", ... },  // minutes 2-4
  { link: ["track","data","1","0"], secret: "...", ... },  // minutes 8-10
  { link: ["track","index"],        secret: "...", ... }   // full index
]
```

The recipient can decrypt exactly the subtrees they hold keys for. Jets verify
each grant's access level covers the requested link path before serving.

---

### 1.7 Tracks — top-level branches

Tracks are the first level of path segments below the root. The Merkle root
commits to all tracks jointly — swapping one track invalidates the root.
Each track is independently grantable because the key derivation branches
at the track level.

**Currently defined tracks:**

| Track name | Link path prefix | Content |
|-----------|-----------------|---------|
| `data` | `["track","data",...]` | Encrypted content chunks |
| `index` | `["track","index"]` | Encrypted metadata (initSegment, chapters, codec) |

**Future tracks (no protocol change needed):**

| Track name | Content |
|-----------|---------|
| `thumbs` | Thumbnail images per chapter |
| `preview` | Low-resolution rendition |
| `audio` | Alternative audio language |
| `audit` | Provenance / access log |

Tracks run in parallel — same coordinate system (chunk index = time for video),
committed by the same root, independently encrypted and grantable.

The index track carries what would otherwise be unencrypted manifest metadata:
codec, resolution, duration, chapter timestamps, fMP4 init segment.
Without an index track grant, a recipient knows nothing about the content
except that it exists and has N chunks.

---

### 1.8 Prolly tree — inventory, not content

Owned entirely by Jets and Drops. Cloud never calls `Q.Data.Prolly` directly.

The Prolly tree records `{ rootCid → present }` per Jet/Drop.
It answers "do you have this file?" — not anything about the file's structure.

Bloom filter = fast pre-screen (`O(1)`, false positives OK).
Prolly diff = precise set reconciliation.

Completely separate from the per-file Merkle tree.

---

### 1.9 Bloom filter

Owned entirely by Drops and Jets. Cloud never calls `Q.Data.Bloom`.

---

### 1.10 Chunking and tree shape

Fixed chunk size: `defaultChunkSize = 256 * 1024` (256 KB).

For video, GOP-aligned chunks (every chunk starts with a keyframe) allow any
subtree node to be decoded independently without needing prior chunks.

**Tree shape selection at upload time:**
- Branching factor N (default 2, stored in `manifest.treeN`)
- Depth D computed from `ceil(log_N(chunkCount))`, stored in `manifest.treeDepth`
- The data track is a complete N-ary tree padded to the nearest `N^D` leaves

For N=2, depth=5: 32 chunks per subtree ≈ 8MB.
A 1-hour 1080p video at 4Mbit/s ≈ 1800MB ≈ 7000 chunks ≈ depth 13.

---

### 1.11 Binding proof

`manifest.bindingProof` ties `encryptionRootPublicKey` and `accessRootPublicKey`
together and commits to `rootCid`. Signed by `encryptionRoot` via `Q.Crypto.sign`.
Anyone can verify using `encryptionRootPublicKey` from the manifest.

---

### 1.12 Manifest

Fully public. Contains no content metadata — all of that is in the encrypted
`track/index` node.

```json
{
  "v":                       1,
  "rootCid":                 "bafy...",
  "treeN":                   2,
  "treeDepth":               5,
  "chunkCount":              143,
  "chunkSize":               262144,
  "size":                    37498880,
  "name":                    "video.mp4",
  "type":                    "video/mp4",
  "created":                 1700000000,
  "tracks":                  ["data", "index"],
  "encryptionRootPublicKey": "<base64 P-256 uncompressed>",
  "accessRootPublicKey":     "<base64 P-256 uncompressed>",
  "bindingProof": {
    "statement": { "encryptionRootPublicKey": "...", "accessRootPublicKey": "...", "rootCid": "..." },
    "proof":     { ... }
  },
  "jurisdiction":   null,
  "aiAttestation":  null
}
```

Key changes from the old flat design:
- `treeN` and `treeDepth` describe the N-ary data track structure
- `tracks` lists which tracks are present
- No `indexCid` field — the index track CID is found by
  `Merkle.getNode(rootCid, ["track","index"], store)`. The root commits to it;
  no separate field is needed or desirable (it would be redundant and
  potentially inconsistent).

---

### 1.13 Capability schema

A capability is an array of grants, each covering one subtree node by link path.

```js
// Single grant:
{
  link:      Array,    // path from rootCid, e.g. ["track","data","0","1"]
  secret:    String,   // base64 subtreeKey at this node (encryption tree)
  statement: Object,   // access tree delegation statement
                       // stm.context = JSON { rootCid, link, readLevel,
                       //               writeLevel, adminLevel, exp }
  proof:     Object    // Q.Crypto.sign result
}

// Full capability passed to fetch() / stream():
{
  rootCid:  String,
  grants:   Array<Grant>,
  manifest: Object
}

// Owner shorthand (Cloud derives everything):
{ rootKey: String }
```

Multi-track access: grants for different tracks in the same array.

```js
grants: [
  { link: ["track","data","0"],    ... },  // data track left subtree
  { link: ["track","data","1"],    ... },  // data track right subtree
  { link: ["track","index"],       ... }   // index track
]
```

---

### 1.14 HLS, service worker, and player integration

The SW now resolves keys by navigating link paths rather than flat `{start,end}`
ranges. When a segment request arrives for chunk index N, the SW finds the grant
whose link path covers that chunk's position in the tree, then chains `HKDF`
down the path to recover the subtreeKey, derives chunkKey, and decrypts.

MSE path (iOS 16.4+): fetch index track first to get `initSegment`, codec,
and chapter timestamps. Then feed decrypted data chunks to `SourceBuffer`.

---

### 1.15 Versioned trees — multiple renditions

Unchanged from before. `videoKey` → per-version `rootKey` via
`delegate("safecloud.version.720p")`. Each version has its own Merkle tree
and its own link path space. Tree shape (`treeN`, `treeDepth`) should be
identical across versions so chunk index i is the same time in all versions.

---

## Part 2 — Jets, Drops and platform interface

### `Q.Safecloud.Jets.put(subtree, options, callback)`

```
subtree: {
  chunks:  Array<{ cid, iv, ciphertext, tag, size, tags }>,
  link:    Array,   // path to this subtree node in the tree
  grants:  Array    // capability grants for this subtree
}
options: { authorizations, payments, onProgress }
Returns: Promise<{ results: Array<{ cid, stored }> }>
```

### `Q.Safecloud.Jets.get(subtree, options, callback)`

```
subtree: {
  rootCid: String,
  link:    Array,   // path to the subtree to fetch, e.g. ["track","data","0"]
  grants:  Array    // capability grants covering this link path
}
options: { authorizations, payments, onProgress }
Returns: Promise<{
  chunks: Array<{ cid, iv, ciphertext, tag, proof }|null>
}>
```

All other Jets/Drops/Q.Data/Q.Crypto methods unchanged.

---

## Part 3 — `_internal.js` helpers

### `_.LABELS`

```
// Q.Crypto.delegate labels
LABELS.encryptionRoot      = 'safecloud.encryption.root'
LABELS.accessRoot          = 'safecloud.access.root'
LABELS.version(v)          = 'safecloud.version.' + v
LABELS.track(name)         = 'safecloud.track.' + name
  // e.g. 'safecloud.track.data', 'safecloud.track.index'
LABELS.accessTrack(name)   = 'safecloud.access.track.' + name
LABELS.node(segment)       = 'safecloud.node.' + segment
  // e.g. 'safecloud.node.0', 'safecloud.node.1'
LABELS.accessNode(segment) = 'safecloud.access.node.' + segment

// Q.Data.derive labels (chunk-level only, never delegated)
LABELS.chunkKey(i)         = 'safecloud.chunk.key.' + i
LABELS.chunkIV(i)          = 'safecloud.chunk.iv.' + i
```

### `_.deriveByPath(parentKey, linkPath, tipContext)` → Promise<Object>

New core helper. Chains `Q.Crypto.delegate` once per segment in `linkPath`.

```
linkPath = ["track", "data", "0", "1"]

1. label = LABELS.track("data")   → delegate(parentKey, label, '{}')
2. label = LABELS.node("0")       → delegate(step1.secret, label, '{}')
3. label = LABELS.node("1")       → delegate(step2.secret, label, tipContext)

Returns: step3 full delegation result { secret, statement, proof }
```

The first segment uses `LABELS.track(segment)` / `LABELS.accessTrack(segment)`.
All deeper segments use `LABELS.node(segment)` / `LABELS.accessNode(segment)`.
This distinction allows Jets to identify track-level vs subtree-level grants.

### `_.deriveSubtreeKey(encryptionRoot, linkPath)` → Promise<Object>

Wraps `_.deriveByPath(encryptionRoot, linkPath, '{}')`.
Used at upload time when rootCid is not yet known.

### `_.deriveByAccessPath(accessRoot, linkPath, grantContext)` → Promise<Object>

Same as `_.deriveByPath` but uses `LABELS.accessTrack` and `LABELS.accessNode`.
Used when producing access tree grants.

### All chunk helpers unchanged

`_.deriveChunkKey`, `_.deriveChunkIV`, `_.chunkAAD`, `_.chunkCid`,
`_.blobToBuffer`, `_.chunkify`, `_.base32`, `_.digestToCid`,
`_.deriveEncryptionRoot`, `_.deriveAccessRootBytes`, `_.deriveVersionKey`.

### `_.buildManifest(p)` — updated fields

Now includes `treeN`, `treeDepth`, `tracks`. No `indexCid`.

---

## Part 4 — Ergonomic public API

Unchanged: `upload`, `download`, `play`, `pause`. Same signatures.
`play()` → `stream()` → auto-detects SW/MSE/blob path.

---

## Part 5 — Power API

### `store(file, options, callback)` — updated

**Step 8 onwards changes:**

Instead of one flat subtree `[0, N)`, build the N-ary tree:

```
chunks = chunkify(buffer, chunkSize)          // M chunks
treeN  = options.treeN || 2
treeDepth = ceil(log_N(chunks.length))

// Build data track Merkle tree
// + encrypt index (if options.index provided)
// + build root over [trackDataNode, trackIndexNode]

// For each internal node in the tree, derive subtreeKey:
// deriveByPath(encryptionRoot, ["track","data","0"], '{}') → subtreeKey for left half
// deriveByPath(encryptionRoot, ["track","data","1"], '{}') → subtreeKey for right half
// etc. — one delegation per internal node

// Jets.put per track:
Jets.put({ chunks: dataChunks, link: ["track","data"], grants: [...] })
Jets.put({ chunks: [idxChunk], link: ["track","index"], grants: [...] })
```

### `grant(manifest, rootKey, options, callback)` — updated signature

```js
grant(manifest, rootKey, {
  linkPaths:  Array<Array>,  // e.g. [["track","data","0"],["track","index"]]
  readLevel:  'content',
  writeLevel: null,
  adminLevel: null,
  exp:        0,
  format:     'ES256'
})
```

For each link path:
1. `deriveByPath(encryptionRoot, linkPath, '{}')` → encSubtreeKey (secret)
2. `deriveByAccessPath(accessRoot, linkPath, fullContext)` → access proof
   where `fullContext = JSON.stringify({ rootCid, link: linkPath, readLevel, exp })`
3. Returns `{ link, secret: toBase64(encSecret), statement: accessProof.statement, proof: accessProof.proof }`

### `fetch(manifest, capability, options, callback)` — updated

For each grant in `capability.grants`:
1. Navigate `Merkle.getNode(rootCid, grant.link)` → get CIDs in that subtree
2. Use `grant.secret` as `subtreeKey`
3. Decrypt each chunk with `deriveChunkKey(subtreeKey, relIndex)` where
   `relIndex` is position within that subtree node's leaf range

---

## Part 6 — Implementation Order

1. `_.LABELS` — updated with track/node/accessTrack/accessNode labels
2. `_.base32`, `_.digestToCid`, `_.chunkAAD`, `_.blobToBuffer`, `_.chunkify` — unchanged
3. `_.deriveEncryptionRoot`, `_.deriveAccessRootBytes`, `_.deriveVersionKey` — unchanged
4. **`_.deriveByPath(parentKey, linkPath, tipContext)`** — new core helper
5. **`_.deriveByAccessPath(accessRoot, linkPath, grantContext)`** — new access helper
6. `_.deriveSubtreeKey(encryptionRoot, linkPath)` — wraps `deriveByPath`
7. `_.deriveChunkKey`, `_.deriveChunkIV` — unchanged
8. `_.chunkCid`, `_.buildManifest` — updated for treeN/treeDepth/tracks
9. `store.js` — N-ary `Merkle.buildTree`, `deriveByPath` per node
10. `fetch.js` — `Merkle.getNode` + navigate by link path
11. `grant.js` — takes `linkPaths`, calls `deriveByPath` + `deriveByAccessPath`
12. `fetchIndex.js` — navigates `["track","index"]`
13. `grantIndex.js` — grants `["track","index"]` only
14. `_prefetchLoop.js` — resolves key by link path from grants
15. `stream.js`, `streamMSE.js` — fetch index track first; key resolution by link
16. `upload.js`, `download.js`, `play.js`, `pause.js` — unchanged

---

## Part 7 — What is NOT in Cloud.js

- `Q.Data.Prolly.*` — Jets only (inventory comparison, not file structure)
- `Q.Data.Bloom.*` — Drops and Jets only
- OCP payment and authorization verification — Jets and Drops only
- On-chain balance checks — server-side only
- Service Worker fetch handler — `Safecloud/sw.js`
- HLS video segmentation / ffmpeg — pre-processing pipeline
- Socket.io connection management — Jets only
- Drop registration and lifecycle — Jets and Drops only
