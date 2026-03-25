# Q.Safe.Cloud — Implementation Design Document

## Table of Contents

- [Part 1 — Key Design Decisions](#part-1--key-design-decisions)
  - [1.1 Responsibilities: Cloud vs Jets vs Drops](#11-responsibilities-cloud-vs-jets-vs-drops)
  - [1.2 Q.Crypto.delegate everywhere](#12-qcryptodelegateverywhere)
  - [1.3 Chunking](#13-chunking)
  - [1.4 Merkle tree](#14-merkle-tree)
  - [1.5 Prolly tree](#15-prolly-tree)
  - [1.6 Bloom filter](#16-bloom-filter)
  - [1.7 Binding proof](#17-binding-proof)
  - [1.8 Manifest](#18-manifest)
  - [1.9 Capability schema](#19-capability-schema)
  - [1.10 HLS, service worker, and player integration](#110-hls-service-worker-and-player-integration)
  - [1.11 Versioned trees — multiple renditions of the same logical file](#111-versioned-trees--multiple-renditions-of-the-same-logical-file)
- [Part 2 — Jets, Drops and platform interface (called by Cloud)](#part-2--jets-drops-and-platform-interface-called-by-cloud)
  - [Q.Safe.Jets.connect(callback)](#qsafejetsconnectcallback)
  - [Q.Safe.Jets.dropAnnounce(info, callback)](#qsafejetsdroppannounceinfoinfo-callback)
  - [Q.Safe.Jets.put(subtree, options, callback)](#qsafejetsputsubtree-options-callback)
  - [Q.Safe.Jets.get(subtree, options, callback)](#qsafejetsgetsubtree-options-callback)
  - [Q.Safe.Drops.put(chunks, options, callback)](#qsafedropsputchunks-options-callback)
  - [Q.Data.importKey(keyBytes, algo)](#qdataimportkeykeybytes-algo)
  - [Q.Crypto.sign(options)](#qcryptosignoptions)
  - [Q.Data.Merkle.build(leaves)](#qdatamerklebuildleaves)
  - [Q.Data.Merkle.verify(leaf, proof, root)](#qdatamerkleverifyleaf-proof-root)
  - [Q.Crypto.internalKeypair(options)](#qcryptointernalkeypaitoptions)
  - [Q.Data.encrypt(cryptoKey, data, options)](#qdataencryptcryptokey-data-options)
  - [Q.Data.decrypt(cryptoKey, iv, ciphertext, options)](#qdatadecryptcryptokey-iv-ciphertext-options)
  - [Q.Data.toBase64 / Q.Data.fromBase64](#qdatatbase64--qdatafrombase64)
  - [Q.Data.digest(algorithm, data)](#qdatadigestalgorithm-data)
  - [Q.Data.Merkle.proof(leaves, index)](#qdatamerkleproofleaves-index)
  - [Q.Crypto.delegate(options)](#qcryptodelegateoptions)
- [Part 3 — _internal.js helpers (bottom of the dependency tree)](#part-3--_internaljs-helpers-bottom-of-the-dependency-tree)
  - [_.LABELS](#_labels)
  - [_.base32(bytes)](#_base32bytes)
  - [_.digestToCid(digest)](#_digesttociddigest)
  - [_.chunkAAD(absIndex)](#_chunkaadabsindex)
  - [_.blobToBuffer(blob)](#_blobtobufferblobpromisearraybuffer)
  - [_.chunkify(buffer, chunkSize)](#_chunkifybuffer-chunksize)
  - [_.deriveEncryptionRoot(rootKey)](#_deriveencryptionrootrootkey)
  - [_.deriveAccessRootBytes(rootKey)](#_deriveaccessrootbytesrootkey)
  - [_.deriveVersionKey(videoKey, versionLabel)](#_deriveversionkeyvideokeyersionlabel)
  - [_.deriveSubtreeKey(encryptionRoot, start, end)](#_derivesubtreekeyencryptionroot-start-end)
  - [_.deriveChunkKey(subtreeKey, relIndex)](#_derivechunkkeysubtreekey-relindex)
  - [_.deriveChunkIV(subtreeKey, relIndex)](#_derivechunkivsubtreekey-relindex)
  - [_.chunkCid(ciphertextB64, tagB64)](#_chunkcidciphertextb64-tagb64)
  - [_.buildManifest(p)](#_buildmanifestp)
  - [_.levelFromLabel(type, word)](#_levelfromlabeltype-word)
  - [_.parseLabel(label)](#_parselabellabel)
  - [_.verifyCapability(proof, type, required, chunkIndex)](#_verifycapabilityproof-type-required-chunkindex)
- [Part 4 — Ergonomic public API](#part-4--ergonomic-public-api)
  - [Q.Safe.Cloud.download(manifest, capability, options, callback)](#qsafeclouddownloadmanifest-capability-options-callback)
  - [Q.Safe.Cloud.pause(handle)](#qsafecloudpausehandle)
  - [Q.Safe.Cloud.play(videoManifest, capability, options)](#qsafecloudplayvideomanifest-capability-options)
  - [Q.Safe.Cloud.upload(file, options, callback)](#qsafeclouduploadfile-options-callback)
- [Part 5 — Power API and internals](#part-5--power-api-and-internals)
  - [Q.Safe.Cloud._ensureServiceWorker()](#qsafecloud_ensureserviceworker)
  - [Q.Safe.Cloud._prefetchLoop(videoId, videoManifest, capability, options)](#qsafecloud_prefetchloopvideoid-videomanifest-capability-options)
  - [Q.Safe.Cloud.fetch(manifest, capability, options, callback)](#qsafecloudfetchmanifest-capability-options-callback)
  - [Q.Safe.Cloud.grant(manifest, rootKey, options, callback)](#qsafecloudgrantmanifest-rootkey-options-callback)
  - [Q.Safe.Cloud.reshare(chunks, options, callback)](#qsafecloudresharechunks-options-callback)
  - [Q.Safe.Cloud.store(file, options, callback)](#qsafecloudstorefile-options-callback)
  - [Q.Safe.Cloud.stream(videoManifest, capability, options)](#qsafecloudstreamvideomanifest-capability-options)
- [Part 6 — Implementation Order](#part-6--implementation-order)
- [Part 7 — What is NOT in Cloud.js](#part-7--what-is-not-in-cloudjs)

---

This document is the authoritative spec for an LLM to implement `Q.Safe.Cloud`
function by function, bottom-up. Every decision that could have gone another way
is explained. Read `safecloud_summary.md` first for the broader architecture.

---

## Part 1 — Key Design Decisions

### 1.1 Responsibilities: Cloud vs Jets vs Drops

Understanding the boundary between these three layers is critical before
implementing any method.

**Q.Safe.Cloud** (this file) is responsible for:
- Key derivation hierarchy (rootKey → encryptionRoot → subtreeKey → chunkKey/IV)
- Encrypting plaintext chunks with AES-256-GCM before any data leaves the device
- Decrypting received ciphertext and verifying Merkle proofs before returning plaintext
- Producing capabilities (delegation proofs) that authorize third parties
- Assembling and parsing the public manifest
- Requesting upload/download via `Jets.put()` / `Jets.get()` — which are thin
  wrappers over the Jets socket that accept a subtree (range + capability) as the unit of work
- Setting up the HLS service worker for video playback

**Q.Safe.Jets** (client-side socket layer, already implemented) is responsible for:
- Maintaining the socket.io connection to the Jet server
- `Jets.put(subtree, options)` — receives a subtree of encrypted chunks and
  their CIDs from Cloud, handles routing to Drops including retries and
  replication, tracks Prolly tree state for inventory reconciliation, returns
  per-chunk results
- `Jets.get(subtree, options)` — receives a subtree descriptor (manifest rootCid
  + chunk range), fetches from Drops, attaches Merkle proofs, returns encrypted
  chunks with proofs
- Prolly tree building, diffing, and Drop reconciliation entirely within Jets
- Bloom filter cold-start handshake with Drops
- Proof-of-storage challenges to Drops
- OCP authorization and payment verification on received requests

**Q.Safe.Drops** (browser IndexedDB storage, already implemented) is responsible for:
- Storing encrypted chunks in IndexedDB keyed by CID
- Serving encrypted chunks on request
- LRU eviction when storage quota is exceeded
- Responding to proof-of-storage challenges from Jets

**The key boundary rule:** Cloud never stores ciphertext. Jets never sees
plaintext. Drops never sees plaintext. The only plaintext that exists is in
Cloud's memory during `store()` and `fetch()`.

---

### 1.2 `Q.Crypto.delegate` everywhere

`Q.Crypto.delegate` is used for **all subtree key derivations**, not just at
grant time. This is the correct design for the following reasons:

**Every subtreeKey is potentially a third-party token.** The purpose of a
subtreeKey is to hand a bounded slice of decryption capability to a grantee.
Even for a full-file owner fetch, the subtreeKey for `[0, N)` is the thing
the owner holds and could delegate. Using `Q.Crypto.delegate` from the start
means the derivation is always provable, consistent, and auditable — the same
code path whether or not you end up sharing it.

**`issuedTime` is in the statement wrapper, not in the derived secret bytes.**
The derived secret itself — `Q.Data.derive(encryptionRoot, "q.crypto.delegate."
+ label, {size:32})` — is deterministic regardless of when `delegate` is called.
Two calls to `delegate` for the same (encryptionRoot, label) at different times
produce different statements, but identical `secret` bytes. The convergent
encryption property is fully preserved: same rootKey + same content → same
chunk keys → same CIDs.

**Multi-subtree clip grants.** A video clip that doesn't align cleanly to a
single subtree boundary is granted as an array of capabilities, one per subtree
range. This is natural with `delegate`: call it once per subtree with the
appropriate label and context. The grantee presents the array to Jets, which
validates the union covers the requested range.

**`Q.Crypto.delegate` overhead per call:** ~2 HKDFs + 1 P-256 scalar
multiply + 1 ECDSA sign ≈ 3–5ms. For the roots and subtree this is called
once per operation — completely negligible. For chunkKey/IV it would be
O(N chunks), so those two stay as `Q.Data.derive`.

**Canonical derivation table:**

| Step | Function | Reason |
|------|----------|--------|
| `rootKey → encryptionRoot` | `Q.Crypto.delegate` | Consistent; trivial cost once per operation |
| `rootKey → accessRootBytes` | `Q.Crypto.delegate` | Consistent; trivial cost once per operation |
| `videoKey → versionRootKey` | `Q.Crypto.delegate` | Consistent; trivial cost once per version |
| `encryptionRoot → subtreeKey` | `Q.Crypto.delegate` | Unit of delegation; proof used by Jets |
| `subtreeKey → chunkKey[i]` | `Q.Data.derive` | O(N chunks); proof never used; pure perf |
| `subtreeKey → chunkIV[i]` | `Q.Data.derive` | O(N chunks); proof never used; pure perf |

The proof returned by each `Q.Crypto.delegate` call is kept in hand — `grant()`
reuses it rather than calling `delegate` again.

**Delegate label examples:**

```
rootKey → encryptionRoot:
  rootSecret = rootKey
  label      = LABELS.encryptionRoot  = 'safecloud.encryption.root'
  context    = '{}'

rootKey → accessRootBytes:
  rootSecret = rootKey
  label      = LABELS.accessRoot      = 'safecloud.access.root'
  context    = '{}'

videoKey → versionRootKey:
  rootSecret = videoKey
  label      = LABELS.version(label)  = 'safecloud.version.720p'
  context    = '{}'

encryptionRoot → subtreeKey:
  rootSecret = encryptionRoot
  label      = LABELS.subtree(0,1000) = 'safecloud.subtree.0.1000'
  context    = JSON.stringify({ rootCid, start, end [, exp] })
```

---

### 1.3 Chunking

Fixed chunk size: `Q.Safe.Cloud.defaultChunkSize = 256 * 1024` (256 KB).

Tradeoffs:
- Small enough that first-chunk latency is low (good for streaming start)
- Large enough that per-chunk overhead (CID lookup, decrypt setup) does not dominate
- Matches HLS segment size well at typical video bitrates (1–4 Mbit/s →
  6s segment = 750 KB–3 MB = 3–12 chunks per segment)
- Last chunk is always smaller (trimmed to actual file length)

SubtleCrypto (`Q.Data.encrypt`, `Q.Data.derive`) runs off the main thread
natively. `Promise.all(chunks.map(...encrypt...))` gets real parallelism without
Web Workers. No additional Worker infrastructure is needed.

---

### 1.4 Merkle tree

`Q.Data.Merkle.build(cids)` over the ordered array of CID strings.

- CIDs are strings, treated as UTF-8 by `Merkle.build`
- The root is stored as `manifest.rootCid`
- Domain separation: leaf = `SHA-256(0x00 || bytes)`, internal = `SHA-256(0x01 || L || R)`
- Used for **integrity verification on fetch** — each chunk is Merkle-verified
  before decryption
- NOT used for content-addressing chunks themselves (CIDs do that)
- NOT used for inventory reconciliation (Prolly does that, inside Jets)

Jets attaches the Merkle proof for each requested chunk alongside the ciphertext
in the `Jets.get()` response.

---

### 1.5 Prolly tree

Owned entirely by Jets. Cloud methods never call `Q.Data.Prolly` directly.
Jets maintains a Prolly tree of `{ cid → cid }` per Drop for inventory
reconciliation. `Jets.put()` and `Jets.get()` are the only interface Cloud
uses — Jets handles all Prolly mechanics internally.

---

### 1.6 Bloom filter

Owned entirely by Drops and Jets. Cloud methods never call `Q.Data.Bloom`
directly.

---

### 1.7 Binding proof

`manifest.bindingProof` ties `encryptionRootPublicKey` and `accessRootPublicKey`
together and commits to `rootCid`. Signed by `encryptionRoot` via `Q.Crypto.sign`
(not `delegate` — no child secret is being delegated; this is a pure attestation
that the two roots and the Merkle root belong to the same file).

Anyone can verify this signature using `encryptionRootPublicKey` from the
manifest — no secret needed.

---

### 1.8 Manifest

Fully public. Contains no secrets. Schema:

```js
{
  v:                       Number,   // manifestVersion = 1
  rootCid:                 String,   // hex Merkle root over ordered CID strings
  encryptionRootPublicKey: String,   // base64 raw P-256 uncompressed (65 bytes)
  accessRootPublicKey:     String,   // base64 raw P-256 uncompressed (65 bytes)
  bindingProof: {
    statement: {
      encryptionRootPublicKey: String,
      accessRootPublicKey:     String,
      rootCid:                 String
    },
    proof: Object                    // Q.Crypto.sign result
  },
  chunkCount:              Number,
  chunkSize:               Number,   // bytes (last chunk may be smaller)
  size:                    Number,   // total file bytes
  name:                    String,
  type:                    String,   // MIME type
  created:                 Number,   // Unix timestamp seconds
  jurisdiction:            String|null,
  aiAttestation:           Object|null
}
```

---

### 1.9 Capability schema

`grant()` returns an array of subtree grants, one per contiguous chunk range.
This natively handles clip grants that span multiple subtrees, as well as
simple full-file grants (array of length 1).

```js
// Return value of grant():
{
  grants: [
    {
      secret:       String,      // base64 subtreeKey (Q.Crypto.delegate result.secret)
      statement:    Object,      // delegation statement (label, context, issuedTime, secretHash, parent)
      proof:        Object,      // Q.Crypto.sign result (signature + publicKey)
      start:        Number,      // first chunk index (inclusive)
      end:          Number,      // last chunk index (exclusive)
      merkleProofs: Array|null   // [{index, proof}] — included for clip grants,
                                 // null for full-file grants (Jets provides proofs on fetch)
    },
    // ...additional subtrees for clip grants
  ],
  manifest: Object,              // reference to the public manifest
  readLevel:  String|null,       // Streams word granted for read
  writeLevel: String|null,
  adminLevel: String|null
}
```

The `secret` field is the raw subtreeKey bytes (base64), which the grantee
uses directly with `Q.Data.derive` to compute chunk keys (chunk-level derivation stays as `derive` — see section 1.2). The `statement` and
`proof` together are the OCP delegation proof the grantee presents to Jets.

**Fetch capability input** — what `fetch()` accepts:

```js
// Owner shorthand:
{ rootKey: String }    // base64 master key — Cloud derives everything internally

// Delegated (output of grant(), passed directly):
{
  grants:   Array,     // same shape as grant() output
  manifest: Object
}
```

---

### 1.10 HLS, service worker, and player integration

`Q.Safe.Cloud.stream()` returns a fake HLS URL
(`https://safecloud-hls.local/{videoId}/master.m3u8`) that any HTML5 player
can consume as if it were a real HTTP stream. The service worker at
`{{Safe}}/js/Safe/sw.js` intercepts all fetch requests to that fake hostname,
builds playlists dynamically from the manifest, and serves decrypted segment
bytes — sourced from the prefetch cache populated by `_prefetchLoop`.

**How the SW serves requests:**

- `master.m3u8` — SW builds a master HLS playlist from `manifest`. Single
  rendition in v1 (see ABR note below). No network call needed.
- `{rendition}/index.m3u8` — SW builds the segment playlist (one line per
  chunk in the range). No network call needed.
- `{rendition}/seg{N}.m4s` — SW looks up the prefetched ciphertext for chunk
  N, decrypts it using the subtreeKey from the session, responds with decrypted
  bytes. Must handle `Range:` headers (see below).

The SW never makes network calls. All Jets I/O lives in the page via
`_prefetchLoop`, which races ahead of the playhead and posts ciphertext to the
SW session cache keyed by `{ videoId, segIndex }`.

**Pause and seek:**

When the player pauses, `_prefetchLoop` detects this via
`videoElement.paused` and suspends — no more Jets calls until resume.
When the player fires a `seeked` event, `_prefetchLoop` discards its in-flight
window and jumps to the new segment index. The SW session cache is keyed by
segment index, so stale prefetched segments are simply unused — no need to
flush them explicitly.

**Safari range request requirement:**

Safari sends an initial `Range: bytes=0-1` probe on every video source before
committing to playback. If the SW returns a plain 200 response, Safari refuses
to play. The SW must detect the `Range` header and respond with:
- Status 206 Partial Content
- `Content-Range: bytes {start}-{end}/{total}`
- The sliced `ArrayBuffer` for the requested byte range

Since HLS segments are self-contained fMP4 chunks (not seekable mid-segment),
Safari's range probes are always small `bytes=0-1` initialisation requests.
The SW handles these by returning the first 2 bytes of the decrypted segment.
This is the only range case that needs special handling in practice.

**Adaptive bitrate (ABR):**

True ABR (videojs-http-streaming switching renditions based on throughput
measurement) is deferred to v2. In v1, `stream()` exposes a single rendition
in the master playlist. Callers control quality by encoding multiple manifests
at different bitrates and calling `stream()` with the appropriate one.

In v2, the manifest will carry per-rendition chunk arrays, and `_prefetchLoop`
will signal measured decryption throughput back to the SW via `postMessage`.
The SW will include multiple `#EXT-X-STREAM-INF` entries in `master.m3u8`,
and videojs-http-streaming (VHS, built into videojs 7+) will switch renditions
automatically. The `Q/video` tool's existing videojs adapter handles this with
no changes needed — VHS ABR is transparent at the `<video>` level.

**Integration with `Q/video` tool:**

The `Q/video` tool uses an adapter pattern (`tool.adapters.<name>.init()`).
A `safecloud` adapter should be added that:

1. Calls `Q.Safe.Cloud.stream(manifest, capability, options)` to get the handle
   `{ url, currentTime, seek, setVersion, pause, stop }`
2. Passes the URL to `tool.initVideojsPlayer` as an HLS source:
   ```js
   tool.initVideojsPlayer({
       sources: [{ src: handle.url, type: 'application/x-mpegURL' }]
   });
   ```
3. Wires `handle.stop()` into `Q.beforeRemove` alongside the existing
   `player.dispose()` call
4. Wires `handle.pause()` / `handle.seek()` to the player's `pause` / `seeked`
   events (already fired by videojs and handled in `initVideojsPlayer`)

The `adapterNameFromUrl()` method detects `safecloud://` scheme or a manifest
object passed directly via `state.manifest`. All existing player features —
`clipStart`/`clipEnd`, ads, metrics, floating player, clips mode — work
unchanged because they operate on `state.player.currentTime()` and
`state.player.pause()`/`play()`, which videojs exposes identically regardless
of the underlying source type.

**iOS Safari:**

On iOS Safari (regular pages, not just PWAs), the SW intercepts all `fetch()`
calls including those made by the native HLS parser inside `<video>`. This was
confirmed working by StriveCast for their P2P HLS proxy. The SW must be served
from the same origin as the page. No special iOS code path is needed; the same
`stream()` → SW pipeline works across all modern browsers.

---

### 1.11 Versioned trees — multiple renditions of the same logical file

A single logical asset (a video, a large document) may have multiple versions
that share the same coordinate system but differ only in their leaf chunks:

```
videoKey  (shared parent secret)
  │
  ├─ derive('safecloud.version.360p')  → encryptionRoot_360p
  │    └─ delegate([0, N))             → subtreeKey_360p[0,N)
  │         └─ chunkKey[0], chunkKey[1], ...   (360p frames)
  │
  ├─ derive('safecloud.version.720p')  → encryptionRoot_720p
  │    └─ delegate([0, N))             → subtreeKey_720p[0,N)
  │         └─ chunkKey[0], chunkKey[1], ...   (720p frames)
  │
  └─ derive('safecloud.version.1080p') → encryptionRoot_1080p
       └─ delegate([0, N))             → subtreeKey_1080p[0,N)
            └─ chunkKey[0], chunkKey[1], ...   (1080p frames)
```

**All versions share the same chunk count and chunk boundaries.** Encoding all
renditions with the same segment duration (e.g. `-hls_time 6`) ensures that
chunk index `i` always means "seconds `[i×6, (i+1)×6)`" regardless of version.
Chunk sizes differ (a 6-second 360p chunk is ~200 KB; 1080p is ~4 MB), but
indices are identical.

What diverges at the bottom: the actual encoded bytes per chunk → different
CIDs → different Merkle roots → separate Safecloud manifests. Everything above
the leaf level — subtree boundaries, grant coordinate space, time-to-index
mapping — is identical across versions.

**The video manifest** is a Cloud-level envelope that references all version
manifests and records the shared timeline:

```js
{
  v:             1,
  type:          'safecloud.videomanifest',
  videoKey:      String|null,   // base64 videoKey — OWNER ONLY. Must be stripped
                                // before sharing. store() and grant() must never
                                // serialize a videoManifest with videoKey present
                                // into any payload sent over the network or to Jets.
  duration:      Number,        // seconds — shared logical timeline length
  chunkDuration: Number,        // seconds per chunk (same across all versions)
  versions: [
    {
      label:     String,        // e.g. '360p', '720p', '1080p', 'dubbed-es', 'subtitles-fr'
      manifest:  Object,        // Safecloud manifest for this version
      bandwidth: Number|null,   // bits/sec hint for ABR switching
      mimeType:  String         // e.g. 'video/mp4', 'text/vtt'
    },
    // ...
  ]
}
```

**Key derivation for versioned uploads:**

`store()` accepts `options.videoKey` + `options.version`. Internally:
```
rootKey = _.deriveVersionKey(videoKey, version).secret
```
Then proceeds normally. `store()` returns `{ manifest, rootKey }` as usual.
The caller accumulates per-version manifests and assembles the video manifest.

Versions are cryptographically isolated: knowing the 360p `rootKey` does not
help derive the 720p `rootKey`. The `videoKey` is the only token that unlocks
all versions simultaneously.

**Granting access across versions:**

`grant()` accepts `options.videoManifest` + `options.videoKey` instead of a
single manifest + rootKey. It produces one grant per version for the same chunk
range, all encoded in a single `videoCapability`:

```js
// videoCapability shape:
{
  type:      'safecloud.videocapability',
  timeStart: Number,   // seconds (for human reference — chunk indices are canonical)
  timeEnd:   Number,
  versions: {
    '360p':  { grants: [...], manifest: Object },
    '720p':  { grants: [...], manifest: Object },
    '1080p': { grants: [...], manifest: Object }
  }
}
```

OCP claims nest naturally: the videoCapability is one OCP claim containing
per-version sub-claims. Jets verifies each sub-claim when the corresponding
version's chunks are requested.

**`stream()` and `play()` with versioned assets:**

`stream()` and `play()` accept either:
- A single `manifest` + `capability` (single-version, existing behaviour)
- A `videoManifest` + `videoCapability` (multi-version)

In the multi-version case, `stream()` starts prefetching from `options.version`
(default: highest-bandwidth version the capability covers). The returned handle
gains a `setVersion(label)` method that:
1. Derives the new version's subtreeKey from `videoCapability.versions[label]`
2. Posts `{ type: 'Q.Safe.Cloud.setVersion', videoId, version: label, manifest }` to SW
3. Resets `_prefetchLoop` to the new version's tree at the current timestamp
4. The SW updates the HLS playlist to point to new segment URLs; videojs-http-streaming
   handles the rendition switch as a discontinuity

**Seek is an argument to `play()`:**

```js
// Ergonomic:
var handle = await Q.Safe.Cloud.play(videoManifest, capability, { at: 42, version: '720p' });
handle.seek(120);        // jump to 2 minutes
handle.setVersion('1080p');  // switch rendition at current position
Q.Safe.Cloud.pause(handle);  // suspend prefetch + SW session

// Low-level:
var s = await Q.Safe.Cloud.stream(videoManifest, capability, { at: 42, version: '720p' });
videoElement.src = s.url;
// s.seek(t), s.setVersion(label), s.stop()
```

**Version labels are not restricted to video quality.** The same mechanism
handles: dubbed audio tracks (same video chunks, different audio mux), subtitle
overlays (VTT chunks at same timestamps), translated documents (same structure,
different text chunks), or any other parallel version of a logical asset that
shares the same positional coordinate system.

---

## Part 2 — Jets, Drops and platform interface (called by Cloud)

These are the methods Cloud calls on already-implemented layers. They sit at the
same dependency level as `_internal.js` helpers — below all Cloud method files.
Cloud treats these as black boxes and does not depend on their internal mechanics
(Prolly trees, socket.io, IndexedDB).

---

### `Q.Safe.Jets.connect(callback)`

```
Returns: Promise<Q.Socket>
Called by: store.js (implicitly via Jets.put), fetch.js (implicitly via Jets.get)
```

Connects to the Jet server. Idempotent. `Jets.put` and `Jets.get` call this
internally via `_withSocket`. Cloud method files do not call `connect` directly.

---

### `Q.Safe.Jets.dropAnnounce(info, callback)`

```
info: { storage: { GB }, used, prollyRoot?, bloomFilter? }
Returns: Promise
Called by: reshare.js
```

Announces this client as a Drop with updated stats. Called by `reshare()` after
storing chunks locally.

---

### `Q.Safe.Jets.put(subtree, options, callback)`

```
subtree: {
  chunks:  Array<{ cid, iv, ciphertext, tag, size, tags }>,
  start:   Number,   // absolute start index in file
  end:     Number,   // absolute end index (exclusive)
  grants:  Array     // capability grants for this subtree range
}
options: { authorizations, payments }
Returns: Promise<{ results: Array<{ cid, stored: Boolean }> }>
Called by: store.js
```

Uploads a subtree of encrypted chunks to the network via Jets. Cloud provides
the encrypted chunk data and the capability grants authorizing this upload. Jets
handles routing to Drops, replication, Prolly tree updates, and retry logic.

**This replaces the old `Q.Safe.Jets.chunkPut`.** The subtree framing means
Jets knows the logical grouping of chunks and can optimize routing and Prolly
updates accordingly.

Progress is reported chunk-by-chunk. `options.onProgress(stored, total)` is
called after each chunk is confirmed stored.

---

### `Q.Safe.Jets.get(subtree, options, callback)`

```
subtree: {
  rootCid: String,   // manifest.rootCid — for Merkle proof generation
  start:   Number,
  end:     Number,
  grants:  Array     // capability grants authorizing this range
}
options: { authorizations, payments, onProgress }
Returns: Promise<{
  chunks: Array<{
    cid:        String,
    iv:         String,   // base64
    ciphertext: String,   // base64
    tag:        String,   // base64
    proof:      Array     // Merkle proof [{hex, side}]
  }|null>
}>
Called by: fetch.js, _prefetchLoop.js
```

Downloads a range of encrypted chunks from the network via Jets, with Merkle
proofs attached. Null entries indicate chunks that could not be retrieved.
Jets handles Drop selection, fallback, and Prolly-based routing internally.

**This replaces the old `Q.Safe.Jets.chunkGet`.** The subtree + grants framing
allows Jets to verify authorization before fetching and to use the Prolly tree
coverage data to select the best Drops for this range.

---

### `Q.Safe.Drops.put(chunks, options, callback)`

```
chunks:  Array<{ iv, data: ArrayBuffer, tags }>
options: { authorizations, payments }
Returns: Promise<{ results: Array<{ cid, iv, size }|false> }>
Called by: reshare.js
```

Stores encrypted chunks in local IndexedDB. Called by `reshare()` to turn this
browser into a temporary Drop. This is the only direct Drops call Cloud makes
— all other Drops interaction goes through Jets.

---

### `Q.Data.importKey(keyBytes, algo)` → Promise<CryptoKey>

```
keyBytes: Uint8Array   — raw 32-byte AES key material
algo:     Object       — optional override (default: { name:'AES-GCM', length:256, usages:['encrypt','decrypt'] })
Returns:  Promise<CryptoKey>
Called by: store.js, fetch.js (once per chunk, inside Promise.all)
```

Imports raw key bytes into a `CryptoKey` for use with SubtleCrypto. Wraps
`crypto.subtle.importKey('raw', keyBytes, ...)`. The returned `CryptoKey` is
non-extractable. Always called with the output of `_.deriveChunkKey` — no other
key material is imported through this path.

---

### `Q.Crypto.sign(options)` → Promise<Object>

```
options.secret:  Uint8Array   — signing key bytes (encryptionRoot)
options.message: Object       — JSON-serialisable statement to sign
options.format:  'ES256'|'EIP712'
Returns: { signature: String, publicKey: String }  — both base64
Called by: store.js (bindingProof only)
```

Signs a statement with a key derived from `options.secret`. Used only for the
binding proof in `store()` — not for delegation (which uses `Q.Crypto.delegate`).
The returned `{ signature, publicKey }` is stored verbatim as
`manifest.bindingProof.proof`.

---

### `Q.Data.Merkle.build(leaves)` → String

```
leaves:  Array<String>   — ordered CID strings (UTF-8 encoded before hashing)
Returns: String           — hex-encoded 32-byte Merkle root
Called by: store.js
```

Builds a binary Merkle tree over `leaves` and returns the root as a lowercase
hex string. Domain separation: leaf hash = `SHA-256(0x00 || UTF8(leaf))`,
internal node = `SHA-256(0x01 || left || right)`. The returned hex string is
stored as `manifest.rootCid` and used as the anchor for all `Merkle.verify`
calls in `fetch.js`.

---

### `Q.Data.Merkle.verify(leaf, proof, root)` → Promise<Boolean>

```
leaf:  String          — CID string of the chunk being verified
proof: Array<{hex: String, side: 'left'|'right'}>   — sibling hashes up to root
root:  String          — hex root from manifest.rootCid
Returns: Promise<Boolean>
Called by: fetch.js (once per chunk, before decryption)
```

Verifies that `leaf` is a member of the Merkle tree with the given `root`, using
the provided proof path. Returns `false` (does not throw) if the proof is invalid.
`fetch.js` must reject the entire download if any chunk fails verification.

---

### `Q.Crypto.internalKeypair(options)` → Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>

```
options.secret: Uint8Array   — seed bytes (encryptionRoot or accessRootBytes)
options.format: 'ES256'|'EIP712'
Returns: { publicKey: Uint8Array, privateKey: Uint8Array }  — raw bytes
Called by: store.js (×2: encryptionRoot keypair + accessRoot keypair)
```

Derives a deterministic P-256 keypair from `options.secret` via HKDF. The
`publicKey` (65-byte uncompressed) is stored in the manifest as
`encryptionRootPublicKey` and `accessRootPublicKey` (base64-encoded).
The `privateKey` is used only for `Q.Crypto.sign` to produce the binding proof
and is never stored.

---

### `Q.Data.encrypt(cryptoKey, data, options)` → Promise<{ ciphertext: String, tag: String }>

```
cryptoKey: CryptoKey       — imported AES-256-GCM key from Q.Data.importKey
data:      ArrayBuffer     — plaintext chunk bytes
options.iv:         Uint8Array   — 12-byte IV from _.deriveChunkIV
options.additional: Uint8Array   — AAD from _.chunkAAD
Returns: { ciphertext: String (base64), tag: String (base64, 16 bytes) }
Called by: store.js (once per chunk, inside Promise.all)
```

Encrypts a plaintext chunk with AES-256-GCM. Returns ciphertext and auth tag
as separate base64 strings so the tag can be included in the CID computation
and stored separately in the chunk object sent to Jets.

---

### `Q.Data.decrypt(cryptoKey, iv, ciphertext, options)` → Promise<ArrayBuffer>

```
cryptoKey:        CryptoKey   — imported AES-256-GCM key
iv:               Uint8Array  — 12-byte IV from _.deriveChunkIV
ciphertext:       String      — base64 ciphertext from Jets
options.tag:      String      — base64 auth tag (16 bytes)
options.additional: Uint8Array — AAD from _.chunkAAD
Returns: Promise<ArrayBuffer>  — plaintext chunk bytes
Called by: fetch.js (once per chunk)
```

Decrypts an AES-256-GCM ciphertext. Throws if authentication fails (wrong key,
wrong AAD, or tampered ciphertext). `fetch.js` lets this throw propagate —
a failed GCM auth is a hard error, not a soft retry.

---

### `Q.Data.toBase64(bytes)` → String  /  `Q.Data.fromBase64(str)` → Uint8Array

```
Q.Data.toBase64(Uint8Array)  → String   (standard base64, no line breaks)
Q.Data.fromBase64(String)    → Uint8Array
Called by: grant.js, fetch.js, _internal.chunkCid
```

Standard base64 encode/decode utilities. Used throughout to serialise raw key
bytes and ciphertext into the string fields stored in capabilities and chunk
objects.

---

### `Q.Data.digest(algorithm, data)` → Promise<Uint8Array>

```
algorithm: String       — e.g. 'SHA-256'
data:      Uint8Array   — bytes to hash
Returns:   Promise<Uint8Array>  — digest bytes (32 bytes for SHA-256)
Called by: _.chunkCid (to hash ciphertext || tag before CID encoding)
```

Thin wrapper over `crypto.subtle.digest`. Used by `_.chunkCid` to compute the
SHA-256 hash of the concatenated ciphertext and tag bytes before encoding as a
CIDv1 string.

---

### `Q.Data.Merkle.proof(leaves, index)` → Promise<Array>

```
leaves:  Array<String>   — same ordered CID array passed to Merkle.build
index:   Number          — leaf index to generate proof for
Returns: Promise<Array<{ hex: String, side: 'left'|'right' }>>
Called by: grant.js (when options.includeMerkleProofs is true)
```

Generates the Merkle inclusion proof for the leaf at `index`. The returned
array of `{ hex, side }` siblings can be passed directly to `Merkle.verify`.
Requires the original `leaves` array — the proof cannot be reconstructed from
the root alone.

---

### `Q.Crypto.delegate(options)` → Promise<Object>

```
options.rootSecret: Uint8Array   — parent secret bytes
options.label:      String       — HKDF domain-separation label
options.context:    String       — JSON string bound into the statement
options.format:     'ES256'|'EIP712'
Returns: {
  secret:    Uint8Array,  // derived child secret (HKDF of rootSecret + label)
  statement: {
    label:       String,
    context:     String,
    issuedTime:  Number,   // Unix seconds — in wrapper only, NOT in secret derivation
    secretHash:  String,   // hex hash of secret bytes
    parent:      String    // hex of parent public key
  },
  proof: {
    signature:  String,   // base64
    publicKey:  String    // base64 — P-256 uncompressed, 65 bytes
  }
}
Called by: _.deriveEncryptionRoot, _.deriveAccessRootBytes, _.deriveVersionKey,
           _.deriveSubtreeKey, grant.js (directly, with full context)
```

Derives a child secret from `rootSecret` using HKDF with `label` as the info
string, then signs a statement binding the child secret to the parent. The
`secret` bytes are deterministic — two calls with the same inputs always produce
the same bytes regardless of `issuedTime`. Only the `statement` wrapper differs
between calls. This is what preserves convergent encryption while still
producing a verifiable proof.

---

## Part 3 — `_internal.js` helpers (bottom of the dependency tree)

Shared helpers passed as `_` to all Cloud method files. Only call
`Q.Data.*`, `Q.Crypto.*`, and native browser APIs.

---

### `_.LABELS`

```
Type: Object (constants + factory functions)
```

Single source of truth for all HKDF domain-separation labels in Safecloud.
All labels are prefixed `safecloud.` and must be globally unique.

```
// Q.Crypto.delegate labels (all non-chunk derivations)
LABELS.encryptionRoot          = 'safecloud.encryption.root'
LABELS.accessRoot              = 'safecloud.access.root'
LABELS.version(label)          = 'safecloud.version.' + label
LABELS.subtree(start, end)     = 'safecloud.subtree.' + start + '.' + end
LABELS.read(word)              = 'safecloud.read.' + word
LABELS.write(word)             = 'safecloud.write.' + word
LABELS.admin(word)             = 'safecloud.admin.' + word

// Q.Data.derive labels (chunk-level only — O(N), proof unused)
LABELS.chunkKey(relIndex)      = 'safecloud.chunk.key.' + relIndex
LABELS.chunkIV(relIndex)       = 'safecloud.chunk.iv.' + relIndex

// Other
LABELS.binding                 = 'safecloud.binding'
```

---

### `_.base32(bytes)` → String

```
Calls: nothing (pure)
Called by: _.digestToCid
```

RFC 4648 base32 encoding without padding, lowercase alphabet
`abcdefghijklmnopqrstuvwxyz234567` (multibase `b` alphabet for CIDv1).
Processes 5 bits per output character.

---

### `_.digestToCid(digest)` → String

```
Calls: _.base32
Called by: _.chunkCid
```

Encodes a 32-byte SHA-256 digest as a CIDv1 string.

Binary layout: `[0x01][0x55][0x12][0x20][digest 32 bytes]`
(version=1, codec=raw, hash=sha2-256, length=32)

Prefixed with `'b'` (multibase base32 marker). Result is always 59 characters
starting with `'bafy'`.

Must be byte-identical to `Q.Safe.Drops._cidFromDigest`.

---

### `_.chunkAAD(absIndex)` → Uint8Array

```
Calls: TextEncoder.encode
Called by: store.js, fetch.js (once per chunk)
```

Additional Authenticated Data for chunk at absolute index `absIndex`.
Value: UTF-8(`'safecloud.chunk:' + absIndex`).

Uses the **absolute** index even though chunk keys use the **relative** index.
This prevents swapping attacks: substituting chunk 5 for chunk 3 causes AAD
mismatch → GCM authentication failure. The relative index is for key isolation
(grantee derives same key as owner); the absolute index is for position binding.

---

### `_.blobToBuffer(blob)` → Promise<ArrayBuffer>

```
Calls: FileReader API
Called by: store.js
```

Converts a `Blob` to `ArrayBuffer` via `FileReader`. Used instead of
`Blob.arrayBuffer()` for broader browser compatibility.

---

### `_.chunkify(buffer, chunkSize)` → Array<ArrayBuffer>

```
Calls: ArrayBuffer.prototype.slice
Called by: store.js
```

Splits an `ArrayBuffer` into an ordered array of chunks. Each is `chunkSize`
bytes except the last, which is trimmed. Never returns empty array — a zero-byte
input produces one zero-byte chunk. Slices are views into the original buffer;
callers must not mutate the source.

---

### `_.deriveEncryptionRoot(rootKey)` → Promise<Object>

```
Calls: Q.Crypto.delegate({ rootSecret: rootKey, label: LABELS.encryptionRoot, context: '{}', format: 'ES256' })
Called by: store.js, fetch.js, grant.js
Returns: { secret: Uint8Array, statement, proof }
```

Derives the encryption root from the master `rootKey` using `Q.Crypto.delegate`.
The `secret` bytes (32) are the parent of all subtree keys. The `proof` is kept
in hand for audit trail use. Never stored or transmitted directly.

---

### `_.deriveAccessRootBytes(rootKey)` → Promise<Object>

```
Calls: Q.Crypto.delegate({ rootSecret: rootKey, label: LABELS.accessRoot, context: '{}', format: 'ES256' })
Called by: store.js
Returns: { secret: Uint8Array, statement, proof }
```

Derives the access root from the master `rootKey` using `Q.Crypto.delegate`.
`secret` bytes (32) are used to derive the access root keypair for
`manifest.accessRootPublicKey`. Reserved for future access control (v2+).

---

### `_.deriveVersionKey(videoKey, versionLabel)` → Promise<Object>

```
Calls: Q.Crypto.delegate({ rootSecret: videoKey, label: LABELS.version(versionLabel), context: '{}', format: 'ES256' })
Called by: store.js (when options.videoKey provided)
Returns: { secret: Uint8Array, statement, proof }
```

Derives the per-version `rootKey` from the shared `videoKey` using
`Q.Crypto.delegate`. The returned `secret` is used as the `rootKey` for all
subsequent derivations for that version. Versions are cryptographically
isolated: knowing one version's `rootKey` does not help derive another's.

---

### `_.deriveSubtreeKey(encryptionRoot, start, end)` → Promise<Object>

```
Calls: Q.Crypto.delegate({
         rootSecret: encryptionRoot,
         label:      LABELS.subtree(start, end),
         context:    JSON.stringify({ start, end }),
         format:     'ES256'
       })
Called by: store.js, fetch.js, grant.js
Returns: Q.Crypto.delegate result — { secret: Uint8Array, statement, proof }
```

Derives the subtreeKey for chunk range `[start, end)` using `Q.Crypto.delegate`.
Returns the full delegation result so that `store()`, `fetch()`, and `grant()`
have the proof in hand without a second `delegate` call.

The `secret` bytes are used for chunk key derivation. The `statement` + `proof`
pair becomes the authorization credential presented to Jets.

For full-file operations, `start=0`, `end=chunkCount`. For clip grants, called
once per contiguous range.

Note: context at this level only encodes `{ start, end }` — the rootCid is not
known yet at subtree derivation time during `store()`. At `grant()` time, a
new delegation is produced with the full context `{ rootCid, start, end, exp }`.
See `grant.js` for details.

---

### `_.deriveChunkKey(subtreeKey, relIndex)` → Promise<Uint8Array>

```
Calls: Q.Data.derive(subtreeKey, LABELS.chunkKey(relIndex), { size: 32 })
Called by: store.js, fetch.js
```

Derives the 32-byte AES-256-GCM key for chunk at relative index `relIndex`
within the subtree. `relIndex = absIndex - subtreeStart`. Must be imported via
`Q.Data.importKey` before use.

`Q.Data.derive` (not `Q.Crypto.delegate`) because chunk keys are never handed
to third parties — they are internal owner-only derivation steps.

---

### `_.deriveChunkIV(subtreeKey, relIndex)` → Promise<Uint8Array>

```
Calls: Q.Data.derive(subtreeKey, LABELS.chunkIV(relIndex), { size: 12 })
Called by: store.js, fetch.js
```

Derives the 12-byte AES-256-GCM IV for chunk at relative index `relIndex`.
12 bytes is the required GCM nonce size. Deterministic: same (subtreeKey,
relIndex) → same IV → convergent encryption.

**Security invariant:** GCM requires (key, IV) pairs to never be reused for
different plaintexts. Safe here because each (subtreeKey, relIndex) pair is
unique: relIndex is unique per subtree, and subtreeKey is unique per (file, range).

`Q.Data.derive` (not `Q.Crypto.delegate`) — internal only.

---

### `_.chunkCid(ciphertextB64, tagB64)` → Promise<String>

```
Calls: Q.Data.fromBase64, Q.Data.digest('SHA-256', ...), _.digestToCid
Called by: store.js (once per chunk)
```

Computes CIDv1 for a chunk. CID covers `ciphertext || tag` concatenated —
not plaintext, not ciphertext alone. Including the tag commits the CID to the
full authenticated blob; a corrupted tag produces a different CID.

Must match `Q.Safe.Drops.cidFromData(arrayBuffer)` where `arrayBuffer` is
the same `ciphertext || tag` concatenation.

---

### `_.buildManifest(p)` → Object

```
Calls: Date.now(), Q.Safe.Cloud.manifestVersion
Called by: store.js
```

Assembles the public manifest object. All required fields must be in `p`;
optional fields (`jurisdiction`, `aiAttestation`) default to `null`.
Sets `created = Math.floor(Date.now() / 1000)`.

---

### `_.levelFromLabel(type, word)` → Number

```
Calls: Q.Streams[type.toUpperCase() + '_LEVEL'] (if available), else 0
Called by: grant.js, _.parseLabel
```

Maps a Streams-compatible access level word (e.g. `'content'`) to its numeric
value for type `'read'`, `'write'`, or `'admin'`. Uses `Q.Streams` constants
so Safecloud stays in sync with the broader access level system. Returns `0`
if `Q.Streams` is not loaded or the word is unknown.

---

### `_.parseLabel(label)` → Object|null

```
Calls: _.levelFromLabel
Called by: _.verifyCapability
```

Parses a Safecloud delegation label `'safecloud.{type}.{word}'`.
Returns `{ type, word, level }` or `null` if format doesn't match.

Examples:
- `'safecloud.read.content'` → `{ type: 'read', word: 'content', level: 23 }`
- `'notasafecloud.label'`    → `null`

---

### `_.verifyCapability(proof, type, required, chunkIndex)` → Boolean

```
Calls: _.parseLabel, Date.now()
Called by: fetch.js
```

Lightweight synchronous check that a delegation proof authorizes access to
`chunkIndex`. Checks in order:

1. `proof` and `proof.statement` present
2. `parseLabel(proof.statement.label)` valid
3. Parsed `type` matches argument
4. Parsed `level >= required`
5. `context = JSON.parse(proof.statement.context)` succeeds
6. `context.start <= chunkIndex < context.end`
7. `proof.statement.exp` not expired (if present)

Full cryptographic verification is done server-side by Jets. This is a fast
local guard against obviously wrong capabilities before making network requests.

---

## Part 4 — Ergonomic public API

These methods are the intended entry points for most callers. They hide all
internal mechanics behind intent-based interfaces. `play()` and `pause()` are
the video/audio equivalents of `upload()` and `download()` — a normie thinks
"play" and "pause", not "stream" and "stop prefetch loop".

| Method | Wraps | Summary |
|--------|-------|---------|
| `Q.Safe.Cloud.download(manifest, capability, options, callback)` | `fetch()` | Download and decrypt to Blob or trigger browser save |
| `Q.Safe.Cloud.pause(handle)` | `handle.pause()` | Suspend a playing stream |
| `Q.Safe.Cloud.play(videoManifest, capability, options)` | `stream()` | Start playback, return a live handle |
| `Q.Safe.Cloud.upload(file, options, callback)` | `store()` | Encrypt and upload a file |

---

### `Q.Safe.Cloud.download(manifest, capability, options, callback)` → Promise

```
Calls: Q.Safe.Cloud.fetch
```

Downloads and decrypts a file. Thin ergonomic wrapper over `fetch()`. If
`options.save` is true, triggers a browser download dialog via a temporary
`<a download>` blob URL and returns `null`. Otherwise returns a `Blob`.

**Parameters:** same as `fetch()`, plus:
- `options.save` — Boolean (default false). If true, auto-triggers browser
  file save dialog using `manifest.name` as the filename.

**Returns:** `Blob` (or `null` if `options.save` is true)

---

### `Q.Safe.Cloud.pause(handle)` → void

```
Calls: handle.pause()
```

Suspends an active streaming session returned by `play()`. The player's existing
buffer continues playing out; the prefetch loop halts and the SW stops receiving
new segments. Resuming is done by calling `play()` again with the same capability
and `options.at = handle.currentTime()`.

`pause(handle)` is equivalent to `handle.pause()` — both forms are supported.

---

### `Q.Safe.Cloud.play(videoManifest, capability, options)` → Promise<handle>

```
Calls: Q.Safe.Cloud.stream
```

Starts encrypted playback and returns a live handle. Wraps `stream()` with
player-oriented ergonomics. Accepts either a single `manifest` or a full
`videoManifest` with multiple versions. Seek is `options.at` — there is no
separate `seek()` call at the ergonomic layer.

**Parameters:**
- `videoManifest` — Safecloud manifest, or video manifest (type `safecloud.videomanifest`)
- `capability` — owner `{ rootKey }`, delegated `{ grants, manifest }`, or
  `videoCapability` (type `safecloud.videocapability`, with `versions` map)
- `options.at` — start timestamp in seconds (default 0) — this is seek
- `options.version` — version label to start with (default: highest bandwidth
  in capability; ignored for single-manifest)
- `options.videoElement` — attach `<video>.src` automatically (optional)
- `options.prefetchAhead` — chunks to buffer ahead (default 3)
- `options.onError(err)`

**Returns:** `Promise<handle>` where handle exposes:

```js
{
  url:          String,    // fake HLS URL — set as <video>.src
  currentTime:  Function,  // () → Number (seconds) — current playhead
  seek:         Function,  // (seconds) → void — reposition prefetch window
  setVersion:   Function,  // (label) → void — switch rendition at current position
  pause:        Function,  // () → void — suspend prefetch loop
  stop:         Function   // () → void — revoke SW session entirely
}
```

`seek(t)` resets the prefetch window to the chunk covering `t` and posts
`{ type: 'Q.Safe.Cloud.seek', videoId, segIndex }` to the SW to flush stale
buffered segments.

`setVersion(label)` switches to a different version tree at the current
timestamp. Requires `videoManifest` + `videoCapability` that includes the
target version. Internally: derives new subtreeKey, posts new version manifest
to SW, resets prefetch window at same timestamp.

```js
Q.Safe.Cloud.play(videoManifest, capability, {
    at: 0,
    version: '720p',
    videoElement: document.getElementById('player')
}).then(function (handle) {
    // handle.seek(42)          — jump to 42 seconds
    // handle.setVersion('1080p') — switch quality
    // Q.Safe.Cloud.pause(handle) or handle.pause()
    // handle.stop()            — on unmount
});
```

---

### `Q.Safe.Cloud.upload(file, options, callback)` → Promise

```
Calls: Q.Safe.Cloud.store
```

Encrypts and uploads a file. Thin ergonomic wrapper over `store()`.

**Parameters:** same as `store()`, plus:
- `options.videoKey` — base64 shared parent key for versioned uploads (passed through)
- `options.version` — version label e.g. `'720p'` (passed through to `store()`)

**Returns:** `{ manifest: Object, rootKey: String (base64) }`

---

## Part 5 — Power API and internals

These methods are for power users, server-side tooling, and internal use by the
ergonomic layer above. All accept an optional callback as final argument and
return a `Q.Promise`.

| Method | File | Summary |
|--------|------|---------|
| `Q.Safe.Cloud._ensureServiceWorker()` | `_ensureServiceWorker.js` | Register + activate SW |
| `Q.Safe.Cloud._prefetchLoop(videoId, videoManifest, capability, options)` | `_prefetchLoop.js` | Sliding prefetch window, version-aware |
| `Q.Safe.Cloud.fetch(manifest, capability, options, callback)` | `fetch.js` | Download + verify + decrypt → Blob |
| `Q.Safe.Cloud.grant(manifest, rootKey, options, callback)` | `grant.js` | Produce capability (single or multi-version) |
| `Q.Safe.Cloud.reshare(chunks, options, callback)` | `reshare.js` | Become a temporary Drop |
| `Q.Safe.Cloud.store(file, options, callback)` | `store.js` | Encrypt + upload → manifest + rootKey |
| `Q.Safe.Cloud.stream(videoManifest, capability, options)` | `stream.js` | Low-level: register SW, start prefetch, return handle |

---

### `Q.Safe.Cloud._ensureServiceWorker()` → Promise

```
Calls: navigator.serviceWorker.register, controllerchange event
Called by: stream.js
```

Registers `{{Safe}}/js/Safe/sw.js` with scope `/` (requires
`Service-Worker-Allowed: /` response header on the SW file). Idempotent —
caches registration and resolves immediately on repeat calls. Waits for the SW
to be controlling the page before resolving, so the first `postMessage` is
guaranteed to reach an active controller.

---

### `Q.Safe.Cloud._prefetchLoop(videoId, videoManifest, capability, options)` → Object

```
Calls: Q.Safe.Jets.get, navigator.serviceWorker.controller.postMessage
Called by: stream.js
```

Maintains a sliding window of prefetched encrypted segments ahead of the
playhead. Polls `options.videoElement.currentTime` to determine current chunk
index. Fetches the next `options.prefetchAhead` (default 3) chunks not already
in flight via `Jets.get()`. Suspends when `videoElement.paused`.

Version-aware: tracks `state.version` (active version label). On
`setVersion(label, timestamp)` call: cancels in-flight requests, reads the
pre-derived subtreeKey directly from `videoCapability.versions[label].grants[0].secret`
(no re-derivation needed — the grant already contains the subtreeKey bytes as base64),
resets window at the chunk index for `timestamp`.

Posts each fetched segment to the SW:
```js
{ type: 'Q.Safe.Cloud.segment', videoId, version, segIndex, ciphertext, tag, iv }
```

Returns:
```js
{
  stop:       Function,             // cancel loop + revoke SW session
  pause:      Function,             // suspend without revoking
  seek:       Function,             // (seconds) → reposition window
  setVersion: Function              // (label, timestamp?) → switch tree
}
```

---

### `Q.Safe.Cloud.stream(videoManifest, capability, options)` → Promise<handle>

```
Calls: Q.Safe.Cloud._ensureServiceWorker, Q.Safe.Cloud._prefetchLoop
Called by: play.js
```

Low-level streaming entry point. Registers the SW, posts the session, starts
the prefetch loop, and returns the raw handle. Accepts either a single manifest
or a `videoManifest` with multiple versions.

**Parameters:**
- `videoManifest` — Safecloud manifest or video manifest
- `capability` — owner `{ rootKey }`, delegated, or `videoCapability`
- `options.at` — start timestamp in seconds (default 0)
- `options.version` — starting version label (default: first in `versions` array)
- `options.videoElement` — used by `_prefetchLoop` to track playhead
- `options.prefetchAhead` — default 3
- `options.onError(err)`

**Returns:** same handle shape as `play()`:
```js
{ url, currentTime, seek, setVersion, pause, stop }
```

**SW session registration message:**
```js
{
  type:        'Q.Safe.Cloud.register',
  videoId:     String,
  manifest:    Object,        // active version's manifest
  capability:  Object,        // active version's grants
  versions:    Object|null    // full versions map if videoManifest
}
```

---

### `Q.Safe.Cloud.fetch(manifest, capability, options, callback)` → Promise<Blob>

```
Calls (in order):
  _.deriveEncryptionRoot       (owner path only)
  _.deriveSubtreeKey           (owner path only)
  _.verifyCapability           (delegated path, per grant per chunk)
  Q.Safe.Jets.get             (Jets layer)
  [per chunk, in parallel:]
    Q.Data.Merkle.verify
    _.deriveChunkKey
    _.deriveChunkIV
    Q.Data.importKey
    Q.Data.decrypt
```

Downloads, Merkle-verifies, and decrypts a chunk range. Returns a `Blob`.

**Parameters:**
- `manifest` — public manifest from `store()`
- `capability` — owner `{ rootKey: base64 }` or delegated `{ grants, manifest }`
- `options.start` — default 0
- `options.end` — default `manifest.chunkCount`
- `options.authorizations`, `options.payments` — forwarded to Jets via `Jets.get`
- `options.onProgress(decrypted, total)`

**Returns:** `Blob` with `manifest.type`

**Pipeline:**

1. Validate range `0 <= start < end <= manifest.chunkCount`
2. Resolve subtreeKey(s):
   - **Owner:** `encDelegation = deriveEncryptionRoot(rootKey)`, then
     `delegation = deriveSubtreeKey(encDelegation.secret, 0, manifest.chunkCount)`,
     `subtreeKey = delegation.secret`
   - **Delegated:** for each grant in `capability.grants`, verify it covers its
     portion of the requested range via `_.verifyCapability`, then use
     `Q.Data.fromBase64(grant.secret)` as the subtreeKey for that range
3. Call `Jets.get({ rootCid: manifest.rootCid, start, end, grants: capability.grants },
   { authorizations, payments })` — returns chunks with Merkle proofs
4. For each chunk at `absIdx = start + relIdx` (verify all Merkle proofs first, then decrypt in parallel):
   - `Q.Data.Merkle.verify(chunk.cid, chunk.proof, manifest.rootCid)` — fail
     entire fetch if any proof fails; never decrypt without proof
   - `chunkKey = deriveChunkKey(subtreeKey, relIdx)`
   - `chunkIV  = deriveChunkIV(subtreeKey, relIdx)`
   - `aad      = chunkAAD(absIdx)`
   - `cryptoKey = Q.Data.importKey(chunkKey)` — returns `CryptoKey` for AES-256-GCM
   - `Q.Data.decrypt(cryptoKey, chunkIV, ciphertext, { tag, additional: aad })` —
     GCM failure throws; let it propagate
5. Reassemble `new Blob(plaintexts, { type: manifest.type })`

---

### `Q.Safe.Cloud.grant(manifest, rootKey, options, callback)` → Promise

```
Calls (in order):
  _.deriveEncryptionRoot
  Q.Crypto.delegate           (directly, with full context including rootCid — see pipeline)
  Q.Data.Merkle.proof         (for clip grants with options.includeMerkleProofs)
  Q.Data.toBase64
```

Produces a capability array authorizing a grantee to decrypt one or more
chunk ranges at the specified access levels.

**Parameters (single-manifest form):**
- `manifest` — public manifest
- `rootKey` — base64 or Uint8Array
- `options.ranges` — Array of `{ start, end }` (default: `[{ start: 0, end: chunkCount }]`)
- `options.readLevel` — default `'content'`
- `options.writeLevel`, `options.adminLevel` — optional
- `options.format` — `'ES256'` (default) or `'EIP712'`
- `options.exp` — Unix timestamp expiry
- `options.includeMerkleProofs` — Boolean, include per-chunk Merkle proofs in grant
- `options.cids` — Array<String> ordered CID array from the original store() call; required when `options.includeMerkleProofs` is true (not stored in the public manifest)

**Parameters (multi-version form — pass `null` for `manifest` and `rootKey`):**
- `manifest` — `null`
- `rootKey` — `null`
- `options.videoManifest` — video manifest with `versions` array
- `options.videoKey` — base64 or Uint8Array shared parent key
- `options.versions` — Array of version labels to include (default: all in videoManifest)
- `options.timeStart`, `options.timeEnd` — seconds; converted to chunk indices per version
- All other options same as single-manifest form

**Returns (single):** `{ grants: Array, manifest, readLevel, writeLevel, adminLevel }`

**Returns (multi-version):** `videoCapability`:
```js
{
  type:      'safecloud.videocapability',
  timeStart: Number,
  timeEnd:   Number,
  versions: {
    '720p':  { grants: Array, manifest: Object },
    '1080p': { grants: Array, manifest: Object },
    // ...
  }
}
```

**Pipeline (per range):**

1. `encDelegation = deriveEncryptionRoot(rootKey)` (once, reused for all ranges); `encryptionRoot = encDelegation.secret`
2. For each `{ start, end }` in `options.ranges`:
   - Call `Q.Crypto.delegate` directly (not via `_.deriveSubtreeKey`) with the full context that includes `rootCid` and optional `exp`:
     ```js
     delegation = Q.Crypto.delegate({
       rootSecret: encryptionRoot,
       label:      LABELS.subtree(start, end),
       context:    JSON.stringify({ rootCid: manifest.rootCid, start, end, ...(exp ? { exp } : {}) }),
       format:     options.format || 'ES256'
     })
     ```
   - `merkleProofs = options.includeMerkleProofs ? await Promise.all( Array.from({length: end-start}, (_, i) => Q.Data.Merkle.proof(options.cids, start + i)) ) : null`
     — Note: `options.cids` is the ordered CID array from the original `store()` call; it is NOT stored in the public manifest (only `rootCid` is). Required when `includeMerkleProofs` is true.
   - Collect `{ secret: Q.Data.toBase64(delegation.secret), statement: delegation.statement, proof: delegation.proof, start, end, merkleProofs }`
3. Return `{ grants, manifest, readLevel, writeLevel, adminLevel }`

**Why `grant()` calls `Q.Crypto.delegate` directly:** `_.deriveSubtreeKey` encodes only `{ start, end }` in its context (rootCid is unknown at upload time). `grant()` needs the full context `{ rootCid, start, end [, exp] }` so Jets can verify the grant is bound to this specific file. This is the only call site that bypasses the helper.

**Why no separate read/write/admin delegation per grant?**

The level is encoded in the `context` of the delegation rather than producing
separate proofs. The grant carries `readLevel`/`writeLevel`/`adminLevel` as
plain string fields alongside the grants array. Jets verifies the level claim
against the delegation proof's context when the grantee presents the capability.
This avoids multiplying delegation calls by the number of levels.

**Sub-delegation:**

A grantee may further restrict by calling `grant()` with their grant's `secret`
as a `Uint8Array` rootKey and a sub-range within `[start, end)`. The resulting
sub-capability has a shorter range and equal-or-lower level. Jets verify the
chain never widens range or elevates level.

---

### `Q.Safe.Cloud.reshare(chunks, options, callback)` → Promise

```
Calls:
  Q.Safe.Drops.put
  Q.Safe.Jets.dropAnnounce
```

Stores received encrypted chunks in local IndexedDB and announces them to Jets,
turning this browser into a temporary Drop. Never exposes plaintext — only
operates on already-encrypted chunks as received from `fetch()`.

**Parameters:**
- `chunks` — Array of `{ cid, ciphertext, iv, tag, tags }` (encrypted)
- `options.authorizations`, `options.payments`

**Returns:** `{ announced: Number }`

---

### `Q.Safe.Cloud.store(file, options, callback)` → Promise

```
Calls (in order):
  _.blobToBuffer
  _.deriveVersionKey          (only if options.videoKey provided)
  _.deriveEncryptionRoot
  _.deriveAccessRootBytes
  Q.Crypto.internalKeypair    (×2: encryptionRoot keypair + accessRoot keypair)
  _.chunkify
  _.deriveSubtreeKey          (Q.Crypto.delegate — full-file subtree [0, N))
  [per chunk, in parallel via Promise.all:]
    _.deriveChunkKey
    _.deriveChunkIV
    Q.Data.importKey
    Q.Data.encrypt
    _.chunkCid
  Q.Data.Merkle.build
  Q.Crypto.sign               (bindingProof only — attestation, not delegation)
  Q.Safe.Jets.put            (Jets layer)
  _.buildManifest
```

Encrypts a file and uploads it. Returns public manifest + rootKey.

**Parameters:**
- `file.data` — Blob (required)
- `file.name` — String (required)
- `file.type` — MIME String (optional, falls back to `file.data.type`)
- `file.tags` — Array (optional)
- `options.key` — Uint8Array existing rootKey for re-upload (optional; omit to generate)
- `options.videoKey` — base64 or Uint8Array shared parent key for versioned uploads.
  If provided, `rootKey = _.deriveVersionKey(videoKey, options.version).secret`.
  The caller must also provide `options.version`.
- `options.version` — String version label e.g. `'720p'`, `'dubbed-es'` (required with `videoKey`)
- `options.chunkSize` — Number (default `defaultChunkSize`)
- `options.authorizations`, `options.payments` — forwarded to Jets via `Jets.put`
- `options.jurisdiction`, `options.aiAttestation` — stored in manifest
- `options.onProgress(uploaded, total)`

**Returns:** `{ manifest: Object, rootKey: String (base64) }`

**Pipeline:**

1. Resolve `rootKey`:
   - If `options.videoKey` provided: `versionDelegation = deriveVersionKey(videoKey, options.version)`, `rootKey = versionDelegation.secret`
   - If `options.key` provided: use as-is
   - Otherwise: `crypto.getRandomValues(new Uint8Array(32))`
2. `encDelegation = deriveEncryptionRoot(rootKey)` → `encryptionRoot = encDelegation.secret`
3. `accDelegation = deriveAccessRootBytes(rootKey)` → `accessRootBytes = accDelegation.secret`
4. `encKeypair = Q.Crypto.internalKeypair({ secret: encryptionRoot, format: 'ES256' })`
   — `encryptionRoot` = `encDelegation.secret` from step 2
5. `accKeypair = Q.Crypto.internalKeypair({ secret: accessRootBytes, format: 'ES256' })`
   — `accessRootBytes` = `accDelegation.secret` from step 3
6. `buffer = blobToBuffer(file.data)`
7. `chunks = chunkify(buffer, chunkSize)`
8. `subtreeDelegation = deriveSubtreeKey(encryptionRoot, 0, chunkCount)`
   — returns `{ secret: subtreeKey, statement, proof }`
   — context at this stage: `{ start: 0, end: chunkCount }` (rootCid not yet known)
9. Encrypt all chunks in parallel (`Promise.all`):
   - `chunkKey[i] = deriveChunkKey(subtreeKey, i)` → `Q.Data.derive(subtreeKey, LABELS.chunkKey(i), { size: 32 })`
   - `chunkIV[i]  = deriveChunkIV(subtreeKey, i)` → `Q.Data.derive(subtreeKey, LABELS.chunkIV(i), { size: 12 })`
   - `aad[i]      = chunkAAD(i)` (absolute = relative for full-file)
   - `cryptoKey[i] = Q.Data.importKey(chunkKey[i])` — returns CryptoKey for AES-256-GCM
   - `enc[i]      = Q.Data.encrypt(cryptoKey[i], chunkData, { iv: chunkIV[i], additional: aad[i] })`
   - `cid[i]      = chunkCid(enc[i].ciphertext, enc[i].tag)`
10. `rootCid = Q.Data.Merkle.build(cids)` — hex Merkle root over ordered CID strings
11. Build binding proof (attestation, not delegation):
    - `statement = { encryptionRootPublicKey: Q.Data.toBase64(encKeypair.publicKey), accessRootPublicKey: Q.Data.toBase64(accKeypair.publicKey), rootCid }`
    - `bindingProof = Q.Crypto.sign({ secret: encryptionRoot, message: statement, format: 'ES256' })`
    - Note: `encryptionRoot` here is `encDelegation.secret` (Uint8Array from step 2)
12. `Jets.put({ chunks: encChunks, start: 0, end: chunkCount, grants: [subtreeDelegation] }, options)`
    — passes the delegation proof so Jets can verify upload authorization
13. `manifest = buildManifest({ rootCid, encryptionRootPublicKey, accessRootPublicKey, bindingProof, chunkCount, chunkSize, size, name, type, jurisdiction, aiAttestation })`
14. `callback(null, { manifest, rootKey: Q.Data.toBase64(rootKey) })`

**Encrypted chunk shape sent to `Jets.put`:**
```js
{
  cid:        String,   // CIDv1
  iv:         String,   // base64 (12 bytes)
  ciphertext: String,   // base64
  tag:        String,   // base64 (16 bytes)
  size:       Number,   // plaintext chunk byte length
  tags:       Array     // content tags
}
```

**Note on rootCid in delegation context:** The subtreeDelegation produced in
step 8 has context `{ start: 0, end: N }` without rootCid because the Merkle
root is not computed until step 10. This is acceptable for upload authorization
(Jets accepts it since the file is new). For `grant()` calls after the fact,
the delegation is re-produced with full context including rootCid.

---

## Part 6 — Implementation Order

Each step only calls things already listed above it.

1. `_.LABELS` — pure constants
2. `_.base32(bytes)` — pure function
3. `_.digestToCid(digest)` — calls `_.base32`
4. `_.chunkAAD(absIndex)` — calls `TextEncoder`
5. `_.blobToBuffer(blob)` — calls `FileReader`
6. `_.chunkify(buffer, chunkSize)` — calls `ArrayBuffer.slice`
7. `_.deriveEncryptionRoot(rootKey)` — calls `Q.Crypto.delegate`
8. `_.deriveAccessRootBytes(rootKey)` — calls `Q.Crypto.delegate`
9. `_.deriveVersionKey(videoKey, versionLabel)` — calls `Q.Crypto.delegate`
10. `_.deriveSubtreeKey(encryptionRoot, start, end)` — calls `Q.Crypto.delegate`
11. `_.deriveChunkKey(subtreeKey, relIndex)` — calls `Q.Data.derive`
12. `_.deriveChunkIV(subtreeKey, relIndex)` — calls `Q.Data.derive`
13. `_.chunkCid(ciphertextB64, tagB64)` — calls `Q.Data.fromBase64`, `Q.Data.digest`, `_.digestToCid`
14. `_.levelFromLabel(type, word)` — calls `Q.Streams.*_LEVEL`
15. `_.parseLabel(label)` — calls `_.levelFromLabel`
16. `_.verifyCapability(proof, type, required, chunkIndex)` — calls `_.parseLabel`
17. `_.buildManifest(p)` — pure assembly
18. `store.js` — calls all `_internal` helpers + `Q.Crypto.internalKeypair`, `Q.Crypto.sign`, `Q.Data.Merkle.build`, `Q.Safe.Jets.put`; handles `options.videoKey` via `_.deriveVersionKey`
19. `fetch.js` — calls subset of helpers + `Q.Data.Merkle.verify`, `Q.Safe.Jets.get`
20. `grant.js` — calls `_.deriveEncryptionRoot`, `Q.Crypto.delegate` (directly with full context), optionally `Q.Data.Merkle.proof`; handles multi-version form
21. `reshare.js` — calls `Q.Safe.Drops.put`, `Q.Safe.Jets.dropAnnounce`
22. `_ensureServiceWorker.js` — calls `navigator.serviceWorker.register`
23. `_prefetchLoop.js` — calls `Q.Safe.Jets.get`, `postMessage`; version-aware
24. `stream.js` — calls `_ensureServiceWorker()`, `_prefetchLoop()`; returns handle
25. `upload.js` — calls `store()`
26. `download.js` — calls `fetch()`
27. `play.js` — calls `stream()`; returns handle with ergonomic seek-as-option
28. `pause.js` — one-liner: calls `handle.pause()`; may be defined inline in `Cloud.js` instead of a separate file

---

## Part 7 — What is NOT in Cloud.js

- `Q.Data.Prolly.*` — Jets only
- `Q.Data.Bloom.*` — Drops and Jets only
- OCP payment and authorization verification — Jets and Drops only
- On-chain balance checks — server-side infrastructure only
- Service Worker fetch handler — `Safe/sw.js` (separate file)
- HLS video segmentation / ffmpeg — pre-processing pipeline, not in-browser
- Socket.io connection management — Jets only
- Drop registration and lifecycle — Jets and Drops only
