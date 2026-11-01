# Safecloud Release Notes

## Safecloud 3.2

ML-DSA-65 hybrid governance attestation and Safebox liveness check. Layered on top of the 3.1 PQClaim scanner authorization — adds quantum-resistant verification to the Safebox's own identity claim, and a challenge-response heartbeat to prove the TEE is live at connection time.

All changes are additive. No existing API surfaces changed. Older Qbix versions without `@noble/post-quantum` continue to work for classical attestation; the new PQ options degrade gracefully with a clear diagnostic.

---

### ML-DSA-65 governance attestation (`requirePQAttestation`)

The 3.1 PQClaim proves who authorized a scannerCID. Governance attestation goes one level deeper: it verifies that the Safebox's own governance claim (the OpenClaim OCP document that authorized the Safebox to operate) carries a valid ML-DSA-65 signature.

After the Qbix platform PQ patch, a Safebox governance claim has parallel `key[]`/`sig[]` arrays with both ES256 and ML-DSA-65 entries. Index `i` of `key[]` pairs with index `i` of `sig[]`. The new `requirePQAttestation` policy option verifies that at least one of those signatures is a valid ML-DSA-65 signature over the canonical claim text.

**Usage:**

```js
var policy = new AttestationPolicy({
    scannerCID:           'bafybeig…',
    requirePQAttestation: true,          // require ML-DSA-65 sig in governance claim
    pqTrustedKeys: [                     // optional: pin specific key URI(s)
        'data:key/ml-dsa-65;base64,<1952-byte raw pk>'
    ]
});

var pass = await policy.evaluate(verifierResult, {
    govClaim:      parsedGovClaim,     // parsed OCP document with key[]/sig[] arrays
    govClaimCanon: canonicalClaimText  // Q.Crypto.OpenClaim.canonicalize(parsedGovClaim)
});
// { pass: true, reason: null }
```

Degradation on older Qbix (no `@noble/post-quantum`):

```js
// { pass: false, reason: 'requirePQAttestation: ML-DSA-65 library unavailable on this Qbix version — install @noble/post-quantum ^0.7.1 or disable requirePQAttestation' }
```

---

### Safebox liveness check (`livenessCheck`)

A cached attestation document proves the Safebox was genuine when it was issued — not that it's alive right now. The liveness check closes that gap with a challenge-response: the client posts a fresh nonce, the Safebox signs it with its ML-DSA-65 key, and the client verifies the signature over `SHA-256(nonce || claim_bytes)`.

Three states (default: `null`, i.e. disabled):

| `livenessCheck` | Behavior on failure |
|-----------------|---------------------|
| `null` / `false` | No-op; old Safeboxes unaffected |
| `true` | Warn to console; proceed anyway |
| `'strict'` | Reject — resolves `{ live: false, reason: '...' }` |

**Usage:**

```js
var fetcher = new AttestationFetcher(trustStore, {
    livenessCheck: 'strict'  // or true for non-blocking
});

var liveness = await fetcher.checkLiveness(
    'https://safebox.example.com',
    canonicalClaimText,
    govClaim.key   // key[] array from the governance claim
);
if (!liveness.live) {
    throw new Error('Safebox liveness failed: ' + liveness.reason);
}
```

The Safebox endpoint: `POST {safeboxUrl}/attestation/challenge` receives `{ nonce: "<32-byte hex>" }` and returns `{ signature: "<base64 ML-DSA-65 sig over SHA-256(nonce || claim)>" }`. Old Safeboxes without this endpoint are unaffected when `livenessCheck` is at its default `null`.

---

### `AttestationVerifier.verifyMLDSASig` static helper

New shared helper called by both the policy checker and the liveness check. Lazy-imports `@noble/post-quantum/ml-dsa.js` and caches the module. Returns a structured result rather than throwing:

```js
var result = await AttestationVerifier.verifyMLDSASig(sigB64, msg, pkB64);
// { ok: true,  available: true,  error: null }              — verified
// { ok: false, available: true,  error: 'signature check returned false' } — bad sig
// { ok: false, available: false, error: '@noble/post-quantum unavailable: …' } — old Qbix
```

`msg` may be a Buffer or UTF-8 string. FIPS 204 applies its own SHAKE256 internally — pass raw canonical bytes for governance claim verification, or `SHA-256(nonce || claim)` for challenge-response.

---

### Backward compatibility and EVM

- **Older Qbix (no `@noble/post-quantum`):** classical attestation (ES256/ES384/RS256) works exactly as in 3.0/3.1. The new options default to `null`. If `requirePQAttestation` is set on such a Qbix, the error message names the missing package and how to enable it.
- **Old Safeboxes (no `/attestation/challenge`):** unaffected when `livenessCheck` is at its default. `livenessCheck: true` catches the 404 and continues; `'strict'` returns `{ live: false }`.
- **EVM/EIP-712:** the `ecrecover`-based signing path is completely untouched. ML-DSA-65 is additive — a separate module invoked only when the new options are set.

---

### Files changed

| File | Change |
|------|--------|
| `classes/Safecloud/Attestation/AttestationVerifier.js` | Added `verifyMLDSASig` static method + ML-DSA-65 lazy loader |
| `classes/Safecloud/Attestation/AttestationPolicy.js` | Added `requirePQAttestation`, `pqTrustedKeys` options; refactored `evaluate()` to `Promise.all` pattern |
| `classes/Safecloud/Attestation/AttestationFetcher.js` | Added `livenessCheck` option, `checkLiveness()` method, `_post()` helper |

---

## Safecloud 3.0

The trust, persistence, and authoring release. Ships in one batch: TEE attestation across six hardware providers, post-quantum scanner authorization, durable SafecloudDB state, Jet HTTP file serving, a browser-native author upload pipeline, and embed player polish.

---

### TEE attestation

Proves that a Safebox chaperone is running an approved scanner WASM inside a genuine TEE before it can participate in content moderation. Implemented in pure Node.js with zero external dependencies.

Three cooperating classes in `classes/Safecloud/Attestation/`:

- **`AttestationVerifier`** (pure, no network) — verifies a raw attestation document given pre-resolved keys. Takes `(provider, doc, resolvedKeys)`, returns `{ valid, scannerCID, claims, ...providerFields }`. All provider errors are wrapped into `{ valid: false, error }` so the caller always gets a structured result.
- **`AttestationFetcher`** (network only) — fetches rotating JWKS from GCP and Azure MAA, the Veraison public key for OCI, AMD VCEK certificates by product + chip ID, and the Intel SGX Root CA. All fetched values are cached.
- **`AttestationPolicy`** — enforces the union of `scannerCID` (approved WASM CID) + allowed provider list + `allowDebug` flag. `evaluate(result)` → `{ pass, reason }`. Serializes with `toJSON`/`fromJSON` for persistence across restarts.

Six TEE providers:

| Provider | Wire format | Sig alg | `scannerCID` field |
|----------|-------------|---------|-------------------|
| AWS Nitro | COSE_Sign1 (CBOR, RFC 8152) | ES384 | `user_data` payload claim |
| GCP Confidential Space | RS256 JWT (OIDC) | RS256 | `user_data` payload claim |
| Azure MAA | RS256 JWT | RS256 | `x-ms-runtime.user-data` (base64) |
| OCI/Veraison | ES256 JWT (EAR, RFC 9334) | ES256 | `user_data` payload claim |
| AMD SEV-SNP | 1184-byte binary report | ES384 | `report_data[0..63]` at 0x050 |
| Intel TDX | TDX Quote v4 | ES256 | `report_data[0..63]` at header+0x248 |

Notable implementation notes: `Date.now()` exceeds the 32-bit CBOR max, so `cbor.js` uses 8-byte big-endian encoding (CBOR additional info 27) for 64-bit integers. `TD_REPORT_SIZE` is 0x288 (648 bytes), not 584 — the off-by-64 error caused `REPORT_DATA_OFF` and `SIG_SIZE_OFF` to resolve to the same offset, silently overwriting the scanner CID. `parseCOSESign1` exposes raw `protectedBytes` alongside the decoded map. `OCI.verify()` accepts a JWKS `{ keys: [...] }` or a bare JWK, selecting by `kid`.

71 Node.js tests in `tests/attestation_verifier.test.js`. Pre-baked fixtures in `tests/fixtures/{provider}/`, generated by `tests/fixtures/generate.js` with test-generated keys and openssl self-signed certs. Zero external test dependencies.

---

### Post-quantum scanner authorization

ML-DSA-65 (FIPS 204 / CRYSTALS-Dilithium) scanner-authorization claims layered on top of the TEE attestation stack.

The hardware attestation signatures — ES256/ES384 from AWS Nitro, GCP, Azure, OCI, Intel TDX, AMD SEV-SNP — are issued by hardware vendors and cannot be changed. Those use ECDSA, which Shor's algorithm breaks in polynomial time. HKDF and AES-256 are unaffected (Grover's algorithm gives only a √ speedup, leaving 128-bit effective security). The vulnerability is in signing, specifically in who authorized the scannerCID. `PQClaim` seals that authorization with a lattice-based signature that resists both Shor and Grover.

**Claim format** (`classes/Safecloud/Attestation/PQClaim.js`):

```json
{
  "v": 1,
  "action": "approve-scanner",
  "scannerCID": "<CID>",
  "issued": "<ISO 8601 UTC>",
  "expires": "<ISO 8601 UTC>",
  "pqPublicKey": "data:key/ml-dsa-65;base64,<1952-byte raw public key>",
  "pqSig": "<base64 ML-DSA-65 signature over canonical bytes>"
}
```

Canonical bytes = UTF-8 of `JSON.stringify` over all fields except `pqSig`, keys sorted lexicographically. ML-DSA-65 performs internal hashing (FIPS 204 §3.4) — no SHA-256 pre-hash. Signature is 3309 bytes; public key is 1952 bytes.

```js
var claim = await PQClaim.sign({
    scannerCID:  'bafybeig…',
    pqPublicKey: 'data:key/ml-dsa-65;base64,<b64>',
    pqSecretKey: secretKeyBytes,   // 4032 bytes
    ttlSeconds:  30 * 24 * 3600   // default 30 days
});

var { valid, error } = await PQClaim.verify(claim, {
    scannerCID: 'bafybeig…',
    trustedKey: 'data:key/ml-dsa-65;base64,<b64>',  // optional; omit to accept any valid sig
    now:        new Date()
});
```

**`AttestationPolicy`** gains two new falsy-by-default options: `requirePQClaim` — when true, `evaluate()` requires a valid `PQClaim` for the `scannerCID` in addition to the classical TEE check; `pqTrustedKey` — pins a specific ML-DSA-65 public key URI as the only accepted claim issuer. When `requirePQClaim` is set, `evaluate()` returns a Promise. Existing synchronous callers are unaffected. `toJSON`/`fromJSON` round-trips both fields.

Dependency: `@noble/post-quantum ^0.7.1`, imported via a lazy `import()` call cached on first use (ESM-only; no impact on CJS callers). Key URI format matches the Qbix platform `Q.Crypto` convention, so keys produced by either layer are interoperable.

16 tests in `tests/pq_claim.test.js`: sign/verify round-trip, tamper detection, expiry and future-issued rejection, wrong CID, wrong trusted key, policy integration with and without PQ claim, `toJSON`/`fromJSON`. Existing 71 attestation verifier tests unaffected.

---

### Persistent SafecloudDB

`_trackStore` (SafecloudDB's in-memory BoundedMap) previously wiped on every Jet restart. WASM apps had to reconstruct state from the receipt chain or treat every boot as a cold start.

WASM handler execution is deterministic and atomic: a completed handler takes (inputs, state-before) → (state-after, receipt). There is no partial state, so a single snapshot of state-after is sufficient for restart recovery — no WAL or redo log needed. The model is analogous to ZFS snapshots or Git commits: once a commit lands, the tree root CID describes the full state.

- **Checkpoint writes.** After each successful handler execution, `WasmRunner` serializes all key→value pairs for every mutated track into a JSON checkpoint blob, content-addresses it (`bafy…` CID), and writes it to Drops via `Safecloud/drop/put`. Fire-and-forget — never blocks the HTTP response path.
- **Local checkpoint index.** After a blob is durably stored, `WasmRunner` updates `~/.safecloud-checkpoints.json` (path configurable) with `"appCid/track" → checkpointCid`. This is what lets a restarted Jet know which CIDs to fetch.
- **Restart recovery.** `WasmRunner.restoreCheckpoints(indexPath)` reads the index, fetches each blob from Drops, and replays entries into `_trackStore`. Called asynchronously during Jet startup — the Jet starts serving immediately without waiting.
- **Root CID gossip.** After each checkpoint write, `WasmRunner._emitRootUpdate` broadcasts `safedb:root-update` over the `/Safecloud/cloud` socket.io namespace:
  ```json
  { "appCid": "bafy…", "track": "posts", "rootCid": "bafy…",
    "checkpointCid": "bafy…", "seq": 42, "jetId": "jet-abc" }
  ```
  Receiving Jets skip their own echoes, then call `WasmRunner.applyRootUpdate(msg)`: if the local sequence number is `>= msg.seq`, the message is dropped; otherwise the checkpoint blob is fetched and merged into `_trackStore`. Jets reach eventual consistency across the network.
- **Receipt track.** The receipt chain (`receipts/<appCid>`) is a regular SafecloudDB track, checkpointed identically. Full execution history survives restarts.

17 tests in `tests/safedb_checkpoint.test.js`: fresh-start on missing index, blob fetch and replay on restore, stale-seq guard (monotone), own-echo no-op, disk persistence of checkpoint CID after `applyRootUpdate`.

---

### Jet HTTP file serving

Jets now serve the Safecloud embed player and companion web assets at `/Safecloud/player` via `express.static`:

```js
app.use('/Safecloud/player', express.static(path.join(__dirname, '../../web'), {
    maxAge: '1h', etag: true
}));
```

Any Jet is now an HTTP origin for iframe embeds — no external CDN required. This also completes the decentralized package registry story: WASM app manifests point to handler CIDs on Drops, and front-end assets are served from the same Jet.

---

### Author upload pipeline

A complete browser-side publish flow. Authors drag a file into a dashboard, fill in optional metadata, click Publish, and receive an `<iframe>` embed snippet. No server-side author tooling, no framework dependency.

**`web/safecloud-upload.js`** — standalone UMD browser library (works without Q.js):

```js
const up = new SafecloudUpload({ jetUrl: 'https://jet.example.com' });
up.on('progress', ({ phase, pct }) => console.log(phase, pct + '%'));
// phases: 'chunking', 'encrypting', 'uploading', 'done'

const { rootCid, embedUrl, urlFragment } = await up.upload(file, {
    title: 'My video', description: 'Episode 42', tags: ['demo'],
    price: '0',    // wei per chunk view ('0' = free)
    encrypt: false // true = AES-256-GCM split-key
});
```

CID scheme matches WasmRunner and the Jet: `'bafy' + SHA-256(bytes).hex().slice(0, 52)`. Files are split into 256 KB chunks, each content-addressed. Optional AES-256-GCM encryption generates a fresh 256-bit key in the browser; the key is split — first 128 bits in the URL fragment (`#key=…`), second 128 bits POSTed to the Jet as a server fragment. The manifest is itself a content-addressed JSON blob; its CID is the root CID. Uploads proceed in batches of 12 chunks (well under the 8 MB body limit). The server fragment is registered on the final batch.

**`web/author.html`** — drag-drop dashboard served at `/Safecloud/player/author.html`:

- Drag-and-drop file zone, metadata form (title, description, tags), optional encryption checkbox.
- Live storage price estimate from `GET /Safecloud/drop/price` before upload begins.
- Progress bar with phase labels (chunking / encrypting / uploading).
- Result panel: root CID, ready-to-paste `<iframe>` snippet, copy buttons, encrypted-key warning with full share URL.
- Dark/light theme via CSS custom properties.

**New Jet HTTP endpoints** in `classes/Safecloud/Jets.js` (all CORS-open):

- `POST /Safecloud/author/upload` — receives base64-encoded chunk batches and proxies them to a connected Drop via `selectDrops` / `callDrop`. Handles inline server fragment registration on the final batch. Global body limit raised from 256 KB to 8 MB.
- `GET /Safecloud/drop/price?bytes=N` — returns upload cost estimate. Configurable via `Safecloud.author.uploadPricePerByte` (defaults `'0'`).
- `POST /safecloud/fragment` — HTTP companion to the existing socket.io fragment-registration event, for browser-only clients without a socket connection.

---

### Embed player

- **Loading spinner** — CSS `@keyframes` spinner visible during all loading phases (initialising, connecting, fetching, buffering). Hidden on error or once video plays.
- **Buffering indicator** — `waiting` / `playing` video events show/hide a "Buffering…" overlay during network stalls.
- **Descriptive error messages** — e.g. "No content specified — add ?rootCid=bafy… to the URL", "Share the full URL including the #… fragment".
- **Mobile layout** — `@media (max-width:480px)` breakpoint for larger spinner and readable status text.
- **`setLoading(msg)` / `setError(msg)` helpers** — reduce duplicated DOM manipulation throughout `player.js`.

---

### Tests

| Suite | Count | Status |
|-------|-------|--------|
| `tests/attestation_verifier.test.js` | 71 | ✓ all pass |
| `tests/pq_claim.test.js` | 16 | ✓ all pass |
| `tests/jet_module.test.js` | 10 | ✓ all pass |
| `tests/safedb_checkpoint.test.js` | 17 | ✓ all pass |

---

### Files changed

| File | Status |
|------|--------|
| `classes/Safecloud/Attestation/` (new directory) | **New** |
| `classes/Safecloud/Attestation/PQClaim.js` | **New** |
| `classes/Safecloud/Jets/WasmRunner.js` | Modified — checkpoint + gossip |
| `classes/Safecloud/Jets.js` | Modified — attestation routes, author upload endpoints, body limit, static serving |
| `web/safecloud-upload.js` | **New** |
| `web/author.html` | **New** |
| `web/embed.html` | Modified — spinner + mobile CSS |
| `web/player.js` | Modified — loading states + error messages |
| `tests/attestation_verifier.test.js` | **New** |
| `tests/pq_claim.test.js` | **New** |
| `tests/safedb_checkpoint.test.js` | **New** |
| `tests/jet_module.test.js` | Modified — Q stub fixes |
| `GetStarted/Author.md` | Modified — dashboard + embed instructions |
| `README.md` | Modified — §20 attestation, §27 SafecloudDB persistence, §28 Jet HTTP serving, §29 author upload pipeline |

---

## 2.9 — Data structures and testing

The implementation release. Introduces five SDK-level data structures built on the `tree_*` host API, a reference TreeStore implementation, and a comprehensive test battery covering Node.js and headless browser environments.

**New host API function:** `tree_diff(cidA, cidB)` — compares two checkpointed tree states and returns an array of `{ key, before, after }` changes.

**TreeStore** — in-memory reference implementation of the full `tree_*` host API, for testing and the `safecloud dev` emulator. Two modes: KV (ordered key-value with range queries) and append (append-only log with subscribe for live tail). Every mutation updates the root CID (Merkle property). ChunkStore for checkpoint/hydrate persistence. Deterministic CID via SHA-256 of JSON with recursively sorted keys.

**Five data structures:**

- **Directory** — static folder (IPFS/IPLD analog). KV tree with slash-delimited path keys and file manifest values. Immutable snapshots addressed by root CID. store, fetch, getFile, list, diff.
- **Feed** — append-only event log (Hypercore/Kafka analog). Wraps an append-mode tree with subscribe for live tail. Checkpoint/restore. For event sourcing, audit trails, deploy logs.
- **Repo** — versioned directory with branch/merge/diff (Git analog). Three internal trees: working tree (KV), commit log (append), branches (KV). LWW and manual merge strategies. Manual merge reports `{ path, ours, theirs }` conflicts for caller resolution.
- **Database** — indexed KV store with version history (Dolt analog). Primary KV tree plus per-field index trees. Index key format: `String(indexValue) + '\0' + primaryKey` for clean range boundaries. Dynamic index management (addIndex, dropIndex). Commit, log, diff, rollback.
- **NameResolver** — mutable name→CID resolution (IPNS analog). KV tree of name → `{ target, seq, owner, updatedAt }`. Monotonic sequence number prevents rollback. Checkpoint/restore.

145 Node.js tests across 11 sections. 53 headless browser tests via Playwright covering all six modules plus integration.

**New docs:** DataStructures.md. **Updated:** Architecture.md, Apps.md, LLM.md, CHANGELOG.md.

---

## 2.8 — Unified architecture

Introduces the unifying three-layer model and revises the chat architecture for metadata protection.

**New file: Architecture.md** (~3,500 words). Documents the unified architecture: **Safecloud = pull** (content-addressed encrypted storage, retrieval by CID), **Intercloud = push** (event propagation along rails, watchers, epochs), **Safebox = trust** (attested TEE compute, push notification gateway, confidential workloads). The three layers form a loop: content enters Safecloud → events propagate through Intercloud → safebots in Safeboxes process → curated notifications push to users → users pull content by CID, decrypt in player.

Also covers: three-tier WASM (Jet-side, client-side, Safebox) with host API tables, tree API replacing flat KV, WAL + checkpoint to Drops, revised chat model, SafecloudApp deployment, and comparisons to Cloudflare Workers, Pear/Hyperswarm, and Signal.

**Tree API** — `tree_create`, `tree_append`, `tree_get`, `tree_put`, `tree_range`, `tree_delete`, `tree_root`, `tree_checkpoint`, `tree_hydrate`. KV functions remain as aliases.

**Revised chat architecture** — rooms are Merkle trees (append-only log of encrypted blobs), not Jet-routed message tracks. WebRTC mesh for real-time delivery; Jet as TURN relay only. 2-hop onion routing for persistence: sender → 2 intermediate Jets → destination Jet. No sender pubkey in envelope (deniability). No wall-clock timestamp — monotonic tree position index for ordering.

**Updated:** Apps.md, LLM.md, CHANGELOG.md.

---

## 2.7 — Flagging and moderation expansion

**Flagging.md** grew from 7,800 to 10,700 words (+2,900). Expanded coverage of the three-layer content safety model: detailed reputation mechanics, stake-based flagging, jury selection algorithms, anti-griefing measures, corroboration requirements, shadowban gradient.

---

## 2.6 — Adaptive streaming

**New file: AdaptiveStreamer.md** — design document for adaptive Drop selection during striped downloads: parallel probing, EMA-based throughput tracking, tier classification (Fast/Marginal/Slow), Drop-side serving policy (`serveWhen`, battery/connection monitoring, pause/resume), micropayment ramping (unsigned intent → signed settlement, per-drop watermark channels).

**New code: AdaptiveStreamer.js** — client-side implementation. Test suite in `tests/adaptive_streamer.test.js`.

---

## 2.5 — LLM primer expansion

**LLM.md** grew from 1,000 to 2,000 words (+1,000). Expanded the coding primer with additional API surface coverage, common mistakes table, and cross-references to companion docs.

---

## 2.4 — README consolidation

**README.md** grew from 9,900 to 11,000 words (+1,100). Consolidated and clarified the core protocol documentation: storage primitives, key hierarchy, OCP delegation, micropayment flows, Jet-to-Jet authentication, Drop lifecycle.

---

## 2.3 — Content safety deepening

**Flagging.md** grew from 6,000 to 7,800 words (+1,800). Expanded coverage of the three-layer content safety model: client-side WASM scanning, Safebox chaperone scanning, E2E chat content safety with per-message key escrow under threshold ElGamal.

---

## 2.2 — Epoch protocol and expanded threat model

**New file: EpochProtocol.md** (3,200 words). Standalone implementation reference for the bidirectional hash-chain epoch protocol: forward chain for forward secrecy, backward chain for post-compromise security, epoch transitions, scope table.

**Attacks.md** grew from 8,000 to 11,500 words (+3,500). Expanded threat model covering SafecloudApp-specific attack vectors: malicious WASM, Jet execution lies, chain tampering, resource exhaustion, trigger and outbound endpoint abuse, epoch key compromise.

---

## 2.1 — SafecloudApps expansion

**Apps.md** grew from 5,100 to 7,900 words (+2,800). New coverage: SafecloudDB tracks with per-track HKDF encryption, handler lifecycle and fuel metering, SafecloudChain (hash-chained receipts for deterministic replay), trigger system, outbound endpoints, rooms and E2E encrypted chat.

---

## 2.0 — Foundation

The initial documentation release. Establishes the core architecture: encrypted chunk storage on Drops, routing through Jets, HLS video streaming via service worker, micropayments via ERC-20 tokens with EIP-712 signatures, identity via hash-chained keychains with dual-threshold recovery.

**Core docs:** README.md (storage primitives, key hierarchy, OCP, micropayments — 9,900 words), Apps.md (SafecloudApps WASM execution model — 5,100 words), Attacks.md (threat model — 8,000 words), Ecosystem.md (keychains, organizations — 4,800 words), Flagging.md (content moderation — 6,000 words), LLM.md (coding primer — 1,000 words), Protocol.md, Trading.md, Qbix.md/QbixPHP.md.

**Code:** Client.js (store, fetch, grant, reshare, HLS streaming), service worker for HLS, Jet routing, Drop storage, demo pages, vendored ethers v6.17.0, payment signing and verification, test suite.
