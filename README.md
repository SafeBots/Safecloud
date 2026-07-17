# Safecloud - decentralised, encrypted, self-pricing data storage and streaming network.

# Complete Architecture & API Reference

This document is an overview of the internals of the Safecloud ecosystem. It can serve as the canonical context file for new LLM sessions working on the Safecloud project. It covers architecture, cryptographic design, all method signatures, and the role of OpenClaiming (OCP) in the system.

---

## Installation & Quick Start

Safecloud is a **Qbix plugin**. It requires the `Users` and `Streams` plugins.

**1. Install the plugin** into your app's `plugins/` directory (symlink or
copy this folder as `plugins/Safecloud`), then register it in your app's
`config/app.json` plugins list.

**2. Add routes** — per Qbix convention, plugins do not ship routes. In your
app's `APP_DIR/config/app.json`:

```json
{ "Q": { "routes": {
    "safecloud/demo": { "module": "Safecloud", "action": "demo" },
    "safecloud/drop": { "module": "Safecloud", "action": "drop" }
}}}
```

**3. Serve the service worker with the right header.** Encrypted streaming
registers `web/js/Safecloud/sw.js` at scope `/`, which browsers only allow
when the file is served with `Service-Worker-Allowed: /`.

- Apache: the shipped `web/js/Safecloud/.htaccess` sets it (ensure
  `mod_headers` is enabled and `AllowOverride` permits it).
- nginx:

```nginx
location ~ /Safecloud/js/Safecloud/sw\.js$ {
    add_header Service-Worker-Allowed "/";
}
```

**4. Configure** in `APP_DIR/local/app.json` (deployment overrides —
defaults live in this plugin's `config/plugin.json`):

```json
{ "Safecloud": {
    "requirePayment": false,
    "jetUrl": "https://your-jet.example.com",
    "jet":          { "address": null, "privateKey": null },
    "safebux":      { "address": null, "chainId": "eip155:56", "perChunkWei": "0" },
    "openclaiming": { "address": null },
    "wallet":       { "privateKey": null },
    "swarm":        { "enabled": false }
}}
```

`jet.privateKey` enables Jet→Drop payment-token signing. `wallet.privateKey`
enables the hyperswarm Jet mesh (experimental — leave unset for single-Jet
deployments). With everything null and `requirePayment:false`, the network
runs in free mode.

**5. Start the Jet** from inside the app:

```
node plugins/Safecloud/demo/jet.js
```

**6. Open** `/safecloud/demo` to upload/stream and `/safecloud/drop` to run
a storage node.

---

## 1. What Safecloud Is

Safecloud is a **decentralised, encrypted, self-pricing storage network** built on top of the Q/Intercoin platform. Files are split into encrypted chunks and
distributed across browser tabs and servers. No node ever sees plaintext — every
chunk is encrypted before it leaves the owner's device, and keys are never
transmitted.

The three network roles are:

| Role | Code | Where it runs |
|------|------|--------------|
| **Cloud** | `Q.Safecloud.Client` | Browser — file owner/consumer SDK |
| **Jets** | `Q.Safecloud.Jets` (client) + `classes/Safecloud/Jets.js` (server) | Browser (socket client) + Node.js (routing server) |
| **Drops** | `Q.Safecloud.Drops` | Browser tabs volunteering IndexedDB storage |

Jets never see plaintext. Drops never see plaintext. Only the Cloud (owner or
authorised grantee) has the keys to decrypt.

---

## 2. Technology Stack

**This is a pure JavaScript project.** Node.js (server) and Web Browser (client).
PHP is present only for compatibility — e.g. verifying OCP payment or
authorisation claims that arrive at a PHP web server before being forwarded.

All crypto runs through:

- `Q.Data.*` — primitive operations: `digest`, `hkdf`, `derive`, `importKey`,
  `encrypt`, `decrypt`, `canonicalize`, and the tree structures `Merkle`, `Prolly`, `Bloom`
- `Q.Crypto.*` — typed signing: `internalKeypair`, `sign`, `verify`, `delegate`, `verifyDelegated`
- `Q.Crypto.OpenClaim.*` — OCP claim envelope: `sign`, `verify`, `canonicalize`, `resolve`
- `Q.Crypto.OpenClaim.EVM.*` — EIP-712 payment + authorisation extensions

Browser implementations use `SubtleCrypto` and dynamic `import()` of noble-curves
(`nist.js`, `secp256k1.js`, `sha3.js`, `eip712.js`, `encoder.js`).
Node.js uses `crypto` built-in and `crypto-js` for keccak256.

---

## 3. Cryptographic Primitives

### 3.1 `Q.Data.derive(seed, label, options)` — HKDF key derivation

The core primitive for the entire key hierarchy. **Every key in Safecloud is
derived from a root secret using this function — nothing is stored except the
root.**

```
seed:    Uint8Array   (must be binary — decode hex/base64 first)
label:   String       (HKDF info / domain separation label)
options.size:    Number  (output bytes, default 32)
options.context: String  (HKDF salt = SHA-256(context), default "")

Returns: Promise<Uint8Array>
```

Internally: `salt = SHA-256(context)`, then HKDF-SHA256 with the label as `info`.
This is byte-identical across browser (SubtleCrypto) and Node.js (crypto built-in)
and PHP.

**Domain separation is critical.** Every label used in Safecloud is unique and
hard-coded in `_internal.js`:

```
safecloud.encryption.root      → encryptionRoot (32 bytes) from rootKey
safecloud.access.root          → accessRoot (32 bytes) from rootKey

Three parallel N-ary trees from one rootCid (binary default):
  Merkle tree    — built bottom up from chunk CIDs (public, cacheable)
  Encryption key tree — built top down via chained Q.Crypto.delegate (Cloud only)
  Access level tree   — built top down via chained Q.Crypto.delegate (Jets enforce)

Same link path array navigates all three:
  ["track","data","0","1"]  → Merkle node / encryption subtreeKey / access grant
safecloud.track.data.{S}.{E}    → subtreeKey for data track chunk range [S, E)
safecloud.track.index           → key for the index track (single encrypted chunk)
safecloud.chunk.key.{i}        → AES-256-GCM key for chunk i (relative)
safecloud.chunk.iv.{i}         → 12-byte IV for chunk i (relative)
safecloud.read.{word}          → label for a read-delegation capability
safecloud.write.{word}         → label for a write-delegation capability
safecloud.admin.{word}       → label for an admin-delegation capability
```

### 3.2 `Q.Data.digest(algorithm, payload)` → Promise<Uint8Array>

SHA-256 (and others). Used directly for CID computation and as a building block
inside `derive` and the tree structures.

### 3.3 `Q.Data.hkdf(ikm, salt, info, length)` → Promise<Uint8Array>

Low-level HKDF-SHA256. Called by `derive`. Rarely used directly.

### 3.4 `Q.Data.encrypt(key, plaintext, options)` → Promise<{iv, ciphertext, tag}>

AES-256-GCM encryption. All three fields are base64 strings.

```
key:              CryptoKey (from Q.Data.importKey)
plaintext:        Uint8Array
options.iv:       Uint8Array|String  (base64 or Uint8Array — MUST be supplied for convergent encryption)
options.additional: Uint8Array       (AAD — additional authenticated data)

Returns: { iv: base64, ciphertext: base64, tag: base64 }
```

The `tag` is always separated out. Safecloud passes `tag` and `ciphertext`
separately everywhere; this matters for `decrypt` and CID computation.

### 3.5 `Q.Data.decrypt(key, ivBase64, ciphertextBase64, options)` → Promise<Uint8Array>

```
options.tag:        base64 String   (16-byte auth tag — appended to ciphertext before decryption)
options.additional: Uint8Array      (must match AAD used at encrypt time, or decryption fails)
```

### 3.6 `Q.Data.importKey(keyBytes, algo)` → Promise<CryptoKey>

Imports raw bytes as an AES-GCM key (default). Used before every
`encrypt`/`decrypt` call.

### 3.7 `Q.Data.canonicalize(object)` → String

RFC 8785 / JCS canonical JSON (keys sorted recursively, deterministic number
serialisation). Used by OCP claim signing. Byte-identical to PHP
`Q_Data::canonicalize()`.

---

## 4. Tree Structures

### 4.1 `Q.Data.Merkle` — ordered Merkle tree for chunk integrity

Used in Safecloud to commit to the ordered set of CIDs in a file. The
Merkle root is stored in the public manifest and allows any party to
verify that a chunk they received was included in the original upload.

Leaf hashing uses domain-separation prefix bytes:
- Leaves: `SHA-256( 0x00 || leafBytes )`
- Internal nodes: `SHA-256( 0x01 || leftHash || rightHash )`

```js
Q.Data.Merkle.build(leaves)           → Promise<rootHex>
  // leaves: Array<Uint8Array|String>

Q.Data.Merkle.proof(leaves, index)    → Promise<{ proof: Array, rootHex: String }>
  // proof: Array<{ hex: String, side: 'left'|'right' }>

Q.Data.Merkle.verify(leaf, proof, rootHex) → Promise<Boolean>
```

### 4.2 `Q.Data.Prolly` — probabilistic B-tree for inventory reconciliation

Used by Drops and Jets to efficiently reconcile chunk inventories after a
reconnect. Structural sharing means subtrees with equal roots are skipped
entirely — diff is O(diff × log n), not O(n).

```js
Q.Data.Prolly.build(entries, store)           → Promise<rootHash>
  // entries: Array<{ key: String, value: String }>
  // store:   { get(hash)->Promise<node|null>, put(hash,node)->Promise } (optional, defaults to in-memory)

Q.Data.Prolly.get(rootHash, key, store)        → Promise<String|null>

Q.Data.Prolly.set(rootHash, key, value, store) → Promise<newRootHash>

Q.Data.Prolly.delete(rootHash, key, store)     → Promise<newRootHash>

Q.Data.Prolly.diff(rootHashA, rootHashB, store) → Promise<Array<{key, before, after}>>
```

### 4.3 `Q.Data.Bloom` — Bloom filter for cold-start inventory hints

Used on first contact between a Drop and a Jet (before any Prolly tree state
is shared). The Drop sends a compact Bloom filter of all its CIDs; the Jet
can probe for specific CIDs before routing.

```js
Q.Data.Bloom.create(n, p)                    → Promise<BloomFilter>
  // n: expected element count, p: false positive rate (e.g. 0.01)

Q.Data.Bloom.fromElements(elements, p)       → Promise<BloomFilter>
  // elements: Array<String> (CID strings), p: false positive rate

Q.Data.Bloom.fromBytes(uint8array, k, m, count) → Promise<BloomFilter>

Q.Data.Bloom.fromBase64(base64str, k, m, count) → Promise<BloomFilter>

// BloomFilter instance methods:
bloom.add(element)     → Promise (adds via SHA-256 hash)
bloom.test(element)    → Promise<Boolean>
bloom.toBase64()       → String
bloom.toBytes()        → Uint8Array
```

---

## 5. Signing and Keypairs

### 5.1 `Q.Crypto.internalKeypair(options)` → Promise<keypair>

**The only place a secret becomes a private key.** Deterministic, no randomness,
no storage.

```js
options.secret: Uint8Array   (32 bytes recommended)
options.format: 'ES256'|'EIP712'

// ES256 (P-256):
//   privateKey = HKDF-SHA256(secret, "q.crypto.p256.private-key", 32 bytes)
//   publicKey  = P-256 uncompressed point (65 bytes: 0x04 || X || Y)

// EIP712 (secp256k1):
//   seed       = keccak256("q.crypto.k256.private-key" || secret)
//   privateKey = seed mod curveOrder
//   publicKey  = secp256k1 uncompressed point (65 bytes)
//   address    = "0x" + last 20 bytes of keccak256(publicKey[1..64])

Returns: { format, curve, hashAlg, privateKey, publicKey, [address] }
```

### 5.2 `Q.Crypto.sign(options)` → Promise<proof>

Signs a typed message. ES256 signs `SHA-256(canonical JSON payload)`. EIP712
signs the EIP-712 struct hash.

```js
options.secret:      Uint8Array
options.format:      'ES256'|'EIP712'
options.message:     Object
options.types:       Object  (EIP-712 type definitions)
options.primaryType: String
options.domain:      Object  (optional)

// ES256 returns DER-encoded signature
// EIP712 returns 65-byte r||s||v (v = 27 + recovery bit)

Returns: { format, curve, hashAlg, domain, primaryType, digest, signature, signatureHex, publicKey, [address] }
```

### 5.3 `Q.Crypto.verify(options)` → Promise<Boolean>

```js
options.format:      'ES256'|'EIP712'
options.message:     Object
options.types:       Object
options.primaryType: String
options.domain:      Object
options.signature:   Uint8Array|String
options.publicKey:   Uint8Array    (ES256 only)
options.address:     String        (EIP712 — expected signer "0x...")
options.recovered:   Object        (optional — .address written here on EIP712 recovery)
```

### 5.4 `Q.Crypto.delegate(options)` → Promise<delegation>

Derives a child secret and creates a signed proof that the parent authorised it.
Used by `Cloud.grant()` to create scoped access tokens.

```js
options.rootSecret: Uint8Array    (parent secret)
options.label:      String        (e.g. "safecloud.read.content")
options.context:    String        (JSON-encoded scope: rootCid, start, end, exp)
options.format:     'ES256'|'EIP712'

// Internally:
//   childSecret = Q.Data.derive(rootSecret, "q.crypto.delegate." + label, {size:32})
//   parentKeypair = Q.Crypto.internalKeypair(rootSecret, format)
//   statement = { parent, label, issuedTime, context, secretHash }
//   proof = Q.Crypto.sign({ secret: rootSecret, message: statement, ... })

Returns: {
  label:     String,
  context:   String,
  secret:    Uint8Array,   // the derived child secret
  statement: Object,
  proof:     Object        // the signed proof (contains signature + publicKey)
}
```

### 5.5 `Q.Crypto.verifyDelegated(options)` → Promise<Boolean>

Verifies one delegation step: the child secret matches `statement.secretHash`,
the statement was signed by the declared parent.

```js
options.format:        'ES256'|'EIP712'
options.statement:     Object
options.signature:     Uint8Array|String
options.derivedSecret: Uint8Array
options.parentPublicKey: Uint8Array  (ES256 only)
options.domain:        Object        (EIP712 only)
options.recovered:     Object        (optional)
```

---

## 6. Safecloud Key Hierarchy

Every file has one master secret: the **rootKey** (32 random bytes). From it,
everything is derived deterministically using `Q.Data.derive`. The owner must
store the rootKey securely — it is not in the manifest.

```
rootKey  (32 bytes — owner must keep this secret)
  │
  ├─ derive("safecloud.encryption.root")
  │    → encryptionRoot  (32 bytes)
  │         │
  │         ├─ Q.Crypto.internalKeypair(ES256)
  │         │    → encryptionRootKeypair
  │         │       publicKey → stored in manifest
  │         │       used to sign the bindingProof
  │         │
  │         └─ derive("safecloud.subtree.{S}.{E}")
  │              → subtreeKey  (32 bytes, covers chunks S..E-1)
  │                   │
  │                   ├─ derive("safecloud.chunk.key.{i}")  (i = relative index)
  │                   │    → AES-256-GCM key for chunk i
  │                   │
  │                   └─ derive("safecloud.chunk.iv.{i}")
  │                        → 12-byte IV for chunk i
  │
  └─ derive("safecloud.access.root")
       → accessRootBytes  (32 bytes)
            │
            └─ Q.Crypto.internalKeypair(ES256)
                 → accessRootKeypair
                    publicKey → stored in manifest
                    used for future access control (v2+)
```

The **subtreeKey** is the unit of delegation. When the owner grants access to
`[start, end)`, they derive `subtreeKey = derive(encryptionRoot, "safecloud.subtree.{start}.{end}")` and run `Q.Crypto.delegate` on it to produce an OCP capability.

The **grantee** receives:
- `capability.secret` — base64 of the subtreeKey (to decrypt chunks)
- `capability.read` / `capability.write` / `capability.admin` — OCP delegation proofs (to present to Jets)

The grantee derives chunk keys using the **relative** index within their range:
`chunkKey = derive(subtreeKey, "safecloud.chunk.key.{relIdx}")` where
`relIdx = absIdx - start`. This means the keys are identical whether derived
by the owner or the grantee.

### Convergent encryption

All key derivation is **deterministic**. Same rootKey + same content → same chunk
keys → same ciphertext → same CIDs. This enables natural deduplication: if the
same file is uploaded twice with the same rootKey, the Jets/Drops can recognise
the identical CIDs and skip redundant storage.

---

## 7. CID (Content Identifier)

Each chunk's identity is a **CIDv1** string: `'b' + base32(bytes)` where:

```
bytes[0]    = 0x01   CIDv1
bytes[1]    = 0x55   raw codec
bytes[2]    = 0x12   sha2-256 multihash
bytes[3]    = 0x20   32-byte digest
bytes[4..35]= SHA-256(ciphertext || tag)
```

The CID is computed over the **ciphertext concatenated with the auth tag** — not
the plaintext. This means:
- CIDs are safe to share publicly (no plaintext leakage)
- The CID commits to the full authenticated ciphertext including the GCM tag
- Drops can verify they have the right chunk without any keys

`Q.Safecloud.Client._internal.chunkCid(ciphertextB64, tagB64)` and
`Q.Safecloud.Drops.cidFromData(arrayBuffer)` must produce identical values.

---

## 8. Additional Authenticated Data (AAD)

Every chunk is encrypted with AAD:
```
aad = UTF-8("safecloud.chunk:" + absoluteIndex)
```

The AAD binds each ciphertext to its absolute position in the file. Even if an
attacker somehow obtained two chunk keys, they could not swap chunks — the AAD
mismatch would cause GCM authentication to fail.

Note: chunk keys and IVs use the **relative** index within the subtree, but AAD
uses the **absolute** index. This is intentional: the relative index is what the
grantee needs to derive keys, while the absolute index is a unique file-wide
position that prevents cross-chunk confusion.

---

## 9. Manifest (public, no secrets)

The manifest is fully public and shareable. It contains everything needed to
locate, verify, and request chunks — but nothing needed to decrypt them.

```js
{
  v:                       1,
  rootCid:                 String,   // Merkle root of all chunk CIDs
  encryptionRootPublicKey: String,   // base64 — verifies bindingProof
  accessRootPublicKey:     String,   // base64 — for access control (v2+)
  bindingProof: {
    statement: { encryptionRootPublicKey, accessRootPublicKey, rootCid },
    proof:     Object   // Q.Crypto.sign result — verifies these two keys belong together
  },
  chunkCount:              Number,
  chunkSize:               Number,   // bytes per chunk (last chunk may be smaller)
  size:                    Number,   // total file bytes
  name:                    String,
  type:                    String,   // MIME type
  created:                 Number,   // Unix timestamp
  jurisdiction:            String|null,
  aiAttestation:           Object|null
}
```

The `bindingProof` is signed by `encryptionRoot` and commits to both public
keys and the `rootCid`. Anyone can verify the two roots belong to the same file
without knowing any secrets.

---

## 10. Q.Safecloud.Client API

**Browser only.** All methods follow `Q.promisify` convention: they accept an
optional callback as the last argument and also return a `Q.Promise`.

### `Q.Safecloud.Client.defaultChunkSize`
`Number` — default chunk size in bytes (256 × 1024 = 262144).

### `Q.Safecloud.Client.manifestVersion`
`Number` — current manifest version (1).

### Level labels
Mapping Streams-compatible level words (e.g. `'content'`) to numeric levels
is handled internally (`methods/Safecloud/Client/_internal.js:levelFromLabel`).
Pass level *words or numbers* in `grant()` options; there is no public
`levelFromLabel` export.

---

### `Q.Safecloud.Client.store(file, options, callback)` → Promise

Chunks, encrypts, and uploads a file to Safecloud via Jets.

```js
file: {
  data:  Blob,           // file content
  name:  String,
  type:  String,         // MIME type (optional)
  tags:  Array           // optional content tags
}

options: {
  key:           Uint8Array,   // existing rootKey (re-upload / update). Omit to generate random key
  chunkSize:     Number,       // default: Q.Safecloud.Client.defaultChunkSize
  authorizations: Array,       // OCP auth claims to send to Jets (v1: accepted but not verified)
  payments:      Array,        // OCP payment claims (v1: accepted but not verified)
  jurisdiction:  String,       // stored in manifest, null in v1
  aiAttestation: Object,       // stored in manifest, null in v1
  onProgress:    function(uploaded, total)
}

callback(err, {
  manifest: Object,          // fully public — safe to store anywhere
  rootKey:  String           // base64 — MUST be kept secret by the caller
})
```

**Steps:**
1. Generate or accept rootKey
2. Derive `encryptionRoot` and `accessRootBytes` from rootKey
3. Derive keypairs for both roots
4. Read blob → split into chunks of `chunkSize`
5. Derive `subtreeKey` for `[0, chunkCount)`
6. For each chunk (in parallel):
   - Derive `chunkKey[i]` and `chunkIV[i]` (relative index)
   - Encrypt with AAD = `"safecloud.chunk:" + i`
   - Compute CIDv1 from `ciphertext || tag`
7. Build Merkle tree over ordered CIDs → `rootCid`
8. Sign binding statement with `encryptionRoot`
9. Upload all chunks via `Q.Safecloud.Jets.chunkPut()`
10. Return manifest + rootKey

---

### `Q.Safecloud.Client.fetch(manifest, capability, options, callback)` → Promise

Downloads, Merkle-verifies, and decrypts a chunk range.

```js
manifest:   Object   // from store()
capability: {
  // Owner path:
  rootKey:  String   // base64

  // Delegated path:
  secret:   String,  // base64 subtreeKey for [start, end)
  read:     Object,  // OCP delegation proof
  start:    Number,
  end:      Number
}

options: {
  start:          Number,   // first chunk (default 0)
  end:            Number,   // last chunk exclusive (default manifest.chunkCount)
  authorizations: Array,
  payments:       Array,
  onProgress:     function(decrypted, total)
}

callback(err, Blob)
```

**Steps:**
1. Resolve `subtreeKey`:
   - Owner: `derive(encryptionRoot, "safecloud.subtree.0.N")`
   - Delegated: `capability.secret` IS the subtreeKey; verify OCP proof covers all requested chunks first
2. Fetch chunks via `Q.Safecloud.Jets.chunkGet({ rootCid, start, end })`
3. For each chunk: verify Merkle proof against `manifest.rootCid`
4. Decrypt using relative index `i = absIdx - start`:
   - `chunkKey = derive(subtreeKey, "safecloud.chunk.key.i")`
   - `chunkIV  = derive(subtreeKey, "safecloud.chunk.iv.i")`
   - AAD = `"safecloud.chunk:" + absIdx`  (absolute)
5. Reassemble decrypted chunks into a `Blob`

---

### `Q.Safecloud.Client.grant(manifest, rootKey, options, callback)` → Promise

Delegates access to a chunk range. Returns a capability that a grantee passes
to `fetch()` and to Jets as OCP authorization proofs.

```js
manifest:  Object
rootKey:   String|Uint8Array   // base64 or Uint8Array

options: {
  start:      Number,   // first chunk (default 0)
  end:        Number,   // last chunk exclusive (default manifest.chunkCount)
  readLevel:  String,   // Streams word e.g. 'content' (always granted)
  writeLevel: String,   // optional
  adminLevel: String,   // optional
  format:     'ES256'|'EIP712',  // default 'ES256'
  exp:        Number    // Unix timestamp expiry
}

callback(err, {
  secret:   String,   // base64 subtreeKey — grantee uses for decryption
  read:     Object,   // Q.Crypto.delegate proof
  write:    Object|null,
  admin:    Object|null,
  manifest: Object,
  start:    Number,
  end:      Number
})
```

**Steps:**
1. Derive `encryptionRoot` from rootKey
2. Derive `subtreeKey = derive(encryptionRoot, "safecloud.subtree.{start}.{end}")`
3. Build context: `JSON.stringify({ rootCid, start, end, [exp] })`
4. For each requested level, call `Q.Crypto.delegate({ rootSecret: subtreeKey, label, context, format })`
5. Return capability with `secret = base64(subtreeKey)` plus delegation proofs

---

### `Q.Safecloud.Client.reshare(chunks, options, callback)` → Promise

Turns this browser tab into a temporary Drop by storing received encrypted
chunks in IndexedDB and announcing them to Jets. Chunks are always encrypted —
resharing never exposes plaintext.

```js
chunks: Array<{ cid, ciphertext, iv, tag, tags }>
options: { authorizations, payments }

callback(err, { announced: Number })
```

---

## 11. Q.Safecloud.Jets API

**Browser only.** Shared socket client used by both `Cloud` (uploaders/downloaders)
and `Drops` (storage providers). All methods follow `Q.promisify` convention.

### Connection

#### `Q.Safecloud.Jets.url` — `String|null`
Override to use a specific server URL instead of `Q.nodeUrl()`.

#### `Q.Safecloud.Jets.connect(callback)` → Promise
Connects (or reuses existing connection) to the Jet server. Safe to call
multiple times. Auto-reconnects with exponential backoff + jitter (±30%,
base 500ms, max 30s) on disconnect.

```js
callback(err, Q.Socket)
```

### Drop lifecycle (called by `Q.Safecloud.Drops.init()`)

#### `Q.Safecloud.Jets.dropRegister(info, callback)` → Promise
Registers this browser tab as a Drop.

```js
info: {
  evmAddress:  String,     // Drop's EVM address (WebAuthn-PRF derived)
  delegation:  Object,     // safecloud:session-delegation OCP claim
  publicKey:   String,     // base64 P-256 session public key
  storage:     { GB: Number },
  prollyRoot:  String|null,
  bloomFilter: String|null
}
callback(err, { dropId: String, cold: Boolean, minStake: String })
```

#### `Q.Safecloud.Jets.dropAnnounce(info, callback)` → Promise
Announces updated storage stats and optionally a new Prolly root or Bloom filter.

```js
info: {
  dropId:      String,
  storage:     { GB: Number },
  used:        Number,           // bytes currently used
  prollyRoot:  String,           // hex Prolly root (optional)
  bloomFilter: String            // base64 Bloom filter bytes (optional, cold-start only)
}
callback(err)
```

#### `Q.Safecloud.Jets.dropDisconnect(callback)` → Promise
Signals intentional offline. Clears the stable `dropId` from `sessionStorage`.

```js
callback(err)
```

### Subtree routing (called by `Q.Safecloud.Client`)

#### `Q.Safecloud.Jets.put(subtree, options, callback)` → Promise
Emits `Safecloud/subtree/put`. Uploads encrypted chunks for a link path;
grant secrets are stripped before anything leaves the browser.

```js
subtree: {
  chunks: Array<{
    cid:        String,     // CIDv1
    iv:         String,     // base64
    ciphertext: String,     // base64
    tag:        String,     // base64
    size:       Number,
    tags:       Array
  }>,
  link:      Array,         // e.g. ["track","data"] or ["track","index"]
  grants:    Array,         // OCP Role A grants ({link,statement,proof,start,end})
  treeN:     Number,        // optional tree metadata
  treeDepth: Number,
  rootCid:   String
}
options: { payments: Array, publisherId: String, streamName: String,
           onProgress: fn(stored, total) }
callback(err, { results: Array<{cid, stored}|false> })
```

Rejects if no Drop stored any chunk, so callers can surface upload failure.

#### `Q.Safecloud.Jets.get(subtree, options, callback)` → Promise
Emits `Safecloud/subtree/get`. Fetches a chunk range by link path; the server
returns chunks with Merkle proofs attached. If
`Q.Safecloud.Jets.cloudEvmPrivateKey` is set, an EIP-712 Cloud→Jet payment
token is auto-signed and attached (see §14).

```js
subtree: { rootCid: String, link: Array, grants: Array, manifest: Object }
options: { payments: Array,          // pre-built tokens (override auto-sign)
           skipPayment: Boolean,     // free/public content
           publisherId: String, streamName: String,
           onProgress: fn(received, total) }
callback(err, {
  chunks: Array<{
    cid:        String,
    iv:         String,   // base64
    ciphertext: String,   // base64
    tag:        String,   // base64
    proof:      Array     // Merkle proof [{hex, side}]
  }|null>
})
```

#### `Q.Safecloud.Jets.dropClaimPayments(payload, callback)` → Promise
Relays accumulated payment tokens to the Jet for on-chain claiming
(Jet covers gas). The payload carries a Drop-side EVM signature over
`{dropId, dropEVM, nonce, tokenCount}` which the Jet verifies before relaying.

### Peer routing
Jet-to-Jet peering is server-side: hyperswarm discovery + authenticated
`safecloud.jet.hello` in `classes/Safecloud/Router.js`. There is no browser
`peerConnect` method.

### Events (Q.Event instances)

| Event | Arguments | Fired when |
|-------|-----------|------------|
| `Q.Safecloud.Jets.onConnect` | `(Q.Socket)` | Socket connects |
| `Q.Safecloud.Jets.onDisconnect` | `()` | Socket disconnects |
| `Q.Safecloud.Jets.onDropPut` | `(payload, ack)` | Jet pushes store request to this Drop |
| `Q.Safecloud.Jets.onDropGet` | `(payload, ack)` | Jet pushes retrieve request to this Drop |
| `Q.Safecloud.Jets.onDropChallenge` | `(payload, ack)` | Jet issues proof-of-storage challenge |
| `Q.Safecloud.Jets.onDropSlashed` | `(payload)` | This Drop's stake is slashed |

`Jets.js` wires `onDropPut` and `onDropGet` directly to `Q.Safecloud.Drops.put()`
and `Q.Safecloud.Drops.get()` so Drops don't need to listen to these events manually.

---

## 12. Q.Safecloud.Drops API

**Browser only.** Stores and serves encrypted chunks using IndexedDB. All
methods follow `Q.promisify` convention.

### Lifecycle

#### `Q.Safecloud.Drops.init(options, callback)` → Promise
Opens IndexedDB, replays the diff log, runs the WebAuthn-PRF delegation
ceremony when needed, and registers with the Jet. Storage cap is an option
here (there is no separate `setStorageMax`).

```js
options: { wallet: Object, storageGB: Number, jetUrl: String }
callback(err)
```

#### `Q.Safecloud.Drops.reset(callback)` → Promise
Clears all IndexedDB stores and announces a reset to the Jet. Keeps the
delegation claim and session keypairs.

### CID
CID computation is internal (`methods/Safecloud/Drops/_internal.js:cidFromData`,
SHA-256 over `ciphertext‖tag`); `put()` recomputes it and rejects chunks whose
supplied `cid` does not match.

### Storage

#### `Q.Safecloud.Drops.put(chunks, options, callback)` → Promise
Stores one or more encrypted chunks in IndexedDB. Evicts LRU chunks if storage
limit would be exceeded.

```js
chunks: Array<{
  cid:        String,     // optional — verified against recomputed CID
  iv:         String,     // base64
  ciphertext: String,     // base64
  tag:        String,     // base64
  tags:       Array       // optional content tags
}>
options: {
  authorizations: Array,  // OCP claims
  payments:       Array   // OCP claims
}
callback(err, {
  results: Array<{ cid: String, stored: Boolean, iv: String, size: Number }>
})
```

#### `Q.Safecloud.Drops.get(cids, options, callback)` → Promise
Retrieves encrypted chunks by CID. Missing chunks are `null` (order preserved).
Updates the LRU `lastAccessed` timestamp.

```js
cids:    Array<String>
options: { paymentToken: Object }   // OCP Payment envelope from the Jet
callback(err, {
  chunks: Array<{ cid, iv: String, ciphertext: String, tag: String }|null>
})
```

When a `paymentToken` is present, the Drop pre-screens the Jet's Safebux
funds on-chain (`availableToday` with `balanceOf` fallback, cached per
`Safecloud.drop.balanceCacheTtlMs`; RPC errors fail open) and returns
all-`null` when insufficient. Tokens are stored for later claiming.

#### `Q.Safecloud.Drops.claimPayments(options, callback)` → Promise
Claims accumulated tokens once total value passes
`Safecloud.drop.claimThresholdSafebux` (or `options.force`). Two paths:
`options.direct:true` submits `paymentsExecute` from the Drop's own wallet;
otherwise the tokens relay through the Jet (`dropClaimPayments`), which pays
gas. Unsigned tokens (`sig: []`) are skipped at claim time.

#### Other methods
`getProllyRoot()`, `getBloomFilter()`, `announce(reason)`, `getStats()` —
see the JSDoc in `web/js/Safecloud.js` for signatures.

---

## 13. Node.js Jet Server (`classes/Safecloud/Jets.js`)

The Jet server routes chunks between Cloud clients and Drop storage providers.
It never decrypts anything.

### Starting the server

```js
Q.require('Safecloud');
Q.Safecloud.listen(options);
// Returns: { internal: httpServer, socket: socketServer }
```

Host/port come from the standard `Q.listen()` / `Users.Socket.listen()`
config (`Q/nodeInternal`). Safecloud-specific config:
- `Q.Config.get(['Safecloud', 'drop', 'offlineGraceMs'])` (default 60000)
- `Q.Config.get(['Safecloud', 'jet', 'privateKey'])` — payment-token signing
- `Q.Config.get(['Safecloud', 'wallet', 'privateKey'])` — enables the swarm

### Drop registry

```js
Q.Safecloud.Jets.drops      // { dropId → dropRecord }
// dropRecord: {
//   dropId, socketId, socket, clientId, userId,
//   storage: { GB }, used,
//   prollyRoot: String|null,
//   offlineSince: Number|null,
//   registeredAt, reconnectedAt
// }
```

### Server methods

#### `Q.Safecloud.Jets.selectDrops(cids, options)` → Promise<Array<dropRecord>>
Selects Drops to store or serve a set of CIDs — delegates to
`Q.Safecloud.Router` (weighted: stake × reliability × available storage),
up to `options.replication` (default 2) Drops.

#### `Q.Safecloud.Jets.callDrop(drop, method, payload, timeoutMs)` → Promise
Emits an event to a Drop socket and waits for the ack. Rejects on timeout (default 10s).

#### `Q.Safecloud.Jets._reconcileDropInventory(drop, dropReportedRoot)`
After reconnect, diffs the Jet's stored Prolly root against the Drop's reported
root. If equal: no-op. If different: calls `Q.Data.Prolly.diff()` to find the
delta and emits `'dropSync'`. On first contact (no jet-side root): emits
`'dropColdSync'`.

### Server events (Q.EventEmitter)

| Event | Arguments | Fired when |
|-------|-----------|------------|
| `'dropRegister'` | `(drop)` | New Drop registers for first time |
| `'dropReconnect'` | `(drop)` | Existing Drop reconnects |
| `'dropOffline'` | `(drop)` | Drop socket disconnects unexpectedly |
| `'dropDisconnect'` | `(drop)` | Drop intentionally disconnects or evicted |
| `'dropAnnounce'` | `(drop)` | Drop announces updated stats |
| `'dropBloom'` | `(drop, bloomFilterBase64)` | Drop sends Bloom filter (cold start) |
| `'dropSync'` | `(drop, changes)` | Prolly diff completed after reconnect |
| `'dropColdSync'` | `(drop, prollyRoot)` | First contact with this Drop (no prior state) |
| `'dropSlash'` | `(drop, payload)` | PHP signals a verified Proof of Corruption |

### Socket events handled

All socket events under the `/Safecloud/cloud` namespace:

| Event (client → server) | Handler |
|--------------------------|---------|
| `Safecloud/drop/register` | Register or reconnect Drop |
| `Safecloud/drop/announce` | Update stats, Prolly root, Bloom filter |
| `Safecloud/drop/disconnect` | Remove Drop from registry |
| `Safecloud/drop/claimPayments` | Relay Drop payment tokens on-chain (Jet pays gas) |
| `Safecloud/subtree/put` | Route encrypted chunks to Drops by link path |
| `Safecloud/subtree/get` | Fetch chunks from Drops, attach Merkle proofs |
| `Safecloud/chunk/challenge` | Forward proof-of-storage challenge to a Drop |

| Event (PHP → server, internal) | Handler |
|--------------------------------|---------|
| `Safecloud/drop/slash` | Signal stake slashing for a Drop |

---

## 14. OpenClaiming (OCP) in Safecloud

**OCP is the authorisation and payment layer that governs who may store and
retrieve chunks.** All chunk routing goes through Jets, so OCP verification
lives primarily in the Jet server.

### What OCP is

An OpenClaim is a JSON envelope:
```js
{
  ocp: 1,
  iss: "example.com",    // issuer
  sub: "alice",          // subject
  stm: { ... },          // statement payload
  nbf: 1700000000,       // not-before Unix timestamp
  exp: 1800000000,       // expiry Unix timestamp
  key: ["data:key/es256;base64,..."],    // array of signer public key URIs
  sig: ["<base64 raw r||s 64 bytes>"]   // corresponding signatures
}
```

All signing uses **raw r||s 64 bytes** (IEEE P1363), NOT DER. Canonical JSON
(RFC 8785) with `sig` stripped is what is actually signed.

### OCP in Safecloud — three roles

**1. Access authorization (`Q.Crypto.OpenClaim.sign/verify` — ES256)**

When `Cloud.grant()` calls `Q.Crypto.delegate()`, it produces an OCP-like proof.
The `capability.read`, `capability.write`, `capability.admin` objects from
`grant()` are delegation proofs that the grantee includes in `options.authorizations`
when calling `Cloud.fetch()` and `Cloud.store()`, which pass them to Jets.

Jets will (in v0.5) call `Q.Crypto.OpenClaim.verify(claim)` to check:
- The proof is validly signed
- The `context` field encodes a `rootCid`, `start`, `end` that covers the
  requested chunks
- `exp` has not passed

**2. Payment (`Q.Crypto.OpenClaim.EVM.sign/verify` — EIP-712 secp256k1)**

Payment claims are EIP-712 typed-data signed by an Ethereum wallet. They
authorise a metered payment from a payer address to storage-provider addresses
for up to `max` tokens on a given `line` (like a trustline — monotonically
incrementing, so each request just presents a higher `max`).

The canonical `verifyingContract` is `0x9999...9999` on the configured chain.

```js
// Payment claim shape:
{
  ocp:        1,
  payer:      "0x...",      // who pays
  token:      "0x...",      // ERC-20 token address
  recipients: ["0x..."],    // Drop operators to pay
  max:        1000,         // max tokens authorised
  line:       1,            // trustline ID (monotonic nonce)
  nbf:        0,
  exp:        9999999999,
  chainId:    1,
  contract:   "0x9999...9999",
  key:        ["data:key/eip712,0x..."],
  sig:        ["<base64 65-byte r||s||v>"]
}
```

Verification: `Q.Crypto.OpenClaim.EVM.verify(claim, sig, expectedAddress)`

**3. Proof of Storage challenge/response**

Jets issue random challenges: "prove you still have CID X by signing
`(cid, nonce)` with your Drop key." The Drop's OCP key (ES256, derived from
a Drop-specific secret) signs the response. In v0.5 this will replace the
current placeholder `iv` in the challenge ack.

### Key URI formats

| URI format | Meaning |
|------------|---------|
| `data:key/es256;base64,<SPKI-DER-base64>` | P-256 public key (inline) |
| `data:key/eip712,<0x-address>` | Ethereum address (secp256k1 — recover via ecrecover) |
| `https://example.com/...#path` | URL-hosted key document (fetched + cached 60s) |

### `Q.Crypto.OpenClaim.sign(claim, secret, existing)` → Promise<claim>
Signs a claim with ES256. Derives keypair from `secret`, appends the SPKI key
URI to `key[]` and the raw r||s signature to `sig[]`. Multisig-safe (pass
`existing = { keys, signatures }` to add alongside existing signers).

### `Q.Crypto.OpenClaim.verify(claim, policy)` → Promise<Boolean>
Verifies ES256 and/or EIP712 signatures. Policy: `null` = any 1 valid,
`N` = at least N valid, `{mode:'all'}` = all keys must sign.

### `Q.Crypto.OpenClaim.EVM.hashTypedData(claim)` → Promise<{ digest, payload }>
Builds the EIP-712 typed-data digest for a Payment or Authorization claim.
Auto-detects claim type by field presence.

### `Q.Crypto.OpenClaim.EVM.sign(claim, secret, existing)` → Promise<claim>
Signs an EVM (Payment or Authorization) claim from a secret. Delegates to
`Q.Crypto.sign({ format: 'EIP712', ... })`.

### `Q.Crypto.OpenClaim.EVM.verify(claim, signature, expectedAddress, recovered)` → Promise<Boolean>
Verifies an EVM claim signature. Delegates to `Q.Crypto.verify({ format: 'EIP712', ... })`.

---

## 15. Where OCP wiring is TODOs in current code

The following stubs exist and need to be filled for v0.5:

| File | Location | What to wire |
|------|----------|-------------|
| `node/Safecloud/.js` | `Safecloud/chunk/put` handler | `Q.Crypto.OpenClaim.verify(options.authorizations[i])` |
| `node/Safecloud/.js` | `Safecloud/chunk/get` handler | same |
| `node/Safecloud/.js` | `Safecloud/chunk/challenge` ack | Sign `(cid, nonce)` with Drop's OCP ES256 key |
| `Drops.js` | `checkAuthorization()` | `Q.Crypto.OpenClaim.verify(claims)` |
| `Drops.js` | `checkPayment()` | `Q.Crypto.OpenClaim.EVM.verify(claims)` — monotonic line check |

---

## 16. File Locations

```
plugins/Safecloud/
├── node/
│   └── Safe.js                                    ← Jet server (Node.js)
└── web/js/
    ├── Safecloud/
    │   ├── Cloud.js                               ← Q.Method.define wiring for Cloud
    │   ├── Jets.js                                ← Shared socket.io client (Cloud + Drops)
    │   ├── Drops.js                               ← Browser Drop node (IndexedDB)
    │   └── DataTrees.js                           ← Lazy-loads Merkle/Prolly/Bloom on Q.Data
    └── methods/Q/Safecloud/Cloud/
        ├── _internal.js                           ← Key derivation, CID, chunking helpers
        ├── store.js                               ← Encrypt + upload pipeline
        ├── fetch.js                               ← Download + Merkle-verify + decrypt
        ├── grant.js                               ← Capability delegation
        └── reshare.js                             ← Re-announce held chunks to Jets

plugins/Q/web/js/
├── methods/Q/
│   ├── Data/
│   │   ├── derive.js, digest.js, hkdf.js
│   │   ├── encrypt.js, decrypt.js
│   │   ├── importKey.js, generateKey.js
│   │   ├── canonicalize.js, compress.js, decompress.js
│   │   ├── sign.js, verify.js
│   │   ├── Merkle/ (build, verify, proof, _internal)
│   │   ├── Prolly/ (build, get, set, delete, diff, _internal)
│   │   └── Bloom/  (create, fromElements, fromBytes, fromBase64, _internal)
│   └── Crypto/
│       ├── internalKeypair.js, sign.js, verify.js
│       ├── delegate.js, verifyDelegated.js
│       └── OpenClaim/
│           ├── canonicalize.js, sign.js, verify.js, resolve.js
│           └── EVM/
│               ├── hashTypedData.js, sign.js, verify.js
└── crypto/
    ├── eip712.js        ← standalone EIP-712 encoder (also used by PHP)
    ├── secp256k1.js     ← noble-curves secp256k1
    ├── nist.js          ← noble-curves P-256
    ├── sha3.js          ← keccak_256
    └── encoder.js       ← DER/ASN.1 helpers

classes/Q/
├── Crypto/
│   ├── EIP712.php
│   └── OpenClaim/ (EVM.php)
└── OpenClaim.php, OpenClaim_EVM.php
```

---

## 17. Pending Items (TODOs)

1. **OCP authorization verification in Jets** — `Safecloud/chunk/put` and `Safecloud/chunk/get` handlers
2. **OCP payment verification in Jets** — same handlers, `options.payments`
3. **Drop proof-of-storage challenge signing** — replace placeholder in `Jets.onDropChallenge`
4. **Range request CID routing index** — Jets need a `rootCid → [cid...]` index for range gets
5. **Prolly-backed routing** — use Prolly tree coverage to weight Drop selection
6. **Erasure coding** — currently replication only
7. **Jet-to-Jet peering** — `Safecloud/peer/connect` stub
8. **`Q.Data.Merkle`/`Prolly`/`Bloom` swap in `store.js`/`fetch.js`/`Drops.js`** — current code uses some inline helpers; replace with canonical `Q.Data.*` method calls (see client.zip analysis)
9. **`Drops.buildProllyTree()`** — replace manual implementation with `Q.Data.Prolly.build(entries, idbStore)`
10. **`Drops.buildBloomFilter()`** — replace with `Q.Data.Bloom.fromElements(cids)`

---

## 18. Q Framework Primitives Used in Safecloud

This section documents the Q platform classes that Safecloud builds on top of,
with notes on exactly where and how each is used. These classes are part of the
Q.js plugin framework shared across all Qbix/Intercoin apps.

---

### 18.1 `Q.Promise` — the promise type

`Q.Promise` is Q's canonical Promise wrapper. It is interchangeable with native
`Promise` and `thenable`. All Safecloud async operations return a `Q.Promise`.

The framework also exposes:
- `Q.resolve(value)` — wraps a value in a resolved promise
- `Q.reject(error)` — wraps an error in a rejected promise
- `Q.Promise.all([...])` — equivalent to `Promise.all`

In Safecloud, `Q.Promise` is the return type of every method in `Q.Safecloud.Client`,
`Q.Safecloud.Jets`, and `Q.Safecloud.Drops`. All crypto primitives (`Q.Data.*`,
`Q.Crypto.*`) also return `Q.Promise`.

---

### 18.2 `Q.promisify(fn, [returnThis], [argCount])` — callback↔Promise bridge

`Q.promisify` wraps a callback-style function so it can be called either as
a callback-accepting function or as a Promise-returning function. This is
how every public method in `Q.Safecloud.Client`, `Q.Safecloud.Jets`, and `Q.Safecloud.Drops`
is defined.

```js
// Declaration pattern:
Q.Safecloud.Client.store = Q.promisify(function (file, options, callback) {
    // ... do async work ...
    callback(null, result);   // or callback(err)
}, false, 2);   // false = don't return `this`; 2 = number of required non-callback args

// Call as callback:
Q.Safecloud.Client.store(file, options, function (err, result) { ... });

// Call as Promise:
Q.Safecloud.Client.store(file, options).then(function (result) { ... });

// Call with no options (promisify handles optional trailing args):
Q.Safecloud.Client.store(file).then(...);
```

The `argCount` parameter tells `Q.promisify` how many non-callback arguments
the function expects, so it can correctly detect whether the caller passed a
callback. For example `store` has `argCount=2` because it expects `(file, options)`.

---

### 18.3 `Q.exports(fn)` — method file declaration

Every `Q.Data.*`, `Q.Crypto.*`, and `Q.Safecloud.Client.*` file is wrapped in
`Q.exports(function(Q, _) { ... })`. This is the Q framework's mechanism
for declaring method files that are loaded on demand.

- `Q` — the global Q namespace, available in every method file
- `_` — a shared internal helpers object loaded via `options.require`, passed
  to all method files in the same sub-namespace (e.g. all `Q.Data.Merkle.*`
  files share the same `_internal.js` helper object `_`)

In Safecloud:
- `Q/Safecloud/Cloud/_internal.js` exports the `_` object used by `store.js`,
  `fetch.js`, `grant.js`, and `reshare.js`
- `Q/Data/Merkle/_internal.js` exports shared Merkle helpers
- `Q/Data/Prolly/_internal.js` exports shared Prolly helpers
- `Q/Data/Bloom/_internal.js` exports the `BloomFilter` class and helpers

---

### 18.4 `Q.extend(target, ...sources)` — shallow object merge

`Q.extend` is Q's equivalent of `Object.assign`. It merges properties from
source objects into target, returning the target. Used throughout Safecloud:

```js
// In store.js — merging context into delegation options:
var context = JSON.stringify(Q.extend(
    { rootCid: manifest.rootCid, start: start, end: end },
    options.exp ? { exp: options.exp } : {}
));

// In node/Safecloud/.js — building a Drop record:
var drop = Q.extend({
    dropId:    dropId,
    socketId:  client.id,
    ...
}, info);
```

---

### 18.5 `Q.Event` — typed, named event system

`Q.Event` is Q's lightweight observable / event system. It differs from
Node.js `EventEmitter` in that each event is a **first-class object** with
its own `.set()` / `.handle()` / `.remove()` methods, and handlers can be
named for later removal.

```js
// Create:
var myEvent = new Q.Event();

// Register a named handler:
myEvent.set(function (payload, ack) {
    // handle the event
}, 'myHandler');

// Fire the event:
myEvent.handle(payload, ack);

// Remove a specific handler by name:
myEvent.remove('myHandler');
```

**Where used in Safecloud:**

`Q.Safecloud.Jets` exposes six `Q.Event` instances:

| Property | Fires when |
|----------|-----------|
| `Q.Safecloud.Jets.onConnect` | Socket connects to Jet server |
| `Q.Safecloud.Jets.onDisconnect` | Socket disconnects |
| `Q.Safecloud.Jets.onDropPut` | Jet pushes a store request to this Drop |
| `Q.Safecloud.Jets.onDropGet` | Jet pushes a retrieve request to this Drop |
| `Q.Safecloud.Jets.onDropChallenge` | Jet issues a proof-of-storage challenge |
| `Q.Safecloud.Jets.onDropSlashed` | This Drop's stake is slashed by the network |

`Jets.js` wires `onDropPut` and `onDropGet` directly to `Q.Safecloud.Drops` by
registering named handlers on them:

```js
Q.Safecloud.Jets.onDropPut.set(function (payload, ack) {
    Q.Safecloud.Drops.put(chunks, payload.options, function (err, result) {
        ack && ack(err ? { error: err.message } : null, result);
    });
}, 'Q.Safecloud.Jets.onDropPut');
```

This means application code can add its own handlers to these events without
removing the built-in wiring:

```js
// Application-level monitoring:
Q.Safecloud.Jets.onDropSlashed.set(function (payload) {
    console.warn('Drop slashed, reason:', payload.reason);
}, 'myApp.slashMonitor');
```

**Node.js: `Q.makeEventEmitter(Safe)`**

On the server side, `node/Safecloud/.js` calls `Q.makeEventEmitter(Safe)` to give
the `Safe` object standard `emit` / `on` / `once` / `off` methods. This is
Q's thin wrapper over Node's `EventEmitter`.

```js
// Listening to Jet-level events in application code:
Safe.on('dropRegister', function (drop) {
    console.log('New Drop:', drop.dropId, drop.storage.GB + ' GB');
});

Safe.on('dropSync', function (drop, changes) {
    // changes: Array<{ key: cid, before: value|null, after: value|null }>
    // Re-route chunks that disappeared from the Drop's Prolly tree
    var disappeared = changes.filter(function (c) { return c.after === null; });
    disappeared.forEach(function (c) { replicateChunk(c.key); });
});
```

---

### 18.6 `Q.Socket` — socket.io wrapper

`Q.Socket` wraps a socket.io client connection with Q conventions. It is
the transport layer for all browser↔Jet communication.

```js
// Connect to a namespace on a server:
Q.Socket.connect(namespace, url, function (err, qs) {
    // qs.socket — the raw socket.io socket
    // qs.socket.emit(event, payload, ackCallback)
    // qs.socket.on(event, handler)
});
```

**Where used in Safecloud:**

`Jets.js` calls `Q.Socket.connect('/Safecloud/', url, ...)` to open the `/Safecloud/`
namespace. All subsequent socket events (`Safecloud/chunk/put`, `Safecloud/drop/register`,
etc.) are emitted and received on `qs.socket`.

Key design decisions:
- **One shared socket** — both `Q.Safecloud.Client` (uploader/downloader) and
  `Q.Safecloud.Drops` (storage provider) share the same `/Safecloud/` namespace connection
  managed by `Q.Safecloud.Jets`. There is no separate socket for each role.
- **Queue before connect** — `_withSocket(fn)` buffers calls made before the
  socket is ready, then drains the queue on connect.
- **Drop identity is stable** — `_dropId()` is derived from `Q.clientId()` and
  stored in `sessionStorage`, so a reconnecting tab presents the same `dropId`
  and the Jet server restores its record rather than creating a new Drop.

`Q.Socket.reconnect(ns, url, options)` is a static helper added by `Jets.js`
for general-purpose reconnect-with-backoff logic. It is not specific to Safe.

---

### 18.7 `Q.Data` — cryptographic and data primitives (complete reference)

All methods return `Q.Promise` and also accept an optional callback as the last
argument. Browser implementations use SubtleCrypto. Node.js uses `crypto` built-in.

#### Encoding / decoding helpers (synchronous)

```js
Q.Data.toBase64(bytes)         → String         // Uint8Array → base64
Q.Data.fromBase64(str)         → Uint8Array      // base64 → Uint8Array
Q.Data.toHex(bytes)            → String          // Uint8Array → lowercase hex
Q.Data.fromHex(str)            → Uint8Array      // hex → Uint8Array
Q.Data.toUint8Array(v)         → Uint8Array      // coerce ArrayBuffer/etc → Uint8Array
```

#### Hash / KDF

```js
Q.Data.digest(algorithm, payload)
// algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512'
// payload: Uint8Array | ArrayBuffer | String (strings are UTF-8 encoded)
// → Promise<Uint8Array>

Q.Data.hkdf(ikm, salt, info, length)
// ikm:    Uint8Array   input key material
// salt:   Uint8Array
// info:   String       context label
// length: Number       output bytes (default 32)
// → Promise<Uint8Array>

Q.Data.derive(seed, label, options)
// seed:            Uint8Array | ArrayBuffer  (MUST be binary — not a string)
// label:           String                   (HKDF info / domain label — must be unique)
// options.size:    Number                   (output bytes, default 32)
// options.context: String                   (salt = SHA-256(context), default "")
// → Promise<Uint8Array>
```

#### Symmetric encryption (AES-256-GCM)

```js
Q.Data.importKey(keyBytes, algo)
// keyBytes: Uint8Array (32 bytes for AES-256)
// algo:     { name, length, usages } (default: AES-GCM 256 encrypt/decrypt)
// → Promise<CryptoKey>

Q.Data.generateKey(algo)
// algo: { name, namedCurve, hash } (default: ECDSA P-256 SHA-256)
// → Promise<{ publicKey: base64, privateKey: base64, algorithm }>

Q.Data.encrypt(key, plaintext, options)
// key:               CryptoKey (AES-GCM)
// plaintext:         Uint8Array
// options.iv:        Uint8Array | base64 String  — REQUIRED for convergent encryption
// options.additional: Uint8Array                 — AAD (authenticated but not encrypted)
// → Promise<{ iv: base64, ciphertext: base64, tag: base64 }>

Q.Data.decrypt(key, ivBase64, ciphertextBase64, options)
// key:               CryptoKey (AES-GCM)
// ivBase64:          base64 String (12 bytes)
// ciphertextBase64:  base64 String (ciphertext WITHOUT tag)
// options.tag:       base64 String (16-byte GCM auth tag — appended before decryption)
// options.additional: Uint8Array   — must match AAD used at encrypt time
// → Promise<Uint8Array>
```

#### Signing (ECDSA, general — not OCP-specific)

```js
Q.Data.sign(data, privateKeyPKCS8Strings, algo)
// data:                     String (UTF-8 encoded before signing)
// privateKeyPKCS8Strings:   Array<base64 PKCS8>
// algo:                     { name, namedCurve, hash } (default ECDSA P-256 SHA-256)
// → Promise<Array<ArrayBuffer>>   (one per key — convert with Q.Data.toBase64)

Q.Data.verify(data, publicKeyRawStrings, signatures, algo)
// data:                  String
// publicKeyRawStrings:   Array<base64 raw public key>
// signatures:            Array<ArrayBuffer | base64 String>
// → Promise<Array<Boolean>>   (one per key)
```

#### Canonicalisation

```js
Q.Data.canonicalize(object)
// RFC 8785 / JCS — keys sorted recursively, stable number serialisation
// NaN and Infinity throw
// → String (synchronous)
```

#### Compression

```js
Q.Data.compress(data, callback, options)
// data:             String | Object (Objects are JSON-stringified)
// options.algorithm: 'gzip' | 'deflate' (default: 'gzip')
// → Promise<ArrayBuffer>

Q.Data.decompress(buffer, callback, options)
// buffer: ArrayBuffer
// → Promise<String>
```

#### Merkle tree

```js
Q.Data.Merkle.build(leaves, callback)
// leaves: Array<Uint8Array | String>  — strings UTF-8 encoded
// → Promise<String>    hex root

Q.Data.Merkle.proof(leaves, index, callback)
// → Promise<{ proof: Array<{hex:String, side:'left'|'right'}>, rootHex: String }>

Q.Data.Merkle.verify(leaf, proof, rootHex, callback)
// leaf:    Uint8Array | String
// proof:   Array<{hex, side}>
// → Promise<Boolean>
```

Domain separation: leaves = `SHA-256(0x00 || bytes)`, internal = `SHA-256(0x01 || left || right)`.

#### Prolly tree

```js
Q.Data.Prolly.build(entries, store, callback)
// entries: Array<{ key: String, value: String }>  — sorted by key internally
// store:   { get(hash)→Promise, put(hash,node)→Promise } | null (defaults to in-memory)
// → Promise<String>   hex root hash

Q.Data.Prolly.get(rootHash, key, store, callback)
// → Promise<String | null>

Q.Data.Prolly.set(rootHash, key, value, store, callback)
// → Promise<String>   new root hash

Q.Data.Prolly.delete(rootHash, key, store, callback)
// → Promise<String | null>   new root hash (null = empty tree)

Q.Data.Prolly.diff(rootHashA, rootHashB, store, callback)
// → Promise<Array<{ key: String, before: String|null, after: String|null }>>
```

Boundary detection: a key is a chunk boundary when `SHA-256(key)[0] < 16`
(branching factor 16, ~16 keys per leaf node). Node identity = `SHA-256(JSON(node))`.

#### Bloom filter

```js
Q.Data.Bloom.create(n, p, callback)
// n: expected elements, p: false positive rate (default 0.01)
// → Promise<BloomFilter>

Q.Data.Bloom.fromElements(elements, p, callback)
// elements: Array<String>  (all SHA-256 calls run in parallel)
// → Promise<BloomFilter>

Q.Data.Bloom.fromBytes(uint8array, callback)
// → Promise<BloomFilter>

Q.Data.Bloom.fromBase64(base64, callback)
// → Promise<BloomFilter>

// BloomFilter instance:
filter.add(element)                   → Promise        (mutates filter)
filter.has(element)                   → Promise<Boolean>
filter.hasMany(elements)              → Promise<Array<Boolean>>
filter.merge(otherFilter)             → Promise        (in-place OR of bit arrays)
filter.falsePositiveRate()            → Number
filter.elementCount()                 → Number
filter.toBytes()                      → Uint8Array
filter.toBase64()                     → String
```

Hashing: Kirsch-Mitzenmacher double hashing — two SHA-256 calls (prefixed `0x00` and
`0x01`) → k positions via `h_i(x) = (h1 + i·h2) mod m`.

---

### 18.8 `Q.Crypto` — typed signing and delegation (complete reference)

All methods return `Q.Promise`. All secrets must be `Uint8Array`.

```js
Q.Crypto.internalKeypair(options)
// options.secret: Uint8Array
// options.format: 'ES256' | 'EIP712'
// → Promise<{ format, curve, hashAlg, privateKey, publicKey, [address] }>
//   ES256:  privateKey = HKDF-SHA256(secret, "q.crypto.p256.private-key", 32)
//   EIP712: privateKey = keccak256("q.crypto.k256.private-key" || secret) mod n

Q.Crypto.sign(options)
// options.secret:      Uint8Array
// options.format:      'ES256' | 'EIP712'
// options.message:     Object
// options.types:       Object     (EIP-712 type defs, also used for ES256 payload)
// options.primaryType: String
// options.domain:      Object     (optional)
// → Promise<{ format, curve, hashAlg, domain, primaryType, digest, signature,
//             signatureHex, publicKey, [address] }>
// ES256:  signature = DER-encoded ECDSA over SHA-256(canonical JSON)
// EIP712: signature = 65-byte r||s||v over EIP-712 struct hash

Q.Crypto.verify(options)
// options.format:      'ES256' | 'EIP712'
// options.domain, types, primaryType, message: same as sign
// options.signature:   Uint8Array | String
// options.publicKey:   Uint8Array     (ES256 required)
// options.address:     String         (EIP712 — expected "0x..." address)
// options.recovered:   Object         (optional — .address written here on EIP712)
// → Promise<Boolean>

Q.Crypto.delegate(options)
// options.rootSecret: Uint8Array
// options.label:      String     (e.g. "safecloud.read.content")
// options.context:    String     (JSON-encoded scope, stored in statement)
// options.format:     'ES256' | 'EIP712'
// → Promise<{ label, context, secret: Uint8Array, statement: Object, proof: Object }>
//   Derives childSecret = Q.Data.derive(rootSecret, "q.crypto.delegate." + label)
//   Signs { parent, label, issuedTime, context, secretHash } with rootSecret

Q.Crypto.verifyDelegated(options)
// options.format:          'ES256' | 'EIP712'
// options.statement:       Object
// options.signature:       Uint8Array | String
// options.derivedSecret:   Uint8Array
// options.parentPublicKey: Uint8Array  (ES256)
// options.domain:          Object      (EIP712)
// options.recovered:       Object      (optional)
// → Promise<Boolean>
// Checks: secretHash matches, signature is valid, signer = declared parent
```

---

### 18.9 `Q.Crypto.OpenClaim` — OCP claim signing and verification

OpenClaim (OCP) is the **claim envelope format** used for authorisation and
payment in Safecloud. It is distinct from `Q.Crypto.sign` — the signing payload
is the whole claim (with `sig` stripped), not a typed-data wrapper.

**Critical difference from `Q.Crypto.sign`:**

| | `Q.Crypto.sign` | `Q.Crypto.OpenClaim.sign` |
|---|---|---|
| Payload | `{domain, primaryType, types, message}` | The claim object itself (sig stripped) |
| Signature format | **DER** (ES256) or r\|\|s\|\|v (EIP712) | **Raw r\|\|s 64 bytes** (IEEE P1363) |
| Used for | `delegate()` capability proofs | OCP claim envelopes sent to Jets/Drops |

Never mix these two signing paths.

```js
Q.Crypto.OpenClaim.canonicalize(claim)
// Strips sig field, applies Q.Data.canonicalize (RFC 8785)
// → Promise<String>   canonical JSON

Q.Crypto.OpenClaim.sign(claim, secret, existing)
// claim:    Object         OCP claim payload
// secret:   Uint8Array     signing secret
// existing: { keys, signatures }  for adding to an existing multisig claim
// Derives ES256 keypair, appends "data:key/es256;base64,<SPKI>" to key[]
// Signs SHA-256(canonical) with noble p256 → raw r||s (not DER)
// → Promise<Object>   claim with key[] and sig[] populated

Q.Crypto.OpenClaim.verify(claim, policy)
// claim:   OCP claim with key[] and sig[]
// policy:  null = at least 1 valid | Number N = at least N | { mode:'all' } = all keys
//          | { minValid: N }
// ES256 keys verified via SubtleCrypto with raw r||s (IEEE P1363)
// EIP712 keys delegate to Q.Crypto.OpenClaim.EVM.verify
// → Promise<Boolean>

Q.Crypto.OpenClaim.resolve(keyStr)
// Resolves a key URI to a parsed key object, cached 60s
// 'data:key/es256;base64,...' → { fmt: 'ES256', value: Uint8Array (SPKI DER) }
// 'data:key/eip712,0x...'    → { fmt: 'EIP712', value: '0x...' }
// 'https://...'              → fetch + follow fragment path → { fmt, value }
// → Promise<{ fmt, value } | Array | null>
```

---

### 18.10 `Q.Crypto.OpenClaim.EVM` — EIP-712 payment and authorisation claims

Used for payment flows where the payer is an Ethereum wallet. The verifying
contract is Intercoin's payment gateway on the configured chain.

```js
Q.Crypto.OpenClaim.EVM.hashTypedData(claim)
// Auto-detects Payment (has payer+token+line) vs Authorization (has authority+subject)
// → Promise<{ digest: Uint8Array(32), payload: { domain, primaryType, types, value } }>

Q.Crypto.OpenClaim.EVM.sign(claim, secret, existing)
// Builds typed payload, calls Q.Crypto.sign({format:'EIP712',...})
// Stores derived Ethereum address as "data:key/eip712,<address>" in key[]
// Signature = 65-byte r||s||v
// → Promise<Object>   claim with key[] and sig[] populated

Q.Crypto.OpenClaim.EVM.verify(claim, signature, expectedAddress, recovered)
// signature: Uint8Array | hex String | base64 String  (65-byte r||s||v)
// expectedAddress: "0x..." | undefined
// recovered: optional Object — recovered.address written here
// → Promise<Boolean>
```

**Payment claim fields:**

```js
{
  ocp:        1,
  payer:      "0x...",           // who pays (recovered from EIP-712 sig)
  token:      "0x...",           // ERC-20 token address (or zero address for native)
  recipients: ["0x...", ...],    // Drop operator addresses to pay
  max:        BigInt | Number,   // max tokens authorised on this line
  line:       BigInt | Number,   // monotonic trustline ID — ever-increasing nonce
  nbf:        Number,            // not-before Unix timestamp
  exp:        Number,            // expiry Unix timestamp
  chainId:    Number,
  contract:   "0x...",           // verifyingContract on-chain
  key:        ["data:key/eip712,0x..."],
  sig:        ["<base64 65-byte r||s||v>"]
}
```

**Authorization claim fields:**

```js
{
  ocp:         1,
  authority:   "0x...",          // who grants the permission
  subject:     "0x...",          // who receives it
  actors:      ["0x...", ...],   // optional actor whitelist
  roles:       ["admin", ...],
  actions:     ["read", ...],
  constraints: [{ key, op, value }, ...],
  contexts:    [{ type, value }, ...],
  nbf:         Number,
  exp:         Number,
  chainId:     Number,
  contract:    "0x...",
  key:         ["data:key/eip712,0x..."],
  sig:         ["<base64 65-byte r||s||v>"]
}
```

---

## 19. Payment Verification Flow (Jets and Drops)

A Jet or Drop receiving a request with payment claims should:

1. **Verify the OCP claim signature** — `Q.Crypto.OpenClaim.EVM.verify(claim, sig, payer)`
2. **Check expiry** — `claim.exp > Date.now() / 1000`
3. **Check the trustline is monotonically increasing** — the `(payer, line)` pair
   must have a `max` greater than the last seen value. Use a local cache.
4. **Check on-chain balance** — query the ERC-20 contract to confirm the payer
   has sufficient balance and allowance on the `contract` address.
5. **Accept the work** and update the cached `(payer, line) → max` value.

### Trustline cache (Jets / Node.js)

```js
// In-memory cache: Map<"payer:line", maxSeen>
var _lineCache = {};

function verifyPayment(claim, callback) {
    Q.Crypto.OpenClaim.EVM.verify(claim, claim.sig[0], claim.payer)
    .then(function (valid) {
        if (!valid) throw new Error('Invalid payment signature');

        var now = Math.floor(Date.now() / 1000);
        if (claim.exp && claim.exp < now) throw new Error('Payment claim expired');
        if (claim.nbf && claim.nbf > now) throw new Error('Payment claim not yet valid');

        var lineKey = claim.payer + ':' + claim.line;
        var prevMax = _lineCache[lineKey] || 0;
        if (Number(claim.max) <= prevMax) throw new Error('Stale payment claim (max not increasing)');

        // Check on-chain balance before accepting
        return checkOnChainBalance(claim);
    })
    .then(function (sufficient) {
        if (!sufficient) throw new Error('Insufficient on-chain balance');
        _lineCache[claim.payer + ':' + claim.line] = Number(claim.max);
        callback(null, true);
    })
    .catch(callback);
}
```

### On-chain balance check

The Jet (Node.js) or a PHP gateway can verify the payer's balance and allowance:

```js
// Minimal ethers-free balance check via JSON-RPC:
function checkOnChainBalance(claim) {
    // ERC-20 balanceOf(address) selector = 0x70a08231
    var data = '0x70a08231' + claim.payer.replace(/^0x/i, '').padStart(64, '0');
    return fetch(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0', id: 1,
            method: 'eth_call',
            params: [{ to: claim.token, data: data }, 'latest']
        })
    })
    .then(function (r) { return r.json(); })
    .then(function (json) {
        var balance = BigInt(json.result || '0x0');
        return balance >= BigInt(claim.max);
    });
}
```

### Authorisation verification flow (Jets)

For OCP ES256 access-authorization claims (the delegation proofs from
`Cloud.grant()`):

```js
function verifyAuthorization(capability, requestedChunks) {
    // capability.read is the delegation proof from Cloud.grant()
    var proof = capability.read;
    if (!proof || !proof.statement) return Promise.resolve(false);

    // 1. Check the context encodes a range covering all requested chunks
    var ctx;
    try { ctx = JSON.parse(proof.statement.context); } catch (e) { return Promise.resolve(false); }
    if (ctx.rootCid !== manifest.rootCid) return Promise.resolve(false);
    for (var i = 0; i < requestedChunks.length; i++) {
        if (requestedChunks[i] < ctx.start || requestedChunks[i] >= ctx.end) {
            return Promise.resolve(false);
        }
    }

    // 2. Check expiry
    var now = Math.floor(Date.now() / 1000);
    if (ctx.exp && ctx.exp < now) return Promise.resolve(false);

    // 3. Verify the delegation signature
    // proof.publicKey is the parent's ES256 public key
    return Q.Crypto.verifyDelegated({
        format:          'ES256',
        statement:       proof.statement,
        signature:       proof.signature,
        derivedSecret:   Q.Data.fromBase64(capability.secret),
        parentPublicKey: Q.Data.fromBase64(proof.publicKey)
    });
}
```

### Where payment verification actually runs (1.0.0-beta.1)

- **Jet (server), Cloud→Jet tokens** — `_checkPayments` in
  `classes/Safecloud/Jets.js`: Safebux-only token/chain allow-list, `nbf/exp`
  window, `recipientsHash` must include this Jet, EIP-712 signature recovery
  (`Q.Crypto.OpenClaim.EVM.verify` when available, else
  `ethers.verifyTypedData`), then `lineAvailable` on OpenClaiming as the
  definitive pre-flight. Unsigned tokens pass only when
  `Safecloud.requirePayment` is `false`.
- **Drop (browser), Jet→Drop tokens** — `Drops.get()` pre-screens the Jet's
  funds on-chain before serving; `Drops.claimPayments()` skips unsigned
  tokens at claim time. Monotonic per-`(payer,line)` accounting is enforced
  on-chain by OpenClaiming itself at `paymentsExecute`.
- **Jet mesh** — `safecloud.jet.hello` delegations are EIP-712-verified and
  bound to the sender's Noise static key (`classes/Safecloud/Router.js`);
  unverified CoC gossip is recorded but never changes routing state.
```

### Caching strategy

Both Jets and Drops should cache verified claims for their `exp` duration to
avoid re-running signature verification on every chunk request:

```js
// Cache key: canonical JSON of the claim (without sig)
// Cache value: { valid: Boolean, exp: Number (Unix timestamp) }
var _claimCache = {};

function verifyWithCache(claim) {
    var key = Q.Data.canonicalize(Object.assign({}, claim, { sig: undefined }));
    var cached = _claimCache[key];
    var now = Math.floor(Date.now() / 1000);
    if (cached && cached.exp > now) return Q.Promise.resolve(cached.valid);

    return Q.Crypto.OpenClaim.verify(claim).then(function (valid) {
        _claimCache[key] = { valid: valid, exp: claim.exp || (now + 3600) };
        return valid;
    });
}
```

## 20. Embedding the player (`embed.html`)

`web/embed.html` is an iframe-embeddable player page. It contains the
`Safecloud/video` tool (the Q/video drop-in with the `safecloud` adapter —
`web/js/Q/video.js`) and uses Safecloud end to end: capability from
IndexedDB → `Client.stream()` → service-worker HLS → chunk requests follow
play/pause/seek/buffer → each request auto-signs micropayment tokens.

### End-to-end flow

1. **Publisher stores content** on the demo page (or via `Client.store()`).
   The demo shows two things: a share link and an embed snippet.
2. **Embed snippet** is an `<iframe>` pointing at
   `{{baseUrl}}/Q/plugins/Safecloud/embed.html?rootCid=…` with the key
   material in the **URL fragment**: `#rootKey=…&m=<base64url manifest>`.
   Fragments are never sent to any server.
3. **First load inside the iframe**: embed.html parses the fragment,
   saves `{manifest, capability}` into the iframe origin's IndexedDB
   (`Client.saveCapability`), and strips the fragment via
   `history.replaceState`. From this moment the keys exist **only in
   IndexedDB of that origin** — the local pristine environment.
4. **Every later load** (and every service-worker restart — the SW
   lazy-restores sessions from the same IndexedDB) streams with nothing
   but `?rootCid=…` in the URL. Keys never re-enter URLs, postMessage,
   or network requests.
5. **Playback**: the video tool activates videojs with no source, calls
   `Client.stream(…, { setSrc: false, path: 'sw' })`, and hands the
   synthetic `https://safecloud-hls.local/...` URL to videojs VHS as
   `application/x-mpegURL`. The service worker intercepts VHS's requests,
   decrypts per-segment, and serves Range responses. The prefetch loop
   follows the playhead; `onPlay`/`onPause`/`onSeek` drive
   `handle.resume()/pause()/seek()` so chunks are fetched exactly as the
   player plays, pauses, seeks and buffers.
6. **Micropayments**: `Client.init({interactive:false})` silently
   re-derives the payer key if a WebAuthn credential exists; otherwise
   requests go unsigned (accepted only when `requirePayment:false`).
   Parents can trigger the interactive ceremony with the
   `safecloud.enablePayments` message (requires the
   `publickey-credentials-get` iframe permission below).

### Iframe snippet

```html
<iframe src="https://app.example.com/Q/plugins/Safecloud/embed.html?rootCid=CID#rootKey=KEY&m=MANIFEST_B64URL"
        allow="autoplay; encrypted-media; publickey-credentials-get *"
        width="640" height="360" frameborder="0"></iframe>
```

Requirements on the serving app: the Safecloud plugin installed, and
`web/js/Safecloud/.htaccess` (or nginx equivalent) sending
`Service-Worker-Allowed: /` so the streaming SW can register at scope `/`.
`embed.html` loads `../Q/js/Q.js`, `../Users/js/Users.js`,
`../Streams/js/Streams.js` and `js/Safecloud.js` relative to the plugin
web directory, and calls `Q.init({})` when server-injected config is
absent — verify this static-boot path against your app build.

### postMessage API

| direction | message | notes |
|---|---|---|
| → iframe | `{type:'safecloud.play'}` | |
| → iframe | `{type:'safecloud.pause'}` | |
| → iframe | `{type:'safecloud.seek', seconds}` | |
| → iframe | `{type:'safecloud.enablePayments'}` | interactive WebAuthn |
| ← iframe | `{type:'safecloud.event', event:'ready'\|'play'\|'pause'\|'timeupdate'\|'ended'\|'error'\|'payments', …}` | includes `rootCid`; `seconds` where relevant |

Pass `?parentOrigin=https://parent.example` to restrict the bridge.

### Why an iframe

The iframe origin is the trust boundary: it holds the keys (IndexedDB is
origin-isolated), runs the honest player code, and signs the payment
tokens. Served from a SafeBox-attested origin, "the player runs honest
code" becomes verifiable rather than assumed — which is exactly the
property the incentive design below leans on.

## 21. Micropayments end to end, and the incentive design

### Configuration

Server (`local/app.json` or plugin config): `Safecloud.jet.privateKey`
(claim/relay gas), `Safecloud.jet.address`, `Safecloud.safebux.address`,
`Safecloud.safebux.perChunkWei`, `Safecloud.requirePayment`. The Jet
publishes all browser-relevant values over the `Safecloud/jet/info`
socket event, fetched automatically on connect — the browser needs no
PHP-exposed config.

Browser: `Q.Safecloud.Client.init()` establishes the payer identity —
WebAuthn PRF label `safecloud.cloud.session` → `internalKeypair(…,
'EIP712')` → `Q.Safecloud.Jets.cloudEvmPrivateKey`. Distinct from the
Drop's label, so one browser has separate payer and earner identities.
After init, every `Jets.get()` auto-signs EIP-712 Payment tokens; ethers
(v6, vendored at `web/js/ethers/`, 516 KB) lazy-loads only when signing
or on-chain reads are actually configured.

### The token is the enforcement primitive

`paymentsExecute` on OpenClaiming takes the signed payment struct plus a
call-time `recipients` array that must hash to the **signed**
`recipientsHash`, and pays `recipient ∈ recipients`. Whoever signs the
token therefore decides, irrevocably, who can ever be paid from it.

**Verified against OpenClaiming.sol** (the canonical rail): EIP-712 domain
name is `OpenClaiming`, version `1`; the signed struct is exactly
`Payment(payer, token, recipientsHash, max, line, nbf, exp, contract)` —
the signed `contract` field is validated `== address(this)` by the rail
(a wallet-visible deployment binding on top of `verifyingContract`).
`recipientsHash` carries either `keccak256(abi.encode(address[]))` (plain
payments) or `keccak256(abi.encode(Policy))` (enforced splits with
fractions, dynamic payee, and custody hooks) — same signed field, two
non-colliding encodings. Funding is `transferFrom(payer → recipient)`, so
payers must approve the rail once (deploy Safebux with EIP-2612 permit to
keep fresh WebAuthn payers gasless). Execution is permissionless;
contracts are valid recipients; `PaymentsExecuted` indexes the recipient,
giving authors a free on-chain discovery feed. `lines[payer][line].spent`
is CUMULATIVE and every claim's `max` is checked against it — claims are
**watermark channel vouchers**, not independent budgets: only the latest
(highest-max) claim per (payer, line) matters. Line 0 is always open
(gasless payers live there); lines ≥ 1 require the payer to call
`lineOpen()` once.

**Dual-token watermark design (v1).** When a manifest carries
`revenue.incomeContract`, each request advances the viewer's line-0
watermark by the request price and signs two claims at the SAME new
ceiling:

- **Infra token** — `recipientsHash = keccak(abi.encode([jetEVM]))`,
  settleable only by this Jet; the envelope's `amount` carries the
  request's infra share.
- **Author token** — `recipientsHash =
  keccak(abi.encode([incomeContract]))`, same watermark; envelope
  `amount` = the creator share (default 9000 bp / 90%, overridable by
  `revenue.split.creator`). Settled after the infra share, it covers
  exactly the remainder up to the watermark.

**Ground truth & analysis.** The deployed rail's verbatim source lives at
`references/OpenClaiming.sol`; every signing/verifying site in this plugin is
byte-compatible with it (proven by `test/recipientsHash.test.js`).
`references/OCP_soundness.md` games out why v1 payments is sound (a payment
authorized to the wrong party only harms the authorizer — OCP has no borrowable
authority of its own, so it cannot be a confused deputy) and where a
third-party-enforcement protocol like Safecloud needed more than a bare
recipient set (composition — fractions, co-payees, atomic multi-party
settlement). The canonical rail solves this by overloading `recipientsHash`:
the same signed field carries `keccak256(abi.encode(Policy))` for enforced
splits with fractions, a constrained dynamic payee, and per-payee custody
hooks — retiring the caller-side splitter. (`references/OCP_v2_design.md`
records the earlier "policyHash field" design this superseded.)

**Economic model.** Two modes, same infrastructure:

- **Consumption** (video streaming, paid content): viewer pays. Creator keeps
  **90%** of the per-chunk price (`SPLIT_CREATOR_BP = 9000`). Infrastructure
  earns **10%**: ~3% Jet (routing, payment verification), ~5% Drop (storage,
  bandwidth), ~2% protocol treasury. Active when manifest carries
  `revenue.incomeContract` or `revenue.creatorAddress`.
- **Storage** (Safebox backup, encrypted archives): the owner IS the customer
  and pays infra to hold their data. No creator royalty — 100% to infra.
  Active when manifest lacks revenue metadata.

Drops and Jets earn from both revenue streams on the same hardware. Content
delivery is the upside; storage is the base load. Jets cannot cherry-pick
lucrative content because chunks are encrypted and content-indistinguishable —
the only decision is "does this payment cover my cost?" Manifest
`revenue.split` overrides per-channel (authors/publishers can adjust).

**Jet→Drop channels.** Lines live on the *payer*: the Jet calls
`lineOpen(jet, uint160(dropEVM), 0)` once at drop registration
(`_openDropLine`, fire-and-forget), then signs per-drop cumulative
watermark tokens on that line. Transient Drops with fresh browser
addresses register **nothing** on-chain — they hold claims and settle
permissionlessly whenever they choose (`claimPayments` groups by
channel, keeps the newest claim, and settles `lineAvailable`).

The Jet relays author tokens on-chain fire-and-forget
(`_relayAuthorTokens`: verify signature → `paymentsExecute` with
`recipient = incomeContract`), and honest players additionally retain
each author token in IndexedDB (`Safecloud.Client/authorTokens`) so
author-side tooling can collect out-of-band.

**What this buys:** infrastructure that colludes can **withhold** the
author's share (drop the token, never relay), but can never **redirect**
it — the recipient set is inside the viewer's signature, and
`test/recipientsHash.test.js` proves tampering breaks recovery. What it
cannot buy: viewers who already hold decryption capability can always
collude with infrastructure to watch without signing anything. That is
the analog hole; the countermeasure is not cryptography but making the
honest path the default artifact (embed.html, attested origins) and
grants that are per-grantee and expiring.

### IncomeContract's role

The author generates a **fresh address** (anonymous going backward),
deploys/owns an IncomeContract instance with `token = Safebux`, and
publishes its address in the manifest's revenue metadata (integrity-bound
via the meta fork to the rootCid). `paymentsExecute` pays straight into
the contract's balance; lockups/gradual release are the author's choice.
One instance per author is fine; per-content instances work too.
Integration note to verify against the deployed contract: `claim()` for a
self-managed recipient pays out the `locked` amount — confirm that
semantic matches the intended "claim what the schedule has released".

The Jet-balance royalty transfer (`_payCreatorRoyalty`) remains as a
fallback for requests that arrive without author tokens (e.g. free mode).

**Deferred (deliberately):** a well-known-URL registry where viewers or
jets post author tokens. It is detection, not prevention — the
recipientsHash already prevents redirection, and withholding is
measurable on-chain (authors see which payer lines produce income). If it
returns, it returns as a reputation feed, not an enforcement layer.
