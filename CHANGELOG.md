# Changelog

## 3.8.0 — 2026-11-05

### Payment replay protection

`RightsManagement.verifyPublisherAuth()` now rejects replay attacks.  Every
`publisherAuth` token carries a `nonce`; on first successful verification the
nonce is recorded in the new `used_nonces` SQLite table.  A second request with
the same token returns **409 Conflict**.  Expired nonces are cleaned up
automatically at most once per minute so the table stays compact.

**Changes to `classes/Safecloud/RightsManagement.js`:**

- New `used_nonces` table (`nonce TEXT PRIMARY KEY`, `publisher TEXT`, `exp
  INTEGER`) with an index on `exp` for fast expiry cleanup — added to the
  SCHEMA array and created on `open()`.
- `verifyPublisherAuth()` — after signature verification, checks for a known
  nonce and throws 409 if found; otherwise inserts the nonce so the token
  cannot be replayed.
- `_cleanupNonces()` — deletes rows where `exp < now`; rate-limited to one
  invocation per 60 s via `this._lastNonceCleanup`.

### Admin control panel (new file: `classes/Safecloud/ControlPanel.js`)

A single-page HTML admin UI + JSON API under `/Safecloud/admin/`.  Gives
operators a live dashboard for every piece of rights-management state without
touching the database directly.

**New admin methods on `RightsManagement`:**

| Method | Returns |
|---|---|
| `listRoots(opts)` | All registered rootCids (paginated, key excluded) |
| `listPublishers(opts)` | All registered publishers |
| `deregisterPublisher(id)` | Removes a publisher; returns `true` on success |
| `listRateLimits(opts)` | All active token-bucket entries |
| `resetRateLimit(bucketKey)` | Deletes one bucket; returns `true` on success |
| `listUsedNonces(opts)` | Active (non-expired) nonces |

**HTTP routes (`ControlPanel.registerRoutes(app, rm, opts)`):**

| Method | Path | Description |
|---|---|---|
| GET | `/Safecloud/admin/` | HTML SPA |
| GET | `/Safecloud/admin/api/stats` | Aggregate counts (roots / publishers / grants / buckets / nonces) |
| GET | `/Safecloud/admin/api/roots` | Root list |
| GET | `/Safecloud/admin/api/roots/:cid` | Root detail + full grant chain |
| GET | `/Safecloud/admin/api/publishers` | Publisher list |
| DELETE | `/Safecloud/admin/api/publishers/:id` | Deregister a publisher |
| GET | `/Safecloud/admin/api/chain/:cid` | Grant chain for a rootCid |
| POST | `/Safecloud/admin/api/chain/:cid` | Append a grant entry |
| GET | `/Safecloud/admin/api/rate-limits` | Rate-limit bucket list |
| DELETE | `/Safecloud/admin/api/rate-limits/:bucket` | Reset one bucket |
| GET | `/Safecloud/admin/api/nonces` | Active nonces |

Optional bearer-token auth: set `Safecloud.admin.token` in `Q.Config`; every
request then requires `Authorization: Bearer <token>`.  Omit the config key to
leave the panel open (suitable for internal/loopback-only deployments).

### Jets.js integration

`listen()` wires the control panel automatically whenever rights management is
enabled.  No new config key is required beyond `Safecloud.admin.token` for
auth.

### Tests

- **`tests/control_panel.test.js`** (24 tests) — covers payment replay
  protection (5 tests) and all HTTP routes including token auth.
- All 27 existing `tests/rights_management.test.js` tests continue to pass.

---

## 3.7.0 — 2026-11-03

### Engine.js / DB — pure-JS in-process SQL engine (drop-in better-sqlite3)

Safecloud/DB is a zero-native-dependency SQL engine that exposes the full
`better-sqlite3` synchronous API (`new Database(path)`, `.prepare()`,
`.run()`, `.get()`, `.all()`, `.iterate()`, `.transaction()`, `.exec()`,
`.pragma()`). It parses MySQL-dialect SQL via `node-sql-parser` and executes
with SQLite semantics — `INTEGER PRIMARY KEY` auto-increment, `AUTOINCREMENT`
keyword, `LIKE` with `ESCAPE`, `COALESCE`/`NULLIF`/`IIF`, `REPLACE INTO`,
`INSERT OR REPLACE`, `ON CONFLICT` clauses, `RETURNING`, `WITH` CTEs, window
functions, aggregate functions, and expression correctness per the SQLite spec.

Because it contains no native bindings it bundles cleanly through esbuild into
a Node SEA (Single Executable Application) binary — all five platform binaries
now ship with full SQL support out of the box.

**New files:**

- **`classes/Safecloud/DB/index.js`** — package entry; exports `Database` as
  default with sub-exports `Engine`, `Catalog`, `TableStore`, `KeyCodec`,
  `Statement`. Drop-in import path for better-sqlite3 consumers:
  ```js
  const Database = require('./classes/Safecloud/DB');
  const db = new Database(':memory:');
  ```
- **`classes/Safecloud/DB/Database.js`** — top-level `Database` class.
  Constructor accepts a path string (currently operates in-memory; WAL
  persistence to Drops is planned for 4.0). Implements the complete
  better-sqlite3 synchronous interface including `transaction()` wrappers,
  `exec()` for multi-statement scripts, `pragma()` passthrough, and
  `aggregate()` / `function()` extension hooks.
- **`classes/Safecloud/DB/Engine.js`** — SQL parser + executor (1 377 lines).
  Accepts AST output from `node-sql-parser` (`MySQL` dialect) and executes
  against in-memory `TableStore` rows. Handles DDL (`CREATE TABLE`,
  `DROP TABLE`, `ALTER TABLE`, `CREATE INDEX`), DML (`INSERT`, `UPDATE`,
  `DELETE`, `REPLACE`), queries (`SELECT` with `WHERE`, `GROUP BY`, `HAVING`,
  `ORDER BY`, `LIMIT`/`OFFSET`, `DISTINCT`, joins, subqueries, CTEs), and
  expressions (arithmetic, string ops, `CAST`, `CASE/WHEN`, all standard
  SQL functions, `IN`/`NOT IN`, `BETWEEN`, `EXISTS`).
- **`classes/Safecloud/DB/Statement.js`** — prepared statement handle.
  Stores the parsed AST and bound parameter array; exposes `.run()`, `.get()`,
  `.all()`, `.iterate()` mirroring better-sqlite3's `Statement` class exactly.
- **`classes/Safecloud/DB/Catalog.js`** — schema registry. Holds table
  definitions (column list, types, constraints, indexes) and generates
  auto-increment sequences.
- **`classes/Safecloud/DB/TableStore.js`** — in-memory row storage with
  ordered-key indexing. Supports range scans, index lookups, and the rowid
  model (`INTEGER PRIMARY KEY` alias).
- **`classes/Safecloud/DB/KeyCodec.js`** — binary key encoding for ordered
  storage. Encodes `NULL`, integers, reals, and text into a comparable byte
  sequence so range queries return rows in the correct sort order without a
  full-table scan.

**Test suite (`tests/db/`, 192 tests, 100 % passing):**

| File | Tests | Coverage |
|---|---|---|
| `01_ddl.test.js` | 18 | CREATE TABLE, column types, PRIMARY KEY, AUTOINCREMENT, DROP, ALTER |
| `02_insert.test.js` | 16 | plain insert, multi-row, named params, REPLACE, INSERT OR REPLACE |
| `03_select.test.js` | 20 | projections, WHERE, DISTINCT, ORDER BY, LIMIT/OFFSET |
| `04_update_delete.test.js` | 14 | UPDATE SET, WHERE filter, DELETE, RETURNING |
| `05_transactions.test.js` | 12 | commit, rollback, nested savepoints, `.transaction()` wrapper |
| `06_indexes.test.js` | 10 | CREATE INDEX, UNIQUE constraint, index-based lookup |
| `07_joins.test.js` | 16 | INNER JOIN, LEFT JOIN, multiple tables, join + aggregate |
| `08_aggregates.test.js` | 14 | COUNT, SUM, MIN, MAX, AVG, GROUP BY, HAVING |
| `09_subqueries.test.js` | 12 | scalar subquery, IN subquery, correlated subquery, EXISTS |
| `10_window_functions.test.js` | 14 | ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, SUM OVER, PARTITION BY |
| `11_cte.test.js` | 12 | WITH, recursive CTE, CTE + join |
| `12_pragmas_and_api.test.js` | 16 | pragma passthrough, `.exec()`, `.function()`, `.aggregate()`, WAL |
| `13_expr_correctness.test.js` | 18 | CAST, COALESCE, NULLIF, IIF, LIKE ESCAPE, arithmetic edge cases |

**Binary release fix (backported from 3.6 bug report):**

`.github/workflows/release.yml` esbuild step now includes
`--external:Q --external:"Q/*" --external:@aws-sdk/client-s3`.
The `Q` namespace is resolved at runtime by the Module._load hook in
`bin/jet.js`; without marking it external esbuild would fail to bundle.
`@aws-sdk/client-s3` is an optional S3 dependency loaded lazily; bundling it
unconditionally added 6 MB and broke in environments without S3 config.
The same externals are added to the `build:bundle` npm script for local builds.

**Motivation — why Engine.js instead of native better-sqlite3:**
Node SEA (Single Executable Application, stable in Node 22) injects a
pre-built blob into the node binary at postject time. Native addons (`.node`
files) cannot be included in the blob — they require a separate
platform-specific `.node` on disk and a matching Node ABI. Engine.js is pure
JS and therefore bundles cleanly through esbuild, producing a single
self-contained binary per platform with no runtime dependencies.

**Planned for 4.0:** WAL checkpointing to Drops (Safecloud content-addressed
storage), giving Engine.js crash recovery and replication semantics on top of
the in-memory store.

## 3.6.0 — 2026-11-02

### Binary releases via GitHub Actions (Node SEA)

Introduces a CI/CD pipeline that builds five self-contained platform binaries
and publishes them as a GitHub Release on every `v*.*.*` tag push. No Node.js
or npm required to run the server.

**New files:**

- **`.github/workflows/release.yml`** — GitHub Actions workflow. Build matrix:
  `linux-x64` (ubuntu-latest), `linux-arm64` (ubuntu-24.04-arm),
  `macos-x64` (macos-13), `macos-arm64` (macos-latest),
  `windows-x64` (windows-latest). Each job: installs Node 22, runs
  `npm ci --omit=dev`, installs esbuild as a build-only dep, bundles
  `bin/jet.js` to `bin/jet-bundle.cjs`, generates the SEA blob via
  `node --experimental-sea-config sea-config.json`, copies the node binary,
  strips the macOS signature, injects the blob with `npx postject`, re-signs
  on macOS, smoke-tests with `--version`, attests provenance via
  `actions/attest-build-provenance`, uploads artifact. The release job
  downloads all five artifacts, flattens the directory, generates a
  `sha256sum`-based `checksums.txt`, and publishes a GitHub Release with all
  binaries and the checksum file.
- **`sea-config.json`** — SEA configuration:
  `{"main":"bin/jet-bundle.cjs","output":"sea-prep.blob","disableExperimentalSEAWarning":true,"useSnapshot":false,"useCodeCache":true}`.

**OIDC provenance attestation:** each binary is attested with
`actions/attest-build-provenance@v1`; consumers can verify with
`gh attestation verify safecloud-jet-linux-x64 --repo Safebots/Safecloud`.

**Known issue (fixed in 3.7.0):** the esbuild step was missing
`--external:Q`, `--external:"Q/*"`, and `--external:@aws-sdk/client-s3`,
causing CI bundle failures. Fixed in 3.7.0.

## 3.5.0 — 2026-11-01

### Five additional storage backends

Extends the storage backend system with five new adapters alongside the
existing IPFS (3.3) and S3 (3.4) backends. All adapters conform to the
same internal interface (`put`, `get`, `delete`, `list`, `exists`, `head`).

**New files:**

- **`classes/Safecloud/Storage/Arweave.js`** (13 KB) — permanent storage on
  the Arweave network via `arweave-js`. Uploads are bundled with Bundlr/Irys
  for cheap layer-2 posting; direct AR transactions available for large blobs.
  `put` returns the transaction ID as the content address.
- **`classes/Safecloud/Storage/Filecoin.js`** (10 KB) — Filecoin storage via
  web3.storage (`@web3-storage/w3up-client`). Uploads to IPFS/Filecoin
  dual-storage; returns CID. Includes deal tracking and retrieval via the
  Filecoin retrieval market.
- **`classes/Safecloud/Storage/Filesystem.js`** (7.7 KB) — local filesystem
  backend for development and single-node deployments. Stores blobs as flat
  files under a configurable base directory. Supports streaming reads and
  atomic writes via temp-file rename.
- **`classes/Safecloud/Storage/Rclone.js`** (11 KB) — rclone subprocess
  backend. Delegates to any rclone-supported provider (Google Drive, Azure
  Blob, Backblaze B2, Dropbox, and 40+ others) by spawning `rclone` with the
  appropriate subcommand. Config path and remote name are configurable.
- **`classes/Safecloud/Storage/Webdav.js`** (11 KB) — WebDAV backend via the
  `webdav` npm package. Compatible with Nextcloud, ownCloud, Seafile,
  Box, and any WebDAV server. Supports PROPFIND-based listing, chunked
  uploads, and bearer-token / basic auth.

## 3.4.0 — 2026-10-31

### S3-compatible storage backend

Adds an S3 adapter for Drops storage, enabling content-addressed chunks to be
persisted in any S3-compatible object store (AWS S3, Cloudflare R2, MinIO,
Backblaze B2, DigitalOcean Spaces, Wasabi, etc.).

**New files:**

- **`classes/Safecloud/Storage/S3.js`** (10.9 KB) — S3 storage adapter using
  `@aws-sdk/client-s3` (`^3.x`). Constructor accepts `{ bucket, region,
  endpoint, credentials: { accessKeyId, secretAccessKey } }`. Implements the
  standard backend interface: `put(key, data)`, `get(key)`, `delete(key)`,
  `list(prefix)`, `exists(key)`, `head(key)`. Uses presigned URLs for
  large-object streaming. Endpoint override supports path-style addressing for
  MinIO and Cloudflare R2.
- **`@aws-sdk/client-s3`** added as an optional dependency (lazy-required;
  throws a clear error if missing and S3 backend is configured).

## 3.3.0 — 2026-10-31

### IPFS/IPNS storage backends

Adds native IPFS content-addressed storage and IPNS mutable-name support,
enabling Drops (content-addressed chunks) to be persisted on and retrieved
from the IPFS network via the Kubo RPC API (PSA v1.0.0).

**New files:**

- **`classes/Safecloud/Ipfs.js`** (25.6 KB) — IPFS storage adapter. Connects
  to a local or remote Kubo node via the `/api/v0/*` RPC endpoints. Implements
  `add` (multipart/form-data upload with chunking options), `cat` (streaming
  download), `pin add/rm/ls`, `dag get/put/resolve`, `files` MFS operations,
  `bitswap stat`, and `swarm peers`. Handles CIDv0/v1 normalization, multipart
  streaming, and timeout/retry logic.
- **`classes/Safecloud/Ipns.js`** (5.9 KB) — IPNS name operations. Wraps the
  Kubo `/api/v0/name/publish` and `/api/v0/name/resolve` endpoints. Manages
  key generation and listing (`/api/v0/key/*`) so Drops can be addressed under
  a stable human-readable or key-derived name that resolves to the latest root
  CID. Supports TTL and lifetime options for publish.

## 3.2.0 — 2026-10-31

### ML-DSA-65 hybrid governance attestation and Safebox liveness check

Extends Safecloud's post-quantum attestation stack to cover the Safebox governance layer — not just the scanner authorization (PQClaim, 3.1.0) but the Safebox's own identity claim. Adds a challenge-response liveness check to prove the Safebox TEE is live at connection time, not replaying a cached attestation document. All changes are additive and backward-compatible: existing policies and older Qbix versions without `@noble/post-quantum` are unaffected.

**Backward-compatible degradation matrix:**

| Qbix version | `@noble/post-quantum` | `requirePQAttestation` | `livenessCheck` | Behavior |
|---|---|---|---|---|
| New (patched) | ✓ installed | not set | not set | Identical to 3.1.0 |
| New (patched) | ✓ installed | set | `'strict'` | Full PQ verification + liveness |
| Old (unpatched) | ✗ missing | not set | not set | Identical to 3.0.0 — no change |
| Old (unpatched) | ✗ missing | set | any | Fails with "library unavailable" reason |

**EVM compatibility:** EIP712/ecrecover path is completely untouched. ML-DSA-65 is additive only.

#### A — `AttestationVerifier.js`: ML-DSA-65 static helper

New static method `AttestationVerifier.verifyMLDSASig(sigB64, msg, pkB64)`:
- Returns `{ ok, available, error }` — distinguishes "library missing" (`available: false`, old Qbix) from "signature bad" (`ok: false, available: true`) to enable the right diagnostic in each caller.
- Lazy-imports `@noble/post-quantum/ml-dsa.js` (ESM-only package) via `import()`, caches the module across calls. Soft-catches import failures so older Qbix without the package does not crash.
- `msg` may be a Buffer or UTF-8 string. FIPS 204 hashes internally (SHAKE256); callers should NOT pre-hash unless signing a challenge-response digest.
- Argument order: `ml_dsa65.verify(signature, message, publicKey)` — matches the `@noble/post-quantum` API and the Qbix platform PQ patch.

#### B — `AttestationPolicy.js`: governance claim PQ attestation

New policy options:

- **`requirePQAttestation`** (default: `null`/falsy) — when set, `evaluate()` verifies that the Safebox governance claim (`opts.govClaim`) carries at least one valid ML-DSA-65 signature. The caller passes:
  - `opts.govClaim` — parsed OpenClaim OCP document with parallel `key[]`/`sig[]` arrays (index `i` of `key[]` paired with index `i` of `sig[]`).
  - `opts.govClaimCanon` — canonical UTF-8 string (output of `Q.Crypto.OpenClaim.canonicalize(claim)`) that was signed.
- **`pqTrustedKeys`** (default: `null`) — when set alongside `requirePQAttestation`, only key URIs in this array are accepted. Key URI format: `data:key/ml-dsa-65;base64,<1952-byte raw public key>`.
- `evaluate()` now returns a `Promise` when either `requirePQClaim` or `requirePQAttestation` is set. For policies with neither, it remains synchronous. Callers should always `await`.

Internals: new private `_checkPQAttestation(policy, opts)` helper. Collects all ML-DSA-65 key/sig pairs from the governance claim, verifies each via `verifyMLDSASig`, passes if any one succeeds. `toJSON()` serializes new fields.

#### C — `AttestationFetcher.js`: Safebox liveness check

New option `livenessCheck` (default: `null`):
- `null` / `false` — `checkLiveness()` is a no-op; resolves `{ live: true }` immediately. Old Safeboxes without `/attestation/challenge` are unaffected.
- `true` — attempt challenge-response; 404 / timeout / missing PQ library → warn to console + resolve live. Non-blocking for clients where liveness is a nice-to-have.
- `'strict'` — challenge-response required; any failure (unreachable endpoint, bad signature, missing library) resolves `{ live: false, reason: '...' }` so the caller can reject the Safebox.

New method `checkLiveness(safeboxUrl, govClaimCanon, govClaimKeys)`:
- POSTs `{ nonce: <32-byte hex> }` to `{safeboxUrl}/attestation/challenge`.
- Expects `{ signature: <base64 ML-DSA-65 sig> }` in response.
- Computes `digest = SHA-256(nonce_bytes || govClaimCanon_bytes)` and verifies the signature via `verifyMLDSASig(resp.signature, digest, pkB64)`. FIPS 204 then applies its own SHAKE256 on top of the digest.
- Finds the first `data:key/ml-dsa-65;base64,` URI in `govClaimKeys` to extract the public key.
- Uses a tighter 5 s timeout (vs the 10 s default for JWKS/cert fetches).

New `_post(url, body, timeoutMs)` helper mirrors `_get` with dual Node.js (`https.request`) / browser (`window.fetch`) paths.

## 3.1.0 — 2026-10-28

### Post-quantum scanner authorization (ML-DSA-65 / FIPS 204)

Extends the attestation stack with quantum-resistant scanner-authorization claims. The TEE hardware attestation signatures (ES256/ES384/RS256 issued by AWS, GCP, Azure, OCI, AMD, Intel) are unchanged — those are defined by hardware vendors. The new PQ layer operates at the application level: who authorized the scannerCID that appears in the attestation.

- **`classes/Safecloud/Attestation/PQClaim.js`** — new module. Signs and verifies self-contained ML-DSA-65 scanner-authorization claims. A claim is a JSON object stating `{ v, action: 'approve-scanner', scannerCID, issued, expires, pqPublicKey, pqSig }`. Canonical bytes (all fields except `pqSig`, keys sorted, no whitespace) are signed directly by `ml_dsa65.sign` — ML-DSA-65 performs internal hashing per FIPS 204; no pre-hash step. Signature is 3309 bytes, public key is 1952 bytes, stored as `data:key/ml-dsa-65;base64,<raw b64>` (same key URI format as Qbix platform Q.Crypto). Uses `@noble/post-quantum ^0.7.1` via lazy ESM import.
  - `PQClaim.sign({ scannerCID, pqPublicKey, pqSecretKey, ttlSeconds? })` → signed claim object
  - `PQClaim.verify(claim, { scannerCID, trustedKey?, now? })` → `{ valid, error? }`
- **`classes/Safecloud/Attestation/AttestationPolicy.js`** — extended with `requirePQClaim` (default falsy) and `pqTrustedKey` options. When `requirePQClaim` is set, `evaluate(result, { pqClaim })` additionally verifies a PQClaim signed by the trusted issuer key alongside the classical TEE attestation check. Existing policies without `requirePQClaim` are unchanged — `evaluate()` remains synchronous for them and returns a plain object; with `requirePQClaim` it returns a Promise.
- **`classes/Safecloud/Attestation/index.js`** — exports `PQClaim` alongside `Verifier`, `Fetcher`, `Policy`, `TrustStore`.
- **`tests/pq_claim.test.js`** — 16 tests: sign/verify round-trip, tamper detection, expiry, future-issued, wrong scanner CID, wrong trusted key, bad signature bytes, policy integration (with/without PQClaim, wrong CID, wrong key, TEE failure + valid PQ still fails, toJSON/fromJSON round-trip).
- **`package.json`** — adds `@noble/post-quantum ^0.7.1`.

**Why bother when HKDF and AES-256 are already quantum-resistant?** HKDF-SHA256 and symmetric encryption are safe against Grover's algorithm (√ speedup, leaving 128-bit effective security). ECDSA (ES256/ES384) and RSA (RS256) are broken by Shor's algorithm in polynomial time — a sufficiently large quantum computer recovers the signing private key from the public key. ML-DSA-65 is lattice-based (CRYSTALS-Dilithium) and resists both Shor and Grover. Hybrid attestation carries both the classical hardware-provider signature and a PQClaim, so the authorization chain remains valid as quantum capability grows.

## 3.0.0 — 2026-10-27

### Attestation Verifier (TEE trust for Safebox chaperone)

Pure-JS attestation module — no external dependencies beyond Node.js built-ins.

- **`classes/Safecloud/Attestation/`** — new top-level module, exported as `Attestation` from the main index.
  - **`AttestationVerifier`** — pure verifier; dispatches by provider name, wraps errors into `{ valid: false, error }` rather than throwing.
  - **`AttestationFetcher`** — network layer; fetches GCP/Azure JWKS, OCI/Veraison public key, AMD VCEK cert, Intel SGX Root CA. All results cached (URL → value map).
  - **`AttestationPolicy`** — enforces `scannerCID` + accepted provider list + `allowDebug` flag. `evaluate(result)` → `{ pass, reason }`. `toJSON`/`fromJSON` for persistence.
  - **`TrustStore`** — loads pinned root CA DER files from `trust-roots/` at startup; exposes `nitroRoot`, `intelRoot`, etc.
- **Six provider modules** (`providers/Nitro`, `GCP`, `Azure`, `OCI`, `SEV_SNP`, `TDX`):
  - **Nitro** — COSE_Sign1 (CBOR, RFC 8152), ES384; cert chain in doc; `user_data` → `scannerCID`.
  - **GCP** — RS256 JWT; rotating JWKS; `user_data` → `scannerCID`.
  - **Azure MAA** — RS256 JWT; rotating JWKS; `x-ms-runtime.user-data` (base64) → `scannerCID`.
  - **OCI/Veraison** — ES256 JWT (EAR); accepts KeyObject, single JWK, or JWKS; `ear.status` must be `affirming`; `user_data` → `scannerCID`.
  - **SEV-SNP** — 1184-byte binary AMD report; ES384; `report_data` at 0x050 → `scannerCID`.
  - **TDX** — TDX Quote v4; ES256; `report_data` at header+0x248 (TD report is 648 bytes, not 584); `TD_REPORT_SIZE` corrected to 0x288.
- **Utility modules** (`util/`):
  - **`cbor.js`** — minimal CBOR encoder/decoder. Fixed `_encodeHead` to support 64-bit integers (CBOR additional info 27) for Nitro millisecond timestamps.
  - **`jwt.js`** — `parseJWT`, `verifyJWT` (takes single JWK or KeyObject, not JWKS), `base64urlEncode`, `base64urlDecode`.
  - **`cose.js`** — `parseCOSESign1` (now returns `protectedBytes` alongside `protectedHeaders`), `verifyCOSESign1`.
  - **`certchain.js`** — `verifyChain(leaf, cabundle, trustedRootDER)`.
- **Fixture generator** (`tests/fixtures/generate.js`) — generates pre-baked signed fixtures for all 6 providers using test-generated keys + openssl self-signed certs.
- **Test suite** (`tests/attestation_verifier.test.js`) — 71 tests, all passing. Node.js built-in test runner (`node --test`), no extra dependencies.

## 2.9.0 — 2026-10-25

### Data structures (SDK)
- Five high-level structures built on `tree_*` host API: **Directory** (static folder, IPFS/IPLD analog), **Feed** (append-only log, Hypercore/Kafka analog), **Repo** (versioned directory with branch/merge/diff, Git analog), **Database** (indexed KV with commit/rollback, Dolt analog), **NameResolver** (mutable name→CID, IPNS analog).
- **TreeStore** reference implementation of `tree_*` for testing and `safecloud dev` emulator. Two modes: KV (ordered key-value with range queries) and append (append-only log with subscribe). Every mutation updates root CID (Merkle property). ChunkStore for checkpoint/hydrate persistence.
- `tree_diff(cidA, cidB)` added to host API — compares two checkpointed tree states, returns `[{ key, before, after }]` changes.

### Test battery
- 145 Node.js tests covering all six modules (TreeStore KV, TreeStore append, checkpoint/hydrate, diff, Directory, Feed, Repo with branches and manual merge, Database with indexed range queries, NameResolver, cross-structure integration, edge cases).
- 53 headless browser tests via Playwright — same coverage in a real browser environment with pure-JS SHA-256, Buffer shim, and module bundling (no webpack).

### Browser bundle
- `browser_bundle.js` builds a single self-contained `browser_tests.bundle.js` via closure wrapping. Includes synchronous pure-JS SHA-256 (no Web Crypto async dependency) and minimal Buffer polyfill (Uint8Array + TextEncoder/TextDecoder).

### Updated docs
- New `DataStructures.md`: full API documentation for all five structures with code examples, cross-structure workflows, interoperability table, wire format.
- `Architecture.md`: added `tree_diff` to host API table, added "Data structures (SDK)" section.
- `Apps.md`: added `tree_diff` to host API function list.
- `LLM.md`: added §19 covering the full data structures API surface.

## 2.8.0 — 2026-10-18

### Architecture document
- New `Architecture.md`: unified three-layer model (Safecloud = pull, Intercloud = push, Safebox = trust), the composition loop, three-tier WASM with host API tables, chat and messaging model, SafecloudApp deployment, OCP Actions access control, standard includes, and comparisons to Cloudflare Workers, Pear/Hyperswarm, and Signal.

### Tree API (generalized storage)
- `tree_create`, `tree_append`, `tree_get`, `tree_put`, `tree_range`, `tree_delete`, `tree_root`, `tree_checkpoint`, `tree_hydrate` replace the flat `safedb_*` KV API as the primary storage surface. The KV functions remain as aliases operating on a default tree in KV mode.
- WAL + checkpoint to Drops: tree state lives in memory while active, WAL on local disk for crash recovery, async checkpoint to Drops as content-addressed chunks. `tree_hydrate(rootCid)` reconstructs from Drops on any Jet for failover.

### Revised chat architecture
- Rooms are Merkle trees (append-only log of encrypted blobs) rather than Jet-routed message tracks.
- WebRTC mesh for real-time delivery between online peers; Jet as TURN relay only.
- 2-hop onion routing for persistence: sender → 2 intermediate Jets → destination Jet. Destination Jet cannot identify sender; traffic is indistinguishable from inter-Jet chunk replication.
- No sender pubkey in envelope (deniability). No wall-clock timestamp in envelope — monotonic tree position index is the canonical ordering.
- Safebox push gateway for notifications: TEE-attested service holds VAPID keys and push subscriptions, enforces per-user rate limits via OCP claims. Jets cannot push directly.
- Room failover via `tree_hydrate`: any Jet can pick up a room from Drops.

### SafecloudApp deployment
- CLI via npm (`@safecloud/cli`): `safecloud deploy`, `safecloud dev`, `safecloud hash`, `safecloud manifest`.
- Zip upload to Jet admin endpoint.
- Web dashboard as a SafecloudApp (dogfooding).
- Access control via OCP Actions Extension: owner/deployer/admin roles with delegation and M-of-N multisig.

### Standard includes
- `/@safecloud/client.js`, `/@safecloud/drop.js`, `/@safecloud/app.js`, `/@safecloud/app.css` served from hosting Jet at well-known paths. Pinned versions available (`/@safecloud/client@2.8.js`).
- Iframe `?css=` querystring for custom styling when embedding.

### Updated docs
- `Apps.md`: tree API in host API section, revised rooms section (WebRTC + onion routing + Safebox push gateway), deployment section, standard includes section, updated attack vectors table.
- `LLM.md`: updated architecture summary, companion docs list, rooms section.

## 1.0.0-beta.1 — 2026-07-06

First packaged release.

### Added
- Installation & Quick Start section in README (routes, Service-Worker-Allowed
  header, local/app.json config, Jet bring-up).
- `web/css/Safecloud.css` plus `css/pages/{demo,drop}.css`; page handlers now
  load `js/pages/{demo,drop}.js` so the demo wiring actually runs.
- `web/js/Safecloud/.htaccess` setting `Service-Worker-Allowed: /` for sw.js.
- `Safecloud/player` tool registered in the lazy-load map.
- Jet-to-Jet hello authentication: EIP-712 `JetSessionDelegation` signed by the
  Jet wallet, bound to the sender's Noise static public key (anti-replay),
  verified on receipt (`Safecloud.swarm.allowUnverifiedDelegations` opts out).
- CoC gossip is now verify-before-act: unverified claims are recorded for
  forensics but never mark an actor corrupt.
- Qbix `pluginInfo` block, `swarm`/`wallet` defaults and `drop.sbuxPerMB`
  in config/plugin.json; `hypercore-crypto` declared in package.json.
- Minimal test suite: `npm test` (manifest validation + delegation roundtrip).

### Fixed
- `demo/jet.js`: `../classes/...` require path; robust `Q.inc` resolution
  (`Q_INC` env override) with a clear error message.
- Removed stale pre-rename `classes/Safe.js` and duplicate
  `demo/Safecloud_player_tool.{js,css}`.
- README §§10–13 now match the shipped API (`Jets.put/get`,
  `Drops.init/claimPayments`, `/Safecloud/cloud` namespace, chunk shapes).
- index.html status matrix synced with code in both directions; the real
  remaining gap (Cloud→Jet payment key derivation) is now listed.
- Text-key casing (`Heading`, `ShareLabel`, `PageTitle`, …) so en.json
  localisation is actually used; player tool template name aligned.
- Drop earnings rate reads `Safecloud.drop.sbuxPerMB` config instead of a
  hardcoded constant (dashboard label follows it).
- demo/drop.html no longer calls Google Fonts; system font stacks.

### Known gaps (tracked on the index.html status board)
- Cloud→Jet payment auto-signing awaits WebAuthn-PRF derivation wiring for
  `Q.Safecloud.Jets.cloudEvmPrivateKey` — run Jets with `requirePayment:false`.
- Safebux ERC-20 deployment pending; JetSwarm `secureIds` (Mode 2) documented,
  not implemented; relay fallback and CoC flooding are Phase 4.

## 1.0.0-beta.2 — 2026-07-07

### Micropayments end to end
- `Client.init()` — Cloud payer identity via WebAuthn PRF
  (`safecloud.cloud.session`), `options.privateKey` path, anonymous
  fallback; credential persisted in `Safecloud.Client` IndexedDB.
- Vendored ethers v6.17.0 (`web/js/ethers/`, MIT, 516 KB) with lazy loader
  `Q.Safecloud.ensureEthers` — used by payment signing, Drop balance
  pre-screening, and direct claims. No CDN.
- New `Safecloud/jet/info` socket event: browsers learn jet address,
  Safebux address/chain/price, and drop thresholds from the Jet itself.
- **Fix:** browser payment tokens carry numeric `chainId`; the Jet now
  normalizes to CAIP-2 before the allow-list check (previously every
  signed token was rejected).
- **Dual-token incentive design:** with `manifest.revenue.incomeContract`,
  viewers sign an infra token (recipients `[jet]`, line 0) plus an author
  token (recipients `[incomeContract]`, line 1, 30-day expiry). Jets relay
  author tokens on-chain (`_relayAuthorTokens`, signature-verified,
  deduped); players retain copies in IndexedDB (`authorTokens`).
  Colluders can withhold the author share, never redirect it.
- `test/recipientsHash.test.js`: browser/server/AbiCoder encodings agree;
  tampered recipient sets break signature recovery.

### Player + embed
- `web/js/Q/video.js` — drop-in replacement for Q/video adding the
  `safecloud` adapter; defines both `Q/video` and `Safecloud/video`.
  SW-HLS through videojs VHS (`setSrc:false` + `application/x-mpegURL`),
  blob fallback, `startStream()`, `setStatus()`, `safecloud:` URL scheme.
- `web/embed.html` — iframe player: fragment consumed once →
  capability persisted to IndexedDB → keyless URLs thereafter;
  postMessage bridge (play/pause/seek/enablePayments; ready/play/pause/
  timeupdate/ended/error/payments); `parentOrigin` restriction.
- Service worker persists sessions to IndexedDB and lazy-restores after
  SW restarts (previously mid-playback 404s).
- `Client.saveCapability` / `loadCapability`; `Client.fetchMeta`
  registered (was orphaned).

### Dashboards + demo
- Drop tool: claimable tokens (real, from IndexedDB via new
  `Drops.getPaymentStats`), requests row with challenge count, live
  activity feed, served-rate sparkline; claim threshold from jet info.
- Demo: share links now carry the manifest in the fragment
  (`#rootKey=…&m=…`) so links play cross-device; embed snippet with copy
  button; payer strip via new `Jets.getCloudStats`; first gesture
  initialises Drop + payer identities.

## 1.0.0 — 2026-07-07

### On-chain format corrected against OpenClaiming.sol (source review)
- **EIP-712 domain fixed everywhere**: name is `OpenClaiming.payments`
  (was `OpenClaiming`) — previously every signature would revert on-chain
  with `PayerMismatch`. Struct corrected to the deployed 7-field
  `Payment(payer, token, recipientsHash, max, line, nbf, exp)` (was 8
  fields in a different order including a `contract` member). Sites:
  browser signer, jet→drop signer, x402 verify, `_checkPayments` fallback
  (extracted to `_ethersVerifyPaymentSig`), author-token relay.
  `test/recipientsHash.test.js` now reconstructs the contract's digest
  from its constants and proves byte-exact equality with what ethers
  signs. NOTE: the platform `Q.Crypto.OpenClaim.EVM` module (Q plugin,
  outside this repo) needs the same domain/struct fix; until then the
  Jet chains its result into the corrected ethers verifier.
- Off-chain drop-relay authorization renamed to its own domain
  (`Safecloud.dropRelay`) to stop masquerading as the payments domain.

### Watermark channel semantics (lines are cumulative)
- Browser and jet→drop signers now issue monotonic watermark claims
  (per-payer line-0 counter; per-drop counters on named lines); per-
  request shares ride as envelope `amount` hints. Author tokens moved to
  line 0 at the shared watermark (line 1 would revert: unopened lines).
- `claimPayments` direct path settles per channel: latest claim only,
  amount = on-chain `lineAvailable`.
- Jet opens `lines[jet][uint160(dropEVM)]` at drop registration
  (`_openDropLine`) — transient drops never transact to register.
- Jet retains the latest verified viewer token per payer
  (`_retainCloudToken`) for future settlement.

### References captured
- Added `references/OpenClaiming.sol` — verbatim deployed contract source, the
  ground truth all EIP-712 code matches (planned canonical home:
  Q/classes/Q/Crypto/OpenClaim/EVM/contract.sol).
- Added `references/OCP_soundness.md` (v1 payments soundness gaming-out: no
  confused-deputy risk; destination-enforceable but not composition-enforceable)
  and `references/OCP_v2_design.md` (opt-in policyHash rail that enforces
  fractions + per-payee targets in-contract, removes self-punishing griefing,
  and retires the side-car splitter — new address, coexists with v1).
