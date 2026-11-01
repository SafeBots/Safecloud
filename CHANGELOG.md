# Changelog

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
