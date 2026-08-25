# Changelog

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

## 1.0.0-beta.3 — 2026-07-07

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
