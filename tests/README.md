# Safecloud tests

Two suites:

## `npm test` — unit tests (Q shims)
Manifest validation, delegation claims, recipientsHash byte-exactness.

## `npm run test:integration` — executable integration tests (400 assertions)
Run against real ethers 6.17, real socket.io, real WebCrypto + IndexedDB.
No blockchain, no browser required.

| File | Covers |
|------|--------|
| `eip712.test.js` | EIP-712 format is byte-identical to OpenClaiming.sol; field order is load-bearing |
| `policy_and_sponsor.test.js` | Policy hash agreement, sponsor line derivation, per-content payer keys |
| `jet_module.test.js` | Loads the REAL Jets.js; verifies access-control vs payment separation |
| `e2e.test.js` | Full four-role circuit (author/viewer/sponsor/jet/drop) against a mock OpenClaiming that mirrors the Solidity settlement rules |
| `transport.test.js` | Real socket.io Drop registration/announce/reconnect + socket-owns-dropId security |
| `drop_storage.test.js` | Encrypted-chunk storage (Drop can't read), watermark accumulation (dashboard math) |
| `adversarial.test.js` | Multi-Drop sessions, sponsor-cap 402, concurrent viewers, Jet solvency, policy-admission edges, expiry/nbf/cross-deployment replay, {App}bux gating, serve/settle independence |
| `tree_math.test.js` | Merkle path→range math + round-trip invariant (binary, 4-ary, ragged trees) — guarantees correct chunk mapping |
| `splitkey.test.js` | Split-entropy share-link recovery (HKDF): exact key recovery, wrong-passphrase/tampered-token/mask all fail, full encrypt→recover→decrypt loop |
| `pricing_and_encoding.test.js` | Drop reliability price curve (exact boundaries, monotonic, min-price filter) + base64url manifest round-trip (unicode, URL-safety) |
| `drop_identity.test.js` | WebAuthn-PRF → stable EVM address invariant: deterministic across wipes, no collision, avalanche |
| `flow_full_circuit.test.js` | **Wired e2e**: author encrypts→uploads (socket)→Drop stores (IndexedDB)→share link→viewer recovers key (HKDF)→pays→Jet serves→viewer decrypts→settles. Video byte-identical end to end |
| `flow_sponsored.test.js` | **Wired e2e**: sponsored viewer arc over socket — jet/info discovery→sponsor token→stream→cap 402→self-pay fallback. Viewer never on-chain while sponsored |
| `flow_multidrop.test.js` | **Wired e2e**: one video's chunks across 2 Drops, fetched in one request, reassembled in order, all parties paid, accounting closes to zero |
| `http_routes.test.js` | **Real shipped HTTP handlers** booted via `Jets.listen()`: /health, /sponsor/token (signature verifies), /faucet, /dashboard, x402 chunk 402 + PAYMENT-REQUIRED. Includes hostile-input regressions |
| `robustness.test.js` | Malformed/hostile input to the real public surface — grants, link paths, Drop registry, unreachable RPC. Nothing may crash a live Jet |
| `http_hostile.test.js` | 66 hostile HTTP inputs against the real routes: malformed base64 OCP params, traversal-ish link paths, bogus payment headers, Range abuse, poisoned PUT bodies. No crashes, no internals leaked |
| `chunk_assembly.test.js` | x402 chunk assembly with malformed Drop responses; tag-less chunks serve correctly; RFC 7233 Range handling (416 for unsatisfiable) |
| `socket_handlers.test.js` | **Real socket handlers** over a genuine socket.io connection: register/announce/disconnect/claimPayments/subtree put+get/jet-info/challenge, ownership enforcement, grace-period lifecycle |
| `socket_dos.test.js` | **Critical regression**: 182 process-kill payloads against all 9 socket events. Asserts no uncaught exception ever escapes a handler |
| `router.test.js` | Real Router: drop weighting under hostile `storage` claims, weighted-random selection fairness, reliability EMA, and self-correction against a capacity liar |
| `operator_setup.test.js` | The config/bootstrap states a human moves through standing up a Jet: empty config, wallet-only, typo'd types, sponsor-without-wallet, the documented demo config, and hostile claim tokens. Each fails safe with a clear signal |

`npm run test:all` runs both.

## Bugs these tests found and fixed
1. **Remote DoS** — a Drop registering with a non-numeric `minPerChunkWei` crashed
   `selectDrops` via `BigInt()`, breaking routing for *every* viewer on that Jet.
   Fixed with `_safeBigInt` + sanitization at the registration boundary.
2. **NaN chunk ranges** — a non-numeric link-path segment produced
   `{start: NaN, end: NaN}`, silently slicing the wrong chunks. Now clamped.
3. **Sponsor 500 + stack-trace leak** — client-supplied `maxWei` hit `BigInt()`
   unguarded, returning 500 with express's stack trace (file paths disclosed).
   Now validated → 400, handler wrapped, no internals leaked.
4. **CRITICAL — remote process kill.** `{ rootCid:'x', grants:'anystring' }` over
   the socket reached `grants.filter(...)`: a string passes the `.length` guard
   but has no `.filter`, so it threw a **synchronous uncaught TypeError inside a
   socket.io handler — terminating the entire Jet process**. One anonymous
   message killed every Drop connection and every viewer's stream. Same class
   existed for `payments` (`.map`) and `chunks` (`.map`). Fixed at the root
   (`Array.isArray` coercion at every untrusted boundary) *and* architecturally:
   all 9 socket handlers now run behind a crash guard that converts any throw
   into an `InternalError` ack, making this bug class non-fatal by construction.
5. **Silent routing exclusion (NaN weights)** — a Drop registering with
   `storage:{GB:"abc"}` produced a NaN weight; `weight > 0` is false for NaN,
   so that Drop was silently **never routed to, forever**, with no error
   anywhere. Now coerced to a finite, bounded number.
6. **Routing capture via unverified storage claim** — claimed storage is
   attacker-controlled and weighting was *linear* in it, so a Drop claiming
   1e15 GB won **200/200** selections: it captured all Drop revenue on a Jet
   and could black-hole every chunk. Fixed three ways: clamp claims to
   `Safecloud.router.maxClaimedGB` (default 64 TB), take `sqrt(available)` so
   weight grows sub-linearly, and make reliability demotion asymmetric
   (`FAIL_W` 0.1 → 0.3) so a non-serving liar collapses from 97% → 1.3% of
   traffic within 20 failed serves while an honest Drop with one blip in 56
   serves keeps 82% of its weight.
7. **x402 chunk crash on tag-less chunks** — `Buffer.from(chunk.tag,'base64')`
   with no guard threw a TypeError on the PUBLIC x402 route whenever a chunk
   carried no separate AEAD tag (a legitimate format), returning 500 with the
   error text leaked. Now `tag` is optional, malformed payloads 404 cleanly,
   unsatisfiable Ranges return 416, and route errors no longer echo internals.

## What these do NOT cover (test manually before mainnet)
- **Solidity** — compile + test contracts in your Hardhat repo (no solc here).
  Especially the fixed `TradedToken.sell()`: pays `amount*sellPrice/FRACTION`,
  burns the sold tokens, rejects locked tokens.
- **Service Worker / WebAuthn passkeys / iOS native HLS** — need a real
  browser and a real iPhone. This is the Sunday rehearsal.
- **The Q platform transport auth middleware** — platform-only.
- **A live on-chain circuit** — deploy to BSC testnet, then verify a real
  settlement on BscScan.
