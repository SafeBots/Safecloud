# Cross-runtime crypto consistency tests

These verify that the **browser** (`plugins/Q/web/js/methods/Q/Crypto/*`) and
**server** (`Q/Crypto/OpenClaim.js`) elliptic-curve paths agree: same key
derivation, same digests, and each verifies the other's signatures.

## Deps
```bash
npm install @noble/curves@1.4.0 @noble/hashes@1.4.0 crypto-js@4.2.0
```

## Run
```bash
node tests/crypto/cross-runtime.test.js    # key derivation + ES256 + secp256k1 (15 assertions)
node tests/crypto/openclaim-layer.test.js  # OpenClaim raw-r||s round-trip (4 assertions)
node tests/crypto/real-openclaim.test.js   # loads the REAL server OpenClaim.js (8 assertions)
```

## What they prove
- **Key derivation identical** across runtimes: P-256 (HKDF-SHA256, salt=SHA256(""),
  info="q.crypto.p256.private-key") and secp256k1 (keccak256-domain-separated),
  plus matching EVM address.
- **ES256**: browser (noble) signature verifies under server (Node crypto), and
  the OpenClaim raw-r||s claim signature verifies under BOTH Node crypto and
  WebCrypto `subtle.verify`.
- **Real server OpenClaim.js**: server-signed claim verifies in the browser
  (WebCrypto); browser-signed claim verifies via the real `OpenClaim.verify()`;
  tampered claims rejected on both sides.
- **EVM digest cross-language**: `EVM.php` and `EVM.js` produce byte-identical
  payment digests (also matches deployed Solidity — typehash 0xa6aa1cd3…).

## Note
`OpenClaim.js` calls `Q.Crypto.internalKeypair` / `Q.Data.*` from the server
`Q` core (not vendored here). `real-openclaim.test.js` injects a faithful `Q`
shim implementing exactly those functions per the documented algorithms, then
loads the REAL `OpenClaim.js`. Swap in the actual `classes/Q/Crypto.js` when
available to test the literal file end-to-end.

## UPDATE — literal server files verified

`literal-server-crypto.test.js` now runs against the **actual** server
`classes/Q/Crypto.js`, `Q/Data.js`, and `Q/Crypto/OpenClaim.js` (no shim).
Result: the production Drop path (raw r||s) signs, self-verifies, rejects
tampering, and the **browser's WebCrypto accepts the real server signature** —
closing the last unverified seam.

Run:
```bash
npm install @noble/secp256k1 @noble/curves @noble/hashes crypto-js
SERVER_CLASSES=/path/to/classes node tests/crypto/literal-server-crypto.test.js
```

Finding worth noting: `Q.Crypto.sign` (generic typed-data) uses Node's
`sign(null, digest)` which is self-consistent Node↔Node but is NOT the path
Drops use. The Drop path is `Q.Crypto.OpenClaim` (raw r||s), which is the one
verified cross-runtime above. The two layers are intentionally separate.
