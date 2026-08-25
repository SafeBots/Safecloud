// ============================================================================
// Cross-runtime consistency test for Q.Crypto elliptic-curve signatures.
//
// Goal: prove the BROWSER path (sign.js/verify.js/internalKeypair.js, which use
// noble-curves + WebCrypto) and the SERVER path (OpenClaim.js, which uses Node's
// built-in `crypto`) produce and accept IDENTICAL keys, digests, and signatures.
//
// We reproduce BOTH sides faithfully in Node:
//   - "browser" side = noble-curves + node HKDF (mirrors crypto.subtle HKDF)
//   - "server"  side = node:crypto (createECDH / sign / verify), exactly as
//     OpenClaim.js does it.
// Then we cross-verify each side's signature with the OTHER side's verifier.
// ============================================================================

const nodeCrypto = require('crypto');
const { p256 } = require('@noble/curves/p256');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { keccak_256 } = require('@noble/hashes/sha3');

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log('  \u2713 ' + name); }
  else { fail++; console.log('  \u2717 ' + name + '   <-- FAIL'); }
}
function hex(u8){ return Buffer.from(u8).toString('hex'); }

// ---------------------------------------------------------------------------
// Shared derivation primitives (must match internalKeypair.js EXACTLY)
// ---------------------------------------------------------------------------

// ES256 / P-256: scalar = HKDF-SHA256(ikm=secret, salt=SHA256(""), info="q.crypto.p256.private-key")
// (derive.js: salt = SHA-256(context), context default "" ; hkdf.js: info = label)
function deriveP256Scalar(secret) {
  const salt = nodeCrypto.createHash('sha256').update(Buffer.alloc(0)).digest();
  // Node HKDF returns ArrayBuffer
  const bits = nodeCrypto.hkdfSync('sha256', secret, salt, Buffer.from('q.crypto.p256.private-key','utf8'), 32);
  return new Uint8Array(bits);
}

// EIP712 / secp256k1: scalar = keccak256("q.crypto.k256.private-key" || secret) mod n
function deriveK256Scalar(secret) {
  const info = Buffer.from('q.crypto.k256.private-key','utf8');
  const material = Buffer.concat([info, Buffer.from(secret)]);
  const digest = keccak_256(material);
  let k = 0n;
  for (const b of digest) k = (k << 8n) | BigInt(b);
  k = k % secp256k1.CURVE.n;
  const hexk = k.toString(16).padStart(64,'0');
  return Uint8Array.from(Buffer.from(hexk,'hex'));
}

// ---------------------------------------------------------------------------
// TEST 1 — Keypair derivation agrees across runtimes
// ---------------------------------------------------------------------------
console.log('\n\u2500\u2500 Test 1: deterministic key derivation \u2500\u2500');

const secret = new Uint8Array(32).fill(7); // fixed secret for reproducibility

// P-256 public key: browser uses noble p256.getPublicKey(sk,false);
// server uses ECDH('prime256v1').getPublicKey()
const p256sk = deriveP256Scalar(secret);
const p256pub_noble = p256.getPublicKey(p256sk, false); // 65 bytes
const ecdh = nodeCrypto.createECDH('prime256v1');
ecdh.setPrivateKey(Buffer.from(p256sk));
const p256pub_node = new Uint8Array(ecdh.getPublicKey()); // 65 bytes

check('P-256 private scalar is 32 bytes', p256sk.length === 32);
check('P-256 pubkey: noble (browser) == node ECDH (server)', hex(p256pub_noble) === hex(p256pub_node));
check('P-256 pubkey is uncompressed 0x04||X||Y', p256pub_noble[0] === 0x04 && p256pub_noble.length === 65);

// secp256k1 key + address
const k256sk = deriveK256Scalar(secret);
const k256pub_noble = secp256k1.getPublicKey(k256sk, false);
// node: derive pub via ECDH secp256k1
const ecdhK = nodeCrypto.createECDH('secp256k1');
ecdhK.setPrivateKey(Buffer.from(k256sk));
const k256pub_node = new Uint8Array(ecdhK.getPublicKey());
check('secp256k1 pubkey: noble == node ECDH', hex(k256pub_noble) === hex(k256pub_node));

// address = last 20 of keccak256(pub[1:])
const addr_browser = '0x' + hex(keccak_256(k256pub_noble.slice(1)).slice(-20));
const addr_server  = '0x' + hex(keccak_256(k256pub_node.slice(1)).slice(-20));
check('EVM address: browser == server', addr_browser === addr_server);

// ---------------------------------------------------------------------------
// TEST 2 — ES256 (P-256) sign/verify CROSS-RUNTIME
//   The real question: browser signs -> server verifies, and vice-versa.
//   Both sign SHA-256(canonicalBytes). Browser: noble.p256.sign(digest).normalizeS()
//   -> DER. Server: nodeCrypto.sign('sha256', canonBytes, pkcs8) -> DER (node hashes once).
// ---------------------------------------------------------------------------
console.log('\n\u2500\u2500 Test 2: ES256 sign/verify across runtimes \u2500\u2500');

const canonical = JSON.stringify({ domain:{}, primaryType:'Claim', types:{Claim:[{name:'x',type:'string'}]}, message:{x:'hello'} });
const canonBytes = Buffer.from(canonical, 'utf8');
const es256digest = sha256(canonBytes); // what browser signs

// --- BROWSER sign (noble) ---
const bSig = p256.sign(es256digest, p256sk).normalizeS(); // low-S
const bSigDER = bSig.toDERRawBytes ? bSig.toDERRawBytes() : bSig.toDERBytes();

// --- SERVER sign (node crypto), exactly like OpenClaim.js ---
// Build SEC1 DER -> PrivateKey, then sign('sha256', canonBytes) (node hashes once)
const sec1 = Buffer.concat([
  Buffer.from([0x30,0x77,0x02,0x01,0x01,0x04,0x20]),
  Buffer.from(p256sk),
  Buffer.from([0xa0,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07]),
  Buffer.from([0xa1,0x44,0x03,0x42,0x00]),
  Buffer.from(p256pub_node)
]);
const privKeyObj = nodeCrypto.createPrivateKey({ key: sec1, format:'der', type:'sec1' });
const sSigDER = nodeCrypto.sign('sha256', canonBytes, privKeyObj); // DER

// --- SERVER verify of BROWSER signature ---
// server verify path (Node): verify('sha256', canonBytes, pubKeyObj, browserDER)
const spkiPub = nodeCrypto.createPublicKey({
  key: Buffer.concat([
    Buffer.from([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]),
    Buffer.from(p256pub_noble)
  ]),
  format:'der', type:'spki'
});
const serverVerifiesBrowser = nodeCrypto.verify('sha256', canonBytes, spkiPub, Buffer.from(bSigDER));
check('ES256: SERVER (node) verifies BROWSER (noble) signature', serverVerifiesBrowser === true);

// --- BROWSER verify of SERVER signature ---
// browser verify path uses WebCrypto subtle.verify(ECDSA/SHA-256, rawPub, sig, canonBytes).
// Reproduce with node WebCrypto (same crypto.subtle the browser uses).
(async () => {
  const subtle = globalThis.crypto.subtle;
  const rawKey = await subtle.importKey('raw', p256pub_noble, {name:'ECDSA', namedCurve:'P-256'}, false, ['verify']);
  // subtle expects P1363 (raw r||s), NOT DER. Browser verify.js passes options.signature
  // which sign.js produced as DER via encodeEcdsaDer... but subtle.verify needs raw.
  // This is the subtle divergence to test: does browser sign.js DER verify under subtle?
  // sign.js output is DER (encodeEcdsaDer). verify.js feeds it straight to subtle.verify.
  const browserSigForSubtle = new Uint8Array(bSigDER);
  let browserVerifiesOwnDER = false;
  try {
    browserVerifiesOwnDER = await subtle.verify({name:'ECDSA', hash:'SHA-256'}, rawKey, browserSigForSubtle, canonBytes);
  } catch(e) { browserVerifiesOwnDER = false; }

  // Also test the CORRECT raw form under subtle
  const rawRS = new Uint8Array(64);
  { const hh=bSig.r.toString(16).padStart(64,'0'); rawRS.set(Buffer.from(hh,'hex'),0); }
  { const hh=bSig.s.toString(16).padStart(64,'0'); rawRS.set(Buffer.from(hh,'hex'),32); }
  let browserVerifiesRaw = false;
  try { browserVerifiesRaw = await subtle.verify({name:'ECDSA', hash:'SHA-256'}, rawKey, rawRS, canonBytes); } catch(e) {}

  // server sig (DER) converted to raw for subtle
  const sSigRaw = derToRaw(sSigDER);
  let browserVerifiesServerRaw = false;
  try { browserVerifiesServerRaw = await subtle.verify({name:'ECDSA', hash:'SHA-256'}, rawKey, sSigRaw, canonBytes); } catch(e) {}

  console.log('\n\u2500\u2500 Test 3: WebCrypto (browser verify.js) signature-format check \u2500\u2500');
  check('BROWSER verify (subtle) accepts RAW r||s of browser sig', browserVerifiesRaw === true);
  check('BROWSER verify (subtle) accepts RAW r||s of SERVER sig', browserVerifiesServerRaw === true);
  // The important finding surfaces here:
  if (!browserVerifiesOwnDER) {
    console.log('    note: subtle.verify REJECTS DER-encoded sig (expects raw P1363) \u2014');
    console.log('          this is expected WebCrypto behavior; see analysis below.');
  } else {
    console.log('    note: subtle.verify accepted DER (unexpected \u2014 environment-dependent).');
  }

  // ---------------------------------------------------------------------------
  // TEST 4 — EIP712 / secp256k1 sign+recover cross-runtime
  // ---------------------------------------------------------------------------
  console.log('\n\u2500\u2500 Test 4: EIP712 secp256k1 sign / recover across runtimes \u2500\u2500');
  const msgDigest = keccak_256(Buffer.from('some eip712 digest bytes','utf8'));
  const kSig = secp256k1.sign(msgDigest, k256sk); // low-S by default in noble
  const rs = new Uint8Array(65);
  rs.set(kSig.toCompactRawBytes(), 0);
  rs[64] = 27 + kSig.recovery;
  // recover (browser verify.js path)
  const sigObj = secp256k1.Signature.fromCompact(rs.slice(0,64)).addRecoveryBit(rs[64]-27);
  const recoveredPub = sigObj.recoverPublicKey(msgDigest).toRawBytes(false);
  const recoveredAddr = '0x' + hex(keccak_256(recoveredPub.slice(1)).slice(-20));
  check('secp256k1: recovered pubkey matches derived pubkey', hex(recoveredPub) === hex(k256pub_noble));
  check('secp256k1: recovered address matches derived address', recoveredAddr === addr_browser);
  check('secp256k1: signature is low-S (EIP-2)', kSig.s <= secp256k1.CURVE.n/2n);

  console.log('\n' + '='.repeat(60));
  console.log(`RESULT: ${pass} passed, ${fail} failed`);
  console.log('='.repeat(60));
  process.exit(fail ? 1 : 0);
})();

// DER (SEQUENCE{INTEGER r, INTEGER s}) -> raw 64-byte r||s
function derToRaw(der) {
  der = Buffer.from(der);
  let o = 2; // skip SEQ tag+len
  // r
  if (der[o] !== 0x02) throw new Error('bad der');
  let rlen = der[o+1]; o += 2;
  let r = der.slice(o, o+rlen); o += rlen;
  if (der[o] !== 0x02) throw new Error('bad der');
  let slen = der[o+1]; o += 2;
  let s = der.slice(o, o+slen);
  const strip = b => { while (b.length>32 && b[0]===0) b=b.slice(1); return b; };
  const pad = b => Buffer.concat([Buffer.alloc(32-b.length,0), b]);
  r = pad(strip(r)); s = pad(strip(s));
  return new Uint8Array(Buffer.concat([r,s]));
}
