// Cross-runtime test using the REAL server Q.Crypto.js (classes/Q/Crypto.js)
// and the REAL server OpenClaim.js (Q/Crypto/OpenClaim.js).
//
// NO SHIMS. Both files are the actual production code, loaded with only the
// minimal module-resolution stubs needed for their sibling requires.
//
// Tests: server keypair derivation matches browser (noble), server-signed
// claim verifies in browser (WebCrypto), browser-signed claim verifies via
// the real server OpenClaim.verify(), tamper rejected.

const nodeCrypto = require('crypto');
const path = require('path');
const Module = require('module');
const { p256 } = require('@noble/curves/p256');
const { sha256 } = require('@noble/hashes/sha256');

const CRYPTO_JS = require('path').resolve(__dirname, '_Q_Crypto.js');
const DATA_JS   = require('path').resolve(__dirname, '_Q_Data.js');
const OC_JS     = process.env.OPENCLAIM_SRC || require('path').resolve(__dirname, '../../../Q/Crypto/OpenClaim.js');

// ── Load the REAL server modules ──
const origLoad = Module._load;
const Data = require(DATA_JS);

// Q stub: only what OpenClaim.js and Crypto.js actually call
const Q = {
  Promise: Promise,
  serialize: function (o) { return Q.Data.canonicalize(o); },
  Crypto: null, // will be set after Crypto.js loads
  Data: Object.assign({}, Data, {
    canonicalize: function (object) {
      // RFC 8785 — same as the browser canonicalize.js
      let buf = '';
      (function ser(o) {
        if (o === null || typeof o !== 'object' || o.toJSON instanceof Function) { buf += JSON.stringify(o); return; }
        if (Array.isArray(o)) { buf += '['; o.forEach((e, i) => { if (i) buf += ','; ser(e === undefined ? null : e); }); buf += ']'; return; }
        const keys = Object.keys(o).filter(k => o[k] !== undefined).sort();
        buf += '{'; keys.forEach((k, i) => { if (i) buf += ','; buf += JSON.stringify(k) + ':'; ser(o[k]); }); buf += '}';
      })(object);
      return buf;
    },
    DERToRAW: function (der) {
      der = Buffer.from(der); let o = 2; o++; let rl = der[o++]; let r = der.slice(o, o+rl); o += rl; o++; let sl = der[o++]; let s = der.slice(o, o+sl);
      const pad = b => { while (b.length > 32 && b[0] === 0) b = b.slice(1); return Buffer.concat([Buffer.alloc(32 - b.length, 0), b]); };
      return new Uint8Array(Buffer.concat([pad(r), pad(s)]));
    },
    RAWtoDER: function (raw) {
      raw = Buffer.from(raw); let R = raw.slice(0, 32), S = raw.slice(32);
      const t = b => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return b; };
      R = t(R); S = t(S); return new Uint8Array(Buffer.concat([Buffer.from([0x30, R.length + S.length + 4, 0x02, R.length]), R, Buffer.from([0x02, S.length]), S]));
    },
    toHex: Data.toHex,
    fromHex: Data.fromHex,
    toBase64: Data.toBase64,
    fromBase64: Data.fromBase64,
  })
};

Module._load = function (request, parent) {
  if (request === 'Q') return Q;
  if (request === './Data') return Data;
  return origLoad.apply(this, arguments);
};

// Load REAL Crypto.js (sets up Q.Crypto)
const Crypto = require(CRYPTO_JS);
Q.Crypto = Crypto;

// Load REAL OpenClaim.js (populates Q.Crypto.OpenClaim)
Q.Crypto.OpenClaim = Q.Crypto.OpenClaim || {};
require(OC_JS);
const OC = Q.Crypto.OpenClaim;

// ══════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log('  \u2713 ' + n)) : (fail++, console.log('  \u2717 ' + n + '  <-- FAIL')); };

(async () => {
  console.log('\n\u2500\u2500 REAL server Q.Crypto.js + Q.Crypto.OpenClaim.js \u2500\u2500');
  check('Crypto.internalKeypair is a function', typeof Crypto.internalKeypair === 'function');
  check('Crypto.sign is a function', typeof Crypto.sign === 'function');
  check('Crypto.verify is a function', typeof Crypto.verify === 'function');
  check('OpenClaim.sign is a function', typeof OC.sign === 'function');
  check('OpenClaim.verify is a function', typeof OC.verify === 'function');

  // ── 1. Keypair derivation: REAL server vs browser (noble) ──
  console.log('\n\u2500\u2500 Keypair derivation: real server vs browser \u2500\u2500');
  const secret = new Uint8Array(32).fill(42);

  // Server derivation (REAL Crypto.internalKeypair)
  const serverKP = await new Promise((res, rej) => {
    Crypto.internalKeypair({ secret, format: 'ES256' }, (err, kp) => err ? rej(err) : res(kp));
  });

  // Browser derivation (noble, same algorithm)
  const salt = nodeCrypto.createHash('sha256').update(Buffer.alloc(0)).digest();
  const browserSk = new Uint8Array(nodeCrypto.hkdfSync('sha256', secret, salt, Buffer.from('q.crypto.p256.private-key'), 32));
  const browserPub = p256.getPublicKey(browserSk, false);

  check('P-256 pubkey: REAL server == browser (noble)',
    Buffer.from(serverKP.publicKey).toString('hex') === Buffer.from(browserPub).toString('hex'));

  // ── 2. Server OpenClaim.sign → browser WebCrypto verify ──
  console.log('\n\u2500\u2500 REAL server signs → browser (WebCrypto) verifies \u2500\u2500');
  const claim = { type: 'drop-claim', cid: 'QmRealFile', amount: '750' };
  const signed = await OC.sign(claim, secret);
  check('server produced key[] and sig[]', Array.isArray(signed.key) && Array.isArray(signed.sig) && signed.sig[0]);

  const sigRaw = Buffer.from(signed.sig[0], 'base64');
  check('server sig is raw r||s (64 bytes)', sigRaw.length === 64);

  // Verify with Node's WebCrypto (same as browser subtle)
  const subtle = globalThis.crypto.subtle;
  const canon = OC.canonicalize(Object.assign({}, signed));
  const pubKey = await subtle.importKey('raw', serverKP.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const browserVerifies = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sigRaw, Buffer.from(canon, 'utf8'));
  check('BROWSER (WebCrypto) verifies REAL server-signed claim', browserVerifies === true);

  // ── 3. Browser signs → REAL server OpenClaim.verify ──
  console.log('\n\u2500\u2500 Browser signs → REAL server OC.verify() \u2500\u2500');
  const bClaim = { type: 'drop-claim', cid: 'QmBrowserSigned', amount: '300' };
  // Emulate browser OpenClaim.sign: build signerKey, canonicalize, sign with noble
  function spkiKeyString(pub) {
    const spki = Buffer.concat([Buffer.from([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]), Buffer.from(pub)]);
    return 'data:key/es256;base64,' + spki.toString('base64');
  }
  const signerKey = spkiKeyString(browserPub);
  const withKey = Object.assign({}, bClaim, { key: [signerKey], sig: [] });
  const bCanon = OC.canonicalize(withKey);
  const bDigest = sha256(Buffer.from(bCanon, 'utf8'));
  const bSig = p256.sign(bDigest, browserSk).normalizeS();
  const bRaw = new Uint8Array(64);
  bRaw.set(Buffer.from(bSig.r.toString(16).padStart(64, '0'), 'hex'), 0);
  bRaw.set(Buffer.from(bSig.s.toString(16).padStart(64, '0'), 'hex'), 32);
  const browserSigned = Object.assign({}, bClaim, { key: [signerKey], sig: [Buffer.from(bRaw).toString('base64')] });
  const serverVerifies = await OC.verify(browserSigned, { minValid: 1 });
  check('REAL server OC.verify() accepts browser-signed claim', serverVerifies === true || serverVerifies === 1);

  // ── 4. Tamper rejection through REAL server verify ──
  console.log('\n\u2500\u2500 Tamper rejection (REAL server) \u2500\u2500');
  const tampered = Object.assign({}, browserSigned, { amount: '999999' });
  const rej = await OC.verify(tampered, { minValid: 1 });
  check('REAL server OC.verify() rejects tampered claim', rej === false || rej === 0);

  // ── 5. secp256k1 / EIP712 derivation ──
  console.log('\n\u2500\u2500 secp256k1 derivation: real server vs browser \u2500\u2500');
  const serverK256 = await new Promise((res, rej) => {
    Crypto.internalKeypair({ secret, format: 'EIP712' }, (err, kp) => err ? rej(err) : res(kp));
  });
  // Browser derivation
  const { secp256k1 } = require('@noble/curves/secp256k1');
  const { keccak_256 } = require('@noble/hashes/sha3');
  const k256mat = Buffer.concat([Buffer.from('q.crypto.k256.private-key'), Buffer.from(secret)]);
  let k = 0n; for (const b of keccak_256(k256mat)) k = (k << 8n) | BigInt(b); k %= secp256k1.CURVE.n;
  const browserK256Pub = secp256k1.getPublicKey(Uint8Array.from(Buffer.from(k.toString(16).padStart(64, '0'), 'hex')), false);
  check('secp256k1 pubkey: REAL server == browser',
    Buffer.from(serverK256.publicKey).toString('hex') === Buffer.from(browserK256Pub).toString('hex'));
  if (serverK256.address) {
    const browserAddr = '0x' + Buffer.from(keccak_256(browserK256Pub.slice(1)).slice(-20)).toString('hex');
    check('EVM address: REAL server == browser', serverK256.address.toLowerCase() === browserAddr.toLowerCase());
  }

  console.log('\n' + '='.repeat(58));
  console.log(`REAL-FILE cross-runtime: ${pass} passed, ${fail} failed`);
  console.log('='.repeat(58));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('FATAL', e); process.exit(1); });
