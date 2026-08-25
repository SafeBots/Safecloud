// Cross-runtime consistency using the LITERAL server files (no shims):
//   classes/Q/Crypto.js, Q/Data.js, Q/Crypto/OpenClaim.js
// Verifies the production Drop path: server signs → browser WebCrypto verifies,
// server verifies its own, tampering rejected. Point SERVER_CLASSES at the dir.
const path = require('path');
const Module = require('module');
const nodeCrypto = require('crypto');

const SERVER = process.env.SERVER_CLASSES ||
  '/home/claude/classes_new/classes';         // dir containing Q/Crypto.js
const XN = path.join(__dirname, 'node_modules');

// redirect the real files' npm deps to this dir's node_modules
const oR = Module._resolveFilename;
Module._resolveFilename = function (req, ...a) {
  if (req === 'crypto-js')          return oR.call(this, path.join(XN, 'crypto-js'), ...a);
  if (req === '@noble/secp256k1')   return oR.call(this, path.join(XN, '@noble/secp256k1'), ...a);
  return oR.call(this, req, ...a);
};

const Crypto = require(path.join(SERVER, 'Q/Crypto.js'));
const Data   = require(path.join(SERVER, 'Q/Data.js'));
const Q = { Crypto, Data, log: () => {} };
Q.Crypto.OpenClaim = Q.Crypto.OpenClaim || {};
const oL = Module._load;
Module._load = function (r, ...a) { if (r === 'Q') return Q; return oL.apply(this, arguments); };
require(path.join(SERVER, 'Q/Crypto/OpenClaim.js'));
const OC = Q.Crypto.OpenClaim;

let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; console.log(`  ${c ? '\u2713' : '\u2717'} ${n}`); };

(async () => {
  console.log('\n\u2500\u2500 LITERAL server files: Q/Crypto.js + OpenClaim.js \u2500\u2500');
  const secret = new Uint8Array(32).fill(9);

  // derivation parity vs browser reproduction
  const kp = await new Promise((res, rej) =>
    Crypto.internalKeypair({ secret, format: 'ES256' }, (e, r) => e ? rej(e) : res(r)));
  const salt = nodeCrypto.createHash('sha256').update(Buffer.alloc(0)).digest();
  const skB = new Uint8Array(nodeCrypto.hkdfSync('sha256', secret, salt, Buffer.from('q.crypto.p256.private-key'), 32));
  const { p256 } = require(path.join(XN, '@noble/curves/p256'));
  ok('P-256 pubkey: real server == browser derivation',
     Buffer.from(kp.publicKey).toString('hex') === Buffer.from(p256.getPublicKey(skB, false)).toString('hex'));

  // production Drop path: server OpenClaim sign → self-verify → tamper reject
  const claim = { type: 'drop-claim', cid: 'QmABC', amount: '500' };
  const signed = await OC.sign(claim, secret);
  ok('server OpenClaim.sign produced raw r||s (64B)', Buffer.from(signed.sig[0], 'base64').length === 64);
  ok('server OpenClaim.verify accepts its own sig', (await OC.verify(signed, { minValid: 1 })) === true);
  ok('server OpenClaim.verify rejects tampering',
     (await OC.verify(Object.assign({}, signed, { amount: '999' }), { minValid: 1 })) === false);

  // cross-runtime: browser WebCrypto verifies the real server signature
  const canon = await OC.canonicalize(Object.assign({}, signed));
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey('raw', kp.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const browserOK = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key,
    Buffer.from(signed.sig[0], 'base64'), Buffer.from(canon, 'utf8'));
  ok('browser WebCrypto verifies REAL-SERVER OpenClaim sig', browserOK === true);

  console.log('\n' + '='.repeat(58));
  console.log(` LITERAL server crypto: ${pass} passed, ${fail} failed`);
  console.log('='.repeat(58));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('FATAL', e.message); process.exit(1); });
