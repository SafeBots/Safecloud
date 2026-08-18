// Loads the REAL server OpenClaim.js and drives it through a faithful Q shim,
// then cross-verifies against the browser modules' documented algorithms.
const nodeCrypto = require('crypto');
const path = require('path');
const Module = require('module');
const { p256 } = require('@noble/curves/p256');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { sha256 } = require('@noble/hashes/sha256');
const { keccak_256 } = require('@noble/hashes/sha3');

// Point at the server OpenClaim.js; override with OPENCLAIM_SRC env var.
const SRC = process.env.OPENCLAIM_SRC || require('path').resolve(__dirname, '../../../Q/Crypto/OpenClaim.js');

// ---- RFC 8785 canonicalize (ported from Data/canonicalize.js) ----
function canonicalize(object){
  let buffer='';
  (function ser(o){
    if(o===null||typeof o!=='object'||o.toJSON instanceof Function){
      if(typeof o==='number'&&!isFinite(o)) throw new Error('non-finite');
      buffer+=JSON.stringify(o); return;
    }
    if(Array.isArray(o)){ buffer+='['; o.forEach((e,i)=>{if(i)buffer+=',';ser(e===undefined?null:e);}); buffer+=']'; return; }
    const keys=Object.keys(o).filter(k=>o[k]!==undefined).sort();
    buffer+='{'; keys.forEach((k,i)=>{if(i)buffer+=',';buffer+=JSON.stringify(k)+':';ser(o[k]);}); buffer+='}';
  })(object);
  return buffer;
}
function derToRaw(der){der=Buffer.from(der);let o=2;o++;let rl=der[o++];let r=der.slice(o,o+rl);o+=rl;o++;let sl=der[o++];let s=der.slice(o,o+sl);const pad=b=>{while(b.length>32&&b[0]===0)b=b.slice(1);return Buffer.concat([Buffer.alloc(32-b.length,0),b]);};return Buffer.concat([pad(r),pad(s)]);}
function rawToDer(raw){raw=Buffer.from(raw);let R=raw.slice(0,32),S=raw.slice(32);const t=b=>{let i=0;while(i<b.length-1&&b[i]===0)i++;b=b.slice(i);if(b[0]&0x80)b=Buffer.concat([Buffer.from([0]),b]);return b;};R=t(R);S=t(S);return Buffer.concat([Buffer.from([0x30,R.length+S.length+4,0x02,R.length]),R,Buffer.from([0x02,S.length]),S]);}

// ---- Faithful Q shim: exactly the functions OpenClaim.js calls ----
const Q = {
  Promise: Promise,
  serialize: (o)=>canonicalize(o),
  Crypto: {},
  Data: {
    canonicalize: (o)=>canonicalize(o),
    DERToRAW: (der)=> new Uint8Array(derToRaw(der)),
    RAWtoDER: (raw)=> new Uint8Array(rawToDer(raw)),
    toHex: (u8)=>Buffer.from(u8).toString('hex'),
    fromHex: (h)=>Uint8Array.from(Buffer.from(h.replace(/^0x/,''),'hex')),
  }
};
// internalKeypair — same derivation as browser internalKeypair.js
Q.Crypto.internalKeypair = function({secret, format}){
  return new Promise((resolve)=>{
    if(format==='ES256'){
      const salt=nodeCrypto.createHash('sha256').update(Buffer.alloc(0)).digest();
      const sk=new Uint8Array(nodeCrypto.hkdfSync('sha256',secret,salt,Buffer.from('q.crypto.p256.private-key'),32));
      resolve({format:'es256',curve:'p256',hashAlg:'sha256',privateKey:sk,publicKey:p256.getPublicKey(sk,false)});
    } else {
      const material=Buffer.concat([Buffer.from('q.crypto.k256.private-key'),Buffer.from(secret)]);
      let k=0n; for(const b of keccak_256(material)) k=(k<<8n)|BigInt(b); k%=secp256k1.CURVE.n;
      const sk=Uint8Array.from(Buffer.from(k.toString(16).padStart(64,'0'),'hex'));
      const pub=secp256k1.getPublicKey(sk,false);
      const address='0x'+Buffer.from(keccak_256(pub.slice(1)).slice(-20)).toString('hex');
      resolve({format:'eip712',curve:'secp256k1',hashAlg:'keccak256',privateKey:sk,publicKey:pub,address});
    }
  });
};

// Load the REAL OpenClaim.js with our Q injected via require hook
const origResolve = Module._resolveFilename;
Module._resolveFilename = function(request, ...a){
  if(request==='Q') return 'Q_SHIM';
  return origResolve.call(this, request, ...a);
};
const origLoad = Module._load;
Module._load = function(request, ...a){
  if(request==='Q') return Q;
  return origLoad.call(this, request, ...a);
};
require(SRC); // populates Q.Crypto.OpenClaim = {...}
const OC = Q.Crypto.OpenClaim;

// ============================ TESTS ============================
let pass=0, fail=0;
const check=(n,c)=>{c?(pass++,console.log('  \u2713 '+n)):(fail++,console.log('  \u2717 '+n+'  <-- FAIL'));};

(async()=>{
  console.log('\n\u2500\u2500 Loaded REAL server OpenClaim.js \u2500\u2500');
  check('OpenClaim.sign is a function', typeof OC.sign==='function');
  check('OpenClaim.verify is a function', typeof OC.verify==='function');
  check('OpenClaim.canonicalize is a function', typeof OC.canonicalize==='function');

  // 1) SERVER signs a claim (real OpenClaim.sign), BROWSER verifies (subtle, raw r||s)
  console.log('\n\u2500\u2500 Server signs \u2192 browser (WebCrypto) verifies \u2500\u2500');
  const secret = new Uint8Array(32).fill(9);
  const claim = { type:'drop-claim', cid:'QmABC', amount:'500', nbf:0, exp:9999999999 };
  const signed = await OC.sign(claim, secret);
  check('server produced key[] and sig[]', Array.isArray(signed.key) && Array.isArray(signed.sig) && signed.sig[0]);

  // derive expected pubkey to import into subtle
  const kp = await Q.Crypto.internalKeypair({secret, format:'ES256'});
  // reproduce the canonical bytes the server signed: canonicalize(claim + sorted key/sig, sig stripped)
  const canon = OC.canonicalize(Object.assign({}, signed)); // OC.canonicalize strips sig
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey('raw', kp.publicKey, {name:'ECDSA',namedCurve:'P-256'}, false, ['verify']);
  const rawSig = Buffer.from(signed.sig[0], 'base64'); // server stores raw r||s base64
  check('server sig[] is raw r||s (64 bytes)', rawSig.length===64);
  const browserVerifies = await subtle.verify({name:'ECDSA',hash:'SHA-256'}, key, rawSig, Buffer.from(canon,'utf8'));
  check('BROWSER (subtle) verifies SERVER-signed claim', browserVerifies===true);

  // 2) BROWSER signs (noble raw r||s) \u2192 SERVER verifies (real OC.verify)
  console.log('\n\u2500\u2500 Browser signs \u2192 server OC.verify() verifies \u2500\u2500');
  // Build a browser-style signed claim: same canonical bytes, raw r||s low-S, base64
  const bClaim = { type:'drop-claim', cid:'QmXYZ', amount:'250' };
  // emulate browser OpenClaim.sign: need signerKey string = data:key/es256;base64,<SPKI>
  function spkiKeyString(pub){
    const spki = Buffer.concat([Buffer.from([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]),Buffer.from(pub)]);
    return 'data:key/es256;base64,'+spki.toString('base64');
  }
  const signerKey = spkiKeyString(kp.publicKey);
  const withKey = Object.assign({}, bClaim, { key:[signerKey], sig:[] });
  const bCanon = OC.canonicalize(withKey);
  const bDigest = sha256(Buffer.from(bCanon,'utf8'));
  const bSig = p256.sign(bDigest, kp.privateKey).normalizeS();
  const bRaw = new Uint8Array(64);
  bRaw.set(Buffer.from(bSig.r.toString(16).padStart(64,'0'),'hex'),0);
  bRaw.set(Buffer.from(bSig.s.toString(16).padStart(64,'0'),'hex'),32);
  const browserSigned = Object.assign({}, bClaim, { key:[signerKey], sig:[Buffer.from(bRaw).toString('base64')] });
  const serverVerifies = await OC.verify(browserSigned, { minValid:1 });
  check('SERVER OC.verify() accepts BROWSER-signed claim', serverVerifies===true || serverVerifies===1);

  // 3) tamper rejection through the real server verify
  console.log('\n\u2500\u2500 Tamper rejection (real server verify) \u2500\u2500');
  const tampered = Object.assign({}, browserSigned, { amount:'999999' });
  const rej = await OC.verify(tampered, { minValid:1 });
  check('SERVER OC.verify() rejects tampered claim', rej===false || rej===0);

  console.log('\n'+'='.repeat(58)+`\nREAL-FILE cross-runtime: ${pass} passed, ${fail} failed\n`+'='.repeat(58));
  process.exit(fail?1:0);
})().catch(e=>{console.error('FATAL', e); process.exit(1);});
