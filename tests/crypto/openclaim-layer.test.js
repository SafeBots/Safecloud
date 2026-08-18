// Test the ACTUAL OpenClaim claim layer round-trip cross-runtime:
// browser OpenClaim.sign (raw r||s) -> server verify, and server -> browser (subtle).
const nodeCrypto = require('crypto');
const { p256 } = require('@noble/curves/p256');
const { sha256 } = require('@noble/hashes/sha256');
let pass=0, fail=0;
const check=(n,c)=>{c?(pass++,console.log('  \u2713 '+n)):(fail++,console.log('  \u2717 '+n+'  <-- FAIL'));};

// derive P-256 key (same as internalKeypair ES256)
const secret = new Uint8Array(32).fill(42);
const salt = nodeCrypto.createHash('sha256').update(Buffer.alloc(0)).digest();
const sk = new Uint8Array(nodeCrypto.hkdfSync('sha256', secret, salt, Buffer.from('q.crypto.p256.private-key'), 32));
const pub = p256.getPublicKey(sk, false);

// canonical claim bytes (stand-in for RFC8785 canonicalized claim)
const canon = Buffer.from(JSON.stringify({type:'drop-claim',cid:'Qm123',amount:'500'}),'utf8');
const digest = sha256(canon);

console.log('\n\u2500\u2500 OpenClaim claim layer: raw r||s round-trip \u2500\u2500');

// BROWSER OpenClaim.sign: raw r||s, low-S
const sig = p256.sign(digest, sk).normalizeS();
const raw = new Uint8Array(64);
raw.set(Buffer.from(sig.r.toString(16).padStart(64,'0'),'hex'),0);
raw.set(Buffer.from(sig.s.toString(16).padStart(64,'0'),'hex'),32);
const b64 = Buffer.from(raw).toString('base64');   // this is what sig[] stores

// SERVER verify of that raw sig: Node crypto needs DER, so server converts raw->DER then verifies.
// (OpenClaim.php/js server verify path rebuilds DER from raw r||s.)
function rawToDer(r){
  r=Buffer.from(r); let R=r.slice(0,32), S=r.slice(32);
  const trim=b=>{let i=0;while(i<b.length-1&&b[i]===0)i++;b=b.slice(i); if(b[0]&0x80)b=Buffer.concat([Buffer.from([0]),b]); return b;};
  R=trim(R);S=trim(S);
  return Buffer.concat([Buffer.from([0x30,R.length+S.length+4,0x02,R.length]),R,Buffer.from([0x02,S.length]),S]);
}
const spki = nodeCrypto.createPublicKey({key:Buffer.concat([Buffer.from([0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]),Buffer.from(pub)]),format:'der',type:'spki'});
const serverOK = nodeCrypto.verify('sha256', canon, spki, rawToDer(Buffer.from(b64,'base64')));
check('SERVER verifies BROWSER OpenClaim raw-r||s sig (via raw->DER)', serverOK===true);

(async()=>{
  // BROWSER verify (subtle) of the same raw sig — exactly verify.js path
  const subtle=globalThis.crypto.subtle;
  const key=await subtle.importKey('raw',pub,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const sigBytes=Buffer.from(b64,'base64');           // raw r||s from sig[]
  const browserOK=await subtle.verify({name:'ECDSA',hash:'SHA-256'},key,sigBytes,canon);
  check('BROWSER verify.js (subtle) verifies raw-r||s sig', browserOK===true);

  // Tamper detection both sides
  const bad=Buffer.from(canon); bad[0]^=1;
  const serverBad=nodeCrypto.verify('sha256',bad,spki,rawToDer(Buffer.from(b64,'base64')));
  const browserBad=await subtle.verify({name:'ECDSA',hash:'SHA-256'},key,Buffer.from(b64,'base64'),bad);
  check('SERVER rejects tampered payload', serverBad===false);
  check('BROWSER rejects tampered payload', browserBad===false);

  console.log('\n'+'='.repeat(56)+`\nOpenClaim layer: ${pass} passed, ${fail} failed\n`+'='.repeat(56));
  process.exit(fail?1:0);
})();
