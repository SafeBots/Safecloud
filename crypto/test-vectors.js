/**
 * Shared test vectors for the OpenClaiming Messaging extension.
 * Every implementation (JS/Node, JS/browser, PHP) MUST reproduce these
 * byte-for-byte. Run: node test-vectors.js
 */
const M=require('module'); const ol=M._load;
const Q={Config:{get:(k,d)=>d},log:()=>{},Crypto:{OpenClaim:{}}};
M._load=function(r){ if(r==='Q')return Q; return ol.apply(this,arguments); };
const EVM=require('./Crypto/OpenClaim/EVM.js');

let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }

// ── Fixed inputs (never change these) ──
const SALT = '0x' + '2b'.repeat(32);
const URL  = 'https://example.com/ocp-inbox';

console.log('\u2500\u2500 endpointType \u2500\u2500');
const vectors = {};
['https','webhook','p2p'].forEach(p => {
  vectors['endpointType:'+p] = EVM.endpointType(p);
  console.log('  '+p.padEnd(9)+' → '+vectors['endpointType:'+p]);
});
check('https and webhook produce DIFFERENT values (no collision)',
  vectors['endpointType:https'] !== vectors['endpointType:webhook']);
check('case-insensitive: HTTPS == https', EVM.endpointType('HTTPS') === EVM.endpointType('https'));
check('rejects empty protocol', (()=>{ try{EVM.endpointType('');return false;}catch(e){return true;} })());

console.log('\n\u2500\u2500 endpointCommitment \u2500\u2500');
const c1 = EVM.endpointCommitment(URL, SALT);
console.log('  url  = '+URL);
console.log('  salt = '+SALT);
console.log('  →      '+c1);
vectors['commitment'] = c1;
check('deterministic', EVM.endpointCommitment(URL, SALT) === c1);
check('different URL → different commitment',
  EVM.endpointCommitment('https://mallory.evil/inbox', SALT) !== c1);
check('different salt → different commitment',
  EVM.endpointCommitment(URL, '0x'+'3c'.repeat(32)) !== c1);
check('rejects missing salt', (()=>{ try{EVM.endpointCommitment(URL);return false;}catch(e){return true;} })());
check('rejects short salt', (()=>{ try{EVM.endpointCommitment(URL,'0xdead');return false;}catch(e){return true;} })());
check('endpointVerify accepts the true (url,salt)', EVM.endpointVerify(c1, URL, SALT));
check('endpointVerify rejects a wrong url', !EVM.endpointVerify(c1,'https://mallory.evil/inbox',SALT));

console.log('\n\u2500\u2500 Regression: raw strings must be REJECTED, not silently collide \u2500\u2500');
async function mustThrow(label, fn) {
  try { await fn(); check(label, false, 'did NOT throw'); }
  catch (e) { check(label, true); }
}
(async () => {
  const A='0x'+'a1'.repeat(20), C='0x'+'99'.repeat(20);
  await mustThrow('human-readable endpointType is rejected', () =>
    EVM.hashTypedData({account:A,endpointType:'https',commitment:c1,chainId:'eip155:1',contract:C}));
  await mustThrow('human-readable commitment is rejected', () =>
    EVM.hashTypedData({account:A,endpointType:vectors['endpointType:https'],
      commitment:'https://example.com/ocp-inbox',chainId:'eip155:1',contract:C}));
  await mustThrow('garbage paramsHash in Actions is rejected', () =>
    EVM.hashTypedData({authority:A,subject:A,contractAddress:A,method:'0x12345678',
      paramsHash:'not-a-hash',minimum:'0',fraction:'0',delay:'0',nbf:'0',exp:'1',
      chainId:'eip155:1',contract:C}));

  console.log('\n\u2500\u2500 Correct usage produces distinct digests \u2500\u2500');
  const d1 = await EVM.hashTypedData({account:A, endpointType:EVM.endpointType('https'),
    commitment:EVM.endpointCommitment(URL,SALT), chainId:'eip155:1', contract:C});
  const d2 = await EVM.hashTypedData({account:A, endpointType:EVM.endpointType('p2p'),
    commitment:EVM.endpointCommitment(URL,SALT), chainId:'eip155:1', contract:C});
  const d3 = await EVM.hashTypedData({account:A, endpointType:EVM.endpointType('https'),
    commitment:EVM.endpointCommitment('https://mallory.evil/inbox',SALT), chainId:'eip155:1', contract:C});
  const h = r => '0x'+Buffer.from(r.digest).toString('hex');
  console.log('  https + alice  : '+h(d1));
  console.log('  p2p   + alice  : '+h(d2));
  console.log('  https + mallory: '+h(d3));
  check('different protocol → different digest', h(d1)!==h(d2));
  check('different endpoint → different digest', h(d1)!==h(d3));
  vectors['digest:https+alice'] = h(d1);

  console.log('\n\u2500\u2500 VECTORS (PHP and browser must match exactly) \u2500\u2500');
  console.log(JSON.stringify({ salt:SALT, url:URL, ...vectors }, null, 2));
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
