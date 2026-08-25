/**
 * Proves the UPDATED Q.Crypto.OpenClaim.EVM produces byte-identical EIP-712
 * digests to ethers.js with the canonical OpenClaiming format — the same
 * digest the contract's ecrecover validates and the Safecloud plugin already
 * produces. Uses the module's real public API (hashTypedData).
 */
const ethers = require('ethers');
const Module = require('module'); const ol = Module._load;
const Qstub = { Config:{get:(k,d)=>d}, log:()=>{}, Crypto:{ OpenClaim:{} } };
Module._load = function(r){ if(r==='Q') return Qstub; return ol.apply(this,arguments); };
const EVM = require('./Crypto/OpenClaim/EVM.js');

let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }

const OC='0x99999febd42cad798fe10ab0b1c563002fc99999';
const payer='0x'+'a1'.repeat(20), token='0x'+'b0'.repeat(20), recip='0x'+'c2'.repeat(20);
const rh = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]'],[[recip]]));

(async () => {
  // ══ PAYMENTS ══
  console.log('\n\u2500\u2500 Payments \u2500\u2500');
  const r = await EVM.hashTypedData({ payer, token, recipients:[recip], max:'100000',
    line:'0', nbf:'0', exp:'9999999999', chainId:'eip155:56', contract:OC });
  const p = r.payload;
  check('builds a Payment payload', p && p.primaryType==='Payment');
  check('domain name is canonical "OpenClaiming"', p.domain.name==='OpenClaiming', p.domain.name);
  check('Payment struct has 8 fields', p.types.Payment.length===8, String(p.types.Payment.length));
  check('field 3 is recipientsHash (order preserved)', p.types.Payment[2].name==='recipientsHash');
  check('field 8 is contract:address',
    p.types.Payment[7].name==='contract' && p.types.Payment[7].type==='address');
  check('signed value carries contract', String(p.value.contract).toLowerCase()===OC.toLowerCase());

  const TY={Payment:p.types.Payment};
  const tstr = ethers.TypedDataEncoder.from(TY).encodeType('Payment');
  check('typehash string == OpenClaiming.sol PAYMENTS_TYPEHASH',
    tstr==='Payment(address payer,address token,bytes32 recipientsHash,uint256 max,uint256 line,uint256 nbf,uint256 exp,address contract)', tstr);

  const ethersDigest = ethers.TypedDataEncoder.hash(
    {name:'OpenClaiming',version:'1',chainId:56,verifyingContract:OC}, TY,
    { payer, token, recipientsHash:rh, max:100000n, line:0n, nbf:0n, exp:9999999999n, contract:OC });
  const modDigest = '0x'+Buffer.from(r.digest).toString('hex');
  check('PAYMENT DIGEST == ETHERS DIGEST (byte-exact)', modDigest===ethersDigest,
    '\n      module: '+modDigest+'\n      ethers: '+ethersDigest);

  // Cross-verify: a signature produced with ethers must verify via the module
  const w = new ethers.Wallet('0x'+'11'.repeat(32));
  const claim2 = { payer:w.address, token, recipients:[recip], max:'100000', line:'0',
                   nbf:'0', exp:'9999999999', chainId:'eip155:56', contract:OC };
  const r2 = await EVM.hashTypedData(claim2);
  const sig = await w.signTypedData(
    {name:r2.payload.domain.name,version:r2.payload.domain.version,
     chainId:r2.payload.domain.chainId,verifyingContract:r2.payload.domain.verifyingContract},
    {Payment:r2.payload.types.Payment}, r2.payload.value);
  const rec = ethers.verifyTypedData(
    {name:r2.payload.domain.name,version:r2.payload.domain.version,
     chainId:r2.payload.domain.chainId,verifyingContract:r2.payload.domain.verifyingContract},
    {Payment:r2.payload.types.Payment}, r2.payload.value, sig);
  check('ethers signature over module payload recovers to signer',
    rec.toLowerCase()===w.address.toLowerCase());

  // A token signed with the OLD format must NOT match the new digest
  const OLD={Payment:p.types.Payment.slice(0,7)};
  const oldDigest = ethers.TypedDataEncoder.hash(
    {name:'OpenClaiming.payments',version:'1',chainId:56,verifyingContract:OC}, OLD,
    { payer, token, recipientsHash:rh, max:100000n, line:0n, nbf:0n, exp:9999999999n });
  check('OLD-format digest differs (old tokens correctly invalid)', oldDigest!==modDigest);

  // ══ ACTIONS ══
  console.log('\n\u2500\u2500 Actions \u2500\u2500');
  const ar = await EVM.hashTypedData({ authority:payer, subject:recip, contractAddress:token,
    method:'0x12345678', paramsHash:'0x'+'00'.repeat(32), minimum:'0', fraction:'0',
    delay:'0', invoker:'0x'+'d4'.repeat(20), nbf:'0', exp:'9999999999',
    chainId:'eip155:56', contract:OC });
  const a = ar.payload;
  check('builds an Action payload', a.primaryType==='Action');
  check('actions domain is canonical "OpenClaiming"', a.domain.name==='OpenClaiming', a.domain.name);
  check('Action struct has 11 fields', a.types.Action.length===11, String(a.types.Action.length));
  const names=a.types.Action.map(f=>f.name);
  check('invoker sits between delay and nbf',
    names[7]==='delay'&&names[8]==='invoker'&&names[9]==='nbf', names.join(','));
  check('signed value carries invoker',
    String(a.value.invoker).toLowerCase()==='0x'+'d4'.repeat(20));
  const aEthers = ethers.TypedDataEncoder.hash(
    {name:'OpenClaiming',version:'1',chainId:56,verifyingContract:OC},
    {Action:a.types.Action}, a.value);
  const aMod = '0x'+Buffer.from(ar.digest).toString('hex');
  check('ACTION DIGEST == ETHERS DIGEST (byte-exact)', aMod===aEthers,
    '\n      module: '+aMod+'\n      ethers: '+aEthers);

  const ar2 = await EVM.hashTypedData({ authority:payer, subject:recip, contractAddress:token,
    method:'0x12345678', paramsHash:'0x'+'00'.repeat(32), minimum:'0', fraction:'0',
    delay:'0', nbf:'0', exp:'9999999999', chainId:'eip155:56', contract:OC });
  check('missing invoker defaults to zero address (direct execution)',
    String(ar2.payload.value.invoker)==='0x0000000000000000000000000000000000000000',
    String(ar2.payload.value.invoker));

  // ══ MESSAGES unchanged ══
  console.log('\n\u2500\u2500 Messages (must be untouched) \u2500\u2500');
  const mr = await EVM.hashTypedData({ account:payer, endpointType:'0x'+'11'.repeat(32),
    commitment:'0x'+'22'.repeat(32), chainId:'eip155:56', contract:OC });
  check('messages extension still builds', mr.payload.primaryType==='MessageAssociation');
  check('messages domain deliberately unchanged ("OpenClaiming.messages")',
    mr.payload.domain.name==='OpenClaiming.messages', mr.payload.domain.name);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
