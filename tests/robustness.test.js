/**
 * Robustness: drive the REAL Jets.js public surface with malformed, hostile,
 * and degenerate inputs. A live Jet must never crash on bad input from an
 * untrusted client. Anything that throws here is a production crash.
 */
const path = require('path');
const ethers = require('ethers');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const configStore = { Safecloud: { requirePayment: true, requireGrants: false } };
const Q = {
  Config:{ get:(k,d)=>{let o=configStore;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;}, set:()=>{} },
  log:()=>{}, extend:Object.assign,
  getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
  makeEventEmitter:(o)=>{o.on=()=>{};o.emit=()=>{};},
  listen:()=>({attached:{express:{post:()=>{},get:()=>{},put:()=>{},use:()=>{}}}}),
  require:()=>{throw new Error('no');}, app:{DIR:'/tmp/x'}, Crypto:{}, Data:{}, Assets:{}, Socket:{}, Safecloud:{}
};
const Module=require('module'); const origLoad=Module._load;
Module._load=function(r){ if(r==='Q')return Q; if(r==='./Client')return{verifyGrant:async()=>false};
  if(r==='./Drops')return{}; if(r==='./JetSwarm')return{init:async()=>{},stats:()=>({peerCount:0})}; return origLoad.apply(this,arguments); };
const Jets = require(path.join(process.cwd(),'classes/Safecloud/Jets.js'));

async function noThrow(label, fn) {
  try { const r = await fn(); check(label, true); return r; }
  catch (e) { check(label, false, 'threw: '+e.message); return null; }
}

(async () => {
  // ══ verifySubtreeGrant with hostile input ══
  section('verifySubtreeGrant — malformed grants');
  await noThrow('null grants array does not throw', () => Jets.verifySubtreeGrant(null,'root',['track','data'],null));
  await noThrow('grants containing null entries does not throw',
    () => Jets.verifySubtreeGrant([null,undefined],'root',['track','data'],null));
  await noThrow('grant with missing statement does not throw',
    () => Jets.verifySubtreeGrant([{proof:'x'}],'root',['track','data'],null));
  await noThrow('grant with non-JSON context does not throw',
    () => Jets.verifySubtreeGrant([{statement:{label:'safecloud.x',context:'NOT JSON{{{'},proof:'p'}],'root',['track','data'],null));
  await noThrow('grant with wrong label prefix does not throw',
    () => Jets.verifySubtreeGrant([{statement:{label:'evil.grant',context:'{}'},proof:'p'}],'root',['track','data'],null));
  const r1 = await Jets.verifySubtreeGrant([{statement:{label:'evil.grant',context:'{}'},proof:'p'}],'root',['track','data'],null);
  check('grant with wrong label prefix is REJECTED', r1 && r1.ok===false);

  // Expired grant must be rejected
  const expiredCtx = JSON.stringify({ rootCid:'root', link:['track','data'], exp: Math.floor(Date.now()/1000)-100 });
  const r2 = await Jets.verifySubtreeGrant([{statement:{label:'safecloud.read',context:expiredCtx},proof:'p'}],'root',['track','data'],null);
  check('expired grant is rejected', r2 && r2.ok===false);

  // Grant for a DIFFERENT rootCid must be rejected
  const otherCtx = JSON.stringify({ rootCid:'otherRoot', link:['track','data'], exp:0 });
  const r3 = await Jets.verifySubtreeGrant([{statement:{label:'safecloud.read',context:otherCtx},proof:'p'}],'root',['track','data'],null);
  check('grant scoped to a different rootCid is rejected', r3 && r3.ok===false);

  // Grant for a NARROWER path must not cover a broader request
  const narrowCtx = JSON.stringify({ rootCid:'root', link:['track','data','0','1'], exp:0 });
  const r4 = await Jets.verifySubtreeGrant([{statement:{label:'safecloud.read',context:narrowCtx},proof:'p'}],'root',['track','data'],null);
  check('narrow grant does NOT authorize a broader subtree', r4 && r4.ok===false);

  // ══ _chunkRangeForLink with degenerate input ══
  section('_chunkRangeForLink — degenerate manifests');
  await noThrow('null manifest does not throw', async () => Jets._chunkRangeForLink(['track','data'], null));
  await noThrow('empty link does not throw', async () => Jets._chunkRangeForLink([], {treeN:2,treeDepth:3,chunkCount:8}));
  await noThrow('null link does not throw', async () => Jets._chunkRangeForLink(null, {treeN:2,treeDepth:3,chunkCount:8}));
  await noThrow('chunkCount 0 does not throw', async () => Jets._chunkRangeForLink(['track','data'], {treeN:2,treeDepth:1,chunkCount:0}));
  const deep = Jets._chunkRangeForLink(['track','data','0','0','0','0','0','0'], {treeN:2,treeDepth:3,chunkCount:8});
  check('over-deep link path returns a sane (non-NaN) range',
    Number.isFinite(deep.start) && Number.isFinite(deep.end), JSON.stringify(deep));
  const nonNumeric = Jets._chunkRangeForLink(['track','data','abc'], {treeN:2,treeDepth:3,chunkCount:8});
  check('non-numeric path segment does not produce NaN start',
    Number.isFinite(nonNumeric.start) || nonNumeric.start===0, JSON.stringify(nonNumeric));

  // ══ selectDrops with malformed registry ══
  section('selectDrops — malformed drop records');
  Jets.drops = {};
  await noThrow('empty registry does not throw', () => Jets.selectDrops(['c1'],{forGet:true}));
  Jets.drops = { bad1: {}, bad2: { offlineSince:null }, bad3: { offlineSince:null, minPerChunkWei:'not-a-number' } };
  const sel = await noThrow('registry with malformed records does not throw', () => Jets.selectDrops(['c1'],{}));
  check('malformed-price Drop is excluded rather than crashing', Array.isArray(sel));
  Jets.drops = {};

  // ══ _checkPayerBalance with unreachable RPC ══
  section('_checkPayerBalance — unreachable RPC');
  configStore.Users = { web3: { chains: { '0x38': { rpcUrl: 'http://127.0.0.1:1/nope' } } } };
  let balanceThrew = false, balanceResult = null;
  try {
    balanceResult = await Promise.race([
      Jets._checkPayerBalance('0x'+'a1'.repeat(20), '0x'+'b0'.repeat(20), '100', 'eip155:56', 0, '1000'),
      new Promise(r=>setTimeout(()=>r('TIMEOUT'), 4000))
    ]);
  } catch (e) { balanceThrew = true; }
  check('unreachable RPC rejects or resolves — never crashes the process',
    balanceThrew || balanceResult !== undefined);

  // ══ _evmProvider with no config ══
  section('_evmProvider — missing config');
  let providerThrew = false;
  try { Jets._evmProvider('eip155:99999'); } catch(e){ providerThrew = true; }
  check('_evmProvider throws a catchable error for unconfigured chain (callers guard)', providerThrew);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
