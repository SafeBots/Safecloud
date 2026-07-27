/**
 * REAL socket handlers from the shipped Jets.js, driven over a genuine
 * socket.io connection. Users.Socket.listen is wired to a real socket.io
 * server so Jets.listen() registers its ACTUAL handlers, then real clients
 * exercise: drop/register, drop/announce, drop/disconnect,
 * drop/claimPayments, subtree/put, subtree/get, jet/info, chunk/challenge.
 *
 * This is the largest previously-unexecuted surface in the codebase.
 */
const http=require('http'), express=require('express'), path=require('path');
const { Server } = require('socket.io');
const { io } = require('socket.io-client');
const ethers=require('ethers');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const configStore={Safecloud:{requirePayment:false,requireGrants:false,
  jet:{privateKey:'0x'+'ce'.repeat(32)},safebux:{perChunkWei:'0'},
  drop:{offlineGraceMs:100000}}};
const app=express();
const httpServer=http.createServer(app);
const ioServer=new Server(httpServer);
const realServer={attached:{express:app}};

const Q={Config:{get:(k,d)=>{let o=configStore;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;},set:()=>{}},
 log:()=>{},extend:Object.assign,getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
 makeEventEmitter:(o)=>{const ls={};o.on=(e,f)=>{(ls[e]=ls[e]||[]).push(f);};o.emit=(e,...a)=>{(ls[e]||[]).forEach(f=>f(...a));};},
 listen:()=>realServer,
 // THE KEY: hand Jets.listen() a REAL socket.io server
 require:(n)=>{ if(n==='Users') return { Socket:{ listen:()=>({ io: ioServer }) } };
                if(n==='Streams') throw new Error('no Streams');
                throw new Error('no '+n); },
 app:{DIR:'/tmp/sc'},
 Crypto:{ OpenClaim:{ verify: async()=>true } },
 Data:{}, Assets:{}, Socket:{}, Safecloud:{}};
const M=require('module'); const ol=M._load;
M._load=function(r){ if(r==='Q')return Q;
 if(r==='./Client')return{ verifyGrant: async()=>true };
 if(r==='./Drops')return{ verifyChallengeResponse:()=>true, verifyAnnounce:()=>true };
 if(r==='./JetSwarm')return{ init:async()=>{}, stats:()=>({peerCount:0}),
   announceRanges:()=>{}, fetchChunks:async()=>({chunks:[]}) };
 return ol.apply(this,arguments); };
const Jets=require(path.join(process.cwd(),'classes/Safecloud/Jets.js'));
Jets.listen({});   // registers REAL handlers on the real socket.io server

// Stub only the outbound leg to Drops (no browser here)
let dropReply = { chunks: [] };
Jets.callDrop = () => Promise.resolve(dropReply);

const drop = new ethers.Wallet('0x'+'d0'.repeat(32));
const drop2 = new ethers.Wallet('0x'+'d1'.repeat(32));

(async () => {
  await new Promise(r=>httpServer.listen(0,r));
  const url=`http://localhost:${httpServer.address().port}/Safecloud/cloud`;
  const connect=()=>new Promise(r=>{const c=io(url,{transports:['websocket'],forceNew:true});c.on('connect',()=>r(c));});
  const emit=(c,ev,p)=>new Promise(r=>{ let done=false;
    const t=setTimeout(()=>{ if(!done){done=true;r({timeout:true});} }, 5000);
    c.emit(ev,p,(err,res)=>{ if(!done){done=true;clearTimeout(t);r({err,res});} }); });

  // ══ jet/info ══
  section('Safecloud/jet/info (real handler)');
  const c1 = await connect();
  const info = await emit(c1,'Safecloud/jet/info',{});
  check('jet/info responds', !info.timeout && !!info.res, JSON.stringify(info).slice(0,80));
  check('jet/info reports requirePayment', info.res && info.res.requirePayment===false);
  check('jet/info includes safebux + openclaiming blocks',
    info.res && !!info.res.safebux && !!info.res.openclaiming);
  check('jet/info does NOT leak the private key',
    JSON.stringify(info.res).indexOf('ce'.repeat(32))===-1);

  // ══ drop/register ══
  section('Safecloud/drop/register (real handler)');
  const bad = await emit(c1,'Safecloud/drop/register',{});
  check('register without dropId errors (BadRequest)', bad.err && bad.err.error.code==='BadRequest');

  const reg = await emit(c1,'Safecloud/drop/register',
    { dropId:'d1', evmAddress:drop.address, storage:{GB:5}, prollyRoot:'root-a' });
  check('valid registration succeeds', !reg.timeout && reg.res && reg.res.dropId==='d1', JSON.stringify(reg).slice(0,90));
  check('first registration reports cold:true', reg.res && reg.res.cold===true);
  check('Jet registry now holds the Drop', !!Jets.drops.d1);
  check('registered Drop has a sanitized numeric price',
    /^[0-9]+$/.test(String(Jets.drops.d1.minPerChunkWei)), String(Jets.drops.d1.minPerChunkWei));

  // REGRESSION (bug 1): hostile price must not poison the registry
  const c2 = await connect();
  const evil = await emit(c2,'Safecloud/drop/register',
    { dropId:'evil', evmAddress:drop2.address, minPerChunkWei:'"; DROP TABLE;--' });
  check('Drop with hostile minPerChunkWei still registers', evil.res && evil.res.dropId==='evil');
  check('hostile price was sanitized to a numeric string',
    /^[0-9]+$/.test(String(Jets.drops.evil.minPerChunkWei)), String(Jets.drops.evil.minPerChunkWei));
  const sel = await Jets.selectDrops(['cid1'],{});
  check('routing still works with a hostile Drop registered (no DoS)', Array.isArray(sel));

  // ══ drop/announce ══
  section('Safecloud/drop/announce (real handler)');
  const annUnknown = await emit(c1,'Safecloud/drop/announce',{ dropId:'nope' });
  check('announce for unknown Drop → NotFound', annUnknown.err && annUnknown.err.error.code==='NotFound');

  const annSpoof = await emit(c2,'Safecloud/drop/announce',{ dropId:'d1', prollyRoot:'evil' });
  check('announce from non-owning socket → Unauthorized',
    annSpoof.err && annSpoof.err.error.code==='Unauthorized');

  const annOk = await emit(c1,'Safecloud/drop/announce',{ dropId:'d1', prollyRoot:'root-b', storage:{GB:9} });
  check('announce from owning socket accepted', !annOk.timeout && !annOk.err);
  check('announce updated the Drop record', Jets.drops.d1.storage.GB===9);

  const annReset = await emit(c1,'Safecloud/drop/announce',{ dropId:'d1', reason:'reset' });
  check('announce reason:reset clears prollyRoot', !annReset.err && Jets.drops.d1.prollyRoot===null);

  // Malformed announce payloads must not crash
  for (const p of [{dropId:'d1',storage:null},{dropId:'d1',used:'abc'},{dropId:'d1',bloomFilter:'!!notb64'},{dropId:'d1',diff:'nope'}]) {
    const r = await emit(c1,'Safecloud/drop/announce',p);
    check('malformed announce survives: '+JSON.stringify(p).slice(0,34), !r.timeout);
  }

  // ══ subtree/put then subtree/get ══
  section('Safecloud/subtree/put + get (real handlers)');
  dropReply = { results:[{cid:'c1',stored:true}] };
  const putR = await emit(c1,'Safecloud/subtree/put',
    { rootCid:'r1', link:['track','data'], chunks:[{cid:'c1'},{cid:'c2'}], treeN:2, treeDepth:1 });
  check('subtree/put succeeds', !putR.timeout && putR.res && Array.isArray(putR.res.results),
    JSON.stringify(putR).slice(0,90));

  dropReply = { chunks:[{cid:'c1',ciphertext:'AAA=',tag:'BBB='},{cid:'c2',ciphertext:'CCC=',tag:'DDD='}] };
  const getR = await emit(c1,'Safecloud/subtree/get',
    { rootCid:'r1', link:['track','data'] });
  check('subtree/get returns chunks', !getR.timeout && getR.res && getR.res.chunks && getR.res.chunks.length>0,
    JSON.stringify(getR).slice(0,100));

  const getMissing = await emit(c1,'Safecloud/subtree/get',{ link:['track','data'] });
  check('subtree/get without rootCid → BadRequest', getMissing.err && getMissing.err.error.code==='BadRequest');

  const getUnknown = await emit(c1,'Safecloud/subtree/get',{ rootCid:'never-uploaded', link:['track','data'] });
  check('subtree/get for unknown rootCid → NotFound', getUnknown.err && getUnknown.err.error.code==='NotFound');

  // Hostile get payloads
  for (const p of [{rootCid:'r1',link:null},{rootCid:'r1',link:['track','data','abc']},
                   {rootCid:'r1',link:['track','data','999']},{rootCid:'r1',grants:'notarray'},
                   {rootCid:'r1',payments:'notarray'},{rootCid:{obj:1}}]) {
    const r = await emit(c1,'Safecloud/subtree/get',p);
    check('hostile subtree/get survives: '+JSON.stringify(p).slice(0,36), !r.timeout);
  }

  // ══ drop/claimPayments ══
  section('Safecloud/drop/claimPayments (real handler)');
  const claimNoDrop = await emit(c1,'Safecloud/drop/claimPayments',{ dropId:'ghost' });
  check('claim for unregistered Drop → NotFound', claimNoDrop.err && claimNoDrop.err.error.code==='NotFound');

  const claimEmpty = await emit(c1,'Safecloud/drop/claimPayments',{ dropId:'d1', paymentTokens:[] });
  check('claim with no tokens returns cleanly (no tokens)',
    !claimEmpty.timeout && claimEmpty.res && claimEmpty.res.txHash===null);

  const claimSpoof = await emit(c2,'Safecloud/drop/claimPayments',{ dropId:'d1', paymentTokens:[{}] });
  check('claim from non-owning socket → Unauthorized',
    claimSpoof.err && claimSpoof.err.error.code==='Unauthorized');

  const claimJunk = await emit(c1,'Safecloud/drop/claimPayments',
    { dropId:'d1', paymentTokens:[null,{},{stm:null},{stm:{},sig:[]}], nonce:'abc' });
  check('claim with junk tokens does not hang or crash', !claimJunk.timeout);

  // ══ chunk/challenge ══
  section('Safecloud/chunk/challenge (real handler)');
  const chNo = await emit(c1,'Safecloud/chunk/challenge',{});
  check('challenge without cid → BadRequest', chNo.err && chNo.err.error.code==='BadRequest');
  dropReply = { cid:'c1', ciphertext:'AAA=' };
  const ch = await emit(c1,'Safecloud/chunk/challenge',{ cid:'c1' });
  check('challenge with cid responds', !ch.timeout);

  // ══ disconnect lifecycle ══
  section('Drop disconnect lifecycle (real handler)');
  const discSpoof = await emit(c2,'Safecloud/drop/disconnect',{ dropId:'d1' });
  check('disconnect from non-owning socket → Unauthorized',
    discSpoof.err && discSpoof.err.error.code==='Unauthorized');
  check('Drop still registered after spoofed disconnect', !!Jets.drops.d1);

  const disc = await emit(c1,'Safecloud/drop/disconnect',{ dropId:'d1' });
  check('owning socket may disconnect its Drop', !disc.err);
  check('Drop removed from registry', !Jets.drops.d1);

  // Transport-level disconnect marks offline (grace period), not eviction
  const c3 = await connect();
  await emit(c3,'Safecloud/drop/register',{ dropId:'d3', evmAddress:drop.address });
  check('d3 registered', !!Jets.drops.d3);
  c3.close();
  await new Promise(r=>setTimeout(r,300));
  check('transport drop marks offlineSince (grace), does not evict immediately',
    Jets.drops.d3 && Jets.drops.d3.offlineSince !== null);

  c1.close(); c2.close();
  ioServer.close(); httpServer.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  setTimeout(()=>process.exit(fail?1:0), 200);
})();
