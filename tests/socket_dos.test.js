/**
 * REGRESSION (critical): remote process-kill via socket messages.
 *
 * socket.io calls handlers synchronously — an exception inside one is an
 * UNCAUGHT exception that terminates Node. Before the fix, sending
 * { rootCid:'x', grants:'anystring' } crashed the entire Jet: every Drop
 * disconnected, every viewer's stream died, from one anonymous message.
 *
 * This test fires ~50 process-kill candidates at the real handlers and
 * asserts the Jet is still answering after every single one.
 */
const http=require('http'), express=require('express'), path=require('path');
const { Server } = require('socket.io');
const { io } = require('socket.io-client');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }

const configStore={Safecloud:{requirePayment:false,requireGrants:false,
  jet:{privateKey:'0x'+'ce'.repeat(32)},safebux:{perChunkWei:'0'}}};
const app=express(); const httpServer=http.createServer(app);
const ioServer=new Server(httpServer); const realServer={attached:{express:app}};
const Q={Config:{get:(k,d)=>{let o=configStore;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;},set:()=>{}},
 log:()=>{},extend:Object.assign,getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
 makeEventEmitter:(o)=>{const ls={};o.on=(e,f)=>{(ls[e]=ls[e]||[]).push(f);};o.emit=(e,...a)=>{(ls[e]||[]).forEach(f=>f(...a));};},
 listen:()=>realServer,
 require:(n)=>{ if(n==='Users') return { Socket:{ listen:()=>({ io: ioServer }) } }; throw new Error('no '+n); },
 app:{DIR:'/tmp/sc'}, Crypto:{ OpenClaim:{ verify: async()=>true } }, Data:{}, Assets:{}, Socket:{}, Safecloud:{}};
const M=require('module'); const ol=M._load;
M._load=function(r){ if(r==='Q')return Q; if(r==='./Client')return{verifyGrant:async()=>true};
 if(r==='./Drops')return{verifyChallengeResponse:()=>true,verifyAnnounce:()=>true};
 if(r==='./JetSwarm')return{init:async()=>{},stats:()=>({peerCount:0}),announceRanges:()=>{},fetchChunks:async()=>({chunks:[]})};
 return ol.apply(this,arguments); };
const Jets=require(path.join(process.cwd(),'classes/Safecloud/Jets.js'));
Jets.listen({});
Jets.callDrop = () => Promise.resolve({ chunks:[] });

// If the guard fails, the process dies here — make that a loud failure.
let died = false;
process.on('uncaughtException', (e) => {
  died = true;
  console.log('  \u2717 FATAL: uncaught exception escaped a handler —', e.message);
  console.log('\n0 passed, 1 failed (PROCESS WOULD HAVE DIED)');
  process.exit(1);
});

(async () => {
  await new Promise(r=>httpServer.listen(0,r));
  const url=`http://localhost:${httpServer.address().port}/Safecloud/cloud`;
  const connect=()=>new Promise(r=>{const c=io(url,{transports:['websocket'],forceNew:true});c.on('connect',()=>r(c));});
  const emit=(c,ev,p)=>new Promise(r=>{ let done=false;
    const t=setTimeout(()=>{if(!done){done=true;r({timeout:true});}},4000);
    try { c.emit(ev,p,(err,res)=>{ if(!done){done=true;clearTimeout(t);r({err,res});} }); }
    catch(e){ if(!done){done=true;clearTimeout(t);r({clientErr:e.message});} } });

  const c = await connect();
  const alive = async () => { const r = await emit(c,'Safecloud/jet/info',{}); return !r.timeout && !!r.res; };
  check('Jet answering before the attack', await alive());

  // Payload shapes designed to hit .filter/.map/.length/.slice/property access
  // on values that are not what the handler expects.
  const nasty = [ 'string', 12345, true, null, [], {}, {length:5}, {length:'x'},
    'a'.repeat(10000), {toString(){throw new Error('boom');}},
    {valueOf(){throw new Error('boom');}}, [null], [undefined], [[[[[]]]]] ];

  const events = ['Safecloud/subtree/get','Safecloud/subtree/put','Safecloud/drop/register',
    'Safecloud/drop/announce','Safecloud/drop/disconnect','Safecloud/drop/claimPayments',
    'Safecloud/chunk/challenge','Safecloud/jet/info','Safecloud/content/registerFragment'];

  // 1. Array-typed fields given non-array values (the actual crash vector)
  let survived = 0, attempted = 0;
  for (const v of nasty) {
    for (const field of ['grants','payments','chunks','link']) {
      const p = { rootCid:'r1' }; p[field] = v;
      attempted++;
      const r = await emit(c,'Safecloud/subtree/get',p);
      if (!r.timeout) survived++;
    }
  }
  check(`subtree/get survived all ${attempted} non-array field injections`, survived===attempted,
    survived+'/'+attempted);
  check('Jet still answering after field-injection barrage', await alive());

  // 2. Every event with every nasty top-level payload
  let s2=0, a2=0;
  for (const ev of events) {
    for (const v of nasty) { a2++; const r = await emit(c, ev, v); if (!r.timeout) s2++; }
  }
  check(`all ${events.length} events survived ${a2} hostile payloads`, s2===a2, s2+'/'+a2);
  check('Jet still answering after full-event barrage', await alive());

  // 3. The exact original crash vector, explicitly
  const orig = await emit(c,'Safecloud/subtree/get',{ rootCid:'r1', grants:'notarray' });
  check('ORIGINAL CRASH VECTOR (grants:"notarray") returns an ack, not death', !orig.timeout);
  check('Jet alive after the original crash vector', await alive());
  const orig2 = await emit(c,'Safecloud/subtree/get',{ rootCid:'r1', payments:'notarray' });
  check('payments:"notarray" also survives', !orig2.timeout);
  const orig3 = await emit(c,'Safecloud/subtree/put',{ rootCid:'r1', chunks:'notarray' });
  check('put chunks:"notarray" also survives', !orig3.timeout);
  check('Jet alive at the end of the attack', await alive());
  check('no uncaught exception escaped at any point', !died);

  c.close(); ioServer.close(); httpServer.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  setTimeout(()=>process.exit(fail?1:0),200);
})();
