/**
 * Operator setup states — the configs a human moves THROUGH while first
 * standing up a Jet. Each must fail safe: never crash, never leak the key,
 * always give a clear signal on /health. These are the states you'll actually
 * be in over the next hour of testing as Jets/Drops.
 */
const http=require('http'), express=require('express'), path=require('path');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

function bootJet(safecloudConfig) {
  // Fresh module instance per config (clear require cache for Jets.js)
  const jetsPath = require.resolve(path.join(process.cwd(),'classes/Safecloud/Jets.js'));
  delete require.cache[jetsPath];
  const configStore = { Safecloud: safecloudConfig };
  const app = express();
  const realServer = { attached: { express: app } };
  const Q = {
    Config:{ get:(k,d)=>{let o=configStore;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;},
             set:(k,v)=>{let o=configStore;for(let i=0;i<k.length-1;i++){o[k[i]]=o[k[i]]||{};o=o[k[i]];}o[k[k.length-1]]=v;} },
    log:()=>{}, extend:Object.assign,
    getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
    makeEventEmitter:(o)=>{const ls={};o.on=(e,f)=>{(ls[e]=ls[e]||[]).push(f);};o.emit=(e,...a)=>{(ls[e]||[]).forEach(f=>f(...a));};},
    listen:()=>realServer,
    require:(n)=>{ if(n==='Users')return{Socket:{listen:()=>({io:{of:()=>({on:()=>{}})}})}}; throw new Error('no '+n); },
    app:{DIR:'/tmp/sc-'+Math.random().toString(36).slice(2)}, Crypto:{}, Data:{}, Assets:{}, Socket:{}, Safecloud:{}
  };
  const M=require('module'); const ol=M._load;
  M._load=function(r){ if(r==='Q')return Q; if(r==='./Client')return{verifyGrant:async()=>true};
    if(r==='./Drops')return{verifyChallengeResponse:()=>true,verifyAnnounce:()=>true};
    if(r==='./JetSwarm')return{init:async()=>{},stats:()=>({peerCount:0}),announceRanges:()=>{}};
    return ol.apply(this,arguments); };
  const Jets = require(jetsPath);
  M._load = ol;
  let bootErr=null;
  try { Jets.listen({}); } catch(e){ bootErr=e; }
  return { Jets, app, bootErr, configStore };
}

function get(server, p) { return new Promise((resolve)=>{
  const r=http.request({host:'localhost',port:server.address().port,path:p,method:'GET'},(res)=>{
    let b=''; res.on('data',c=>b+=c); res.on('end',()=>{ let j=null; try{j=JSON.parse(b);}catch(e){}
      resolve({status:res.statusCode,body:j,raw:b}); }); });
  r.on('error',()=>resolve({status:0,raw:''})); r.end(); }); }

async function withServer(app, fn) {
  const server = http.createServer(app);
  await new Promise(r=>server.listen(0,r));
  try { await fn(server); } finally { server.close(); }
}

(async () => {
  const PK = '0x'+'ce'.repeat(32);

  // ── State 1: totally empty config (operator just installed) ──
  section('State 1: empty config (demo mode, nothing set)');
  {
    const { app, bootErr } = bootJet({});
    check('Jet boots with empty config (no throw)', !bootErr, bootErr && bootErr.message);
    await withServer(app, async (server) => {
      const h = await get(server, '/Safecloud/health');
      check('health responds 200 in demo mode', h.status===200, 'status '+h.status);
      check('health reports signing:false when no wallet', h.body && h.body.signing===false);
      check('health does not crash on missing safebux/openclaiming', !!h.body);
    });
  }

  // ── State 2: wallet set, but NO contract addresses (signing but not settling) ──
  section('State 2: wallet only, no contracts (signature-demo)');
  {
    const { app } = bootJet({ jet:{ privateKey: PK }, requirePayment:true });
    await withServer(app, async (server) => {
      const h = await get(server, '/Safecloud/health');
      check('health reports signing:true', h.body && h.body.signing===true);
      check('health exposes jetAddress', !!h.body.jetAddress);
      check('does NOT leak private key in health', h.raw.indexOf('ce'.repeat(32))===-1);
      const d = await get(server, '/Safecloud/dashboard');
      check('dashboard renders with wallet but no contracts', d.status===200 && d.raw.indexOf('<!doctype html>')>=0);
    });
  }

  // ── State 3: typo'd config — wrong types where addresses go ──
  section('State 3: operator typos (wrong types in app.json)');
  {
    const bad = bootJet({
      jet:{ privateKey: PK },
      safebux: { address: 12345, chainId: {} },   // number instead of string, object chainId
      openclaiming: { address: ['nope'] },          // array
      sponsor: { enabled: 'yes', maxWeiPerViewer: 'not-a-number' },  // string bool, bad number
      requirePayment: 'true'                          // string instead of bool
    });
    check('Jet boots despite typo\'d config (no throw)', !bad.bootErr, bad.bootErr && bad.bootErr.message);
    await withServer(bad.app, async (server) => {
      const h = await get(server, '/Safecloud/health');
      check('health still responds (does not crash on bad types)', h.status===200, 'status '+h.status);
    });
  }

  // ── State 4: sponsor enabled but no wallet (can't sign sponsor tokens) ──
  section('State 4: sponsor enabled, no wallet');
  {
    const { app } = bootJet({ sponsor:{ enabled:true, maxWeiPerViewer:'1000' } });
    await withServer(app, async (server) => {
      const t = await new Promise((resolve)=>{
        const body=JSON.stringify({viewerId:'v1'});
        const r=http.request({host:'localhost',port:server.address().port,path:'/Safecloud/sponsor/token',
          method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},
          (res)=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>resolve({status:res.statusCode,raw:b}));});
        r.on('error',()=>resolve({status:0,raw:''})); r.write(body); r.end();
      });
      check('sponsor without wallet fails cleanly (not 500+trace)',
        t.status!==500 || t.raw.indexOf('at ')===-1, 'status '+t.status);
      check('sponsor error does not leak internals',
        t.raw.indexOf('/home/')===-1 && t.raw.indexOf('TypeError')===-1);
    });
  }

  // ── State 5: the CORRECT demo config from docs ──
  section('State 5: documented demo config (the copy-paste one)');
  {
    const { app, bootErr } = bootJet({
      requirePayment: true,
      requireGrants: false,
      sponsor: { enabled: true, maxWeiPerViewer: '100000' },
      sponsorUrl: '/Safecloud/sponsor/token'
    });
    check('documented demo config boots clean', !bootErr, bootErr && bootErr.message);
    await withServer(app, async (server) => {
      const h = await get(server, '/Safecloud/health');
      check('health 200 on documented demo config', h.status===200);
      check('requirePayment reflected in health', h.body && h.body.requirePayment===true);
      const f = await get(server, '/Safecloud/health');
      check('health is idempotent (repeatable)', f.status===200);
    });
  }

  // ── State 6: Drop claim path with hostile tokens (money-out) ──
  section('State 6: claim path rejects hostile paymentTokens cleanly');
  {
    const { Server } = require('socket.io');
    const { io } = require('socket.io-client');
    const jetsPath = require.resolve(path.join(process.cwd(),'classes/Safecloud/Jets.js'));
    delete require.cache[jetsPath];
    const cs = { Safecloud: { jet:{ privateKey: PK }, requirePayment:false } };
    const app2 = express(); const hs = http.createServer(app2);
    const ioS = new Server(hs); const rs = { attached:{ express:app2 } };
    const Q = { Config:{ get:(k,d)=>{let o=cs;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;}, set:()=>{} },
      log:()=>{}, extend:Object.assign, getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
      makeEventEmitter:(o)=>{const l={};o.on=(e,f)=>{(l[e]=l[e]||[]).push(f);};o.emit=(e,...a)=>{(l[e]||[]).forEach(f=>f(...a));};},
      listen:()=>rs, require:(n)=>{ if(n==='Users')return{Socket:{listen:()=>({io:ioS})}}; throw new Error('no'); },
      app:{DIR:'/tmp/x'}, Crypto:{}, Data:{}, Assets:{}, Socket:{}, Safecloud:{} };
    const MM=require('module'); const oll=MM._load;
    MM._load=function(r){ if(r==='Q')return Q; if(r==='./Client')return{verifyGrant:async()=>true};
      if(r==='./Drops')return{verifyChallengeResponse:()=>true,verifyAnnounce:()=>true};
      if(r==='./JetSwarm')return{init:async()=>{},stats:()=>({peerCount:0}),announceRanges:()=>{}};
      return oll.apply(this,arguments); };
    const Jets2 = require(jetsPath); Jets2.listen({}); MM._load=oll;
    await new Promise(r=>hs.listen(0,r));
    const url=`http://localhost:${hs.address().port}/Safecloud/cloud`;
    const c=io(url,{transports:['websocket'],forceNew:true});
    await new Promise(r=>c.on('connect',r));
    const emit=(ev,p)=>new Promise(r=>{let d=false;const t=setTimeout(()=>{if(!d){d=true;r({timeout:true});}},4000);
      c.emit(ev,p,(err,res)=>{if(!d){d=true;clearTimeout(t);r({err,res});}});});
    await emit('Safecloud/drop/register',{dropId:'d1',evmAddress:'0x'+'d0'.repeat(20)});
    const r1=await emit('Safecloud/drop/claimPayments',{dropId:'d1',paymentTokens:'notarray'});
    check('string paymentTokens → clean response, not InternalError',
      r1.res && r1.res.reason==='no tokens', JSON.stringify(r1).slice(0,80));
    const r2=await emit('Safecloud/drop/claimPayments',{dropId:'d1',paymentTokens:[null,{},'x']});
    check('array with junk entries → filtered cleanly, no crash',
      !r2.timeout && (r2.res || (r2.err && r2.err.error.code!=='InternalError')),
      JSON.stringify(r2).slice(0,80));
    const alive=await emit('Safecloud/jet/info',{});
    check('Jet alive after hostile claims', !!alive.res);
    c.close(); ioS.close(); hs.close();
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
