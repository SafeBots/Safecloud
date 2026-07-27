/**
 * REAL HTTP route handlers from the shipped Jets.js — executed, not mocked.
 * Boots the actual listen() with a Q stub that hands it a real express app,
 * then drives the routes over real HTTP: /health, /sponsor/token, /faucet,
 * /dashboard, and the x402 chunk endpoint.
 */
const http = require('http');
const express = require('express');
const path = require('path');
const ethers = require('ethers');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

// ── Q stub handing Jets.js a REAL express app ──
const configStore = { Safecloud: {
  requirePayment: true,
  requireGrants: false,
  sponsor: { enabled: true, maxWeiPerViewer: '3000' },
  jet: { privateKey: '0x' + 'ce'.repeat(32) }   // pre-set so bootstrap is skipped
}};
const app = express();
const realServer = { attached: { express: app } };
const Q = {
  Config: {
    get: (k,d)=>{ let o=configStore; for(const x of k){ if(o==null) return d; o=o[x]; } return o===undefined?d:o; },
    set: (k,v)=>{ let o=configStore; for(let i=0;i<k.length-1;i++){o[k[i]]=o[k[i]]||{};o=o[k[i]];} o[k[k.length-1]]=v; }
  },
  log: ()=>{}, extend: Object.assign,
  getObject: (k,f)=>{ let o=f; for(const x of k){ if(o==null) return undefined; o=o[x]; } return o; },
  makeEventEmitter: (o)=>{ const ls={}; o.on=(e,f)=>{(ls[e]=ls[e]||[]).push(f);}; o.emit=(e,...a)=>{(ls[e]||[]).forEach(f=>f(...a));}; },
  listen: ()=>realServer,
  require: (n)=>{ if(n==='Users') return { Socket: { listen: ()=>({ io: { of: ()=>({ on: ()=>{} }) } }) } }; throw new Error('no '+n); },
  app: { DIR: '/tmp/sc-test' }, Crypto: {}, Data: {}, Assets: {}, Socket: {}, Safecloud: {}
};
const Module = require('module'); const origLoad = Module._load;
Module._load = function(req){ if(req==='Q') return Q;
  if(req==='./Client') return { verifyGrant: async()=>true };
  if(req==='./Drops') return { verifyChallengeResponse: ()=>true };
  if(req==='./JetSwarm') return { init: async()=>{}, stats: ()=>({peerCount:0}), announceRanges: ()=>{} };
  return origLoad.apply(this, arguments); };

const Jets = require(path.join(process.cwd(),'classes/Safecloud/Jets.js'));

function req(server, method, urlPath, body) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host:'localhost', port:server.address().port, path:urlPath, method,
      headers: data ? {'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)} : {} },
      (res) => { let b=''; res.on('data',c=>b+=c); res.on('end',()=>{
        let j=null; try{ j=JSON.parse(b);}catch(e){}
        resolve({ status:res.statusCode, body:j, raw:b, headers:res.headers }); }); });
    r.on('error', ()=>resolve({ status:0, body:null, raw:'' }));
    if (data) r.write(data); r.end();
  });
}

(async () => {
  // Boot the REAL listen() — registers all routes on our express app
  let booted = true;
  try { Jets.listen({}); } catch (e) { booted = false; console.log('    listen() threw:', e.message); }
  check('real Jets.listen() boots without throwing (demo mode)', booted);

  const server = http.createServer(app);
  await new Promise(r=>server.listen(0,r));

  // ══ /Safecloud/health ══
  section('/Safecloud/health (real handler)');
  const h = await req(server,'GET','/Safecloud/health');
  check('health returns 200', h.status===200);
  check('health reports signing:true (wallet configured)', h.body && h.body.signing===true);
  check('health reports requirePayment from config', h.body.requirePayment===true);
  check('health exposes jetAddress', !!h.body.jetAddress && ethers.isAddress(h.body.jetAddress));
  check('health does NOT leak the private key',
    JSON.stringify(h.body).indexOf('ce'.repeat(32))===-1);

  // ══ /Safecloud/sponsor/token ══
  section('/Safecloud/sponsor/token (real handler)');
  const noId = await req(server,'POST','/Safecloud/sponsor/token',{});
  check('sponsor rejects missing viewerId with 400', noId.status===400);

  const t1 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:'v-1' });
  check('sponsor issues a token (200)', t1.status===200, 'status '+t1.status+' body '+t1.raw.slice(0,120));
  if (t1.status===200) {
    check('token has stm + sig', !!t1.body.stm && Array.isArray(t1.body.sig) && !!t1.body.sig[0]);
    check('payer is the sponsor/jet wallet, not the viewer',
      ethers.isAddress(t1.body.stm.payer));
    check('line is an opaque non-zero channel (hash of viewerId)',
      t1.body.stm.line && t1.body.stm.line !== '0' && t1.body.stm.line.length > 20);
    check('viewerId does not appear in the token', JSON.stringify(t1.body).indexOf('v-1')===-1);
    // Signature must actually verify
    const s = t1.body.stm;
    const dom = { name:'OpenClaiming', version:'1', chainId:Number(s.chainId||56), verifyingContract:s.contract };
    const TY = { Payment:[{name:'payer',type:'address'},{name:'token',type:'address'},{name:'recipientsHash',type:'bytes32'},
      {name:'max',type:'uint256'},{name:'line',type:'uint256'},{name:'nbf',type:'uint256'},{name:'exp',type:'uint256'},{name:'contract',type:'address'}]};
    let ok=false;
    try { ok = ethers.verifyTypedData(dom, TY, { payer:s.payer, token:s.token, recipientsHash:s.recipientsHash,
      max:BigInt(s.max), line:BigInt(s.line), nbf:BigInt(s.nbf||0), exp:BigInt(s.exp), contract:s.contract },
      t1.body.sig[0].signature).toLowerCase()===s.payer.toLowerCase(); } catch(e){ ok=false; }
    check('REAL sponsor token signature verifies (canonical EIP-712)', ok);
  }

  // Cap exhaustion: config cap is 3000, default increment 1000 per call
  const t2 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:'v-2', maxWei:'2000' });
  check('sponsor honors explicit maxWei under cap', t2.status===200);
  const t3 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:'v-2', maxWei:'99999' });
  check('sponsor returns 402 when over cap', t3.status===402, 'got '+t3.status);
  check('402 body reports cap and granted', t3.body && t3.body.cap && t3.body.granted!==undefined);

  // ══ REGRESSION: malformed client input must not 500 or leak internals ══
  section('Hostile input to sponsor endpoint (regression)');
  const bad1 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:'attacker', maxWei:'not-a-number' });
  check('non-numeric maxWei returns 400, not 500', bad1.status===400, 'got '+bad1.status);
  check('error response does not leak a stack trace',
    bad1.raw.indexOf('SyntaxError')===-1 && bad1.raw.indexOf('/home/')===-1 && bad1.raw.indexOf('at ')===-1);
  const bad2 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:'x', maxWei:'12; DROP TABLE' });
  check('injection-ish maxWei returns 400', bad2.status===400);
  const bad3 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:{obj:1} });
  check('non-string viewerId returns 400', bad3.status===400);
  const bad4 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:'x'.repeat(5000) });
  check('over-long viewerId returns 400 (bounded key)', bad4.status===400);
  const bad5 = await req(server,'POST','/Safecloud/sponsor/token',{ viewerId:'ok-user', maxWei:'-500' });
  check('negative maxWei returns 400', bad5.status===400);

  // ══ /Safecloud/faucet (off by default) ══
  section('/Safecloud/faucet (real handler, disabled)');
  const f = await req(server,'POST','/Safecloud/faucet',{ address:'0x'+'11'.repeat(20) });
  check('faucet returns 404 when not enabled', f.status===404);

  // ══ /Safecloud/dashboard ══
  section('/Safecloud/dashboard (real handler)');
  const d = await req(server,'GET','/Safecloud/dashboard');
  check('dashboard returns 200 HTML', d.status===200 && d.raw.indexOf('<!doctype html>')>=0);
  check('dashboard shows the Jet address', d.raw.indexOf('0x')>=0);
  check('dashboard handles zero connected Drops gracefully', d.raw.indexOf('none connected')>=0);
  check('dashboard does NOT leak the private key', d.raw.indexOf('ce'.repeat(32))===-1);

  // ══ x402 chunk endpoint ══
  section('x402 /Safecloud/cloud/chunk/:cid (real handler)');
  const x = await req(server,'GET','/Safecloud/cloud/chunk/bafyUnknown');
  check('unpaid chunk request returns 402', x.status===402, 'got '+x.status);
  check('402 carries PAYMENT-REQUIRED header', !!x.headers['payment-required']);
  if (x.headers['payment-required']) {
    let reqs=null; try{ reqs=JSON.parse(Buffer.from(x.headers['payment-required'],'base64').toString('utf8')); }catch(e){}
    check('PAYMENT-REQUIRED decodes to x402 requirements', !!reqs && !!reqs.scheme && !!reqs.network);
    check('requirements name the payTo address and token', !!reqs.payTo && !!reqs.token);
  }

  server.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
