/**
 * Hostile input to the REAL shipped HTTP routes: malformed base64 OCP params,
 * bogus Range headers, poisoned chunk responses from a Drop. A live Jet takes
 * these from untrusted callers and untrusted Drops — none may crash it or
 * leak internals.
 */
const http=require('http'), express=require('express'), path=require('path');
const ethers=require('ethers');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const configStore={Safecloud:{requirePayment:true,requireGrants:false,
  jet:{privateKey:'0x'+'ce'.repeat(32)},safebux:{perChunkWei:'500'}}};
const app=express(); const realServer={attached:{express:app}};
// A fake Drop the Jet will route to — returns whatever we set
let dropResponse = null;
const Q={Config:{get:(k,d)=>{let o=configStore;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;},set:()=>{}},
 log:()=>{},extend:Object.assign,getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
 makeEventEmitter:(o)=>{const ls={};o.on=(e,f)=>{(ls[e]=ls[e]||[]).push(f);};o.emit=(e,...a)=>{(ls[e]||[]).forEach(f=>f(...a));};},
 listen:()=>realServer,
 require:(n)=>{if(n==='Users')return{Socket:{listen:()=>({io:{of:()=>({on:()=>{}})}})}};throw new Error('no');},
 app:{DIR:'/tmp/sc'},Crypto:{},Data:{},Assets:{},Socket:{},Safecloud:{}};
const M=require('module'); const ol=M._load;
M._load=function(r){ if(r==='Q')return Q; if(r==='./Client')return{verifyGrant:async()=>true};
 if(r==='./Drops')return{verifyChallengeResponse:()=>true,verifyAnnounce:()=>true};
 if(r==='./JetSwarm')return{init:async()=>{},stats:()=>({peerCount:0}),announceRanges:()=>{},fetchChunks:async()=>({chunks:[]})};
 return ol.apply(this,arguments); };
const Jets=require(path.join(process.cwd(),'classes/Safecloud/Jets.js'));
Jets.listen({});

// Install a fake Drop whose callDrop returns our controlled response
Jets.callDrop = function(){ return Promise.resolve(dropResponse); };

function req(server, method, urlPath, opts){ opts=opts||{};
  return new Promise((resolve)=>{
    const data=opts.body?JSON.stringify(opts.body):null;
    const headers=Object.assign({}, opts.headers||{},
      data?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}:{});
    const r=http.request({host:'localhost',port:server.address().port,path:urlPath,method,headers},(res)=>{
      let b=''; res.on('data',c=>b+=c); res.on('end',()=>{ let j=null; try{j=JSON.parse(b);}catch(e){}
        resolve({status:res.statusCode,body:j,raw:b,headers:res.headers}); }); });
    r.on('error',()=>resolve({status:0,raw:'CONNECTION_ERROR'}));
    if(data) r.write(data); r.end(); });
}
function leaksInternals(raw){
  return raw.indexOf('/home/')>=0 || raw.indexOf('TypeError')>=0
      || raw.indexOf('SyntaxError')>=0 || /\n\s+at /.test(raw);
}

(async () => {
  const server=http.createServer(app);
  await new Promise(r=>server.listen(0,r));
  let alive = async () => (await req(server,'GET','/Safecloud/health')).status===200;

  // ══ Malformed OCP query params (base64 grants/payments) ══
  section('HTTP subtree GET — malformed base64 OCP params');
  const cases = [
    ['not-base64-at-all',      '?g=!!!not-base64!!!'],
    ['base64 of invalid JSON', '?g='+Buffer.from('{{{not json').toString('base64')],
    ['base64 of a bare number','?g='+Buffer.from('12345').toString('base64')],
    ['base64 of null',         '?g='+Buffer.from('null').toString('base64')],
    ['deeply nested JSON',     '?g='+Buffer.from(JSON.stringify({a:{b:{c:{d:{e:{f:1}}}}}})).toString('base64')],
    ['payments param garbage', '?p='+Buffer.from('\u0000\u0001binary').toString('base64')],
    ['stream param garbage',   '?s='+Buffer.from('no-tab-separator').toString('base64')],
    ['empty params',           '?g=&p=&s=']
  ];
  for (const [label, qs] of cases) {
    const r = await req(server,'GET','/Safecloud/cloud/subtree/bafyRoot'+qs);
    check('subtree GET survives: '+label, r.status!==0 && r.status<600, 'status '+r.status);
    check('  ↳ no internals leaked ('+label+')', !leaksInternals(r.raw));
  }
  check('Jet still alive after malformed-param barrage', await alive());

  // ══ Hostile link paths via query ══
  section('HTTP subtree GET — hostile link paths');
  const links = ['../../etc/passwd','track/data/'+'9'.repeat(50),'track/data/-1','track/data/abc',
                 'a'.repeat(2000), 'track%2Fdata', ''];
  for (const l of links) {
    const r = await req(server,'GET','/Safecloud/cloud/subtree/bafyRoot?link='+encodeURIComponent(l));
    check('survives link='+l.slice(0,22), r.status!==0 && r.status<600, 'status '+r.status);
  }
  check('Jet alive after hostile link paths', await alive());

  // ══ x402 chunk: malformed PAYMENT-SIGNATURE header ══
  section('x402 chunk — malformed payment header');
  const sigs = ['not-base64','',Buffer.from('{{{').toString('base64'),
    Buffer.from(JSON.stringify({stm:null})).toString('base64'),
    Buffer.from(JSON.stringify({stm:{payer:'not-an-address',max:'abc'},sig:[]})).toString('base64'),
    Buffer.from(JSON.stringify({stm:{payer:'0x'+'a1'.repeat(20),token:'0x'+'b0'.repeat(20),max:'NaN',line:'x'},sig:[{signature:'0xdead'}]})).toString('base64')];
  for (let i=0;i<sigs.length;i++){
    const r = await req(server,'GET','/Safecloud/cloud/chunk/bafyX',{headers:{'payment-signature':sigs[i]}});
    check('chunk survives malformed payment sig #'+i, r.status!==0 && r.status<600, 'status '+r.status);
    check('  ↳ no internals leaked #'+i, !leaksInternals(r.raw));
  }
  check('Jet alive after malformed payment headers', await alive());

  // ══ Range header abuse on the chunk endpoint ══
  section('x402 chunk — hostile Range headers');
  const ranges = ['bytes=-','bytes=999999999-','bytes=5-1','bytes=abc-def','bytes=','garbage',
                  'bytes=0-'+'9'.repeat(30)];
  for (const rg of ranges) {
    const r = await req(server,'GET','/Safecloud/cloud/chunk/bafyX',{headers:{range:rg}});
    check('survives Range: '+rg.slice(0,20), r.status!==0 && r.status<600, 'status '+r.status);
  }
  check('Jet alive after Range abuse', await alive());

  // ══ HTTP subtree PUT with hostile bodies ══
  section('HTTP subtree PUT — hostile bodies');
  const bodies = [ {}, {chunks:null}, {chunks:'not-an-array'}, {chunks:[null,undefined]},
    {chunks:[{cid:null}]}, {chunks:[{}],link:null}, {chunks:[],rootCid:{obj:1}},
    {chunks:[{cid:'c',ciphertext:12345}]} ];
  for (let i=0;i<bodies.length;i++){
    const r = await req(server,'PUT','/Safecloud/cloud/subtree',{body:bodies[i]});
    check('PUT survives hostile body #'+i, r.status!==0 && r.status<600, 'status '+r.status);
    check('  ↳ no internals leaked PUT#'+i, !leaksInternals(r.raw));
  }
  check('Jet alive after hostile PUT bodies', await alive());

  // ══ Fragment endpoint ══
  section('/safecloud/fragment');
  const f1 = await req(server,'GET','/safecloud/fragment');
  check('fragment without rootCid returns 400', f1.status===400);
  const f2 = await req(server,'GET','/safecloud/fragment?rootCid='+encodeURIComponent('../../secret'));
  check('fragment with traversal-ish rootCid returns 404 (no file access)', f2.status===404);
  check('fragment sets permissive CORS for iframe embeds',
    f1.headers['access-control-allow-origin']==='*');

  server.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
