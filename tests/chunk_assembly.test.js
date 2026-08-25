/**
 * REGRESSION: x402 chunk assembly with malformed Drop responses.
 * Reaches the actual Buffer.from() assembly path by disabling payment
 * enforcement and stubbing balance + Drop selection, then feeds the Jet
 * chunks that are missing ciphertext/tag — the shapes that used to throw a
 * TypeError and return 500 with the error leaked on the PUBLIC x402 route.
 */
const http=require('http'), express=require('express'), path=require('path');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const configStore={Safecloud:{requirePayment:false,requireGrants:false,
  jet:{privateKey:'0x'+'ce'.repeat(32)},safebux:{perChunkWei:'0'}}};
const app=express(); const realServer={attached:{express:app}};
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

// Get past the balance pre-screen and Drop selection
Jets._checkPayerBalance = () => Promise.resolve(true);
Jets.drops = { d1: { dropId:'d1', offlineSince:null, reliabilityScore:1, minPerChunkWei:'0',
                     evmAddress:'0x'+'d0'.repeat(20), socket:{} } };
Jets.selectDrops = () => Promise.resolve([Jets.drops.d1]);
let dropReturns = null;
Jets.callDrop = () => Promise.resolve(dropReturns);

function put(server, p, body){ return new Promise((resolve)=>{
  const data=JSON.stringify(body);
  const r=http.request({host:'localhost',port:server.address().port,path:p,method:'PUT',
    headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}},(res)=>{
      let b=''; res.on('data',c=>b+=c); res.on('end',()=>resolve({status:res.statusCode,raw:b})); });
  r.on('error',()=>resolve({status:0,raw:''})); r.write(data); r.end(); }); }

function get(server, p, headers){ return new Promise((resolve)=>{
  const r=http.request({host:'localhost',port:server.address().port,path:p,method:'GET',headers:headers||{}},(res)=>{
    const bufs=[]; res.on('data',c=>bufs.push(c)); res.on('end',()=>{
      const raw=Buffer.concat(bufs); resolve({status:res.statusCode,raw:raw.toString('utf8'),
        len:raw.length,headers:res.headers}); }); });
  r.on('error',()=>resolve({status:0,raw:'CONN_ERR',len:0,headers:{}})); r.end(); }); }
const leaks = raw => raw.indexOf('TypeError')>=0 || raw.indexOf('/home/')>=0 || /\n\s+at /.test(raw);

(async () => {
  const server=http.createServer(app); await new Promise(r=>server.listen(0,r));
  const paySig = Buffer.from(JSON.stringify({ stm:{ payer:'0x'+'a1'.repeat(20),
    token:'0x'+'b0'.repeat(20), max:'1000', line:'0', nbf:'0', exp:String(Math.floor(Date.now()/1000)+3600) },
    sig:[] })).toString('base64');
  const H = { 'payment-signature': paySig };
  const alive = async () => (await get(server,'/Safecloud/health')).status===200;

  // Register c1 in the Jet's CID index (the chunk route requires a known CID)
  dropReturns = { results:[{ cid:'c1', stored:true }] };
  const reg = await put(server,'/Safecloud/cloud/subtree',
    { rootCid:'r1', link:['track','data'], chunks:[{ cid:'c1' }], treeN:2, treeDepth:1 });
  check('PUT registered the CID in the Jet index', reg.status===200, 'status '+reg.status+' '+reg.raw.slice(0,80));

  section('Malformed chunk payloads from a Drop');
  const bad = [
    ['missing ciphertext entirely', { chunks:[{ cid:'c1' }] }],
    ['ciphertext = null',           { chunks:[{ cid:'c1', ciphertext:null, tag:'AAA=' }] }],
    ['ciphertext = number',         { chunks:[{ cid:'c1', ciphertext:12345, tag:'AAA=' }] }],
    ['ciphertext = object',         { chunks:[{ cid:'c1', ciphertext:{a:1}, tag:'AAA=' }] }],
    ['tag missing (valid format!)', { chunks:[{ cid:'c1', ciphertext:Buffer.from('hello').toString('base64') }] }],
    ['tag = null',                  { chunks:[{ cid:'c1', ciphertext:Buffer.from('hi').toString('base64'), tag:null }] }],
    ['empty chunks array',          { chunks:[] }],
    ['chunks = null',               { chunks:null }],
    ['result = null',               null ]
  ];
  for (const [label, ret] of bad) {
    dropReturns = ret;
    const r = await get(server, '/Safecloud/cloud/chunk/c1', H);
    check('no crash / no 500-with-trace: '+label, r.status!==0 && r.status<600 && !leaks(r.raw),
      'status '+r.status+' raw '+r.raw.slice(0,60));
  }
  check('Jet alive after malformed chunk barrage', await alive());

  section('Valid chunk WITHOUT a separate tag must still serve');
  dropReturns = { chunks:[{ cid:'c1', ciphertext: Buffer.from('VIDEO-BYTES').toString('base64') }] };
  const okNoTag = await get(server,'/Safecloud/cloud/chunk/c1', H);
  check('tag-less chunk serves 200 (not 404/500)', okNoTag.status===200, 'status '+okNoTag.status);
  check('body is exactly the ciphertext bytes', okNoTag.raw==='VIDEO-BYTES', okNoTag.raw.slice(0,20));

  section('Valid chunk WITH tag');
  dropReturns = { chunks:[{ cid:'c1', ciphertext: Buffer.from('VIDEO').toString('base64'),
                            tag: Buffer.from('TAG').toString('base64') }] };
  const okTag = await get(server,'/Safecloud/cloud/chunk/c1', H);
  check('chunk with tag serves 200', okTag.status===200);
  check('ciphertext and tag concatenated in order', okTag.raw==='VIDEOTAG', okTag.raw);

  section('Range handling (RFC 7233)');
  const mk = h => get(server,'/Safecloud/cloud/chunk/c1', Object.assign({}, H, h));
  const r1 = await mk({ range:'bytes=0-4' });
  check('valid range returns 206 with correct slice', r1.status===206 && r1.raw==='VIDEO', r1.status+' '+r1.raw);
  const r2 = await mk({ range:'bytes=5-1' });
  check('inverted range returns 416 (was: empty 206)', r2.status===416, 'status '+r2.status);
  const r3 = await mk({ range:'bytes=99999-' });
  check('start beyond EOF returns 416', r3.status===416, 'status '+r3.status);
  check('416 carries Content-Range: bytes */len',
    (r3.headers['content-range']||'').indexOf('bytes */')===0, r3.headers['content-range']);
  const r4 = await mk({ range:'bytes=abc-def' });
  check('non-numeric range degrades safely (200 or 206, no crash)',
    r4.status===200||r4.status===206, 'status '+r4.status);

  server.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
