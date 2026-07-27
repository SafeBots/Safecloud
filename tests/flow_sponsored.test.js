/**
 * SPONSORED VIEWER full arc over real socket transport — the web2 subsidy
 * flow end to end, including cap exhaustion and self-pay fallback.
 *
 *   Viewer connects → asks Jet for jet/info (learns sponsorUrl) → requests a
 *   sponsor token (site is payer) → streams → repeats until the per-viewer
 *   cap is hit → gets 402 → falls back to self-signing → streams again.
 *
 * Real socket.io + real EIP-712 signing (sponsor and viewer are distinct
 * wallets). Asserts the viewer NEVER appears as payer while sponsored, and
 * DOES appear only after falling back to self-pay.
 */
const { Server } = require('socket.io');
const { io } = require('socket.io-client');
const http = require('http');
const ethers = require('ethers');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const OC_ADDR='0x99999febd42cad798fe10ab0b1c563002fc99999';
const SBUX='0x'+'b0'.repeat(20); const CHAIN=56; const ZERO32='0x'+'00'.repeat(32);
const now=()=>Math.floor(Date.now()/1000);
const domain={name:'OpenClaiming',version:'1',chainId:CHAIN,verifyingContract:OC_ADDR};
const TYPES={Payment:[{name:'payer',type:'address'},{name:'token',type:'address'},{name:'recipientsHash',type:'bytes32'},{name:'max',type:'uint256'},{name:'line',type:'uint256'},{name:'nbf',type:'uint256'},{name:'exp',type:'uint256'},{name:'contract',type:'address'}]};

async function sign(w,o){const stm={payer:w.address,token:SBUX,recipientsHash:o.recipientsHash||ZERO32,max:String(o.max),line:String(o.line||0),nbf:'0',exp:String(now()+3600),contract:OC_ADDR};
  const value={...stm,max:BigInt(stm.max),line:BigInt(stm.line),nbf:0n,exp:BigInt(stm.exp)};
  return {stm,sig:[{signature:await w.signTypedData(domain,TYPES,value)}]};}
function verify(env){try{const s=env.stm;const v={payer:s.payer,token:s.token,recipientsHash:s.recipientsHash,max:BigInt(s.max),line:BigInt(s.line),nbf:BigInt(s.nbf),exp:BigInt(s.exp),contract:OC_ADDR};return ethers.verifyTypedData(domain,TYPES,v,env.sig[0].signature).toLowerCase()===s.payer.toLowerCase();}catch(e){return false;}}

(async () => {
  const sponsor = new ethers.Wallet('0x'+'5b'.repeat(32));
  const viewer  = new ethers.Wallet('0x'+'b2'.repeat(32));
  const CAP = 3000n;
  const sponsorWatermarks = {}; // viewerId -> granted

  const srv = http.createServer(); const ioServer = new Server(srv);
  ioServer.of('/Safecloud/cloud').on('connection', (socket) => {
    socket.on('Safecloud/jet/info', (p, ack) =>
      ack(null, { requirePayment:true, sponsorUrl:'/Safecloud/sponsor/token', evmAddress:'0x'+'ce'.repeat(20) }));
    // Sponsor endpoint modeled as a socket op for the harness (HTTP in prod)
    socket.on('Safecloud/sponsor/token', async (b, ack) => {
      const prev = BigInt(sponsorWatermarks[b.viewerId]||'0');
      const want = prev + BigInt(b.increment||1000);
      if (want > CAP) return ack({ error:{ code:'PaymentRequired', status:402, granted:prev.toString() } });
      sponsorWatermarks[b.viewerId] = want.toString();
      const line = BigInt(ethers.keccak256(ethers.toUtf8Bytes('safecloud.sponsor.'+b.viewerId))).toString();
      const env = await sign(sponsor, { max: want.toString(), line });
      ack(null, env);
    });
    socket.on('Safecloud/subtree/get', (payload, ack) => {
      const p = (payload.payments||[])[0];
      if (!p || !verify(p)) return ack({ error:{ code:'PaymentRequired' } });
      ack(null, { chunks:[{ cid:'c0', ciphertext:'x' }], payer:p.stm.payer });
    });
  });
  await new Promise(r=>srv.listen(0,r));
  const url=`http://localhost:${srv.address().port}/Safecloud/cloud`;
  const connect=()=>new Promise(r=>{const c=io(url,{transports:['websocket'],forceNew:true});c.on('connect',()=>r(c));});
  const emit=(c,ev,p)=>new Promise(r=>c.emit(ev,p,(err,res)=>r({err,res})));

  const c = await connect();
  const viewerId = 'anon-visitor-7';

  // ── 1. Discover sponsorship ──
  section('1. Viewer discovers sponsorship via jet/info');
  const info = await emit(c, 'Safecloud/jet/info', {});
  check('jet/info advertises sponsorUrl', info.res.sponsorUrl === '/Safecloud/sponsor/token');

  // ── 2. Sponsored streaming (viewer signs nothing) ──
  section('2. Sponsored streaming — site is payer');
  let servedSponsored = 0, lastPayer = null;
  for (let i=0;i<3;i++){
    const t = await emit(c, 'Safecloud/sponsor/token', { viewerId, increment:1000 });
    if (t.err) break;
    const g = await emit(c, 'Safecloud/subtree/get', { cids:['c0'], payments:[t.res] });
    if (g.res) { servedSponsored++; lastPayer = g.res.payer; }
  }
  check('sponsored streaming served 3 times', servedSponsored === 3);
  check('payer on-chain is the SPONSOR, never the viewer',
    lastPayer && lastPayer.toLowerCase() === sponsor.address.toLowerCase());
  check('viewer wallet was never used to sign while sponsored',
    lastPayer.toLowerCase() !== viewer.address.toLowerCase());

  // ── 3. Cap exhaustion → 402 ──
  section('3. Sponsor cap exhausts → 402');
  const over = await emit(c, 'Safecloud/sponsor/token', { viewerId, increment:1000 }); // would be 4000 > 3000
  check('sponsor returns 402 when cap exceeded', over.err && over.err.error.status === 402);
  check('402 reports the granted-so-far watermark', over.err.error.granted === '3000');

  // ── 4. Self-pay fallback ──
  section('4. Viewer falls back to self-pay');
  const selfEnv = await sign(viewer, { max:1000, line:0 });
  const selfGet = await emit(c, 'Safecloud/subtree/get', { cids:['c0'], payments:[selfEnv] });
  check('self-pay stream succeeds after sponsor exhaustion', !!selfGet.res);
  check('now the payer IS the viewer (fallback engaged)',
    selfGet.res.payer.toLowerCase() === viewer.address.toLowerCase());

  c.close(); ioServer.close(); srv.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
