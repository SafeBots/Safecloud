/**
 * MULTI-DROP flow — one video's chunks spread across two Drops, fetched in a
 * single viewer request, reassembled IN ORDER, with the Jet paying each Drop
 * on its own line and the viewer paying the author+Jet. Full accounting must
 * close: nothing created, nothing lost.
 *
 * Real socket, real IndexedDB (two separate Drop stores), real crypto/EIP-712.
 */
require('fake-indexeddb/auto');
const { Server } = require('socket.io');
const { io } = require('socket.io-client');
const http = require('http');
const ethers = require('ethers');
const { webcrypto } = require('crypto'); const crypto = webcrypto;
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const OC_ADDR='0x99999febd42cad798fe10ab0b1c563002fc99999'; const SBUX='0x'+'b0'.repeat(20);
const CHAIN=56; const ZERO32='0x'+'00'.repeat(32); const now=()=>Math.floor(Date.now()/1000);
const domain={name:'OpenClaiming',version:'1',chainId:CHAIN,verifyingContract:OC_ADDR};
const TYPES={Payment:[{name:'payer',type:'address'},{name:'token',type:'address'},{name:'recipientsHash',type:'bytes32'},{name:'max',type:'uint256'},{name:'line',type:'uint256'},{name:'nbf',type:'uint256'},{name:'exp',type:'uint256'},{name:'contract',type:'address'}]};
const rhPlain=a=>ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]'],[a]));
const polHash=p=>ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]','uint256[]','uint256','bytes32','address[]'],[p.payees,p.fractions.map(BigInt),BigInt(p.dynamicBps),p.dynamicConstraint,p.targets]));
async function sign(w,o){const stm={payer:w.address,token:SBUX,recipientsHash:o.recipientsHash||ZERO32,max:String(o.max),line:String(o.line||0),nbf:'0',exp:String(now()+3600),contract:OC_ADDR};const value={...stm,max:BigInt(stm.max),line:BigInt(stm.line),nbf:0n,exp:BigInt(stm.exp)};const env={stm,sig:[{signature:await w.signTypedData(domain,TYPES,value)}]};if(o.policy)env.stm.policy=o.policy;return env;}
function verify(env){try{const s=env.stm;const v={payer:s.payer,token:s.token,recipientsHash:s.recipientsHash,max:BigInt(s.max),line:BigInt(s.line),nbf:BigInt(s.nbf),exp:BigInt(s.exp),contract:OC_ADDR};return ethers.verifyTypedData(domain,TYPES,v,env.sig[0].signature).toLowerCase()===s.payer.toLowerCase();}catch(e){return false;}}

class MockOC{constructor(){this.lines={};this.rec={};}
  _c(t,r,a){const k=`${t}|${r}`.toLowerCase();this.rec[k]=(this.rec[k]||0n)+a;}
  received(t,r){return this.rec[`${t}|${r}`.toLowerCase()]||0n;}
  _wm(p,l,m){const L=this.lines[p.toLowerCase()]=this.lines[p.toLowerCase()]||{};const s=L[l]||0n;if(m<=s)return 0n;const d=m-s;L[l]=m;return d;}
  execPolicy(stm,sig,amount,pol,dyn){const d=this._wm(stm.payer,stm.line,BigInt(stm.max));const a=amount<d?amount:d;if(a<=0n)return;pol.payees.forEach((p,i)=>{const s=a*BigInt(pol.fractions[i])/10000n;if(s>0n)this._c(stm.token,p,s);});const ds=a*BigInt(pol.dynamicBps)/10000n;if(ds>0n&&dyn)this._c(stm.token,dyn,ds);}
  execPlain(stm,sig,recipient,claimMax){const d=this._wm(stm.payer,stm.line,BigInt(stm.max));const p=d<claimMax?d:claimMax;if(p>0n)this._c(stm.token,recipient,p);return p;}}

function mkStore(name){return new Promise((res,rej)=>{const r=indexedDB.open(name,1);r.onupgradeneeded=e=>e.target.result.createObjectStore('chunks',{keyPath:'cid'});r.onsuccess=e=>res(e.target.result);r.onerror=e=>rej(e.target.error);});}
function put(db,v){return new Promise((res,rej)=>{const t=db.transaction('chunks','readwrite');const q=t.objectStore('chunks').put(v);q.onsuccess=()=>res();q.onerror=()=>rej(q.error);});}
function get(db,cid){return new Promise((res)=>{const q=db.transaction('chunks','readonly').objectStore('chunks').get(cid);q.onsuccess=()=>res(q.result||null);q.onerror=()=>res(null);});}

(async () => {
  const oc = new MockOC();
  const author=new ethers.Wallet('0x'+'a1'.repeat(32));
  const viewer=new ethers.Wallet('0x'+'b2'.repeat(32));
  const jet=new ethers.Wallet('0x'+'ce'.repeat(32));
  const dropA=new ethers.Wallet('0x'+'d0'.repeat(32));
  const dropB=new ethers.Wallet('0x'+'d1'.repeat(32));
  const storeA = await mkStore('DropA'); const storeB = await mkStore('DropB');
  const policy={payees:[author.address],fractions:[9000],dynamicBps:1000,dynamicConstraint:ZERO32,targets:[]};

  // Video: 4 ordered chunks. c0,c2 → Drop A; c1,c3 → Drop B (interleaved).
  const rootKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', rootKey, 'AES-GCM', false, ['encrypt','decrypt']);
  const segs = ['[seg0]','[seg1]','[seg2]','[seg3]'];
  const cids = ['c0','c1','c2','c3'];
  const chunkMap = {}; // cid -> {store, chunk}
  for (let i=0;i<4;i++){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, new TextEncoder().encode(segs[i])));
    const chunk = { cid:cids[i], iv:Buffer.from(iv).toString('base64'), ciphertext:Buffer.from(ct).toString('base64') };
    const store = (i%2===0) ? storeA : storeB;
    await put(store, chunk);
    chunkMap[cids[i]] = { store: (i%2===0)?'A':'B' };
  }
  check('chunks distributed across two Drops (c0/c2→A, c1/c3→B)',
    chunkMap.c0.store==='A' && chunkMap.c1.store==='B' && chunkMap.c2.store==='A' && chunkMap.c3.store==='B');

  // Jet server: on get, fetches each cid from whichever Drop has it, pays that Drop
  const srv=http.createServer(); const io2=new Server(srv);
  const perDropWatermark = {}; // dropAddr -> cumulative
  io2.of('/Safecloud/cloud').on('connection',(socket)=>{
    socket.on('Safecloud/subtree/get', async (payload, ack) => {
      const p=(payload.payments||[])[0];
      if(!p||!verify(p)) return ack({error:{code:'PaymentRequired'}});
      // Fetch each chunk from the correct Drop (Jet knows placement)
      const chunks=[];
      for(const cid of payload.cids){
        const inA = await get(storeA, cid); const inB = inA?null:await get(storeB, cid);
        const chunk = inA||inB; const which = inA?dropA:dropB;
        if(!chunk){ return ack({error:{code:'NotFound',cid}}); }
        chunks.push(chunk);
        // Jet pays the serving Drop on its own line (cumulative watermark)
        const line = BigInt(which.address).toString();
        perDropWatermark[which.address] = (perDropWatermark[which.address]||0n) + 100n;
        const dropEnv = await sign(jet, { recipientsHash: rhPlain([which.address]), max: perDropWatermark[which.address].toString(), line });
        oc.execPlain(dropEnv.stm, dropEnv.sig[0].signature, which.address, 100n);
      }
      // Settle viewer → author+jet
      oc.execPolicy(p.stm, p.sig[0].signature, BigInt(p.stm.max), policy, jet.address);
      ack(null, { chunks });
    });
  });
  await new Promise(r=>srv.listen(0,r));
  const url=`http://localhost:${srv.address().port}/Safecloud/cloud`;
  const c = await new Promise(r=>{const s=io(url,{transports:['websocket'],forceNew:true});s.on('connect',()=>r(s));});
  const emit=(ev,p)=>new Promise(r=>c.emit(ev,p,(err,res)=>r({err,res})));

  section('Multi-Drop fetch + ordered reassembly');
  const payEnv = await sign(viewer, { recipientsHash:polHash(policy), max:4000, line:0, policy });
  const g = await emit('Safecloud/subtree/get', { cids, payments:[payEnv] });
  check('all 4 chunks returned from 2 Drops in one request', g.res && g.res.chunks.length===4);

  // Decrypt + reassemble IN ORDER
  let video='';
  for (const ch of g.res.chunks){
    const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(Buffer.from(ch.iv,'base64'))}, key, new Uint8Array(Buffer.from(ch.ciphertext,'base64')));
    video += new TextDecoder().decode(pt);
  }
  check('chunks reassembled in correct order', video === '[seg0][seg1][seg2][seg3]', video);

  section('Accounting closes across all parties');
  const a = oc.received(SBUX,author.address), j = oc.received(SBUX,jet.address);
  const dA = oc.received(SBUX,dropA.address), dB = oc.received(SBUX,dropB.address);
  check('author got 90% of 4000 (3600)', a===3600n, 'got '+a);
  check('Jet got 10% dynamic of 4000 (400)', j===400n, 'got '+j);
  check('Drop A paid for 2 chunks served (200)', dA===200n, 'got '+dA);
  check('Drop B paid for 2 chunks served (200)', dB===200n, 'got '+dB);
  // The Jet earned 400 from the viewer, paid 400 to Drops — infra margin flows through
  check('Jet infra income (400) == total Drop payouts (400): flow-through balances',
    j === (dA + dB), `jet=${j} drops=${dA+dB}`);

  c.close(); io2.close(); srv.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
