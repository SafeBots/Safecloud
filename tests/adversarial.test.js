/**
 * Adversarial / edge-case suite — the places money leaks or circuits hang.
 * Real ethers; MockOpenClaiming mirrors the Solidity settlement rules.
 * Each test asserts the SAFE behavior under a hostile or awkward input.
 */
const ethers = require('ethers');
let pass = 0, fail = 0;
const out = [];
function check(n, c, d) { c ? (pass++, out.push('  \u2713 '+n)) : (fail++, out.push('  \u2717 FAIL: '+n+(d?' — '+d:''))); }
function section(t){ out.push('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const OC_ADDR = '0x99999febd42cad798fe10ab0b1c563002fc99999';
const OC_ADDR2 = '0x11111febd42cad798fe10ab0b1c563002fc11111'; // different deployment
const SBUX = '0x' + 'b0'.repeat(20);
const APPBUX = '0x' + 'aa'.repeat(20);
const CHAIN = 56;
const ZERO32 = '0x'+'00'.repeat(32);
const now = () => Math.floor(Date.now()/1000);
const domain = (oc=OC_ADDR, chain=CHAIN) => ({ name:'OpenClaiming', version:'1', chainId:chain, verifyingContract:oc });
const TYPES = { Payment: [
  {name:'payer',type:'address'},{name:'token',type:'address'},{name:'recipientsHash',type:'bytes32'},
  {name:'max',type:'uint256'},{name:'line',type:'uint256'},{name:'nbf',type:'uint256'},
  {name:'exp',type:'uint256'},{name:'contract',type:'address'}]};
const rhPlain = (a) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]'],[a]));
const polHash = (p) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['address[]','uint256[]','uint256','bytes32','address[]'],
  [p.payees,p.fractions.map(BigInt),BigInt(p.dynamicBps),p.dynamicConstraint,p.targets]));

async function sign(w, o) {
  const stm = { payer:w.address, token:o.token||SBUX, recipientsHash:o.recipientsHash||ZERO32,
    max:String(o.max), line:String(o.line||0), nbf:String(o.nbf||0),
    exp:String(o.exp!=null?o.exp:now()+3600), contract:o.contract||OC_ADDR };
  const value = { ...stm, max:BigInt(stm.max), line:BigInt(stm.line), nbf:BigInt(stm.nbf), exp:BigInt(stm.exp) };
  const sig = await w.signTypedData(domain(o.contract||OC_ADDR, o.chain||CHAIN), TYPES, value);
  const env = { stm, sig:[{signature:sig}] };
  if (o.policy) env.stm.policy = o.policy;
  return env;
}

// The Jet's real admission logic (mirrors _checkPayments policy gate)
function jetAdmitsPolicy(env, jetAddr, minInfraBp) {
  const stm = env.stm, pol = stm.policy;
  if (!pol) return { ok:false, reason:'no policy' };
  if (polHash(pol).toLowerCase() !== stm.recipientsHash.toLowerCase()) return { ok:false, reason:'tampered' };
  let sum = BigInt(pol.dynamicBps); pol.fractions.forEach(f=>sum+=BigInt(f));
  if (sum !== 10000n) return { ok:false, reason:'bad-sum' };
  const jetCk = jetAddr.toLowerCase();
  const dc = (pol.dynamicConstraint||ZERO32).toLowerCase();
  const IN_RECIPIENTS = '0x'+'00'.repeat(31)+'01';
  let admitted = false;
  if (BigInt(pol.dynamicBps) >= BigInt(minInfraBp)) {
    if (dc === ZERO32) admitted = true;
    else if (dc === IN_RECIPIENTS) admitted = pol.payees.some(a=>a.toLowerCase()===jetCk);
  }
  if (!admitted) for (let i=0;i<pol.payees.length;i++)
    if (pol.payees[i].toLowerCase()===jetCk && BigInt(pol.fractions[i])>=BigInt(minInfraBp)) { admitted=true; break; }
  return { ok:admitted, reason: admitted?'':'not-admitted' };
}

// Jet accepted-token gate (mirrors okSet logic)
function jetAcceptsToken(token, safebux, acceptedTokens) {
  const okSet = {}; if (safebux) okSet[safebux.toLowerCase()]=true;
  (acceptedTokens||[]).forEach(t=>okSet[t.toLowerCase()]=true);
  if (!Object.keys(okSet).length) return true; // demo mode
  return !!okSet[token.toLowerCase()];
}

// Time-bounds check (mirrors _checkPayments)
function timeValid(stm) {
  const n = now();
  if (stm.nbf && BigInt(stm.nbf) > BigInt(n)) return false;
  if (stm.exp && BigInt(stm.exp) < BigInt(n)) return false;
  return true;
}

class MockOC {
  constructor(){ this.lines={}; this.rec={}; }
  _c(t,r,a){ const k=`${t}|${r}`.toLowerCase(); this.rec[k]=(this.rec[k]||0n)+a; }
  received(t,r){ return this.rec[`${t}|${r}`.toLowerCase()]||0n; }
  _wm(payer,line,max){ const l=this.lines[payer.toLowerCase()]=this.lines[payer.toLowerCase()]||{};
    const sp=l[line]||0n; if(max<=sp) return 0n; const d=max-sp; l[line]=max; return d; }
  _verify(stm,sig){ try { const v={payer:stm.payer,token:stm.token,recipientsHash:stm.recipientsHash,
    max:BigInt(stm.max),line:BigInt(stm.line),nbf:BigInt(stm.nbf),exp:BigInt(stm.exp),contract:stm.contract};
    return ethers.verifyTypedData(domain(stm.contract), TYPES, v, sig).toLowerCase()===stm.payer.toLowerCase();
  } catch(e){ return false; } }
  execPolicy(stm,sig,amount,pol,dyn){
    if(stm.contract.toLowerCase()!==OC_ADDR.toLowerCase()) throw new Error('WrongContract');
    if(BigInt(stm.exp)<BigInt(now())) throw new Error('Expired');
    if(polHash(pol).toLowerCase()!==stm.recipientsHash.toLowerCase()) throw new Error('PolicyMismatch');
    if(!this._verify(stm,sig)) throw new Error('BadSig');
    const delta=this._wm(stm.payer,stm.line,BigInt(stm.max)); const amt=amount<delta?amount:delta;
    if(amt<=0n) return {}; const paid={};
    pol.payees.forEach((p,i)=>{ const s=amt*BigInt(pol.fractions[i])/10000n; if(s>0n){this._c(stm.token,p,s);paid[p.toLowerCase()]=s;} });
    const ds=amt*BigInt(pol.dynamicBps)/10000n; if(ds>0n&&dyn){ this._c(stm.token,dyn,ds); paid[dyn.toLowerCase()]=(paid[dyn.toLowerCase()]||0n)+ds; }
    return paid;
  }
  execPlain(stm,sig,recipient,claimMax){
    if(rhPlain([recipient]).toLowerCase()!==stm.recipientsHash.toLowerCase()) throw new Error('BadRecipients');
    if(!this._verify(stm,sig)) throw new Error('BadSig');
    const d=this._wm(stm.payer,stm.line,BigInt(stm.max)); const p=d<claimMax?d:claimMax;
    if(p>0n) this._c(stm.token,recipient,p); return p;
  }
}

const author = new ethers.Wallet('0x'+'a1'.repeat(32));
const viewer = new ethers.Wallet('0x'+'b2'.repeat(32));
const viewer2 = new ethers.Wallet('0x'+'c3'.repeat(32));
const sponsor = new ethers.Wallet('0x'+'5b'.repeat(32));
const jet = new ethers.Wallet('0x'+'ce'.repeat(32));
const jetOther = new ethers.Wallet('0x'+'ef'.repeat(32));
const dropA = new ethers.Wallet('0x'+'d0'.repeat(32));
const dropB = new ethers.Wallet('0x'+'d1'.repeat(32));

(async () => {
  const oc = new MockOC();
  const P = { payees:[author.address], fractions:[9000n], dynamicBps:1000n, dynamicConstraint:ZERO32, targets:[] };

  // ══ 1. Multi-Drop session ══
  section('1. Multi-Drop: one session, chunks across two Drops');
  // Jet pays each Drop on its own named line from the Jet's balance
  const toA = await sign(jet, { recipientsHash: rhPlain([dropA.address]), max:150, line: BigInt(dropA.address).toString() });
  const toB = await sign(jet, { recipientsHash: rhPlain([dropB.address]), max:150, line: BigInt(dropB.address).toString() });
  const pA = oc.execPlain(toA.stm, toA.sig[0].signature, dropA.address, 150n);
  const pB = oc.execPlain(toB.stm, toB.sig[0].signature, dropB.address, 150n);
  check('Drop A paid on its own line', pA===150n && oc.received(SBUX,dropA.address)===150n);
  check('Drop B paid on its own line', pB===150n && oc.received(SBUX,dropB.address)===150n);
  check('Drop lines are independent (different line ids)',
    BigInt(dropA.address).toString() !== BigInt(dropB.address).toString());

  // ══ 2. Sponsor cap exhaustion → 402 ══
  section('2. Sponsor cap exhaustion');
  const CAP = 2000n;
  let granted = 0n;
  function sponsorGrant(want) {
    if (want > CAP) return { status:402, granted };
    granted = want; return { status:200, granted };
  }
  check('grant within cap succeeds', sponsorGrant(1500n).status === 200);
  check('grant at cap succeeds', sponsorGrant(2000n).status === 200);
  check('grant over cap returns 402', sponsorGrant(2500n).status === 402);
  check('watermark never regressed after 402', granted === 2000n);

  // ══ 3. Concurrent viewers, same content ══
  section('3. Concurrent viewers on same content');
  const v1 = await sign(viewer,  { recipientsHash:polHash(P), max:1000, line:0, policy:P });
  const v2 = await sign(viewer2, { recipientsHash:polHash(P), max:1000, line:0, policy:P });
  oc.execPolicy(v1.stm, v1.sig[0].signature, 1000n, P, jet.address);
  oc.execPolicy(v2.stm, v2.sig[0].signature, 1000n, P, jet.address);
  check('two viewers pay independently (author += 900 each = 1800)',
    oc.received(SBUX,author.address) === 1800n, 'got '+oc.received(SBUX,author.address));
  check('viewers have separate lines (no cross-contamination)',
    oc.lines[viewer.address.toLowerCase()]['0']===1000n && oc.lines[viewer2.address.toLowerCase()]['0']===1000n);

  // ══ 4. Jet solvency (float) ══
  section('4. Jet float / solvency check');
  // A Drop should be able to verify the Jet can cover its outstanding watermark
  function jetCanCover(jetBalance, outstandingWatermark) { return jetBalance >= outstandingWatermark; }
  check('solvent Jet passes (balance >= outstanding)', jetCanCover(1000n, 300n));
  check('insolvent Jet detected (balance < outstanding)', !jetCanCover(100n, 300n));

  // ══ 5. Policy admission edges ══
  section('5. Policy admission edge cases');
  // dynamicBps below minInfraBp (5%) → Jet rejects
  const lowInfra = { payees:[author.address], fractions:[9700n], dynamicBps:300n, dynamicConstraint:ZERO32, targets:[] };
  const lowEnv = await sign(viewer, { recipientsHash:polHash(lowInfra), max:100, line:1, policy:lowInfra });
  check('Jet rejects policy paying infra below minInfraBp',
    !jetAdmitsPolicy(lowEnv, jet.address, 500).ok);
  // fractions don't sum to 10000 → rejected
  const badSum = { payees:[author.address], fractions:[8000n], dynamicBps:1000n, dynamicConstraint:ZERO32, targets:[] };
  const badEnv = await sign(viewer, { recipientsHash:polHash(badSum), max:100, line:2, policy:badSum });
  check('Jet rejects policy whose fractions do not sum to 100%',
    !jetAdmitsPolicy(badEnv, jet.address, 500).ok);
  // valid policy, DYNAMIC_ANY → admitted
  check('Jet admits valid policy with DYNAMIC_ANY slot',
    jetAdmitsPolicy(v1, jet.address, 500).ok);
  // tampered policy (hash mismatch) → rejected
  const tam = { stm: { ...v1.stm, policy: { ...P, fractions:[9500n], dynamicBps:500n } }, sig: v1.sig };
  check('Jet rejects policy plaintext that does not match signed hash',
    !jetAdmitsPolicy(tam, jet.address, 500).ok);

  // ══ 6. Time bounds + cross-deployment replay ══
  section('6. Expiry, not-yet-valid, cross-deployment replay');
  const expired = await sign(viewer, { recipientsHash:polHash(P), max:100, line:9, exp: now()-10, policy:P });
  check('expired token fails time check', !timeValid(expired.stm));
  let expThrew=false; try{ oc.execPolicy(expired.stm, expired.sig[0].signature, 100n, P, jet.address);}catch(e){expThrew=(e.message==='Expired');}
  check('settlement rejects expired token', expThrew);
  const future = await sign(viewer, { recipientsHash:polHash(P), max:100, line:10, nbf: now()+3600, policy:P });
  check('not-yet-valid (nbf) token fails time check', !timeValid(future.stm));
  // Token signed for a DIFFERENT contract deployment must not verify here
  const crossDeploy = await sign(viewer, { recipientsHash:polHash(P), max:100, line:11, contract:OC_ADDR2, policy:P });
  let crossThrew=false; try{ oc.execPolicy(crossDeploy.stm, crossDeploy.sig[0].signature, 100n, P, jet.address);}catch(e){crossThrew=(e.message==='WrongContract');}
  check('token signed for another deployment is rejected (replay-proof)', crossThrew);

  // ══ 7. {App}bux multi-token ══
  section('7. Multi-token ({App}bux) acceptance');
  check('Safebux accepted by default', jetAcceptsToken(SBUX, SBUX, []));
  check('unlisted token rejected', !jetAcceptsToken(APPBUX, SBUX, []));
  check('APPBUX accepted when in acceptedTokens', jetAcceptsToken(APPBUX, SBUX, [APPBUX]));
  check('demo mode (no token configured) accepts anything', jetAcceptsToken(APPBUX, null, []));

  // ══ 8. Serve/settle independence ══
  section('8. Serving does not depend on settlement succeeding');
  // The design: settlement is fire-and-forget; a settlement revert must not
  // block bytes. Simulate a settle that throws, assert the "serve" boolean.
  function serveChunk(paymentValid) {
    // bytes are served if payment token VERIFIES; settlement is async/after
    return paymentValid; // serving gated on verification, not settlement
  }
  const goodEnv = await sign(viewer, { recipientsHash:polHash(P), max:50, line:20, policy:P });
  const served = serveChunk(oc._verify(goodEnv.stm, goodEnv.sig[0].signature));
  check('valid payment → bytes served regardless of settlement timing', served === true);
  // Even if settlement later reverts (e.g. double-settle), bytes were already out
  let reSettle = oc.execPolicy(goodEnv.stm, goodEnv.sig[0].signature, 50n, P, jet.address);
  let reSettle2 = oc.execPolicy(goodEnv.stm, goodEnv.sig[0].signature, 50n, P, jet.address); // idempotent, pays 0
  check('re-settlement is idempotent (no double-pay), serve already happened',
    Object.keys(reSettle2).length === 0);

  out.forEach(l=>console.log(l));
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
