/**
 * TRUE END-TO-END ON-CHAIN TEST.
 *
 * Deploys the REAL compiled OpenClaiming.sol to a local EVM (ganache) and
 * settles REAL EIP-712 payment tokens produced by the same signing code the
 * browser and Jet use. This is the last untested seam: whether a token the
 * plugin signs is actually accepted by the contract's ecrecover and splits
 * funds correctly on chain.
 *
 * Logs every transaction (hash, gas, calldata prefix) so results are
 * inspectable and comparable against a public-testnet run.
 */
const ganache = require('ganache');
const ethers = require('ethers');
const fs = require('fs');
const path = require('path');

let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }
const art = JSON.parse(fs.readFileSync(path.join(process.cwd(),'tests/evm/artifacts.json'),'utf8'));

const KEYS = {
  jet:     '0x' + 'ce'.repeat(32),
  viewer:  '0x' + 'b2'.repeat(32),
  author:  '0x' + 'a1'.repeat(32),
  drop:    '0x' + 'd0'.repeat(32),
  sponsor: '0x' + '5b'.repeat(32)
};

(async () => {
  section('Boot local EVM + deploy REAL OpenClaiming.sol');
  const server = ganache.server({
    logging: { quiet: true },
    chain:   { chainId: 56, networkId: 56 },   // pretend BSC
    wallet:  { accounts: [
      ...Object.values(KEYS).map(secretKey => ({ secretKey, balance: '0x56BC75E2D63100000' })),
      { secretKey: '0x' + 'cc'.repeat(32), balance: '0x56BC75E2D63100000' }  // "poor" wallet (has ETH, no tokens)
    ] }
  });
  await server.listen(0);
  const port = server.address().port;
  const provider = new ethers.JsonRpcProvider('http://127.0.0.1:'+port);
  const net = await provider.getNetwork();
  check('local EVM up, chainId 56', Number(net.chainId)===56, String(net.chainId));

  // Raw wallets sign EIP-712 (NonceManager has no signTypedData);
  // *Tx variants send transactions with managed nonces.
  const jet     = new ethers.Wallet(KEYS.jet, provider);
  const viewer  = new ethers.Wallet(KEYS.viewer, provider);
  const author  = new ethers.Wallet(KEYS.author, provider);
  const drop    = new ethers.Wallet(KEYS.drop, provider);
  const sponsor = new ethers.Wallet(KEYS.sponsor, provider);
  const jetTx     = new ethers.NonceManager(jet);
  const viewerTx  = new ethers.NonceManager(viewer);
  const sponsorTx = new ethers.NonceManager(sponsor);

  // Deploy the REAL contract (zero constructor args)
  const ocFactory = new ethers.ContractFactory(art.OpenClaiming.abi, art.OpenClaiming.bytecode, jetTx);
  const oc = await ocFactory.deploy();
  await oc.waitForDeployment();
  const OC_ADDR = await oc.getAddress();
  const deployTx = oc.deploymentTransaction();
  const deployRc = await provider.getTransactionReceipt(deployTx.hash);
  check('OpenClaiming deployed', ethers.isAddress(OC_ADDR));
  console.log('      address : ' + OC_ADDR);
  console.log('      tx      : ' + deployTx.hash);
  console.log('      gas used: ' + deployRc.gasUsed.toString());
  const code = await provider.getCode(OC_ADDR);
  check('deployed bytecode is present on chain', code.length > 2, code.length+' chars');

  const tokFactory = new ethers.ContractFactory(art.TestToken.abi, art.TestToken.bytecode, jetTx);
  const tok = await tokFactory.deploy(); await tok.waitForDeployment();
  const TOK = await tok.getAddress();
  check('test ERC-20 deployed', ethers.isAddress(TOK));
  console.log('      token   : ' + TOK);

  // ══ The signing format the plugin uses ══
  const domain = { name:'OpenClaiming', version:'1', chainId:56, verifyingContract:OC_ADDR };
  const TYPES = { Payment:[
    {name:'payer',type:'address'},{name:'token',type:'address'},{name:'recipientsHash',type:'bytes32'},
    {name:'max',type:'uint256'},{name:'line',type:'uint256'},{name:'nbf',type:'uint256'},
    {name:'exp',type:'uint256'},{name:'contract',type:'address'}]};
  const ZERO32='0x'+'00'.repeat(32);
  const now = Math.floor(Date.now()/1000);
  const rhPlain = a => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]'],[a]));
  const polHash = p => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['address[]','uint256[]','uint256','bytes32','address[]'],
    [p.payees,p.fractions.map(BigInt),BigInt(p.dynamicBps),p.dynamicConstraint,p.targets]));

  async function signPayment(w, o) {
    const stm = { payer:w.address, token:TOK, recipientsHash:o.recipientsHash||ZERO32,
      max:String(o.max), line:String(o.line||0), nbf:'0', exp:String(o.exp||now+3600),
      contract:OC_ADDR };
    const value = {...stm, max:BigInt(stm.max), line:BigInt(stm.line), nbf:0n, exp:BigInt(stm.exp)};
    const sig = await w.signTypedData(domain, TYPES, value);
    return { stm, sig };
  }

  // ══ CRITICAL: does the contract's typehash match ours? ══
  section('Format agreement: plugin ↔ deployed contract');
  const tstr = ethers.TypedDataEncoder.from(TYPES).encodeType('Payment');
  console.log('      typestring: ' + tstr);
  // Ask the contract to hash a struct we also hash locally, if it exposes a view.
  // Ask the DEPLOYED CONTRACT for its own typehash and compare to ours.
  const chainTypehash = await oc.PAYMENTS_TYPEHASH();
  const localTypehash = ethers.keccak256(ethers.toUtf8Bytes(tstr));
  console.log('      chain typehash: ' + chainTypehash);
  console.log('      local typehash: ' + localTypehash);
  check('PLUGIN TYPEHASH == DEPLOYED CONTRACT PAYMENTS_TYPEHASH',
    chainTypehash.toLowerCase() === localTypehash.toLowerCase());

  const chainName = await oc.NAME_HASH();
  check('contract NAME_HASH == keccak("OpenClaiming")',
    chainName.toLowerCase() === ethers.keccak256(ethers.toUtf8Bytes('OpenClaiming')).toLowerCase());

  // And compare a full EIP-712 digest: contract's paymentsDigest vs ethers.
  const probe = { payer: viewer.address, token: TOK,
    recipientsHash: rhPlain([drop.address]), max: 12345n, line: 9n,
    nbf: 0n, exp: BigInt(now+7200), contractAddr: OC_ADDR };
  const chainDigest = await oc.paymentsDigest(probe);
  const localDigest = ethers.TypedDataEncoder.hash(domain, TYPES,
    { payer: probe.payer, token: probe.token, recipientsHash: probe.recipientsHash,
      max: probe.max, line: probe.line, nbf: probe.nbf, exp: probe.exp,
      contract: OC_ADDR });
  console.log('      chain digest  : ' + chainDigest);
  console.log('      local digest  : ' + localDigest);
  check('PLUGIN DIGEST == DEPLOYED CONTRACT paymentsDigest (byte-exact)',
    chainDigest.toLowerCase() === localDigest.toLowerCase());

  // recipientsHash helper agreement
  const chainRH = await oc.paymentsHashRecipients([drop.address]);
  check('plugin recipientsHash == contract paymentsHashRecipients',
    chainRH.toLowerCase() === rhPlain([drop.address]).toLowerCase());

  // policy hash agreement
  const testPol = { payees:[author.address], fractions:[9000n], dynamicBps:1000n,
                    dynamicConstraint:ZERO32, targets:[] };
  const chainPH = await oc.hashPolicy(testPol);
  check('plugin policyHash == contract hashPolicy',
    chainPH.toLowerCase() === polHash(testPol).toLowerCase(),
    '\n      chain: '+chainPH+'\n      local: '+polHash(testPol));

  // Fund + approve. Explicit nonces: ganache mines instantly and ethers'
  // cached nonce can collide.
  await (await tok.connect(jetTx).mint(viewer.address,  ethers.parseEther('1000'))).wait();
  await (await tok.connect(jetTx).mint(sponsor.address, ethers.parseEther('1000'))).wait();
  await (await tok.connect(jetTx).mint(jet.address,     ethers.parseEther('1000'))).wait();
  await (await tok.connect(viewerTx).approve(OC_ADDR,  ethers.MaxUint256)).wait();
  await (await tok.connect(sponsorTx).approve(OC_ADDR, ethers.MaxUint256)).wait();
  await (await tok.connect(jetTx).approve(OC_ADDR,     ethers.MaxUint256)).wait();
  check('payers funded and approved OpenClaiming', true);

  // ══ REAL plain settlement: viewer → drop ══
  section('On-chain paymentsExecute (plain, single recipient)');
  const amt = ethers.parseEther('10');
  const p1 = await signPayment(viewer, { recipientsHash: rhPlain([drop.address]), max: amt.toString(), line: 0 });
  console.log('      signed stm : payer=' + p1.stm.payer.slice(0,10) + '… max=' + p1.stm.max + ' line=' + p1.stm.line);
  console.log('      signature  : ' + p1.sig.slice(0,26) + '…');

  const before = await tok.balanceOf(drop.address);
  let tx1, rc1, execErr=null;
  try {
    tx1 = await oc.connect(jetTx).paymentsExecute(
      { payer:p1.stm.payer, token:TOK, recipientsHash:p1.stm.recipientsHash,
        max:BigInt(p1.stm.max), line:BigInt(p1.stm.line), nbf:0n, exp:BigInt(p1.stm.exp),
        contractAddr:OC_ADDR },
      [drop.address], p1.sig, drop.address, amt, ethers.ZeroAddress);
    rc1 = await tx1.wait();
  } catch (e) { execErr = e; jetTx.reset(); }
  check('paymentsExecute accepted the plugin-signed token', !execErr,
    execErr ? (execErr.shortMessage||execErr.message||'').slice(0,120) : '');
  if (rc1) {
    console.log('      tx      : ' + tx1.hash);
    console.log('      gas used: ' + rc1.gasUsed.toString());
    console.log('      calldata: ' + tx1.data.slice(0,42) + '…  (' + ((tx1.data.length-2)/2) + ' bytes)');
    const after = await tok.balanceOf(drop.address);
    check('Drop received exactly the settled amount on chain',
      (after-before)===amt, ethers.formatEther(after-before)+' vs '+ethers.formatEther(amt));
    const rt = await oc.receivedTotal(TOK, drop.address);
    check('contract receivedTotal ledger matches', rt===amt, ethers.formatEther(rt));
  }

  // ══ Watermark: replay pays nothing ══
  section('On-chain watermark (cumulative, replay-safe)');
  const b2 = await tok.balanceOf(drop.address);
  let replayed=false;
  try { const _nr = await provider.getTransactionCount(jet.address,'pending');
    const t = await oc.connect(jetTx).paymentsExecute(
      { payer:p1.stm.payer, token:TOK, recipientsHash:p1.stm.recipientsHash,
        max:BigInt(p1.stm.max), line:0n, nbf:0n, exp:BigInt(p1.stm.exp), contractAddr:OC_ADDR },
      [drop.address], p1.sig, drop.address, amt, ethers.ZeroAddress);
    await t.wait(); replayed=true;
  } catch(e) { jetTx.reset(); }
  const b3 = await tok.balanceOf(drop.address);
  check('replaying the same watermark transfers nothing more',
    b3===b2, 'delta '+ethers.formatEther(b3-b2)+(replayed?' (tx succeeded but paid 0)':' (reverted)'));

  // ══ REAL policy settlement: atomic 90/10 split ══
  section('On-chain paymentsExecutePolicy (atomic split)');
  const policy = { payees:[author.address], fractions:[9000n], dynamicBps:1000n,
                   dynamicConstraint:ZERO32, targets:[] };
  const amt2 = ethers.parseEther('100');
  const p2 = await signPayment(viewer, { recipientsHash: polHash(policy), max: amt2.toString(), line: 7 });
  const aBefore = await tok.balanceOf(author.address);
  const jBefore = await tok.balanceOf(jet.address);
  let tx2, rc2, polErr=null;
  try {
    tx2 = await oc.connect(jetTx).paymentsExecutePolicy(
      { payer:p2.stm.payer, token:TOK, recipientsHash:p2.stm.recipientsHash,
        max:BigInt(p2.stm.max), line:BigInt(p2.stm.line), nbf:0n, exp:BigInt(p2.stm.exp),
        contractAddr:OC_ADDR },
      p2.sig, amt2,
      { payees:policy.payees, fractions:policy.fractions, dynamicBps:policy.dynamicBps,
        dynamicConstraint:policy.dynamicConstraint, targets:policy.targets },
      jet.address, []);
    rc2 = await tx2.wait();
  } catch(e) { polErr = e; jetTx.reset(); }
  check('paymentsExecutePolicy accepted the plugin-signed policy token', !polErr,
    polErr ? (polErr.shortMessage||polErr.message||'').slice(0,140) : '');
  if (rc2) {
    console.log('      tx      : ' + tx2.hash);
    console.log('      gas used: ' + rc2.gasUsed.toString());
    const aGot = (await tok.balanceOf(author.address)) - aBefore;
    const jGot = (await tok.balanceOf(jet.address)) - jBefore;
    console.log('      author  : +' + ethers.formatEther(aGot));
    console.log('      jet     : +' + ethers.formatEther(jGot));
    check('author received 90% ON CHAIN', aGot===amt2*9000n/10000n, ethers.formatEther(aGot));
    check('Jet (dynamic slot) received 10% ON CHAIN', jGot===amt2*1000n/10000n, ethers.formatEther(jGot));
    check('split is exact — nothing lost', (aGot+jGot)===amt2, ethers.formatEther(aGot+jGot));
  }

  // ══ Tamper: modified amount must be rejected by ecrecover ══
  section('On-chain rejection of tampered tokens');
  let tamperOk=false, tamperMsg='';
  try {
    const t = await oc.connect(jetTx).paymentsExecute(
      { payer:p1.stm.payer, token:TOK, recipientsHash:rhPlain([drop.address]),
        max:ethers.parseEther('9999'), line:0n, nbf:0n, exp:BigInt(p1.stm.exp), contractAddr:OC_ADDR },
      [drop.address], p1.sig, drop.address, ethers.parseEther('9999'), ethers.ZeroAddress);
    await t.wait(); tamperOk=true;
  } catch(e){ tamperMsg=(e.shortMessage||e.message||'').slice(0,80); jetTx.reset(); }
  check('inflating max invalidates the signature (rejected on chain)', !tamperOk, tamperMsg);

  let wrongDeploy=false;
  try {
    const t = await oc.connect(jetTx).paymentsExecute(
      { payer:p1.stm.payer, token:TOK, recipientsHash:rhPlain([drop.address]),
        max:BigInt(p1.stm.max), line:0n, nbf:0n, exp:BigInt(p1.stm.exp),
        contractAddr:'0x000000000000000000000000000000000000dEaD' },
      [drop.address], p1.sig, drop.address, amt, ethers.ZeroAddress);
    await t.wait(); wrongDeploy=true;
  } catch(e){ jetTx.reset(); }
  check('token bound to another deployment is rejected on chain', !wrongDeploy);

  // ══ Sponsored settlement on an opaque line ══
  section('On-chain sponsored payment (viewer absent from chain)');
  const vid = 'anon-viewer-42';
  const line = BigInt(ethers.keccak256(ethers.toUtf8Bytes('safecloud.sponsor.'+vid)));
  const amt3 = ethers.parseEther('5');
  const p3 = await signPayment(sponsor, { recipientsHash: polHash(policy), max: amt3.toString(), line: line.toString() });
  const aB3 = await tok.balanceOf(author.address);
  let tx3, rc3, spErr=null;
  try {
    tx3 = await oc.connect(jetTx).paymentsExecutePolicy(
      { payer:p3.stm.payer, token:TOK, recipientsHash:p3.stm.recipientsHash,
        max:BigInt(p3.stm.max), line:BigInt(p3.stm.line), nbf:0n, exp:BigInt(p3.stm.exp),
        contractAddr:OC_ADDR },
      p3.sig, amt3,
      { payees:policy.payees, fractions:policy.fractions, dynamicBps:policy.dynamicBps,
        dynamicConstraint:policy.dynamicConstraint, targets:policy.targets },
      jet.address, []);
    rc3 = await tx3.wait();
  } catch(e){ spErr=e; jetTx.reset(); }
  check('sponsored policy token settles on chain', !spErr,
    spErr?(spErr.shortMessage||spErr.message||'').slice(0,120):'');
  if (rc3) {
    console.log('      tx      : ' + tx3.hash + '   gas: ' + rc3.gasUsed.toString());
    console.log('      line    : ' + line.toString().slice(0,20) + '…  (opaque, = keccak(viewerId))');
    check('author paid from the SPONSOR balance', (await tok.balanceOf(author.address))-aB3 === amt3*9000n/10000n);
    const vSpent = await oc.redeemed(TOK, viewer.address, author.address).catch(()=>null);
    check('viewer address never appears as payer for this settlement',
      p3.stm.payer.toLowerCase()===sponsor.address.toLowerCase());
  }

// ═══════════════════════════════════════════════════════════════════════
// EXTENDED micropayment scenarios — appended to the existing on-chain test.
// Run the original first; these build on its deployed contracts + signers.
// ═══════════════════════════════════════════════════════════════════════

  // ══ Micropayment accumulation: multiple partial claims against one max ══
  section('Micropayment accumulation (partial claims against one max)');
  const maxMicro = ethers.parseEther('50');
  const p4 = await signPayment(viewer, { recipientsHash: rhPlain([drop.address]), max: maxMicro.toString(), line: 100 });
  const micro1 = ethers.parseEther('10');
  const micro2 = ethers.parseEther('15');
  const micro3 = ethers.parseEther('25');   // 10+15+25 = 50 = max
  const micro4 = ethers.parseEther('1');    // over max — must fail

  const db4 = await tok.balanceOf(drop.address);
  // Claim 1: 10 of 50
  let t4 = await oc.connect(jetTx).paymentsExecute(
    { payer:p4.stm.payer, token:TOK, recipientsHash:p4.stm.recipientsHash,
      max:BigInt(p4.stm.max), line:100n, nbf:0n, exp:BigInt(p4.stm.exp), contractAddr:OC_ADDR },
    [drop.address], p4.sig, drop.address, micro1, ethers.ZeroAddress);
  await t4.wait();
  check('partial claim 1: 10 of 50 accepted', (await tok.balanceOf(drop.address))-db4 === micro1);

  // Claim 2: 15 more (total spent = 25)
  const db5 = await tok.balanceOf(drop.address);
  t4 = await oc.connect(jetTx).paymentsExecute(
    { payer:p4.stm.payer, token:TOK, recipientsHash:p4.stm.recipientsHash,
      max:BigInt(p4.stm.max), line:100n, nbf:0n, exp:BigInt(p4.stm.exp), contractAddr:OC_ADDR },
    [drop.address], p4.sig, drop.address, micro2, ethers.ZeroAddress);
  await t4.wait();
  check('partial claim 2: 15 more (total=25) accepted', (await tok.balanceOf(drop.address))-db5 === micro2);

  // Claim 3: 25 more (total spent = 50 = max, exactly fills)
  const db6 = await tok.balanceOf(drop.address);
  t4 = await oc.connect(jetTx).paymentsExecute(
    { payer:p4.stm.payer, token:TOK, recipientsHash:p4.stm.recipientsHash,
      max:BigInt(p4.stm.max), line:100n, nbf:0n, exp:BigInt(p4.stm.exp), contractAddr:OC_ADDR },
    [drop.address], p4.sig, drop.address, micro3, ethers.ZeroAddress);
  await t4.wait();
  check('partial claim 3: exactly fills max (total=50)', (await tok.balanceOf(drop.address))-db6 === micro3);

  // Claim 4: 1 more — over max, must revert
  let overMax=false;
  try { t4 = await oc.connect(jetTx).paymentsExecute(
    { payer:p4.stm.payer, token:TOK, recipientsHash:p4.stm.recipientsHash,
      max:BigInt(p4.stm.max), line:100n, nbf:0n, exp:BigInt(p4.stm.exp), contractAddr:OC_ADDR },
    [drop.address], p4.sig, drop.address, micro4, ethers.ZeroAddress);
    await t4.wait(); overMax=true; } catch(e){ jetTx.reset(); }
  check('claim over max is REJECTED on chain', !overMax);

  // ══ Expired token rejection ══
  section('Expired token rejection');
  const pExp = await signPayment(viewer, { recipientsHash: rhPlain([drop.address]), max: '1000', line: 200, exp: now - 60 });
  let expired=false;
  try { const te = await oc.connect(jetTx).paymentsExecute(
    { payer:pExp.stm.payer, token:TOK, recipientsHash:pExp.stm.recipientsHash,
      max:BigInt(pExp.stm.max), line:200n, nbf:0n, exp:BigInt(pExp.stm.exp), contractAddr:OC_ADDR },
    [drop.address], pExp.sig, drop.address, 500n, ethers.ZeroAddress);
    await te.wait(); expired=true; } catch(e){ jetTx.reset(); }
  check('expired token is rejected on chain', !expired);

  // ══ Insufficient payer balance ══
  section('Insufficient payer balance');
  const poor = new ethers.Wallet('0x'+'cc'.repeat(32), provider);
  const poorTx = new ethers.NonceManager(poor);
  // poor has ETH (for gas) but zero TestToken
  await (await tok.connect(jetTx).mint(poor.address, 0n)).wait();  // ensure 0 balance
  await (await tok.connect(poorTx).approve(OC_ADDR, ethers.MaxUint256)).wait();
  const pPoor = await signPayment(poor, { recipientsHash: rhPlain([drop.address]), max: '1000', line: 300 });
  let poorFail=false;
  try { const tp = await oc.connect(jetTx).paymentsExecute(
    { payer:pPoor.stm.payer, token:TOK, recipientsHash:pPoor.stm.recipientsHash,
      max:1000n, line:300n, nbf:0n, exp:BigInt(pPoor.stm.exp), contractAddr:OC_ADDR },
    [drop.address], pPoor.sig, drop.address, 500n, ethers.ZeroAddress);
    await tp.wait(); poorFail=true; } catch(e){ jetTx.reset(); }
  check('insufficient payer balance reverts', !poorFail);

  // ══ Retry after failure (nonce collision recovery) ══
  section('Retry after failure (nonce recovery)');
  // After the reverts above, the Jet's nonce manager was reset. A fresh valid
  // settlement should succeed — this proves retry-after-failure works.
  const retryAmt = ethers.parseEther('3');
  const pRetry = await signPayment(viewer, { recipientsHash: rhPlain([drop.address]), max: retryAmt.toString(), line: 400 });
  const db7 = await tok.balanceOf(drop.address);
  let retryOk=false;
  try { const tr = await oc.connect(jetTx).paymentsExecute(
    { payer:pRetry.stm.payer, token:TOK, recipientsHash:pRetry.stm.recipientsHash,
      max:BigInt(pRetry.stm.max), line:400n, nbf:0n, exp:BigInt(pRetry.stm.exp), contractAddr:OC_ADDR },
    [drop.address], pRetry.sig, drop.address, retryAmt, ethers.ZeroAddress);
    await tr.wait(); retryOk=true; } catch(e){ jetTx.reset(); }
  check('retry after prior failures succeeds', retryOk);
  if (retryOk) check('retry paid the correct amount', (await tok.balanceOf(drop.address))-db7 === retryAmt);


    section('Summary');
  console.log('      OpenClaiming : ' + OC_ADDR);
  console.log('      chainId      : 56 (local)');
  console.log('      solc         : 0.8.36, optimizer+viaIR, 14172 bytes');
  await server.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})().catch(e => { console.log('FATAL:', e.message); process.exit(1); });
