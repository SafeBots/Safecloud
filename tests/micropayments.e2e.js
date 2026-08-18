// End-to-end micropayment settlement against the REAL deployed OpenClaiming.sol,
// covering the failure/retry/double-spend scenarios a production Jet hits.
//
//   - happy path: sign a payment token, settle on-chain, recipient paid
//   - watermark accumulation: multiple partial claims against one max
//   - double-spend prevention: claiming past max reverts on-chain
//   - insufficient allowance/balance: settlement fails, then succeeds on retry
//     after funding (real transaction retry)
//   - expired token (exp in the past): rejected
//   - not-yet-valid token (nbf in the future): rejected
//   - wrong-contract binding: a token for another address reverts
const ganache = require('ganache');
const ethers = require('ethers');
const fs = require('fs');
const path = require('path');

const art = JSON.parse(fs.readFileSync(path.join(__dirname, 'evm/artifacts.json'), 'utf8'));

let pass = 0, fail = 0;
function check(n, ok, extra) { ok ? pass++ : fail++; console.log(`  ${ok?'\u2713':'\u2717'} ${n}${extra?'  ('+extra+')':''}`); }
function section(t){ console.log('\n\u2500\u2500 ' + t + ' \u2500\u2500'); }

(async () => {
  const KEYS = {
    jet:    '0x' + '11'.repeat(32),
    viewer: '0x' + '22'.repeat(32),
    drop:   '0x' + '33'.repeat(32),
    author: '0x' + '44'.repeat(32),
  };
  const server = ganache.server({
    logging: { quiet: true },
    chain: { chainId: 56, networkId: 56 },
    wallet: { accounts: Object.values(KEYS).map(secretKey => ({ secretKey, balance: '0x3635C9ADC5DEA00000' })) }
  });
  await server.listen(0);
  const provider = new ethers.JsonRpcProvider('http://127.0.0.1:' + server.address().port);
  const jet    = new ethers.Wallet(KEYS.jet, provider);
  const viewer = new ethers.Wallet(KEYS.viewer, provider);
  const drop   = new ethers.Wallet(KEYS.drop, provider);
  const author = new ethers.Wallet(KEYS.author, provider);
  const jetTx  = new ethers.NonceManager(jet);
  const viewerTx = new ethers.NonceManager(viewer);

  section('Deploy real OpenClaiming + TestToken');
  const oc = await new ethers.ContractFactory(art.OpenClaiming.abi, art.OpenClaiming.bytecode, jetTx).deploy();
  await oc.waitForDeployment();
  const OC_ADDR = await oc.getAddress();
  const tok = await new ethers.ContractFactory(art.TestToken.abi, art.TestToken.bytecode, jetTx).deploy();
  await tok.waitForDeployment();
  const TOK = await tok.getAddress();
  check('OpenClaiming deployed', ethers.isAddress(OC_ADDR));
  check('TestToken deployed', ethers.isAddress(TOK));
  check('typehash gate', (await oc.PAYMENTS_TYPEHASH()).toLowerCase() ===
    '0xa6aa1cd3e819678d29365a4f2d841f112cc67f805d75ae9c99e164b63b955b63');

  const domain = { name:'OpenClaiming', version:'1', chainId:56, verifyingContract:OC_ADDR };
  const TYPES = { Payment:[
    {name:'payer',type:'address'},{name:'token',type:'address'},{name:'recipientsHash',type:'bytes32'},
    {name:'max',type:'uint256'},{name:'line',type:'uint256'},{name:'nbf',type:'uint256'},
    {name:'exp',type:'uint256'},{name:'contract',type:'address'}]};
  const now = Math.floor(Date.now()/1000);
  const rh = a => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]'],[a]));

  async function signPayment(w, o) {
    const stm = { payer:w.address, token:TOK, recipientsHash:o.recipientsHash,
      max:BigInt(o.max), line:BigInt(o.line||0), nbf:BigInt(o.nbf||0),
      exp:BigInt(o.exp!==undefined?o.exp:now+3600), contract:o.contract||OC_ADDR };
    const sig = await w.signTypedData(domain, TYPES, stm);
    return { p: { payer:stm.payer, token:stm.token, recipientsHash:stm.recipientsHash,
      max:stm.max, line:stm.line, nbf:stm.nbf, exp:stm.exp, contractAddr:stm.contract }, sig };
  }
  const ocViewer = oc.connect(viewerTx);

  // ══ Happy path ══
  section('Happy path: viewer signs, settles to drop');
  await (await tok.mint(viewer.address, ethers.parseUnits('1000', 18))).wait();
  await (await tok.connect(viewerTx).approve(OC_ADDR, ethers.MaxUint256)).wait();
  const recipients = [drop.address];
  const t1 = await signPayment(viewer, { recipientsHash: rh(recipients), max: ethers.parseUnits('100', 18) });
  const dropBal0 = await tok.balanceOf(drop.address);
  const amt1 = ethers.parseUnits('10', 18);
  await (await ocViewer.paymentsExecute(t1.p, recipients, t1.sig, drop.address, amt1, ethers.ZeroAddress)).wait();
  const dropBal1 = await tok.balanceOf(drop.address);
  check('drop received first micropayment', dropBal1 - dropBal0 === amt1, ethers.formatUnits(amt1,18));

  // ══ Watermark accumulation: same token, second partial claim ══
  section('Watermark: second partial claim against same max accumulates');
  const amt2 = ethers.parseUnits('15', 18);
  await (await ocViewer.paymentsExecute(t1.p, recipients, t1.sig, drop.address, amt2, ethers.ZeroAddress)).wait();
  const dropBal2 = await tok.balanceOf(drop.address);
  check('second claim accumulated (spent = 25)', dropBal2 - dropBal0 === amt1 + amt2, '25 total');

  // ══ Double-spend prevention: claim beyond max reverts ══
  section('Double-spend: claiming past max reverts on-chain');
  let reverted = false;
  try {
    // already spent 25 of 100; try to claim 80 more → 105 > 100
    await (await ocViewer.paymentsExecute(t1.p, recipients, t1.sig, drop.address, ethers.parseUnits('80',18), ethers.ZeroAddress)).wait();
  } catch (e) { reverted = true; }
  viewerTx.reset();
  check('over-max claim reverted (watermark enforced)', reverted);
  const dropBalAfterRevert = await tok.balanceOf(drop.address);
  check('no funds moved on reverted claim', dropBalAfterRevert === dropBal2);

  // ══ Remaining balance is claimable (75 left) ══
  section('Remaining watermark is claimable');
  await (await ocViewer.paymentsExecute(t1.p, recipients, t1.sig, drop.address, ethers.parseUnits('75',18), ethers.ZeroAddress)).wait();
  const dropBal3 = await tok.balanceOf(drop.address);
  check('exactly max (100) now spent', dropBal3 - dropBal0 === ethers.parseUnits('100',18), '100 total');

  // ══ Insufficient balance → fail, then retry after funding ══
  section('Insufficient balance: fails, then succeeds on retry after funding');
  const poorPayer = new ethers.Wallet('0x'+'55'.repeat(32), provider);
  await (await jetTx.sendTransaction({ to: poorPayer.address, value: ethers.parseEther('1') })).wait();
  // poorPayer approves but has NO token balance
  const poorApproveNM = new ethers.NonceManager(poorPayer);
  await (await tok.connect(poorApproveNM).approve(OC_ADDR, ethers.MaxUint256)).wait();
  const tPoor = await signPayment(poorPayer, { recipientsHash: rh(recipients), max: ethers.parseUnits('50',18) });
  const ocPoorNM = new ethers.NonceManager(poorPayer);
  const ocPoor = oc.connect(ocPoorNM);
  let failedNoFunds = false;
  try {
    await (await ocPoor.paymentsExecute(tPoor.p, recipients, tPoor.sig, drop.address, ethers.parseUnits('20',18), ethers.ZeroAddress)).wait();
  } catch (e) { failedNoFunds = true; }
  ocPoorNM.reset();
  check('settlement failed with no payer balance', failedNoFunds);
  // RETRY after funding the payer
  await (await tok.mint(poorPayer.address, ethers.parseUnits('100',18))).wait();
  const dropBalR0 = await tok.balanceOf(drop.address);
  await (await ocPoor.paymentsExecute(tPoor.p, recipients, tPoor.sig, drop.address, ethers.parseUnits('20',18), ethers.ZeroAddress)).wait();
  const dropBalR1 = await tok.balanceOf(drop.address);
  check('RETRY succeeded after funding (same signed token)', dropBalR1 - dropBalR0 === ethers.parseUnits('20',18));

  // ══ Expired token ══
  section('Expired token (exp in the past) rejected');
  const tExp = await signPayment(viewer, { recipientsHash: rh(recipients), max: ethers.parseUnits('10',18), exp: now - 10 });
  let expRejected = false;
  try { await (await ocViewer.paymentsExecute(tExp.p, recipients, tExp.sig, drop.address, ethers.parseUnits('5',18), ethers.ZeroAddress)).wait(); }
  catch (e) { expRejected = true; }
  viewerTx.reset();
  check('expired token rejected', expRejected);

  // ══ Not-yet-valid token ══
  section('Not-yet-valid token (nbf in the future) rejected');
  const tNbf = await signPayment(viewer, { recipientsHash: rh(recipients), max: ethers.parseUnits('10',18), nbf: now + 3600 });
  let nbfRejected = false;
  try { await (await ocViewer.paymentsExecute(tNbf.p, recipients, tNbf.sig, drop.address, ethers.parseUnits('5',18), ethers.ZeroAddress)).wait(); }
  catch (e) { nbfRejected = true; }
  viewerTx.reset();
  check('not-yet-valid token rejected', nbfRejected);

  // ══ Wrong-contract binding ══
  section('Wrong-contract binding rejected (anti-replay)');
  const tWrong = await signPayment(viewer, { recipientsHash: rh(recipients), max: ethers.parseUnits('10',18),
    contract: '0x'+'de'.repeat(20) });
  let wrongRejected = false;
  try { await (await ocViewer.paymentsExecute(tWrong.p, recipients, tWrong.sig, drop.address, ethers.parseUnits('5',18), ethers.ZeroAddress)).wait(); }
  catch (e) { wrongRejected = true; }
  viewerTx.reset();
  check('token bound to a different contract rejected', wrongRejected);

  // ══ Forged signature ══
  section('Forged signature rejected');
  const tForge = await signPayment(viewer, { recipientsHash: rh(recipients), max: ethers.parseUnits('10',18) });
  tForge.p.max = ethers.parseUnits('1000000',18); // tamper the amount after signing
  let forgeRejected = false;
  try { await (await ocViewer.paymentsExecute(tForge.p, recipients, tForge.sig, drop.address, ethers.parseUnits('5',18), ethers.ZeroAddress)).wait(); }
  catch (e) { forgeRejected = true; }
  viewerTx.reset();
  check('tampered/forged token rejected by ecrecover', forgeRejected);

  console.log(`\n${pass} passed, ${fail} failed`);
  await server.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('FATAL', e.message); process.exit(1); });
