/**
 * Full end-to-end test of the OCP + IncomeContract payment pipeline.
 *
 * Simulates the complete Safecloud economics flow:
 *   1. Deploy Safebux ERC-20 and OpenClaiming
 *   2. Deploy IncomeContract for creator revenue distribution
 *   3. Cloud pays Drop via OpenClaiming policy payment (60/20/15/5 split)
 *   4. Creator's 15% goes to IncomeContract, which distributes to team members
 *   5. Team members claim from IncomeContract
 *
 * This models the full Safe Store payment flow:
 *   User buys access → Cloud signs payment → Drop claims via policy →
 *   Revenue splits to Drop/Jet/Creator/Protocol → Creator share flows
 *   to IncomeContract → Individual contributors claim their share
 */

const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

function loadArtifact(dir, name) {
  return JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), 'utf8'));
}

const CHAIN_ID = 31337;
const RPC_URL = 'http://127.0.0.1:8545';

const PAYMENT_TYPES = {
  Payment: [
    { name: 'payer', type: 'address' },
    { name: 'token', type: 'address' },
    { name: 'recipientsHash', type: 'bytes32' },
    { name: 'max', type: 'uint256' },
    { name: 'line', type: 'uint256' },
    { name: 'nbf', type: 'uint256' },
    { name: 'exp', type: 'uint256' },
    { name: 'contract', type: 'address' },
  ]
};

let passed = 0, failed = 0;
function pass(label) { passed++; console.log(`  ✅ ${label}`); }
function fail(label, detail) { failed++; console.log(`  ❌ ${label}: ${detail}`); }

async function main() {
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║  OCP + IncomeContract Full Economics Test               ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  const provider = new ethers.JsonRpcProvider(RPC_URL);

  // Roles
  const deployer   = await provider.getSigner(0);  // contract deployer
  const cloud      = await provider.getSigner(1);  // Safecloud client (payer)
  const drop       = await provider.getSigner(2);  // Drop storage server
  const jet        = await provider.getSigner(3);  // Jet routing server
  const protocol   = await provider.getSigner(4);  // protocol fee address
  // Creator team members (their revenue flows through IncomeContract)
  const leadDev    = await provider.getSigner(5);  // 50% of creator share
  const designer   = await provider.getSigner(6);  // 30% of creator share
  const pmLead     = await provider.getSigner(7);  // 20% of creator share

  const addrs = {};
  for (const [name, signer] of Object.entries({deployer,cloud,drop,jet,protocol,leadDev,designer,pmLead})) {
    addrs[name] = await signer.getAddress();
  }

  console.log('Roles:');
  console.log('  Cloud (payer):      ', addrs.cloud);
  console.log('  Drop (storage):     ', addrs.drop);
  console.log('  Jet (router):       ', addrs.jet);
  console.log('  Protocol (fee):     ', addrs.protocol);
  console.log('  Lead Dev (creator): ', addrs.leadDev);
  console.log('  Designer (creator): ', addrs.designer);
  console.log('  PM Lead (creator):  ', addrs.pmLead);

  // ════════════════════════════════════════════════
  // PHASE 1: Deploy contracts
  // ════════════════════════════════════════════════
  console.log('\n\n═══ PHASE 1: Deploy Contracts ═══\n');

  // Deploy Safebux
  const safebuxArt = loadArtifact(path.join(__dirname, 'artifacts'), 'Safebux');
  const safebux = await (await new ethers.ContractFactory(safebuxArt.abi, safebuxArt.bytecode, deployer)
    .deploy(ethers.parseEther('10000000'))).waitForDeployment();
  const safebuxAddr = await safebux.getAddress();
  console.log('  Safebux ERC-20:', safebuxAddr, '(10M SBUX)');

  // Deploy OpenClaiming
  const ocArt = loadArtifact(path.join(__dirname, 'artifacts'), 'OpenClaiming');
  const oc = await (await new ethers.ContractFactory(ocArt.abi, ocArt.bytecode, deployer)
    .deploy()).waitForDeployment();
  const ocAddr = await oc.getAddress();
  console.log('  OpenClaiming:  ', ocAddr);

  // Deploy IncomeContract (for creator revenue distribution)
  // Uses a direct-deploy version that models the same economics as Intercoin's
  // upgradeable IncomeContract: owner registers recipients, calls pay() to credit,
  // recipients call claim() to withdraw.
  const icArt = loadArtifact(path.join(__dirname, 'artifacts'), 'IncomeContractDirect');
  const ic = await (await new ethers.ContractFactory(icArt.abi, icArt.bytecode, deployer)
    .deploy(safebuxAddr)).waitForDeployment();
  const icAddr = await ic.getAddress();
  console.log('  IncomeContract:', icAddr, '(initialized with Safebux)');

  // Register creator team as recipients in IncomeContract
  console.log('\n  Registering creator team in IncomeContract...');
  await (await ic.connect(deployer).addRecipient(addrs.leadDev)).wait();
  await (await ic.connect(deployer).addRecipient(addrs.designer)).wait();
  await (await ic.connect(deployer).addRecipient(addrs.pmLead)).wait();
  console.log('    Lead Dev registered ✓');
  console.log('    Designer registered ✓');
  console.log('    PM Lead registered ✓');

  // ════════════════════════════════════════════════
  // PHASE 2: Fund and approve
  // ════════════════════════════════════════════════
  console.log('\n\n═══ PHASE 2: Fund & Approve ═══\n');

  // Fund Cloud with 100k SBUX
  await (await safebux.connect(deployer).transfer(addrs.cloud, ethers.parseEther('100000'))).wait();
  console.log('  Cloud funded: 100,000 SBUX');

  // Cloud approves OpenClaiming
  await (await safebux.connect(cloud).approve(ocAddr, ethers.MaxUint256)).wait();
  console.log('  Cloud approved OpenClaiming: unlimited ✓');

  const domain = {
    name: 'OpenClaiming', version: '1',
    chainId: CHAIN_ID, verifyingContract: ocAddr
  };
  const now = Math.floor(Date.now() / 1000);

  // ════════════════════════════════════════════════
  // PHASE 3: Safe Store purchase with policy split
  // ════════════════════════════════════════════════
  console.log('\n\n═══ PHASE 3: Safe Store Purchase ═══');
  console.log('  Scenario: User buys an app from Safe Store for 10,000 SBUX');
  console.log('  Revenue split: Drop 60% | Jet 20% | Creator(IC) 15% | Protocol 5%\n');

  // The creator share goes to the IncomeContract address, not directly to a person
  const payees = [addrs.drop, addrs.jet, icAddr, addrs.protocol];
  const fractions = [6000, 2000, 1500, 500];

  const policyStruct = {
    payees, fractions,
    dynamicBps: 0,
    dynamicConstraint: ethers.ZeroHash,
    targets: []
  };

  const policyHash = await oc.hashPolicy(policyStruct);

  const payment = {
    payer: addrs.cloud,
    token: safebuxAddr,
    recipientsHash: policyHash,
    max: ethers.parseEther('10000'),
    line: 0,
    nbf: 0,
    exp: now + 86400,
    contract: ocAddr
  };

  const sig = await cloud.signTypedData(domain, PAYMENT_TYPES, payment);

  // Capture balances before
  const balBefore = {};
  for (const [name, addr] of Object.entries({cloud:addrs.cloud, drop:addrs.drop, jet:addrs.jet, incomeContract:icAddr, protocol:addrs.protocol})) {
    balBefore[name] = await safebux.balanceOf(addr);
  }

  // Execute the policy payment
  console.log('  Cloud signs EIP-712 payment for 10,000 SBUX...');
  console.log('  Drop calls paymentsExecutePolicy()...\n');

  const tx = await oc.connect(drop).paymentsExecutePolicy(
    {
      payer: payment.payer, token: payment.token,
      recipientsHash: payment.recipientsHash, max: payment.max,
      line: payment.line, nbf: payment.nbf, exp: payment.exp,
      contractAddr: payment.contract
    },
    sig,
    ethers.parseEther('10000'),
    policyStruct,
    ethers.ZeroAddress,
    []
  );
  const receipt = await tx.wait();
  console.log('  Gas used:', receipt.gasUsed.toString());

  // Check splits
  const balAfter = {};
  for (const [name, addr] of Object.entries({cloud:addrs.cloud, drop:addrs.drop, jet:addrs.jet, incomeContract:icAddr, protocol:addrs.protocol})) {
    balAfter[name] = await safebux.balanceOf(addr);
  }

  const dropGot = balAfter.drop - balBefore.drop;
  const jetGot = balAfter.jet - balBefore.jet;
  const icGot = balAfter.incomeContract - balBefore.incomeContract;
  const protGot = balAfter.protocol - balBefore.protocol;

  console.log('\n  Revenue distribution (10,000 SBUX):');
  console.log('    Drop:            +' + ethers.formatEther(dropGot) + ' SBUX (60%)');
  console.log('    Jet:             +' + ethers.formatEther(jetGot) + ' SBUX (20%)');
  console.log('    IncomeContract:  +' + ethers.formatEther(icGot) + ' SBUX (15% → creator team)');
  console.log('    Protocol:        +' + ethers.formatEther(protGot) + ' SBUX (5%)');

  const splitOk =
    dropGot === ethers.parseEther('6000') &&
    jetGot === ethers.parseEther('2000') &&
    icGot === ethers.parseEther('1500') &&
    protGot === ethers.parseEther('500');

  if (splitOk) {
    pass('Policy split: all 4 parties received correct amounts');
  } else {
    fail('Policy split', 'amounts differ from expected');
  }

  // ════════════════════════════════════════════════
  // PHASE 4: Distribute creator share via IncomeContract
  // ════════════════════════════════════════════════
  console.log('\n\n═══ PHASE 4: Creator Team Revenue Distribution ═══');
  console.log('  1,500 SBUX sitting in IncomeContract');
  console.log('  Distributing: Lead Dev 50% | Designer 30% | PM 20%\n');

  // The owner (deployer) calls pay() for each team member
  // IncomeContract.pay(recipient, amount) — credits the recipient's internal balance
  const leadDevShare = ethers.parseEther('750');   // 50% of 1500
  const designerShare = ethers.parseEther('450');  // 30% of 1500
  const pmShare = ethers.parseEther('300');        // 20% of 1500

  await (await ic.connect(deployer).pay(addrs.leadDev, leadDevShare)).wait();
  console.log('  pay(Lead Dev, 750 SBUX) ✓');
  await (await ic.connect(deployer).pay(addrs.designer, designerShare)).wait();
  console.log('  pay(Designer, 450 SBUX) ✓');
  await (await ic.connect(deployer).pay(addrs.pmLead, pmShare)).wait();
  console.log('  pay(PM Lead, 300 SBUX) ✓');

  // Check claimable balance before claiming
  const ldAvail = await ic.claimable(addrs.leadDev);
  console.log('\n  Lead Dev claimable:', ethers.formatEther(ldAvail), 'SBUX');
  const dsAvail = await ic.claimable(addrs.designer);
  console.log('  Designer claimable:', ethers.formatEther(dsAvail), 'SBUX');
  const pmAvail = await ic.claimable(addrs.pmLead);
  console.log('  PM Lead claimable: ', ethers.formatEther(pmAvail), 'SBUX');

  // ════════════════════════════════════════════════
  // PHASE 5: Team members claim their earnings
  // ════════════════════════════════════════════════
  console.log('\n\n═══ PHASE 5: Team Claims ═══\n');

  // Lead Dev claims
  const ldBalBefore = await safebux.balanceOf(addrs.leadDev);
  await (await ic.connect(leadDev).claim()).wait();
  const ldBalAfter = await safebux.balanceOf(addrs.leadDev);
  const ldReceived = ldBalAfter - ldBalBefore;
  console.log('  Lead Dev claimed:', ethers.formatEther(ldReceived), 'SBUX');
  if (ldReceived === leadDevShare) {
    pass('Lead Dev received 750 SBUX (50% of creator share)');
  } else {
    fail('Lead Dev claim', `expected 750, got ${ethers.formatEther(ldReceived)}`);
  }

  // Designer claims
  const dsBalBefore = await safebux.balanceOf(addrs.designer);
  await (await ic.connect(designer).claim()).wait();
  const dsBalAfter = await safebux.balanceOf(addrs.designer);
  const dsReceived = dsBalAfter - dsBalBefore;
  console.log('  Designer claimed:', ethers.formatEther(dsReceived), 'SBUX');
  if (dsReceived === designerShare) {
    pass('Designer received 450 SBUX (30% of creator share)');
  } else {
    fail('Designer claim', `expected 450, got ${ethers.formatEther(dsReceived)}`);
  }

  // PM claims
  const pmBalBefore = await safebux.balanceOf(addrs.pmLead);
  await (await ic.connect(pmLead).claim()).wait();
  const pmBalAfter = await safebux.balanceOf(addrs.pmLead);
  const pmReceived = pmBalAfter - pmBalBefore;
  console.log('  PM Lead claimed:', ethers.formatEther(pmReceived), 'SBUX');
  if (pmReceived === pmShare) {
    pass('PM Lead received 300 SBUX (20% of creator share)');
  } else {
    fail('PM Lead claim', `expected 300, got ${ethers.formatEther(pmReceived)}`);
  }

  // IncomeContract should be empty now
  const icRemaining = await safebux.balanceOf(icAddr);
  console.log('\n  IncomeContract remaining balance:', ethers.formatEther(icRemaining), 'SBUX');
  if (icRemaining === 0n) {
    pass('IncomeContract fully distributed');
  } else {
    fail('IncomeContract drain', `${ethers.formatEther(icRemaining)} remaining`);
  }

  // ════════════════════════════════════════════════
  // PHASE 6: Second purchase (accumulation test)
  // ════════════════════════════════════════════════
  console.log('\n\n═══ PHASE 6: Second Purchase (Accumulation) ═══');
  console.log('  Another user buys the same app for 5,000 SBUX\n');

  const payment2 = {
    payer: addrs.cloud,
    token: safebuxAddr,
    recipientsHash: policyHash,
    max: ethers.parseEther('15000'),  // cumulative watermark: 10k already spent + 5k new
    line: 0,
    nbf: 0,
    exp: now + 86400,
    contract: ocAddr
  };
  const sig2 = await cloud.signTypedData(domain, PAYMENT_TYPES, payment2);

  await (await oc.connect(drop).paymentsExecutePolicy(
    {
      payer: payment2.payer, token: payment2.token,
      recipientsHash: payment2.recipientsHash, max: payment2.max,
      line: payment2.line, nbf: payment2.nbf, exp: payment2.exp,
      contractAddr: payment2.contract
    },
    sig2, ethers.parseEther('5000'), policyStruct, ethers.ZeroAddress, []
  )).wait();

  const icBal2 = await safebux.balanceOf(icAddr);
  console.log('  IncomeContract received:', ethers.formatEther(icBal2), 'SBUX (15% of 5000 = 750)');
  if (icBal2 === ethers.parseEther('750')) {
    pass('Second purchase: IncomeContract received 750 SBUX');
  } else {
    fail('Second purchase IC balance', `expected 750, got ${ethers.formatEther(icBal2)}`);
  }

  // Pay and claim in one go
  await (await ic.connect(deployer).pay(addrs.leadDev, ethers.parseEther('375'))).wait();
  await (await ic.connect(deployer).pay(addrs.designer, ethers.parseEther('225'))).wait();
  await (await ic.connect(deployer).pay(addrs.pmLead, ethers.parseEther('150'))).wait();

  await (await ic.connect(leadDev).claim()).wait();
  await (await ic.connect(designer).claim()).wait();
  await (await ic.connect(pmLead).claim()).wait();

  const icFinal = await safebux.balanceOf(icAddr);
  if (icFinal === 0n) {
    pass('Second round: all team claims successful, IC drained');
  } else {
    fail('Second round drain', `${ethers.formatEther(icFinal)} remaining`);
  }

  // ════════════════════════════════════════════════
  // FINAL SUMMARY
  // ════════════════════════════════════════════════
  console.log('\n\n╔══════════════════════════════════════════════════════════╗');
  console.log('║  FINAL SUMMARY                                         ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  console.log('  Contracts:');
  console.log('    Safebux (ERC-20):   ', safebuxAddr);
  console.log('    OpenClaiming:       ', ocAddr);
  console.log('    IncomeContract:     ', icAddr);
  console.log('    Chain ID:           ', CHAIN_ID);

  console.log('\n  Final balances (after two purchases totaling 15,000 SBUX):');
  const finalBals = {
    'Cloud':          await safebux.balanceOf(addrs.cloud),
    'Drop (60%)':     await safebux.balanceOf(addrs.drop),
    'Jet (20%)':      await safebux.balanceOf(addrs.jet),
    'Protocol (5%)':  await safebux.balanceOf(addrs.protocol),
    'Lead Dev':       await safebux.balanceOf(addrs.leadDev),
    'Designer':       await safebux.balanceOf(addrs.designer),
    'PM Lead':        await safebux.balanceOf(addrs.pmLead),
    'IncomeContract': await safebux.balanceOf(icAddr),
  };
  for (const [name, bal] of Object.entries(finalBals)) {
    console.log(`    ${name.padEnd(18)} ${ethers.formatEther(bal).padStart(12)} SBUX`);
  }

  console.log('\n  Economics flow:');
  console.log('    User → Cloud → OpenClaiming → Policy Split →');
  console.log('      60% → Drop     (storage)');
  console.log('      20% → Jet      (routing)');
  console.log('      15% → IncomeContract → Lead Dev 50% | Designer 30% | PM 20%');
  console.log('       5% → Protocol (Safebots)');

  console.log(`\n  Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('\n  The full Safe Store economics pipeline works end to end. 🎉');
  }
}

main().catch(err => {
  console.error('\n❌ Fatal error:', err.message);
  if (err.data) console.error('  Revert data:', err.data);
  process.exit(1);
});
