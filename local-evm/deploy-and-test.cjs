/**
 * End-to-end deployment and test of the OCP payment pipeline.
 *
 * Deploys OpenClaiming + Safebux on a running Hardhat node,
 * then exercises the full payment flow:
 *   1. Direct payment with EIP-712 signature
 *   2. Line-based watermark channel
 *   3. Policy-based payment with 4-way revenue split
 *   4. Expired payment (should revert)
 *   5. Wrong signer (should revert)
 */

const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

function loadArtifact(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'artifacts', `${name}.json`), 'utf8'));
}

const CHAIN_ID = 31337;
const RPC_URL = 'http://127.0.0.1:8545';

// EIP-712 types matching OpenClaiming's PAYMENTS_TYPEHASH
// The struct field is "contract" in the EIP-712 typehash, but "contractAddr" in Solidity
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

let passed = 0;
let failed = 0;
function pass(label) { passed++; console.log(`  ✅ ${label}`); }
function fail(label, detail) { failed++; console.log(`  ❌ ${label}: ${detail}`); }

async function main() {
  console.log('=== OCP Payment Pipeline End-to-End Test ===\n');

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const deployer = await provider.getSigner(0);
  const cloud    = await provider.getSigner(1);
  const drop     = await provider.getSigner(2);
  const jet      = await provider.getSigner(3);
  const creator  = await provider.getSigner(4);
  const protocol = await provider.getSigner(5);

  const deployerAddr  = await deployer.getAddress();
  const cloudAddr     = await cloud.getAddress();
  const dropAddr      = await drop.getAddress();
  const jetAddr       = await jet.getAddress();
  const creatorAddr   = await creator.getAddress();
  const protocolAddr  = await protocol.getAddress();

  console.log('Accounts:');
  console.log('  Deployer:', deployerAddr);
  console.log('  Cloud:   ', cloudAddr);
  console.log('  Drop:    ', dropAddr);
  console.log('  Jet:     ', jetAddr);
  console.log('  Creator: ', creatorAddr);
  console.log('  Protocol:', protocolAddr);

  // ── Deploy Safebux ──
  console.log('\n── Deploying Safebux ERC-20 ──');
  const safebuxArt = loadArtifact('Safebux');
  const sfbxFactory = new ethers.ContractFactory(safebuxArt.abi, safebuxArt.bytecode, deployer);
  const initialSupply = ethers.parseEther('1000000');
  const safebux = await sfbxFactory.deploy(initialSupply);
  await safebux.waitForDeployment();
  const safebuxAddr = await safebux.getAddress();
  console.log('  Safebux at:', safebuxAddr);
  console.log('  Supply:', ethers.formatEther(await safebux.totalSupply()), 'SBUX');

  // ── Deploy OpenClaiming ──
  console.log('\n── Deploying OpenClaiming ──');
  const ocArt = loadArtifact('OpenClaiming');
  const ocFactory = new ethers.ContractFactory(ocArt.abi, ocArt.bytecode, deployer);
  const oc = await ocFactory.deploy();
  await oc.waitForDeployment();
  const ocAddr = await oc.getAddress();
  console.log('  OpenClaiming at:', ocAddr);

  // ── Fund & approve ──
  console.log('\n── Funding Cloud with 100,000 SBUX ──');
  await (await safebux.connect(deployer).transfer(cloudAddr, ethers.parseEther('100000'))).wait();
  console.log('  Cloud balance:', ethers.formatEther(await safebux.balanceOf(cloudAddr)), 'SBUX');

  await (await safebux.connect(cloud).approve(ocAddr, ethers.MaxUint256)).wait();
  console.log('  Cloud approved OpenClaiming: unlimited ✓');

  const domain = {
    name: 'OpenClaiming',
    version: '1',
    chainId: CHAIN_ID,
    verifyingContract: ocAddr
  };

  const now = Math.floor(Date.now() / 1000);

  // ==================================================
  // TEST 1: Direct Payment (Cloud → Drop)
  // ==================================================
  console.log('\n\n══════════════════════════════════════');
  console.log('TEST 1: Direct Payment (Cloud → Drop)');
  console.log('══════════════════════════════════════');

  // recipientsHash for a single recipient
  const singleRecipients = [dropAddr];
  const recipientsHash = await oc.paymentsHashRecipients(singleRecipients);
  console.log('  recipientsHash:', recipientsHash.slice(0, 20) + '...');

  const payment1 = {
    payer: cloudAddr,
    token: safebuxAddr,
    recipientsHash: recipientsHash,
    max: ethers.parseEther('1000'),
    line: 0,
    nbf: 0,
    exp: now + 86400,
    contract: ocAddr  // must equal address(this) — explicit binding to this deployment
  };

  console.log('  Signing EIP-712 Payment...');
  const sig1 = await cloud.signTypedData(domain, PAYMENT_TYPES, payment1);
  console.log('  Signature:', sig1.slice(0, 20) + '...');

  // paymentsExecute(Payment p, address[] recipients, bytes sig, address recipient, uint256 amount, address hook)
  const claimAmount = ethers.parseEther('500');
  console.log('  Drop calling paymentsExecute() for 500 SBUX...');
  const tx1 = await oc.connect(drop).paymentsExecute(
    {
      payer: payment1.payer,
      token: payment1.token,
      recipientsHash: payment1.recipientsHash,
      max: payment1.max,
      line: payment1.line,
      nbf: payment1.nbf,
      exp: payment1.exp,
      contractAddr: payment1.contract
    },
    singleRecipients,
    sig1,
    dropAddr,
    claimAmount,
    ethers.ZeroAddress // no hook
  );
  const receipt1 = await tx1.wait();
  console.log('  Gas used:', receipt1.gasUsed.toString());

  const dropBal1 = await safebux.balanceOf(dropAddr);
  console.log('  Drop balance:', ethers.formatEther(dropBal1), 'SBUX');
  if (dropBal1 === claimAmount) {
    pass('Direct payment: Drop received 500 SBUX');
  } else {
    fail('Direct payment', `expected 500, got ${ethers.formatEther(dropBal1)}`);
  }

  // Claim again — another 300, same signature (watermark advances)
  console.log('\n  Drop claiming another 300 SBUX from same signature...');
  const tx1b = await oc.connect(drop).paymentsExecute(
    {
      payer: payment1.payer, token: payment1.token,
      recipientsHash: payment1.recipientsHash, max: payment1.max,
      line: payment1.line, nbf: payment1.nbf, exp: payment1.exp,
      contractAddr: payment1.contract
    },
    singleRecipients, sig1, dropAddr,
    ethers.parseEther('300'), ethers.ZeroAddress
  );
  await tx1b.wait();
  const dropBal1b = await safebux.balanceOf(dropAddr);
  console.log('  Drop balance:', ethers.formatEther(dropBal1b), 'SBUX');
  if (dropBal1b === ethers.parseEther('800')) {
    pass('Incremental claim: Drop received cumulative 800 SBUX');
  } else {
    fail('Incremental claim', `expected 800, got ${ethers.formatEther(dropBal1b)}`);
  }

  // Try to claim beyond max (should revert)
  console.log('\n  Trying to over-claim (remaining 200, requesting 500)...');
  try {
    await oc.connect(drop).paymentsExecute(
      {
        payer: payment1.payer, token: payment1.token,
        recipientsHash: payment1.recipientsHash, max: payment1.max,
        line: payment1.line, nbf: payment1.nbf, exp: payment1.exp,
        contractAddr: payment1.contract
      },
      singleRecipients, sig1, dropAddr,
      ethers.parseEther('500'), ethers.ZeroAddress
    );
    fail('Over-claim', 'should have reverted');
  } catch (e) {
    pass('Over-claim correctly reverted');
  }

  // ==================================================
  // TEST 2: Line-Based Watermark Channel
  // ==================================================
  console.log('\n\n══════════════════════════════════════');
  console.log('TEST 2: Line-Based Watermark Channel');
  console.log('══════════════════════════════════════');

  const lineId = 1n;
  const lineMax = ethers.parseEther('10000');
  console.log('  Cloud opening line #1 with 10,000 SBUX cap...');
  const lineOpenTx = await oc.connect(cloud).lineOpen(cloudAddr, lineId, lineMax);
  await lineOpenTx.wait();

  const lineIsOpen = await oc.lineIsOpen(cloudAddr, lineId);
  console.log('  Line open:', lineIsOpen);
  if (lineIsOpen) pass('Line #1 opened'); else fail('Line open', 'not open');

  // Check available
  const lineAvail = await oc.lineAvailable(cloudAddr, lineId, ethers.parseEther('5000'));
  console.log('  Line available (cap check at 5000):', ethers.formatEther(lineAvail), 'SBUX');

  // Payment against the line
  const payment2 = {
    payer: cloudAddr,
    token: safebuxAddr,
    recipientsHash: recipientsHash,
    max: ethers.parseEther('3000'),
    line: lineId,
    nbf: 0,
    exp: now + 86400,
    contract: ocAddr
  };
  const sig2 = await cloud.signTypedData(domain, PAYMENT_TYPES, payment2);

  const dropBalBefore2 = await safebux.balanceOf(dropAddr);
  console.log('\n  Drop claiming 2000 SBUX against line #1...');
  await (await oc.connect(drop).paymentsExecute(
    {
      payer: payment2.payer, token: payment2.token,
      recipientsHash: payment2.recipientsHash, max: payment2.max,
      line: payment2.line, nbf: payment2.nbf, exp: payment2.exp,
      contractAddr: payment2.contract
    },
    singleRecipients, sig2, dropAddr,
    ethers.parseEther('2000'), ethers.ZeroAddress
  )).wait();

  const dropBal2 = await safebux.balanceOf(dropAddr);
  const lineGot = dropBal2 - dropBalBefore2;
  console.log('  Drop received:', ethers.formatEther(lineGot), 'SBUX');
  if (lineGot === ethers.parseEther('2000')) {
    pass('Line-based payment: 2000 SBUX transferred');
  } else {
    fail('Line-based payment', `got ${ethers.formatEther(lineGot)}`);
  }

  // Close the line
  console.log('\n  Cloud closing line #1...');
  await (await oc.connect(cloud).lineClose(cloudAddr, lineId)).wait();
  const lineStillOpen = await oc.lineIsOpen(cloudAddr, lineId);
  if (!lineStillOpen) pass('Line #1 closed'); else fail('Line close', 'still open');

  // ==================================================
  // TEST 3: Policy Payment (Revenue Splits)
  // ==================================================
  console.log('\n\n══════════════════════════════════════');
  console.log('TEST 3: Policy Payment (Revenue Splits)');
  console.log('══════════════════════════════════════');

  // 60% Drop, 20% Jet, 15% Creator, 5% Protocol
  const payees = [dropAddr, jetAddr, creatorAddr, protocolAddr];
  const fractions = [6000, 2000, 1500, 500];

  const policyStruct = {
    payees: payees,
    fractions: fractions,
    dynamicBps: 0,
    dynamicConstraint: ethers.ZeroHash,
    targets: []
  };

  // Use the contract's own hashPolicy to get the correct hash
  const policyHash = await oc.hashPolicy(policyStruct);
  console.log('  Policy hash:', policyHash.slice(0, 20) + '...');
  console.log('  Split: Drop 60% | Jet 20% | Creator 15% | Protocol 5%');

  const payment3 = {
    payer: cloudAddr,
    token: safebuxAddr,
    recipientsHash: policyHash,
    max: ethers.parseEther('5000'),
    line: 0,
    nbf: 0,
    exp: now + 86400,
    contract: ocAddr
  };
  const sig3 = await cloud.signTypedData(domain, PAYMENT_TYPES, payment3);

  const dropB = await safebux.balanceOf(dropAddr);
  const jetB = await safebux.balanceOf(jetAddr);
  const creatorB = await safebux.balanceOf(creatorAddr);
  const protocolB = await safebux.balanceOf(protocolAddr);

  const policyClaim = ethers.parseEther('1000');
  console.log('\n  Executing policy payment of 1000 SBUX...');

  // paymentsExecutePolicy(Payment, bytes sig, uint256 amount, Policy, address dynamicPayee, bytes32[] dynamicProof)
  const tx3 = await oc.connect(drop).paymentsExecutePolicy(
    {
      payer: payment3.payer, token: payment3.token,
      recipientsHash: payment3.recipientsHash, max: payment3.max,
      line: payment3.line, nbf: payment3.nbf, exp: payment3.exp,
      contractAddr: payment3.contract
    },
    sig3,
    policyClaim,
    policyStruct,
    ethers.ZeroAddress,  // dynamicPayee
    []                   // dynamicProof
  );
  const receipt3 = await tx3.wait();
  console.log('  Gas used:', receipt3.gasUsed.toString());

  const dropGot = (await safebux.balanceOf(dropAddr)) - dropB;
  const jetGot = (await safebux.balanceOf(jetAddr)) - jetB;
  const creatorGot = (await safebux.balanceOf(creatorAddr)) - creatorB;
  const protocolGot = (await safebux.balanceOf(protocolAddr)) - protocolB;

  console.log('\n  Revenue distribution (of 1000 SBUX):');
  console.log('    Drop:     +' + ethers.formatEther(dropGot) + ' (expected 600)');
  console.log('    Jet:      +' + ethers.formatEther(jetGot) + ' (expected 200)');
  console.log('    Creator:  +' + ethers.formatEther(creatorGot) + ' (expected 150)');
  console.log('    Protocol: +' + ethers.formatEther(protocolGot) + ' (expected 50)');

  if (dropGot === ethers.parseEther('600') &&
      jetGot === ethers.parseEther('200') &&
      creatorGot === ethers.parseEther('150') &&
      protocolGot === ethers.parseEther('50')) {
    pass('Policy revenue split: all amounts correct');
  } else {
    fail('Policy revenue split', 'amounts differ');
  }

  // ==================================================
  // TEST 4: Expired Payment (Should Revert)
  // ==================================================
  console.log('\n\n══════════════════════════════════════');
  console.log('TEST 4: Expired Payment');
  console.log('══════════════════════════════════════');

  const payment4 = {
    payer: cloudAddr,
    token: safebuxAddr,
    recipientsHash: recipientsHash,
    max: ethers.parseEther('100'),
    line: 0,
    nbf: 0,
    exp: now - 3600,  // expired 1 hour ago
    contract: ocAddr
  };
  const sig4 = await cloud.signTypedData(domain, PAYMENT_TYPES, payment4);

  try {
    await oc.connect(drop).paymentsExecute(
      {
        payer: payment4.payer, token: payment4.token,
        recipientsHash: payment4.recipientsHash, max: payment4.max,
        line: payment4.line, nbf: payment4.nbf, exp: payment4.exp,
        contractAddr: payment4.contract
      },
      singleRecipients, sig4, dropAddr,
      ethers.parseEther('50'), ethers.ZeroAddress
    );
    fail('Expired payment', 'should have reverted');
  } catch (e) {
    pass('Expired payment correctly reverted');
  }

  // ==================================================
  // TEST 5: Wrong Signer
  // ==================================================
  console.log('\n\n══════════════════════════════════════');
  console.log('TEST 5: Wrong Signer');
  console.log('══════════════════════════════════════');

  const payment5 = {
    payer: cloudAddr,
    token: safebuxAddr,
    recipientsHash: recipientsHash,
    max: ethers.parseEther('100'),
    line: 0,
    nbf: 0,
    exp: now + 86400,
    contract: ocAddr
  };
  // Signed by Jet instead of Cloud
  const sig5 = await jet.signTypedData(domain, PAYMENT_TYPES, payment5);

  try {
    await oc.connect(drop).paymentsExecute(
      {
        payer: payment5.payer, token: payment5.token,
        recipientsHash: payment5.recipientsHash, max: payment5.max,
        line: payment5.line, nbf: payment5.nbf, exp: payment5.exp,
        contractAddr: payment5.contract
      },
      singleRecipients, sig5, dropAddr,
      ethers.parseEther('50'), ethers.ZeroAddress
    );
    fail('Wrong signer', 'should have reverted');
  } catch (e) {
    pass('Wrong signer correctly reverted');
  }

  // ==================================================
  // TEST 6: Not-Yet-Valid Payment (nbf in the future)
  // ==================================================
  console.log('\n\n══════════════════════════════════════');
  console.log('TEST 6: Not-Yet-Valid Payment');
  console.log('══════════════════════════════════════');

  const payment6 = {
    payer: cloudAddr,
    token: safebuxAddr,
    recipientsHash: recipientsHash,
    max: ethers.parseEther('100'),
    line: 0,
    nbf: now + 7200,  // valid in 2 hours
    exp: now + 86400,
    contract: ocAddr
  };
  const sig6 = await cloud.signTypedData(domain, PAYMENT_TYPES, payment6);

  try {
    await oc.connect(drop).paymentsExecute(
      {
        payer: payment6.payer, token: payment6.token,
        recipientsHash: payment6.recipientsHash, max: payment6.max,
        line: payment6.line, nbf: payment6.nbf, exp: payment6.exp,
        contractAddr: payment6.contract
      },
      singleRecipients, sig6, dropAddr,
      ethers.parseEther('50'), ethers.ZeroAddress
    );
    fail('Not-yet-valid payment', 'should have reverted');
  } catch (e) {
    pass('Not-yet-valid payment correctly reverted');
  }

  // ==================================================
  // SUMMARY
  // ==================================================
  console.log('\n\n══════════════════════════════════════');
  console.log('SUMMARY');
  console.log('══════════════════════════════════════');
  console.log('  Safebux (ERC-20):  ', safebuxAddr);
  console.log('  OpenClaiming:      ', ocAddr);
  console.log('  Chain ID:          ', CHAIN_ID);
  console.log('  EIP-712 Domain:     OpenClaiming v1');
  console.log('');

  const cloudFinal = await safebux.balanceOf(cloudAddr);
  const dropFinal = await safebux.balanceOf(dropAddr);
  console.log('  Final balances:');
  console.log('    Cloud:    ', ethers.formatEther(cloudFinal), 'SBUX');
  console.log('    Drop:     ', ethers.formatEther(dropFinal), 'SBUX');
  console.log('    Jet:      ', ethers.formatEther(await safebux.balanceOf(jetAddr)), 'SBUX');
  console.log('    Creator:  ', ethers.formatEther(await safebux.balanceOf(creatorAddr)), 'SBUX');
  console.log('    Protocol: ', ethers.formatEther(await safebux.balanceOf(protocolAddr)), 'SBUX');
  console.log('');
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('\n  The OCP payment pipeline works end to end. 🎉');
  }
}

main().catch(err => {
  console.error('\n❌ Fatal error:', err.message);
  if (err.data) console.error('  Revert data:', err.data);
  process.exit(1);
});
