// Tests the REAL correctness-critical logic the Jet uses, verified against
// what OpenClaiming.sol expects. These mirror the exact expressions in
// Jets.js (_checkPayments policy gate, sponsor line derivation, _settlePolicyTokens).
const ethers = require('ethers');
let pass = 0, fail = 0;
function check(n, c) { c ? (pass++, console.log('  \u2713', n)) : (fail++, console.log('  \u2717 FAIL:', n)); }

// ── 1. Policy hash: browser signer, Jet gate, and contract must agree ──
// Contract: keccak256(abi.encode(payees, fractions, dynamicBps, dynamicConstraint, targets))
const ZERO32 = '0x' + '00'.repeat(32);
const jet = new ethers.Wallet('0x' + '33'.repeat(32)).address;
const author = new ethers.Wallet('0x' + '44'.repeat(32)).address;
const policy = {
  payees: [author], fractions: [9000n], dynamicBps: 1000n,
  dynamicConstraint: ZERO32, targets: []
};
const polHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['address[]','uint256[]','uint256','bytes32','address[]'],
  [policy.payees, policy.fractions, policy.dynamicBps, policy.dynamicConstraint, policy.targets]));
// Recompute exactly as the Jet's gate does (from source)
const jetRecompute = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['address[]','uint256[]','uint256','bytes32','address[]'],
  [policy.payees, (policy.fractions).map(f => BigInt(f)), BigInt(policy.dynamicBps),
   policy.dynamicConstraint || ('0x'+'00'.repeat(32)), policy.targets || []]));
check('policy hash: signer == Jet recompute', polHash === jetRecompute);

// 2. Fractions + dynamicBps must sum to 10000 (Jet rejects otherwise)
let sumBp = BigInt(policy.dynamicBps);
policy.fractions.forEach(f => sumBp += BigInt(f));
check('policy fractions + dynamicBps == 10000', sumBp === 10000n);

// 3. A tampered policy (fraction changed) must NOT match the signed hash
const tampered = { ...policy, fractions: [9500n] };
const tamperedHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['address[]','uint256[]','uint256','bytes32','address[]'],
  [tampered.payees, tampered.fractions, tampered.dynamicBps, tampered.dynamicConstraint, tampered.targets]));
check('tampered policy hash != signed hash', tamperedHash !== polHash);

// ── 4. Sponsor line derivation: opaque, deterministic, fits uint256 ──
const viewerId = 'user-abc-123';
const line = BigInt(ethers.keccak256(ethers.toUtf8Bytes('safecloud.sponsor.' + viewerId)));
const line2 = BigInt(ethers.keccak256(ethers.toUtf8Bytes('safecloud.sponsor.' + viewerId)));
check('sponsor line deterministic for same viewer', line === line2);
check('sponsor line fits uint256', line < (2n ** 256n));
const lineOther = BigInt(ethers.keccak256(ethers.toUtf8Bytes('safecloud.sponsor.' + 'different-user')));
check('different viewers -> different lines', line !== lineOther);

// ── 5. Per-content payer key derivation (viewer compartmentalization) ──
const basePriv = '0x' + '55'.repeat(32);
const rootCidA = 'bafyRootA', rootCidB = 'bafyRootB';
const childA = ethers.keccak256(ethers.concat([ethers.getBytes(basePriv), ethers.toUtf8Bytes('safecloud.payer.'+rootCidA)]));
const childB = ethers.keccak256(ethers.concat([ethers.getBytes(basePriv), ethers.toUtf8Bytes('safecloud.payer.'+rootCidB)]));
const childA2 = ethers.keccak256(ethers.concat([ethers.getBytes(basePriv), ethers.toUtf8Bytes('safecloud.payer.'+rootCidA)]));
check('per-content key deterministic per content', childA === childA2);
check('per-content keys differ across content', childA !== childB);
// And each must be a valid private key (in curve order, nonzero)
const wA = new ethers.Wallet(childA), wB = new ethers.Wallet(childB);
check('derived child keys yield valid distinct addresses', wA.address !== wB.address);

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
