/**
 * recipientsHash + dual-token separation tests.
 *
 * Proves three things end to end (no network):
 *  1. The browser's hand-rolled abi.encode([addr]) (Jets/get.js) and the
 *     server's Buffer construction (Jets.js) both equal
 *     keccak256(AbiCoder.encode(['address[]'], [[addr]])) — i.e. tokens the
 *     Cloud signs will verify at the Jet and on-chain.
 *  2. Infra and author tokens commit DIFFERENT recipient sets, so neither
 *     party can claim the other's token (redirect-proof).
 *  3. The Jet's relay verification (ethers.verifyTypedData) recovers the
 *     payer from an author-share token signed the way the browser signs it.
 *
 * Run: NODE_PATH=test/shims node test/recipientsHash.test.js
 */
'use strict';
const assert = require('assert');
const { ethers } = require('ethers');

const OC_ADDRESS = '0x99999febd42cad798fe10ab0b1c563002fc99999';

// ── Reference: canonical abi.encode(['address[]']) via ethers ────────────────
function referenceHash(addr) {
    const enc = ethers.AbiCoder.defaultAbiCoder()
        .encode(['address[]'], [[addr]]);
    return ethers.keccak256(enc).toLowerCase();
}

// ── Browser construction (web/js/methods/Safecloud/Jets/get.js) ──────────────
function browserHash(addr) {
    const addrBytes  = ethers.getBytes(ethers.zeroPadValue(addr, 32));
    const abiEncoded = new Uint8Array(96);
    abiEncoded[31] = 32;
    abiEncoded[63] = 1;
    abiEncoded.set(addrBytes, 64);
    return ethers.keccak256(abiEncoded).toLowerCase();
}

// ── Server construction (classes/Safecloud/Jets.js _recipientsHashOf) ────────
function serverHash(addr) {
    const a = String(addr).toLowerCase().replace(/^0x/i, '').padStart(40, '0');
    const abiEncoded = Buffer.concat([
        Buffer.from('0000000000000000000000000000000000000000000000000000000000000020', 'hex'),
        Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex'),
        Buffer.concat([Buffer.alloc(12, 0), Buffer.from(a, 'hex')])
    ]);
    return ethers.keccak256(abiEncoded).toLowerCase();
}

(async function main() {
    const jet    = ethers.Wallet.createRandom().address;
    const income = ethers.Wallet.createRandom().address;

    // 1. All three constructions agree, for both addresses
    for (const addr of [jet, income]) {
        const ref = referenceHash(addr);
        assert.strictEqual(browserHash(addr), ref, 'browser encoding must match AbiCoder');
        assert.strictEqual(serverHash(addr),  ref, 'server encoding must match AbiCoder');
    }
    console.log('✓ browser/server/AbiCoder recipientsHash agree');

    // 2. Dual-token separation: different recipient sets → different hashes
    assert.notStrictEqual(browserHash(jet), browserHash(income),
        'infra and author tokens must bind different recipient sets');
    console.log('✓ infra token and author token commit different recipients');

    // 3. Byte-exact compatibility with the OpenClaiming contract.
    //    Reconstruct the contract's digest by hand from its constants:
    //      NAME_HASH         = keccak256("OpenClaiming")
    //      PAYMENTS_TYPEHASH = keccak256("Payment(address payer,address token,"
    //        + "bytes32 recipientsHash,uint256 max,uint256 line,"
    //        + "uint256 nbf,uint256 exp,address contract)")
    //    and prove ethers' TypedDataEncoder (what the plugin signs with)
    //    produces the identical digest.
    const viewer  = ethers.Wallet.createRandom();
    const domain  = { name: 'OpenClaiming', version: '1',
                      chainId: 56, verifyingContract: OC_ADDRESS };
    const types   = { Payment: [
        { name: 'payer',          type: 'address' },
        { name: 'token',          type: 'address' },
        { name: 'recipientsHash', type: 'bytes32' },
        { name: 'max',            type: 'uint256' },
        { name: 'line',           type: 'uint256' },
        { name: 'nbf',            type: 'uint256' },
        { name: 'exp',            type: 'uint256' },
        { name: 'contract',       type: 'address' }
    ] };
    const value = {
        payer: viewer.address,
        token: ethers.Wallet.createRandom().address, // stand-in Safebux
        recipientsHash: browserHash(income),
        max: 150000n, line: 0n, nbf: 0n,
        exp: BigInt(Math.floor(Date.now() / 1000) + 30 * 86400),
        contract: OC_ADDRESS
    };

    const PAYMENT_TYPE_STRING =
        'Payment(address payer,address token,bytes32 recipientsHash,'
        + 'uint256 max,uint256 line,uint256 nbf,uint256 exp,address contract)';
    assert.strictEqual(
        ethers.TypedDataEncoder.from(types).encodeType('Payment'),
        PAYMENT_TYPE_STRING,
        'plugin type array must encode to the contract PAYMENTS_TYPEHASH preimage');

    const domainSep = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
        [
            ethers.keccak256(ethers.toUtf8Bytes(
                'EIP712Domain(string name,string version,'
                + 'uint256 chainId,address verifyingContract)')),
            ethers.keccak256(ethers.toUtf8Bytes('OpenClaiming')),
            ethers.keccak256(ethers.toUtf8Bytes('1')),
            56,
            OC_ADDRESS
        ]));
    const structHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes32', 'address', 'address', 'bytes32',
         'uint256', 'uint256', 'uint256', 'uint256', 'address'],
        [ethers.keccak256(ethers.toUtf8Bytes(PAYMENT_TYPE_STRING)),
         value.payer, value.token, value.recipientsHash,
         value.max, value.line, value.nbf, value.exp, value.contract]));
    const contractDigest = ethers.keccak256(ethers.concat(
        ['0x1901', domainSep, structHash]));
    assert.strictEqual(
        ethers.TypedDataEncoder.hash(domain, types, value),
        contractDigest,
        'ethers digest must equal the contract-reconstructed digest');
    console.log('✓ digest byte-exact vs OpenClaiming contract constants');
    const sig = await viewer.signTypedData(domain, types, value);
    const recovered = ethers.verifyTypedData(domain, types, value, sig);
    assert.strictEqual(recovered.toLowerCase(), viewer.address.toLowerCase(),
        'relay verification must recover the payer');
    console.log('✓ author-share token signs and verifies (relay path)');

    // and a tampered recipient set must NOT verify
    const tampered = Object.assign({}, value, {
        recipientsHash: browserHash(ethers.Wallet.createRandom().address)
    });
    const recovered2 = ethers.verifyTypedData(domain, types, tampered, sig);
    assert.notStrictEqual(recovered2.toLowerCase(), viewer.address.toLowerCase(),
        'changing the recipient set must break signature recovery');
    console.log('✓ redirected recipients invalidate the signature');

    // 4. Policy tokens: recipientsHash = keccak256(abi.encode(Policy)) —
    //    same signed field, different encoding; must sign/verify identically
    //    and can never collide with a plain address[] hash.
    const policy = {
        payees: [ethers.Wallet.createRandom().address],   // author
        fractions: [9000n],                               // 90% creator
        dynamicBps: 1000n,                                // 10% to whoever serves
        dynamicConstraint: ethers.ZeroHash,               // DYNAMIC_ANY
        targets: []
    };
    const policyHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint256[]', 'uint256', 'bytes32', 'address[]'],
        [policy.payees, policy.fractions, policy.dynamicBps,
         policy.dynamicConstraint, policy.targets]));
    assert.notStrictEqual(policyHash, value.recipientsHash,
        'policy hash must differ from plain recipients hash');
    const polValue = Object.assign({}, value, { recipientsHash: policyHash });
    const polSig   = await viewer.signTypedData(domain, types, polValue);
    assert.strictEqual(
        ethers.verifyTypedData(domain, types, polValue, polSig).toLowerCase(),
        viewer.address.toLowerCase(),
        'policy token must sign and verify with the same 8-field struct');
    // Tampering with the policy (changing fractions) changes the hash → sig dies
    const policy2Hash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint256[]', 'uint256', 'bytes32', 'address[]'],
        [policy.payees, [8000n], 2000n, policy.dynamicConstraint, policy.targets]));
    const polTampered = Object.assign({}, polValue, { recipientsHash: policy2Hash });
    assert.notStrictEqual(
        ethers.verifyTypedData(domain, types, polTampered, polSig).toLowerCase(),
        viewer.address.toLowerCase(),
        'tampering with policy fractions must break signature recovery');
    console.log('✓ policy tokens: same struct, enforced-split hash, tamper-proof');

    console.log('\nrecipientsHash.test.js: all assertions passed');
})().catch(function (err) {
    console.error('FAIL:', err.message);
    process.exit(1);
});
