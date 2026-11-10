'use strict';
/**
 * PQClaim + AttestationPolicy PQ integration tests.
 *
 * Tests ML-DSA-65 scanner-authorization claims and the requirePQClaim policy
 * option introduced in Safecloud 3.1.0.
 *
 * Run: node tests/pq_claim.test.js
 */

var assert    = require('assert');
var crypto    = require('crypto');
var Attestation = require('../classes/Safecloud/Attestation');
var PQClaim   = Attestation.PQClaim;
var Policy    = Attestation.Policy;

// ─── helpers ────────────────────────────────────────────────────────────────

var PK_PREFIX = 'data:key/ml-dsa-65;base64,';

/** Derive an ML-DSA-65 keypair from a 32-byte seed. */
async function makeKeypair(seed) {
    seed = seed || crypto.randomBytes(32);
    var mod = await import('@noble/post-quantum/ml-dsa.js');
    var kp  = mod.ml_dsa65.keygen(seed);
    return {
        publicKey:  kp.publicKey,
        secretKey:  kp.secretKey,
        pqPublicKey: PK_PREFIX + Buffer.from(kp.publicKey).toString('base64')
    };
}

/** Minimal fake attestation result that passes classical checks. */
function fakeResult(scannerCID) {
    return {
        valid:      true,
        provider:   'nitro',
        scannerCID: scannerCID || 'bafybeig_test_scanner_cid',
        claims:     {}
    };
}

var SCANNER_CID = 'bafybeig_test_scanner_cid_pq';
var OTHER_CID   = 'bafybeig_other_cid';

// ─── test runner ────────────────────────────────────────────────────────────

var tests   = [];
var passed  = 0;
var failed  = 0;

function test(name, fn) {
    tests.push({ name, fn });
}

async function runAll() {
    for (var t of tests) {
        try {
            await t.fn();
            console.log('  ok  ' + t.name);
            passed++;
        } catch (e) {
            console.log('  FAIL ' + t.name);
            console.log('       ' + e.message);
            failed++;
        }
    }
    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exit(1);
}

// ─── PQClaim.sign / verify ───────────────────────────────────────────────────

test('sign produces a verifiable claim', async function () {
    var kp    = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });

    assert.strictEqual(claim.v,          1);
    assert.strictEqual(claim.action,     'approve-scanner');
    assert.strictEqual(claim.scannerCID, SCANNER_CID);
    assert.ok(claim.pqSig,               'pqSig present');

    var result = await PQClaim.verify(claim, { scannerCID: SCANNER_CID });
    assert.ok(result.valid, result.error);
});

test('verify rejects wrong scannerCID', async function () {
    var kp    = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    var result = await PQClaim.verify(claim, { scannerCID: OTHER_CID });
    assert.ok(!result.valid);
    assert.match(result.error, /mismatch/);
});

test('verify rejects tampered scannerCID', async function () {
    var kp    = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    claim.scannerCID = OTHER_CID;   // tamper after signing
    var result = await PQClaim.verify(claim, { scannerCID: OTHER_CID });
    assert.ok(!result.valid);
    assert.match(result.error, /ML-DSA-65 signature verification failed/);
});

test('verify rejects expired claim', async function () {
    var kp    = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey,
        ttlSeconds:  3600
    });
    var future = new Date(Date.now() + 2 * 3600 * 1000);
    var result = await PQClaim.verify(claim, { scannerCID: SCANNER_CID, now: future });
    assert.ok(!result.valid);
    assert.match(result.error, /expired/);
});

test('verify rejects wrong trustedKey', async function () {
    var kp1   = await makeKeypair();
    var kp2   = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp1.pqPublicKey,
        pqSecretKey: kp1.secretKey
    });
    var result = await PQClaim.verify(claim, {
        scannerCID: SCANNER_CID,
        trustedKey: kp2.pqPublicKey   // different key
    });
    assert.ok(!result.valid);
    assert.match(result.error, /does not match trusted issuer/);
});

test('verify accepts correct trustedKey', async function () {
    var kp    = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    var result = await PQClaim.verify(claim, {
        scannerCID: SCANNER_CID,
        trustedKey: kp.pqPublicKey    // same key — must pass
    });
    assert.ok(result.valid, result.error);
});

test('verify rejects future-issued claim', async function () {
    var kp    = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    var past = new Date(Date.now() - 24 * 3600 * 1000);
    var result = await PQClaim.verify(claim, { scannerCID: SCANNER_CID, now: past });
    assert.ok(!result.valid);
    assert.match(result.error, /future/);
});

test('verify rejects claim with bad pqSig bytes', async function () {
    var kp    = await makeKeypair();
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    // Flip one bit in the signature
    var sigBuf = Buffer.from(claim.pqSig, 'base64');
    sigBuf[42] ^= 0x01;
    claim.pqSig = sigBuf.toString('base64');
    var result = await PQClaim.verify(claim, { scannerCID: SCANNER_CID });
    assert.ok(!result.valid);
    assert.match(result.error, /ML-DSA-65 signature verification failed/);
});

// ─── AttestationPolicy with requirePQClaim ───────────────────────────────────

test('policy without requirePQClaim passes without pqClaim', async function () {
    var policy = new Policy({ scannerCID: SCANNER_CID });
    var result = await policy.evaluate(fakeResult(SCANNER_CID));
    assert.ok(result.pass, result.reason);
});

test('policy with requirePQClaim fails without pqClaim', async function () {
    var policy = new Policy({ scannerCID: SCANNER_CID, requirePQClaim: true });
    var result = await policy.evaluate(fakeResult(SCANNER_CID));
    assert.ok(!result.pass);
    assert.match(result.reason, /requires a PQ claim/i);
});

test('policy with requirePQClaim passes with valid pqClaim', async function () {
    var kp     = await makeKeypair();
    var policy = new Policy({
        scannerCID:    SCANNER_CID,
        requirePQClaim: true,
        pqTrustedKey:  kp.pqPublicKey
    });
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    var result = await policy.evaluate(fakeResult(SCANNER_CID), { pqClaim: claim });
    assert.ok(result.pass, result.reason);
});

test('policy with requirePQClaim fails with wrong pqClaim scannerCID', async function () {
    var kp     = await makeKeypair();
    var policy = new Policy({ scannerCID: SCANNER_CID, requirePQClaim: true });
    var claim  = await PQClaim.sign({
        scannerCID:  OTHER_CID,      // different CID
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    var result = await policy.evaluate(fakeResult(SCANNER_CID), { pqClaim: claim });
    assert.ok(!result.pass);
    assert.match(result.reason, /PQ claim invalid/);
});

test('policy with requirePQClaim fails with wrong trustedKey', async function () {
    var kp1    = await makeKeypair();
    var kp2    = await makeKeypair();
    var policy = new Policy({
        scannerCID:    SCANNER_CID,
        requirePQClaim: true,
        pqTrustedKey:  kp2.pqPublicKey   // expect kp2
    });
    var claim = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp1.pqPublicKey,    // signed by kp1
        pqSecretKey: kp1.secretKey
    });
    var result = await policy.evaluate(fakeResult(SCANNER_CID), { pqClaim: claim });
    assert.ok(!result.pass);
    assert.match(result.reason, /PQ claim invalid/);
});

test('policy still fails TEE attestation even with valid pqClaim', async function () {
    var kp     = await makeKeypair();
    var policy = new Policy({ scannerCID: SCANNER_CID, requirePQClaim: true });
    var claim  = await PQClaim.sign({
        scannerCID:  SCANNER_CID,
        pqPublicKey: kp.pqPublicKey,
        pqSecretKey: kp.secretKey
    });
    var badResult = { valid: false, error: 'bad cert chain', provider: 'nitro', scannerCID: SCANNER_CID };
    var result = await policy.evaluate(badResult, { pqClaim: claim });
    assert.ok(!result.pass);
    assert.match(result.reason, /attestation verification failed/);
});

test('toJSON / fromJSON round-trips requirePQClaim and pqTrustedKey', async function () {
    var kp     = await makeKeypair();
    var policy = new Policy({
        scannerCID:    SCANNER_CID,
        requirePQClaim: true,
        pqTrustedKey:  kp.pqPublicKey
    });
    var json     = policy.toJSON();
    var restored = Policy.fromJSON(json);
    assert.strictEqual(restored.requirePQClaim, true);
    assert.strictEqual(restored.pqTrustedKey,   kp.pqPublicKey);
    assert.strictEqual(restored.scannerCID,      SCANNER_CID);
});

test('toJSON omits requirePQClaim when false', function () {
    var policy = new Policy({ scannerCID: SCANNER_CID });
    var json   = policy.toJSON();
    assert.ok(!('requirePQClaim' in json), 'requirePQClaim should not appear when false');
    assert.ok(!('pqTrustedKey'   in json), 'pqTrustedKey should not appear when requirePQClaim is false');
});

// ─── run ────────────────────────────────────────────────────────────────────

console.log('\nPQClaim + AttestationPolicy PQ tests\n');
runAll();
