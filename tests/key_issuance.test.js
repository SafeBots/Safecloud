/**
 * Key issuance tests for the pay-per-minute / attested key issuance system.
 *
 * Tests:
 *   1. Key derivation — deterministic, one-way, isolated per index
 *   2. Access model parsing — defaults, field validation, model-specific defaults
 *   3. issueKeys — permanent (open), session, pay-per-minute gating
 *   4. Payment gate — 402 on missing/invalid sig, passes on approved
 *   5. Attestation gate — 403 without token, passes on blessed build, blocks unblessed
 *   6. Rolling-rewind — isChunkExpired logic
 *   7. HKDF — determinism and length contract
 */

'use strict';
const { webcrypto } = require('crypto');
const assert = require('assert/strict');

// ── Stubs for modules that pull in platform/Q deps ────────────────────────
// KeyIssuance only requires 'crypto' and './Attestation' (lazy-required inside
// verifyClientAttestation).  We stub Attestation before the require so the
// test suite stays self-contained.
const path = require('path');
// Provide a minimal stub at the module-resolution path so require('./Attestation')
// resolves to our stub instead of the real module (which loads OpenSSL bindings etc.)
// We use a module mock via the cache:
const ATTEST_PATH = require.resolve('../classes/Safecloud/Attestation');
require.cache[ATTEST_PATH] = {
    id: ATTEST_PATH,
    filename: ATTEST_PATH,
    loaded: true,
    exports: {
        TrustStore: function () { this.nitroRoot = null; },
        Verifier:   function (store) {
            this.verify = function (provider, doc, opts) {
                // Parse the stub document: { claims: {...}, pass: bool }
                try {
                    var d = typeof doc === 'string' ? JSON.parse(doc)
                        : (Buffer.isBuffer(doc) ? JSON.parse(doc.toString()) : doc);
                    if (!d.pass) return Promise.reject(new Error('invalid document'));
                    return Promise.resolve({ claims: d.claims || {} });
                } catch (e) {
                    return Promise.reject(e);
                }
            };
        },
        Policy: function (opts) {
            this.evaluate = function (result) {
                return { pass: true, reason: null };
            };
        }
    }
};

const Access       = require('../classes/Safecloud/Access');
const KeyIssuance  = require('../classes/Safecloud/KeyIssuance');

// ─────────────────────────────────────────────────────────────────────────────
// Test runner helpers
// ─────────────────────────────────────────────────────────────────────────────
let _pass = 0, _fail = 0;
function ok(label, cond) {
    if (cond) { _pass++; console.log('  ✓', label); }
    else        { _fail++; console.log('  ✗ FAIL:', label); }
}
async function run(label, fn) {
    try { await fn(); }
    catch (e) { _fail++; console.log('  ✗ FAIL:', label, '\n   ', e.message || e); return; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────
const ROOT_CID  = 'bafybeig4qnxyqfxazq3h7jqedfg4r7hjmpllc7x7mhfyj3i5kqnxyq0000';
const ROOT_KEY  = webcrypto.getRandomValues(new Uint8Array(32));
const ROOT_KEY_BUF = Buffer.from(ROOT_KEY);

(async () => {

// ─────────────────────────────────────────────────────────────────────────────
// 1. HKDF
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n1. HKDF');

await run('hkdf returns 32 bytes by default', async function () {
    const out = KeyIssuance.hkdf(ROOT_KEY_BUF, 'test.info');
    ok('hkdf returns 32 bytes by default', out.length === 32);
});

await run('hkdf is deterministic', async function () {
    const a = KeyIssuance.hkdf(ROOT_KEY_BUF, 'safecloud.chunk.v1.0');
    const b = KeyIssuance.hkdf(ROOT_KEY_BUF, 'safecloud.chunk.v1.0');
    ok('hkdf is deterministic', a.equals(b));
});

await run('hkdf info string changes output', async function () {
    const a = KeyIssuance.hkdf(ROOT_KEY_BUF, 'safecloud.chunk.v1.0');
    const b = KeyIssuance.hkdf(ROOT_KEY_BUF, 'safecloud.chunk.v1.1');
    ok('hkdf info string changes output', !a.equals(b));
});

await run('hkdf honours length param', async function () {
    const out = KeyIssuance.hkdf(ROOT_KEY_BUF, 'safecloud.chunk.v1.0', 16);
    ok('hkdf honours length param', out.length === 16);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. deriveChunkKey
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n2. deriveChunkKey');

await run('deriveChunkKey returns 32-byte Buffer', async function () {
    const k = KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 0);
    ok('deriveChunkKey returns 32-byte Buffer', Buffer.isBuffer(k) && k.length === 32);
});

await run('deriveChunkKey is deterministic', async function () {
    const a = KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 5);
    const b = KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 5);
    ok('deriveChunkKey is deterministic', a.equals(b));
});

await run('chunk keys differ by index', async function () {
    const k0 = KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 0);
    const k1 = KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 1);
    ok('chunk keys differ by index', !k0.equals(k1));
});

await run('deriveChunkKey accepts base64 root key string', async function () {
    const b64 = ROOT_KEY_BUF.toString('base64');
    const kBuf = KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 3);
    const kStr = KeyIssuance.deriveChunkKey(b64, ROOT_CID, 3);
    ok('deriveChunkKey accepts base64 root key string', kBuf.equals(kStr));
});

await run('chunk keys are one-way (can\'t reconstruct root)', async function () {
    // This just checks that chunk keys don't equal or contain the root key — not a
    // proof of one-wayness, but a sanity smoke test.
    const k0 = KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 0);
    ok('chunk keys are one-way (can\'t reconstruct root)', !k0.equals(ROOT_KEY_BUF));
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Access.parseAccessModel
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n3. Access.parseAccessModel');

{
    const def = Access.parseAccessModel(null);
    ok('null → permanent defaults', def.model === 'permanent' && def.keyPolicy === 'permanent' && !def.requireAttestation);
}

{
    const m = Access.parseAccessModel(JSON.stringify({
        model: 'pay-per-minute',
        rewindWindow: 120,
        ratePerSecond: '0.0002',
        keyPolicy: 'rolling-rewind',
        requireAttestation: true
    }));
    ok('pay-per-minute parses correctly', m.model === 'pay-per-minute');
    ok('rewindWindow is numeric', m.rewindWindow === 120);
    ok('ratePerSecond preserved', m.ratePerSecond === '0.0002');
    ok('keyPolicy rolling-rewind', m.keyPolicy === 'rolling-rewind');
    ok('requireAttestation true', m.requireAttestation === true);
}

{
    const m = Access.parseAccessModel({ model: 'pay-per-second' });
    ok('pay-per-second defaults rewindWindow=10', m.rewindWindow === 10);
    ok('pay-per-second defaults rolling-rewind policy', m.keyPolicy === 'rolling-rewind');
}

{
    const m = Access.parseAccessModel({ model: 'session' });
    ok('session defaults keyPolicy=session', m.keyPolicy === 'session');
    ok('session rewindWindow defaults 0', m.rewindWindow === 0);
}

{
    const m = Access.parseAccessModel({ model: 'nonsense' });
    ok('invalid model → permanent', m.model === 'permanent');
}

{
    ok('requireAttestation defaults falsy', !Access.parseAccessModel({ model: 'permanent' }).requireAttestation);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Access.isChunkExpired
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n4. Access.isChunkExpired');

{
    const m = Access.parseAccessModel({ model: 'pay-per-minute', rewindWindow: 120 });
    ok('chunk within window is not expired', !Access.isChunkExpired(m, 300, 200));
    ok('chunk outside window is expired',     Access.isChunkExpired(m, 300, 100));
    ok('chunk at exact boundary is not expired', !Access.isChunkExpired(m, 300, 180));
    ok('chunk before boundary is expired',     Access.isChunkExpired(m, 300, 179));
}

{
    const m = Access.parseAccessModel({ model: 'permanent' });
    ok('permanent model never expires chunks', !Access.isChunkExpired(m, 300, 0));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. issueKeys — open access (no checkPayment)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n5. issueKeys — open access (permanent model)');

await run('issues keys for permanent model without checkPayment', async function () {
    const result = await KeyIssuance.issueKeys({
        rootCid:      ROOT_CID,
        chunkIndices: [0, 1, 2],
        rootKey:      ROOT_KEY_BUF,
        accessModel:  Access.parseAccessModel(null),
        // No checkPayment → allowed for permanent
    });
    ok('keys object has index "0"', typeof result.keys['0'] === 'string');
    ok('keys object has index "1"', typeof result.keys['1'] === 'string');
    ok('keys object has index "2"', typeof result.keys['2'] === 'string');
    ok('keys are base64', Buffer.from(result.keys['0'], 'base64').length === 32);
    ok('keys[0] matches deriveChunkKey',
        result.keys['0'] === KeyIssuance.deriveChunkKey(ROOT_KEY_BUF, ROOT_CID, 0).toString('base64'));
});

await run('rejects when no checkPayment and non-permanent model', async function () {
    try {
        await KeyIssuance.issueKeys({
            rootCid:      ROOT_CID,
            chunkIndices: [0],
            rootKey:      ROOT_KEY_BUF,
            accessModel:  Access.parseAccessModel({ model: 'pay-per-minute' })
            // No checkPayment
        });
        ok('should have thrown', false);
    } catch (e) {
        ok('rejects pay-per-minute without checkPayment', e.statusCode === 500);
    }
});

await run('rejects with 400 when rootCid missing', async function () {
    try {
        await KeyIssuance.issueKeys({ chunkIndices: [0], rootKey: ROOT_KEY_BUF,
            accessModel: Access.DEFAULT_MODEL });
        ok('should have thrown', false);
    } catch (e) {
        ok('400 on missing rootCid', e.statusCode === 400);
    }
});

await run('rejects with 400 when chunkIndices missing', async function () {
    try {
        await KeyIssuance.issueKeys({ rootCid: ROOT_CID, rootKey: ROOT_KEY_BUF,
            accessModel: Access.DEFAULT_MODEL, chunkIndices: [] });
        ok('should have thrown', false);
    } catch (e) {
        ok('400 on empty chunkIndices', e.statusCode === 400);
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. issueKeys — payment gate
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n6. issueKeys — payment gate');

await run('402 when payment sig missing and checkPayment returns not-ok', async function () {
    try {
        await KeyIssuance.issueKeys({
            rootCid:      ROOT_CID,
            chunkIndices: [0, 1],
            rootKey:      ROOT_KEY_BUF,
            accessModel:  Access.parseAccessModel({ model: 'pay-per-minute' }),
            paymentSig:   null,
            checkPayment: function () {
                return Promise.resolve({ ok: false, error: 'Payment required' });
            }
        });
        ok('should have thrown', false);
    } catch (e) {
        ok('402 on missing payment', e.statusCode === 402);
        ok('code is PaymentRequired', e.code === 'PaymentRequired');
    }
});

await run('issues keys when payment check passes', async function () {
    const result = await KeyIssuance.issueKeys({
        rootCid:      ROOT_CID,
        chunkIndices: [0, 1],
        rootKey:      ROOT_KEY_BUF,
        accessModel:  Access.parseAccessModel({ model: 'pay-per-minute' }),
        paymentSig:   'mock-sig',
        checkPayment: function () { return Promise.resolve({ ok: true }); }
    });
    ok('keys returned on paid request', Object.keys(result.keys).length === 2);
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. issueKeys — attestation gate
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n7. issueKeys — attestation gate');

const BLESSED_HASH   = 'aabbccdd1122334455667788990011223344556677889900112233445566778899';
const UNBLESSED_HASH = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function makeAttestToken(buildHash, pass) {
    // Our stub verifier expects base64(JSON) with { pass, claims: { buildHash } }
    var doc = JSON.stringify({ pass: pass !== false, claims: { buildHash: buildHash } });
    var envelope = { provider: 'nitro', document: Buffer.from(doc).toString('base64') };
    return Buffer.from(JSON.stringify(envelope)).toString('base64');
}

await run('403 when attestation required but not supplied', async function () {
    try {
        await KeyIssuance.issueKeys({
            rootCid:      ROOT_CID,
            chunkIndices: [0],
            rootKey:      ROOT_KEY_BUF,
            accessModel:  Access.parseAccessModel({ model: 'pay-per-minute', requireAttestation: true }),
            checkPayment: function () { return Promise.resolve({ ok: true }); },
            blessedBuilds: [BLESSED_HASH]
            // No attestation
        });
        ok('should have thrown', false);
    } catch (e) {
        ok('403 on missing attestation', e.statusCode === 403);
        ok('code is AttestationRequired', e.code === 'AttestationRequired');
    }
});

await run('403 when build hash not on blessed list', async function () {
    try {
        await KeyIssuance.issueKeys({
            rootCid:      ROOT_CID,
            chunkIndices: [0],
            rootKey:      ROOT_KEY_BUF,
            accessModel:  Access.parseAccessModel({ model: 'pay-per-minute', requireAttestation: true }),
            attestation:  makeAttestToken(UNBLESSED_HASH, true),
            checkPayment: function () { return Promise.resolve({ ok: true }); },
            blessedBuilds: [BLESSED_HASH]
        });
        ok('should have thrown', false);
    } catch (e) {
        ok('403 on unblessed build', e.statusCode === 403);
    }
});

await run('issues keys when attestation passes for blessed build', async function () {
    const result = await KeyIssuance.issueKeys({
        rootCid:      ROOT_CID,
        chunkIndices: [0, 1, 2],
        rootKey:      ROOT_KEY_BUF,
        accessModel:  Access.parseAccessModel({ model: 'pay-per-minute', requireAttestation: true }),
        attestation:  makeAttestToken(BLESSED_HASH, true),
        checkPayment: function () { return Promise.resolve({ ok: true }); },
        blessedBuilds: [BLESSED_HASH]
    });
    ok('keys issued for blessed build', Object.keys(result.keys).length === 3);
});

await run('issues keys when blessedBuilds is empty (any attested build)', async function () {
    const result = await KeyIssuance.issueKeys({
        rootCid:      ROOT_CID,
        chunkIndices: [0],
        rootKey:      ROOT_KEY_BUF,
        accessModel:  Access.parseAccessModel({ model: 'pay-per-minute', requireAttestation: true }),
        attestation:  makeAttestToken(UNBLESSED_HASH, true),
        checkPayment: function () { return Promise.resolve({ ok: true }); },
        blessedBuilds: []  // empty → accept any valid attestation
    });
    ok('keys issued for any attested build', typeof result.keys['0'] === 'string');
});

await run('no attestation needed when requireAttestation is false', async function () {
    const result = await KeyIssuance.issueKeys({
        rootCid:      ROOT_CID,
        chunkIndices: [0],
        rootKey:      ROOT_KEY_BUF,
        accessModel:  Access.parseAccessModel({ model: 'pay-per-minute', requireAttestation: false }),
        checkPayment: function () { return Promise.resolve({ ok: true }); }
        // No attestation, requireAttestation=false → should succeed
    });
    ok('keys issued without attestation when not required', typeof result.keys['0'] === 'string');
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Access.encodeAccessModel / round-trip
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n8. Access round-trip');

{
    const original = {
        model: 'pay-per-second',
        rewindWindow: 30,
        ratePerSecond: '0.001',
        keyPolicy: 'rolling-rewind',
        requireAttestation: true
    };
    const encoded = Access.encodeAccessModel(original);
    const decoded = Access.parseAccessModel(encoded);
    ok('round-trip model',              decoded.model === original.model);
    ok('round-trip rewindWindow',       decoded.rewindWindow === original.rewindWindow);
    ok('round-trip ratePerSecond',      decoded.ratePerSecond === original.ratePerSecond);
    ok('round-trip keyPolicy',          decoded.keyPolicy === original.keyPolicy);
    ok('round-trip requireAttestation', decoded.requireAttestation === original.requireAttestation);
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n' + _pass + ' passed, ' + _fail + ' failed');
process.exit(_fail ? 1 : 0);

})();
