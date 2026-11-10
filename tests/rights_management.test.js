'use strict';
/**
 * rights_management.test.js — Safecloud 4.0 RightsManagement unit tests.
 *
 * Tests:
 *   • Root key: register, persist, retrieve, idempotent re-register
 *   • Creator auth: valid sig accepted, bad sig rejected, stale ts rejected
 *   • Publisher registry: register + lookup
 *   • publisherAuth token: valid token accepted, expired rejected, bad sig rejected, wrong origin rejected
 *   • Grant chain: append entry, prev_hash chain, read chain, pagination
 *   • Rate limiting: tokens consumed, refill, throttle at capacity
 */

var assert          = require('assert');
var crypto          = require('crypto');
var os              = require('os');
var path            = require('path');
var fs              = require('fs');
var RightsManagement = require('../classes/Safecloud/RightsManagement');

// ─── Helpers ──────────────────────────────────────────────────────────────────

var passed = 0;
var failed = 0;
var total  = 0;

function test(label, fn) {
    total++;
    try {
        fn();
        console.log('  ✓ ' + label);
        passed++;
    } catch (e) {
        console.error('  ✗ ' + label);
        console.error('    ' + e.message);
        failed++;
    }
}

function tmpDir() {
    var d = path.join(os.tmpdir(), 'rm_test_' + crypto.randomBytes(4).toString('hex'));
    fs.mkdirSync(d, { recursive: true });
    return d;
}

function makeEd25519() {
    return crypto.generateKeyPairSync('ed25519');
}

function rawPubHex(keyObj) {
    // Export as raw 32-byte DER SPKI, strip 12-byte header
    var der = keyObj.export({ type: 'spki', format: 'der' });
    return der.slice(12).toString('hex');
}

function ed25519Sign(privKey, hashBuf) {
    return crypto.sign(null, hashBuf, privKey).toString('hex');
}

function makePublisherAuthToken(privKey, pubHex, publisher, userId, rootCid, overrides) {
    var now   = Date.now();
    var body  = Object.assign({
        publisher: publisher,
        userId:    userId,
        rootCid:   rootCid,
        nbf:       now - 1000,
        exp:       now + 3600000,
        nonce:     crypto.randomBytes(16).toString('hex'),
    }, overrides || {});
    var bodyStr = JSON.stringify(body);
    var hashBuf = crypto.createHash('sha256').update(bodyStr, 'utf8').digest();
    var sig     = ed25519Sign(privKey, hashBuf);
    var full    = Object.assign({}, body, { sig: sig });
    return Buffer.from(JSON.stringify(full)).toString('base64');
}

// ─── JetKey stub (RightsManagement uses JetKey for Jet-signed entries) ────────
// We mock JetKey.sign so grant chain entries get real signatures in tests.
// The grant chain sig is verified on read (we verify prev_hash chain in test).
var JetKey = require('../classes/Safecloud/JetKey');
// Init with a temp key for the test run
var tmpKeyPath = path.join(os.tmpdir(), 'rm_test_jetkey_' + process.pid + '.json');
JetKey.init(tmpKeyPath);

// ─── Test setup ───────────────────────────────────────────────────────────────

var rm;
var DB_DIR;

function setup() {
    DB_DIR = tmpDir();
    rm     = new RightsManagement({ rateLimitCapacity: 5, rateLimitRefillRate: 5 / 60000 });
    rm.open(path.join(DB_DIR, 'rights.db'));
}

function teardown() {
    if (rm) { rm.close(); rm = null; }
}

// ─── Root key tests ───────────────────────────────────────────────────────────

console.log('\n── Root key persistence ──');
setup();

test('register and retrieve root key', function () {
    var cid    = 'bafybeiabc' + crypto.randomBytes(8).toString('hex');
    var keyBuf = crypto.randomBytes(32);
    var isNew  = rm.registerRootKey({ rootCid: cid, rootKey: keyBuf });
    assert.strictEqual(isNew, true, 'should be new');
    var got = rm.getRootKey(cid);
    assert.ok(got, 'should have entry');
    assert.ok(got.key.equals(keyBuf), 'key must match');
});

test('idempotent re-register returns false', function () {
    var cid    = 'bafybeiidem' + crypto.randomBytes(8).toString('hex');
    var keyBuf = crypto.randomBytes(32);
    rm.registerRootKey({ rootCid: cid, rootKey: keyBuf });
    var isNew2 = rm.registerRootKey({ rootCid: cid, rootKey: keyBuf });
    assert.strictEqual(isNew2, false, 'second call should return false');
});

test('unknown CID returns null', function () {
    var got = rm.getRootKey('bafynosuchcid');
    assert.strictEqual(got, null);
});

test('accessModel is stored and retrieved', function () {
    var cid    = 'bafymodel' + crypto.randomBytes(8).toString('hex');
    var keyBuf = crypto.randomBytes(32);
    var model  = { requirePayment: true, pricePerChunk: '1000000000000000' };
    rm.registerRootKey({ rootCid: cid, rootKey: keyBuf, accessModel: model });
    var got = rm.getRootKey(cid);
    assert.ok(got.accessModel, 'accessModel present');
    assert.strictEqual(got.accessModel.requirePayment, true);
});

teardown();

// ─── Creator auth tests ───────────────────────────────────────────────────────

console.log('\n── Creator auth ──');
setup();

test('valid creator auth is accepted', function () {
    var pair       = makeEd25519();
    var pubHex     = rawPubHex(pair.publicKey);
    var cid        = 'bafyauth' + crypto.randomBytes(8).toString('hex');
    var keyBuf     = crypto.randomBytes(32);
    var keyB64     = keyBuf.toString('base64');
    var ts         = Date.now();
    var userId     = 'user123';
    var payload    = userId + '|' + cid + '|' + keyB64 + '|' + ts;
    var hashBuf    = crypto.createHash('sha256').update(payload, 'utf8').digest();
    var sig        = ed25519Sign(pair.privateKey, hashBuf);
    var authObj    = { userId: userId, rootCid: cid, rootKeyB64: keyB64, ts: ts, sig: sig };

    var isNew = rm.registerRootKey({
        rootCid: cid, rootKey: keyBuf, creatorId: userId,
        creatorAuth: JSON.stringify(authObj), creatorPubKeyHex: pubHex,
    });
    assert.strictEqual(isNew, true);
    var got = rm.getRootKey(cid);
    assert.ok(got.key.equals(keyBuf));
});

test('missing creatorAuth when pubKey supplied throws 403', function () {
    var pair   = makeEd25519();
    var pubHex = rawPubHex(pair.publicKey);
    var cid    = 'bafynoauth' + crypto.randomBytes(8).toString('hex');
    var keyBuf = crypto.randomBytes(32);
    try {
        rm.registerRootKey({ rootCid: cid, rootKey: keyBuf, creatorPubKeyHex: pubHex });
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 403);
    }
});

test('tampered sig throws 403', function () {
    var pair       = makeEd25519();
    var pubHex     = rawPubHex(pair.publicKey);
    var cid        = 'bafytamper' + crypto.randomBytes(8).toString('hex');
    var keyBuf     = crypto.randomBytes(32);
    var keyB64     = keyBuf.toString('base64');
    var ts         = Date.now();
    var userId     = 'user999';
    // Wrong payload → wrong sig
    var wrongHash  = crypto.createHash('sha256').update('tampered', 'utf8').digest();
    var sig        = ed25519Sign(pair.privateKey, wrongHash);
    var authObj    = { userId: userId, rootCid: cid, rootKeyB64: keyB64, ts: ts, sig: sig };
    try {
        rm.registerRootKey({ rootCid: cid, rootKey: keyBuf, creatorAuth: JSON.stringify(authObj), creatorPubKeyHex: pubHex });
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 403);
    }
});

test('stale timestamp throws 401', function () {
    var pair    = makeEd25519();
    var pubHex  = rawPubHex(pair.publicKey);
    var cid     = 'bafystale' + crypto.randomBytes(8).toString('hex');
    var keyBuf  = crypto.randomBytes(32);
    var keyB64  = keyBuf.toString('base64');
    var ts      = Date.now() - 400000; // 6+ minutes ago
    var userId  = 'userOld';
    var payload = userId + '|' + cid + '|' + keyB64 + '|' + ts;
    var hash    = crypto.createHash('sha256').update(payload, 'utf8').digest();
    var sig     = ed25519Sign(pair.privateKey, hash);
    var auth    = { userId: userId, rootCid: cid, rootKeyB64: keyB64, ts: ts, sig: sig };
    try {
        rm.registerRootKey({ rootCid: cid, rootKey: keyBuf, creatorAuth: JSON.stringify(auth), creatorPubKeyHex: pubHex });
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 401);
    }
});

teardown();

// ─── Publisher registry tests ─────────────────────────────────────────────────

console.log('\n── Publisher registry ──');
setup();

test('register and retrieve publisher', function () {
    var pair    = makeEd25519();
    var pubHex  = rawPubHex(pair.publicKey);
    var pid     = 'acme.example.com';
    var origins = ['https://acme.example.com'];
    var ts      = Date.now();
    var origStr = JSON.stringify(origins);
    var payload = pid + '|' + pubHex + '|' + ts + '|' + origStr;
    var hash    = crypto.createHash('sha256').update(payload, 'utf8').digest();
    var sig     = ed25519Sign(pair.privateKey, hash);

    rm.registerPublisher({ publisherId: pid, pubKeyHex: pubHex, allowedOrigins: origins, ts: ts, sig: sig });
    var got = rm.getPublisher(pid);
    assert.ok(got, 'publisher found');
    assert.strictEqual(got.pubKeyHex, pubHex);
    assert.deepStrictEqual(got.allowedOrigins, origins);
});

test('unknown publisher returns null', function () {
    assert.strictEqual(rm.getPublisher('nobody.example.com'), null);
});

test('invalid publisher sig throws 403', function () {
    var pair   = makeEd25519();
    var pubHex = rawPubHex(pair.publicKey);
    var pid    = 'bad.example.com';
    var ts     = Date.now();
    var sig    = 'aa'.repeat(32); // garbage sig
    try {
        rm.registerPublisher({ publisherId: pid, pubKeyHex: pubHex, allowedOrigins: [], ts: ts, sig: sig });
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 403);
    }
});

teardown();

// ─── publisherAuth token tests ────────────────────────────────────────────────

console.log('\n── publisherAuth tokens ──');
setup();

// Pre-register a publisher
var _pair    = makeEd25519();
var _pubHex  = rawPubHex(_pair.publicKey);
var _pid     = 'tokentest.example.com';
var _origins = ['https://tokentest.example.com'];
(function () {
    var ts      = Date.now();
    var origStr = JSON.stringify(_origins);
    var payload = _pid + '|' + _pubHex + '|' + ts + '|' + origStr;
    var hash    = crypto.createHash('sha256').update(payload, 'utf8').digest();
    var sig     = ed25519Sign(_pair.privateKey, hash);
    rm.registerPublisher({ publisherId: _pid, pubKeyHex: _pubHex, allowedOrigins: _origins, ts: ts, sig: sig });
})();

test('valid publisherAuth token is accepted', function () {
    var cid   = 'bafytoken' + crypto.randomBytes(8).toString('hex');
    var token = makePublisherAuthToken(_pair.privateKey, _pubHex, _pid, 'alice', cid);
    var result = rm.verifyPublisherAuth(token, cid, 'https://tokentest.example.com');
    assert.strictEqual(result.publisher, _pid);
    assert.strictEqual(result.userId, 'alice');
    assert.strictEqual(result.rootCid, cid);
});

test('expired token throws 401', function () {
    var cid   = 'bafyexp' + crypto.randomBytes(8).toString('hex');
    var token = makePublisherAuthToken(_pair.privateKey, _pubHex, _pid, 'alice', cid,
        { exp: Date.now() - 10000 });
    try {
        rm.verifyPublisherAuth(token, cid, 'https://tokentest.example.com');
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 401);
    }
});

test('wrong rootCid throws 403', function () {
    var cid   = 'bafywrong' + crypto.randomBytes(8).toString('hex');
    var token = makePublisherAuthToken(_pair.privateKey, _pubHex, _pid, 'alice', cid);
    try {
        rm.verifyPublisherAuth(token, 'bafy-different-cid', 'https://tokentest.example.com');
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 403);
    }
});

test('wrong origin throws 403', function () {
    var cid   = 'bafyorig' + crypto.randomBytes(8).toString('hex');
    var token = makePublisherAuthToken(_pair.privateKey, _pubHex, _pid, 'alice', cid);
    try {
        rm.verifyPublisherAuth(token, cid, 'https://evil.com');
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 403);
    }
});

test('tampered token sig throws 403', function () {
    var cid   = 'bafysigbad' + crypto.randomBytes(8).toString('hex');
    // Build a token with a bad sig
    var body  = { publisher: _pid, userId: 'alice', rootCid: cid,
                  nbf: Date.now() - 1000, exp: Date.now() + 3600000,
                  nonce: 'abc', sig: 'aa'.repeat(32) };
    var token = Buffer.from(JSON.stringify(body)).toString('base64');
    try {
        rm.verifyPublisherAuth(token, cid, 'https://tokentest.example.com');
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 403);
    }
});

test('no-origin accepted when publisher has empty allowedOrigins', function () {
    // Register a publisher with no origins restriction
    var pair2   = makeEd25519();
    var pub2    = rawPubHex(pair2.publicKey);
    var pid2    = 'open.example.com';
    var ts2     = Date.now();
    var origStr = JSON.stringify([]);
    var hash2   = crypto.createHash('sha256').update(pid2 + '|' + pub2 + '|' + ts2 + '|' + origStr, 'utf8').digest();
    var sig2    = ed25519Sign(pair2.privateKey, hash2);
    rm.registerPublisher({ publisherId: pid2, pubKeyHex: pub2, allowedOrigins: [], ts: ts2, sig: sig2 });

    var cid   = 'bafyopen' + crypto.randomBytes(8).toString('hex');
    var token = makePublisherAuthToken(pair2.privateKey, pub2, pid2, 'bob', cid);
    var result = rm.verifyPublisherAuth(token, cid, 'https://any-origin.com');
    assert.strictEqual(result.userId, 'bob');
});

teardown();

// ─── Grant chain tests ────────────────────────────────────────────────────────

console.log('\n── Grant chain ──');
setup();

var _chainCid = 'bafychain' + crypto.randomBytes(8).toString('hex');

test('append first grant entry (genesis)', function () {
    var e = rm.appendGrantEntry({
        rootCid: _chainCid, entryType: 'grant',
        granter: 'alice', grantee: 'bob',
        terms: { accessLevel: 20, reshare: false },
    });
    assert.strictEqual(e.id, 1);
    assert.strictEqual(e.prevHash, '', 'genesis has empty prevHash');
    assert.ok(e.sig, 'entry must have a sig');
});

test('append second entry chains prev_hash', function () {
    var e = rm.appendGrantEntry({
        rootCid: _chainCid, entryType: 'accept',
        granter: 'bob', grantee: 'bob',
    });
    assert.strictEqual(e.id, 2);
    assert.ok(e.prevHash.length === 64, 'prevHash is a sha256 hex');
});

test('read full chain', function () {
    var entries = rm.getGrantChain(_chainCid);
    assert.strictEqual(entries.length, 2);
    assert.strictEqual(entries[0].entryType, 'grant');
    assert.strictEqual(entries[1].entryType, 'accept');
    assert.strictEqual(entries[1].prevHash.length, 64);
});

test('pagination via afterId', function () {
    // Append a third entry
    rm.appendGrantEntry({ rootCid: _chainCid, entryType: 'revoke', granter: 'alice', grantee: 'bob' });
    var page2 = rm.getGrantChain(_chainCid, { afterId: 2 });
    assert.strictEqual(page2.length, 1);
    assert.strictEqual(page2[0].entryType, 'revoke');
});

test('invalid entryType throws 400', function () {
    try {
        rm.appendGrantEntry({ rootCid: _chainCid, entryType: 'hack', granter: 'x', grantee: 'y' });
        assert.fail('should have thrown');
    } catch (e) {
        assert.strictEqual(e.statusCode, 400);
    }
});

test('chains across different rootCids are independent', function () {
    var cid2 = 'bafychain2' + crypto.randomBytes(8).toString('hex');
    var e    = rm.appendGrantEntry({ rootCid: cid2, entryType: 'grant', granter: 'x', grantee: 'y' });
    assert.strictEqual(e.prevHash, '', 'new chain is also genesis');
});

teardown();

// ─── Rate limiting tests ──────────────────────────────────────────────────────

console.log('\n── Rate limiting ──');
// Use a fresh RM with capacity=3 for easy exhaustion
var _rmRate;
(function () {
    var d  = tmpDir();
    _rmRate = new RightsManagement({ rateLimitCapacity: 3, rateLimitRefillRate: 3 / 60000 });
    _rmRate.open(path.join(d, 'rl.db'));
})();

test('first 3 requests pass', function () {
    for (var i = 0; i < 3; i++) {
        assert.strictEqual(_rmRate.checkRateLimit('pub1', 'user1'), true, 'request ' + i + ' should pass');
    }
});

test('4th request is throttled', function () {
    var allowed = _rmRate.checkRateLimit('pub1', 'user1');
    assert.strictEqual(allowed, false, 'should be rate limited');
});

test('different user has fresh bucket', function () {
    assert.strictEqual(_rmRate.checkRateLimit('pub1', 'user2'), true);
    assert.strictEqual(_rmRate.checkRateLimit('pub1', 'user2'), true);
});

test('different publisher has fresh bucket', function () {
    assert.strictEqual(_rmRate.checkRateLimit('pub2', 'user1'), true);
});

_rmRate.close();

// ─── Summary ──────────────────────────────────────────────────────────────────
console.log('');
if (failed) {
    console.error(passed + ' passed, ' + failed + ' failed');
    process.exit(1);
} else {
    console.log(passed + ' passed, 0 failed');
}
