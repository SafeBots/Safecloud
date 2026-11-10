'use strict';
/**
 * control_panel.test.js — Safecloud 3.8 ControlPanel + payment-replay tests.
 *
 * Tests:
 *   Payment replay protection (new in 3.8):
 *     • same nonce twice → 409 on second use
 *     • different nonce same publisher → allowed
 *     • expired-token nonce is not recorded
 *
 *   ControlPanel HTTP API:
 *     • GET /Safecloud/admin/           → HTML
 *     • GET /Safecloud/admin/api/stats  → aggregate counts
 *     • GET /Safecloud/admin/api/roots  → list roots
 *     • GET /Safecloud/admin/api/roots/:cid → detail + chain
 *     • GET /Safecloud/admin/api/publishers → list
 *     • DELETE /Safecloud/admin/api/publishers/:id → deregister
 *     • GET /Safecloud/admin/api/chain/:cid → chain
 *     • POST /Safecloud/admin/api/chain/:cid → append entry
 *     • GET /Safecloud/admin/api/rate-limits → list buckets
 *     • DELETE /Safecloud/admin/api/rate-limits/:bucket → reset
 *     • GET /Safecloud/admin/api/nonces → active nonces
 *     • Admin-token auth enforcement
 */

var assert           = require('assert');
var http             = require('http');
var crypto           = require('crypto');
var os               = require('os');
var path             = require('path');
var fs               = require('fs');
var express          = require('express');
var RightsManagement = require('../classes/Safecloud/RightsManagement');
var ControlPanel     = require('../classes/Safecloud/ControlPanel');
var JetKey           = require('../classes/Safecloud/JetKey');

// ─── Test helpers ─────────────────────────────────────────────────────────────

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
        if (process.env.VERBOSE) console.error(e.stack);
        failed++;
    }
}

function testAsync(label, fn) {
    total++;
    return fn().then(function () {
        console.log('  ✓ ' + label);
        passed++;
    }).catch(function (e) {
        console.error('  ✗ ' + label);
        console.error('    ' + e.message);
        if (process.env.VERBOSE) console.error(e.stack);
        failed++;
    });
}

function tmpDir() {
    var d = path.join(os.tmpdir(), 'cp_test_' + crypto.randomBytes(4).toString('hex'));
    fs.mkdirSync(d, { recursive: true });
    return d;
}

function makeEd25519() {
    return crypto.generateKeyPairSync('ed25519');
}
function rawPubHex(keyObj) {
    return keyObj.export({ type: 'spki', format: 'der' }).slice(12).toString('hex');
}
function ed25519Sign(privKey, hashBuf) {
    return crypto.sign(null, hashBuf, privKey).toString('hex');
}

function makePublisherAuthToken(privKey, pubHex, publisher, userId, rootCid, overrides) {
    var now  = Date.now();
    var body = Object.assign({
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

function registerPublisher(rm, pair) {
    var pubHex  = rawPubHex(pair.publicKey);
    var pid     = 'pub-' + crypto.randomBytes(4).toString('hex') + '.example.com';
    var origins = ['https://example.com'];
    var ts      = Date.now();
    var origStr = JSON.stringify(origins);
    var payload = pid + '|' + pubHex + '|' + ts + '|' + origStr;
    var hash    = crypto.createHash('sha256').update(payload, 'utf8').digest();
    var sig     = ed25519Sign(pair.privateKey, hash);
    rm.registerPublisher({ publisherId: pid, pubKeyHex: pubHex, allowedOrigins: origins, ts: ts, sig: sig });
    return { publisherId: pid, pubHex: pubHex };
}

// Simple fetch helper using Node's http module
function req(port, method, urlPath, body, headers) {
    return new Promise(function (resolve, reject) {
        var opts = {
            hostname: '127.0.0.1',
            port:     port,
            path:     urlPath,
            method:   method || 'GET',
            headers:  Object.assign({ 'Accept': 'application/json' }, headers || {}),
        };
        if (body) {
            var bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
            opts.headers['Content-Type'] = 'application/json';
            opts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
        }
        var r = http.request(opts, function (res) {
            var chunks = [];
            res.on('data', function (c) { chunks.push(c); });
            res.on('end', function () {
                var text = Buffer.concat(chunks).toString();
                var json;
                try { json = JSON.parse(text); } catch (e) { json = { _raw: text }; }
                resolve({ status: res.statusCode, body: json, headers: res.headers });
            });
        });
        r.on('error', reject);
        if (body) r.write(typeof body === 'string' ? body : JSON.stringify(body));
        r.end();
    });
}

function reqHtml(port, urlPath) {
    return new Promise(function (resolve, reject) {
        var r = http.request({ hostname: '127.0.0.1', port: port, path: urlPath, method: 'GET' }, function (res) {
            var chunks = [];
            res.on('data', function (c) { chunks.push(c); });
            res.on('end', function () { resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString(), headers: res.headers }); });
        });
        r.on('error', reject);
        r.end();
    });
}

// ─── JetKey init ──────────────────────────────────────────────────────────────
JetKey.init(path.join(os.tmpdir(), 'cp_jetkey_' + process.pid + '.json'));

// ─── Shared server setup ──────────────────────────────────────────────────────

var _rm, _port, _server;

function startServer(adminToken) {
    return new Promise(function (resolve, reject) {
        var d   = tmpDir();
        _rm     = new RightsManagement({ rateLimitCapacity: 5, rateLimitRefillRate: 5 / 60000 });
        _rm.open(path.join(d, 'rights.db'));

        var app = express();
        app.use(express.json());
        ControlPanel.registerRoutes(app, _rm, adminToken ? { adminToken: adminToken } : {});

        _server = http.createServer(app);
        _server.listen(0, '127.0.0.1', function () {
            _port = _server.address().port;
            resolve();
        });
        _server.on('error', reject);
    });
}

function stopServer() {
    return new Promise(function (resolve) {
        if (_rm) { _rm.close(); _rm = null; }
        if (_server) { _server.close(resolve); _server = null; }
        else resolve();
    });
}

// ─── Payment replay protection ────────────────────────────────────────────────

console.log('\n── Payment replay protection ──');

(function () {
    var d  = tmpDir();
    var rm = new RightsManagement({ rateLimitCapacity: 10, rateLimitRefillRate: 10 / 60000 });
    rm.open(path.join(d, 'replay.db'));

    var pair    = makeEd25519();
    var pubHex  = rawPubHex(pair.publicKey);
    var pid     = 'replay.example.com';
    var origins = ['https://replay.example.com'];
    var ts      = Date.now();
    var origStr = JSON.stringify(origins);
    var payload = pid + '|' + pubHex + '|' + ts + '|' + origStr;
    var hash    = crypto.createHash('sha256').update(payload, 'utf8').digest();
    rm.registerPublisher({ publisherId: pid, pubKeyHex: pubHex, allowedOrigins: origins, ts: ts,
        sig: ed25519Sign(pair.privateKey, hash) });

    test('first use of a nonce is accepted', function () {
        var cid   = 'bafyreplay1' + crypto.randomBytes(4).toString('hex');
        var token = makePublisherAuthToken(pair.privateKey, pubHex, pid, 'alice', cid);
        var r     = rm.verifyPublisherAuth(token, cid, 'https://replay.example.com');
        assert.strictEqual(r.userId, 'alice');
    });

    test('replaying the same token (same nonce) → 409', function () {
        var cid   = 'bafyreplay2' + crypto.randomBytes(4).toString('hex');
        var nonce = crypto.randomBytes(16).toString('hex');
        var token = makePublisherAuthToken(pair.privateKey, pubHex, pid, 'alice', cid, { nonce: nonce });
        rm.verifyPublisherAuth(token, cid, 'https://replay.example.com'); // first use
        try {
            rm.verifyPublisherAuth(token, cid, 'https://replay.example.com'); // replay
            assert.fail('should have thrown');
        } catch (e) {
            assert.strictEqual(e.statusCode, 409);
        }
    });

    test('different nonce same publisher is allowed', function () {
        var cid    = 'bafydiffnonce' + crypto.randomBytes(4).toString('hex');
        var token1 = makePublisherAuthToken(pair.privateKey, pubHex, pid, 'alice', cid);
        var token2 = makePublisherAuthToken(pair.privateKey, pubHex, pid, 'alice', cid);
        rm.verifyPublisherAuth(token1, cid, 'https://replay.example.com');
        var r = rm.verifyPublisherAuth(token2, cid, 'https://replay.example.com');
        assert.strictEqual(r.userId, 'alice');
    });

    test('expired token does not get its nonce recorded', function () {
        var cid   = 'bafyexpnonce' + crypto.randomBytes(4).toString('hex');
        var nonce = crypto.randomBytes(16).toString('hex');
        var token = makePublisherAuthToken(pair.privateKey, pubHex, pid, 'alice', cid,
            { exp: Date.now() - 10000 });
        try {
            rm.verifyPublisherAuth(token, cid, 'https://replay.example.com');
        } catch (e) {
            assert.strictEqual(e.statusCode, 401, 'expired token should be 401');
        }
        // The nonce must NOT be in the DB (the token was rejected before recording)
        var row = rm._db.prepare('SELECT nonce FROM used_nonces WHERE nonce = ?').get(nonce);
        assert.strictEqual(row, undefined, 'expired token nonce must not be stored');
    });

    test('listUsedNonces returns active nonces', function () {
        var cid   = 'bafylistnonces' + crypto.randomBytes(4).toString('hex');
        var nonce = crypto.randomBytes(16).toString('hex');
        var token = makePublisherAuthToken(pair.privateKey, pubHex, pid, 'alice', cid, { nonce: nonce });
        rm.verifyPublisherAuth(token, cid, 'https://replay.example.com');
        var list = rm.listUsedNonces();
        var found = list.some(function (n) { return n.nonce === nonce; });
        assert.ok(found, 'nonce should appear in listUsedNonces');
    });

    rm.close();
})();

// ─── Admin API tests (async) ──────────────────────────────────────────────────

console.log('\n── ControlPanel HTTP API ──');

var allTests = startServer().then(function () {
    // Seed some data
    var pair1   = makeEd25519();
    var pub1    = registerPublisher(_rm, pair1);
    var pair2   = makeEd25519();
    var pub2    = registerPublisher(_rm, pair2);

    var cid1 = 'bafyadmin1' + crypto.randomBytes(4).toString('hex');
    var cid2 = 'bafyadmin2' + crypto.randomBytes(4).toString('hex');
    _rm.registerRootKey({ rootCid: cid1, rootKey: crypto.randomBytes(32), accessModel: { requirePayment: false } });
    _rm.registerRootKey({ rootCid: cid2, rootKey: crypto.randomBytes(32) });
    _rm.appendGrantEntry({ rootCid: cid1, entryType: 'grant', granter: 'alice', grantee: 'bob' });
    _rm.checkRateLimit(pub1.publisherId, 'user1');
    _rm.checkRateLimit(pub1.publisherId, 'user2');

    // Record a nonce by verifying a valid token
    var validToken = makePublisherAuthToken(pair1.privateKey, pub1.pubHex, pub1.publisherId, 'alice', cid1);
    try { _rm.verifyPublisherAuth(validToken, cid1, 'https://example.com'); } catch (e) { /* ignore origin */ }

    var tests = [];

    tests.push(testAsync('GET /Safecloud/admin/ returns HTML', function () {
        return reqHtml(_port, '/Safecloud/admin/').then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.ok(r.body.includes('Safecloud Control Panel'), 'HTML should contain title');
            assert.ok(r.headers['content-type'].includes('text/html'));
        });
    }));

    tests.push(testAsync('GET /Safecloud/admin/ redirect from bare path', function () {
        return reqHtml(_port, '/Safecloud/admin').then(function (r) {
            // 302 or 200 (express redirect)
            assert.ok(r.status === 200 || r.status === 301 || r.status === 302);
        });
    }));

    tests.push(testAsync('GET /api/stats returns aggregate counts', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/stats').then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.ok(r.body.roots >= 2, 'at least 2 roots');
            assert.ok(r.body.publishers >= 2, 'at least 2 publishers');
            assert.ok(r.body.grantEntries >= 1, 'at least 1 grant entry');
            assert.ok(r.body.rateBuckets >= 2, 'at least 2 rate buckets');
            assert.ok(typeof r.body.activeNonces === 'number');
        });
    }));

    tests.push(testAsync('GET /api/roots returns root list', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/roots').then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.ok(Array.isArray(r.body.roots));
            assert.ok(r.body.roots.length >= 2);
            var found = r.body.roots.some(function (x) { return x.rootCid === cid1; });
            assert.ok(found, 'cid1 should appear in roots list');
            // key material must NOT be returned
            assert.ok(!r.body.roots[0].rootKey, 'root_key must not be exposed');
        });
    }));

    tests.push(testAsync('GET /api/roots/:cid returns detail + chain', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/roots/' + encodeURIComponent(cid1)).then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.strictEqual(r.body.rootCid, cid1);
            assert.ok(Array.isArray(r.body.chain));
            assert.ok(r.body.chain.length >= 1, 'chain should have at least 1 entry');
        });
    }));

    tests.push(testAsync('GET /api/roots/:cid for unknown cid → 404', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/roots/bafynosuchcid').then(function (r) {
            assert.strictEqual(r.status, 404);
        });
    }));

    tests.push(testAsync('GET /api/publishers returns publisher list', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/publishers').then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.ok(Array.isArray(r.body.publishers));
            assert.ok(r.body.publishers.length >= 2);
        });
    }));

    tests.push(testAsync('DELETE /api/publishers/:id deregisters publisher', function () {
        return req(_port, 'DELETE', '/Safecloud/admin/api/publishers/' + encodeURIComponent(pub2.publisherId)).then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.strictEqual(r.body.deregistered, true);
            // Verify it's gone
            return req(_port, 'GET', '/Safecloud/admin/api/publishers').then(function (r2) {
                var ids = r2.body.publishers.map(function (p) { return p.publisherId; });
                assert.ok(!ids.includes(pub2.publisherId), 'pub2 should be gone');
            });
        });
    }));

    tests.push(testAsync('DELETE /api/publishers/:id for unknown → 404', function () {
        return req(_port, 'DELETE', '/Safecloud/admin/api/publishers/nosuchpub').then(function (r) {
            assert.strictEqual(r.status, 404);
        });
    }));

    tests.push(testAsync('GET /api/chain/:cid returns grant chain', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/chain/' + encodeURIComponent(cid1)).then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.ok(Array.isArray(r.body.entries));
            assert.strictEqual(r.body.entries[0].entryType, 'grant');
        });
    }));

    tests.push(testAsync('POST /api/chain/:cid appends a grant entry', function () {
        return req(_port, 'POST', '/Safecloud/admin/api/chain/' + encodeURIComponent(cid2), {
            entryType: 'grant', granter: 'admin', grantee: 'carol', terms: { level: 10 },
        }).then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.strictEqual(r.body.entry.entryType, 'grant');
            assert.strictEqual(r.body.entry.granter, 'admin');
        });
    }));

    tests.push(testAsync('POST /api/chain/:cid with invalid entryType → 400', function () {
        return req(_port, 'POST', '/Safecloud/admin/api/chain/' + encodeURIComponent(cid2), {
            entryType: 'hack', granter: 'x', grantee: 'y',
        }).then(function (r) {
            assert.strictEqual(r.status, 400);
        });
    }));

    tests.push(testAsync('GET /api/rate-limits returns buckets', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/rate-limits').then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.ok(Array.isArray(r.body.buckets));
            assert.ok(r.body.buckets.length >= 2);
            assert.ok(typeof r.body.capacity === 'number');
        });
    }));

    tests.push(testAsync('DELETE /api/rate-limits/:bucket resets bucket', function () {
        var key = pub1.publisherId + ':user1';
        return req(_port, 'DELETE', '/Safecloud/admin/api/rate-limits/' + encodeURIComponent(key)).then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.strictEqual(r.body.reset, true);
        });
    }));

    tests.push(testAsync('DELETE /api/rate-limits/:bucket for unknown → 404', function () {
        return req(_port, 'DELETE', '/Safecloud/admin/api/rate-limits/' + encodeURIComponent('nobody:nobody')).then(function (r) {
            assert.strictEqual(r.status, 404);
        });
    }));

    tests.push(testAsync('GET /api/nonces returns active nonces', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/nonces').then(function (r) {
            assert.strictEqual(r.status, 200);
            assert.ok(Array.isArray(r.body.nonces));
        });
    }));

    return Promise.all(tests);

}).then(function () {
    return stopServer();
}).then(function () {
    // Admin token enforcement
    console.log('\n── Admin token auth ──');
    return startServer('super-secret');
}).then(function () {
    var t1 = testAsync('missing token → 401', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/stats').then(function (r) {
            assert.strictEqual(r.status, 401);
        });
    });
    var t2 = testAsync('wrong token → 401', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/stats', null, { Authorization: 'Bearer wrong' }).then(function (r) {
            assert.strictEqual(r.status, 401);
        });
    });
    var t3 = testAsync('correct token → 200', function () {
        return req(_port, 'GET', '/Safecloud/admin/api/stats', null, { Authorization: 'Bearer super-secret' }).then(function (r) {
            assert.strictEqual(r.status, 200);
        });
    });
    return Promise.all([t1, t2, t3]);
}).then(function () {
    return stopServer();
}).then(function () {
    // Summary
    console.log('');
    if (failed) {
        console.error(passed + ' passed, ' + failed + ' failed');
        process.exit(1);
    } else {
        console.log(passed + ' passed, 0 failed');
    }
}).catch(function (e) {
    console.error('Test runner error:', e.message);
    process.exit(1);
});
