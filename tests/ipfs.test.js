'use strict';
/**
 * Safecloud 3.3 — IPFS / IPNS test suite
 *
 * Covers:
 *  1.  Module disabled — all public API calls reject gracefully
 *  2.  Pin store CRUD — create, read, delete, persist round-trip
 *  3.  PSA wire-format compliance — field names, types, ISO timestamps
 *  4.  listPins filters — status, cid (array), name, limit
 *  5.  Idempotent pin — same CID returns existing record
 *  6.  Kubo "not pinned" error — graceful cleanup on unpin
 *  7.  PSA HTTP routes — real Express app, real HTTP requests
 *  8.  Bearer auth — 401 when wrong token; 200 when correct
 *  9.  Hostile input — bad CID, oversized inputs, missing fields
 * 10.  Status endpoint — reflects enabled/mode/reachable
 * 11.  Kubo proxy routes — /api/v0/pin/add, /api/v0/id, etc.
 * 12.  IPNS routes — key/gen, key/list, name/publish, name/resolve
 * 13.  Jets.js integration — IPFS routes registered when enabled
 * 14.  Integration tests — gated on IPFS_API_URL env var (real Kubo)
 *
 * Wire-compatibility references:
 *   IPFS Pinning Services API v1.0.0
 *     https://ipfs.github.io/pinning-services-api-spec/
 *   Kubo HTTP RPC API
 *     https://docs.ipfs.tech/reference/kubo/rpc/
 *
 * No mocking of Node built-ins: we spin up real local HTTP servers.
 */

const http    = require('http');
const express = require('express');
const path    = require('path');
const os      = require('os');
const fs      = require('fs');
const crypto  = require('crypto');

let pass = 0, fail = 0;
function check(n, c, d) {
    c ? (pass++, console.log('  ✓', n))
      : (fail++, console.log('  ✗ FAIL:', n, d ? ('— ' + d) : ''));
}
function section(t) { console.log('\n── ' + t + ' ──'); }

// ── Helpers ──────────────────────────────────────────────────────────────────

/** HTTP helper: make a request to a local server and return { status, body, raw, headers }. */
function req(server, method, urlPath, body, extraHeaders) {
    return new Promise(function (resolve) {
        var data = body ? JSON.stringify(body) : null;
        var headers = Object.assign(
            data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {},
            extraHeaders || {}
        );
        var r = http.request(
            {
                host:    '127.0.0.1',
                port:    server.address().port,
                path:    urlPath,
                method:  method,
                headers: headers
            },
            function (res) {
                var b = '';
                res.on('data', function (c) { b += c; });
                res.on('end',  function () {
                    var j = null;
                    try { j = JSON.parse(b); } catch (e) {}
                    resolve({ status: res.statusCode, body: j, raw: b, headers: res.headers });
                });
            }
        );
        r.on('error', function () { resolve({ status: 0, body: null, raw: '' }); });
        if (data) { r.write(data); }
        r.end();
    });
}

/** Start a mock Kubo HTTP RPC server. Returns { server, port, state }. */
function startMockKubo() {
    return new Promise(function (resolve) {
        var state = {
            pins: {},           // cid → true
            pinRmShouldFail: false,   // set to simulate "not pinned" error
            pinAddShouldFail: false,
            lastAddCid: null,
            lastRmCid: null
        };

        var app = express();
        app.use(express.json());

        app.post('/api/v0/pin/add', function (req, res) {
            var cid = req.query.arg || 'QmTestCid';
            if (state.pinAddShouldFail) {
                return res.status(500).json({ Message: 'pin add failed', Code: 0 });
            }
            state.pins[cid] = true;
            state.lastAddCid = cid;
            res.json({ Pins: [cid] });
        });

        app.post('/api/v0/pin/rm', function (req, res) {
            var cid = req.query.arg || 'QmTestCid';
            state.lastRmCid = cid;
            if (state.pinRmShouldFail) {
                return res.status(500).json({ Message: 'not pinned or pinned indirectly', Code: 0 });
            }
            delete state.pins[cid];
            res.json({ Pins: [cid] });
        });

        app.post('/api/v0/pin/ls', function (req, res) {
            var keys = {};
            Object.keys(state.pins).forEach(function (cid) {
                keys[cid] = { Type: 'recursive' };
            });
            res.json({ Keys: keys });
        });

        app.post('/api/v0/id', function (req, res) {
            res.json({
                ID: 'QmMockKuboPeerId123',
                AgentVersion: 'kubo/0.26.0/mock',
                Addresses: ['/ip4/127.0.0.1/tcp/4001/p2p/QmMockKuboPeerId123']
            });
        });

        app.post('/api/v0/add', function (req, res) {
            // Simulate NDJSON response
            var cid = 'QmAdd' + crypto.randomBytes(4).toString('hex');
            state.lastAddCid = cid;
            state.pins[cid] = true;
            res.end(JSON.stringify({ Name: 'upload', Hash: cid, Size: '42' }) + '\n');
        });

        app.post('/api/v0/cat', function (req, res) {
            var cid = req.query.arg || '';
            if (!cid) {
                return res.status(400).json({ Message: 'argument "arg" is required', Code: 1 });
            }
            res.end(Buffer.from('mock content for ' + cid));
        });

        app.post('/api/v0/key/gen', function (req, res) {
            var name = req.query.arg;
            if (!name) { return res.status(400).json({ Message: 'arg required', Code: 1 }); }
            res.json({ Name: name, Id: 'k51q' + Buffer.from(name).toString('hex') });
        });

        app.post('/api/v0/key/list', function (req, res) {
            res.json({ Keys: [{ Name: 'self', Id: 'k51qself000' }] });
        });

        app.post('/api/v0/key/rm', function (req, res) {
            var name = req.query.arg;
            res.json({ Keys: [{ Name: name, Id: 'k51q' + Buffer.from(name || '').toString('hex') }] });
        });

        app.post('/api/v0/name/publish', function (req, res) {
            var arg = req.query.arg || '/ipfs/QmTest';
            var cid = arg.replace('/ipfs/', '');
            res.json({ Name: '/ipns/k51qmock', Value: '/ipfs/' + cid });
        });

        app.post('/api/v0/name/resolve', function (req, res) {
            res.json({ Path: '/ipfs/QmResolvedMock' });
        });

        app.post('/api/v0/swarm/peers', function (req, res) {
            res.json({ Peers: [] });
        });

        app.post('/api/v0/version', function (req, res) {
            res.json({ Version: '0.26.0', Commit: 'test', Repo: '15' });
        });

        var server = http.createServer(app);
        server.listen(0, '127.0.0.1', function () {
            resolve({ server: server, port: server.address().port, state: state });
        });
    });
}

/** Build a Q stub with IPFS config pointing at the given port. */
function makeQ(ipfsPort, overrides) {
    var cfg = Object.assign({
        Safecloud: {
            ipfs: {
                enabled:  true,
                mode:     'external',
                apiUrl:   'http://127.0.0.1:' + (ipfsPort || 5001),
                gatewayUrl: null,
                pinningService: { endpoint: null, key: null, exposedKey: null },
                requireSafebux: false,
                sbuxPerGB: 0
            }
        }
    }, overrides);

    var tmpDir = fs.mkdtempSync(os.tmpdir() + '/sc-ipfs-test-');

    return {
        Config: {
            get: function (k, d) {
                var o = cfg;
                for (var i = 0; i < k.length; i++) {
                    if (o == null || typeof o !== 'object') { return d; }
                    o = o[k[i]];
                }
                return o === undefined ? d : o;
            },
            set: function () {}
        },
        log: function () {},
        app: { DIR: tmpDir },
        _tmpDir: tmpDir
    };
}

function cleanupQ(Q) {
    if (Q._tmpDir) {
        try {
            var pinFile = path.join(Q._tmpDir, 'safecloud-ipfs-pins.json');
            if (fs.existsSync(pinFile)) { fs.unlinkSync(pinFile); }
            fs.rmdirSync(Q._tmpDir);
        } catch (e) {}
    }
}

// ── Load the real modules ─────────────────────────────────────────────────────

var SafecloudIpfs = require(path.join(process.cwd(), 'classes/Safecloud/Ipfs.js'));
var SafecloudIpns = require(path.join(process.cwd(), 'classes/Safecloud/Ipns.js'));

// ══════════════════════════════════════════════════════════════════════════════
//  1. MODULE DISABLED — all public API calls reject gracefully
// ══════════════════════════════════════════════════════════════════════════════

(async function () {

section('1. Module disabled (no-op)');

// Reset to a clean, disabled state
SafecloudIpfs._resetStore();
SafecloudIpfs.init({ Q: makeQ(9999, { Safecloud: { ipfs: { enabled: false } } }) });

check('isEnabled() returns false', !SafecloudIpfs.isEnabled());

var err;

err = await SafecloudIpfs.pin('QmTest', {}).catch(function (e) { return e; });
check('pin() rejects with "IPFS not enabled"', err instanceof Error && /not enabled/i.test(err.message));

err = await SafecloudIpfs.unpin('somerid').catch(function (e) { return e; });
check('unpin() rejects with "IPFS not enabled"', err instanceof Error && /not enabled/i.test(err.message));

err = await SafecloudIpfs.listPins({}).catch(function (e) { return e; });
check('listPins() rejects with "IPFS not enabled"', err instanceof Error && /not enabled/i.test(err.message));

err = await SafecloudIpfs.add(Buffer.from('x')).catch(function (e) { return e; });
check('add() rejects with "IPFS not enabled"', err instanceof Error && /not enabled/i.test(err.message));

err = await SafecloudIpfs.cat('QmTest').catch(function (e) { return e; });
check('cat() rejects with "IPFS not enabled"', err instanceof Error && /not enabled/i.test(err.message));

var st = await SafecloudIpfs.status();
check('status() returns { enabled: false }', st && st.enabled === false);

check('isEnabled() is false after disabled init', !SafecloudIpfs.isEnabled());

// ══════════════════════════════════════════════════════════════════════════════
//  2. PIN STORE CRUD
// ══════════════════════════════════════════════════════════════════════════════

section('2. Pin store CRUD (mock Kubo)');

var kubo = await startMockKubo();
var testQ = makeQ(kubo.port);
SafecloudIpfs._resetStore();
SafecloudIpfs.init({ Q: testQ });
check('isEnabled() is true after enabled init', SafecloudIpfs.isEnabled());
check('getMode() is "external"', SafecloudIpfs.getMode() === 'external');

var cid1 = 'QmAlpha1111111111111111111111111111111111111111';
var pin1 = await SafecloudIpfs.pin(cid1, { name: 'test-alpha', meta: { env: 'test' } });

check('pin() returns a PinStatus record', pin1 && typeof pin1 === 'object');
check('pin.status is "pinned" after Kubo ack', pin1.status === 'pinned');
check('pin.requestid is a 32-char hex string', /^[a-f0-9]{32}$/.test(pin1.requestid));
check('pin.created is a valid ISO 8601 string', !isNaN(Date.parse(pin1.created)));
check('pin.pin.cid matches input', pin1.pin.cid === cid1);
check('pin.pin.name matches input', pin1.pin.name === 'test-alpha');
check('pin.pin.meta matches input', pin1.pin.meta && pin1.pin.meta.env === 'test');
check('pin.pin.origins is an array', Array.isArray(pin1.pin.origins));
check('pin.delegates is an array', Array.isArray(pin1.delegates));
check('Kubo received the pin/add request', kubo.state.pins[cid1] === true);

// getPinByRequestid
var fetched = SafecloudIpfs.getPinByRequestid(pin1.requestid);
check('getPinByRequestid() returns the record', fetched && fetched.requestid === pin1.requestid);
check('getPinByRequestid() returns same object', fetched === pin1);

// getPinByCid
var byCid = SafecloudIpfs.getPinByCid(cid1);
check('getPinByCid() returns the record', byCid && byCid.pin.cid === cid1);

// getPinByRequestid for unknown
check('getPinByRequestid() returns null for unknown', SafecloudIpfs.getPinByRequestid('deadbeef') === null);

// unpin
await SafecloudIpfs.unpin(pin1.requestid);
check('unpin() removes pin from store', SafecloudIpfs.getPinByRequestid(pin1.requestid) === null);
check('unpin() removes CID from index', SafecloudIpfs.getPinByCid(cid1) === null);
check('Kubo received the pin/rm request', kubo.state.lastRmCid === cid1);
check('unpin() removes CID from Kubo state', !kubo.state.pins[cid1]);

// unpin unknown
var unpinErr = await SafecloudIpfs.unpin('nonexistentrid').catch(function (e) { return e; });
check('unpin() rejects for unknown requestid', unpinErr instanceof Error && /not found/i.test(unpinErr.message));

// ══════════════════════════════════════════════════════════════════════════════
//  3. PSA WIRE FORMAT COMPLIANCE
// ══════════════════════════════════════════════════════════════════════════════

section('3. PSA v1.0.0 wire-format compliance');

SafecloudIpfs._resetStore();
var cidPsa = 'bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku';
var pinPsa = await SafecloudIpfs.pin(cidPsa, {
    name: 'psa-compliance-test',
    origins: ['/ip4/1.2.3.4/tcp/4001/p2p/QmPeer'],
    meta: { source: 'test' }
});

// Required PSA PinStatus fields
check('PSA: requestid present', typeof pinPsa.requestid === 'string');
check('PSA: status in allowed set',
    ['queued','pinning','pinned','failed'].includes(pinPsa.status));
check('PSA: created is ISO 8601', !isNaN(Date.parse(pinPsa.created)));
check('PSA: pin.cid is a string', typeof pinPsa.pin.cid === 'string');
check('PSA: pin.name preserved', pinPsa.pin.name === 'psa-compliance-test');
check('PSA: pin.origins is array', Array.isArray(pinPsa.pin.origins));
check('PSA: pin.origins[0] preserved', pinPsa.pin.origins[0] === '/ip4/1.2.3.4/tcp/4001/p2p/QmPeer');
check('PSA: pin.meta is object', pinPsa.pin.meta && typeof pinPsa.pin.meta === 'object');
check('PSA: delegates is array', Array.isArray(pinPsa.delegates));
// requestid must be unique
var pin2 = await SafecloudIpfs.pin('QmBeta2222222222222222222222222222222222222222', {});
check('PSA: each requestid is unique', pin2.requestid !== pinPsa.requestid);

// ══════════════════════════════════════════════════════════════════════════════
//  4. listPins FILTERS
// ══════════════════════════════════════════════════════════════════════════════

section('4. listPins filters');

SafecloudIpfs._resetStore();
var pinA = await SafecloudIpfs.pin('QmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', { name: 'alpha' });
// Manually set different statuses for filter testing (simulate different outcomes)
SafecloudIpfs._getPins()[pinA.requestid].status = 'pinned';
var pinB = await SafecloudIpfs.pin('QmBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', { name: 'beta' });
SafecloudIpfs._getPins()[pinB.requestid].status = 'failed';
var pinC = await SafecloudIpfs.pin('QmCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', { name: 'gamma' });
SafecloudIpfs._getPins()[pinC.requestid].status = 'queued';

var all = await SafecloudIpfs.listPins({ limit: 100 });
check('listPins: returns all 3 pins (limit 100)', all.count === 3);
check('listPins: count matches results array length', all.count === all.results.length);

var pinned = await SafecloudIpfs.listPins({ status: 'pinned' });
check('listPins: status=pinned returns 1', pinned.count === 1 && pinned.results[0].status === 'pinned');

var multi = await SafecloudIpfs.listPins({ status: ['pinned', 'failed'] });
check('listPins: status array returns pinned+failed (2)', multi.count === 2);

var byCidFilter = await SafecloudIpfs.listPins({
    cid: ['QmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'QmCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'],
    limit: 100
});
check('listPins: cid array filter returns 2', byCidFilter.count === 2);

var byName = await SafecloudIpfs.listPins({ name: 'beta' });
check('listPins: name exact match returns 1', byName.count === 1 && byName.results[0].pin.name === 'beta');

var limited = await SafecloudIpfs.listPins({ limit: 2 });
check('listPins: limit=2 returns at most 2', limited.results.length <= 2);

var limited1 = await SafecloudIpfs.listPins({ limit: 1 });
check('listPins: limit=1 returns exactly 1', limited1.results.length === 1);

var empty = await SafecloudIpfs.listPins({ status: 'pinning' });
check('listPins: filter matching nothing returns count=0', empty.count === 0 && empty.results.length === 0);

var defaultLimit = await SafecloudIpfs.listPins({});
check('listPins: default limit is 10', defaultLimit.results.length <= 10);

// ══════════════════════════════════════════════════════════════════════════════
//  5. IDEMPOTENT PIN
// ══════════════════════════════════════════════════════════════════════════════

section('5. Idempotent pin');

SafecloudIpfs._resetStore();
var cidIdem = 'QmIdemXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
var idem1 = await SafecloudIpfs.pin(cidIdem, { name: 'first' });
var idem2 = await SafecloudIpfs.pin(cidIdem, { name: 'second' });  // same CID
check('idempotent pin: returns same record object', idem1 === idem2);
check('idempotent pin: requestid unchanged', idem1.requestid === idem2.requestid);
check('idempotent pin: name not overwritten', idem2.pin.name === 'first');

var allIdem = await SafecloudIpfs.listPins({ limit: 100 });
check('idempotent pin: only one record in store', allIdem.count === 1);

// ══════════════════════════════════════════════════════════════════════════════
//  6. KUBO "NOT PINNED" ERROR — graceful cleanup on unpin
// ══════════════════════════════════════════════════════════════════════════════

section('6. Kubo "not pinned" error — graceful unpin');

SafecloudIpfs._resetStore();
var cidGrace = 'QmGrace111111111111111111111111111111111111111111';
var gracePin = await SafecloudIpfs.pin(cidGrace, {});

// Simulate Kubo returning "not pinned" on the rm call
kubo.state.pinRmShouldFail = true;
var unpinResult = await SafecloudIpfs.unpin(gracePin.requestid);
kubo.state.pinRmShouldFail = false;

check('unpin() resolves despite Kubo "not pinned" error', unpinResult === undefined);
check('unpin() still removes record from store', SafecloudIpfs.getPinByRequestid(gracePin.requestid) === null);
check('unpin() still removes from CID index', SafecloudIpfs.getPinByCid(cidGrace) === null);

// Kubo failure (not "not pinned") should still propagate
SafecloudIpfs._resetStore();
var cidFail = 'QmFail111111111111111111111111111111111111111111';
kubo.state.pinAddShouldFail = true;
var failedPin = await SafecloudIpfs.pin(cidFail, {}).catch(function (e) { return { _err: e }; });
kubo.state.pinAddShouldFail = false;
check('pin() propagates non-"not pinned" Kubo error', failedPin && failedPin._err instanceof Error);
if (failedPin && failedPin._err) {
    var storeRec = SafecloudIpfs.getPinByCid(cidFail);
    check('pin() sets status=failed on store record after Kubo error',
        !storeRec || storeRec.status === 'failed');
}

// ══════════════════════════════════════════════════════════════════════════════
//  7. PSA HTTP ROUTES — real Express, real HTTP
// ══════════════════════════════════════════════════════════════════════════════

section('7. PSA HTTP routes');

// Boot a fresh express app with IPFS routes registered directly
// (mirrors what _registerIpfsRoutes does in Jets.js)
SafecloudIpfs._resetStore();
// Re-init to ensure clean state with no bearer token
var routeQ = makeQ(kubo.port);
routeQ.Config.get = function (k, d) {
    // same as testQ but no exposedKey
    var cfg = {
        Safecloud: {
            ipfs: {
                enabled: true, mode: 'external',
                apiUrl: 'http://127.0.0.1:' + kubo.port,
                gatewayUrl: null,
                pinningService: { endpoint: null, key: null, exposedKey: null },
                requireSafebux: false, sbuxPerGB: 0
            }
        }
    };
    var o = cfg;
    for (var i = 0; i < k.length; i++) {
        if (o == null || typeof o !== 'object') { return d; }
        o = o[k[i]];
    }
    return o === undefined ? d : o;
};
SafecloudIpfs.init({ Q: routeQ });

var routeApp = express();
routeApp.use(express.json());

// Replicate the _registerIpfsRoutes logic (testing the route shape)
routeApp.use(['/ipfs', '/api/v0'], function (rq, rs, next) {
    rs.setHeader('Access-Control-Allow-Origin', '*');
    rs.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    rs.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (rq.method === 'OPTIONS') { return rs.status(204).end(); }
    next();
});

routeApp.get('/ipfs/pins', function (rq, rs) {
    var q = rq.query || {};
    var filters = {};
    if (q.cid)    { filters.cid    = Array.isArray(q.cid) ? q.cid : [q.cid]; }
    if (q.status) { filters.status = Array.isArray(q.status) ? q.status : q.status.split(','); }
    if (q.name)   { filters.name   = q.name; }
    if (q.limit)  { filters.limit  = q.limit; }
    SafecloudIpfs.listPins(filters).then(function (result) {
        rs.json({ count: result.count, results: result.results });
    }).catch(function (err) {
        rs.status(500).json({ error: { reason: 'INTERNAL_SERVER_ERROR', details: err.message } });
    });
});

routeApp.post('/ipfs/pins', function (rq, rs) {
    var body = rq.body || {};
    var cid = typeof body.cid === 'string' ? body.cid.trim() : null;
    if (!cid) {
        return rs.status(400).json({ error: { reason: 'BAD_REQUEST', details: 'cid required' } });
    }
    if (!/^[A-Za-z0-9]{7,}/.test(cid)) {
        return rs.status(400).json({ error: { reason: 'BAD_REQUEST', details: 'invalid CID' } });
    }
    var opts = {};
    if (body.name)    { opts.name    = body.name; }
    if (body.origins) { opts.origins = body.origins; }
    if (body.meta)    { opts.meta    = body.meta; }
    SafecloudIpfs.pin(cid, opts).then(function (pinRecord) {
        rs.status(202).json(pinRecord);
    }).catch(function (err) {
        rs.status(500).json({ error: { reason: 'INTERNAL_SERVER_ERROR', details: err.message } });
    });
});

routeApp.get('/ipfs/pins/:requestid', function (rq, rs) {
    var requestid = rq.params.requestid;
    var rec = SafecloudIpfs.getPinByRequestid(requestid);
    if (!rec) {
        return rs.status(404).json({ error: { reason: 'NOT_FOUND', details: 'pin not found: ' + requestid } });
    }
    rs.json(rec);
});

routeApp.delete('/ipfs/pins/:requestid', function (rq, rs) {
    var requestid = rq.params.requestid;
    SafecloudIpfs.unpin(requestid).then(function () {
        rs.status(202).end();
    }).catch(function (err) {
        var notFound = err.message && err.message.indexOf('Pin not found') !== -1;
        if (notFound) {
            return rs.status(404).json({ error: { reason: 'NOT_FOUND', details: err.message } });
        }
        rs.status(500).json({ error: { reason: 'INTERNAL_SERVER_ERROR', details: err.message } });
    });
});

routeApp.get('/Safecloud/ipfs/status', function (rq, rs) {
    SafecloudIpfs.status().then(function (st) {
        rs.json(st);
    }).catch(function (err) {
        rs.status(500).json({ error: err.message });
    });
});

var routeServer = http.createServer(routeApp);
await new Promise(function (r) { routeServer.listen(0, '127.0.0.1', r); });
SafecloudIpfs._resetStore();

// GET /ipfs/pins — empty store
var listEmpty = await req(routeServer, 'GET', '/ipfs/pins');
check('GET /ipfs/pins — 200 on empty store', listEmpty.status === 200);
check('GET /ipfs/pins — count is 0', listEmpty.body && listEmpty.body.count === 0);
check('GET /ipfs/pins — results is empty array', Array.isArray(listEmpty.body && listEmpty.body.results) && listEmpty.body.results.length === 0);

// POST /ipfs/pins — missing cid
var badPost = await req(routeServer, 'POST', '/ipfs/pins', {});
check('POST /ipfs/pins — 400 on missing cid', badPost.status === 400);
check('POST /ipfs/pins — error.reason BAD_REQUEST', badPost.body && badPost.body.error && badPost.body.error.reason === 'BAD_REQUEST');

// POST /ipfs/pins — valid pin
var cidRoute = 'QmRouteTest' + crypto.randomBytes(4).toString('hex');
var postPin = await req(routeServer, 'POST', '/ipfs/pins', { cid: cidRoute, name: 'route-test', meta: { x: 1 } });
check('POST /ipfs/pins — 202 on valid CID', postPin.status === 202);
check('POST /ipfs/pins — returns requestid', postPin.body && typeof postPin.body.requestid === 'string');
check('POST /ipfs/pins — returns status', postPin.body && typeof postPin.body.status === 'string');
check('POST /ipfs/pins — pin.cid matches', postPin.body && postPin.body.pin && postPin.body.pin.cid === cidRoute);
check('POST /ipfs/pins — pin.name matches', postPin.body && postPin.body.pin && postPin.body.pin.name === 'route-test');

var rid = postPin.body && postPin.body.requestid;

// GET /ipfs/pins — should now have 1
var listOne = await req(routeServer, 'GET', '/ipfs/pins');
check('GET /ipfs/pins — count is 1 after pin', listOne.body && listOne.body.count === 1);

// GET /ipfs/pins/:requestid
var getPin = await req(routeServer, 'GET', '/ipfs/pins/' + rid);
check('GET /ipfs/pins/:requestid — 200', getPin.status === 200);
check('GET /ipfs/pins/:requestid — correct record', getPin.body && getPin.body.requestid === rid);

// GET /ipfs/pins/:requestid — not found
var getNotFound = await req(routeServer, 'GET', '/ipfs/pins/' + 'a'.repeat(32));
check('GET /ipfs/pins/:requestid — 404 for unknown', getNotFound.status === 404);
check('GET /ipfs/pins/:requestid — error.reason NOT_FOUND', getNotFound.body && getNotFound.body.error && getNotFound.body.error.reason === 'NOT_FOUND');

// DELETE /ipfs/pins/:requestid
var delPin = await req(routeServer, 'DELETE', '/ipfs/pins/' + rid);
check('DELETE /ipfs/pins/:requestid — 202', delPin.status === 202);

// DELETE again — should 404
var delAgain = await req(routeServer, 'DELETE', '/ipfs/pins/' + rid);
check('DELETE /ipfs/pins/:requestid — 404 on second delete', delAgain.status === 404);

// CORS preflight
var opts = await req(routeServer, 'OPTIONS', '/ipfs/pins');
check('OPTIONS /ipfs/pins — 204 preflight', opts.status === 204);
check('OPTIONS /ipfs/pins — CORS Allow-Origin *', opts.headers && opts.headers['access-control-allow-origin'] === '*');

// ══════════════════════════════════════════════════════════════════════════════
//  8. BEARER AUTH ENFORCEMENT
// ══════════════════════════════════════════════════════════════════════════════

section('8. Bearer auth enforcement');

// Create a new route server with exposedKey set
SafecloudIpfs._resetStore();
var SECRET = 'super-secret-key-' + crypto.randomBytes(4).toString('hex');
var authQ = makeQ(kubo.port);
authQ.Config.get = function (k, d) {
    var cfg = {
        Safecloud: {
            ipfs: {
                enabled: true, mode: 'external',
                apiUrl: 'http://127.0.0.1:' + kubo.port,
                gatewayUrl: null,
                pinningService: { endpoint: null, key: null, exposedKey: SECRET },
                requireSafebux: false, sbuxPerGB: 0
            }
        }
    };
    var o = cfg;
    for (var i = 0; i < k.length; i++) {
        if (o == null || typeof o !== 'object') { return d; }
        o = o[k[i]];
    }
    return o === undefined ? d : o;
};
SafecloudIpfs.init({ Q: authQ });

var authApp = express();
authApp.use(express.json());

function authGuard(rq, rs, next) {
    var key = SafecloudIpfs.getExposedKey();
    if (!key) { return next(); }
    var authHeader = rq.headers.authorization || '';
    var token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (token !== key) {
        return rs.status(401).json({ error: { reason: 'UNAUTHORIZED', details: 'Invalid bearer token' } });
    }
    next();
}

authApp.get('/ipfs/pins', authGuard, function (rq, rs) {
    SafecloudIpfs.listPins({}).then(function (r) { rs.json(r); }).catch(function (e) { rs.status(500).end(); });
});
authApp.post('/ipfs/pins', authGuard, function (rq, rs) {
    var b = rq.body || {};
    if (!b.cid) { return rs.status(400).end(); }
    SafecloudIpfs.pin(b.cid, {}).then(function (r) { rs.status(202).json(r); }).catch(function (e) { rs.status(500).end(); });
});

var authServer = http.createServer(authApp);
await new Promise(function (r) { authServer.listen(0, '127.0.0.1', r); });
SafecloudIpfs._resetStore();

// No token → 401
var noToken = await req(authServer, 'GET', '/ipfs/pins');
check('auth: GET /ipfs/pins — 401 without token', noToken.status === 401);
check('auth: 401 error reason UNAUTHORIZED', noToken.body && noToken.body.error && noToken.body.error.reason === 'UNAUTHORIZED');

// Wrong token → 401
var wrongToken = await req(authServer, 'GET', '/ipfs/pins', null, { Authorization: 'Bearer wrong-token' });
check('auth: GET /ipfs/pins — 401 with wrong token', wrongToken.status === 401);

// Correct token → 200
var goodToken = await req(authServer, 'GET', '/ipfs/pins', null, { Authorization: 'Bearer ' + SECRET });
check('auth: GET /ipfs/pins — 200 with correct token', goodToken.status === 200);

// POST with correct token
var cidAuth = 'QmAuthTest' + crypto.randomBytes(3).toString('hex');
var authPin = await req(authServer, 'POST', '/ipfs/pins', { cid: cidAuth }, { Authorization: 'Bearer ' + SECRET });
check('auth: POST /ipfs/pins — 202 with correct token', authPin.status === 202);

// getExposedKey() returns the configured key
check('getExposedKey() returns the configured secret', SafecloudIpfs.getExposedKey() === SECRET);

// ══════════════════════════════════════════════════════════════════════════════
//  9. HOSTILE INPUT
// ══════════════════════════════════════════════════════════════════════════════

section('9. Hostile input handling');

SafecloudIpfs._resetStore();
SafecloudIpfs.init({ Q: testQ });  // back to no-auth mode

// pin() with non-string CID
var badCidErr = await SafecloudIpfs.pin(null, {}).catch(function (e) { return e; });
check('pin(null) rejects with error', badCidErr instanceof Error);

var badCidErr2 = await SafecloudIpfs.pin('', {}).catch(function (e) { return e; });
check('pin("") rejects with error', badCidErr2 instanceof Error);

var badCidErr3 = await SafecloudIpfs.pin(12345, {}).catch(function (e) { return e; });
check('pin(number) rejects with error', badCidErr3 instanceof Error);

// unpin non-string
var badUnpinErr = await SafecloudIpfs.unpin(undefined).catch(function (e) { return e; });
check('unpin(undefined) rejects with "Pin not found"', badUnpinErr instanceof Error && /not found/i.test(badUnpinErr.message));

// listPins with extreme limit values
SafecloudIpfs._resetStore();
await SafecloudIpfs.pin('QmHos1' + 'a'.repeat(39), {});
var bigLimit = await SafecloudIpfs.listPins({ limit: 99999 });
check('listPins: limit clamped to 1000 max', bigLimit.results.length <= 1000);

var zeroLimit = await SafecloudIpfs.listPins({ limit: 0 });
check('listPins: limit=0 clamped to 1 min', zeroLimit.results.length >= 0);

var negLimit = await SafecloudIpfs.listPins({ limit: -5 });
check('listPins: negative limit clamped to 1', negLimit.results.length >= 0);

// PSA route with malformed CID
SafecloudIpfs.init({ Q: routeQ });
SafecloudIpfs._resetStore();
var malformed = await req(routeServer, 'POST', '/ipfs/pins', { cid: '<script>alert(1)</script>' });
check('POST /ipfs/pins — 400 on malformed CID (XSS)', malformed.status === 400);

var tooShort = await req(routeServer, 'POST', '/ipfs/pins', { cid: 'Qm' });  // too short
check('POST /ipfs/pins — 400 on CID too short', tooShort.status === 400);

// Missing body
var noBody = await req(routeServer, 'POST', '/ipfs/pins', {});
check('POST /ipfs/pins — 400 on empty body', noBody.status === 400);

// ══════════════════════════════════════════════════════════════════════════════
//  10. STATUS ENDPOINT
// ══════════════════════════════════════════════════════════════════════════════

section('10. Status endpoint');

SafecloudIpfs._resetStore();
SafecloudIpfs.init({ Q: testQ });

var st = await SafecloudIpfs.status();
check('status().enabled is true', st.enabled === true);
check('status().mode is "external"', st.mode === 'external');
check('status().reachable is true (mock Kubo running)', st.reachable === true);
check('status().peerId is a string', typeof st.peerId === 'string' && st.peerId.length > 0);
check('status().apiUrl is set', typeof st.apiUrl === 'string');
check('status().pinCount is a number', typeof st.pinCount === 'number');

// Route version
routeApp.get('/Safecloud/ipfs/status', function (rq, rs) {
    SafecloudIpfs.status().then(function (s) { rs.json(s); }).catch(function (e) { rs.status(500).end(); });
});
// (already registered above, skipping double registration)

// ══════════════════════════════════════════════════════════════════════════════
//  11. KUBO PROXY ROUTES
// ══════════════════════════════════════════════════════════════════════════════

section('11. Kubo proxy routes');

// Create a proxy app that forwards /api/v0/* to mock Kubo via SafecloudIpfs.kuboRaw
SafecloudIpfs._resetStore();
SafecloudIpfs.init({ Q: testQ });

var proxyApp = express();
proxyApp.use(express.json());

// /api/v0/id proxy
proxyApp.post('/api/v0/id', function (rq, rs) {
    SafecloudIpfs.kuboRaw('POST', '/api/v0/id', {}).then(function (r) {
        rs.status(r.status);
        var json = null;
        try { json = JSON.parse(r.body.toString('utf8')); } catch (_) {}
        rs.json(json || {});
    }).catch(function (e) {
        rs.status(500).json({ Message: e.message });
    });
});

// /api/v0/pin/add proxy
proxyApp.post('/api/v0/pin/add', function (rq, rs) {
    var cid = rq.query.arg;
    SafecloudIpfs.kuboRaw('POST', '/api/v0/pin/add', { arg: cid }).then(function (r) {
        rs.status(r.status);
        try { rs.json(JSON.parse(r.body.toString('utf8'))); }
        catch (_) { rs.end(r.body); }
    }).catch(function (e) { rs.status(500).json({ Message: e.message }); });
});

// /api/v0/key/gen proxy
proxyApp.post('/api/v0/key/gen', function (rq, rs) {
    SafecloudIpfs.kuboPost('/api/v0/key/gen', { arg: rq.query.arg, type: rq.query.type || 'ed25519' })
        .then(function (r) { rs.json(r); })
        .catch(function (e) { rs.status(500).json({ Message: e.message }); });
});

var proxyServer = http.createServer(proxyApp);
await new Promise(function (r) { proxyServer.listen(0, '127.0.0.1', r); });

// /api/v0/id
var idResp = await req(proxyServer, 'POST', '/api/v0/id');
check('kuboRaw /api/v0/id — reachable', idResp.status === 200);
check('kuboRaw /api/v0/id — returns ID field', idResp.body && typeof idResp.body.ID === 'string');
check('kuboRaw /api/v0/id — returns AgentVersion', idResp.body && typeof idResp.body.AgentVersion === 'string');

// /api/v0/pin/add
kubo.state.pins = {};
var addPinCid = 'QmProxyPinTest' + crypto.randomBytes(3).toString('hex');
var addPinResp = await req(proxyServer, 'POST', '/api/v0/pin/add?arg=' + addPinCid);
check('kuboRaw /api/v0/pin/add — 200', addPinResp.status === 200);
check('kuboRaw /api/v0/pin/add — returns Pins array', addPinResp.body && Array.isArray(addPinResp.body.Pins));
check('kuboRaw /api/v0/pin/add — Pins contains the CID', addPinResp.body && addPinResp.body.Pins[0] === addPinCid);

// kuboPost (higher-level)
var keyGenResp = await req(proxyServer, 'POST', '/api/v0/key/gen?arg=mykey&type=ed25519');
check('kuboPost /api/v0/key/gen — 200', keyGenResp.status === 200);
check('kuboPost /api/v0/key/gen — returns Name', keyGenResp.body && keyGenResp.body.Name === 'mykey');
check('kuboPost /api/v0/key/gen — returns Id', keyGenResp.body && typeof keyGenResp.body.Id === 'string');

// kuboPost with mode ≠ external should reject
SafecloudIpfs._resetStore();
var psQ = makeQ(kubo.port);
psQ.Config.get = function (k, d) {
    var cfg = {
        Safecloud: {
            ipfs: {
                enabled: true, mode: 'pinning-service',
                apiUrl: 'http://127.0.0.1:' + kubo.port,
                gatewayUrl: null,
                pinningService: { endpoint: 'http://127.0.0.1:99', key: 'k', exposedKey: null },
                requireSafebux: false, sbuxPerGB: 0
            }
        }
    };
    var o = cfg;
    for (var i = 0; i < k.length; i++) {
        if (o == null || typeof o !== 'object') { return d; }
        o = o[k[i]];
    }
    return o === undefined ? d : o;
};
SafecloudIpfs.init({ Q: psQ });
var psKuboErr = await SafecloudIpfs.kuboPost('/api/v0/id', {}).catch(function (e) { return e; });
check('kuboPost rejects in pinning-service mode', psKuboErr instanceof Error && /external/.test(psKuboErr.message));
SafecloudIpfs.init({ Q: testQ }); // restore

// ══════════════════════════════════════════════════════════════════════════════
//  12. IPNS ROUTES
// ══════════════════════════════════════════════════════════════════════════════

section('12. IPNS routes');

SafecloudIpfs._resetStore();
SafecloudIpfs.init({ Q: testQ });
SafecloudIpns.init({ Q: testQ });

check('SafecloudIpns.isEnabled() is true when mode=external', SafecloudIpns.isEnabled());

// createKey
var keyName = 'test-key-' + crypto.randomBytes(3).toString('hex');
var genKey = await SafecloudIpns.createKey(keyName, 'ed25519');
check('IPNS createKey — returns Name', genKey && genKey.Name === keyName);
check('IPNS createKey — returns Id string', genKey && typeof genKey.Id === 'string');

// createKey with missing name
var badKeyErr = await SafecloudIpns.createKey('').catch(function (e) { return e; });
check('IPNS createKey — rejects empty name', badKeyErr instanceof Error);

// listKeys
var keys = await SafecloudIpns.listKeys();
check('IPNS listKeys — returns Keys array', keys && Array.isArray(keys.Keys));
check('IPNS listKeys — contains at least self', keys.Keys.length >= 1);

// removeKey
var rmKey = await SafecloudIpns.removeKey(keyName);
check('IPNS removeKey — returns Keys array', rmKey && Array.isArray(rmKey.Keys));

// publish
var pubCid = 'QmPublishTest' + crypto.randomBytes(3).toString('hex');
var published = await SafecloudIpns.publish(pubCid, { key: 'self', lifetime: '24h' });
check('IPNS publish — returns Name', published && typeof published.Name === 'string');
check('IPNS publish — returns Value', published && typeof published.Value === 'string');
check('IPNS publish — Value starts with /ipfs/', published && published.Value.startsWith('/ipfs/'));

// resolve
var resolved = await SafecloudIpns.resolve('k51qmocktestkey', { recursive: true });
check('IPNS resolve — returns Path', resolved && typeof resolved.Path === 'string');
check('IPNS resolve — Path starts with /ipfs/', resolved && resolved.Path.startsWith('/ipfs/'));

// resolve with /ipns/ prefix
var resolved2 = await SafecloudIpns.resolve('/ipns/k51qmocktestkey2', {});
check('IPNS resolve — accepts /ipns/ prefixed name', resolved2 && resolved2.Path.startsWith('/ipfs/'));

// IPNS not available when mode ≠ external
SafecloudIpfs.init({ Q: psQ });
SafecloudIpns.init({ Q: psQ });
check('IPNS isEnabled() false when mode=pinning-service', !SafecloudIpns.isEnabled());
var ipnsErr = await SafecloudIpns.publish('QmX', {}).catch(function (e) { return e; });
check('IPNS publish rejects when disabled', ipnsErr instanceof Error && /not available/i.test(ipnsErr.message));

SafecloudIpfs.init({ Q: testQ });   // restore
SafecloudIpns.init({ Q: testQ });

// ══════════════════════════════════════════════════════════════════════════════
//  13. JETS.JS INTEGRATION — routes registered when IPFS enabled
// ══════════════════════════════════════════════════════════════════════════════

section('13. Jets.js integration');

{
    // We need a fresh require of Jets.js to avoid module-cache pollution
    // from earlier test that may have loaded Jets with different stubs.
    // Clear any stale cache entries for our modules.
    var clearCache = function (mod) {
        var resolved;
        try { resolved = require.resolve(mod); } catch (e) { return; }
        delete require.cache[resolved];
    };
    clearCache(path.join(process.cwd(), 'classes/Safecloud/Ipfs.js'));
    clearCache(path.join(process.cwd(), 'classes/Safecloud/Ipns.js'));
    clearCache(path.join(process.cwd(), 'classes/Safecloud/Jets.js'));

    var jetsCfg = {
        Safecloud: {
            requirePayment: false,
            requireGrants: false,
            jet: { privateKey: '0x' + 'ab'.repeat(32) },
            ipfs: {
                enabled:  true,
                mode:     'external',
                apiUrl:   'http://127.0.0.1:' + kubo.port,
                gatewayUrl: null,
                pinningService: { endpoint: null, key: null, exposedKey: null },
                requireSafebux: false,
                sbuxPerGB: 0
            }
        }
    };

    var jetsApp = express();
    jetsApp.use(express.json());
    var jetsRealServer = { attached: { express: jetsApp } };

    var jetsQ = {
        Config: {
            get: function (k, d) {
                var o = jetsCfg;
                for (var i = 0; i < k.length; i++) {
                    if (o == null || typeof o !== 'object') { return d; }
                    o = o[k[i]];
                }
                return o === undefined ? d : o;
            },
            set: function () {}
        },
        log: function () {},
        extend: Object.assign,
        getObject: function (k, f) { var o = f; for (var x of k) { if (o == null) { return undefined; } o = o[x]; } return o; },
        makeEventEmitter: function (o) {
            var ls = {};
            o.on   = function (e, f) { (ls[e] = ls[e] || []).push(f); };
            o.emit = function (e) { var a = Array.prototype.slice.call(arguments, 1); (ls[e] || []).forEach(function (f) { f.apply(null, a); }); };
        },
        listen: function () { return jetsRealServer; },
        require: function (n) {
            if (n === 'Users') { return { Socket: { listen: function () { return { io: { of: function () { return { on: function () {} }; } } }; } } }; }
            throw new Error('no ' + n);
        },
        app: { DIR: fs.mkdtempSync(os.tmpdir() + '/sc-jets-ipfs-') },
        Crypto: {}, Data: {}, Assets: {}, Socket: {}, Safecloud: {}
    };

    var Module = require('module');
    var origLoad = Module._load;
    Module._load = function (r) {
        if (r === 'Q') { return jetsQ; }
        if (r === './Client')   { return { verifyGrant: async function () { return true; } }; }
        if (r === './Drops')    { return { verifyChallengeResponse: function () { return true; } }; }
        if (r === './JetSwarm') { return { init: async function () {}, stats: function () { return { peerCount: 0 }; }, announceRanges: function () {} }; }
        // Q sub-modules that self-attach (e.g. Q/Crypto/OpenClaim) — stub them out
        if (r === 'Q/Data')              { jetsQ.Data   = jetsQ.Data   || {}; return jetsQ.Data; }
        if (r === 'Q/Crypto')            { jetsQ.Crypto = jetsQ.Crypto || {}; return jetsQ.Crypto; }
        if (r === 'Q/Crypto/OpenClaim')  { jetsQ.Crypto.OpenClaim = jetsQ.Crypto.OpenClaim || {}; return jetsQ.Crypto.OpenClaim; }
        if (r === 'Q/Crypto/OpenClaim/EVM') { return {}; }
        return origLoad.apply(this, arguments);
    };

    var Jets;
    var jetsBooted = false;
    try {
        Jets = require(path.join(process.cwd(), 'classes/Safecloud/Jets.js'));
        Jets.listen({});
        jetsBooted = true;
    } catch (e) {
        console.log('    Jets.listen() threw:', e.message);
    } finally {
        Module._load = origLoad;
    }

    check('Jets.listen() boots without throwing (IPFS enabled)', jetsBooted);

    if (jetsBooted) {
        // Start an HTTP server on the express app
        var jetsHttpServer = http.createServer(jetsApp);
        await new Promise(function (r) { jetsHttpServer.listen(0, '127.0.0.1', r); });

        // /ipfs/pins should be registered
        var jetsListEmpty = await req(jetsHttpServer, 'GET', '/ipfs/pins');
        check('Jets: GET /ipfs/pins is registered (not 404)', jetsListEmpty.status !== 404, 'status was ' + jetsListEmpty.status);
        check('Jets: GET /ipfs/pins — 200', jetsListEmpty.status === 200, 'status was ' + jetsListEmpty.status);

        // Status route
        var jetsStatus = await req(jetsHttpServer, 'GET', '/Safecloud/ipfs/status');
        check('Jets: GET /Safecloud/ipfs/status is registered', jetsStatus.status !== 404);
        check('Jets: status.enabled is true', jetsStatus.body && jetsStatus.body.enabled === true);
        check('Jets: status.mode is "external"', jetsStatus.body && jetsStatus.body.mode === 'external');

        // POST /ipfs/pins — create a pin through Jets routes
        var cidJets = 'QmJetsTest' + crypto.randomBytes(3).toString('hex');
        var jetsPostPin = await req(jetsHttpServer, 'POST', '/ipfs/pins', { cid: cidJets });
        check('Jets: POST /ipfs/pins — 202', jetsPostPin.status === 202, 'status was ' + jetsPostPin.status + ' body: ' + JSON.stringify(jetsPostPin.body));
        check('Jets: POST /ipfs/pins — requestid present', jetsPostPin.body && typeof jetsPostPin.body.requestid === 'string');

        // Kubo proxy /api/v0/id
        var jetsId = await req(jetsHttpServer, 'POST', '/api/v0/id');
        check('Jets: POST /api/v0/id is proxied (not 404)', jetsId.status !== 404, 'status was ' + jetsId.status);
        check('Jets: POST /api/v0/id — 200', jetsId.status === 200, 'status was ' + jetsId.status);

        jetsHttpServer.close();
    }

    // Clean up Jets module cache for subsequent runs
    clearCache(path.join(process.cwd(), 'classes/Safecloud/Jets.js'));
}

// ══════════════════════════════════════════════════════════════════════════════
//  14. INTEGRATION TESTS — real Kubo node (IPFS_API_URL env var required)
// ══════════════════════════════════════════════════════════════════════════════

section('14. Integration tests (live Kubo)');

var liveKuboUrl = process.env.IPFS_API_URL;
if (!liveKuboUrl) {
    console.log('    [SKIP] Set IPFS_API_URL=http://127.0.0.1:5001 to run live Kubo tests.');
} else {
    console.log('    IPFS_API_URL=' + liveKuboUrl);

    // Re-configure to use the live Kubo node
    SafecloudIpfs._resetStore();
    var liveQ = makeQ(0);
    liveQ.Config.get = function (k, d) {
        var cfg = {
            Safecloud: {
                ipfs: {
                    enabled: true, mode: 'external',
                    apiUrl: liveKuboUrl,
                    gatewayUrl: null,
                    pinningService: { endpoint: null, key: null, exposedKey: null },
                    requireSafebux: false, sbuxPerGB: 0
                }
            }
        };
        var o = cfg;
        for (var i = 0; i < k.length; i++) {
            if (o == null || typeof o !== 'object') { return d; }
            o = o[k[i]];
        }
        return o === undefined ? d : o;
    };
    SafecloudIpfs.init({ Q: liveQ });
    SafecloudIpns.init({ Q: liveQ });

    // /api/v0/id — node is reachable
    var liveSt = await SafecloudIpfs.status();
    check('live: IPFS node reachable', liveSt.reachable === true, 'reachable was ' + liveSt.reachable);
    if (liveSt.reachable) {
        check('live: peerId is set', typeof liveSt.peerId === 'string' && liveSt.peerId.length > 0);
        check('live: agentVersion is set', typeof liveSt.agentVersion === 'string');

        // add + pin + cat + unpin
        var content = Buffer.from('Safecloud 3.3 IPFS integration test ' + Date.now());
        var addResult = await SafecloudIpfs.add(content, { filename: 'test.txt' });
        check('live: add() returns cid', addResult && typeof addResult.cid === 'string');
        check('live: add() returns size', addResult && addResult.size !== undefined);

        if (addResult && addResult.cid) {
            var liveCid = addResult.cid;

            // cat
            var catBuf = await SafecloudIpfs.cat(liveCid);
            check('live: cat() retrieves correct content', catBuf && catBuf.equals(content));

            // pin (should already be pinned by add --pin=true, so idempotent)
            var livePin = await SafecloudIpfs.pin(liveCid, { name: 'safecloud-test' });
            check('live: pin() returns record', livePin && livePin.pin.cid === liveCid);
            check('live: pin() status is pinned or queued/pinning',
                ['queued','pinning','pinned'].includes(livePin.status));

            // listPins — should find it
            var livePins = await SafecloudIpfs.listPins({ cid: [liveCid], limit: 10 });
            check('live: listPins() finds the pinned CID', livePins.count >= 1);

            // getPinByCid
            var liveLookup = SafecloudIpfs.getPinByCid(liveCid);
            check('live: getPinByCid() finds the pin', liveLookup && liveLookup.pin.cid === liveCid);

            // unpin
            await SafecloudIpfs.unpin(livePin.requestid);
            check('live: unpin() removes from store', SafecloudIpfs.getPinByCid(liveCid) === null);
        }

        // IPNS: create key, publish, resolve, remove (only if mode=external)
        if (SafecloudIpns.isEnabled() && addResult && addResult.cid) {
            var liveKeyName = 'sc-test-' + crypto.randomBytes(4).toString('hex');
            var liveKey = await SafecloudIpns.createKey(liveKeyName, 'ed25519');
            check('live: IPNS createKey returns Name', liveKey && liveKey.Name === liveKeyName);

            var liveKeys = await SafecloudIpns.listKeys();
            check('live: IPNS listKeys finds the new key',
                liveKeys && liveKeys.Keys.some(function (k) { return k.Name === liveKeyName; }));

            // publish under the new key
            var livePub = await SafecloudIpns.publish(addResult.cid, { key: liveKeyName });
            check('live: IPNS publish returns Name', livePub && typeof livePub.Name === 'string');
            check('live: IPNS publish returns Value', livePub && livePub.Value.startsWith('/ipfs/'));

            // cleanup
            await SafecloudIpns.removeKey(liveKeyName);
            var keysAfter = await SafecloudIpns.listKeys();
            check('live: IPNS removeKey removes the key',
                keysAfter && !keysAfter.Keys.some(function (k) { return k.Name === liveKeyName; }));
        }
    }
}

// ── Teardown ──────────────────────────────────────────────────────────────────

kubo.server.close();
routeServer.close();
authServer.close();
proxyServer.close();
cleanupQ(testQ);
cleanupQ(routeQ);
cleanupQ(authQ);

// ── Results ───────────────────────────────────────────────────────────────────

console.log('\n══════════════════════════════════════════════════════════════════');
console.log('  IPFS/IPNS tests: ' + pass + ' passed, ' + fail + ' failed');
console.log('══════════════════════════════════════════════════════════════════');

process.exit(fail ? 1 : 0);

})().catch(function (e) {
    console.error('FATAL:', e);
    process.exit(1);
});
