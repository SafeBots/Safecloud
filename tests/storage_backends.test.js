'use strict';

/**
 * Safecloud 3.5 — Storage Backend Tests
 *
 * Sections:
 *   1  Filesystem — init validation
 *   2  Filesystem — put / get / has / delete
 *   3  Filesystem — shard path layout
 *   4  Filesystem — list with prefix
 *   5  Filesystem — edge cases (non-existent get, idempotent delete)
 *   6  Filesystem — uninitialized errors
 *   7  WebDAV mock — init validation
 *   8  WebDAV mock — put / get / has / delete
 *   9  WebDAV mock — list
 *  10  WebDAV mock — 404 tolerance
 *  11  WebDAV mock — uninitialized errors
 *  12  Arweave integration (ARWEAVE_KEY + ARWEAVE_KEYFILE required — skip otherwise)
 *  13  Filecoin integration (WEB3_STORAGE_KEY required — skip otherwise)
 *  14  Rclone integration (RCLONE_REMOTE required — skip otherwise)
 */

var Module = require('module');
var os     = require('os');
var fs     = require('fs');
var path   = require('path');
var crypto = require('crypto');

// ------------------------------------------------------------------ //
//  Paths
// ------------------------------------------------------------------ //

var PLUGIN_ROOT      = path.join(__dirname, '..');
var Q_PATH           = path.join(PLUGIN_ROOT, 'Q');
var FILESYSTEM_PATH  = path.join(PLUGIN_ROOT, 'classes/Safecloud/Storage/Filesystem');
var WEBDAV_PATH      = path.join(PLUGIN_ROOT, 'classes/Safecloud/Storage/Webdav');
var ARWEAVE_PATH     = path.join(PLUGIN_ROOT, 'classes/Safecloud/Storage/Arweave');
var FILECOIN_PATH    = path.join(PLUGIN_ROOT, 'classes/Safecloud/Storage/Filecoin');
var RCLONE_PATH      = path.join(PLUGIN_ROOT, 'classes/Safecloud/Storage/Rclone');

// ------------------------------------------------------------------ //
//  Test helpers
// ------------------------------------------------------------------ //

var pass = 0;
var fail = 0;
var currentSection = '';

function section(title) {
    currentSection = title;
    console.log('\n--- ' + title + ' ---');
}

function check(num, condition, desc) {
    var label = '[' + currentSection + '] ' + num + ': ' + desc;
    if (condition) {
        pass++;
        console.log('  PASS ' + num + ': ' + desc);
    } else {
        fail++;
        console.error('  FAIL ' + num + ': ' + desc);
    }
}

function randCid(prefix) {
    prefix = prefix || '';
    return prefix + crypto.randomBytes(16).toString('hex');
}

function randBuf(size) {
    return crypto.randomBytes(size || 64);
}

// ------------------------------------------------------------------ //
//  Q stub (common to all backends)
// ------------------------------------------------------------------ //

var stubQ = {
    Config: {
        get: function (k, d) { return d; },
        set: function () {}
    },
    Data: {},
    log: function () {},
    Crypto: { OpenClaim: { EVM: {} } }
};

// ------------------------------------------------------------------ //
//  WebDAV mock
// ------------------------------------------------------------------ //

function buildWebdavMock() {
    var store = {};  // { remotePath: Buffer }
    var dirs  = {};  // { remotePath: true }

    function MockClient(url, opts) {
        this._url  = url;
        this._opts = opts;
    }

    MockClient.prototype.createDirectory = function (dirPath) {
        dirs[dirPath] = true;
        return Promise.resolve();
    };

    MockClient.prototype.putFileContents = function (filePath, data) {
        store[filePath] = Buffer.isBuffer(data) ? data : Buffer.from(data);
        return Promise.resolve(true);
    };

    MockClient.prototype.getFileContents = function (filePath) {
        if (!Object.prototype.hasOwnProperty.call(store, filePath)) {
            var err = new Error('Not Found');
            err.status = 404;
            return Promise.reject(err);
        }
        return Promise.resolve(Buffer.from(store[filePath]));
    };

    MockClient.prototype.exists = function (filePath) {
        return Promise.resolve(
            Object.prototype.hasOwnProperty.call(store, filePath)
        );
    };

    MockClient.prototype.deleteFile = function (filePath) {
        delete store[filePath];
        return Promise.resolve();
    };

    MockClient.prototype.getDirectoryContents = function (dirPath) {
        var results = [];
        Object.keys(store).forEach(function (p) {
            // Return items directly under dirPath
            var rel = p.slice(dirPath.length);
            if (rel.startsWith('/') && rel.indexOf('/', 1) === -1) {
                // Direct child file
                results.push({
                    type: 'file',
                    filename: p,
                    basename: path.basename(p)
                });
            }
        });
        Object.keys(dirs).forEach(function (d) {
            var rel = d.slice(dirPath.length);
            if (rel.startsWith('/') && rel.indexOf('/', 1) === -1) {
                results.push({
                    type: 'directory',
                    filename: d,
                    basename: path.basename(d)
                });
            }
        });
        return Promise.resolve(results);
    };

    function createClient(url, opts) {
        return new MockClient(url, opts);
    }

    function resetStore() {
        store = {};
        dirs  = {};
    }

    return {
        module: { createClient: createClient },
        reset:  resetStore,
        store:  store
    };
}

// ------------------------------------------------------------------ //
//  Module._load intercept
//  Stays active throughout mock sections; only real-backend sections
//  bypass it per-module.
// ------------------------------------------------------------------ //

var mockWebdav    = buildWebdavMock();
var useMockWebdav = true;
var origLoad      = Module._load;

Module._load = function (r, parent, isMain) {
    if (r === 'webdav' && useMockWebdav) { return mockWebdav.module; }
    if (r === Q_PATH) { return stubQ; }
    return origLoad.call(this, r, parent, isMain);
};

// Require backend modules while interceptor is active.
var FilesystemStorage = require(FILESYSTEM_PATH);
var WebdavStorage     = require(WEBDAV_PATH);

// ------------------------------------------------------------------ //
//  Main async IIFE
// ------------------------------------------------------------------ //

(async function main() {

    // ============================================================== //
    //  SECTION 1 — Filesystem init validation
    // ============================================================== //

    section('Filesystem init validation');

    // Missing storageDir
    try {
        await FilesystemStorage.init({});
        check(1, false, 'should throw on missing storageDir');
    } catch (e) {
        check(1, e.message.indexOf('storageDir') !== -1, 'throws on missing storageDir');
    }

    // null config
    try {
        await FilesystemStorage.init(null);
        check(2, false, 'should throw on null config');
    } catch (e) {
        check(2, e.message.indexOf('storageDir') !== -1, 'throws on null config');
    }

    // ============================================================== //
    //  SECTION 2 — Filesystem put / get / has / delete
    // ============================================================== //

    section('Filesystem put / get / has / delete');

    FilesystemStorage._reset();
    var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-fs-test-'));

    await FilesystemStorage.init({ storageDir: tmpDir });
    check(3, FilesystemStorage._ready, 'init sets _ready');

    var cid1 = randCid('ab');
    var buf1 = randBuf(128);

    // put
    await FilesystemStorage.put(cid1, buf1);
    check(4, true, 'put resolves without error');

    // get — round-trip
    var got = await FilesystemStorage.get(cid1);
    check(5, Buffer.isBuffer(got), 'get returns Buffer');
    check(6, got.equals(buf1), 'get returns correct data');

    // has → true
    var h = await FilesystemStorage.has(cid1);
    check(7, h === true, 'has returns true after put');

    // delete
    await FilesystemStorage.delete(cid1);
    var gone = await FilesystemStorage.get(cid1);
    check(8, gone === null, 'get returns null after delete');

    var h2 = await FilesystemStorage.has(cid1);
    check(9, h2 === false, 'has returns false after delete');

    // ============================================================== //
    //  SECTION 3 — Filesystem shard path layout
    // ============================================================== //

    section('Filesystem shard path layout');

    var cid2 = 'deadbeef1234567890';
    var buf2 = randBuf(32);
    await FilesystemStorage.put(cid2, buf2);

    var expectedDir  = path.join(tmpDir, 'de');
    var expectedFile = path.join(expectedDir, cid2 + '.bin');

    check(10, fs.existsSync(expectedDir), 'shard directory created (cid[0..1])');
    check(11, fs.existsSync(expectedFile), 'chunk file stored at correct shard path');

    var rawOnDisk = fs.readFileSync(expectedFile);
    check(12, rawOnDisk.equals(buf2), 'bytes on disk match what was put');

    // Short cid (< 2 chars) falls back to __
    var cidShort = 'x';
    var bufShort = randBuf(8);
    await FilesystemStorage.put(cidShort, bufShort);
    var shortDir = path.join(tmpDir, '__');
    check(13, fs.existsSync(shortDir), 'short CID uses __ shard dir');

    await FilesystemStorage.delete(cidShort);

    // ============================================================== //
    //  SECTION 4 — Filesystem list with prefix
    // ============================================================== //

    section('Filesystem list with prefix');

    // Store several CIDs with varied prefixes
    var cids = ['aa' + randCid(), 'ab' + randCid(), 'ab' + randCid(), 'bc' + randCid()];
    for (var i = 0; i < cids.length; i++) {
        await FilesystemStorage.put(cids[i], randBuf(16));
    }

    var listAll  = await FilesystemStorage.list('');
    var listAb   = await FilesystemStorage.list('ab');
    var listBc   = await FilesystemStorage.list('bc');
    var listNone = await FilesystemStorage.list('zz');

    // cid2 ('deadbeef…') is still present; cids[0-3] + cid2 = at least 5
    check(14, listAll.length >= 5, 'list() returns all stored CIDs');
    check(15, listAb.length === 2, 'list("ab") returns exactly 2 CIDs');
    check(16, listBc.length === 1, 'list("bc") returns exactly 1 CID');
    check(17, listNone.length === 0, 'list("zz") returns empty array');

    // All returned CIDs must start with the requested prefix
    check(18, listAb.every(function (c) { return c.startsWith('ab'); }),
        'all list("ab") results start with "ab"');

    // ============================================================== //
    //  SECTION 5 — Filesystem edge cases
    // ============================================================== //

    section('Filesystem edge cases');

    // get non-existent → null
    var missingCid = 'ffff' + randCid();
    var missingResult = await FilesystemStorage.get(missingCid);
    check(19, missingResult === null, 'get on missing CID returns null');

    // delete non-existent → no throw
    try {
        await FilesystemStorage.delete(missingCid);
        check(20, true, 'delete on missing CID does not throw');
    } catch (e) {
        check(20, false, 'delete on missing CID threw: ' + e.message);
    }

    // has non-existent → false
    var hasMissing = await FilesystemStorage.has(missingCid);
    check(21, hasMissing === false, 'has on missing CID returns false');

    // list on empty dir
    var emptyTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-fs-empty-'));
    FilesystemStorage._reset();
    await FilesystemStorage.init({ storageDir: emptyTmpDir });
    var emptyList = await FilesystemStorage.list('');
    check(22, Array.isArray(emptyList) && emptyList.length === 0,
        'list on empty store returns empty array');

    // put creates storageDir if not yet present
    FilesystemStorage._reset();
    var newDir = path.join(os.tmpdir(), 'sc-fs-new-' + Date.now());
    await FilesystemStorage.init({ storageDir: newDir });
    check(23, fs.existsSync(newDir), 'init creates storageDir when missing');

    // ============================================================== //
    //  SECTION 6 — Filesystem uninitialized errors
    // ============================================================== //

    section('Filesystem uninitialized errors');

    FilesystemStorage._reset();

    var unInitChecks = [
        ['put',    FilesystemStorage.put.bind(FilesystemStorage, 'x', Buffer.from(''))],
        ['get',    FilesystemStorage.get.bind(FilesystemStorage, 'x')],
        ['has',    FilesystemStorage.has.bind(FilesystemStorage, 'x')],
        ['delete', FilesystemStorage.delete.bind(FilesystemStorage, 'x')],
        ['list',   FilesystemStorage.list.bind(FilesystemStorage, '')]
    ];

    var checkNum = 24;
    for (var ui = 0; ui < unInitChecks.length; ui++) {
        var op = unInitChecks[ui][0];
        var fn = unInitChecks[ui][1];
        try {
            await fn();
            check(checkNum, false, op + ' before init should throw');
        } catch (e) {
            check(checkNum, e.message.indexOf('not initialised') !== -1,
                op + ' before init throws "not initialised"');
        }
        checkNum++;
    }
    // checkNum is now 29

    // ============================================================== //
    //  SECTION 7 — WebDAV mock init validation
    // ============================================================== //

    section('WebDAV mock init validation');

    WebdavStorage._reset();
    mockWebdav.reset();

    // missing url
    try {
        await WebdavStorage.init({ username: 'u', password: 'p' });
        check(29, false, 'should throw on missing url');
    } catch (e) {
        check(29, e.message.indexOf('url') !== -1, 'throws on missing url');
    }

    // missing username
    try {
        await WebdavStorage.init({ url: 'http://x', password: 'p' });
        check(30, false, 'should throw on missing username');
    } catch (e) {
        check(30, e.message.indexOf('username') !== -1, 'throws on missing username');
    }

    // missing password
    try {
        await WebdavStorage.init({ url: 'http://x', username: 'u' });
        check(31, false, 'should throw on missing password');
    } catch (e) {
        check(31, e.message.indexOf('password') !== -1, 'throws on missing password');
    }

    // valid init
    await WebdavStorage.init({
        url:      'https://dav.example.com',
        username: 'user',
        password: 'pass',
        basePath: '/sc-test'
    });
    check(32, WebdavStorage._ready, 'WebDAV init sets _ready');
    check(33, WebdavStorage._basePath === '/sc-test', 'init stores basePath');

    // ============================================================== //
    //  SECTION 8 — WebDAV mock put / get / has / delete
    // ============================================================== //

    section('WebDAV mock put / get / has / delete');

    var wcid1 = 'ab' + randCid();
    var wbuf1 = randBuf(64);

    // put
    await WebdavStorage.put(wcid1, wbuf1);
    check(34, true, 'put resolves');

    // get — round-trip
    var wgot = await WebdavStorage.get(wcid1);
    check(35, Buffer.isBuffer(wgot), 'get returns Buffer');
    check(36, wgot.equals(wbuf1), 'get returns correct data');

    // has → true
    var wh1 = await WebdavStorage.has(wcid1);
    check(37, wh1 === true, 'has returns true after put');

    // delete
    await WebdavStorage.delete(wcid1);

    var wgone = await WebdavStorage.get(wcid1);
    check(38, wgone === null, 'get returns null after delete');

    var wh2 = await WebdavStorage.has(wcid1);
    check(39, wh2 === false, 'has returns false after delete');

    // ============================================================== //
    //  SECTION 9 — WebDAV mock list
    // ============================================================== //

    section('WebDAV mock list');

    WebdavStorage._reset();
    mockWebdav.reset();

    await WebdavStorage.init({
        url: 'https://dav.example.com', username: 'u', password: 'p',
        basePath: '/safecloud'
    });

    var wCids = ['aa' + randCid(), 'ab' + randCid(), 'cd' + randCid()];
    for (var wi = 0; wi < wCids.length; wi++) {
        await WebdavStorage.put(wCids[wi], randBuf(16));
    }

    var wListAll = await WebdavStorage.list('');
    var wListAa  = await WebdavStorage.list('aa');
    var wListAb  = await WebdavStorage.list('ab');
    var wListZz  = await WebdavStorage.list('zz');

    check(40, wListAll.length >= 3, 'list() returns all stored CIDs');
    check(41, wListAa.length === 1, 'list("aa") returns 1 CID');
    check(42, wListAb.length === 1, 'list("ab") returns 1 CID');
    check(43, wListZz.length === 0, 'list("zz") returns empty');
    check(44, wListAb[0] === wCids[1], 'list("ab") returns the right CID');

    // ============================================================== //
    //  SECTION 10 — WebDAV 404 tolerance
    // ============================================================== //

    section('WebDAV 404 tolerance');

    var missingWcid = 'ff' + randCid();

    // get missing → null (not a throw)
    var wmissing = await WebdavStorage.get(missingWcid);
    check(45, wmissing === null, 'get on missing key returns null');

    // has missing → false
    var whasM = await WebdavStorage.has(missingWcid);
    check(46, whasM === false, 'has on missing key returns false');

    // delete missing → no throw
    try {
        await WebdavStorage.delete(missingWcid);
        check(47, true, 'delete on missing key does not throw');
    } catch (e) {
        check(47, false, 'delete on missing key threw: ' + e.message);
    }

    // ============================================================== //
    //  SECTION 11 — WebDAV uninitialized errors
    // ============================================================== //

    section('WebDAV uninitialized errors');

    WebdavStorage._reset();

    var wUnInitChecks = [
        ['put',    WebdavStorage.put.bind(WebdavStorage, 'x', Buffer.from(''))],
        ['get',    WebdavStorage.get.bind(WebdavStorage, 'x')],
        ['has',    WebdavStorage.has.bind(WebdavStorage, 'x')],
        ['delete', WebdavStorage.delete.bind(WebdavStorage, 'x')],
        ['list',   WebdavStorage.list.bind(WebdavStorage, '')]
    ];

    var wCheckNum = 48;
    for (var wui = 0; wui < wUnInitChecks.length; wui++) {
        var wop = wUnInitChecks[wui][0];
        var wfn = wUnInitChecks[wui][1];
        try {
            await wfn();
            check(wCheckNum, false, wop + ' before init should throw');
        } catch (e) {
            check(wCheckNum, e.message.indexOf('not initialised') !== -1,
                wop + ' before init throws "not initialised"');
        }
        wCheckNum++;
    }
    // wCheckNum is now 53

    // ============================================================== //
    //  SECTION 12 — Arweave integration (gated)
    // ============================================================== //

    section('Arweave integration');

    var arweaveKeyfile = process.env.ARWEAVE_KEYFILE;

    if (!arweaveKeyfile) {
        console.log('  SKIP: set ARWEAVE_KEYFILE env var to run live Arweave tests');
        check(53, true, 'Arweave integration skipped (ARWEAVE_KEYFILE not set)');
    } else {
        useMockWebdav = false;
        Module._load  = origLoad;
        delete require.cache[require.resolve(ARWEAVE_PATH)];
        var RealArweave = require(ARWEAVE_PATH);

        var arHost     = process.env.ARWEAVE_HOST     || 'arweave.net';
        var arProtocol = process.env.ARWEAVE_PROTOCOL || 'https';
        var arPort     = parseInt(process.env.ARWEAVE_PORT || '443', 10);

        try {
            await RealArweave.init({
                keyfile:  arweaveKeyfile,
                host:     arHost,
                protocol: arProtocol,
                port:     arPort
            });
            check(53, RealArweave._ready, 'Arweave init with keyfile succeeds');

            var arCid = 'artest-' + Date.now().toString(16);
            var arBuf = Buffer.from('safecloud-arweave-test-' + arCid);

            await RealArweave.put(arCid, arBuf);
            check(54, true, 'Arweave put completes without error');

            // NOTE: Arweave transactions take ~2 minutes to confirm.
            // We skip immediate get/has checks in CI.
            console.log('  INFO: transaction submitted; check in ~2min that it is mined.');

            var arList = await RealArweave.list('artest-');
            check(55, Array.isArray(arList), 'Arweave list returns array');

            // delete is a no-op
            await RealArweave.delete(arCid);
            check(56, true, 'Arweave delete is a no-op (resolves)');

        } catch (e) {
            console.error('  ERROR: ' + e.message);
            check(53, false, 'Arweave integration error: ' + e.message);
        }

        RealArweave._reset();
        // Restore interceptor for subsequent sections
        useMockWebdav = true;
        Module._load  = function (r, parent, isMain) {
            if (r === 'webdav' && useMockWebdav) { return mockWebdav.module; }
            if (r === Q_PATH) { return stubQ; }
            return origLoad.call(this, r, parent, isMain);
        };
    }

    // ============================================================== //
    //  SECTION 13 — Filecoin integration (gated)
    // ============================================================== //

    section('Filecoin integration');

    var w3Key = process.env.WEB3_STORAGE_KEY;

    if (!w3Key) {
        console.log('  SKIP: set WEB3_STORAGE_KEY env var to run live Filecoin tests');
        check(57, true, 'Filecoin integration skipped (WEB3_STORAGE_KEY not set)');
    } else {
        var FilecoinStorage2 = require(FILECOIN_PATH);
        var fcTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-fc-test-'));

        try {
            await FilecoinStorage2.init({
                endpoint:   process.env.WEB3_STORAGE_ENDPOINT || 'https://api.web3.storage',
                gatewayUrl: process.env.WEB3_STORAGE_GATEWAY  || 'https://w3s.link/ipfs',
                key:        w3Key,
                indexDir:   fcTmpDir
            });
            check(57, FilecoinStorage2._ready, 'Filecoin init succeeds');

            var fcCid = 'fctest-' + Date.now().toString(16);
            var fcBuf = Buffer.from('safecloud-filecoin-test-' + fcCid);

            await FilecoinStorage2.put(fcCid, fcBuf);
            check(58, true, 'Filecoin put completes without error');

            var fcHas = await FilecoinStorage2.has(fcCid);
            check(59, fcHas === true, 'Filecoin has returns true after put');

            var fcList = await FilecoinStorage2.list('fctest-');
            check(60, fcList.length >= 1, 'Filecoin list finds uploaded CID');

            var fcGot = await FilecoinStorage2.get(fcCid);
            check(61, Buffer.isBuffer(fcGot), 'Filecoin get returns Buffer');
            check(62, fcGot && fcGot.equals(fcBuf), 'Filecoin get returns correct data');

            await FilecoinStorage2.delete(fcCid);
            var fcHas2 = await FilecoinStorage2.has(fcCid);
            check(63, fcHas2 === false, 'Filecoin has returns false after delete (index removed)');

        } catch (e) {
            console.error('  ERROR: ' + e.message);
            check(57, false, 'Filecoin integration error: ' + e.message);
        }

        FilecoinStorage2._reset();
    }

    // ============================================================== //
    //  SECTION 14 — Rclone integration (gated)
    // ============================================================== //

    section('Rclone integration');

    var rcloneRemote = process.env.RCLONE_REMOTE;

    if (!rcloneRemote) {
        console.log('  SKIP: set RCLONE_REMOTE env var to run live Rclone tests');
        check(64, true, 'Rclone integration skipped (RCLONE_REMOTE not set)');
    } else {
        var RcloneStorage2 = require(RCLONE_PATH);
        var rcTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-rc-test-'));

        try {
            await RcloneStorage2.init({
                remote:   rcloneRemote,
                basePath: 'safecloud-ci-test-' + Date.now().toString(16),
                tmpDir:   rcTmpDir
            });
            check(64, RcloneStorage2._ready, 'Rclone init succeeds');

            var rcCid = 'ef' + randCid();
            var rcBuf = randBuf(128);

            await RcloneStorage2.put(rcCid, rcBuf);
            check(65, true, 'Rclone put completes without error');

            var rcHas = await RcloneStorage2.has(rcCid);
            check(66, rcHas === true, 'Rclone has returns true after put');

            var rcGot = await RcloneStorage2.get(rcCid);
            check(67, Buffer.isBuffer(rcGot), 'Rclone get returns Buffer');
            check(68, rcGot && rcGot.equals(rcBuf), 'Rclone get returns correct data');

            var rcList = await RcloneStorage2.list('ef');
            check(69, rcList.some(function (c) { return c === rcCid; }),
                'Rclone list contains the stored CID');

            await RcloneStorage2.delete(rcCid);
            var rcHas2 = await RcloneStorage2.has(rcCid);
            check(70, rcHas2 === false, 'Rclone has returns false after delete');

            var rcMissing = await RcloneStorage2.get(rcCid);
            check(71, rcMissing === null, 'Rclone get returns null after delete');

        } catch (e) {
            console.error('  ERROR: ' + e.message);
            check(64, false, 'Rclone integration error: ' + e.message);
        }

        RcloneStorage2._reset();
    }

    // ============================================================== //
    //  Restore Module._load and cleanup
    // ============================================================== //

    Module._load = origLoad;

    // Clean up temp directories
    try {
        var rimraf = function (dir) {
            if (!fs.existsSync(dir)) { return; }
            fs.readdirSync(dir).forEach(function (entry) {
                var ep = path.join(dir, entry);
                if (fs.statSync(ep).isDirectory()) { rimraf(ep); }
                else { fs.unlinkSync(ep); }
            });
            fs.rmdirSync(dir);
        };
        rimraf(tmpDir);
        rimraf(emptyTmpDir);
        rimraf(newDir);
    } catch (e) {
        // best-effort cleanup
    }

    // ============================================================== //
    //  Summary
    // ============================================================== //

    console.log('\n=================================================');
    console.log('Storage Backends Test Suite');
    console.log('  PASS: ' + pass);
    console.log('  FAIL: ' + fail);
    console.log('=================================================\n');

    process.exit(fail > 0 ? 1 : 0);

})().catch(function (err) {
    console.error('\nUNHANDLED ERROR:', err);
    process.exit(1);
});
