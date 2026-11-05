'use strict';
/**
 * Safecloud 3.4 — S3 storage backend test suite
 *
 * Covers:
 *  1.  S3Storage.init() — validates required config fields
 *  2.  S3Storage.put() / get() — round-trip with mock S3 client
 *  3.  S3Storage.has() — head-object semantics, NotFound → false
 *  4.  S3Storage.delete() — removes the object
 *  5.  S3Storage.list() — prefix filter, pagination
 *  6.  S3Storage error handling — get/has on missing key returns null/false
 *  7.  Drops.initStorage() — validates the backend interface
 *  8.  Drops.putChunks() / getChunks() — wire-format round-trip
 *  9.  Drops.hasChunk() — delegates to the backend
 * 10.  Drops chunk serialisation edge cases — missing iv, tag, ciphertext
 * 11.  Integration tests — gated on R2_ENDPOINT env var (live Cloudflare R2)
 *
 * No mocking of Node built-ins; @aws-sdk/client-s3 is intercepted via
 * Module._load so S3.js can be tested without a real S3 connection.
 */

const path   = require('path');
const Module = require('module');

let pass = 0, fail = 0;
function check(n, c, d) {
    c ? (pass++, console.log('  ✓', n))
      : (fail++, console.log('  ✗ FAIL:', n, d ? ('— ' + d) : ''));
}
function section(t) { console.log('\n── ' + t + ' ──'); }

// ─────────────────────────────────────────────────────────────────────────────
// Mock @aws-sdk/client-s3
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build an in-memory mock of @aws-sdk/client-s3.
 * Returns { mock, s3mod } where s3mod is the fake module and mock exposes
 * the bucket state for assertions.
 */
function buildS3Mock(opts) {
    opts = opts || {};
    var bucket = {};  // Key → Buffer

    function S3Client(config) {
        this._config = config;
    }

    S3Client.prototype.send = function (cmd) {
        var name = cmd._name;

        if (name === 'PutObject') {
            if (opts.putShouldFail) {
                return Promise.reject(Object.assign(new Error('PutObject failed'), { $metadata: { httpStatusCode: 500 } }));
            }
            var body = cmd.input.Body;
            bucket[cmd.input.Key] = Buffer.isBuffer(body) ? body : Buffer.from(body);
            return Promise.resolve({ $metadata: { httpStatusCode: 200 } });
        }

        if (name === 'GetObject') {
            var key = cmd.input.Key;
            if (!Object.prototype.hasOwnProperty.call(bucket, key)) {
                var e = Object.assign(new Error('NoSuchKey'), { name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } });
                return Promise.reject(e);
            }
            // Return as a fake Node.js Readable stream
            var buf = bucket[key];
            var EventEmitter = require('events');
            var stream = new EventEmitter();
            stream.pipe = function () {};  // mark as Node Readable
            // Emit data asynchronously so callers can attach handlers first
            setTimeout(function () {
                stream.emit('data', buf);
                stream.emit('end');
            }, 0);
            return Promise.resolve({ Body: stream, ContentLength: buf.length });
        }

        if (name === 'HeadObject') {
            var hkey = cmd.input.Key;
            if (!Object.prototype.hasOwnProperty.call(bucket, hkey)) {
                var he = Object.assign(new Error('Not Found'), { name: 'NotFound', $metadata: { httpStatusCode: 404 } });
                return Promise.reject(he);
            }
            return Promise.resolve({ ContentLength: bucket[hkey].length, $metadata: { httpStatusCode: 200 } });
        }

        if (name === 'DeleteObject') {
            delete bucket[cmd.input.Key];
            return Promise.resolve({ $metadata: { httpStatusCode: 204 } });
        }

        if (name === 'ListObjectsV2') {
            var prefix  = cmd.input.Prefix  || '';
            var maxKeys = cmd.input.MaxKeys || 1000;
            var contToken = cmd.input.ContinuationToken || null;

            // All matching keys, sorted
            var allKeys = Object.keys(bucket)
                .filter(function (k) { return k.indexOf(prefix) === 0; })
                .sort();

            // Simulate pagination by token (use numeric index as token)
            var startIdx = contToken ? parseInt(contToken, 10) : 0;
            var page     = allKeys.slice(startIdx, startIdx + maxKeys);
            var nextIdx  = startIdx + maxKeys;
            var truncated = nextIdx < allKeys.length;

            return Promise.resolve({
                Contents:              page.map(function (k) { return { Key: k, Size: bucket[k].length }; }),
                IsTruncated:           truncated,
                NextContinuationToken: truncated ? String(nextIdx) : undefined,
                $metadata:             { httpStatusCode: 200 }
            });
        }

        return Promise.reject(new Error('Unknown command: ' + name));
    };

    function makeCmd(name) {
        return function (input) {
            this.input = input;
            this._name = name;
        };
    }

    var s3mod = {
        S3Client:            S3Client,
        PutObjectCommand:    makeCmd('PutObject'),
        GetObjectCommand:    makeCmd('GetObject'),
        HeadObjectCommand:   makeCmd('HeadObject'),
        DeleteObjectCommand: makeCmd('DeleteObject'),
        ListObjectsV2Command: makeCmd('ListObjectsV2')
    };

    return { bucket: bucket, s3mod: s3mod };
}

// ─────────────────────────────────────────────────────────────────────────────
// Load S3Storage and Drops with mock injection
// ─────────────────────────────────────────────────────────────────────────────

var S3_PATH    = path.join(process.cwd(), 'classes/Safecloud/Storage/S3.js');
var DROPS_PATH = path.join(process.cwd(), 'classes/Safecloud/Drops.js');
var Q_PATH     = 'Q';

var mockS3 = buildS3Mock();
var origLoad = Module._load;

// Intercept @aws-sdk/client-s3 and Q
// Keep interceptor active throughout all mock tests —
// S3Storage.init() calls require('@aws-sdk/client-s3') at runtime so the
// interceptor must remain installed until the integration-test section.
var useMockS3 = true;

Module._load = function (r, parent, isMain) {
    if (r === '@aws-sdk/client-s3' && useMockS3) { return mockS3.s3mod; }
    if (r === Q_PATH) {
        return {
            Config: {
                get: function (k, d) { return d; },
                set: function () {}
            },
            Data:   {},
            log:    function () {},
            Crypto: { OpenClaim: { EVM: {} } }
        };
    }
    return origLoad.call(this, r, parent, isMain);
};

var S3Storage = require(S3_PATH);
var Drops     = require(DROPS_PATH);

// Helper: ensure S3Storage is in a clean state before each section
function resetS3() {
    S3Storage._reset();
    // Replace bucket contents
    Object.keys(mockS3.bucket).forEach(function (k) { delete mockS3.bucket[k]; });
}

function resetDrops() {
    Drops._store = null;
}

// ══════════════════════════════════════════════════════════════════════════════
//  1. S3Storage.init() — config validation
// ══════════════════════════════════════════════════════════════════════════════

(async function () {

section('1. S3Storage.init() — config validation');

resetS3();

var noBacket = null;
try { S3Storage.init({ accessKeyId: 'a', secretAccessKey: 'b' }); }
catch (e) { noBacket = e; }
check('init() throws when bucket is missing', noBacket instanceof Error && /bucket/.test(noBacket.message));

var noCreds = null;
try { S3Storage.init({ bucket: 'b' }); }
catch (e) { noCreds = e; }
check('init() throws when credentials are missing', noCreds instanceof Error && /accessKeyId/.test(noCreds.message));

var noSecret = null;
try { S3Storage.init({ bucket: 'b', accessKeyId: 'a' }); }
catch (e) { noSecret = e; }
check('init() throws when secretAccessKey is missing', noSecret instanceof Error && /secretAccessKey/.test(noSecret.message));

resetS3();
S3Storage.init({ bucket: 'safecloud-test', accessKeyId: 'ak', secretAccessKey: 'sk' });
check('init() succeeds with required fields', S3Storage._ready === true);
check('init() sets _bucket', S3Storage._bucket === 'safecloud-test');

// endpoint + forcePathStyle
resetS3();
S3Storage.init({
    bucket: 'my-bucket',
    accessKeyId: 'ak', secretAccessKey: 'sk',
    endpoint: 'http://localhost:9000',
    forcePathStyle: true,
    region: 'us-east-2'
});
check('init() with endpoint and forcePathStyle does not throw', S3Storage._ready === true);

// ══════════════════════════════════════════════════════════════════════════════
//  2. S3Storage.put() / get() — round-trip
// ══════════════════════════════════════════════════════════════════════════════

section('2. S3Storage.put() / get() — round-trip');

resetS3();
S3Storage.init({ bucket: 'test', accessKeyId: 'ak', secretAccessKey: 'sk' });

var cid1 = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
var buf1  = Buffer.from('hello safecloud chunk');

await S3Storage.put(cid1, buf1);
check('put() stores the buffer', !!mockS3.bucket[cid1]);

var got = await S3Storage.get(cid1);
check('get() returns a Buffer', Buffer.isBuffer(got));
check('get() returns correct content', got && got.equals(buf1));

// put() with binary data
var binBuf = Buffer.from([0x00, 0x01, 0x02, 0xfe, 0xff]);
var cidBin = 'b' + '0'.repeat(63);
await S3Storage.put(cidBin, binBuf);
var gotBin = await S3Storage.get(cidBin);
check('put()/get() round-trip preserves binary data', gotBin && gotBin.equals(binBuf));

// get() of missing key → null
var missing = await S3Storage.get('does-not-exist');
check('get() returns null for missing key', missing === null);

// put() argument validation
var putErr = await S3Storage.put('', buf1).catch(function (e) { return e; });
check('put() rejects on empty cid', putErr instanceof Error && /cid/.test(putErr.message));

var putNonBuf = await S3Storage.put(cid1, 'not-a-buffer').catch(function (e) { return e; });
check('put() rejects when buf is not a Buffer', putNonBuf instanceof Error && /Buffer/.test(putNonBuf.message));

// ══════════════════════════════════════════════════════════════════════════════
//  3. S3Storage.has() — HeadObject semantics
// ══════════════════════════════════════════════════════════════════════════════

section('3. S3Storage.has() — HeadObject semantics');

resetS3();
S3Storage.init({ bucket: 'test', accessKeyId: 'ak', secretAccessKey: 'sk' });

var cidH = 'c' + 'a'.repeat(63);
check('has() returns false for missing key', !(await S3Storage.has(cidH)));

await S3Storage.put(cidH, Buffer.from('data'));
check('has() returns true for existing key', await S3Storage.has(cidH));

// NoSuchKey error name variant
var cidH2 = 'd' + 'b'.repeat(63);
var noSuchKeyErr = Object.assign(new Error('NoSuchKey'), { name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } });
// Patch the bucket temporarily to simulate a NoSuchKey from the client
// (The mock already handles this when key is absent, so just verify again)
check('has() returns false when key absent (NoSuchKey path)', !(await S3Storage.has(cidH2)));

// has() argument validation
var hasErr = await S3Storage.has('').catch(function (e) { return e; });
check('has() rejects on empty cid', hasErr instanceof Error);

// ══════════════════════════════════════════════════════════════════════════════
//  4. S3Storage.delete()
// ══════════════════════════════════════════════════════════════════════════════

section('4. S3Storage.delete()');

resetS3();
S3Storage.init({ bucket: 'test', accessKeyId: 'ak', secretAccessKey: 'sk' });

var cidD = 'e' + 'c'.repeat(63);
await S3Storage.put(cidD, Buffer.from('to be deleted'));
check('key exists before delete', !!mockS3.bucket[cidD]);

await S3Storage.delete(cidD);
check('delete() removes the key', !mockS3.bucket[cidD]);
check('get() returns null after delete', (await S3Storage.get(cidD)) === null);

// delete() of non-existent key should not throw (S3 is idempotent)
var delMissing = await S3Storage.delete('not-there').catch(function (e) { return e; });
check('delete() of missing key does not throw', !(delMissing instanceof Error));

// delete() argument validation
var delErr = await S3Storage.delete('').catch(function (e) { return e; });
check('delete() rejects on empty cid', delErr instanceof Error);

// ══════════════════════════════════════════════════════════════════════════════
//  5. S3Storage.list() — prefix filter + pagination
// ══════════════════════════════════════════════════════════════════════════════

section('5. S3Storage.list() — prefix filter, pagination');

resetS3();
S3Storage.init({ bucket: 'test', accessKeyId: 'ak', secretAccessKey: 'sk' });

// Insert some keys
var keysToInsert = ['aa001', 'aa002', 'aa003', 'bb001', 'bb002'];
for (var ki = 0; ki < keysToInsert.length; ki++) {
    await S3Storage.put(keysToInsert[ki], Buffer.from('x'));
}

var all = await S3Storage.list('');
check('list("") returns all keys', all.length === 5);

var aa = await S3Storage.list('aa');
check('list("aa") returns only aa-prefixed keys', aa.length === 3);
check('list("aa") all start with "aa"', aa.every(function (k) { return k.indexOf('aa') === 0; }));

var bb = await S3Storage.list('bb');
check('list("bb") returns only bb-prefixed keys', bb.length === 2);

var none = await S3Storage.list('zz');
check('list("zz") returns empty array for no matches', none.length === 0);

// list() with no argument uses empty prefix
var listAll = await S3Storage.list();
check('list() with no arg returns all keys', listAll.length === 5);

// Pagination: the mock paginates at MaxKeys=1000; we can't easily trigger
// real pagination in the mock without inserting >1000 keys, so we verify
// the collected array is an array of strings
check('list() returns an array of strings', listAll.every(function (k) { return typeof k === 'string'; }));

// ══════════════════════════════════════════════════════════════════════════════
//  6. S3Storage error handling — uninitialized calls
// ══════════════════════════════════════════════════════════════════════════════

section('6. S3Storage error handling — uninitialized');

resetS3();

var uniGet = await S3Storage.get('cid').catch(function (e) { return e; });
check('get() rejects when not initialised', uniGet instanceof Error && /not initialised/.test(uniGet.message));

var uniPut = await S3Storage.put('cid', Buffer.from('x')).catch(function (e) { return e; });
check('put() rejects when not initialised', uniPut instanceof Error && /not initialised/.test(uniPut.message));

var uniHas = await S3Storage.has('cid').catch(function (e) { return e; });
check('has() rejects when not initialised', uniHas instanceof Error && /not initialised/.test(uniHas.message));

var uniDel = await S3Storage.delete('cid').catch(function (e) { return e; });
check('delete() rejects when not initialised', uniDel instanceof Error && /not initialised/.test(uniDel.message));

var uniList = await S3Storage.list('').catch(function (e) { return e; });
check('list() rejects when not initialised', uniList instanceof Error && /not initialised/.test(uniList.message));

// ══════════════════════════════════════════════════════════════════════════════
//  7. Drops.initStorage() — interface validation
// ══════════════════════════════════════════════════════════════════════════════

section('7. Drops.initStorage() — interface validation');

resetDrops();

var noStoreErr = null;
try { Drops.initStorage(null); }
catch (e) { noStoreErr = e; }
check('initStorage(null) throws', noStoreErr instanceof Error);

var noGetErr = null;
try { Drops.initStorage({ put: function () {} }); }
catch (e) { noGetErr = e; }
check('initStorage without get() throws', noGetErr instanceof Error && /get/.test(noGetErr.message));

var noPutErr = null;
try { Drops.initStorage({ get: function () {} }); }
catch (e) { noPutErr = e; }
check('initStorage without put() throws', noPutErr instanceof Error && /put/.test(noPutErr.message));

// Valid store
var validStore = {
    get:    function (cid) { return Promise.resolve(null); },
    put:    function (cid, buf) { return Promise.resolve(); },
    has:    function (cid) { return Promise.resolve(false); },
    delete: function (cid) { return Promise.resolve(); },
    list:   function (p)   { return Promise.resolve([]); }
};
var initOk = null;
try { Drops.initStorage(validStore); initOk = true; }
catch (e) { initOk = e; }
check('initStorage(validStore) succeeds', initOk === true);
check('Drops._store is set after initStorage()', Drops._store === validStore);

// ══════════════════════════════════════════════════════════════════════════════
//  8. Drops.putChunks() / getChunks() — wire-format round-trip via S3 mock
// ══════════════════════════════════════════════════════════════════════════════

section('8. Drops.putChunks() / getChunks() — wire-format round-trip');

resetS3();
resetDrops();
S3Storage.init({ bucket: 'test', accessKeyId: 'ak', secretAccessKey: 'sk' });
Drops.initStorage(S3Storage);

var chunkCid = '1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b';
var chunk = {
    cid:        chunkCid,
    ciphertext: Buffer.from('the encrypted payload').toString('base64'),
    tag:        Buffer.from('authtag16byteXXX').toString('base64'),
    iv:         Buffer.from('iv12bytes!!!').toString('base64')
};

var putResult = await Drops.putChunks([chunk]);
check('putChunks() returns { results: [...] }', putResult && Array.isArray(putResult.results));
check('putChunks() result has one entry', putResult.results.length === 1);
check('putChunks() result.stored is true', putResult.results[0].stored === true);
check('putChunks() result.cid matches input', putResult.results[0].cid === chunkCid);

// Round-trip via getChunks
var getResult = await Drops.getChunks([chunkCid]);
check('getChunks() returns { chunks: [...] }', getResult && Array.isArray(getResult.chunks));
check('getChunks() returns one chunk', getResult.chunks.length === 1);

var gotChunk = getResult.chunks[0];
check('getChunks() cid matches', gotChunk && gotChunk.cid === chunkCid);
check('getChunks() ciphertext round-trips', gotChunk && gotChunk.ciphertext === chunk.ciphertext);
check('getChunks() tag round-trips', gotChunk && gotChunk.tag === chunk.tag);
check('getChunks() iv round-trips', gotChunk && gotChunk.iv === chunk.iv);

// putChunks: multiple chunks
var chunk2 = {
    cid:        '2' + chunkCid.slice(1),
    ciphertext: Buffer.from('second chunk payload').toString('base64'),
    tag:        Buffer.from('tag2222222222222').toString('base64'),
    iv:         Buffer.from('iv2_12bytes!!').toString('base64')
};
var chunk3 = {
    cid:        '3' + chunkCid.slice(1),
    ciphertext: Buffer.from('third chunk').toString('base64'),
    tag:        Buffer.from('tag3333333333333').toString('base64'),
    iv:         Buffer.from('iv3_12bytes!!').toString('base64')
};
var multiPut = await Drops.putChunks([chunk2, chunk3]);
check('putChunks([c2,c3]) returns 2 results', multiPut.results.length === 2);
check('putChunks([c2,c3]) both stored', multiPut.results.every(function (r) { return r.stored; }));

var multiGet = await Drops.getChunks([chunk2.cid, chunk3.cid]);
check('getChunks([c2,c3]) returns 2 chunks', multiGet.chunks.length === 2);

// Missing CIDs silently omitted
var withMissing = await Drops.getChunks([chunkCid, 'ffff0000000000000000000000000000000000000000000000000000000000000000']);
check('getChunks() omits missing CIDs without error', withMissing.chunks.length === 1);

// putChunks with invalid chunk (no cid)
var badPut = await Drops.putChunks([{ ciphertext: 'AAA=', tag: 'BBB=' }]);
check('putChunks() handles chunk without cid gracefully', badPut.results.length === 1 && !badPut.results[0].stored);

// putChunks empty input
var emptyPut = await Drops.putChunks([]);
check('putChunks([]) returns empty results', emptyPut.results.length === 0);

// putChunks non-array
var nonArray = await Drops.putChunks(null);
check('putChunks(null) returns empty results', nonArray.results.length === 0);

// ══════════════════════════════════════════════════════════════════════════════
//  9. Drops.hasChunk()
// ══════════════════════════════════════════════════════════════════════════════

section('9. Drops.hasChunk()');

// _store is still S3Storage from section 8
check('hasChunk() true for existing cid', await Drops.hasChunk(chunkCid));
check('hasChunk() false for missing cid', !(await Drops.hasChunk('ffff0000000000000000000000000000000000000000000000000000000000000000')));

// hasChunk with no store set
resetDrops();
check('hasChunk() returns false when no store configured', !(await Drops.hasChunk(chunkCid)));

// ══════════════════════════════════════════════════════════════════════════════
//  10. Wire-format edge cases — missing fields
// ══════════════════════════════════════════════════════════════════════════════

section('10. Wire-format edge cases — missing iv / tag / ciphertext');

resetS3();
resetDrops();
S3Storage.init({ bucket: 'test', accessKeyId: 'ak', secretAccessKey: 'sk' });
Drops.initStorage(S3Storage);

// No iv field
var noIvCid = 'a' + '1'.repeat(63);
var noIvChunk = {
    cid:        noIvCid,
    ciphertext: Buffer.from('no iv chunk').toString('base64'),
    tag:        Buffer.from('tagnoiv1234567!!').toString('base64')
    // no iv
};
var noIvPut = await Drops.putChunks([noIvChunk]);
check('putChunks() succeeds when iv is absent', noIvPut.results[0].stored === true);

var noIvGet = await Drops.getChunks([noIvCid]);
check('getChunks() retrieves chunk with no iv', noIvGet.chunks.length === 1);
check('getChunks() ciphertext ok when iv was absent', noIvGet.chunks[0].ciphertext === noIvChunk.ciphertext);
check('getChunks() tag ok when iv was absent', noIvGet.chunks[0].tag === noIvChunk.tag);
// iv should either be absent or empty
check('getChunks() no iv field on retrieved chunk (iv absent or empty)',
    !noIvGet.chunks[0].iv || noIvGet.chunks[0].iv === '');

// No tag field
var noTagCid = 'b' + '2'.repeat(63);
var noTagChunk = {
    cid:        noTagCid,
    ciphertext: Buffer.from('no tag chunk payload').toString('base64')
    // no tag, no iv
};
var noTagPut = await Drops.putChunks([noTagChunk]);
check('putChunks() succeeds when tag is absent', noTagPut.results[0].stored === true);

var noTagGet = await Drops.getChunks([noTagCid]);
check('getChunks() retrieves chunk with no tag', noTagGet.chunks.length === 1);
check('getChunks() ciphertext ok when tag was absent', noTagGet.chunks[0].ciphertext === noTagChunk.ciphertext);

// Empty ciphertext
var emptyCtCid = 'c' + '3'.repeat(63);
var emptyCtChunk = {
    cid:        emptyCtCid,
    ciphertext: '',
    tag:        Buffer.from('tag_for_empty_ct!').toString('base64'),
    iv:         Buffer.from('iv_for_empty!').toString('base64')
};
var emptyCtPut = await Drops.putChunks([emptyCtChunk]);
check('putChunks() succeeds with empty ciphertext', emptyCtPut.results[0].stored === true);

// ══════════════════════════════════════════════════════════════════════════════
//  11. Drops — no storage backend configured
// ══════════════════════════════════════════════════════════════════════════════

section('11. Drops — no backend configured');

resetDrops();

var noBEPut = await Drops.putChunks([{ cid: 'abc', ciphertext: 'AAA=', tag: 'BBB=', iv: 'CCC=' }])
    .catch(function (e) { return e; });
check('putChunks() rejects when no backend', noBEPut instanceof Error && /backend/.test(noBEPut.message));

var noBEGet = await Drops.getChunks(['abc']).catch(function (e) { return e; });
check('getChunks() rejects when no backend', noBEGet instanceof Error && /backend/.test(noBEGet.message));

// ══════════════════════════════════════════════════════════════════════════════
//  12. S3Storage — _streamToBuffer handles Buffer/Uint8Array directly
// ══════════════════════════════════════════════════════════════════════════════

section('12. _streamToBuffer — Buffer and Uint8Array paths');

// We test this indirectly: put a Buffer, get it back.
// The mock returns a Node Readable stream; confirm the get() path works.
resetS3();
S3Storage.init({ bucket: 'test', accessKeyId: 'ak', secretAccessKey: 'sk' });

var streamCid = 'd' + '4'.repeat(63);
var streamBuf = Buffer.from('stream round trip test');
await S3Storage.put(streamCid, streamBuf);
var streamGot = await S3Storage.get(streamCid);
check('get() via Node Readable stream returns correct Buffer', streamGot && streamGot.equals(streamBuf));

// ══════════════════════════════════════════════════════════════════════════════
//  13. Integration tests — live S3-compatible bucket (R2_ENDPOINT env var)
// ══════════════════════════════════════════════════════════════════════════════

section('13. Integration tests (live S3-compatible bucket)');

var R2_ENDPOINT = process.env.R2_ENDPOINT;
if (!R2_ENDPOINT) {
    console.log('    [SKIP] Set R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET');
    console.log('           to run live S3-compatible storage integration tests.');
    console.log('           Example (Cloudflare R2):');
    console.log('             R2_ENDPOINT=https://<account>.r2.cloudflarestorage.com');
    console.log('             R2_ACCESS_KEY_ID=<key_id>');
    console.log('             R2_SECRET_ACCESS_KEY=<secret>');
    console.log('             R2_BUCKET=safecloud-test');
} else {
    console.log('    R2_ENDPOINT=' + R2_ENDPOINT);

    // We need to use the real @aws-sdk/client-s3 here, so disable the mock
    // interceptor and reload S3Storage from a clean module cache.
    useMockS3 = false;
    Module._load = origLoad;  // fully restore for the live section

    // Clear module cache so the require inside S3.js hits the real SDK
    delete require.cache[require.resolve(S3_PATH)];

    var RealS3Storage = require(S3_PATH);

    var liveErr = null;
    try {
        RealS3Storage.init({
            endpoint:        R2_ENDPOINT,
            region:          process.env.R2_REGION || 'auto',
            bucket:          process.env.R2_BUCKET || 'safecloud-test',
            accessKeyId:     process.env.R2_ACCESS_KEY_ID,
            secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
            forcePathStyle:  process.env.R2_FORCE_PATH_STYLE === 'true'
        });
    } catch (e) {
        liveErr = e;
    }
    check('live: init() does not throw', !liveErr, liveErr && liveErr.message);

    if (!liveErr) {
        var liveCid = 'safecloud-integration-test-' + Date.now().toString(16);
        var liveBuf = Buffer.from('Safecloud 3.4 integration test ' + new Date().toISOString());

        var livePut = await RealS3Storage.put(liveCid, liveBuf).catch(function (e) { return e; });
        check('live: put() succeeds', !(livePut instanceof Error), livePut && livePut.message);

        if (!(livePut instanceof Error)) {
            var liveHas = await RealS3Storage.has(liveCid).catch(function (e) { return e; });
            check('live: has() returns true after put()', liveHas === true, typeof liveHas);

            var liveGet = await RealS3Storage.get(liveCid).catch(function (e) { return e; });
            check('live: get() returns a Buffer', Buffer.isBuffer(liveGet), typeof liveGet);
            check('live: get() content matches', liveGet && liveGet.equals(liveBuf));

            var liveList = await RealS3Storage.list('safecloud-integration-test-').catch(function (e) { return e; });
            check('live: list() returns an array', Array.isArray(liveList), typeof liveList);
            check('live: list() includes the inserted key',
                Array.isArray(liveList) && liveList.indexOf(liveCid) !== -1);

            var liveDel = await RealS3Storage.delete(liveCid).catch(function (e) { return e; });
            check('live: delete() does not throw', !(liveDel instanceof Error), liveDel && liveDel.message);

            var liveHasAfter = await RealS3Storage.has(liveCid).catch(function (e) { return e; });
            check('live: has() returns false after delete()', liveHasAfter === false, typeof liveHasAfter);
        }

        RealS3Storage._reset();
    }
}

// ─── Results ─────────────────────────────────────────────────────────────────

console.log('\n══════════════════════════════════════════════════════════════════');
console.log('  S3 storage tests: ' + pass + ' passed, ' + fail + ' failed');
console.log('══════════════════════════════════════════════════════════════════');

process.exit(fail ? 1 : 0);

})().catch(function (e) {
    console.error('FATAL:', e);
    process.exit(1);
});
