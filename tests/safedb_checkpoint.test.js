/**
 * tests/safedb_checkpoint.test.js
 *
 * Unit tests for WasmRunner's durable checkpoint and gossip behaviour added
 * in Safecloud 3.2.  WasmRunner has no Q dependency at module level, so it
 * can be required directly.  We mock WasmRunner._Jets to control Drops I/O
 * and use temporary files for the index path.
 */
'use strict';

const path   = require('path');
const fs     = require('fs');
const os     = require('os');
const crypto = require('crypto');

// ── helpers ────────────────────────────────────────────────────────────────

let pass = 0, fail = 0;
function check(name, cond) {
    if (cond) { pass++; console.log('  ✓', name); }
    else       { fail++; console.log('  ✗ FAIL:', name); }
}

function tmpFile() {
    return path.join(os.tmpdir(), 'safedb-test-' + crypto.randomBytes(6).toString('hex') + '.json');
}

/** Build a minimal checkpoint blob and its content-addressed CID (same algo as WasmRunner). */
function makeBlob(appCid, track, seq, entries) {
    const blob = {
        v:              1,
        appCid,
        track,
        rootCid:        'bafyROOT',
        seq,
        jetId:          'jet-test',
        checkpointedAt: Math.floor(Date.now() / 1000),
        entries:        entries || []
    };
    const blobBytes = Buffer.from(JSON.stringify(blob));
    const cid = 'bafy' + crypto.createHash('sha256').update(blobBytes).digest('hex').slice(0, 52);
    return { blob, blobBytes, cid };
}

// ── load WasmRunner (no Q dependency at module level) ──────────────────────

// Clear require cache so each test gets a state reset.
function freshWasmRunner() {
    const key = require.resolve(
        path.join(process.cwd(), 'classes/Safecloud/Jets/WasmRunner')
    );
    delete require.cache[key];
    const boundedKey = require.resolve(
        path.join(process.cwd(), 'classes/Safecloud/Jets/_bounded')
    );
    delete require.cache[boundedKey];
    return require(path.join(process.cwd(), 'classes/Safecloud/Jets/WasmRunner'));
}

// ─────────────────────────────────────────────────────────────────────────────

(async () => {

// ── 1. Module loads without Q ──────────────────────────────────────────────
{
    let WR;
    try { WR = freshWasmRunner(); } catch (e) { WR = null; }
    check('WasmRunner loads without Q or ethers', !!WR);
    check('WasmRunner exports init', typeof WR.init === 'function');
    check('WasmRunner exports restoreCheckpoints', typeof WR.restoreCheckpoints === 'function');
    check('WasmRunner exports applyRootUpdate', typeof WR.applyRootUpdate === 'function');
    check('_emitRootUpdate is null initially', WR._emitRootUpdate === null);
}

// ── 2. restoreCheckpoints — missing index file → fresh start ──────────────
{
    const WR = freshWasmRunner();
    const nonExistent = tmpFile(); // guaranteed not to exist
    let resolved = false, threw = false;
    try {
        await WR.restoreCheckpoints(nonExistent);
        resolved = true;
    } catch (e) { threw = true; }
    check('restoreCheckpoints with missing index resolves (no throw)', resolved && !threw);
}

// ── 3. restoreCheckpoints — empty index → resolves immediately ─────────────
{
    const WR = freshWasmRunner();
    const idx = tmpFile();
    fs.writeFileSync(idx, '{}', 'utf8');
    let resolved = false;
    try { await WR.restoreCheckpoints(idx); resolved = true; } catch (_) {}
    check('restoreCheckpoints with empty {} index resolves', resolved);
    fs.unlinkSync(idx);
}

// ── 4. restoreCheckpoints — valid index → fetches blob from Drops ──────────
{
    const WR = freshWasmRunner();
    const appCid = 'bafyAPP1';
    const track  = 'my-track';
    const { blob, blobBytes, cid } = makeBlob(appCid, track, 1, [
        { key: 'hello', value: Buffer.from('world').toString('base64') }
    ]);

    const idx = tmpFile();
    fs.writeFileSync(idx, JSON.stringify({ [appCid + '/' + track]: cid }), 'utf8');

    // Track which Drops calls are made
    const getCalls = [];
    WR._Jets = {
        selectDrops: async (cids, opts) => {
            // forGet=true → selectForGet path
            return [{ id: 'drop-A' }];
        },
        callDrop: async (drop, endpoint, payload) => {
            getCalls.push({ drop, endpoint, payload });
            if (endpoint === 'Safecloud/drop/get') {
                return { chunks: { [payload.cids[0]]: blobBytes.toString('base64') } };
            }
            return {};
        }
    };
    WR._jetId = 'jet-test';

    await WR.restoreCheckpoints(idx);

    check('restoreCheckpoints calls drop/get for the checkpoint CID',
        getCalls.some(c => c.endpoint === 'Safecloud/drop/get'));
    check('restoreCheckpoints passes the correct CID',
        getCalls.some(c => c.payload && c.payload.cids && c.payload.cids[0] === cid));

    fs.unlinkSync(idx);
}

// ── 5. applyRootUpdate — invalid / malformed msg → no-op ──────────────────
{
    const WR = freshWasmRunner();
    let callCount = 0;
    WR._Jets = { selectDrops: async () => { callCount++; return []; }, callDrop: async () => ({}) };

    await WR.applyRootUpdate(null);
    await WR.applyRootUpdate({});
    await WR.applyRootUpdate({ appCid: 'x', track: 'y' }); // missing checkpointCid

    check('applyRootUpdate with invalid msg makes no Drops calls', callCount === 0);
}

// ── 6. applyRootUpdate — stale seq guard ──────────────────────────────────
{
    const WR = freshWasmRunner();
    const appCid = 'bafyAPP2';
    const track  = 'state';
    const { blob, blobBytes, cid } = makeBlob(appCid, track, 5, []);

    // Prime the seq by applying seq=5 first
    const fetchCalls = [];
    WR._Jets = {
        selectDrops: async () => [{ id: 'drop-A' }],
        callDrop: async (drop, endpoint, payload) => {
            fetchCalls.push(endpoint);
            if (endpoint === 'Safecloud/drop/get') {
                return { chunks: { [payload.cids[0]]: blobBytes.toString('base64') } };
            }
            return {};
        }
    };
    WR._jetId = 'jet-peer';

    // First application at seq=5 should fetch
    await WR.applyRootUpdate({ appCid, track, rootCid: 'bafyR', checkpointCid: cid, seq: 5, jetId: 'jet-peer' });
    const callsAfterFirst = fetchCalls.length;

    // Second application at same seq=5 should be a no-op
    await WR.applyRootUpdate({ appCid, track, rootCid: 'bafyR', checkpointCid: cid, seq: 5, jetId: 'jet-peer' });
    check('applyRootUpdate skips stale seq (monotone guard)', fetchCalls.length === callsAfterFirst);

    // Lower seq should also be skipped
    await WR.applyRootUpdate({ appCid, track, rootCid: 'bafyR', checkpointCid: cid, seq: 3, jetId: 'jet-peer' });
    check('applyRootUpdate skips lower seq', fetchCalls.length === callsAfterFirst);
}

// ── 7. applyRootUpdate — fresh seq → fetches and applies ──────────────────
{
    const WR = freshWasmRunner();
    const appCid = 'bafyAPP3';
    const track  = 'game';
    const { blob, blobBytes, cid } = makeBlob(appCid, track, 10, [
        { key: 'score', value: Buffer.from('42').toString('base64') }
    ]);

    const fetchedCids = [];
    WR._Jets = {
        selectDrops: async () => [{ id: 'drop-X' }],
        callDrop: async (drop, endpoint, payload) => {
            if (endpoint === 'Safecloud/drop/get') {
                fetchedCids.push(payload.cids[0]);
                return { chunks: { [payload.cids[0]]: blobBytes.toString('base64') } };
            }
            return {};
        }
    };
    WR._jetId = 'jet-other';

    await WR.applyRootUpdate({
        appCid, track, rootCid: 'bafyR', checkpointCid: cid, seq: 10, jetId: 'jet-other'
    });

    check('applyRootUpdate with fresh seq fetches the checkpoint CID',
        fetchedCids.includes(cid));
}

// ── 8. applyRootUpdate — own jet echo ignored ─────────────────────────────
// Jets.js filters own jetId before calling applyRootUpdate, so if it somehow
// reaches WasmRunner, seq guard stops redundant fetch.  Test seq path:
{
    const WR = freshWasmRunner();
    const appCid = 'bafyAPP4';
    const track  = 'echo';
    const { blobBytes, cid } = makeBlob(appCid, track, 7, []);

    // Apply once to set seq=7
    const calls = [];
    WR._Jets = {
        selectDrops: async () => [{ id: 'drop-A' }],
        callDrop: async (drop, ep, pl) => {
            calls.push(ep);
            if (ep === 'Safecloud/drop/get') {
                return { chunks: { [pl.cids[0]]: blobBytes.toString('base64') } };
            }
            return {};
        }
    };
    await WR.applyRootUpdate({ appCid, track, rootCid: 'bafyR', checkpointCid: cid, seq: 7, jetId: 'self' });
    const before = calls.length;
    // Re-apply same seq (simulating echo of own gossip)
    await WR.applyRootUpdate({ appCid, track, rootCid: 'bafyR', checkpointCid: cid, seq: 7, jetId: 'self' });
    check('own-echo at same seq is a no-op (seq guard)', calls.length === before);
}

// ── 9. _emitRootUpdate callback wired correctly ───────────────────────────
{
    // WasmRunner._emitRootUpdate is set externally by Jets.js.  Verify that
    // the public slot exists and accepts a function value.
    const WR = freshWasmRunner();
    check('_emitRootUpdate slot exists on fresh module', '_emitRootUpdate' in WR);
    let called = false;
    WR._emitRootUpdate = (msg) => { called = true; };
    check('_emitRootUpdate slot is writable', typeof WR._emitRootUpdate === 'function');
}

// ── 10. Checkpoint index persists to disk after applyRootUpdate ───────────
{
    const WR = freshWasmRunner();
    const appCid = 'bafyAPP5';
    const track  = 'persist';
    const { blobBytes, cid } = makeBlob(appCid, track, 1, []);

    const idx = tmpFile();
    // Give WasmRunner an index path so _persistCheckpointIndex can write
    await WR.restoreCheckpoints(idx);  // creates fresh index (file doesn't exist yet)

    WR._Jets = {
        selectDrops: async () => [{ id: 'drop-A' }],
        callDrop: async (drop, ep, pl) => {
            if (ep === 'Safecloud/drop/get') {
                return { chunks: { [pl.cids[0]]: blobBytes.toString('base64') } };
            }
            return {};
        }
    };

    await WR.applyRootUpdate({ appCid, track, rootCid: 'bafyR', checkpointCid: cid, seq: 1, jetId: 'other' });

    let written = false;
    try {
        const saved = JSON.parse(fs.readFileSync(idx, 'utf8'));
        written = saved[appCid + '/' + track] === cid;
    } catch (_) {}
    check('applyRootUpdate persists checkpoint CID to index file', written);
    try { fs.unlinkSync(idx); } catch (_) {}
}

// ─────────────────────────────────────────────────────────────────────────────

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);

})();
