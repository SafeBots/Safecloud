/**
 * Tests for Safecloud Chat DAG walker and forward chain logic.
 *
 *   node tests/chat_dag.test.js
 */

'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// HKDF and AES-256-GCM shim (same as chat_send_receive.test.js)
// ─────────────────────────────────────────────────────────────────────────────

function hkdf(secretBytes, info, length) {
    var salt = Buffer.alloc(32, 0);
    var prk  = crypto.createHmac('sha256', salt).update(secretBytes).digest();
    var infoBytes = Buffer.from(info, 'utf8');
    var counter   = Buffer.from([1]);
    var okm = crypto.createHmac('sha256', prk)
                    .update(Buffer.concat([infoBytes, counter]))
                    .digest();
    return okm.slice(0, length);
}

function aesgcmEncrypt(keyBytes, ivBytes, plaintext) {
    var cipher = crypto.createCipheriv('aes-256-gcm', keyBytes, ivBytes);
    var ct  = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    var tag = cipher.getAuthTag();
    return {
        ciphertext: ct.toString('base64'),
        tag:        tag.toString('base64'),
        iv:         Buffer.from(ivBytes).toString('base64')
    };
}

function aesgcmDecrypt(keyBytes, ivB64, ciphertextB64, tagB64) {
    var iv  = Buffer.from(ivB64, 'base64');
    var ct  = Buffer.from(ciphertextB64, 'base64');
    var tag = Buffer.from(tagB64, 'base64');
    var d   = crypto.createDecipheriv('aes-256-gcm', keyBytes, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
}

function computeCid(ciphertextB64, tagB64) {
    var buf = Buffer.concat([Buffer.from(ciphertextB64, 'base64'), Buffer.from(tagB64, 'base64')]);
    return crypto.createHash('sha256').update(buf).digest('hex');
}

// ─────────────────────────────────────────────────────────────────────────────
// Q shim
// ─────────────────────────────────────────────────────────────────────────────

function makeDropStore() {
    var store = {};
    return {
        store: function (d) {
            var cid = computeCid(d.ciphertext, d.tag);
            store[cid] = d;
            return Promise.resolve({ cid: cid });
        },
        fetch: function (cid) { return Promise.resolve(store[cid] || null); },
        _store: store
    };
}

var Q = {
    Data: {
        fromBase64: function (s) { return new Uint8Array(Buffer.from(s, 'base64')); },
        toBase64:   function (u) { return Buffer.from(u).toString('base64'); },
        derive: function (secretBytes, info, opts) {
            var size = (opts && opts.size) || 32;
            var out  = hkdf(Buffer.from(secretBytes), info, size);
            return Promise.resolve(new Uint8Array(out));
        },
        importKey: function (keyBytes) {
            return Promise.resolve({ _bytes: Buffer.from(keyBytes) });
        },
        encrypt: function (cryptoKey, plaintext, opts) {
            var ivIn = opts && opts.iv;
            var iv = ivIn
                ? (Buffer.isBuffer(ivIn) ? ivIn : Buffer.from(ivIn))
                : crypto.randomBytes(12);
            return Promise.resolve(aesgcmEncrypt(cryptoKey._bytes, iv, Buffer.from(plaintext)));
        },
        decrypt: function (cryptoKey, ivB64, ciphertextB64, opts) {
            var tagB64 = opts && opts.tag;
            try {
                return Promise.resolve(aesgcmDecrypt(cryptoKey._bytes, ivB64, ciphertextB64, tagB64));
            } catch (e) {
                return Promise.reject(e);
            }
        }
    },
    Crypto: {},
    Streams: { message: function () {}, subscribe: function () { return { unsubscribe: function () {} }; } },
    log: function () {}
};

function loadQModule(relPath) {
    var code = fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
    var exported;
    var localQ = Object.assign({}, Q, {
        exports: function (fn) { exported = fn(Q, {}); }
    });
    // eslint-disable-next-line no-new-func
    new Function('Q', 'crypto', code)(localQ, globalThis.crypto);
    return exported;
}

Q.Safecloud = { Chat: {} };
Q.Safecloud.Chat.message      = loadQModule('web/js/methods/Safecloud/Chat/message.js');
Q.Safecloud.Chat.send         = loadQModule('web/js/methods/Safecloud/Chat/send.js');
Q.Safecloud.Chat.receive      = loadQModule('web/js/methods/Safecloud/Chat/receive.js');
Q.Safecloud.Chat.dag          = loadQModule('web/js/methods/Safecloud/Chat/dag.js');
Q.Safecloud.Chat.forwardChain = loadQModule('web/js/methods/Safecloud/Chat/forwardChain.js');
Q.Safecloud.Chat.revoke       = loadQModule('web/js/methods/Safecloud/Chat/revoke.js');

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

var pass = 0, fail = 0;
function check(name, cond, detail) {
    if (cond) { pass++; console.log('  ✓', name); }
    else       { fail++; console.log('  ✗ FAIL:', name, detail ? ('— ' + detail) : ''); }
}
function checkErr(name, err) {
    fail++;
    console.log('  ✗ ERROR:', name, '—', err && err.message || err);
}

var THREAD_ID  = 'dag-test-thread';
var EPOCH_KEY  = new Uint8Array(crypto.randomBytes(32));
var EPOCH_IDX  = 0;

// ─────────────────────────────────────────────────────────────────────────────
// 1. DAG pure operations
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.dag pure operations ──');

var dag = Q.Safecloud.Chat.dag;

// Linear chain: A → B → C
var chain = [
    { cid: 'A', parentIds: [],    timestamp: 1000 },
    { cid: 'B', parentIds: ['A'], timestamp: 2000 },
    { cid: 'C', parentIds: ['B'], timestamp: 3000 }
];
check('roots of linear chain: [A]', JSON.stringify(dag.roots(chain)) === JSON.stringify(['A']));
check('tips of linear chain: [C]',  JSON.stringify(dag.tips(chain))  === JSON.stringify(['C']));
var sorted = dag.topoSort(chain);
check('topoSort linear: A,B,C', sorted.map(function (n) { return n.cid; }).join(',') === 'A,B,C');
var threaded = dag.thread(chain);
check('thread linear: A,B,C', threaded.map(function (n) { return n.cid; }).join(',') === 'A,B,C');

// Branched: A → B, A → C
var branched = [
    { cid: 'A', parentIds: [],    timestamp: 1000 },
    { cid: 'B', parentIds: ['A'], timestamp: 2000 },
    { cid: 'C', parentIds: ['A'], timestamp: 2001 }
];
var bTips = dag.tips(branched);
check('branched tips: B and C', bTips.length === 2 && bTips.includes('B') && bTips.includes('C'));
var bSorted = dag.topoSort(branched);
check('branched topoSort: A first', bSorted[0].cid === 'A');
check('branched topoSort: B before C (timestamp)', bSorted[1].cid === 'B' && bSorted[2].cid === 'C');
var bThread = dag.thread(branched);
check('branched thread ends at C (latest tip)', bThread[bThread.length - 1].cid === 'C');

// Merge: A → B, A → C, (B,C) → D
var merged = [
    { cid: 'A', parentIds: [],         timestamp: 1000 },
    { cid: 'B', parentIds: ['A'],      timestamp: 2000 },
    { cid: 'C', parentIds: ['A'],      timestamp: 2001 },
    { cid: 'D', parentIds: ['B', 'C'], timestamp: 3000 }
];
var mTips = dag.tips(merged);
check('merged tips: only D', mTips.length === 1 && mTips[0] === 'D');
var mSorted = dag.topoSort(merged);
check('merged topoSort: A first, D last',
    mSorted[0].cid === 'A' && mSorted[mSorted.length - 1].cid === 'D');

// Cycle detection
try {
    dag.topoSort([
        { cid: 'X', parentIds: ['Y'], timestamp: 1000 },
        { cid: 'Y', parentIds: ['X'], timestamp: 2000 }
    ]);
    check('cycle detection: throws', false, 'should have thrown');
} catch (e) {
    check('cycle detection: throws', e.message.includes('cycle'));
}

// Empty
check('roots of empty: []', dag.roots([]).length === 0);
check('tips of empty: []',  dag.tips([]).length  === 0);
check('thread of empty: []', dag.thread([]).length === 0);

// ─────────────────────────────────────────────────────────────────────────────
// 2. DAG.fetchAll — build DAG from actual encrypted drops
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.dag.fetchAll ──');

var allTests = [];

var t1 = new Promise(function (resolve) {
    var drops = makeDropStore();

    // Send 3 messages: A (root), B (parent=A), C (parent=B)
    var send = Q.Safecloud.Chat.send;
    var cidA, cidB, cidC;

    send({ threadId: THREAD_ID, epochKey: EPOCH_KEY, epochIndex: EPOCH_IDX,
           text: 'msg A', drops: drops },
    function (e, r) {
        if (e) { checkErr('fetchAll: send A', e); return resolve(); }
        cidA = r.cid;

        send({ threadId: THREAD_ID, epochKey: EPOCH_KEY, epochIndex: EPOCH_IDX,
               text: 'msg B', parentIds: [cidA], drops: drops },
        function (e2, r2) {
            if (e2) { checkErr('fetchAll: send B', e2); return resolve(); }
            cidB = r2.cid;

            send({ threadId: THREAD_ID, epochKey: EPOCH_KEY, epochIndex: EPOCH_IDX,
                   text: 'msg C', parentIds: [cidB], drops: drops },
            function (e3, r3) {
                if (e3) { checkErr('fetchAll: send C', e3); return resolve(); }
                cidC = r3.cid;

                // fetchAll
                dag.fetchAll([cidA, cidB, cidC], EPOCH_KEY, EPOCH_IDX, { drops: drops },
                function (err, nodes) {
                    if (err) { checkErr('fetchAll: fetch', err); return resolve(); }
                    check('fetchAll: 3 nodes returned', nodes.length === 3, 'got ' + nodes.length);

                    var sorted = dag.topoSort(nodes);
                    var texts  = sorted.map(function (n) { return n.envelope.text; });
                    check('fetchAll topoSort: A first', texts[0] === 'msg A',  'got ' + texts[0]);
                    check('fetchAll topoSort: C last',  texts[2] === 'msg C',  'got ' + texts[2]);

                    var thread = dag.thread(nodes);
                    check('fetchAll thread: 3 nodes', thread.length === 3);
                    check('fetchAll thread tips: msg C', thread[2].envelope.text === 'msg C');

                    resolve();
                });
            });
        });
    });
});
allTests.push(t1);

// fetchAll with unknown CID — should return only found nodes
var t2 = new Promise(function (resolve) {
    var drops = makeDropStore();

    Q.Safecloud.Chat.send({
        threadId: THREAD_ID, epochKey: EPOCH_KEY, epochIndex: EPOCH_IDX,
        text: 'real msg', drops: drops
    }, function (e, r) {
        if (e) { checkErr('fetchAll unknown CID: send', e); return resolve(); }

        dag.fetchAll([r.cid, 'nonexistentcid'], EPOCH_KEY, EPOCH_IDX, { drops: drops },
        function (err, nodes) {
            if (err) { checkErr('fetchAll unknown CID: fetch', err); return resolve(); }
            check('fetchAll unknown CID: 1 node', nodes.length === 1, 'got ' + nodes.length);
            check('fetchAll unknown CID: correct node', nodes[0].envelope.text === 'real msg');
            resolve();
        });
    });
});
allTests.push(t2);

// ─────────────────────────────────────────────────────────────────────────────
// 3. forwardChain.post and follow
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.forwardChain ──');

var t3 = new Promise(function (resolve) {
    var drops    = makeDropStore();
    var epoch0   = new Uint8Array(crypto.randomBytes(32));
    var epoch1   = new Uint8Array(crypto.randomBytes(32));

    Q.Safecloud.Chat.forwardChain.post({
        threadId:      THREAD_ID,
        oldEpochKey:   epoch0,
        oldEpochIndex: 0,
        newEpochKey:   epoch1,
        drops:         drops
    }, function (err, result) {
        if (err) { checkErr('forwardChain.post', err); return resolve(); }
        check('forwardChain.post: no error', !err);
        check('forwardChain.post: forwardCid is string', typeof result.forwardCid === 'string');
        check('forwardChain.post: newEpochKeyCid is string', typeof result.newEpochKeyCid === 'string');

        // Verify the wrapped key Drop is in the store
        var keyDrop = drops._store[result.newEpochKeyCid];
        check('forwardChain.post: key drop stored', !!keyDrop);

        // Follow the forward chain from the control message
        Q.Safecloud.Chat.forwardChain.follow(
            result.forwardCid, epoch0, 0, { drops: drops },
            function (err2, state) {
                if (err2) { checkErr('forwardChain.follow', err2); return resolve(); }
                check('forwardChain.follow: no error', !err2);
                check('forwardChain.follow: epochIndex advanced', state.epochIndex === 1,
                    'got ' + state.epochIndex);

                // Verify the returned epoch key matches epoch1
                var returnedB64 = Buffer.from(state.epochKey).toString('base64');
                var epoch1B64   = Buffer.from(epoch1).toString('base64');
                check('forwardChain.follow: epoch key matches', returnedB64 === epoch1B64);

                // Verify we can send/receive with the new key
                Q.Safecloud.Chat.send({
                    threadId: THREAD_ID, epochKey: state.epochKey, epochIndex: 1,
                    text: 'msg after rekey', drops: drops
                }, function (e3, sent) {
                    if (e3) { checkErr('post-rekey send', e3); return resolve(); }
                    Q.Safecloud.Chat.receive(sent.cid, state.epochKey, 1, { drops: drops },
                    function (e4, env) {
                        if (e4) { checkErr('post-rekey receive', e4); return resolve(); }
                        check('post-rekey message decrypts', env.text === 'msg after rekey');
                        resolve();
                    });
                });
            }
        );
    });
});
allTests.push(t3);

// ─────────────────────────────────────────────────────────────────────────────
// 4. revoke.deriveEpochKey — sibling key derivation
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.revoke.deriveEpochKey ──');

var t4 = new Promise(function (resolve) {
    var threadKey = new Uint8Array(crypto.randomBytes(32));
    var revoke    = Q.Safecloud.Chat.revoke;

    Promise.all([
        revoke.deriveEpochKey(threadKey, 0),
        revoke.deriveEpochKey(threadKey, 1),
        revoke.deriveEpochKey(threadKey, 0)   // same as first → must match
    ]).then(function (keys) {
        var k0a = Buffer.from(keys[0]).toString('base64');
        var k1  = Buffer.from(keys[1]).toString('base64');
        var k0b = Buffer.from(keys[2]).toString('base64');

        check('deriveEpochKey: epoch 0 is deterministic', k0a === k0b);
        check('deriveEpochKey: epoch 0 ≠ epoch 1', k0a !== k1);
        check('deriveEpochKey: 32 bytes', keys[0].length === 32);
        resolve();
    }).catch(function (err) {
        checkErr('deriveEpochKey', err);
        resolve();
    });
});
allTests.push(t4);

// ─────────────────────────────────────────────────────────────────────────────
// 5. revoke.revokeAndRekey — O(1) rekey
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.revoke.revokeAndRekey ──');

var t5 = new Promise(function (resolve) {
    var drops     = makeDropStore();
    var threadKey = new Uint8Array(crypto.randomBytes(32));
    var revoke    = Q.Safecloud.Chat.revoke;

    // First derive epoch 0 key so we can send a message in epoch 0
    revoke.deriveEpochKey(threadKey, 0).then(function (epoch0Key) {
        // Send a message in epoch 0
        return new Promise(function (r) {
            Q.Safecloud.Chat.send({
                threadId: THREAD_ID, epochKey: epoch0Key, epochIndex: 0,
                text: 'pre-revoke message', drops: drops
            }, function (e, s) {
                if (e) { checkErr('revokeAndRekey: pre-revoke send', e); return r(); }
                r(s.cid);
            });
        });
    }).then(function (preRevokeCid) {
        // Now revoke and rekey
        revoke.revokeAndRekey({
            threadId:          THREAD_ID,
            threadKey:         threadKey,
            currentEpochIndex: 0,
            drops:             drops
        }, function (err, result) {
            if (err) { checkErr('revokeAndRekey', err); return resolve(); }

            check('revokeAndRekey: no error', !err);
            check('revokeAndRekey: newEpochIndex is 1', result.newEpochIndex === 1);
            check('revokeAndRekey: newEpochKey is 32 bytes', result.newEpochKey.length === 32);
            check('revokeAndRekey: forwardCid is string', typeof result.forwardCid === 'string');
            check('revokeAndRekey: newEpochKeyCid is string', typeof result.newEpochKeyCid === 'string');

            var newKey = result.newEpochKey;

            // Can send/receive with new epoch key
            Q.Safecloud.Chat.send({
                threadId: THREAD_ID, epochKey: newKey, epochIndex: 1,
                text: 'post-revoke message', drops: drops
            }, function (e2, sent2) {
                if (e2) { checkErr('revokeAndRekey: post-revoke send', e2); return resolve(); }

                Q.Safecloud.Chat.receive(sent2.cid, newKey, 1, { drops: drops },
                function (e3, env) {
                    if (e3) { checkErr('revokeAndRekey: post-revoke receive', e3); return resolve(); }
                    check('post-revoke message decrypts', env.text === 'post-revoke message');
                });

                // Revoked member (only has epoch 0 key) CANNOT read new messages
                revoke.deriveEpochKey(threadKey, 0).then(function (epoch0Key) {
                    Q.Safecloud.Chat.receive(sent2.cid, epoch0Key, 0, { drops: drops },
                    function (e4) {
                        check('revoked member cannot decrypt new message', !!e4,
                            'should have failed');
                        resolve();
                    });
                });
            });
        });
    }).catch(function (err) {
        checkErr('revokeAndRekey: setup', err);
        resolve();
    });
});
allTests.push(t5);

// ─────────────────────────────────────────────────────────────────────────────
// 6. forwardChain.follow on a non-forward-chain Drop → returns current state
// ─────────────────────────────────────────────────────────────────────────────

var t6 = new Promise(function (resolve) {
    var drops  = makeDropStore();
    var epoch0 = new Uint8Array(crypto.randomBytes(32));

    // Send a regular message Drop, then try to follow it as a forward chain
    Q.Safecloud.Chat.send({
        threadId: THREAD_ID, epochKey: epoch0, epochIndex: 0,
        text: 'regular message', drops: drops
    }, function (e, s) {
        if (e) { checkErr('follow non-chain drop: send', e); return resolve(); }

        Q.Safecloud.Chat.forwardChain.follow(
            s.cid, epoch0, 0, { drops: drops },
            function (err, state) {
                // A regular message decrypts fine but is not a forward_chain type
                // so follow should return the same epoch unchanged
                if (err) { checkErr('follow non-chain drop', err); return resolve(); }
                check('follow non-chain: epochIndex unchanged', state.epochIndex === 0,
                    'got ' + state.epochIndex);
                resolve();
            }
        );
    });
});
allTests.push(t6);

// ─────────────────────────────────────────────────────────────────────────────

Promise.all(allTests).then(function () {
    console.log('\n' + (fail ? '✗' : '✓') + ' ' + pass + ' passed, ' + fail + ' failed');
    process.exit(fail ? 1 : 0);
}).catch(function (err) {
    console.error('Fatal test error:', err);
    process.exit(2);
});
