/**
 * Tests for Safecloud Chat send/receive round-trip and key derivation.
 *
 * Uses a pure Node.js crypto shim to exercise send.js / receive.js logic
 * without a running Q platform.
 *
 *   node tests/chat_send_receive.test.js
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
// Minimal Q shim matching the APIs used by send.js / receive.js
// ─────────────────────────────────────────────────────────────────────────────

// CID = hex(SHA-256(ciphertext || tag))  (same formula used in Drops.store)
function computeCid(ciphertextB64, tagB64) {
    var ct  = Buffer.from(ciphertextB64, 'base64');
    var tag = Buffer.from(tagB64, 'base64');
    var buf = Buffer.concat([ct, tag]);
    return crypto.createHash('sha256').update(buf).digest('hex');
}

// In-memory drops store
var dropsStore = {};

var FakeDrops = {
    store: function (drop) {
        // drop = { ciphertext: b64, tag: b64, iv: b64 }
        var cid = computeCid(drop.ciphertext, drop.tag);
        dropsStore[cid] = drop;
        return Promise.resolve({ cid: cid });
    },
    fetch: function (cid) {
        return Promise.resolve(dropsStore[cid] || null);
    }
};

// HKDF-SHA256 (matches Q.Crypto.delegate / Q.Data.derive expected behavior)
function hkdf(secretBytes, info, length) {
    // Extract: PRK = HMAC-SHA256(salt=zeros, IKM=secret)
    var salt = Buffer.alloc(32, 0);
    var prk  = crypto.createHmac('sha256', salt).update(secretBytes).digest();
    // Expand: OKM = HMAC-SHA256(PRK, info || 0x01)[0..length]
    var infoBytes  = Buffer.from(info, 'utf8');
    var counter    = Buffer.from([1]);
    var okm        = crypto.createHmac('sha256', prk)
                           .update(Buffer.concat([infoBytes, counter]))
                           .digest();
    return okm.slice(0, length);
}

// AES-256-GCM helpers
function aesgcmEncrypt(keyBytes, ivBytes, plaintext) {
    var cipher = crypto.createCipheriv('aes-256-gcm', keyBytes, ivBytes);
    var ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
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
    var decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Q shim
var Q = {
    Data: {
        fromBase64: function (s) { return new Uint8Array(Buffer.from(s, 'base64')); },
        toBase64:   function (u) { return Buffer.from(u).toString('base64'); },
        derive: function (secretBytes, info, opts) {
            var size = (opts && opts.size) || 32;
            var buf  = Buffer.from(secretBytes);
            var out  = hkdf(buf, info, size);
            return Promise.resolve(new Uint8Array(out));
        },
        importKey: function (keyBytes) {
            // Returns an opaque handle — we just carry the bytes through
            return Promise.resolve({ _bytes: Buffer.from(keyBytes) });
        },
        encrypt: function (cryptoKey, plaintext, opts) {
            var iv = opts && opts.iv
                ? (Buffer.isBuffer(opts.iv) ? opts.iv : Buffer.from(opts.iv))
                : crypto.randomBytes(12);
            var enc = aesgcmEncrypt(cryptoKey._bytes, iv, Buffer.from(plaintext));
            return Promise.resolve(enc);
        },
        decrypt: function (cryptoKey, ivB64, ciphertextB64, opts) {
            var tagB64 = opts && opts.tag;
            try {
                var plain = aesgcmDecrypt(cryptoKey._bytes, ivB64, ciphertextB64, tagB64);
                return Promise.resolve(plain);
            } catch (e) {
                return Promise.reject(e);
            }
        }
    },
    Crypto: {},
    Streams: { message: function () {} },
    log: function () {},
    exports: function (fn) {
        // Q.exports(fn) — fn receives (Q, _) and returns the module export
        // For testing we don't need _ (internal helpers)
        return fn(Q, {});
    }
};

// Node 22 provides globalThis.crypto.getRandomValues natively — no polyfill needed.
// TextEncoder/TextDecoder are also available globally in Node 18+.

// ─────────────────────────────────────────────────────────────────────────────
// Load Chat.message, Chat.send, Chat.receive by evaluating with Q in scope
// ─────────────────────────────────────────────────────────────────────────────

var fs   = require('fs');
var path = require('path');

function loadQModule(relPath) {
    var code = fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
    // Q.exports(function(Q, _){ return export; })  →  we capture the return value
    var exported;
    var localQ = Object.assign({}, Q, {
        exports: function (fn) { exported = fn(Q, {}); }
    });
    // Pass localQ as Q and globalThis.crypto as crypto (available in Node 18+)
    // eslint-disable-next-line no-new-func
    new Function('Q', 'crypto', code)(localQ, globalThis.crypto);
    return exported;
}

// Bootstrap Q namespace for sub-module loading
Q.Safecloud = { Chat: {} };
Q.Safecloud.Chat.message  = loadQModule('web/js/methods/Safecloud/Chat/message.js');
Q.Safecloud.Chat.send     = loadQModule('web/js/methods/Safecloud/Chat/send.js');
Q.Safecloud.Chat.receive  = loadQModule('web/js/methods/Safecloud/Chat/receive.js');

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

var pass = 0, fail = 0;
function check(name, cond, detail) {
    if (cond) {
        pass++;
        console.log('  ✓', name);
    } else {
        fail++;
        console.log('  ✗ FAIL:', name, detail ? ('— ' + detail) : '');
    }
}
function checkErr(name, err) {
    fail++;
    console.log('  ✗ ERROR:', name, '—', err && err.message || err);
}

// Fake epoch key (32 random bytes)
var EPOCH_KEY = new Uint8Array(crypto.randomBytes(32));
var EPOCH_IDX = 0;
var THREAD_ID = 'test-thread-001';

// ─────────────────────────────────────────────────────────────────────────────
// 1. message.build / message.validate
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.message ──');

var msg = Q.Safecloud.Chat.message;

var env1 = msg.build({ threadId: THREAD_ID, epochIndex: 0, text: 'Hello!' });
check('build: type is Safecloud/chat/message', env1.type === 'Safecloud/chat/message');
check('build: threadId', env1.threadId === THREAD_ID);
check('build: epochIndex', env1.epochIndex === 0);
check('build: parentIds default []', Array.isArray(env1.parentIds) && env1.parentIds.length === 0);
check('build: text', env1.text === 'Hello!');
check('build: timestamp is number', typeof env1.timestamp === 'number');
check('build: senderHint default null', env1.senderHint === null);

var env2 = msg.build({ threadId: THREAD_ID, epochIndex: 2, text: 'Reply', parentIds: ['cid1'], senderHint: 'alice' });
check('build with parentIds + senderHint', env2.parentIds[0] === 'cid1' && env2.senderHint === 'alice');

check('validate: good envelope', msg.validate(env1) === true);
try { msg.validate({ type: 'wrong' }); check('validate: bad type throws', false); }
catch (e) { check('validate: bad type throws', e.message.includes('type')); }
try { msg.validate(null); check('validate: null throws', false); }
catch (e) { check('validate: null throws', true); }

// ─────────────────────────────────────────────────────────────────────────────
// 2. Chat.send — basic send
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.send ──');

var allTests = [];

var t1 = new Promise(function (resolve) {
    dropsStore = {};  // reset
    Q.Safecloud.Chat.send({
        threadId:   THREAD_ID,
        epochKey:   EPOCH_KEY,
        epochIndex: EPOCH_IDX,
        text:       'Hello world!',
        drops:      FakeDrops
    }, function (err, result) {
        if (err) { checkErr('send: basic round-trip', err); return resolve(); }
        check('send: no error', !err);
        check('send: result.cid is string', typeof result.cid === 'string');
        check('send: result.envelope.text', result.envelope.text === 'Hello world!');
        check('send: result.envelope.threadId', result.envelope.threadId === THREAD_ID);
        check('send: result.envelope.epochIndex', result.envelope.epochIndex === EPOCH_IDX);
        check('send: drop stored', !!dropsStore[result.cid]);
        var drop = dropsStore[result.cid];
        check('send: drop has ciphertext', typeof drop.ciphertext === 'string');
        check('send: drop has tag', typeof drop.tag === 'string');
        check('send: drop has iv', typeof drop.iv === 'string');
        resolve({ cid: result.cid });
    });
});

allTests.push(t1);

// ─────────────────────────────────────────────────────────────────────────────
// 3. Chat.receive — basic receive
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.receive ──');

var t2 = t1.then(function (sent) {
    if (!sent) { return; }

    return new Promise(function (resolve) {
        Q.Safecloud.Chat.receive(sent.cid, EPOCH_KEY, EPOCH_IDX, { drops: FakeDrops },
        function (err, env) {
            if (err) { checkErr('receive: decryption', err); return resolve(); }
            check('receive: no error', !err);
            check('receive: env.text matches', env.text === 'Hello world!');
            check('receive: env.threadId matches', env.threadId === THREAD_ID);
            check('receive: env.epochIndex matches', env.epochIndex === EPOCH_IDX);
            check('receive: env.type correct', env.type === 'Safecloud/chat/message');
            check('receive: env.parentIds is []', Array.isArray(env.parentIds) && env.parentIds.length === 0);
            resolve();
        });
    });
});

allTests.push(t2);

// ─────────────────────────────────────────────────────────────────────────────
// 4. Send/receive round-trip with parentIds and senderHint
// ─────────────────────────────────────────────────────────────────────────────

var t3 = new Promise(function (resolve) {
    var opts = {
        threadId:   THREAD_ID,
        epochKey:   EPOCH_KEY,
        epochIndex: 1,
        text:       'Reply to parent',
        parentIds:  ['Qm123', 'Qm456'],
        senderHint: 'bob',
        drops:      FakeDrops
    };
    Q.Safecloud.Chat.send(opts, function (err, sent) {
        if (err) { checkErr('round-trip with parentIds', err); return resolve(); }
        Q.Safecloud.Chat.receive(sent.cid, EPOCH_KEY, 1, { drops: FakeDrops }, function (err2, env) {
            if (err2) { checkErr('round-trip with parentIds receive', err2); return resolve(); }
            check('round-trip: parentIds preserved', JSON.stringify(env.parentIds) === '["Qm123","Qm456"]');
            check('round-trip: senderHint preserved', env.senderHint === 'bob');
            check('round-trip: epochIndex 1', env.epochIndex === 1);
            resolve();
        });
    });
});

allTests.push(t3);

// ─────────────────────────────────────────────────────────────────────────────
// 5. Receive with wrong epoch key → decryption error
// ─────────────────────────────────────────────────────────────────────────────

var t4 = new Promise(function (resolve) {
    // Send with one key
    var key1 = new Uint8Array(crypto.randomBytes(32));
    var key2 = new Uint8Array(crypto.randomBytes(32));

    Q.Safecloud.Chat.send({
        threadId: THREAD_ID, epochKey: key1, epochIndex: 0, text: 'Secret', drops: FakeDrops
    }, function (err, sent) {
        if (err) { checkErr('wrong key: send', err); return resolve(); }
        // Try to receive with key2
        Q.Safecloud.Chat.receive(sent.cid, key2, 0, { drops: FakeDrops }, function (err2) {
            check('receive with wrong key fails', !!err2, 'expected error but got success');
            resolve();
        });
    });
});

allTests.push(t4);

// ─────────────────────────────────────────────────────────────────────────────
// 6. Receive non-existent CID → null
// ─────────────────────────────────────────────────────────────────────────────

var t5 = new Promise(function (resolve) {
    Q.Safecloud.Chat.receive('nosuchcid', EPOCH_KEY, 0, { drops: FakeDrops }, function (err, env) {
        check('receive missing CID: no error', !err, err && err.message);
        check('receive missing CID: env is null', env === null);
        resolve();
    });
});

allTests.push(t5);

// ─────────────────────────────────────────────────────────────────────────────
// 7. Each message gets a unique IV (defence-in-depth, ciphertext uniqueness)
// ─────────────────────────────────────────────────────────────────────────────

var t6 = new Promise(function (resolve) {
    var key = new Uint8Array(crypto.randomBytes(32));
    var localStore = {};
    var localDrops = {
        store: function (d) {
            var cid = computeCid(d.ciphertext, d.tag);
            localStore[cid] = d;
            return Promise.resolve({ cid: cid });
        },
        fetch: function (cid) { return Promise.resolve(localStore[cid] || null); }
    };

    var sendOpts = function (text) { return {
        threadId: THREAD_ID, epochKey: key, epochIndex: 0, text: text, drops: localDrops
    }; };

    Promise.all([
        new Promise(function (r) {
            Q.Safecloud.Chat.send(sendOpts('msg A'), function (e, s) { r(s && s.cid); });
        }),
        new Promise(function (r) {
            Q.Safecloud.Chat.send(sendOpts('msg A'), function (e, s) { r(s && s.cid); }); // same text
        })
    ]).then(function (cids) {
        var d1 = localStore[cids[0]];
        var d2 = localStore[cids[1]];
        check('unique IVs: different IVs for same text', d1.iv !== d2.iv, d1.iv + ' vs ' + d2.iv);
        check('unique IVs: different ciphertexts', d1.ciphertext !== d2.ciphertext);
        resolve();
    });
});

allTests.push(t6);

// ─────────────────────────────────────────────────────────────────────────────
// 8. Chat.send input validation
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Chat.send input validation ──');

var t7 = new Promise(function (resolve) {
    var tests = [
        [{ epochKey: EPOCH_KEY, epochIndex: 0, text: 'x' }, 'threadId required'],
        [{ threadId: THREAD_ID, epochIndex: 0, text: 'x' }, 'epochKey required'],
        [{ threadId: THREAD_ID, epochKey: EPOCH_KEY, text: 'x' }, 'epochIndex required'],
        [{ threadId: THREAD_ID, epochKey: EPOCH_KEY, epochIndex: 0 }, 'text required']
    ];
    var pending = tests.length;
    tests.forEach(function (tc) {
        Q.Safecloud.Chat.send(tc[0], function (err) {
            check('validation: ' + tc[1], !!err && err.message.toLowerCase().includes(tc[1].split(' ')[0].toLowerCase()),
                err && err.message);
            if (--pending === 0) { resolve(); }
        });
    });
});

allTests.push(t7);

// ─────────────────────────────────────────────────────────────────────────────
// 9. Chat.receive input validation
// ─────────────────────────────────────────────────────────────────────────────

var t8 = new Promise(function (resolve) {
    var pending = 2;
    function done() { if (--pending === 0) resolve(); }

    Q.Safecloud.Chat.receive(null, EPOCH_KEY, 0, { drops: FakeDrops }, function (err) {
        check('receive validation: cid required', !!err && err.message.includes('cid'), err && err.message);
        done();
    });
    Q.Safecloud.Chat.receive('somecid', null, 0, { drops: FakeDrops }, function (err) {
        check('receive validation: epochKey required', !!err && err.message.includes('epochKey'), err && err.message);
        done();
    });
});

allTests.push(t8);

// ─────────────────────────────────────────────────────────────────────────────
// 10. Multiple epoch keys: messages from different epochs don't cross-decrypt
// ─────────────────────────────────────────────────────────────────────────────

var t9 = new Promise(function (resolve) {
    var key0 = new Uint8Array(crypto.randomBytes(32));
    var key1 = new Uint8Array(crypto.randomBytes(32));
    var localStore = {};
    var localDrops = {
        store: function (d) {
            var cid = computeCid(d.ciphertext, d.tag);
            localStore[cid] = d;
            return Promise.resolve({ cid: cid });
        },
        fetch: function (cid) { return Promise.resolve(localStore[cid] || null); }
    };

    // Send with epoch 0 key, try to decrypt with epoch 1 key
    Q.Safecloud.Chat.send({
        threadId: THREAD_ID, epochKey: key0, epochIndex: 0, text: 'epoch0 msg', drops: localDrops
    }, function (err, sent) {
        if (err) { checkErr('cross-epoch: send', err); return resolve(); }

        // Correctly decrypt with key0
        Q.Safecloud.Chat.receive(sent.cid, key0, 0, { drops: localDrops }, function (err1, env1) {
            check('cross-epoch: correct key decrypts', !err1 && env1.text === 'epoch0 msg');
        });

        // Incorrectly try key1
        Q.Safecloud.Chat.receive(sent.cid, key1, 0, { drops: localDrops }, function (err2) {
            check('cross-epoch: wrong key fails', !!err2);
            resolve();
        });
    });
});

allTests.push(t9);

// ─────────────────────────────────────────────────────────────────────────────
// Wait for all async tests then print summary
// ─────────────────────────────────────────────────────────────────────────────

Promise.all(allTests).then(function () {
    console.log('\n' + (fail ? '✗' : '✓') + ' ' + pass + ' passed, ' + fail + ' failed');
    process.exit(fail ? 1 : 0);
}).catch(function (err) {
    console.error('Fatal test error:', err);
    process.exit(2);
});
