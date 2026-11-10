/**
 * Tests for:
 *   - Q.Safecloud.Client.topics (Innovation 4 — Spatial/Topic Trees)
 *   - Q.Safecloud.Client.grant.timeRange (Innovation 3 — Temporal Trees)
 *
 *   node tests/chat_topics_grant.test.js
 */

'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// HKDF and crypto shim (same approach as other test files)
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

// ─────────────────────────────────────────────────────────────────────────────
// Q shim
// ─────────────────────────────────────────────────────────────────────────────

var delegateCount = 0;

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
        }
    },
    Crypto: {
        // Minimal delegate shim: derive secret via HKDF, produce a stub proof
        delegate: function (opts) {
            delegateCount++;
            var secretIn = opts.rootSecret;
            var label    = opts.label    || '';
            var context  = opts.context  || '{}';
            var info = label + '|' + context;
            var derived  = hkdf(Buffer.from(secretIn), info, 32);
            return Promise.resolve({
                secret:    new Uint8Array(derived),
                statement: { label: label, context: context, delegateCount: delegateCount },
                proof:     { signature: new Uint8Array(32), publicKey: new Uint8Array(32) }
            });
        }
    },
    extend: function (target) {
        for (var i = 1; i < arguments.length; i++) {
            var src = arguments[i];
            if (src) { Object.keys(src).forEach(function (k) { target[k] = src[k]; }); }
        }
        return target;
    },
    log: function () {}
};

function loadQModule(relPath, namespace) {
    var code = fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
    var exported;
    var localQ = Object.assign({}, Q, {
        exports: function (fn) { exported = fn(localQ, namespace || {}); }
    });
    // eslint-disable-next-line no-new-func
    new Function('Q', 'crypto', code)(localQ, globalThis.crypto);
    return exported;
}

// Load _internal.js to get the _ helpers
var _internal = loadQModule('web/js/methods/Safecloud/Client/_internal.js');

// Patch Q with the Safecloud namespace so modules can reference Q.Safecloud.Client
Q.Safecloud = { Client: { _internal: _internal } };

// Load topics.js and grant.js with the _ namespace
var Topics = loadQModule('web/js/methods/Safecloud/Client/topics.js', _internal);
var Grant  = loadQModule('web/js/methods/Safecloud/Client/grant.js',  _internal);

// Wire grant back so recursive calls inside grant.js work
Q.Safecloud.Client.grant = Grant;

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

// A fake chat root (would normally come from deriveChatRoot)
var CHAT_ROOT = new Uint8Array(crypto.randomBytes(32));

// ─────────────────────────────────────────────────────────────────────────────
// 1. Topics.create
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Topics.create ──');

var allTests = [];

var t1 = Topics.create(CHAT_ROOT, ['sports'])
    .then(function (del) {
        check('create: returns secret Uint8Array', del.secret instanceof Uint8Array);
        check('create: secret is 32 bytes', del.secret.length === 32);
        check('create: statement has label', typeof del.statement.label === 'string');
    })
    .catch(function (err) { checkErr('create basic', err); });
allTests.push(t1);

// Two-level path
var t2 = Topics.create(CHAT_ROOT, ['sports', 'football'])
    .then(function (del) {
        check('create nested: 32 bytes', del.secret.length === 32);
    })
    .catch(function (err) { checkErr('create nested', err); });
allTests.push(t2);

// Parent grant ≠ child grant
var t3 = Promise.all([
    Topics.create(CHAT_ROOT, ['sports']),
    Topics.create(CHAT_ROOT, ['sports', 'football'])
]).then(function (results) {
    var sA = Buffer.from(results[0].secret).toString('hex');
    var sB = Buffer.from(results[1].secret).toString('hex');
    check('parent ≠ child secret', sA !== sB);
})
.catch(function (err) { checkErr('parent vs child', err); });
allTests.push(t3);

// Deterministic — same path → same secret
var t4 = Promise.all([
    Topics.create(CHAT_ROOT, ['news', 'tech']),
    Topics.create(CHAT_ROOT, ['news', 'tech'])
]).then(function (results) {
    var sA = Buffer.from(results[0].secret).toString('hex');
    var sB = Buffer.from(results[1].secret).toString('hex');
    check('create: deterministic', sA === sB);
})
.catch(function (err) { checkErr('deterministic', err); });
allTests.push(t4);

// Different roots → different secrets
var OTHER_ROOT = new Uint8Array(crypto.randomBytes(32));
var t5 = Promise.all([
    Topics.create(CHAT_ROOT, ['news']),
    Topics.create(OTHER_ROOT, ['news'])
]).then(function (results) {
    var sA = Buffer.from(results[0].secret).toString('hex');
    var sB = Buffer.from(results[1].secret).toString('hex');
    check('different roots → different secrets', sA !== sB);
})
.catch(function (err) { checkErr('different roots', err); });
allTests.push(t5);

// ─────────────────────────────────────────────────────────────────────────────
// 2. Topics.grant
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Topics.grant ──');

var t6 = new Promise(function (resolve) {
    Topics.grant(CHAT_ROOT, ['engineering'], {}, function (err, g) {
        if (err) { checkErr('grant basic', err); return resolve(); }
        check('grant: no error', !err);
        check('grant: topicPath matches', JSON.stringify(g.topicPath) === JSON.stringify(['engineering']));
        check('grant: secret is base64 string', typeof g.secret === 'string' && g.secret.length > 0);
        check('grant: readLevel default', g.readLevel === 'content');
        check('grant: proof.signature is string', typeof (g.proof && g.proof.signature) === 'string');
        resolve();
    });
});
allTests.push(t6);

// grant with explicit readLevel and exp
var t7 = new Promise(function (resolve) {
    Topics.grant(CHAT_ROOT, ['vip'], { readLevel: 'admin', exp: 9999999999 }, function (err, g) {
        if (err) { checkErr('grant with options', err); return resolve(); }
        check('grant options: readLevel', g.readLevel === 'admin');
        check('grant options: topicPath', JSON.stringify(g.topicPath) === JSON.stringify(['vip']));
        resolve();
    });
});
allTests.push(t7);

// ─────────────────────────────────────────────────────────────────────────────
// 3. Topics.list
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Topics.list ──');

var t8 = new Promise(function (resolve) {
    Topics.grant(CHAT_ROOT, ['a', 'b', 'c'], {}, function (err, g) {
        if (err) { checkErr('list setup', err); return resolve(); }
        var info = Topics.list(g);
        check('list: topicPath correct', JSON.stringify(info.topicPath) === JSON.stringify(['a', 'b', 'c']));
        check('list: readLevel', info.readLevel === 'content');
        resolve();
    });
});
allTests.push(t8);

// list with invalid grant
try {
    Topics.list({ notAGrant: true });
    check('list: throws on invalid', false, 'should have thrown');
} catch (e) {
    check('list: throws on invalid', e.message.includes('topicPath'));
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Topics path validation
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── Topics path validation ──');

var t9 = Topics.create(CHAT_ROOT, [])
    .then(function () { check('empty path throws', false, 'should reject'); })
    .catch(function (e) { check('empty path rejects', e.message.includes('non-empty')); });
allTests.push(t9);

var t10 = Topics.create(CHAT_ROOT, ['UPPERCASE'])
    .then(function () { check('uppercase throws', false, 'should reject'); })
    .catch(function (e) { check('uppercase rejects', e.message.includes('invalid')); });
allTests.push(t10);

var t11 = Topics.create(CHAT_ROOT, ['has.dot'])
    .then(function () { check('dot in segment throws', false, 'should reject'); })
    .catch(function (e) { check('dot rejects', e.message.includes('invalid')); });
allTests.push(t11);

// Hyphens are OK
var t12 = Topics.create(CHAT_ROOT, ['my-channel', 'sub-topic'])
    .then(function (del) { check('hyphens OK', del.secret.length === 32); })
    .catch(function (err) { checkErr('hyphens', err); });
allTests.push(t12);

// ─────────────────────────────────────────────────────────────────────────────
// 5. grant.timeRange
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── grant.timeRange ──');

// Single-day grant
var t13 = new Promise(function (resolve) {
    Grant.timeRange(CHAT_ROOT, {
        startDate:   new Date('2026-03-15'),
        endDate:     new Date('2026-03-15'),
        granularity: 'day'
    }, function (err, result) {
        if (err) { checkErr('timeRange single day', err); return resolve(); }
        check('timeRange single day: no error', !err);
        check('timeRange single day: 1 path', result.timePaths.length === 1,
            'got ' + result.timePaths.length);
        check('timeRange single day: 1 grant', result.grants.length === 1);
        check('timeRange single day: grant has secret', typeof result.grants[0].secret === 'string');
        check('timeRange single day: timePath in grant', Array.isArray(result.grants[0].timePath));
        resolve();
    });
});
allTests.push(t13);

// Multi-day grant
var t14 = new Promise(function (resolve) {
    Grant.timeRange(CHAT_ROOT, {
        startDate:   new Date('2026-01-01'),
        endDate:     new Date('2026-01-03'),
        granularity: 'day'
    }, function (err, result) {
        if (err) { checkErr('timeRange multi-day', err); return resolve(); }
        check('timeRange 3 days: 3 paths', result.timePaths.length === 3,
            'got ' + result.timePaths.length);
        check('timeRange 3 days: 3 grants', result.grants.length === 3);
        check('timeRange: startDate echoed', result.startDate instanceof Date);
        resolve();
    });
});
allTests.push(t14);

// Month granularity
var t15 = new Promise(function (resolve) {
    Grant.timeRange(CHAT_ROOT, {
        startDate:   new Date('2026-01-01'),
        endDate:     new Date('2026-03-31'),
        granularity: 'month'
    }, function (err, result) {
        if (err) { checkErr('timeRange month', err); return resolve(); }
        check('timeRange 3 months: 3 paths', result.timePaths.length === 3,
            'got ' + result.timePaths.length);
        resolve();
    });
});
allTests.push(t15);

// Year granularity — full year = 1 path
var t16 = new Promise(function (resolve) {
    Grant.timeRange(CHAT_ROOT, {
        startDate:   new Date('2026-01-01'),
        endDate:     new Date('2026-12-31'),
        granularity: 'year'
    }, function (err, result) {
        if (err) { checkErr('timeRange year', err); return resolve(); }
        check('timeRange year: 1 path', result.timePaths.length === 1,
            'got ' + result.timePaths.length);
        check('timeRange year: grant timePath starts with time label',
            result.grants[0].timePath[0].includes('time'));
        resolve();
    });
});
allTests.push(t16);

// Error: endDate < startDate
var t17 = new Promise(function (resolve) {
    Grant.timeRange(CHAT_ROOT, {
        startDate: new Date('2026-12-31'),
        endDate:   new Date('2026-01-01')
    }, function (err) {
        check('timeRange: endDate < startDate returns error', !!err && err.message.includes('endDate'));
        resolve();
    });
});
allTests.push(t17);

// Two different day grants → different secrets
var t18 = new Promise(function (resolve) {
    Promise.all([
        new Promise(function (r) {
            Grant.timeRange(CHAT_ROOT, {
                startDate: new Date('2026-06-01'), endDate: new Date('2026-06-01')
            }, function (e, res) { r(res); });
        }),
        new Promise(function (r) {
            Grant.timeRange(CHAT_ROOT, {
                startDate: new Date('2026-06-02'), endDate: new Date('2026-06-02')
            }, function (e, res) { r(res); });
        })
    ]).then(function (results) {
        var s1 = results[0].grants[0].secret;
        var s2 = results[1].grants[0].secret;
        check('timeRange: different days → different secrets', s1 !== s2);
        resolve();
    }).catch(function (err) { checkErr('different days', err); resolve(); });
});
allTests.push(t18);

// Same day → same secret (deterministic)
var t19 = new Promise(function (resolve) {
    Promise.all([
        new Promise(function (r) {
            Grant.timeRange(CHAT_ROOT, {
                startDate: new Date('2026-06-15'), endDate: new Date('2026-06-15')
            }, function (e, res) { r(res); });
        }),
        new Promise(function (r) {
            Grant.timeRange(CHAT_ROOT, {
                startDate: new Date('2026-06-15'), endDate: new Date('2026-06-15')
            }, function (e, res) { r(res); });
        })
    ]).then(function (results) {
        var s1 = results[0].grants[0].secret;
        var s2 = results[1].grants[0].secret;
        check('timeRange: same day → same secret', s1 === s2);
        resolve();
    }).catch(function (err) { checkErr('same day deterministic', err); resolve(); });
});
allTests.push(t19);

// ─────────────────────────────────────────────────────────────────────────────

Promise.all(allTests).then(function () {
    console.log('\n' + (fail ? '✗' : '✓') + ' ' + pass + ' passed, ' + fail + ' failed');
    process.exit(fail ? 1 : 0);
}).catch(function (err) {
    console.error('Fatal test error:', err);
    process.exit(2);
});
