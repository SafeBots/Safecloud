/**
 * AdaptiveStreamer unit tests — tier classification, EMA tracking,
 * payment ramping, in-flight management, and edge cases.
 *
 * Runs in Node.js with a minimal Q shim — no browser APIs needed.
 * The AdaptiveStreamer is loaded by extracting its constructor from
 * the Q.exports wrapper.
 */
const path = require('path');
let pass = 0, fail = 0;
function check(n, c, d) {
    c ? (pass++, console.log('  ✓', n))
      : (fail++, console.log('  ✗ FAIL:', n, d ? ('— ' + d) : ''));
}
function section(t) { console.log('\n── ' + t + ' ──'); }

// ── Minimal Q shim ──────────────────────────────────────────────────────────

const configStore = { Safecloud: { adaptive: {} } };
const Q = {
    Config: {
        get: function (k, d) {
            var o = configStore;
            for (var i = 0; i < k.length; i++) {
                if (o == null) return d;
                o = o[k[i]];
            }
            return o === undefined ? d : o;
        }
    },
    log: function () {},
    Safecloud: { Jets: { get: function () { return Promise.resolve(null); } } }
};

// ── Load AdaptiveStreamer via its Q.exports wrapper ──────────────────────────

let AdaptiveStreamer;
const srcPath = path.join(process.cwd(),
    'web/js/methods/Safecloud/Client/AdaptiveStreamer.js');

// The file calls Q.exports(function(Q, _) { ... return AdaptiveStreamer; });
// We intercept Q.exports to extract the constructor.
const origCode = require('fs').readFileSync(srcPath, 'utf8');

// Build a module-level scope with Q.exports as our hook, plus performance shim
const fakeExports = { value: null };
const moduleScope = new Function('Q', 'performance', 'setTimeout', 'clearTimeout', 'Promise',
    origCode.replace('Q.exports(', '(') + '\n;return arguments[0];'
);

// performance.now shim for Node
const { performance } = require('perf_hooks');

try {
    // The IIFE pattern: Q.exports(function(Q, _) { ... return Ctor; })
    // After our replacement it becomes: (function(Q, _) { ... return Ctor; })
    // We need to call it with (Q, {}) to get the constructor.
    // Actually the pattern is: Q.exports(fn) where fn receives (Q, _)
    // Let's parse it differently — extract the factory function.
    const factoryMatch = origCode.match(/Q\.exports\(function\s*\(Q,\s*_\)\s*\{/);
    if (!factoryMatch) throw new Error('Could not find Q.exports factory');

    // Provide chunkLinkPath on the _ scope (used in probe)
    const underscoreMethods = {
        chunkLinkPath: function (idx) { return ['chunks', idx]; }
    };

    // Override Q.exports to capture the returned constructor
    const fakeQ = Object.assign({}, Q, {
        exports: function (factory) {
            AdaptiveStreamer = factory(Q, underscoreMethods);
        }
    });

    // Execute the file source in a sandboxed scope
    const vm = require('vm');
    const sandbox = {
        Q: fakeQ, performance: performance,
        setTimeout: setTimeout, clearTimeout: clearTimeout,
        Promise: Promise, console: console,
        BigInt: BigInt, Math: Math, Date: Date,
        Object: Object, Array: Array, Number: Number
    };
    vm.runInNewContext(origCode, sandbox, { filename: srcPath });

    check('AdaptiveStreamer loads', typeof AdaptiveStreamer === 'function');
} catch (e) {
    check('AdaptiveStreamer loads', false, e.message);
    console.log('\n' + pass + ' passed, ' + fail + ' failed');
    process.exit(1);
}

// ── Helper: create a streamer with pre-populated drops ──────────────────────

function makeStreamer(dropConfigs, opts) {
    var s = new AdaptiveStreamer(
        { rootCid: 'test-cid', chunkCount: 20 },
        { grants: [] },
        opts || {}
    );
    s._probed = true; // skip actual network probe
    dropConfigs.forEach(function (dc) {
        s._drops[dc.id] = {
            dropId:          dc.id,
            emaBps:          dc.bps || 0,
            tier:            'fast',
            chunksDelivered: dc.delivered || 0,
            chunksFailed:    dc.failed || 0,
            lastMeasuredMs:  Date.now(),
            latencyMs:       dc.latency || 100,
            servingPolicy:   dc.policy || null
        };
    });
    s._classifyTiers();
    return s;
}

// ═════════════════════════════════════════════════════════════════════════════
// TIER CLASSIFICATION
// ═════════════════════════════════════════════════════════════════════════════

section('Tier classification — basic');

(function () {
    var s = makeStreamer([
        { id: 'fast1',  bps: 1000000 },  // 1 MB/s
        { id: 'fast2',  bps: 800000 },   // 800 KB/s — 80% of best → Fast
        { id: 'marg1',  bps: 200000 },   // 200 KB/s — 20% of best → Marginal
        { id: 'slow1',  bps: 50000 },    // 50 KB/s — 5% of best → Slow
        { id: 'dead',   bps: 0 }         // timeout → Slow
    ]);
    check('fast1 classified as fast', s._drops.fast1.tier === 'fast');
    check('fast2 classified as fast (80% of best)', s._drops.fast2.tier === 'fast');
    check('marg1 classified as marginal (20% of best)', s._drops.marg1.tier === 'marginal');
    check('slow1 classified as slow (5% of best)', s._drops.slow1.tier === 'slow');
    check('dead classified as slow (0 bps)', s._drops.dead.tier === 'slow');
    check('_ranked excludes slow drops', s._ranked.indexOf('slow1') < 0 && s._ranked.indexOf('dead') < 0);
    check('_ranked orders fast before marginal',
        s._ranked.indexOf('fast1') < s._ranked.indexOf('marg1'));
    check('_ranked orders higher bps first within fast tier',
        s._ranked.indexOf('fast1') < s._ranked.indexOf('fast2'));
})();

section('Tier classification — edge cases');

(function () {
    // All drops at exactly the same speed
    var s = makeStreamer([
        { id: 'a', bps: 500000 },
        { id: 'b', bps: 500000 },
        { id: 'c', bps: 500000 }
    ]);
    check('equal-speed drops all classified as fast',
        s._drops.a.tier === 'fast' && s._drops.b.tier === 'fast' && s._drops.c.tier === 'fast');

    // Single drop
    var s2 = makeStreamer([{ id: 'only', bps: 100000 }]);
    check('single drop classified as fast', s2._drops.only.tier === 'fast');
    check('single drop is in ranked list', s2._ranked.length === 1 && s2._ranked[0] === 'only');

    // All drops below minAcceptableBps (50 KB/s = 51200 bps)
    var s3 = makeStreamer([
        { id: 'x', bps: 10000 },
        { id: 'y', bps: 20000 }
    ]);
    check('all drops below minAcceptableBps classified as slow',
        s3._drops.x.tier === 'slow' && s3._drops.y.tier === 'slow');
    check('ranked list empty when all are slow', s3._ranked.length === 0);

    // Empty drop set
    var s4 = makeStreamer([]);
    check('empty drop set does not crash _classifyTiers', s4._ranked.length === 0);
})();

section('Tier classification — threshold boundary');

(function () {
    // Drop at exactly 50% of best should be fast (>= fastThreshold)
    var s = makeStreamer([
        { id: 'best', bps: 1000000 },
        { id: 'half', bps: 500000 },
        { id: 'justBelow', bps: 499999 }
    ]);
    check('drop at exactly 50% of best is fast', s._drops.half.tier === 'fast');
    check('drop at 49.9999% of best is marginal', s._drops.justBelow.tier === 'marginal');

    // Drop at exactly 10% boundary
    var s2 = makeStreamer([
        { id: 'best', bps: 1000000 },
        { id: 'tenth', bps: 100000 },
        { id: 'justBelow10', bps: 99999 }
    ]);
    check('drop at exactly 10% of best is marginal', s2._drops.tenth.tier === 'marginal');
    check('drop below 10% of best is slow', s2._drops.justBelow10.tier === 'slow');
})();

// ═════════════════════════════════════════════════════════════════════════════
// EMA TRACKING
// ═════════════════════════════════════════════════════════════════════════════

section('EMA tracking — recordResult');

(function () {
    var s = makeStreamer([
        { id: 'd1', bps: 500000 },
        { id: 'd2', bps: 500000 }
    ]);

    var before = s._drops.d1.emaBps;
    // Record a fast result: 1 MB transferred in 500ms = 2 MB/s
    s.recordResult('d1', true, 1000000, 500);
    var after = s._drops.d1.emaBps;
    check('successful result with higher throughput raises EMA', after > before,
        before + ' → ' + after);

    // Record a failure
    var beforeFail = s._drops.d2.emaBps;
    s.recordResult('d2', false, 0, 0);
    var afterFail = s._drops.d2.emaBps;
    check('failure halves EMA (asymmetric decay)', afterFail === beforeFail * 0.5,
        beforeFail + ' → ' + afterFail);

    // Multiple failures drive toward zero
    for (var i = 0; i < 20; i++) { s.recordResult('d2', false, 0, 0); }
    check('repeated failures drive EMA near zero', s._drops.d2.emaBps < 1,
        String(s._drops.d2.emaBps));
})();

section('EMA tracking — demotion and promotion');

(function () {
    var s = makeStreamer([
        { id: 'good', bps: 1000000 },
        { id: 'degrades', bps: 800000 }
    ]);
    check('degrades starts as fast', s._drops.degrades.tier === 'fast');

    // Simulate degradation: several slow results
    for (var i = 0; i < 10; i++) {
        s.recordResult('degrades', true, 10000, 1000); // 10 KB/s
    }
    check('after degradation, degrades is demoted from fast',
        s._drops.degrades.tier !== 'fast',
        'tier: ' + s._drops.degrades.tier);

    // Simulate recovery
    for (var i = 0; i < 15; i++) {
        s.recordResult('degrades', true, 1000000, 500); // 2 MB/s
    }
    check('after recovery, degrades is promoted back to fast',
        s._drops.degrades.tier === 'fast',
        'tier: ' + s._drops.degrades.tier + ' bps: ' + s._drops.degrades.emaBps);
})();

section('EMA tracking — unknown dropId');

(function () {
    var s = makeStreamer([{ id: 'd1', bps: 500000 }]);
    // Should not throw
    s.recordResult('nonexistent', true, 100000, 100);
    check('recordResult for unknown dropId does not throw', true);
})();

// ═════════════════════════════════════════════════════════════════════════════
// DROP ASSIGNMENT
// ═════════════════════════════════════════════════════════════════════════════

section('assignDrop — selection logic');

(function () {
    var s = makeStreamer([
        { id: 'best',   bps: 1000000 },
        { id: 'second', bps: 700000 },
        { id: 'slow',   bps: 30000 }  // below min → slow tier
    ]);

    var assigned = s.assignDrop();
    check('assignDrop returns the best fast drop', assigned === 'best',
        'got: ' + assigned);

    // Fill up best's in-flight slots
    for (var i = 0; i < 3; i++) { s.startFetch('best'); }
    var next = s.assignDrop();
    check('when best is full, assignDrop returns second', next === 'second',
        'got: ' + next);

    // Fill up second too
    for (var i = 0; i < 3; i++) { s.startFetch('second'); }
    var none = s.assignDrop();
    check('when all fast/marginal are full, returns null', none === null);

    // Free one slot
    s.endFetch('best');
    var freed = s.assignDrop();
    check('after endFetch, slot is available again', freed === 'best');
})();

section('assignDrop — slow drops are never assigned');

(function () {
    var s = makeStreamer([
        { id: 'onlySlow', bps: 10000 }
    ]);
    var assigned = s.assignDrop();
    check('slow-only pool returns null', assigned === null);
})();

// ═════════════════════════════════════════════════════════════════════════════
// PAYMENT RAMPING
// ═════════════════════════════════════════════════════════════════════════════

section('Payment ramping — maxUnpaidFor schedule');

(function () {
    var s = makeStreamer([
        { id: 'p1', bps: 500000, delivered: 0 },
        { id: 'p2', bps: 500000, delivered: 5 },
        { id: 'p3', bps: 500000, delivered: 50 },
        { id: 'p4', bps: 500000, delivered: 150 }
    ]);

    check('probe phase (0 delivered): maxUnpaid = 1', s.maxUnpaidFor('p1') === 1);
    check('ramp-up phase (5 delivered): maxUnpaid = 3', s.maxUnpaidFor('p2') === 3);
    check('steady phase (50 delivered): maxUnpaid = 8', s.maxUnpaidFor('p3') === 8);
    check('trusted phase (150 delivered): maxUnpaid = 16', s.maxUnpaidFor('p4') === 16);
    check('unknown drop: maxUnpaid = 1', s.maxUnpaidFor('unknown') === 1);
})();

section('Payment ramping — boundary values');

(function () {
    var s = makeStreamer([
        { id: 'at1',   bps: 500000, delivered: 1 },
        { id: 'at2',   bps: 500000, delivered: 2 },
        { id: 'at9',   bps: 500000, delivered: 9 },
        { id: 'at10',  bps: 500000, delivered: 10 },
        { id: 'at99',  bps: 500000, delivered: 99 },
        { id: 'at100', bps: 500000, delivered: 100 }
    ]);
    check('1 delivered: maxUnpaid = 1 (still probe)', s.maxUnpaidFor('at1') === 1);
    check('2 delivered: maxUnpaid = 3 (enters ramp-up)', s.maxUnpaidFor('at2') === 3);
    check('9 delivered: maxUnpaid = 3 (still ramp-up)', s.maxUnpaidFor('at9') === 3);
    check('10 delivered: maxUnpaid = 8 (enters steady)', s.maxUnpaidFor('at10') === 8);
    check('99 delivered: maxUnpaid = 8 (still steady)', s.maxUnpaidFor('at99') === 8);
    check('100 delivered: maxUnpaid = 16 (enters trusted)', s.maxUnpaidFor('at100') === 16);
})();

section('Payment ramping — throttle and settlement');

(function () {
    var s = makeStreamer([{ id: 't1', bps: 500000, delivered: 0 }]);

    check('no payments recorded: shouldThrottle = false', !s.shouldThrottle('t1'));

    s.recordDelivery('t1');
    check('1 unpaid with maxUnpaid=1: shouldThrottle = true', s.shouldThrottle('t1'));

    s.recordSettlement('t1', '1000');
    check('after settlement: shouldThrottle = false', !s.shouldThrottle('t1'));
    check('watermark advances to settlement value',
        s._payments.t1.watermark === BigInt(1000));
    check('unpaidCount resets to 0 after settlement', s._payments.t1.unpaidCount === 0);
})();

section('Payment ramping — per-drop line indices');

(function () {
    var s = makeStreamer([
        { id: 'a', bps: 500000 },
        { id: 'b', bps: 500000 },
        { id: 'c', bps: 500000 }
    ]);
    s.recordDelivery('a');
    s.recordDelivery('b');
    s.recordDelivery('c');
    check('first drop gets line index 1', s._payments.a.lineIndex === 1);
    check('second drop gets line index 2', s._payments.b.lineIndex === 2);
    check('third drop gets line index 3', s._payments.c.lineIndex === 3);
})();

// ═════════════════════════════════════════════════════════════════════════════
// IN-FLIGHT TRACKING
// ═════════════════════════════════════════════════════════════════════════════

section('In-flight tracking');

(function () {
    var s = makeStreamer([{ id: 'f1', bps: 500000 }]);
    check('initial in-flight is 0', (s._inFlight.f1 || 0) === 0);

    s.startFetch('f1');
    check('after startFetch: in-flight = 1', s._inFlight.f1 === 1);

    s.startFetch('f1');
    s.startFetch('f1');
    check('after 3x startFetch: in-flight = 3', s._inFlight.f1 === 3);

    s.endFetch('f1');
    check('after endFetch: in-flight = 2', s._inFlight.f1 === 2);

    // endFetch past zero
    s.endFetch('f1');
    s.endFetch('f1');
    s.endFetch('f1'); // this should not go negative
    check('endFetch past zero does not go negative', (s._inFlight.f1 || 0) >= 0);
})();

// ═════════════════════════════════════════════════════════════════════════════
// STATS AND ACCESSORS
// ═════════════════════════════════════════════════════════════════════════════

section('Stats and accessors');

(function () {
    var s = makeStreamer([
        { id: 'f1', bps: 1000000, delivered: 10 },
        { id: 'f2', bps: 800000,  delivered: 5 },
        { id: 'm1', bps: 200000,  delivered: 2 },
        { id: 's1', bps: 10000,   delivered: 0 }
    ]);

    var stats = s.stats();
    check('stats() returns non-slow drops only', stats.length === 3,
        'got ' + stats.length);
    check('stats() entries have expected shape',
        stats[0].dropId && stats[0].tier && stats[0].emaBps !== undefined);

    var fast = s.fastDrops();
    check('fastDrops() returns only fast-tier drops',
        fast.every(function (id) { return s._drops[id].tier === 'fast'; }),
        fast.join(', '));
})();

section('onDropStats callback');

(function () {
    var callCount = 0;
    var lastStats = null;
    var s = makeStreamer(
        [{ id: 'd1', bps: 500000 }, { id: 'd2', bps: 300000 }],
        { onDropStats: function (stats) { callCount++; lastStats = stats; } }
    );
    // _classifyTiers was called in makeStreamer, which calls _emitStats
    // but our onDropStats was set after construction... let's force it
    s._onDropStats = function (stats) { callCount++; lastStats = stats; };
    s.recordResult('d1', true, 500000, 500);
    check('onDropStats called on recordResult', callCount >= 1);
    check('onDropStats receives array with drop info',
        Array.isArray(lastStats) && lastStats.length === 2);
})();

// ═════════════════════════════════════════════════════════════════════════════
// DESTROY
// ═════════════════════════════════════════════════════════════════════════════

section('Destroy cleanup');

(function () {
    var s = makeStreamer([
        { id: 'd1', bps: 1000000 },
        { id: 'd2', bps: 500000 }
    ]);
    s.startFetch('d1');
    s.recordDelivery('d1');
    s.destroy();
    check('after destroy: _drops is empty', Object.keys(s._drops).length === 0);
    check('after destroy: _ranked is empty', s._ranked.length === 0);
    check('after destroy: _inFlight is empty', Object.keys(s._inFlight).length === 0);
    check('after destroy: _payments is empty', Object.keys(s._payments).length === 0);
    check('after destroy: _destroyed is true', s._destroyed === true);
})();

// ═════════════════════════════════════════════════════════════════════════════
// STRESS / ADVERSARIAL
// ═════════════════════════════════════════════════════════════════════════════

section('Stress — large drop set');

(function () {
    var drops = [];
    for (var i = 0; i < 100; i++) {
        drops.push({ id: 'drop' + i, bps: Math.random() * 2000000 + 51200 });
    }
    var s = makeStreamer(drops);
    var fastCount = s.fastDrops().length;
    var totalRanked = s._ranked.length;
    check('100 drops: some are classified fast', fastCount > 0,
        'fast: ' + fastCount + ', ranked: ' + totalRanked);
    check('100 drops: ranked list is sorted by tier then bps', (function () {
        for (var i = 1; i < s._ranked.length; i++) {
            var prev = s._drops[s._ranked[i-1]];
            var curr = s._drops[s._ranked[i]];
            if (prev.tier === 'fast' && curr.tier === 'marginal') continue;
            if (prev.tier === curr.tier && prev.emaBps < curr.emaBps) return false;
        }
        return true;
    })());

    // Many recordResults should not crash
    for (var j = 0; j < 500; j++) {
        var dropId = 'drop' + Math.floor(Math.random() * 100);
        s.recordResult(dropId, Math.random() > 0.2, Math.floor(Math.random() * 500000), Math.floor(Math.random() * 2000) + 1);
    }
    check('500 random recordResults do not crash', true);
    check('ranked list is still valid after churn',
        s._ranked.every(function (id) { return s._drops[id] && s._drops[id].tier !== 'slow'; }));
})();

// ═════════════════════════════════════════════════════════════════════════════
// DONE
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
