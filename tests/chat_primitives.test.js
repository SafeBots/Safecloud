/**
 * Tests for Safecloud.ChatPrimitives — pure temporal/topic/DAG functions.
 *
 * Zero external dependencies (no Q shims needed).  Runs directly in Node.
 *
 *   node tests/chat_primitives.test.js
 */

'use strict';

const path = require('path');
const CP   = require(path.join(__dirname, '../classes/Safecloud/ChatPrimitives.js'));

let pass = 0, fail = 0;
function check(name, cond, detail) {
    if (cond) {
        pass++;
        console.log('  ✓', name);
    } else {
        fail++;
        console.log('  ✗ FAIL:', name, detail ? ('— ' + detail) : '');
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LABELS sanity
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── LABELS ──');
check('chatRoot label', CP.LABELS.chatRoot === 'safecloud.chat');
check('timeRoot label', CP.LABELS.timeRoot === 'safecloud.chat.time');
check('topicRoot label', CP.LABELS.topicRoot === 'safecloud.chat.topic');
check('epoch(0) label', CP.LABELS.epoch(0) === 'safecloud.chat.epoch.0');
check('epoch(7) label', CP.LABELS.epoch(7) === 'safecloud.chat.epoch.7');
check('chatThread label', CP.LABELS.chatThread('abc123') === 'safecloud.chat.thread.abc123');
check('timeYear(2026)', CP.LABELS.timeYear(2026) === 'safecloud.time.year.2026');
check('timeMonth(3) zero-padded', CP.LABELS.timeMonth(3) === 'safecloud.time.month.03');
check('timeMonth(12)', CP.LABELS.timeMonth(12) === 'safecloud.time.month.12');
check('timeWeek(1) zero-padded', CP.LABELS.timeWeek(1) === 'safecloud.time.week.01');
check('timeDay(5) zero-padded', CP.LABELS.timeDay(5) === 'safecloud.time.day.05');
check('topic("general")', CP.LABELS.topic('general') === 'safecloud.topic.general');

// ─────────────────────────────────────────────────────────────────────────────
// ISO WEEK NUMBER
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── isoWeek ──');
// 2026-01-01 is a Thursday — it's in week 1
check('2026-01-01 is week 1', CP.isoWeek(new Date('2026-01-01')) === 1,
    'got ' + CP.isoWeek(new Date('2026-01-01')));
// 2026-01-04 is a Sunday — still week 1
check('2026-01-04 (Sun) is week 1', CP.isoWeek(new Date('2026-01-04')) === 1);
// 2026-01-05 is Monday — start of week 2
check('2026-01-05 (Mon) is week 2', CP.isoWeek(new Date('2026-01-05')) === 2);
// 2026-12-28 is Monday — week 53
check('2026-12-28 (Mon) is week 53', CP.isoWeek(new Date('2026-12-28')) === 53);
// 2025-12-29 is Monday — week 1 of 2026
check('2025-12-29 is week 1 (of 2026)', CP.isoWeek(new Date('2025-12-29')) === 1,
    'got ' + CP.isoWeek(new Date('2025-12-29')));

// ─────────────────────────────────────────────────────────────────────────────
// timePath — label array construction
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── timePath ──');

var d = new Date('2026-03-15T12:00:00Z'); // Sunday, week 11, Q1

var pDay = CP.timePath(d, 'day');
check('day path length is 5', pDay.length === 5, 'got ' + pDay.length);
check('day[0] is timeRoot', pDay[0] === 'safecloud.chat.time');
check('day[1] is year 2026', pDay[1] === 'safecloud.time.year.2026');
check('day[2] is quarter 1', pDay[2] === 'safecloud.time.quarter.1');
check('day[3] is month 03', pDay[3] === 'safecloud.time.month.03');
check('day[4] is day 15', pDay[4] === 'safecloud.time.day.15');

var pMonth = CP.timePath(d, 'month');
check('month path length is 4', pMonth.length === 4);
check('month path ends with month.03', pMonth[3] === 'safecloud.time.month.03');

var pQuarter = CP.timePath(d, 'quarter');
check('quarter path length is 3', pQuarter.length === 3);
check('quarter path ends with quarter.1', pQuarter[2] === 'safecloud.time.quarter.1');

var pYear = CP.timePath(d, 'year');
check('year path length is 2', pYear.length === 2);
check('year path ends with year.2026', pYear[1] === 'safecloud.time.year.2026');

var pWeek = CP.timePath(d, 'week');
check('week path length is 4', pWeek.length === 4, 'got ' + pWeek.length);
check('week path[2] is quarter.1', pWeek[2] === 'safecloud.time.quarter.1');
check('week path ends with week.11', pWeek[3] === 'safecloud.time.week.11',
    'got ' + pWeek[3]);

// Q1 boundary: March 31 → Q1; April 1 → Q2
var q1end = CP.timePath(new Date('2026-03-31'), 'quarter');
var q2start = CP.timePath(new Date('2026-04-01'), 'quarter');
check('2026-03-31 is quarter 1', q1end[2] === 'safecloud.time.quarter.1');
check('2026-04-01 is quarter 2', q2start[2] === 'safecloud.time.quarter.2');

// String input
var pStr = CP.timePath('2026-03-15', 'month');
check('string date input works', pStr[3] === 'safecloud.time.month.03');

// Default granularity is 'day'
var pDefault = CP.timePath(d);
check('default granularity is day', pDefault.length === 5);

// ─────────────────────────────────────────────────────────────────────────────
// timePathsForRange
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── timePathsForRange ──');

// Single day
var r1 = CP.timePathsForRange(new Date('2026-03-15'), new Date('2026-03-15'), 'day');
check('single day: 1 path', r1.length === 1, 'got ' + r1.length);

// Three days
var r3 = CP.timePathsForRange(new Date('2026-03-13'), new Date('2026-03-15'), 'day');
check('3 days: 3 paths', r3.length === 3, 'got ' + r3.length);

// Same month, monthly granularity → 1 path
var rm = CP.timePathsForRange(new Date('2026-03-01'), new Date('2026-03-31'), 'month');
check('all of March at month granularity: 1 path', rm.length === 1, 'got ' + rm.length);

// Two months, monthly granularity → 2 paths
var rm2 = CP.timePathsForRange(new Date('2026-03-15'), new Date('2026-04-15'), 'month');
check('Mar–Apr at month granularity: 2 paths', rm2.length === 2, 'got ' + rm2.length);

// Weekly range spanning 2 weeks: Mar 7 (Sat, week 10) → Mar 9 (Mon, week 11)
var rw = CP.timePathsForRange(new Date('2026-03-07'), new Date('2026-03-09'), 'week');
check('Sat–Mon spanning weeks 10–11: 2 paths', rw.length === 2, 'got ' + rw.length);

// Quarter granularity spanning 2 quarters → 2 paths
var rq = CP.timePathsForRange(new Date('2026-03-01'), new Date('2026-04-01'), 'quarter');
check('Q1–Q2 boundary: 2 paths', rq.length === 2, 'got ' + rq.length);

// Order: paths should be chronological
var ro = CP.timePathsForRange(new Date('2026-01-01'), new Date('2026-03-01'), 'month');
check('month range is chronological', ro[0][3] === 'safecloud.time.month.01' && ro[2][3] === 'safecloud.time.month.03',
    JSON.stringify(ro.map(function(p){return p[3];})));

// ─────────────────────────────────────────────────────────────────────────────
// topicPath
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── topicPath ──');

var tp1 = CP.topicPath(['general']);
check('single-segment topic path', tp1.length === 2 && tp1[0] === 'safecloud.chat.topic' && tp1[1] === 'safecloud.topic.general');

var tp2 = CP.topicPath(['engineering', 'backend']);
check('two-segment topic path length', tp2.length === 3);
check('topic path[1] is engineering', tp2[1] === 'safecloud.topic.engineering');
check('topic path[2] is backend', tp2[2] === 'safecloud.topic.backend');

try {
    CP.topicPath([]);
    check('empty topicPath throws', false, 'should have thrown');
} catch (e) {
    check('empty topicPath throws', true);
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG operations
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── DAG ──');

// Simple linear chain: A → B → C
var chain = [
    { cid: 'A', parentIds: [],    timestamp: 1000 },
    { cid: 'B', parentIds: ['A'], timestamp: 2000 },
    { cid: 'C', parentIds: ['B'], timestamp: 3000 }
];
check('linear roots: [A]', JSON.stringify(CP.dagRoots(chain)) === JSON.stringify(['A']));
check('linear tips: [C]',  JSON.stringify(CP.dagTips(chain))  === JSON.stringify(['C']));
var sorted = CP.dagTopoSort(chain);
check('linear topo order: A,B,C', sorted.map(function(n){return n.cid;}).join(',') === 'A,B,C');

// Branch: A → B, A → C (concurrent messages)
var branched = [
    { cid: 'A', parentIds: [],    timestamp: 1000 },
    { cid: 'B', parentIds: ['A'], timestamp: 2000 },
    { cid: 'C', parentIds: ['A'], timestamp: 2001 }  // slightly later
];
var bRoots = CP.dagRoots(branched);
check('branched roots: [A]', bRoots.length === 1 && bRoots[0] === 'A');
var bTips = CP.dagTips(branched);
check('branched tips: B and C', bTips.length === 2 && bTips.includes('B') && bTips.includes('C'));
var bSorted = CP.dagTopoSort(branched);
check('branched: A is first', bSorted[0].cid === 'A');
check('branched: B before C (timestamp)', bSorted[1].cid === 'B' && bSorted[2].cid === 'C');

// Merge: A → B, A → C, (B,C) → D
var merged = [
    { cid: 'A', parentIds: [],         timestamp: 1000 },
    { cid: 'B', parentIds: ['A'],      timestamp: 2000 },
    { cid: 'C', parentIds: ['A'],      timestamp: 2001 },
    { cid: 'D', parentIds: ['B', 'C'], timestamp: 3000 }
];
var mTips = CP.dagTips(merged);
check('merged: single tip D', mTips.length === 1 && mTips[0] === 'D');
var mSorted = CP.dagTopoSort(merged);
check('merged: D is last', mSorted[mSorted.length - 1].cid === 'D');
check('merged: A is first', mSorted[0].cid === 'A');

// Cycle detection
var cycle = [
    { cid: 'X', parentIds: ['Y'], timestamp: 1000 },
    { cid: 'Y', parentIds: ['X'], timestamp: 2000 }
];
try {
    CP.dagTopoSort(cycle);
    check('cycle detected', false, 'should have thrown');
} catch (e) {
    check('cycle detected', e.message.includes('cycle'));
}

// dagThread on linear chain → same as chain
var thread = CP.dagThread(chain);
check('thread of linear chain is A,B,C', thread.map(function(n){return n.cid;}).join(',') === 'A,B,C');

// dagThread on branch follows latest tip back to root
var bThread = CP.dagThread(branched);
check('branched thread starts at A', bThread[0].cid === 'A');
check('branched thread ends at C (latest tip)', bThread[bThread.length - 1].cid === 'C');

// ─────────────────────────────────────────────────────────────────────────────
// Forward chain message
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── forwardChainMessage ──');

var fc = CP.forwardChainMessage(0, 'QmNextEpochCid', 'thread-1');
check('type is Safecloud/chat/forwardChain', fc.type === 'Safecloud/chat/forwardChain');
check('epochIndex is 0', fc.epochIndex === 0);
check('nextEpochIndex is 1', fc.nextEpochIndex === 1);
check('nextEpochKeyCid set', fc.nextEpochKeyCid === 'QmNextEpochCid');
check('threadId set', fc.threadId === 'thread-1');
check('timestamp is a number', typeof fc.timestamp === 'number');

// ─────────────────────────────────────────────────────────────────────────────
// Message envelope
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n── messageEnvelope ──');

var env = CP.messageEnvelope('Hello!', 'thread-1', 2, ['cidA', 'cidB'], 'alice');
check('type is Safecloud/chat/message', env.type === 'Safecloud/chat/message');
check('threadId set', env.threadId === 'thread-1');
check('epochIndex set', env.epochIndex === 2);
check('parentIds set', JSON.stringify(env.parentIds) === '["cidA","cidB"]');
check('text set', env.text === 'Hello!');
check('senderHint set', env.senderHint === 'alice');
check('timestamp is a number', typeof env.timestamp === 'number');

// No parentIds → empty array (root message)
var root = CP.messageEnvelope('First!', 'thread-1', 0, null, null);
check('null parentIds → []', JSON.stringify(root.parentIds) === '[]');
check('null senderHint → null', root.senderHint === null);

// ─────────────────────────────────────────────────────────────────────────────
// SUMMARY
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n' + (fail ? '✗' : '✓') + ' ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
