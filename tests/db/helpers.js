'use strict';
/**
 * Test helpers for the DB test suite.
 *
 * Each test file gets a fresh in-memory database so tests are independent.
 */

var fs       = require('fs');
var path     = require('path');
var Database = require('../../classes/Safecloud/DB');

var _pass = 0, _fail = 0;

/** Create a fresh in-memory DB for one test file. */
function makeDB() {
    return new Database(':memory:');
}

/**
 * Minimal assertion helpers (no external deps).
 */
function assert(cond, msg) {
    if (!cond) throw new Error('Assertion failed: ' + msg);
}

function assertEqual(a, b, msg) {
    var ok = (a === b) || (
        a !== null && b !== null &&
        typeof a === 'object' && typeof b === 'object' &&
        JSON.stringify(a) === JSON.stringify(b)
    );
    if (!ok) throw new Error(
        (msg || 'assertEqual') + '\n  expected: ' + JSON.stringify(b) + '\n  got:      ' + JSON.stringify(a)
    );
}

function assertDeepEqual(a, b, msg) {
    var sa = JSON.stringify(a), sb = JSON.stringify(b);
    if (sa !== sb) throw new Error(
        (msg || 'assertDeepEqual') + '\n  expected: ' + sb + '\n  got:      ' + sa
    );
}

function assertThrows(fn, msgFragment, label) {
    var threw = false, err = null;
    try { fn(); } catch (e) { threw = true; err = e; }
    if (!threw) throw new Error((label || 'assertThrows') + ': expected an error to be thrown');
    if (msgFragment && !(err.message || '').includes(msgFragment)) {
        throw new Error((label || 'assertThrows') + ': expected error containing "' + msgFragment
            + '" but got: ' + err.message);
    }
}

/**
 * Run a test suite.
 *
 * @param {string}   suiteName
 * @param {Array}    tests    [{name, fn}]
 * @returns {{pass, fail}}
 */
function runSuite(suiteName, tests) {
    var pass = 0, fail = 0;
    console.log('\n── ' + suiteName + ' ─────────────────────────────');
    tests.forEach(function (t) {
        try {
            t.fn();
            console.log('  ✓ ' + t.name);
            pass++;
        } catch (e) {
            console.log('  ✗ ' + t.name);
            console.log('    ' + (e.message || e));
            if (process.env.DB_TEST_VERBOSE) console.log(e.stack);
            fail++;
        }
    });
    _pass += pass; _fail += fail;
    return { pass: pass, fail: fail };
}

function totals() { return { pass: _pass, fail: _fail }; }

module.exports = { makeDB, assert, assertEqual, assertDeepEqual, assertThrows, runSuite, totals };
