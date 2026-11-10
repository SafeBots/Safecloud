#!/usr/bin/env node
'use strict';
/**
 * run_all.js — runs every DB test file in sequence and prints a summary.
 *
 *   node tests/db/run_all.js
 *   npm run test:db
 */

var path = require('path');

var TEST_FILES = [
    '01_ddl.test.js',
    '02_crud.test.js',
    '03_where.test.js',
    '04_ordering.test.js',
    '05_indexes.test.js',
    '06_joins.test.js',
    '07_aggregates.test.js',
    '08_transactions.test.js',
    '09_types.test.js',
    '10_dedup.test.js',
    '11_large.test.js',
    '12_null_semantics.test.js',
    '13_expr_correctness.test.js',
];

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log('║           Safecloud/DB  test suite                  ║');
console.log('╚══════════════════════════════════════════════════════╝');

var t0 = Date.now();

TEST_FILES.forEach(function (f) {
    require(path.join(__dirname, f));
});

// Collect totals from helpers
var helpers = require('./helpers');
var totals  = helpers.totals();
var elapsed = Date.now() - t0;

console.log('\n══════════════════════════════════════════════════════');
console.log(
    totals.fail === 0
        ? '✅  All ' + totals.pass + ' tests passed  (' + elapsed + 'ms)'
        : '❌  ' + totals.pass + ' passed, ' + totals.fail + ' FAILED  (' + elapsed + 'ms)'
);
console.log('══════════════════════════════════════════════════════\n');

if (totals.fail > 0) process.exit(1);
