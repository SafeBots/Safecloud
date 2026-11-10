'use strict';
var { makeDB, assertEqual, assertThrows, runSuite } = require('./helpers');

runSuite('Expression correctness — AND 3VL, comparisons, BETWEEN, LIKE, CASE, CAST, dates', [

    // ── AND three-valued logic ────────────────────────────────────────────────

    { name: 'TRUE AND NULL = NULL (3VL)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (1 AND NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL AND TRUE = NULL (3VL)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL AND 1) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'FALSE AND NULL = 0 (3VL — false wins)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (0 AND NULL) AS v').get();
        assertEqual(r.v, 0);
        db.close();
    }},

    { name: 'NULL AND FALSE = 0 (3VL — false wins)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL AND 0) AS v').get();
        assertEqual(r.v, 0);
        db.close();
    }},

    // ── Comparison operators propagate NULL ───────────────────────────────────

    { name: '1 = NULL = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (1 = NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL = NULL = NULL (use IS NULL for identity)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL = NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: '1 != NULL = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (1 != NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: '1 < NULL = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (1 < NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL > 1 = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL > 1) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL <= NULL = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL <= NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'comparison NULLs exclude rows in WHERE (same as before)', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)');
        db.prepare('INSERT INTO t (id, x) VALUES (1, NULL)').run();
        db.prepare('INSERT INTO t (id, x) VALUES (2, 5)').run();
        // WHERE x = 5: row 1 (x=NULL) → null → excluded; row 2 → 1 → included
        var rows = db.prepare('SELECT id FROM t WHERE x = 5').all();
        assertEqual(rows.length, 1);
        assertEqual(rows[0].id, 2);
        db.close();
    }},

    // ── BETWEEN propagates NULL ───────────────────────────────────────────────

    { name: 'NULL BETWEEN 1 AND 10 = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL BETWEEN 1 AND 10) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: '5 BETWEEN NULL AND 10 = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (5 BETWEEN NULL AND 10) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: '5 BETWEEN 1 AND NULL = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (5 BETWEEN 1 AND NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    // ── LIKE propagates NULL ──────────────────────────────────────────────────

    { name: "NULL LIKE '%' = NULL", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT (NULL LIKE '%') AS v").get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: "'abc' LIKE NULL = NULL", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT ('abc' LIKE NULL) AS v").get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: "NULL NOT LIKE '%' = NULL", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT (NULL NOT LIKE '%') AS v").get();
        assertEqual(r.v, null);
        db.close();
    }},

    // ── Simple CASE ───────────────────────────────────────────────────────────

    { name: 'simple CASE matches equal value', fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT CASE 2 WHEN 1 THEN 'one' WHEN 2 THEN 'two' ELSE 'other' END AS v").get();
        assertEqual(r.v, 'two');
        db.close();
    }},

    { name: 'simple CASE falls to ELSE', fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT CASE 9 WHEN 1 THEN 'one' WHEN 2 THEN 'two' ELSE 'other' END AS v").get();
        assertEqual(r.v, 'other');
        db.close();
    }},

    { name: 'simple CASE with no match and no ELSE returns NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT CASE 9 WHEN 1 THEN 'one' WHEN 2 THEN 'two' END AS v").get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'simple CASE with NULL operand falls to ELSE (no match)', fn: function () {
        var db = makeDB();
        // NULL operand never matches any WHEN, so ELSE applies
        var r = db.prepare("SELECT CASE NULL WHEN 1 THEN 'one' ELSE 'other' END AS v").get();
        assertEqual(r.v, 'other');
        db.close();
    }},

    { name: 'simple CASE with NULL operand and no ELSE returns NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT CASE NULL WHEN 1 THEN 'one' END AS v").get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'simple CASE on column value', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        db.prepare('INSERT INTO t (id, n) VALUES (1, 1)').run();
        db.prepare('INSERT INTO t (id, n) VALUES (2, 2)').run();
        db.prepare('INSERT INTO t (id, n) VALUES (3, 3)').run();
        var rows = db.prepare("SELECT CASE n WHEN 1 THEN 'one' WHEN 2 THEN 'two' ELSE 'many' END AS label FROM t ORDER BY id").all();
        assertEqual(rows[0].label, 'one');
        assertEqual(rows[1].label, 'two');
        assertEqual(rows[2].label, 'many');
        db.close();
    }},

    // ── CAST type coercion ────────────────────────────────────────────────────

    { name: "CAST('3' AS INTEGER) = 3", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT CAST('3' AS SIGNED) AS v").get();
        assertEqual(r.v, 3);
        assertEqual(typeof r.v, 'number');
        db.close();
    }},

    { name: "CAST('3.7' AS INTEGER) truncates to 3", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT CAST('3.7' AS SIGNED) AS v").get();
        assertEqual(r.v, 3);
        db.close();
    }},

    { name: "CAST(42 AS CHAR) = '42'", fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT CAST(42 AS CHAR) AS v').get();
        assertEqual(r.v, '42');
        assertEqual(typeof r.v, 'string');
        db.close();
    }},

    { name: "CAST('3.14' AS DECIMAL) = 3.14", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT CAST('3.14' AS DECIMAL) AS v").get();
        assertEqual(r.v, 3.14);
        db.close();
    }},

    { name: 'CAST(NULL AS INTEGER) = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT CAST(NULL AS SIGNED) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    // ── Date / time functions ─────────────────────────────────────────────────

    { name: "DATE('now') returns a YYYY-MM-DD string", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT DATE('now') AS v").get();
        // Should match YYYY-MM-DD
        assertEqual(typeof r.v, 'string');
        assertEqual(/^\d{4}-\d{2}-\d{2}$/.test(r.v), true, 'DATE should return YYYY-MM-DD: ' + r.v);
        db.close();
    }},

    { name: "DATETIME('now') returns a YYYY-MM-DD HH:MM:SS string", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT DATETIME('now') AS v").get();
        assertEqual(typeof r.v, 'string');
        assertEqual(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(r.v), true, 'DATETIME format: ' + r.v);
        db.close();
    }},

    { name: "STRFTIME('%Y', 'now') returns a 4-digit year string", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT STRFTIME('%Y', 'now') AS v").get();
        assertEqual(typeof r.v, 'string');
        assertEqual(/^\d{4}$/.test(r.v), true, 'STRFTIME %Y: ' + r.v);
        db.close();
    }},

]);
