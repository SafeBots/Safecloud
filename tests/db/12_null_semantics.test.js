'use strict';
var { makeDB, assertEqual, assertThrows, runSuite } = require('./helpers');

runSuite('NULL semantics & correctness fixes', [

    // ── NULL arithmetic ───────────────────────────────────────────────────────

    { name: 'NULL + n = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT NULL + 5 AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'n - NULL = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT 10 - NULL AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL * n = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT NULL * 3 AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL / n = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT NULL / 2 AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL % n = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT NULL % 3 AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    // ── NULL concatenation ────────────────────────────────────────────────────

    { name: "NULL || 'x' = NULL", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT NULL || 'x' AS v").get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: "'x' || NULL = NULL", fn: function () {
        var db = makeDB();
        var r = db.prepare("SELECT 'x' || NULL AS v").get();
        assertEqual(r.v, null);
        db.close();
    }},

    // ── Three-valued logic: OR ────────────────────────────────────────────────

    { name: 'FALSE OR NULL = NULL (3VL)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (0 OR NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL OR FALSE = NULL (3VL)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL OR 0) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NULL OR NULL = NULL (3VL)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL OR NULL) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'TRUE OR NULL = 1 (short-circuit)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (1 OR NULL) AS v').get();
        assertEqual(r.v, 1);
        db.close();
    }},

    { name: 'NULL OR TRUE = 1 (short-circuit)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL OR 1) AS v').get();
        assertEqual(r.v, 1);
        db.close();
    }},

    // ── Three-valued logic: NOT ───────────────────────────────────────────────

    { name: 'NOT NULL = NULL (3VL)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT NOT NULL AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    // ── Unary minus on NULL ───────────────────────────────────────────────────

    { name: '-NULL = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT -NULL AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    // ── IN / NOT IN with NULLs in list ───────────────────────────────────────

    { name: 'x IN (list with NULL) returns NULL when not found', fn: function () {
        var db = makeDB();
        // 3 is not in the list, but NULL is present → should return NULL
        var r = db.prepare('SELECT (3 IN (1, NULL, 2)) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'x IN (list with NULL) returns 1 when found', fn: function () {
        var db = makeDB();
        // 1 is in the list → match found before any null matters → 1
        var r = db.prepare('SELECT (1 IN (1, NULL, 2)) AS v').get();
        assertEqual(r.v, 1);
        db.close();
    }},

    { name: 'NULL IN (list) = NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT (NULL IN (1, 2, 3)) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'x NOT IN (list with NULL) returns NULL when not found', fn: function () {
        var db = makeDB();
        // 3 is not in list, but NULL is present → unknown → NULL
        var r = db.prepare('SELECT (3 NOT IN (1, NULL, 2)) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'NOT IN with NULL in list excludes rows in WHERE', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)');
        db.prepare('INSERT INTO t (id, x) VALUES (1, 3)').run();
        db.prepare('INSERT INTO t (id, x) VALUES (2, 1)').run();
        db.exec('CREATE TABLE excl (v INTEGER)');
        db.prepare('INSERT INTO excl (v) VALUES (1)').run();
        db.prepare('INSERT INTO excl (v) VALUES (NULL)').run();
        // id=2 (x=1) matches the exclusion list; id=1 (x=3) is NOT IN but list has NULL → NULL filter → excluded
        var rows = db.prepare('SELECT id FROM t WHERE x NOT IN (SELECT v FROM excl) ORDER BY id').all();
        // SQLite excludes id=1 because NULL in the subquery makes NOT IN return NULL
        // id=2 is excluded because x=1 is directly in the list
        assertEqual(rows.length, 0, 'NULL in NOT IN subquery should exclude all uncertain rows');
        db.close();
    }},

    // ── PRIMARY KEY duplicate check ───────────────────────────────────────────

    { name: 'INSERT duplicate PK throws UNIQUE constraint error', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('first');
        assertThrows(function () {
            db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('second');
        }, 'UNIQUE', 'duplicate PK should throw');
        // original row should still be intact
        var r = db.prepare('SELECT v FROM t WHERE id = 1').get();
        assertEqual(r.v, 'first', 'original row should be unchanged');
        db.close();
    }},

    // ── DISTINCT before LIMIT ─────────────────────────────────────────────────

    { name: 'DISTINCT + LIMIT respects distinct set size', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)');
        // 4 rows, 2 distinct x values
        db.prepare('INSERT INTO t (id, x) VALUES (1, 1)').run();
        db.prepare('INSERT INTO t (id, x) VALUES (2, 1)').run();
        db.prepare('INSERT INTO t (id, x) VALUES (3, 2)').run();
        db.prepare('INSERT INTO t (id, x) VALUES (4, 2)').run();
        var rows = db.prepare('SELECT DISTINCT x FROM t LIMIT 10').all();
        // DISTINCT should produce 2 rows; LIMIT 10 doesn't cut them
        assertEqual(rows.length, 2, 'DISTINCT should deduplicate before LIMIT');
        db.close();
    }},

    { name: 'DISTINCT with LIMIT 1 returns exactly 1 unique row', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)');
        db.prepare('INSERT INTO t (id, x) VALUES (1, 5)').run();
        db.prepare('INSERT INTO t (id, x) VALUES (2, 5)').run();
        db.prepare('INSERT INTO t (id, x) VALUES (3, 6)').run();
        var rows = db.prepare('SELECT DISTINCT x FROM t ORDER BY x LIMIT 1').all();
        assertEqual(rows.length, 1);
        assertEqual(rows[0].x, 5);
        db.close();
    }},

    // ── NULL arithmetic in aggregates ─────────────────────────────────────────

    { name: 'SUM ignores NULL arithmetic (NULL+1 stays NULL, not inflated)', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        db.prepare('INSERT INTO t (id, n) VALUES (1, 10)').run();
        db.prepare('INSERT INTO t (id, n) VALUES (2, NULL)').run();
        // n+1 for row 1 = 11; n+1 for row 2 = NULL (ignored by SUM)
        var r = db.prepare('SELECT SUM(n + 1) AS v FROM t').get();
        assertEqual(r.v, 11, 'SUM should not count NULL arithmetic as 1');
        db.close();
    }},

]);
