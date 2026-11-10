'use strict';
var { makeDB, assertEqual, assertThrows, runSuite } = require('./helpers');

runSuite('Types, NULLs & constraints', [

    { name: 'INTEGER column truncates float', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        db.prepare('INSERT INTO t (id, n) VALUES (1, ?)').run(3.9);
        var r = db.prepare('SELECT n FROM t WHERE id = 1').get();
        assertEqual(r.n, 3, 'float should be truncated to int');
        db.close();
    }},

    { name: 'REAL column stores float', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n REAL)');
        db.prepare('INSERT INTO t (id, n) VALUES (1, ?)').run(3.14159);
        var r = db.prepare('SELECT n FROM t WHERE id = 1').get();
        assertEqual(r.n, 3.14159);
        db.close();
    }},

    { name: 'TEXT column stores string', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)');
        db.prepare('INSERT INTO t (id, s) VALUES (1, ?)').run('hello world');
        var r = db.prepare('SELECT s FROM t WHERE id = 1').get();
        assertEqual(r.s, 'hello world');
        db.close();
    }},

    { name: 'NULL stored and retrieved', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x TEXT)');
        db.prepare('INSERT INTO t (id, x) VALUES (1, NULL)').run();
        var r = db.prepare('SELECT x FROM t WHERE id = 1').get();
        assertEqual(r.x, null);
        db.close();
    }},

    { name: 'NULL arithmetic returns NULL', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        db.prepare('INSERT INTO t (id, n) VALUES (1, NULL)').run();
        var r = db.prepare('SELECT n + 1 AS v FROM t WHERE id = 1').get();
        assertEqual(r.v, null, 'NULL + 1 should be NULL (SQLite semantics)');
        db.close();
    }},

    { name: 'boolean true/false coerce to 1/0', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, b INTEGER)');
        db.prepare('INSERT INTO t (id, b) VALUES (1, TRUE)').run();
        db.prepare('INSERT INTO t (id, b) VALUES (2, FALSE)').run();
        var r1 = db.prepare('SELECT b FROM t WHERE id = 1').get();
        var r2 = db.prepare('SELECT b FROM t WHERE id = 2').get();
        assertEqual(r1.b, 1);
        assertEqual(r2.b, 0);
        db.close();
    }},

    { name: 'negative numbers stored correctly', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        db.prepare('INSERT INTO t (id, n) VALUES (1, ?)').run(-42);
        var r = db.prepare('SELECT n FROM t WHERE id = 1').get();
        assertEqual(r.n, -42);
        db.close();
    }},

    { name: 'large integers', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        db.prepare('INSERT INTO t (id, n) VALUES (1, ?)').run(9007199254740991);
        var r = db.prepare('SELECT n FROM t WHERE id = 1').get();
        assertEqual(r.n, 9007199254740991);
        db.close();
    }},

    { name: 'text with unicode', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)');
        db.prepare('INSERT INTO t (id, s) VALUES (1, ?)').run('こんにちは 🌍');
        var r = db.prepare('SELECT s FROM t WHERE id = 1').get();
        assertEqual(r.s, 'こんにちは 🌍');
        db.close();
    }},

    { name: 'text with embedded quote', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)');
        db.prepare("INSERT INTO t (id, s) VALUES (1, ?)").run("it's a test");
        var r = db.prepare('SELECT s FROM t WHERE id = 1').get();
        assertEqual(r.s, "it's a test");
        db.close();
    }},

    { name: 'DEFAULT value applied on INSERT', fn: function () {
        var db = makeDB();
        db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, status TEXT DEFAULT 'pending')");
        db.prepare('INSERT INTO t (id) VALUES (1)').run();
        var r = db.prepare('SELECT status FROM t WHERE id = 1').get();
        assertEqual(r.status, 'pending');
        db.close();
    }},

    { name: 'multiple primary-key types: INTEGER', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.prepare('INSERT INTO t (id, v) VALUES (?, ?)').run(42, 'x');
        var r = db.prepare('SELECT v FROM t WHERE id = 42').get();
        assertEqual(r.v, 'x');
        db.close();
    }},

    { name: 'multiple primary-key types: TEXT', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id TEXT PRIMARY KEY, v INTEGER)');
        db.prepare("INSERT INTO t (id, v) VALUES ('abc', 7)").run();
        var r = db.prepare("SELECT v FROM t WHERE id = 'abc'").get();
        assertEqual(r.v, 7);
        db.close();
    }},

    { name: 'scalar functions: LENGTH', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)');
        db.prepare('INSERT INTO t (id, s) VALUES (1, ?)').run('hello');
        var r = db.prepare('SELECT LENGTH(s) AS len FROM t WHERE id = 1').get();
        assertEqual(r.len, 5);
        db.close();
    }},

    { name: 'scalar functions: UPPER / LOWER', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)');
        db.prepare('INSERT INTO t (id, s) VALUES (1, ?)').run('Hello');
        var r = db.prepare('SELECT UPPER(s) AS u, LOWER(s) AS l FROM t WHERE id = 1').get();
        assertEqual(r.u, 'HELLO');
        assertEqual(r.l, 'hello');
        db.close();
    }},

    { name: 'scalar functions: SUBSTR', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)');
        db.prepare('INSERT INTO t (id, s) VALUES (1, ?)').run('abcdefgh');
        var r = db.prepare('SELECT SUBSTR(s, 3, 4) AS v FROM t WHERE id = 1').get();
        assertEqual(r.v, 'cdef');
        db.close();
    }},

    { name: 'scalar functions: TRIM', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)');
        db.prepare('INSERT INTO t (id, s) VALUES (1, ?)').run('  hi  ');
        var r = db.prepare('SELECT TRIM(s) AS v FROM t WHERE id = 1').get();
        assertEqual(r.v, 'hi');
        db.close();
    }},

    { name: 'scalar functions: ROUND', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT ROUND(3.14159, 2) AS v').get();
        assertEqual(r.v, 3.14);
        db.close();
    }},

    { name: 'scalar functions: ABS', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT ABS(-42) AS v').get();
        assertEqual(r.v, 42);
        db.close();
    }},

    { name: 'SELECT without FROM (expression only)', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT 1 + 1 AS v').get();
        assertEqual(r.v, 2);
        db.close();
    }},

    { name: 'NULLIF returns NULL when args equal', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT NULLIF(1, 1) AS v').get();
        assertEqual(r.v, null);
        db.close();
    }},

    { name: 'IFNULL picks second arg when first is NULL', fn: function () {
        var db = makeDB();
        var r = db.prepare('SELECT IFNULL(NULL, 42) AS v').get();
        assertEqual(r.v, 42);
        db.close();
    }},

]);
