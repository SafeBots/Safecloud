'use strict';
var { makeDB, assertEqual, runSuite } = require('./helpers');

var N = 10000;

runSuite('Large dataset — correctness & timing', [

    { name: 'insert ' + N + ' rows', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT, n REAL)');
        var ins = db.prepare('INSERT INTO t (id, val, n) VALUES (?, ?, ?)');
        var t0 = Date.now();
        var tx = db.transaction(function () {
            for (var i = 1; i <= N; i++) ins.run(i, 'item' + i, i * 0.5);
        });
        tx();
        var elapsed = Date.now() - t0;
        console.log('    insert ' + N + ' rows: ' + elapsed + 'ms');
        var c = db.prepare('SELECT COUNT(*) AS c FROM t').get();
        assertEqual(c.c, N, N + ' rows expected');
        db.close();
    }},

    { name: 'point lookup by primary key in ' + N + '-row table', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)');
        var ins = db.prepare('INSERT INTO t (id, val) VALUES (?, ?)');
        var tx = db.transaction(function () {
            for (var i = 1; i <= N; i++) ins.run(i, 'item' + i);
        });
        tx();
        var t0 = Date.now();
        var mid = Math.floor(N / 2);
        var r = db.prepare('SELECT val FROM t WHERE id = ?').get(mid);
        var elapsed = Date.now() - t0;
        console.log('    point lookup in ' + N + ' rows: ' + elapsed + 'ms');
        assertEqual(r.val, 'item' + mid);
        db.close();
    }},

    { name: 'range scan (BETWEEN) correctness', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        var ins = db.prepare('INSERT INTO t (id, n) VALUES (?, ?)');
        var tx = db.transaction(function () {
            for (var i = 1; i <= N; i++) ins.run(i, i);
        });
        tx();
        var rows = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n BETWEEN 100 AND 200').get();
        assertEqual(rows.c, 101, '100..200 inclusive = 101 rows');
        db.close();
    }},

    { name: 'ORDER BY DESC + LIMIT on large table', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)');
        var ins = db.prepare('INSERT INTO t (id, val) VALUES (?, ?)');
        var tx = db.transaction(function () {
            for (var i = 1; i <= N; i++) ins.run(i, 'v' + i);
        });
        tx();
        var rows = db.prepare('SELECT id FROM t ORDER BY id DESC LIMIT 5').all();
        assertEqual(rows.length, 5);
        assertEqual(rows[0].id, N);
        assertEqual(rows[4].id, N - 4);
        db.close();
    }},

    { name: 'bulk delete half the rows', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        var ins = db.prepare('INSERT INTO t (id, n) VALUES (?, ?)');
        var tx = db.transaction(function () {
            for (var i = 1; i <= N; i++) ins.run(i, i);
        });
        tx();
        var r = db.prepare('DELETE FROM t WHERE n % 2 = 0').run();
        assertEqual(r.changes, N / 2, 'half should be deleted');
        var c = db.prepare('SELECT COUNT(*) AS c FROM t').get();
        assertEqual(c.c, N / 2, 'half should remain');
        db.close();
    }},

    { name: 'GROUP BY on ' + N + ' rows', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, bucket INTEGER, val REAL)');
        var ins = db.prepare('INSERT INTO t (id, bucket, val) VALUES (?, ?, ?)');
        var tx = db.transaction(function () {
            for (var i = 1; i <= N; i++) ins.run(i, i % 10, i);
        });
        tx();
        var rows = db.prepare('SELECT bucket, COUNT(*) AS c, SUM(val) AS s FROM t GROUP BY bucket ORDER BY bucket').all();
        assertEqual(rows.length, 10, '10 buckets');
        // bucket 0: ids 10,20,...,N → N/10 rows, sum = 10+20+...+N
        var b0 = rows.find(function(r){return r.bucket===0;});
        assertEqual(b0.c, N / 10);
        db.close();
    }},

    { name: 'UPDATE ' + (N / 10) + ' rows', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, flag INTEGER)');
        var ins = db.prepare('INSERT INTO t (id, flag) VALUES (?, 0)');
        var tx = db.transaction(function () {
            for (var i = 1; i <= N; i++) ins.run(i);
        });
        tx();
        var r = db.prepare('UPDATE t SET flag = 1 WHERE id <= ?').run(N / 10);
        assertEqual(r.changes, N / 10, 'N/10 rows updated');
        var c = db.prepare('SELECT COUNT(*) AS c FROM t WHERE flag = 1').get();
        assertEqual(c.c, N / 10);
        db.close();
    }},

]);
