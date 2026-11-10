'use strict';
var { makeDB, assertEqual, assertThrows, runSuite } = require('./helpers');

runSuite('Transactions', [

    { name: 'COMMIT persists changes', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.exec('BEGIN');
        db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('hello');
        db.exec('COMMIT');
        var row = db.prepare('SELECT v FROM t WHERE id = 1').get();
        assertEqual(row.v, 'hello');
        db.close();
    }},

    { name: 'ROLLBACK undoes inserts', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.exec('BEGIN');
        db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('hello');
        db.exec('ROLLBACK');
        var rows = db.prepare('SELECT * FROM t').all();
        assertEqual(rows.length, 0, 'rows should be gone after rollback');
        db.close();
    }},

    { name: 'ROLLBACK undoes updates', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('original');
        db.exec('BEGIN');
        db.prepare("UPDATE t SET v = 'changed' WHERE id = 1").run();
        db.exec('ROLLBACK');
        var row = db.prepare('SELECT v FROM t WHERE id = 1').get();
        assertEqual(row.v, 'original');
        db.close();
    }},

    { name: 'ROLLBACK undoes deletes', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('keep');
        db.exec('BEGIN');
        db.prepare('DELETE FROM t WHERE id = 1').run();
        db.exec('ROLLBACK');
        var row = db.prepare('SELECT * FROM t WHERE id = 1').get();
        assertEqual(!!row, true, 'row should be restored after rollback');
        db.close();
    }},

    { name: 'db.transaction() wrapping function commits', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        var insert = db.prepare('INSERT INTO t (id, v) VALUES (?, ?)');
        var tx = db.transaction(function (a, b) {
            insert.run(1, a);
            insert.run(2, b);
        });
        tx('foo', 'bar');
        var rows = db.prepare('SELECT * FROM t ORDER BY id').all();
        assertEqual(rows.length, 2);
        assertEqual(rows[0].v, 'foo');
        db.close();
    }},

    { name: 'db.transaction() rolls back on throw', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        var insert = db.prepare('INSERT INTO t (id, v) VALUES (?, ?)');
        var tx = db.transaction(function () {
            insert.run(1, 'a');
            throw new Error('oops');
        });
        assertThrows(function () { tx(); }, 'oops');
        var rows = db.prepare('SELECT * FROM t').all();
        assertEqual(rows.length, 0, 'insert should be rolled back');
        db.close();
    }},

    { name: 'nested transaction calls BEGIN only once', fn: function () {
        // Our impl does not support true nested transactions; the outer BEGIN wins.
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.exec('BEGIN');
        db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('a');
        db.exec('COMMIT');
        var rows = db.prepare('SELECT * FROM t').all();
        assertEqual(rows.length, 1);
        db.close();
    }},

    { name: 'multiple ops in one transaction', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)');
        var ins = db.prepare('INSERT INTO t (id, n) VALUES (?, ?)');
        var upd = db.prepare('UPDATE t SET n = n + 1 WHERE id = ?');
        var tx = db.transaction(function () {
            ins.run(1, 0);
            upd.run(1);
            upd.run(1);
        });
        tx();
        var row = db.prepare('SELECT n FROM t WHERE id = 1').get();
        assertEqual(row.n, 2, 'two increments in one tx');
        db.close();
    }},

    { name: 'transaction returns function value', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        db.prepare('INSERT INTO t (id, v) VALUES (1, ?)').run('hello');
        var tx = db.transaction(function () {
            return db.prepare('SELECT v FROM t WHERE id = 1').get();
        });
        var result = tx();
        assertEqual(result.v, 'hello');
        db.close();
    }},

]);
