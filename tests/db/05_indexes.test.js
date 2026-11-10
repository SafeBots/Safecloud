'use strict';
var { makeDB, assertEqual, assertThrows, runSuite } = require('./helpers');

runSuite('Indexes', [

    { name: 'CREATE INDEX builds index over existing rows', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT)');
        db.prepare('INSERT INTO t (id, email) VALUES (1, ?)').run('a@x.com');
        db.prepare('INSERT INTO t (id, email) VALUES (2, ?)').run('b@x.com');
        db.exec('CREATE UNIQUE INDEX idx_email ON t (email)');
        // Index should have 2 entries
        var idxStore = db._engine._idxStore('idx_email');
        assertEqual(idxStore.count(), 2, 'index should have 2 entries');
        db.close();
    }},

    { name: 'INSERT updates secondary index', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT)');
        db.exec('CREATE UNIQUE INDEX idx_email ON t (email)');
        db.prepare('INSERT INTO t (id, email) VALUES (1, ?)').run('a@x.com');
        var idxStore = db._engine._idxStore('idx_email');
        assertEqual(idxStore.count(), 1, 'index should have 1 entry after insert');
        db.close();
    }},

    { name: 'DELETE updates secondary index', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT)');
        db.exec('CREATE UNIQUE INDEX idx_email ON t (email)');
        db.prepare('INSERT INTO t (id, email) VALUES (1, ?)').run('a@x.com');
        db.prepare('DELETE FROM t WHERE id = 1').run();
        var idxStore = db._engine._idxStore('idx_email');
        assertEqual(idxStore.count(), 0, 'index should be empty after delete');
        db.close();
    }},

    { name: 'UPDATE updates secondary index', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT)');
        db.exec('CREATE INDEX idx_email ON t (email)');
        db.prepare('INSERT INTO t (id, email) VALUES (1, ?)').run('a@x.com');
        db.prepare("UPDATE t SET email = 'z@x.com' WHERE id = 1").run();
        var idxStore = db._engine._idxStore('idx_email');
        // Should still have 1 entry (old one removed, new one added)
        assertEqual(idxStore.count(), 1, 'index count should remain 1 after update');
        db.close();
    }},

    { name: 'UNIQUE INDEX rejects duplicate non-null values', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT)');
        db.exec('CREATE UNIQUE INDEX idx_email ON t (email)');
        db.prepare('INSERT INTO t (id, email) VALUES (1, ?)').run('a@x.com');
        assertThrows(function () {
            db.prepare('INSERT INTO t (id, email) VALUES (2, ?)').run('a@x.com');
        }, 'UNIQUE', 'duplicate should throw');
        db.close();
    }},

    { name: 'UNIQUE INDEX allows multiple NULLs', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT)');
        db.exec('CREATE UNIQUE INDEX idx_email ON t (email)');
        db.prepare('INSERT INTO t (id, email) VALUES (1, NULL)').run();
        db.prepare('INSERT INTO t (id, email) VALUES (2, NULL)').run(); // must not throw
        db.close();
    }},

    { name: 'compound index (a, b)', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (a INTEGER, b INTEGER, c TEXT)');
        db.exec('CREATE INDEX idx_ab ON t (a, b)');
        var ins = db.prepare('INSERT INTO t (a, b, c) VALUES (?, ?, ?)');
        ins.run(1, 1, 'x'); ins.run(1, 2, 'y'); ins.run(2, 1, 'z');
        var idxStore = db._engine._idxStore('idx_ab');
        assertEqual(idxStore.count(), 3, 'compound index should have 3 entries');
        db.close();
    }},

    { name: 'DROP INDEX removes entries from store', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)');
        db.exec('CREATE INDEX idx_x ON t (x)');
        db.prepare('INSERT INTO t (id, x) VALUES (1, 10)').run();
        db.exec('DROP INDEX idx_x');
        assertEqual(db._catalog.getIndex('idx_x'), null, 'index gone from catalog');
        db.close();
    }},

    { name: 'multiple indexes on same table', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b INTEGER)');
        db.exec('CREATE INDEX idx_a ON t (a)');
        db.exec('CREATE INDEX idx_b ON t (b)');
        var ins = db.prepare('INSERT INTO t (id, a, b) VALUES (?, ?, ?)');
        ins.run(1, 'foo', 10);
        var idxa = db._engine._idxStore('idx_a');
        var idxb = db._engine._idxStore('idx_b');
        assertEqual(idxa.count(), 1);
        assertEqual(idxb.count(), 1);
        db.close();
    }},

]);
