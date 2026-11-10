'use strict';
var { makeDB, assertEqual, assertThrows, runSuite } = require('./helpers');

runSuite('DDL — CREATE / DROP TABLE / INDEX', [

    { name: 'CREATE TABLE basic', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)');
        var tables = db._catalog.listTables();
        assertEqual(tables.includes('t'), true, 'table t should exist');
        db.close();
    }},

    { name: 'CREATE TABLE IF NOT EXISTS (no error on duplicate)', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER)');
        db.exec('CREATE TABLE IF NOT EXISTS t (id INTEGER)'); // must not throw
        db.close();
    }},

    { name: 'CREATE TABLE duplicate throws', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER)');
        assertThrows(function () { db.exec('CREATE TABLE t (id INTEGER)'); }, 'already exists');
        db.close();
    }},

    { name: 'CREATE TABLE with column default', fn: function () {
        var db = makeDB();
        db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, status TEXT DEFAULT 'active')");
        db.prepare('INSERT INTO t (id) VALUES (1)').run();
        var row = db.prepare('SELECT * FROM t WHERE id = 1').get();
        assertEqual(row.status, 'active', 'default value should be applied');
        db.close();
    }},

    { name: 'DROP TABLE basic', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER)');
        db.exec('DROP TABLE t');
        assertEqual(db._catalog.getTable('t'), null, 'table should be gone');
        db.close();
    }},

    { name: 'DROP TABLE IF EXISTS (no error on missing)', fn: function () {
        var db = makeDB();
        db.exec('DROP TABLE IF EXISTS nonexistent');
        db.close();
    }},

    { name: 'DROP TABLE throws when missing', fn: function () {
        var db = makeDB();
        assertThrows(function () { db.exec('DROP TABLE nonexistent'); }, 'not found');
        db.close();
    }},

    { name: 'CREATE INDEX and DROP INDEX', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)');
        db.exec('CREATE UNIQUE INDEX idx_email ON users (email)');
        assertEqual(!!db._catalog.getIndex('idx_email'), true, 'index should exist');
        db.exec('DROP INDEX idx_email');
        assertEqual(db._catalog.getIndex('idx_email'), null, 'index should be gone');
        db.close();
    }},

    { name: 'CREATE INDEX IF NOT EXISTS (no error on duplicate)', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)');
        db.exec('CREATE INDEX idx_x ON t (x)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_x ON t (x)');
        db.close();
    }},

    { name: 'DROP TABLE cascades to indexes', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)');
        db.exec('CREATE INDEX idx_x ON t (x)');
        db.exec('DROP TABLE t');
        // Index should have been removed from catalog
        assertEqual(db._catalog.getIndex('idx_x'), null, 'index should cascade-drop');
        db.close();
    }},

    { name: 'auto-rowid table (no explicit PK)', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (name TEXT)');
        db.prepare('INSERT INTO t (name) VALUES (?)').run('Alice');
        db.prepare('INSERT INTO t (name) VALUES (?)').run('Bob');
        var rows = db.prepare('SELECT * FROM t').all();
        assertEqual(rows.length, 2, 'should have 2 rows');
        db.close();
    }},

    { name: 'table-level PRIMARY KEY constraint', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (a INTEGER, b INTEGER, PRIMARY KEY (a, b))');
        var tbl = db._catalog.getTable('t');
        assertEqual(JSON.stringify(tbl.primaryKey), JSON.stringify(['a', 'b']), 'composite PK');
        db.close();
    }},

]);
