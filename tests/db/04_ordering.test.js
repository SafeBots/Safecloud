'use strict';
var { makeDB, assertEqual, assertDeepEqual, runSuite } = require('./helpers');

function setup() {
    var db = makeDB();
    db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT, n REAL)');
    var ins = db.prepare('INSERT INTO t (id, s, n) VALUES (?, ?, ?)');
    ins.run(1, 'cherry', 3);
    ins.run(2, 'apple',  1);
    ins.run(3, 'date',   4);
    ins.run(4, 'banana', 2);
    return db;
}

runSuite('ORDER BY, LIMIT, OFFSET', [

    { name: 'ORDER BY ASC (default)', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT id FROM t ORDER BY n').all();
        assertDeepEqual(rows.map(function(r){return r.id;}), [2,4,1,3]);
        db.close();
    }},

    { name: 'ORDER BY DESC', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT id FROM t ORDER BY n DESC').all();
        assertDeepEqual(rows.map(function(r){return r.id;}), [3,1,4,2]);
        db.close();
    }},

    { name: 'ORDER BY text column ASC', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT s FROM t ORDER BY s').all();
        assertDeepEqual(rows.map(function(r){return r.s;}), ['apple','banana','cherry','date']);
        db.close();
    }},

    { name: 'ORDER BY text column DESC', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT s FROM t ORDER BY s DESC').all();
        assertDeepEqual(rows.map(function(r){return r.s;}), ['date','cherry','banana','apple']);
        db.close();
    }},

    { name: 'LIMIT', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT id FROM t ORDER BY id LIMIT 2').all();
        assertEqual(rows.length, 2);
        assertEqual(rows[0].id, 1);
        assertEqual(rows[1].id, 2);
        db.close();
    }},

    { name: 'LIMIT 0 returns empty', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT * FROM t LIMIT 0').all();
        assertEqual(rows.length, 0);
        db.close();
    }},

    { name: 'LIMIT larger than row count', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT * FROM t LIMIT 100').all();
        assertEqual(rows.length, 4);
        db.close();
    }},

    { name: 'LIMIT + OFFSET', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT id FROM t ORDER BY id LIMIT 2 OFFSET 1').all();
        assertDeepEqual(rows.map(function(r){return r.id;}), [2,3]);
        db.close();
    }},

    { name: 'OFFSET without LIMIT not an error', fn: function () {
        var db = setup();
        // MySQL-style: LIMIT big OFFSET n
        var rows = db.prepare('SELECT id FROM t ORDER BY id LIMIT 100 OFFSET 2').all();
        assertEqual(rows.length, 2);
        assertEqual(rows[0].id, 3);
        db.close();
    }},

    { name: 'multi-column ORDER BY', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (a INTEGER, b INTEGER)');
        var ins = db.prepare('INSERT INTO t (a, b) VALUES (?, ?)');
        ins.run(2, 1); ins.run(1, 2); ins.run(2, 2); ins.run(1, 1);
        var rows = db.prepare('SELECT a, b FROM t ORDER BY a ASC, b DESC').all();
        assertDeepEqual(
            rows.map(function(r){return [r.a, r.b];}),
            [[1,2],[1,1],[2,2],[2,1]]
        );
        db.close();
    }},

    { name: 'NULL sorts first in ASC', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (n REAL)');
        var ins = db.prepare('INSERT INTO t (n) VALUES (?)');
        ins.run(2); ins.run(null); ins.run(1);
        var rows = db.prepare('SELECT n FROM t ORDER BY n ASC').all();
        assertEqual(rows[0].n, null, 'NULL should sort first ASC');
        db.close();
    }},

    { name: 'ORDER BY + WHERE + LIMIT', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT s FROM t WHERE n > 1 ORDER BY n DESC LIMIT 2').all();
        assertDeepEqual(rows.map(function(r){return r.s;}), ['date','cherry']);
        db.close();
    }},

    { name: 'SELECT DISTINCT removes duplicates', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (x INTEGER)');
        var ins = db.prepare('INSERT INTO t (x) VALUES (?)');
        ins.run(1); ins.run(2); ins.run(1); ins.run(3);
        var rows = db.prepare('SELECT DISTINCT x FROM t ORDER BY x').all();
        assertDeepEqual(rows.map(function(r){return r.x;}), [1,2,3]);
        db.close();
    }},

]);
