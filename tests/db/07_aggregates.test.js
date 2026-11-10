'use strict';
var { makeDB, assertEqual, assertDeepEqual, runSuite } = require('./helpers');

function setup() {
    var db = makeDB();
    db.exec('CREATE TABLE sales (id INTEGER PRIMARY KEY, dept TEXT, amount REAL)');
    var ins = db.prepare('INSERT INTO sales (id, dept, amount) VALUES (?, ?, ?)');
    ins.run(1, 'eng',  100);
    ins.run(2, 'eng',  200);
    ins.run(3, 'mkt',   50);
    ins.run(4, 'mkt',  150);
    ins.run(5, 'eng',  null);
    return db;
}

runSuite('Aggregate functions & GROUP BY / HAVING', [

    { name: 'COUNT(*)', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(*) AS n FROM sales').get();
        assertEqual(r.n, 5);
        db.close();
    }},

    { name: 'COUNT(col) ignores NULLs', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(amount) AS n FROM sales').get();
        assertEqual(r.n, 4, 'NULL row should not be counted');
        db.close();
    }},

    { name: 'SUM ignores NULLs', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT SUM(amount) AS s FROM sales').get();
        assertEqual(r.s, 500);
        db.close();
    }},

    { name: 'AVG ignores NULLs', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT AVG(amount) AS a FROM sales').get();
        assertEqual(r.a, 125, '500 / 4 non-null rows');
        db.close();
    }},

    { name: 'MIN', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT MIN(amount) AS m FROM sales').get();
        assertEqual(r.m, 50);
        db.close();
    }},

    { name: 'MAX', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT MAX(amount) AS m FROM sales').get();
        assertEqual(r.m, 200);
        db.close();
    }},

    { name: 'GROUP BY single column', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT dept, COUNT(*) AS n FROM sales GROUP BY dept ORDER BY dept').all();
        assertEqual(rows.length, 2);
        assertEqual(rows[0].dept, 'eng'); assertEqual(rows[0].n, 3);
        assertEqual(rows[1].dept, 'mkt'); assertEqual(rows[1].n, 2);
        db.close();
    }},

    { name: 'GROUP BY with SUM', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT dept, SUM(amount) AS total FROM sales GROUP BY dept ORDER BY dept').all();
        assertEqual(rows.find(function(r){return r.dept==='eng';}).total, 300);
        assertEqual(rows.find(function(r){return r.dept==='mkt';}).total, 200);
        db.close();
    }},

    { name: 'GROUP BY with AVG', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT dept, AVG(amount) AS avg FROM sales GROUP BY dept ORDER BY dept').all();
        // eng: (100+200)/2 = 150 (null excluded)
        assertEqual(rows.find(function(r){return r.dept==='eng';}).avg, 150);
        db.close();
    }},

    { name: 'HAVING filters groups', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT dept, SUM(amount) AS total FROM sales GROUP BY dept HAVING total > 250').all();
        assertEqual(rows.length, 1);
        assertEqual(rows[0].dept, 'eng');
        db.close();
    }},

    { name: 'HAVING COUNT(*)', fn: function () {
        var db = setup();
        var rows = db.prepare('SELECT dept FROM sales GROUP BY dept HAVING COUNT(*) > 2').all();
        assertEqual(rows.length, 1);
        assertEqual(rows[0].dept, 'eng');
        db.close();
    }},

    { name: 'aggregate over empty table', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (n INTEGER)');
        var r = db.prepare('SELECT COUNT(*) AS c, SUM(n) AS s FROM t').get();
        assertEqual(r.c, 0);
        assertEqual(r.s, null);
        db.close();
    }},

    { name: 'COUNT DISTINCT', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(DISTINCT dept) AS n FROM sales').get();
        assertEqual(r.n, 2);
        db.close();
    }},

    { name: 'GROUP_CONCAT', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, tag TEXT)');
        db.prepare('INSERT INTO t (id, tag) VALUES (?, ?)').run(1, 'a');
        db.prepare('INSERT INTO t (id, tag) VALUES (?, ?)').run(2, 'b');
        db.prepare('INSERT INTO t (id, tag) VALUES (?, ?)').run(3, 'c');
        var r = db.prepare('SELECT GROUP_CONCAT(tag) AS tags FROM t ORDER BY id').get();
        assertEqual(typeof r.tags, 'string');
        assertEqual(r.tags.split(',').length, 3, 'should have 3 tags');
        db.close();
    }},

    { name: 'multiple aggregates in one SELECT', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(*) AS n, MIN(amount) AS lo, MAX(amount) AS hi FROM sales').get();
        assertEqual(r.n, 5);
        assertEqual(r.lo, 50);
        assertEqual(r.hi, 200);
        db.close();
    }},

]);
