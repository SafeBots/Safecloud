'use strict';
var { makeDB, assertEqual, assertDeepEqual, runSuite } = require('./helpers');

function setup() {
    var db = makeDB();
    db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT, n REAL)');
    var ins = db.prepare('INSERT INTO t (id, s, n) VALUES (?, ?, ?)');
    ins.run(1, 'apple',  1.5);
    ins.run(2, 'banana', 2.5);
    ins.run(3, 'cherry', 3.5);
    ins.run(4, 'date',   null);
    ins.run(5, null,     5.0);
    return db;
}

runSuite('WHERE — operators and expressions', [

    { name: '= on integer', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT s FROM t WHERE id = 2').get();
        assertEqual(r.s, 'banana');
        db.close();
    }},

    { name: '!= / <>', fn: function () {
        var db = setup();
        var r1 = db.prepare('SELECT COUNT(*) AS c FROM t WHERE id != 1').get();
        var r2 = db.prepare('SELECT COUNT(*) AS c FROM t WHERE id <> 1').get();
        assertEqual(r1.c, 4);
        assertEqual(r2.c, 4);
        db.close();
    }},

    { name: '< and >', fn: function () {
        var db = setup();
        var r1 = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n < 3').get();
        var r2 = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n > 3').get();
        assertEqual(r1.c, 2, '< 3');
        assertEqual(r2.c, 2, '> 3');
        db.close();
    }},

    { name: '<= and >=', fn: function () {
        var db = setup();
        var r1 = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n <= 2.5').get();
        var r2 = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n >= 3.5').get();
        assertEqual(r1.c, 2, '<= 2.5');
        assertEqual(r2.c, 2, '>= 3.5');
        db.close();
    }},

    { name: 'BETWEEN inclusive', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n BETWEEN 1.5 AND 3.5').get();
        assertEqual(r.c, 3);
        db.close();
    }},

    { name: 'NOT BETWEEN', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n NOT BETWEEN 2 AND 4').get();
        // n=1.5 and n=5.0 qualify (n=null rows excluded by comparison)
        assertEqual(r.c, 2);
        db.close();
    }},

    { name: 'IN list', fn: function () {
        var db = setup();
        var r = db.prepare("SELECT s FROM t WHERE s IN ('apple', 'cherry') ORDER BY id").all();
        assertDeepEqual(r.map(function(x){return x.s;}), ['apple','cherry']);
        db.close();
    }},

    { name: 'NOT IN list', fn: function () {
        var db = setup();
        // rows without NULL s: 1,2,3,4
        var r = db.prepare("SELECT COUNT(*) AS c FROM t WHERE s NOT IN ('apple','banana') AND s IS NOT NULL").get();
        assertEqual(r.c, 2, 'cherry and date');
        db.close();
    }},

    { name: 'IS NULL', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT id FROM t WHERE n IS NULL').get();
        assertEqual(r.id, 4);
        db.close();
    }},

    { name: 'IS NOT NULL', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(*) AS c FROM t WHERE n IS NOT NULL').get();
        assertEqual(r.c, 4);
        db.close();
    }},

    { name: 'LIKE % wildcard', fn: function () {
        var db = setup();
        var r = db.prepare("SELECT s FROM t WHERE s LIKE 'a%'").get();
        assertEqual(r.s, 'apple');
        db.close();
    }},

    { name: 'LIKE _ wildcard', fn: function () {
        var db = setup();
        // 'date' has 4 chars → matches 'd__e' (two underscores)
        var r = db.prepare("SELECT s FROM t WHERE s LIKE 'd__e'").get();
        assertEqual(r.s, 'date');
        db.close();
    }},

    { name: 'NOT LIKE', fn: function () {
        var db = setup();
        var r = db.prepare("SELECT COUNT(*) AS c FROM t WHERE s NOT LIKE 'a%' AND s IS NOT NULL").get();
        assertEqual(r.c, 3); // banana, cherry, date
        db.close();
    }},

    { name: 'AND combines conditions', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT id FROM t WHERE id > 1 AND id < 4 AND n > 2').get();
        assertEqual(r.id, 2);
        db.close();
    }},

    { name: 'OR selects either branch', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(*) AS c FROM t WHERE id = 1 OR id = 5').get();
        assertEqual(r.c, 2);
        db.close();
    }},

    { name: 'NOT inverts condition', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COUNT(*) AS c FROM t WHERE NOT id = 1').get();
        assertEqual(r.c, 4);
        db.close();
    }},

    { name: 'arithmetic in WHERE', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT id FROM t WHERE n * 2 > 8').get();
        assertEqual(r.id, 5);
        db.close();
    }},

    { name: 'string concat ||', fn: function () {
        var db = setup();
        var r = db.prepare("SELECT s || '!' AS v FROM t WHERE id = 1").get();
        assertEqual(r.v, 'apple!');
        db.close();
    }},

    { name: 'CASE WHEN THEN ELSE', fn: function () {
        var db = setup();
        var r = db.prepare(
            "SELECT CASE WHEN n < 2 THEN 'low' WHEN n < 4 THEN 'mid' ELSE 'high' END AS band FROM t WHERE id = 1"
        ).get();
        assertEqual(r.band, 'low');
        db.close();
    }},

    { name: 'COALESCE returns first non-null', fn: function () {
        var db = setup();
        var r = db.prepare('SELECT COALESCE(s, n, 99) AS v FROM t WHERE id = 5').get();
        assertEqual(r.v, 5.0); // s is null so fallback to n
        db.close();
    }},

    { name: 'IS / IS NOT distinguishes NULL', fn: function () {
        var db = setup();
        var r1 = db.prepare('SELECT id FROM t WHERE s IS NULL').get();
        var r2 = db.prepare('SELECT id FROM t WHERE n IS NOT NULL AND id = 4').get();
        assertEqual(r1.id, 5);
        assertEqual(r2, undefined, 'n=null for id=4 so IS NOT NULL should miss');
        db.close();
    }},

]);
