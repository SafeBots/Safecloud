'use strict';
var { makeDB, assertEqual, assertDeepEqual, runSuite } = require('./helpers');

function setup() {
    var db = makeDB();
    db.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT);
    `);
    db.prepare('INSERT INTO users (id, name) VALUES (?, ?)').run(1, 'Alice');
    db.prepare('INSERT INTO users (id, name) VALUES (?, ?)').run(2, 'Bob');
    db.prepare('INSERT INTO users (id, name) VALUES (?, ?)').run(3, 'Carol');
    db.prepare('INSERT INTO orders (id, user_id, item) VALUES (?, ?, ?)').run(10, 1, 'Widget');
    db.prepare('INSERT INTO orders (id, user_id, item) VALUES (?, ?, ?)').run(11, 1, 'Gadget');
    db.prepare('INSERT INTO orders (id, user_id, item) VALUES (?, ?, ?)').run(12, 2, 'Doohickey');
    return db;
}

runSuite('JOINs', [

    { name: 'INNER JOIN basic', fn: function () {
        var db = setup();
        var rows = db.prepare(
            'SELECT users.name, orders.item FROM users JOIN orders ON users.id = orders.user_id ORDER BY orders.id'
        ).all();
        assertEqual(rows.length, 3);
        assertEqual(rows[0].name, 'Alice');
        assertEqual(rows[0].item, 'Widget');
        db.close();
    }},

    { name: 'INNER JOIN excludes non-matching rows', fn: function () {
        var db = setup();
        var rows = db.prepare(
            'SELECT users.name FROM users INNER JOIN orders ON users.id = orders.user_id'
        ).all();
        // Carol has no orders → not included
        var names = rows.map(function(r){return r.name;});
        assertEqual(names.includes('Carol'), false, 'Carol should be excluded');
        db.close();
    }},

    { name: 'LEFT JOIN includes rows with no match', fn: function () {
        var db = setup();
        var rows = db.prepare(
            'SELECT users.name, orders.item FROM users LEFT JOIN orders ON users.id = orders.user_id ORDER BY users.id'
        ).all();
        // Carol should appear with null item
        var carol = rows.find(function(r){return r.name === 'Carol';});
        assertEqual(!!carol, true, 'Carol should appear in LEFT JOIN');
        assertEqual(carol.item, null, "Carol's item should be null");
        db.close();
    }},

    { name: 'LEFT JOIN preserves all left rows', fn: function () {
        var db = setup();
        var rows = db.prepare(
            'SELECT users.name FROM users LEFT JOIN orders ON users.id = orders.user_id'
        ).all();
        var names = rows.map(function(r){return r.name;});
        assertEqual(names.includes('Carol'), true);
        db.close();
    }},

    { name: 'JOIN with WHERE filters after join', fn: function () {
        var db = setup();
        var rows = db.prepare(
            "SELECT users.name, orders.item FROM users JOIN orders ON users.id = orders.user_id WHERE orders.item = 'Gadget'"
        ).all();
        assertEqual(rows.length, 1);
        assertEqual(rows[0].name, 'Alice');
        db.close();
    }},

    { name: 'self-join', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE emp (id INTEGER PRIMARY KEY, name TEXT, mgr_id INTEGER)');
        db.prepare('INSERT INTO emp (id, name, mgr_id) VALUES (?, ?, ?)').run(1, 'Boss', null);
        db.prepare('INSERT INTO emp (id, name, mgr_id) VALUES (?, ?, ?)').run(2, 'Worker', 1);
        var rows = db.prepare(
            'SELECT e.name AS emp, m.name AS mgr FROM emp e LEFT JOIN emp m ON e.mgr_id = m.id'
        ).all();
        assertEqual(rows.length, 2);
        var worker = rows.find(function(r){return r.emp === 'Worker';});
        assertEqual(worker.mgr, 'Boss');
        db.close();
    }},

    { name: 'JOIN aggregation', fn: function () {
        var db = setup();
        var rows = db.prepare(
            'SELECT users.name, COUNT(orders.id) AS cnt FROM users LEFT JOIN orders ON users.id = orders.user_id GROUP BY users.id ORDER BY users.id'
        ).all();
        assertEqual(rows.length, 3);
        assertEqual(rows[0].cnt, 2, 'Alice has 2 orders');
        assertEqual(rows[1].cnt, 1, 'Bob has 1 order');
        // Carol: COUNT of NULL order IDs
        // Our engine counts non-null values; for Carol all order cols are null → 0
        assertEqual(rows[2].cnt, 0, 'Carol has 0 orders');
        db.close();
    }},

    { name: 'two-table join, aliased columns', fn: function () {
        var db = setup();
        var rows = db.prepare(
            'SELECT u.name AS who, o.item AS what FROM users u JOIN orders o ON u.id = o.user_id WHERE u.id = 1 ORDER BY o.id'
        ).all();
        assertDeepEqual(rows.map(function(r){return r.what;}), ['Widget','Gadget']);
        db.close();
    }},

]);
