'use strict';
var { makeDB, assertEqual, assertDeepEqual, assertThrows, runSuite } = require('./helpers');

function setup() {
    var db = makeDB();
    db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER)');
    return db;
}

runSuite('CRUD — INSERT / SELECT / UPDATE / DELETE', [

    { name: 'INSERT positional params + SELECT *', fn: function () {
        var db = setup();
        var ins = db.prepare('INSERT INTO users (id, name, age) VALUES (?, ?, ?)');
        ins.run(1, 'Alice', 30);
        ins.run(2, 'Bob', 25);
        var rows = db.prepare('SELECT * FROM users').all();
        assertEqual(rows.length, 2);
        db.close();
    }},

    { name: 'INSERT named params', fn: function () {
        var db = setup();
        var ins = db.prepare('INSERT INTO users (id, name, age) VALUES (:id, :name, :age)');
        ins.run({ id: 1, name: 'Alice', age: 30 });
        var row = db.prepare('SELECT * FROM users WHERE id = 1').get();
        assertEqual(row.name, 'Alice');
        db.close();
    }},

    { name: 'INSERT auto-increment', fn: function () {
        var db = makeDB();
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)');
        var ins = db.prepare('INSERT INTO t (val) VALUES (?)');
        var r1 = ins.run('a');
        var r2 = ins.run('b');
        assertEqual(r1.lastInsertRowid, 1);
        assertEqual(r2.lastInsertRowid, 2);
        db.close();
    }},

    { name: 'INSERT returns correct changes count', fn: function () {
        var db = setup();
        var r = db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 20)').run('X');
        assertEqual(r.changes, 1);
        db.close();
    }},

    { name: 'SELECT specific columns', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 30)').run('Alice');
        var row = db.prepare('SELECT id, name FROM users WHERE id = 1').get();
        assertEqual(Object.keys(row).length, 2);
        assertEqual(row.id, 1);
        assertEqual(row.name, 'Alice');
        db.close();
    }},

    { name: 'SELECT aliased columns', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 30)').run('Alice');
        var row = db.prepare("SELECT name AS n, age AS years FROM users WHERE id = 1").get();
        assertEqual(row.n, 'Alice');
        assertEqual(row.years, 30);
        db.close();
    }},

    { name: 'SELECT with WHERE = param', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 30)').run('Alice');
        db.prepare('INSERT INTO users (id, name, age) VALUES (2, ?, 25)').run('Bob');
        var row = db.prepare('SELECT * FROM users WHERE id = ?').get(2);
        assertEqual(row.name, 'Bob');
        db.close();
    }},

    { name: 'SELECT .get() returns undefined for no match', fn: function () {
        var db = setup();
        var row = db.prepare('SELECT * FROM users WHERE id = 999').get();
        assertEqual(row, undefined);
        db.close();
    }},

    { name: 'UPDATE single column', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 20)').run('Alice');
        var r = db.prepare('UPDATE users SET age = ? WHERE id = 1').run(99);
        assertEqual(r.changes, 1);
        var row = db.prepare('SELECT age FROM users WHERE id = 1').get();
        assertEqual(row.age, 99);
        db.close();
    }},

    { name: 'UPDATE multiple columns', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 20)').run('Alice');
        db.prepare("UPDATE users SET name = ?, age = ? WHERE id = 1").run('Zara', 40);
        var row = db.prepare('SELECT * FROM users WHERE id = 1').get();
        assertEqual(row.name, 'Zara');
        assertEqual(row.age, 40);
        db.close();
    }},

    { name: 'UPDATE returns 0 changes when no match', fn: function () {
        var db = setup();
        var r = db.prepare('UPDATE users SET age = 1 WHERE id = 999').run();
        assertEqual(r.changes, 0);
        db.close();
    }},

    { name: 'DELETE single row', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 20)').run('Alice');
        db.prepare('INSERT INTO users (id, name, age) VALUES (2, ?, 25)').run('Bob');
        var r = db.prepare('DELETE FROM users WHERE id = 1').run();
        assertEqual(r.changes, 1);
        var rows = db.prepare('SELECT * FROM users').all();
        assertEqual(rows.length, 1);
        assertEqual(rows[0].name, 'Bob');
        db.close();
    }},

    { name: 'DELETE all rows', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 20)').run('Alice');
        db.prepare('INSERT INTO users (id, name, age) VALUES (2, ?, 25)').run('Bob');
        db.prepare('DELETE FROM users').run();
        var rows = db.prepare('SELECT * FROM users').all();
        assertEqual(rows.length, 0);
        db.close();
    }},

    { name: 'pluck() returns first column value', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 30)').run('Alice');
        var name = db.prepare('SELECT name FROM users WHERE id = 1').pluck().get();
        assertEqual(name, 'Alice');
        db.close();
    }},

    { name: 'iterate() yields rows one by one', fn: function () {
        var db = setup();
        db.prepare('INSERT INTO users (id, name, age) VALUES (1, ?, 20)').run('Alice');
        db.prepare('INSERT INTO users (id, name, age) VALUES (2, ?, 25)').run('Bob');
        var names = [];
        for (var row of db.prepare('SELECT name FROM users ORDER BY id').iterate()) {
            names.push(row.name);
        }
        assertDeepEqual(names, ['Alice', 'Bob']);
        db.close();
    }},

    { name: 'exec() runs multiple statements', fn: function () {
        var db = makeDB();
        db.exec(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);" +
            "INSERT INTO t VALUES (1, 'a');" +
            "INSERT INTO t VALUES (2, 'b');"
        );
        var rows = db.prepare('SELECT * FROM t').all();
        assertEqual(rows.length, 2);
        db.close();
    }},

]);
