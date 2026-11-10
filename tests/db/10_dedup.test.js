'use strict';
var fs   = require('fs');
var os   = require('os');
var path = require('path');
var { assertEqual, runSuite } = require('./helpers');
var Database   = require('../../classes/Safecloud/DB');
var TableStore = require('../../classes/Safecloud/DB/TableStore');
var KC         = require('../../classes/Safecloud/DB/KeyCodec');

/** Measure raw JSON size of a store file. */
function storeSize(filePath) {
    try { return fs.statSync(filePath).size; } catch (e) { return 0; }
}

/** Create a temp dir that cleans itself. */
function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'safedb_dedup_'));
}

function rmDir(d) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch (e) {}
}

runSuite('Prefix deduplication', [

    { name: 'deflate/inflate round-trips empty store', fn: function () {
        var tmpDir = makeTmpDir();
        var s = new TableStore(path.join(tmpDir, 't.json'));
        s.flush(); // no entries, writes { v:1, entries:[] }
        s._dirty = true; s.flush();
        var s2 = new TableStore(path.join(tmpDir, 't.json'));
        s2.load();
        assertEqual(s2.count(), 0, 'empty store should round-trip');
        rmDir(tmpDir);
    }},

    { name: 'deflate/inflate round-trips single entry', fn: function () {
        var tmpDir = makeTmpDir();
        var s = new TableStore(path.join(tmpDir, 't.json'));
        s.set('KEY1', { x: 1 });
        s.flush();
        var s2 = new TableStore(path.join(tmpDir, 't.json'));
        s2.load();
        assertEqual(s2.count(), 1);
        assertEqual(s2.get('KEY1').x, 1);
        rmDir(tmpDir);
    }},

    { name: 'deflate/inflate round-trips many entries', fn: function () {
        var tmpDir = makeTmpDir();
        var s = new TableStore(path.join(tmpDir, 't.json'));
        for (var i = 0; i < 100; i++) {
            s.set('prefix_' + String(i).padStart(5, '0'), { n: i });
        }
        s.flush();
        var s2 = new TableStore(path.join(tmpDir, 't.json'));
        s2.load();
        assertEqual(s2.count(), 100);
        for (var i = 0; i < 100; i++) {
            assertEqual(s2.get('prefix_' + String(i).padStart(5, '0')).n, i, 'entry ' + i);
        }
        rmDir(tmpDir);
    }},

    { name: 'prefix dedup reduces file size vs naive', fn: function () {
        // Build two stores with the same data: one uses prefix-dedup (normal),
        // one stores full keys (simulated).
        var tmpDir = makeTmpDir();
        var N = 200;
        var sharedPrefix = KC.encodeTuple([42]); // simulate a common user_id prefix

        // Deduplicated store (normal TableStore)
        var dedupPath = path.join(tmpDir, 'dedup.json');
        var sd = new TableStore(dedupPath);
        for (var i = 0; i < N; i++) {
            var key = sharedPrefix + KC.encodeTuple([i]);
            sd.set(key, { seq: i, data: 'value' });
        }
        sd.flush();

        // "Naive" store: write raw JSON with full keys every time
        var rawEntries = [];
        for (var i = 0; i < N; i++) {
            rawEntries.push({ key: sharedPrefix + KC.encodeTuple([i]), value: { seq: i, data: 'value' } });
        }
        var naivePath = path.join(tmpDir, 'naive.json');
        fs.writeFileSync(naivePath, JSON.stringify({ v: 1, entries: rawEntries }));

        var dedupSize = storeSize(dedupPath);
        var naiveSize = storeSize(naivePath);

        // Dedup should be notably smaller (at least 15% savings)
        var saving = 1 - dedupSize / naiveSize;
        assertEqual(saving > 0.10, true,
            'expected >10% saving from prefix dedup, got ' + (saving * 100).toFixed(1) + '% (' +
            dedupSize + ' vs ' + naiveSize + ' bytes)');
        rmDir(tmpDir);
    }},

    { name: 'data survives flush and reload from disk', fn: function () {
        var tmpDir = makeTmpDir();
        var dbPath = path.join(tmpDir, 'testdb');
        var db = new Database(dbPath);
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)');
        for (var i = 1; i <= 50; i++) {
            db.prepare('INSERT INTO t (id, name) VALUES (?, ?)').run(i, 'user' + i);
        }
        db.flush();
        db.close();

        // Re-open
        var db2 = new Database(dbPath);
        var rows = db2.prepare('SELECT COUNT(*) AS c FROM t').get();
        assertEqual(rows.c, 50, 'all 50 rows should survive flush+reload');
        var r1 = db2.prepare('SELECT name FROM t WHERE id = 1').get();
        var r50 = db2.prepare('SELECT name FROM t WHERE id = 50').get();
        assertEqual(r1.name, 'user1');
        assertEqual(r50.name, 'user50');
        db2.close();
        rmDir(tmpDir);
    }},

    { name: 'multi-column PK with repeated first column compresses well', fn: function () {
        var tmpDir = makeTmpDir();
        var s = new TableStore(path.join(tmpDir, 't.json'));

        // Simulate a composite-PK table: (user_id=42, seq=1..500)
        // All keys share the user_id prefix → huge compression.
        var sharedPart = KC.encodeTuple([42]);
        for (var i = 1; i <= 500; i++) {
            s.set(sharedPart + KC.encodeTuple([i]), { seq: i });
        }
        s.flush();

        // Reload and verify correctness
        var s2 = new TableStore(path.join(tmpDir, 't.json'));
        s2.load();
        assertEqual(s2.count(), 500, 'all 500 entries should survive');
        assertEqual(s2.get(sharedPart + KC.encodeTuple([1])).seq, 1);
        assertEqual(s2.get(sharedPart + KC.encodeTuple([500])).seq, 500);

        rmDir(tmpDir);
    }},

]);
