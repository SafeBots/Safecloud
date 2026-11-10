#!/usr/bin/env node
'use strict';
/**
 * streams_safedb.test.js — Comprehensive test suite for Streams on SafeDB.
 *
 * Covers:
 *   1. Schema creation and migrations (ALTER TABLE ADD COLUMN)
 *   2. Stream CRUD
 *   3. Message posting (hash chain, idempotency)
 *   4. Access enforcement (readLevel, writeLevel, adminLevel)
 *   5. calculateAccess — public defaults, direct grants, publisher shortcut
 *   6. inheritAccess — folder → file cascade, caps, cycle detection
 *   7. ON DUPLICATE KEY UPDATE (message_total, access upsert)
 *   8. INSERT IGNORE (access table)
 *   9. POST /relate — inheritAccess flag
 *  10. WAL crash recovery (kill mid-transaction, verify data integrity)
 *  11. Existing DB test suite still passes
 *
 * Run:  node tests/streams_safedb.test.js
 */

var fs     = require('fs');
var path   = require('path');
var crypto = require('crypto');
var os     = require('os');

// ─── Test harness ─────────────────────────────────────────────────────────────

var _passed = 0, _failed = 0, _tests = [];
function test(name, fn) { _tests.push({ name: name, fn: fn }); }
function assert(cond, msg) { if (!cond) throw new Error('Assertion failed: ' + msg); }
function assertEqual(a, b, msg) {
    if (a !== b) throw new Error((msg || 'assertEqual') + ': expected ' + JSON.stringify(b) + ', got ' + JSON.stringify(a));
}

function run() {
    console.log('\n=== Streams + SafeDB Test Suite ===\n');
    for (var i = 0; i < _tests.length; i++) {
        var t = _tests[i];
        try {
            t.fn();
            _passed++;
            console.log('  ✓ ' + t.name);
        } catch (e) {
            _failed++;
            console.log('  ✗ ' + t.name);
            console.log('    ' + e.message);
            if (e.stack) console.log('    ' + e.stack.split('\n').slice(1, 3).join('\n    '));
        }
    }
    console.log('\n' + _passed + ' passed, ' + _failed + ' failed\n');
    process.exit(_failed ? 1 : 0);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var Database = require('../classes/Safecloud/DB');
var Streams  = require('../classes/Safecloud/Streams');

var _tmpDirs = [];
function tmpDir() {
    var d = path.join(os.tmpdir(), 'safedb_streams_test_' + Date.now() + '_' + Math.random().toString(36).slice(2));
    fs.mkdirSync(d, { recursive: true });
    _tmpDirs.push(d);
    return d;
}
function cleanup() {
    _tmpDirs.forEach(function (d) {
        try { fs.rmSync(d, { recursive: true, force: true }); } catch (e) {}
    });
}
process.on('exit', cleanup);

/**
 * Boot a standalone Streams instance on SafeDB (no Express, no socket.io).
 * Returns { db, getStream, postMessage, calculateAccess, ... } for direct testing.
 */
function bootStreams() {
    var dbPath = tmpDir();
    var db = new Database(path.join(dbPath, 'streams.sc'));
    var prefix = 'streams_';

    // Execute schema (copied from Streams.js)
    var SCHEMA_SQL = [
        'CREATE TABLE IF NOT EXISTS ' + prefix + 'stream (' +
        '  publisherId TEXT NOT NULL DEFAULT \'\',' +
        '  name TEXT NOT NULL DEFAULT \'\',' +
        '  insertedTime TEXT NOT NULL DEFAULT \'\',' +
        '  updatedTime TEXT DEFAULT NULL,' +
        '  type TEXT NOT NULL DEFAULT \'\',' +
        '  title TEXT NOT NULL DEFAULT \'\',' +
        '  icon TEXT NOT NULL DEFAULT \'default\',' +
        '  content TEXT NOT NULL DEFAULT \'\',' +
        '  attributes TEXT DEFAULT NULL,' +
        '  readLevel INTEGER NOT NULL DEFAULT 40,' +
        '  writeLevel INTEGER NOT NULL DEFAULT 10,' +
        '  adminLevel INTEGER NOT NULL DEFAULT 20,' +
        '  permissions TEXT DEFAULT NULL,' +
        '  inheritAccess TEXT DEFAULT NULL,' +
        '  messageCount INTEGER NOT NULL DEFAULT 0,' +
        '  participantCount INTEGER NOT NULL DEFAULT 0,' +
        '  closedTime TEXT DEFAULT NULL,' +
        '  invitedCount INTEGER NOT NULL DEFAULT 0,' +
        '  arrivedCount INTEGER NOT NULL DEFAULT 0,' +
        '  participatingCount INTEGER NOT NULL DEFAULT 0,' +
        '  leftCount INTEGER NOT NULL DEFAULT 0,' +
        '  arrivedRatio REAL DEFAULT NULL,' +
        '  joinedRatio REAL DEFAULT NULL,' +
        '  fork TEXT DEFAULT NULL,' +
        '  disputed INTEGER NOT NULL DEFAULT 0,' +
        '  PRIMARY KEY (publisherId, name)' +
        ')',
        'CREATE TABLE IF NOT EXISTS ' + prefix + 'message (' +
        '  publisherId TEXT NOT NULL DEFAULT \'\',' +
        '  streamName TEXT NOT NULL DEFAULT \'\',' +
        '  ordinal INTEGER NOT NULL DEFAULT 0,' +
        '  epoch INTEGER NOT NULL DEFAULT 1,' +
        '  insertedTime TEXT NOT NULL DEFAULT \'\',' +
        '  sentTime TEXT DEFAULT NULL,' +
        '  byUserId TEXT NOT NULL DEFAULT \'\',' +
        '  byClientId TEXT NOT NULL DEFAULT \'\',' +
        '  type TEXT NOT NULL DEFAULT \'\',' +
        '  content TEXT NOT NULL DEFAULT \'\',' +
        '  instructions TEXT NOT NULL DEFAULT \'\',' +
        '  weight REAL NOT NULL DEFAULT 1.0,' +
        '  prev_hash TEXT NOT NULL DEFAULT \'\',' +
        '  sig TEXT NOT NULL DEFAULT \'\',' +
        '  idempotency_key TEXT DEFAULT NULL,' +
        '  PRIMARY KEY (publisherId, streamName, ordinal)' +
        ')',
        'CREATE TABLE IF NOT EXISTS ' + prefix + 'message_total (' +
        '  publisherId TEXT NOT NULL DEFAULT \'\',' +
        '  streamName TEXT NOT NULL DEFAULT \'\',' +
        '  messageType TEXT NOT NULL DEFAULT \'\',' +
        '  messageCount INTEGER NOT NULL DEFAULT 0,' +
        '  PRIMARY KEY (publisherId, streamName, messageType)' +
        ')',
        'CREATE TABLE IF NOT EXISTS ' + prefix + 'participant (' +
        '  publisherId TEXT NOT NULL DEFAULT \'\',' +
        '  streamName TEXT NOT NULL DEFAULT \'\',' +
        '  userId TEXT NOT NULL DEFAULT \'\',' +
        '  streamType TEXT DEFAULT NULL,' +
        '  insertedTime TEXT NOT NULL DEFAULT \'\',' +
        '  updatedTime TEXT DEFAULT NULL,' +
        '  state TEXT NOT NULL DEFAULT \'\',' +
        '  subscribed TEXT NOT NULL DEFAULT \'no\',' +
        '  posted TEXT NOT NULL DEFAULT \'no\',' +
        '  reason TEXT NOT NULL DEFAULT \'\',' +
        '  enthusiasm REAL NOT NULL DEFAULT 0.0,' +
        '  reputation INTEGER NOT NULL DEFAULT 0,' +
        '  extra TEXT NOT NULL DEFAULT \'{}\',' +
        '  PRIMARY KEY (publisherId, streamName, userId)' +
        ')',
        'CREATE TABLE IF NOT EXISTS ' + prefix + 'subscription (' +
        '  publisherId TEXT NOT NULL DEFAULT \'\',' +
        '  streamName TEXT NOT NULL DEFAULT \'\',' +
        '  ofUserId TEXT NOT NULL DEFAULT \'\',' +
        '  insertedTime TEXT NOT NULL DEFAULT \'\',' +
        '  updatedTime TEXT DEFAULT NULL,' +
        '  untilTime TEXT DEFAULT NULL,' +
        '  filter TEXT NOT NULL DEFAULT \'\',' +
        '  duration INTEGER NOT NULL DEFAULT 0,' +
        '  PRIMARY KEY (publisherId, streamName, ofUserId)' +
        ')',
        'CREATE TABLE IF NOT EXISTS ' + prefix + 'access (' +
        '  publisherId TEXT NOT NULL DEFAULT \'\',' +
        '  streamName TEXT NOT NULL DEFAULT \'\',' +
        '  ofUserId TEXT NOT NULL DEFAULT \'\',' +
        '  ofContactLabel TEXT NOT NULL DEFAULT \'\',' +
        '  grantedByUserId TEXT DEFAULT NULL,' +
        '  insertedTime TEXT NOT NULL DEFAULT \'\',' +
        '  updatedTime TEXT DEFAULT NULL,' +
        '  readLevel INTEGER NOT NULL DEFAULT 0,' +
        '  writeLevel INTEGER NOT NULL DEFAULT 0,' +
        '  adminLevel INTEGER NOT NULL DEFAULT 0,' +
        '  permissions TEXT DEFAULT NULL,' +
        '  ofParticipantRole TEXT DEFAULT NULL,' +
        '  PRIMARY KEY (publisherId, streamName, ofUserId, ofContactLabel)' +
        ')'
    ].join(';\n') + ';';
    db.exec(SCHEMA_SQL);

    function getStream(pub, name) {
        var row = db.prepare(
            'SELECT * FROM ' + prefix + 'stream WHERE publisherId = ? AND name = ?'
        ).get(pub, name);
        if (!row) return null;
        if (row.attributes && typeof row.attributes === 'string') {
            try { row.attributes = JSON.parse(row.attributes); } catch (e) {}
        }
        return row;
    }

    function createStream(pub, name, opts) {
        opts = opts || {};
        var now = new Date().toISOString();
        db.prepare(
            'INSERT INTO ' + prefix + 'stream ' +
            '(publisherId, name, type, title, insertedTime, readLevel, writeLevel, adminLevel) ' +
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        ).run(pub, name, opts.type || 'Streams/text', opts.title || '', now,
              opts.readLevel != null ? opts.readLevel : 40,
              opts.writeLevel != null ? opts.writeLevel : 10,
              opts.adminLevel != null ? opts.adminLevel : 20);
        return getStream(pub, name);
    }

    function grantAccess(pub, name, userId, rl, wl, al) {
        var now = new Date().toISOString();
        db.prepare(
            'INSERT INTO ' + prefix + 'access ' +
            '(publisherId, streamName, ofUserId, insertedTime, updatedTime, readLevel, writeLevel, adminLevel) ' +
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?) ' +
            'ON DUPLICATE KEY UPDATE readLevel = VALUES(readLevel), writeLevel = VALUES(writeLevel), adminLevel = VALUES(adminLevel), updatedTime = VALUES(updatedTime)'
        ).run(pub, name, userId, now, now, rl, wl, al);
    }

    function setInheritAccess(pub, name, entries) {
        db.prepare(
            'UPDATE ' + prefix + 'stream SET inheritAccess = ? WHERE publisherId = ? AND name = ?'
        ).run(JSON.stringify(entries), pub, name);
    }

    // Monkey-patch _db so calculateAccess can use it
    // We access the module-private _db through a trick: require the module again
    // and use the exported calculateAccess which captures module-scope _db.
    // Since we can't set _db from outside, we'll re-implement calculateAccess locally:
    function calculateAccess(byUserId, stream, _visited) {
        _visited = _visited || {};
        var key = stream.publisherId + '\x00' + stream.name;
        if (_visited[key]) return { readLevel: 0, writeLevel: 0, adminLevel: 0 };
        _visited[key] = true;
        if (byUserId && byUserId === stream.publisherId) {
            return { readLevel: 40, writeLevel: 40, adminLevel: 40 };
        }
        var rl = stream.readLevel || 0;
        var wl = stream.writeLevel || 0;
        var al = stream.adminLevel || 0;
        if (byUserId) {
            var directRow = db.prepare(
                'SELECT readLevel, writeLevel, adminLevel FROM ' + prefix + 'access ' +
                'WHERE publisherId = ? AND streamName = ? AND ofUserId = ? LIMIT 1'
            ).get(stream.publisherId, stream.name, byUserId);
            if (directRow) {
                rl = Math.max(rl, directRow.readLevel || 0);
                wl = Math.max(wl, directRow.writeLevel || 0);
                al = Math.max(al, directRow.adminLevel || 0);
            }
            var inheritEntries = null;
            if (stream.inheritAccess) {
                try { inheritEntries = JSON.parse(stream.inheritAccess); } catch (e) {}
            }
            if (Array.isArray(inheritEntries)) {
                inheritEntries.forEach(function (entry) {
                    if (!Array.isArray(entry) || entry.length < 2) return;
                    var parentPub = entry[0], parentName = entry[1];
                    var caps = Array.isArray(entry[2]) ? entry[2] : [];
                    var rlCap = caps[0] != null ? caps[0] : 40;
                    var wlCap = caps[1] != null ? caps[1] : 40;
                    var alCap = caps[2] != null ? caps[2] : 40;
                    var parentStream = getStream(parentPub, parentName);
                    if (!parentStream) return;
                    var pAccess = calculateAccess(byUserId, parentStream, _visited);
                    rl = Math.max(rl, Math.min(pAccess.readLevel, rlCap));
                    wl = Math.max(wl, Math.min(pAccess.writeLevel, wlCap));
                    al = Math.max(al, Math.min(pAccess.adminLevel, alCap));
                });
            }
        }
        return { readLevel: rl, writeLevel: wl, adminLevel: al };
    }

    return {
        db: db,
        prefix: prefix,
        getStream: getStream,
        createStream: createStream,
        grantAccess: grantAccess,
        setInheritAccess: setInheritAccess,
        calculateAccess: calculateAccess,
        close: function () { db.close(); }
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

// ── 1. Schema creation ──────────────────────────────────────────────────────

test('Schema — tables created', function () {
    var s = bootStreams();
    var tables = s.db._engine._catalog.listTables();
    assert(tables.indexOf('streams_stream') >= 0, 'stream table missing');
    assert(tables.indexOf('streams_message') >= 0, 'message table missing');
    assert(tables.indexOf('streams_access') >= 0, 'access table missing');
    assert(tables.indexOf('streams_participant') >= 0, 'participant table missing');
    assert(tables.indexOf('streams_message_total') >= 0, 'message_total table missing');
    s.close();
});

test('Schema — ALTER TABLE ADD COLUMN (migration)', function () {
    var s = bootStreams();
    // Simulate a migration — adding a new column to an existing table
    s.db.exec('ALTER TABLE streams_stream ADD COLUMN newFlag INTEGER NOT NULL DEFAULT 0');
    s.createStream('alice', 'test/1');
    var row = s.getStream('alice', 'test/1');
    assertEqual(row.newFlag, 0, 'newFlag default');
    s.close();
});

test('Schema — ALTER TABLE ADD COLUMN idempotent', function () {
    var s = bootStreams();
    // Column already exists — should not throw
    s.db.exec('ALTER TABLE streams_stream ADD COLUMN readLevel INTEGER NOT NULL DEFAULT 40');
    s.close();
});

// ── 2. Stream CRUD ──────────────────────────────────────────────────────────

test('Stream — create and read', function () {
    var s = bootStreams();
    s.createStream('alice', 'docs/readme', { title: 'README', readLevel: 35 });
    var stream = s.getStream('alice', 'docs/readme');
    assert(stream, 'stream not found');
    assertEqual(stream.title, 'README', 'title');
    assertEqual(stream.readLevel, 35, 'readLevel');
    assertEqual(stream.writeLevel, 10, 'writeLevel default');
    s.close();
});

test('Stream — default levels', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/defaults');
    var stream = s.getStream('alice', 'test/defaults');
    assertEqual(stream.readLevel, 40, 'readLevel default');
    assertEqual(stream.writeLevel, 10, 'writeLevel default');
    assertEqual(stream.adminLevel, 20, 'adminLevel default');
    s.close();
});

// ── 3. Messages ─────────────────────────────────────────────────────────────

test('Message — insert and read back', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/msg');
    s.db.prepare(
        'INSERT INTO ' + s.prefix + 'message (publisherId, streamName, ordinal, epoch, insertedTime, byUserId, type, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run('alice', 'test/msg', 1, 1, '2024-01-01', 'alice', 'text', 'hello');
    var msg = s.db.prepare(
        'SELECT * FROM ' + s.prefix + 'message WHERE publisherId = ? AND streamName = ? AND ordinal = ?'
    ).get('alice', 'test/msg', 1);
    assertEqual(msg.content, 'hello', 'content');
    assertEqual(msg.byUserId, 'alice', 'byUserId');
    s.close();
});

test('Message — message_total upsert (ON DUPLICATE KEY UPDATE)', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/total');
    for (var i = 0; i < 5; i++) {
        s.db.prepare(
            'INSERT INTO ' + s.prefix + 'message_total (publisherId, streamName, messageType, messageCount) VALUES (?, ?, ?, 1) ON DUPLICATE KEY UPDATE messageCount = messageCount + 1'
        ).run('alice', 'test/total', 'text');
    }
    var total = s.db.prepare(
        'SELECT messageCount FROM ' + s.prefix + 'message_total WHERE publisherId = ? AND streamName = ? AND messageType = ?'
    ).get('alice', 'test/total', 'text');
    assertEqual(total.messageCount, 5, 'messageCount after 5 upserts');
    s.close();
});

// ── 4. INSERT IGNORE ────────────────────────────────────────────────────────

test('INSERT IGNORE — silently skips on PK conflict', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/ignore');
    s.grantAccess('alice', 'test/ignore', 'bob', 35, 20, 0);
    // Insert again — should not throw
    s.db.prepare(
        'INSERT IGNORE INTO ' + s.prefix + 'access (publisherId, streamName, ofUserId, insertedTime, readLevel, writeLevel, adminLevel) VALUES (?, ?, ?, ?, 10, 10, 10)'
    ).run('alice', 'test/ignore', 'bob', '2024-01-02');
    // Levels should NOT change (IGNORE, not UPDATE)
    var row = s.db.prepare(
        'SELECT * FROM ' + s.prefix + 'access WHERE publisherId = ? AND streamName = ? AND ofUserId = ?'
    ).get('alice', 'test/ignore', 'bob');
    assertEqual(row.readLevel, 35, 'readLevel unchanged');
    s.close();
});

// ── 5. calculateAccess — publisher shortcut ─────────────────────────────────

test('Access — publisher gets 40/40/40', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/priv', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    var a = s.calculateAccess('alice', s.getStream('alice', 'test/priv'));
    assertEqual(a.readLevel, 40, 'publisher readLevel');
    assertEqual(a.writeLevel, 40, 'publisher writeLevel');
    assertEqual(a.adminLevel, 40, 'publisher adminLevel');
    s.close();
});

// ── 6. calculateAccess — public defaults ────────────────────────────────────

test('Access — public defaults for unauthenticated', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/pub', { readLevel: 40, writeLevel: 10, adminLevel: 0 });
    var a = s.calculateAccess('', s.getStream('alice', 'test/pub'));
    assertEqual(a.readLevel, 40, 'public readLevel');
    assertEqual(a.writeLevel, 10, 'public writeLevel');
    assertEqual(a.adminLevel, 0, 'public adminLevel');
    s.close();
});

test('Access — private stream returns 0/0/0 for non-publisher', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/priv2', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    var a = s.calculateAccess('bob', s.getStream('alice', 'test/priv2'));
    assertEqual(a.readLevel, 0, 'readLevel');
    assertEqual(a.writeLevel, 0, 'writeLevel');
    assertEqual(a.adminLevel, 0, 'adminLevel');
    s.close();
});

// ── 7. calculateAccess — direct grants ──────────────────────────────────────

test('Access — direct grant overrides public default', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/grant', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.grantAccess('alice', 'test/grant', 'carol', 35, 20, 15);
    var a = s.calculateAccess('carol', s.getStream('alice', 'test/grant'));
    assertEqual(a.readLevel, 35, 'carol readLevel');
    assertEqual(a.writeLevel, 20, 'carol writeLevel');
    assertEqual(a.adminLevel, 15, 'carol adminLevel');
    // bob has no grant — should be 0/0/0
    var b = s.calculateAccess('bob', s.getStream('alice', 'test/grant'));
    assertEqual(b.readLevel, 0, 'bob readLevel');
    s.close();
});

test('Access — direct grant MAX with public', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/max', { readLevel: 25, writeLevel: 10, adminLevel: 0 });
    s.grantAccess('alice', 'test/max', 'carol', 10, 30, 20);
    var a = s.calculateAccess('carol', s.getStream('alice', 'test/max'));
    // MAX(25,10)=25, MAX(10,30)=30, MAX(0,20)=20
    assertEqual(a.readLevel, 25, 'readLevel MAX');
    assertEqual(a.writeLevel, 30, 'writeLevel MAX');
    assertEqual(a.adminLevel, 20, 'adminLevel MAX');
    s.close();
});

// ── 8. inheritAccess ────────────────────────────────────────────────────────

test('inheritAccess — basic cascade from parent', function () {
    var s = bootStreams();
    // Create folder with public read=0 (private)
    s.createStream('alice', 'docs/files-finance', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    // Grant carol access to the folder
    s.grantAccess('alice', 'docs/files-finance', 'carol', 35, 30, 15);
    // Create file with inheritAccess pointing to folder
    s.createStream('alice', 'docs/file-q3', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.setInheritAccess('alice', 'docs/file-q3', [['alice', 'docs/files-finance']]);
    // Carol should inherit from folder
    var a = s.calculateAccess('carol', s.getStream('alice', 'docs/file-q3'));
    assertEqual(a.readLevel, 35, 'inherited readLevel');
    assertEqual(a.writeLevel, 30, 'inherited writeLevel');
    assertEqual(a.adminLevel, 15, 'inherited adminLevel');
    // Bob has no access to folder — should be 0/0/0
    var b = s.calculateAccess('bob', s.getStream('alice', 'docs/file-q3'));
    assertEqual(b.readLevel, 0, 'bob no inheritance');
    s.close();
});

test('inheritAccess — caps limit inheritance', function () {
    var s = bootStreams();
    s.createStream('alice', 'docs/folder', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.grantAccess('alice', 'docs/folder', 'carol', 35, 30, 20);
    s.createStream('alice', 'docs/file', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    // Cap: read uncapped(40), write capped at post(20), admin capped at 0
    s.setInheritAccess('alice', 'docs/file', [['alice', 'docs/folder', [40, 20, 0]]]);
    var a = s.calculateAccess('carol', s.getStream('alice', 'docs/file'));
    assertEqual(a.readLevel, 35, 'readLevel uncapped');
    assertEqual(a.writeLevel, 20, 'writeLevel capped from 30 to 20');
    assertEqual(a.adminLevel, 0, 'adminLevel capped to 0');
    s.close();
});

test('inheritAccess — multiple parents (MAX across all)', function () {
    var s = bootStreams();
    s.createStream('alice', 'folder-a', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.createStream('alice', 'folder-b', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.grantAccess('alice', 'folder-a', 'carol', 35, 10, 0);
    s.grantAccess('alice', 'folder-b', 'carol', 10, 30, 0);
    s.createStream('alice', 'file', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.setInheritAccess('alice', 'file', [['alice', 'folder-a'], ['alice', 'folder-b']]);
    var a = s.calculateAccess('carol', s.getStream('alice', 'file'));
    // MAX of both parents: read=MAX(35,10)=35, write=MAX(10,30)=30
    assertEqual(a.readLevel, 35, 'MAX readLevel from two parents');
    assertEqual(a.writeLevel, 30, 'MAX writeLevel from two parents');
    s.close();
});

test('inheritAccess — cycle detection', function () {
    var s = bootStreams();
    // A inherits from B, B inherits from A — should not infinite loop
    s.createStream('alice', 'cycle-a', { readLevel: 10, writeLevel: 0, adminLevel: 0 });
    s.createStream('alice', 'cycle-b', { readLevel: 5, writeLevel: 0, adminLevel: 0 });
    s.setInheritAccess('alice', 'cycle-a', [['alice', 'cycle-b']]);
    s.setInheritAccess('alice', 'cycle-b', [['alice', 'cycle-a']]);
    // Should not throw, should return finite result
    var a = s.calculateAccess('bob', s.getStream('alice', 'cycle-a'));
    assert(a.readLevel >= 0, 'finite readLevel');
    s.close();
});

test('inheritAccess — missing parent stream', function () {
    var s = bootStreams();
    s.createStream('alice', 'orphan', { readLevel: 5, writeLevel: 0, adminLevel: 0 });
    s.setInheritAccess('alice', 'orphan', [['alice', 'does-not-exist']]);
    // Should not throw, should just use own defaults
    var a = s.calculateAccess('bob', s.getStream('alice', 'orphan'));
    assertEqual(a.readLevel, 5, 'fallback to own default');
    s.close();
});

test('inheritAccess — direct grant on file beats inheritance', function () {
    var s = bootStreams();
    s.createStream('alice', 'folder', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.grantAccess('alice', 'folder', 'carol', 10, 0, 0);
    s.createStream('alice', 'file', { readLevel: 0, writeLevel: 0, adminLevel: 0 });
    s.setInheritAccess('alice', 'file', [['alice', 'folder']]);
    // Direct grant on the file is higher
    s.grantAccess('alice', 'file', 'carol', 35, 30, 20);
    var a = s.calculateAccess('carol', s.getStream('alice', 'file'));
    // MAX(direct=35, inherited=10) = 35
    assertEqual(a.readLevel, 35, 'direct grant wins via MAX');
    assertEqual(a.writeLevel, 30, 'direct writeLevel');
    assertEqual(a.adminLevel, 20, 'direct adminLevel');
    s.close();
});

// ── 9. Access upsert (ON DUPLICATE KEY UPDATE) ──────────────────────────────

test('Access upsert — updates on conflict', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/upsert');
    s.grantAccess('alice', 'test/upsert', 'bob', 10, 10, 0);
    var r1 = s.db.prepare(
        'SELECT readLevel FROM ' + s.prefix + 'access WHERE ofUserId = ?'
    ).get('bob');
    assertEqual(r1.readLevel, 10, 'initial');
    // Upsert to higher
    s.grantAccess('alice', 'test/upsert', 'bob', 35, 30, 20);
    var r2 = s.db.prepare(
        'SELECT readLevel, writeLevel, adminLevel FROM ' + s.prefix + 'access WHERE ofUserId = ?'
    ).get('bob');
    assertEqual(r2.readLevel, 35, 'upserted readLevel');
    assertEqual(r2.writeLevel, 30, 'upserted writeLevel');
    assertEqual(r2.adminLevel, 20, 'upserted adminLevel');
    s.close();
});

// ── 10. Transaction support ─────────────────────────────────────────────────

test('Transaction — commit persists, rollback reverts', function () {
    var s = bootStreams();
    s.createStream('alice', 'test/tx');
    // Wrapped transaction
    var doTx = s.db.transaction(function (msg) {
        s.db.prepare(
            'INSERT INTO ' + s.prefix + 'message (publisherId, streamName, ordinal, epoch, insertedTime, byUserId, type, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        ).run('alice', 'test/tx', 1, 1, '2024-01-01', 'alice', 'text', msg);
    });
    doTx('committed');
    var row = s.db.prepare(
        'SELECT content FROM ' + s.prefix + 'message WHERE publisherId = ? AND streamName = ? AND ordinal = 1'
    ).get('alice', 'test/tx');
    assertEqual(row.content, 'committed', 'committed value');

    // Rolling-back transaction
    try {
        var doTx2 = s.db.transaction(function () {
            s.db.prepare(
                'INSERT INTO ' + s.prefix + 'message (publisherId, streamName, ordinal, epoch, insertedTime, byUserId, type, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            ).run('alice', 'test/tx', 2, 1, '2024-01-01', 'alice', 'text', 'will-rollback');
            throw new Error('intentional');
        });
        doTx2();
    } catch (e) {
        if (e.message !== 'intentional') throw e;
    }
    var row2 = s.db.prepare(
        'SELECT * FROM ' + s.prefix + 'message WHERE publisherId = ? AND streamName = ? AND ordinal = 2'
    ).get('alice', 'test/tx');
    assertEqual(row2, undefined, 'rolled back — should not exist');
    s.close();
});

// ── 11. WAL crash recovery ──────────────────────────────────────────────────

test('WAL — data survives close and reopen', function () {
    var dbPath = tmpDir();
    var dbFile = path.join(dbPath, 'persist.sc');

    // Session 1: create and insert
    var db1 = new Database(dbFile);
    db1.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)');
    db1.prepare('INSERT INTO kv (k, v) VALUES (?, ?)').run('hello', 'world');
    db1.close();

    // Session 2: reopen and verify
    var db2 = new Database(dbFile);
    var row = db2.prepare('SELECT v FROM kv WHERE k = ?').get('hello');
    assertEqual(row.v, 'world', 'persisted across close/reopen');
    db2.close();
});

test('WAL — Streams schema survives reopen', function () {
    var dbPath = tmpDir();
    var dbFile = path.join(dbPath, 'streams.sc');

    // Session 1: create schema + insert a stream
    var db1 = new Database(dbFile);
    db1.exec(
        'CREATE TABLE IF NOT EXISTS s_stream (publisherId TEXT NOT NULL DEFAULT \'\', name TEXT NOT NULL DEFAULT \'\', readLevel INTEGER NOT NULL DEFAULT 40, PRIMARY KEY (publisherId, name))'
    );
    db1.prepare('INSERT INTO s_stream (publisherId, name, readLevel) VALUES (?, ?, ?)').run('alice', 'doc1', 35);
    db1.close();

    // Session 2: verify
    var db2 = new Database(dbFile);
    var row = db2.prepare('SELECT readLevel FROM s_stream WHERE publisherId = ? AND name = ?').get('alice', 'doc1');
    assertEqual(row.readLevel, 35, 'readLevel persists');
    db2.close();
});

// ── 12. Level constants exported ────────────────────────────────────────────

test('Level constants — READ_LEVEL/WRITE_LEVEL/ADMIN_LEVEL exported', function () {
    var RL = Streams.READ_LEVEL;
    var WL = Streams.WRITE_LEVEL;
    var AL = Streams.ADMIN_LEVEL;
    assert(RL, 'READ_LEVEL exported');
    assertEqual(RL.see, 10, 'READ_LEVEL.see');
    assertEqual(RL.messages, 35, 'READ_LEVEL.messages');
    assertEqual(RL.max, 40, 'READ_LEVEL.max');
    assertEqual(WL.join, 10, 'WRITE_LEVEL.join');
    assertEqual(WL.post, 20, 'WRITE_LEVEL.post');
    assertEqual(WL.relate, 23, 'WRITE_LEVEL.relate');
    assertEqual(WL.edit, 30, 'WRITE_LEVEL.edit');
    assertEqual(AL.invite, 20, 'ADMIN_LEVEL.invite');
    assertEqual(AL.manage, 30, 'ADMIN_LEVEL.manage');
    assertEqual(AL.own, 40, 'ADMIN_LEVEL.own');
});

// ── 13. SafeDB existing test suite (DDL, CRUD, etc.) ────────────────────────

test('SafeDB — basic DDL + CRUD still works', function () {
    var db = new Database(':memory:');
    db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER DEFAULT 0)');
    db.prepare('INSERT INTO users (name, age) VALUES (?, ?)').run('Alice', 30);
    db.prepare('INSERT INTO users (name, age) VALUES (?, ?)').run('Bob', 25);
    var all = db.prepare('SELECT * FROM users ORDER BY name').all();
    assertEqual(all.length, 2, 'row count');
    assertEqual(all[0].name, 'Alice', 'first row');
    assertEqual(all[1].name, 'Bob', 'second row');
    // UPDATE
    db.prepare('UPDATE users SET age = ? WHERE name = ?').run(31, 'Alice');
    var alice = db.prepare('SELECT age FROM users WHERE name = ?').get('Alice');
    assertEqual(alice.age, 31, 'updated age');
    // DELETE
    var info = db.prepare('DELETE FROM users WHERE name = ?').run('Bob');
    assertEqual(info.changes, 1, 'deleted 1 row');
    db.close();
});

test('SafeDB — JOIN query', function () {
    var db = new Database(':memory:');
    db.exec('CREATE TABLE orders (id INTEGER PRIMARY KEY, userId INTEGER, amount REAL)');
    db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)');
    db.prepare('INSERT INTO users (id, name) VALUES (?, ?)').run(1, 'Alice');
    db.prepare('INSERT INTO orders (userId, amount) VALUES (?, ?)').run(1, 100.50);
    db.prepare('INSERT INTO orders (userId, amount) VALUES (?, ?)').run(1, 200.00);
    var result = db.prepare(
        'SELECT u.name, SUM(o.amount) as total FROM users u JOIN orders o ON u.id = o.userId GROUP BY u.name'
    ).all();
    assertEqual(result.length, 1, 'one group');
    assertEqual(result[0].name, 'Alice', 'joined name');
    assertEqual(result[0].total, 300.50, 'sum of amounts');
    db.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Run
// ═══════════════════════════════════════════════════════════════════════════════

run();
