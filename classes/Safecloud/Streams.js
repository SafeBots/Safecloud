'use strict';
/**
 * Safecloud/Streams.js — Q.Streams-compatible HTTP + socket.io API backed by SQLite.
 *
 * Implements Streams protocol Tier 1 (append-only log, subscriptions, notifications)
 * using better-sqlite3 for synchronous SQLite access.  Registered as Express routes
 * and socket.io handlers on the existing Jet server.
 *
 * Routes (mounted at /action.php/Streams and /Streams):
 *   POST /stream        — create stream
 *   GET  /stream        — get stream by publisherId + streamName
 *   POST /message       — post a message
 *   GET  /message       — get one message (ordinal=N) or a range
 *   GET  /messages      — range alias: ?after=N&limit=L  (for pull replication)
 *   POST /subscribe     — subscribe (join as participant)
 *   POST /unsubscribe   — unsubscribe
 *   GET  /epoch         — current Jet epoch metadata (epoch, publicKeyHex)
 *
 * Socket.io:
 *   Clients join rooms 'stream:<publisherId>:<streamName>' to receive push.
 *   Client events: 'Streams/subscribe', 'Streams/unsubscribe', 'Streams/ephemeral'
 *   Server emits:  'Streams/message' on new persisted message
 *                  'Streams/ephemeral' relayed to room (not persisted)
 *
 * Signed hash chain (Phase 1):
 *   Each message carries prev_hash (SHA-256 of previous record's signing payload)
 *   and sig (Ed25519 signature by this Jet, over the signing payload).
 *   Signing payload = "epoch|ordinal|prev_hash|publisherId|streamName|content|byUserId|insertedTime"
 *   The Jet's current public key is returned by GET /epoch.
 *
 * Idempotency:
 *   POST /message accepts an optional `idempotencyKey` (UUID).  If a row with
 *   that key already exists the Jet returns its ordinal without re-inserting.
 *
 * Authentication:
 *   byUserId is taken from X-User-Id header, ?byUserId= query param, or POST body.
 *
 * Config (in local/app.json under "Streams"):
 *   dbPath   — path to the SQLite DB file  (default: <cwd>/local/streams.db)
 *   prefix   — table prefix                (default: "streams_")
 */

var path   = require('path');
var crypto = require('crypto');

// ─── better-sqlite3 ──────────────────────────────────────────────────────────
var Database;
try {
    Database = require('better-sqlite3');
} catch (e) {
    console.warn('[Streams] better-sqlite3 not found — Streams Jet disabled. Run: npm install better-sqlite3');
}

// ─── JetKey (signing) ────────────────────────────────────────────────────────
var JetKey;
try {
    JetKey = require('./JetKey');
} catch (e) {
    console.warn('[Streams] JetKey not found — message signing disabled: ' + e.message);
}

// ─── Module-level state ───────────────────────────────────────────────────────
var _db        = null;
var _io        = null;
var _prefix    = 'streams_';
var _epoch     = 1;          // current Jet epoch — incremented on succession
var _halted    = false;      // set true on fork detection; blocks new writes

// ─── Hook system ─────────────────────────────────────────────────────────────
var _hooks = {};

function addHook(event, fn) {
    if (!_hooks[event]) _hooks[event] = [];
    _hooks[event].push(fn);
}

function runHooks(event, ctx) {
    var handlers = _hooks[event];
    if (!handlers || !handlers.length) return;
    for (var i = 0; i < handlers.length; i++) { handlers[i](ctx); }
}

// ─── Schema ───────────────────────────────────────────────────────────────────
var SCHEMA_SQL = [
    'CREATE TABLE IF NOT EXISTS {{P}}stream (' +
    '  publisherId TEXT NOT NULL DEFAULT \'\',' +
    '  name TEXT NOT NULL DEFAULT \'\',' +
    '  insertedTime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
    '  updatedTime TEXT NULL DEFAULT NULL,' +
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
    '  closedTime TEXT NULL DEFAULT NULL,' +
    '  invitedCount INTEGER NOT NULL DEFAULT 0,' +
    '  arrivedCount INTEGER NOT NULL DEFAULT 0,' +
    '  participatingCount INTEGER NOT NULL DEFAULT 0,' +
    '  leftCount INTEGER NOT NULL DEFAULT 0,' +
    '  arrivedRatio REAL NULL DEFAULT NULL,' +
    '  joinedRatio REAL NULL DEFAULT NULL,' +
    '  fork TEXT NULL DEFAULT NULL,' +
    '  disputed INTEGER NOT NULL DEFAULT 0,' +
    '  PRIMARY KEY (publisherId, name)' +
    ')',

    'CREATE TABLE IF NOT EXISTS {{P}}message (' +
    '  publisherId TEXT NOT NULL DEFAULT \'\',' +
    '  streamName TEXT NOT NULL DEFAULT \'\',' +
    '  ordinal INTEGER NOT NULL DEFAULT 0,' +
    '  epoch INTEGER NOT NULL DEFAULT 1,' +
    '  insertedTime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
    '  sentTime TEXT NULL DEFAULT NULL,' +
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

    'CREATE UNIQUE INDEX IF NOT EXISTS {{P}}message_idem ON {{P}}message (idempotency_key) WHERE idempotency_key IS NOT NULL',

    'CREATE TABLE IF NOT EXISTS {{P}}message_total (' +
    '  publisherId TEXT NOT NULL DEFAULT \'\',' +
    '  streamName TEXT NOT NULL DEFAULT \'\',' +
    '  messageType TEXT NOT NULL DEFAULT \'\',' +
    '  messageCount INTEGER NOT NULL DEFAULT 0,' +
    '  PRIMARY KEY (publisherId, streamName, messageType)' +
    ')',

    'CREATE TABLE IF NOT EXISTS {{P}}participant (' +
    '  publisherId TEXT NOT NULL DEFAULT \'\',' +
    '  streamName TEXT NOT NULL DEFAULT \'\',' +
    '  userId TEXT NOT NULL DEFAULT \'\',' +
    '  streamType TEXT DEFAULT NULL,' +
    '  insertedTime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
    '  updatedTime TEXT NULL DEFAULT NULL,' +
    '  state TEXT NOT NULL DEFAULT \'\',' +
    '  subscribed TEXT NOT NULL DEFAULT \'no\',' +
    '  posted TEXT NOT NULL DEFAULT \'no\',' +
    '  reason TEXT NOT NULL DEFAULT \'\',' +
    '  enthusiasm REAL NOT NULL DEFAULT 0.0,' +
    '  reputation INTEGER NOT NULL DEFAULT 0,' +
    '  extra TEXT NOT NULL DEFAULT \'{}\',' +
    '  PRIMARY KEY (publisherId, streamName, userId)' +
    ')',

    'CREATE TABLE IF NOT EXISTS {{P}}subscription (' +
    '  publisherId TEXT NOT NULL DEFAULT \'\',' +
    '  streamName TEXT NOT NULL DEFAULT \'\',' +
    '  ofUserId TEXT NOT NULL DEFAULT \'\',' +
    '  insertedTime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
    '  updatedTime TEXT NULL DEFAULT NULL,' +
    '  untilTime TEXT NULL DEFAULT NULL,' +
    '  filter TEXT NOT NULL DEFAULT \'\',' +
    '  duration INTEGER NOT NULL DEFAULT 0,' +
    '  PRIMARY KEY (publisherId, streamName, ofUserId)' +
    ')',

    'CREATE TABLE IF NOT EXISTS {{P}}access (' +
    '  publisherId TEXT NOT NULL DEFAULT \'\',' +
    '  streamName TEXT NOT NULL DEFAULT \'\',' +
    '  ofUserId TEXT NOT NULL DEFAULT \'\',' +
    '  ofContactLabel TEXT NOT NULL DEFAULT \'\',' +
    '  grantedByUserId TEXT DEFAULT NULL,' +
    '  insertedTime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
    '  updatedTime TEXT NULL DEFAULT NULL,' +
    '  readLevel INTEGER NOT NULL DEFAULT 0,' +
    '  writeLevel INTEGER NOT NULL DEFAULT 0,' +
    '  adminLevel INTEGER NOT NULL DEFAULT 0,' +
    '  permissions TEXT DEFAULT NULL,' +
    '  ofParticipantRole TEXT DEFAULT NULL,' +
    '  PRIMARY KEY (publisherId, streamName, ofUserId, ofContactLabel)' +
    ')'
].join(';\n') + ';';

// Migrations to add new columns to existing databases
var MIGRATIONS = [
    // Phase 1 columns on existing message tables
    'ALTER TABLE {{P}}message ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1',
    'ALTER TABLE {{P}}message ADD COLUMN prev_hash TEXT NOT NULL DEFAULT \'\'',
    'ALTER TABLE {{P}}message ADD COLUMN sig TEXT NOT NULL DEFAULT \'\'',
    'ALTER TABLE {{P}}message ADD COLUMN idempotency_key TEXT DEFAULT NULL',
    // Idempotency unique index (CREATE UNIQUE INDEX IF NOT EXISTS is idempotent)
    'CREATE UNIQUE INDEX IF NOT EXISTS {{P}}message_idem ON {{P}}message (idempotency_key) WHERE idempotency_key IS NOT NULL',
    // disputed flag on stream table
    'ALTER TABLE {{P}}stream ADD COLUMN disputed INTEGER NOT NULL DEFAULT 0'
];

// ─── Database init ────────────────────────────────────────────────────────────

function initDb(dbPath, prefix) {
    if (!Database) return null;
    _prefix = prefix || 'streams_';
    var db  = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    var schema = SCHEMA_SQL.replace(/\{\{P\}\}/g, _prefix);
    try { db.exec(schema); }
    catch (e) { console.error('[Streams] Schema init error: ' + e.message); }

    // Apply migrations idempotently (ALTER TABLE errors if column already exists)
    MIGRATIONS.forEach(function (sql) {
        try { db.exec(sql.replace(/\{\{P\}\}/g, _prefix)); }
        catch (e) { /* column already exists — ignore */ }
    });

    console.log('[Streams] SQLite ready at ' + dbPath + ' (prefix=' + _prefix + ')');
    _db = db;
    return db;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function nowIso() {
    return new Date().toISOString().replace('T', ' ').slice(0, 23);
}

function qResponse(res, slots, statusCode) {
    res.status(statusCode || 200).json({ slots: slots, timestamp: Date.now() / 1000 });
}

function qError(res, httpCode, message) {
    res.status(typeof httpCode === 'number' ? httpCode : 500).json({
        errors: [{ code: String(httpCode), message: message }],
        timestamp: Date.now() / 1000
    });
}

function getByUserId(req) {
    return (req.headers && req.headers['x-user-id'])
        || (req.query  && req.query.byUserId)
        || (req.body   && req.body.byUserId)
        || '';
}

function getStream(publisherId, streamName) {
    var row = _db.prepare(
        'SELECT * FROM ' + _prefix + 'stream WHERE publisherId = ? AND name = ?'
    ).get(publisherId, streamName);
    if (!row) return null;
    if (row.attributes && typeof row.attributes === 'string') {
        try { row.attributes = JSON.parse(row.attributes); } catch (e) {}
    }
    return row;
}

/** Compute SHA-256 hex digest of a string. */
function sha256hex(str) {
    return crypto.createHash('sha256').update(Buffer.from(str, 'utf8')).digest('hex');
}

// ─── Signed transactional message post ───────────────────────────────────────
//
// All in one db.transaction (BEGIN IMMEDIATE via better-sqlite3):
//   1. Check idempotency_key — if found, return existing ordinal.
//   2. Lock stream, read messageCount + last prev_hash.
//   3. Build signing payload, compute prev_hash for this record.
//   4. Sign (Ed25519).  Fork detection: stream.disputed halts writes.
//   5. INSERT message with all new columns.
//   6. UPDATE stream.messageCount.
//   7. UPSERT message_total.
//
// Returns { ordinal, insertedTime, prev_hash, sig, idempotent }.

var _txPostMessage = null;

function _buildTxPostMessage() {
    var t = _prefix;

    var stmtCheckIdem = _db.prepare(
        'SELECT ordinal, insertedTime, prev_hash, sig FROM ' + t + 'message ' +
        'WHERE idempotency_key = ? LIMIT 1'
    );
    var stmtGetStream = _db.prepare(
        'SELECT messageCount, disputed FROM ' + t + 'stream WHERE publisherId = ? AND name = ?'
    );
    var stmtGetLastHash = _db.prepare(
        'SELECT prev_hash, sig, epoch, ordinal, publisherId, streamName, content, byUserId, insertedTime ' +
        'FROM ' + t + 'message ' +
        'WHERE publisherId = ? AND streamName = ? ' +
        'ORDER BY ordinal DESC LIMIT 1'
    );
    var stmtInsert = _db.prepare(
        'INSERT INTO ' + t + 'message ' +
        '(publisherId, streamName, ordinal, epoch, insertedTime, sentTime,' +
        ' byUserId, byClientId, type, content, instructions, weight,' +
        ' prev_hash, sig, idempotency_key) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    var stmtUpdateCount = _db.prepare(
        'UPDATE ' + t + 'stream SET messageCount = ?, updatedTime = ? ' +
        'WHERE publisherId = ? AND name = ?'
    );
    var stmtUpsertTotal = _db.prepare(
        'INSERT INTO ' + t + 'message_total (publisherId, streamName, messageType, messageCount) ' +
        'VALUES (?, ?, ?, 1) ' +
        'ON CONFLICT(publisherId, streamName, messageType) ' +
        'DO UPDATE SET messageCount = messageCount + 1'
    );

    return _db.transaction(function (p) {
        // 1. Idempotency check (runs outside the stream lock — idempotency key is globally unique)
        if (p.idempotency_key) {
            var existing = stmtCheckIdem.get(p.idempotency_key);
            if (existing) {
                return {
                    ordinal:      existing.ordinal,
                    insertedTime: existing.insertedTime,
                    prev_hash:    existing.prev_hash,
                    sig:          existing.sig,
                    idempotent:   true
                };
            }
        }

        // 2. Read stream metadata (this begins the write lock via BEGIN IMMEDIATE)
        var stream = stmtGetStream.get(p.publisherId, p.streamName);
        if (!stream) {
            throw Object.assign(new Error('Stream not found: ' + p.publisherId + '/' + p.streamName), { statusCode: 404 });
        }
        if (stream.disputed) {
            throw Object.assign(new Error('Stream ' + p.publisherId + '/' + p.streamName + ' is disputed — writes halted pending fork resolution'), { statusCode: 409 });
        }

        var ordinal = stream.messageCount + 1;
        var now     = nowIso();

        // 3. Compute prev_hash from the last record's signing payload
        var prevHashVal = '';
        if (ordinal > 1) {
            var lastRow = stmtGetLastHash.get(p.publisherId, p.streamName);
            if (lastRow) {
                var lastPayload = JetKey
                    ? JetKey.sigPayload({
                        epoch:        lastRow.epoch,
                        ordinal:      lastRow.ordinal,
                        prev_hash:    lastRow.prev_hash,
                        publisherId:  lastRow.publisherId,
                        streamName:   lastRow.streamName,
                        content:      lastRow.content,
                        byUserId:     lastRow.byUserId,
                        insertedTime: lastRow.insertedTime
                    })
                    : [lastRow.epoch, lastRow.ordinal, lastRow.prev_hash,
                       lastRow.publisherId, lastRow.streamName,
                       lastRow.content, lastRow.byUserId, lastRow.insertedTime].join('|');
                prevHashVal = sha256hex(lastPayload);
            }
        }

        // 4. Build signing payload and sign
        var sigPayloadStr = JetKey
            ? JetKey.sigPayload({
                epoch:        _epoch,
                ordinal:      ordinal,
                prev_hash:    prevHashVal,
                publisherId:  p.publisherId,
                streamName:   p.streamName,
                content:      p.content || '',
                byUserId:     p.byUserId || '',
                insertedTime: now
            })
            : [_epoch, ordinal, prevHashVal,
               p.publisherId, p.streamName,
               p.content || '', p.byUserId || '', now].join('|');

        var sigVal = '';
        if (JetKey) {
            try { sigVal = JetKey.sign(sigPayloadStr); }
            catch (e) { console.error('[Streams] Signing failed:', e.message); }
        }

        // 5. Insert
        stmtInsert.run(
            p.publisherId, p.streamName, ordinal, _epoch, now, now,
            p.byUserId || '', p.byClientId || '', p.type,
            p.content || '', p.instructions || '',
            p.weight != null ? p.weight : 1.0,
            prevHashVal, sigVal, p.idempotency_key || null
        );

        // 6–7. Update counts
        stmtUpdateCount.run(ordinal, now, p.publisherId, p.streamName);
        stmtUpsertTotal.run(p.publisherId, p.streamName, p.type);

        return { ordinal: ordinal, insertedTime: now, prev_hash: prevHashVal, sig: sigVal, idempotent: false };
    });
}

function postMessage(params) {
    if (!_txPostMessage) { _txPostMessage = _buildTxPostMessage(); }
    return _txPostMessage(params);
}

// ─── Socket.io push ───────────────────────────────────────────────────────────

function notifyRoom(publisherId, streamName, eventName, data) {
    if (!_io) return;
    _io.to('stream:' + publisherId + ':' + streamName).emit(eventName, data);
}

// ─── Express route registration ───────────────────────────────────────────────

/** List all streams (for admin panel). */
function listStreams() {
    if (!_db) return [];
    try {
        return _db.prepare('SELECT publisherId, name, type, title, readLevel, writeLevel, adminLevel, messageCount, insertedTime FROM ' + _prefix + 'stream ORDER BY insertedTime DESC LIMIT 500').all();
    } catch (e) {
        return [];
    }
}

/** Update stream access levels (for admin panel). */
function updateStreamAccess(publisherId, streamName, readLevel, writeLevel, adminLevel) {
    if (!_db) return { ok: false, error: 'DB not ready' };
    if (!publisherId || !streamName) return { ok: false, error: 'Missing publisherId or streamName' };
    var stream = getStream(publisherId, streamName);
    if (!stream) return { ok: false, error: 'Stream not found' };
    var sets = [];
    var vals = [];
    if (readLevel  != null) { sets.push('readLevel = ?');  vals.push(parseInt(readLevel,  10)); }
    if (writeLevel != null) { sets.push('writeLevel = ?'); vals.push(parseInt(writeLevel, 10)); }
    if (adminLevel != null) { sets.push('adminLevel = ?'); vals.push(parseInt(adminLevel, 10)); }
    if (!sets.length) return { ok: false, error: 'Nothing to update' };
    vals.push(publisherId, streamName);
    _db.prepare('UPDATE ' + _prefix + 'stream SET ' + sets.join(', ') + ' WHERE publisherId = ? AND name = ?').run(vals);
    return { ok: true };
}

function listen(app, io, configStore, AdminAuth) {
    if (!Database) {
        console.warn('[Streams] better-sqlite3 not available — routes not registered');
        return;
    }

    _io  = io;
    var cfg    = (configStore && configStore.Streams) || {};
    var dbPath = cfg.dbPath
        || path.join(process.env.SAFECLOUD_DIR || process.cwd(), 'local', 'streams.db');
    var prefix = cfg.prefix || 'streams_';

    initDb(dbPath, prefix);
    if (!_db) return;

    // Init signing keypair
    if (JetKey) {
        try {
            var keyPath = path.join(process.env.SAFECLOUD_DIR || process.cwd(), 'local', 'jet-key.json');
            JetKey.init(keyPath);
            console.log('[Streams] Jet public key: ' + JetKey.publicKeyHex());
        } catch (e) {
            console.error('[Streams] JetKey init failed:', e.message);
        }
    }

    var express = require('express');
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));

    var router = express.Router();

    // ── GET /stream ────────────────────────────────────────────────────────────
    router.get('/stream', function (req, res) {
        var publisherId = req.query.publisherId;
        var name        = req.query.streamName || req.query.name;
        if (!publisherId || !name) return qError(res, 400, 'Missing publisherId or streamName');
        var stream = getStream(publisherId, name);
        if (!stream) return qError(res, 404, 'Stream not found');
        qResponse(res, { stream: stream });
    });

    // ── POST /stream ───────────────────────────────────────────────────────────
    router.post('/stream', function (req, res) {
        var body        = req.body || {};
        var publisherId = body.publisherId;
        var name        = body.name || body.streamName;
        if (!publisherId || !name) return qError(res, 400, 'Missing publisherId or name');

        var now   = nowIso();
        var attrs = body.attributes != null
            ? (typeof body.attributes === 'string' ? body.attributes : JSON.stringify(body.attributes))
            : null;

        try {
            _db.prepare(
                'INSERT INTO ' + _prefix + 'stream ' +
                '(publisherId, name, type, title, content, attributes, insertedTime,' +
                ' readLevel, writeLevel, adminLevel) ' +
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(
                publisherId, name,
                body.type    || 'Streams/text',
                body.title   || '',
                body.content || '',
                attrs, now,
                parseInt(body.readLevel,  10) || 40,
                parseInt(body.writeLevel, 10) || 10,
                parseInt(body.adminLevel, 10) || 20
            );
            qResponse(res, { stream: getStream(publisherId, name) }, 201);
        } catch (e) {
            if (e.message && e.message.indexOf('UNIQUE') >= 0) return qError(res, 409, 'Stream already exists');
            return qError(res, 500, e.message);
        }
    });

    // ── POST /message ──────────────────────────────────────────────────────────
    router.post('/message', function (req, res) {
        var body        = req.body || {};
        var publisherId = body.publisherId;
        var streamName  = body.streamName;
        var type        = body.type;
        if (!publisherId || !streamName || !type) {
            return qError(res, 400, 'Missing publisherId, streamName, or type');
        }

        if (_halted) return qError(res, 503, 'Jet is halted — fork detected on this Jet');

        var byUserId = getByUserId(req) || publisherId;
        var stream   = getStream(publisherId, streamName);
        if (!stream) return qError(res, 404, 'Stream not found: ' + publisherId + '/' + streamName);

        var params = {
            publisherId:     publisherId,
            streamName:      streamName,
            byUserId:        byUserId,
            type:            type,
            content:         body.content      || '',
            instructions:    body.instructions || '',
            weight:          parseFloat(body.weight) || 1.0,
            idempotency_key: body.idempotencyKey || null
        };

        try {
            runHooks('before:post', { publisherId: publisherId, streamName: streamName, stream: stream, params: params });
        } catch (hookErr) {
            return qError(res, hookErr.statusCode || 400, hookErr.message);
        }

        try {
            var result = postMessage(params);

            var msg = _db.prepare(
                'SELECT * FROM ' + _prefix + 'message ' +
                'WHERE publisherId = ? AND streamName = ? AND ordinal = ?'
            ).get(publisherId, streamName, result.ordinal);

            if (!result.idempotent) {
                notifyRoom(publisherId, streamName, 'Streams/message', {
                    publisherId:  publisherId,
                    streamName:   streamName,
                    ordinal:      result.ordinal,
                    epoch:        _epoch,
                    type:         type,
                    byUserId:     byUserId,
                    insertedTime: result.insertedTime,
                    prev_hash:    result.prev_hash,
                    sig:          result.sig
                });
            }

            qResponse(res, {
                message: msg,
                extras: {
                    publisherId:   publisherId,
                    streamName:    streamName,
                    streamType:    msg ? msg.type : type,
                    messageCount:  result.ordinal,
                    idempotent:    result.idempotent || false
                }
            });
        } catch (e) {
            var status = e.statusCode || (e.message && e.message.indexOf('not found') >= 0 ? 404 : 500);
            return qError(res, status, e.message);
        }
    });

    // ── GET /message — single or range ────────────────────────────────────────
    router.get('/message', function (req, res) {
        var publisherId = req.query.publisherId;
        var streamName  = req.query.streamName;
        if (!publisherId || !streamName) return qError(res, 400, 'Missing publisherId or streamName');

        if (req.query.ordinal != null) {
            var msg = _db.prepare(
                'SELECT * FROM ' + _prefix + 'message ' +
                'WHERE publisherId = ? AND streamName = ? AND ordinal = ?'
            ).get(publisherId, streamName, parseInt(req.query.ordinal, 10));
            if (!msg) return qError(res, 404, 'Message not found');
            var str = getStream(publisherId, streamName);
            return qResponse(res, { message: msg, extras: { publisherId: publisherId, streamName: streamName, streamType: str ? str.type : '', messageCount: str ? str.messageCount : 0 } });
        }

        return _rangeResponse(req, res, publisherId, streamName);
    });

    // ── GET /messages — range alias for pull replication ──────────────────────
    // Accepts: ?publisherId=&streamName=&after=N&limit=L
    // Returns: same shape as /message range, but keyed on ordinal.
    router.get('/messages', function (req, res) {
        var publisherId = req.query.publisherId;
        var streamName  = req.query.streamName;
        if (!publisherId || !streamName) return qError(res, 400, 'Missing publisherId or streamName');
        return _rangeResponse(req, res, publisherId, streamName);
    });

    // ── GET /epoch — Jet epoch metadata ───────────────────────────────────────
    router.get('/epoch', function (req, res) {
        qResponse(res, {
            epoch:        _epoch,
            publicKeyHex: JetKey ? JetKey.publicKeyHex() : null,
            halted:       _halted
        });
    });

    // ── POST /subscribe ────────────────────────────────────────────────────────
    router.post('/subscribe', function (req, res) {
        var body        = req.body || {};
        var publisherId = body.publisherId;
        var streamName  = body.streamName;
        if (!publisherId || !streamName) return qError(res, 400, 'Missing publisherId or streamName');
        var byUserId = getByUserId(req) || publisherId;
        var now = nowIso();
        try {
            _db.prepare(
                'INSERT INTO ' + _prefix + 'participant ' +
                '(publisherId, streamName, userId, insertedTime, updatedTime, state, subscribed) ' +
                'VALUES (?, ?, ?, ?, ?, ?, ?) ' +
                'ON CONFLICT(publisherId, streamName, userId) ' +
                'DO UPDATE SET subscribed = \'yes\', state = \'participating\', updatedTime = excluded.updatedTime'
            ).run(publisherId, streamName, byUserId, now, now, 'participating', 'yes');
            _db.prepare(
                'INSERT INTO ' + _prefix + 'subscription ' +
                '(publisherId, streamName, ofUserId, insertedTime, updatedTime) ' +
                'VALUES (?, ?, ?, ?, ?) ' +
                'ON CONFLICT(publisherId, streamName, ofUserId) ' +
                'DO UPDATE SET updatedTime = excluded.updatedTime'
            ).run(publisherId, streamName, byUserId, now, now);
            var participant = _db.prepare(
                'SELECT * FROM ' + _prefix + 'participant ' +
                'WHERE publisherId = ? AND streamName = ? AND userId = ?'
            ).get(publisherId, streamName, byUserId);
            qResponse(res, { participant: participant });
        } catch (e) { return qError(res, 500, e.message); }
    });

    // ── POST /unsubscribe ──────────────────────────────────────────────────────
    router.post('/unsubscribe', function (req, res) {
        var body        = req.body || {};
        var publisherId = body.publisherId;
        var streamName  = body.streamName;
        if (!publisherId || !streamName) return qError(res, 400, 'Missing publisherId or streamName');
        var byUserId = getByUserId(req) || publisherId;
        var now = nowIso();
        try {
            _db.prepare(
                'UPDATE ' + _prefix + 'participant SET subscribed = \'no\', updatedTime = ? ' +
                'WHERE publisherId = ? AND streamName = ? AND userId = ?'
            ).run(now, publisherId, streamName, byUserId);
            _db.prepare(
                'DELETE FROM ' + _prefix + 'subscription WHERE publisherId = ? AND streamName = ? AND ofUserId = ?'
            ).run(publisherId, streamName, byUserId);
            qResponse(res, { success: true });
        } catch (e) { return qError(res, 500, e.message); }
    });

    // Mount at both URL patterns
    app.use('/action.php/Streams', router);
    app.use('/Streams', router);

    // ── Admin routes (/Streams/admin/*) ───────────────────────────────────────
    if (AdminAuth) {
        var fs       = require('fs');
        var APP_DIR  = process.env.SAFECLOUD_DIR || process.cwd();
        var CFG_PATH = require('path').join(APP_DIR, 'local', 'app.json');

        /** Helper: derive expected origin from request */
        function _getOrigin(req) {
            var proto = req.headers['x-forwarded-proto'] || (req.connection && req.connection.encrypted ? 'https' : 'http');
            return proto + '://' + req.get('host');
        }

        /** Middleware: require a valid admin session token */
        function _requireAdmin(req, res, next) {
            var auth  = req.headers.authorization || '';
            var token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : (req.query.token || '');
            var check = AdminAuth.verifySession(token);
            if (!check.ok) return res.status(401).json({ slots: { error: check.error || 'Unauthorized' } });
            next();
        }

        /** Read local/app.json (for CORS config updates) */
        function _readLocalCfg() {
            try { return JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); } catch (e) { return {}; }
        }
        function _writeLocalCfg(cfg) {
            fs.mkdirSync(require('path').dirname(CFG_PATH), { recursive: true });
            fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
        }

        var adminRouter = require('express').Router();

        // GET /Streams/admin/status — is passkey registered?
        adminRouter.get('/status', function (req, res) {
            res.json({ slots: { registered: AdminAuth.isRegistered(), version: '1.0' } });
        });

        // GET /Streams/admin/register-options — WebAuthn create challenge (unauthenticated)
        adminRouter.get('/register-options', function (req, res) {
            if (AdminAuth.isRegistered()) {
                return res.status(409).json({ slots: { error: 'Admin passkey already registered. Use /admin/login-options.' } });
            }
            var origin = _getOrigin(req);
            var rpId   = new (require('url').URL)(origin).hostname;
            var challenge = AdminAuth.generateChallenge();
            res.json({ slots: {
                challenge: challenge,
                rp:        { name: 'Safecloud Jet', id: rpId },
                user:      { id: Buffer.from('admin').toString('base64url'), name: 'admin', displayName: 'Jet Admin' },
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
                timeout: 60000
            }});
        });

        // POST /Streams/admin/register — store passkey (unauthenticated, one-time)
        adminRouter.post('/register', function (req, res) {
            if (AdminAuth.isRegistered()) {
                return res.status(409).json({ slots: { error: 'Admin passkey already registered' } });
            }
            var origin = _getOrigin(req);
            var rpId   = new (require('url').URL)(origin).hostname;
            var result = AdminAuth.verifyRegistration(req.body, origin, rpId);
            if (!result.ok) return res.status(400).json({ slots: { error: result.error } });
            console.log('[AdminAuth] Admin passkey registered, credId:', result.credentialId);
            res.json({ slots: { ok: true, credentialId: result.credentialId } });
        });

        // GET /Streams/admin/login-options — WebAuthn get challenge (unauthenticated)
        adminRouter.get('/login-options', function (req, res) {
            if (!AdminAuth.isRegistered()) {
                return res.status(404).json({ slots: { error: 'No admin passkey registered. Visit /admin.html to register.' } });
            }
            var challenge = AdminAuth.generateChallenge();
            res.json({ slots: { challenge: challenge, timeout: 60000 } });
        });

        // POST /Streams/admin/login — verify assertion, return Bearer token
        adminRouter.post('/login', function (req, res) {
            var origin = _getOrigin(req);
            var rpId   = new (require('url').URL)(origin).hostname;
            var result = AdminAuth.verifyAuthentication(req.body, origin, rpId);
            if (!result.ok) return res.status(401).json({ slots: { error: result.error } });
            console.log('[AdminAuth] Admin logged in');
            res.json({ slots: { ok: true, token: result.token } });
        });

        // GET /Streams/admin/cors — read CORS allowlist [auth required]
        adminRouter.get('/cors', _requireAdmin, function (req, res) {
            var cfg     = _readLocalCfg();
            var origins = (cfg.Safecloud && cfg.Safecloud.cors && cfg.Safecloud.cors.allowedOrigins) || ['*'];
            res.json({ slots: { allowedOrigins: origins } });
        });

        // PUT /Streams/admin/cors — update CORS allowlist [auth required]
        adminRouter.put('/cors', _requireAdmin, function (req, res) {
            var origins = (req.body || {}).allowedOrigins;
            if (!Array.isArray(origins)) return res.status(400).json({ slots: { error: 'allowedOrigins must be an array' } });
            // Validate each entry
            for (var i = 0; i < origins.length; i++) {
                if (origins[i] !== '*') {
                    try { new (require('url').URL)(origins[i]); } catch (e) {
                        return res.status(400).json({ slots: { error: 'Invalid origin: ' + origins[i] } });
                    }
                }
            }
            var cfg = _readLocalCfg();
            if (!cfg.Safecloud) cfg.Safecloud = {};
            if (!cfg.Safecloud.cors) cfg.Safecloud.cors = {};
            cfg.Safecloud.cors.allowedOrigins = origins;
            _writeLocalCfg(cfg);
            AdminAuth.updateAllowedOrigins(origins); // update runtime CORS immediately
            res.json({ slots: { ok: true, allowedOrigins: origins } });
        });

        // GET /Streams/admin/streams — list all streams with ACLs [auth required]
        adminRouter.get('/streams', _requireAdmin, function (req, res) {
            res.json({ slots: { streams: listStreams() } });
        });

        // PUT /Streams/admin/stream-access — update stream ACLs [auth required]
        adminRouter.put('/stream-access', _requireAdmin, function (req, res) {
            var b = req.body || {};
            var r = updateStreamAccess(b.publisherId, b.streamName, b.readLevel, b.writeLevel, b.adminLevel);
            if (!r.ok) return res.status(400).json({ slots: { error: r.error } });
            res.json({ slots: { ok: true } });
        });

        app.use('/Streams/admin', adminRouter);
        console.log('[Streams] Admin routes registered (/Streams/admin/*)');
    }

    // ── Socket.io: room management + ephemeral relay ──────────────────────────
    if (io) {
        io.on('connection', function (socket) {
            socket.on('Streams/subscribe', function (data) {
                if (data && data.publisherId && data.streamName) {
                    socket.join('stream:' + data.publisherId + ':' + data.streamName);
                }
            });
            socket.on('Streams/unsubscribe', function (data) {
                if (data && data.publisherId && data.streamName) {
                    socket.leave('stream:' + data.publisherId + ':' + data.streamName);
                }
            });
            // Relay ephemeral messages (typing, cursors, presence) without persisting
            socket.on('Streams/ephemeral', function (data) {
                if (data && data.publisherId && data.streamName) {
                    socket.to('stream:' + data.publisherId + ':' + data.streamName)
                          .emit('Streams/ephemeral', data);
                }
            });
        });
    }

    console.log('[Streams] Routes registered (/action.php/Streams, /Streams)');
}

// ─── Private helpers ──────────────────────────────────────────────────────────

function _rangeResponse(req, res, publisherId, streamName) {
    // Support both ?after=N (pull-replication style) and ?min=N (generic)
    var after     = req.query.after != null ? parseInt(req.query.after, 10) : null;
    var min       = after != null ? after + 1 : (req.query.min != null ? parseInt(req.query.min, 10) : 0);
    var max       = req.query.max != null ? parseInt(req.query.max, 10) : null;
    var limit     = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
    var ascending = req.query.ascending !== '0';
    var type      = req.query.type || null;

    var where  = 'publisherId = ? AND streamName = ?';
    var params = [publisherId, streamName];
    if (min  > 0)    { where += ' AND ordinal >= ?'; params.push(min); }
    if (max != null) { where += ' AND ordinal <= ?'; params.push(max); }
    if (type)        { where += ' AND type = ?';     params.push(type); }

    var sql  = 'SELECT * FROM ' + _prefix + 'message WHERE ' + where
        + ' ORDER BY ordinal ' + (ascending ? 'ASC' : 'DESC')
        + ' LIMIT ' + limit;
    var rows = _db.prepare(sql).all(params);

    var byOrdinal = {};
    rows.forEach(function (m) { byOrdinal[m.ordinal] = m; });

    var str = getStream(publisherId, streamName);
    qResponse(res, {
        messages: byOrdinal,
        extras: {
            publisherId:  publisherId,
            streamName:   streamName,
            messageCount: str ? str.messageCount : 0,
            publicKeyHex: JetKey ? JetKey.publicKeyHex() : null,
            epoch:        _epoch
        }
    });
}

/** Expose internals for testing and other modules. */
function getDb()  { return _db; }
function getEpoch() { return _epoch; }
function setEpoch(e) { _epoch = e; }
function halt()   { _halted = true; }

module.exports = {
    listen:              listen,
    getDb:               getDb,
    addHook:             addHook,
    getEpoch:            getEpoch,
    setEpoch:            setEpoch,
    halt:                halt,
    postMessage:         postMessage,
    listStreams:         listStreams,
    updateStreamAccess:  updateStreamAccess
};
