'use strict';
/**
 * WAL — append-only write-ahead log for cross-table transaction atomicity.
 *
 * File: {dbPath}/wal.ndjson  (one JSON record per line)
 * Record types:
 *   {op:"set",    tx:N, table:"t", key:"k", row:{...}}
 *   {op:"delete", tx:N, table:"t", key:"k"}
 *   {op:"commit", tx:N}
 *   {op:"checkpoint", tx:N}   — signals all txs ≤ N are safely on disk
 *
 * BEGIN is implicit — no record is written; every set/delete carries its txId.
 * On startup, committed entries not yet covered by the last checkpoint are
 * replayed onto in-memory stores so that crash recovery is automatic.
 *
 * Hot-path write (happy case):
 *   1. Buffer mutations in memory during the transaction.
 *   2. commit(): write all entries + COMMIT + fdatasync → atomic commit point.
 *   3. flush() column files, then checkpoint() to compact the WAL.
 *
 * Crash recovery: on restart, replay() reads the WAL and applies any committed
 * transactions whose column files had not yet been flushed at crash time.
 */

var fs = require('fs');

function WAL(walPath) {
    this._path     = walPath;
    this._fd       = -1;
    this._nextTxId = 1;
    this._lastCkpt = 0;
}

/**
 * Open (or create) the WAL.  Scans the existing file to establish
 * _nextTxId and _lastCkpt so we never reuse an old transaction ID.
 */
WAL.prototype.open = function () {
    this._nextTxId = 1;
    this._lastCkpt = 0;
    if (fs.existsSync(this._path)) {
        var lines;
        try { lines = fs.readFileSync(this._path, 'utf8').split('\n'); }
        catch (e) { lines = []; }
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (!line) continue;
            var rec;
            try { rec = JSON.parse(line); } catch (e) { continue; }
            if (rec.tx !== undefined && rec.tx >= this._nextTxId) {
                this._nextTxId = rec.tx + 1;
            }
            if (rec.op === 'checkpoint' && rec.tx > this._lastCkpt) {
                this._lastCkpt = rec.tx;
            }
        }
    }
    this._fd = fs.openSync(this._path, 'a');
};

WAL.prototype.close = function () {
    if (this._fd >= 0) { fs.closeSync(this._fd); this._fd = -1; }
};

WAL.prototype._append = function (record) {
    fs.writeSync(this._fd, JSON.stringify(record) + '\n');
};

/** Allocate a new transaction ID. */
WAL.prototype.beginTx = function () {
    return this._nextTxId++;
};

/**
 * Persist a transaction atomically.
 * Writes all entries then a COMMIT record, then fdatasyncs.
 * After this call returns, the transaction is permanently durable on disk.
 *
 * @param {number} txId
 * @param {Array}  entries  [{op:'set'|'delete', table, key, row?}]
 */
WAL.prototype.commit = function (txId, entries) {
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        var rec = { op: e.op, tx: txId, table: e.table, key: e.key };
        if (e.row !== null && e.row !== undefined) rec.row = e.row;
        this._append(rec);
    }
    this._append({ op: 'commit', tx: txId });
    // fdatasync guarantees the bytes reach the storage device
    try { fs.fdatasyncSync(this._fd); }
    catch (e) { try { fs.fsyncSync(this._fd); } catch (e2) {} }
};

/**
 * Replay committed WAL entries onto in-memory stores.
 * Called on startup after the column files have been loaded.
 * Returns true if any entries were applied (crash recovery happened),
 * false if the WAL was clean (normal startup).
 *
 * @param {function(tableName:string): ColumnarStore|null} getStore
 */
WAL.prototype.replay = function (getStore) {
    if (!fs.existsSync(this._path)) return false;
    var raw;
    try { raw = fs.readFileSync(this._path, 'utf8'); } catch (e) { return false; }
    var lines = raw.split('\n');

    // Two-pass: collect committed txIds, then apply their SET/DELETE entries.
    var committed = Object.create(null); // txId → true
    var entries   = [];

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (!line) continue;
        var rec;
        try { rec = JSON.parse(line); } catch (e) { continue; }
        if (rec.op === 'commit')      committed[rec.tx] = true;
        if (rec.op === 'checkpoint') this._lastCkpt = Math.max(this._lastCkpt, rec.tx);
        if ((rec.op === 'set' || rec.op === 'delete') && rec.tx > this._lastCkpt) {
            entries.push(rec);
        }
    }

    var applied = 0;
    for (var i = 0; i < entries.length; i++) {
        var rec = entries[i];
        if (!committed[rec.tx]) continue; // uncommitted transaction — skip
        var store = getStore(rec.table);
        if (!store) continue;
        if (rec.op === 'set')    store.set(rec.key, rec.row);
        if (rec.op === 'delete') store.delete(rec.key);
        applied++;
    }
    return applied > 0;
};

/**
 * Compact the WAL by removing all entries for txIds <= upToTxId.
 * Closes the append fd, rewrites the file atomically, then reopens.
 * Call this after all column files for committed transactions are flushed.
 */
WAL.prototype.checkpoint = function (upToTxId) {
    if (this._fd >= 0) { fs.closeSync(this._fd); this._fd = -1; }

    var keep = [];
    if (fs.existsSync(this._path)) {
        var lines;
        try { lines = fs.readFileSync(this._path, 'utf8').split('\n'); }
        catch (e) { lines = []; }
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (!line) continue;
            var rec;
            try { rec = JSON.parse(line); } catch (e) { continue; }
            if (rec.tx > upToTxId) keep.push(line);
        }
    }

    var out = JSON.stringify({ op: 'checkpoint', tx: upToTxId }) + '\n';
    if (keep.length) out += keep.join('\n') + '\n';

    var tmp = this._path + '.tmp';
    try {
        fs.writeFileSync(tmp, out, 'utf8');
        fs.renameSync(tmp, this._path);
    } catch (e) {
        try { fs.unlinkSync(tmp); } catch (e2) {}
    }
    this._lastCkpt = upToTxId;
    this._fd = fs.openSync(this._path, 'a');
};

module.exports = WAL;
