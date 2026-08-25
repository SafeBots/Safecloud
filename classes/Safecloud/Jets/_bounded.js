/**
 * Safecloud/Jets/_bounded.js
 *
 * Production-hardening utilities for the Jet's in-memory state:
 *
 *  - BoundedMap: an LRU-ish object map with a hard entry cap and optional
 *    per-entry TTL, so long-running Jets can't grow memory without bound
 *    from per-viewer / per-IP / per-payer keys.
 *
 *  - PersistentIndex: a write-behind JSON snapshot of a plain object to
 *    local/, so a Jet restart doesn't lose the CID index (which is rebuilt
 *    from PUTs otherwise, forcing clients to re-upload metadata).
 *
 * No external deps. Pure Node. Safe to require from Jets.js.
 *
 * @module Safecloud
 * @class Safecloud.Jets._bounded
 */
'use strict';

var fs   = require('fs');
var path = require('path');

/**
 * A Map wrapper with a maximum entry count and optional TTL eviction.
 * Eviction is O(1) amortized: on insert past the cap we drop the oldest
 * inserted key (insertion-ordered via the underlying Map).
 *
 * @class BoundedMap
 * @constructor
 * @param {Object} [opts]
 * @param {Number} [opts.max=10000]  Hard cap on number of entries.
 * @param {Number} [opts.ttlMs=0]    If > 0, entries older than this are
 *                                    treated as absent and lazily purged.
 */
function BoundedMap(opts) {
    opts = opts || {};
    this._max   = opts.max   || 10000;
    this._ttlMs = opts.ttlMs || 0;
    this._m     = new Map(); // key → { v, t }
}

BoundedMap.prototype.get = function (k) {
    var e = this._m.get(k);
    if (!e) { return undefined; }
    if (this._ttlMs && (Date.now() - e.t) > this._ttlMs) {
        this._m.delete(k);
        return undefined;
    }
    return e.v;
};

BoundedMap.prototype.has = function (k) {
    return this.get(k) !== undefined;
};

BoundedMap.prototype.set = function (k, v) {
    // refresh insertion order: delete then re-insert
    if (this._m.has(k)) { this._m.delete(k); }
    this._m.set(k, { v: v, t: Date.now() });
    // evict oldest while over cap
    while (this._m.size > this._max) {
        var oldest = this._m.keys().next().value;
        this._m.delete(oldest);
    }
    return v;
};

BoundedMap.prototype.delete = function (k) { return this._m.delete(k); };
BoundedMap.prototype.size   = function () { return this._m.size; };

/**
 * Sweep expired entries eagerly (optional; lazy purge on get() also works).
 * @method sweep
 */
BoundedMap.prototype.sweep = function () {
    if (!this._ttlMs) { return 0; }
    var now = Date.now(), n = 0;
    for (var pair of this._m) {
        if ((now - pair[1].t) > this._ttlMs) { this._m.delete(pair[0]); n++; }
    }
    return n;
};

/**
 * A plain object mirrored to a JSON file with debounced write-behind.
 * Load once at boot, mutate the .data object as before, call markDirty()
 * after writes. A restart reloads the last snapshot.
 *
 * @class PersistentIndex
 * @constructor
 * @param {String} filePath     Absolute path to the snapshot file.
 * @param {Object} [opts]
 * @param {Number} [opts.debounceMs=2000]  Coalesce writes within this window.
 */
function PersistentIndex(filePath, opts) {
    opts = opts || {};
    this._path = filePath;
    this._debounce = opts.debounceMs || 2000;
    this._timer = null;
    this._writing = false;
    this._pending = false;
    this.data = {};
    this._load();
}

PersistentIndex.prototype._load = function () {
    try {
        if (fs.existsSync(this._path)) {
            var raw = fs.readFileSync(this._path, 'utf8');
            this.data = raw ? JSON.parse(raw) : {};
        }
    } catch (e) {
        // Corrupt snapshot → start empty rather than crash the Jet.
        this.data = {};
    }
};

/**
 * Schedule a debounced snapshot. Cheap to call on every mutation.
 * @method markDirty
 */
PersistentIndex.prototype.markDirty = function () {
    var self = this;
    if (self._timer) { return; }
    self._timer = setTimeout(function () {
        self._timer = null;
        self._flush();
    }, self._debounce);
    // don't keep the event loop alive just for a snapshot
    if (self._timer.unref) { self._timer.unref(); }
};

PersistentIndex.prototype._flush = function () {
    var self = this;
    if (self._writing) { self._pending = true; return; }
    self._writing = true;
    var tmp = self._path + '.tmp';
    var body;
    try { body = JSON.stringify(self.data); }
    catch (e) { self._writing = false; return; }
    fs.writeFile(tmp, body, function (err) {
        if (err) { self._writing = false; return; }
        fs.rename(tmp, self._path, function () {
            self._writing = false;
            if (self._pending) { self._pending = false; self._flush(); }
        });
    });
};

/**
 * Synchronous final flush — call on graceful shutdown (SIGTERM/SIGINT).
 * @method flushSync
 */
PersistentIndex.prototype.flushSync = function () {
    try {
        var tmp = this._path + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(this.data));
        fs.renameSync(tmp, this._path);
    } catch (e) { /* best effort */ }
};

module.exports = { BoundedMap: BoundedMap, PersistentIndex: PersistentIndex };
