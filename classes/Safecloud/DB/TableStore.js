'use strict';
/**
 * TableStore — synchronous in-memory sorted key-value store with JSON persistence.
 *
 * Keeps a sorted array of keys for O(log n) binary-search lookups and
 * O(log n + k) range scans.  Inserts are O(n) (splice into sorted array)
 * which is fine for local-DB workloads; the Prolly-tree backend swaps in
 * later for distributed use.
 *
 * Prefix deduplication on disk:
 *   Sorted adjacent entries that share a key prefix store only the suffix.
 *   This compresses repeated column prefixes (e.g. all rows for a user_id)
 *   before encryption, saving significant storage.
 *
 * Persistence: one `.json` file per store, written by flush() / close().
 */

var fs = require('fs');
var path = require('path');

// ─── Binary search ────────────────────────────────────────────────────────────

/**
 * Returns the index of `key` in sorted array `arr`, or -(insertionPoint+1) if absent.
 * Invariant: insertionPoint is the first index where arr[idx] >= key.
 */
function bisect(arr, key) {
    var lo = 0, hi = arr.length;
    while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (arr[mid] < key) lo = mid + 1;
        else hi = mid;
    }
    if (lo < arr.length && arr[lo] === key) return lo;
    return -(lo + 1);
}

/** First index where arr[idx] >= key (insertion point). */
function lowerBound(arr, key) {
    var lo = 0, hi = arr.length;
    while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (arr[mid] < key) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

/** First index where arr[idx] > key. */
function upperBound(arr, key) {
    var lo = 0, hi = arr.length;
    while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (arr[mid] <= key) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

// ─── Prefix deduplication ─────────────────────────────────────────────────────

function commonPrefixLen(a, b) {
    var n = Math.min(a.length, b.length), i = 0;
    while (i < n && a.charCodeAt(i) === b.charCodeAt(i)) i++;
    return i;
}

/**
 * Deflate sorted entries to delta-encoded form for compact storage.
 * Each entry stores only the number of shared prefix bytes (p) and
 * the key suffix (k).  Values are stored verbatim (JSON); a column-level
 * dictionary would be a further optimisation for repeated values.
 */
function deflate(entries) {
    var out = new Array(entries.length);
    var prev = '';
    for (var i = 0; i < entries.length; i++) {
        var key = entries[i].key;
        var p = commonPrefixLen(prev, key);
        out[i] = { p: p, k: key.slice(p), v: entries[i].value };
        prev = key;
    }
    return out;
}

/** Inflate back to {key, value} pairs. */
function inflate(deflated) {
    var out = new Array(deflated.length);
    var prev = '';
    for (var i = 0; i < deflated.length; i++) {
        var e = deflated[i];
        var key = prev.slice(0, e.p) + e.k;
        out[i] = { key: key, value: e.v };
        prev = key;
    }
    return out;
}

// ─── TableStore ───────────────────────────────────────────────────────────────

function TableStore(filePath) {
    this._path  = filePath;
    this._keys  = [];   // sorted encoded-key strings
    this._data  = Object.create(null); // key → value object
    this._dirty = false;
}

/** Load from disk, or start empty if the file doesn't exist. */
TableStore.prototype.load = function () {
    // Clean up any leftover temp file from a previously crashed flush.
    // The rename did not complete, so the target (if present) is still valid.
    try { fs.unlinkSync(this._path + '.tmp'); } catch (e) {}
    if (!fs.existsSync(this._path)) return;
    var raw;
    try { raw = fs.readFileSync(this._path, 'utf8'); }
    catch (e) { return; }
    var parsed;
    try { parsed = JSON.parse(raw); }
    catch (e) { return; }
    if (!parsed || !parsed.entries) return;
    var entries = inflate(parsed.entries);
    this._keys = entries.map(function (e) { return e.key; });
    for (var i = 0; i < entries.length; i++) {
        this._data[entries[i].key] = entries[i].value;
    }
    this._dirty = false;
};

/**
 * Flush to disk if dirty.
 *
 * Uses an atomic write-to-temp-then-rename pattern so a crash mid-write
 * never leaves a corrupt store file.  POSIX rename(2) is atomic within
 * a single filesystem, so the file is either the old version or the new
 * version — never a half-written intermediate.
 *
 * Note on multi-table commit atomicity: Engine.flush() (called from
 * commitTx) flushes all table stores first, then saves the catalog last.
 * The catalog therefore acts as a commit marker: if the catalog is
 * consistent, every table it references was fully flushed.  A crash
 * between individual table renames leaves at most one stale .tmp file
 * (cleaned up on the next load) and the catalog pointing at the previous
 * committed state for that table.  Full write-ahead logging would be
 * required for strict cross-table atomicity; this is intentionally a
 * pragmatic trade-off for the local/embedded use case.
 */
TableStore.prototype.flush = function () {
    if (!this._dirty) return;
    var entries = this._keys.map(function (k) {
        return { key: k, value: this._data[k] };
    }, this);
    var json = JSON.stringify({ v: 1, entries: deflate(entries) });
    var dir  = path.dirname(this._path);
    var tmp  = this._path + '.tmp';
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(tmp, json, 'utf8');
    fs.renameSync(tmp, this._path);
    this._dirty = false;
};

/** Point lookup. Returns value object or undefined. */
TableStore.prototype.get = function (key) {
    return this._data[key];
};

/** Upsert. */
TableStore.prototype.set = function (key, value) {
    var idx = bisect(this._keys, key);
    if (idx >= 0) {
        this._data[key] = value;
    } else {
        this._keys.splice(-idx - 1, 0, key);
        this._data[key] = value;
    }
    this._dirty = true;
};

/** Delete. Returns true if the key existed. */
TableStore.prototype.delete = function (key) {
    var idx = bisect(this._keys, key);
    if (idx < 0) return false;
    this._keys.splice(idx, 1);
    delete this._data[key];
    this._dirty = true;
    return true;
};

/**
 * Range scan.  Returns an array of {key, value} in ascending key order.
 *
 * @param {string|null} startKey  inclusive lower bound; null = start of range
 * @param {string|null} endKey    inclusive upper bound; null = end of range
 * @param {object}      opts      { reverse: bool, limit: number }
 */
TableStore.prototype.scan = function (startKey, endKey, opts) {
    opts = opts || {};
    var results = [];
    var limit = (opts.limit > 0) ? opts.limit : Infinity;

    if (!opts.reverse) {
        var lo = (startKey != null) ? lowerBound(this._keys, startKey) : 0;
        for (var i = lo; i < this._keys.length && results.length < limit; i++) {
            if (endKey != null && this._keys[i] > endKey) break;
            results.push({ key: this._keys[i], value: this._data[this._keys[i]] });
        }
    } else {
        var hi = (endKey != null) ? upperBound(this._keys, endKey) - 1 : this._keys.length - 1;
        var lo = (startKey != null) ? lowerBound(this._keys, startKey) : 0;
        for (var i = hi; i >= lo && results.length < limit; i--) {
            results.push({ key: this._keys[i], value: this._data[this._keys[i]] });
        }
    }
    return results;
};

/** Return all {key, value} pairs in sorted order. */
TableStore.prototype.all = function () {
    return this._keys.map(function (k) {
        return { key: k, value: this._data[k] };
    }, this);
};

/** Number of entries. */
TableStore.prototype.count = function () {
    return this._keys.length;
};

/** Remove all entries. */
TableStore.prototype.clear = function () {
    this._keys = [];
    this._data = Object.create(null);
    this._dirty = true;
};

module.exports = TableStore;
