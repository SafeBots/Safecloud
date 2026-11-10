'use strict';
/**
 * ColumnarStore — synchronous in-memory columnar store with per-column file persistence.
 *
 * Layout on disk (one directory per table):
 *   {dir}/index.json         — {"v":2,"posToKey":["key0","key1",null,...]}
 *                              posToKey[N] = key occupying row position N; null = hole
 *   {dir}/col_{slotId}.json  — {"v":2,"slot":N,"values":[v0,v1,...]}
 *                              one file per column slot, indexed by row position
 *
 * Benefits over row-storage:
 *   - Hot columns (e.g. `cid`) stay in OS page cache; cold columns are evicted.
 *   - DROP COLUMN = flip `active:false` in catalog + delete col_{id}.json (O(1) DDL).
 *   - ADD COLUMN = new slot ID + new col_{id}.json; existing rows get null at the slot.
 *   - Pipelined reads: column files for one query can be fetched concurrently.
 *
 * Deleted rows leave null holes; hole positions are recycled (LIFO) on new inserts.
 *
 * API matches TableStore so Engine can swap one for the other without other changes.
 */

var fs   = require('fs');
var path = require('path');

// ─── Binary search helpers ────────────────────────────────────────────────────

function bisect(arr, key) {
    var lo = 0, hi = arr.length;
    while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (arr[mid] < key) lo = mid + 1; else hi = mid;
    }
    if (lo < arr.length && arr[lo] === key) return lo;
    return -(lo + 1);
}

function lowerBound(arr, key) {
    var lo = 0, hi = arr.length;
    while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (arr[mid] < key) lo = mid + 1; else hi = mid;
    }
    return lo;
}

function upperBound(arr, key) {
    var lo = 0, hi = arr.length;
    while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (arr[mid] <= key) lo = mid + 1; else hi = mid;
    }
    return lo;
}

// ─── ColumnarStore ────────────────────────────────────────────────────────────

/**
 * @param {string} dir     Directory that holds this table's column files.
 * @param {object} schema  {slots:[{id:N, name:"col", type:"TEXT", active:bool}]}
 */
function ColumnarStore(dir, schema) {
    this._dir        = dir;
    this._keys       = [];                  // sorted primary-key strings
    this._keyToPos   = Object.create(null); // key → integer row position
    this._posToKey   = [];                  // row position → key (null at holes)
    this._cols       = Object.create(null); // slotId → Array of column values
    this._holes      = [];                  // recycled positions (LIFO stack)
    this._nextPos    = 0;
    this._dirty      = Object.create(null); // slotId → bool
    this._indexDirty = false;
    this._schema     = null;
    this._slotByName = Object.create(null); // colName → slot descriptor
    if (schema) this._applySchema(schema);
}

ColumnarStore.prototype._applySchema = function (schema) {
    this._schema     = schema;
    this._slotByName = Object.create(null);
    var self = this;
    (schema.slots || []).forEach(function (s) {
        if (s.active !== false) self._slotByName[s.name] = s;
        // Ensure column array exists (don't clobber data already loaded from disk)
        if (!self._cols[s.id]) self._cols[s.id] = [];
    });
};

/** Return only the active (non-dropped) column slots. */
ColumnarStore.prototype._activeSlots = function () {
    if (!this._schema) return [];
    return (this._schema.slots || []).filter(function (s) { return s.active !== false; });
};

/** Refresh schema in-place after DDL (ADD/DROP/RENAME COLUMN). */
ColumnarStore.prototype.updateSchema = function (schema) {
    this._applySchema(schema);
};

/** Load from disk.  Call once after construction; safe to call on an empty dir. */
ColumnarStore.prototype.load = function () {
    // Remove stale temp files left by a previously crashed flush
    var indexPath = path.join(this._dir, 'index.json');
    try { fs.unlinkSync(indexPath + '.tmp'); } catch (e) {}

    if (!fs.existsSync(indexPath)) return; // brand-new or empty store

    var raw;
    try { raw = JSON.parse(fs.readFileSync(indexPath, 'utf8')); } catch (e) { return; }
    if (!raw || !Array.isArray(raw.posToKey)) return;

    var posToKey   = raw.posToKey;
    this._posToKey = posToKey;
    this._nextPos  = posToKey.length;
    this._keys     = [];
    this._keyToPos = Object.create(null);
    this._holes    = [];

    for (var i = 0; i < posToKey.length; i++) {
        if (posToKey[i] !== null && posToKey[i] !== undefined) {
            this._keyToPos[posToKey[i]] = i;
            this._keys.push(posToKey[i]);
        } else {
            this._holes.push(i);
        }
    }
    this._keys.sort(); // positions may be non-contiguous after deletes

    // Load each column file defined in the schema
    var self = this;
    if (this._schema) {
        (this._schema.slots || []).forEach(function (s) {
            var colPath = path.join(self._dir, 'col_' + s.id + '.json');
            try { fs.unlinkSync(colPath + '.tmp'); } catch (e) {}
            if (!fs.existsSync(colPath)) { self._cols[s.id] = []; return; }
            try {
                var cr = JSON.parse(fs.readFileSync(colPath, 'utf8'));
                self._cols[s.id] = Array.isArray(cr.values) ? cr.values : [];
            } catch (e) {
                self._cols[s.id] = [];
            }
        });
    }

    this._dirty      = Object.create(null);
    this._indexDirty = false;
};

/** Reconstruct a row object from column arrays at the given position. */
ColumnarStore.prototype._rowFromPos = function (pos) {
    var row   = Object.create(null);
    var slots = this._activeSlots();
    for (var i = 0; i < slots.length; i++) {
        var s   = slots[i];
        var col = this._cols[s.id];
        row[s.name] = (col && pos < col.length && col[pos] !== undefined) ? col[pos] : null;
    }
    return row;
};

/** Point lookup.  Returns row object or undefined. */
ColumnarStore.prototype.get = function (key) {
    var pos = this._keyToPos[key];
    if (pos === undefined) return undefined;
    return this._rowFromPos(pos);
};

/** Upsert. */
ColumnarStore.prototype.set = function (key, row) {
    var pos = this._keyToPos[key];
    if (pos === undefined) {
        // New key — allocate or recycle a row position
        pos = this._holes.length > 0 ? this._holes.pop() : this._nextPos++;
        this._keyToPos[key] = pos;
        this._posToKey[pos] = key;
        var idx = bisect(this._keys, key);
        // Only insert when key is not already present (idx < 0 means not found).
        // A non-negative idx means _keys has the key but _keyToPos lost it (shouldn't
        // happen, but guard against it rather than inserting a duplicate).
        if (idx < 0) this._keys.splice(-idx - 1, 0, key);
        this._indexDirty = true;
    }
    // Scatter the row's values into each active column array
    var slots = this._activeSlots();
    for (var i = 0; i < slots.length; i++) {
        var s = slots[i];
        if (!this._cols[s.id]) this._cols[s.id] = [];
        this._cols[s.id][pos] = (row && Object.prototype.hasOwnProperty.call(row, s.name)) ? row[s.name] : null;
        this._dirty[s.id] = true;
    }
};

/** Delete.  Returns true if the key existed. */
ColumnarStore.prototype.delete = function (key) {
    var pos = this._keyToPos[key];
    if (pos === undefined) return false;
    var idx = bisect(this._keys, key);
    if (idx >= 0) this._keys.splice(idx, 1);
    delete this._keyToPos[key];
    this._posToKey[pos] = null; // mark as hole
    this._holes.push(pos);
    this._indexDirty = true;
    // Null out column values at this position
    var slots = this._activeSlots();
    for (var i = 0; i < slots.length; i++) {
        var s = slots[i];
        if (this._cols[s.id]) { this._cols[s.id][pos] = null; this._dirty[s.id] = true; }
    }
    return true;
};

/**
 * Range scan.
 * @param {string|null} startKey  inclusive lower bound; null = start of store
 * @param {string|null} endKey    inclusive upper bound; null = end of store
 * @param {object}      opts      { reverse: bool, limit: number }
 */
ColumnarStore.prototype.scan = function (startKey, endKey, opts) {
    opts = opts || {};
    var results = [];
    var limit   = (opts.limit > 0) ? opts.limit : Infinity;
    var i, lo, hi;

    if (!opts.reverse) {
        lo = (startKey != null) ? lowerBound(this._keys, startKey) : 0;
        for (i = lo; i < this._keys.length && results.length < limit; i++) {
            if (endKey != null && this._keys[i] > endKey) break;
            results.push({ key: this._keys[i], value: this.get(this._keys[i]) });
        }
    } else {
        hi = (endKey != null)   ? upperBound(this._keys, endKey) - 1 : this._keys.length - 1;
        lo = (startKey != null) ? lowerBound(this._keys, startKey)   : 0;
        for (i = hi; i >= lo && results.length < limit; i--) {
            results.push({ key: this._keys[i], value: this.get(this._keys[i]) });
        }
    }
    return results;
};

/** Return all {key, value} pairs in sorted key order. */
ColumnarStore.prototype.all = function () {
    var self = this;
    return this._keys.map(function (k) {
        return { key: k, value: self.get(k) };
    });
};

/** Number of live rows. */
ColumnarStore.prototype.count = function () {
    return this._keys.length;
};

/** Remove all rows. */
/**
 * Add a new column to an existing table, backfilling all existing rows with defVal.
 * Called by Engine._alter() when processing ALTER TABLE ADD COLUMN.
 * @param {number}  slotId   The new column's stable slot ID.
 * @param {*}       defVal   Default value for existing rows (null if none).
 */
ColumnarStore.prototype.addColumn = function (slotId, defVal) {
    var values = new Array(this._nextPos);
    for (var i = 0; i < this._nextPos; i++) {
        values[i] = (this._posToKey[i] != null) ? defVal : null;
    }
    this._cols[slotId]  = values;
    this._dirty[slotId] = true;
};

ColumnarStore.prototype.clear = function () {
    this._keys       = [];
    this._keyToPos   = Object.create(null);
    this._posToKey   = [];
    this._holes      = [];
    this._nextPos    = 0;
    this._indexDirty = true;
    var slots = this._schema ? (this._schema.slots || []) : [];
    for (var i = 0; i < slots.length; i++) {
        this._cols[slots[i].id]  = [];
        this._dirty[slots[i].id] = true;
    }
};

/**
 * Flush dirty column files and the index file to disk atomically.
 * Uses write-to-temp-then-rename so a crash mid-flush never leaves a
 * corrupt file; the previous version is always the fallback.
 */
ColumnarStore.prototype.flush = function () {
    var self     = this;
    var hasDirty = this._indexDirty;
    if (!hasDirty) {
        var ids = Object.keys(this._dirty);
        for (var i = 0; i < ids.length; i++) {
            if (this._dirty[ids[i]]) { hasDirty = true; break; }
        }
    }
    if (!hasDirty) return;

    fs.mkdirSync(this._dir, { recursive: true });

    // Flush each dirty column file
    Object.keys(this._dirty).forEach(function (slotId) {
        if (!self._dirty[slotId]) return;
        var colPath = path.join(self._dir, 'col_' + slotId + '.json');
        var tmp     = colPath + '.tmp';
        var values  = self._cols[slotId] || [];
        fs.writeFileSync(tmp, JSON.stringify({ v: 2, slot: Number(slotId), values: values }), 'utf8');
        fs.renameSync(tmp, colPath);
        self._dirty[slotId] = false;
    });

    // Flush the index (posToKey mapping)
    if (this._indexDirty) {
        var indexPath = path.join(this._dir, 'index.json');
        var tmp       = indexPath + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify({ v: 2, posToKey: this._posToKey }), 'utf8');
        fs.renameSync(tmp, indexPath);
        this._indexDirty = false;
    }
};

module.exports = ColumnarStore;
