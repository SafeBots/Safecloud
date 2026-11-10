'use strict';
/**
 * Statement — a better-sqlite3-compatible prepared statement.
 *
 * API surface:
 *   stmt.get(...params)       → first row or undefined
 *   stmt.all(...params)       → all rows
 *   stmt.run(...params)       → { changes, lastInsertRowid }
 *   stmt.iterate(...params)   → sync iterator (Symbol.iterator)
 *   stmt.bind(...params)      → returns this (bound params)
 *   stmt.pluck([on])          → return first column value only
 *   stmt.expand([on])         → return rows with table-qualified keys
 *   stmt.raw([on])            → return rows as arrays
 *
 * Parameter forms (mirrors better-sqlite3):
 *   positional  → stmt.get(1, 2, 3) or stmt.get([1, 2, 3])
 *   named       → stmt.get({ id: 1, name: 'Alice' })
 */

function Statement(engine, sql) {
    this._engine  = engine;
    this._sql     = sql;
    this._bound   = null;
    this._pluck   = false;
    this._rawMode = false;
}

// Normalise variadic / array / object params into a single value.
function normaliseParams(args, bound) {
    if (bound) return bound;
    if (args.length === 0) return [];
    if (args.length === 1) {
        var a = args[0];
        if (Array.isArray(a)) return a;
        if (a !== null && typeof a === 'object' && !Buffer.isBuffer(a)) return a;
    }
    return Array.from(args);
}

Statement.prototype._exec = function (args) {
    var params = normaliseParams(args, this._bound);
    return this._engine.execute(this._sql, params);
};

/** Return the first row, or undefined. */
Statement.prototype.get = function () {
    var result = this._exec(arguments);
    var row = result.rows && result.rows.length ? result.rows[0] : undefined;
    return this._transform(row);
};

/** Return all rows. */
Statement.prototype.all = function () {
    var result = this._exec(arguments);
    var self   = this;
    return (result.rows || []).map(function (r) { return self._transform(r); });
};

/** Execute, returning { changes, lastInsertRowid }. */
Statement.prototype.run = function () {
    var result = this._exec(arguments);
    return { changes: result.changes, lastInsertRowid: result.lastInsertRowid };
};

/** Sync iterator over rows. */
Statement.prototype.iterate = function () {
    var rows = this.all.apply(this, arguments);
    var i = 0;
    var iter = {
        next: function () {
            if (i < rows.length) return { value: rows[i++], done: false };
            return { value: undefined, done: true };
        }
    };
    iter[Symbol.iterator] = function () { return iter; };
    return iter;
};

/** Bind permanent params (returns this for chaining). */
Statement.prototype.bind = function () {
    this._bound = normaliseParams(arguments, null);
    return this;
};

/** When on=true, .get()/.all() return just the first-column value. */
Statement.prototype.pluck = function (on) {
    this._pluck = (on !== false);
    return this;
};

/** Raw mode: return rows as arrays rather than objects. */
Statement.prototype.raw = function (on) {
    this._rawMode = (on !== false);
    return this;
};

/** Expand mode: no-op here (already uses unqualified keys). */
Statement.prototype.expand = function () { return this; };

Statement.prototype._transform = function (row) {
    if (row === undefined || row === null) return row;
    if (this._pluck) {
        var keys = Object.keys(row);
        return keys.length ? row[keys[0]] : null;
    }
    if (this._rawMode) {
        return Object.values(row);
    }
    return row;
};

module.exports = Statement;
