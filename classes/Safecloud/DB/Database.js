'use strict';
/**
 * Database — better-sqlite3-compatible Database class.
 *
 * Drop-in replacement for:  new Database(filename, options?)
 *
 * API surface:
 *   db.prepare(sql)             → Statement
 *   db.exec(sql)                → this  (runs multiple semicolon-separated statements)
 *   db.transaction(fn)          → wrapping function  (BEGIN/COMMIT/ROLLBACK)
 *   db.pragma(str, opts)        → [] (no-op)
 *   db.close()
 *   db.name                     → filename
 *   db.memory                   → true if ":memory:"
 *   db.open                     → true while open
 *
 * The database is stored on disk as a directory:
 *   <name>/catalog.json         — schema (tables, indexes, auto-increment counters)
 *   <name>/tables/<t>.json      — data for table <t>
 *   <name>/indexes/<i>.json     — data for secondary index <i>
 *
 * Special filename ":memory:" creates a temp dir and deletes it on close().
 */

var fs      = require('fs');
var os      = require('os');
var path    = require('path');
var Engine  = require('./Engine');
var Catalog = require('./Catalog');
var Stmt    = require('./Statement');

var _tmpIdx = 0;

function Database(filename, options) {
    options = options || {};

    this.name   = filename;
    this.memory = (filename === ':memory:');
    this.open   = false;

    var dbPath;
    if (this.memory) {
        dbPath = path.join(os.tmpdir(), 'safedb_mem_' + process.pid + '_' + (++_tmpIdx));
        this._tmpPath = dbPath;
    } else {
        dbPath = path.resolve(filename);
    }
    this._dbPath = dbPath;

    // Ensure directory exists
    fs.mkdirSync(dbPath, { recursive: true });

    this._catalog = new Catalog(dbPath);
    this._catalog.load();

    this._engine = new Engine(dbPath, this._catalog);
    this.open    = true;
}

// ─── Core API ─────────────────────────────────────────────────────────────────

/** Compile and return a prepared Statement. */
Database.prototype.prepare = function (sql) {
    this._checkOpen();
    return new Stmt(this._engine, sql.trim());
};

/**
 * Execute one or more semicolon-separated SQL statements.
 * Returns this for chaining.
 */
Database.prototype.exec = function (sql) {
    this._checkOpen();
    var stmts = splitStatements(sql);
    for (var i = 0; i < stmts.length; i++) {
        var s = stmts[i].trim();
        if (s) this._engine.execute(s, []);
    }
    return this;
};

/**
 * Wrap a function in a transaction.
 * Returns a new function: when called it runs BEGIN, fn(...args), COMMIT.
 * If fn throws, ROLLBACK is issued and the error re-thrown.
 */
Database.prototype.transaction = function (fn) {
    var db = this;
    return function () {
        db._checkOpen();
        db._engine.beginTx();
        try {
            var result = fn.apply(this, arguments);
            db._engine.commitTx();
            return result;
        } catch (e) {
            try { db._engine.rollbackTx(); } catch (e2) {}
            throw e;
        }
    };
};

/** Flush all dirty stores to disk and close the database. */
Database.prototype.close = function () {
    if (!this.open) return;
    this._engine.close();
    this.open = false;
    if (this._tmpPath) {
        try { fs.rmSync(this._tmpPath, { recursive: true, force: true }); } catch (e) {}
    }
};

/** No-op pragma shim (returns []). */
Database.prototype.pragma = function (str, opts) {
    return [];
};

/** Flush all dirty stores without closing. */
Database.prototype.flush = function () {
    this._checkOpen();
    this._engine.flush();
};

// ─── Internal ─────────────────────────────────────────────────────────────────

Database.prototype._checkOpen = function () {
    if (!this.open) throw new Error('Database is closed');
};

/**
 * Very simple statement splitter: split on ';' but honour single-quoted
 * string literals (SQLite-style: '' escapes a quote inside a string).
 */
function splitStatements(sql) {
    var stmts = [];
    var cur   = '';
    var inStr = false;
    for (var i = 0; i < sql.length; i++) {
        var ch = sql[i];
        if (inStr) {
            cur += ch;
            if (ch === "'") {
                if (sql[i + 1] === "'") { cur += sql[++i]; } // escaped ''
                else inStr = false;
            }
        } else if (ch === "'") {
            inStr = true;
            cur += ch;
        } else if (ch === ';') {
            stmts.push(cur);
            cur = '';
        } else {
            cur += ch;
        }
    }
    if (cur.trim()) stmts.push(cur);
    return stmts;
}

module.exports = Database;
