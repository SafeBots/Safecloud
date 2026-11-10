'use strict';
/**
 * Catalog — schema registry persisted as catalog.json in the database directory.
 *
 * Tracks table definitions (column names, types, constraints, primary key)
 * and secondary index definitions.  Also maintains the per-table auto-increment
 * counter so it survives reopens.
 */

var fs   = require('fs');
var path = require('path');

function Catalog(dbPath) {
    this._dbPath      = dbPath;
    this._catalogPath = path.join(dbPath, 'catalog.json');
    this._tables      = Object.create(null); // name → TableDef
    this._indexes     = Object.create(null); // name → IndexDef
}

// ─── Persistence ─────────────────────────────────────────────────────────────

Catalog.prototype.load = function () {
    // Clean up any leftover temp file from a previously crashed save.
    try { fs.unlinkSync(this._catalogPath + '.tmp'); } catch (e) {}
    if (!fs.existsSync(this._catalogPath)) return;
    try {
        var data = JSON.parse(fs.readFileSync(this._catalogPath, 'utf8'));
        this._tables  = data.tables  || Object.create(null);
        this._indexes = data.indexes || Object.create(null);
    } catch (e) { /* corrupt or missing → start empty */ }
    // Assign stable slot IDs to any columns that pre-date this change.
    this._migrateSlotIds();
};

/**
 * Ensure every column in every table has a stable integer slotId.
 * Tables created before columnar storage was introduced have no slotIds;
 * we assign them sequentially and save so the next startup is a no-op.
 */
Catalog.prototype._migrateSlotIds = function () {
    var dirty = false;
    var self  = this;
    Object.keys(this._tables).forEach(function (name) {
        var t = self._tables[name];
        var needsMigration = t.columns.some(function (c) { return !c.slotId; });
        if (needsMigration) {
            var nextId = 1;
            t.columns.forEach(function (c) { c.slotId = nextId++; c.active = true; });
            t._nextSlotId = nextId;
            dirty = true;
        } else if (!t._nextSlotId) {
            var maxId = 0;
            t.columns.forEach(function (c) { if ((c.slotId || 0) > maxId) maxId = c.slotId; });
            t._nextSlotId = maxId + 1;
        }
    });
    if (dirty) this.save();
};

/**
 * Persist the catalog atomically via write-to-temp-then-rename.
 * The catalog is always written last by Engine.flush(), making it
 * the commit marker: a consistent catalog means all table data it
 * references was successfully flushed before this save completed.
 */
Catalog.prototype.save = function () {
    fs.mkdirSync(this._dbPath, { recursive: true });
    var tmp = this._catalogPath + '.tmp';
    fs.writeFileSync(
        tmp,
        JSON.stringify({ v: 1, tables: this._tables, indexes: this._indexes }),
        'utf8'
    );
    fs.renameSync(tmp, this._catalogPath);
};

// ─── Tables ──────────────────────────────────────────────────────────────────

/**
 * @param {string}   name
 * @param {Array}    columns   [{name, type, notNull, defaultValue, primaryKey, autoIncrement}]
 * @param {Array}    [constraints]  [{type: 'primary_key'|'unique', columns: []}]
 */
Catalog.prototype.createTable = function (name, columns, constraints) {
    if (this._tables[name]) throw new Error('Table already exists: ' + name);
    constraints = constraints || [];

    // Determine primary key columns
    var pk = [];
    for (var i = 0; i < columns.length; i++) {
        if (columns[i].primaryKey) pk.push(columns[i].name);
    }
    // Table-level PRIMARY KEY constraint overrides column-level
    for (var j = 0; j < constraints.length; j++) {
        if (constraints[j].type === 'primary_key' && constraints[j].columns.length) {
            pk = constraints[j].columns;
        }
    }

    // Implicit rowid if no PK specified
    var autoRowid = pk.length === 0;
    if (autoRowid) pk = ['__rowid__'];

    // Assign stable slot IDs to each column so they can be persisted in separate files.
    var nextSlotId = 1;
    columns = columns.map(function (c) {
        return Object.assign({}, c, { slotId: nextSlotId++, active: true });
    });

    this._tables[name] = {
        name:        name,
        columns:     columns,
        primaryKey:  pk,
        autoRowid:   autoRowid,
        constraints: constraints,
        _nextRowid:  1,
        _nextSlotId: nextSlotId
    };
    this.save();
};

Catalog.prototype.dropTable = function (name, ifExists) {
    if (!this._tables[name]) {
        if (ifExists) return;
        throw new Error('Table not found: ' + name);
    }
    delete this._tables[name];
    // Cascade drop to indexes
    var self = this;
    Object.keys(this._indexes).forEach(function (iName) {
        if (self._indexes[iName].table === name) delete self._indexes[iName];
    });
    this.save();
};

Catalog.prototype.getTable = function (name) {
    return this._tables[name] || null;
};

Catalog.prototype.listTables = function () {
    return Object.keys(this._tables);
};

Catalog.prototype.getColumn = function (tableName, colName) {
    var t = this._tables[tableName];
    if (!t) return null;
    for (var i = 0; i < t.columns.length; i++) {
        if (t.columns[i].name === colName) return t.columns[i];
    }
    return null;
};

/** Allocate the next rowid for a table. */
Catalog.prototype.nextRowid = function (tableName) {
    var t = this._tables[tableName];
    if (!t) throw new Error('Table not found: ' + tableName);
    var id = t._nextRowid++;
    this.save();
    return id;
};

/** Bump _nextRowid if needed (e.g. after learning a max value from a scan). */
Catalog.prototype.bumpRowid = function (tableName, minNext) {
    var t = this._tables[tableName];
    if (t && t._nextRowid <= minNext) {
        t._nextRowid = minNext + 1;
        this.save();
    }
};

// ─── Indexes ─────────────────────────────────────────────────────────────────

/**
 * @param {string}  name
 * @param {string}  tableName
 * @param {Array}   columns   [{name, desc}]
 * @param {boolean} unique
 */
Catalog.prototype.createIndex = function (name, tableName, columns, unique) {
    if (!this._tables[tableName]) throw new Error('Table not found: ' + tableName);
    if (this._indexes[name]) throw new Error('Index already exists: ' + name);
    this._indexes[name] = { name: name, table: tableName, columns: columns, unique: !!unique };
    this.save();
};

Catalog.prototype.dropIndex = function (name, ifExists) {
    if (!this._indexes[name]) {
        if (ifExists) return;
        throw new Error('Index not found: ' + name);
    }
    delete this._indexes[name];
    this.save();
};

Catalog.prototype.getIndex = function (name) {
    return this._indexes[name] || null;
};

Catalog.prototype.getTableIndexes = function (tableName) {
    var self = this;
    return Object.keys(this._indexes)
        .filter(function (n) { return self._indexes[n].table === tableName; })
        .map(function (n) { return self._indexes[n]; });
};

/**
 * Return the columnar schema for a table: the slot descriptor for every column.
 * Used by ColumnarStore to know which column files to read/write.
 *
 * @param  {string} tableName
 * @returns {{ slots: Array<{id:number, name:string, type:string, active:boolean}> }}
 */
Catalog.prototype.getSchema = function (tableName) {
    var t = this._tables[tableName];
    if (!t) return { slots: [] };
    return {
        slots: t.columns.map(function (c) {
            return {
                id:     c.slotId || 0,
                name:   c.name,
                type:   c.type,
                active: c.active !== false
            };
        })
    };
};

module.exports = Catalog;
