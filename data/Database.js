"use strict";
/**
 * Database — indexed KV store with version history, built on TreeStore.
 *
 * A database consists of:
 *   - A primary tree (KV mode) — keys are primary keys, values are records
 *   - Index trees (KV mode) — one per indexed field, keys are "indexValue\0primaryKey"
 *   - A commit log (append-only) — snapshots of all tree roots for versioning
 *   - A schema record — stored at the reserved key "_schema" in the primary tree
 *
 * Dolt analog: versioned database with commit history, diff, rollback.
 *
 * @module data/Database
 */

const SEP = '\0'; // Null byte separator for index keys

class Database {
    /**
     * @param {TreeStore} store
     * @param {string} name
     * @param {object} [schema] — { fields: { name: type }, indexes: [fieldName, ...] }
     */
    constructor(store, name, schema) {
        this._store = store;
        this._name = name;

        // Primary data tree
        const pt = store.createTree('db:' + name + ':primary', { mode: 'kv' });
        this._primaryId = pt.treeId;

        // Commit log
        const cl = store.createTree('db:' + name + ':commits', { mode: 'append' });
        this._commitsId = cl.treeId;

        // Index trees: fieldName → treeId
        this._indexes = new Map();

        // Schema
        this._schema = schema || { fields: {}, indexes: [] };

        // Create index trees
        if (schema && schema.indexes) {
            for (const field of schema.indexes) {
                this.addIndex(field);
            }
        }

        // Store schema in primary tree
        store.put(this._primaryId, '_schema', this._schema);

        this._headCommitIndex = -1;
    }

    // ── CRUD ──

    /**
     * Put a record. Automatically updates all indexes.
     * @param {string} key — primary key
     * @param {object} record
     */
    put(key, record) {
        // Remove old index entries if updating
        const existing = this._store.get(this._primaryId, key);
        if (existing && existing.value) {
            this._removeFromIndexes(key, existing.value);
        }

        // Write primary
        this._store.put(this._primaryId, key, record);

        // Update indexes
        this._addToIndexes(key, record);
    }

    /**
     * Get a record by primary key.
     * @param {string} key
     * @returns {object|null}
     */
    get(key) {
        const result = this._store.get(this._primaryId, key);
        return result ? result.value : null;
    }

    /**
     * Delete a record. Automatically updates all indexes.
     * @param {string} key
     * @returns {boolean}
     */
    delete(key) {
        const existing = this._store.get(this._primaryId, key);
        if (existing && existing.value) {
            this._removeFromIndexes(key, existing.value);
        }
        return this._store.delete(this._primaryId, key);
    }

    /**
     * Scan the primary tree.
     * @param {object} [opts] — { gte, lt, limit, reverse }
     * @returns {Array<{ key: string, value: object }>}
     */
    scan(opts) {
        const results = this._store.range(this._primaryId, opts || {});
        // Filter out the _schema key
        return results.filter(e => e.key !== '_schema');
    }

    /**
     * Count records (excluding _schema).
     * @returns {number}
     */
    count() {
        return this._store.size(this._primaryId) - 1; // minus _schema
    }

    // ── Index queries ──

    /**
     * Query by index.
     * @param {string} field — indexed field name
     * @param {object} opts — { eq, gte, lt, limit, reverse }
     *   eq is a convenience for exact match (sets gte and lt automatically)
     * @returns {Array<{ key: string, value: object }>}
     */
    query(field, opts) {
        const indexTreeId = this._indexes.get(field);
        if (!indexTreeId) throw new Error(`No index on field: ${field}`);

        const rangeOpts = {};

        if (opts.eq !== undefined) {
            const val = String(opts.eq);
            rangeOpts.gte = val + SEP;
            rangeOpts.lt = val + SEP + '\xff';
        } else {
            if (opts.gte !== undefined) rangeOpts.gte = String(opts.gte) + SEP;
            if (opts.gt !== undefined)  rangeOpts.gt = String(opts.gt) + SEP + '\xff';
            if (opts.lt !== undefined)  rangeOpts.lt = String(opts.lt) + SEP;
            if (opts.lte !== undefined) rangeOpts.lte = String(opts.lte) + SEP + '\xff';
        }

        if (opts.limit) rangeOpts.limit = opts.limit;
        if (opts.reverse) rangeOpts.reverse = true;

        const indexEntries = this._store.range(indexTreeId, rangeOpts);

        // Look up primary records
        const results = [];
        for (const entry of indexEntries) {
            const primaryKey = entry.value;
            const record = this._store.get(this._primaryId, primaryKey);
            if (record) {
                results.push({ key: primaryKey, value: record.value });
            }
        }
        return results;
    }

    // ── Index management ──

    /**
     * Add an index on a field.
     * If records already exist, builds the index from existing data.
     * @param {string} field
     */
    addIndex(field) {
        if (this._indexes.has(field)) return;

        const { treeId } = this._store.createTree(
            'db:' + this._name + ':idx:' + field,
            { mode: 'kv' }
        );
        this._indexes.set(field, treeId);

        // Build index from existing records
        const records = this._store.range(this._primaryId, {});
        for (const { key, value } of records) {
            if (key === '_schema') continue;
            if (value && value[field] !== undefined) {
                const indexKey = String(value[field]) + SEP + key;
                this._store.put(treeId, indexKey, key);
            }
        }

        // Update schema
        if (!this._schema.indexes.includes(field)) {
            this._schema.indexes.push(field);
            this._store.put(this._primaryId, '_schema', this._schema);
        }
    }

    /**
     * Drop an index.
     * @param {string} field
     */
    dropIndex(field) {
        this._indexes.delete(field);
        const idx = this._schema.indexes.indexOf(field);
        if (idx >= 0) {
            this._schema.indexes.splice(idx, 1);
            this._store.put(this._primaryId, '_schema', this._schema);
        }
    }

    /**
     * List current indexes.
     * @returns {string[]}
     */
    getIndexes() {
        return Array.from(this._indexes.keys());
    }

    // ── Versioning ──

    /**
     * Create a versioned snapshot (commit).
     * @param {string} message
     * @returns {{ commitIndex: number, primaryCid: string }}
     */
    commit(message) {
        const primaryCid = this._store.checkpoint(this._primaryId);
        const indexCids = {};
        for (const [field, treeId] of this._indexes) {
            indexCids[field] = this._store.checkpoint(treeId);
        }

        const commitRecord = {
            primaryCid: primaryCid,
            indexCids: indexCids,
            message: message,
            timestamp: Date.now()
        };

        const { index } = this._store.append(this._commitsId, commitRecord);
        this._headCommitIndex = index;
        return { commitIndex: index, primaryCid };
    }

    /**
     * Get commit history.
     * @param {object} [opts]
     * @param {number} [opts.limit]
     * @returns {Array<{ index: number, primaryCid: string, message: string, timestamp: number }>}
     */
    log(opts) {
        const allCommits = this._store.range(this._commitsId, {
            reverse: true,
            limit: opts && opts.limit
        });
        return allCommits.map(e => ({ index: e.key, ...e.value }));
    }

    /**
     * Rollback to a previous commit.
     * @param {number} commitIndex
     */
    rollback(commitIndex) {
        const commitResult = this._store.get(this._commitsId, commitIndex);
        if (!commitResult) throw new Error(`Commit not found: ${commitIndex}`);

        const commit = commitResult.value;

        // Hydrate primary tree
        const { treeId: primaryId } = this._store.hydrate(commit.primaryCid);
        this._primaryId = primaryId;

        // Hydrate index trees
        this._indexes.clear();
        for (const [field, cid] of Object.entries(commit.indexCids)) {
            const { treeId } = this._store.hydrate(cid);
            this._indexes.set(field, treeId);
        }

        this._headCommitIndex = commitIndex;
    }

    /**
     * Diff two commits.
     * @param {number} commitIndexA
     * @param {number} commitIndexB
     * @returns {Array<{ key: string, type: string, before: *, after: * }>}
     */
    diff(commitIndexA, commitIndexB) {
        const commitA = this._store.get(this._commitsId, commitIndexA);
        const commitB = this._store.get(this._commitsId, commitIndexB);
        if (!commitA || !commitB) throw new Error('Commit not found');

        const changes = this._store.diff(commitA.value.primaryCid, commitB.value.primaryCid);
        return changes
            .filter(c => c.key !== '_schema')
            .map(c => ({
                key: c.key,
                type: c.before === null ? 'added' : c.after === null ? 'removed' : 'modified',
                before: c.before,
                after: c.after
            }));
    }

    // ── Internal ──

    _addToIndexes(primaryKey, record) {
        for (const [field, treeId] of this._indexes) {
            if (record[field] !== undefined) {
                const indexKey = String(record[field]) + SEP + primaryKey;
                this._store.put(treeId, indexKey, primaryKey);
            }
        }
    }

    _removeFromIndexes(primaryKey, record) {
        for (const [field, treeId] of this._indexes) {
            if (record[field] !== undefined) {
                const indexKey = String(record[field]) + SEP + primaryKey;
                this._store.delete(treeId, indexKey);
            }
        }
    }
}

module.exports = Database;
