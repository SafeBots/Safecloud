"use strict";
/**
 * TreeStore — in-memory reference implementation of the Safecloud tree_* host API.
 *
 * This is the storage primitive that SafecloudApps (Tier 1 WASM) call on the Jet.
 * In production, the Jet implements this in compiled code with WAL and checkpoint.
 * This JS implementation is for testing, local development, and the `safecloud dev`
 * emulator.
 *
 * Two modes per tree:
 *   "kv"     — ordered key-value store with range queries
 *   "append" — append-only log with integer index access
 *
 * Every tree produces a root CID (content identifier) that changes on every
 * mutation. The CID is a SHA-256 hash of the tree's serialised state. This is
 * the Merkle property that makes diff, checkpoint, and hydrate possible.
 *
 * @module data/TreeStore
 */

const crypto = require('crypto');

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function cidFromState(state) {
    // Deterministic serialisation: sort keys at every level.
    // The replacer-array form of JSON.stringify filters keys at ALL depths,
    // so we use a replacer function instead.
    const serialised = JSON.stringify(state, function (key, value) {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            const sorted = {};
            for (const k of Object.keys(value).sort()) sorted[k] = value[k];
            return sorted;
        }
        return value;
    });
    return 'bafy' + sha256(serialised).slice(0, 56);
}

/**
 * In-memory chunk store. Maps CID → serialised state.
 * In production, this is Drops (content-addressed encrypted storage).
 */
class ChunkStore {
    constructor() {
        this._chunks = new Map();
    }
    put(cid, data) {
        this._chunks.set(cid, data);
    }
    get(cid) {
        return this._chunks.get(cid) || null;
    }
    has(cid) {
        return this._chunks.has(cid);
    }
}

class TreeStore {
    /**
     * @param {ChunkStore} [chunkStore] — shared chunk store for checkpoint/hydrate.
     *   Defaults to a new in-memory store.
     */
    constructor(chunkStore) {
        this._chunks = chunkStore || new ChunkStore();
        this._trees = new Map(); // treeId → { mode, name, ... }
        this._nextId = 1;
    }

    // ── Creation ──

    /**
     * Create a named tree.
     * @param {string} name
     * @param {object} [opts]
     * @param {string} [opts.mode='kv'] — 'kv' or 'append'
     * @returns {{ treeId: number }}
     */
    createTree(name, opts) {
        const mode = (opts && opts.mode) || 'kv';
        if (mode !== 'kv' && mode !== 'append') {
            throw new Error(`Invalid tree mode: ${mode}`);
        }
        const treeId = this._nextId++;
        const tree = {
            id: treeId,
            name: name,
            mode: mode,
            // KV mode: sorted entries
            entries: mode === 'kv' ? new Map() : null,
            // Append mode: ordered log
            log: mode === 'append' ? [] : null,
            // Subscribers for live tail
            _subscribers: []
        };
        this._trees.set(treeId, tree);
        return { treeId };
    }

    _getTree(treeId) {
        const tree = this._trees.get(treeId);
        if (!tree) throw new Error(`Tree not found: ${treeId}`);
        return tree;
    }

    // ── Append mode ──

    /**
     * Append a value to an append-only tree.
     * @param {number} treeId
     * @param {*} value
     * @returns {{ index: number, proof: object }}
     */
    append(treeId, value) {
        const tree = this._getTree(treeId);
        if (tree.mode !== 'append') throw new Error('append() requires append-mode tree');
        const index = tree.log.length;
        const entry = { index, value, cid: cidFromState({ index, value }) };
        tree.log.push(entry);
        // Notify subscribers
        for (const cb of tree._subscribers) {
            try { cb(entry); } catch (e) { /* subscriber error, ignore */ }
        }
        return { index, proof: { root: this.root(treeId), index, entryCid: entry.cid } };
    }

    // ── KV mode ──

    /**
     * Put a key-value pair.
     * @param {number} treeId
     * @param {string} key
     * @param {*} value
     * @returns {{ proof: object }}
     */
    put(treeId, key, value) {
        const tree = this._getTree(treeId);
        if (tree.mode !== 'kv') throw new Error('put() requires kv-mode tree');
        tree.entries.set(key, value);
        return { proof: { root: this.root(treeId), key } };
    }

    /**
     * Get a value by key (KV mode) or index (append mode).
     * @param {number} treeId
     * @param {string|number} keyOrIndex
     * @returns {{ value: *, proof: object } | null}
     */
    get(treeId, keyOrIndex) {
        const tree = this._getTree(treeId);
        if (tree.mode === 'kv') {
            if (!tree.entries.has(keyOrIndex)) return null;
            return {
                value: tree.entries.get(keyOrIndex),
                proof: { root: this.root(treeId), key: keyOrIndex }
            };
        } else {
            const idx = Number(keyOrIndex);
            if (idx < 0 || idx >= tree.log.length) return null;
            const entry = tree.log[idx];
            return {
                value: entry.value,
                proof: { root: this.root(treeId), index: idx, entryCid: entry.cid }
            };
        }
    }

    /**
     * Range query over a KV tree.
     * @param {number} treeId
     * @param {object} opts — { gte, gt, lte, lt, limit, reverse }
     * @returns {Array<{ key: string, value: * }>}
     */
    range(treeId, opts) {
        const tree = this._getTree(treeId);
        if (tree.mode === 'kv') {
            return this._kvRange(tree, opts);
        } else {
            return this._appendRange(tree, opts);
        }
    }

    _kvRange(tree, opts) {
        const keys = Array.from(tree.entries.keys()).sort();
        let filtered = keys;

        if (opts.gte !== undefined) filtered = filtered.filter(k => k >= opts.gte);
        if (opts.gt !== undefined)  filtered = filtered.filter(k => k > opts.gt);
        if (opts.lte !== undefined) filtered = filtered.filter(k => k <= opts.lte);
        if (opts.lt !== undefined)  filtered = filtered.filter(k => k < opts.lt);
        if (opts.reverse) filtered = filtered.reverse();
        if (opts.limit) filtered = filtered.slice(0, opts.limit);

        return filtered.map(k => ({ key: k, value: tree.entries.get(k) }));
    }

    _appendRange(tree, opts) {
        let start = 0;
        let end = tree.log.length;

        if (opts.gte !== undefined) start = Math.max(start, opts.gte);
        if (opts.gt !== undefined)  start = Math.max(start, opts.gt + 1);
        if (opts.lte !== undefined) end = Math.min(end, opts.lte + 1);
        if (opts.lt !== undefined)  end = Math.min(end, opts.lt);

        let results = [];
        if (opts.reverse) {
            for (let i = end - 1; i >= start; i--) {
                results.push({ key: i, value: tree.log[i].value });
                if (opts.limit && results.length >= opts.limit) break;
            }
        } else {
            for (let i = start; i < end; i++) {
                results.push({ key: i, value: tree.log[i].value });
                if (opts.limit && results.length >= opts.limit) break;
            }
        }
        return results;
    }

    /**
     * Delete a key from a KV tree.
     * @param {number} treeId
     * @param {string} key
     * @returns {boolean} — true if key existed
     */
    delete(treeId, key) {
        const tree = this._getTree(treeId);
        if (tree.mode !== 'kv') throw new Error('delete() requires kv-mode tree');
        return tree.entries.delete(key);
    }

    // ── Root CID ──

    /**
     * Current root CID of a tree.
     * @param {number} treeId
     * @returns {string}
     */
    root(treeId) {
        const tree = this._getTree(treeId);
        if (tree.mode === 'kv') {
            const sorted = Array.from(tree.entries.keys()).sort();
            const state = { mode: 'kv', name: tree.name, entries: {} };
            for (const k of sorted) state.entries[k] = tree.entries.get(k);
            return cidFromState(state);
        } else {
            const state = {
                mode: 'append',
                name: tree.name,
                length: tree.log.length,
                entries: tree.log.map(e => e.cid)
            };
            return cidFromState(state);
        }
    }

    // ── Checkpoint / Hydrate ──

    /**
     * Checkpoint a tree's state to the chunk store (Drops).
     * Returns the root CID.
     * @param {number} treeId
     * @returns {string} rootCid
     */
    checkpoint(treeId) {
        const tree = this._getTree(treeId);
        const rootCid = this.root(treeId);
        const snapshot = {
            mode: tree.mode,
            name: tree.name,
        };
        if (tree.mode === 'kv') {
            snapshot.entries = {};
            for (const [k, v] of tree.entries) snapshot.entries[k] = v;
        } else {
            snapshot.log = tree.log.map(e => ({ index: e.index, value: e.value, cid: e.cid }));
        }
        this._chunks.put(rootCid, JSON.stringify(snapshot));
        return rootCid;
    }

    /**
     * Hydrate a tree from the chunk store using its root CID.
     * Creates a new treeId backed by the stored state.
     * @param {string} rootCid
     * @returns {{ treeId: number }}
     */
    hydrate(rootCid) {
        const data = this._chunks.get(rootCid);
        if (!data) throw new Error(`Cannot hydrate: CID not found: ${rootCid}`);
        const snapshot = JSON.parse(data);
        const treeId = this._nextId++;
        const tree = {
            id: treeId,
            name: snapshot.name,
            mode: snapshot.mode,
            entries: null,
            log: null,
            _subscribers: []
        };
        if (snapshot.mode === 'kv') {
            tree.entries = new Map();
            for (const [k, v] of Object.entries(snapshot.entries)) {
                tree.entries.set(k, v);
            }
        } else {
            tree.log = snapshot.log.map(e => ({
                index: e.index,
                value: e.value,
                cid: e.cid
            }));
        }
        this._trees.set(treeId, tree);
        return { treeId };
    }

    // ── Diff ──

    /**
     * Diff two tree states by their root CIDs.
     * Returns an array of { key, before, after } for each changed entry.
     * @param {string} cidA
     * @param {string} cidB
     * @returns {Array<{ key: string, before: *, after: * }>}
     */
    diff(cidA, cidB) {
        if (cidA === cidB) return [];

        const dataA = this._chunks.get(cidA);
        const dataB = this._chunks.get(cidB);
        if (!dataA) throw new Error(`CID not found for diff: ${cidA}`);
        if (!dataB) throw new Error(`CID not found for diff: ${cidB}`);

        const snapA = JSON.parse(dataA);
        const snapB = JSON.parse(dataB);

        if (snapA.mode !== snapB.mode) {
            throw new Error('Cannot diff trees with different modes');
        }

        if (snapA.mode === 'kv') {
            return this._diffKV(snapA.entries, snapB.entries);
        } else {
            return this._diffAppend(snapA.log, snapB.log);
        }
    }

    _diffKV(entriesA, entriesB) {
        const allKeys = new Set([...Object.keys(entriesA), ...Object.keys(entriesB)]);
        const changes = [];
        for (const key of Array.from(allKeys).sort()) {
            const a = entriesA[key];
            const b = entriesB[key];
            const aStr = JSON.stringify(a);
            const bStr = JSON.stringify(b);
            if (aStr !== bStr) {
                changes.push({
                    key,
                    before: a !== undefined ? a : null,
                    after: b !== undefined ? b : null
                });
            }
        }
        return changes;
    }

    _diffAppend(logA, logB) {
        const changes = [];
        const maxLen = Math.max(logA.length, logB.length);
        for (let i = 0; i < maxLen; i++) {
            const a = i < logA.length ? logA[i] : null;
            const b = i < logB.length ? logB[i] : null;
            if (!a) {
                changes.push({ key: i, before: null, after: b.value });
            } else if (!b) {
                changes.push({ key: i, before: a.value, after: null });
            } else if (a.cid !== b.cid) {
                changes.push({ key: i, before: a.value, after: b.value });
            }
        }
        return changes;
    }

    // ── Subscribe (append-only trees) ──

    /**
     * Subscribe to new appends on a tree.
     * @param {number} treeId
     * @param {function} callback — called with { index, value, cid }
     * @returns {function} unsubscribe
     */
    subscribe(treeId, callback) {
        const tree = this._getTree(treeId);
        if (tree.mode !== 'append') throw new Error('subscribe() requires append-mode tree');
        tree._subscribers.push(callback);
        return function unsubscribe() {
            const idx = tree._subscribers.indexOf(callback);
            if (idx >= 0) tree._subscribers.splice(idx, 1);
        };
    }

    // ── Utility ──

    /**
     * Get the length of an append-only tree.
     * @param {number} treeId
     * @returns {number}
     */
    length(treeId) {
        const tree = this._getTree(treeId);
        if (tree.mode !== 'append') throw new Error('length() requires append-mode tree');
        return tree.log.length;
    }

    /**
     * Get the number of entries in a KV tree.
     * @param {number} treeId
     * @returns {number}
     */
    size(treeId) {
        const tree = this._getTree(treeId);
        if (tree.mode !== 'kv') throw new Error('size() requires kv-mode tree');
        return tree.entries.size;
    }
}

TreeStore.ChunkStore = ChunkStore;
TreeStore.cidFromState = cidFromState;
TreeStore.sha256 = sha256;

module.exports = TreeStore;
