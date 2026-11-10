"use strict";
/**
 * NameResolver — mutable name → CID resolution, built on TreeStore.
 *
 * A name is a mutable pointer: "this name currently resolves to this CID."
 * Each update bumps a sequence number. Latest sequence wins (rollback
 * prevention). The owner's identity (pubkey) is recorded so resolution
 * can verify the pointer is authentic.
 *
 * IPNS analog: signed mutable pointer to content-addressed data.
 *
 * @module data/NameResolver
 */

class NameResolver {
    /**
     * @param {TreeStore} store
     * @param {object} [opts]
     * @param {string} [opts.owner] — owner identifier (pubkey or name)
     */
    constructor(store, opts) {
        this._store = store;
        this._owner = (opts && opts.owner) || 'default';

        const { treeId } = store.createTree('names:' + this._owner, { mode: 'kv' });
        this._treeId = treeId;
    }

    /**
     * Restore from a checkpoint.
     * @param {TreeStore} store
     * @param {string} rootCid
     * @returns {NameResolver}
     */
    static fromCheckpoint(store, rootCid) {
        const { treeId } = store.hydrate(rootCid);
        const resolver = Object.create(NameResolver.prototype);
        resolver._store = store;
        resolver._treeId = treeId;
        resolver._owner = 'hydrated';
        return resolver;
    }

    /**
     * Create or update a name → CID mapping.
     * @param {string} name
     * @param {string} targetCid
     * @returns {{ seq: number }}
     */
    update(name, targetCid) {
        const existing = this._store.get(this._treeId, name);
        const seq = existing ? existing.value.seq + 1 : 1;

        const record = {
            target: targetCid,
            seq: seq,
            owner: this._owner,
            updatedAt: Date.now()
        };

        this._store.put(this._treeId, name, record);
        return { seq };
    }

    /**
     * Resolve a name to its current target CID.
     * @param {string} name
     * @returns {{ target: string, seq: number, owner: string, updatedAt: number } | null}
     */
    resolve(name) {
        const result = this._store.get(this._treeId, name);
        return result ? result.value : null;
    }

    /**
     * Delete a name mapping.
     * @param {string} name
     * @returns {boolean}
     */
    remove(name) {
        return this._store.delete(this._treeId, name);
    }

    /**
     * List all name mappings.
     * @param {object} [opts] — { prefix, limit }
     * @returns {Array<{ name: string, target: string, seq: number }>}
     */
    list(opts) {
        const rangeOpts = {};
        if (opts && opts.prefix) {
            rangeOpts.gte = opts.prefix;
            const p = opts.prefix;
            rangeOpts.lt = p.slice(0, -1) + String.fromCharCode(p.charCodeAt(p.length - 1) + 1);
        }
        if (opts && opts.limit) rangeOpts.limit = opts.limit;

        return this._store.range(this._treeId, rangeOpts).map(e => ({
            name: e.key,
            target: e.value.target,
            seq: e.value.seq,
            owner: e.value.owner,
            updatedAt: e.value.updatedAt
        }));
    }

    /**
     * Checkpoint to Drops.
     * @returns {string} rootCid
     */
    checkpoint() {
        return this._store.checkpoint(this._treeId);
    }
}

module.exports = NameResolver;
