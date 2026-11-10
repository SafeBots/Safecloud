"use strict";
/**
 * Feed — append-only event log built on TreeStore.
 *
 * A feed is a tree in append-only mode. Entries are ordered by their
 * monotonic index. Subscribers get notified of new appends in real time.
 *
 * Hypercore / Kafka analog: append-only signed feed.
 *
 * @module data/Feed
 */

class Feed {
    /**
     * @param {TreeStore} store
     * @param {string} name — feed name
     */
    constructor(store, name) {
        this._store = store;
        this._name = name;
        const { treeId } = store.createTree('feed:' + name, { mode: 'append' });
        this._treeId = treeId;
    }

    /**
     * Restore a feed from a checkpoint.
     * @param {TreeStore} store
     * @param {string} rootCid
     * @returns {Feed}
     */
    static fromCheckpoint(store, rootCid) {
        const { treeId } = store.hydrate(rootCid);
        const feed = Object.create(Feed.prototype);
        feed._store = store;
        feed._treeId = treeId;
        feed._name = 'hydrated';
        return feed;
    }

    /** Current length of the feed. */
    get length() {
        return this._store.length(this._treeId);
    }

    /**
     * Append a value.
     * @param {*} value
     * @returns {{ index: number, proof: object }}
     */
    append(value) {
        return this._store.append(this._treeId, value);
    }

    /**
     * Get entry by index.
     * @param {number} index
     * @returns {*} value, or null if out of range
     */
    get(index) {
        const result = this._store.get(this._treeId, index);
        return result ? result.value : null;
    }

    /**
     * Range query.
     * @param {object} opts — { gte, lt, limit, reverse }
     * @returns {Array<{ index: number, value: * }>}
     */
    range(opts) {
        const entries = this._store.range(this._treeId, opts);
        return entries.map(e => ({ index: e.key, value: e.value }));
    }

    /**
     * Subscribe to new appends.
     * @param {function} callback — called with { index, value, cid }
     * @returns {function} unsubscribe
     */
    subscribe(callback) {
        return this._store.subscribe(this._treeId, callback);
    }

    /**
     * Checkpoint feed to Drops.
     * @returns {string} rootCid
     */
    checkpoint() {
        return this._store.checkpoint(this._treeId);
    }

    /** Current root CID. */
    get rootCid() {
        return this._store.root(this._treeId);
    }
}

module.exports = Feed;
