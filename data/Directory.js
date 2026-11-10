"use strict";
/**
 * Directory — static folder API built on TreeStore.
 *
 * A directory is a KV tree where keys are slash-delimited paths and values
 * are file manifests ({ cid, size, type }). The root CID of the tree is
 * the permanent address of the entire directory.
 *
 * IPFS/IPLD analog: content-addressed, immutable directory snapshot.
 *
 * @module data/Directory
 */

const TreeStore = require('./TreeStore');

class Directory {
    /**
     * @param {TreeStore} store
     */
    constructor(store) {
        this._store = store;
    }

    /**
     * Store a set of files as a directory tree.
     * @param {Object<string, { content: Buffer|string, type: string }>} files
     *   Map of path → { content, type }. Paths are slash-delimited, no leading slash.
     * @returns {{ rootCid: string, manifest: Object }}
     */
    store(files) {
        const { treeId } = this._store.createTree('dir_' + Date.now(), { mode: 'kv' });
        const manifest = {};

        for (const [path, file] of Object.entries(files)) {
            const content = typeof file.content === 'string'
                ? Buffer.from(file.content)
                : file.content;
            const cid = TreeStore.cidFromState({ content: content.toString('base64') });
            const entry = {
                cid: cid,
                size: content.length,
                type: file.type || 'application/octet-stream'
            };
            this._store.put(treeId, path, entry);
            manifest[path] = entry;

            // Store the actual content in the chunk store
            this._store._chunks.put(cid, content);
        }

        const rootCid = this._store.checkpoint(treeId);
        return { rootCid, manifest, treeId };
    }

    /**
     * Fetch a directory manifest from a root CID.
     * @param {string} rootCid
     * @returns {{ files: Object<string, { cid, size, type }>, treeId: number }}
     */
    fetch(rootCid) {
        const { treeId } = this._store.hydrate(rootCid);
        const entries = this._store.range(treeId, {});
        const files = {};
        for (const { key, value } of entries) {
            files[key] = value;
        }
        return { files, treeId };
    }

    /**
     * Get a single file's content from a directory.
     * @param {string} rootCid — directory root CID
     * @param {string} path — file path within directory
     * @returns {Buffer|null}
     */
    getFile(rootCid, path) {
        const { treeId } = this._store.hydrate(rootCid);
        const result = this._store.get(treeId, path);
        if (!result) return null;
        const content = this._store._chunks.get(result.value.cid);
        return content || null;
    }

    /**
     * List files in a directory, optionally filtered by prefix.
     * @param {string} rootCid
     * @param {string} [prefix='']
     * @returns {Array<{ path: string, cid: string, size: number, type: string }>}
     */
    list(rootCid, prefix) {
        const { treeId } = this._store.hydrate(rootCid);
        const opts = {};
        if (prefix) {
            opts.gte = prefix;
            // Next char after last char of prefix for upper bound
            opts.lt = prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
        }
        const entries = this._store.range(treeId, opts);
        return entries.map(e => ({
            path: e.key,
            cid: e.value.cid,
            size: e.value.size,
            type: e.value.type
        }));
    }

    /**
     * Diff two directory snapshots.
     * @param {string} cidA
     * @param {string} cidB
     * @returns {Array<{ path: string, type: string, before: object|null, after: object|null }>}
     *   type is 'added', 'removed', or 'modified'
     */
    diff(cidA, cidB) {
        const changes = this._store.diff(cidA, cidB);
        return changes.map(c => ({
            path: c.key,
            type: c.before === null ? 'added' : c.after === null ? 'removed' : 'modified',
            before: c.before,
            after: c.after
        }));
    }
}

module.exports = Directory;
