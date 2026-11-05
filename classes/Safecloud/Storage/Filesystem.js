'use strict';

/**
 * Safecloud Storage — Filesystem backend
 *
 * Stores encrypted chunks as files under a local directory, sharded into
 * two-character subdirectories to avoid inode limits on large stores:
 *
 *   {storageDir}/{cid[0..1]}/{cid}.bin
 *
 * Zero external dependencies — only Node.js built-ins (fs, path, os).
 *
 * Config keys (under Safecloud.storage.filesystem):
 *   storageDir  string  Required. Absolute path to the root storage directory.
 */

var fs   = require('fs');
var path = require('path');

var FilesystemStorage = {

    _storageDir: null,
    _ready: false,

    /**
     * init(config)
     * @param {Object} config  The Safecloud.storage.filesystem sub-config.
     * @returns {Promise<void>}
     */
    init: function (config) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!config || !config.storageDir) {
                return reject(new Error(
                    'Safecloud.Storage.Filesystem: storageDir is required'
                ));
            }

            var dir = config.storageDir;

            fs.mkdir(dir, { recursive: true }, function (err) {
                if (err) {
                    return reject(new Error(
                        'Safecloud.Storage.Filesystem: cannot create storageDir "' +
                        dir + '": ' + err.message
                    ));
                }
                self._storageDir = dir;
                self._ready = true;
                resolve();
            });
        });
    },

    /**
     * put(cid, buf)
     * @param {string} cid
     * @param {Buffer} buf
     * @returns {Promise<void>}
     */
    put: function (cid, buf) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Filesystem: not initialised'));
            }
            var filePath = self._pathFor(cid);
            var dir      = path.dirname(filePath);

            fs.mkdir(dir, { recursive: true }, function (err) {
                if (err) {
                    return reject(new Error(
                        'Safecloud.Storage.Filesystem: mkdir failed: ' + err.message
                    ));
                }
                fs.writeFile(filePath, buf, function (err2) {
                    if (err2) {
                        return reject(new Error(
                            'Safecloud.Storage.Filesystem: write failed for ' + cid +
                            ': ' + err2.message
                        ));
                    }
                    resolve();
                });
            });
        });
    },

    /**
     * get(cid)
     * @param {string} cid
     * @returns {Promise<Buffer|null>}
     */
    get: function (cid) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Filesystem: not initialised'));
            }
            var filePath = self._pathFor(cid);
            fs.readFile(filePath, function (err, data) {
                if (err) {
                    if (err.code === 'ENOENT') { return resolve(null); }
                    return reject(new Error(
                        'Safecloud.Storage.Filesystem: read failed for ' + cid +
                        ': ' + err.message
                    ));
                }
                resolve(data);
            });
        });
    },

    /**
     * has(cid)
     * @param {string} cid
     * @returns {Promise<boolean>}
     */
    has: function (cid) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Filesystem: not initialised'));
            }
            fs.access(self._pathFor(cid), fs.constants.F_OK, function (err) {
                resolve(!err);
            });
        });
    },

    /**
     * delete(cid) — idempotent; resolves even if the file does not exist.
     * @param {string} cid
     * @returns {Promise<void>}
     */
    delete: function (cid) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Filesystem: not initialised'));
            }
            fs.unlink(self._pathFor(cid), function (err) {
                if (err && err.code !== 'ENOENT') {
                    return reject(new Error(
                        'Safecloud.Storage.Filesystem: delete failed for ' + cid +
                        ': ' + err.message
                    ));
                }
                resolve();
            });
        });
    },

    /**
     * list(prefix)
     * Returns all stored CIDs whose names begin with prefix (may be empty).
     * @param {string} prefix
     * @returns {Promise<string[]>}
     */
    list: function (prefix) {
        var self = this;
        prefix = prefix || '';
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Filesystem: not initialised'));
            }

            // Determine which shard subdirectories to scan.
            // If prefix is at least 2 chars the first two narrow to one shard.
            var shardFilter = prefix.length >= 2 ? prefix.slice(0, 2) : null;

            fs.readdir(self._storageDir, function (err, entries) {
                if (err) {
                    if (err.code === 'ENOENT') { return resolve([]); }
                    return reject(err);
                }

                // Filter shard dirs (2-char dirs)
                var shards = entries.filter(function (e) {
                    return e.length === 2 && (!shardFilter || e === shardFilter);
                });

                var results = [];
                var pending = shards.length;

                if (!pending) { return resolve(results); }

                shards.forEach(function (shard) {
                    var shardPath = path.join(self._storageDir, shard);
                    fs.readdir(shardPath, function (err2, files) {
                        if (err2) {
                            // Shard dir may have been removed; skip gracefully.
                            if (err2.code !== 'ENOENT') {
                                return reject(err2);
                            }
                        } else {
                            files.forEach(function (fname) {
                                if (fname.endsWith('.bin')) {
                                    var cid = fname.slice(0, -4); // strip .bin
                                    if (!prefix || cid.startsWith(prefix)) {
                                        results.push(cid);
                                    }
                                }
                            });
                        }
                        pending--;
                        if (pending === 0) { resolve(results); }
                    });
                });
            });
        });
    },

    // ------------------------------------------------------------------ //
    //  Internal helpers
    // ------------------------------------------------------------------ //

    /** Compute the full file path for a CID. */
    _pathFor: function (cid) {
        var s     = (cid || '').slice(0, 2);
        var shard = s.length === 2 ? s : '__';
        return path.join(this._storageDir, shard, cid + '.bin');
    },

    /** Reset state for test isolation. */
    _reset: function () {
        this._storageDir = null;
        this._ready = false;
    }
};

module.exports = FilesystemStorage;
