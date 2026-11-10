'use strict';

/**
 * Safecloud Storage — WebDAV backend
 *
 * Stores encrypted chunks on any WebDAV server (Nextcloud, ownCloud,
 * Box, Synology NAS, Apache mod_dav, …) using the `webdav` npm package.
 *
 * Chunks are stored at:
 *   {basePath}/{cid[0..1]}/{cid}.bin
 *
 * Required npm dependency:
 *   npm install webdav
 *
 * Config keys (under Safecloud.storage.webdav):
 *   url       string   Required. WebDAV server root URL.
 *   username  string   Required. Username or token.
 *   password  string   Required. Password or app-password.
 *   basePath  string   Optional. Remote path prefix (default: "/safecloud").
 */

var WebdavStorage = {

    _client: null,
    _basePath: '/safecloud',
    _ready: false,

    /**
     * init(config)
     * @param {Object} config
     * @returns {Promise<void>}
     */
    init: function (config) {
        var self = this;
        return new Promise(function (resolve, reject) {
            var webdav;
            try {
                webdav = require('webdav');
            } catch (e) {
                return reject(new Error(
                    'Safecloud.Storage.WebDAV: webdav is not installed. ' +
                    'Run: npm install webdav'
                ));
            }

            if (!config || !config.url) {
                return reject(new Error(
                    'Safecloud.Storage.WebDAV: url is required'
                ));
            }
            if (!config.username || !config.password) {
                return reject(new Error(
                    'Safecloud.Storage.WebDAV: username and password are required'
                ));
            }

            self._basePath = config.basePath || '/safecloud';

            var createClient = webdav.createClient;
            self._client = createClient(config.url, {
                username: config.username,
                password: config.password
            });

            // Ensure the base directory exists.
            self._client.createDirectory(self._basePath, { recursive: true })
                .then(function () {
                    self._ready = true;
                    resolve();
                })
                .catch(function (err) {
                    // 405 Method Not Allowed is returned by some servers when
                    // the directory already exists — treat it as success.
                    if (err && err.status === 405) {
                        self._ready = true;
                        return resolve();
                    }
                    reject(new Error(
                        'Safecloud.Storage.WebDAV: cannot create base directory "' +
                        self._basePath + '": ' + (err && err.message)
                    ));
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
                return reject(new Error('Safecloud.Storage.WebDAV: not initialised'));
            }
            var remotePath = self._remotePathFor(cid);
            var shardPath  = self._shardPathFor(cid);

            // Ensure shard directory exists first.
            self._client.createDirectory(shardPath, { recursive: true })
                .then(function () {
                    return self._client.putFileContents(remotePath, buf, {
                        overwrite: true,
                        contentLength: buf.length
                    });
                })
                .then(function () { resolve(); })
                .catch(function (err) {
                    // Ignore 405 on createDirectory (already exists).
                    if (err && err.status === 405) {
                        return self._client.putFileContents(remotePath, buf, {
                            overwrite: true,
                            contentLength: buf.length
                        }).then(resolve).catch(function (e) {
                            reject(new Error(
                                'Safecloud.Storage.WebDAV: put failed for ' + cid +
                                ': ' + (e && e.message)
                            ));
                        });
                    }
                    reject(new Error(
                        'Safecloud.Storage.WebDAV: put failed for ' + cid +
                        ': ' + (err && err.message)
                    ));
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
                return reject(new Error('Safecloud.Storage.WebDAV: not initialised'));
            }
            self._client.getFileContents(self._remotePathFor(cid))
                .then(function (data) {
                    resolve(Buffer.isBuffer(data) ? data : Buffer.from(data));
                })
                .catch(function (err) {
                    var status = err && (err.status || err.statusCode);
                    if (status === 404 || status === 405) { return resolve(null); }
                    // Some servers use a generic error for missing files.
                    var msg = (err && err.message) || '';
                    if (msg.indexOf('404') !== -1 || msg.indexOf('Not Found') !== -1) {
                        return resolve(null);
                    }
                    reject(new Error(
                        'Safecloud.Storage.WebDAV: get failed for ' + cid +
                        ': ' + msg
                    ));
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
                return reject(new Error('Safecloud.Storage.WebDAV: not initialised'));
            }
            self._client.exists(self._remotePathFor(cid))
                .then(function (result) { resolve(!!result); })
                .catch(function () { resolve(false); });
        });
    },

    /**
     * delete(cid) — idempotent.
     * @param {string} cid
     * @returns {Promise<void>}
     */
    delete: function (cid) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.WebDAV: not initialised'));
            }
            self._client.deleteFile(self._remotePathFor(cid))
                .then(function () { resolve(); })
                .catch(function (err) {
                    var status = err && (err.status || err.statusCode);
                    if (status === 404 || status === 405) { return resolve(); }
                    var msg = (err && err.message) || '';
                    if (msg.indexOf('404') !== -1 || msg.indexOf('Not Found') !== -1) {
                        return resolve();
                    }
                    reject(new Error(
                        'Safecloud.Storage.WebDAV: delete failed for ' + cid +
                        ': ' + msg
                    ));
                });
        });
    },

    /**
     * list(prefix)
     * @param {string} prefix
     * @returns {Promise<string[]>}
     */
    list: function (prefix) {
        var self = this;
        prefix = prefix || '';
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.WebDAV: not initialised'));
            }

            // Scope to one shard dir when prefix is long enough.
            var shardFilter = prefix.length >= 2 ? prefix.slice(0, 2) : null;

            var listDir = function (dirPath) {
                return self._client.getDirectoryContents(dirPath)
                    .then(function (items) {
                        var results = [];
                        items.forEach(function (item) {
                            if (item.type === 'file' &&
                                    item.basename.endsWith('.bin')) {
                                var cid = item.basename.slice(0, -4);
                                if (!prefix || cid.startsWith(prefix)) {
                                    results.push(cid);
                                }
                            }
                        });
                        return results;
                    })
                    .catch(function (err) {
                        var status = err && (err.status || err.statusCode);
                        if (status === 404 || status === 405) { return []; }
                        throw err;
                    });
            };

            if (shardFilter) {
                // Scan only the matching shard directory.
                return listDir(self._basePath + '/' + shardFilter)
                    .then(resolve)
                    .catch(function (err) {
                        reject(new Error(
                            'Safecloud.Storage.WebDAV: list failed: ' +
                            (err && err.message)
                        ));
                    });
            }

            // Scan the base directory to find all shard directories.
            self._client.getDirectoryContents(self._basePath)
                .then(function (items) {
                    var shardDirs = items.filter(function (i) {
                        return i.type === 'directory' && i.basename.length === 2;
                    });
                    return Promise.all(shardDirs.map(function (d) {
                        return listDir(d.filename);
                    }));
                })
                .then(function (arrays) {
                    var all = [];
                    arrays.forEach(function (a) { a.forEach(function (v) { all.push(v); }); });
                    resolve(all);
                })
                .catch(function (err) {
                    reject(new Error(
                        'Safecloud.Storage.WebDAV: list failed: ' +
                        (err && err.message)
                    ));
                });
        });
    },

    // ------------------------------------------------------------------ //
    //  Internal helpers
    // ------------------------------------------------------------------ //

    _shardPathFor: function (cid) {
        var shard = (cid || '').slice(0, 2) || '__';
        return this._basePath + '/' + shard;
    },

    _remotePathFor: function (cid) {
        return this._shardPathFor(cid) + '/' + cid + '.bin';
    },

    _reset: function () {
        this._client   = null;
        this._basePath = '/safecloud';
        this._ready    = false;
    }
};

module.exports = WebdavStorage;
