'use strict';

/**
 * Safecloud Storage — Rclone backend
 *
 * Delegates chunk storage to the `rclone` CLI binary, which supports 40+
 * cloud storage providers (Google Drive, Dropbox, OneDrive, SFTP, S3, B2,
 * Azure Blob, GCS, …).  No npm package is needed — just an `rclone` binary
 * configured with a named remote.
 *
 * Chunks are stored at:
 *   {remote}:{basePath}/{cid[0..1]}/{cid}.bin
 *
 * where `remote` is any rclone remote name (e.g. "myremote", "s3-backup").
 *
 * Required: rclone binary in PATH (or full path via config.rclonePath).
 *
 * Config keys (under Safecloud.storage.rclone):
 *   remote      string  Required. Rclone remote name (from rclone config).
 *   basePath    string  Optional. Remote path prefix (default: "safecloud").
 *   rclonePath  string  Optional. Full path to rclone binary (default: "rclone").
 *   timeout     number  Optional. Per-command timeout ms (default: 30000).
 */

var child_process = require('child_process');
var os   = require('os');
var path = require('path');
var fs   = require('fs');

var RcloneStorage = {

    _remote:     null,
    _basePath:   'safecloud',
    _rclone:     'rclone',
    _timeout:    30000,
    _ready:      false,
    _tmpDir:     null,

    /**
     * init(config)
     * @param {Object} config
     * @returns {Promise<void>}
     */
    init: function (config) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!config || !config.remote) {
                return reject(new Error(
                    'Safecloud.Storage.Rclone: remote name is required'
                ));
            }

            self._remote   = config.remote;
            self._basePath = config.basePath  || 'safecloud';
            self._rclone   = config.rclonePath || 'rclone';
            self._timeout  = config.timeout   || 30000;
            self._tmpDir   = config.tmpDir    || os.tmpdir();

            // Verify rclone is available.
            self._exec(['version'], function (err) {
                if (err) {
                    return reject(new Error(
                        'Safecloud.Storage.Rclone: rclone binary not found or ' +
                        'not executable ("' + self._rclone + '"): ' + err.message
                    ));
                }

                // Ensure the base path exists on the remote.
                self._exec(['mkdir', self._remotePath('')], function (mkErr) {
                    if (mkErr) {
                        return reject(new Error(
                            'Safecloud.Storage.Rclone: mkdir failed on remote: ' +
                            mkErr.message
                        ));
                    }
                    self._ready = true;
                    resolve();
                });
            });
        });
    },

    /**
     * put(cid, buf)
     * Writes buf to a temp file then copies it to the remote.
     * @param {string} cid
     * @param {Buffer} buf
     * @returns {Promise<void>}
     */
    put: function (cid, buf) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Rclone: not initialised'));
            }

            var tmpFile = path.join(self._tmpDir, 'sc-rclone-' + cid + '.bin');

            fs.writeFile(tmpFile, buf, function (err) {
                if (err) {
                    return reject(new Error(
                        'Safecloud.Storage.Rclone: tmp write failed: ' + err.message
                    ));
                }

                var remoteDest = self._remotePath(self._shardFor(cid));
                self._exec(['copyto', tmpFile, remoteDest + '/' + cid + '.bin'],
                    function (cpErr) {
                        fs.unlink(tmpFile, function () {});  // best-effort cleanup
                        if (cpErr) {
                            return reject(new Error(
                                'Safecloud.Storage.Rclone: put failed for ' + cid +
                                ': ' + cpErr.message
                            ));
                        }
                        resolve();
                    }
                );
            });
        });
    },

    /**
     * get(cid)
     * Copies the remote file to a temp file and reads it.
     * @param {string} cid
     * @returns {Promise<Buffer|null>}
     */
    get: function (cid) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Rclone: not initialised'));
            }

            var tmpFile  = path.join(self._tmpDir, 'sc-rclone-get-' + cid + '.bin');
            var remoteSrc = self._remotePath(self._shardFor(cid)) + '/' + cid + '.bin';

            self._exec(['copyto', remoteSrc, tmpFile], function (err) {
                if (err) {
                    // rclone exits 1 with "object not found" when file missing.
                    fs.unlink(tmpFile, function () {});
                    if (self._isNotFound(err)) { return resolve(null); }
                    return reject(new Error(
                        'Safecloud.Storage.Rclone: get failed for ' + cid +
                        ': ' + err.message
                    ));
                }

                fs.readFile(tmpFile, function (readErr, data) {
                    fs.unlink(tmpFile, function () {});
                    if (readErr) {
                        if (readErr.code === 'ENOENT') { return resolve(null); }
                        return reject(new Error(
                            'Safecloud.Storage.Rclone: read tmp failed: ' +
                            readErr.message
                        ));
                    }
                    resolve(data);
                });
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
                return reject(new Error('Safecloud.Storage.Rclone: not initialised'));
            }
            var remotePath = self._remotePath(self._shardFor(cid)) + '/' + cid + '.bin';
            self._exec(['lsf', remotePath], function (err, stdout) {
                if (err || !stdout || !stdout.trim()) { return resolve(false); }
                resolve(stdout.trim().length > 0);
            });
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
                return reject(new Error('Safecloud.Storage.Rclone: not initialised'));
            }
            var remotePath = self._remotePath(self._shardFor(cid)) + '/' + cid + '.bin';
            self._exec(['deletefile', remotePath], function (err) {
                if (err && !self._isNotFound(err)) {
                    return reject(new Error(
                        'Safecloud.Storage.Rclone: delete failed for ' + cid +
                        ': ' + err.message
                    ));
                }
                resolve();
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
                return reject(new Error('Safecloud.Storage.Rclone: not initialised'));
            }

            // Scope to one shard when prefix is specific enough.
            var scanPath = prefix.length >= 2
                ? self._remotePath(prefix.slice(0, 2))
                : self._remotePath('');

            self._exec(['lsf', '--recursive', '--files-only', scanPath],
                function (err, stdout) {
                    if (err) {
                        if (self._isNotFound(err)) { return resolve([]); }
                        return reject(new Error(
                            'Safecloud.Storage.Rclone: list failed: ' + err.message
                        ));
                    }

                    var lines   = (stdout || '').split('\n');
                    var results = [];
                    lines.forEach(function (line) {
                        line = line.trim();
                        if (line.endsWith('.bin')) {
                            // lsf --recursive returns paths relative to the
                            // scan root; strip any leading shard dir component.
                            var base = path.basename(line, '.bin');
                            if (!prefix || base.startsWith(prefix)) {
                                results.push(base);
                            }
                        }
                    });
                    resolve(results);
                }
            );
        });
    },

    // ------------------------------------------------------------------ //
    //  Internal helpers
    // ------------------------------------------------------------------ //

    _shardFor: function (cid) {
        return (cid || '').slice(0, 2) || '__';
    },

    /** Full remote path: remote:basePath/subPath */
    _remotePath: function (subPath) {
        var base = this._remote + ':' + this._basePath;
        return subPath ? base + '/' + subPath : base;
    },

    _isNotFound: function (err) {
        if (!err) { return false; }
        var msg = (err.message || '').toLowerCase();
        return msg.indexOf('object not found') !== -1 ||
               msg.indexOf('not found') !== -1 ||
               msg.indexOf('directory not found') !== -1 ||
               msg.indexOf('no such file') !== -1;
    },

    /**
     * _exec(args, cb) — runs rclone with the given args.
     * cb(err, stdout)
     */
    _exec: function (args, cb) {
        var self = this;
        var stdout = '';
        var stderr = '';

        try {
            var proc = child_process.spawn(self._rclone, args, {
                timeout: self._timeout,
                windowsHide: true
            });

            proc.stdout.on('data', function (d) { stdout += d.toString(); });
            proc.stderr.on('data', function (d) { stderr += d.toString(); });

            proc.on('close', function (code) {
                if (code !== 0) {
                    var msg = stderr.trim() || ('rclone exited with code ' + code);
                    return cb(new Error(msg));
                }
                cb(null, stdout);
            });

            proc.on('error', function (err) {
                cb(err);
            });
        } catch (e) {
            cb(e);
        }
    },

    _reset: function () {
        this._remote   = null;
        this._basePath = 'safecloud';
        this._rclone   = 'rclone';
        this._timeout  = 30000;
        this._ready    = false;
        this._tmpDir   = null;
    }
};

module.exports = RcloneStorage;
