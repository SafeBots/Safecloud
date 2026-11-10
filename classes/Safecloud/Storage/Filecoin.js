'use strict';

/**
 * Safecloud Storage — Filecoin backend (via web3.storage / Storacha)
 *
 * Uploads encrypted chunks to web3.storage (or any compatible endpoint) over
 * a simple multipart HTTP upload.  A local JSON index maps each CID to the
 * upload response so chunks can be retrieved by IPFS gateway without
 * maintaining an IPFS node.
 *
 * Upload flow:
 *   1. POST multipart/form-data to <endpoint>/upload with the chunk as a
 *      single named file "{cid}.bin".
 *   2. Response: { cid: "<ipfs-cid>", ... } — stored in the local index.
 *
 * Retrieval flow:
 *   1. Look up the IPFS CID in the local index.
 *   2. Fetch from <gatewayUrl>/<ipfsCid>/{cid}.bin
 *
 * NOTE: Filecoin deals are long-term commitments — `delete()` removes the
 * local index entry but does NOT cancel existing storage deals.
 *
 * Required npm dependency: none (uses Node.js built-in http/https).
 *
 * Config keys (under Safecloud.storage.filecoin):
 *   endpoint    string  Required. Upload API base URL.
 *                       Default: "https://api.web3.storage"
 *   gatewayUrl  string  Optional. IPFS gateway for retrieval.
 *                       Default: "https://w3s.link/ipfs"
 *   key         string  Required. API bearer token.
 *   indexDir    string  Required. Local directory to store the CID index.
 */

var fs   = require('fs');
var path = require('path');
var http  = require('http');
var https = require('https');
var url   = require('url');

var FilecoinStorage = {

    _endpoint:   'https://api.web3.storage',
    _gatewayUrl: 'https://w3s.link/ipfs',
    _key:        null,
    _indexDir:   null,
    _indexPath:  null,
    _index:      null,   // { [safecloud-cid]: ipfsCid }
    _ready:      false,

    /**
     * init(config)
     * @param {Object} config
     * @returns {Promise<void>}
     */
    init: function (config) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!config || !config.key) {
                return reject(new Error(
                    'Safecloud.Storage.Filecoin: API key is required'
                ));
            }
            if (!config.indexDir) {
                return reject(new Error(
                    'Safecloud.Storage.Filecoin: indexDir is required'
                ));
            }

            self._endpoint   = config.endpoint   || 'https://api.web3.storage';
            self._gatewayUrl = config.gatewayUrl  || 'https://w3s.link/ipfs';
            self._key        = config.key;
            self._indexDir   = config.indexDir;
            self._indexPath  = path.join(config.indexDir, 'filecoin-index.json');

            fs.mkdir(config.indexDir, { recursive: true }, function (err) {
                if (err) {
                    return reject(new Error(
                        'Safecloud.Storage.Filecoin: cannot create indexDir: ' +
                        err.message
                    ));
                }

                // Load existing index or start fresh.
                fs.readFile(self._indexPath, 'utf8', function (err2, raw) {
                    if (err2 && err2.code !== 'ENOENT') {
                        return reject(new Error(
                            'Safecloud.Storage.Filecoin: cannot read index: ' +
                            err2.message
                        ));
                    }
                    try {
                        self._index = raw ? JSON.parse(raw) : {};
                    } catch (e) {
                        self._index = {};
                    }
                    self._ready = true;
                    resolve();
                });
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
                return reject(new Error('Safecloud.Storage.Filecoin: not initialised'));
            }

            var boundary = '----SafecloudBoundary' + Date.now().toString(16);
            var filename  = cid + '.bin';

            var preamble = Buffer.from(
                '--' + boundary + '\r\n' +
                'Content-Disposition: form-data; name="file"; filename="' +
                filename + '"\r\n' +
                'Content-Type: application/octet-stream\r\n\r\n'
            );
            var epilogue = Buffer.from('\r\n--' + boundary + '--\r\n');
            var body     = Buffer.concat([preamble, buf, epilogue]);

            var uploadUrl = self._endpoint.replace(/\/$/, '') + '/upload';
            var parsed    = url.parse(uploadUrl);
            var isHttps   = parsed.protocol === 'https:';
            var httpMod   = isHttps ? https : http;

            var options = {
                hostname: parsed.hostname,
                port:     parsed.port || (isHttps ? 443 : 80),
                path:     parsed.path,
                method:   'POST',
                headers: {
                    'Authorization':  'Bearer ' + self._key,
                    'Content-Type':   'multipart/form-data; boundary=' + boundary,
                    'Content-Length': body.length
                }
            };

            var req = httpMod.request(options, function (res) {
                var chunks = [];
                res.on('data', function (d) { chunks.push(d); });
                res.on('end', function () {
                    if (res.statusCode < 200 || res.statusCode >= 300) {
                        return reject(new Error(
                            'Safecloud.Storage.Filecoin: upload returned ' +
                            res.statusCode
                        ));
                    }
                    try {
                        var data      = JSON.parse(Buffer.concat(chunks).toString());
                        var ipfsCid   = data.cid || data['/'] || null;
                        if (!ipfsCid) { throw new Error('No CID in response'); }
                        self._index[cid] = ipfsCid;
                        self._saveIndex(function (err) {
                            if (err) { return reject(err); }
                            resolve();
                        });
                    } catch (e) {
                        reject(new Error(
                            'Safecloud.Storage.Filecoin: bad response: ' + e.message
                        ));
                    }
                });
            });

            req.on('error', function (e) {
                reject(new Error(
                    'Safecloud.Storage.Filecoin: put failed for ' + cid +
                    ': ' + e.message
                ));
            });

            req.write(body);
            req.end();
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
                return reject(new Error('Safecloud.Storage.Filecoin: not initialised'));
            }
            var ipfsCid = self._index[cid];
            if (!ipfsCid) { return resolve(null); }

            var fetchUrl = self._gatewayUrl.replace(/\/$/, '') + '/' +
                ipfsCid + '/' + cid + '.bin';
            var parsed   = url.parse(fetchUrl);
            var isHttps  = parsed.protocol === 'https:';
            var httpMod  = isHttps ? https : http;

            var req = httpMod.get({
                hostname: parsed.hostname,
                port:     parsed.port || (isHttps ? 443 : 80),
                path:     parsed.path,
                headers:  { 'Authorization': 'Bearer ' + self._key }
            }, function (res) {
                if (res.statusCode === 404) { return resolve(null); }
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return reject(new Error(
                        'Safecloud.Storage.Filecoin: gateway returned ' +
                        res.statusCode + ' for ' + cid
                    ));
                }
                var chunks = [];
                res.on('data', function (d) { chunks.push(d); });
                res.on('end', function () { resolve(Buffer.concat(chunks)); });
            });

            req.on('error', function (e) {
                reject(new Error(
                    'Safecloud.Storage.Filecoin: get failed for ' + cid +
                    ': ' + e.message
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
        if (!this._ready) { return Promise.resolve(false); }
        return Promise.resolve(Object.prototype.hasOwnProperty.call(this._index, cid));
    },

    /**
     * delete(cid)
     * Removes the local index entry.  Does NOT cancel any Filecoin deal.
     * @param {string} cid
     * @returns {Promise<void>}
     */
    delete: function (cid) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Filecoin: not initialised'));
            }
            delete self._index[cid];
            self._saveIndex(function (err) {
                if (err) { return reject(err); }
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
        if (!this._ready) { return Promise.resolve([]); }
        prefix = prefix || '';
        var results = Object.keys(this._index).filter(function (cid) {
            return !prefix || cid.startsWith(prefix);
        });
        return Promise.resolve(results);
    },

    // ------------------------------------------------------------------ //
    //  Internal helpers
    // ------------------------------------------------------------------ //

    _saveIndex: function (cb) {
        var self = this;
        var data = JSON.stringify(self._index, null, 2);
        fs.writeFile(self._indexPath, data, 'utf8', function (err) {
            if (err) {
                return cb(new Error(
                    'Safecloud.Storage.Filecoin: cannot save index: ' + err.message
                ));
            }
            cb(null);
        });
    },

    _reset: function () {
        this._endpoint   = 'https://api.web3.storage';
        this._gatewayUrl = 'https://w3s.link/ipfs';
        this._key        = null;
        this._indexDir   = null;
        this._indexPath  = null;
        this._index      = null;
        this._ready      = false;
    }
};

module.exports = FilecoinStorage;
