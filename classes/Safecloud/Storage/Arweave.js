'use strict';

/**
 * Safecloud Storage — Arweave backend
 *
 * Stores encrypted chunks on the Arweave permaweb.  Each chunk is submitted
 * as an Arweave data transaction tagged with:
 *
 *   { name: "safecloud-cid", value: "<cid>" }
 *   { name: "Content-Type",  value: "application/octet-stream" }
 *   { name: "App-Name",      value: "Safecloud" }
 *
 * Retrieval uses the Arweave GraphQL API to look up the transaction ID for a
 * given CID, then fetches the transaction data.
 *
 * NOTE: Arweave storage is pay-once and permanent — `delete()` is a no-op.
 * Caller wallets must hold enough AR tokens to cover transaction fees.
 *
 * Required npm dependency:
 *   npm install arweave
 *
 * Config keys (under Safecloud.storage.arweave):
 *   keyfile   string   Required. Path to the Arweave JWK wallet JSON file.
 *   host      string   Optional. Gateway host (default: "arweave.net").
 *   port      number   Optional. Gateway port (default: 443).
 *   protocol  string   Optional. "https" or "http" (default: "https").
 *   timeout   number   Optional. Request timeout ms (default: 20000).
 */

var fs = require('fs');

var ArweaveStorage = {

    _arweave: null,
    _wallet:  null,
    _ready:   false,
    _host:    'arweave.net',
    _port:    443,
    _protocol: 'https',

    /**
     * init(config)
     * @param {Object} config
     * @returns {Promise<void>}
     */
    init: function (config) {
        var self = this;
        return new Promise(function (resolve, reject) {
            var Arweave;
            try {
                Arweave = require('arweave');
            } catch (e) {
                return reject(new Error(
                    'Safecloud.Storage.Arweave: arweave is not installed. ' +
                    'Run: npm install arweave'
                ));
            }

            if (!config || !config.keyfile) {
                return reject(new Error(
                    'Safecloud.Storage.Arweave: keyfile path is required'
                ));
            }

            var host     = config.host     || 'arweave.net';
            var port     = config.port     || 443;
            var protocol = config.protocol || 'https';
            var timeout  = config.timeout  || 20000;

            self._host     = host;
            self._port     = port;
            self._protocol = protocol;

            // Arweave exports the constructor in different ways depending on
            // module format.  Support both CJS default and named exports.
            var ArweaveInit = (Arweave && Arweave.default) ? Arweave.default : Arweave;

            self._arweave = ArweaveInit.init({
                host:     host,
                port:     port,
                protocol: protocol,
                timeout:  timeout,
                logging:  false
            });

            fs.readFile(config.keyfile, 'utf8', function (err, raw) {
                if (err) {
                    return reject(new Error(
                        'Safecloud.Storage.Arweave: cannot read keyfile "' +
                        config.keyfile + '": ' + err.message
                    ));
                }

                try {
                    self._wallet = JSON.parse(raw);
                } catch (parseErr) {
                    return reject(new Error(
                        'Safecloud.Storage.Arweave: keyfile is not valid JSON: ' +
                        parseErr.message
                    ));
                }

                self._ready = true;
                resolve();
            });
        });
    },

    /**
     * put(cid, buf)
     * Submits a new Arweave transaction carrying the chunk data.
     * @param {string} cid
     * @param {Buffer} buf
     * @returns {Promise<void>}
     */
    put: function (cid, buf) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Arweave: not initialised'));
            }

            self._arweave.createTransaction({ data: buf }, self._wallet)
                .then(function (tx) {
                    tx.addTag('Content-Type', 'application/octet-stream');
                    tx.addTag('App-Name',     'Safecloud');
                    tx.addTag('safecloud-cid', cid);
                    return self._arweave.transactions.sign(tx, self._wallet)
                        .then(function () { return self._arweave.transactions.post(tx); })
                        .then(function (response) {
                            var status = response && response.status;
                            if (status !== 200 && status !== 202) {
                                throw new Error(
                                    'Arweave post returned status ' + status
                                );
                            }
                            resolve();
                        });
                })
                .catch(function (err) {
                    reject(new Error(
                        'Safecloud.Storage.Arweave: put failed for ' + cid +
                        ': ' + (err && err.message)
                    ));
                });
        });
    },

    /**
     * get(cid)
     * Looks up the latest confirmed transaction by safecloud-cid tag and
     * returns the data, or null if not found.
     * @param {string} cid
     * @returns {Promise<Buffer|null>}
     */
    get: function (cid) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Arweave: not initialised'));
            }

            self._queryTxId(cid)
                .then(function (txId) {
                    if (!txId) { return resolve(null); }
                    return self._arweave.transactions.getData(txId, {
                        decode: true,
                        string: false
                    }).then(function (data) {
                        if (!data) { return resolve(null); }
                        resolve(Buffer.isBuffer(data) ? data : Buffer.from(data));
                    });
                })
                .catch(function (err) {
                    reject(new Error(
                        'Safecloud.Storage.Arweave: get failed for ' + cid +
                        ': ' + (err && err.message)
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
                return reject(new Error('Safecloud.Storage.Arweave: not initialised'));
            }
            self._queryTxId(cid)
                .then(function (txId) { resolve(!!txId); })
                .catch(function () { resolve(false); });
        });
    },

    /**
     * delete(cid) — no-op on Arweave (data is permanent).
     * @param {string} cid
     * @returns {Promise<void>}
     */
    delete: function (cid) { // eslint-disable-line no-unused-vars
        return Promise.resolve();
    },

    /**
     * list(prefix)
     * Queries GraphQL for all transactions with an App-Name=Safecloud tag
     * whose safecloud-cid starts with prefix.  Expensive on large stores —
     * prefer more specific prefix queries when possible.
     * @param {string} prefix
     * @returns {Promise<string[]>}
     */
    list: function (prefix) {
        var self = this;
        prefix = prefix || '';
        return new Promise(function (resolve, reject) {
            if (!self._ready) {
                return reject(new Error('Safecloud.Storage.Arweave: not initialised'));
            }

            // Arweave GraphQL does not support prefix queries, so we fetch
            // all CIDs owned by this wallet and filter client-side.
            self._arweave.wallets.jwkToAddress(self._wallet)
                .then(function (address) {
                    return self._graphqlQuery([
                        { name: 'App-Name', values: ['Safecloud'] }
                    ], address, []);
                })
                .then(function (txNodes) {
                    var cids = [];
                    txNodes.forEach(function (node) {
                        var tags = node.tags || [];
                        tags.forEach(function (t) {
                            if (t.name === 'safecloud-cid') {
                                var cid = t.value;
                                if (!prefix || cid.startsWith(prefix)) {
                                    cids.push(cid);
                                }
                            }
                        });
                    });
                    resolve(cids);
                })
                .catch(function (err) {
                    reject(new Error(
                        'Safecloud.Storage.Arweave: list failed: ' +
                        (err && err.message)
                    ));
                });
        });
    },

    // ------------------------------------------------------------------ //
    //  Internal helpers
    // ------------------------------------------------------------------ //

    /**
     * _queryTxId(cid) → string|null
     * Returns the most recent confirmed Arweave TX ID tagged with the given CID.
     */
    _queryTxId: function (cid) {
        var self = this;
        return self._arweave.wallets.jwkToAddress(self._wallet)
            .then(function (address) {
                return self._graphqlQuery([
                    { name: 'App-Name',      values: ['Safecloud'] },
                    { name: 'safecloud-cid', values: [cid] }
                ], address, []);
            })
            .then(function (nodes) {
                if (!nodes || !nodes.length) { return null; }
                return nodes[0].id || null;
            });
    },

    /**
     * _graphqlQuery(tags, owner, cursor) → nodes[]
     * Paginates through all results using the GraphQL cursor.
     */
    _graphqlQuery: function (tags, owner, accumulated, cursor) {
        var self    = this;
        var results = accumulated || [];

        var tagFilters = tags.map(function (t) {
            return '{ name: "' + t.name + '", values: ' +
                JSON.stringify(t.values) + ' }';
        }).join(', ');

        var afterClause = cursor ? ', after: "' + cursor + '"' : '';

        var query = '{ transactions(owners: ["' + owner + '"], ' +
            'tags: [' + tagFilters + ']' +
            afterClause +
            ', sort: HEIGHT_DESC, first: 100) { ' +
            'edges { cursor node { id tags { name value } } } } }';

        var url = self._protocol + '://' + self._host + ':' + self._port +
            '/graphql';

        var http = require(self._protocol === 'https' ? 'https' : 'http');

        return new Promise(function (resolve, reject) {
            var body = JSON.stringify({ query: query });
            var parsedUrl = require('url').parse(url);
            var options = {
                hostname: parsedUrl.hostname,
                port:     parsedUrl.port || (self._protocol === 'https' ? 443 : 80),
                path:     parsedUrl.path,
                method:   'POST',
                headers:  {
                    'Content-Type':   'application/json',
                    'Content-Length': Buffer.byteLength(body)
                }
            };

            var req = http.request(options, function (res) {
                var chunks = [];
                res.on('data', function (d) { chunks.push(d); });
                res.on('end', function () {
                    try {
                        var raw  = Buffer.concat(chunks).toString('utf8');
                        var data = JSON.parse(raw);
                        var edges = (data.data &&
                            data.data.transactions &&
                            data.data.transactions.edges) || [];

                        edges.forEach(function (e) {
                            results.push(e.node);
                        });

                        if (edges.length === 100) {
                            // There may be more — recurse with the last cursor.
                            var lastCursor = edges[edges.length - 1].cursor;
                            resolve(self._graphqlQuery(tags, owner, results, lastCursor));
                        } else {
                            resolve(results);
                        }
                    } catch (e) {
                        reject(e);
                    }
                });
            });

            req.on('error', reject);
            req.write(body);
            req.end();
        });
    },

    _reset: function () {
        this._arweave  = null;
        this._wallet   = null;
        this._ready    = false;
        this._host     = 'arweave.net';
        this._port     = 443;
        this._protocol = 'https';
    }
};

module.exports = ArweaveStorage;
