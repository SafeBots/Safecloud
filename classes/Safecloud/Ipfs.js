'use strict';
/**
 * Safecloud 3.3 — IPFS pinning and content retrieval.
 *
 * Wire-compatible with:
 *   IPFS Pinning Services API v1.0.0
 *     https://ipfs.github.io/pinning-services-api-spec/
 *   Kubo HTTP RPC API
 *     https://docs.ipfs.tech/reference/kubo/rpc/
 *
 * Two modes — set via Safecloud.ipfs.mode (default: "external"):
 *
 *   "external"         Connect to a locally running Kubo (go-ipfs) node via its
 *                      HTTP API at Safecloud.ipfs.apiUrl (default 127.0.0.1:5001).
 *                      Enables the full Kubo API proxy and IPNS operations.
 *
 *   "pinning-service"  Delegate all pinning to a remote IPFS Pinning Services API
 *                      (Pinata, web3.storage, nft.storage, Filebase, Storj, …).
 *                      Content retrieval uses Safecloud.ipfs.gatewayUrl.
 *
 * All features default to off (Safecloud.ipfs.enabled: false).
 */

var http   = require('http');
var https  = require('https');
var urlMod = require('url');
var crypto = require('crypto');
var fs     = require('fs');
var path   = require('path');

// ── Module-level state (reset on init) ───────────────────────────────────────

var _Q            = null;
var _enabled      = false;
var _mode         = 'external';
var _apiUrl       = 'http://127.0.0.1:5001';
var _gatewayUrl   = 'http://127.0.0.1:8080';
var _psEndpoint   = null;   // remote Pinning Services API endpoint
var _psKey        = null;   // bearer token for remote Pinning Services API
var _exposedKey   = null;   // bearer token the Jet requires on its own PSA endpoint (null = open)
var _requireSbux  = false;
var _sbuxPerGB    = 0;
var _storePath    = null;
var _persistTimer = null;

// ── Local pin store ───────────────────────────────────────────────────────────
// Keyed by requestid. Mirrors the Pinning Services API PinStatus schema.
// { requestid, status, created, pin:{cid,name,origins[],meta{}}, delegates[] }
var _pins   = {};   // { [requestid]: PinStatus }
var _cidIdx = {};   // { [cid]: requestid }   — reverse index for dedup / lookup

// ── Disk persistence (debounced, best-effort) ─────────────────────────────────

function _schedPersist() {
    if (!_storePath) { return; }
    clearTimeout(_persistTimer);
    _persistTimer = setTimeout(function () {
        var tmp = _storePath + '.tmp';
        try {
            fs.writeFileSync(tmp, JSON.stringify({ pins: _pins }, null, 2), 'utf8');
            fs.renameSync(tmp, _storePath);
        } catch (e) {
            if (_Q) { _Q.log('Safecloud.Ipfs: pin store write failed: ' + e.message, 'Safecloud'); }
        }
    }, 800);
}

function _loadStore() {
    _pins   = {};
    _cidIdx = {};
    if (!_storePath) { return; }
    try {
        var raw  = fs.readFileSync(_storePath, 'utf8');
        var data = JSON.parse(raw);
        if (data && data.pins && typeof data.pins === 'object') {
            _pins = data.pins;
            Object.keys(_pins).forEach(function (rid) {
                var rec = _pins[rid];
                if (rec && rec.pin && typeof rec.pin.cid === 'string') {
                    _cidIdx[rec.pin.cid] = rid;
                }
            });
        }
    } catch (e) {
        _pins   = {};
        _cidIdx = {};
    }
}

// ── Low-level Kubo HTTP RPC client ────────────────────────────────────────────

/**
 * Make an HTTP request to the Kubo node.
 *
 * @param {string}  method       HTTP method ('POST', 'GET')
 * @param {string}  apiPath      e.g. '/api/v0/pin/add'
 * @param {Object}  queryParams  key→value pairs appended as query string
 * @param {Buffer}  [bodyBuf]    request body bytes
 * @param {string}  [contentType]
 * @returns {Promise<{status:number, body:Buffer, headers:Object}>}
 */
function _kuboRaw(method, apiPath, queryParams, bodyBuf, contentType) {
    return new Promise(function (resolve, reject) {
        var base     = urlMod.parse(_apiUrl);
        var qs       = queryParams
            ? ('?' + Object.keys(queryParams).map(function (k) {
                return encodeURIComponent(k) + '=' + encodeURIComponent(queryParams[k]);
              }).join('&'))
            : '';
        var reqPath  = (base.pathname || '').replace(/\/$/, '') + apiPath + qs;
        var useHttps = base.protocol === 'https:';
        var lib      = useHttps ? https : http;

        var reqOpts = {
            hostname: base.hostname,
            port:     parseInt(base.port, 10) || (useHttps ? 443 : 5001),
            path:     reqPath,
            method:   method,
            headers:  {}
        };
        if (bodyBuf) {
            reqOpts.headers['Content-Type']   = contentType || 'application/octet-stream';
            reqOpts.headers['Content-Length'] = bodyBuf.length;
        }

        var req = lib.request(reqOpts, function (res) {
            var chunks = [];
            res.on('data', function (c) { chunks.push(c); });
            res.on('end',  function () {
                resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers });
            });
        });
        req.setTimeout(30000, function () { req.destroy(new Error('Kubo request timeout')); });
        req.on('error', reject);
        if (bodyBuf) { req.write(bodyBuf); }
        req.end();
    });
}

/**
 * POST to Kubo, expect JSON response. Rejects on non-200 or parse failure.
 *
 * @param {string} apiPath
 * @param {Object} [params]   appended as query string
 * @returns {Promise<Object>}
 */
function _kuboPost(apiPath, params) {
    return _kuboRaw('POST', apiPath, params || {}).then(function (r) {
        var text = r.body.toString('utf8');
        if (r.status !== 200) {
            return Promise.reject(new Error(
                'Kubo ' + apiPath + ' HTTP ' + r.status + ': ' + text.slice(0, 200)));
        }
        try { return JSON.parse(text); }
        catch (e) {
            // Kubo sometimes returns newline-delimited JSON (e.g. streaming add);
            // take the last complete line as the final result.
            var lines = text.split('\n').filter(Boolean);
            for (var i = lines.length - 1; i >= 0; i--) {
                try { return JSON.parse(lines[i]); } catch (_) {}
            }
            return { _raw: text };
        }
    });
}

/**
 * POST /api/v0/add with multipart/form-data body.
 * Returns {cid:string, size:string}.
 */
function _kuboAdd(buffer, filename) {
    var boundary = '----SafecloudIpfsBoundary' + crypto.randomBytes(8).toString('hex');
    var fn       = (filename || 'upload').replace(/"/g, '');
    var head     = '--' + boundary + '\r\n'
                 + 'Content-Disposition: form-data; name="file"; filename="' + fn + '"\r\n'
                 + 'Content-Type: application/octet-stream\r\n\r\n';
    var tail     = '\r\n--' + boundary + '--\r\n';
    var body     = Buffer.concat([Buffer.from(head, 'utf8'), buffer, Buffer.from(tail, 'utf8')]);

    return _kuboRaw('POST', '/api/v0/add', { pin: 'true' }, body,
        'multipart/form-data; boundary=' + boundary)
    .then(function (r) {
        var text = r.body.toString('utf8');
        if (r.status !== 200) {
            return Promise.reject(new Error('Kubo add HTTP ' + r.status + ': ' + text.slice(0, 200)));
        }
        // Newline-delimited JSON — last Hash line is the root
        var last = null;
        text.split('\n').filter(Boolean).forEach(function (ln) {
            try { var obj = JSON.parse(ln); if (obj.Hash) { last = obj; } } catch (_) {}
        });
        if (!last || !last.Hash) {
            return Promise.reject(new Error('Kubo add: missing Hash in response'));
        }
        return { cid: last.Hash, size: last.Size || '0' };
    });
}

// ── Low-level Pinning Services API client (remote service) ───────────────────

/**
 * Call a remote IPFS Pinning Services API.
 *
 * @param {string}  method   'GET' | 'POST' | 'DELETE'
 * @param {string}  apiPath  e.g. '/pins'
 * @param {Object}  [body]   JSON body (for POST)
 * @returns {Promise<{status:number, body:Object|null, raw:string}>}
 */
function _psRequest(method, apiPath, body) {
    return new Promise(function (resolve, reject) {
        var base    = urlMod.parse(_psEndpoint);
        var reqPath = (base.pathname || '').replace(/\/$/, '') + apiPath;
        var useHttps = base.protocol === 'https:';
        var lib     = useHttps ? https : http;
        var bodyBuf = body ? Buffer.from(JSON.stringify(body), 'utf8') : null;

        var reqOpts = {
            hostname: base.hostname,
            port:     parseInt(base.port, 10) || (useHttps ? 443 : 80),
            path:     reqPath,
            method:   method,
            headers: {
                'Authorization': 'Bearer ' + (_psKey || ''),
                'Content-Type':  'application/json'
            }
        };
        if (bodyBuf) { reqOpts.headers['Content-Length'] = bodyBuf.length; }

        var req = lib.request(reqOpts, function (res) {
            var chunks = [];
            res.on('data', function (c) { chunks.push(c); });
            res.on('end',  function () {
                var raw  = Buffer.concat(chunks).toString('utf8');
                var json = null;
                try { json = JSON.parse(raw); } catch (_) {}
                resolve({ status: res.statusCode, body: json, raw: raw });
            });
        });
        req.setTimeout(30000, function () { req.destroy(new Error('PS API request timeout')); });
        req.on('error', reject);
        if (bodyBuf) { req.write(bodyBuf); }
        req.end();
    });
}

// ── Pin record helpers (Pinning Services API schema) ─────────────────────────

function _newPinRecord(cid, opts) {
    opts = opts || {};
    return {
        requestid: crypto.randomBytes(16).toString('hex'),
        status:    'queued',
        created:   new Date().toISOString(),
        pin: {
            cid:     cid,
            name:    opts.name    || null,
            origins: opts.origins || [],
            meta:    opts.meta    || {}
        },
        delegates: []
    };
}

function _storePinRecord(rec) {
    _pins[rec.requestid]  = rec;
    _cidIdx[rec.pin.cid]  = rec.requestid;
    _schedPersist();
    return rec;
}

function _deletePinRecord(requestid) {
    var rec = _pins[requestid];
    if (rec && rec.pin && rec.pin.cid) { delete _cidIdx[rec.pin.cid]; }
    delete _pins[requestid];
    _schedPersist();
}

// ── Public API ────────────────────────────────────────────────────────────────

var SafecloudIpfs = module.exports = {};

/**
 * Initialise the module from Q config.  Called from Jets.js once inside
 * listen() after the Q stub is ready.
 *
 * @param {Object} opts   { Q }
 */
SafecloudIpfs.init = function (opts) {
    _Q           = opts.Q;
    _enabled     = _Q.Config.get(['Safecloud', 'ipfs', 'enabled'],  false);
    _mode        = _Q.Config.get(['Safecloud', 'ipfs', 'mode'],     'external');
    _apiUrl      = _Q.Config.get(['Safecloud', 'ipfs', 'apiUrl'],   'http://127.0.0.1:5001');
    _gatewayUrl  = _Q.Config.get(['Safecloud', 'ipfs', 'gatewayUrl'], 'http://127.0.0.1:8080');
    _psEndpoint  = _Q.Config.get(['Safecloud', 'ipfs', 'pinningService', 'endpoint'], null);
    _psKey       = _Q.Config.get(['Safecloud', 'ipfs', 'pinningService', 'key'],      null);
    _exposedKey  = _Q.Config.get(['Safecloud', 'ipfs', 'pinningService', 'exposedKey'], null);
    _requireSbux = _Q.Config.get(['Safecloud', 'ipfs', 'requireSafebux'], false);
    _sbuxPerGB   = _Q.Config.get(['Safecloud', 'ipfs', 'sbuxPerGB'],      0);

    var baseDir  = (_Q.app && _Q.app.DIR) || require('os').homedir();
    _storePath   = path.join(baseDir, 'safecloud-ipfs-pins.json');
    _loadStore();

    if (_enabled) {
        _Q.log('Safecloud.Ipfs: enabled, mode=' + _mode
            + (_mode === 'external' ? ', apiUrl=' + _apiUrl : ', endpoint=' + _psEndpoint),
            'Safecloud');
    }
};

/** @returns {boolean} */
SafecloudIpfs.isEnabled = function () { return _enabled; };

/** @returns {string} 'external' | 'pinning-service' */
SafecloudIpfs.getMode = function () { return _mode; };

/** @returns {string} configured Kubo HTTP API base URL */
SafecloudIpfs.getApiUrl = function () { return _apiUrl; };

/** @returns {string|null} configured IPFS gateway URL */
SafecloudIpfs.getGatewayUrl = function () { return _gatewayUrl; };

/** @returns {string|null} required bearer token for the Jet's own PSA endpoint */
SafecloudIpfs.getExposedKey = function () { return _exposedKey; };

/**
 * Internal Kubo POST helper — exported for Ipns.js.
 * Throws if IPFS is not in external mode.
 */
SafecloudIpfs.kuboPost = function (apiPath, params) {
    if (!_enabled) { return Promise.reject(new Error('IPFS not enabled')); }
    if (_mode !== 'external') {
        return Promise.reject(new Error('kuboPost requires mode: "external"'));
    }
    return _kuboPost(apiPath, params);
};

/**
 * Raw Kubo request — exported for streaming proxy in Jets.js.
 */
SafecloudIpfs.kuboRaw = function (method, apiPath, queryParams, bodyBuf, contentType) {
    return _kuboRaw(method, apiPath, queryParams, bodyBuf, contentType);
};

// ── Content operations ────────────────────────────────────────────────────────

/**
 * Add bytes to IPFS via Kubo's /api/v0/add.
 * Only available in mode: "external".
 *
 * @param {Buffer} buffer
 * @param {Object} [opts]   { filename }
 * @returns {Promise<{cid:string, size:string}>}
 */
SafecloudIpfs.add = function (buffer, opts) {
    if (!_enabled) { return Promise.reject(new Error('IPFS not enabled')); }
    if (_mode !== 'external') {
        return Promise.reject(new Error('add() requires mode: "external"'));
    }
    return _kuboAdd(buffer, opts && opts.filename);
};

/**
 * Retrieve content by CID.
 * "external" mode uses Kubo /api/v0/cat; "pinning-service" mode uses the
 * configured gateway URL.
 *
 * @param {string} cid
 * @returns {Promise<Buffer>}
 */
SafecloudIpfs.cat = function (cid) {
    if (!_enabled) { return Promise.reject(new Error('IPFS not enabled')); }
    if (_mode === 'external') {
        return _kuboRaw('POST', '/api/v0/cat', { arg: cid }).then(function (r) {
            if (r.status !== 200) {
                return Promise.reject(new Error('Kubo cat HTTP ' + r.status));
            }
            return r.body;
        });
    }
    // Gateway fetch (works for any mode if gatewayUrl is configured)
    if (_gatewayUrl) {
        var gwUrl = _gatewayUrl.replace(/\/$/, '') + '/ipfs/' + cid;
        var parsed = urlMod.parse(gwUrl);
        return new Promise(function (resolve, reject) {
            var lib = parsed.protocol === 'https:' ? https : http;
            var req = lib.request({
                hostname: parsed.hostname,
                port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                path:     parsed.path,
                method:   'GET'
            }, function (res) {
                if (res.statusCode !== 200) {
                    return reject(new Error('Gateway HTTP ' + res.statusCode + ' for ' + cid));
                }
                var chunks = [];
                res.on('data', function (c) { chunks.push(c); });
                res.on('end',  function () { resolve(Buffer.concat(chunks)); });
            });
            req.on('error', reject);
            req.end();
        });
    }
    return Promise.reject(new Error('cat() requires mode: "external" or a configured gatewayUrl'));
};

// ── Pinning operations ────────────────────────────────────────────────────────

/**
 * Pin a CID. Idempotent: returns existing pin record if the CID is already
 * tracked. Creates a local PinStatus record and then delegates to Kubo or
 * a remote Pinning Services API depending on mode.
 *
 * @param {string} cid
 * @param {Object} [opts]   { name, origins, meta }
 * @returns {Promise<PinStatus>}
 */
SafecloudIpfs.pin = function (cid, opts) {
    if (!_enabled) { return Promise.reject(new Error('IPFS not enabled')); }
    if (!cid || typeof cid !== 'string') {
        return Promise.reject(new Error('pin: cid must be a non-empty string'));
    }

    // Idempotent: return existing record
    var existingRid = _cidIdx[cid];
    if (existingRid && _pins[existingRid]) {
        return Promise.resolve(_pins[existingRid]);
    }

    var rec = _newPinRecord(cid, opts);
    _storePinRecord(rec);

    if (_mode === 'external') {
        rec.status = 'pinning';
        return _kuboPost('/api/v0/pin/add', { arg: cid, progress: 'false' })
            .then(function () {
                rec.status = 'pinned';
                _schedPersist();
                return rec;
            })
            .catch(function (err) {
                rec.status = 'failed';
                _schedPersist();
                return Promise.reject(err);
            });
    }

    if (_mode === 'pinning-service') {
        if (!_psEndpoint || !_psKey) {
            _deletePinRecord(rec.requestid);
            return Promise.reject(new Error(
                'pinning-service mode requires Safecloud.ipfs.pinningService.endpoint and .key'));
        }
        rec.status = 'pinning';
        var psBody = { cid: cid };
        if (opts && opts.name)    { psBody.name    = opts.name; }
        if (opts && opts.origins) { psBody.origins = opts.origins; }
        if (opts && opts.meta)    { psBody.meta    = opts.meta; }

        return _psRequest('POST', '/pins', psBody).then(function (r) {
            if (r.status !== 200 && r.status !== 202) {
                return Promise.reject(new Error(
                    'Pinning service POST /pins HTTP ' + r.status + ': ' + r.raw.slice(0, 200)));
            }
            if (r.body && r.body.requestid) {
                // Adopt remote requestid so future status queries use the same ID
                delete _pins[rec.requestid];
                delete _cidIdx[cid];
                rec.requestid = r.body.requestid;
                rec.status    = r.body.status || 'pinning';
                if (r.body.delegates) { rec.delegates = r.body.delegates; }
                _storePinRecord(rec);
            } else {
                rec.status = 'pinned';
                _schedPersist();
            }
            return rec;
        }).catch(function (err) {
            rec.status = 'failed';
            _schedPersist();
            return Promise.reject(err);
        });
    }

    _deletePinRecord(rec.requestid);
    return Promise.reject(new Error('Unknown IPFS mode: ' + _mode));
};

/**
 * Remove a pin by requestid.
 *
 * @param {string} requestid
 * @returns {Promise<void>}
 */
SafecloudIpfs.unpin = function (requestid) {
    if (!_enabled) { return Promise.reject(new Error('IPFS not enabled')); }
    var rec = _pins[requestid];
    if (!rec) {
        return Promise.reject(new Error('Pin not found: ' + requestid));
    }
    var cid = rec.pin.cid;

    if (_mode === 'external') {
        return _kuboPost('/api/v0/pin/rm', { arg: cid })
            .then(function () {
                _deletePinRecord(requestid);
            })
            .catch(function (err) {
                // Kubo reports "not pinned" if it was never pinned there — still clean up locally
                var msg = err && err.message ? err.message : '';
                if (msg.indexOf('not pinned') !== -1 || msg.indexOf('is not pinned') !== -1) {
                    _deletePinRecord(requestid);
                    return;
                }
                return Promise.reject(err);
            });
    }

    if (_mode === 'pinning-service') {
        return _psRequest('DELETE', '/pins/' + requestid, null).then(function (r) {
            // 202 = accepted, 404 = already gone — both are fine
            if (r.status !== 202 && r.status !== 204 && r.status !== 404) {
                return Promise.reject(new Error(
                    'Pinning service DELETE /pins/' + requestid
                    + ' HTTP ' + r.status + ': ' + r.raw.slice(0, 200)));
            }
            _deletePinRecord(requestid);
        });
    }

    return Promise.reject(new Error('Unknown IPFS mode: ' + _mode));
};

/**
 * List pins with optional filters.  Wire-compatible with Pinning Services API.
 *
 * @param {Object} [filters]
 *   { cid: string|string[], status: string|string[], name: string, limit: number }
 * @returns {Promise<{count:number, results:PinStatus[]}>}
 */
SafecloudIpfs.listPins = function (filters) {
    if (!_enabled) { return Promise.reject(new Error('IPFS not enabled')); }
    filters = filters || {};

    var results = Object.keys(_pins).map(function (rid) { return _pins[rid]; });

    // status filter
    if (filters.status) {
        var statuses = Array.isArray(filters.status)
            ? filters.status
            : String(filters.status).split(',').map(function (s) { return s.trim(); });
        results = results.filter(function (r) { return statuses.indexOf(r.status) !== -1; });
    }

    // cid filter
    if (filters.cid) {
        var cids = Array.isArray(filters.cid)
            ? filters.cid
            : String(filters.cid).split(',').map(function (c) { return c.trim(); });
        results = results.filter(function (r) { return cids.indexOf(r.pin.cid) !== -1; });
    }

    // name filter (exact match)
    if (filters.name) {
        results = results.filter(function (r) { return r.pin.name === filters.name; });
    }

    // sort by created desc (newest first — PSA convention)
    results = results.slice().sort(function (a, b) {
        return (b.created || '').localeCompare(a.created || '');
    });

    // limit (1–1000, default 10 per PSA spec)
    var limit = parseInt(filters.limit, 10) || 10;
    if (limit < 1)    { limit = 1; }
    if (limit > 1000) { limit = 1000; }
    results = results.slice(0, limit);

    return Promise.resolve({ count: results.length, results: results });
};

/**
 * Get a single pin record by requestid. Returns null if not found.
 *
 * @param {string} requestid
 * @returns {PinStatus|null}
 */
SafecloudIpfs.getPinByRequestid = function (requestid) {
    return _pins[requestid] || null;
};

/**
 * Get a single pin record by CID. Returns null if not found.
 *
 * @param {string} cid
 * @returns {PinStatus|null}
 */
SafecloudIpfs.getPinByCid = function (cid) {
    var rid = _cidIdx[cid];
    return (rid && _pins[rid]) ? _pins[rid] : null;
};

// ── Status / health ───────────────────────────────────────────────────────────

/**
 * Return IPFS node status.
 * For mode:"external" this calls /api/v0/id; for "pinning-service" it
 * probes the remote PSA endpoint.
 *
 * @returns {Promise<Object>}
 */
SafecloudIpfs.status = function () {
    if (!_enabled) {
        return Promise.resolve({ enabled: false });
    }

    var pinCount = Object.keys(_pins).length;

    if (_mode === 'external') {
        return _kuboPost('/api/v0/id', {}).then(function (data) {
            return {
                enabled:      true,
                mode:         'external',
                apiUrl:       _apiUrl,
                reachable:    true,
                peerId:       data.ID          || null,
                agentVersion: data.AgentVersion || null,
                addresses:    data.Addresses   || [],
                pinCount:     pinCount
            };
        }).catch(function () {
            return {
                enabled:   true,
                mode:      'external',
                apiUrl:    _apiUrl,
                reachable: false,
                pinCount:  pinCount
            };
        });
    }

    if (_mode === 'pinning-service') {
        return _psRequest('GET', '/pins?limit=1', null).then(function (r) {
            return {
                enabled:   true,
                mode:      'pinning-service',
                endpoint:  _psEndpoint,
                reachable: r.status === 200,
                pinCount:  pinCount
            };
        }).catch(function () {
            return {
                enabled:   true,
                mode:      'pinning-service',
                endpoint:  _psEndpoint,
                reachable: false,
                pinCount:  pinCount
            };
        });
    }

    return Promise.resolve({ enabled: true, mode: _mode, reachable: false, pinCount: pinCount });
};

// ── Internals exposed for testing ─────────────────────────────────────────────

/** @private — for tests only */
SafecloudIpfs._getPins   = function () { return _pins;   };
SafecloudIpfs._getCidIdx = function () { return _cidIdx; };

/**
 * Reset in-memory pin store (for test isolation).
 * @private
 */
SafecloudIpfs._resetStore = function () {
    _pins   = {};
    _cidIdx = {};
};
