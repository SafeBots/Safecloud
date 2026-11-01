/**
 * Safecloud/Jets/WasmRunner.js
 *
 * WASM execution engine for SafecloudApps.
 *
 * Responsibilities:
 *   - Load SafecloudApp manifests by CID (from Drops via Safecloud_Client)
 *   - Instantiate WASM handler modules with the Safecloud host API
 *   - Execute handlers in a metered sandbox (fuel + memory limits)
 *   - Produce SafecloudEnvelopes with proof blocks
 *   - Generate SafecloudReceipts with full execution traces
 *   - Chain receipts into SafecloudChains (SafecloudDB tracks)
 *   - Route HTTP and socket requests to the appropriate handler by manifest
 *
 * The host API exposed to WASM (from Apps.md):
 *   safedb_get(track, key)           → Option<Vec<u8>>
 *   safedb_range(track, gte, lte)    → Iterator<(Vec<u8>, Vec<u8>)>
 *   safedb_put(track, key, value)
 *   safedb_delete(track, key)
 *   request_claim()                  → Option<OCPClaim>
 *   request_params()                 → Map<String, String>
 *   request_body()                   → Vec<u8>
 *   now()                            → u64
 *   random_seed()                    → [u8; 32]
 *   respond(envelope)
 *   call(handler_cid, input)         → SafecloudEnvelope
 *
 * No external deps beyond what Jets.js already pulls in.
 *
 * @module Safecloud
 * @class Safecloud.Jets.WasmRunner
 */
'use strict';

var crypto   = require('crypto');
var _fs      = require('fs');
var _bounded = require('./_bounded');

// ─────────────────────────────────────────────────────────────────────────────
// Module-level caches
// ─────────────────────────────────────────────────────────────────────────────

// Compiled WASM modules keyed by handlerCid. WebAssembly.compile() is
// expensive; cache the compiled Module so repeated invocations of the same
// handler pay only instantiation cost.
var _compiledModules = new _bounded.BoundedMap({ max: 1000, ttlMs: 3600000 }); // 1h

// Fetched app manifests keyed by appCid.
var _manifestCache = new _bounded.BoundedMap({ max: 5000, ttlMs: 600000 }); // 10m

// In-memory SafecloudDB track state keyed by "appCid/track/key".
// Production: backed by actual SafecloudDB prolly trees on Drops.
// This is a working prototype store so handlers can run end-to-end.
var _trackStore = new _bounded.BoundedMap({ max: 500000, ttlMs: 0 });

// Receipt chains keyed by appCid — most recent receiptCid.
var _chainHeads = {};

// ── Checkpoint persistence (Safecloud 3.2) ────────────────────────────────
// Latest checkpoint CID on Drops for each 'appCid/track', persisted to disk
// so Jets can restore _trackStore after restart.
var _checkpointCids   = {};
var _checkpointSeq    = {};  // 'appCid/track' → monotonically increasing seq
var _checkpointIndexPath = null;  // set by WasmRunner.init() or restoreCheckpoints()

// ─────────────────────────────────────────────────────────────────────────────
// Configuration defaults
// ─────────────────────────────────────────────────────────────────────────────

var DEFAULT_FUEL_LIMIT   = 10000000; // ~10M instructions
var DEFAULT_MEMORY_LIMIT = 16 * 1024 * 1024; // 16 MiB
var MAX_CALL_DEPTH       = 8;

// ─────────────────────────────────────────────────────────────────────────────
// WasmRunner public API
// ─────────────────────────────────────────────────────────────────────────────

var WasmRunner = module.exports = {};

/**
 * Initialize the runner with references to Q and Jets for fetching
 * WASM bytes from Drops and signing receipts.
 *
 * @method init
 * @param {Object} opts
 * @param {Object} opts.Q           The Q framework object
 * @param {Object} opts.Jets        Q.Safecloud.Jets reference
 * @param {Object} opts.Client      Q.Safecloud.Client reference (for fetch)
 * @param {Function} opts.signFn    Signs a buffer, returns hex sig
 * @param {String}   opts.jetId     This Jet's public identifier
 */
WasmRunner.init = function (opts) {
    WasmRunner._Q      = opts.Q;
    WasmRunner._Jets   = opts.Jets;
    WasmRunner._Client = opts.Client;
    WasmRunner._signFn = opts.signFn;
    WasmRunner._jetId  = opts.jetId;
    WasmRunner._fuelLimit   = opts.fuelLimit   || DEFAULT_FUEL_LIMIT;
    WasmRunner._memoryLimit = opts.memoryLimit  || DEFAULT_MEMORY_LIMIT;
    // Checkpoint index path for durable track persistence (3.2)
    if (opts.checkpointIndexPath) {
        _checkpointIndexPath = opts.checkpointIndexPath;
    }
    // Gossip callback set by Jets.js after socket.io namespace is wired (3.2)
    // WasmRunner._emitRootUpdate = function(msg) { ... } — set externally
};

/**
 * Callback invoked after each successful checkpoint write.
 * Jets.js sets this to emit 'safedb:root-update' over /Safecloud/cloud socket.io.
 * @type {Function|null}
 */
WasmRunner._emitRootUpdate = null;

// ─────────────────────────────────────────────────────────────────────────────
// Manifest loading
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch and cache a SafecloudApp manifest by its CID.
 *
 * Manifest format (from Apps.md):
 * {
 *   "v": 1,
 *   "name": "...",
 *   "handlers": {
 *     "GET /posts/*":  "bafy...posts",
 *     "POST /posts":   "bafy...posts",
 *     "on_key_request": "bafy...keyrelease"
 *   },
 *   "contentCid": "bafy..." | null
 * }
 *
 * @method loadManifest
 * @param {String} appCid
 * @return {Promise<Object>} parsed manifest
 */
WasmRunner.loadManifest = function (appCid) {
    var cached = _manifestCache.get(appCid);
    if (cached) {
        return Promise.resolve(cached);
    }
    return _fetchBytesByCid(appCid).then(function (buf) {
        var manifest = JSON.parse(Buffer.from(buf).toString('utf8'));
        if (!manifest || typeof manifest !== 'object') {
            throw new Error('Invalid manifest: not an object');
        }
        if (!manifest.handlers || typeof manifest.handlers !== 'object') {
            throw new Error('Invalid manifest: missing handlers map');
        }
        _manifestCache.set(appCid, manifest);
        return manifest;
    });
};

// ─────────────────────────────────────────────────────────────────────────────
// Handler execution
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute a SafecloudApp handler and return a SafecloudEnvelope.
 *
 * @method execute
 * @param {Object} opts
 * @param {String} opts.appCid       CID of the SafecloudApp manifest
 * @param {String} opts.handlerCid   CID of the specific WASM handler
 * @param {Object} [opts.claim]      OCP claim from the caller (or null)
 * @param {Object} [opts.params]     Request parameters (key-value map)
 * @param {Buffer} [opts.body]       Request body bytes
 * @param {String} [opts.method]     HTTP method (for dynamic site routing)
 * @param {String} [opts.path]       Request path (for dynamic site routing)
 * @param {Number} [opts.callDepth]  Current call depth (for composable handlers)
 * @return {Promise<Object>}  { envelope, receipt }
 */
WasmRunner.execute = function (opts) {
    var appCid     = opts.appCid;
    var handlerCid = opts.handlerCid;
    var claim      = opts.claim    || null;
    var params     = opts.params   || {};
    var body       = opts.body     || Buffer.alloc(0);
    var method     = opts.method   || 'GET';
    var path       = opts.path     || '/';
    var callDepth  = opts.callDepth || 0;

    if (callDepth >= MAX_CALL_DEPTH) {
        return Promise.reject(new Error('call() depth exceeded (max ' + MAX_CALL_DEPTH + ')'));
    }

    // Build the deterministic input for hashing
    var inputObj = {
        appCid: appCid,
        handlerCid: handlerCid,
        claim: claim,
        params: params,
        body: body.toString('base64'),
        method: method,
        path: path
    };
    var inputHash = _hashObject(inputObj);

    // Capture the state root before execution
    var stateRootBefore = _computeStateRoot(appCid);

    // Deterministic timestamp: from the chain, not wall clock.
    // Use the previous receipt's timestamp + 1 if available, else Date.now().
    var timestamp = _chainTimestamp(appCid);

    // Deterministic random seed: HKDF(inputHash || timestamp)
    var seedInput = Buffer.concat([
        Buffer.from(inputHash, 'hex'),
        _uint64ToBuffer(timestamp)
    ]);
    var randomSeed = crypto.createHmac('sha256', 'safecloud.wasm.seed')
        .update(seedInput).digest();

    return _getCompiledModule(handlerCid).then(function (compiled) {
        return _instantiateAndRun(compiled, {
            appCid:      appCid,
            handlerCid:  handlerCid,
            claim:       claim,
            params:      params,
            body:        body,
            method:      method,
            path:        path,
            timestamp:   timestamp,
            randomSeed:  randomSeed,
            inputHash:   inputHash,
            callDepth:   callDepth,
            stateRootBefore: stateRootBefore
        });
    });
};

/**
 * Execute a handler by route from an app manifest.
 * Resolves the handler CID from the manifest's route map.
 *
 * @method executeByRoute
 * @param {String} appCid   CID of the SafecloudApp manifest
 * @param {String} method   HTTP method
 * @param {String} path     Request path
 * @param {Object} [opts]   Additional options (claim, params, body)
 * @return {Promise<Object>}  { envelope, receipt }
 */
WasmRunner.executeByRoute = function (appCid, method, reqPath, opts) {
    opts = opts || {};
    return WasmRunner.loadManifest(appCid).then(function (manifest) {
        var handlerCid = _resolveRoute(manifest, method, reqPath);
        if (!handlerCid) {
            throw new Error('No handler for ' + method + ' ' + reqPath + ' in app ' + appCid);
        }
        return WasmRunner.execute({
            appCid:     appCid,
            handlerCid: handlerCid,
            claim:      opts.claim   || null,
            params:     opts.params  || {},
            body:       opts.body    || Buffer.alloc(0),
            method:     method,
            path:       reqPath,
            callDepth:  opts.callDepth || 0
        });
    });
};

/**
 * Execute a named handler (e.g. "on_key_request") from an app manifest.
 *
 * @method executeByName
 * @param {String} appCid
 * @param {String} handlerName
 * @param {Object} [opts]
 * @return {Promise<Object>}
 */
WasmRunner.executeByName = function (appCid, handlerName, opts) {
    opts = opts || {};
    return WasmRunner.loadManifest(appCid).then(function (manifest) {
        var handlerCid = manifest.handlers[handlerName];
        if (!handlerCid) {
            throw new Error('No handler named "' + handlerName + '" in app ' + appCid);
        }
        return WasmRunner.execute({
            appCid:     appCid,
            handlerCid: handlerCid,
            claim:      opts.claim   || null,
            params:     opts.params  || {},
            body:       opts.body    || Buffer.alloc(0),
            method:     opts.method  || 'CALL',
            path:       '/' + handlerName,
            callDepth:  opts.callDepth || 0
        });
    });
};

/**
 * Get the receipt chain head for a given app.
 *
 * @method getChainHead
 * @param {String} appCid
 * @return {String|null}  CID of the latest receipt, or null
 */
WasmRunner.getChainHead = function (appCid) {
    return _chainHeads[appCid] || null;
};

/**
 * Retrieve a stored receipt by its CID.
 *
 * @method getReceipt
 * @param {String} appCid
 * @param {String} receiptCid
 * @return {Object|null}  The SafecloudReceipt, or null
 */
WasmRunner.getReceipt = function (appCid, receiptCid) {
    var key = _trackKey(appCid, 'receipts/' + appCid, receiptCid);
    var val = _trackStore.get(key);
    if (!val) { return null; }
    try { return JSON.parse(val.toString('utf8')); }
    catch (e) { return null; }
};

/**
 * Walk the receipt chain for an app, most recent first.
 *
 * @method walkChain
 * @param {String} appCid
 * @param {Number} [limit]  Max receipts to return (default 100)
 * @return {Array<Object>}  Array of SafecloudReceipts
 */
WasmRunner.walkChain = function (appCid, limit) {
    limit = limit || 100;
    var results = [];
    var cid = _chainHeads[appCid];
    while (cid && results.length < limit) {
        var receipt = WasmRunner.getReceipt(appCid, cid);
        if (!receipt) { break; }
        results.push(receipt);
        cid = receipt.prevReceiptCid;
    }
    return results;
};

// ─────────────────────────────────────────────────────────────────────────────
// Track store operations (the SafecloudDB interface for handlers)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Read a value from a SafecloudDB track for a given app.
 * @private
 */
function _trackGet(appCid, track, key) {
    var k = _trackKey(appCid, track, key);
    var v = _trackStore.get(k);
    return v !== undefined ? v : null;
}

/**
 * Range scan over a SafecloudDB track for a given app.
 * Returns an array of [key, value] pairs where key >= gte and key <= lte.
 * @private
 */
function _trackRange(appCid, track, gte, lte) {
    // Scan all keys with the track prefix and filter.
    // In production this hits the prolly tree range query; here we scan linearly.
    var prefix = appCid + '/' + track + '/';
    var results = [];
    // BoundedMap doesn't expose iteration, so we maintain a secondary index.
    var idx = _trackIndices[appCid + '/' + track];
    if (!idx) { return results; }
    var gteStr = gte.toString();
    var lteStr = lte.toString();
    for (var i = 0; i < idx.length; i++) {
        var k = idx[i];
        if (k >= gteStr && k <= lteStr) {
            var v = _trackStore.get(prefix + k);
            if (v !== undefined) {
                results.push([Buffer.from(k), v]);
            }
        }
    }
    return results;
}

/**
 * Write a value to a SafecloudDB track.
 * @private
 */
function _trackPut(appCid, track, key, value) {
    var k = _trackKey(appCid, track, key);
    _trackStore.set(k, value);
    // Maintain sorted index for range queries
    var idxKey = appCid + '/' + track;
    if (!_trackIndices[idxKey]) { _trackIndices[idxKey] = []; }
    var keyStr = key.toString();
    var arr = _trackIndices[idxKey];
    if (arr.indexOf(keyStr) === -1) {
        arr.push(keyStr);
        arr.sort();
    }
}

/**
 * Delete a value from a SafecloudDB track.
 * @private
 */
function _trackDelete(appCid, track, key) {
    var k = _trackKey(appCid, track, key);
    _trackStore.set(k, undefined); // BoundedMap doesn't expose delete
    var idxKey = appCid + '/' + track;
    var arr = _trackIndices[idxKey];
    if (arr) {
        var keyStr = key.toString();
        var pos = arr.indexOf(keyStr);
        if (pos !== -1) { arr.splice(pos, 1); }
    }
}

/** Sorted key indices for range queries: "appCid/track" → sorted array of key strings */
var _trackIndices = {};

function _trackKey(appCid, track, key) {
    return appCid + '/' + track + '/' + key;
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint persistence  (Safecloud 3.2)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Serialize all entries for one track and write them to Drops as an
 * immutable checkpoint blob.  Fire-and-forget — called after resolve()
 * in _instantiateAndRun so it never blocks the response path.
 *
 * Blob format (JSON):
 *   { v:1, appCid, track, rootCid, seq, jetId, checkpointedAt,
 *     entries: [{key, value}]  (value is base64-encoded bytes) }
 *
 * The blob's SHA-256 becomes its CID (bafy… scheme).  After a successful
 * Drop write the CID is added to _checkpointCids and flushed to the local
 * index file so a restarted Jet knows where to fetch it from Drops.
 *
 * @private
 */
function _storeCheckpoint(appCid, track, rootCid) {
    var idxKey = appCid + '/' + track;
    var seq    = (_checkpointSeq[idxKey] || 0) + 1;
    _checkpointSeq[idxKey] = seq;

    // Collect all key→value pairs for this track.
    var idx    = _trackIndices[idxKey] || [];
    var prefix = appCid + '/' + track + '/';
    var entries = [];
    for (var i = 0; i < idx.length; i++) {
        var k = idx[i];
        var v = _trackStore.get(prefix + k);
        if (v !== undefined) {
            entries.push({
                key:   k,
                value: Buffer.isBuffer(v) ? v.toString('base64') : String(v)
            });
        }
    }

    var blob      = {
        v:              1,
        appCid:         appCid,
        track:          track,
        rootCid:        rootCid,
        seq:            seq,
        jetId:          WasmRunner._jetId,
        checkpointedAt: Math.floor(Date.now() / 1000),
        entries:        entries
    };
    var blobBytes     = Buffer.from(JSON.stringify(blob));
    var checkpointCid = 'bafy' + crypto.createHash('sha256')
        .update(blobBytes).digest('hex').slice(0, 52);

    if (!WasmRunner._Jets) { return; }

    // Select a Drop for writing (no forGet → selectForPut path).
    WasmRunner._Jets.selectDrops([checkpointCid], {}).then(function (drops) {
        if (!drops || !drops.length) { return Promise.resolve(); }
        return WasmRunner._Jets.callDrop(drops[0], 'Safecloud/drop/put', {
            chunks:  [{ cid: checkpointCid, data: blobBytes.toString('base64') }],
            options: {}
        });
    }).then(function () {
        // Checkpoint is durable on at least one Drop — update local index.
        _checkpointCids[idxKey] = checkpointCid;
        _persistCheckpointIndex();

        // Gossip the new root to peer Jets.
        if (typeof WasmRunner._emitRootUpdate === 'function') {
            WasmRunner._emitRootUpdate({
                appCid:        appCid,
                track:         track,
                rootCid:       rootCid,
                checkpointCid: checkpointCid,
                seq:           seq,
                jetId:         WasmRunner._jetId
            });
        }
    }).catch(function (err) {
        if (WasmRunner._Q) {
            WasmRunner._Q.log('WasmRunner._storeCheckpoint: write failed for '
                + checkpointCid + ': ' + (err && err.message), 'Safecloud');
        }
    });
}

/**
 * Write the checkpoint CID index to disk (best-effort).
 * @private
 */
function _persistCheckpointIndex() {
    if (!_checkpointIndexPath) { return; }
    try {
        _fs.writeFileSync(_checkpointIndexPath,
            JSON.stringify(_checkpointCids, null, 2), 'utf8');
    } catch (e) {
        if (WasmRunner._Q) {
            WasmRunner._Q.log('WasmRunner: failed to persist checkpoint index: '
                + (e && e.message), 'Safecloud');
        }
    }
}

/**
 * Replay a checkpoint blob into _trackStore.
 * @private
 */
function _applyCheckpointBlob(blob) {
    if (!blob || blob.v !== 1 || !blob.appCid || !blob.track
            || !Array.isArray(blob.entries)) { return; }
    for (var i = 0; i < blob.entries.length; i++) {
        var e = blob.entries[i];
        if (e && e.key) {
            var value = (typeof e.value === 'string')
                ? Buffer.from(e.value, 'base64')
                : e.value;
            _trackPut(blob.appCid, blob.track, e.key, value);
        }
    }
    var idxKey = blob.appCid + '/' + blob.track;
    if (blob.seq && blob.seq > (_checkpointSeq[idxKey] || 0)) {
        _checkpointSeq[idxKey] = blob.seq;
    }
}

/**
 * Load the checkpoint CID index from disk and restore all track data from
 * Drops.  Called during Jets startup after WasmRunner.init().
 *
 * @param  {String} indexPath   Path to the JSON checkpoint index file.
 * @return {Promise}
 */
WasmRunner.restoreCheckpoints = function (indexPath) {
    _checkpointIndexPath = indexPath;

    var index;
    try {
        var raw = _fs.readFileSync(indexPath, 'utf8');
        index   = JSON.parse(raw);
    } catch (e) {
        return Promise.resolve(); // no index yet — fresh start
    }

    _checkpointCids = index || {};
    var keys = Object.keys(_checkpointCids);
    if (!keys.length) { return Promise.resolve(); }

    var promises = keys.map(function (idxKey) {
        var cid = _checkpointCids[idxKey];
        if (!cid) { return Promise.resolve(); }
        return _fetchBytesByCid(cid).then(function (buf) {
            try {
                var blob = JSON.parse(buf.toString('utf8'));
                _applyCheckpointBlob(blob);
                if (WasmRunner._Q) {
                    WasmRunner._Q.log('WasmRunner: restored checkpoint ' + cid
                        + ' for ' + idxKey + ' ('
                        + (blob.entries || []).length + ' entries)', 'Safecloud');
                }
            } catch (parseErr) {
                if (WasmRunner._Q) {
                    WasmRunner._Q.log('WasmRunner: bad checkpoint blob '
                        + cid + ': ' + (parseErr && parseErr.message), 'Safecloud');
                }
            }
        }).catch(function (fetchErr) {
            if (WasmRunner._Q) {
                WasmRunner._Q.log('WasmRunner: failed to fetch checkpoint '
                    + cid + ' for ' + idxKey + ': '
                    + (fetchErr && fetchErr.message), 'Safecloud');
            }
        });
    });

    return Promise.all(promises);
};

/**
 * Merge a received gossip root-update into local _trackStore.
 * Called by Jets.js when 'safedb:root-update' arrives from a peer Jet.
 *
 * Skipped if seq is not newer than what we already have, so the Bloom
 * anti-entropy check degrades gracefully to a monotone seq guard here.
 *
 * @param  {Object} msg  { appCid, track, rootCid, checkpointCid, seq, jetId }
 * @return {Promise}
 */
WasmRunner.applyRootUpdate = function (msg) {
    if (!msg || !msg.appCid || !msg.track || !msg.checkpointCid) {
        return Promise.resolve();
    }
    var idxKey = msg.appCid + '/' + msg.track;
    if (msg.seq && msg.seq <= (_checkpointSeq[idxKey] || 0)) {
        return Promise.resolve(); // already at or ahead of this state
    }
    return _fetchBytesByCid(msg.checkpointCid).then(function (buf) {
        try {
            var blob = JSON.parse(buf.toString('utf8'));
            _applyCheckpointBlob(blob);
            _checkpointCids[idxKey] = msg.checkpointCid;
            _persistCheckpointIndex();
            if (WasmRunner._Q) {
                WasmRunner._Q.log('WasmRunner: merged root-update from jet '
                    + msg.jetId + ' for ' + idxKey + ' seq=' + msg.seq, 'Safecloud');
            }
        } catch (e) {
            if (WasmRunner._Q) {
                WasmRunner._Q.log('WasmRunner: applyRootUpdate parse error for '
                    + idxKey + ': ' + (e && e.message), 'Safecloud');
            }
        }
    }).catch(function (err) {
        if (WasmRunner._Q) {
            WasmRunner._Q.log('WasmRunner: applyRootUpdate fetch failed for '
                + msg.checkpointCid + ': ' + (err && err.message), 'Safecloud');
        }
    });
};

// ─────────────────────────────────────────────────────────────────────────────
// WASM compilation and instantiation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch WASM bytes by CID from Drops and compile to a WebAssembly.Module.
 * @private
 */
function _getCompiledModule(handlerCid) {
    var cached = _compiledModules.get(handlerCid);
    if (cached) {
        return Promise.resolve(cached);
    }
    return _fetchBytesByCid(handlerCid).then(function (buf) {
        return WebAssembly.compile(buf);
    }).then(function (mod) {
        _compiledModules.set(handlerCid, mod);
        return mod;
    });
}

/**
 * Fetch raw bytes by CID. Tries the local Jet's drop network first.
 * @private
 */
function _fetchBytesByCid(cid) {
    if (!WasmRunner._Jets) {
        return Promise.reject(new Error('WasmRunner not initialized'));
    }
    // Use the Jet's existing subtree-get infrastructure to fetch from Drops.
    // Wrap in a Promise for consistency.
    return new Promise(function (resolve, reject) {
        WasmRunner._Jets.selectDrops([cid], { forGet: true }).then(function (drops) {
            if (!drops || !drops.length) {
                return reject(new Error('No Drop available for CID ' + cid));
            }
            return WasmRunner._Jets.callDrop(drops[0], 'Safecloud/drop/get', {
                cids: [cid]
            });
        }).then(function (response) {
            if (!response || !response.chunks || !response.chunks[cid]) {
                return reject(new Error('CID ' + cid + ' not found on any Drop'));
            }
            var chunk = response.chunks[cid];
            if (typeof chunk === 'string') {
                resolve(Buffer.from(chunk, 'base64'));
            } else if (Buffer.isBuffer(chunk)) {
                resolve(chunk);
            } else {
                resolve(Buffer.from(chunk));
            }
        }).catch(reject);
    });
}

/**
 * Instantiate a compiled WASM module with the host API and run it.
 *
 * The host API functions are injected as WASM imports under the "env"
 * namespace. The WASM module exports a single entry point: `handle`.
 *
 * Memory metering: we create a WebAssembly.Memory with a hard page limit.
 * Fuel metering: we count host API calls as fuel units (since we can't
 * instrument WASM opcodes without a custom runtime, we meter at the
 * host-call boundary — each host call costs fuel proportional to its work).
 *
 * @private
 */
function _instantiateAndRun(compiled, ctx) {
    return new Promise(function (resolve, reject) {
        // ── Execution state ──────────────────────────────────────────────
        var fuelRemaining = WasmRunner._fuelLimit;
        var memoryPeak    = 0;
        var stateChanges  = []; // track mutations for the receipt
        var response      = null; // the envelope set by respond()
        var childReceipts = []; // from call()

        // ── Fuel accounting ──────────────────────────────────────────────
        function consumeFuel(amount) {
            fuelRemaining -= amount;
            if (fuelRemaining <= 0) {
                throw new Error('Fuel exhausted');
            }
        }

        // ── Shared linear memory ─────────────────────────────────────────
        // 1 page = 64 KiB. Max pages = memoryLimit / 64KiB.
        var maxPages = Math.ceil(WasmRunner._memoryLimit / 65536);
        var memory = new WebAssembly.Memory({ initial: 1, maximum: maxPages });

        // ── String encoding helpers ──────────────────────────────────────
        // WASM imports/exports use i32 offsets into linear memory.
        // We use a simple bump allocator for passing data in/out.
        var heapOffset = 65536; // start after first page (reserved for stack)

        function allocBytes(buf) {
            if (!(buf instanceof Buffer || buf instanceof Uint8Array)) {
                buf = Buffer.from(buf);
            }
            var len = buf.length;
            var ptr = heapOffset;
            // Grow memory if needed
            var needed = ptr + len + 4; // 4 bytes for length prefix
            var currentBytes = memory.buffer.byteLength;
            if (needed > currentBytes) {
                var pagesToGrow = Math.ceil((needed - currentBytes) / 65536);
                try {
                    memory.grow(pagesToGrow);
                } catch (e) {
                    throw new Error('Memory limit exceeded');
                }
            }
            var view = new DataView(memory.buffer);
            view.setUint32(ptr, len, true); // little-endian length prefix
            new Uint8Array(memory.buffer).set(buf, ptr + 4);
            heapOffset = ptr + 4 + len;
            // Align to 8 bytes
            heapOffset = (heapOffset + 7) & ~7;
            // Track peak
            if (heapOffset > memoryPeak) { memoryPeak = heapOffset; }
            return ptr;
        }

        function readBytes(ptr) {
            var view = new DataView(memory.buffer);
            var len = view.getUint32(ptr, true);
            return Buffer.from(new Uint8Array(memory.buffer, ptr + 4, len));
        }

        function readString(ptr) {
            return readBytes(ptr).toString('utf8');
        }

        // ── Host API implementation ──────────────────────────────────────

        var hostEnv = {
            // safedb_get(track_ptr, key_ptr) → result_ptr (0 if not found)
            safedb_get: function (trackPtr, keyPtr) {
                consumeFuel(100);
                var track = readString(trackPtr);
                var key   = readBytes(keyPtr);
                var val   = _trackGet(ctx.appCid, track, key.toString());
                if (val === null) { return 0; }
                return allocBytes(Buffer.from(val));
            },

            // safedb_range(track_ptr, gte_ptr, lte_ptr) → result_ptr
            // Result is a packed array: [count:u32, (key_len:u32, key, val_len:u32, val)*]
            safedb_range: function (trackPtr, gtePtr, ltePtr) {
                consumeFuel(500);
                var track  = readString(trackPtr);
                var gte    = readBytes(gtePtr);
                var lte    = readBytes(ltePtr);
                var pairs  = _trackRange(ctx.appCid, track, gte, lte);
                // Pack into a single buffer
                var parts = [_uint32Buffer(pairs.length)];
                for (var i = 0; i < pairs.length; i++) {
                    var k = pairs[i][0];
                    var v = pairs[i][1];
                    if (!Buffer.isBuffer(k)) { k = Buffer.from(k); }
                    if (!Buffer.isBuffer(v)) { v = Buffer.from(String(v)); }
                    parts.push(_uint32Buffer(k.length));
                    parts.push(k);
                    parts.push(_uint32Buffer(v.length));
                    parts.push(v);
                }
                return allocBytes(Buffer.concat(parts));
            },

            // safedb_put(track_ptr, key_ptr, value_ptr)
            safedb_put: function (trackPtr, keyPtr, valuePtr) {
                consumeFuel(200);
                var track = readString(trackPtr);
                var key   = readBytes(keyPtr);
                var value = readBytes(valuePtr);
                _trackPut(ctx.appCid, track, key.toString(), value);
                stateChanges.push({ op: 'put', track: track, key: key.toString('hex') });
            },

            // safedb_delete(track_ptr, key_ptr)
            safedb_delete: function (trackPtr, keyPtr) {
                consumeFuel(200);
                var track = readString(trackPtr);
                var key   = readBytes(keyPtr);
                _trackDelete(ctx.appCid, track, key.toString());
                stateChanges.push({ op: 'delete', track: track, key: key.toString('hex') });
            },

            // request_claim() → ptr (0 if no claim)
            request_claim: function () {
                consumeFuel(10);
                if (!ctx.claim) { return 0; }
                return allocBytes(Buffer.from(JSON.stringify(ctx.claim)));
            },

            // request_params() → ptr
            request_params: function () {
                consumeFuel(10);
                return allocBytes(Buffer.from(JSON.stringify(ctx.params)));
            },

            // request_body() → ptr
            request_body: function () {
                consumeFuel(10);
                return allocBytes(ctx.body);
            },

            // now() → u64 (as two i32s for WASM: low, high)
            // WASM doesn't have i64 in the JS API, so we return low 32 bits.
            // The high bits are always 0 for timestamps until 2106.
            now: function () {
                consumeFuel(1);
                return ctx.timestamp;
            },

            // random_seed() → ptr to 32 bytes
            random_seed: function () {
                consumeFuel(1);
                return allocBytes(ctx.randomSeed);
            },

            // respond(envelope_ptr) — set the handler's response
            respond: function (envelopePtr) {
                consumeFuel(50);
                var raw = readString(envelopePtr);
                try {
                    response = JSON.parse(raw);
                } catch (e) {
                    response = { v: 1, type: 'safecloud/error',
                        payload: { code: 'InvalidResponse', message: 'Handler returned invalid JSON' } };
                }
            },

            // call(handler_cid_ptr, input_ptr) → envelope_ptr
            // Synchronous from WASM's perspective. We can't truly block in
            // the JS host, so for MVP we execute the sub-handler inline
            // (blocking the event loop). Production: use Atomics.wait or
            // worker threads.
            call: function (handlerCidPtr, inputPtr) {
                consumeFuel(1000);
                // For the synchronous MVP, we cannot do async sub-calls
                // inside a WASM import. Store the request; the orchestrator
                // handles it after the main handler returns.
                var subHandlerCid = readString(handlerCidPtr);
                var subInput      = readBytes(inputPtr);
                childReceipts.push({
                    handlerCid: subHandlerCid,
                    input:      subInput,
                    pending:    true
                });
                // Return a placeholder — the orchestrator resolves child
                // calls in a post-pass and re-links the receipts.
                var placeholder = { v: 1, type: 'safecloud/data',
                    payload: { pending: true, childIndex: childReceipts.length - 1 } };
                return allocBytes(Buffer.from(JSON.stringify(placeholder)));
            },

            // request_method() → ptr (non-spec convenience for dynamic sites)
            request_method: function () {
                consumeFuel(1);
                return allocBytes(Buffer.from(ctx.method));
            },

            // request_path() → ptr (non-spec convenience for dynamic sites)
            request_path: function () {
                consumeFuel(1);
                return allocBytes(Buffer.from(ctx.path));
            }
        };

        // ── Instantiate ──────────────────────────────────────────────────
        var importObject = {
            env: Object.assign({ memory: memory }, hostEnv)
        };

        var instance;
        try {
            // WebAssembly.instantiate (sync variant with Module)
            instance = new WebAssembly.Instance(compiled, importObject);
        } catch (e) {
            return reject(new Error('WASM instantiation failed: ' + e.message));
        }

        // ── Run the handler ──────────────────────────────────────────────
        try {
            // The WASM module exports `handle()` as its entry point.
            // It reads request context via the host API and calls respond().
            if (typeof instance.exports.handle !== 'function') {
                throw new Error('WASM module does not export handle()');
            }
            instance.exports.handle();
        } catch (e) {
            if (e.message === 'Fuel exhausted') {
                response = { v: 1, type: 'safecloud/error',
                    payload: { code: 'FuelExhausted', message: 'Handler exceeded fuel limit' } };
            } else if (e.message === 'Memory limit exceeded') {
                response = { v: 1, type: 'safecloud/error',
                    payload: { code: 'MemoryExceeded', message: 'Handler exceeded memory limit' } };
            } else {
                response = { v: 1, type: 'safecloud/error',
                    payload: { code: 'RuntimeError', message: e.message } };
            }
        }

        // ── Default response if handler didn't call respond() ────────────
        if (!response) {
            response = { v: 1, type: 'safecloud/error',
                payload: { code: 'NoResponse', message: 'Handler did not call respond()' } };
        }

        // ── Compute state root after execution ───────────────────────────
        var stateRootAfter = _computeStateRoot(ctx.appCid);

        // ── Build output hash ────────────────────────────────────────────
        var outputHash = _hashObject(response);

        // ── Build SafecloudReceipt ───────────────────────────────────────
        var prevReceiptCid = _chainHeads[ctx.appCid] || null;
        var fuelConsumed = WasmRunner._fuelLimit - fuelRemaining;

        var receipt = {
            v:                1,
            prevReceiptCid:   prevReceiptCid,
            appCid:           ctx.appCid,
            handlerCid:       ctx.handlerCid,
            inputHash:        'sha256:' + ctx.inputHash,
            outputHash:       'sha256:' + outputHash,
            stateRootBefore:  ctx.stateRootBefore,
            stateRootAfter:   stateRootAfter,
            fuelConsumed:     fuelConsumed,
            memoryPeak:       memoryPeak,
            jetId:            WasmRunner._jetId,
            timestamp:        ctx.timestamp,
            childReceipts:    childReceipts.length ? childReceipts.map(function (c) {
                return { handlerCid: c.handlerCid, pending: c.pending };
            }) : undefined,
            signature:        null // filled below
        };

        // ── Sign the receipt ─────────────────────────────────────────────
        var receiptBytes = Buffer.from(JSON.stringify(receipt));
        var receiptCid = 'bafy' + crypto.createHash('sha256')
            .update(receiptBytes).digest('hex').slice(0, 52);

        if (WasmRunner._signFn) {
            try {
                receipt.signature = WasmRunner._signFn(receiptBytes);
            } catch (e) {
                receipt.signature = null;
            }
        }

        // ── Store the receipt in the chain ────────────────────────────────
        var receiptTrack = 'receipts/' + ctx.appCid;
        var receiptKey = ctx.timestamp + '/' + receiptCid;
        _trackPut(ctx.appCid, receiptTrack, receiptKey,
            Buffer.from(JSON.stringify(receipt)));
        _chainHeads[ctx.appCid] = receiptCid;

        // ── Checkpoint modified tracks to Drops  (Safecloud 3.2) ─────────
        // Collect the distinct tracks touched by this execution (from the
        // stateChanges log) plus the receipt track, then fire-and-forget a
        // Drops write for each.  Async — does NOT block the response path.
        var _modifiedTracks = {};
        for (var _sci = 0; _sci < stateChanges.length; _sci++) {
            if (stateChanges[_sci].track) {
                _modifiedTracks[stateChanges[_sci].track] = true;
            }
        }
        _modifiedTracks[receiptTrack] = true; // always checkpoint the receipt track
        var _tracksToCheckpoint = Object.keys(_modifiedTracks);
        for (var _tci = 0; _tci < _tracksToCheckpoint.length; _tci++) {
            _storeCheckpoint(ctx.appCid, _tracksToCheckpoint[_tci], stateRootAfter);
        }

        // ── Build SafecloudEnvelope ──────────────────────────────────────
        var envelope = {
            v:       response.v || 1,
            type:    response.type,
            payload: response.payload,
            headers: response.headers || undefined,
            proof: {
                jetId:      WasmRunner._jetId,
                appCid:     ctx.appCid,
                handlerCid: ctx.handlerCid,
                stateRoot:  stateRootAfter,
                receiptCid: receiptCid,
                signature:  null // filled below
            }
        };

        // Sign the full envelope
        var envBytes = Buffer.from(JSON.stringify(envelope));
        if (WasmRunner._signFn) {
            try {
                envelope.proof.signature = WasmRunner._signFn(envBytes);
            } catch (e) {
                envelope.proof.signature = null;
            }
        }

        resolve({ envelope: envelope, receipt: receipt, receiptCid: receiptCid });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Route resolution
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Match a method+path against the manifest's handler map.
 * Supports exact matches and wildcard suffixes (e.g. "GET /posts/*").
 *
 * @private
 * @param {Object} manifest
 * @param {String} method
 * @param {String} reqPath
 * @return {String|null}  handlerCid or null
 */
function _resolveRoute(manifest, method, reqPath) {
    var handlers = manifest.handlers;
    // 1. Exact match: "GET /posts/latest"
    var exact = method + ' ' + reqPath;
    if (handlers[exact]) { return handlers[exact]; }

    // 2. Wildcard match: "GET /posts/*"
    var segments = reqPath.split('/');
    for (var i = segments.length; i >= 1; i--) {
        var prefix = segments.slice(0, i).join('/');
        var wild = method + ' ' + prefix + '/*';
        if (handlers[wild]) { return handlers[wild]; }
    }

    // 3. Named handler (no method prefix): "on_key_request"
    // These are called by name, not by route — skip for route resolution.

    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────

function _hashObject(obj) {
    var canonical = JSON.stringify(obj);
    return crypto.createHash('sha256').update(canonical).digest('hex');
}

function _computeStateRoot(appCid) {
    // In production: the prolly tree root CID for this app's tracks.
    // For MVP: hash all track keys belonging to this app.
    var prefix = appCid + '/';
    // We can't iterate BoundedMap, so hash the index entries.
    var indexKeys = Object.keys(_trackIndices).filter(function (k) {
        return k.indexOf(prefix) === 0;
    }).sort();
    var parts = [];
    for (var i = 0; i < indexKeys.length; i++) {
        var arr = _trackIndices[indexKeys[i]];
        if (arr) { parts.push(indexKeys[i] + ':' + arr.join(',')); }
    }
    if (!parts.length) { return 'bafy' + '0'.repeat(52); }
    return 'bafy' + crypto.createHash('sha256')
        .update(parts.join('|')).digest('hex').slice(0, 52);
}

function _chainTimestamp(appCid) {
    // Deterministic: if the chain has receipts, use last timestamp + 1.
    // Otherwise use wall clock (first execution).
    var head = _chainHeads[appCid];
    if (head) {
        var receipt = WasmRunner.getReceipt(appCid, head);
        if (receipt && receipt.timestamp) {
            return receipt.timestamp + 1;
        }
    }
    return Math.floor(Date.now() / 1000);
}

function _uint64ToBuffer(n) {
    var buf = Buffer.alloc(8);
    buf.writeUInt32LE(n & 0xFFFFFFFF, 0);
    buf.writeUInt32LE(Math.floor(n / 0x100000000), 4);
    return buf;
}

function _uint32Buffer(n) {
    var buf = Buffer.alloc(4);
    buf.writeUInt32LE(n, 0);
    return buf;
}
