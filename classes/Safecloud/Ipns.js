'use strict';
/**
 * Safecloud 3.3 — IPNS key management and name publishing.
 *
 * IPNS (InterPlanetary Name System) provides mutable pointers to IPFS
 * content.  Stable names derived from public keys let consumers subscribe
 * to "the latest version of X" without re-distributing a new CID on every
 * update.
 *
 * This module wraps the Kubo HTTP RPC /api/v0/key/* and /api/v0/name/*
 * endpoints via SafecloudIpfs.kuboPost().  It therefore requires:
 *   Safecloud.ipfs.enabled: true
 *   Safecloud.ipfs.mode: "external"
 *
 * Wire-compatible with:
 *   Kubo HTTP RPC API /api/v0/key/* and /api/v0/name/*
 *   https://docs.ipfs.tech/reference/kubo/rpc/
 */

var SafecloudIpfs = require('./Ipfs');

var _Q       = null;
var _enabled = false;   // shadows Safecloud.ipfs.enabled

var SafecloudIpns = module.exports = {};

/**
 * Initialise from Q config.  Called by Jets.js after SafecloudIpfs.init().
 *
 * @param {Object} opts   { Q }
 */
SafecloudIpns.init = function (opts) {
    _Q       = opts.Q;
    _enabled = SafecloudIpfs.isEnabled() && (SafecloudIpfs.getMode() === 'external');
    if (_enabled) {
        _Q.log('Safecloud.Ipns: enabled (Kubo at ' + SafecloudIpfs.getApiUrl() + ')', 'Safecloud');
    } else if (SafecloudIpfs.isEnabled()) {
        _Q.log('Safecloud.Ipns: disabled — IPNS requires mode: "external"', 'Safecloud');
    }
};

SafecloudIpns.isEnabled = function () { return _enabled; };

// ── Key management ────────────────────────────────────────────────────────────

/**
 * Generate a new IPNS key on the Kubo node.
 *
 * @param {string} name    local name for the key (e.g. "safecloud-stream-1")
 * @param {string} [type]  key type: "ed25519" (default) or "rsa"
 * @param {number} [size]  key size in bits (only for RSA, default 2048)
 * @returns {Promise<{Name:string, Id:string}>}
 *   Name  — local key name
 *   Id    — IPNS peer ID (k51… or Qm… encoded)
 */
SafecloudIpns.createKey = function (name, type, size) {
    if (!_enabled) { return Promise.reject(new Error('IPNS not available')); }
    if (!name || typeof name !== 'string') {
        return Promise.reject(new Error('createKey: name must be a non-empty string'));
    }
    type = type || 'ed25519';
    var params = { arg: name, type: type };
    if (type === 'rsa' && size) { params.size = String(size); }
    return SafecloudIpfs.kuboPost('/api/v0/key/gen', params);
    // Kubo response: { Name: "name", Id: "k51..." }
};

/**
 * List all IPNS keys on the Kubo node.
 *
 * @returns {Promise<{Keys: Array<{Name:string, Id:string}>}>}
 */
SafecloudIpns.listKeys = function () {
    if (!_enabled) { return Promise.reject(new Error('IPNS not available')); }
    return SafecloudIpfs.kuboPost('/api/v0/key/list', {});
    // Kubo response: { Keys: [{ Name: "...", Id: "..." }, ...] }
};

/**
 * Delete an IPNS key from the Kubo node.
 *
 * @param {string} name   local key name
 * @returns {Promise<{Keys: Array<{Name:string, Id:string}>}>}
 */
SafecloudIpns.removeKey = function (name) {
    if (!_enabled) { return Promise.reject(new Error('IPNS not available')); }
    if (!name || typeof name !== 'string') {
        return Promise.reject(new Error('removeKey: name must be a non-empty string'));
    }
    return SafecloudIpfs.kuboPost('/api/v0/key/rm', { arg: name });
};

// ── Publishing and resolution ─────────────────────────────────────────────────

/**
 * Publish an IPFS CID under an IPNS key.
 *
 * Makes the content reachable at /ipns/<peerId> without distributing a
 * new CID to every consumer.
 *
 * @param {string} cid       IPFS CID to publish (e.g. "bafy...")
 * @param {Object} [opts]
 *   key       {string} local key name (default: "self")
 *   lifetime  {string} record TTL (default: "24h")
 *   ttl       {string} caching hint (default: "1m")
 * @returns {Promise<{Name:string, Value:string}>}
 *   Name  — "/ipns/k51…" (or /ipns/Qm… for legacy keys)
 *   Value — "/ipfs/<cid>" that this name now resolves to
 */
SafecloudIpns.publish = function (cid, opts) {
    if (!_enabled) { return Promise.reject(new Error('IPNS not available')); }
    if (!cid || typeof cid !== 'string') {
        return Promise.reject(new Error('publish: cid must be a non-empty string'));
    }
    opts = opts || {};
    return SafecloudIpfs.kuboPost('/api/v0/name/publish', {
        arg:      '/ipfs/' + cid,
        key:      opts.key      || 'self',
        lifetime: opts.lifetime || '24h',
        ttl:      opts.ttl      || '1m'
    });
    // Kubo response: { Name: "/ipns/k51…", Value: "/ipfs/Qm…" }
};

/**
 * Resolve an IPNS name to its current IPFS path.
 *
 * @param {string} name   IPNS name: "/ipns/k51…", "/ipns/Qm…",
 *                        or bare "k51…" (the /ipns/ prefix is added if missing)
 * @param {Object} [opts]
 *   recursive  {boolean} follow chains of IPNS records (default: true)
 *   nocache    {boolean} bypass local cache (default: false)
 * @returns {Promise<{Path:string}>}   e.g. { Path: "/ipfs/bafy..." }
 */
SafecloudIpns.resolve = function (name, opts) {
    if (!_enabled) { return Promise.reject(new Error('IPNS not available')); }
    if (!name || typeof name !== 'string') {
        return Promise.reject(new Error('resolve: name must be a non-empty string'));
    }
    opts = opts || {};
    // Accept bare peer IDs as well as full /ipns/… paths
    var arg = name.startsWith('/ipns/') ? name : ('/ipns/' + name);
    return SafecloudIpfs.kuboPost('/api/v0/name/resolve', {
        arg:       arg,
        recursive: opts.recursive === false ? 'false' : 'true',
        nocache:   opts.nocache             ? 'true'  : 'false'
    });
    // Kubo response: { Path: "/ipfs/bafy..." }
};
