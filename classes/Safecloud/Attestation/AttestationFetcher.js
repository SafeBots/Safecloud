'use strict';
/**
 * AttestationFetcher — network layer for attestation verification.
 *
 * Fetches the external keys/certs that AttestationVerifier needs but cannot
 * reach itself. All methods return Promises and are safe to cache.
 *
 * Used on both the Jet side (Node.js) and the Safecloud client (browser via
 * fetch API). Node.js uses https.get; browser uses window.fetch. Both are
 * wrapped by _get() below.
 *
 * Methods:
 *   fetchGCPJwks(url?)          → { keys: [...] }
 *   fetchAzureJwks(url?)        → { keys: [...] }
 *   fetchVeraisonKey(url)       → crypto.KeyObject  (ES256, P-256)
 *   fetchVCEKCert(product, chipId, tcb) → Buffer (DER)  — AMD SEV-SNP chip cert
 *   fetchIntelRootCA()          → Buffer (DER)  — Intel SGX Root CA
 *
 * All fetches time out after opts.timeoutMs (default 10 000).
 *
 * @module Attestation/AttestationFetcher
 */

var DEFAULT_TIMEOUT = 10000; // ms

/**
 * @class AttestationFetcher
 * @param {TrustStore} trustStore  Provides default endpoint URLs.
 * @param {Object} [opts]
 * @param {number} [opts.timeoutMs]  Request timeout in ms (default 10 000).
 * @param {Map}    [opts.cache]      Optional pre-populated cache (key → value).
 */
function AttestationFetcher(trustStore, opts) {
    opts = opts || {};
    this.trustStore  = trustStore || {};
    this.timeoutMs   = opts.timeoutMs || DEFAULT_TIMEOUT;
    this._cache      = opts.cache || new Map();
}

// ── GCP ───────────────────────────────────────────────────────────────────────

/**
 * Fetch GCP Confidential Space JWKS.
 * @param {string} [url]  Override the default JWKS URL from TrustStore.
 * @returns {Promise<Object>} JWKS { keys: [...] }
 */
AttestationFetcher.prototype.fetchGCPJwks = function (url) {
    url = url || this.trustStore.gcpJwksUrl;
    return this._cachedGet(url, _parseJSON);
};

// ── Azure ─────────────────────────────────────────────────────────────────────

/**
 * Fetch Azure MAA JWKS.
 * @param {string} [url]  Override the default MAA certs URL from TrustStore.
 * @returns {Promise<Object>} JWKS { keys: [...] }
 */
AttestationFetcher.prototype.fetchAzureJwks = function (url) {
    url = url || this.trustStore.azureJwksUrl;
    return this._cachedGet(url, _parseJSON);
};

// ── OCI / Veraison ────────────────────────────────────────────────────────────

/**
 * Fetch the Veraison service's ES256 public key from its JWKS endpoint.
 * @param {string} url  Veraison JWKS URL (region-specific).
 * @returns {Promise<crypto.KeyObject>}
 */
AttestationFetcher.prototype.fetchVeraisonKey = function (url) {
    if (!url) return Promise.reject(new Error('fetchVeraisonKey: url is required'));
    return this._cachedGet(url, function (body) {
        var jwks = JSON.parse(body);
        var keys = jwks.keys || [jwks];
        // Take the first ES256 key.
        var jwk  = keys.filter(function (k) { return k.alg === 'ES256' || k.crv === 'P-256'; })[0];
        if (!jwk) throw new Error('fetchVeraisonKey: no ES256 key found in JWKS');
        return require('crypto').createPublicKey({ key: jwk, format: 'jwk' });
    });
};

// ── AMD SEV-SNP VCEK ──────────────────────────────────────────────────────────

/**
 * Fetch the VCEK certificate for a specific AMD chip from AMD's KDS.
 *
 * AMD Key Distribution Service URL pattern:
 *   https://kdsintf.amd.com/vcek/v1/{product}/{chipId}?blSPL={bl}&teeSPL={tee}&...
 *
 * @param {string} product  Processor product name: 'Milan', 'Genoa', 'Turin', ...
 * @param {string} chipId   64-byte chip ID as hex string.
 * @param {Object} tcb      TCB version components: { blSPL, teeSPL, snpSPL, ucodeSPL }
 * @returns {Promise<Buffer>} DER-encoded VCEK certificate.
 */
AttestationFetcher.prototype.fetchVCEKCert = function (product, chipId, tcb) {
    tcb = tcb || {};
    var params = [
        'blSPL='    + (tcb.blSPL    || 0),
        'teeSPL='   + (tcb.teeSPL   || 0),
        'snpSPL='   + (tcb.snpSPL   || 0),
        'ucodeSPL=' + (tcb.ucodeSPL || 0)
    ].join('&');
    var url = 'https://kdsintf.amd.com/vcek/v1/' + product + '/' + chipId + '?' + params;
    return this._cachedGet(url, _parseBinary);
};

// ── Intel SGX/TDX Root CA ─────────────────────────────────────────────────────

/**
 * Fetch the Intel SGX Attestation Root CA (DER).
 * This cert is stable and should be pinned after first fetch.
 * @returns {Promise<Buffer>}
 */
AttestationFetcher.prototype.fetchIntelRootCA = function () {
    var url = 'https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.der';
    return this._cachedGet(url, _parseBinary);
};

// ── Internal ──────────────────────────────────────────────────────────────────

AttestationFetcher.prototype._cachedGet = function (url, transform) {
    var self  = this;
    var cached = self._cache.get(url);
    if (cached !== undefined) return Promise.resolve(cached);
    return _get(url, self.timeoutMs).then(function (body) {
        var value = transform(body);
        self._cache.set(url, value);
        return value;
    });
};

function _parseJSON(body) {
    return JSON.parse(typeof body === 'string' ? body : body.toString('utf8'));
}

function _parseBinary(body) {
    return Buffer.isBuffer(body) ? body : Buffer.from(body);
}

/**
 * HTTP GET that works in Node.js (https module) and browsers (fetch API).
 * Returns the body as a Buffer (Node) or string (browser).
 */
function _get(url, timeoutMs) {
    // Browser environment
    if (typeof window !== 'undefined' && typeof window.fetch === 'function') {
        var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        var timer = controller
            ? setTimeout(function () { controller.abort(); }, timeoutMs)
            : null;
        return window.fetch(url, controller ? { signal: controller.signal } : {})
            .then(function (res) {
                if (timer) clearTimeout(timer);
                if (!res.ok) throw new Error('fetch ' + url + ': HTTP ' + res.status);
                return res.text();
            });
    }

    // Node.js environment
    return new Promise(function (resolve, reject) {
        var https   = require('https');
        var http    = require('http');
        var mod     = url.startsWith('https') ? https : http;
        var timer   = setTimeout(function () { req.destroy(new Error('timeout')); }, timeoutMs);
        var chunks  = [];
        var req     = mod.get(url, function (res) {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                clearTimeout(timer);
                return resolve(_get(res.headers.location, timeoutMs));
            }
            if (res.statusCode < 200 || res.statusCode >= 300) {
                return reject(new Error('GET ' + url + ': HTTP ' + res.statusCode));
            }
            res.on('data', function (c) { chunks.push(c); });
            res.on('end',  function ()  {
                clearTimeout(timer);
                resolve(Buffer.concat(chunks));
            });
        });
        req.on('error', function (e) { clearTimeout(timer); reject(e); });
    });
}

module.exports = AttestationFetcher;
