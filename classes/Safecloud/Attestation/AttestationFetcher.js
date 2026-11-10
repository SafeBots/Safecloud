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
 *   checkLiveness(safeboxUrl, govClaimCanon, govClaimKeys)
 *                               → { live: boolean, reason: string|null }
 *
 * All fetches time out after opts.timeoutMs (default 10 000).
 *
 * Liveness check (challenge-response)
 * ------------------------------------
 * When `opts.livenessCheck` is set, checkLiveness() POSTs a 32-byte nonce to
 * `{safeboxUrl}/attestation/challenge` and verifies the ML-DSA-65 response
 * signature over SHA-256(nonce || canonical_claim_bytes).  This proves the
 * Safebox TEE is alive and holds the signing key that issued the governance
 * claim — not a replay of a cached attestation document.
 *
 * Three-state option (default null = disabled):
 *   null / false  — no liveness call; checkLiveness() resolves immediately.
 *   true          — attempt check; 404/timeout/library-missing → warn + continue.
 *   'strict'      — check required; any failure rejects the claim.
 *
 * Old Safeboxes without the /attestation/challenge endpoint are unaffected
 * when livenessCheck is at its default (null/false).
 *
 * @module Attestation/AttestationFetcher
 */

var AttestationVerifier = require('./AttestationVerifier');

var DEFAULT_TIMEOUT     = 10000; // ms
var LIVENESS_TIMEOUT    = 5000;  // ms — tighter budget for challenge-response
var PQ_KEY_URI_PREFIX   = 'data:key/ml-dsa-65;base64,';

/**
 * @class AttestationFetcher
 * @param {TrustStore} trustStore  Provides default endpoint URLs.
 * @param {Object} [opts]
 * @param {number}          [opts.timeoutMs]     Request timeout in ms (default 10 000).
 * @param {Map}             [opts.cache]         Optional pre-populated cache (key → value).
 * @param {null|true|'strict'} [opts.livenessCheck]
 *   null/false = disabled (default); true = attempt, warn on failure;
 *   'strict'   = required, reject on failure.
 */
function AttestationFetcher(trustStore, opts) {
    opts = opts || {};
    this.trustStore    = trustStore || {};
    this.timeoutMs     = opts.timeoutMs || DEFAULT_TIMEOUT;
    this._cache        = opts.cache || new Map();
    this.livenessCheck = opts.livenessCheck || null;
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

// ── Liveness check ────────────────────────────────────────────────────────────

/**
 * Challenge-response liveness check.
 *
 * Posts a 32-byte random nonce to `{safeboxUrl}/attestation/challenge` and
 * verifies the Safebox's ML-DSA-65 signature over SHA-256(nonce || claim_bytes).
 * This proves the Safebox TEE is live and holds the signing key — it cannot
 * replay a cached attestation document.
 *
 * Behavior depends on `this.livenessCheck`:
 *   null / false — returns { live: true, reason: null } immediately (no-op).
 *   true         — attempts check; unreachable / bad sig / no PQ lib → warn + live.
 *   'strict'     — any failure returns { live: false, reason: '...' }.
 *
 * @param {string}   safeboxUrl     Base URL of the Safebox (no trailing slash needed).
 * @param {string}   govClaimCanon  Canonical UTF-8 text of the governance claim.
 * @param {string[]} govClaimKeys   key[] array from the governance OCP claim.
 * @returns {Promise<{ live: boolean, reason: string|null }>}
 */
AttestationFetcher.prototype.checkLiveness = function (safeboxUrl, govClaimCanon, govClaimKeys) {
    var mode = this.livenessCheck;
    if (!mode) return Promise.resolve({ live: true, reason: null });

    var self     = this;
    var crypto   = require('crypto');
    var nonceHex = crypto.randomBytes(32).toString('hex');
    var url      = safeboxUrl.replace(/\/$/, '') + '/attestation/challenge';

    return _post(url, JSON.stringify({ nonce: nonceHex }), LIVENESS_TIMEOUT)
        .then(function (body) {
            var resp = JSON.parse(typeof body === 'string' ? body : body.toString('utf8'));
            if (!resp.signature) throw new Error('no signature in liveness response');

            // digest = SHA-256(nonce_bytes || claim_bytes)
            var nonceBytes = Buffer.from(nonceHex, 'hex');
            var claimBytes = Buffer.from(govClaimCanon, 'utf8');
            var digest     = crypto.createHash('sha256')
                .update(nonceBytes).update(claimBytes).digest();

            // Find the first ML-DSA-65 key in the governance claim
            var pqKeys = (govClaimKeys || []).filter(function (k) {
                return typeof k === 'string' && k.indexOf(PQ_KEY_URI_PREFIX) === 0;
            });

            if (pqKeys.length === 0) {
                throw new Error('no ML-DSA-65 key found in governance claim for liveness check');
            }

            var pkB64 = pqKeys[0].slice(PQ_KEY_URI_PREFIX.length);
            return AttestationVerifier.verifyMLDSASig(resp.signature, digest, pkB64);
        })
        .then(function (result) {
            if (!result.available) {
                if (mode === 'strict') {
                    return { live: false, reason: 'liveness requires ML-DSA-65 but @noble/post-quantum is unavailable' };
                }
                console.warn('[AttestationFetcher] liveness: ML-DSA-65 library unavailable, skipping check');
                return { live: true, reason: null };
            }
            if (!result.ok) {
                if (mode === 'strict') {
                    return { live: false, reason: 'liveness signature invalid: ' + result.error };
                }
                console.warn('[AttestationFetcher] liveness: signature check failed (' + result.error + '), continuing');
                return { live: true, reason: null };
            }
            return { live: true, reason: null };
        })
        .catch(function (e) {
            if (mode === 'strict') {
                return { live: false, reason: 'liveness endpoint unreachable: ' + (e && e.message) };
            }
            console.warn('[AttestationFetcher] liveness: endpoint unreachable (' + (e && e.message) + '), skipping');
            return { live: true, reason: null };
        });
};

// ── Internal ──────────────────────────────────────────────────────────────────

/**
 * HTTP POST that works in Node.js (https module) and browsers (fetch API).
 * Sends JSON body; returns the response body as a Buffer (Node) or string (browser).
 *
 * @param {string} url
 * @param {string} body  Serialized JSON string.
 * @param {number} timeoutMs
 * @returns {Promise<Buffer|string>}
 */
function _post(url, body, timeoutMs) {
    // Browser environment
    if (typeof window !== 'undefined' && typeof window.fetch === 'function') {
        var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        var timer = controller
            ? setTimeout(function () { controller.abort(); }, timeoutMs)
            : null;
        return window.fetch(url, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    body,
            signal:  controller ? controller.signal : undefined
        }).then(function (res) {
            if (timer) clearTimeout(timer);
            if (!res.ok) throw new Error('POST ' + url + ': HTTP ' + res.status);
            return res.text();
        });
    }

    // Node.js environment
    return new Promise(function (resolve, reject) {
        var https   = require('https');
        var http    = require('http');
        var parsed  = require('url').parse(url);
        var bodyBuf = Buffer.from(body, 'utf8');
        var mod     = url.startsWith('https') ? https : http;
        var options = {
            hostname: parsed.hostname,
            port:     parsed.port,
            path:     parsed.path,
            method:   'POST',
            headers: {
                'Content-Type':   'application/json',
                'Content-Length': bodyBuf.length
            }
        };
        var chunks = [];
        var req    = mod.request(options, function (res) {
            if (res.statusCode < 200 || res.statusCode >= 300) {
                return reject(new Error('POST ' + url + ': HTTP ' + res.statusCode));
            }
            res.on('data', function (c) { chunks.push(c); });
            res.on('end',  function ()  { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
        });
        var timer = setTimeout(function () { req.destroy(new Error('timeout')); }, timeoutMs);
        req.on('error', function (e) { clearTimeout(timer); reject(e); });
        req.write(bodyBuf);
        req.end();
    });
}

module.exports = AttestationFetcher;
