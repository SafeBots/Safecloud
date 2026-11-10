'use strict';
/**
 * AttestationPolicy — declares and enforces what a room requires from a Safebox.
 *
 * A room owner sets a policy specifying:
 *   - which scanner WASM CID must be running
 *   - which TEE providers are acceptable
 *   - whether debug mode is permitted
 *   - (optional) that the scannerCID must be backed by an ML-DSA-65 PQClaim
 *   - (optional) that the Safebox governance claim carries a valid ML-DSA-65 sig
 *
 * When a Safebox joins the room, it presents an attestation document. Before
 * sharing epoch keys with it, the client verifies the document and checks the
 * result against this policy. A Safebox that fails the check is not admitted.
 *
 * PQ claim option (requirePQClaim)
 * ---------------------------------
 * When `requirePQClaim` is truthy, `evaluate()` takes an optional second
 * argument `{ pqClaim }`.  The claim must be a valid PQClaim signed by the
 * key at `pqTrustedKey` (if provided) and authorizing the same scannerCID.
 * This gives quantum-resistant scanner authorization on top of the classical
 * ES256/ES384 hardware attestation signatures that TEE providers issue.
 *
 * PQ attestation option (requirePQAttestation)
 * ---------------------------------------------
 * When `requirePQAttestation` is truthy, `evaluate()` additionally verifies
 * that the Safebox governance claim (the OpenClaim OCP document that authorized
 * the Safebox to operate) carries at least one valid ML-DSA-65 signature.
 * This uses AttestationVerifier.verifyMLDSASig() which degrades gracefully:
 * if @noble/post-quantum is not installed (older Qbix without the PQ patch)
 * the check fails with a clear "library unavailable" reason rather than
 * silently passing or crashing.
 *
 * Backward compatibility
 * ----------------------
 * Both new options default to null (falsy). Existing policies that set neither
 * see identical synchronous behavior — evaluate() still returns a plain object
 * for them.  evaluate() returns a Promise only when at least one async check is
 * needed (requirePQClaim or requirePQAttestation).  Callers should always
 * await the return value.
 *
 * @module Attestation/AttestationPolicy
 */

var PQClaim             = require('./PQClaim');
var AttestationVerifier = require('./AttestationVerifier');

var PQ_KEY_URI_PREFIX = 'data:key/ml-dsa-65;base64,';

/** Default set of accepted providers for a Safecloud room. */
var DEFAULT_PROVIDERS = ['nitro', 'gcp', 'azure', 'oci', 'sev_snp', 'tdx'];

/**
 * @class AttestationPolicy
 * @param {Object} opts
 * @param {string}   opts.scannerCID             Required: WASM CID of the scanner.
 * @param {string[]} [opts.providers]            Accepted providers (default: all six).
 * @param {boolean}  [opts.allowDebug]           Allow debug-mode enclaves (default: false).
 * @param {boolean}  [opts.requirePQClaim]       When true, evaluate() requires a valid
 *                                               ML-DSA-65 PQClaim for the scannerCID.
 *                                               Default: null (falsy).
 * @param {string}   [opts.pqTrustedKey]         If requirePQClaim is set, the PQClaim's
 *                                               pqPublicKey must equal this key URI.
 *                                               Format: "data:key/ml-dsa-65;base64,<b64>".
 *                                               Omit to accept any valid ML-DSA-65 sig.
 * @param {boolean}  [opts.requirePQAttestation] When true, evaluate() also verifies that
 *                                               the Safebox governance claim (opts.govClaim)
 *                                               contains at least one valid ML-DSA-65
 *                                               signature.  Gracefully fails with a
 *                                               distinct reason when @noble/post-quantum
 *                                               is unavailable (older Qbix).  Default: null.
 * @param {string[]} [opts.pqTrustedKeys]        If requirePQAttestation is set, only key
 *                                               URIs in this list are accepted.  Omit to
 *                                               accept any valid ML-DSA-65 sig in the claim.
 */
function AttestationPolicy(opts) {
    opts = opts || {};
    if (!opts.scannerCID) throw new Error('AttestationPolicy: scannerCID is required');

    this.scannerCID              = opts.scannerCID;
    this.providers               = opts.providers || DEFAULT_PROVIDERS.slice();
    this.allowDebug              = !!opts.allowDebug;
    this.requirePQClaim          = !!opts.requirePQClaim;
    this.pqTrustedKey            = opts.pqTrustedKey   || null;
    this.requirePQAttestation    = opts.requirePQAttestation || null;
    this.pqTrustedKeys           = opts.pqTrustedKeys  || null;
}

/**
 * Evaluate an attestation result against this policy.
 *
 * When `requirePQClaim` is set on the policy, opts.pqClaim must be provided.
 * When `requirePQAttestation` is set, opts.govClaim and opts.govClaimCanon
 * must be provided (the parsed governance OCP claim and its canonical UTF-8
 * text that was signed).
 *
 * Because the PQ checks are async, evaluate() returns a Promise whenever
 * requirePQClaim or requirePQAttestation is set.  For policies with neither,
 * it returns a plain synchronous object.  Callers should always await.
 *
 * @param {Object} result              Output of AttestationVerifier.verify().
 * @param {Object} [opts]
 * @param {Object} [opts.pqClaim]      Parsed PQClaim (required with requirePQClaim).
 * @param {Object} [opts.govClaim]     Parsed governance OCP claim with key[]/sig[] arrays
 *                                     (required with requirePQAttestation).
 * @param {string} [opts.govClaimCanon] Canonical UTF-8 text of the governance claim
 *                                     that was signed (required with requirePQAttestation).
 * @param {Date}   [opts.now]          Override current time (for tests).
 * @returns {Promise<{ pass: boolean, reason: string|null }>|{ pass: boolean, reason: string|null }}
 */
AttestationPolicy.prototype.evaluate = function (result, opts) {
    var policy     = this;
    var needsAsync = !!(policy.requirePQClaim || policy.requirePQAttestation);

    // -- synchronous checks first ------------------------------------------
    if (!result || !result.valid) {
        var r = { pass: false, reason: 'attestation verification failed: ' + (result && result.error || 'unknown') };
        return needsAsync ? Promise.resolve(r) : r;
    }

    if (policy.providers.indexOf(result.provider) === -1) {
        var r = { pass: false, reason: 'provider "' + result.provider + '" is not in the accepted set' };
        return needsAsync ? Promise.resolve(r) : r;
    }

    if (result.scannerCID !== policy.scannerCID) {
        var r = {
            pass:   false,
            reason: 'scanner CID mismatch: expected "' + policy.scannerCID
                  + '", got "' + result.scannerCID + '"'
        };
        return needsAsync ? Promise.resolve(r) : r;
    }

    if (!policy.allowDebug && result.claims && result.claims.debug) {
        var r = { pass: false, reason: 'debug-mode enclave is not permitted by policy' };
        return needsAsync ? Promise.resolve(r) : r;
    }

    // -- async checks -------------------------------------------------------
    if (!needsAsync) {
        return { pass: true, reason: null };
    }

    opts = opts || {};
    var checks = [];

    // Check A: requirePQClaim (scanner-authorization PQClaim)
    if (policy.requirePQClaim) {
        if (!opts.pqClaim) {
            return Promise.resolve({ pass: false, reason: 'policy requires a PQ claim but none was provided' });
        }
        checks.push(
            PQClaim.verify(opts.pqClaim, {
                scannerCID: policy.scannerCID,
                trustedKey: policy.pqTrustedKey || undefined,
                now:        opts.now
            }).then(function (pqResult) {
                if (!pqResult.valid) {
                    return { pass: false, reason: 'PQ claim invalid: ' + pqResult.error };
                }
                return { pass: true, reason: null };
            })
        );
    }

    // Check B: requirePQAttestation (ML-DSA-65 sig in governance OpenClaim)
    if (policy.requirePQAttestation) {
        checks.push(_checkPQAttestation(policy, opts));
    }

    return Promise.all(checks).then(function (results) {
        for (var i = 0; i < results.length; i++) {
            if (!results[i].pass) return results[i];
        }
        return { pass: true, reason: null };
    });
};

/**
 * Serialize to a plain object (for storage in room state / epoch protocol).
 * @returns {Object}
 */
AttestationPolicy.prototype.toJSON = function () {
    var obj = {
        scannerCID: this.scannerCID,
        providers:  this.providers,
        allowDebug: this.allowDebug
    };
    if (this.requirePQClaim) {
        obj.requirePQClaim = true;
        if (this.pqTrustedKey) obj.pqTrustedKey = this.pqTrustedKey;
    }
    if (this.requirePQAttestation) {
        obj.requirePQAttestation = true;
        if (this.pqTrustedKeys) obj.pqTrustedKeys = this.pqTrustedKeys;
    }
    return obj;
};

/**
 * Restore from a plain object.
 * @param {Object} obj
 * @returns {AttestationPolicy}
 */
AttestationPolicy.fromJSON = function (obj) {
    return new AttestationPolicy(obj);
};

// ── Private helpers ────────────────────────────────────────────────────────────

/**
 * Verify that the governance OpenClaim carries at least one valid ML-DSA-65
 * signature.  Uses AttestationVerifier.verifyMLDSASig() for graceful
 * degradation when @noble/post-quantum is absent (older Qbix).
 *
 * @param {AttestationPolicy} policy
 * @param {Object} opts
 * @param {Object} opts.govClaim       Parsed OCP governance claim with key[]/sig[] arrays.
 * @param {string} opts.govClaimCanon  Canonical UTF-8 text signed by each key.
 * @returns {Promise<{ pass: boolean, reason: string|null }>}
 */
function _checkPQAttestation(policy, opts) {
    var govClaim      = opts.govClaim;
    var govClaimCanon = opts.govClaimCanon;

    if (!govClaim || !govClaimCanon) {
        return Promise.resolve({
            pass:   false,
            reason: 'requirePQAttestation: opts.govClaim and opts.govClaimCanon are required'
        });
    }

    var keys = Array.isArray(govClaim.key) ? govClaim.key : [];
    var sigs = Array.isArray(govClaim.sig) ? govClaim.sig : [];

    // Collect (pkB64, sigB64) pairs for ML-DSA-65 keys, filtered by trustedKeys if set
    var pqPairs = [];
    for (var i = 0; i < keys.length; i++) {
        var keyUri = typeof keys[i] === 'string' ? keys[i] : null;
        if (!keyUri || keyUri.indexOf(PQ_KEY_URI_PREFIX) !== 0) continue;
        if (policy.pqTrustedKeys && policy.pqTrustedKeys.indexOf(keyUri) === -1) continue;
        if (!sigs[i]) continue;
        pqPairs.push({ pkB64: keyUri.slice(PQ_KEY_URI_PREFIX.length), sigB64: sigs[i] });
    }

    if (pqPairs.length === 0) {
        return Promise.resolve({
            pass:   false,
            reason: 'requirePQAttestation: no ML-DSA-65 key/signature pairs found in governance claim'
                  + (policy.pqTrustedKeys ? ' matching the trusted key list' : '')
        });
    }

    return Promise.all(pqPairs.map(function (pair) {
        return AttestationVerifier.verifyMLDSASig(pair.sigB64, govClaimCanon, pair.pkB64);
    })).then(function (results) {
        if (results.some(function (r) { return r.ok; })) {
            return { pass: true, reason: null };
        }
        // Distinguish "library missing" from "all sigs bad"
        if (results.some(function (r) { return !r.available; })) {
            return {
                pass:   false,
                reason: 'requirePQAttestation: ML-DSA-65 library unavailable on this Qbix version'
                      + ' — install @noble/post-quantum ^0.7.1 or disable requirePQAttestation'
            };
        }
        return {
            pass:   false,
            reason: 'requirePQAttestation: no valid ML-DSA-65 signature found in governance claim'
        };
    });
}

module.exports = AttestationPolicy;
