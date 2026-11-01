'use strict';
/**
 * AttestationPolicy — declares and enforces what a room requires from a Safebox.
 *
 * A room owner sets a policy specifying:
 *   - which scanner WASM CID must be running
 *   - which TEE providers are acceptable
 *   - whether debug mode is permitted
 *   - (optional) that the scannerCID must be backed by an ML-DSA-65 PQClaim
 *
 * When a Safebox joins the room, it presents an attestation document. Before
 * sharing epoch keys with it, the client verifies the document and checks the
 * result against this policy. A Safebox that fails the check is not admitted.
 *
 * PQ claim option
 * ---------------
 * When `requirePQClaim` is truthy, `evaluate()` takes an optional second
 * argument `{ pqClaim }`.  The claim must be a valid PQClaim signed by the
 * key at `pqTrustedKey` (if provided) and authorizing the same scannerCID.
 * This gives quantum-resistant scanner authorization on top of the classical
 * ES256/ES384 hardware attestation signatures that TEE providers issue.
 *
 * @module Attestation/AttestationPolicy
 */

var PQClaim = require('./PQClaim');

/** Default set of accepted providers for a Safecloud room. */
var DEFAULT_PROVIDERS = ['nitro', 'gcp', 'azure', 'oci', 'sev_snp', 'tdx'];

/**
 * @class AttestationPolicy
 * @param {Object} opts
 * @param {string}   opts.scannerCID        Required: WASM CID of the scanner.
 * @param {string[]} [opts.providers]       Accepted providers (default: all six).
 * @param {boolean}  [opts.allowDebug]      Allow debug-mode enclaves (default: false).
 * @param {boolean}  [opts.requirePQClaim]  When true, evaluate() requires a valid
 *                                          ML-DSA-65 PQClaim for the scannerCID.
 *                                          Default: false.
 * @param {string}   [opts.pqTrustedKey]   If requirePQClaim is set, the PQClaim's
 *                                          pqPublicKey must equal this key URI.
 *                                          Format: "data:key/ml-dsa-65;base64,<b64>".
 *                                          Omit to accept any valid ML-DSA-65 signature.
 */
function AttestationPolicy(opts) {
    opts = opts || {};
    if (!opts.scannerCID) throw new Error('AttestationPolicy: scannerCID is required');

    this.scannerCID     = opts.scannerCID;
    this.providers      = opts.providers || DEFAULT_PROVIDERS.slice();
    this.allowDebug     = !!opts.allowDebug;
    this.requirePQClaim = !!opts.requirePQClaim;
    this.pqTrustedKey   = opts.pqTrustedKey || null;
}

/**
 * Evaluate an attestation result against this policy.
 *
 * When `requirePQClaim` is set on the policy, opts.pqClaim must be provided
 * and must be a valid PQClaim signed by the trusted issuer key.  Because
 * PQClaim.verify() is async, this method is async when requirePQClaim is set
 * and synchronous otherwise.  Callers should always await the return value.
 *
 * @param {Object} result   The output of AttestationVerifier.verify().
 * @param {Object} [opts]
 * @param {Object} [opts.pqClaim]  Parsed PQClaim object (required when requirePQClaim is set).
 * @param {Date}   [opts.now]      Override current time (for tests).
 * @returns {Promise<{ pass: boolean, reason: string|null }>|{ pass: boolean, reason: string|null }}
 */
AttestationPolicy.prototype.evaluate = function (result, opts) {
    var policy = this;

    // -- synchronous checks first ------------------------------------------
    if (!result || !result.valid) {
        var syncResult = { pass: false, reason: 'attestation verification failed: ' + (result && result.error || 'unknown') };
        return policy.requirePQClaim ? Promise.resolve(syncResult) : syncResult;
    }

    if (policy.providers.indexOf(result.provider) === -1) {
        var syncResult = { pass: false, reason: 'provider "' + result.provider + '" is not in the accepted set' };
        return policy.requirePQClaim ? Promise.resolve(syncResult) : syncResult;
    }

    if (result.scannerCID !== policy.scannerCID) {
        var syncResult = {
            pass:   false,
            reason: 'scanner CID mismatch: expected "' + policy.scannerCID
                  + '", got "' + result.scannerCID + '"'
        };
        return policy.requirePQClaim ? Promise.resolve(syncResult) : syncResult;
    }

    if (!policy.allowDebug && result.claims && result.claims.debug) {
        var syncResult = { pass: false, reason: 'debug-mode enclave is not permitted by policy' };
        return policy.requirePQClaim ? Promise.resolve(syncResult) : syncResult;
    }

    // -- PQ claim check (async) --------------------------------------------
    if (!policy.requirePQClaim) {
        return { pass: true, reason: null };
    }

    opts = opts || {};
    var pqClaim = opts.pqClaim;
    if (!pqClaim) {
        return Promise.resolve({ pass: false, reason: 'policy requires a PQ claim but none was provided' });
    }

    return PQClaim.verify(pqClaim, {
        scannerCID: policy.scannerCID,
        trustedKey: policy.pqTrustedKey || undefined,
        now:        opts.now
    }).then(function (pqResult) {
        if (!pqResult.valid) {
            return { pass: false, reason: 'PQ claim invalid: ' + pqResult.error };
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

module.exports = AttestationPolicy;
