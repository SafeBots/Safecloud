'use strict';
/**
 * PQClaim — ML-DSA-65 post-quantum scanner-authorization claims for Safecloud.
 *
 * A PQClaim is a self-contained JSON object that a policy issuer signs with
 * their ML-DSA-65 (FIPS 204) private key to authorize a specific scannerCID.
 * AttestationPolicy can require a valid PQClaim alongside a TEE attestation
 * result, giving quantum-resistant scanner authorization on top of the
 * classical ES256/ES384 signatures that TEE hardware providers issue.
 *
 * Claim schema
 * ------------
 *   {
 *     "v":          1,
 *     "action":     "approve-scanner",
 *     "scannerCID": "<CID string>",
 *     "issued":     "<ISO 8601 UTC>",
 *     "expires":    "<ISO 8601 UTC>",
 *     "pqPublicKey":"data:key/ml-dsa-65;base64,<1952-byte raw public key>",
 *     "pqSig":      "<base64url ML-DSA-65 signature over canonical bytes>"
 *   }
 *
 * Canonical bytes = UTF-8 encoding of a JSON object containing every field
 * EXCEPT pqSig, with keys sorted lexicographically and no extra whitespace.
 *
 * Key URI format matches Qbix platform Q.Crypto convention:
 *   data:key/ml-dsa-65;base64,<raw 1952-byte public key as standard base64>
 *
 * Why ML-DSA-65?  ECDSA (ES256, used by all six TEE providers) is broken by
 * Shor's algorithm on a quantum computer.  HKDF and AES-256 are unaffected
 * (Grover gives only a √ speedup, leaving 128-bit effective security).
 * ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) is lattice-based and resists
 * Shor.  Hybrid attestation carries both the hardware ES256/ES384 attestation
 * and a PQClaim so the authorization chain remains valid when quantum
 * computers become capable of breaking elliptic-curve discrete log.
 *
 * @module Attestation/PQClaim
 */

var PK_PREFIX  = 'data:key/ml-dsa-65;base64,';
var PK_SIZE    = 1952;   // bytes
var SIG_SIZE   = 3309;   // bytes

/** Lazy-cached ESM import of @noble/post-quantum. */
var _mlDsaPromise = null;
function _getMlDsa() {
    if (!_mlDsaPromise) {
        _mlDsaPromise = import('@noble/post-quantum/ml-dsa.js');
    }
    return _mlDsaPromise;
}

/**
 * Parse a public key URI into a Buffer.
 * @param {string} keyString  "data:key/ml-dsa-65;base64,<b64>"
 * @returns {Buffer}
 */
function _parsePublicKey(keyString) {
    if (typeof keyString !== 'string' || !keyString.startsWith(PK_PREFIX)) {
        throw new Error('PQClaim: pqPublicKey must start with "' + PK_PREFIX + '"');
    }
    var buf = Buffer.from(keyString.slice(PK_PREFIX.length), 'base64');
    if (buf.length !== PK_SIZE) {
        throw new Error('PQClaim: pqPublicKey must be ' + PK_SIZE + ' bytes, got ' + buf.length);
    }
    return buf;
}

/**
 * Produce the canonical bytes that are signed / verified.
 * All fields except pqSig, keys sorted, no whitespace.
 * @param {Object} claim
 * @returns {Uint8Array}
 */
function _canonicalBytes(claim) {
    var obj = {
        action:     claim.action,
        expires:    claim.expires,
        issued:     claim.issued,
        pqPublicKey: claim.pqPublicKey,
        scannerCID: claim.scannerCID,
        v:          claim.v
    };
    // Keys are already sorted in the literal above; JSON.stringify preserves
    // insertion order in every conforming ES2015+ engine.
    return new TextEncoder().encode(JSON.stringify(obj));
}

/**
 * Create a signed PQClaim.
 *
 * @param {Object} opts
 * @param {string}   opts.scannerCID   The CID being authorized.
 * @param {string}   opts.pqPublicKey  The issuer's public key URI.
 * @param {Buffer|Uint8Array} opts.pqSecretKey  The issuer's 4032-byte secret key.
 * @param {number}   [opts.ttlSeconds] Validity window in seconds (default: 30 days).
 * @returns {Promise<Object>} Signed claim object ready to be serialized.
 */
PQClaim.sign = async function (opts) {
    if (!opts || !opts.scannerCID)  throw new Error('PQClaim.sign: scannerCID required');
    if (!opts.pqPublicKey)          throw new Error('PQClaim.sign: pqPublicKey required');
    if (!opts.pqSecretKey)          throw new Error('PQClaim.sign: pqSecretKey required');

    var ttl     = (opts.ttlSeconds != null ? opts.ttlSeconds : 30 * 24 * 3600);
    var now     = new Date();
    var expires = new Date(now.getTime() + ttl * 1000);

    var claim = {
        v:          1,
        action:     'approve-scanner',
        scannerCID: opts.scannerCID,
        issued:     now.toISOString(),
        expires:    expires.toISOString(),
        pqPublicKey: opts.pqPublicKey
    };

    var canonBytes = _canonicalBytes(claim);
    var mod = await _getMlDsa();
    var sigBytes = mod.ml_dsa65.sign(canonBytes, opts.pqSecretKey);

    claim.pqSig = Buffer.from(sigBytes).toString('base64');
    return claim;
};

/**
 * Verify a PQClaim.
 *
 * Checks:
 *   1. Schema (v, action, fields present)
 *   2. Not expired
 *   3. scannerCID matches the expected value
 *   4. ML-DSA-65 signature over canonical bytes
 *   5. Public key matches the trusted issuer key (when provided)
 *
 * @param {Object} claim  The claim object (parsed JSON).
 * @param {Object} opts
 * @param {string}   opts.scannerCID       Expected scanner CID.
 * @param {string}   [opts.trustedKey]     If provided, pqPublicKey must equal this.
 * @param {Date}     [opts.now]            Override current time (for tests).
 * @returns {Promise<{ valid: boolean, error?: string }>}
 */
PQClaim.verify = async function (claim, opts) {
    opts = opts || {};
    try {
        // 1. Schema
        if (!claim || claim.v !== 1 || claim.action !== 'approve-scanner') {
            return { valid: false, error: 'PQClaim: invalid schema (v or action)' };
        }
        if (!claim.scannerCID || !claim.pqPublicKey || !claim.pqSig
                || !claim.issued || !claim.expires) {
            return { valid: false, error: 'PQClaim: missing required field' };
        }

        // 2. Expiry
        var now = opts.now || new Date();
        if (now > new Date(claim.expires)) {
            return { valid: false, error: 'PQClaim: claim expired at ' + claim.expires };
        }
        if (now < new Date(claim.issued)) {
            return { valid: false, error: 'PQClaim: claim issued in the future' };
        }

        // 3. scannerCID match
        if (claim.scannerCID !== opts.scannerCID) {
            return {
                valid: false,
                error: 'PQClaim: scannerCID mismatch: expected "'
                     + opts.scannerCID + '", got "' + claim.scannerCID + '"'
            };
        }

        // 4. Trusted key check (optional)
        if (opts.trustedKey && claim.pqPublicKey !== opts.trustedKey) {
            return { valid: false, error: 'PQClaim: pqPublicKey does not match trusted issuer key' };
        }

        // 5. ML-DSA-65 signature
        var pk       = _parsePublicKey(claim.pqPublicKey);
        var sigBytes = Buffer.from(claim.pqSig, 'base64');
        if (sigBytes.length !== SIG_SIZE) {
            return { valid: false, error: 'PQClaim: pqSig must be ' + SIG_SIZE + ' bytes, got ' + sigBytes.length };
        }
        var canonBytes = _canonicalBytes(claim);
        var mod    = await _getMlDsa();
        var ok     = mod.ml_dsa65.verify(sigBytes, canonBytes, pk);

        if (!ok) {
            return { valid: false, error: 'PQClaim: ML-DSA-65 signature verification failed' };
        }

        return { valid: true };

    } catch (e) {
        return { valid: false, error: 'PQClaim: unexpected error: ' + e.message };
    }
};

/**
 * @class PQClaim
 * Namespace object — all methods are static; this constructor is not used.
 */
function PQClaim() {}

module.exports = PQClaim;
