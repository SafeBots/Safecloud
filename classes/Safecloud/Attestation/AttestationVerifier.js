'use strict';
/**
 * AttestationVerifier — pure, network-free attestation document verifier.
 *
 * Takes a raw attestation document (Buffer or JWT string) plus pre-resolved
 * keys/certs (from AttestationFetcher or from TrustStore) and returns a
 * structured result. Never makes network calls itself.
 *
 * Supports six providers:
 *   'nitro'   — AWS Nitro Enclaves (COSE_Sign1, ES384, P-384 cert chain)
 *   'gcp'     — GCP Confidential Space (JWT, RS256, JWKS)
 *   'azure'   — Azure MAA (JWT, RS256, JWKS)
 *   'oci'     — OCI/Veraison (JWT/EAR, ES256, Veraison public key)
 *   'sev_snp' — Raw AMD SEV-SNP (binary, ES384, VCEK cert chain)
 *   'tdx'     — Raw Intel TDX (binary quote, ES256, AK + PCK cert chain)
 *
 * Static helpers:
 *   AttestationVerifier.verifyMLDSASig(sigB64, msg, pkB64)
 *     Verify a single ML-DSA-65 signature with graceful degradation when
 *     @noble/post-quantum is not installed (older Qbix without the PQ patch).
 *     Returns { ok, available, error } — distinguishes "library missing"
 *     from "signature bad" so callers can emit the right diagnostic.
 *
 * Usage:
 *   var verifier  = new AttestationVerifier(trustStore);
 *   var result    = await verifier.verify('nitro', doc, resolvedKeys);
 *   // result.valid === true, result.scannerCID === 'bafybeig...'
 *
 * @module Attestation/AttestationVerifier
 */

var Nitro   = require('./providers/Nitro');
var GCP     = require('./providers/GCP');
var Azure   = require('./providers/Azure');
var OCI     = require('./providers/OCI');
var SEV_SNP = require('./providers/SEV_SNP');
var TDX     = require('./providers/TDX');

// ── ML-DSA-65 lazy loader ──────────────────────────────────────────────────────
// Cached after first successful import.  If @noble/post-quantum is not
// installed (older Qbix without the PQ patch) the import throws — the
// catch path in verifyMLDSASig returns { available: false } instead of
// crashing the caller.
var _mlDsaModule = null;

function _getMlDsa() {
    if (_mlDsaModule) return Promise.resolve(_mlDsaModule);
    // ESM-only package — must use dynamic import
    return import('@noble/post-quantum/ml-dsa.js').then(function (mod) {
        _mlDsaModule = mod;
        return mod;
    });
}

var PROVIDERS = ['nitro', 'gcp', 'azure', 'oci', 'sev_snp', 'tdx'];

/**
 * @class AttestationVerifier
 * @param {TrustStore} trustStore  Pinned roots and JWKS URLs.
 */
function AttestationVerifier(trustStore) {
    this.trustStore = trustStore;
}

/**
 * Verify an attestation document.
 *
 * @param {string} provider
 *   One of: 'nitro' | 'gcp' | 'azure' | 'oci' | 'sev_snp' | 'tdx'
 * @param {Buffer|string} doc
 *   The raw attestation document. Buffer for nitro/sev_snp/tdx, JWT string for
 *   gcp/azure/oci.
 * @param {Object} keys
 *   Pre-resolved keys/certs for this provider:
 *     nitro:   { trustedRoot: Buffer } (DER of Nitro root CA)
 *     gcp:     { jwks: Object }        (JWKS from GCP endpoint)
 *     azure:   { jwks: Object }        (JWKS from MAA endpoint)
 *     oci:     { veraisonKey: KeyObject|JWK }
 *     sev_snp: { vcekCertDER: Buffer, amdRootDER: Buffer }
 *     tdx:     { intelRootDER: Buffer }
 * @param {Object} [opts]
 * @param {boolean} [opts.skipExpiry]   Skip timestamp/exp checks.
 * @param {boolean} [opts.skipChain]    Skip cert chain (sev_snp/tdx tests).
 * @param {Object}  [opts.akKey]        Pre-loaded AK key (tdx tests).
 * @param {Object}  [opts.vcekKey]      Pre-loaded VCEK key (sev_snp tests).
 * @returns {Promise<AttestationResult>}
 */
AttestationVerifier.prototype.verify = function (provider, doc, keys, opts) {
    var self = this;
    opts = opts || {};
    keys = keys || {};

    return Promise.resolve().then(function () {
        if (PROVIDERS.indexOf(provider) === -1) {
            throw new Error('AttestationVerifier: unknown provider "' + provider + '"');
        }

        var ts = self.trustStore || {};
        var claims;

        switch (provider) {
            case 'nitro':
                var nitroRoot = keys.trustedRoot || ts.nitroRoot;
                if (!nitroRoot) throw new Error('nitro: no trusted root provided');
                claims = Nitro.verify(doc, nitroRoot, opts);
                break;

            case 'gcp':
                if (!keys.jwks) throw new Error('gcp: keys.jwks is required');
                claims = GCP.verify(doc, keys.jwks, opts);
                break;

            case 'azure':
                if (!keys.jwks) throw new Error('azure: keys.jwks is required');
                claims = Azure.verify(doc, keys.jwks, opts);
                break;

            case 'oci':
                var vkey = keys.veraisonKey || ts.veraisonKey;
                if (!vkey) throw new Error('oci: no Veraison key provided');
                claims = OCI.verify(doc, vkey, opts);
                break;

            case 'sev_snp':
                var vcert   = keys.vcekCertDER;
                var amdRoot = keys.amdRootDER || ts.amdRoot;
                if (!opts.skipChain && !vcert)   throw new Error('sev_snp: keys.vcekCertDER is required');
                if (!opts.skipChain && !amdRoot) throw new Error('sev_snp: keys.amdRootDER is required');
                claims = SEV_SNP.verify(doc, vcert, amdRoot, opts);
                break;

            case 'tdx':
                var intelRoot = keys.intelRootDER || ts.intelRoot;
                if (!opts.skipChain && !intelRoot) throw new Error('tdx: keys.intelRootDER is required');
                claims = TDX.verify(doc, intelRoot, opts);
                break;
        }

        return {
            valid:      true,
            provider:   claims.provider,
            scannerCID: claims.scannerCID || null,
            claims:     claims
        };
    }).catch(function (err) {
        return {
            valid:    false,
            provider: provider,
            error:    err.message,
            claims:   null
        };
    });
};

/**
 * Detect the provider from a raw document.
 * Returns a best guess; pass the explicit provider to verify() to be certain.
 *
 * @param {Buffer|string} doc
 * @returns {string|null} provider name or null if undetectable.
 */
AttestationVerifier.detect = function (doc) {
    if (typeof doc === 'string') {
        // JWT: header.payload.sig
        var parts = doc.split('.');
        if (parts.length === 3) {
            try {
                var hdr = JSON.parse(Buffer.from(
                    parts[0].replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8'));
                var pay = JSON.parse(Buffer.from(
                    parts[1].replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8'));
                if (pay['ear.status'] !== undefined) return 'oci';
                if (pay['iss'] && pay['iss'].indexOf('confidentialcomputing.googleapis.com') >= 0) return 'gcp';
                if (pay['iss'] && pay['iss'].indexOf('.attest.azure.net') >= 0) return 'azure';
            } catch (e) {}
            return null;
        }
        return null;
    }
    if (Buffer.isBuffer(doc)) {
        // COSE_Sign1 (Nitro): starts with CBOR array tag or CBOR array header.
        // Major type 4 (array) = 0x84 (4-item array) or tagged with tag 18 = 0xd2 0x84
        var b0 = doc[0];
        if (b0 === 0x84 || b0 === 0xd2) return 'nitro';
        // SEV-SNP: 1184-byte binary, first 4 bytes = version (LE u32) = 2
        if (doc.length >= 4 && doc.readUInt32LE(0) === 2 && doc.length >= 1184) return 'sev_snp';
        // TDX: starts with version u16 = 4, tee_type u32 = 0x81
        if (doc.length >= 8 && doc.readUInt16LE(0) === 4 && doc.readUInt32LE(4) === 0x00000081) return 'tdx';
    }
    return null;
};

// ── ML-DSA-65 static helper ────────────────────────────────────────────────────

/**
 * Verify a single ML-DSA-65 signature.
 *
 * Returns a structured result rather than throwing so callers can distinguish
 * "PQ library not installed" from "signature is bad":
 *   { ok: false, available: false } — @noble/post-quantum not installed (older Qbix)
 *   { ok: false, available: true  } — library present but signature failed
 *   { ok: true,  available: true  } — signature verified
 *
 * Argument order matches @noble/post-quantum and the Qbix platform patch:
 *   ml_dsa65.verify(signature, message, publicKey)
 *
 * Pass raw canonical bytes as `msg` — FIPS 204 hashes internally (SHAKE256
 * per §3.4); do NOT pre-hash with SHA-256 unless the Safebox is specifically
 * signing a digest (e.g. for a challenge-response).
 *
 * @param {string}         sigB64  Base64-encoded ML-DSA-65 signature (3309 bytes).
 * @param {Buffer|string}  msg     Canonical message bytes (Buffer or UTF-8 string).
 * @param {string}         pkB64   Base64-encoded ML-DSA-65 public key (1952 bytes).
 * @returns {Promise<{ ok: boolean, available: boolean, error: string|null }>}
 */
AttestationVerifier.verifyMLDSASig = function (sigB64, msg, pkB64) {
    return _getMlDsa()
        .then(function (mod) {
            try {
                var sigRaw = Buffer.from(sigB64, 'base64');
                var pk     = Buffer.from(pkB64, 'base64');
                var msgBuf = Buffer.isBuffer(msg) ? msg : Buffer.from(msg, 'utf8');
                // ml_dsa65.verify(signature, message, publicKey) → boolean
                var ok = mod.ml_dsa65.verify(sigRaw, msgBuf, pk);
                return ok
                    ? { ok: true,  available: true, error: null }
                    : { ok: false, available: true, error: 'signature check returned false' };
            } catch (e) {
                return { ok: false, available: true, error: e.message };
            }
        })
        .catch(function (e) {
            // @noble/post-quantum not installed on this Qbix version — soft fail.
            // Callers check available:false to distinguish from a bad sig.
            return {
                ok:        false,
                available: false,
                error:     '@noble/post-quantum unavailable: ' + (e && e.message)
            };
        });
};

module.exports = AttestationVerifier;
