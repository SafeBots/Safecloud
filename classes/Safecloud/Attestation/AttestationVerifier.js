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

module.exports = AttestationVerifier;
