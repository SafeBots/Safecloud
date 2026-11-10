'use strict';
/**
 * TrustStore — pinned root CA certificates and verifier keys for each TEE provider.
 *
 * In production these are embedded at build time from the authoritative sources
 * listed in the comments. For tests, a mock TrustStore is passed in instead.
 *
 * Usage:
 *   var store = new TrustStore();        // loads defaults (bundled certs)
 *   var store = new TrustStore(custom);  // override individual entries for tests
 *
 * @module Attestation/TrustStore
 */

/**
 * @typedef {Object} TrustStoreConfig
 * @property {Buffer}           [nitroRoot]     AWS Nitro root CA (DER).
 * @property {Buffer}           [amdRoot]       AMD root CA (DER) for SEV-SNP.
 * @property {Buffer}           [intelRoot]     Intel SGX root CA (DER) for TDX.
 * @property {crypto.KeyObject} [veraisonKey]   OCI/Veraison ES256 public key.
 * @property {string}           [gcpJwksUrl]    GCP JWKS endpoint URL.
 * @property {string}           [azureJwksUrl]  Azure MAA JWKS endpoint URL.
 */

/**
 * @class TrustStore
 * @param {TrustStoreConfig} [overrides]  Override any default for tests.
 */
function TrustStore(overrides) {
    overrides = overrides || {};

    /**
     * AWS Nitro root CA (DER).
     * Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
     * SHA-256: 8c:f6:0e:08:6e:0d:19:0a:54:89:4e:47:22:6c:10:03:...
     */
    this.nitroRoot = overrides.nitroRoot || _loadBundledCert('nitro-root.der');

    /**
     * AMD Root CA (DER) for SEV-SNP VCEK chain.
     * Source: https://kdsintf.amd.com/vlek/v1/Milan/cert_chain
     * (The root is the same across all AMD Milan/Genoa processors.)
     */
    this.amdRoot = overrides.amdRoot || _loadBundledCert('amd-root.der');

    /**
     * Intel SGX Root CA (DER) for TDX quote chain.
     * Source: https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.der
     */
    this.intelRoot = overrides.intelRoot || _loadBundledCert('intel-root.der');

    /**
     * OCI/Veraison ES256 public key (crypto.KeyObject or JWK).
     * Source: published at the Veraison service's JWKS endpoint.
     * Must be set via override; no bundled default (endpoint is region-specific).
     */
    this.veraisonKey = overrides.veraisonKey || null;

    /**
     * GCP Confidential Space JWKS URL (fetched at verify time by AttestationFetcher).
     * https://www.googleapis.com/service_accounts/v1/jwk/[service-account-email]
     * or via OIDC discovery at:
     * https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
     */
    this.gcpJwksUrl = overrides.gcpJwksUrl ||
        'https://confidentialcomputing.googleapis.com/jwk/v1';

    /**
     * Azure MAA JWKS URL — region-specific, pattern:
     * https://{instance}.attest.azure.net/certs
     * Default to the shared instance; callers override for region-specific endpoints.
     */
    this.azureJwksUrl = overrides.azureJwksUrl ||
        'https://sharedeus2.eus2.attest.azure.net/certs';
}

// ── Bundled cert loader ───────────────────────────────────────────────────────
// In production, DER files are committed alongside this module in trust-roots/.
// If a file is missing, we return null — the verifier will throw when it tries
// to use it, which is the right behavior (fail closed rather than fail open).

var path = require('path');
var fs   = require('fs');

function _loadBundledCert(filename) {
    var p = path.join(__dirname, 'trust-roots', filename);
    try { return fs.readFileSync(p); } catch (e) { return null; }
}

module.exports = TrustStore;
