'use strict';
/**
 * Azure Confidential Computing (MAA) attestation verifier.
 *
 * Wire format: JWT signed with RS256, issued by Microsoft Azure Attestation (MAA).
 * Root of trust: JWKS from MAA endpoint (fetched by AttestationFetcher, passed in).
 *
 * MAA endpoint pattern: https://{instance}.attest.azure.net
 * JWKS URL:             https://{instance}.attest.azure.net/certs
 *
 * Relevant claims:
 *   x-ms-ver               : string   — MAA API version
 *   x-ms-attestation-type  : string   — "sevsnpvm" | "tdxvm" | "sgx" | ...
 *   x-ms-compliance-status : string   — "azure-compliant-cvm" for prod
 *   x-ms-runtime           : object   — runtime claims passed in by the workload
 *     x-ms-runtime.user-data : string — base64; we treat as scannerCID
 *   x-ms-sevsnpvm-*        : various  — AMD SEV-SNP hardware claims
 *   x-ms-tdx-*             : various  — Intel TDX hardware claims
 *   nonce                  : string   — anti-replay
 *
 * @module Attestation/providers/Azure
 */

var jwtUtil = require('../util/jwt');

/** Known MAA issuers — region-specific but share the same JWKS signing keys. */
var ISSUER_SUFFIX = '.attest.azure.net';

/**
 * Verify an Azure MAA attestation token.
 *
 * @param {string} token    JWT from MAA.
 * @param {Object} jwks     JWKS from https://{instance}.attest.azure.net/certs
 * @param {Object} [opts]
 * @param {boolean} [opts.skipExpiry]   Skip exp/nbf checks (for tests).
 * @param {boolean} [opts.skipIssuer]   Skip issuer suffix check (for tests).
 * @returns {{ provider, attestationType, complianceStatus, scannerCID, nonce, hwClaims, claims }}
 * @throws on any verification failure.
 */
function verify(token, jwks, opts) {
    opts = opts || {};

    var parsed = jwtUtil.parseJWT(token);
    var kid    = parsed.header.kid;
    var alg    = parsed.header.alg;

    if (alg !== 'RS256') throw new Error('azure: expected RS256, got ' + alg);

    var jwk = _selectJWK(jwks, kid);
    if (!jwk) throw new Error('azure: no matching JWK for kid=' + kid);

    var result = jwtUtil.verifyJWT(token, jwk, { skipExpiry: !!opts.skipExpiry });
    var p      = result.payload;

    // Issuer check: must end in .attest.azure.net
    if (!opts.skipIssuer) {
        var iss = p.iss || '';
        if (iss.indexOf(ISSUER_SUFFIX) === -1) {
            throw new Error('azure: unexpected issuer "' + iss + '"');
        }
    }

    var attestationType  = p['x-ms-attestation-type']  || null;
    var complianceStatus = p['x-ms-compliance-status'] || null;
    var runtime          = p['x-ms-runtime']           || {};
    var nonce            = p['nonce']                  || null;

    // User data is base64-encoded in x-ms-runtime.user-data
    var rawUserData  = runtime['user-data'] || null;
    var userData     = rawUserData ? Buffer.from(rawUserData, 'base64').toString('utf8').trim() : null;
    var scannerCID   = userData || null;

    // Collect hardware-specific sub-claims for the caller.
    var hwClaims = {};
    Object.keys(p).forEach(function (k) {
        if (k.indexOf('x-ms-sevsnpvm') === 0 || k.indexOf('x-ms-tdx') === 0) {
            hwClaims[k] = p[k];
        }
    });

    return {
        provider:         'azure',
        attestationType,
        complianceStatus,
        scannerCID,
        nonce,
        hwClaims,
        claims: p
    };
}

function _selectJWK(jwks, kid) {
    if (!jwks || !Array.isArray(jwks.keys)) throw new Error('azure: invalid JWKS (no keys array)');
    if (!kid) return jwks.keys[0];
    for (var i = 0; i < jwks.keys.length; i++) {
        if (jwks.keys[i].kid === kid) return jwks.keys[i];
    }
    return null;
}

module.exports = { verify };
