'use strict';
/**
 * GCP Confidential Space attestation verifier.
 *
 * Wire format: JWT signed with RS256.
 * Root of trust: OIDC JWKS endpoint (fetched by AttestationFetcher, passed in).
 *
 * GCP Confidential Space issues an OIDC token from the issuer:
 *   https://confidentialcomputing.googleapis.com
 *
 * The token header contains `kid`; the matching JWK is selected from the JWKS.
 *
 * Relevant claims in the payload:
 *   sub            : string  — identity of the workload
 *   iss            : string  — "https://confidentialcomputing.googleapis.com"
 *   aud            : string  — audience (typically the verifier's URL)
 *   eat_nonce      : string  — anti-replay nonce
 *   submods.container.image_digest : string — sha256 of the container image
 *   submods.container.image_reference : string — image ref (repo:tag)
 *   google_service_accounts : string[] — SA emails bound to this workload
 *   dbgstat        : string  — debug status ("disabled-since-boot" for production)
 *   hwmodel        : string  — hardware model ("GCP_AMD_SEV")
 *   swname         : string  — software name ("CONFIDENTIAL_SPACE")
 *   tee            : object  — TEE-specific sub-claims
 *
 * We extract the container image digest as the scannerCID (or user_data if set).
 *
 * @module Attestation/providers/GCP
 */

var jwtUtil = require('../util/jwt');

/** GCP Confidential Space OIDC issuer. */
var EXPECTED_ISSUER = 'https://confidentialcomputing.googleapis.com';

/**
 * Verify a GCP Confidential Space attestation token.
 *
 * @param {string} token    JWT attestation token.
 * @param {Object} jwks     JWKS object ({ keys: [...] }) fetched from the OIDC endpoint.
 * @param {Object} [opts]
 * @param {string}  [opts.audience]     Expected audience claim (optional).
 * @param {boolean} [opts.skipExpiry]   Skip exp/nbf checks (for fixtures/tests).
 * @returns {{ provider, imageDigest, imageRef, scannerCID, nonce, debug, claims }}
 * @throws on any verification failure.
 */
function verify(token, jwks, opts) {
    opts = opts || {};

    var parsed = jwtUtil.parseJWT(token);
    var kid    = parsed.header.kid;
    var alg    = parsed.header.alg;

    if (alg !== 'RS256') {
        throw new Error('gcp: expected RS256, got ' + alg);
    }

    // Select the matching JWK by kid.
    var jwk = _selectJWK(jwks, kid);
    if (!jwk) throw new Error('gcp: no matching JWK for kid=' + kid);

    // Verify signature and expiry.
    var result = jwtUtil.verifyJWT(token, jwk, { skipExpiry: !!opts.skipExpiry });
    var p      = result.payload;

    // Issuer check.
    if (p.iss !== EXPECTED_ISSUER) {
        throw new Error('gcp: unexpected issuer "' + p.iss + '"');
    }

    // Audience check (optional).
    if (opts.audience && p.aud !== opts.audience) {
        throw new Error('gcp: audience mismatch (expected "' + opts.audience + '", got "' + p.aud + '")');
    }

    // Debug status check — production enclaves must have debug disabled.
    var dbgstat = p['dbgstat'];
    if (dbgstat && dbgstat !== 'disabled-since-boot') {
        // Warn rather than hard-fail; callers can treat this as a policy violation.
        result._debugEnabled = true;
    }

    var container    = (p['submods'] && p['submods']['container']) || {};
    var imageDigest  = container['image_digest']    || null;
    var imageRef     = container['image_reference'] || null;
    var nonce        = p['eat_nonce']               || null;

    // scannerCID: by convention we use the image digest as the scanner identifier.
    // If user_data is set (non-standard extension), prefer that.
    var scannerCID = p['user_data'] || imageDigest;

    return {
        provider:   'gcp',
        imageDigest,
        imageRef,
        scannerCID,
        nonce,
        debug:      !!result._debugEnabled,
        claims:     p
    };
}

function _selectJWK(jwks, kid) {
    if (!jwks || !Array.isArray(jwks.keys)) throw new Error('gcp: invalid JWKS (no keys array)');
    if (!kid) return jwks.keys[0]; // take first if no kid hint
    for (var i = 0; i < jwks.keys.length; i++) {
        if (jwks.keys[i].kid === kid) return jwks.keys[i];
    }
    return null;
}

module.exports = { verify };
