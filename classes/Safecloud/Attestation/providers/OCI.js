'use strict';
/**
 * OCI (Oracle Cloud Infrastructure) Confidential Computing attestation verifier.
 *
 * Wire format: JWT in EAT (Entity Attestation Token) / EAR format, signed ES256.
 * Root of trust: Veraison verifier public key (ES256, P-256).
 *
 * OCI uses the IETF EAT standard (RFC 9334) with Veraison as the verifier service.
 * The token is issued by the Veraison attestation service after it validates the
 * hardware evidence (AMD SEV-SNP on OCI Confidential VMs).
 *
 * Relevant claims (EAR sub-claims under "ear.verifier-id"):
 *   iss            : string  — Veraison verifier identifier
 *   iat            : number  — issued at
 *   eat_nonce      : string  — anti-replay
 *   ear.status     : string  — "affirming" (verified), "warning", "contraindicated"
 *   submods        : object  — per-component sub-attestations
 *     submods.CCA_SSD_PLATFORM.ear.appraisal-policy-id : string
 *     submods.CCA_SSD_PLATFORM.ear.trustworthiness-vector : object
 *   ear.raw-evidence : Buffer? — the raw AMD SEV-SNP report (optional)
 *   user_data      : string? — caller-supplied (we use for scannerCID)
 *
 * @module Attestation/providers/OCI
 */

var jwtUtil = require('../util/jwt');

/**
 * Verify an OCI/Veraison EAR attestation token.
 *
 * @param {string}                     token        JWT (ES256) from Veraison.
 * @param {crypto.KeyObject|Object}    veraisonKey  Veraison public key — may be:
 *   - a Node.js crypto.KeyObject,
 *   - a single JWK ({ kty, crv, x, y, ... }),
 *   - a JWKS ({ keys: [...] }) — key selected by kid from JWT header.
 * @param {Object} [opts]
 * @param {boolean} [opts.skipExpiry]   Skip iat/exp checks.
 * @param {boolean} [opts.skipStatus]   Skip ear.status check.
 * @returns {{ provider, status, scannerCID, nonce, submods, claims }}
 * @throws on any verification failure.
 */
function verify(token, veraisonKey, opts) {
    opts = opts || {};

    var parsed = jwtUtil.parseJWT(token);
    if (parsed.header.alg !== 'ES256') {
        throw new Error('oci: expected ES256, got ' + parsed.header.alg);
    }

    // Normalise veraisonKey: accept a JWKS { keys: [...] }, a single JWK, or a KeyObject.
    var resolvedKey = veraisonKey;
    if (veraisonKey && Array.isArray(veraisonKey.keys)) {
        var kid = parsed.header.kid;
        var found = null;
        for (var i = 0; i < veraisonKey.keys.length; i++) {
            if (!kid || veraisonKey.keys[i].kid === kid) {
                found = veraisonKey.keys[i];
                if (kid) break;
            }
        }
        if (!found) throw new Error('oci: no matching JWK in JWKS for kid=' + kid);
        resolvedKey = found;
    }

    var result = jwtUtil.verifyJWT(token, resolvedKey, { skipExpiry: !!opts.skipExpiry });
    var p      = result.payload;

    var status = p['ear.status'] || null;
    if (!opts.skipStatus && status !== 'affirming') {
        throw new Error('oci: ear.status is "' + status + '" (expected "affirming")');
    }

    var nonce    = p['eat_nonce'] || null;
    var submods  = p['submods']   || {};
    var userData = p['user_data'] || null;

    // scannerCID: caller puts the scanner WASM CID in user_data.
    var scannerCID = userData || null;

    return {
        provider:  'oci',
        status,
        scannerCID,
        nonce,
        submods,
        claims: p
    };
}

module.exports = { verify };
