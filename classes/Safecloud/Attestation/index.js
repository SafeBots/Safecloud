'use strict';
/**
 * Safecloud Attestation — public API.
 *
 * Usage (Node.js / Jet side):
 *
 *   var Attestation        = require('./classes/Safecloud/Attestation');
 *   var store    = new Attestation.TrustStore();          // loads bundled roots
 *   var fetcher  = new Attestation.Fetcher(store);
 *   var verifier = new Attestation.Verifier(store);
 *
 *   // Nitro: no network fetch needed (cert chain is in the document)
 *   var result = await verifier.verify('nitro', docBuffer, {
 *       trustedRoot: store.nitroRoot
 *   });
 *
 *   // GCP: fetch JWKS first, then verify
 *   var jwks   = await fetcher.fetchGCPJwks();
 *   var result = await verifier.verify('gcp', jwtString, { jwks });
 *
 *   var policy = new Attestation.Policy({
 *       scannerCID: 'bafybeig...',
 *       providers:  ['nitro', 'gcp', 'azure']
 *   });
 *   var { pass, reason } = policy.evaluate(result);
 *
 * @module Safecloud/Attestation
 */

var AttestationVerifier = require('./AttestationVerifier');
var AttestationFetcher  = require('./AttestationFetcher');
var AttestationPolicy   = require('./AttestationPolicy');
var TrustStore          = require('./TrustStore');
var PQClaim             = require('./PQClaim');

module.exports = {
    /** Pure verifier — no network calls. */
    Verifier: AttestationVerifier,

    /** Network layer — fetches JWKS, VCEK certs, Intel root CA. */
    Fetcher:  AttestationFetcher,

    /** Policy checker — enforces scannerCID + provider list + optional PQ claim. */
    Policy:   AttestationPolicy,

    /**
     * PQ claim signer/verifier — ML-DSA-65 (FIPS 204) scanner-authorization claims.
     * Use PQClaim.sign() to create a claim and PQClaim.verify() to check one.
     * Enable PQ-required policy with: new Policy({ ..., requirePQClaim: true }).
     */
    PQClaim:  PQClaim,

    /** Pinned root CA store. */
    TrustStore: TrustStore,

    // Provider modules exposed for direct use / testing.
    providers: {
        Nitro:   require('./providers/Nitro'),
        GCP:     require('./providers/GCP'),
        Azure:   require('./providers/Azure'),
        OCI:     require('./providers/OCI'),
        SEV_SNP: require('./providers/SEV_SNP'),
        TDX:     require('./providers/TDX')
    },

    // Utilities exposed for advanced use / testing.
    util: {
        cbor:      require('./util/cbor'),
        jwt:       require('./util/jwt'),
        certchain: require('./util/certchain'),
        cose:      require('./util/cose')
    }
};
