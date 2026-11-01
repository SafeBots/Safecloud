'use strict';
/**
 * AWS Nitro Enclaves attestation verifier.
 *
 * Wire format: CBOR-encoded COSE_Sign1 (RFC 8152), algorithm ES384 (ECDSA P-384).
 *
 * Structure of the Nitro attestation document (CBOR map inside COSE payload):
 *   module_id     : string  — enclave module identifier
 *   timestamp     : number  — milliseconds since epoch
 *   digest        : string  — hash algorithm used ("SHA384")
 *   pcrs          : map     — PCR index → sha384 hash (Buffer)
 *   certificate   : Buffer  — DER-encoded end-entity cert (enclave's signing cert)
 *   cabundle      : Buffer[]— DER certs from intermediate to root
 *   public_key    : Buffer? — optional public key of enclave (if requested)
 *   user_data     : Buffer? — caller-supplied opaque data (we put scannerCID here)
 *   nonce         : Buffer? — anti-replay
 *
 * Verification steps:
 *   1. Decode COSE_Sign1 and extract leaf cert + cabundle.
 *   2. Build the cert chain: [leaf, ...cabundle].
 *   3. Verify the chain against the trusted Nitro root CA.
 *   4. Verify the COSE_Sign1 signature using the leaf cert's public key.
 *   5. Return parsed claims (PCRs, user_data, module_id, timestamp).
 *
 * @module Attestation/providers/Nitro
 */

var cbor      = require('../util/cbor');
var cose      = require('../util/cose');
var certchain = require('../util/certchain');

/**
 * Verify a Nitro attestation document.
 *
 * @param {Buffer} doc          Raw COSE_Sign1 bytes from the enclave.
 * @param {Buffer} trustedRoot  DER-encoded AWS Nitro root CA certificate.
 * @param {Object} [opts]
 * @param {boolean} [opts.skipExpiry]  Skip timestamp check (for fixtures/tests).
 * @returns {{ provider, moduleId, timestamp, pcrs, scannerCID, userData, nonce }}
 * @throws on any verification failure.
 */
function verify(doc, trustedRoot, opts) {
    opts = opts || {};

    // 1. Verify COSE_Sign1 structure — we need the leaf cert first to get the key.
    //    Parse without verifying signature, extract cert, build chain, then verify.
    var parsed   = cose.parseCOSESign1(doc);
    var payload  = cbor.decodeCBOR(parsed.payload);

    var leafDER    = payload['certificate'];
    var cabundle   = payload['cabundle'] || [];

    if (!leafDER) throw new Error('nitro: attestation payload missing "certificate"');

    // 2. Build chain: leaf first, then intermediates, root last.
    var chain = [leafDER].concat(cabundle);

    // 3. Verify cert chain against the trusted Nitro root.
    var leafKey = certchain.verifyCertChain(chain, trustedRoot);

    // 4. Verify COSE_Sign1 signature using the leaf's public key.
    cose.verifyCOSESign1(doc, leafKey);

    // 5. Timestamp check.
    if (!opts.skipExpiry) {
        var nowMs  = Date.now();
        var ts     = payload['timestamp'];
        var ageMs  = nowMs - ts;
        // Nitro docs are short-lived; reject anything older than 3 hours.
        if (ageMs > 3 * 60 * 60 * 1000) {
            throw new Error('nitro: attestation document is too old (' + Math.round(ageMs/1000) + 's)');
        }
        if (ageMs < -60 * 1000) {
            throw new Error('nitro: attestation document timestamp is in the future');
        }
    }

    // 6. Extract claims.
    var pcrs      = payload['pcrs']      || {};
    var userData  = payload['user_data'] || null;
    var nonce     = payload['nonce']     || null;
    var moduleId  = payload['module_id'] || null;

    // Convention: user_data carries the scanner WASM CID as a UTF-8 string.
    var scannerCID = userData ? userData.toString('utf8').trim() : null;

    return {
        provider:   'nitro',
        moduleId,
        timestamp:  payload['timestamp'],
        pcrs,
        scannerCID,
        userData,
        nonce
    };
}

module.exports = { verify };
