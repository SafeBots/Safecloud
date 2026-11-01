'use strict';
/**
 * COSE_Sign1 parser for AWS Nitro attestation documents.
 *
 * AWS Nitro encodes its attestation as a CBOR-serialized COSE_Sign1 structure:
 *   Tag 18 [ protected-headers, unprotected-headers, payload, signature ]
 *
 * The protected headers are themselves CBOR-encoded (a byte string wrapping
 * a CBOR map). The signature covers:
 *   Sig_Structure = CBOR(["Signature1", protected-headers-bytes, "", payload])
 *
 * Reference: RFC 8152 §4.2 (COSE_Sign1)
 */

var crypto = require('crypto');
var cbor   = require('./cbor');

/**
 * Parse a COSE_Sign1 document from a Buffer.
 * Returns { protectedHeaders, unprotectedHeaders, payload, signature, sigStructure }.
 * sigStructure is the raw bytes that were signed (ready for crypto.verify).
 *
 * @param {Buffer} buf  Raw COSE_Sign1 bytes (may have a leading CBOR tag 18).
 */
function parseCOSESign1(buf) {
    var decoded = cbor.decodeCBOR(buf);

    // decoded is either [ protected, unprotected, payload, sig ]
    // (the tag 18 is consumed by the CBOR decoder's tag handler)
    if (!Array.isArray(decoded) || decoded.length !== 4) {
        throw new Error('cose: expected COSE_Sign1 array of 4 elements');
    }

    var protectedBytes  = decoded[0]; // Buffer — raw CBOR of the protected headers
    var unprotected     = decoded[1]; // map (may be empty {})
    var payload         = decoded[2]; // Buffer
    var signature       = decoded[3]; // Buffer

    var protectedHeaders = cbor.decodeCBOR(protectedBytes);

    // Build the Sig_Structure: ["Signature1", protected-bytes, aad="", payload]
    // per RFC 8152 §4.4
    var sigStructure = cbor.encodeCBOR([
        'Signature1',        // context
        protectedBytes,      // protected headers (raw bytes, not decoded)
        Buffer.alloc(0),     // external AAD (empty for Nitro)
        payload              // payload
    ]);

    return {
        protectedHeaders,    // decoded map: { 1: alg, 4: kid, ... }
        protectedBytes,      // raw CBOR bytes of the protected header (for re-signing / inspection)
        unprotectedHeaders: unprotected,
        payload,
        signature,
        sigStructure         // what was signed
    };
}

/**
 * Verify a COSE_Sign1 document given the signer's public key.
 *
 * @param {Buffer}           buf     Raw COSE_Sign1 bytes.
 * @param {crypto.KeyObject} pubKey  Signer's public key.
 * @returns {{ payload, protectedHeaders }} on success; throws on failure.
 */
function verifyCOSESign1(buf, pubKey) {
    var parsed = parseCOSESign1(buf);

    // COSE algorithm label 1 → alg value:
    //  -35 = ES384 (ECDSA P-384 + SHA-384) — used by Nitro
    //  -7  = ES256 (ECDSA P-256 + SHA-256)
    var algId  = parsed.protectedHeaders[1];
    var hash, dsaEncoding;
    if (algId === -35) {
        hash = 'sha384'; dsaEncoding = 'ieee-p1363';
    } else if (algId === -7) {
        hash = 'sha256'; dsaEncoding = 'ieee-p1363';
    } else {
        throw new Error('cose: unsupported algorithm id ' + algId);
    }

    var ok = crypto.verify(hash, parsed.sigStructure,
        { key: pubKey, dsaEncoding: dsaEncoding }, parsed.signature);
    if (!ok) throw new Error('cose: COSE_Sign1 signature verification failed');

    return {
        payload:          parsed.payload,
        protectedHeaders: parsed.protectedHeaders
    };
}

module.exports = { parseCOSESign1, verifyCOSESign1 };
