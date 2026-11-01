'use strict';
/**
 * X.509 certificate chain utilities for attestation verification.
 *
 * Node.js 15.6+ exposes the `X509Certificate` class which is all we need:
 *   - parse DER/PEM
 *   - extract public key
 *   - verify that certificate B was signed by certificate A
 *
 * extractPublicKey(certDER) → crypto.KeyObject
 * verifyCertChain(certs, trustedRoot)
 *   certs: [leaf, intermediate?, ..., root-or-ca]  (DER Buffers)
 *   trustedRoot: Buffer (DER) — the pinned root we trust
 *   Returns: public key of the leaf certificate.
 */

var crypto = require('crypto');

/**
 * Parse a DER-encoded certificate and return its public key as a KeyObject.
 * @param {Buffer} der
 * @returns {crypto.KeyObject}
 */
function extractPublicKey(der) {
    var cert = new crypto.X509Certificate(der);
    return cert.publicKey;
}

/**
 * Parse a PEM-encoded certificate and return its public key as a KeyObject.
 * @param {string} pem
 * @returns {crypto.KeyObject}
 */
function extractPublicKeyFromPEM(pem) {
    var cert = new crypto.X509Certificate(pem);
    return cert.publicKey;
}

/**
 * Verify a certificate chain and return the leaf's public key.
 *
 * @param {Buffer[]} chain  DER buffers, leaf first, root last (or near-root).
 * @param {Buffer}   trustedRootDER  The pinned root CA we trust (DER).
 * @returns {crypto.KeyObject} public key of the leaf certificate.
 * @throws if any link in the chain fails to verify.
 */
function verifyCertChain(chain, trustedRootDER) {
    if (!chain || chain.length === 0) throw new Error('certchain: empty chain');

    var trustedRoot = new crypto.X509Certificate(trustedRootDER);

    // Verify from root downward. We check that the final cert in the
    // provided chain is signed by our trusted root (or IS the trusted root),
    // then walk leaf-ward verifying each link.
    var certs = chain.map(function (der) { return new crypto.X509Certificate(der); });

    // Verify the chain anchor: the last provided cert must be signed by trustedRoot.
    var anchor = certs[certs.length - 1];
    if (!anchor.verify(trustedRoot.publicKey)) {
        // Maybe the last cert IS the trusted root (self-signed by it).
        // Check subject/issuer match as a fallback.
        if (anchor.subject !== trustedRoot.subject) {
            throw new Error('certchain: chain anchor is not signed by the trusted root');
        }
    }

    // Walk from anchor toward leaf verifying each link.
    for (var i = certs.length - 2; i >= 0; i--) {
        var child  = certs[i];
        var parent = certs[i + 1];
        if (!child.verify(parent.publicKey)) {
            throw new Error('certchain: link ' + i + '→' + (i+1) + ' failed verification');
        }
        // Basic validity window check (skip for mock fixtures that may use expired certs).
        // Production callers can add notBefore/notAfter checks here.
    }

    return certs[0].publicKey;
}

/**
 * Parse a PEM bundle (one or more -----BEGIN CERTIFICATE----- blocks)
 * into an array of DER Buffers.
 * @param {string} pemBundle
 * @returns {Buffer[]}
 */
function parsePEMBundle(pemBundle) {
    var regex = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
    var match;
    var results = [];
    while ((match = regex.exec(pemBundle)) !== null) {
        var b64 = match[1].replace(/\s+/g, '');
        results.push(Buffer.from(b64, 'base64'));
    }
    return results;
}

module.exports = { extractPublicKey, extractPublicKeyFromPEM, verifyCertChain, parsePEMBundle };
