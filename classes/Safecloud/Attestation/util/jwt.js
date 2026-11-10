'use strict';
/**
 * Minimal JWT utilities for attestation verification.
 *
 * parse()  — splits and base64url-decodes a JWT without verifying.
 * verify() — verifies signature using a JWK or KeyObject, checks exp/nbf.
 *
 * Supports RS256 (RSA-PKCS1-v1_5 + SHA-256) and ES256 (ECDSA P-256 + SHA-256).
 * Does NOT support HS* (symmetric) algorithms — attestation JWTs are always
 * asymmetric.
 */

var crypto = require('crypto');

/**
 * Parse a JWT without verifying. Returns { header, payload, signingInput, sig }.
 * @param {string} token
 */
function parseJWT(token) {
    var parts = token.split('.');
    if (parts.length !== 3) throw new Error('jwt: malformed token (expected 3 parts)');
    var header  = JSON.parse(base64urlDecode(parts[0]).toString('utf8'));
    var payload = JSON.parse(base64urlDecode(parts[1]).toString('utf8'));
    return {
        header,
        payload,
        signingInput: parts[0] + '.' + parts[1],
        signature:    base64urlDecode(parts[2])
    };
}

/**
 * Verify a JWT.
 * @param {string} token
 * @param {Object|crypto.KeyObject} key
 *   JWK object OR a Node.js KeyObject (public key).
 *   If JWK, must have `kty` field.
 * @param {Object} [opts]
 * @param {boolean} [opts.skipExpiry=false]  skip exp/nbf checks (for fixtures)
 * @returns {{ header, payload }} on success; throws on failure.
 */
function verifyJWT(token, key, opts) {
    opts = opts || {};
    var parsed = parseJWT(token);
    var alg    = parsed.header.alg;

    var keyObj = _toKeyObject(key, alg);
    var ok     = _verifySignature(alg, parsed.signingInput, parsed.signature, keyObj);
    if (!ok) throw new Error('jwt: signature verification failed (alg=' + alg + ')');

    if (!opts.skipExpiry) {
        var now = Math.floor(Date.now() / 1000);
        if (parsed.payload.exp && parsed.payload.exp < now) {
            throw new Error('jwt: token expired (exp=' + parsed.payload.exp + ')');
        }
        if (parsed.payload.nbf && parsed.payload.nbf > now) {
            throw new Error('jwt: token not yet valid (nbf=' + parsed.payload.nbf + ')');
        }
    }

    return { header: parsed.header, payload: parsed.payload };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function _verifySignature(alg, signingInput, sig, keyObj) {
    var input = Buffer.from(signingInput, 'ascii');
    switch (alg) {
        case 'RS256':
            return crypto.verify('sha256', input, keyObj, sig);
        case 'RS384':
            return crypto.verify('sha384', input, keyObj, sig);
        case 'RS512':
            return crypto.verify('sha512', input, keyObj, sig);
        case 'ES256':
            return crypto.verify('sha256', input, { key: keyObj, dsaEncoding: 'ieee-p1363' }, sig);
        case 'ES384':
            return crypto.verify('sha384', input, { key: keyObj, dsaEncoding: 'ieee-p1363' }, sig);
        default:
            throw new Error('jwt: unsupported algorithm ' + alg);
    }
}

function _toKeyObject(key, alg) {
    if (key && typeof key.asymmetricKeyType === 'string') return key; // already a KeyObject
    if (key && key.kty) return _jwkToKeyObject(key, alg);
    throw new Error('jwt: key must be a JWK or a Node.js KeyObject');
}

function _jwkToKeyObject(jwk, alg) {
    // Node.js 15+ supports createPublicKey({ key: jwk, format: 'jwk' })
    if (typeof crypto.createPublicKey === 'function') {
        try {
            return crypto.createPublicKey({ key: jwk, format: 'jwk' });
        } catch (e) {
            throw new Error('jwt: failed to import JWK: ' + e.message);
        }
    }
    throw new Error('jwt: Node.js version too old to import JWK directly');
}

function base64urlDecode(str) {
    // Convert base64url → base64
    var b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    var pad = (4 - (b64.length % 4)) % 4;
    b64 += '='.repeat(pad);
    return Buffer.from(b64, 'base64');
}

function base64urlEncode(buf) {
    return Buffer.from(buf).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

module.exports = { parseJWT, verifyJWT, base64urlDecode, base64urlEncode };
