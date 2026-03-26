"use strict";
/**
 * Q.Safecloud.Drops — server-side counterpart to Q.Safecloud.Drops.
 *
 * Provides helpers that Jets.js calls when managing Drops:
 *   - Announce signature verification
 *   - Challenge response CID verification
 *   - Reputation tracking helpers
 *   - CoC pattern detection (slash threshold)
 *
 * @class Q.Safecloud.Drops
 * @static
 */

var Q      = require('Q');
var crypto = require('crypto');
var Q      = require('Q');

var Drops = module.exports = {};

// ─────────────────────────────────────────────────────────────────────────────
// Announce verification
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify the P-256 signature on a Safecloud/drop/announce payload.
 * The signature covers canonicalJSON(entry_without_signature).
 *
 * @method verifyAnnounce
 * @param {Object} announce   Full announce payload including signature field
 * @param {Buffer} publicKey  65-byte uncompressed P-256 public key
 * @return {Boolean}
 */
Drops.verifyAnnounce = function (announce, publicKey) {
    if (!announce || !announce.signature || !publicKey) { return false; }
    try {
        var copy = Object.assign({}, announce);
        delete copy.signature;

        // RFC 8785 canonical JSON — inline sort (same as Q.Data.canonicalize)
        var canonical = Q.Data.canonicalize(copy);
        var payload   = Buffer.from(canonical, 'utf8');

        // Signature is base64 raw r‖s (64 bytes, IEEE P1363) from WebCrypto ECDSA
        var sigBuf = Buffer.from(announce.signature, 'base64');

        // Node verify expects DER; convert r‖s → DER
        var derSig = _p1363ToDer(sigBuf);

        // Import P-256 public key — handle both raw (65 bytes) and SPKI DER (91 bytes)
        var buf  = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
        var spki = (buf.length === 65) ? _rawP256ToSpki(buf) : buf;
        var key  = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });

        // sign(null, ...) = raw bytes, no re-hashing — matches sign(null, ...) on signing side
        // But WebCrypto ECDSA SHA-256 hashes the payload, so we must hash first
        var digest = crypto.createHash('sha256').update(payload).digest();
        return crypto.verify(null, digest, key, derSig);
    } catch (e) {
        return false;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Challenge response CID verification
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a chunk returned in response to Safecloud/drop/challenge.
 * SHA-256(ciphertext || tag) must equal the requested CID.
 * Self-verifying — no external state needed.
 *
 * @method verifyChallengeResponse
 * @param {String} requestedCid   CID from the challenge
 * @param {Object} chunk          { iv, ciphertext, tag } all base64
 * @return {Boolean}
 */
Drops.verifyChallengeResponse = function (requestedCid, chunk) {
    if (!chunk || !chunk.ciphertext || !chunk.tag) { return false; }
    try {
        var ct  = Buffer.from(chunk.ciphertext, 'base64');
        var tag = Buffer.from(chunk.tag, 'base64');
        var combined = Buffer.concat([ct, tag]);
        var digest   = crypto.createHash('sha256').update(combined).digest();
        var computed = _digestToCid(digest);
        return computed === requestedCid;
    } catch (e) {
        return false;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Reputation / slash pattern detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check whether a Drop has reached the slash threshold.
 * Returns true if the Drop should be reported to PHP for slashing.
 *
 * @method shouldSlash
 * @param {Object} drop         Drop record from Q.Safecloud.Jets.drops
 * @param {Object} failureLog   { [cid]: Array<timestamp_ms> }
 * @return {Boolean}
 */
Drops.shouldSlash = function (drop, failureLog) {
    var minFailures = Q.Config.get(['Safecloud', 'drop', 'minSlashFailures'], 3);
    var windowMs    = Q.Config.get(['Safecloud', 'drop', 'slashWindowMs'], 3600000);
    var now         = Date.now();

    for (var cid in failureLog) {
        var times = failureLog[cid].filter(function (t) { return (now - t) < windowMs; });
        if (times.length >= minFailures) { return true; }
    }
    return false;
};

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/** RFC 8785 canonical JSON (inline, no external dep). */

/** CIDv1 from a 32-byte SHA-256 Buffer. */
function _digestToCid(digest) {
    var header = Buffer.from([0x01, 0x55, 0x12, 0x20]);
    var full   = Buffer.concat([header, digest]);
    return 'b' + _base32(full);
}

function _base32(buf) {
    var alpha = 'abcdefghijklmnopqrstuvwxyz234567';
    var out = '', bits = 0, val = 0;
    for (var i = 0; i < buf.length; i++) {
        val = (val << 8) | buf[i]; bits += 8;
        while (bits >= 5) { bits -= 5; out += alpha[(val >>> bits) & 0x1f]; }
    }
    if (bits > 0) { out += alpha[(val << (5 - bits)) & 0x1f]; }
    return out;
}

/** Convert raw P-256 uncompressed key (65 bytes) to SPKI DER for Node.createPublicKey. */
function _rawP256ToSpki(rawPoint) {
    var buf = Buffer.isBuffer(rawPoint) ? rawPoint : Buffer.from(rawPoint);
    var header = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
    return Buffer.concat([header, buf]);
}

/** Convert IEEE P1363 raw r‖s (64 bytes) to DER ECDSA signature. */
function _p1363ToDer(raw) {
    if (raw.length !== 64) { throw new Error('Expected 64-byte r‖s'); }
    var r = raw.slice(0, 32);
    var s = raw.slice(32, 64);

    function _encodeInt(buf) {
        // Strip leading zeros; prepend 0x00 if high bit set
        var i = 0;
        while (i < buf.length - 1 && buf[i] === 0) { i++; }
        buf = buf.slice(i);
        if (buf[0] & 0x80) { buf = Buffer.concat([Buffer.from([0x00]), buf]); }
        return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);
    }

    var rDer = _encodeInt(r);
    var sDer = _encodeInt(s);
    var seq  = Buffer.concat([rDer, sDer]);
    return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}
