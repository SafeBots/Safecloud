"use strict";
/**
 * Q.Safecloud.Drops — server-side counterpart to Q.Safecloud.Drops.
 *
 * Provides helpers that Jets.js calls when managing Drops:
 *   - Announce signature verification
 *   - Challenge response CID verification
 *   - Reputation tracking helpers
 *   - CoC pattern detection (slash threshold)
 *   - Storage backend adapter (Safecloud 3.4)
 *
 * Safecloud 3.4 storage adapter
 * ─────────────────────────────
 * A configurable storage backend can be injected at startup via
 * `Drops.initStorage(store)`. The backend must implement:
 *
 *   store.get(cid)          → Promise<Buffer|null>
 *   store.put(cid, buf)     → Promise<void>
 *   store.has(cid)          → Promise<Boolean>
 *   store.delete(cid)       → Promise<void>
 *   store.list(prefix)      → Promise<String[]>
 *
 * When a backend is set Jets.js routes chunk I/O through `Drops.putChunks()`
 * and `Drops.getChunks()` for the built-in local Drop (`__local_s3__`) rather
 * than forwarding requests over socket.io to browser Drop nodes. The existing
 * proof-of-storage challenge logic, reputation tracking, and Safebux accounting
 * are untouched.
 *
 * Wire format inside the storage layer
 * ─────────────────────────────────────
 * Each chunk is serialised as a fixed-layout Buffer:
 *
 *   [ IV_LEN  (4 bytes, big-endian uint32) ]
 *   [ IV      (IV_LEN bytes)               ]
 *   [ TAG_LEN (4 bytes, big-endian uint32) ]
 *   [ TAG     (TAG_LEN bytes)              ]
 *   [ CIPHERTEXT (remaining bytes)         ]
 *
 * This keeps the storage layer opaque and version-upgradeable without changing
 * the CID or the chunk semantics visible to Cloud clients.
 *
 * @class Q.Safecloud.Drops
 * @static
 */

var Q      = require('Q');
var crypto = require('crypto');

var Drops = module.exports = {};

// ─────────────────────────────────────────────────────────────────────────────
// Safecloud 3.4 — Storage backend adapter
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The injected storage backend. Null when no backend is configured (default:
 * browser-based IndexedDB Drops handle all storage via socket.io).
 * @property {Object|null} _store
 * @private
 */
Drops._store = null;

/**
 * Inject a storage backend. Called by Jets.js during `listen()` when
 * `Safecloud.storage.backend` is set to something other than `"indexeddb"`.
 *
 * @method initStorage
 * @param {Object} store  Object implementing get/put/has/delete/list
 */
Drops.initStorage = function (store) {
    if (!store || typeof store.get !== 'function' || typeof store.put !== 'function') {
        throw new Error('Drops.initStorage: store must implement get(cid) and put(cid, buf)');
    }
    Drops._store = store;
};

/**
 * Store an array of chunks using the configured backend.
 * Each chunk object must have: `cid` (String), `ciphertext` (base64 String),
 * `tag` (base64 String), and optionally `iv` (base64 String).
 *
 * @method putChunks
 * @param {Array<Object>} chunks
 * @return {Promise<{results: Array<{cid: String, stored: Boolean}>}>}
 */
Drops.putChunks = function (chunks) {
    if (!Drops._store) {
        return Promise.reject(new Error('Drops.putChunks: no storage backend configured'));
    }
    if (!Array.isArray(chunks)) {
        return Promise.resolve({ results: [] });
    }

    var promises = chunks.map(function (chunk) {
        if (!chunk || typeof chunk.cid !== 'string' || !chunk.cid) {
            return Promise.resolve({ cid: null, stored: false });
        }
        try {
            var buf = _serializeChunk(chunk);
            return Drops._store.put(chunk.cid, buf).then(function () {
                return { cid: chunk.cid, stored: true };
            }).catch(function () {
                return { cid: chunk.cid, stored: false };
            });
        } catch (e) {
            return Promise.resolve({ cid: chunk.cid, stored: false });
        }
    });

    return Promise.all(promises).then(function (results) {
        return { results: results };
    });
};

/**
 * Retrieve an array of chunks by CID from the configured backend.
 * Missing chunks are omitted from the result array.
 *
 * @method getChunks
 * @param {Array<String>} cids
 * @return {Promise<{chunks: Array<Object>}>}
 */
Drops.getChunks = function (cids) {
    if (!Drops._store) {
        return Promise.reject(new Error('Drops.getChunks: no storage backend configured'));
    }
    if (!Array.isArray(cids)) {
        return Promise.resolve({ chunks: [] });
    }

    var promises = cids.map(function (cid) {
        if (typeof cid !== 'string' || !cid) { return Promise.resolve(null); }
        return Drops._store.get(cid).then(function (buf) {
            if (!buf) { return null; }
            try {
                return _deserializeChunk(cid, buf);
            } catch (e) {
                return null;
            }
        }).catch(function () { return null; });
    });

    return Promise.all(promises).then(function (results) {
        return { chunks: results.filter(Boolean) };
    });
};

/**
 * Check whether a single CID exists in the configured backend.
 *
 * @method hasChunk
 * @param {String} cid
 * @return {Promise<Boolean>}
 */
Drops.hasChunk = function (cid) {
    if (!Drops._store) { return Promise.resolve(false); }
    return Drops._store.has(cid).catch(function () { return false; });
};

// ── Private serialisation helpers ─────────────────────────────────────────────

/**
 * Serialise a chunk object to the storage wire format:
 *   IV_LEN(4) | IV | TAG_LEN(4) | TAG | CIPHERTEXT
 * @private
 */
function _serializeChunk(chunk) {
    var ivBuf  = chunk.iv  ? Buffer.from(chunk.iv,  'base64') : Buffer.alloc(0);
    var tagBuf = chunk.tag ? Buffer.from(chunk.tag, 'base64') : Buffer.alloc(0);
    var ctBuf  = chunk.ciphertext ? Buffer.from(chunk.ciphertext, 'base64') : Buffer.alloc(0);

    var ivLen  = Buffer.allocUnsafe(4); ivLen.writeUInt32BE(ivBuf.length, 0);
    var tagLen = Buffer.allocUnsafe(4); tagLen.writeUInt32BE(tagBuf.length, 0);

    return Buffer.concat([ivLen, ivBuf, tagLen, tagBuf, ctBuf]);
}

/**
 * Deserialise the storage wire format back to a chunk object.
 * @private
 */
function _deserializeChunk(cid, buf) {
    if (!buf || buf.length < 8) { return null; }

    var offset = 0;
    var ivLen  = buf.readUInt32BE(offset); offset += 4;
    if (offset + ivLen > buf.length) { return null; }
    var ivBuf  = buf.slice(offset, offset + ivLen); offset += ivLen;

    if (offset + 4 > buf.length) { return null; }
    var tagLen = buf.readUInt32BE(offset); offset += 4;
    if (offset + tagLen > buf.length) { return null; }
    var tagBuf = buf.slice(offset, offset + tagLen); offset += tagLen;

    var ctBuf  = buf.slice(offset);

    var result = { cid: cid, ciphertext: ctBuf.toString('base64') };
    if (tagBuf.length > 0) { result.tag = tagBuf.toString('base64'); }
    if (ivBuf.length  > 0) { result.iv  = ivBuf.toString('base64'); }

    return result;
}

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

        // Pass the raw payload with algorithm 'sha256' so Node hashes it once,
        // matching what WebCrypto's ECDSA+SHA-256 signed. The earlier
        // verify(null, sha256(payload)) form hashed twice and rejected every
        // announce a real Drop ever sent (see the identical fix in
        // Q.Crypto.OpenClaim.verify's ES256 branch).
        return crypto.verify('sha256', payload, key, derSig);
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
