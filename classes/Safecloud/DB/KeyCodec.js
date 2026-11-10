'use strict';
/**
 * KeyCodec — encode SQL scalar values into strings that sort lexicographically.
 *
 * Sort order matches SQLite affinity rules:
 *   NULL < INTEGER/REAL < TEXT < BLOB
 *
 * Numeric encoding adjusts the IEEE 754 big-endian representation so the
 * byte string compares in the same direction as the numeric value:
 *   positive numbers: flip the sign bit (high bit of byte 0)
 *   negative numbers: flip all bits (so more-negative < less-negative)
 *
 * TEXT values are null-terminated and interior null bytes are escaped,
 * so a text key can never collide with a key from another type.
 */

var KC = module.exports = {};

var TAG_NULL = '\x00';
var TAG_NUM  = '\x20';
var TAG_TEXT = '\x40';
var TAG_BLOB = '\x60';

/**
 * Encode one SQL value to a sortable string.
 */
KC.encodeValue = function (v) {
    if (v === null || v === undefined) {
        return TAG_NULL;
    }
    if (typeof v === 'boolean') {
        return KC.encodeValue(v ? 1 : 0);
    }
    if (typeof v === 'number') {
        var buf = Buffer.allocUnsafe(8);
        buf.writeDoubleBE(v, 0);
        if (buf[0] & 0x80) {
            // negative: flip all bits so more-negative sorts earlier
            for (var i = 0; i < 8; i++) buf[i] ^= 0xff;
        } else {
            // positive or zero: flip sign bit so positives sort after negatives
            buf[0] ^= 0x80;
        }
        return TAG_NUM + buf.toString('binary');
    }
    if (typeof v === 'string') {
        // Escape interior \x00 bytes; use \x00\x01 as the escape sequence.
        // Terminate with \x00\x00 so text keys never bleed into the next type tag.
        return TAG_TEXT + v.replace(/\x00/g, '\x00\x01') + '\x00\x00';
    }
    if (Buffer.isBuffer(v)) {
        return TAG_BLOB + v.toString('binary');
    }
    // Fallback: stringify
    return TAG_TEXT + String(v).replace(/\x00/g, '\x00\x01') + '\x00\x00';
};

/**
 * Decode a previously-encoded value back to its JavaScript type.
 */
KC.decodeValue = function (s) {
    if (!s || s.length === 0) return null;
    var tag = s[0];
    var body = s.slice(1);
    if (tag === TAG_NULL) return null;
    if (tag === TAG_NUM) {
        var buf = Buffer.from(body, 'binary');
        if (buf.length < 8) return null;
        if (!(buf[0] & 0x80)) {
            // was negative: flip all bits back
            for (var i = 0; i < 8; i++) buf[i] ^= 0xff;
        } else {
            // was positive: flip sign bit back
            buf[0] ^= 0x80;
        }
        return buf.readDoubleBE(0);
    }
    if (tag === TAG_TEXT) {
        // Remove the two-byte terminator and unescape \x00\x01 → \x00
        return body.slice(0, -2).replace(/\x00\x01/g, '\x00');
    }
    if (tag === TAG_BLOB) {
        return Buffer.from(body, 'binary');
    }
    return null;
};

/**
 * Encode an ordered tuple of SQL values into a single comparison string.
 * The encoded tuple sorts correctly as a composite key.
 */
KC.encodeTuple = function (values) {
    return values.map(KC.encodeValue).join('');
};

/**
 * Lexicographic comparator for encoded keys.
 */
KC.compare = function (a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
};
