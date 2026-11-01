'use strict';
/**
 * Minimal CBOR decoder — handles the subset used by AWS Nitro attestation
 * documents (COSE_Sign1 structure): maps, arrays, byte strings, text strings,
 * unsigned and negative integers, booleans, null.
 *
 * Does NOT support indefinite-length items, floats, tags (ignored), or the
 * full CBOR spec — only what Nitro actually emits.
 */

/**
 * Decode a CBOR-encoded Buffer/Uint8Array.
 * @param {Buffer|Uint8Array} buf
 * @returns {*} decoded value
 */
function decodeCBOR(buf) {
    var view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    var pos  = { offset: 0 };
    var val  = _readItem(view, pos);
    return val;
}

function _readItem(v, pos) {
    var b    = v[pos.offset++];
    var mt   = (b >> 5) & 0x07;   // major type (top 3 bits)
    var ai   = b & 0x1f;           // additional info (bottom 5 bits)
    var arg  = _readArg(v, pos, ai);

    switch (mt) {
        case 0: // unsigned integer
            return arg;
        case 1: // negative integer: -1 - arg
            return -1 - arg;
        case 2: // byte string
            return _readBytes(v, pos, arg);
        case 3: // text string
            return _readText(v, pos, arg);
        case 4: // array
            return _readArray(v, pos, arg);
        case 5: // map
            return _readMap(v, pos, arg);
        case 6: // tag — consume and recurse (we ignore the tag value)
            return _readItem(v, pos);
        case 7: // float/simple
            if (ai === 20) return false;
            if (ai === 21) return true;
            if (ai === 22) return null;
            if (ai === 23) return undefined;
            // float16 (ai=25), float32 (ai=26), float64 (ai=27)
            // skip the bytes; return null (Nitro doesn't use floats here)
            if (ai === 25) { pos.offset += 2; return null; }
            if (ai === 26) { pos.offset += 4; return null; }
            if (ai === 27) { pos.offset += 8; return null; }
            return null;
        default:
            throw new Error('cbor: unknown major type ' + mt);
    }
}

function _readArg(v, pos, ai) {
    if (ai <= 23)  return ai;
    if (ai === 24) return v[pos.offset++];
    if (ai === 25) {
        var n = (v[pos.offset] << 8) | v[pos.offset + 1];
        pos.offset += 2;
        return n;
    }
    if (ai === 26) {
        var n2 = ((v[pos.offset] << 24) | (v[pos.offset+1] << 16) |
                  (v[pos.offset+2] << 8) | v[pos.offset+3]) >>> 0;
        pos.offset += 4;
        return n2;
    }
    if (ai === 27) {
        // 64-bit — only safe for lengths that fit in 53 bits; Nitro doc sizes do
        var hi = ((v[pos.offset] * 0x1000000) +
                  ((v[pos.offset+1] << 16) | (v[pos.offset+2] << 8) | v[pos.offset+3]));
        var lo = ((v[pos.offset+4] * 0x1000000) +
                  ((v[pos.offset+5] << 16) | (v[pos.offset+6] << 8) | v[pos.offset+7]));
        pos.offset += 8;
        return hi * 0x100000000 + lo;
    }
    throw new Error('cbor: indefinite-length not supported (ai=' + ai + ')');
}

function _readBytes(v, pos, len) {
    var slice = v.slice(pos.offset, pos.offset + len);
    pos.offset += len;
    return Buffer.from(slice);
}

function _readText(v, pos, len) {
    var slice = v.slice(pos.offset, pos.offset + len);
    pos.offset += len;
    return Buffer.from(slice).toString('utf8');
}

function _readArray(v, pos, count) {
    var arr = [];
    for (var i = 0; i < count; i++) arr.push(_readItem(v, pos));
    return arr;
}

function _readMap(v, pos, count) {
    var map = {};
    for (var i = 0; i < count; i++) {
        var key = _readItem(v, pos);
        var val = _readItem(v, pos);
        map[key] = val;
    }
    return map;
}

// ── Encoder (used by fixture generator only) ──────────────────────────────────

function encodeCBOR(val) {
    if (val === null || val === undefined) return Buffer.from([0xf6]);
    if (val === true)  return Buffer.from([0xf5]);
    if (val === false) return Buffer.from([0xf4]);
    if (typeof val === 'number') {
        if (val < 0) {
            // Negative: major type 1, value = -1 - n
            return _encodeHead(1, -1 - val);
        }
        return _encodeHead(0, val);
    }
    if (typeof val === 'string') {
        var sb = Buffer.from(val, 'utf8');
        return Buffer.concat([_encodeHead(3, sb.length), sb]);
    }
    if (Buffer.isBuffer(val) || val instanceof Uint8Array) {
        var b2 = Buffer.isBuffer(val) ? val : Buffer.from(val);
        return Buffer.concat([_encodeHead(2, b2.length), b2]);
    }
    if (Array.isArray(val)) {
        var parts = [_encodeHead(4, val.length)];
        for (var i = 0; i < val.length; i++) parts.push(encodeCBOR(val[i]));
        return Buffer.concat(parts);
    }
    if (typeof val === 'object') {
        var keys = Object.keys(val);
        var mp   = [_encodeHead(5, keys.length)];
        for (var k = 0; k < keys.length; k++) {
            mp.push(encodeCBOR(keys[k]));
            mp.push(encodeCBOR(val[keys[k]]));
        }
        return Buffer.concat(mp);
    }
    throw new Error('cbor: unsupported type ' + typeof val);
}

function _encodeHead(mt, val) {
    var prefix = mt << 5;
    if (val <= 23)  return Buffer.from([prefix | val]);
    if (val <= 0xff) return Buffer.from([prefix | 24, val]);
    if (val <= 0xffff) return Buffer.from([prefix | 25, val >> 8, val & 0xff]);
    if (val <= 0xffffffff) {
        return Buffer.from([prefix | 26,
            (val >>> 24) & 0xff, (val >>> 16) & 0xff,
            (val >>> 8)  & 0xff,  val         & 0xff]);
    }
    // 8-byte uint (CBOR additional info 27): split into high and low 32-bit halves.
    // JavaScript numbers are IEEE-754 doubles, so integers up to 2^53 are exact.
    var hi = Math.floor(val / 0x100000000);
    var lo = val >>> 0; // low 32 bits (unsigned)
    return Buffer.from([
        prefix | 27,
        (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
        (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff
    ]);
}

module.exports = { decodeCBOR, encodeCBOR };
