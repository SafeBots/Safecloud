'use strict';
/**
 * AdminAuth.js — WebAuthn passkey authentication and session tokens for the Safecloud Jet.
 *
 * No external npm dependencies — uses only Node.js built-in crypto and fs.
 *
 * Admin login flow:
 *   1. First visit:
 *        GET  /Streams/admin/register-options  → challenge + RP info
 *        browser: navigator.credentials.create({publicKey: ...})
 *        POST /Streams/admin/register          → stores credential in local/admin-cred.json
 *   2. Subsequent visits:
 *        GET  /Streams/admin/login-options     → challenge
 *        browser: navigator.credentials.get({publicKey: ...})
 *        POST /Streams/admin/login             → verifies assertion, returns Bearer token
 *   3. Protected API calls:
 *        Authorization: Bearer <token>
 *        AdminAuth.verifySession(token) → { ok: true } or { ok: false, error }
 *
 * Session tokens: base64url(JSON payload) + '.' + Ed25519-hex-sig (JetKey)
 * Credentials:    local/admin-cred.json — { credentialId, publicKeySpki, signCount }
 * Challenges:     in-memory, 5-minute TTL, consumed on use
 */

var crypto = require('crypto');
var fs     = require('fs');
var path   = require('path');

// ─── Module state ─────────────────────────────────────────────────────────────
var _credPath    = null;   // local/admin-cred.json
var _JetKey      = null;   // injected JetKey module
var _sessionMs   = 8 * 3600 * 1000;  // 8 hours default
var _challenges  = {};     // { b64u → { expiry: ms } }
var _pruneTimer  = null;
var _updateCors  = null;   // callback(origins) → update runtime CORS

/**
 * Wire up AdminAuth.
 * @param {Object} JetKey               — JetKey module for session signing
 * @param {string} appDir               — APP_DIR (parent of local/)
 * @param {number} [sessionHours=8]     — session lifetime
 * @param {Function} [updateCors]       — called with new origins array after PUT /admin/cors
 */
function init(JetKey, appDir, sessionHours, updateCors) {
    _JetKey     = JetKey;
    _credPath   = path.join(appDir || process.cwd(), 'local', 'admin-cred.json');
    _sessionMs  = ((sessionHours || 8) * 3600 * 1000);
    _updateCors = updateCors || null;

    // Prune expired challenges every 5 minutes
    if (_pruneTimer) clearInterval(_pruneTimer);
    _pruneTimer = setInterval(function () {
        var now = Date.now();
        Object.keys(_challenges).forEach(function (k) {
            if (_challenges[k].expiry < now) delete _challenges[k];
        });
    }, 5 * 60 * 1000).unref();
}

// ─── Credential file ──────────────────────────────────────────────────────────

function isRegistered() {
    return !!_credPath && fs.existsSync(_credPath);
}

function loadCredential() {
    if (!_credPath) return null;
    try { return JSON.parse(fs.readFileSync(_credPath, 'utf8')); }
    catch (e) { return null; }
}

function saveCredential(cred) {
    fs.mkdirSync(path.dirname(_credPath), { recursive: true });
    fs.writeFileSync(_credPath, JSON.stringify(cred, null, 2), 'utf8');
}

// ─── Challenge management ─────────────────────────────────────────────────────

/**
 * Generate a fresh 32-byte random challenge. Stored in memory, TTL 5 min.
 * @returns {string}  base64url-encoded challenge (safe to send to browser)
 */
function generateChallenge() {
    var raw  = crypto.randomBytes(32);
    var b64u = _toBase64Url(raw);
    _challenges[b64u] = { expiry: Date.now() + 5 * 60 * 1000 };
    return b64u;
}

/** Consume and validate a challenge. Returns true once only. */
function _consumeChallenge(b64u) {
    var entry = _challenges[b64u];
    if (!entry) return false;
    delete _challenges[b64u];
    return entry.expiry >= Date.now();
}

// ─── WebAuthn Registration ────────────────────────────────────────────────────

/**
 * Verify a WebAuthn `create` response and store the new admin credential.
 *
 * body shape (from browser PublicKeyCredential.toJSON() or manual encode):
 *   { id: string, response: { attestationObject: string, clientDataJSON: string } }
 * Both `attestationObject` and `clientDataJSON` are base64url-encoded.
 *
 * @param {Object} body
 * @param {string} expectedOrigin   e.g. 'http://localhost:9091'
 * @param {string} rpId             e.g. 'localhost'
 * @returns {{ ok: boolean, credentialId?: string, error?: string }}
 */
function verifyRegistration(body, expectedOrigin, rpId) {
    try {
        if (!body || !body.response) return { ok: false, error: 'Missing response' };

        // 1. Parse and validate clientDataJSON
        var clientDataBuf = _fromBase64Url(body.response.clientDataJSON);
        var clientData;
        try { clientData = JSON.parse(clientDataBuf.toString('utf8')); }
        catch (e) { return { ok: false, error: 'Invalid clientDataJSON: ' + e.message }; }

        if (clientData.type !== 'webauthn.create') {
            return { ok: false, error: 'clientData.type must be webauthn.create, got: ' + clientData.type };
        }
        if (!_consumeChallenge(clientData.challenge)) {
            return { ok: false, error: 'Invalid or expired challenge' };
        }
        // Normalise origin comparison (strip trailing slash)
        var gotOrigin = (clientData.origin || '').replace(/\/$/, '');
        var expOrigin = (expectedOrigin || '').replace(/\/$/, '');
        if (gotOrigin !== expOrigin) {
            return { ok: false, error: 'Origin mismatch: got ' + gotOrigin + ', expected ' + expOrigin };
        }

        // 2. Parse attestationObject (CBOR → { fmt, attStmt, authData })
        var attObjBuf = _fromBase64Url(body.response.attestationObject);
        var attObj;
        try { attObj = _cborDecode(attObjBuf); }
        catch (e) { return { ok: false, error: 'CBOR parse error: ' + e.message }; }

        var authData = attObj['authData'];
        if (!authData) return { ok: false, error: 'Missing authData in attestationObject' };
        if (!Buffer.isBuffer(authData)) authData = Buffer.from(authData);
        if (authData.length < 37) return { ok: false, error: 'authData too short' };

        // 3. Verify rpIdHash (first 32 bytes of authData)
        var rpIdHash = crypto.createHash('sha256').update(rpId, 'utf8').digest();
        if (!authData.slice(0, 32).equals(rpIdHash)) {
            return { ok: false, error: 'rpId hash mismatch — wrong hostname?' };
        }

        // 4. Flags (byte 32): bit 0 = UP (User Present), bit 2 = UV (User Verified)
        var flags = authData[32];
        if (!(flags & 0x01)) return { ok: false, error: 'User Presence flag not set' };
        // bit 6 = AT (Attested Credential Data included) — required for registration
        if (!(flags & 0x40)) return { ok: false, error: 'AT flag not set — no attested credential data' };

        // 5. Parse attestedCredentialData (starts at byte 37)
        //    Layout: AAGUID(16) | credIdLen(2 BE) | credId(credIdLen) | COSE_Key
        var offset = 37;
        if (authData.length < offset + 18) return { ok: false, error: 'authData truncated before credId' };
        offset += 16; // skip AAGUID
        var credIdLen = authData.readUInt16BE(offset); offset += 2;
        if (authData.length < offset + credIdLen) return { ok: false, error: 'authData truncated during credId' };
        var credentialId = authData.slice(offset, offset + credIdLen);
        offset += credIdLen;
        var coseKeyBuf = authData.slice(offset);

        // 6. Parse COSE P-256 public key → SPKI DER buffer
        var spki = _cosePubKeyToSpki(coseKeyBuf);
        if (!spki) return { ok: false, error: 'Could not parse COSE_Key — expected P-256 (alg -7)' };

        // 7. Store credential
        var cred = {
            credentialId:  credentialId.toString('hex'),
            publicKeySpki: spki.toString('hex'),
            signCount:     authData.readUInt32BE(33),
            createdAt:     new Date().toISOString()
        };
        saveCredential(cred);

        return { ok: true, credentialId: cred.credentialId };
    } catch (e) {
        return { ok: false, error: 'verifyRegistration: ' + e.message };
    }
}

// ─── WebAuthn Authentication ──────────────────────────────────────────────────

/**
 * Verify a WebAuthn `get` assertion and return a session token.
 *
 * body shape:
 *   { id: string, response: { authenticatorData: string, clientDataJSON: string, signature: string } }
 * All response fields are base64url-encoded.
 *
 * @param {Object} body
 * @param {string} expectedOrigin
 * @param {string} rpId
 * @returns {{ ok: boolean, token?: string, error?: string }}
 */
function verifyAuthentication(body, expectedOrigin, rpId) {
    try {
        var cred = loadCredential();
        if (!cred) return { ok: false, error: 'No admin passkey registered. Visit /admin.html to register one.' };

        if (!body || !body.response) return { ok: false, error: 'Missing response' };

        // 1. Verify credential ID
        var credIdHex = _fromBase64Url(body.id).toString('hex');
        if (credIdHex !== cred.credentialId) {
            return { ok: false, error: 'Credential ID mismatch' };
        }

        // 2. Parse clientDataJSON
        var clientDataBuf = _fromBase64Url(body.response.clientDataJSON);
        var clientData;
        try { clientData = JSON.parse(clientDataBuf.toString('utf8')); }
        catch (e) { return { ok: false, error: 'Invalid clientDataJSON' }; }

        if (clientData.type !== 'webauthn.get') {
            return { ok: false, error: 'clientData.type must be webauthn.get' };
        }
        if (!_consumeChallenge(clientData.challenge)) {
            return { ok: false, error: 'Invalid or expired challenge' };
        }
        var gotOrigin = (clientData.origin || '').replace(/\/$/, '');
        var expOrigin = (expectedOrigin || '').replace(/\/$/, '');
        if (gotOrigin !== expOrigin) {
            return { ok: false, error: 'Origin mismatch: got ' + gotOrigin + ', expected ' + expOrigin };
        }

        // 3. Parse authenticatorData
        var authData = _fromBase64Url(body.response.authenticatorData);
        if (!Buffer.isBuffer(authData)) authData = Buffer.from(authData);
        if (authData.length < 37) return { ok: false, error: 'authenticatorData too short' };

        // 4. Verify rpIdHash
        var rpIdHash = crypto.createHash('sha256').update(rpId, 'utf8').digest();
        if (!authData.slice(0, 32).equals(rpIdHash)) {
            return { ok: false, error: 'rpId hash mismatch' };
        }

        // 5. Check UP flag
        var flags = authData[32];
        if (!(flags & 0x01)) return { ok: false, error: 'User Presence flag not set' };

        // 6. Verify signature: ECDSA-P256-SHA256 over (authenticatorData ‖ SHA-256(clientDataJSON))
        var clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
        var verificationData = Buffer.concat([authData, clientDataHash]);

        var sigBuf  = _fromBase64Url(body.response.signature);
        var spkiBuf = Buffer.from(cred.publicKeySpki, 'hex');
        var pubKey;
        try {
            pubKey = crypto.createPublicKey({ key: spkiBuf, format: 'der', type: 'spki' });
        } catch (e) {
            return { ok: false, error: 'Invalid stored public key: ' + e.message };
        }

        var valid;
        try {
            // Node's crypto.verify with 'sha256' hashes the data once internally —
            // correct for ECDSA signing where the algo is ECDSA(SHA256(data)).
            valid = crypto.verify('sha256', verificationData, pubKey, sigBuf);
        } catch (e) {
            return { ok: false, error: 'Signature verification threw: ' + e.message };
        }

        if (!valid) return { ok: false, error: 'Signature verification failed' };

        // 7. Anti-clone: sign count must increase (unless it was 0)
        var newCount = authData.readUInt32BE(33);
        if (cred.signCount !== 0 && newCount !== 0 && newCount <= cred.signCount) {
            console.warn('[AdminAuth] WARNING: sign count did not increase (%d → %d) — possible cloned authenticator',
                cred.signCount, newCount);
        }
        cred.signCount = newCount;
        saveCredential(cred);

        // 8. Issue session token
        return { ok: true, token: createSessionToken() };
    } catch (e) {
        return { ok: false, error: 'verifyAuthentication: ' + e.message };
    }
}

// ─── Session tokens ───────────────────────────────────────────────────────────

/**
 * Create a new signed session token.
 * Format: base64url(JSON) + '.' + Ed25519-hex-sig
 */
function createSessionToken() {
    var payload = JSON.stringify({
        sub: 'admin',
        iat: Date.now(),
        exp: Date.now() + _sessionMs
    });
    var sigHex = _JetKey
        ? _JetKey.sign(payload)
        : crypto.randomBytes(64).toString('hex'); // fallback: unverifiable random (dev only)
    return _toBase64Url(Buffer.from(payload, 'utf8')) + '.' + sigHex;
}

/**
 * Verify a session token.
 * @param {string} token
 * @returns {{ ok: boolean, payload?: Object, error?: string }}
 */
function verifySession(token) {
    if (!token || typeof token !== 'string') return { ok: false, error: 'No token' };
    try {
        var dot = token.indexOf('.');
        if (dot < 0) return { ok: false, error: 'Malformed token' };
        var payloadBuf = _fromBase64Url(token.slice(0, dot));
        var sigHex     = token.slice(dot + 1);
        var payload;
        try { payload = JSON.parse(payloadBuf.toString('utf8')); }
        catch (e) { return { ok: false, error: 'Invalid token payload' }; }
        if (payload.sub !== 'admin') return { ok: false, error: 'Not an admin token' };
        if (!payload.exp || payload.exp < Date.now()) return { ok: false, error: 'Token expired' };
        if (_JetKey && !_JetKey.verify(payloadBuf.toString('utf8'), sigHex, _JetKey.publicKeyHex())) {
            return { ok: false, error: 'Invalid token signature' };
        }
        return { ok: true, payload: payload };
    } catch (e) {
        return { ok: false, error: 'verifySession: ' + e.message };
    }
}

/** Expose the runtime CORS updater for use by admin routes. */
function updateAllowedOrigins(origins) {
    if (typeof _updateCors === 'function') _updateCors(origins);
}

// ─── COSE public key → SPKI DER ──────────────────────────────────────────────

/**
 * Parse a COSE_Key encoding of a P-256 public key and return an SPKI DER buffer
 * suitable for crypto.createPublicKey({ key, format:'der', type:'spki' }).
 *
 * Expected CBOR map keys:
 *   1  (kty)  → 2  (EC)
 *   3  (alg)  → -7 (ES256 / ECDSA-P256-SHA256)
 *  -1  (crv)  → 1  (P-256)
 *  -2  (x)    → 32-byte Buffer
 *  -3  (y)    → 32-byte Buffer
 */
function _cosePubKeyToSpki(cbor) {
    try {
        var map = _cborDecode(cbor);
        var x, y;
        // Keys come out as numbers (integers in CBOR)
        Object.keys(map).forEach(function (k) {
            var ki = Number(k);
            if (ki === -2) x = map[k];
            if (ki === -3) y = map[k];
        });
        if (!x || !y || x.length !== 32 || y.length !== 32) return null;
        // Uncompressed P-256 point: 0x04 ‖ x ‖ y
        var point  = Buffer.concat([Buffer.from([0x04]), Buffer.from(x), Buffer.from(y)]);
        // P-256 SPKI DER header (SubjectPublicKeyInfo for id-ecPublicKey + P-256 OID)
        var header = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
        return Buffer.concat([header, point]);
    } catch (e) {
        return null;
    }
}

// ─── Minimal CBOR decoder ─────────────────────────────────────────────────────
// Handles: unsigned int (0), negative int (1), byte string (2), text string (3),
//          array (4), map (5) — sufficient for WebAuthn attestationObject / COSE_Key.

function _cborDecode(buf) {
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
    var off = { v: 0 };
    return _cborRead(buf, off);
}

function _cborRead(buf, off) {
    if (off.v >= buf.length) throw new Error('CBOR: unexpected end at offset ' + off.v);
    var byte0 = buf[off.v++];
    var mt    = (byte0 >> 5) & 0x07;   // major type
    var ai    = byte0 & 0x1f;           // additional info
    var len   = _cborLen(buf, off, ai);

    switch (mt) {
        case 0:  // unsigned integer
            return len;
        case 1:  // negative integer: value is -1 - len
            return -1 - len;
        case 2: { // byte string
            var bs = buf.slice(off.v, off.v + len);
            off.v += len;
            return bs;
        }
        case 3: { // text string
            var ts = buf.slice(off.v, off.v + len).toString('utf8');
            off.v += len;
            return ts;
        }
        case 4: { // array
            var arr = [];
            for (var i = 0; i < len; i++) arr.push(_cborRead(buf, off));
            return arr;
        }
        case 5: { // map
            var map = {};
            for (var j = 0; j < len; j++) {
                var k = _cborRead(buf, off);
                var v = _cborRead(buf, off);
                map[String(k)] = v;
            }
            return map;
        }
        default:
            throw new Error('CBOR: unsupported major type ' + mt + ' at offset ' + (off.v - 1));
    }
}

function _cborLen(buf, off, ai) {
    if (ai < 24) return ai;
    if (ai === 24) { return buf[off.v++]; }
    if (ai === 25) { var v  = buf.readUInt16BE(off.v); off.v += 2; return v; }
    if (ai === 26) { var v2 = buf.readUInt32BE(off.v); off.v += 4; return v2; }
    // ai 27 would be a 64-bit integer — not needed for our use case
    throw new Error('CBOR: unsupported additional info ' + ai);
}

// ─── base64url helpers ────────────────────────────────────────────────────────

function _toBase64Url(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function _fromBase64Url(str) {
    if (!str) return Buffer.alloc(0);
    // Re-add standard base64 padding
    var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    var pad = s.length % 4;
    if (pad === 2) s += '==';
    else if (pad === 3) s += '=';
    return Buffer.from(s, 'base64');
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
    init:                  init,
    isRegistered:          isRegistered,
    generateChallenge:     generateChallenge,
    verifyRegistration:    verifyRegistration,
    verifyAuthentication:  verifyAuthentication,
    createSessionToken:    createSessionToken,
    verifySession:         verifySession,
    updateAllowedOrigins:  updateAllowedOrigins,
    // exposed for tests
    _cborDecode:           _cborDecode,
    _cosePubKeyToSpki:     _cosePubKeyToSpki
};
