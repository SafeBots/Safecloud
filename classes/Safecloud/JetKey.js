'use strict';
/**
 * JetKey.js — Ed25519 keypair management for the Safecloud Jet.
 *
 * Generates a keypair on first use and persists it to local/jet-key.json.
 * Provides sign() and verify() helpers using Node.js built-in crypto
 * (Ed25519 is available from Node 15+).
 *
 * Signing payload for each message record:
 *   "${epoch}|${ordinal}|${prev_hash}|${publisherId}|${streamName}|${content}|${byUserId}|${insertedTime}"
 *
 * prev_hash of record N = SHA-256(sigPayload(record N-1)), hex-encoded.
 * prev_hash of the first record in a stream = '' (genesis).
 *
 * This creates a linear hash chain: tampering with any record invalidates
 * all subsequent records, and equivocation (two signed records with the
 * same (epoch, ordinal)) is detectable by any verifier who holds both.
 */

var crypto = require('crypto');
var fs     = require('fs');
var path   = require('path');

var _keyPair   = null;
var _publicHex = null;

// ─── Ed25519 SPKI DER construction ───────────────────────────────────────────
// ASN.1: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (key) }
// 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 raw bytes>
var ED25519_SPKI_HEADER = Buffer.from('302a300506032b6570032100', 'hex');

function _rawEd25519ToSpki(raw32) {
    return Buffer.concat([ED25519_SPKI_HEADER, raw32]);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Load or generate the Jet Ed25519 keypair.
 * Saves the key material to `keyPath` (default: local/jet-key.json).
 * Idempotent — safe to call multiple times.
 *
 * @param {string} [keyPath]
 * @returns {{ publicKeyHex: string }}
 */
function init(keyPath) {
    if (_keyPair) return { publicKeyHex: _publicHex };

    keyPath = keyPath || path.join(
        process.env.SAFECLOUD_DIR || process.cwd(),
        'local', 'jet-key.json'
    );

    try {
        var saved   = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
        _keyPair    = {
            privateKey: crypto.createPrivateKey({ key: Buffer.from(saved.privateKeyDer, 'hex'), format: 'der', type: 'pkcs8' }),
            publicKey:  crypto.createPublicKey({ key: Buffer.from(saved.publicKeyDer, 'hex'), format: 'der', type: 'spki' })
        };
        _publicHex = saved.publicKeyHex;
        console.log('[JetKey] Loaded existing Ed25519 keypair from ' + keyPath);
    } catch (e) {
        var kp     = crypto.generateKeyPairSync('ed25519');
        var privDer = kp.privateKey.export({ type: 'pkcs8', format: 'der' });
        var pubDer  = kp.publicKey.export({ type: 'spki', format: 'der' });
        // Ed25519 raw 32-byte public key is the last 32 bytes of SPKI DER
        var rawPub  = pubDer.slice(pubDer.length - 32);
        _publicHex  = rawPub.toString('hex');

        fs.mkdirSync(path.dirname(keyPath), { recursive: true });
        fs.writeFileSync(keyPath, JSON.stringify({
            privateKeyDer: privDer.toString('hex'),
            publicKeyDer:  pubDer.toString('hex'),
            publicKeyHex:  _publicHex
        }, null, 2), 'utf8');

        _keyPair = kp;
        console.log('[JetKey] Generated new Ed25519 keypair, saved to ' + keyPath);
    }

    return { publicKeyHex: _publicHex };
}

/**
 * Build the canonical signing payload string for a message record.
 *
 * @param {Object} p  { epoch, ordinal, prev_hash, publisherId, streamName, content, byUserId, insertedTime }
 * @returns {string}
 */
function sigPayload(p) {
    return [
        p.epoch        != null ? String(p.epoch)    : '1',
        p.ordinal      != null ? String(p.ordinal)  : '0',
        p.prev_hash    || '',
        p.publisherId  || '',
        p.streamName   || '',
        p.content      || '',
        p.byUserId     || '',
        p.insertedTime || ''
    ].join('|');
}

/**
 * Compute SHA-256 of a signing payload string — becomes the prev_hash
 * stored in the next record.
 *
 * @param {string} payload
 * @returns {string}  hex-encoded SHA-256 digest
 */
function hashPayload(payload) {
    return crypto.createHash('sha256').update(Buffer.from(payload, 'utf8')).digest('hex');
}

/**
 * Sign `payload` with the Jet's Ed25519 private key.
 * Returns a hex-encoded 64-byte signature.
 *
 * @param {string|Buffer} payload
 * @returns {string}
 */
function sign(payload) {
    if (!_keyPair) throw new Error('JetKey.sign: call init() first');
    var buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
    return crypto.sign(null, buf, _keyPair.privateKey).toString('hex');
}

/**
 * Verify an Ed25519 signature.
 *
 * @param {string|Buffer} payload    The signed payload
 * @param {string}        sigHex     hex-encoded 64-byte signature
 * @param {string}        pubKeyHex  hex-encoded 32-byte raw public key
 * @returns {boolean}
 */
function verify(payload, sigHex, pubKeyHex) {
    try {
        var buf    = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
        var sigBuf = Buffer.from(sigHex, 'hex');
        var rawPub = Buffer.from(pubKeyHex, 'hex');
        var spki   = _rawEd25519ToSpki(rawPub);
        var pubKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
        return crypto.verify(null, buf, pubKey, sigBuf);
    } catch (e) {
        return false;
    }
}

/** Return the hex-encoded 32-byte public key (after init). */
function publicKeyHex() { return _publicHex; }

module.exports = { init: init, sign: sign, verify: verify, publicKeyHex: publicKeyHex, sigPayload: sigPayload, hashPayload: hashPayload };
