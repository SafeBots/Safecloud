/**
 * ocp.js — OpenClaiming Protocol verifier (standalone, browser + Node.js).
 *
 * Zero-dependency. Uses:
 *   • Browser: Web Crypto API (SubtleCrypto) — available in all modern browsers
 *   • Node.js: built-in `crypto` module (Node 15+ for Ed25519 support)
 *
 * Usage (browser — returns a Promise):
 *   import OCP from './ocp.js';
 *   const result = await OCP.verify(claimObj);
 *   if (!result.ok) { console.error(result.error); return; }
 *   console.log(result.pub, result.sub, result.stm);
 *
 * Usage (Node.js — same API):
 *   const OCP = require('./ocp.js');
 *   const result = await OCP.verify(claimJson);
 *
 * @version 1.0
 * @see https://openclaiming.org/spec
 */

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        // Node.js
        module.exports = factory(require('crypto'));
    } else if (typeof define === 'function' && define.amd) {
        // AMD
        define([], function () { return factory(null); });
    } else {
        // Browser global
        root.OCP = factory(null);
    }
}(typeof self !== 'undefined' ? self : this, function (nodeCrypto) {
    'use strict';

    // ── Environment detection ──────────────────────────────────────────────────

    var isNode = typeof module !== 'undefined' && module.exports;

    // ── Utilities ─────────────────────────────────────────────────────────────

    function hexToBytes(hex) {
        var bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
        return bytes;
    }

    function ok(pub, sub, stm, nbf, exp, claim) {
        return { ok: true, pub: pub, sub: sub, stm: stm, nbf: nbf || null, exp: exp || null, claim: claim };
    }

    function fail(error) {
        return { ok: false, error: error };
    }

    // ── Canonicalization (§2) ─────────────────────────────────────────────────

    /**
     * Produce the canonical byte string of a claim for signing/verification.
     *
     * §2: Remove the `sig` field, sort the remaining keys alphabetically, and
     * JSON-serialise with no extra whitespace (no unescaped Unicode escaping
     * required; browsers and Node produce equivalent output for ASCII keys and
     * values).
     *
     * @param {object} claim  the full claim object (may include sig)
     * @returns {string}  canonical JSON string
     */
    function canonicalize(claim) {
        var unsigned = Object.assign({}, claim);
        delete unsigned.sig;
        var keys = Object.keys(unsigned).sort();
        var out = {};
        for (var i = 0; i < keys.length; i++) { out[keys[i]] = unsigned[keys[i]]; }
        return JSON.stringify(out);
    }

    // ── Signature verification (§3 — Ed25519 over SHA-256) ───────────────────

    /**
     * Verify an Ed25519 signature.
     *
     * §3: The signed bytes are SHA-256(canonicalize(claim)).
     * The signature is 64 raw bytes; the issuer key is the 32-byte raw Ed25519
     * public key.  Both are encoded as lowercase hex in the claim.
     *
     * @param {string} canon     canonical claim string
     * @param {string} sigHex    64-byte (128 hex char) signature
     * @param {string} pubHex    32-byte (64 hex char) public key
     * @returns {Promise<boolean>}
     */
    function verifySignature(canon, sigHex, pubHex) {
        if (isNode) {
            return verifySignatureNode(canon, sigHex, pubHex);
        }
        return verifySignatureBrowser(canon, sigHex, pubHex);
    }

    function verifySignatureBrowser(canon, sigHex, pubHex) {
        var enc     = new TextEncoder();
        var sigBuf  = hexToBytes(sigHex);
        var pubRaw  = hexToBytes(pubHex);
        // Build SPKI DER for Ed25519: 12-byte header + 32-byte key
        var spkiHeader = new Uint8Array([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]);
        var spki       = new Uint8Array(spkiHeader.length + pubRaw.length);
        spki.set(spkiHeader);
        spki.set(pubRaw, spkiHeader.length);

        return crypto.subtle.importKey('spki', spki.buffer, { name: 'Ed25519' }, false, ['verify'])
            .then(function (key) {
                return crypto.subtle.digest('SHA-256', enc.encode(canon)).then(function (hash) {
                    return crypto.subtle.verify({ name: 'Ed25519' }, key, sigBuf, hash);
                });
            });
    }

    function verifySignatureNode(canon, sigHex, pubHex) {
        return new Promise(function (resolve) {
            try {
                var pubRaw    = Buffer.from(pubHex, 'hex');
                // Build SPKI DER for Ed25519: 12-byte header + 32-byte key
                var header    = Buffer.from('302a300506032b6570032100', 'hex');
                var spki      = Buffer.concat([header, pubRaw]);
                var pubKey    = nodeCrypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
                var hashBuf   = nodeCrypto.createHash('sha256').update(canon, 'utf8').digest();
                var sigBuf    = Buffer.from(sigHex, 'hex');
                resolve(nodeCrypto.verify(null, hashBuf, pubKey, sigBuf));
            } catch (e) {
                resolve(false);
            }
        });
    }

    // ── Core verify ───────────────────────────────────────────────────────────

    /**
     * Parse and verify an OCP claim.
     *
     * @param {string|object} input  JSON string or decoded claim object
     * @returns {Promise<object>}
     *   { ok: true,  pub, sub, stm, nbf, exp, claim }
     *   { ok: false, error }
     */
    function verify(input) {
        // ── 1. Decode ────────────────────────────────────────────────────────
        var claim;
        if (typeof input === 'string') {
            try { claim = JSON.parse(input); }
            catch (e) { return Promise.resolve(fail('OCP: JSON parse failed')); }
        } else if (input && typeof input === 'object') {
            claim = input;
        } else {
            return Promise.resolve(fail('OCP: input must be a string or object'));
        }

        // ── 2. Required fields ───────────────────────────────────────────────
        if (claim.ocp !== 1) {
            return Promise.resolve(fail('OCP: ocp field must equal 1'));
        }
        if (!claim.iss || typeof claim.iss !== 'string') {
            return Promise.resolve(fail('OCP: iss field required'));
        }
        if (!claim.sig || typeof claim.sig !== 'string') {
            return Promise.resolve(fail('OCP: sig field required'));
        }

        // ── 3. Parse issuer (§1 — iss URI) ──────────────────────────────────
        // iss = "data:key/ed25519;hex,<64 hex chars>"
        var issMatch = claim.iss.match(/^data:key\/ed25519;hex,([0-9a-f]{64})$/i);
        if (!issMatch) {
            return Promise.resolve(fail('OCP: iss must be data:key/ed25519;hex,<64hexchars>'));
        }
        var pubHex = issMatch[1].toLowerCase();

        // Sig must be 128 hex chars (64 bytes)
        if (!/^[0-9a-f]{128}$/i.test(claim.sig)) {
            return Promise.resolve(fail('OCP: sig must be 128 hex chars (64-byte Ed25519 signature)'));
        }
        var sigHex = claim.sig.toLowerCase();

        // ── 4. Temporal validation (§1 — nbf / exp) ──────────────────────────
        var now = Math.floor(Date.now() / 1000);
        if (claim.nbf && claim.nbf > now + 300) {   // 5-minute clock skew
            return Promise.resolve(fail('OCP: claim not yet valid (nbf)'));
        }
        if (claim.exp && claim.exp < now) {
            return Promise.resolve(fail('OCP: claim expired (exp)'));
        }

        // ── 5. Canonicalize & verify signature (§2, §3) ──────────────────────
        var canon = canonicalize(claim);

        return verifySignature(canon, sigHex, pubHex).then(function (valid) {
            if (!valid) { return fail('OCP: signature verification failed'); }
            return ok(pubHex, claim.sub || null, claim.stm || {}, claim.nbf || null, claim.exp || null, claim);
        }).catch(function (e) {
            return fail('OCP: verification error — ' + e.message);
        });
    }

    // ── Publisher cert helper ─────────────────────────────────────────────────

    /**
     * Verify that a claim is a valid publisher cert for the given publisher ID
     * and optionally a specific root CID.
     *
     * @param {string|object} input     OCP claim
     * @param {string} publisherId      expected sub / stm.publisherId
     * @param {string|null} [rootCid]   if set, cert must cover this root (or all roots)
     * @returns {Promise<object>}  same as verify()
     */
    function verifyPublisherCert(input, publisherId, rootCid) {
        return verify(input).then(function (result) {
            if (!result.ok) { return result; }
            var stm = result.stm || {};
            var sub = result.sub || stm.publisherId || null;
            if (sub !== publisherId) {
                return fail('OCP: cert sub does not match expected publisher');
            }
            if (rootCid != null) {
                var certRoot = stm.rootCid || null;
                if (certRoot != null && certRoot !== rootCid) {
                    return fail('OCP: cert rootCid does not cover this content');
                }
            }
            return result;
        });
    }

    // ── Sign (requires private key — Node.js or browser with Ed25519 keygen) ──

    /**
     * Sign a claim object with an Ed25519 private key.
     *
     * @param {object} claimFields  claim fields WITHOUT sig (ocp, iss, sub, stm, nbf, exp, …)
     * @param {string} privHex      32-byte Ed25519 private key scalar as 64 hex chars
     * @returns {Promise<object>}   claim object with sig field set
     */
    function sign(claimFields, privHex) {
        var claim = Object.assign({ ocp: 1 }, claimFields);
        delete claim.sig;
        var canon = canonicalize(claim);
        if (isNode) {
            return new Promise(function (resolve, reject) {
                try {
                    var privBytes  = Buffer.from(privHex, 'hex');
                    var pkcs8Hdr   = Buffer.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
                    var pkcs8      = Buffer.concat([pkcs8Hdr, privBytes]);
                    var privKey    = nodeCrypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
                    var hashBuf    = nodeCrypto.createHash('sha256').update(canon, 'utf8').digest();
                    var sigBuf     = nodeCrypto.sign(null, hashBuf, privKey);
                    claim.sig = sigBuf.toString('hex');
                    resolve(claim);
                } catch (e) { reject(e); }
            });
        }
        // Browser
        var privBytes = hexToBytes(privHex);
        var pkcs8Hdr  = new Uint8Array([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
        var pkcs8     = new Uint8Array(pkcs8Hdr.length + privBytes.length);
        pkcs8.set(pkcs8Hdr); pkcs8.set(privBytes, pkcs8Hdr.length);
        return crypto.subtle.importKey('pkcs8', pkcs8.buffer, { name: 'Ed25519' }, false, ['sign'])
            .then(function (key) {
                return crypto.subtle.digest('SHA-256', new TextEncoder().encode(canon)).then(function (hash) {
                    return crypto.subtle.sign({ name: 'Ed25519' }, key, hash);
                });
            })
            .then(function (sigBuf) {
                var sigArr = new Uint8Array(sigBuf);
                claim.sig = Array.from(sigArr).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
                return claim;
            });
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    return {
        verify:               verify,
        verifyPublisherCert:  verifyPublisherCert,
        sign:                 sign,
        canonicalize:         canonicalize,
        /** OCP spec version this library implements */
        version: '1.0',
    };
}));
