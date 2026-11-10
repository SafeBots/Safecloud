'use strict';
/**
 * Safecloud KeyIssuance — per-chunk key derivation and gated issuance.
 *
 * # Architecture
 *
 * For pay-per-minute / pay-per-second streams the Jet holds the stream's root
 * encryption key server-side and releases only *per-chunk* derived keys to
 * paying, optionally attested, clients.
 *
 * The derivation is one-way:
 *
 *   chunkKey_i = HKDF-SHA256(rootKey, "safecloud.chunk.v1.<i>", 32 bytes)
 *
 * A client holding chunkKey_3 cannot reconstruct the rootKey or any other
 * chunkKey_j (j ≠ 3) — the HKDF PRF gives standard one-wayness.
 *
 * The Jet issues keys *only* for the chunks the client is currently permitted
 * to decode (the rolling-rewind window, or all of them for session/permanent
 * models).  The client is responsible for destroying expired keys; on a
 * Safebox-attested client the Jet can verify this by refusing to re-issue a
 * key for a chunk that has fallen outside the window.
 *
 * # Payment gate
 *
 * `issueKeys` delegates payment verification to an injected `checkPayment`
 * function so the caller (Jets.js) can reuse the existing OCP/EIP-712
 * infrastructure without coupling this module to it.
 *
 * # Attestation gate (optional)
 *
 * When `accessModel.requireAttestation` is true the client MUST supply an
 * `attestation` token.  `verifyClientAttestation` checks:
 *   1. The token is a valid Safebox attestation document.
 *   2. The build hash inside the token appears on the `blessedBuilds` list.
 *
 * Individual users can always extract in-memory keys from an unattested
 * browser — that is accepted (screen-capture equivalent).  The gate blocks
 * *distribution* of a patched client, because a modified build has a
 * different hash and therefore can't be on the blessed list.
 *
 * @module Safecloud/KeyIssuance
 */

var crypto = require('crypto');

/**
 * HKDF-SHA256 (RFC 5869), Node.js built-in.
 *
 * @param  {Buffer|Uint8Array} ikm       Input keying material.
 * @param  {string}            info      Context string.
 * @param  {number}            [len=32]  Output length in bytes.
 * @return {Buffer}
 */
function hkdf(ikm, info, len) {
    // Node 15+ exposes crypto.hkdfSync; fall back to the callback API for older
    // runtimes still in production use on some Safecloud hosts.
    var length = len || 32;
    var salt = Buffer.alloc(32); // zero salt (intentional; rootKey carries all entropy)
    var infoBytes = Buffer.from(info, 'utf8');

    if (typeof crypto.hkdfSync === 'function') {
        return Buffer.from(
            crypto.hkdfSync('sha256', ikm, salt, infoBytes, length)
        );
    }

    // Callback fallback — wrap in a sync-like block via a fiber-free approach:
    // We implement HKDF manually for environments without hkdfSync.
    return _hkdfManual('sha256', ikm, salt, infoBytes, length);
}

/**
 * Manual HKDF-SHA256 (RFC 5869) for older Node.js runtimes.
 * @private
 */
function _hkdfManual(hashName, ikm, salt, info, length) {
    // Extract
    var prk = crypto.createHmac(hashName, salt).update(ikm).digest();
    // Expand
    var blocks = Math.ceil(length / prk.length);
    var t = Buffer.alloc(0);
    var okm = Buffer.alloc(0);
    for (var i = 1; i <= blocks; i++) {
        var input = Buffer.concat([t, info, Buffer.from([i])]);
        t = crypto.createHmac(hashName, prk).update(input).digest();
        okm = Buffer.concat([okm, t]);
    }
    return okm.slice(0, length);
}

/**
 * Derive a chunk-level decryption key from the stream root key.
 *
 * The derivation is deterministic and one-way: given `chunkKey_i` an
 * attacker cannot reconstruct `rootKey` or any `chunkKey_j` (j ≠ i).
 *
 * @param  {Buffer|string} rootKey     32-byte root key (Buffer or base64 string).
 * @param  {string}        rootCid     Content-identifier of the root manifest.
 * @param  {number}        chunkIndex  Zero-based chunk index.
 * @return {Buffer}  32-byte chunk key.
 */
function deriveChunkKey(rootKey, rootCid, chunkIndex) {
    var ikmBuf = Buffer.isBuffer(rootKey) ? rootKey : Buffer.from(rootKey, 'base64');
    var info = 'safecloud.chunk.v1.' + String(chunkIndex);
    return hkdf(ikmBuf, info, 32);
}

/**
 * Issue per-chunk decryption keys after payment and (optionally) attestation
 * verification.
 *
 * @param  {Object}   opts
 * @param  {string}   opts.rootCid           CID of the root manifest.
 * @param  {number[]} opts.chunkIndices       Indices to issue keys for.
 * @param  {Buffer|string} opts.rootKey       Root key (from the Jet's key store).
 * @param  {Object}   opts.accessModel        Parsed AccessModel from Access.js.
 * @param  {string}   [opts.paymentSig]       Base64-encoded OCP envelope (required
 *                                            when accessModel.model !== 'permanent'
 *                                            or the caller wants payment gating).
 * @param  {string}   [opts.attestation]      Base64-encoded attestation token
 *                                            (required when requireAttestation).
 * @param  {string[]} [opts.blessedBuilds]    Allowed build hashes for attestation.
 * @param  {Function} opts.checkPayment       `async (paymentSig, accessModel, rootCid)
 *                                            → { ok, error }`. Injected by Jets.js.
 * @param  {Function} [opts.verifyAttestation] `async (token, blessedBuilds)
 *                                             → { ok, buildHash, error }`.
 *                                             Defaults to verifyClientAttestation.
 * @return {Promise<{ keys: Object<number,string> }>}
 *         Resolves to `{ keys: { "<index>": "<base64>" } }` or rejects with an
 *         error that carries a `.statusCode` for the HTTP layer to use.
 */
function issueKeys(opts) {
    var rootCid        = opts.rootCid;
    var chunkIndices   = opts.chunkIndices;
    var rootKey        = opts.rootKey;
    var accessModel    = opts.accessModel;
    var paymentSig     = opts.paymentSig;
    var attestation    = opts.attestation;
    var blessedBuilds  = opts.blessedBuilds || [];
    var checkPayment   = opts.checkPayment;
    var attestFn       = opts.verifyAttestation || verifyClientAttestation;

    if (!rootCid)      return Promise.reject(_err(400, 'rootCid required'));
    if (!chunkIndices || !chunkIndices.length)
                       return Promise.reject(_err(400, 'chunkIndices required'));
    if (!rootKey)      return Promise.reject(_err(500, 'root key not available'));
    if (!accessModel)  return Promise.reject(_err(500, 'accessModel required'));

    // ── Attestation gate (runs before payment to give clear 403 when required) ──
    var attestPromise;
    if (accessModel.requireAttestation) {
        if (!attestation) {
            return Promise.reject(_err(403, 'Attestation required', 'AttestationRequired'));
        }
        attestPromise = attestFn(attestation, blessedBuilds).then(function (r) {
            if (!r.ok) {
                throw _err(403, r.error || 'Attestation failed', 'AttestationFailed');
            }
        });
    } else {
        attestPromise = Promise.resolve();
    }

    return attestPromise.then(function () {
        // ── Payment gate ──────────────────────────────────────────────────────
        // Permanent key policy with no payment function means open access
        // (e.g. the stream is free).  Callers must inject checkPayment for all
        // paid streams.
        if (!checkPayment) {
            if (accessModel.model !== 'permanent') {
                return Promise.reject(_err(500, 'checkPayment required for non-permanent streams'));
            }
            return _deriveAll(rootKey, rootCid, chunkIndices);
        }

        return checkPayment(paymentSig, accessModel, rootCid).then(function (result) {
            if (!result.ok) {
                var e = _err(402, result.error || 'Payment required', 'PaymentRequired');
                e.paymentDetails = result.paymentDetails;
                throw e;
            }
            return _deriveAll(rootKey, rootCid, chunkIndices);
        });
    });
}

/**
 * Derive keys for all requested indices.
 * @private
 */
function _deriveAll(rootKey, rootCid, chunkIndices) {
    var keys = {};
    for (var i = 0; i < chunkIndices.length; i++) {
        var idx = chunkIndices[i];
        keys[idx] = deriveChunkKey(rootKey, rootCid, idx).toString('base64');
    }
    return { keys: keys };
}

/**
 * Verify a Safebox client attestation token.
 *
 * Uses the existing `Safecloud/Attestation` infrastructure.  The function:
 *   1. Decodes and verifies the attestation document (TEE, Nitro, GCP, etc.).
 *   2. Checks the `buildHash` claim inside the document against `blessedBuilds`.
 *
 * @param  {string}   token          Base64-encoded attestation document.
 * @param  {string[]} blessedBuilds  Allowed build hashes (Nix derivation hashes
 *                                   of blessed Safecloud builds, hex-encoded).
 * @return {Promise<{ ok: boolean, buildHash?: string, error?: string }>}
 */
function verifyClientAttestation(token, blessedBuilds) {
    var Attestation;
    try {
        Attestation = require('./Attestation');
    } catch (e) {
        return Promise.resolve({ ok: false, error: 'Attestation module not available' });
    }

    var store;
    var verifier;
    try {
        store    = new Attestation.TrustStore();
        verifier = new Attestation.Verifier(store);
    } catch (e) {
        return Promise.resolve({ ok: false, error: 'Attestation setup failed: ' + e.message });
    }

    // Decode token to determine provider and format.
    // Tokens are base64-encoded JSON: { provider, document }
    var envelope;
    try {
        envelope = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    } catch (e) {
        return Promise.resolve({ ok: false, error: 'Invalid attestation token format' });
    }

    var provider = (envelope && envelope.provider) || 'nitro';
    var document = envelope && envelope.document;
    if (!document) {
        return Promise.resolve({ ok: false, error: 'Missing attestation document' });
    }

    var docBuf;
    try {
        docBuf = Buffer.from(document, 'base64');
    } catch (e) {
        docBuf = document;
    }

    var policy = new Attestation.Policy({
        // No scannerCID restriction — we check blessedBuilds manually below.
        providers:    [provider],
        allowDebug:   false
    });

    return verifier.verify(provider, docBuf, {
        trustedRoot: store[provider + 'Root'] || store.nitroRoot
    }).then(function (result) {
        var policyResult = policy.evaluate(result);
        if (!policyResult.pass) {
            return { ok: false, error: policyResult.reason };
        }

        // Extract build hash from the claims (Safebox puts it under pcr.buildHash
        // or userdata.buildHash depending on the TEE type).
        var buildHash = (result.claims && (
            result.claims.buildHash ||
            (result.claims.pcrs && result.claims.pcrs.buildHash) ||
            (result.claims.userData && result.claims.userData.buildHash)
        )) || null;

        if (!buildHash) {
            return { ok: false, error: 'No buildHash in attestation claims' };
        }

        // Normalize to lowercase hex for comparison
        var normalBuild = buildHash.toLowerCase().replace(/^0x/, '');

        if (!blessedBuilds.length) {
            // No blessed list configured — accept any valid attestation
            return { ok: true, buildHash: normalBuild };
        }

        var blessed = blessedBuilds.some(function (h) {
            return h.toLowerCase().replace(/^0x/, '') === normalBuild;
        });

        if (!blessed) {
            return {
                ok:        false,
                buildHash: normalBuild,
                error:     'Build hash not on blessed list: ' + normalBuild
            };
        }

        return { ok: true, buildHash: normalBuild };

    }).catch(function (e) {
        return { ok: false, error: 'Attestation verification error: ' + (e.message || e) };
    });
}

// ── Private helpers ───────────────────────────────────────────────────────────

function _err(statusCode, message, code) {
    var e = new Error(message);
    e.statusCode = statusCode;
    e.code = code || (statusCode === 402 ? 'PaymentRequired' :
                      statusCode === 403 ? 'Forbidden' : 'BadRequest');
    return e;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
    hkdf:                    hkdf,
    deriveChunkKey:          deriveChunkKey,
    issueKeys:               issueKeys,
    verifyClientAttestation: verifyClientAttestation
};
