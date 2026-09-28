"use strict";
/**
 * Q.Safecloud.Client — server-side counterpart to Q.Safecloud.Client.
 *
 * Provides helpers that Jets.js calls when handling Cloud client requests:
 *   - Manifest validation
 *   - Binding proof verification
 *   - Grant chain verification (OCP Role A, full cryptographic)
 *
 * All heavy crypto uses the server-side Q.Crypto module.
 *
 * @class Q.Safecloud.Client
 * @static
 */

var Q      = require('Q');
var Crypto = Q.Crypto;
var Data   = Q.Data;


var Client = module.exports = {};

// ─────────────────────────────────────────────────────────────────────────────
// Manifest validation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validate a public manifest object has the required fields.
 * Synchronous — does not verify the binding proof signature.
 *
 * @method validateManifest
 * @param {Object} manifest
 * @return {{ ok: Boolean, reason: String|null }}
 */
Client.validateManifest = function (manifest) {
    if (!manifest || typeof manifest !== 'object') {
        return { ok: false, reason: 'manifest is not an object' };
    }
    var required = ['v', 'rootCid', 'encryptionRootPublicKey', 'accessRootPublicKey',
                    'bindingProof', 'chunkCount', 'chunkSize', 'size', 'name'];
    for (var i = 0; i < required.length; i++) {
        if (manifest[required[i]] == null) {
            return { ok: false, reason: 'missing field: ' + required[i] };
        }
    }
    if (manifest.v !== 1) {
        return { ok: false, reason: 'unsupported manifest version: ' + manifest.v };
    }
    return { ok: true, reason: null };
};

// ─────────────────────────────────────────────────────────────────────────────
// Binding proof verification
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify the manifest's binding proof — confirms encryptionRootPublicKey,
 * accessRootPublicKey, and rootCid belong to the same root key.
 *
 * @method verifyBindingProof
 * @param {Object} manifest
 * @return {Promise<Boolean>}
 */
Client.verifyBindingProof = function (manifest) {
    var bp = manifest && manifest.bindingProof;
    if (!bp || !bp.statement || !bp.proof) { return Promise.resolve(false); }

    var statement = bp.statement;
    var proof     = bp.proof;

    // The binding proof is signed with the encryptionRoot (ES256 / P-256)
    // Q.Crypto.verify needs the public key and the signed statement
    return Crypto.verify({
        format:      'ES256',
        domain:      {},
        primaryType: 'SafecloudBinding',
        message:     statement,
        types: {
            SafecloudBinding: [
                { name: 'encryptionRootPublicKey', type: 'string' },
                { name: 'accessRootPublicKey',     type: 'string' },
                { name: 'rootCid',                 type: 'string' }
            ]
        },
        publicKey:  Data.fromBase64(manifest.encryptionRootPublicKey),
        signature:  proof.signature
    }).catch(function () { return false; });
};

// ─────────────────────────────────────────────────────────────────────────────
// OCP Role A grant verification (full cryptographic)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a single OCP Role A grant using Q.Crypto.verifyDelegated.
 *
 * Grant model (new): grants carry a link path, not {start,end}.
 *   grant.link      Array    — path from rootCid, e.g. ["track","data","0","1"]
 *   ctx.link        Array    — same path in statement context
 *   ctx.readLevel   Number   — minimum read level
 *   ctx.rootCid     String   — expected rootCid
 *   ctx.exp         Number   — expiry unix seconds
 *
 * A grant covers chunkIndex if its link path is an ancestor-or-equal
 * of the chunk's position path in the tree.
 *
 * Backward compat: if grant has ctx.start/ctx.end instead of ctx.link,
 * falls back to the old range check.
 *
 * @method verifyGrant
 * @param {Object}      grant        { statement, proof, link, [start, end] }
 * @param {String|null} rootCid      Expected rootCid (null on upload)
 * @param {Number}      chunkIndex   Absolute chunk index to check
 * @param {Object|null} manifest     Manifest (needed for link path resolution)
 * @return {Promise<Boolean>}
 */
Client.verifyGrant = function (grant, rootCid, chunkIndex, manifest) {
    if (!grant || !grant.statement || !grant.proof) { return Promise.resolve(false); }

    var stmt = grant.statement;
    var now  = Math.floor(Date.now() / 1000);

    var ctx;
    try { ctx = JSON.parse(stmt.context); } catch (e) { return Promise.resolve(false); }

    if (rootCid && ctx.rootCid && ctx.rootCid !== rootCid) { return Promise.resolve(false); }
    if (ctx.exp && ctx.exp > 0 && now > ctx.exp) { return Promise.resolve(false); }

    // Link path check (new model)
    if (ctx.link && Array.isArray(ctx.link)) {
        // Index-track grants (ctx.link = ["track","index"]) aren't chunked
        // like the data track — there's no "chunkIndex within the index
        // track" to resolve, so _chunkLinkPath() below (which always
        // builds a ["track","data",...] path) doesn't apply here at all;
        // comparing its output against ctx.link would always mismatch on
        // the second segment ("data" vs "index") and reject every index
        // grant regardless of validity. verifySubtreeGrant() (our only
        // caller) already confirmed ctx.link covers the actual requested
        // link path before calling us — nothing more to check here.
        if (ctx.link[1] !== 'index') {
            var chunkPath = manifest ? _chunkLinkPath(chunkIndex, manifest) : null;
            if (chunkPath && !_isAncestorOrEqual(ctx.link, chunkPath)) {
                return Promise.resolve(false);
            }
        }
    } else if (typeof ctx.start === 'number' && typeof ctx.end === 'number') {
        // Legacy range check
        if (chunkIndex < ctx.start || chunkIndex >= ctx.end) { return Promise.resolve(false); }
    } else {
        return Promise.resolve(false);
    }

    // Cryptographic verification — delegate to the platform's own
    // Q.Crypto.verify() (classes/Q/Crypto.js), the exact counterpart of
    // the browser's Q.Crypto.sign()/delegate() that actually produced
    // this statement/proof. This block used to hand-roll the digest and
    // signature check itself, and had two independent bugs, both silently
    // swallowed by the catch below (surfacing only as the generic "Grant
    // crypto verification failed" from verifySubtreeGrant's caller):
    //   1. Q.Crypto.sign()'s ES256 path already DER-encodes the signature
    //      (see sign.js: `signatureDer = encodeEcdsaDer(...)`) — but this
    //      code then ran it through Data.RAWtoDER() again, which requires
    //      exactly 64 raw r||s bytes and throws on anything else (an
    //      already-DER signature is never 64 bytes), so verification
    //      failed on literally every delegated grant ever presented here.
    //   2. Even past that, the digest was recomputed over just the bare
    //      statement (SHA-256(canonicalize(stmt))), but what was actually
    //      signed is SHA-256(canonicalize({domain, primaryType, types,
    //      message: stmt})) — see sign.js's `payload` — so the digests
    //      would never have matched either.
    // Both are exactly the kind of thing that only breaks a *delegated*
    // (grant-based) capability — the owner/rootKey path never exercised
    // this verification at all, which is why it went unnoticed until the
    // teaser feature (the first delegated-capability consumer) shipped.
    try {
        var types = {
            EIP712Domain: [
                { name: 'name',    type: 'string'  },
                { name: 'version', type: 'string'  },
                { name: 'salt',    type: 'bytes32' }
            ],
            Delegation: [
                { name: 'parent',     type: 'bytes32' },
                { name: 'label',      type: 'string'  },
                { name: 'issuedTime', type: 'uint64'  },
                { name: 'context',    type: 'string'  },
                { name: 'secretHash', type: 'bytes32' }
            ]
        };
        var sigBuf = _asBuffer(grant.proof.signature);
        var pubBuf = _asBuffer(grant.proof.publicKey);
        if (!sigBuf || !pubBuf) { return Promise.resolve(false); }

        return Crypto.verify({
            format:      'ES256',
            domain:      {},
            types:       types,
            primaryType: 'Delegation',
            message:     stmt,
            signature:   sigBuf,
            publicKey:   pubBuf
        });
    } catch (e) {
        return Promise.resolve(false);
    }
};

/**
 * Normalizes proof.signature/proof.publicKey into a real Buffer,
 * regardless of which shape they arrive in:
 *   - Buffer/Uint8Array: passed straight through.
 *   - base64 string: what Client/grant.js now emits (this codebase's own
 *     wire-safe convention for these fields — same as `secret`).
 *   - a plain object with numeric-string keys ("0","1",...): a Uint8Array
 *     that went through JSON.stringify/JSON.parse before grant.js started
 *     base64-encoding these fields — e.g. a teaser capability saved to
 *     disk before that fix shipped. Reconstructed from its own values
 *     rather than left to fail, so already-saved data doesn't need the
 *     creator to re-save it.
 * @method _asBuffer
 */
function _asBuffer(x) {
    if (Buffer.isBuffer(x)) { return x; }
    if (x instanceof Uint8Array) { return Buffer.from(x); }
    if (typeof x === 'string') { return Buffer.from(x, 'base64'); }
    if (x && typeof x === 'object') {
        var values = Object.keys(x)
            .filter(function (k) { return /^\d+$/.test(k); })
            .sort(function (a, b) { return Number(a) - Number(b); })
            .map(function (k) { return x[k]; });
        if (values.length) { return Buffer.from(values); }
    }
    return null;
}

// ── Tree helpers (server-side mirror of _internal.js) ─────────────────────────

function _chunkLinkPath(absIndex, manifest) {
    var treeN     = manifest.treeN     || 2;
    var treeDepth = manifest.treeDepth ||
                    Math.max(1, Math.ceil(Math.log(manifest.chunkCount || 1) / Math.log(treeN)));
    var path = ['track', 'data'];
    var n    = Math.pow(treeN, treeDepth);
    var idx  = absIndex;
    for (var d = 0; d < treeDepth; d++) {
        n = n / treeN;
        path.push(String(Math.floor(idx / n)));
        idx = idx % n;
    }
    return path;
}

function _isAncestorOrEqual(pathA, pathB) {
    if (pathA.length > pathB.length) { return false; }
    for (var i = 0; i < pathA.length; i++) {
        if (String(pathA[i]) !== String(pathB[i])) { return false; }
    }
    return true;
}
