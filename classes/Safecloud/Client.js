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
var crypto = require('crypto');


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
        var chunkPath = manifest ? _chunkLinkPath(chunkIndex, manifest) : null;
        if (chunkPath && !_isAncestorOrEqual(ctx.link, chunkPath)) {
            return Promise.resolve(false);
        }
    } else if (typeof ctx.start === 'number' && typeof ctx.end === 'number') {
        // Legacy range check
        if (chunkIndex < ctx.start || chunkIndex >= ctx.end) { return Promise.resolve(false); }
    } else {
        return Promise.resolve(false);
    }

    // Cryptographic verification via Q.Data helpers — matches Q.Crypto.delegate signing.
    // Q.Crypto.delegate signs: SHA-256(Q.Data.canonicalize(statement)) with ES256 / P-256.
    try {
        var sigB64  = typeof grant.proof.signature === 'string'
            ? grant.proof.signature
            : Data.toBase64(grant.proof.signature);
        var pubRaw  = grant.proof.publicKey;
        var pubB64  = (pubRaw instanceof Uint8Array || Buffer.isBuffer(pubRaw))
            ? Data.toBase64(pubRaw) : pubRaw;
        if (!sigB64 || !pubB64) { return Promise.resolve(false); }

        // P1363 r||s → DER using Q.Data.RAWtoDER
        var derSig = Data.RAWtoDER(Buffer.from(sigB64, 'base64'));

        // Raw P-256 public key → SPKI DER (same prefix as Q.Crypto.OpenClaim)
        var pubBuf = Buffer.from(pubB64, 'base64');
        var spki   = pubBuf.length === 91 ? pubBuf : Buffer.concat([
            Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
            pubBuf.slice(0, 65)
        ]);
        var key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });

        var digest = crypto.createHash('sha256')
            .update(Buffer.from(Data.canonicalize(stmt), 'utf8')).digest();

        var ok = crypto.verify(null, digest, key, derSig);
        return Promise.resolve(ok);
    } catch (e) {
        return Promise.resolve(false);
    }
};

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
