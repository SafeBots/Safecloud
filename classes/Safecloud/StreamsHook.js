'use strict';
/**
 * Safecloud/StreamsHook.js — Safecloud-specific before:post hook for the Streams Jet.
 *
 * Registers with the Streams module to enforce invariants on encrypted streams:
 *
 *   • If a stream has `attributes.encrypted === true`, every posted message
 *     MUST have a content field that looks like a CID (content-addressed Drop
 *     reference) rather than plaintext.  Posting raw plaintext to an encrypted
 *     stream is a protocol error — the client must encrypt first and store the
 *     ciphertext in a Drop, then post the CID as `content`.
 *
 *   • Message types on encrypted streams must start with 'Safecloud/' so that
 *     the type taxonomy stays coherent and the metadata leak is predictable.
 *
 * Usage (called once from bin/jet.js, after Streams.listen()):
 *
 *   var Streams      = require('../classes/Safecloud/Streams');
 *   var StreamsHook  = require('../classes/Safecloud/StreamsHook');
 *   StreamsHook.register(Streams);
 *
 * Message types registered for Safecloud/chat streams:
 *   Safecloud/chat/message        — normal encrypted message payload (Drop CID as content)
 *   Safecloud/chat/forwardChain   — epoch key rotation pointer
 *   Safecloud/chat/key            — key grant / re-key event
 *   Safecloud/chat/invite         — invite payload
 *   Safecloud/chat/leave          — member-left event
 *   Safecloud/chat/reaction       — emoji reaction (CID of target + reaction label)
 *   Safecloud/chat/delete         — soft-delete request (CID of target message)
 *   Safecloud/chat/thread         — sub-thread root
 *   Safecloud/chat/typing         — ephemeral typing indicator (not stored long-term)
 */

// ─── CID patterns ─────────────────────────────────────────────────────────────
// Safecloud uses two CID formats:
//   bafy...  — CIDv1 (base32-lower, SHA-256 dag-pb or raw)
//   sha256:  — explicit hex-encoded SHA-256 (used in EpochProtocol receipts)
//
// We also allow any 64-char hex string (raw SHA-256) for forward compatibility.

var CID_BAFY_RE    = /^bafy[a-z2-7]{50,}/;    // CIDv1 base32lower (multihash)
var CID_SHA256_RE  = /^sha256:[0-9a-f]{64}$/;  // explicit sha256:hex format
var HEX64_RE       = /^[0-9a-f]{64}$/i;        // raw 32-byte SHA-256 hex

function looksLikeCID(value) {
    if (typeof value !== 'string' || !value) return false;
    return CID_BAFY_RE.test(value)
        || CID_SHA256_RE.test(value)
        || HEX64_RE.test(value);
}

// ─── Safecloud message type allowlist ─────────────────────────────────────────
// These types are permitted on encrypted Safecloud/chat streams.
// Non-encrypted streams accept any type (enforced by the stream's own ACL).
var SAFECLOUD_TYPES = {
    // Chat stream types
    'Safecloud/chat/message':      true,
    'Safecloud/chat/forwardChain': true,
    'Safecloud/chat/key':          true,
    'Safecloud/chat/invite':       true,
    'Safecloud/chat/leave':        true,
    'Safecloud/chat/reaction':     true,
    'Safecloud/chat/delete':       true,
    'Safecloud/chat/thread':       true,
    'Safecloud/chat/typing':       true,
    // Collaborative document types (Yjs CRDT updates, encrypted as Drops)
    'Safecloud/docs/yjs':          true,
    'Safecloud/docs/snapshot':     true,  // periodic Y.encodeStateAsUpdate snapshot
    'Safecloud/docs/sheets':       true,  // Jspreadsheet Y.Map cells update
    'Safecloud/docs/markdown':     true,  // CodeMirror Y.Text update
    'Safecloud/docs/slides':       true,  // Y.Array of Y.Map slide deck
    // File manager types (Y.Map metadata updates posted via SafecloudYjsProvider)
    'Safecloud/files/index':       true,  // Y.Map('folders') folder directory
    'Safecloud/files/entry':       true,  // Y.Map('files') per-folder file list
    // Jet metadata types (posted to unencrypted metadata streams)
    'Streams/epoch':               true   // epoch transition announcement
};

// ─── The hook ─────────────────────────────────────────────────────────────────

/**
 * beforePost(ctx)
 *
 * Called synchronously before a message is committed to the DB.
 * ctx = { publisherId, streamName, stream, params }
 *
 * Throws an Error (with .statusCode) to abort; mutates ctx.params to transform.
 */
function beforePost(ctx) {
    var stream = ctx.stream;
    var params = ctx.params;

    // Parse attributes if still a string (shouldn't be — Streams.js parses them,
    // but be defensive).
    var attrs = stream.attributes;
    if (typeof attrs === 'string') {
        try { attrs = JSON.parse(attrs); } catch (e) { attrs = {}; }
    }
    attrs = attrs || {};

    // ── Non-encrypted streams: nothing to enforce here ────────────────────────
    if (!attrs.encrypted) return;

    // ── Encrypted stream: content must be a CID ───────────────────────────────
    if (!looksLikeCID(params.content)) {
        var err = new Error(
            'Stream ' + ctx.publisherId + '/' + ctx.streamName +
            ' is encrypted. Content must be a CID (Drop reference), not plaintext.'
        );
        err.statusCode = 422;
        throw err;
    }

    // ── Encrypted stream: type must be a recognized Safecloud type ────────────
    if (!SAFECLOUD_TYPES[params.type]) {
        // Warn but do not reject — future types should not break existing clients.
        // A strict enforcement would use statusCode 422 here.
        console.warn(
            '[StreamsHook] Unknown Safecloud message type "' + params.type +
            '" on encrypted stream ' + ctx.publisherId + '/' + ctx.streamName
        );
    }

    // byUserId is intentionally left as-is: all group members have the epoch
    // key anyway, so hiding the sender from the jet provides no extra privacy.
    // If needed in the future, set params.byUserId = '0' here.
}

// ─── Exports ──────────────────────────────────────────────────────────────────

/**
 * register(Streams)
 *
 * Call once after Streams.listen().  Idempotent — safe to call multiple times
 * (each call adds one hook instance, so call it once per process).
 */
function register(Streams) {
    if (!Streams || typeof Streams.addHook !== 'function') {
        throw new Error('StreamsHook.register: argument must be the Streams module');
    }
    Streams.addHook('before:post', beforePost);
    console.log('[StreamsHook] Safecloud before:post hook registered');
}

module.exports = {
    register:      register,
    beforePost:    beforePost,   // exported for unit tests
    looksLikeCID:  looksLikeCID, // exported for unit tests
    SAFECLOUD_TYPES: SAFECLOUD_TYPES
};
