/**
 * Q.Safecloud.Client.topics — topic-tree grants (Innovation 4 — Spatial/Topic Trees).
 *
 * INNOVATION 4 — Spatial / Topic Trees:
 *   Chat content is organized into a topic hierarchy rooted at the chat root.
 *   The derivation chain is:
 *
 *     encryptionRoot
 *       └─ chatRoot            ('safecloud.chat')
 *           └─ topicRoot       ('safecloud.chat.topic')
 *               └─ topic(seg)  ('safecloud.topic.<seg>')
 *                   └─ topic(subseg) …
 *
 *   A grant at any level covers all descendant topics.  Granting 'sports'
 *   implicitly covers 'sports/football', 'sports/tennis', etc.
 *
 *   Topic segments must be non-empty lowercase alphanumeric strings (a-z0-9
 *   plus hyphens; no slashes, dots or uppercase).  Hierarchies are expressed
 *   as arrays: ['sports', 'football'].
 *
 * API:
 *   Topics.create(chatRoot, topicPath, options)
 *     → Promise<{ secret, statement, proof }>
 *     Derives a topic key (encryption) and optional access proof.
 *     Used by the channel manager to set up new topic channels.
 *
 *   Topics.grant(chatRoot, topicPath, options, callback)
 *     Produce a transportable grant for a subscriber.
 *     options:
 *       readLevel   {string}  default 'content'
 *       exp         {number}  optional expiry (unix seconds)
 *       format      {string}  default 'ES256'
 *     callback(err, { topicPath, secret, statement, proof, readLevel })
 *
 *   Topics.list(topicGrant)
 *     → { topicPath, readLevel }
 *     Parse a grant produced by Topics.grant() (convenience helper).
 *
 * Note: chatRoot is the raw secret Uint8Array derived from the encryption root.
 * Use Q.Safecloud.Client._internal.deriveChatRoot(encryptionRootBytes)
 * to get it, or pass the bytes from a stored manifest.
 */

Q.exports(function (Q, _) {

    // ── Validation ────────────────────────────────────────────────────────────

    var SEGMENT_RE = /^[a-z0-9][a-z0-9-]*$/;

    function _validatePath(topicPath) {
        if (!Array.isArray(topicPath) || topicPath.length === 0) {
            throw new Error('topics: topicPath must be a non-empty array');
        }
        topicPath.forEach(function (seg, i) {
            if (typeof seg !== 'string' || !SEGMENT_RE.test(seg)) {
                throw new Error(
                    'topics: segment[' + i + '] "' + seg + '" is invalid; ' +
                    'use lowercase alphanumeric with optional hyphens'
                );
            }
        });
    }

    // ── create ────────────────────────────────────────────────────────────────

    /**
     * create(chatRoot, topicPath, options)
     *   → Promise<{ secret: Uint8Array, statement, proof }>
     *
     * Derive the topic key (encryption secret) and an access delegation proof
     * at the given topic path.  The secret can be used to encrypt/decrypt
     * messages in that topic channel.
     *
     * chatRoot   — Uint8Array (output of deriveChatRoot)
     * topicPath  — string[]  e.g. ['sports', 'football']
     * options:
     *   readLevel  {string}  default 'content'
     *   exp        {number}  optional expiry (unix seconds)
     *   format     {string}  default 'ES256'
     */
    function create(chatRoot, topicPath, options) {
        options = options || {};
        try { _validatePath(topicPath); } catch (e) { return Promise.reject(e); }

        var readLevelNum = _.levelFromLabel('read', options.readLevel || 'content');
        var ctxObj  = { topicPath: topicPath, readLevel: readLevelNum };
        if (options.exp) { ctxObj.exp = options.exp; }
        var tipContext = JSON.stringify(ctxObj);

        var chatRootBytes = (typeof chatRoot === 'string')
            ? Q.Data.fromBase64(chatRoot) : chatRoot;

        return _.deriveByTopicPath(chatRootBytes, topicPath, tipContext)
            .then(function (del) {
                return {
                    secret:    del.secret,
                    statement: del.statement,
                    proof:     del.proof
                };
            });
    }

    // ── grant ─────────────────────────────────────────────────────────────────

    /**
     * grant(chatRoot, topicPath, options, callback)
     *
     * Produce a transportable topic grant for a subscriber.
     * The grant contains the derived secret (base64) and an access proof.
     *
     * callback(err, {
     *   topicPath:  string[],
     *   secret:     base64 string,
     *   statement:  object,
     *   proof:      { signature: base64, publicKey: base64 },
     *   readLevel:  string
     * })
     */
    function grant(chatRoot, topicPath, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        try { _validatePath(topicPath); } catch (e) { return callback(e); }

        create(chatRoot, topicPath, options)
            .then(function (del) {
                var proof = del.proof;
                // Ensure proof fields are base64 for safe JSON transport
                if (proof && proof.signature && ArrayBuffer.isView(proof.signature)) {
                    proof = {
                        signature: Q.Data.toBase64(proof.signature),
                        publicKey: Q.Data.toBase64(proof.publicKey)
                    };
                }
                callback(null, {
                    topicPath:  topicPath,
                    secret:     Q.Data.toBase64(del.secret),
                    statement:  del.statement,
                    proof:      proof,
                    readLevel:  options.readLevel || 'content'
                });
            })
            .catch(function (err) { callback(err); });
    }

    // ── list ──────────────────────────────────────────────────────────────────

    /**
     * list(topicGrant) → { topicPath, readLevel }
     *
     * Convenience: extract human-readable fields from a grant produced by
     * Topics.grant().  Does not verify the proof.
     */
    function list(topicGrant) {
        if (!topicGrant || !Array.isArray(topicGrant.topicPath)) {
            throw new Error('topics.list: invalid grant — missing topicPath');
        }
        return {
            topicPath: topicGrant.topicPath.slice(),
            readLevel: topicGrant.readLevel || 'content'
        };
    }

    return { create: create, grant: grant, list: list };
});
