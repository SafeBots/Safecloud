/**
 * Q.Safecloud.Chat.revoke — O(1) member revocation and rekeying.
 *
 * INNOVATION 5 — O(1) Rekeying:
 *   Thread keys are arranged in sibling pairs: epoch/0 and epoch/1.
 *   The group manager holds the parent threadKey and can derive any epoch key.
 *   When a member is revoked at epoch N:
 *     1. The manager derives epoch/N+1 from the same threadKey.
 *     2. Posts a forward_chain message (Innovation 2.5) pointing to the new key.
 *     3. Future messages use epoch/N+1.
 *   The revoked member had epoch/N; they cannot derive epoch/N+1 without the
 *   threadKey (which only the manager holds).
 *   This is O(1) because the manager only needs to post ONE forward_chain
 *   message, regardless of group size.
 *
 * INNOVATION 2.5 — In-Band Key Distribution:
 *   The new epoch key is announced via a forward_chain message so current
 *   members can discover it without out-of-band signalling.
 *
 * API:
 *   revoke.revokeAndRekey(options, callback)
 *     Advance the epoch, derive a new epoch key, and post a forward chain.
 *     options:
 *       threadId       {string}    required
 *       threadKey      {Uint8Array|string} required — parent key (manager only)
 *       currentEpochIndex {number} required — the epoch being rotated out
 *       streamChannel  {string}    optional
 *       drops          {Object}    optional
 *     callback(err, { newEpochKey, newEpochIndex, forwardCid, newEpochKeyCid })
 *
 *   revoke.deriveEpochKey(threadKey, epochIndex) → Promise<Uint8Array>
 *     Derive the epoch key at a specific index from the threadKey.
 *     (Useful for granting access to specific epochs.)
 */

Q.exports(function (Q, _) {
    var ForwardChain = Q.Safecloud.Chat.forwardChain;

    // Label prefix for epoch keys (must match _internal.js)
    var EPOCH_LABEL_PREFIX = 'safecloud.chat.epoch.';

    /**
     * deriveEpochKey(threadKey, epochIndex) → Promise<Uint8Array>
     * Derives the epoch key at the given index from the thread key.
     * Uses HKDF with label 'safecloud.chat.epoch.<N>'.
     */
    function deriveEpochKey(threadKey, epochIndex) {
        var keyBytes = (typeof threadKey === 'string')
            ? Q.Data.fromBase64(threadKey)
            : threadKey;
        var label = EPOCH_LABEL_PREFIX + epochIndex;
        return Q.Data.derive(keyBytes, label, { size: 32 });
    }

    /**
     * revokeAndRekey(options, callback)
     *
     * Derives the new epoch key (epochIndex+1) from the threadKey and posts a
     * forward_chain message so current members can follow the chain.
     *
     * The revoked member had epoch key at currentEpochIndex; they cannot
     * derive currentEpochIndex+1 without the threadKey.
     */
    function revokeAndRekey(options, callback) {
        if (!options.threadId)      { return callback(new Error('revoke.revokeAndRekey: threadId required')); }
        if (!options.threadKey)     { return callback(new Error('revoke.revokeAndRekey: threadKey required')); }
        if (typeof options.currentEpochIndex !== 'number') {
            return callback(new Error('revoke.revokeAndRekey: currentEpochIndex required'));
        }

        var threadKeyBytes = (typeof options.threadKey === 'string')
            ? Q.Data.fromBase64(options.threadKey)
            : options.threadKey;

        var currentEpochIndex = options.currentEpochIndex;
        var newEpochIndex     = currentEpochIndex + 1;

        // 1. Derive the current epoch key (to encrypt the forward chain message)
        // 2. Derive the new epoch key (the key to announce)
        Promise.all([
            deriveEpochKey(threadKeyBytes, currentEpochIndex),
            deriveEpochKey(threadKeyBytes, newEpochIndex)
        ]).then(function (keys) {
            var oldEpochKey = keys[0];
            var newEpochKey = keys[1];

            // 3. Post the forward chain message
            ForwardChain.post({
                threadId:      options.threadId,
                oldEpochKey:   oldEpochKey,
                oldEpochIndex: currentEpochIndex,
                newEpochKey:   newEpochKey,
                streamChannel: options.streamChannel || null,
                drops:         options.drops
            }, function (err, result) {
                if (err) { return callback(err); }

                callback(null, {
                    newEpochKey:    newEpochKey,
                    newEpochIndex:  newEpochIndex,
                    forwardCid:     result.forwardCid,
                    newEpochKeyCid: result.newEpochKeyCid
                });
            });
        }).catch(function (err) {
            callback(err);
        });
    }

    return {
        revokeAndRekey: revokeAndRekey,
        deriveEpochKey: deriveEpochKey
    };
});
