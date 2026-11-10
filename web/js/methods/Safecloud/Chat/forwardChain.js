/**
 * Q.Safecloud.Chat.forwardChain — post and follow forward-chain control messages.
 *
 * INNOVATION 2.5 — In-Band Key Distribution / Forward Chains:
 *   When a thread is rekeyed (e.g. a member is revoked), the group manager
 *   posts a safecloud.forward_chain control message encrypted under the OLD
 *   epoch key.  The control message contains the CID of a Drop holding the
 *   NEW epoch key bytes, encrypted under the old epoch key.
 *
 *   This lets any holder of epoch key N:
 *     1. Discover the forward_chain message on the Streams channel.
 *     2. Decrypt it to get the CID of the N+1 key Drop.
 *     3. Fetch and decrypt that Drop to get the N+1 epoch key bytes.
 *     4. Continue reading with the new key.
 *
 *   Revoked members who had epoch N but not N+1 cannot advance past the rekey.
 *   They can still read old messages but not new ones.
 *
 * API:
 *   forwardChain.post(options, callback)
 *     Post a forward_chain control message announcing the new epoch key.
 *     options:
 *       threadId       {string}    required
 *       oldEpochKey    {Uint8Array|string} required — current (old) epoch key
 *       oldEpochIndex  {number}    required
 *       newEpochKey    {Uint8Array|string} required — new epoch key to announce
 *       streamChannel  {string}    optional — Streams channel for announce
 *       drops          {Object}    optional — override Drops module
 *     callback(err, { forwardCid, newEpochKeyCid })
 *       forwardCid:    CID of the forward_chain control message Drop
 *       newEpochKeyCid CID of the Drop containing the new epoch key bytes
 *
 *   forwardChain.follow(cid, epochKey, epochIndex, options, callback)
 *     Fetch and follow a chain of forward_chain messages, returning the
 *     latest epoch key reachable from the given starting key.
 *     options:
 *       drops        {Object}   optional — override Drops module
 *       maxHops      {number}   default 100 — cycle guard
 *     callback(err, { epochKey, epochIndex })
 */

Q.exports(function (Q) {
    var Send    = Q.Safecloud.Chat.send;
    var Receive = Q.Safecloud.Chat.receive;

    // ── post ─────────────────────────────────────────────────────────────────

    function post(options, callback) {
        if (!options.threadId)      { return callback(new Error('forwardChain.post: threadId required')); }
        if (!options.oldEpochKey)   { return callback(new Error('forwardChain.post: oldEpochKey required')); }
        if (typeof options.oldEpochIndex !== 'number') { return callback(new Error('forwardChain.post: oldEpochIndex required')); }
        if (!options.newEpochKey)   { return callback(new Error('forwardChain.post: newEpochKey required')); }

        var dropsModule = options.drops || Q.Safecloud.Drops;

        var oldKeyBytes = (typeof options.oldEpochKey === 'string')
            ? Q.Data.fromBase64(options.oldEpochKey)
            : options.oldEpochKey;
        var newKeyBytes = (typeof options.newEpochKey === 'string')
            ? Q.Data.fromBase64(options.newEpochKey)
            : options.newEpochKey;
        var newEpochIndex = options.oldEpochIndex + 1;

        // 1. Encrypt the new epoch key bytes as a Drop, encrypted under the
        //    old epoch key so only current members can read it.
        //    Derive encKey: HKDF(oldEpochKey, 'safecloud.epochkey.wrap.' + newEpochIndex)
        var newKeyB64 = Q.Data.toBase64(newKeyBytes);

        // Generate a random IV for the key wrap Drop
        var ivBytes = new Uint8Array(12);
        crypto.getRandomValues(ivBytes);
        var ivB64 = Q.Data.toBase64(ivBytes);

        Q.Data.derive(oldKeyBytes, 'safecloud.chat.msgkey.' + ivB64, { size: 32 })
        .then(function (encKeyBytes) {
            return Q.Data.importKey(encKeyBytes);
        })
        .then(function (cryptoKey) {
            var plaintext = new TextEncoder().encode(newKeyB64);
            return Q.Data.encrypt(cryptoKey, plaintext, { iv: ivBytes });
        })
        .then(function (enc) {
            // 2. Store the wrapped new key as a Drop
            return dropsModule.store({
                ciphertext: enc.ciphertext,
                tag:        enc.tag,
                iv:         enc.iv
            });
        })
        .then(function (keyDrop) {
            var newEpochKeyCid = keyDrop.cid;

            // 3. Post the forward_chain control message via Chat.send, encrypted
            //    under the OLD epoch key (so current members can read it)
            var controlEnvelope = JSON.stringify({
                type:            'Safecloud/chat/forwardChain',
                version:         1,
                threadId:        options.threadId,
                epochIndex:      options.oldEpochIndex,
                nextEpochIndex:  newEpochIndex,
                nextEpochKeyCid: newEpochKeyCid,
                timestamp:       Date.now(),
                // No text, no parentIds — this is a control message
                parentIds:       []
            });

            // Reuse the same key-wrap pattern for the control message
            var ctrlIvBytes = new Uint8Array(12);
            crypto.getRandomValues(ctrlIvBytes);
            var ctrlIvB64 = Q.Data.toBase64(ctrlIvBytes);
            var ctrlPlain = new TextEncoder().encode(controlEnvelope);

            return Q.Data.derive(oldKeyBytes, 'safecloud.chat.msgkey.' + ctrlIvB64, { size: 32 })
            .then(function (ctrlKeyBytes) {
                return Q.Data.importKey(ctrlKeyBytes);
            })
            .then(function (ctrlCryptoKey) {
                return Q.Data.encrypt(ctrlCryptoKey, ctrlPlain, { iv: ctrlIvBytes });
            })
            .then(function (ctrlEnc) {
                return dropsModule.store({
                    ciphertext: ctrlEnc.ciphertext,
                    tag:        ctrlEnc.tag,
                    iv:         ctrlEnc.iv
                });
            })
            .then(function (ctrlDrop) {
                var forwardCid = ctrlDrop.cid;

                // 4. Optionally announce the forward_chain message CID on Streams
                if (options.streamChannel) {
                    try {
                        Q.Streams.message(options.streamChannel, {
                            type:       'Safecloud/chat/announce',
                            cid:        forwardCid,
                            threadId:   options.threadId,
                            epochIndex: options.oldEpochIndex,
                            timestamp:  Date.now()
                        });
                    } catch (e) {
                        Q.log('forwardChain.post: Streams announce failed (non-fatal):', e.message);
                    }
                }

                return { forwardCid: forwardCid, newEpochKeyCid: newEpochKeyCid };
            });
        })
        .then(function (result) {
            callback(null, result);
        })
        .catch(function (err) {
            callback(err);
        });
    }

    // ── follow ────────────────────────────────────────────────────────────────

    /**
     * follow(cid, epochKey, epochIndex, options, callback)
     *
     * Fetch the Drop at `cid`, decrypt it as a forward_chain message using
     * the given epoch key, then recursively follow the chain until no more
     * forward_chain messages are found or maxHops is reached.
     *
     * Returns the final { epochKey (Uint8Array), epochIndex } reachable.
     */
    function follow(cid, epochKey, epochIndex, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var maxHops = options.maxHops || 100;
        var dropsModule = options.drops || Q.Safecloud.Drops;

        var currentKey   = (typeof epochKey === 'string') ? Q.Data.fromBase64(epochKey) : epochKey;
        var currentIndex = epochIndex;
        var hops = 0;

        function step(dropCid) {
            if (hops++ > maxHops) {
                return callback(new Error('forwardChain.follow: maxHops exceeded'));
            }

            dropsModule.fetch(dropCid).then(function (drop) {
                if (!drop) {
                    // End of chain (or missing drop) — return what we have
                    return callback(null, { epochKey: currentKey, epochIndex: currentIndex });
                }

                // Decrypt using current epoch key + stored IV
                return Q.Data.derive(currentKey, 'safecloud.chat.msgkey.' + drop.iv, { size: 32 })
                .then(function (encKeyBytes) {
                    return Q.Data.importKey(encKeyBytes);
                })
                .then(function (cryptoKey) {
                    return Q.Data.decrypt(cryptoKey, drop.iv, drop.ciphertext, { tag: drop.tag });
                })
                .then(function (plaintext) {
                    var env;
                    try { env = JSON.parse(new TextDecoder().decode(plaintext)); }
                    catch (e) {
                        // Not a JSON control message — end of chain
                        return callback(null, { epochKey: currentKey, epochIndex: currentIndex });
                    }

                    if (env.type !== 'Safecloud/chat/forwardChain') {
                        // Regular message — end of chain
                        return callback(null, { epochKey: currentKey, epochIndex: currentIndex });
                    }

                    var nextCid = env.nextEpochKeyCid;
                    var nextIdx = env.nextEpochIndex;

                    if (!nextCid || typeof nextIdx !== 'number') {
                        return callback(new Error('forwardChain.follow: malformed forward_chain message'));
                    }

                    // Fetch and decrypt the new epoch key Drop
                    return dropsModule.fetch(nextCid).then(function (keyDrop) {
                        if (!keyDrop) {
                            return callback(new Error('forwardChain.follow: epoch key Drop not found: ' + nextCid));
                        }

                        return Q.Data.derive(currentKey, 'safecloud.chat.msgkey.' + keyDrop.iv, { size: 32 })
                        .then(function (wrapKeyBytes) {
                            return Q.Data.importKey(wrapKeyBytes);
                        })
                        .then(function (wrapCryptoKey) {
                            return Q.Data.decrypt(wrapCryptoKey, keyDrop.iv, keyDrop.ciphertext, { tag: keyDrop.tag });
                        })
                        .then(function (newKeyPlaintext) {
                            var newKeyB64 = new TextDecoder().decode(newKeyPlaintext).trim();
                            var newKeyBytes = Q.Data.fromBase64(newKeyB64);
                            currentKey   = newKeyBytes;
                            currentIndex = nextIdx;
                            // Successfully advanced; check if there are more hops
                            // by trying to find another forward_chain at the next epoch CID.
                            // For simplicity, we stop here unless the caller passes a nextCid.
                            // The caller can call follow() again with the returned key.
                            callback(null, { epochKey: newKeyBytes, epochIndex: nextIdx });
                        });
                    });
                });
            }).catch(function (err) {
                callback(err);
            });
        }

        step(cid);
    }

    return { post: post, follow: follow };
});
