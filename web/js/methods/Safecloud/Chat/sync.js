/**
 * Q.Safecloud.Chat.sync — subscribe to and replay a chat thread.
 *
 * INNOVATION 2.5 — In-Band Key Distribution / Forward Chains:
 *   When a new epoch key is in use, `send.js` posts a safecloud.forward_chain
 *   control message.  sync.js detects this and follows the chain to get the
 *   new epoch key automatically, so the caller doesn't need to track epochs.
 *
 * INNOVATION 9 — DAG Threading:
 *   Each incoming announce carries a CID.  sync.js fetches messages by CID,
 *   assembles them into a DAG, and returns them in topological order.
 *
 * INNOVATION 6 — Transcript Simulability:
 *   Messages have no per-message signatures; decryption is the only
 *   authentication.
 *
 * Usage:
 *   Q.Safecloud.Chat.sync(options, callback)
 *
 * options:
 *   threadId       {string}    required
 *   epochKey       {Uint8Array|string} required — current epoch key
 *   epochIndex     {number}    required
 *   streamChannel  {string}    required — Streams channel to listen on
 *   knownCids      {string[]}  default [] — CIDs already in local history
 *   drops          {Object}    optional — override Drops module (for testing)
 *   onMessage      {Function(node)} — called for each new decrypted message node
 *                     node = { cid, parentIds, timestamp, envelope }
 *   onEpochChange  {Function(epochKey, epochIndex)} — called when epoch advances
 *
 * callback(err, { nodes, unsubscribe })
 *   nodes:       all fetched nodes in topological order at time of call
 *   unsubscribe: function to stop listening
 *
 * Note: sync does NOT yet handle multi-hop forward chains (epoch+2, epoch+3).
 *       It follows exactly one forward_chain hop per message received.
 *       For full chain walking use Chat.forwardChain when implemented.
 */

Q.exports(function (Q) {
    var Receive  = Q.Safecloud.Chat.receive;
    var Dag      = Q.Safecloud.Chat.dag;

    return function Q_Safecloud_Chat_sync(options, callback) {
        if (!options.threadId)     { return callback(new Error('Chat.sync: threadId required')); }
        if (!options.epochKey)     { return callback(new Error('Chat.sync: epochKey required')); }
        if (typeof options.epochIndex !== 'number') { return callback(new Error('Chat.sync: epochIndex required')); }
        if (!options.streamChannel){ return callback(new Error('Chat.sync: streamChannel required')); }

        var epochKey   = options.epochKey;
        var epochIndex = options.epochIndex;
        var known      = {};
        var nodes      = [];
        var subHandle  = null;

        (options.knownCids || []).forEach(function (c) { known[c] = true; });

        // Handle an incoming announce (CID of a new message)
        function handleAnnounce(msg) {
            var cid = msg && msg.cid;
            if (!cid || known[cid]) { return; }
            known[cid] = true;

            Receive(cid, epochKey, epochIndex, { drops: options.drops }, function (err, env) {
                if (err || !env) { return; }  // decrypt failed — wrong epoch, skip

                // Detect forward_chain control messages
                if (env.type === 'Safecloud/chat/forwardChain') {
                    var newEpochIndex = env.nextEpochIndex;
                    var newEpochKeyCid = env.nextEpochKeyCid;
                    if (typeof newEpochIndex !== 'number' || !newEpochKeyCid) { return; }

                    // Fetch the new epoch key from Drops, then switch
                    var dropsModule = options.drops || Q.Safecloud.Drops;
                    dropsModule.fetch(newEpochKeyCid).then(function (drop) {
                        if (!drop) { return; }
                        // The epoch key Drop contains the raw key bytes encrypted
                        // under the current epoch key — this is a simplified version
                        // that expects the new key bytes as the Drop's plaintext.
                        // A production version would use Chat.forwardChain.follow().
                        var newKeyBytes = Q.Data.fromBase64(drop.ciphertext);
                        epochKey   = newKeyBytes;
                        epochIndex = newEpochIndex;
                        if (options.onEpochChange) {
                            options.onEpochChange(newKeyBytes, newEpochIndex);
                        }
                    }).catch(function () {});
                    return;
                }

                // Regular chat message
                if (env.type !== 'Safecloud/chat/message') { return; }
                if (env.threadId !== options.threadId) { return; }

                var node = {
                    cid:       cid,
                    parentIds: env.parentIds || [],
                    timestamp: env.timestamp || 0,
                    envelope:  env
                };
                nodes.push(node);

                if (options.onMessage) { options.onMessage(node); }
            });
        }

        // Subscribe to the Streams channel
        try {
            subHandle = Q.Streams.subscribe(options.streamChannel, function (streamMsg) {
                if (streamMsg && streamMsg.type === 'Safecloud/chat/announce') {
                    handleAnnounce(streamMsg);
                }
            });
        } catch (subErr) {
            return callback(new Error('Chat.sync: Streams.subscribe failed: ' + subErr.message));
        }

        function unsubscribe() {
            if (subHandle && typeof subHandle.unsubscribe === 'function') {
                subHandle.unsubscribe();
            }
        }

        // Return current state immediately; live updates arrive via onMessage
        try {
            var sorted = Dag.topoSort(nodes);
            callback(null, { nodes: sorted, unsubscribe: unsubscribe });
        } catch (sortErr) {
            callback(sortErr);
        }
    };
});
