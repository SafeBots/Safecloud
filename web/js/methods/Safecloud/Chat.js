/**
 * Q.Safecloud.Chat — bundle loader for the Safecloud Chat subsystem.
 *
 * This file is the entry point that wires together all Chat modules in the
 * correct dependency order and exposes them on Q.Safecloud.Chat.
 *
 * MODULE DEPENDENCY ORDER:
 *   message      — no Chat deps (pure schema + validate)
 *   send         — requires message
 *   receive      — requires message
 *   dag          — requires receive
 *   forwardChain — requires send, receive
 *   revoke       — requires forwardChain
 *   sync         — requires receive, dag, forwardChain
 *
 * INNOVATIONS COVERED:
 *   Innovation 2.5 — Forward chains / in-band key distribution (forwardChain)
 *   Innovation 5   — O(1) rekeying (revoke)
 *   Innovation 6   — Transcript simulability / deniability (send/receive — symmetric keys)
 *   Innovation 9   — DAG threading (dag, sync)
 *
 * Usage (browser, via Q module system):
 *   Q.Safecloud.Chat.send(options, callback)
 *   Q.Safecloud.Chat.receive(cid, epochKey, epochIndex, options, callback)
 *   Q.Safecloud.Chat.dag.topoSort(nodes)
 *   Q.Safecloud.Chat.dag.fetchAll(cids, epochKey, epochIndex, options, callback)
 *   Q.Safecloud.Chat.sync(options, callback)
 *   Q.Safecloud.Chat.forwardChain.post(options, callback)
 *   Q.Safecloud.Chat.forwardChain.follow(cid, epochKey, epochIndex, options, callback)
 *   Q.Safecloud.Chat.revoke.revokeAndRekey(options, callback)
 *   Q.Safecloud.Chat.revoke.deriveEpochKey(threadKey, epochIndex)
 *   Q.Safecloud.Chat.message.build(options)
 *   Q.Safecloud.Chat.message.validate(env)
 */

Q.exports(function (Q) {
    // Ensure the namespace exists
    Q.Safecloud         = Q.Safecloud         || {};
    Q.Safecloud.Chat    = Q.Safecloud.Chat    || {};

    var Chat = Q.Safecloud.Chat;

    // The individual sub-modules are loaded by the Q module system in the
    // order listed in the manifest; by the time this bundle's body runs they
    // are already attached to Q.Safecloud.Chat.  Here we simply re-export
    // them through a stable top-level API so callers can import Chat as a
    // single unit if desired.

    return {
        /**
         * message — envelope schema, build() and validate()
         * Innovation 6: symmetric-only envelopes, no per-message signatures.
         */
        message: Chat.message,

        /**
         * send(options, callback) — encrypt and store a message.
         * options: { threadId, epochKey, epochIndex, text, parentIds, senderHint, drops }
         * callback(err, { cid })
         */
        send: Chat.send,

        /**
         * receive(cid, epochKey, epochIndex, options, callback)
         * Fetch drop and decrypt it into an envelope.
         * options: { drops }
         * callback(err, envelope|null)
         */
        receive: Chat.receive,

        /**
         * dag — DAG walker helpers.
         * dag.roots(nodes), dag.tips(nodes), dag.topoSort(nodes),
         * dag.thread(nodes), dag.fetchAll(cids, epochKey, epochIndex, options, callback)
         * Innovation 9: DAG threading.
         */
        dag: Chat.dag,

        /**
         * sync(options, callback) — subscribe to live updates.
         * options: { threadId, epochKey, epochIndex, streamChannel, drops,
         *            knownCids, onMessage, onEpochChange }
         * callback(err, { nodes, unsubscribe })
         * Innovation 2.5: auto-follows forward chains on epoch change.
         */
        sync: Chat.sync,

        /**
         * forwardChain — in-band key transition.
         * forwardChain.post(options, callback)
         * forwardChain.follow(cid, epochKey, epochIndex, options, callback)
         * Innovation 2.5: forward chain messages encrypted under old key.
         */
        forwardChain: Chat.forwardChain,

        /**
         * revoke — O(1) member revocation and rekeying.
         * revoke.revokeAndRekey(options, callback)
         * revoke.deriveEpochKey(threadKey, epochIndex) → Promise<Uint8Array>
         * Innovation 5: manager derives new epoch from threadKey; revoked member cannot.
         */
        revoke: Chat.revoke
    };
});
