/**
 * Q.Safecloud.Chat.receive — fetch and decrypt a chat message by CID.
 *
 * INNOVATION 6 — Transcript Simulability (Deniability):
 *   The message was encrypted with a shared symmetric epoch key; there are
 *   no per-message signatures.  Decryption only verifies the GCM auth tag —
 *   it does not prove origin.
 *
 * INNOVATION 2.5 — In-Band Key Distribution / Forward Chains:
 *   If decryption fails because the message was sent with a later epoch key,
 *   the caller should follow the forward chain to get the new epoch key and
 *   retry.  This module does not auto-follow chains; use Chat.sync for that.
 *
 * Usage:
 *   Q.Safecloud.Chat.receive(cid, epochKey, epochIndex, callback)
 *   Q.Safecloud.Chat.receive(cid, epochKey, epochIndex, options, callback)
 *
 * options:
 *   drops {Object} — override Drops module (for testing)
 *
 * callback(err, envelope)
 *   envelope: validated plaintext message object (see Chat.message)
 *             null if the Drop is not found
 *
 * KEY DERIVATION (must match send.js exactly):
 *   The IV was stored in the Drop by send.js (drop.iv, base64).
 *   encKey = HKDF-SHA256(epochKey, info='safecloud.chat.msgkey.' + drop.iv, 32 bytes)
 */

Q.exports(function (Q) {
    var Message = Q.Safecloud.Chat.message;

    return function Q_Safecloud_Chat_receive(cid, epochKey, epochIndex, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        if (!cid)      { return callback(new Error('Chat.receive: cid required')); }
        if (!epochKey) { return callback(new Error('Chat.receive: epochKey required')); }

        var epochKeyBytes = (typeof epochKey === 'string')
            ? Q.Data.fromBase64(epochKey)
            : epochKey;

        var dropsModule = options.drops || Q.Safecloud.Drops;

        // 1. Fetch the Drop by CID
        dropsModule.fetch(cid).then(function (drop) {
            if (!drop) {
                callback(null, null);
                return;
            }

            // drop = { ciphertext: base64, tag: base64, iv: base64 }
            // 2. Re-derive the message key using the IV stored in the Drop.
            //    encKey = HKDF(epochKey, info='safecloud.chat.msgkey.' + drop.iv, 32)
            //    This is deterministic given (epochKey, iv) so both sides can compute it.
            return Q.Data.derive(epochKeyBytes, 'safecloud.chat.msgkey.' + drop.iv, { size: 32 })
            .then(function (encKeyBytes) {
                return Q.Data.importKey(encKeyBytes);
            })
            .then(function (cryptoKey) {
                // 3. Decrypt — Q.Data.decrypt(cryptoKey, iv_b64, ciphertext_b64, {tag})
                return Q.Data.decrypt(cryptoKey, drop.iv, drop.ciphertext, {
                    tag: drop.tag
                });
            })
            .then(function (plaintext) {
                // 4. Parse the envelope
                var env;
                try {
                    env = JSON.parse(new TextDecoder().decode(plaintext));
                } catch (parseErr) {
                    throw new Error('Chat.receive: failed to parse envelope: ' + parseErr.message);
                }

                // 5. Validate
                Message.validate(env);

                callback(null, env);
            });
        }).catch(function (err) {
            callback(err);
        });
    };
});
