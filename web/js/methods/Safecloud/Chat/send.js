/**
 * Q.Safecloud.Chat.send — encrypt and store a chat message.
 *
 * INNOVATION 6 — Transcript Simulability (Deniability):
 *   The message is encrypted with the shared symmetric epoch key.
 *   No per-message signatures are attached — any epoch key holder can
 *   produce valid ciphertext, so contents are deniable.
 *
 * INNOVATION 2.5 — In-Band Key Distribution:
 *   The encrypted message CID is announced over Streams so that all current
 *   epoch key holders can discover and fetch it without out-of-band signalling.
 *
 * INNOVATION 9 — DAG Threading:
 *   parentIds[] is included in the envelope so the DAG topology is preserved.
 *
 * Usage:
 *   Q.Safecloud.Chat.send(options, callback)
 *
 * options:
 *   threadId       {string}    required — thread this message belongs to
 *   epochKey       {Uint8Array|string} — raw secret of the current epoch key
 *   epochIndex     {number}    required
 *   text           {string}    required — message body
 *   parentIds      {string[]}  default [] — CIDs of parent messages (DAG)
 *   senderHint     {string}    default null — advisory sender ID (not signed)
 *   streamChannel  {string}    optional — Streams channel for in-band announce
 *   drops          {Object}    optional — override Drops module (for testing)
 *
 * callback(err, { cid, envelope })
 *   cid:      SHA-256 CID of the stored Drop (content address)
 *   envelope: plaintext message envelope (after build)
 *
 * KEY DERIVATION:
 *   1. Generate a random 12-byte IV.
 *   2. encKey = HKDF-SHA256(epochKey, info='safecloud.chat.msgkey.' + base64(iv), 32 bytes)
 *   3. Encrypt plaintext with AES-256-GCM using (encKey, iv).
 *   4. Store Drop as { ciphertext, tag, iv } — all base64.
 *
 *   Because IV is stored with the Drop, receive.js can re-derive encKey
 *   deterministically from (epochKey, drop.iv) without any plaintext header.
 */

Q.exports(function (Q, _) {
    var Message = Q.Safecloud.Chat.message;

    return function Q_Safecloud_Chat_send(options, callback) {
        if (!options || !options.threadId)         { return callback(new Error('Chat.send: threadId required')); }
        if (typeof options.epochIndex !== 'number') { return callback(new Error('Chat.send: epochIndex required')); }
        if (!options.epochKey)                     { return callback(new Error('Chat.send: epochKey required')); }
        if (!options.text)                         { return callback(new Error('Chat.send: text required')); }

        // 1. Build the plaintext envelope
        var envelope = Message.build({
            threadId:   options.threadId,
            epochIndex: options.epochIndex,
            parentIds:  options.parentIds  || [],
            text:       options.text,
            senderHint: options.senderHint || null
        });

        // 2. Serialize the envelope to UTF-8 bytes
        var plaintext;
        try {
            plaintext = new TextEncoder().encode(JSON.stringify(envelope));
        } catch (e) {
            return callback(new Error('Chat.send: failed to serialize envelope: ' + e.message));
        }

        var epochKeyBytes = (typeof options.epochKey === 'string')
            ? Q.Data.fromBase64(options.epochKey)
            : options.epochKey;

        // 3. Generate a random one-time IV
        var ivBytes = new Uint8Array(12);
        crypto.getRandomValues(ivBytes);
        var ivB64 = Q.Data.toBase64(ivBytes);

        // 4. Derive per-message enc key from epoch key + iv
        //    encKey = HKDF(epochKey, info='safecloud.chat.msgkey.' + base64(iv), 32)
        //    Both sender and receiver can compute this since iv is stored in the Drop.
        Q.Data.derive(epochKeyBytes, 'safecloud.chat.msgkey.' + ivB64, { size: 32 })
        .then(function (encKeyBytes) {
            return Q.Data.importKey(encKeyBytes);
        })
        .then(function (cryptoKey) {
            // 5. Encrypt with AES-256-GCM
            return Q.Data.encrypt(cryptoKey, plaintext, { iv: ivBytes });
        })
        .then(function (enc) {
            // enc = { ciphertext: base64, tag: base64, iv: base64 }
            // 6. Store as a Drop (content-addressed)
            var dropsModule = options.drops || Q.Safecloud.Drops;

            return dropsModule.store({
                ciphertext: enc.ciphertext,
                tag:        enc.tag,
                iv:         enc.iv   // base64 IV as returned by Q.Data.encrypt
            }).then(function (dropResult) {
                // dropResult.cid = SHA-256 CID of the stored Drop
                var cid = dropResult.cid;

                // 7. Announce over Streams so other epoch key holders can find this message
                if (options.streamChannel) {
                    try {
                        Q.Streams.message(options.streamChannel, {
                            type:       'Safecloud/chat/announce',
                            cid:        cid,
                            threadId:   envelope.threadId,
                            epochIndex: envelope.epochIndex,
                            timestamp:  envelope.timestamp
                        });
                    } catch (streamErr) {
                        // Non-fatal: message is stored; stream announce is best-effort
                        Q.log('Chat.send: Streams announce failed (non-fatal):', streamErr.message);
                    }
                }

                return { cid: cid, envelope: envelope };
            });
        })
        .then(function (result) {
            callback(null, result);
        })
        .catch(function (err) {
            callback(err);
        });
    };
});
