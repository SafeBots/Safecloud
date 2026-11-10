/**
 * Q.Safecloud.Chat.message — build and parse deniable chat message envelopes.
 *
 * INNOVATION 6 — Transcript Simulability (Deniability):
 *   Messages are encrypted with a shared symmetric epoch key.
 *   There are NO per-message signatures.
 *   Because any holder of the epoch key can produce valid ciphertext that
 *   decrypts to any plaintext, transcript contents cannot be proven to have
 *   come from a specific participant.  This provides off-the-record deniability
 *   analogous to OTR, but at the group level.
 *
 * INNOVATION 9 — DAG Threading:
 *   Each message carries parentIds[] — an array of CIDs of messages this
 *   message replies to (zero or more).  This forms a DAG rather than a strict
 *   linear thread, allowing concurrent messages to be represented faithfully.
 *
 * Message envelope (plaintext before encryption):
 * {
 *   type:        'Safecloud/chat/message'  — identifies the envelope format
 *   version:     1                   — schema version
 *   threadId:    string              — identifies the chat thread / conversation
 *   epochIndex:  number              — which epoch key was used for this message
 *   parentIds:   string[]            — CIDs of parent messages in the DAG ([] for root)
 *   text:        string              — message body
 *   senderHint:  string | null       — advisory sender ID; NOT cryptographically signed
 *   timestamp:   number             — UTC milliseconds
 * }
 *
 * The senderHint is advisory only.  Recipients trust it only to the extent that
 * they trust the epoch key was not leaked to adversaries.
 */

Q.exports(function (Q) {
    var MESSAGE_VERSION = 1;
    var MESSAGE_TYPE    = 'Safecloud/chat/message';

    /**
     * build(options) → plaintext envelope Object
     *
     * options:
     *   threadId    {string}   required
     *   epochIndex  {number}   required
     *   text        {string}   required
     *   parentIds   {string[]} default []
     *   senderHint  {string}   default null
     *   timestamp   {number}   default Date.now()
     */
    function build(options) {
        if (!options.threadId)       { throw new Error('Chat.message.build: threadId required'); }
        if (typeof options.epochIndex !== 'number') { throw new Error('Chat.message.build: epochIndex (number) required'); }
        if (!options.text)           { throw new Error('Chat.message.build: text required'); }
        return {
            type:       MESSAGE_TYPE,
            version:    MESSAGE_VERSION,
            threadId:   options.threadId,
            epochIndex: options.epochIndex,
            parentIds:  options.parentIds  || [],
            text:       options.text,
            senderHint: options.senderHint || null,
            timestamp:  options.timestamp  || Date.now()
        };
    }

    /**
     * validate(envelope) → true | throws
     *
     * Checks that a decrypted message envelope has the expected shape.
     */
    function validate(env) {
        if (!env || typeof env !== 'object') { throw new Error('Chat.message.validate: not an object'); }
        if (env.type !== MESSAGE_TYPE)        { throw new Error('Chat.message.validate: unexpected type ' + env.type); }
        if (typeof env.threadId !== 'string') { throw new Error('Chat.message.validate: missing threadId'); }
        if (typeof env.epochIndex !== 'number') { throw new Error('Chat.message.validate: missing epochIndex'); }
        if (!Array.isArray(env.parentIds))    { throw new Error('Chat.message.validate: parentIds must be array'); }
        if (typeof env.text !== 'string')     { throw new Error('Chat.message.validate: missing text'); }
        return true;
    }

    return {
        build:    build,
        validate: validate,
        TYPE:     MESSAGE_TYPE,
        VERSION:  MESSAGE_VERSION
    };
});
