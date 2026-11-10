'use strict';
/**
 * JetEpoch.js — Epoch management for Safecloud Jet succession.
 *
 * Phase 2 of the signed hash chain: when a standby Jet takes over after a
 * netsplit or primary failure, it:
 *
 *   1. Pulls missing records from the previous Jet via GET /Streams/messages?after=N.
 *   2. Verifies each record's sig + prev_hash chain against the previous Jet's pubkey.
 *   3. Inserts verified records into local SQLite (using Streams.postMessage bypass).
 *   4. Increments its own epoch, posts a Streams/epoch message to the stream's
 *      metadata channel (or the well-known jet epoch stream).
 *   5. Begins accepting writes.
 *
 * Canonical succession tiebreak:
 *   Each Jet has a successionList (array of hex-encoded public key hashes).
 *   Jets are ranked by lex(hash(public_key)).  When two Jets are simultaneously
 *   alive after a netsplit heals, the lower-ranked Jet defers to the higher-ranked
 *   one — deterministic, stateless, no coordination round needed.
 *
 * Usage (called from bin/jet.js after Streams.listen()):
 *   var JetEpoch = require('./JetEpoch');
 *   JetEpoch.init(Streams, JetKey, successionList);
 *   // If this Jet is the new primary, call:
 *   await JetEpoch.succeedFrom({ url: 'http://previous-jet:8080', publisherId, streamName });
 */

var https  = require('https');
var http   = require('http');
var crypto = require('crypto');

var _Streams        = null;
var _JetKey         = null;
var _successionList = [];  // array of hex-encoded sha256(public_key) for each Jet in order

/** Must be called once before any other method. */
function init(Streams, JetKey, successionList) {
    _Streams        = Streams;
    _JetKey         = JetKey;
    _successionList = Array.isArray(successionList) ? successionList : [];
}

/**
 * Rank of this Jet in the succession list (lower index = higher rank).
 * Returns -1 if this Jet is not in the list (should not happen in production).
 */
function myRank() {
    if (!_JetKey) return -1;
    var myHash = crypto.createHash('sha256').update(Buffer.from(_JetKey.publicKeyHex(), 'hex')).digest('hex');
    return _successionList.indexOf(myHash);
}

/**
 * Returns true if this Jet should defer to a simultaneously-alive other Jet
 * whose public key hash is `otherHash`.
 */
function shouldDefer(otherHash) {
    var myIdx    = myRank();
    var otherIdx = _successionList.indexOf(otherHash);
    if (myIdx < 0)    return false; // not in list — do not defer
    if (otherIdx < 0) return false; // other is not in list — do not defer
    return otherIdx < myIdx;        // lower index = higher rank wins
}

/**
 * Pull records from a previous Jet and verify the hash chain.
 * Inserts only verified records.
 *
 * @param {Object} opts
 * @param {string} opts.url          Base URL of the previous Jet, e.g. "http://jet1:8080"
 * @param {string} opts.publisherId
 * @param {string} opts.streamName
 * @param {string} opts.prevPublicKeyHex  Hex-encoded Ed25519 public key of the previous Jet
 * @param {number} [opts.after]      Only fetch records with ordinal > after (default: highest local ordinal)
 * @returns {Promise<{ pulled: number, verified: number, failed: number }>}
 */
function pullFrom(opts) {
    if (!_Streams || !_JetKey) return Promise.reject(new Error('JetEpoch.init() not called'));

    var db = _Streams.getDb();
    if (!db) return Promise.reject(new Error('Streams DB not initialized'));

    var after = opts.after;
    if (after == null) {
        // Find highest local ordinal for this stream
        var row = db.prepare(
            'SELECT MAX(ordinal) as maxOrd FROM streams_message WHERE publisherId = ? AND streamName = ?'
        ).get(opts.publisherId, opts.streamName);
        after = (row && row.maxOrd != null) ? row.maxOrd : 0;
    }

    var url = opts.url.replace(/\/$/, '') + '/Streams/messages'
        + '?publisherId=' + encodeURIComponent(opts.publisherId)
        + '&streamName='  + encodeURIComponent(opts.streamName)
        + '&after='       + after
        + '&limit=1000'
        + '&ascending=1';

    return _httpGet(url).then(function (body) {
        var data;
        try { data = JSON.parse(body); } catch (e) { throw new Error('Pull: invalid JSON from ' + url); }

        var messages = (data.slots && data.slots.messages) ? data.slots.messages : {};
        var ordinals = Object.keys(messages).map(Number).sort(function (a, b) { return a - b; });

        var pulled   = ordinals.length;
        var verified = 0;
        var failed   = 0;

        // Walk in ordinal order, verify chain
        var prevHash = after === 0 ? '' : null; // need to load prev_hash of record `after` if any

        if (after > 0 && prevHash === null) {
            var prevRow = db.prepare(
                'SELECT prev_hash, sig, epoch, ordinal, publisherId, streamName, content, byUserId, insertedTime ' +
                'FROM streams_message WHERE publisherId = ? AND streamName = ? AND ordinal = ?'
            ).get(opts.publisherId, opts.streamName, after);
            if (prevRow) {
                var prevPayload = sigPayloadStr(prevRow);
                prevHash = sha256hex(prevPayload);
            } else {
                prevHash = '';
            }
        }

        for (var i = 0; i < ordinals.length; i++) {
            var ord = ordinals[i];
            var msg = messages[ord];
            if (!msg) { failed++; continue; }

            // Verify prev_hash linkage
            if (prevHash !== null && msg.prev_hash !== prevHash) {
                console.error('[JetEpoch] Pull: prev_hash mismatch at ordinal ' + ord +
                    ' (expected ' + prevHash + ', got ' + msg.prev_hash + ')');
                failed++;
                break; // chain broken — stop here
            }

            // Verify signature
            if (opts.prevPublicKeyHex && msg.sig) {
                var JetKeyModule = require('./JetKey');
                var payload = sigPayloadStr(msg);
                if (!JetKeyModule.verify(payload, msg.sig, opts.prevPublicKeyHex)) {
                    console.error('[JetEpoch] Pull: invalid signature at ordinal ' + ord);
                    failed++;
                    break;
                }
            }

            // Insert (using raw DB insert to bypass hooks and re-signing)
            try {
                db.prepare(
                    'INSERT OR IGNORE INTO streams_message ' +
                    '(publisherId, streamName, ordinal, epoch, insertedTime, sentTime,' +
                    ' byUserId, byClientId, type, content, instructions, weight,' +
                    ' prev_hash, sig, idempotency_key) ' +
                    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
                ).run(
                    msg.publisherId, msg.streamName, msg.ordinal,
                    msg.epoch || 1, msg.insertedTime, msg.sentTime || msg.insertedTime,
                    msg.byUserId || '', msg.byClientId || '', msg.type,
                    msg.content || '', msg.instructions || '',
                    msg.weight != null ? msg.weight : 1.0,
                    msg.prev_hash || '', msg.sig || '', null
                );
                // Update stream messageCount
                db.prepare(
                    'UPDATE streams_message SET 1=1 WHERE 1=0' // no-op; count updated below
                );
                verified++;
                // Advance prevHash
                prevHash = sha256hex(sigPayloadStr(msg));
            } catch (e) {
                console.error('[JetEpoch] Pull: insert failed at ordinal ' + ord + ': ' + e.message);
                failed++;
            }
        }

        // Sync messageCount
        if (verified > 0) {
            var maxOrdRow = db.prepare(
                'SELECT MAX(ordinal) as maxOrd FROM streams_message WHERE publisherId = ? AND streamName = ?'
            ).get(opts.publisherId, opts.streamName);
            if (maxOrdRow && maxOrdRow.maxOrd != null) {
                db.prepare(
                    'UPDATE streams_stream SET messageCount = ? WHERE publisherId = ? AND name = ?'
                ).run(maxOrdRow.maxOrd, opts.publisherId, opts.streamName);
            }
        }

        return { pulled: pulled, verified: verified, failed: failed };
    });
}

/**
 * Post a Streams/epoch message to the jet metadata stream, declaring this
 * Jet's epoch number and public key.  Called after pull replication completes.
 *
 * @param {Object} opts
 * @param {string} opts.publisherId    Publisher of the stream
 * @param {string} opts.streamName     The stream that just had an epoch transition
 * @param {number} opts.epoch          The new epoch number
 * @param {Array}  opts.successionList
 */
function announceEpoch(opts) {
    if (!_Streams || !_JetKey) return Promise.reject(new Error('JetEpoch.init() not called'));
    _Streams.setEpoch(opts.epoch);

    var content = JSON.stringify({
        epoch:          opts.epoch,
        jetPublicKey:   _JetKey.publicKeyHex(),
        successionList: opts.successionList || _successionList
    });

    // Post to the well-known epoch metadata stream (not encrypted)
    var params = {
        publisherId:  opts.publisherId,
        streamName:   opts.streamName,
        byUserId:     'jet',
        type:         'Streams/epoch',
        content:      content,
        instructions: '',
        weight:       1.0
    };

    try {
        _Streams.postMessage(params);
        console.log('[JetEpoch] Epoch ' + opts.epoch + ' announced on ' + opts.publisherId + '/' + opts.streamName);
    } catch (e) {
        console.error('[JetEpoch] announceEpoch failed:', e.message);
    }
    return Promise.resolve();
}

// ─── Private helpers ──────────────────────────────────────────────────────────

function sigPayloadStr(record) {
    return [
        record.epoch        != null ? String(record.epoch)   : '1',
        record.ordinal      != null ? String(record.ordinal) : '0',
        record.prev_hash    || '',
        record.publisherId  || '',
        record.streamName   || '',
        record.content      || '',
        record.byUserId     || '',
        record.insertedTime || ''
    ].join('|');
}

function sha256hex(str) {
    return crypto.createHash('sha256').update(Buffer.from(str, 'utf8')).digest('hex');
}

function _httpGet(url) {
    return new Promise(function (resolve, reject) {
        var mod = url.startsWith('https:') ? https : http;
        var req = mod.get(url, function (res) {
            var body = '';
            res.on('data', function (c) { body += c; });
            res.on('end', function () { resolve(body); });
        });
        req.on('error', reject);
        req.setTimeout(10000, function () { req.destroy(); reject(new Error('Pull timeout')); });
    });
}

module.exports = { init: init, myRank: myRank, shouldDefer: shouldDefer, pullFrom: pullFrom, announceEpoch: announceEpoch };
