'use strict';
/**
 * Safecloud Access — stream access model definitions.
 *
 * Access models are stored as unencrypted metadata on the stream so viewers
 * can inspect the terms before paying.  The model is set by the content
 * publisher via the stream's `Safecloud.access` attribute (a JSON string).
 *
 * Models
 * ------
 * "permanent"      Pay once, keys are issued and kept. The client may cache
 *                  them indefinitely (like buying a file).  Default when no
 *                  access attribute is present.
 *
 * "session"        Keys are issued for the session.  The client MUST discard
 *                  all keys when the player is closed or the page unloads.
 *                  Rewatching requires a new payment.
 *
 * "pay-per-minute" / "pay-per-second"
 *                  The Jet issues keys only for the current rewind window
 *                  (default: last 120 seconds of decoded content).  Keys for
 *                  chunks older than the window are never re-issued without a
 *                  fresh payment.  The client MUST destroy keys that fall
 *                  outside the window; on an attested Safebox the Jet can
 *                  enforce this by refusing to re-issue.
 *
 * Key policies (keyPolicy)
 * ------------------------
 * "permanent"      Issued once, never revoked.
 * "session"        Valid until the player closes.
 * "rolling-rewind" Valid only for chunks within [currentPosition - rewindWindow].
 *
 * Attestation requirement (requireAttestation)
 * --------------------------------------------
 * When true the Jet will only issue keys to clients that present a valid
 * Safebox attestation token proving the requesting origin is running a
 * blessed build of Safecloud.  Requests without a valid attestation receive
 * HTTP 403.  When false (default), any paying client receives keys.
 *
 * Individual users can always extract in-memory keys from an unattested
 * browser session — that is accepted.  requireAttestation closes the gap
 * that matters: distributing a patched Safecloud client that suppresses key
 * destruction at scale is impossible without a blessed Safebox build.
 *
 * @module Safecloud/Access
 */

/** @constant {string} Attribute name on the stream that holds the access policy. */
var ATTR = 'Safecloud.access';

/**
 * Default access model when the stream carries no Safecloud.access attribute.
 * @type {AccessModel}
 */
var DEFAULT_MODEL = {
    model:               'permanent',
    rewindWindow:        0,          // seconds; 0 = no rolling window
    ratePerSecond:       '0',        // wei per second of decoded content
    keyPolicy:           'permanent',
    requireAttestation:  false
};

/**
 * @typedef {Object} AccessModel
 * @property {'permanent'|'session'|'pay-per-minute'|'pay-per-second'} model
 * @property {number}  rewindWindow       Seconds of content the client may rewind
 *                                        without a new payment (0 = no limit).
 * @property {string}  ratePerSecond      Safebux (wei) charged per second of decoded
 *                                        content; "0" means free or already paid.
 * @property {'permanent'|'session'|'rolling-rewind'} keyPolicy
 *                                        How the Jet treats issued keys.
 * @property {boolean} requireAttestation Whether the Jet requires an attested
 *                                        Safebox client before issuing keys.
 */

/**
 * Parse an access model from a stream attribute value.
 *
 * The attribute value is a JSON string written by the publisher.  Unknown
 * fields are ignored; missing fields fall back to the defaults for the
 * declared model.
 *
 * @param  {string|Object|null} raw  The value of the stream's Safecloud.access
 *                                   attribute (JSON string or already-parsed object).
 * @return {AccessModel}
 */
function parseAccessModel(raw) {
    if (!raw) return Object.assign({}, DEFAULT_MODEL);

    var parsed;
    if (typeof raw === 'string') {
        try { parsed = JSON.parse(raw); } catch (e) { return Object.assign({}, DEFAULT_MODEL); }
    } else {
        parsed = raw;
    }

    if (!parsed || typeof parsed !== 'object') return Object.assign({}, DEFAULT_MODEL);

    var model = _validModel(parsed.model) ? parsed.model : DEFAULT_MODEL.model;

    // keyPolicy defaults: pay-per-* → rolling-rewind, session → session, else permanent.
    var defaultPolicy = (model === 'pay-per-minute' || model === 'pay-per-second')
        ? 'rolling-rewind'
        : (model === 'session' ? 'session' : 'permanent');

    return {
        model: model,
        rewindWindow: (typeof parsed.rewindWindow === 'number' && parsed.rewindWindow >= 0)
            ? parsed.rewindWindow
            : (model === 'pay-per-minute' ? 120 : model === 'pay-per-second' ? 10 : 0),
        ratePerSecond: (typeof parsed.ratePerSecond === 'string')
            ? parsed.ratePerSecond
            : DEFAULT_MODEL.ratePerSecond,
        keyPolicy: _validKeyPolicy(parsed.keyPolicy) ? parsed.keyPolicy : defaultPolicy,
        requireAttestation: parsed.requireAttestation === true
    };
}

/**
 * Read the access model from a stream-fields object as returned by the
 * Safecloud / Streams API.
 *
 * @param  {Object} streamFields  Stream fields object (must have an `attributes` property
 *                                or individual attribute keys).
 * @return {AccessModel}
 */
function fromStream(streamFields) {
    if (!streamFields) return Object.assign({}, DEFAULT_MODEL);

    // Streams stores attributes in a nested object under "attributes" or as
    // top-level keys prefixed with the attribute name.
    var attrs = streamFields.attributes || streamFields;
    var raw   = (attrs && typeof attrs.getAttribute === 'function')
        ? attrs.getAttribute(ATTR)
        : (attrs && attrs[ATTR]);

    return parseAccessModel(raw || null);
}

/**
 * Encode an AccessModel back to the JSON string stored as a stream attribute.
 *
 * @param  {AccessModel} model
 * @return {string}
 */
function encodeAccessModel(model) {
    return JSON.stringify({
        model:              model.model,
        rewindWindow:       model.rewindWindow,
        ratePerSecond:      model.ratePerSecond,
        keyPolicy:          model.keyPolicy,
        requireAttestation: model.requireAttestation
    });
}

/**
 * Returns true when model is rolling-rewind and the given chunk position
 * (in seconds) has fallen outside the rewind window.
 *
 * @param  {AccessModel} model
 * @param  {number}      currentPositionSec  Current playback position (seconds).
 * @param  {number}      chunkPositionSec    Start time of the chunk (seconds).
 * @return {boolean}
 */
function isChunkExpired(model, currentPositionSec, chunkPositionSec) {
    if (model.keyPolicy !== 'rolling-rewind' || model.rewindWindow <= 0) return false;
    return chunkPositionSec < currentPositionSec - model.rewindWindow;
}

// ── Private helpers ──────────────────────────────────────────────────────────

var VALID_MODELS = { permanent: true, session: true, 'pay-per-minute': true, 'pay-per-second': true };
function _validModel(v) { return typeof v === 'string' && VALID_MODELS[v]; }

var VALID_POLICIES = { permanent: true, session: true, 'rolling-rewind': true };
function _validKeyPolicy(v) { return typeof v === 'string' && VALID_POLICIES[v]; }

// ── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
    ATTR:               ATTR,
    DEFAULT_MODEL:      DEFAULT_MODEL,
    parseAccessModel:   parseAccessModel,
    fromStream:         fromStream,
    encodeAccessModel:  encodeAccessModel,
    isChunkExpired:     isChunkExpired
};
