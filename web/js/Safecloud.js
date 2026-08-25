"use strict";
/**
 * @module Safecloud
 */
(function (Q, $) {

/**
 * Text for Safecloud plugin, will be overridden by loaded language file
 * @property Q.text.Safecloud
 * @type {Object}
 */
Q.text.Safecloud = {};
Q.Text.addFor(
    ['Q.Tool.define', 'Q.Template.set'],
    'Safecloud/', ['Safecloud/content']
);

/**
 * Lazy-loaded tools.
 * Each file calls Q.Tool.define() directly.
 */
Q.Tool.define({
    "Safecloud/drop": {
        js:   "{{Safecloud}}/js/tools/drop.js",
        css:  "{{Safecloud}}/css/tools/drop.css",
        text: ["Safecloud/content"]
    },
    "Safecloud/upload": {
        js:   "{{Safecloud}}/js/tools/upload.js",
        css:  "{{Safecloud}}/css/tools/upload.css",
        text: ["Safecloud/content"]
    },
    "Safecloud/player": {
        js:   "{{Safecloud}}/js/tools/player.js",
        css:  "{{Safecloud}}/css/tools/player.css",
        text: ["Safecloud/content"]
    },
    // Safecloud-aware video player. Same file also (re)defines "Q/video" as a
    // drop-in replacement adding the 'safecloud' adapter — see js/Q/video.js.
    "Safecloud/video": {
        js: "{{Safecloud}}/js/Q/video.js"
    },
    // Uncommenting this remaps the core Q/video tool to the drop-in above for
    // the whole app (all existing adapters preserved):
    // "Q/video": { js: "{{Safecloud}}/js/Q/video.js" },
    "Safecloud/video": {
        js:   "{{Safecloud}}/js/tools/video.js",
        css:  "{{Safecloud}}/css/tools/video.css",
        text: ["Safecloud/content"]
    }
});

var Safecloud = Q.Safecloud = Q.plugins.Safecloud = Q.Safecloud || {};

Q.onInit.add(function () {
    Q.Text.get('Safecloud/content', function (err, text) {
        if (text) { Q.extend(Q.text.Safecloud, 10, text); }
    });
}, 'Safecloud');

// ── Q.Safecloud.Client / Jets / Drops — browser-side method stubs ────────────
// Implementations are loaded on demand from
//   {{Safecloud}}/js/methods/Safecloud/Client/<method>.js  etc.
// ─────────────────────────────────────────────────────────────────────────────

Q.Safecloud.Client = Q.Method.define({

    // ── Power API ─────────────────────────────────────────────────────────────

    /**
     * Encrypt a file and upload it to the network via Jets.
     *
     * Pipeline:
     *   rootKey → encryptionRoot → subtreeKey → chunkKey[i] / chunkIV[i]
     *   → AES-256-GCM encrypt → CID → Merkle root → Jets.put
     *
     * @method store
     * @param {Object}   file         { data: Blob, name: String, type: String, tags: Array }
     * @param {Object}   [options]    { key, videoKey, version, chunkSize,
     *                                  authorizations, payments,
     *                                  jurisdiction, aiAttestation, onProgress }
     * @param {Function} [callback]
     * @return {Promise<{ manifest: Object, rootKey: String }>}
     */
    store: new Q.Method(),

    /**
     * Download, Merkle-verify and decrypt a range of chunks.
     *
     * @method fetch
     * @param {Object}   manifest     Public manifest from store()
     * @param {Object}   capability   { rootKey: String } | { grants: Array, manifest: Object }
     * @param {Object}   [options]    { start, end, authorizations, payments, onProgress }
     * @param {Function} [callback]
     * @return {Promise<Blob>}
     */
    fetch: new Q.Method(),

    /**
     * Produce a capability (subtree grant) authorising a grantee to decrypt
     * one or more chunk ranges.
     *
     * @method grant
     * @param {Object|null}       manifest  Public manifest (null for multi-version)
     * @param {Uint8Array|String} rootKey   Master key (null for multi-version)
     * @param {Object}            [options] { ranges, readLevel, writeLevel, adminLevel,
     *                                        format, exp, includeMerkleProofs, cids,
     *                                        videoManifest, videoKey, versions,
     *                                        timeStart, timeEnd }
     * @param {Function}          [callback]
     * @return {Promise<Object>}  { grants, manifest, readLevel, writeLevel, adminLevel }
     *                        or  videoCapability for the multi-version form
     */
    grant: new Q.Method(),

    /**
     * Store received encrypted chunks locally and announce to Jets,
     * turning this browser into a temporary Drop.
     *
     * @method reshare
     * @param {Array}    chunks    [ { cid, ciphertext, iv, tag, tags } ]
     * @param {Object}   [options] { authorizations, payments }
     * @param {Function} [callback]
     * @return {Promise<{ announced: Number }>}
     */
    reshare: new Q.Method(),

    /**
     * Register and activate the HLS service worker.  Idempotent.
     *
     * @method _ensureServiceWorker
     * @return {Promise<void>}
     */
    _ensureServiceWorker: new Q.Method(),

    /**
     * Maintain a sliding prefetch window of encrypted segments ahead of
     * the video playhead.  Version-aware; suspends when paused.
     *
     * @method _prefetchLoop
     * @param {String} videoId
     * @param {Object} videoManifest
     * @param {Object} capability
     * @param {Object} [options]  { at, version, videoElement, prefetchAhead, onError }
     * @return {Object}  { stop, pause, seek, setVersion }
     */
    _prefetchLoop: new Q.Method(),

    /**
     * Low-level streaming entry point.
     * Registers service worker, posts session, starts prefetch loop.
     *
     * @method stream
     * @param {Object} videoManifest
     * @param {Object} capability
     * @param {Object} [options]  { at, version, videoElement, prefetchAhead, onError }
     * @return {Promise<Object>}  { url, currentTime, seek, setVersion, pause, stop }
     */
    stream: new Q.Method(),

    /**
     * MSE-based streaming for iOS Safari 16.4+ and other MSE-capable browsers.
     * Requires manifest.initSegment, manifest.chunks[], manifest.keyframes[].
     * Use stream() instead of calling this directly — it auto-detects the best path.
     *
     * @method streamMSE
     * @param {Object} videoManifest
     * @param {Object} capability
     * @param {Object} [options]  { at, version, videoElement, prefetchAhead, onError }
     * @return {Promise<Object>}  { url, path, currentTime, seek, setVersion, pause, resume, stop }
     */
    streamMSE: new Q.Method(),

    /**
     * Fetch and decrypt the index track from manifest.indexCid.
     * Returns the index object (chapters, initSegment, codec, etc.) or null.
     *
     * @method fetchIndex
     * @param {Object}   manifest     Must have indexCid
     * @param {Object}   capability   { rootKey } or { indexGrant }
     * @param {Object}   [options]
     * @param {Function} [callback]
     * @return {Promise<Object|null>}
     */
    fetchIndex: new Q.Method(),

    /**
     * Produce a grant for the index track only (no data track access).
     * Shorthand for grant(manifest, rootKey, { indexOnly: true }, callback).
     *
     * @method grantIndex
     * @param {Object}   manifest
     * @param {String}   rootKey
     * @param {Object}   [options]  { exp, format }
     * @param {Function} [callback]
     * @return {Promise<{ indexGrant, manifest }>}
     */
    grantIndex: new Q.Method(),

    // ── Ergonomic public API ──────────────────────────────────────────────────

    /**
     * Encrypt and upload a file.  Thin wrapper over store().
     *
     * @method upload
     * @param {File|Object} file
     * @param {Object}      [options]  { videoKey, version, ... }
     * @param {Function}    [callback]
     * @return {Promise<{ manifest: Object, rootKey: String }>}
     */
    upload: new Q.Method(),

    /**
     * Download and decrypt a file; optionally trigger browser save dialog.
     *
     * @method download
     * @param {Object}   manifest
     * @param {Object}   capability
     * @param {Object}   [options]   { save: Boolean, ...fetchOptions }
     * @param {Function} [callback]
     * @return {Promise<Blob|null>}
     */
    download: new Q.Method(),

    /**
     * Start encrypted video/audio playback.  Returns a live handle.
     *
     * @method play
     * @param {Object} videoManifest
     * @param {Object} capability
     * @param {Object} [options]   { at, version, videoElement, prefetchAhead, onError }
     * @return {Promise<Object>}  { url, currentTime, seek, setVersion, pause, stop }
     */
    play: new Q.Method(),

    /**
     * Suspend an active streaming session returned by play().
     *
     * @method pause
     * @param {Object} handle   Return value of play()
     * @return {void}
     */
    pause: new Q.Method(),

    /**
     * Establish the Cloud's payer identity for micropayments.
     * Derives a stable EVM keypair via WebAuthn PRF (label
     * "safecloud.cloud.session"), or uses options.privateKey directly.
     * Sets Q.Safecloud.Jets.cloudEvmPrivateKey/cloudEvmAddress so
     * Jets.get() auto-signs Cloud→Jet payment tokens.
     *
     * @method init
     * @param {Object}   [options]  { privateKey, interactive }
     * @param {Function} [callback]
     * @return {Promise<{ evmAddress: String|null, anonymous: Boolean }>}
     */
    init: new Q.Method(),

    /**
     * Persist a {manifest, capability} pair to IndexedDB under its rootCid,
     * so players (including iframe embeds in a pristine environment) can
     * later stream with only the rootCid.
     *
     * @method saveCapability
     * @param {String}   rootCid
     * @param {Object}   data      { manifest, capability }
     * @param {Function} [callback]
     * @return {Promise<void>}
     */
    saveCapability: new Q.Method(),

    /**
     * Load a previously saved {manifest, capability} pair by rootCid.
     *
     * @method loadCapability
     * @param {String}   rootCid
     * @param {Function} [callback]
     * @return {Promise<{ manifest, capability }|null>}
     */
    loadCapability: new Q.Method(),

    /**
     * Create a share link with split-entropy bootstrap.
     * Returns { url, passphrase, split } — the URL goes through Channel 1,
     * the passphrase through Channel 2 (voice, QR, separate message).
     * Neither alone can decrypt the content.
     *
     * @method createShareLink
     * @param {Object}   manifest
     * @param {String}   rootKey
     * @param {Object}   [options]  { split: true, words: 4, embed: true }
     * @param {Function} [callback]
     * @return {Promise<Object>}
     */
    createShareLink: new Q.Method(),

    /**
     * Recover rootKey from a split-entropy share link.
     * Combines URL token + mask (Channel 1) with passphrase (Channel 2).
     *
     * @method recoverSplitKey
     * @param {String}   rootCid
     * @param {String}   tokenHex   from URL fragment 'st='
     * @param {String}   maskB64    from URL fragment 'sm='
     * @param {String}   passphrase from out-of-band channel
     * @param {Function} [callback]
     * @return {Promise<String>} rootKey as base64
     */
    recoverSplitKey: new Q.Method(),

    /**
     * Fetch and decrypt the metadata fork (price, royalty split, title).
     *
     * @method fetchMeta
     * @param {Object}   manifest
     * @param {String}   rootKey
     * @param {Object}   [options]
     * @param {Function} [callback]
     * @return {Promise<Object>}
     */
    fetchMeta: new Q.Method()

}, "{{Safecloud}}/js/methods/Safecloud/Client", function () {
    return [Q];
}, {
    require: "_internal"
});

/** Default chunk size: 256 KB. @property {Number} */
Q.Safecloud.Client.defaultChunkSize = 256 * 1024;

/** Manifest format version. @property {Number} */
Q.Safecloud.Client.manifestVersion = 1;


// ─────────────────────────────────────────────────────────────────────────────
// Q.Safecloud.Jets  — browser socket client for the Jet server
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Browser socket client.
 * Maintains the /Safecloud/ socket.io connection, exposes subtree put/get for Cloud,
 * and manages Drop lifecycle events.
 *
 * @class Q.Safecloud.Jets
 * @static
 */
Q.Safecloud.Jets = Q.Method.define({

    /**
     * Connect to the Jet server (idempotent).
     * @method connect
     * @param {Function} [callback]  fn(err, Q.Socket)
     * @return {Promise<Q.Socket>}
     */
    connect: new Q.Method(),

    /**
     * Upload a subtree of encrypted chunks.
     * @method put
     * @param {Object}   subtree   { chunks, start, end, grants }
     * @param {Object}   [options] { authorizations, payments, onProgress }
     * @param {Function} [callback]
     * @return {Promise<{ results: Array }>}
     */
    put: new Q.Method(),

    /**
     * Download a chunk range (with Merkle proofs attached).
     * @method get
     * @param {Object}   subtree   { rootCid, start, end, grants }
     * @param {Object}   [options] { authorizations, payments, onProgress }
     * @param {Function} [callback]
     * @return {Promise<{ chunks: Array }>}
     */
    get: new Q.Method(),

    /**
     * Register this browser as a Drop.
     * @method dropRegister
     * @param {Object}   info      { evmAddress, delegation, publicKey,
     *                               storage, prollyRoot, bloomFilter }
     * @param {Function} [callback]
     * @return {Promise<{ dropId: String, cold: Boolean, minStake: String }>}
     */
    dropRegister: new Q.Method(),

    /**
     * Announce updated Drop inventory to the Jet.
     * @method dropAnnounce
     * @param {Object}   info      { dropId, storage, used, prollyRoot, bloomFilter }
     * @param {Function} [callback]
     * @return {Promise<void>}
     */
    dropAnnounce: new Q.Method(),

    /**
     * Signal intentional Drop disconnection.
     * @method dropDisconnect
     * @param {Function} [callback]
     * @return {Promise<void>}
     */
    dropDisconnect: new Q.Method(),

    /**
     * Submit accumulated OCP payment tokens for on-chain claiming.
     * @method dropClaimPayments
     * @param {Object}   payload   { dropId, paymentTokens, signature }
     * @param {Function} [callback]
     * @return {Promise<{ txHash: String|null }>}
     */
    dropClaimPayments: new Q.Method(),

    /**
     * Live Cloud payer statistics for in-tab dashboards.
     * @method getCloudStats
     * @return {Object} { chunksFetched, bytesFetched, chunksUploaded,
     *                    bytesUploaded, paymentsSigned, paidWei, paidSbux }
     */
    getCloudStats: new Q.Method()

}, "{{Safecloud}}/js/methods/Safecloud/Jets", function () {
    return [Q];
}, {
    require: "_internal"
});

/** Override to point the client at a specific Jet URL. Defaults to Q.nodeUrl(). */
Q.Safecloud.Jets.url = null;

/** Fired after socket connects. @event onConnect @param {Q.Socket} qs */
Q.Safecloud.Jets.onConnect = new Q.Event();

/** Fired on socket disconnect. @event onDisconnect */
Q.Safecloud.Jets.onDisconnect = new Q.Event();

/** Incoming Safecloud/drop/put push from Jet. @event onDropPut */
Q.Safecloud.Jets.onDropPut = new Q.Event();

/** Incoming Safecloud/drop/get push from Jet. @event onDropGet */
Q.Safecloud.Jets.onDropGet = new Q.Event();

/** Incoming Safecloud/drop/challenge push from Jet. @event onDropChallenge */
Q.Safecloud.Jets.onDropChallenge = new Q.Event();

/** Incoming Safecloud/drop/slashed push from Jet. @event onDropSlashed */
Q.Safecloud.Jets.onDropSlashed = new Q.Event();

/** Fired when the Jet publishes its payment/network info. @event onInfo @param {Object} info */
Q.Safecloud.Jets.onInfo = new Q.Event();


// ─────────────────────────────────────────────────────────────────────────────
// Q.Safecloud.Drops  — browser IndexedDB storage layer
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Browser storage layer.  Stores and serves opaque ciphertext.
 * Never sees plaintext.  Never decrypts anything.
 *
 * @class Q.Safecloud.Drops
 * @static
 */
Q.Safecloud.Drops = Q.Method.define({

    /**
     * Initialise: open IndexedDB, replay diff log, run delegation ceremony
     * if needed, register with Jet.
     * @method init
     * @param {Object}   [options]  { wallet, storageGB, jetUrl }
     * @param {Function} [callback]
     * @return {Promise<void>}
     */
    init: new Q.Method(),

    /**
     * Store encrypted chunks in IndexedDB.
     * Triggers LRU eviction + announce-before-evict when quota exceeded.
     * @method put
     * @param {Array}    chunks    [ { iv, ciphertext, tag, size, tags } ]
     * @param {Object}   [options] { authorizations, payments }
     * @param {Function} [callback]
     * @return {Promise<{ results: Array }>}
     */
    put: new Q.Method(),

    /**
     * Retrieve encrypted chunks from IndexedDB.
     * Verifies Jet Safebux balance before serving if paymentToken present.
     * @method get
     * @param {Array}    cids
     * @param {Object}   [options] { paymentToken }
     * @param {Function} [callback]
     * @return {Promise<{ chunks: Array }>}
     */
    get: new Q.Method(),

    /**
     * Return the current Prolly root from in-memory state.  O(1).
     * @method getProllyRoot
     * @param {Function} [callback]
     * @return {Promise<String|null>}
     */
    getProllyRoot: new Q.Method(),

    /**
     * Return the serialised Bloom filter (base64).
     * Rebuilds from IndexedDB if invalidated by eviction.
     * @method getBloomFilter
     * @param {Function} [callback]
     * @return {Promise<String|null>}
     */
    getBloomFilter: new Q.Method(),

    /**
     * Sign and send Safecloud/drop/announce to the Jet.
     * Called automatically by put() after each batch.
     * @method announce
     * @param {String}   reason    'stored' | 'eviction' | 'reset'
     * @param {Function} [callback]
     * @return {Promise<void>}
     */
    announce: new Q.Method(),

    /**
     * Claim accumulated Safebux payment tokens on-chain.
     * @method claimPayments
     * @param {Object}   [options]  { direct: Boolean, force: Boolean }
     * @param {Function} [callback]
     * @return {Promise<{ claimed: Number, txHashes: Array }>}
     */
    claimPayments: new Q.Method(),

    /**
     * Clear all IndexedDB stores and announce a reset to the Jet.
     * Does NOT clear the delegation claim or session keypairs.
     * @method reset
     * @param {Function} [callback]
     * @return {Promise<void>}
     */
    reset: new Q.Method(),

    /**
     * Return live performance statistics for this Drop node.
     * @method getStats
     * @return {Object} { servedMB, servedChunks, storedMB, storedChunks, safebuxEarned, dropId, evmAddress, prollyRoot, uptime }
     */
    getStats: new Q.Method(),

    /**
     * Asynchronous payment-token statistics from IndexedDB.
     * @method getPaymentStats
     * @param {Function} [callback]
     * @return {Promise<{ tokens, totalWei, totalSbux, thresholdWei, claimable }>}
     */
    getPaymentStats: new Q.Method()

}, "{{Safecloud}}/js/methods/Safecloud/Drops", function () {
    return [Q];
}, {
    require: "_internal"
});

})(Q, Q.jQuery);
