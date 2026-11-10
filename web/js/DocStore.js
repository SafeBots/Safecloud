/**
 * DocStore.js — Safecloud 4.0 Google-Suite layer.
 *
 * Wraps SafecloudYjsProvider with:
 *   1. Periodic Y.js STATE-VECTOR SNAPSHOTS stored in the doc's Streams
 *      attributes field — so reconnect replays only deltas after the last
 *      snapshot ordinal instead of the full history from ordinal 0.
 *   2. A "docs index" stream per publisher listing all document streams.
 *   3. Simple doc metadata (title, mime type, participants).
 *
 * Architecture recap
 * ──────────────────
 *
 *   Editor (Tiptap / jspreadsheet / CodeMirror / Slides)
 *     │  local change → ydoc transaction (applied immediately — OT-style)
 *   Y.Doc  (CRDT engine: merges concurrent edits from any ordinal order)
 *     │
 *   SafecloudYjsProvider
 *     │  encryptUpdate(Uint8Array) → CID
 *     │  POST /Streams/message { content: CID, type: 'Safecloud/docs/yjs' }
 *     │      ordinal = server-assigned (Streams.js, via better-sqlite3)
 *     │      sig/prev_hash = Ed25519 signed hash chain
 *     │  GET  /Streams/messages?after=<snapshotOrdinal>  (catch-up)
 *     │  socket.io 'Streams/message' (real-time push to other editors)
 *   Streams table (streams_message) — the ordered log
 *
 *   DocStore adds:
 *     • GET  /Streams/stream   — read stream attributes (snapshot_cid, snapshot_ordinal)
 *     • POST /Streams/stream   — save snapshot CID into stream attributes
 *     • GET  <snapshot_cid>    — decrypt Y.js state snapshot from Drop
 *     • GET  <publisherId>/docs/index stream — list of all docs
 *
 * Snapshot protocol
 * ─────────────────
 *   Every SNAPSHOT_INTERVAL_MS (default 60 s) or SNAPSHOT_UPDATE_COUNT
 *   updates (whichever comes first) DocStore:
 *     1. Y.encodeStateAsUpdate(ydoc) → Uint8Array (full current state)
 *     2. encryptUpdate(snapshot)     → snapshotCid
 *     3. POST /Streams/stream { attributes: { snapshot_cid: snapshotCid,
 *                                             snapshot_ordinal: highestOrdinal } }
 *   On next connect/reconnect:
 *     1. GET /Streams/stream → read attributes.snapshot_cid, attributes.snapshot_ordinal
 *     2. decryptUpdate(snapshot_cid) → Uint8Array
 *     3. Y.applyUpdate(ydoc, snapshot) — restores full state at snapshot ordinal
 *     4. SafecloudYjsProvider._catchUp() starts from snapshot_ordinal + 1
 *        (not from 0), so only the delta since the last snapshot is replayed.
 *
 * Usage
 * ─────
 *   const store = new DocStore({
 *     jetUrl:      'http://localhost:8080',
 *     publisherId: 'alice',
 *     docId:       'docs/my-report',      // used as the stream name
 *     userId:      'alice',
 *     encryptUpdate: async (u8) => cid,   // same crypto hooks as SafecloudYjsProvider
 *     decryptUpdate:  async (cid) => u8,
 *   });
 *
 *   // Open a Y.Doc (restores snapshot then replays delta):
 *   const ydoc = await store.open();
 *
 *   // Wire to Tiptap:
 *   new Editor({ extensions: [StarterKit, Collaboration.configure({ document: ydoc })] });
 *
 *   // Wire to CodeMirror markdown:
 *   const ytext = ydoc.getText('content');
 *   // ... bind ytext ↔ CodeMirror as in collab.html
 *
 *   // Wire to jspreadsheet sheets:
 *   const ycells = ydoc.getMap('cells');
 *   // ... bind ycells ↔ jspreadsheet as in collab.html
 *
 *   // List all docs for this publisher:
 *   const docs = await DocStore.listDocs(jetUrl, publisherId);
 *
 *   // Create a new doc:
 *   await DocStore.createDoc(jetUrl, publisherId, { docId, title, type });
 *
 *   // Close / destroy:
 *   store.close();
 *
 * @module DocStore
 * @version 1.0
 */

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.DocStore = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ─── Constants ────────────────────────────────────────────────────────────

    var DOC_STREAM_TYPE    = 'Safecloud/docs/document';
    var INDEX_STREAM_NAME  = 'docs/index';
    var INDEX_MESSAGE_TYPE = 'Safecloud/docs/index';

    // Take a snapshot every 60 s or every 200 Y.js updates, whichever comes first.
    var SNAPSHOT_INTERVAL_MS    = 60 * 1000;
    var SNAPSHOT_UPDATE_COUNT   = 200;

    // ─── DocStore constructor ──────────────────────────────────────────────────

    /**
     * @constructor
     * @param {Object} opts
     * @param {string}   opts.jetUrl          Jet base URL (no trailing slash)
     * @param {string}   opts.publisherId     Publisher / org ID
     * @param {string}   opts.docId           Stream name, e.g. 'docs/quarterly-report'
     * @param {string}   [opts.userId]        User ID for attribution / awareness
     * @param {Function} [opts.encryptUpdate] async (Uint8Array) → string cid
     * @param {Function} [opts.decryptUpdate]  async (string cid) → Uint8Array
     * @param {number}   [opts.debounceMs]    Provider flush debounce (default 300)
     * @param {*}        [opts.yjs]           Y.js instance (defaults to global Y)
     * @param {*}        [opts.io]            socket.io instance (defaults to global io)
     */
    function DocStore(opts) {
        this.opts         = opts || {};
        this.jetUrl       = (opts.jetUrl || '').replace(/\/$/, '');
        this.publisherId  = opts.publisherId;
        this.docId        = opts.docId;        // also the stream name
        this.userId       = opts.userId   || 'anonymous';
        this.debounceMs   = opts.debounceMs != null ? opts.debounceMs : 300;

        this._encryptUpdate = opts.encryptUpdate || null;
        this._decryptUpdate  = opts.decryptUpdate  || null;
        this._Y             = opts.yjs || (typeof Y !== 'undefined' ? Y : null);
        this._io            = opts.io  || (typeof io !== 'undefined' ? io : null);

        // ── Runtime state ──
        this.ydoc           = null;
        this._provider      = null;
        this._updatesSince  = 0;    // Y.js update count since last snapshot
        this._snapshotTimer = null;
        this._closed        = false;

        this._snapOrdinal   = 0;    // highest ordinal covered by last loaded snapshot
    }

    // ─── open() ───────────────────────────────────────────────────────────────

    /**
     * Open the document.
     *
     * 1. Load latest snapshot (if any) → restores Y.Doc state.
     * 2. Connect SafecloudYjsProvider → catch-up from (snapshot_ordinal+1).
     * 3. Start the auto-snapshot timer.
     *
     * @returns {Promise<Y.Doc>}
     */
    DocStore.prototype.open = function () {
        var self = this;
        if (!this._Y) return Promise.reject(new Error('DocStore: Y.js not found. Pass yjs via opts.yjs or include globally.'));
        if (!this._io) return Promise.reject(new Error('DocStore: socket.io-client not found. Pass io via opts.io or include globally.'));

        this.ydoc = new this._Y.Doc();

        // Step 1: load snapshot, then adjust provider to start catch-up from that ordinal
        return this._loadSnapshot().then(function (snapOrdinal) {
            self._snapOrdinal = snapOrdinal;

            // Step 2: build provider — patch _catchUp to start from snapOrdinal+1
            var SafecloudYjsProvider = _requireProvider();
            if (!SafecloudYjsProvider) {
                return Promise.reject(new Error('DocStore: SafecloudYjsProvider not found. Include SafecloudYjsProvider.js.'));
            }

            self._provider = new SafecloudYjsProvider(self.ydoc, {
                yjs:           self._Y,
                io:            self._io,
                jetUrl:        self.jetUrl,
                publisherId:   self.publisherId,
                streamName:    self.docId,
                userId:        self.userId,
                encryptUpdate: self._encryptUpdate,
                decryptUpdate:  self._decryptUpdate,
                debounceMs:    self.debounceMs
            });

            // Patch _catchUp to start from snapshot ordinal (skip already-applied history)
            if (snapOrdinal > 0) {
                var origCatchUp = self._provider._catchUp.bind(self._provider);
                self._provider._catchUp = function () {
                    return self._catchUpFrom(snapOrdinal + 1);
                };
            }

            // Track update count for auto-snapshot trigger
            self.ydoc.on('update', function (update, origin) {
                if (origin === self._provider) {
                    self._updatesSince++;
                    if (self._updatesSince >= SNAPSHOT_UPDATE_COUNT) {
                        self._scheduleSnapshot(0); // immediate
                    }
                }
            });

            self._provider.connect();
            self._startSnapshotTimer();
            return self.ydoc;
        });
    };

    // ─── close() ──────────────────────────────────────────────────────────────

    /**
     * Save a final snapshot then destroy the provider.
     * @returns {Promise<void>}
     */
    DocStore.prototype.close = function () {
        this._closed = true;
        clearTimeout(this._snapshotTimer);
        this._snapshotTimer = null;

        var self = this;
        var snapPromise = this._updatesSince > 0 ? this._saveSnapshot() : Promise.resolve();
        return snapPromise.then(function () {
            if (self._provider) {
                self._provider.destroy();
                self._provider = null;
            }
        });
    };

    // ─── Awareness proxy ──────────────────────────────────────────────────────

    /**
     * Forward awareness state to the underlying provider.
     * @param {Object} state  e.g. { cursor: { index, length }, user: { name, color } }
     */
    DocStore.prototype.setAwarenessState = function (state) {
        if (this._provider) this._provider.setAwarenessState(state);
    };

    Object.defineProperty(DocStore.prototype, 'awareness', {
        get: function () { return this._provider ? this._provider.awareness : null; }
    });

    Object.defineProperty(DocStore.prototype, 'onAwarenessChange', {
        set: function (fn) { if (this._provider) this._provider.onAwarenessChange = fn; }
    });

    // ─── Snapshot: save ───────────────────────────────────────────────────────

    DocStore.prototype._saveSnapshot = function () {
        if (!this._encryptUpdate || !this._Y || !this.ydoc) return Promise.resolve();
        var self = this;
        var currentOrdinal = this._provider ? this._provider._highestOrdinal : 0;

        try {
            var stateU8 = this._Y.encodeStateAsUpdate(this.ydoc);
        } catch (e) {
            console.warn('[DocStore] encodeStateAsUpdate error:', e);
            return Promise.resolve();
        }

        return Promise.resolve(this._encryptUpdate(stateU8)).then(function (cid) {
            // Store snapshot reference in the stream's attributes field
            var url  = self.jetUrl + '/Streams/stream';
            var body = JSON.stringify({
                publisherId: self.publisherId,
                streamName:  self.docId,
                attributes:  JSON.stringify({
                    snapshot_cid:     cid,
                    snapshot_ordinal: currentOrdinal,
                    snapshot_time:    Math.floor(Date.now() / 1000)
                })
            });
            return _fetchPost(url, body);
        }).then(function () {
            self._updatesSince = 0;
        }).catch(function (e) {
            console.warn('[DocStore] snapshot save error:', e);
        });
    };

    // ─── Snapshot: load ───────────────────────────────────────────────────────

    /**
     * Load the latest snapshot from the stream attributes.
     * Returns the snapshot ordinal (0 if no snapshot found — full history replay).
     * @returns {Promise<number>}
     */
    DocStore.prototype._loadSnapshot = function () {
        var self = this;
        var url  = this.jetUrl + '/Streams/stream'
            + '?publisherId=' + encodeURIComponent(this.publisherId)
            + '&streamName='  + encodeURIComponent(this.docId);

        return _fetchGet(url).then(function (json) {
            var stream = (json.slots && json.slots.stream) ? json.slots.stream : null;
            if (!stream) return 0;  // stream doesn't exist yet

            var attrs;
            try {
                attrs = JSON.parse(stream.attributes || '{}');
            } catch (e) {
                return 0;
            }

            if (!attrs.snapshot_cid || !self._decryptUpdate) return 0;

            var snapOrdinal = attrs.snapshot_ordinal || 0;

            return Promise.resolve(self._decryptUpdate(attrs.snapshot_cid)).then(function (u8) {
                if (!u8 || !self._Y || !self.ydoc) return 0;
                try {
                    self._Y.applyUpdate(self.ydoc, u8);
                    return snapOrdinal;
                } catch (e) {
                    console.warn('[DocStore] snapshot apply error:', e);
                    return 0;
                }
            }).catch(function (e) {
                console.warn('[DocStore] snapshot load error:', e);
                return 0;
            });
        }).catch(function () {
            return 0;  // stream doesn't exist yet — first open
        });
    };

    // ─── Catch-up from a specific ordinal ─────────────────────────────────────

    DocStore.prototype._catchUpFrom = function (fromOrdinal) {
        var self    = this;
        var p       = this._provider;
        p._catchingUp = true;
        var url = this.jetUrl + '/Streams/messages'
            + '?publisherId=' + encodeURIComponent(this.publisherId)
            + '&streamName='  + encodeURIComponent(this.docId)
            + '&after=' + (fromOrdinal - 1)
            + '&limit=2000&ascending=1';

        return _fetchGet(url).then(function (json) {
            var messages = (json.slots && json.slots.messages) ? json.slots.messages : {};
            var ordinals = Object.keys(messages).map(Number).sort(function (a, b) { return a - b; });
            var chain    = Promise.resolve();

            ordinals.forEach(function (ord) {
                var msg = messages[ord];
                if (!msg || msg.type !== 'Safecloud/docs/yjs') return;
                if (ord <= p._highestOrdinal) return;
                chain = chain.then(function () {
                    p._highestOrdinal = ord;
                    return p._applyRemote(msg.content);
                });
            });

            return chain;
        }).catch(function (e) {
            console.error('[DocStore] delta catch-up error:', e);
        }).then(function () {
            p._catchingUp = false;
        });
    };

    // ─── Snapshot timer ───────────────────────────────────────────────────────

    DocStore.prototype._startSnapshotTimer = function () {
        this._scheduleSnapshot(SNAPSHOT_INTERVAL_MS);
    };

    DocStore.prototype._scheduleSnapshot = function (delayMs) {
        clearTimeout(this._snapshotTimer);
        if (this._closed) return;
        var self = this;
        this._snapshotTimer = setTimeout(function () {
            self._snapshotTimer = null;
            if (self._closed || self._updatesSince === 0) {
                // Nothing to snapshot — reschedule check
                self._scheduleSnapshot(SNAPSHOT_INTERVAL_MS);
                return;
            }
            self._saveSnapshot().then(function () {
                self._scheduleSnapshot(SNAPSHOT_INTERVAL_MS);
            });
        }, delayMs);
    };

    // ─── Static: list docs ───────────────────────────────────────────────────

    /**
     * List all documents for a publisher.
     *
     * Documents are stored as messages in the publisher's 'docs/index' stream.
     * Each message content is a JSON object:
     *   { docId, title, type, createdAt, updatedAt, creatorId }
     *
     * @param {string} jetUrl
     * @param {string} publisherId
     * @returns {Promise<Array<{docId, title, type, createdAt, updatedAt, creatorId}>>}
     */
    DocStore.listDocs = function (jetUrl, publisherId) {
        var url = jetUrl.replace(/\/$/, '') + '/Streams/messages'
            + '?publisherId=' + encodeURIComponent(publisherId)
            + '&streamName='  + encodeURIComponent(INDEX_STREAM_NAME)
            + '&after=0&limit=1000&ascending=1';

        return _fetchGet(url).then(function (json) {
            var messages = (json.slots && json.slots.messages) ? json.slots.messages : {};
            var docs     = [];
            var seen     = {};

            // Walk in reverse ordinal order so latest entry wins per docId
            var ordinals = Object.keys(messages).map(Number).sort(function (a, b) { return b - a; });
            ordinals.forEach(function (ord) {
                var msg = messages[ord];
                if (!msg || msg.type !== INDEX_MESSAGE_TYPE) return;
                try {
                    var d = JSON.parse(msg.content);
                    if (d.docId && !seen[d.docId]) {
                        seen[d.docId] = true;
                        if (!d.deleted) docs.push(d);
                    }
                } catch (e) {}
            });

            return docs;
        }).catch(function () { return []; });
    };

    // ─── Static: create doc ───────────────────────────────────────────────────

    /**
     * Create a new document stream and register it in the docs index.
     *
     * @param {string} jetUrl
     * @param {string} publisherId
     * @param {Object} opts
     * @param {string}   opts.docId     stream name, e.g. 'docs/quarterly-report'
     * @param {string}   opts.title     human-readable title
     * @param {string}   [opts.type]    'doc' | 'sheet' | 'markdown' | 'slides'
     * @param {string}   [opts.userId]  creator ID
     * @returns {Promise<void>}
     */
    DocStore.createDoc = function (jetUrl, publisherId, opts) {
        jetUrl = (jetUrl || '').replace(/\/$/, '');
        var docId     = opts.docId;
        var now       = Math.floor(Date.now() / 1000);

        // 1. Create the doc's own stream
        var createUrl  = jetUrl + '/Streams/stream';
        var createBody = JSON.stringify({
            publisherId: publisherId,
            streamName:  docId,
            type:        DOC_STREAM_TYPE,
            title:       opts.title || docId,
            attributes:  JSON.stringify({ docType: opts.type || 'doc', createdAt: now, creatorId: opts.userId || '' })
        });

        return _fetchPost(createUrl, createBody).then(function () {
            // 2. Register in the index stream — ensure index stream exists
            var indexCreate  = jetUrl + '/Streams/stream';
            var indexBody    = JSON.stringify({
                publisherId: publisherId,
                streamName:  INDEX_STREAM_NAME,
                type:        'Safecloud/docs/index',
                title:       'Documents'
            });
            return _fetchPost(indexCreate, indexBody);
        }).then(function () {
            // 3. Post an index message
            var msgUrl  = jetUrl + '/Streams/message';
            var msgBody = JSON.stringify({
                publisherId: publisherId,
                streamName:  INDEX_STREAM_NAME,
                type:        INDEX_MESSAGE_TYPE,
                byUserId:    opts.userId || '',
                content:     JSON.stringify({
                    docId:     docId,
                    title:     opts.title || docId,
                    type:      opts.type || 'doc',
                    createdAt: now,
                    updatedAt: now,
                    creatorId: opts.userId || ''
                })
            });
            return _fetchPost(msgUrl, msgBody);
        });
    };

    // ─── Static: delete doc (soft delete) ────────────────────────────────────

    /**
     * Soft-delete a document from the index (marks deleted:true in index stream).
     */
    DocStore.deleteDoc = function (jetUrl, publisherId, docId, userId) {
        jetUrl = (jetUrl || '').replace(/\/$/, '');
        var url  = jetUrl + '/Streams/message';
        var body = JSON.stringify({
            publisherId: publisherId,
            streamName:  INDEX_STREAM_NAME,
            type:        INDEX_MESSAGE_TYPE,
            byUserId:    userId || '',
            content:     JSON.stringify({ docId: docId, deleted: true, deletedAt: Math.floor(Date.now() / 1000) })
        });
        return _fetchPost(url, body);
    };

    // ─── Utilities ───────────────────────────────────────────────────────────

    function _requireProvider() {
        if (typeof SafecloudYjsProvider !== 'undefined') return SafecloudYjsProvider;
        try { return require('./SafecloudYjsProvider'); } catch (e) { return null; }
    }

    function _fetchPost(url, body) {
        if (typeof fetch !== 'undefined') {
            return fetch(url, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    body
            }).then(function (r) { return r.json(); })
              .catch(function () { return {}; });
        }
        return _nodePost(url, body);
    }

    function _fetchGet(url) {
        if (typeof fetch !== 'undefined') {
            return fetch(url).then(function (r) { return r.json(); })
                             .catch(function () { return {}; });
        }
        return _nodeGet(url);
    }

    function _nodePost(url, body) {
        return new Promise(function (resolve) {
            try {
                var mod  = url.startsWith('https:') ? require('https') : require('http');
                var opts = require('url').parse(url);
                opts.method  = 'POST';
                opts.headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
                var req = mod.request(opts, function (res) {
                    var buf = '';
                    res.on('data', function (c) { buf += c; });
                    res.on('end', function () { try { resolve(JSON.parse(buf)); } catch (e) { resolve({}); } });
                });
                req.on('error', function () { resolve({}); });
                req.write(body);
                req.end();
            } catch (e) { resolve({}); }
        });
    }

    function _nodeGet(url) {
        return new Promise(function (resolve) {
            try {
                var mod = url.startsWith('https:') ? require('https') : require('http');
                var req = mod.get(url, function (res) {
                    var buf = '';
                    res.on('data', function (c) { buf += c; });
                    res.on('end', function () { try { resolve(JSON.parse(buf)); } catch (e) { resolve({}); } });
                });
                req.on('error', function () { resolve({}); });
            } catch (e) { resolve({}); }
        });
    }

    return DocStore;
}));
