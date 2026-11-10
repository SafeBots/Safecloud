/**
 * SafecloudYjsProvider.js — Yjs provider for Safecloud encrypted Streams.
 *
 * Maps a Y.Doc to a Safecloud encrypted Stream backed by the SQLite Jet.
 * One provider instance works with TipTap, Milkdown, and Univer — any editor
 * that accepts a standard Yjs provider.
 *
 * Usage:
 *   const provider = new SafecloudYjsProvider(ydoc, {
 *     jetUrl:      'http://localhost:8080',
 *     publisherId: 'alice',
 *     streamName:  'docs/my-doc',
 *     // Crypto hooks — called by the provider to encrypt/decrypt Yjs updates:
 *     encryptUpdate: async (uint8array) => cid_string,
 *     decryptUpdate:  async (cid_string) => uint8array,
 *     // Optional:
 *     userId:          'alice',
 *     debounceMs:      300,
 *     socketPath:      '/socket.io'
 *   });
 *   provider.connect();
 *
 *   // With TipTap:
 *   new Editor({ extensions: [Collaboration.configure({ document: ydoc })] });
 *
 *   // With Milkdown:
 *   editor.use(collab({ ydoc }));
 *
 * Encryption contract:
 *   encryptUpdate(update: Uint8Array) → Promise<string cid>
 *     Encrypts the Yjs binary update, stores ciphertext in a Drop, returns the CID.
 *   decryptUpdate(cid: string) → Promise<Uint8Array>
 *     Fetches the Drop by CID, decrypts, returns the Yjs binary update.
 *
 * Network protocol:
 *   - On connect: GET /Streams/messages?after=0 to catch up all history.
 *   - Local Y.Doc changes: buffered for `debounceMs`, then:
 *       1. Y.mergeUpdates(pendingUpdates) → merged Uint8Array
 *       2. encryptUpdate(merged) → cid
 *       3. POST /Streams/message { type: 'Safecloud/docs/yjs', content: cid }
 *   - Remote messages: socket.io 'Streams/message' event with type 'Safecloud/docs/yjs'
 *       1. Fetch by ordinal (or use the content field directly if already in event)
 *       2. decryptUpdate(cid) → update
 *       3. Y.applyUpdate(ydoc, update, this)  (origin = provider = no echo)
 *   - Awareness (cursors, presence, typing): 'Streams/ephemeral' socket events.
 *
 * This module is a plain ES5-compatible IIFE so it can be loaded without a bundler.
 * It expects Y (yjs) and io (socket.io-client) to be on the global scope,
 * OR they can be passed as options.yjs and options.io.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.SafecloudYjsProvider = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var MESSAGE_TYPE = 'Safecloud/docs/yjs';

    /**
     * @constructor
     * @param {Y.Doc}  ydoc
     * @param {Object} opts
     */
    function SafecloudYjsProvider(ydoc, opts) {
        this.ydoc         = ydoc;
        this.opts         = opts || {};
        this.jetUrl       = (opts.jetUrl || '').replace(/\/$/, '');
        this.publisherId  = opts.publisherId;
        this.streamName   = opts.streamName;
        this.userId       = opts.userId   || 'anonymous';
        this.debounceMs   = opts.debounceMs != null ? opts.debounceMs : 300;

        // Crypto hooks — MUST be supplied by the caller
        this._encryptUpdate = opts.encryptUpdate || null;
        this._decryptUpdate = opts.decryptUpdate || null;

        // Dependencies — accept injected instances or use globals
        this._Y  = opts.yjs || (typeof Y  !== 'undefined' ? Y  : null);
        this._io = opts.io  || (typeof io !== 'undefined' ? io : null);

        // Internal state
        this._socket          = null;
        this._pending         = [];   // array of Uint8Array pending flush
        this._flushTimer      = null;
        this._connected       = false;
        this._catchingUp      = false;
        this._highestOrdinal  = 0;
        this._destroyed       = false;
        this._idempotencySeq  = 0;

        // Awareness — simple in-memory map of userId → state
        this.awareness        = {
            clientID:   Math.floor(Math.random() * 0xFFFFFFFF),
            localState: null,
            states:     {}
        };

        // Bind handlers
        this._onDocUpdate   = this._onDocUpdate.bind(this);
        this._onSocketMsg   = this._onSocketMsg.bind(this);
        this._onEphemeral   = this._onEphemeral.bind(this);
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    SafecloudYjsProvider.prototype.connect = function () {
        if (this._destroyed) throw new Error('SafecloudYjsProvider: already destroyed');
        if (this._connected) return this;

        var self = this;

        // 1. Open socket.io connection
        var sockUrl  = this.jetUrl || window.location.origin;
        var sockOpts = { path: this.opts.socketPath || '/socket.io', transports: ['websocket', 'polling'] };

        if (!this._io) { throw new Error('SafecloudYjsProvider: socket.io-client not found. Pass io via opts.io or include socket.io-client globally.'); }
        this._socket = this._io(sockUrl, sockOpts);

        this._socket.on('connect', function () {
            self._connected = true;
            // Join the stream room
            self._socket.emit('Streams/subscribe', {
                publisherId: self.publisherId,
                streamName:  self.streamName
            });
            // Catch up from ordinal 0
            self._catchUp();
        });

        this._socket.on('disconnect', function () {
            self._connected = false;
        });

        this._socket.on('Streams/message', this._onSocketMsg);
        this._socket.on('Streams/ephemeral', this._onEphemeral);

        // 2. Listen for local Y.Doc changes
        if (this._Y) {
            this.ydoc.on('update', this._onDocUpdate);
        }

        return this;
    };

    SafecloudYjsProvider.prototype.disconnect = function () {
        this._connected = false;
        if (this._socket) {
            this._socket.emit('Streams/unsubscribe', { publisherId: this.publisherId, streamName: this.streamName });
            this._socket.off('Streams/message', this._onSocketMsg);
            this._socket.off('Streams/ephemeral', this._onEphemeral);
            this._socket.disconnect();
            this._socket = null;
        }
        if (this._Y) { this.ydoc.off('update', this._onDocUpdate); }
        clearTimeout(this._flushTimer);
    };

    SafecloudYjsProvider.prototype.destroy = function () {
        this.disconnect();
        this._destroyed = true;
    };

    /**
     * Set local awareness state (cursor, presence, typing indicator).
     * Sends via Streams/ephemeral — not persisted, high frequency OK.
     *
     * @param {Object} state  e.g. { cursor: {index, length}, user: { name, color } }
     */
    SafecloudYjsProvider.prototype.setAwarenessState = function (state) {
        this.awareness.localState = state;
        if (this._socket && this._connected) {
            this._socket.emit('Streams/ephemeral', {
                publisherId: this.publisherId,
                streamName:  this.streamName,
                byUserId:    this.userId,
                clientID:    this.awareness.clientID,
                state:       state
            });
        }
    };

    // ─── Internal: local doc changes ─────────────────────────────────────────

    SafecloudYjsProvider.prototype._onDocUpdate = function (update, origin) {
        if (origin === this) return; // our own apply — do not echo
        if (this._destroyed) return;
        this._pending.push(update);
        this._scheduleFlush();
    };

    SafecloudYjsProvider.prototype._scheduleFlush = function () {
        if (this._flushTimer) return;
        var self = this;
        this._flushTimer = setTimeout(function () {
            self._flushTimer = null;
            self._flush();
        }, this.debounceMs);
    };

    SafecloudYjsProvider.prototype._flush = function () {
        if (!this._pending.length || !this._connected) return;
        var pending  = this._pending.slice();
        this._pending = [];

        var self   = this;
        var merged = pending.length === 1 ? pending[0]
            : (this._Y ? this._Y.mergeUpdates(pending) : _mergeRaw(pending));

        var ikey = 'yjsp-' + this.publisherId + '-' + this.streamName + '-' + (++this._idempotencySeq);

        if (this._encryptUpdate) {
            Promise.resolve(this._encryptUpdate(merged)).then(function (cid) {
                return self._postMessage(cid, ikey);
            }).catch(function (e) {
                console.error('[SafecloudYjsProvider] flush error:', e);
                // Re-queue on failure
                self._pending = pending.concat(self._pending);
            });
        } else {
            // No encryption — post raw base64 (dev/test mode)
            var b64 = _uint8ToBase64(merged);
            this._postMessage('data:application/octet-stream;base64,' + b64, ikey)
                .catch(function (e) { console.error('[SafecloudYjsProvider] flush error:', e); });
        }
    };

    SafecloudYjsProvider.prototype._postMessage = function (content, idempotencyKey) {
        var url  = this.jetUrl + '/Streams/message';
        var body = JSON.stringify({
            publisherId:    this.publisherId,
            streamName:     this.streamName,
            byUserId:       this.userId,
            type:           MESSAGE_TYPE,
            content:        content,
            idempotencyKey: idempotencyKey
        });
        return _fetchPost(url, body);
    };

    // ─── Internal: remote messages ────────────────────────────────────────────

    SafecloudYjsProvider.prototype._onSocketMsg = function (data) {
        if (!data || data.publisherId !== this.publisherId || data.streamName !== this.streamName) return;
        if (data.type !== MESSAGE_TYPE) return;
        if (this._catchingUp) return; // catch-up will apply it in order
        if (data.ordinal <= this._highestOrdinal) return; // already applied
        this._highestOrdinal = data.ordinal;
        this._applyRemote(data.content);
    };

    SafecloudYjsProvider.prototype._applyRemote = function (cid) {
        var self = this;
        var applyUpdate = function (update) {
            if (self._Y) {
                self._Y.applyUpdate(self.ydoc, update, self);
            }
        };
        if (cid && cid.startsWith('data:')) {
            // Dev mode — base64 raw update
            var b64 = cid.split(',')[1] || '';
            try { applyUpdate(_base64ToUint8(b64)); } catch (e) { console.error('[SafecloudYjsProvider] applyUpdate error:', e); }
        } else if (this._decryptUpdate) {
            Promise.resolve(this._decryptUpdate(cid)).then(applyUpdate)
                .catch(function (e) { console.error('[SafecloudYjsProvider] decrypt error:', e); });
        }
    };

    // ─── Internal: catch-up on connect ───────────────────────────────────────

    SafecloudYjsProvider.prototype._catchUp = function () {
        var self = this;
        this._catchingUp = true;
        var url = this.jetUrl + '/Streams/messages'
            + '?publisherId=' + encodeURIComponent(this.publisherId)
            + '&streamName='  + encodeURIComponent(this.streamName)
            + '&after=0&limit=1000&ascending=1';

        _fetchGet(url).then(function (json) {
            var messages = (json.slots && json.slots.messages) ? json.slots.messages : {};
            var ordinals = Object.keys(messages).map(Number).sort(function (a, b) { return a - b; });
            var chain    = Promise.resolve();

            ordinals.forEach(function (ord) {
                var msg = messages[ord];
                if (!msg || msg.type !== MESSAGE_TYPE) return;
                if (ord <= self._highestOrdinal) return;
                chain = chain.then(function () {
                    self._highestOrdinal = ord;
                    return self._applyRemote(msg.content);
                });
            });

            return chain;
        }).catch(function (e) {
            console.error('[SafecloudYjsProvider] catch-up error:', e);
        }).then(function () {
            self._catchingUp = false;
        });
    };

    // ─── Internal: awareness ─────────────────────────────────────────────────

    SafecloudYjsProvider.prototype._onEphemeral = function (data) {
        if (!data || data.publisherId !== this.publisherId || data.streamName !== this.streamName) return;
        if (data.clientID === this.awareness.clientID) return; // own echo
        this.awareness.states[data.clientID] = {
            userId: data.byUserId,
            state:  data.state
        };
        if (typeof this.onAwarenessChange === 'function') {
            this.onAwarenessChange(data.clientID, data.state);
        }
    };

    // ─── Utility helpers ─────────────────────────────────────────────────────

    function _fetchPost(url, body) {
        if (typeof fetch !== 'undefined') {
            return fetch(url, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    body
            }).then(function (r) { return r.json(); });
        }
        // Node.js fallback (for tests)
        return new Promise(function (resolve, reject) {
            var mod  = url.startsWith('https:') ? require('https') : require('http');
            var opts = require('url').parse(url);
            opts.method  = 'POST';
            opts.headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
            var req = mod.request(opts, function (res) {
                var buf = '';
                res.on('data', function (c) { buf += c; });
                res.on('end', function () { try { resolve(JSON.parse(buf)); } catch (e) { resolve({}); } });
            });
            req.on('error', reject);
            req.write(body);
            req.end();
        });
    }

    function _fetchGet(url) {
        if (typeof fetch !== 'undefined') {
            return fetch(url).then(function (r) { return r.json(); });
        }
        return new Promise(function (resolve, reject) {
            var mod = url.startsWith('https:') ? require('https') : require('http');
            var req = mod.get(url, function (res) {
                var buf = '';
                res.on('data', function (c) { buf += c; });
                res.on('end', function () { try { resolve(JSON.parse(buf)); } catch (e) { resolve({}); } });
            });
            req.on('error', reject);
        });
    }

    /** Minimal merge of raw Uint8Array Yjs updates (concatenate — Yjs tolerates duplicates). */
    function _mergeRaw(updates) {
        var len = updates.reduce(function (s, u) { return s + u.length; }, 0);
        var out = new Uint8Array(len);
        var off = 0;
        updates.forEach(function (u) { out.set(u, off); off += u.length; });
        return out;
    }

    function _uint8ToBase64(arr) {
        var bin = '';
        for (var i = 0; i < arr.length; i++) { bin += String.fromCharCode(arr[i]); }
        return btoa(bin);
    }

    function _base64ToUint8(b64) {
        var bin = atob(b64);
        var arr = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) { arr[i] = bin.charCodeAt(i); }
        return arr;
    }

    return SafecloudYjsProvider;
}));
