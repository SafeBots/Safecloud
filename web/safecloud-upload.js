/**
 * safecloud-upload.js — Safecloud 3.3 browser upload library
 *
 * No framework dependencies. Works in any modern browser with SubtleCrypto.
 *
 * Usage:
 *   const up = new SafecloudUpload({ jetUrl: 'https://jet.example.com' });
 *   up.on('progress', ({ phase, pct }) => console.log(phase, pct + '%'));
 *   const { rootCid, embedUrl } = await up.upload(fileObj, {
 *     title:       'My video',
 *     description: 'A short description',
 *     tags:        ['music', 'demo'],
 *     price:       '0',      // wei per chunk view ('0' = free / public)
 *     encrypt:     false     // true = AES-256-GCM; key travels in URL fragment
 *   });
 *
 * Events:
 *   progress  { phase: 'chunking'|'encrypting'|'uploading'|'done', pct: 0-100 }
 *   error     { message }
 */

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.SafecloudUpload = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /* ── Constants ─────────────────────────────────────────────────────────── */

    var CHUNK_SIZE = 256 * 1024;  // 256 KB data chunks
    var BATCH_SIZE = 12;          // chunks per HTTP request (stays well under 8 MB body limit)

    /* ── Utilities ─────────────────────────────────────────────────────────── */

    function _toHex(buf) {
        return Array.from(new Uint8Array(buf))
            .map(function (b) { return b.toString(16).padStart(2, '0'); })
            .join('');
    }

    function _toB64(buf) {
        var bytes = new Uint8Array(buf);
        var bin = '';
        var len = bytes.length;
        for (var i = 0; i < len; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin);
    }

    /** Safecloud CID: 'bafy' + SHA-256-hex.slice(0, 52) — matches WasmRunner / Jet. */
    async function _cid(buf) {
        var hash = await crypto.subtle.digest('SHA-256', buf);
        return 'bafy' + _toHex(hash).slice(0, 52);
    }

    /** Minimal event emitter mixin. */
    function _emitter(obj) {
        var _ls = {};
        obj.on  = function (ev, fn) {
            (_ls[ev] = _ls[ev] || []).push(fn);
            return obj;
        };
        obj.off = function (ev, fn) {
            if (!fn) { _ls[ev] = []; return obj; }
            _ls[ev] = (_ls[ev] || []).filter(function (f) { return f !== fn; });
            return obj;
        };
        obj._emit = function (ev, data) {
            (_ls[ev] || []).forEach(function (f) {
                try { f(data); } catch (_) {}
            });
        };
        return obj;
    }

    /* ── SafecloudUpload constructor ───────────────────────────────────────── */

    /**
     * @param {Object} opts
     * @param {string} opts.jetUrl  Base URL of the Jet (e.g. https://jet.example.com)
     */
    function SafecloudUpload(opts) {
        opts = opts || {};
        this.jetUrl = (opts.jetUrl || window.location.origin).replace(/\/$/, '');
        _emitter(this);
    }

    /* ── Chunking ───────────────────────────────────────────────────────────── */

    /**
     * Split a File into 256 KB chunks, each with a content-addressed CID.
     * @param   {File}    file
     * @returns {Promise<Array<{cid:string, data:ArrayBuffer}>>}
     */
    SafecloudUpload.prototype.chunkFile = async function (file) {
        var chunks = [];
        var offset = 0;
        var total  = Math.ceil(file.size / CHUNK_SIZE) || 1;
        var self   = this;

        while (offset < file.size) {
            var slice = file.slice(offset, offset + CHUNK_SIZE);
            var buf   = await slice.arrayBuffer();
            var cid   = await _cid(buf);
            chunks.push({ cid: cid, data: buf });
            offset += CHUNK_SIZE;
            self._emit('progress', {
                phase: 'chunking',
                pct:   Math.round(chunks.length / total * 100)
            });
        }

        // Empty file → one empty chunk
        if (!chunks.length) {
            var empty = new ArrayBuffer(0);
            chunks.push({ cid: await _cid(empty), data: empty });
        }

        return chunks;
    };

    /* ── Encryption (optional) ─────────────────────────────────────────────── */

    /**
     * AES-256-GCM encrypt every chunk.
     * Each output chunk = 12-byte IV ‖ ciphertext. CIDs are recomputed.
     * Returns { chunks, keyHex } where keyHex is a 64-char hex string.
     */
    SafecloudUpload.prototype.encryptChunks = async function (chunks) {
        var key = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        var rawKey = await crypto.subtle.exportKey('raw', key);
        var keyHex = _toHex(rawKey);

        var encrypted = [];
        var total = chunks.length;
        var self = this;

        for (var i = 0; i < total; i++) {
            var iv  = crypto.getRandomValues(new Uint8Array(12));
            var enc = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv }, key, chunks[i].data
            );
            var combined = new Uint8Array(12 + enc.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(enc), 12);
            var cid = await _cid(combined.buffer);
            encrypted.push({ cid: cid, data: combined.buffer });
            self._emit('progress', {
                phase: 'encrypting',
                pct:   Math.round((i + 1) / total * 100)
            });
        }

        return { chunks: encrypted, keyHex: keyHex };
    };

    /* ── Manifest ──────────────────────────────────────────────────────────── */

    /**
     * Build and content-address the manifest JSON.
     * The manifest CID is the root CID for the upload.
     */
    SafecloudUpload.prototype.buildManifest = async function (chunks, meta) {
        var manifest = {
            v:           1,
            type:        'safecloud-content',
            title:       meta.title       || '',
            description: meta.description || '',
            tags:        meta.tags        || [],
            mimeType:    meta.mimeType    || 'application/octet-stream',
            size:        meta.size        || 0,
            chunkSize:   CHUNK_SIZE,
            chunks:      chunks.map(function (c) { return c.cid; }),
            encrypted:   meta.encrypted   || false,
            price:       meta.price       || '0',
            createdAt:   Math.floor(Date.now() / 1000)
        };
        var json  = JSON.stringify(manifest);
        var bytes = new TextEncoder().encode(json);
        var cid   = await _cid(bytes.buffer);
        return { cid: cid, manifest: manifest, data: bytes.buffer };
    };

    /* ── Upload ────────────────────────────────────────────────────────────── */

    /**
     * Full pipeline: chunk → [encrypt] → manifest → upload batches → return rootCid.
     *
     * @param  {File}   file
     * @param  {Object} meta
     * @param  {string} meta.title
     * @param  {string} meta.description
     * @param  {Array}  meta.tags
     * @param  {string} meta.price     wei per view ('0' = free)
     * @param  {boolean} meta.encrypt  true = AES-256-GCM; key in URL fragment
     * @returns {Promise<{rootCid, embedUrl, urlFragment}>}
     */
    SafecloudUpload.prototype.upload = async function (file, meta) {
        meta = meta || {};
        var self = this;

        /* 1. Chunk ──────────────────────────────────────────────────────────── */
        self._emit('progress', { phase: 'chunking', pct: 0 });
        var chunks = await self.chunkFile(file);

        /* 2. Encrypt (optional) ─────────────────────────────────────────────── */
        var keyHex = null;
        if (meta.encrypt) {
            self._emit('progress', { phase: 'encrypting', pct: 0 });
            var encResult = await self.encryptChunks(chunks);
            chunks = encResult.chunks;
            keyHex = encResult.keyHex;
        }

        /* 3. Manifest ───────────────────────────────────────────────────────── */
        var manifestResult = await self.buildManifest(chunks, {
            title:       meta.title,
            description: meta.description,
            tags:        meta.tags,
            mimeType:    file.type || 'application/octet-stream',
            size:        file.size,
            encrypted:   !!meta.encrypt,
            price:       meta.price || '0'
        });
        var rootCid = manifestResult.cid;

        /* 4. Split-entropy fragment for encrypted uploads ───────────────────── */
        // User half (first 32 hex chars = 128 bits) travels in URL fragment.
        // Server half (last 32 hex chars = 128 bits) is POSTed to Jet.
        // Together they reconstruct the 256-bit AES-GCM key.
        var serverFragment = null;
        var urlFragment    = '';
        if (keyHex) {
            var userHalf   = keyHex.slice(0, 32);
            serverFragment = keyHex.slice(32);
            urlFragment    = '#key=' + userHalf;
        }

        /* 5. Upload all chunks + manifest in batches ─────────────────────────── */
        // Manifest is just another content-addressed chunk; push it last.
        var allChunks = chunks.concat([manifestResult]);
        var total     = allChunks.length;
        var done      = 0;

        self._emit('progress', { phase: 'uploading', pct: 0 });

        for (var i = 0; i < allChunks.length; i += BATCH_SIZE) {
            var batch  = allChunks.slice(i, i + BATCH_SIZE);
            var isLast = (i + BATCH_SIZE >= allChunks.length);

            var body = {
                chunks: batch.map(function (c) {
                    return { cid: c.cid, data: _toB64(c.data) };
                })
            };

            // On the final batch, register the server fragment.
            if (isLast && serverFragment) {
                body.fragment = { rootCid: rootCid, value: serverFragment };
            }

            var resp = await fetch(self.jetUrl + '/Safecloud/author/upload', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(body)
            });

            if (!resp.ok) {
                var errBody = await resp.json().catch(function () { return {}; });
                var msg = 'Upload failed (' + resp.status + '): '
                    + (errBody.error || resp.statusText || 'unknown error');
                self._emit('error', { message: msg });
                throw new Error(msg);
            }

            done += batch.length;
            self._emit('progress', {
                phase: 'uploading',
                pct:   Math.round(done / total * 100)
            });
        }

        self._emit('progress', { phase: 'done', pct: 100 });

        /* 6. Build embed URL ────────────────────────────────────────────────── */
        var query = '?rootCid=' + encodeURIComponent(rootCid)
                  + '&jetUrl='  + encodeURIComponent(self.jetUrl);
        if (keyHex) {
            // sf=1 tells the player to fetch the server fragment
            query += '&sf=1';
        }
        var embedUrl = self.jetUrl + '/Safecloud/player/embed.html' + query + urlFragment;

        return {
            rootCid:     rootCid,
            embedUrl:    embedUrl,
            urlFragment: urlFragment
        };
    };

    /* ── Static helpers (exposed for testing / tooling) ──────────────────── */

    SafecloudUpload.cid         = _cid;
    SafecloudUpload.CHUNK_SIZE  = CHUNK_SIZE;

    return SafecloudUpload;
});
