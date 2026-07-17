/**
 * Q.Safecloud.Client — HLS Service Worker
 *
 * Intercepts fetch requests to https://safecloud-hls.local/{videoId}/...
 * and serves synthetic HLS playlists and decrypted segments.
 *
 * KEY RESOLUTION MODEL (link path):
 *   Grants carry a link path, e.g. ["track","data","0","1"].
 *   To resolve the subtreeKey for a segment at absIndex:
 *     1. Find the grant whose link path is an ancestor-or-equal of
 *        chunkLinkPath(absIndex, manifest)
 *     2. Use grant.secret as the subtreeKey at that node
 *     3. navigate from grant node down to leaf (deriveLeafKeyFromGrant equivalent)
 *   For owner path (rootKey present):
 *     Chain HKDF down the leaf path from encryptionRoot.
 *
 * Session cache populated by _prefetchLoop via postMessage:
 *   { type: 'Q.Safecloud.Client.register', videoId, manifest, capability, versions }
 *   { type: 'Q.Safecloud.Client.segment',  videoId, version, segIndex, ciphertext, tag, iv }
 *   { type: 'Q.Safecloud.Client.seek',     videoId, segIndex }
 *   { type: 'Q.Safecloud.Client.setVersion', videoId, version, manifest }
 *   { type: 'Q.Safecloud.Client.stop',     videoId }
 *
 * Must be served with header: Service-Worker-Allowed: /
 */

/* global self, crypto */
'use strict';

var HLS_HOST = 'safecloud-hls.local';

// sessions[videoId] = { manifest, capability, versions, activeVersion }
var sessions = {};
// segments[videoId][version][segIndex] = { ciphertext, tag, iv }
var segments = {};

// ── IndexedDB session persistence ─────────────────────────────────────────────
// Browsers kill idle service workers; without persistence a restart mid-
// playback would 404 every request. Sessions therefore also live in the
// page-shared 'Safecloud.Client' database (store 'swSessions') and are
// lazily restored on the first request after a restart. This is also what
// lets an iframe player in a pristine environment resume from IndexedDB
// alone: keys never re-enter the URL or postMessage after first register.

var IDB_NAME  = 'Safecloud.Client';
var IDB_STORE = 'swSessions';
var _dbPromise = null;

function _db() {
    if (_dbPromise) { return _dbPromise; }
    _dbPromise = new Promise(function (resolve, reject) {
        var req = indexedDB.open(IDB_NAME, 1);
        req.onupgradeneeded = function () {
            var db = req.result;
            ['capabilities', 'session', 'swSessions', 'authorTokens']
            .forEach(function (name) {
                if (!db.objectStoreNames.contains(name)) {
                    db.createObjectStore(name);
                }
            });
        };
        req.onsuccess = function () { resolve(req.result); };
        req.onerror   = function () { _dbPromise = null; reject(req.error); };
    });
    return _dbPromise;
}

function _idbPutSession(videoId, session) {
    return _db().then(function (db) {
        return new Promise(function (resolve) {
            var tx = db.transaction(IDB_STORE, 'readwrite');
            tx.objectStore(IDB_STORE).put(session, videoId);
            tx.oncomplete = resolve;
            tx.onerror    = resolve;   // persistence is best-effort
        });
    }).catch(function () {});
}

function _idbGetSession(videoId) {
    return _db().then(function (db) {
        return new Promise(function (resolve) {
            var tx  = db.transaction(IDB_STORE, 'readonly');
            var req = tx.objectStore(IDB_STORE).get(videoId);
            req.onsuccess = function () { resolve(req.result || null); };
            req.onerror   = function () { resolve(null); };
        });
    }).catch(function () { return null; });
}

function _idbDeleteSession(videoId) {
    return _db().then(function (db) {
        var tx = db.transaction(IDB_STORE, 'readwrite');
        tx.objectStore(IDB_STORE).delete(videoId);
    }).catch(function () {});
}

// ── Message handler ───────────────────────────────────────────────────────────

self.addEventListener('message', function (event) {
    var msg = event.data;
    if (!msg || !msg.type) { return; }

    switch (msg.type) {

        case 'Q.Safecloud.Client.register':
            sessions[msg.videoId] = {
                manifest:      msg.manifest,
                capability:    msg.capability,
                versions:      msg.versions || null,
                activeVersion: msg.version  || ''
            };
            if (!segments[msg.videoId]) { segments[msg.videoId] = {}; }
            _idbPutSession(msg.videoId, sessions[msg.videoId]);
            break;

        case 'Q.Safecloud.Client.segment':
            if (!segments[msg.videoId]) { segments[msg.videoId] = {}; }
            if (!segments[msg.videoId][msg.version || '']) {
                segments[msg.videoId][msg.version || ''] = {};
            }
            segments[msg.videoId][msg.version || ''][msg.segIndex] = {
                ciphertext: msg.ciphertext,
                tag:        msg.tag,
                iv:         msg.iv
            };
            break;

        case 'Q.Safecloud.Client.seek':
            if (segments[msg.videoId]) {
                var sess = sessions[msg.videoId];
                var ver  = sess && (sess.activeVersion || '');
                if (segments[msg.videoId][ver]) {
                    var keep = {}, si = msg.segIndex;
                    for (var k in segments[msg.videoId][ver]) {
                        if (Math.abs(k - si) <= 2) { keep[k] = segments[msg.videoId][ver][k]; }
                    }
                    segments[msg.videoId][ver] = keep;
                }
            }
            break;

        case 'Q.Safecloud.Client.setVersion':
            if (sessions[msg.videoId]) {
                sessions[msg.videoId].activeVersion = msg.version || '';
                if (msg.manifest) { sessions[msg.videoId].manifest = msg.manifest; }
                _idbPutSession(msg.videoId, sessions[msg.videoId]);
            }
            break;

        case 'Q.Safecloud.Client.stop':
            delete sessions[msg.videoId];
            delete segments[msg.videoId];
            _idbDeleteSession(msg.videoId);
            break;
    }
});

// ── Fetch handler ─────────────────────────────────────────────────────────────

self.addEventListener('fetch', function (event) {
    var url = new URL(event.request.url);
    if (url.hostname !== HLS_HOST) { return; }
    event.respondWith(handleSafecloudRequest(event.request, url));
});

function handleSafecloudRequest(request, url) {
    var parts   = url.pathname.replace(/^\//, '').split('/');
    var videoId = parts[0];
    var rest    = parts.slice(1).join('/');

    var session = sessions[videoId];
    if (session) { return _routeSafecloud(request, videoId, rest, session); }

    // SW may have restarted since register — restore from IndexedDB
    return _idbGetSession(videoId).then(function (restored) {
        if (!restored) {
            return new Response('Safecloud session not found', { status: 404 });
        }
        sessions[videoId] = restored;
        if (!segments[videoId]) { segments[videoId] = {}; }
        return _routeSafecloud(request, videoId, rest, restored);
    });
}

function _routeSafecloud(request, videoId, rest, session) {

    if (rest === 'master.m3u8') { return serveMasterPlaylist(videoId, session); }

    // {version}/index.m3u8 or index.m3u8
    if (rest.match(/\/index\.m3u8$/) || rest === 'index.m3u8') {
        var version = rest.indexOf('/') >= 0 ? rest.split('/')[0] : (session.activeVersion || '');
        return serveSegmentPlaylist(videoId, version, session);
    }

    // {version}/init.mp4 or init.mp4 — fMP4 init segment from index track
    var initMatch = rest.match(/^(?:(.+)\/)?init\.mp4$/);
    if (initMatch) {
        var initVersion = initMatch[1] || session.activeVersion || '';
        return serveInitSegment(videoId, initVersion, session);
    }

    // {version}/seg{N}.m4s or seg{N}.m4s — media segment
    var segMatch = rest.match(/(?:(.+)\/)?seg(\d+)\.m4s$/);
    if (segMatch) {
        var segVersion = segMatch[1] || session.activeVersion || '';
        var segIndex   = parseInt(segMatch[2], 10);
        return serveSegment(request, videoId, segVersion, segIndex, session);
    }

    return new Response('Not found', { status: 404 });
}

// ── Playlists ─────────────────────────────────────────────────────────────────

function serveMasterPlaylist(videoId, session) {
    var lines = ['#EXTM3U', '#EXT-X-VERSION:7'];
    if (session.versions && session.versions.length) {
        session.versions.forEach(function (v) {
            var manifest = _getVersionManifest(session, v.label);
            var idx      = manifest && manifest._index;
            var codec    = (idx && idx.codec)      || (manifest && manifest.codec)      || 'avc1.42e01e';
            var audio    = (idx && idx.audioCodec) || (manifest && manifest.audioCodec) || null;
            var codecs   = audio ? codec + ',' + audio : codec;
            var bw       = v.bandwidth || (manifest && manifest.bandwidth) || 1000000;
            var res      = v.resolution || (manifest && manifest.resolution) || null;
            var inf = '#EXT-X-STREAM-INF:BANDWIDTH=' + bw + ',CODECS="' + codecs + '"';
            if (res) { inf += ',RESOLUTION=' + res; }
            lines.push(inf);
            lines.push(v.label + '/index.m3u8');
        });
    } else {
        var m   = session.manifest;
        var idx = m && m._index;
        var codec  = (idx && idx.codec)      || (m && m.codec)      || 'avc1.42e01e';
        var audio  = (idx && idx.audioCodec) || (m && m.audioCodec) || null;
        var codecs = audio ? codec + ',' + audio : codec;
        lines.push('#EXT-X-STREAM-INF:BANDWIDTH=1000000,CODECS="' + codecs + '"');
        lines.push('index.m3u8');
    }
    return new Response(lines.join('\n') + '\n', {
        headers: { 'Content-Type': 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-cache' }
    });
}

function serveSegmentPlaylist(videoId, version, session) {
    var manifest = _getVersionManifest(session, version);
    if (!manifest) { return new Response('Manifest not found', { status: 404 }); }

    var idx        = manifest._index;
    var chapters   = idx && idx.chapters;   // per-chunk [{pts, duration}] from index track
    var totalDur   = (idx && idx.totalDuration) || manifest.duration;
    var chunkCount = manifest.chunkCount || 0;
    var defDur     = manifest.chunkDuration || 6;
    var prefix     = version ? version + '/' : '';

    // Compute max segment duration for #EXT-X-TARGETDURATION (must be integer, >= all durations)
    var maxDur = defDur;
    if (chapters && chapters.length) {
        for (var j = 0; j < chapters.length; j++) {
            var d = chapters[j].duration || defDur;
            if (d > maxDur) { maxDur = d; }
        }
    }

    var lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:7',
        '#EXT-X-TARGETDURATION:' + Math.ceil(maxDur),
        '#EXT-X-MEDIA-SEQUENCE:0'
    ];

    // EXT-X-PLAYLIST-TYPE must appear before EXT-X-MAP (HLS spec §4.4.3.5)
    if (totalDur) {
        lines.push('#EXT-X-PLAYLIST-TYPE:VOD');
    }

    // init.mp4 is a separate request (no seg index), served from _index.initSegment
    lines.push('#EXT-X-MAP:URI="' + prefix + 'init.mp4"');

    for (var i = 0; i < chunkCount; i++) {
        var dur = chapters && chapters[i] && chapters[i].duration
            ? chapters[i].duration
            : defDur;
        lines.push('#EXTINF:' + dur.toFixed(6) + ',');
        lines.push(prefix + 'seg' + i + '.m4s');
    }
    lines.push('#EXT-X-ENDLIST');

    return new Response(lines.join('\n') + '\n', {
        headers: { 'Content-Type': 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-cache' }
    });
}

// ── Init segment server ───────────────────────────────────────────────────────

/**
 * Serve the fMP4 init segment (ftyp + moov boxes) from the decrypted index track.
 * This is the #EXT-X-MAP resource and must be served before any media segments.
 */
function serveInitSegment(videoId, version, session) {
    var manifest = _getVersionManifest(session, version);
    var idx = manifest && manifest._index;
    var initB64 = idx && idx.initSegment;

    if (!initB64) {
        return new Response('Init segment not available — index track not loaded', { status: 503 });
    }

    var initBytes = fromBase64(initB64);
    return new Response(initBytes, {
        status: 200,
        headers: {
            'Content-Type':   'video/mp4',
            'Content-Length': String(initBytes.byteLength),
            'Cache-Control':  'no-store'
        }
    });
}

// ── Segment server ─────────────────────────────────────────────────────────────

function serveSegment(request, videoId, version, segIndex, session) {
    var segData = segments[videoId] &&
                  segments[videoId][version] &&
                  segments[videoId][version][segIndex];

    if (!segData) {
        return new Response('Segment not yet available', {
            status: 503, headers: { 'Retry-After': '1' }
        });
    }

    return decryptSegment(segData, segIndex, session, version)
        .then(function (plaintext) {
            var rangeHeader = request.headers.get('Range');
            if (rangeHeader) { return serveRange(plaintext, rangeHeader); }
            return new Response(plaintext, {
                status: 200,
                headers: {
                    'Content-Type':   'video/mp4',
                    'Content-Length': String(plaintext.byteLength),
                    'Cache-Control':  'no-store'
                }
            });
        })
        .catch(function (err) {
            return new Response('Decryption failed: ' + err.message, { status: 500 });
        });
}

function serveRange(buffer, rangeHeader) {
    var total = buffer.byteLength;
    var match = rangeHeader.match(/bytes=(\d*)-(\d*)/);
    if (!match) { return new Response(buffer, { status: 200 }); }
    var start = match[1] !== '' ? parseInt(match[1], 10) : 0;
    var end   = match[2] !== '' ? parseInt(match[2], 10) : total - 1;
    end = Math.min(end, total - 1);
    return new Response(buffer.slice(start, end + 1), {
        status: 206,
        headers: {
            'Content-Type':   'video/mp4',
            'Content-Range':  'bytes ' + start + '-' + end + '/' + total,
            'Content-Length': String(end - start + 1),
            'Cache-Control':  'no-store'
        }
    });
}

// ── Decryption ────────────────────────────────────────────────────────────────

function decryptSegment(segData, absIndex, session, version) {
    var capability = session.capability;
    if (!capability) { return Promise.reject(new Error('No capability in session')); }

    var manifest = _getVersionManifest(session, version) || session.manifest;

    return resolveLeafKey(capability, absIndex, version, session, manifest)
        .then(function (keyInfo) {
            // keyInfo = { subtreeKey: Uint8Array, relIdx: Number }
            return deriveChunkKey(keyInfo.subtreeKey, keyInfo.relIdx)
                .then(function (chunkKeyBytes) {
                    return crypto.subtle.importKey(
                        'raw', chunkKeyBytes, { name: 'AES-GCM', length: 256 },
                        false, ['decrypt']
                    );
                })
                .then(function (cryptoKey) {
                    var iv         = fromBase64(segData.iv);
                    var ciphertext = fromBase64(segData.ciphertext);
                    var tag        = fromBase64(segData.tag);
                    var combined   = new Uint8Array(ciphertext.length + tag.length);
                    combined.set(ciphertext, 0);
                    combined.set(tag, ciphertext.length);
                    var aad = new TextEncoder().encode('safecloud.chunk:' + absIndex);
                    return crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: iv, additionalData: aad },
                        cryptoKey, combined
                    );
                });
        });
}

/**
 * Resolve the leaf subtreeKey and relIdx for a chunk at absIndex.
 *
 * Owner path: chain HKDF down from encryptionRoot through the chunk's link path.
 * Delegated path: find the grant whose link path covers absIndex, use its secret.
 */
function resolveLeafKey(capability, absIndex, version, session, manifest) {
    if (capability.rootKey) {
        var rootKey = fromBase64(capability.rootKey);
        return deriveEncryptionRoot(rootKey).then(function (encRoot) {
            // Navigate down the leaf path from encRoot
            var leafPath = chunkLinkPath(absIndex, manifest);
            // leafPath = ["track","data","0","1",...] — skip "track" prefix
            // Step 1: track label
            return hkdf(encRoot, 'q.crypto.delegate.safecloud.track.' + leafPath[1], 32)
                .then(function (trackKey) {
                    // Steps 2+: node labels for segments below track level
                    var nodeSegs = leafPath.slice(2);
                    return nodeSegs.reduce(function (prev, seg) {
                        return prev.then(function (currentKey) {
                            return hkdf(currentKey, 'q.crypto.delegate.safecloud.node.' + seg, 32);
                        });
                    }, Promise.resolve(trackKey));
                })
                .then(function (leafKey) {
                    // For leaf nodes, relIdx is always 0 (each leaf = one chunk)
                    return { subtreeKey: leafKey, relIdx: 0 };
                });
        });
    }

    // Delegated path
    var grants = [];
    if (capability.versions && version && capability.versions[version]) {
        grants = capability.versions[version].grants || [];
    } else {
        grants = capability.grants || [];
    }

    for (var i = 0; i < grants.length; i++) {
        var g = grants[i];
        if (!g || !g.secret || !g.link) { continue; }
        if (isAncestorOrEqual(g.link, chunkLinkPath(absIndex, manifest))) {
            // Navigate from grant node down to chunk leaf, then relIdx=0
            return navigateToLeaf(fromBase64(g.secret), g.link, absIndex, manifest)
                .then(function (leafKey) {
                    return { subtreeKey: leafKey, relIdx: 0 };
                });
        }
    }

    // Legacy fallback: old {start,end} grants (flat model, relIdx is absolute)
    for (var j = 0; j < grants.length; j++) {
        var lg = grants[j];
        if (!lg || !lg.secret) { continue; }
        try {
            var ctx = JSON.parse(lg.statement.context);
            if (typeof ctx.start === 'number' && absIndex >= ctx.start && absIndex < ctx.end) {
                // Legacy flat model: relIdx directly into subtreeKey
                return Promise.resolve({
                    subtreeKey: fromBase64(lg.secret),
                    relIdx:     absIndex - ctx.start
                });
            }
        } catch (e) {}
    }

    return Promise.reject(new Error('No grant covers segment ' + absIndex));
}

// ── Inline crypto helpers (SW has no access to Q.Data) ───────────────────────

/**
 * HKDF-SHA-256 matching Q.Data.derive exactly:
 *   salt = SHA-256("") (empty string context)
 *   info = UTF-8(label)
 *
 * Fixed promise chain — compute salt and import key in parallel,
 * then derive bits in a single chained step.
 */
function hkdf(ikm, label, length) {
    var saltPromise = crypto.subtle.digest('SHA-256', new Uint8Array(0));
    var keyPromise  = crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    var info        = new TextEncoder().encode(label);

    return Promise.all([saltPromise, keyPromise]).then(function (results) {
        var saltBuf = results[0];
        var baseKey = results[1];
        return crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: saltBuf, info: info },
            baseKey,
            length * 8
        );
    }).then(function (bits) { return new Uint8Array(bits); });
}

function deriveEncryptionRoot(rootKeyBytes) {
    return hkdf(rootKeyBytes, 'q.crypto.delegate.safecloud.encryption.root', 32);
}

function deriveChunkKey(subtreeKey, relIndex) {
    return hkdf(subtreeKey, 'safecloud.chunk.key.' + relIndex, 32);
}

// ── Tree navigation helpers ───────────────────────────────────────────────────

/**
 * Navigate from a grant node key down to a chunk's leaf node key.
 * Chains HKDF once per path segment between grantLink and leafPath.
 *
 * @param {Uint8Array} grantKeyBytes  Key at grantLink node
 * @param {Array}      grantLink      e.g. ["track","data"]
 * @param {Number}     absIndex       Absolute chunk index
 * @param {Object}     manifest
 * @return {Promise<Uint8Array>}      Leaf node key
 */
function navigateToLeaf(grantKeyBytes, grantLink, absIndex, manifest) {
    var leafPath  = chunkLinkPath(absIndex, manifest);
    var segsBelow = leafPath.slice(grantLink ? grantLink.length : 2);

    if (!segsBelow.length) {
        return Promise.resolve(grantKeyBytes); // already at leaf
    }

    return segsBelow.reduce(function (prev, seg) {
        return prev.then(function (currentKey) {
            return hkdf(currentKey, 'q.crypto.delegate.safecloud.node.' + seg, 32);
        });
    }, Promise.resolve(grantKeyBytes));
}



/**
 * Compute the full link path for a leaf chunk at absIndex.
 * Returns e.g. ["track","data","0","1","0"] for a binary tree depth 3.
 */
function chunkLinkPath(absIndex, manifest) {
    var treeN     = (manifest && manifest.treeN)     || 2;
    var treeDepth = (manifest && manifest.treeDepth) ||
                    Math.max(1, Math.ceil(Math.log((manifest && manifest.chunkCount) || 1) / Math.log(treeN)));
    var path      = ['track', 'data'];
    var n         = Math.pow(treeN, treeDepth);
    var idx       = absIndex;
    for (var d = 0; d < treeDepth; d++) {
        n = n / treeN;
        path.push(String(Math.floor(idx / n)));
        idx = idx % n;
    }
    return path;
}

/**
 * Compute the start leaf index for a grant's link path.
 * e.g. ["track","data","0","1"] in a binary tree depth 3 → start = 16
 */
function leafRangeStart(linkPath, manifest) {
    var treeN     = (manifest && manifest.treeN)     || 2;
    var treeDepth = (manifest && manifest.treeDepth) || 1;
    var total     = Math.pow(treeN, treeDepth);
    var nodeSegs  = linkPath.slice(2);
    var start     = 0;
    var width     = total;
    for (var i = 0; i < nodeSegs.length; i++) {
        width = width / treeN;
        start = start + parseInt(nodeSegs[i], 10) * width;
    }
    return Math.floor(start);
}

/**
 * Returns true if pathA is a prefix of (or equal to) pathB.
 * Used to check whether a grant's link covers a chunk's path.
 */
function isAncestorOrEqual(pathA, pathB) {
    if (pathA.length > pathB.length) { return false; }
    for (var i = 0; i < pathA.length; i++) {
        if (String(pathA[i]) !== String(pathB[i])) { return false; }
    }
    return true;
}

function fromBase64(b64) {
    var binary = atob(b64);
    var bytes  = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    return bytes;
}

function _getVersionManifest(session, version) {
    if (!version || version === 'default') { return session.manifest; }
    if (session.versions) {
        var v = session.versions.find(function (v) { return v.label === version; });
        return v ? v.manifest : session.manifest;
    }
    return session.manifest;
}

// ── Install / activate ────────────────────────────────────────────────────────

self.addEventListener('install',  function (e) { e.waitUntil(self.skipWaiting()); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
