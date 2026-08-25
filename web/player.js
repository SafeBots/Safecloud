/**
 * Safecloud Embed Player — self-contained, no framework dependencies.
 *
 * Plays encrypted Safecloud content via a service worker that synthesizes
 * HLS playlists from decrypted chunks. Native <video> element, no videojs.
 *
 * URL parameters (query — safe to share):
 *   rootCid=<cid>         content identifier
 *   jet=<wss://url>       Jet server URL
 *   autoplay=1            attempt autoplay (muted for browser policy)
 *   controls=1            show native controls (default: 1)
 *   parentOrigin=<origin> restrict postMessage to this origin
 *
 * URL fragment (consumed once, never sent to server):
 *   Classic:       #rootKey=<base64>&m=<base64url manifest JSON>
 *   Split-entropy: #st=<tokenHex>&sm=<maskB64>&m=<base64url manifest JSON>
 *                  (viewer must provide passphrase from Channel 2)
 *
 * postMessage API (parent → iframe):
 *   { action: 'play' }
 *   { action: 'pause' }
 *   { action: 'seek', time: <seconds> }
 *   { action: 'mute', muted: <boolean> }
 *   { action: 'volume', level: <0-1> }
 *
 * postMessage events (iframe → parent):
 *   { event: 'ready', duration: <seconds> }
 *   { event: 'play' }
 *   { event: 'pause' }
 *   { event: 'timeupdate', time: <seconds>, duration: <seconds> }
 *   { event: 'ended' }
 *   { event: 'error', message: <string> }
 *   { event: 'passphrase-required' }
 */
(function () {
    'use strict';

    // ── Parse URL ────────────────────────────────────────────────────────────

    var params = new URLSearchParams(window.location.search);
    var rootCid      = params.get('rootCid') || params.get('rootcid');
    var jetUrl       = params.get('jet');
    var autoplay     = params.get('autoplay') === '1';
    var controls     = params.get('controls') !== '0';
    var parentOrigin = params.get('parentOrigin') || '*';

    // Parse fragment (consumed once)
    var frag = {};
    if (window.location.hash.length > 1) {
        window.location.hash.slice(1).split('&').forEach(function (part) {
            var i = part.indexOf('=');
            if (i > 0) { frag[part.slice(0, i)] = decodeURIComponent(part.slice(i + 1)); }
        });
        // Strip fragment — keys must not linger in the URL
        history.replaceState(null, '', window.location.pathname + window.location.search);
    }

    var rootKey       = frag.rootKey || null;
    var splitToken    = frag.st || null;
    var splitMask     = frag.sm || null;
    var manifestB64   = frag.m || null;
    var manifest      = manifestB64 ? b64urlToJSON(manifestB64) : null;

    // DOM
    var video   = document.getElementById('video');
    var status  = document.getElementById('status');
    var overlay = document.getElementById('pass-overlay');
    var passIn  = document.getElementById('pass-input');
    var passBtn = document.getElementById('pass-btn');
    var passErr = document.getElementById('pass-error');

    video.controls = controls;

    // ── Emit to parent ───────────────────────────────────────────────────────

    function emit(data) {
        if (window.parent !== window) {
            try { window.parent.postMessage(data, parentOrigin); } catch (e) {}
        }
    }

    // ── Status display ───────────────────────────────────────────────────────

    function setStatus(msg, isError) {
        status.textContent = msg || '';
        status.className = msg ? (isError ? 'error' : '') : 'hidden';
    }

    // ── Base64 / JSON helpers ────────────────────────────────────────────────

    function b64urlToJSON(s) {
        try {
            s = s.replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4) s += '=';
            return JSON.parse(decodeURIComponent(escape(atob(s))));
        } catch (e) { return null; }
    }

    function fromBase64(b64) {
        var bin = atob(b64);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    function toBase64(bytes) {
        var bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    }

    // ── HKDF (matches sw.js exactly) ─────────────────────────────────────────

    function hkdf(ikm, label, length) {
        var saltP = crypto.subtle.digest('SHA-256', new Uint8Array(0));
        var keyP  = crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        var info  = new TextEncoder().encode(label);
        return Promise.all([saltP, keyP]).then(function (r) {
            return crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: r[0], info: info },
                r[1], length * 8
            );
        }).then(function (bits) { return new Uint8Array(bits); });
    }

    // ── Split-entropy key recovery ───────────────────────────────────────────

    function recoverSplitKey(rootCid, tokenHex, maskB64, passphrase) {
        var token = new Uint8Array(tokenHex.match(/.{2}/g).map(function (h) {
            return parseInt(h, 16);
        }));
        var mask = fromBase64(maskB64);
        var passBytes = new TextEncoder().encode(passphrase);
        var ikm = new Uint8Array(token.length + passBytes.length);
        ikm.set(token, 0);
        ikm.set(passBytes, token.length);

        return hkdf(ikm, 'safecloud.splitkey.v1', 32).then(function (derived) {
            // Workaround: hkdf returns ArrayBuffer-backed Uint8Array
            var derivedBytes = new Uint8Array(derived);
            var rootKeyBytes = new Uint8Array(32);
            for (var j = 0; j < 32; j++) {
                rootKeyBytes[j] = derivedBytes[j] ^ mask[j];
            }
            return toBase64(rootKeyBytes);
        });
    }

    // ── Capability persistence (IndexedDB, shared with sw.js) ────────────────

    var DB_NAME = 'Safecloud.Client';
    var DB_VERSION = 4;

    function openDB() {
        return new Promise(function (resolve, reject) {
            var req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = function (e) {
                var db = e.target.result;
                ['capabilities', 'session', 'swSessions', 'authorTokens'].forEach(function (s) {
                    if (!db.objectStoreNames.contains(s)) db.createObjectStore(s);
                });
            };
            req.onsuccess = function () { resolve(req.result); };
            req.onerror = function () { reject(req.error); };
        });
    }

    function saveCapability(rootCid, manifest, capability) {
        return openDB().then(function (db) {
            return new Promise(function (resolve, reject) {
                var tx = db.transaction('capabilities', 'readwrite');
                tx.objectStore('capabilities').put(
                    { manifest: manifest, capability: capability, savedAt: Date.now() },
                    rootCid
                );
                tx.oncomplete = resolve;
                tx.onerror = function () { reject(tx.error); };
            });
        });
    }

    function loadCapability(rootCid) {
        return openDB().then(function (db) {
            return new Promise(function (resolve, reject) {
                var tx = db.transaction('capabilities', 'readonly');
                var req = tx.objectStore('capabilities').get(rootCid);
                req.onsuccess = function () { resolve(req.result || null); };
                req.onerror = function () { reject(req.error); };
            });
        });
    }

    // ── Service worker registration ──────────────────────────────────────────

    function registerSW() {
        if (!('serviceWorker' in navigator)) {
            return Promise.reject(new Error('Service workers not supported'));
        }
        // sw.js lives alongside this file
        var swUrl = new URL('js/Safecloud/sw.js', window.location.href).href;
        return navigator.serviceWorker.register(swUrl, { scope: './' })
            .then(function (reg) {
                // Wait for the SW to be ready
                if (navigator.serviceWorker.controller) return;
                return new Promise(function (resolve) {
                    navigator.serviceWorker.addEventListener('controllerchange', resolve, { once: true });
                });
            });
    }

    // ── Start playback ───────────────────────────────────────────────────────

    function startPlayback(manifest, capability) {
        setStatus('Loading…');

        registerSW().then(function () {
            var videoId = manifest.rootCid || 'default';

            // Register the session with the SW
            navigator.serviceWorker.controller.postMessage({
                type:       'Q.Safecloud.Client.register',
                videoId:    videoId,
                manifest:   manifest,
                capability: capability,
                versions:   manifest.versions || null,
                version:    ''
            });

            // Save capability for refresh resilience
            if (manifest.rootCid) {
                saveCapability(manifest.rootCid, manifest, capability).catch(function () {});
            }

            // Build HLS URL pointing at the SW scope
            var hlsUrl = new URL(
                'safecloud/' + videoId + '/master.m3u8',
                navigator.serviceWorker.controller.scriptURL
            ).href;

            // Warm the first segments through the SW before the <video>
            // element requests them. Closes the iOS 15/16 first-segment
            // race (native HLS occasionally bypasses a cold SW) and makes
            // startup faster everywhere — by the time the media pipeline
            // asks, segments 0-2 are already decrypted in the SW cache.
            var base = hlsUrl.replace(/master\.m3u8$/, '');
            var warm = [0, 1, 2].map(function (i) {
                return fetch(base + 'segment-' + i + '.ts')
                    .then(function (r) { return r.ok; })
                    .catch(function () { return false; });
            });

            Promise.all(warm).then(function () {
                video.src = hlsUrl;
            });

            if (autoplay) {
                video.muted = true; // browsers require muted for autoplay
                video.play().catch(function () {});
            }

            // Wire video events → postMessage
            video.addEventListener('loadedmetadata', function () {
                setStatus('', false);
                emit({ event: 'ready', duration: video.duration || 0 });
            });

            video.addEventListener('play', function () { emit({ event: 'play' }); });
            video.addEventListener('pause', function () { emit({ event: 'pause' }); });
            video.addEventListener('ended', function () { emit({ event: 'ended' }); });

            var _lastTime = -1;
            video.addEventListener('timeupdate', function () {
                var t = Math.floor(video.currentTime * 10) / 10; // 100ms resolution
                if (t !== _lastTime) {
                    _lastTime = t;
                    emit({ event: 'timeupdate', time: video.currentTime, duration: video.duration || 0 });
                }
            });

            video.addEventListener('error', function () {
                var msg = video.error ? video.error.message : 'Playback error';
                setStatus(msg, true);
                emit({ event: 'error', message: msg });
            });

        }).catch(function (err) {
            setStatus(err.message, true);
            emit({ event: 'error', message: err.message });
        });
    }

    // ── Receive commands from parent ─────────────────────────────────────────

    window.addEventListener('message', function (e) {
        if (parentOrigin !== '*' && e.origin !== parentOrigin) return;
        var msg = e.data;
        if (!msg || !msg.action) return;

        switch (msg.action) {
            case 'play':   video.play().catch(function () {}); break;
            case 'pause':  video.pause(); break;
            case 'seek':   if (typeof msg.time === 'number') video.currentTime = msg.time; break;
            case 'mute':   video.muted = !!msg.muted; break;
            case 'volume': if (typeof msg.level === 'number') video.volume = Math.max(0, Math.min(1, msg.level)); break;
        }
    });

    // ── Jet-gated fragment fetch ─────────────────────────────────────────────
    // The Jet holds one entropy fragment (NOT a decryption key). The player
    // fetches it, combines with the URL's token client-side via HKDF.
    // The Jet never learns the rootKey — it only releases its own fragment,
    // optionally gated by rate limiting, payment verification, or attestation.

    function fetchJetFragment(rootCid, jetUrl) {
        return new Promise(function (resolve, reject) {
            // Simple HTTP fetch — the Jet exposes a /fragment endpoint
            // that returns { fragment: <hex> } gated by rootCid
            var url = jetUrl.replace(/^wss?:/, 'https:').replace(/\/$/, '')
                + '/safecloud/fragment?rootCid=' + encodeURIComponent(rootCid);
            fetch(url).then(function (r) {
                if (!r.ok) throw new Error('Fragment request rejected');
                return r.json();
            }).then(function (data) {
                if (!data || !data.fragment) throw new Error('No fragment');
                resolve(data.fragment);
            }).catch(reject);
        });
    }

    function recoverFromServerFragment(rootCid, tokenHex, maskB64, fragmentHex) {
        // Server fragment replaces the passphrase as the second HKDF input
        var token = new Uint8Array(tokenHex.match(/.{2}/g).map(function (h) {
            return parseInt(h, 16);
        }));
        var mask = fromBase64(maskB64);
        var frag = new Uint8Array(fragmentHex.match(/.{2}/g).map(function (h) {
            return parseInt(h, 16);
        }));
        var ikm = new Uint8Array(token.length + frag.length);
        ikm.set(token, 0);
        ikm.set(frag, token.length);

        return hkdf(ikm, 'safecloud.splitkey.v1', 32).then(function (derived) {
            var derivedBytes = new Uint8Array(derived);
            var rootKeyBytes = new Uint8Array(32);
            for (var j = 0; j < 32; j++) {
                rootKeyBytes[j] = derivedBytes[j] ^ mask[j];
            }
            return toBase64(rootKeyBytes);
        });
    }

    // ── Passphrase modal ─────────────────────────────────────────────────────

    function showPassphraseModal() {
        overlay.classList.remove('hidden');
        emit({ event: 'passphrase-required' });

        function tryUnlock() {
            var pass = passIn.value.trim();
            if (!pass) { passErr.textContent = 'Enter the passphrase.'; return; }
            passErr.textContent = '';
            passBtn.disabled = true;
            passBtn.textContent = 'Unlocking\u2026';

            recoverSplitKey(
                rootCid || manifest.rootCid, splitToken, splitMask, pass
            ).then(function (rk) {
                rootKey = rk;
                overlay.classList.add('hidden');
                startPlayback(manifest, { rootKey: rootKey });
            }).catch(function () {
                passErr.textContent = 'Incorrect passphrase.';
                passBtn.disabled = false;
                passBtn.textContent = 'Unlock';
                passIn.select();
            });
        }

        passBtn.onclick = tryUnlock;
        passIn.onkeydown = function (e) { if (e.key === 'Enter') tryUnlock(); };
        passIn.focus();
    }

        // ── Bootstrap ────────────────────────────────────────────────────────────

    function boot() {
        if (!manifest) {
            // No manifest in fragment — try loading from IndexedDB
            if (rootCid) {
                loadCapability(rootCid).then(function (saved) {
                    if (saved && saved.manifest && saved.capability) {
                        manifest = saved.manifest;
                        startPlayback(manifest, saved.capability);
                    } else {
                        setStatus('No key for this content on this device.', true);
                    }
                }).catch(function () {
                    setStatus('Could not load saved capability.', true);
                });
            } else {
                setStatus('No content specified.', true);
            }
            return;
        }

        // Split-entropy mode: need a second entropy source.
        // Path A: Jet-gated (sf=1 flag) — fetch server fragment automatically.
        // Path B: Manual passphrase — viewer enters words from side channel.
        // Both derive the same rootKey. IndexedDB caches it for repeat visits.
        if (splitToken && splitMask && !rootKey) {
            if (jetUrl && params.get('sf') === '1') {
                setStatus('Fetching key fragment…');
                fetchJetFragment(rootCid || manifest.rootCid, jetUrl)
                    .then(function (serverFragment) {
                        return recoverFromServerFragment(
                            rootCid || manifest.rootCid,
                            splitToken, splitMask, serverFragment
                        );
                    })
                    .then(function (rk) {
                        rootKey = rk;
                        startPlayback(manifest, { rootKey: rootKey });
                    })
                    .catch(function () {
                        // Jet unavailable — fall back to passphrase
                        showPassphraseModal();
                    });
            } else {
                showPassphraseModal();
            }
            return;
        }

        // Classic mode: rootKey in fragment
        if (rootKey) {
            startPlayback(manifest, { rootKey: rootKey });
            return;
        }

        // Manifest but no key — try IndexedDB
        if (rootCid || manifest.rootCid) {
            loadCapability(rootCid || manifest.rootCid).then(function (saved) {
                if (saved && saved.capability) {
                    startPlayback(manifest, saved.capability);
                } else {
                    setStatus('Missing decryption key.', true);
                }
            });
        } else {
            setStatus('Missing decryption key.', true);
        }
    }

    boot();
})();
