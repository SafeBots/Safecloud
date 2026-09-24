/**
 * Safecloud Embed Player — uses Q.js and Q.Safecloud.Client.stream().
 *
 * URL parameters (query — safe to share):
 *   rootCid=<cid>         content identifier
 *   jet=<wss://url>       Jet server URL (optional — defaults to Q.nodeUrl())
 *   autoplay=1            attempt autoplay (muted for browser policy)
 *   controls=1            show native controls (default: 1)
 *   parentOrigin=<origin> restrict postMessage to this origin
 *
 * URL fragment (consumed once, never sent to server):
 *   Classic:       #rootKey=<base64>&m=<base64url manifest JSON>
 *   Split-entropy: #st=<tokenHex>&sm=<maskB64>&m=<base64url manifest JSON>
 *
 * postMessage API (parent → iframe):
 *   { action: 'play' | 'pause' | 'seek' | 'mute' | 'volume' }
 *
 * postMessage events (iframe → parent):
 *   { event: 'ready' | 'play' | 'pause' | 'timeupdate' | 'ended' | 'error' | 'passphrase-required' }
 */
(function () {
    'use strict';

    // ── Parse URL ────────────────────────────────────────────────────────────

    var params = new URLSearchParams(window.location.search);
    var rootCid      = params.get('rootCid') || params.get('rootcid');
    var jetUrl       = params.get('jet') || null;
    var autoplay     = params.get('autoplay') === '1';
    var controls     = params.get('controls') !== '0';
    var parentOrigin = params.get('parentOrigin') || '*';

    // Parse fragment (consumed once, never sent to server)
    var frag = {};
    if (window.location.hash.length > 1) {
        window.location.hash.slice(1).split('&').forEach(function (part) {
            var i = part.indexOf('=');
            if (i > 0) { frag[part.slice(0, i)] = decodeURIComponent(part.slice(i + 1)); }
        });
        history.replaceState(null, '', window.location.pathname + window.location.search);
    }

    var rootKey     = frag.rootKey || null;
    var splitToken  = frag.st || null;
    var splitMask   = frag.sm || null;
    var manifestB64 = frag.m || null;
    var manifest    = manifestB64 ? _b64urlToJSON(manifestB64) : null;
    var capB64      = frag.cap || null;
    var teaserCap   = capB64 ? _b64urlToJSON(capB64) : null;

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

    function setStatus(msg, isError) {
        status.textContent = msg || '';
        status.className = msg ? (isError ? 'error' : '') : 'hidden';
    }

    function _b64urlToJSON(s) {
        try {
            s = s.replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4) s += '=';
            return JSON.parse(decodeURIComponent(escape(atob(s))));
        } catch (e) { return null; }
    }

    // ── Wait for Q.js to be ready ────────────────────────────────────────────

    function onQReady(callback) {
        if (typeof Q !== 'undefined' && Q.Safecloud && Q.Safecloud.Client) {
            return callback();
        }
        // Q.js fires Q.onReady or we poll
        var poll = setInterval(function () {
            if (typeof Q !== 'undefined' && Q.Safecloud && Q.Safecloud.Client) {
                clearInterval(poll);
                callback();
            }
        }, 100);
        // Give up after 10s
        setTimeout(function () { clearInterval(poll); }, 10000);
    }

    // ── Start playback using Q.Safecloud.Client.stream() ─────────────────────

    function startPlayback(manifest, capability) {
        setStatus('Loading…');

        // Override the Jet URL if provided via query param
        if (jetUrl) {
            Q.Safecloud.Jets.jetUrl = jetUrl;
        }

        // Connect to the Jet (uses Q.Socket.connect — correct path automatically)
        Q.Safecloud.Jets.connect(function (err) {
            if (err) {
                setStatus('Could not connect to Jet: ' + err.message, true);
                emit({ event: 'error', message: err.message });
                return;
            }

            // Stream: registers SW, fetches chunks via socket, plays
            Q.Safecloud.Client.stream(video, {
                manifest:   manifest,
                capability: capability,
                autoplay:   autoplay
            }).then(function (handle) {
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
                    var t = Math.floor(video.currentTime * 10) / 10;
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

                if (autoplay) {
                    video.muted = true;
                    video.play().catch(function () {});
                }
            }).catch(function (err) {
                setStatus(err.message, true);
                emit({ event: 'error', message: err.message });
            });
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

    // ── Split-entropy passphrase modal ───────────────────────────────────────

    function showPassphraseModal() {
        overlay.classList.remove('hidden');
        emit({ event: 'passphrase-required' });

        function tryUnlock() {
            var pass = passIn.value.trim();
            if (!pass) { passErr.textContent = 'Enter the passphrase.'; return; }
            passErr.textContent = '';
            passBtn.disabled = true;
            passBtn.textContent = 'Unlocking\u2026';

            // Use Q.Crypto for split-key recovery
            Q.Safecloud.Client.recoverSplitKey(
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
        onQReady(function () {
            if (!manifest) {
                if (rootCid) {
                    // Try loading from Q.Safecloud.Client's IndexedDB cache
                    Q.Safecloud.Client.loadCapability(rootCid).then(function (saved) {
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

            // Teaser: grant-based capability in fragment (no rootKey)
            if (teaserCap && manifest) {
                startPlayback(manifest, teaserCap);
                return;
            }

            // Split-entropy: need passphrase or server fragment
            if (splitToken && splitMask && !rootKey) {
                if (jetUrl && params.get('sf') === '1') {
                    setStatus('Fetching key fragment\u2026');
                    Q.Safecloud.Client.fetchJetFragment(rootCid || manifest.rootCid, jetUrl)
                        .then(function (fragment) {
                            return Q.Safecloud.Client.recoverFromFragment(
                                rootCid || manifest.rootCid, splitToken, splitMask, fragment
                            );
                        })
                        .then(function (rk) {
                            rootKey = rk;
                            startPlayback(manifest, { rootKey: rootKey });
                        })
                        .catch(function () { showPassphraseModal(); });
                } else {
                    showPassphraseModal();
                }
                return;
            }

            // Classic: rootKey in fragment
            if (rootKey) {
                startPlayback(manifest, { rootKey: rootKey });
                return;
            }

            // Manifest but no key — try cache
            if (rootCid || manifest.rootCid) {
                Q.Safecloud.Client.loadCapability(rootCid || manifest.rootCid).then(function (saved) {
                    if (saved && saved.capability) {
                        startPlayback(manifest, saved.capability);
                    } else {
                        setStatus('Missing decryption key.', true);
                    }
                });
            } else {
                setStatus('Missing decryption key.', true);
            }
        });
    }

    boot();
})();
