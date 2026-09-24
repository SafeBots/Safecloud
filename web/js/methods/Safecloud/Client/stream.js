/**
 * Q.Safecloud.Client.stream — detect platform and dispatch to the right path.
 *
 * Three paths:
 *
 *   'sw'   — desktop Chrome/Firefox/Edge + Android Chrome
 *            Service worker intercepts safecloud-hls.local, decrypts per-request.
 *            Best: true streaming, CDN-cacheable encrypted bytes, minimal memory.
 *
 *   'mse'  — iOS Safari 16.4+, or any browser with MediaSource + fMP4 support
 *            _prefetchLoop decrypts eagerly, SourceBuffer receives plaintext.
 *            Requires manifest.initSegment + manifest.chunks[].pts
 *
 *   'blob' — fallback: iOS < 16.4, short clips, or when MSE is unavailable
 *            Full decrypt upfront via Client.fetch(), play as Blob URL.
 *            Not true streaming — entire file must be decrypted into memory.
 *
 * Returns a Promise<handle> where handle = { url, currentTime, seek, setVersion, pause, stop }
 */

Q.exports(function (Q, _) {
    // ── hls.js (lazy-loaded, non-Safari only) ────────────────────────────────
    // A native <video>.src = <m3u8 url> only plays via native HLS support,
    // which exists in Safari only — Chrome/Firefox/Edge have no built-in HLS
    // parser at all. player.js (the standalone embed player) already learned
    // this the hard way (DEMUXER_ERROR_COULD_NOT_PARSE) and carries the same
    // hls.js integration; this in-page "socket player" path (used right
    // after upload and by the share-link demo page, via the Safecloud/video
    // tool) set videoElement.src directly with no hls.js at all, so it never
    // actually played outside Safari. Mirrors player.js's ensureHls()/attach
    // logic exactly, matching hls.js's own documented priority order: prefer
    // hls.js (MediaSource-based) whenever supported, native src= only as a
    // last resort.
    var _hlsScriptPromise = null;
    function _ensureHls() {
        if (window.Hls) { return Promise.resolve(window.Hls); }
        if (_hlsScriptPromise) { return _hlsScriptPromise; }
        _hlsScriptPromise = new Promise(function (resolve, reject) {
            var s = document.createElement('script');
            s.src = Q.url('{{Safecloud}}/js/hls/hls.light.min.js');
            s.onload = function () {
                if (window.Hls) { resolve(window.Hls); }
                else { reject(new Error('hls.js failed to load')); }
            };
            s.onerror = function () { reject(new Error('hls.js failed to load')); };
            document.head.appendChild(s);
        });
        return _hlsScriptPromise;
    }

    // Fatal errors get a few recovery attempts (hls.js's own documented
    // pattern) before this instance gives up for good — bounded so a
    // truly-broken stream doesn't retry forever.
    var MAX_FATAL_RECOVERIES = 3;

    function _attachHls(video, hlsUrl, videoId) {
        var nativeHls = video.canPlayType('application/vnd.apple.mpegurl');
        // Was never declared anywhere — every read/increment below silently
        // operated on an implicit global that started at undefined, so
        // fatalRecoveries++ produced NaN and "NaN >= MAX_FATAL_RECOVERIES"
        // is always false. The "bounded so a truly-broken stream doesn't
        // retry forever" cap documented below had never actually been
        // enforced.
        var fatalRecoveries = 0;
        return _ensureHls().then(function (Hls) {
            if (!Hls.isSupported()) {
                if (nativeHls) { video.src = hlsUrl; return; }
                throw new Error('HLS playback not supported in this browser');
            }
            var hls = new Hls({
                // The service worker answers a not-yet-delivered segment
                // with a bare 503 (sw.js's serveSegment) rather than holding
                // the fetch open until _prefetchLoop posts it — so hls.js's
                // own retry/backoff is what bridges that gap. The defaults
                // are tuned for a normal CDN 404, not "the SW's in-memory
                // segment cache was just evicted after a long background
                // stall and needs a fresh round trip to the Jet" — widen
                // the budget so that redelivery has time to land instead of
                // hls.js exhausting retries first.
                fragLoadingMaxRetry:        8,
                fragLoadingMaxRetryTimeout: 20000
            });
            // Diagnostic-only, no behavior change: the last incident (a
            // fresh upload → immediately redirected to watch it → never
            // played) left readyState stuck at 0 for 10+ seconds with no
            // fatal error ever firing — meaning the existing fatal-error
            // handler below had nothing to react to. That's consistent with
            // at least two very different failures (the SW never actually
            // intercepting the fetch to the fake host at all, vs. it
            // responding but something downstream — MediaSource attach,
            // fragment append — silently stalling) and nothing here could
            // tell them apart. Logging hls.js's own lifecycle events (not
            // just fatal ones) is what will actually distinguish them next
            // time instead of guessing again.
            // videoId used to not be a parameter of this function at all —
            // it was a bare, out-of-scope reference here and in the
            // non-fatal branch below, so evaluating either console line
            // threw a ReferenceError. hls.js's own event dispatcher wraps
            // every listener invocation in try/catch specifically so one
            // broken external listener can't crash its internal loop — and
            // reports whatever it caught as its OWN fatal error, with
            // details:'internalException' (ErrorDetails.INTERNAL_EXCEPTION).
            // Non-fatal hls.js errors are frequent BY DESIGN (every "segment
            // not yet available" 503 from the SW starts as one), so this
            // ReferenceError was very likely firing constantly — turning
            // routine, self-resolving non-fatal errors into the fatal
            // 'internalException' errors chased across this entire
            // debugging session, with every earlier timing fix only
            // reducing how often a non-fatal error occurred in the first
            // place rather than addressing why one could escalate to fatal
            // at all.
            var milestones = [
                'mediaAttaching', 'mediaAttached', 'manifestLoading', 'manifestParsed',
                'levelLoading', 'levelLoaded', 'fragLoading', 'fragLoaded',
                'bufferAppending', 'bufferAppended', 'bufferEos'
            ];
            milestones.forEach(function (name) {
                var evt = Hls.Events[name.replace(/([A-Z])/g, '_$1').toUpperCase()];
                if (!evt) { return; }
                hls.on(evt, function () {
                    console.info('Q.Safecloud.Client.stream: hls.js ' + name + ' ' + JSON.stringify({
                        videoId: videoId, readyState: video.readyState, networkState: video.networkState
                    }));
                });
            });
            hls.on(Hls.Events.ERROR, function (event, data) {
                if (!data) { return; }
                if (!data.fatal) {
                    // Non-fatal errors (e.g. a 503 while the SW is still
                    // waiting for _prefetchLoop to post a segment) are
                    // normal and usually self-resolve — but a long run of
                    // them with nothing ever going fatal is itself a useful
                    // signal, so log them too instead of only the fatal case.
                    console.warn('Q.Safecloud.Client.stream: non-fatal HLS error: '
                        + (data.details || 'unknown') + ' ' + JSON.stringify({
                            videoId: videoId, type: data.type, url: data.url
                        }));
                    return;
                }
                Q.log('Q.Safecloud.Client.stream: fatal HLS error: '
                    + (data.details || 'unknown'), 'Safecloud');

                // Without this, ANY fatal error permanently killed playback
                // — hls.js does not retry past a fatal error on its own,
                // and this handler used to just log. Confirmed live:
                // returning to a tab after 10-20 minutes away hit a
                // fragLoadError with no recovery, so playback stayed dead
                // even after clicking play again, despite the underlying
                // connection being healthy (Q.Safecloud.Jets.connectionStats()
                // showed normal latency — the data was gettable, nothing
                // fetched it back).
                if (fatalRecoveries >= MAX_FATAL_RECOVERIES) {
                    Q.log('Q.Safecloud.Client.stream: giving up after '
                        + MAX_FATAL_RECOVERIES + ' fatal-error recovery attempts', 'Safecloud');
                    return;
                }
                fatalRecoveries++;
                if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
                    hls.startLoad();
                } else if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
                    hls.recoverMediaError();
                } else if (data.details === 'internalException') {
                    // hls.js's own textbook advice treats anything that
                    // isn't NETWORK_ERROR/MEDIA_ERROR as unrecoverable and
                    // destroys the player — reasonable for a normal CDN,
                    // but confirmed live to be the wrong call here: a
                    // fresh upload, watched immediately, hit exactly this
                    // ('internalException', type OTHER_ERROR) on the very
                    // first fragment attempt — hls.js autostarts loading
                    // segment 0 as soon as the manifest parses, before
                    // _prefetchLoop has delivered anything yet, and the
                    // SW's by-design 503 ("not yet available", see
                    // serveSegment) for that very first attempt seems to
                    // land hls.js in an internal state it doesn't expect.
                    // That's exactly the transient condition
                    // fragLoadingMaxRetry above exists to ride out — so
                    // retry instead of tearing the whole player down over
                    // it, same as the NETWORK_ERROR case.
                    hls.startLoad();
                } else {
                    hls.destroy();
                }
            });
            hls.loadSource(hlsUrl);
            hls.attachMedia(video);
        }).catch(function (err) {
            if (nativeHls) { video.src = hlsUrl; return; }
            Q.log('Q.Safecloud.Client.stream: ' + (err && err.message || err), 'Safecloud');
            throw err;
        });
    }

    return function Q_Safecloud_Client_stream(videoManifest, capability, options) {
        options = options || {};

        var path = options.path || _choosePath(videoManifest);

        if (path === 'mse') {
            return Q.Safecloud.Client.streamMSE(videoManifest, capability, options);
        }
        if (path === 'blob') {
            return _streamBlob(videoManifest, capability, options);
        }

        // ── SW path (default) ─────────────────────────────────────────────────
        return _streamSW(videoManifest, capability, options);
    };

    // ── Path selection ────────────────────────────────────────────────────────

    function _choosePath(videoManifest) {
        // SW HLS path requires an index track (provides initSegment for fMP4)
        // For plain file uploads without an index track, go straight to blob path
        var active = (videoManifest.versions && videoManifest.versions[0])
            ? videoManifest.versions[0].manifest
            : videoManifest;
        var hasIndexTrack = active && active.tracks
            && active.tracks.indexOf('index') >= 0;

        // Service workers work everywhere except iOS (AVFoundation bypasses SW)
        if ('serviceWorker' in navigator && !_isIOS() && hasIndexTrack) {
            return 'sw';
        }
        // MSE: needs MediaSource + fMP4 support + initSegment in manifest
        var activeManifest = (videoManifest.versions && videoManifest.versions[0])
            ? videoManifest.versions[0].manifest
            : videoManifest;
        // MSE path needs MediaSource support.
        // We check for MediaSource + index track (which carries initSegment).
        // If no index track, fall back to blob (can't stream without initSegment).
        var hasIdx = activeManifest.tracks && activeManifest.tracks.indexOf('index') >= 0;
        var probeMime = 'video/mp4; codecs="avc1.42e01e,mp4a.40.2"';
        if ('MediaSource' in window && hasIdx && MediaSource.isTypeSupported(probeMime)) {
            return 'mse';
        }
        return 'blob';
    }

    function _isIOS() {
        return /iP(hone|od|ad)/.test(navigator.userAgent)
            || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    }

    // ── SW path ───────────────────────────────────────────────────────────────

    function _streamSW(videoManifest, capability, options) {
        var rootCid = videoManifest.rootCid
            || (videoManifest.versions && videoManifest.versions[0]
                && videoManifest.versions[0].manifest.rootCid)
            || ('video-' + Date.now());
        var videoId = rootCid.slice(0, 20);

        var startVersion = options.version
            || (videoManifest.versions && videoManifest.versions[0]
                && videoManifest.versions[0].label)
            || null;
        var activeManifest = startVersion
            ? (videoManifest.versions || []).reduce(function (m, v) {
                return v.label === startVersion ? v.manifest : m;
              }, videoManifest)
            : videoManifest;

        // Fetch index track first if present — provides initSegment, codec, chapters
        var hasIndex = activeManifest.tracks && activeManifest.tracks.indexOf('index') >= 0;
        var indexPromise = hasIndex
            ? Q.Safecloud.Client.fetchIndex(activeManifest, capability, options)
            : Promise.resolve(null);

        // Also fetch indices for all versions so ABR quality switching works in SW
        var allVersions = videoManifest.versions || [];
        var versionIndexPromises = allVersions.map(function (v) {
            if (!v.manifest || !v.manifest.tracks ||
                v.manifest.tracks.indexOf('index') < 0) { return Promise.resolve(v); }
            var vCap = (capability.versions && capability.versions[v.label])
                ? { grants: capability.versions[v.label].grants }
                : capability;
            return Q.Safecloud.Client.fetchIndex(v.manifest, vCap, options)
                .then(function (idx) {
                    return idx
                        ? Q.extend({}, v, { manifest: Q.extend({}, v.manifest, { _index: idx }) })
                        : v;
                }).catch(function () { return v; });
        });

        return Promise.all([indexPromise, Promise.all(versionIndexPromises)])
        .then(function (results) {
        var index            = results[0];
        var hydratedVersions = results[1];
        if (index) { activeManifest = Q.extend({}, activeManifest, { _index: index }); }

        return Q.Safecloud.Client._ensureServiceWorker().then(function () {
            var sw = navigator.serviceWorker.controller;
            if (!sw) {
                // SW didn't take control — fall back to blob path
                Q.log('Q.Safecloud.Client.stream: SW not controlling page, falling back', 'Safecloud');
                return _streamBlob(videoManifest, capability, options);
            }
            // Without "version" set explicitly here, sw.js's register handler
            // defaults session.activeVersion to '' (msg.version || ''), while
            // _prefetchLoop (below) independently derives this exact same
            // startVersion via its own _getFirstVersion() and posts every
            // segment under THAT key — so whenever a manifest actually has a
            // non-empty first version label, segments were stored under e.g.
            // "original" but looked up under '' the instant a fragment URL
            // didn't embed a version (serveSegment's segVersion falls back to
            // session.activeVersion). Confirmed live: _prefetchLoop reported
            // deliveredCount:3 (real — it did post them) while the SW's own
            // serveSegment logged segmentNotAvailable for segIndex 0 at the
            // same time — two different storage keys, both truthfully empty/
            // full from their own side. This is what was actually killing
            // playback, not a slow Drop.
            function _registerMessage() {
                return {
                    type:       'Q.Safecloud.Client.register',
                    videoId:    videoId,
                    manifest:   activeManifest,
                    capability: capability,
                    versions:   hydratedVersions.length ? hydratedVersions : null,
                    version:    startVersion
                };
            }

            // SW is active — proceed with HLS service worker path
            if (sw) {
                sw.postMessage(_registerMessage());
            }

            var fakeUrl = 'https://safecloud-hls.local/' + videoId + '/master.m3u8';

            // options.setSrc === false lets the caller (e.g. the Q/video
            // safecloud adapter) attach the URL through its own player —
            // videojs VHS must handle the m3u8 on browsers without native HLS.
            var attachPromise = (options.videoElement && options.setSrc !== false)
                ? _attachHls(options.videoElement, fakeUrl, videoId)
                : Promise.resolve();

            // _prefetchLoop figures out which segment playback currently
            // needs from manifest._index.chapters[].pts (the real,
            // mediabunny-authoritative per-chunk timestamps) when available,
            // falling back to a naive currentTime/chunkDuration guess
            // otherwise. videoManifest here is the ORIGINAL, un-enriched
            // manifest — index/hydratedVersions (with ._index merged in)
            // were only ever merged into the local activeManifest variable
            // above, never propagated down — so _prefetchLoop always fell
            // back to the naive guess. Nothing in this schema ever sets
            // manifest.chunkDuration, so that guess defaulted to a flat 6s;
            // this content's real per-chunk duration is ~5.3s, and that ~12%
            // drift compounds over minutes of playback until the prefetch
            // window undershoots which segment is genuinely needed next —
            // confirmed live: fetchedMB and currentTime both flatlined
            // permanently around 100s into a 10-minute video, with the
            // "already delivered, nothing left to fetch" skip (see
            // _delivered above _fetchSeg) meaning the loop never even
            // attempted to look further ahead once drift exceeded
            // prefetchAhead's safety margin.
            var prefetchManifest = Q.extend({}, videoManifest, { _index: index || videoManifest._index });
            if (hydratedVersions.length) { prefetchManifest.versions = hydratedVersions; }

            // _prefetchLoop is a lazily-loaded Q.Method — on its first-ever
            // call in a page's lifetime it can return a bare Promise instead
            // of the real {stop,pause,resume,seek,setVersion} handle (see
            // the identical bug fixed in Drops/announce.js, Client/store.js
            // and Drops/get.js), so it must be awaited rather than used
            // synchronously here.
            return attachPromise.then(function () {
                return Promise.resolve(
                    Q.Safecloud.Client._prefetchLoop(videoId, prefetchManifest, capability, options)
                ).then(function (loop) {
                    // A service worker's in-memory session for this videoId
                    // can go missing for reasons the page can't reliably
                    // enumerate up front — a controllerchange (browser-
                    // initiated idle restart, or a new sw.js deployed while
                    // this tab stayed open) is one; a plain race where
                    // 'register' just never lands on whichever worker
                    // instance ends up fielding master.m3u8 is another
                    // (confirmed live: a 'segment' message for this exact
                    // videoId was handled successfully — that handler has no
                    // session guard at all — while 'register' never shows up
                    // anywhere in the log, and the very next master.m3u8
                    // fetch gets sessionFrom:"none"). Rather than keep
                    // chasing each individual cause, react directly to the
                    // symptom the SW already reports for every fetch it
                    // can't serve: its own sessionFrom:"none" diagnostic,
                    // relayed to this page by _ensureServiceWorker.js. A
                    // cooldown avoids re-registering on every single fetch
                    // in a burst of them.
                    var _lastRecovery = 0;
                    function _recoverSession() {
                        var sw = navigator.serviceWorker.controller;
                        if (!sw) { return; }
                        var now = Date.now();
                        if (now - _lastRecovery < 2000) { return; }
                        _lastRecovery = now;
                        sw.postMessage(_registerMessage());
                        loop.seek(options.videoElement ? options.videoElement.currentTime : 0);
                    }
                    function _onControllerChange() { _recoverSession(); }
                    function _onSWMessage(event) {
                        var msg = event.data;
                        if (!msg || msg.type !== 'Q.Safecloud.sw.diagnostic') { return; }
                        if (msg.event === 'fetch' && msg.sessionFrom === 'none'
                        && msg.videoId === videoId) {
                            _recoverSession();
                        }
                    }
                    navigator.serviceWorker.addEventListener('controllerchange', _onControllerChange);
                    navigator.serviceWorker.addEventListener('message', _onSWMessage);

                    return {
                        url:    fakeUrl,
                        path:   'sw',
                        index:  index,
                        currentTime: function () {
                            return options.videoElement ? options.videoElement.currentTime : 0;
                        },
                        seek:       loop.seek.bind(loop),
                        setVersion: loop.setVersion.bind(loop),
                        pause:      loop.pause.bind(loop),
                        resume:     loop.resume.bind(loop),
                        stop:       function () {
                            navigator.serviceWorker.removeEventListener('controllerchange', _onControllerChange);
                            navigator.serviceWorker.removeEventListener('message', _onSWMessage);
                            loop.stop();
                        },
                        stats:      loop.stats.bind(loop)
                    };
                });
            });
        }); // _ensureServiceWorker
        }); // Promise.all indices
    }

    // ── Blob fallback path ────────────────────────────────────────────────────

    function _streamBlob(videoManifest, capability, options) {
        var videoEl = options.videoElement;

        return Q.Safecloud.Client.fetch(videoManifest, capability, options)
            .then(function (blob) {
                var url = URL.createObjectURL(blob);
                if (videoEl && options.setSrc !== false) { videoEl.src = url; }
                if (options.at && videoEl) { videoEl.currentTime = options.at; }

                return {
                    url:  url,
                    path: 'blob',
                    currentTime: function () { return videoEl ? videoEl.currentTime : 0; },
                    seek: function (t) { if (videoEl) { videoEl.currentTime = t; } },
                    setVersion: function () { /* not supported in blob path */ },
                    pause: function () { if (videoEl) { videoEl.pause(); } },
                    resume: function () { if (videoEl) { videoEl.play(); } },
                    stop: function () {
                        if (videoEl) { videoEl.src = ''; }
                        URL.revokeObjectURL(url);
                    },
                    // No prefetch loop on this path — the whole file was
                    // already decrypted upfront, so there's nothing to stall.
                    stats: function () { return null; }
                };
            });
    }
});
