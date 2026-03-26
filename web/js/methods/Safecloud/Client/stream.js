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
            // SW is active — proceed with HLS service worker path
            if (sw) {
                sw.postMessage({
                    type:       'Q.Safecloud.Client.register',
                    videoId:    videoId,
                    manifest:   activeManifest,
                    capability: capability,
                    versions:   hydratedVersions.length ? hydratedVersions : null
                });
            }

            var loop    = Q.Safecloud.Client._prefetchLoop(videoId, videoManifest, capability, options);
            var fakeUrl = 'https://safecloud-hls.local/' + videoId + '/master.m3u8';

            if (options.videoElement) {
                options.videoElement.src = fakeUrl;
            }

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
                stop:       loop.stop.bind(loop)
            };
        }); // _ensureServiceWorker
        }); // Promise.all indices
    }

    // ── Blob fallback path ────────────────────────────────────────────────────

    function _streamBlob(videoManifest, capability, options) {
        var videoEl = options.videoElement;

        return Q.Safecloud.Client.fetch(videoManifest, capability, options)
            .then(function (blob) {
                var url = URL.createObjectURL(blob);
                if (videoEl) { videoEl.src = url; }
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
                    }
                };
            });
    }
});
