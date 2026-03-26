/**
 * Q.Safecloud.Client.streamMSE — MSE-based streaming for iOS Safari 16.4+.
 *
 * Fetches the index track first to obtain video metadata, then streams
 * the data track into a MediaSource SourceBuffer.
 *
 * Requires the manifest to have tracks: ["data","index"], where the
 * index track (found via Merkle.getNode) contains:
 *   index.initSegment   String (base64) — fMP4 ftyp+moov init segment
 *   index.codec         String — e.g. "avc1.64001f"
 *   index.audioCodec    String — e.g. "mp4a.40.2" (optional)
 *   index.chapters[]    Array<{pts, dts}> — per-chunk timestamps
 *   index.keyframes[]   Array<Number> — keyframe chunk indices
 *   index.totalDuration Number — total duration in seconds
 *
 * Pipeline:
 *   fetchIndex(manifest) → initSegment, codec, chapters
 *   MediaSource → SourceBuffer(codec)
 *   → appendBuffer(initSegment)
 *   → _prefetchLoop(onChunk) decrypts each data chunk
 *   → queue → appendBuffer(plaintextChunk)
 *
 * QuotaExceededError: evict data >10s behind playhead, retry.
 *
 * Returns a handle: { url, path, index, currentTime, seek, setVersion, pause, resume, stop }
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_streamMSE(videoManifest, capability, options) {
        options = options || {};

        var videoEl      = options.videoElement;
        var startVersion = options.version
            || (videoManifest.versions && videoManifest.versions[0]
                && videoManifest.versions[0].label)
            || null;

        var _manifest = startVersion
            ? (videoManifest.versions || []).reduce(function (m, v) {
                return v.label === startVersion ? v.manifest : m;
              }, videoManifest)
            : videoManifest;

        // Fetch index track first — provides initSegment, codec, chapters
        // These live encrypted in manifest.indexCid, not in plaintext
        var hasIndexTrack = _manifest.tracks && _manifest.tracks.indexOf('index') >= 0;
        var _indexPromise = hasIndexTrack
            ? Q.Safecloud.Client.fetchIndex(_manifest, capability, options)
            : Promise.resolve(_manifest._index || null); // pre-fetched by stream()

        return _indexPromise.then(function (_index) {

        var initSegmentB64 = _index && _index.initSegment;
        var codec          = (_index && _index.codec)      || _manifest.codec      || 'avc1.42e01e';
        var audioCodec     = (_index && _index.audioCodec) || _manifest.audioCodec || null;

        if (!initSegmentB64) {
            return Promise.reject(new Error(
                'Q.Safecloud.Client.streamMSE: initSegment required in index track. ' +
                'Re-encode with an encoder that produces fMP4 output and stores ' +
                'the init segment in the index track via options.index.initSegment.'
            ));
        }

        // Merge index data into _manifest for _chunkAtTime and _nearestKeyframe
        if (_index) {
            _manifest = Q.extend({}, _manifest, {
                chunks:    _index.chapters || _manifest.chunks,
                keyframes: _index.keyframes || _manifest.keyframes,
                duration:  _index.totalDuration || _manifest.duration
            });
        }

        var mimeType = 'video/mp4; codecs="'
            + codec
            + (audioCodec ? ',' + audioCodec : '')
            + '"';

        if (!MediaSource.isTypeSupported(mimeType)) {
            return Promise.reject(new Error(
                'Q.Safecloud.Client.streamMSE: codec not supported: ' + mimeType
            ));
        }

        // ── State ─────────────────────────────────────────────────────────────

        var ms           = new MediaSource();
        var sb           = null;        // SourceBuffer, set in sourceopen
        var queue        = [];          // { index, buffer } waiting to append
        var appending    = false;
        var initDone     = false;
        var endOfStream  = false;
        var _loop        = null;
        var _blobUrl     = URL.createObjectURL(ms);
        var _seeking     = false;
        var _receivedSet = {};         // segIndex → true, tracks received chunks

        if (videoEl) { videoEl.src = _blobUrl; }

        // ── SourceBuffer setup ────────────────────────────────────────────────

        ms.addEventListener('sourceopen', function () {
            sb = ms.addSourceBuffer(mimeType);
            sb.mode = 'segments';

            sb.addEventListener('updateend', function () {
                appending = false;
                _drainQueue();
            });

            sb.addEventListener('error', function (e) {
                (options.onError || function () {})(
                    new Error('SourceBuffer error: ' + (e.message || 'unknown'))
                );
            });

            // Set total duration
            if (_manifest.duration) {
                try { ms.duration = _manifest.duration; } catch(e) {}
            }

            // Append init segment first
            _appendInitSegment();
        });

        function _appendInitSegment() {
            if (!sb || sb.updating) { return; }
            appending = true;
            initDone  = false;
            try {
                sb.appendBuffer(Q.Data.fromBase64(initSegmentB64));
            } catch (e) {
                appending = false;
                (options.onError || function () {})(e);
            }
            // After updateend, initDone = true, drain will start
            sb.addEventListener('updateend', function _afterInit() {
                sb.removeEventListener('updateend', _afterInit);
                initDone = true;
                _drainQueue();
            }, { once: true });
        }

        // ── Queue drain ───────────────────────────────────────────────────────

        function _drainQueue() {
            if (!sb || appending || !initDone || !queue.length) {
                // Signal end of stream when loop is done and queue empty
                if (endOfStream && !appending && queue.length === 0 && ms.readyState === 'open') {
                    try { ms.endOfStream(); } catch(e) {}
                }
                return;
            }

            // Sort queue by index so we append in order
            queue.sort(function (a, b) { return a.index - b.index; });
            var next = queue.shift();
            appending = true;

            try {
                sb.appendBuffer(next.buffer);
            } catch (e) {
                if (e.name === 'QuotaExceededError' && videoEl) {
                    // Evict buffered data >10s behind playhead, then retry
                    var behind = Math.max(0, videoEl.currentTime - 10);
                    if (behind > 0 && !sb.updating) {
                        queue.unshift(next);  // put back
                        appending = false;
                        sb.remove(0, behind);
                    } else {
                        appending = false;
                        (options.onError || function () {})(e);
                    }
                } else {
                    appending = false;
                    (options.onError || function () {})(e);
                }
            }
        }

        // ── onChunk callback — receives decrypted chunks from _prefetchLoop ───

        function _onChunk(segIndex, plaintextBuffer) {
            if (endOfStream) { return; }
            if (_receivedSet[segIndex]) { return; } // deduplicate
            _receivedSet[segIndex] = true;
            queue.push({ index: segIndex, buffer: plaintextBuffer });
            _drainQueue();

            // End of stream only when ALL chunks 0..chunkCount-1 received
            var total = _manifest.chunkCount || 0;
            var allReceived = total > 0;
            for (var ci = 0; ci < total && allReceived; ci++) {
                if (!_receivedSet[ci]) { allReceived = false; }
            }
            if (allReceived) { endOfStream = true; }
        }

        // ── Seek ──────────────────────────────────────────────────────────────

        function _doSeek(seconds) {
            if (!sb || _seeking) { return; }
            _seeking = true;

            // Snap to nearest keyframe at or before requested position
            var targetChunk = _chunkAtTime(seconds, _manifest);
            var kfChunk     = _nearestKeyframe(targetChunk, _manifest.keyframes);
            var kfTime      = _manifest.chunks
                ? _manifest.chunks[kfChunk].pts
                : kfChunk * (_manifest.chunkDuration || 6);

            // Reset state
            queue        = [];
            endOfStream  = false;
            initDone     = false;
            _receivedSet = {};   // allow re-fetching chunks after seek

            // Tell prefetch loop to restart from keyframe
            if (_loop) { _loop.seek(kfTime); }

            // Flush SourceBuffer then re-append init segment
            function _flushAndReinit() {
                if (sb.updating) {
                    sb.addEventListener('updateend', _flushAndReinit, { once: true });
                    return;
                }
                try {
                    sb.remove(0, ms.duration || Infinity);
                    sb.addEventListener('updateend', function () {
                        _seeking = false;
                        _appendInitSegment();
                        if (videoEl) { videoEl.currentTime = kfTime; }
                    }, { once: true });
                } catch(e) {
                    _seeking = false;
                }
            }
            _flushAndReinit();
        }

        // Wire seeking event
        if (videoEl) {
            videoEl.addEventListener('seeking', function () {
                _doSeek(videoEl.currentTime);
            });
        }

        // ── Start prefetch loop ───────────────────────────────────────────────

        _loop = Q.Safecloud.Client._prefetchLoop(
            'mse-' + (_manifest.rootCid || Date.now()).toString().slice(0, 12),
            videoManifest,
            capability,
            Q.extend({}, options, { onChunk: _onChunk })
        );

        // ── Public handle ─────────────────────────────────────────────────────

        return Promise.resolve({
            url:   _blobUrl,
            path:  'mse',
            index: _index,
            currentTime: function () { return videoEl ? videoEl.currentTime : 0; },
            seek: function (seconds) { _doSeek(seconds); },
            setVersion: function (label, timestamp) {
                // Switch to a different quality version
                startVersion = label;
                var newManifest = (videoManifest.versions || []).reduce(function (m, v) {
                    return v.label === label ? v.manifest : m;
                }, videoManifest);

                // Fetch new version's index track if it has one (may have different codec/init)
                var hasNewIndex = newManifest.tracks && newManifest.tracks.indexOf('index') >= 0;
                // Use version-specific capability for fetchIndex if available
                var vCap = (capability.versions && capability.versions[label])
                    ? { grants: capability.versions[label].grants }
                    : capability;
                var indexP = hasNewIndex
                    ? Q.Safecloud.Client.fetchIndex(newManifest, vCap, options)
                    : Promise.resolve(null);

                indexP.then(function (newIndex) {
                    if (newIndex) {
                        // Merge new index data into manifest
                        newManifest = Q.extend({}, newManifest, {
                            chunks:    newIndex.chapters  || newManifest.chunks,
                            keyframes: newIndex.keyframes || newManifest.keyframes,
                            duration:  newIndex.totalDuration || newManifest.duration
                        });
                        // Update initSegment if different
                        if (newIndex.initSegment && newIndex.initSegment !== initSegmentB64) {
                            initSegmentB64 = newIndex.initSegment;
                            // Re-append init segment after flush
                        }
                    }
                    _manifest = newManifest;

                    // Update mime type if codec changed
                    var newCodec   = (newIndex && newIndex.codec) || newManifest.codec || 'avc1.42e01e';
                    var newAudio   = (newIndex && newIndex.audioCodec) || newManifest.audioCodec || null;
                    var newMime    = 'video/mp4; codecs="' + newCodec + (newAudio ? ',' + newAudio : '') + '"';
                    if (newMime !== mimeType && sb && typeof sb.changeType === 'function') {
                        sb.changeType(newMime);
                        mimeType = newMime;
                    }
                    _loop.setVersion(label, timestamp);
                    // Always reset received-chunk tracking when switching versions —
                    // the new version has different chunks that haven't been received yet
                    _receivedSet = {};
                    endOfStream  = false;
                    if (timestamp != null) { _doSeek(timestamp); }
                }).catch(function () {
                    // Index fetch failed — still switch version, use existing codec
                    _manifest = newManifest;
                    _loop.setVersion(label, timestamp);
                    // Always reset received-chunk tracking when switching versions —
                    // the new version has different chunks that haven't been received yet
                    _receivedSet = {};
                    endOfStream  = false;
                    if (timestamp != null) { _doSeek(timestamp); }
                });
            },
            pause: function () {
                if (_loop) { _loop.pause(); }
                if (videoEl) { videoEl.pause(); }
            },
            resume: function () {
                if (_loop) { _loop.resume(); }
                if (videoEl) { videoEl.play(); }
            },
            stop: function () {
                if (_loop) { _loop.stop(); }
                if (videoEl) { videoEl.src = ''; }
                try { if (ms.readyState === 'open') { ms.endOfStream(); } } catch(e) {}
                URL.revokeObjectURL(_blobUrl);
            }
        }); // Promise.resolve
        }); // _indexPromise.then
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Map playback time → chunk index using per-chunk pts (binary search)
     * or uniform chunkDuration fallback.
     */
    function _chunkAtTime(seconds, manifest) {
        if (manifest && manifest.chunks && manifest.chunks.length) {
            var chunks = manifest.chunks;
            var lo = 0, hi = chunks.length - 1;
            while (lo < hi) {
                var mid = (lo + hi + 1) >> 1;
                if (chunks[mid].pts <= seconds) { lo = mid; } else { hi = mid - 1; }
            }
            return lo;
        }
        return Math.max(0, Math.floor(seconds / (manifest.chunkDuration || 6)));
    }

    /**
     * Return the nearest keyframe chunk index at or before chunkIndex.
     * Falls back to chunkIndex itself if no keyframe list.
     */

    function _nearestKeyframe(chunkIndex, keyframes) {
        if (!keyframes || !keyframes.length) { return chunkIndex; }
        for (var i = keyframes.length - 1; i >= 0; i--) {
            if (keyframes[i] <= chunkIndex) { return keyframes[i]; }
        }
        return keyframes[0];
    }
});
