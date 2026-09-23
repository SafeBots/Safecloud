/**
 * Q.Safecloud.Client._prefetchLoop — sliding prefetch window.
 *
 * LINK PATH MODEL:
 *   Each grant covers a subtree identified by link path.
 *   When decrypting a chunk (MSE path), we find the covering grant,
 *   use its secret as subtreeKey, and compute:
 *     leafKey = deriveLeafKeyFromGrant(grant.secret, grant.link, absIdx, manifest)
 *
 * Two delivery modes (options.onChunk):
 *   SW path:  post encrypted ciphertext to service worker (default)
 *   MSE path: decrypt here and call onChunk(segIndex, plaintextBuffer)
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client__prefetchLoop(videoId, videoManifest, capability, options) {
        options = options || {};

        var chunkDuration = videoManifest.chunkDuration || 6;
        var prefetchAhead = options.prefetchAhead  || 3;
        var videoElement  = options.videoElement   || null;
        var onChunk       = options.onChunk        || null;
        // A silent no-op default meant a segment fetch failure (including
        // the timeout added to Jets/_internal.js's _.emit) left zero trace
        // anywhere — confirmed live: playback stalled permanently on a real
        // upload with fetchedMB flatlined and not a single warning in the
        // console, because tools/video.js's startStream() never passes
        // onError. Logging by default costs nothing for callers that do
        // pass their own (options.onError still wins) and turns a silent,
        // undiagnosable freeze into a visible, actionable one.
        var onError       = options.onError        || function (err) {
            console.warn('Q.Safecloud.Client._prefetchLoop: segment fetch failed — '
                + (err && err.message || err));
        };
        var startAt       = options.at             || 0;
        var startVersion  = options.version        || _getFirstVersion(videoManifest);
        // How long with zero chunks delivered before we treat this as a
        // stall worth logging — not a hard error (the loop keeps retrying
        // regardless), just the line between "normal buffering" and "this
        // looks like the Drop for this content isn't answering."
        var stallLogMs    = options.stallLogMs     || 8000;

        var _stopped   = false;
        var _paused    = false;
        var _version   = startVersion;
        var _inFlight  = {};
        // Segments already delivered to the SW (or, for MSE, already handed
        // to onChunk) this "epoch" — without this, _tick() re-requests the
        // same [current, current+prefetchAhead) window on every 1s tick for
        // as long as currentTime stays inside it (e.g. ~5s chunks re-fetched
        // ~5x each over their own playback duration), hammering the Jet/Drop
        // for content it already has and inflating "Fetched MB" far past the
        // real file size. Reset on seek/setVersion since the SW prunes its
        // own segment cache to a small window around the seek target (see
        // sw.js's 'Q.Safecloud.Client.seek' handler) and a version switch is
        // an entirely different set of chunks.
        var _delivered = {};
        var _segStart  = _chunkAtTime(startAt, chunkDuration, videoManifest);
        // Next index the tick loop hasn't requested yet — see _tick() for
        // why this, not currentTime, drives the window's upper edge.
        var _frontier  = _segStart;
        var _manifest  = _getVersionManifest(videoManifest, _version);
        var _grants    = _getVersionGrants(capability, _version);
        var _loopTimer = null;
        var _loopStartedAt   = Date.now();
        var _lastDeliveredAt = null;
        var _stalled         = false;
        // Per-content counters (as opposed to Q.Safecloud.Jets.connectionStats'
        // socket-wide ones) — how THIS video's own fetches are faring, so a
        // stall log can tell "only this content's requests are failing" apart
        // from "the whole connection is unhealthy."
        var _segStats = { nullChunks: 0, timeouts: 0, errors: 0 };

        function _getFirstVersion(vm) {
            return (vm.versions && vm.versions[0] && vm.versions[0].label) || null;
        }
        function _getVersionManifest(vm, label) {
            if (!label || !vm.versions) { return vm; }
            var v = vm.versions.find(function (v) { return v.label === label; });
            return v ? v.manifest : vm;
        }
        function _getVersionGrants(cap, label) {
            if (!label) { return cap.grants || []; }
            if (cap.versions && cap.versions[label]) {
                return cap.versions[label].grants || [];
            }
            return cap.grants || [];
        }

        function _currentSegIndex() {
            if (!videoElement) { return _segStart; }
            return _chunkAtTime(videoElement.currentTime, chunkDuration, _manifest);
        }

        // ── Find the grant covering absIndex ──────────────────────────────────

        function _findCoveringGrant(absIndex) {
            var requiredLevel = _.levelFromLabel('read', 'content');
            for (var i = 0; i < _grants.length; i++) {
                if (_.grantCoversChunk(_grants[i], requiredLevel, absIndex, _manifest)) {
                    return _grants[i];
                }
            }
            return null;
        }

        // ── Fetch (+ optional decrypt for MSE path) ───────────────────────────

        function _fetchSeg(segIndex) {
            if (_inFlight[segIndex] || _delivered[segIndex]) { return; }
            if (segIndex >= _manifest.chunkCount) { return; }
            _inFlight[segIndex] = true;

            // Request by the chunk's own leaf link path so Jets returns exactly one chunk
            var chunkLeafLink = _.chunkLinkPath(segIndex, _manifest);

            Q.Safecloud.Jets.get({
                rootCid: _manifest.rootCid,
                link:    chunkLeafLink,
                grants:  _grants
            }, {
                authorizations: options.authorizations,
                payments:       options.payments
            }).then(function (result) {
                var chunk = result.chunks && result.chunks[0];
                if (!chunk) {
                    // Not an error (Jets/get.js: null means "unavailable,
                    // retry"), but silently swallowing it left zero trace of
                    // a Drop that never actually has the chunk it's supposed
                    // to be serving — count it so a stall log can show
                    // "N consecutive nulls for this content" instead of
                    // just "no chunk yet."
                    _segStats.nullChunks++;
                    return;
                }

                if (onChunk) {
                    // ── MSE path: decrypt and deliver plaintext ──────────────
                    return _decryptChunk(chunk, segIndex).then(function (plaintext) {
                        if (!_stopped) {
                            onChunk(segIndex, plaintext);
                            _delivered[segIndex] = true;
                            _onDelivered();
                        }
                    });
                }

                // ── SW path: post ciphertext to service worker ────────────────
                var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                if (sw) {
                    sw.postMessage({
                        type:       'Q.Safecloud.Client.segment',
                        videoId:    videoId,
                        version:    _version,
                        segIndex:   segIndex,
                        ciphertext: chunk.ciphertext,
                        tag:        chunk.tag,
                        iv:         chunk.iv
                    });
                    _delivered[segIndex] = true;
                    _onDelivered();
                }
            }).catch(function (err) {
                if (/timeout/i.test(err && err.message)) { _segStats.timeouts++; }
                else { _segStats.errors++; }
                onError(err);
            }).then(function () {
                delete _inFlight[segIndex];
            });
        }

        // ── Decrypt chunk (MSE path) ──────────────────────────────────────────

        function _decryptChunk(chunk, absIndex) {
            // Find covering grant and compute relIdx
            if (capability.rootKey) {
                return _decryptWithRootKey(chunk, absIndex);
            }
            var grant = _findCoveringGrant(absIndex);
            if (!grant) {
                return Promise.reject(new Error('No grant covers chunk ' + absIndex));
            }
            var grantKeyBytes = (typeof grant.secret === 'string')
                ? Q.Data.fromBase64(grant.secret) : grant.secret;

            // Navigate from grant node down to leaf, then derive chunk key
            return _.deriveLeafKeyFromGrant(grantKeyBytes, grant.link, absIndex, _manifest)
                .then(function (leafKey) {
                    return Promise.all([
                        _.deriveChunkKey(leafKey, 0),
                        _.deriveChunkIV(leafKey,  0)
                    ]).then(function (kv) {
                        return Q.Data.importKey(kv[0]).then(function (cryptoKey) {
                            return Q.Data.decrypt(cryptoKey, chunk.iv, chunk.ciphertext, {
                                tag:        chunk.tag,
                                additional: _.chunkAAD(absIndex)
                            });
                        });
                    });
                });
        }

        function _decryptWithRootKey(chunk, absIndex) {
            var rkBytes = (typeof capability.rootKey === 'string')
                ? Q.Data.fromBase64(capability.rootKey)
                : capability.rootKey;
            return _.deriveEncryptionRoot(rkBytes).then(function (encDel) {
                // Navigate all the way to the leaf in one call via deriveByPath
                var leafPath = _.chunkLinkPath(absIndex, _manifest);
                return _.deriveByPath(encDel.secret, leafPath, '{}');
            }).then(function (leafDel) {
                var leafKey = leafDel.secret;
                return Promise.all([
                    _.deriveChunkKey(leafKey, 0),
                    _.deriveChunkIV(leafKey,  0)
                ]).then(function (kv) {
                    return Q.Data.importKey(kv[0]).then(function (cryptoKey) {
                        return Q.Data.decrypt(cryptoKey, chunk.iv, chunk.ciphertext, {
                            tag:        chunk.tag,
                            additional: _.chunkAAD(absIndex)
                        });
                    });
                });
            });
        }

        // ── Tick ──────────────────────────────────────────────────────────────

        function _onDelivered() {
            _lastDeliveredAt = Date.now();
            if (_stalled) {
                _stalled = false;
                console.info('Q.Safecloud.Client._prefetchLoop: recovered — '
                    + 'chunk delivered for videoId ' + videoId + ' after a stall.');
            }
        }

        // Fires once when this content has gone stallLogMs with zero chunks
        // delivered — the concrete, actionable version of "the player never
        // starts / freezes": distinguishes a slow Drop (isolated nulls/
        // timeouts for THIS content while the socket's overall latency stays
        // normal) from a broken connection (elevated timedOut/errored across
        // Q.Safecloud.Jets.connectionStats() too), without needing devtools
        // open at the exact moment it happens to have caught the raw frames.
        function _checkStall() {
            // Fully delivered — nothing left to fetch, not a stall.
            if (_manifest.chunkCount
                && Object.keys(_delivered).length >= _manifest.chunkCount) { return; }
            var since = Date.now() - (_lastDeliveredAt || _loopStartedAt);
            if (since < stallLogMs) { return; }
            if (_stalled) { return; } // already logged this episode
            _stalled = true;

            var snapshot = {
                videoId:          videoId,
                version:          _version,
                segIndex:         _currentSegIndex(),
                chunkCount:       _manifest.chunkCount,
                deliveredCount:   Object.keys(_delivered).length,
                deliveredIndices: Object.keys(_delivered),
                inFlightCount:    Object.keys(_inFlight).length,
                msSinceDelivery:  since,
                nullChunks:       _segStats.nullChunks,
                timeouts:         _segStats.timeouts,
                errors:           _segStats.errors,
                documentHidden:   (typeof document !== 'undefined') && document.hidden,
                connection:       Q.Safecloud.Jets.connectionStats
                                      ? Q.Safecloud.Jets.connectionStats() : null
            };
            console.warn('Q.Safecloud.Client._prefetchLoop: no chunk delivered in '
                + Math.round(since / 1000) + 's for videoId ' + videoId
                + ' — likely a slow or unreachable Drop for this content. '
                + JSON.stringify(snapshot));
            if (options.onStall) { options.onStall(snapshot); }
        }

        function _tick() {
            if (_stopped || _paused) { return; }
            if (videoElement && videoElement.paused && !options.prefetchWhenPaused) {
                _loopTimer = setTimeout(_tick, 500);
                return;
            }
            var current = _currentSegIndex();
            // The window's upper edge must NOT be pinned to current+prefetchAhead:
            // hls.js buffers forward toward its own target (default ~30s) as fast
            // as fetches resolve, regardless of how much of the buffer has
            // actually played back yet — a fresh upload with a fast/local SW
            // round-trip can exhaust an initial [current, current+prefetchAhead)
            // window in well under a second, long before currentTime has moved.
            // Confirmed live: playback consistently stalled right around
            // prefetchAhead * chunkDuration seconds in. Instead, _frontier keeps
            // advancing by prefetchAhead segments every tick (~1/s) regardless of
            // playback position, so the loop races ahead of hls.js's own demand
            // instead of trailing behind it — while still never falling behind
            // current itself, so a forward seek (including one driven directly by
            // the native scrubber, which doesn't go through this loop's own
            // seek()) doesn't leave the frontier stuck fetching an already-passed
            // range.
            if (current > _frontier) { _frontier = current; }
            var windowEnd = Math.min(_frontier + prefetchAhead, _manifest.chunkCount || Infinity);
            for (var i = _frontier; i < windowEnd; i++) { _fetchSeg(i); }
            _frontier = windowEnd;
            _checkStall();
            _loopTimer = setTimeout(_tick, 1000);
        }

        // Browsers aggressively terminate an idle service worker (Chrome:
        // ~30s with no activity) — confirmed live: pause the video, switch
        // tabs for a while, come back, and the SW is a fresh instance whose
        // in-memory segments[videoId] cache is empty (sw.js restores only
        // the session metadata from IndexedDB on restart — the actual
        // decrypted chunk bytes were never persisted anywhere). This page's
        // own _delivered tracking has no way to know that happened, so
        // without this it permanently believed already-delivered segments
        // were still sitting in the SW's cache and never resent them —
        // every segment beyond whatever was already buffered in the video
        // element's own MediaSource buffer 503'd forever, escalating to a
        // fatal hls.js fragLoadError. Treat becoming visible again after
        // being hidden as "the SW may have restarted" and just resend
        // everything the loop still thinks is needed from here on — worst
        // case is a few redundant re-deliveries if it didn't actually
        // restart, which costs bandwidth but not correctness.
        var _onVisible = function () {
            if (document.visibilityState === 'visible') { _delivered = {}; }
        };
        if (typeof document !== 'undefined' && document.addEventListener) {
            document.addEventListener('visibilitychange', _onVisible);
        }

        _loopTimer = setTimeout(_tick, 0);

        // ── Public handle ─────────────────────────────────────────────────────

        return {
            stop: function () {
                _stopped = true;
                clearTimeout(_loopTimer);
                _inFlight = {};
                if (typeof document !== 'undefined' && document.removeEventListener) {
                    document.removeEventListener('visibilitychange', _onVisible);
                }
                var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                if (sw) { sw.postMessage({ type: 'Q.Safecloud.Client.stop', videoId: videoId }); }
            },
            // On-demand diagnostic snapshot — same shape _checkStall() logs,
            // so a caller (tools/video.js's own start-stall watchdog) can
            // pull it without waiting for stallLogMs to elapse first.
            stats: function () {
                return {
                    videoId:         videoId,
                    segIndex:        _currentSegIndex(),
                    chunkCount:      _manifest.chunkCount,
                    deliveredCount:  Object.keys(_delivered).length,
                    inFlightCount:   Object.keys(_inFlight).length,
                    msSinceDelivery: Date.now() - (_lastDeliveredAt || _loopStartedAt),
                    nullChunks:      _segStats.nullChunks,
                    timeouts:        _segStats.timeouts,
                    errors:          _segStats.errors,
                    connection:      Q.Safecloud.Jets.connectionStats
                                         ? Q.Safecloud.Jets.connectionStats() : null
                };
            },
            pause: function () { _paused = true; },
            resume: function () {
                _paused = false;
                if (!_stopped) { clearTimeout(_loopTimer); _loopTimer = setTimeout(_tick, 0); }
            },
            seek: function (seconds) {
                _inFlight  = {};
                // The SW prunes its own segment cache to a small window
                // around the seek target (sw.js's 'seek' handler), so
                // anything outside that window needs to be treated as
                // undelivered again even though we sent it once before.
                _delivered = {};
                // Give the new position a fresh stallLogMs grace period
                // instead of comparing against a pre-seek delivery time that
                // may already be stale.
                _lastDeliveredAt = Date.now();
                _stalled = false;
                _segStart = _chunkAtTime(seconds, chunkDuration, _manifest);
                _frontier = _segStart;
                if (!_paused && !_stopped) { clearTimeout(_loopTimer); _loopTimer = setTimeout(_tick, 0); }
                var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                if (sw) {
                    sw.postMessage({ type: 'Q.Safecloud.Client.seek', videoId: videoId, segIndex: _segStart });
                }
            },
            setVersion: function (label, timestamp) {
                _inFlight  = {};
                _delivered = {}; // switching renditions means an entirely different chunk set
                _lastDeliveredAt = Date.now();
                _stalled = false;
                _version  = label;
                _manifest = _getVersionManifest(videoManifest, label);
                _grants   = _getVersionGrants(capability, label);
                // Update chunkDuration for the new version (may differ between renditions)
                chunkDuration = _manifest.chunkDuration || videoManifest.chunkDuration || 6;
                if (timestamp != null) { _segStart = _chunkAtTime(timestamp, chunkDuration, _manifest); }
                _frontier = _segStart;
                var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                if (sw) {
                    sw.postMessage({ type: 'Q.Safecloud.Client.setVersion', videoId: videoId,
                                     version: label, manifest: _manifest });
                }
                if (!_paused && !_stopped) { clearTimeout(_loopTimer); _loopTimer = setTimeout(_tick, 0); }
            }
        };
    };

    function _chunkAtTime(seconds, chunkDuration, manifest) {
        // The real, mediabunny-authoritative per-chunk start times live at
        // manifest._index.chapters[].pts (see buildVideoIndex.js/Protocol.md)
        // — manifest.chunks never exists in this schema, so that branch was
        // pure dead code and every caller silently fell back to the naive
        // currentTime/chunkDuration guess below. Nothing in the manifest
        // schema ever sets chunkDuration either, so that guess always used
        // the flat 6s default — wrong for any content whose real per-chunk
        // duration differs (e.g. ~5.3s for a typical GOP-fragmented upload),
        // and the resulting drift compounds over minutes of playback until
        // the prefetch window undershoots the segment actually needed,
        // permanently stalling once the buffered-ahead margin runs out.
        var chapters = manifest && manifest._index && manifest._index.chapters;
        if (chapters && chapters.length) {
            var lo = 0, hi = chapters.length - 1;
            while (lo < hi) {
                var mid = (lo + hi + 1) >> 1;
                if (chapters[mid].pts <= seconds) { lo = mid; } else { hi = mid - 1; }
            }
            return lo;
        }
        return Math.max(0, Math.min(Math.floor(seconds / chunkDuration),
            (manifest && manifest.chunkCount ? manifest.chunkCount - 1 : Infinity)));
    }
});
