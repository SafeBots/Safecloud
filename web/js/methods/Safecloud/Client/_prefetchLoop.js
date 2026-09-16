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
        var _manifest  = _getVersionManifest(videoManifest, _version);
        var _grants    = _getVersionGrants(capability, _version);
        var _loopTimer = null;

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
                if (!chunk) { return; }

                if (onChunk) {
                    // ── MSE path: decrypt and deliver plaintext ──────────────
                    return _decryptChunk(chunk, segIndex).then(function (plaintext) {
                        if (!_stopped) { onChunk(segIndex, plaintext); _delivered[segIndex] = true; }
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
                }
            }).catch(function (err) {
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

        function _tick() {
            if (_stopped || _paused) { return; }
            if (videoElement && videoElement.paused && !options.prefetchWhenPaused) {
                _loopTimer = setTimeout(_tick, 500);
                return;
            }
            var current = _currentSegIndex();
            for (var i = 0; i < prefetchAhead; i++) { _fetchSeg(current + i); }
            _loopTimer = setTimeout(_tick, 1000);
        }

        _loopTimer = setTimeout(_tick, 0);

        // ── Public handle ─────────────────────────────────────────────────────

        return {
            stop: function () {
                _stopped = true;
                clearTimeout(_loopTimer);
                _inFlight = {};
                var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                if (sw) { sw.postMessage({ type: 'Q.Safecloud.Client.stop', videoId: videoId }); }
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
                _segStart = _chunkAtTime(seconds, chunkDuration, _manifest);
                if (!_paused && !_stopped) { clearTimeout(_loopTimer); _loopTimer = setTimeout(_tick, 0); }
                var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                if (sw) {
                    sw.postMessage({ type: 'Q.Safecloud.Client.seek', videoId: videoId, segIndex: _segStart });
                }
            },
            setVersion: function (label, timestamp) {
                _inFlight  = {};
                _delivered = {}; // switching renditions means an entirely different chunk set
                _version  = label;
                _manifest = _getVersionManifest(videoManifest, label);
                _grants   = _getVersionGrants(capability, label);
                // Update chunkDuration for the new version (may differ between renditions)
                chunkDuration = _manifest.chunkDuration || videoManifest.chunkDuration || 6;
                if (timestamp != null) { _segStart = _chunkAtTime(timestamp, chunkDuration, _manifest); }
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
        // The real, ffmpeg-authoritative per-chunk start times live at
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
