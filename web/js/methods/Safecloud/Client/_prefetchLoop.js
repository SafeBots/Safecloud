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
        var onError       = options.onError        || function () {};
        var startAt       = options.at             || 0;
        var startVersion  = options.version        || _getFirstVersion(videoManifest);

        var _stopped   = false;
        var _paused    = false;
        var _version   = startVersion;
        var _inFlight  = {};
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
            if (_inFlight[segIndex]) { return; }
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
                        if (!_stopped) { onChunk(segIndex, plaintext); }
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
                _inFlight = {};
                _segStart = _chunkAtTime(seconds, chunkDuration, _manifest);
                if (!_paused && !_stopped) { clearTimeout(_loopTimer); _loopTimer = setTimeout(_tick, 0); }
                var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                if (sw) {
                    sw.postMessage({ type: 'Q.Safecloud.Client.seek', videoId: videoId, segIndex: _segStart });
                }
            },
            setVersion: function (label, timestamp) {
                _inFlight = {};
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
        if (manifest && manifest.chunks && manifest.chunks.length) {
            var chunks = manifest.chunks;
            var lo = 0, hi = chunks.length - 1;
            while (lo < hi) {
                var mid = (lo + hi + 1) >> 1;
                if (chunks[mid].pts <= seconds) { lo = mid; } else { hi = mid - 1; }
            }
            return lo;
        }
        return Math.max(0, Math.min(Math.floor(seconds / chunkDuration),
            (manifest && manifest.chunkCount ? manifest.chunkCount - 1 : Infinity)));
    }
});
