/**
 * Q.Safecloud.Client.buildVideoIndex — remux/transcode a video into
 * fragmented MP4 and build the real Protocol.md index-track object, so
 * uploaded video actually works in the embed/HLS player (Client/store.js
 * only ever encrypted whatever index object a caller handed it; nothing
 * in the plugin ever built one — this is that missing piece).
 *
 * Pipeline (mediabunny — see bugfix-log for why this replaced ffmpeg.wasm):
 *   1. Open the input file as a mediabunny Input against ALL_FORMATS, so
 *      any container mediabunny knows (not just MP4/MOV) is accepted.
 *   2. Read video/audio codec, dimensions and duration straight off
 *      mediabunny's own track objects — no manual moov/stsd parsing, and
 *      no hardcoded codec allow-list the way ffmpeg's output parser had.
 *   3. Run a Conversion into a fragmented MP4 Output. mediabunny copies
 *      packets straight through untouched whenever the source codec is
 *      natively containable in MP4 (avc/hevc/vp9/av1 video, aac/opus/mp3/
 *      vorbis/flac/... audio — no re-encode), and only falls back to a
 *      real decode+re-encode when the source codec genuinely can't be
 *      contained, rather than failing the whole upload outright.
 *   4. Walk the produced output's top-level boxes to find the init
 *      segment (everything before the first moof) and one chunk boundary
 *      per moof+mdat fragment, and read each fragment's tfdt for its
 *      authoritative pts — unchanged from the ffmpeg pipeline, since this
 *      part only cares about standard ISOBMFF box layout, not which
 *      muxer produced it.
 *
 * Never throws for an unsupported/malformed input — always resolves with
 * either { ok: true, buffer, chunkBoundaries, index } or
 * { ok: false, reason }, so callers (web/js/tools/upload.js) can fall back
 * to a plain store() call without the upload ever being blocked.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_buildVideoIndex(file, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        function ok(result) {
            if (callback) { callback(null, result); }
            return result;
        }
        function fail(reason) {
            var result = { ok: false, reason: reason };
            if (callback) { callback(null, result); }
            return result;
        }

        function findBox(boxes, type) {
            for (var i = 0; i < boxes.length; i++) {
                if (boxes[i].type === type) { return boxes[i]; }
            }
            return null;
        }

        var input = null;

        var _promise = _.ensureMediabunny().then(function (Mediabunny) {
            input = new Mediabunny.Input({
                formats: Mediabunny.ALL_FORMATS,
                source: new Mediabunny.BlobSource(file.data)
            });

            return Promise.all([
                input.getPrimaryVideoTrack(),
                input.getPrimaryAudioTrack()
            ]).then(function (primaryTracks) {
                var videoTrack = primaryTracks[0], audioTrack = primaryTracks[1];
                if (!videoTrack) { return fail('no video track found in input file'); }

                return Promise.all([
                    videoTrack.getCodecParameterString(),
                    audioTrack ? audioTrack.getCodecParameterString() : Promise.resolve(null),
                    input.computeDuration()
                ]).then(function (r) {
                    var videoCodec = r[0], audioCodec = r[1], sourceDuration = r[2];
                    if (!videoCodec) { return fail('could not determine video codec'); }

                    var target = new Mediabunny.BufferTarget();
                    var output = new Mediabunny.Output({
                        format: new Mediabunny.Mp4OutputFormat({ fastStart: 'fragmented' }),
                        target: target
                    });

                    return Mediabunny.Conversion.init({ input: input, output: output })
                        .then(function (conversion) {
                            if (!conversion.isValid) {
                                var reasons = conversion.discardedTracks.map(function (d) {
                                    return d.track.type + ': ' + d.reason;
                                }).join(', ');
                                return fail('conversion is not valid: ' + (reasons || 'no usable tracks'));
                            }

                            return conversion.execute().then(function () {
                                var buffer = target.buffer;

                                var top  = _.walkTopLevelBoxes(buffer);
                                var moov = findBox(top, 'moov');
                                if (!moov) { return fail('output has no moov box'); }

                                var tracks = _.parseMoovTracks(buffer, moov);
                                if (!tracks.ok) { return fail(tracks.reason); }

                                var moofs = top.filter(function (b) { return b.type === 'moof'; });
                                if (!moofs.length) { return fail('no moof fragments produced'); }

                                var initSegmentEnd = moofs[0].start;
                                var chunkBoundaries = moofs.map(function (moof, i) {
                                    var end = (i + 1 < moofs.length) ? moofs[i + 1].start : buffer.byteLength;
                                    return end - moof.start;
                                });

                                // Not every fragment is guaranteed to carry a
                                // traf for the video track specifically —
                                // mediabunny (unlike ffmpeg's always-multiplexed
                                // frag_keyframe output) only writes a traf for
                                // tracks that actually have queued samples at
                                // the moment a fragment gets finalized, so a
                                // trailing fragment can end up audio-only once
                                // the video track has already closed. Prefer
                                // the video track's own tfdt (the authoritative
                                // source), fall back to the audio track's tfdt
                                // for that same fragment, and only as a last
                                // resort reuse the previous fragment's pts —
                                // never fail the whole index over one fragment
                                // missing a track it was never going to have.
                                var chapters = [];
                                for (var i = 0; i < moofs.length; i++) {
                                    var pts;
                                    var rawVideo = _.readTfdt(buffer, moofs[i], tracks.video.trackId);
                                    if (rawVideo !== null) {
                                        pts = rawVideo / tracks.video.timescale;
                                    } else if (tracks.audio) {
                                        var rawAudio = _.readTfdt(buffer, moofs[i], tracks.audio.trackId);
                                        pts = (rawAudio !== null)
                                            ? rawAudio / tracks.audio.timescale
                                            : (chapters.length ? chapters[chapters.length - 1].pts : 0);
                                    } else {
                                        pts = chapters.length ? chapters[chapters.length - 1].pts : 0;
                                    }
                                    chapters.push({ pts: pts, dts: pts, label: null });
                                }

                                // mediabunny reports the source file's real
                                // duration directly (largest end timestamp
                                // among all tracks) — no ffmpeg-era
                                // empty_moov/mvhd.duration=0 workaround
                                // needed. Only fall back to extrapolating
                                // from the last inter-fragment gap if that
                                // ever comes back non-finite/zero.
                                var lastIdx = chapters.length - 1;
                                var totalDuration = (sourceDuration > 0 && isFinite(sourceDuration))
                                    ? sourceDuration
                                    : (function () {
                                        var lastGap = chapters.length > 1
                                            ? (chapters[lastIdx].pts - chapters[lastIdx - 1].pts)
                                            : (chapters[0].pts || 1);
                                        return chapters[lastIdx].pts + lastGap;
                                    }());

                                var index = {
                                    initSegment:   Q.Data.toBase64(new Uint8Array(buffer.slice(0, initSegmentEnd))),
                                    totalDuration: totalDuration,
                                    codec:         videoCodec,
                                    audioCodec:    audioCodec,
                                    width:         videoTrack.displayWidth,
                                    height:        videoTrack.displayHeight,
                                    chapters:      chapters
                                };

                                // The init segment (ftyp+moov) is already carried separately in
                                // index.initSegment (served via serveInitSegment/EXT-X-MAP) — it
                                // must NOT also be included in the data track. chunkBoundaries
                                // are fragment-only lengths (moof[i+1].start - moof[i].start),
                                // which only line up correctly against a buffer that starts at
                                // the first moof; passing the full buffer (starting at ftyp)
                                // shifted every single chunk earlier by initSegmentEnd bytes,
                                // corrupting the whole stream (each chunk missing its own tail
                                // and starting mid-way through the previous fragment instead).
                                return ok({
                                    ok: true,
                                    buffer: buffer.slice(initSegmentEnd),
                                    chunkBoundaries: chunkBoundaries,
                                    index: index
                                });
                            });
                        });
                });
            });
        }).catch(function (err) {
            return fail((err && err.message) || String(err));
        }).finally(function () {
            if (input) { try { input.dispose(); } catch (e) {} }
        });

        if (!callback) { return _promise; }
        // callback already invoked from ok()/fail() above with (null, result);
        // this only covers a truly unexpected rejection that skipped fail().
        _promise.catch(function (err) { callback(err); });
    };
});
