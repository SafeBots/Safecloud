/**
 * Q.Safecloud.Client.buildVideoIndex — remux a video into fragmented MP4
 * and build the real Protocol.md index-track object, so uploaded video
 * actually works in the embed/HLS player (Client/store.js only ever
 * encrypted whatever index object a caller handed it; nothing in the
 * plugin ever built one — this is that missing piece).
 *
 * Pipeline:
 *   1. ffmpeg.wasm stream-copy remux: -c copy -movflags
 *      frag_keyframe+empty_moov+default_base_moof — one fragment per
 *      keyframe/GOP, no re-encode.
 *   2. Walk the remuxed output's top-level boxes to find the init segment
 *      (everything before the first moof) and one chunk boundary per
 *      moof+mdat fragment.
 *   3. Parse moov for the video/audio track info (codec, resolution) —
 *      scope is exactly one avc1 video track + at most one mp4a audio
 *      track; anything else resolves { ok: false, reason }.
 *   4. Read each fragment's tfdt for its authoritative pts (no second
 *      ffprobe pass needed).
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

        function ok(result, ffmpeg) {
            if (ffmpeg) { try { ffmpeg.terminate(); } catch (e) {} }
            if (callback) { callback(null, result); }
            return result;
        }
        function fail(reason, ffmpeg) {
            var result = { ok: false, reason: reason };
            if (ffmpeg) { try { ffmpeg.terminate(); } catch (e) {} }
            if (callback) { callback(null, result); }
            return result;
        }

        function extFromName(name) {
            var m = /\.([a-zA-Z0-9]+)$/.exec(name || '');
            return m ? '.' + m[1] : '.bin';
        }

        function findBox(boxes, type) {
            for (var i = 0; i < boxes.length; i++) {
                if (boxes[i].type === type) { return boxes[i]; }
            }
            return null;
        }

        var _promise = _.blobToBuffer(file.data).then(function (inputBuffer) {
            return _.newFFmpeg().then(function (ffmpeg) {
                var inputName  = 'input' + extFromName(file.name);
                var outputName = 'output.mp4';

                return ffmpeg.writeFile(inputName, new Uint8Array(inputBuffer))
                    .then(function () {
                        return ffmpeg.exec([
                            '-i', inputName,
                            '-c', 'copy',
                            '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
                            '-f', 'mp4',
                            outputName
                        ]);
                    })
                    .then(function (execResult) {
                        if (execResult !== 0) {
                            throw new Error('ffmpeg exec failed with code ' + execResult);
                        }
                        return ffmpeg.readFile(outputName);
                    })
                    .then(function (data) {
                        var remuxed = data.buffer.slice(
                            data.byteOffset, data.byteOffset + data.byteLength);
                        return { remuxed: remuxed, ffmpeg: ffmpeg };
                    });
            });
        }).then(function (r) {
            var buffer = r.remuxed, ffmpeg = r.ffmpeg;

            var top  = _.walkTopLevelBoxes(buffer);
            var moov = findBox(top, 'moov');
            if (!moov) { return fail('remuxed output has no moov box', ffmpeg); }

            var tracks = _.parseMoovTracks(buffer, moov);
            if (!tracks.ok) { return fail(tracks.reason, ffmpeg); }

            var moofs = top.filter(function (b) { return b.type === 'moof'; });
            if (!moofs.length) { return fail('no moof fragments produced', ffmpeg); }

            var initSegmentEnd = moofs[0].start;
            var chunkBoundaries = moofs.map(function (moof, i) {
                var end = (i + 1 < moofs.length) ? moofs[i + 1].start : buffer.byteLength;
                return end - moof.start;
            });

            var chapters = [];
            for (var i = 0; i < moofs.length; i++) {
                var raw = _.readTfdt(buffer, moofs[i], tracks.video.trackId);
                if (raw === null) {
                    return fail('missing tfdt for video track in fragment ' + i, ffmpeg);
                }
                var pts = raw / tracks.video.timescale;
                chapters.push({ pts: pts, dts: pts, label: null });
            }

            // mvhd.duration is 0 under empty_moov (fragmented output doesn't
            // know total duration up front) — extrapolate from the last
            // inter-fragment gap rather than running a second ffprobe pass.
            var lastIdx = chapters.length - 1;
            var lastGap = chapters.length > 1
                ? (chapters[lastIdx].pts - chapters[lastIdx - 1].pts)
                : (chapters[0].pts || 1);
            var totalDuration = chapters[lastIdx].pts + lastGap;

            var index = {
                initSegment:   Q.Data.toBase64(new Uint8Array(buffer.slice(0, initSegmentEnd))),
                totalDuration: totalDuration,
                codec:         tracks.video.codec,
                audioCodec:    tracks.audio ? tracks.audio.codec : null,
                width:         tracks.video.width,
                height:        tracks.video.height,
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
            }, ffmpeg);
        }).catch(function (err) {
            return fail((err && err.message) || String(err));
        });

        if (!callback) { return _promise; }
        // callback already invoked from ok()/fail() above with (null, result);
        // this only covers a truly unexpected rejection that skipped fail().
        _promise.catch(function (err) { callback(err); });
    };
});
