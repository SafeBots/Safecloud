(function (Q, $) {

/**
 * @module Safecloud
 */

/**
 * Encrypted file upload widget.
 * Drag-drop or click to select → encrypts in browser → stores via Jets.
 *
 * @class Safecloud upload
 * @constructor
 * @param {Object} [options]
 *   @param {String}  [options.jetUrl]       Jet server URL.
 *   @param {Number}  [options.chunkSize]    Bytes per chunk. Default 256 KB.
 *   @param {Boolean} [options.multiple]     Allow multiple file uploads.
 *   @param {String}  [options.accept]       File input accept string.
 *   @param {Q.Event} [options.onStore]      Fired with (manifest, rootKey, videoThumbnail, videoDuration) after upload.
 *     videoThumbnail is a "data:image/jpeg;base64,..." data URL captured from a
 *     random frame of the video during the "Preparing…" stage, or null if the
 *     file wasn't a video or the frame couldn't be captured (e.g. unsupported codec).
 *     videoDuration is the video's length in seconds (from buildVideoIndex's
 *     remux pass), or null if unavailable.
 *   @param {Q.Event} [options.onProgress]   Fired with (pct) during upload.
 *   @param {Q.Event} [options.onError]      Fired on error.
 */
Q.Tool.define('Safecloud/upload', function (options) {
    var tool  = this;
    var state = tool.state;

        tool.text.upload = Q.extend({
        DropLabel: 'Drop a file here or click to upload',
        DropSub: 'Encrypted with AES-256-GCM · Stored on Safecloud Drops',
        Preparing: 'Preparing…',
        Remuxing: 'Preparing video for streaming…',
        Encrypting: 'Encrypting…',
        Uploaded: 'Uploaded',
        UploadFailed: 'Upload failed',
        WaitingForDrop: 'Waiting for storage node…',
        NoDropsMessage: 'No storage nodes (Drops) are online right now. '
            + 'You can help by becoming one yourself: open the link below in another '
            + 'tab, click "Connect to Safecloud" there, then come back to this tab '
            + 'and try uploading again.',
        OpenDropButton: 'Open Safecloud Drop'
    }, tool.text.upload || {});

    if (state.jetUrl) { Q.Safecloud.Jets.url = state.jetUrl; }
    Q.Safecloud.Jets.connect();

    tool.refresh();
},

{
    jetUrl:    null,
    chunkSize: 256 * 1024,
    multiple:  false,
    accept:    '*/*',
    onStore:   new Q.Event(),
    onProgress:new Q.Event(),
    onError:   new Q.Event(function (err) {
        console.warn('Safecloud/upload error:', err);
    })
},

{
    refresh: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        Q.Template.render('Safecloud/upload', {
            text:     tool.text,
            accept:   state.accept,
            multiple: state.multiple,
            dropUrl:  Q.url('safecloud/drop')
        }, function (err, html) {
            if (err) return Q.handle(state.onError, tool, [err]);
            $te.html(html, true).activate(function () {
                tool.addEvents();
            });
        });
    },

    addEvents: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        // Click-to-open file picker
        $te.on(Q.Pointer.fastclick, '.Safecloud_upload_zone', function (e) {
            if ($(e.target).is('input')) return;
            $te.find('.Safecloud_upload_input').click();
        });

        // File picker change
        $te.on('change', '.Safecloud_upload_input', function () {
            var files = this.files;
            if (files && files.length) { tool.storeFile(files[0]); }
        });

        // Drag and drop
        $te.on('dragover', '.Safecloud_upload_zone', function (e) {
            e.preventDefault();
            $(this).addClass('Safecloud_upload_dragover');
        }).on('dragleave drop', '.Safecloud_upload_zone', function (e) {
            $(this).removeClass('Safecloud_upload_dragover');
        }).on('drop', '.Safecloud_upload_zone', function (e) {
            e.preventDefault();
            var f = e.originalEvent.dataTransfer.files[0];
            if (f) { tool.storeFile(f); }
        });
    },

    storeFile: function (file) {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);
        var isVideo = file.type && file.type.indexOf('video/') === 0;

        // Hide any hint left over from a previous failed attempt — a retry
        // shouldn't keep showing "no Drops available" once it's underway.
        $te.find('.Safecloud_upload_noDrops').hide();

        // Progress row is hidden (Safecloud_upload_hasFile in upload.css)
        // until a file is actually picked — showing it earlier displayed a
        // 0% bar with nothing happening yet.
        $te.addClass('Safecloud_upload_hasFile');

        // Captured asynchronously below, in parallel with the drop-wait /
        // remuxing / encryption steps that follow — by the time doStore()'s
        // upload finishes (always much later than a single canvas grab),
        // this closure variable already holds the result (or null).
        var videoThumbnail = null;

        // buildVideoIndex() already computes this (from the remuxed
        // fragments' tfdt boxes, see buildVideoIndex.js) for its own
        // index-track needs, but that index gets encrypted into
        // track/index — the plain manifest never carries duration. Capture
        // it here, before encryption, so callers (e.g. per-minute pricing)
        // can use it without needing the rootKey to decrypt anything.
        var videoDuration = null;

        function doStore(fileData, extraOptions) {
            Q.Safecloud.Client.store(
                { data: fileData, name: file.name, type: (extraOptions && extraOptions.type) || file.type },
                Q.extend({
                    chunkSize: state.chunkSize,
                    onProgress: function (stored, total) {
                        var pct = Math.round(stored / total * 100);
                        tool.setProgress(pct);
                        Q.handle(state.onProgress, tool, [pct]);
                    }
                }, extraOptions),
                function (err, result) {
                    if (err) {
                        $te.removeClass('Safecloud_upload_uploading');
                        var errMsg = err.message || String(err);
                        tool.setStatus((Q.getObject('upload.UploadFailed', tool.text) || 'Upload failed') +
                            ': ' + errMsg, 'error');
                        // The Jet returns this exact message (Jets.js) when no
                        // Drop is registered to store the chunks at all — as
                        // opposed to other failures (network, quota, etc.),
                        // this one has a concrete action the uploader can take
                        // themselves: become a Drop and retry.
                        if (/no drops available/i.test(errMsg)) {
                            $te.find('.Safecloud_upload_noDrops').show();
                        }
                        return Q.handle(state.onError, tool, [err]);
                    }
                    tool.setStatus(
                        (Q.getObject('upload.Uploaded', tool.text) || 'Uploaded') + ': ' + file.name, 'ok');
                    tool.setProgress(100);
                    Q.handle(state.onStore, tool, [result.manifest, result.rootKey, videoThumbnail, videoDuration]);
                }
            );
        }

        $te.addClass('Safecloud_upload_uploading');
        tool.setStatus(
            Q.getObject('upload.Preparing', tool.text) || 'Preparing…', 'working');
        tool.setProgress(0);

        if (isVideo) {
            tool.captureVideoThumbnail(file, function (dataUrl) {
                videoThumbnail = dataUrl;
            });
        }

        // Wait up to 8 s for a Drop to register before uploading.
        // Guards against the race where the user drops a file before
        // WebAuthn completes (same tab auto-init from demo.js).
        _waitForDrop(15000, function () {
            if (!isVideo || !Q.Safecloud.Client.buildVideoIndex) {
                tool.setStatus(
                    Q.getObject('upload.Encrypting', tool.text) || 'Encrypting…', 'working');
                return doStore(file, {});
            }

            // Real MP4 index-track generation (Protocol.md), so the embed/HLS
            // player can actually play this video — see buildVideoIndex.js.
            // Never blocks the upload: any failure falls back to plain
            // store() exactly as for non-video files.
            tool.setStatus(
                Q.getObject('upload.Remuxing', tool.text) || 'Preparing video for streaming…', 'working');

            Q.Safecloud.Client.buildVideoIndex(
                { data: file, name: file.name, type: file.type }, {},
                function (err, result) {
                    tool.setStatus(
                        Q.getObject('upload.Encrypting', tool.text) || 'Encrypting…', 'working');

                    if (err || !result || !result.ok) {
                        console.warn('Safecloud/upload: buildVideoIndex skipped — '
                            + (err ? (err.message || err) : (result && result.reason)));
                        return doStore(file, {});
                    }

                    videoDuration = Q.getObject('index.totalDuration', result) || null;

                    doStore(result.buffer, {
                        type: 'video/mp4',
                        chunkBoundaries: result.chunkBoundaries,
                        index: result.index
                    });
                }
            );
        });
    },

    setStatus: function (msg, cls) {
        $(this.element).find('.Safecloud_upload_status')
            .text(msg).removeClass('working ok error').addClass(cls || '');
    },

    setProgress: function (pct) {
        pct = Math.min(Math.max(Math.round(pct), 0), 100);
        var $te = $(this.element);
        $te.find('.Safecloud_upload_progress_fill').css('width', pct + '%');
        $te.find('.Safecloud_upload_progress_pct').text(pct + '%');
    },

    /**
     * Grabs a single frame from a random point in the video (10%-90% of its
     * duration, to avoid black/blank frames right at the start or end) and
     * returns it as a "data:image/jpeg;base64,..." data URL, downscaled to
     * at most 800px on the longer side. Never throws — calls back with null
     * on any failure (unsupported codec, decode error, timeout), so a failed
     * capture just falls back to whatever default thumbnail the caller uses.
     * @method captureVideoThumbnail
     * @param {File} file
     * @param {Function} callback Called with (dataUrl|null)
     */
    captureVideoThumbnail: function (file, callback) {
        var called = false;
        var objectUrl;
        var video = document.createElement('video');

        function finish(dataUrl) {
            if (called) { return; }
            called = true;
            clearTimeout(timeoutId);
            video.removeAttribute('src');
            video.load();
            if (objectUrl) { URL.revokeObjectURL(objectUrl); }
            callback(dataUrl || null);
        }

        var timeoutId = setTimeout(function () { finish(null); }, 8000);

        try {
            objectUrl = URL.createObjectURL(file);
        } catch (e) {
            return finish(null);
        }

        video.muted = true;
        video.playsInline = true;
        video.preload = 'auto';
        video.addEventListener('error', function () { finish(null); });
        video.addEventListener('loadedmetadata', function () {
            var duration = video.duration;
            var seekTo = 0;
            if (isFinite(duration) && duration > 0.5) {
                seekTo = duration * (0.1 + Math.random() * 0.8);
            }
            try {
                video.currentTime = seekTo;
            } catch (e) {
                finish(null);
            }
        });
        video.addEventListener('seeked', function () {
            try {
                var w = video.videoWidth, h = video.videoHeight;
                if (!w || !h) { return finish(null); }
                var maxSide = 800;
                var scale = Math.min(1, maxSide / Math.max(w, h));
                var canvas = document.createElement('canvas');
                canvas.width = Math.round(w * scale);
                canvas.height = Math.round(h * scale);
                canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
                finish(canvas.toDataURL('image/jpeg', 0.85));
            } catch (e) {
                finish(null);
            }
        });
        video.src = objectUrl;
    }
});

Q.Template.set('Safecloud/upload',
    '<div class="Safecloud_upload_tool">' +
        '<div class="Safecloud_upload_zone">' +
            '<div class="Safecloud_upload_icon">&#x2B21;</div>' +
            '<div class="Safecloud_upload_label">{{text.upload.DropLabel}}</div>' +
            '<div class="Safecloud_upload_sub">{{text.upload.DropSub}}</div>' +
            '<input class="Safecloud_upload_input" type="file"' +
                   ' accept="{{accept}}"' +
                   '{{#if multiple}} multiple{{/if}}' +
                   ' style="display:none">' +
        '</div>' +
        '<div class="Safecloud_upload_progress_row">' +
            '<div class="Safecloud_upload_progress">' +
                '<div class="Safecloud_upload_progress_fill"></div>' +
            '</div>' +
            '<div class="Safecloud_upload_progress_pct"></div>' +
        '</div>' +
        '<div class="Safecloud_upload_status"></div>' +
        '<div class="Safecloud_upload_noDrops" style="display:none">' +
            '<div class="Safecloud_upload_noDropsMessage">{{text.upload.NoDropsMessage}}</div>' +
            '<a class="Safecloud_upload_openDrop Q_button" href="{{dropUrl}}"' +
               ' target="_blank" rel="noopener">{{text.upload.OpenDropButton}}</a>' +
        '</div>' +
    '</div>'
);

// ── _waitForDrop — poll until a Drop is registered or timeout ────────────────
function _waitForDrop(timeoutMs, callback) {
    var elapsed = 0, interval = 300;
    (function check() {
        try {
            var s = Q.Safecloud.Drops
                 && Q.Safecloud.Drops._
                 && Q.Safecloud.Drops._._state;
            if (s && s.dropId) { return callback(); }
        } catch (e) {}
        elapsed += interval;
        if (elapsed >= timeoutMs) { return callback(); } // timeout — proceed anyway
        setTimeout(check, interval);
    }());
}

})(Q, Q.jQuery);
