(function (Q, $) {

/**
 * Safecloud Player Tool
 * Handles file upload (store) and encrypted HLS playback via Q.Safecloud.Client
 *
 * Usage:
 *   Q.Tool.define('Safecloud/player', ...)  — see below
 *
 * @module Safecloud
 */

/**
 * Upload a file to Safecloud and play it back with encrypted HLS streaming.
 * @class Safecloud player
 * @constructor
 * @param {Object} [options]
 *   @param {String}  [options.rootCid]     CID of content to play (if already stored)
 *   @param {String}  [options.rootKey]     base64 root key (if owner)
 *   @param {Object}  [options.capability]  Grant capability (if grantee)
 *   @param {Object}  [options.manifest]    Manifest object (if already stored)
 *   @param {String}  [options.jetUrl]      Jet server URL
 *   @param {Boolean} [options.showUpload=true]  Whether to show upload UI
 *   @param {Q.Event} [options.onStore]     Fired after successful upload
 *   @param {Q.Event} [options.onError]     Fired on error
 */
Q.Tool.define('Safecloud/player', function (options) {
    var tool = this;
    var state = tool.state;

    // Connect to Jet if not already connected
    if (state.jetUrl) {
        Q.Safecloud.Jets.url = state.jetUrl;
    }
    Q.Safecloud.Jets.connect();

    tool.refresh();
},

/* Default state */
{
    rootCid:     null,
    rootKey:     null,
    capability:  null,
    manifest:    null,
    jetUrl:      null,
    showUpload:  true,
    chunkSize:   256 * 1024, // 256 KB
    onStore:  new Q.Event(),
    onError:  new Q.Event(function (err) {
        console.warn('Safecloud/player error:', err);
    })
},

/* Methods */
{
    refresh: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        Q.Template.render('Safecloud/player', {
            showUpload: state.showUpload,
            hasContent: !!(state.manifest && state.rootKey)
        }, function (err, html) {
            if (err) return Q.handle(state.onError, tool, [err]);
            $te.html(html, true).activate(function () {
                tool.addEvents();
                // If we already have content, start playing
                if (state.manifest && (state.rootKey || state.capability)) {
                    tool.startPlayback();
                }
            });
        }, tool.state.templates.main);
    },

    addEvents: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        // File picker → upload
        $te.on('change', '.Safecloud_player_file', function () {
            var file = this.files[0];
            if (!file) return;
            tool.storeFile(file);
        });

        // Drag & drop
        $te.on('dragover', '.Safecloud_player_dropzone', function (e) {
            e.preventDefault();
            $(this).addClass('Safecloud_player_dragover');
        }).on('dragleave', '.Safecloud_player_dropzone', function () {
            $(this).removeClass('Safecloud_player_dragover');
        }).on('drop', '.Safecloud_player_dropzone', function (e) {
            e.preventDefault();
            $(this).removeClass('Safecloud_player_dragover');
            var file = e.originalEvent.dataTransfer.files[0];
            if (file) tool.storeFile(file);
        });

        // Click dropzone → trigger file input
        $te.on(Q.Pointer.fastclick, '.Safecloud_player_dropzone', function () {
            $te.find('.Safecloud_player_file').click();
        });
    },

    storeFile: function (file) {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        tool.setStatus('Encrypting and uploading…', 'working');
        tool.setProgress(0);

        Q.Safecloud.Client.store(
            { data: file, name: file.name, type: file.type },
            {
                chunkSize: state.chunkSize,
                onProgress: function (stored, total) {
                    tool.setProgress(Math.round(stored / total * 100));
                }
            },
            function (err, result) {
                if (err) {
                    tool.setStatus('Upload failed: ' + (err.message || err), 'error');
                    return Q.handle(state.onError, tool, [err]);
                }

                state.manifest = result.manifest;
                state.rootKey  = result.rootKey;

                tool.setStatus('Uploaded! ' + file.name, 'ok');
                tool.setProgress(100);

                Q.handle(state.onStore, tool, [result]);

                // Start streaming playback
                setTimeout(function () {
                    tool.startPlayback();
                }, 500);
            }
        );
    },

    startPlayback: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        var manifest   = state.manifest;
        var capability = state.capability || (state.rootKey
            ? { rootKey: state.rootKey }
            : null);

        if (!manifest || !capability) {
            return tool.setStatus('Missing manifest or capability', 'error');
        }

        tool.setStatus('Starting playback…', 'working');

        var $videoEl = $te.find('.Safecloud_player_video');
        if (!$videoEl.length) return;

        // Use Q/video tool for playback (Safecloud SW path provides HLS URL)
        Q.Safecloud.Client.stream(manifest, capability, {
            videoElement: $videoEl[0]
        }).then(function (handle) {
            tool.handle = handle;
            tool.setStatus('Playing', 'ok');

            // stream.js already set videoElement.src = handle.url directly.
            // Show the video wrapper and try to play.
            $te.find('.Safecloud_player_video_wrap').addClass('Safecloud_active').show();
            $videoEl[0].play().catch(function () {
                // Autoplay blocked (requires user gesture) — that's fine,
                // controls are visible and user can press play.
            });
        }).catch(function (err) {
            tool.setStatus('Playback error: ' + err.message, 'error');
            Q.handle(state.onError, tool, [err]);
        });
    },

    setStatus: function (msg, cls) {
        var $s = $(this.element).find('.Safecloud_player_status');
        $s.text(msg).removeClass('working ok error').addClass(cls || '');
    },

    setProgress: function (pct) {
        $(this.element).find('.Safecloud_player_progress_fill')
            .css('width', Math.min(pct, 100) + '%');
    },

    Q: {
        beforeRemove: function () {
            if (this.handle) {
                try { this.handle.stop(); } catch(e) {}
            }
        }
    },

    templates: {
        main: {
            dir: '{{Safecloud}}/views',
            name: 'Safecloud/player/main',
            fields: {}
        }
    }
});

/* ── Template ─────────────────────────────────────────────── */

Q.Template.set('Safecloud/player/main',
  '<div class="Safecloud_player_tool">' +
  '{{#if showUpload}}' +
  '<div class="Safecloud_player_dropzone">' +
    '<div class="Safecloud_player_drop_icon">&#x2B21;</div>' +
    '<div class="Safecloud_player_drop_label">Drop a file here or click to upload</div>' +
    '<div class="Safecloud_player_drop_sub">Encrypted with AES-256-GCM &middot; Stored on Safecloud Drops</div>' +
    '<input type="file" class="Safecloud_player_file" accept="video/*,audio/*,image/*" style="display:none">' +
  '</div>' +
  '<div class="Safecloud_player_progress">' +
    '<div class="Safecloud_player_progress_fill"></div>' +
  '</div>' +
  '<div class="Safecloud_player_status"></div>' +
  '{{/if}}' +
  '<div class="Safecloud_player_video_wrap">' +
    '<video class="Safecloud_player_video" controls playsinline></video>' +
  '</div>' +
  '</div>'
);

})(Q, Q.jQuery);
