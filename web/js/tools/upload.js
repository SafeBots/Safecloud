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
 *   @param {Q.Event} [options.onStore]      Fired with (manifest, rootKey) after upload.
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
        Encrypting: 'Encrypting…',
        Uploaded: 'Uploaded',
        UploadFailed: 'Upload failed',
        WaitingForDrop: 'Waiting for storage node…'
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
            multiple: state.multiple
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

        tool.setStatus(
            Q.getObject('upload.Preparing', tool.text) || 'Preparing…', 'working');
        tool.setProgress(0);

        // Wait up to 8 s for a Drop to register before uploading.
        // Guards against the race where the user drops a file before
        // WebAuthn completes (same tab auto-init from demo.js).
        _waitForDrop(15000, function () {
            tool.setStatus(
                Q.getObject('upload.Encrypting', tool.text) || 'Encrypting…', 'working');

            Q.Safecloud.Client.store(
                { data: file, name: file.name, type: file.type },
                {
                    chunkSize: state.chunkSize,
                    onProgress: function (stored, total) {
                        var pct = Math.round(stored / total * 100);
                        tool.setProgress(pct);
                        Q.handle(state.onProgress, tool, [pct]);
                    }
                },
                function (err, result) {
                    if (err) {
                        tool.setStatus((Q.getObject('upload.UploadFailed', tool.text) || 'Upload failed') +
                            ': ' + (err.message || err), 'error');
                        return Q.handle(state.onError, tool, [err]);
                    }
                    tool.setStatus(
                        (Q.getObject('upload.Uploaded', tool.text) || 'Uploaded') + ': ' + file.name, 'ok');
                    tool.setProgress(100);
                    Q.handle(state.onStore, tool, [result.manifest, result.rootKey]);
                }
            );
        });
    },

    setStatus: function (msg, cls) {
        $(this.element).find('.Safecloud_upload_status')
            .text(msg).removeClass('working ok error').addClass(cls || '');
    },

    setProgress: function (pct) {
        $(this.element).find('.Safecloud_upload_progress_fill')
            .css('width', Math.min(pct, 100) + '%');
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
        '<div class="Safecloud_upload_progress">' +
            '<div class="Safecloud_upload_progress_fill"></div>' +
        '</div>' +
        '<div class="Safecloud_upload_status"></div>' +
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
