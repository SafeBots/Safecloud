(function (Q, $) {

/**
 * @module Safecloud
 */

/**
 * Encrypted video/audio player.
 *
 * Passes a native <video> element to Q.Safecloud.Client.stream(), which sets
 * its src to an HLS URL served by the Safecloud service worker.
 * The browser plays it natively — no Q/video wrapper needed.
 *
 * @class Safecloud video
 * @constructor
 * @param {Object} [options]
 *   @param {Object}  [options.manifest]    Manifest from Q.Safecloud.Client.store()
 *   @param {Object}  [options.capability]  { rootKey } or { grants }
 *   @param {String}  [options.jetUrl]      Jet server URL.
 *   @param {Number}  [options.at]          Start position in seconds.
 *   @param {Q.Event} [options.onLoad]      Fired when player is ready.
 *   @param {Q.Event} [options.onError]     Fired on error.
 */
Q.Tool.define('Safecloud/video', function (options) {
    var tool  = this;
    var state = tool.state;

        tool.text.video = Q.extend({
        Starting: 'Starting stream…',
        Error: 'Playback error',
        NoManifest: 'No content loaded'
    }, tool.text.video || {});

    if (state.jetUrl) { Q.Safecloud.Jets.url = state.jetUrl; }

    tool.refresh();
},

{
    manifest:   null,
    capability: null,
    jetUrl:     null,
    at:         0,
    onLoad:     new Q.Event(),
    onError:    new Q.Event(function (err) {
        console.warn('Safecloud/video error:', err);
    })
},

{
    refresh: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        Q.Template.render('Safecloud/video', {
            text: tool.text
        }, function (err, html) {
            if (err) return Q.handle(state.onError, tool, [err]);
            $te.html(html, true).activate(function () {
                if (state.manifest && state.capability) {
                    tool.startStream(state.manifest, state.capability);
                }
            });
        });
    },

    /**
     * Begin encrypted streaming.
     * stream() sets videoEl.src = HLS URL intercepted by the service worker.
     * @method startStream
     * @param {Object} manifest
     * @param {Object} capability  { rootKey } or { grants }
     */
    startStream: function (manifest, capability) {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        state.manifest   = manifest;
        state.capability = capability;

        tool.setStatus(
            Q.getObject('video.Starting', tool.text) || 'Starting…', 'working'
        );

        var mimeType = (manifest && manifest.type) || '';
        var isImage  = mimeType.indexOf('image/') === 0;

        if (isImage) {
            // Images: decrypt all bytes, show in <img>
            Q.Safecloud.Client.fetch(manifest, capability, {})
            .then(function (blob) {
                var url  = URL.createObjectURL(blob);
                var $wrap = $te.find('.Safecloud_video_wrap').empty().show();
                $('<img class="Safecloud_video_img">').attr('src', url)
                    .css({'max-width':'100%','display':'block'}).appendTo($wrap);
                tool.setStatus('', '');
                Q.handle(state.onLoad, tool, [{ url: url, path: 'image' }]);
            }).catch(function (err) {
                tool.setStatus(
                    (Q.getObject('video.Error', tool.text) || 'Error') +
                    ': ' + (err.message || String(err)), 'error');
                Q.handle(state.onError, tool, [err]);
            });
            return;
        }

        // Video or audio: stream into <video> element
        var videoEl = $te.find('.Safecloud_video_el')[0];
        if (!videoEl) { return; }

        Q.Safecloud.Client.stream(manifest, capability, {
            at:           state.at || 0,
            videoElement: videoEl
        }).then(function (handle) {
            tool._handle = handle;
            tool.setStatus('', '');
            $te.find('.Safecloud_video_wrap').show();
            Q.handle(state.onLoad, tool, [handle]);
            videoEl.play().catch(function () {});
        }).catch(function (err) {
            tool.setStatus(
                (Q.getObject('video.Error', tool.text) || 'Error') +
                ': ' + (err.message || String(err)), 'error');
            Q.handle(state.onError, tool, [err]);
        });
    },

    setStatus: function (msg, cls) {
        $(this.element).find('.Safecloud_video_status')
            .text(msg).removeClass('working ok error').addClass(cls || '');
    },

    play:  function () { var v = $(this.element).find('.Safecloud_video_el')[0]; v && v.play();  },
    pause: function () { var v = $(this.element).find('.Safecloud_video_el')[0]; v && v.pause(); },
    seek:  function (t){ var v = $(this.element).find('.Safecloud_video_el')[0];
                         if (v) v.currentTime = t; },

    Q: {
        beforeRemove: function () {
            if (this._handle) { try { this._handle.stop(); } catch(e) {} }
        }
    }
});

Q.Template.set('Safecloud/video',
    '<div class="Safecloud_video_tool">' +
        '<div class="Safecloud_video_status"></div>' +
        '<div class="Safecloud_video_wrap" style="display:none">' +
            '<video class="Safecloud_video_el" controls playsinline></video>' +
        '</div>' +
    '</div>'
);

})(Q, Q.jQuery);
