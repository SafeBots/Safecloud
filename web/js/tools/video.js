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

    tool._startStallTimer = null;

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
    // Seconds between onPlaying firings while playing — same option name/
    // meaning as Q/video's state.positionUpdatePeriod, since Media/clip.js's
    // watchClip() reads it directly off whichever video tool is playing.
    positionUpdatePeriod: 5,
    // How long to wait after calling play() for the 'playing' event before
    // logging a start-stall diagnostic (see startStream).
    startStallMs: 10000,
    onLoad:     new Q.Event(),
    onPlay:     new Q.Event(),
    onPlaying:  new Q.Event(),
    onStall:    new Q.Event(),
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

        // Stop any previous stream first — e.g. the demo page calls
        // startStream() again if the user uploads a second file without
        // reloading. Without this, the old _prefetchLoop/hls.js instance
        // was never told to stop and just kept running orphaned (still
        // polling the Jet, still attached to hls.js internals) alongside
        // the new one. The sibling Q/video.js adapter already guards this;
        // this tool (the one actually in use) didn't.
        if (tool._handle) {
            try { tool._handle.stop(); } catch (e) {}
            tool._handle = null;
        }

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

            // Media/clip.js's watchClip()/joinClip() (credit-earning watch
            // timer + joining the episode's Media/channel/* stream) rely on
            // onPlaying/onPlay firing the same way Q/video's do — this tool
            // had neither before, so a safecloud clip silently never
            // triggered either.
            //
            // The billing interval is gated on 'playing'/'waiting', not on
            // 'play': the DOM 'play' event fires as soon as .play() is
            // called, even while readyState has no data yet (the spinner
            // case), whereas 'playing' only fires once frames are actually
            // rendering. Starting the per-minute charge timer on 'play'
            // meant a stalled prefetch (e.g. the Jet/Drop socket loop
            // getting starved by background-tab throttling) kept billing
            // the viewer for a video that was never actually playing —
            // confirmed live via a stuck spinner with active per-minute
            // deductions. 'waiting' fires the moment playback stalls for
            // lack of data, so it also stops the timer immediately when a
            // previously-playing video re-buffers, not just on pause.
            videoEl.addEventListener('play', function () {
                Q.handle(state.onPlay, tool);
            });
            videoEl.addEventListener('playing', function () {
                tool._everPlayed = true;
                clearTimeout(tool._startStallTimer);
                tool._clearPlayInterval();
                tool._playIntervalId = setInterval(function () {
                    Q.handle(state.onPlaying, tool, [tool]);
                }, (state.positionUpdatePeriod || 5) * 1000);
            });
            videoEl.addEventListener('waiting', function () {
                tool._clearPlayInterval();
            });

            // The reported "player appears, loader just spins, no video
            // loads" case: 'playing' never fires at all — 'waiting' does
            // (or nothing does, if the video can't even get that far), so
            // there's no natural event to hang a diagnostic off. This is
            // the one case the billing fix above doesn't touch (billing was
            // already correctly never starting), and until now it left
            // zero trace anywhere unless devtools happened to be open with
            // the Network tab already recording. Logs once, with the same
            // per-content + connection-wide stats _prefetchLoop's own stall
            // log uses, so a report like "it hung" has something to check
            // after the fact.
            tool._startStallTimer = setTimeout(function () {
                if (tool._everPlayed) { return; }
                console.warn('Safecloud/video: playback never started within '
                    + (state.startStallMs / 1000) + 's of calling play() — '
                    + 'likely the Drop storing this content is slow or unreachable. '
                    + JSON.stringify({
                        readyState:     videoEl.readyState,
                        networkState:   videoEl.networkState,
                        documentHidden: (typeof document !== 'undefined') && document.hidden,
                        prefetch:       handle.stats ? handle.stats() : null
                    }));
                Q.handle(state.onStall, tool, [{ phase: 'start' }]);
            }, state.startStallMs || 10000);
            videoEl.addEventListener('pause', function () {
                tool._clearPlayInterval();
            });

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

    _clearPlayInterval: function () {
        if (this._playIntervalId) {
            clearInterval(this._playIntervalId);
            this._playIntervalId = null;
        }
    },

    Q: {
        beforeRemove: function () {
            this._clearPlayInterval();
            clearTimeout(this._startStallTimer);
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
