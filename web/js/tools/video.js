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
 *   @param {Q.Event} [options.onTeaserEnd] Fired when playback reaches the end
 *     of a teaser (grant-limited) capability's granted range — video is
 *     paused automatically just before this fires. See Client/stream.js's
 *     hls.js error handler (checks for the SW's 403 "no grant" response).
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
    // Pause and fire onTeaserEnd once currentTime reaches this — a
    // grant's own coverage is chunk-rounded (Client/grant.js widens
    // [clipStart, clipEnd) out to whole chunk boundaries), so relying on
    // the SW/prefetch loop simply running out of granted chunks lets
    // playback run a couple of seconds past the intended cutoff. Only
    // meaningful together with a grant-limited (not rootKey) capability.
    stopAt:     null,
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
    onTeaserEnd: new Q.Event(),
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

        // Shared by two independent triggers below: the grant-boundary
        // detectors inside Q.Safecloud.Client.stream() itself (a real
        // "no grant past here" rejection), and the state.stopAt
        // 'timeupdate' watchdog just below (currentTime reaching the
        // range's end on the nose, regardless of how far the underlying
        // grant's own chunk-rounded coverage actually extends). Guarded
        // so reaching both around the same moment doesn't pause twice or
        // fire state.onTeaserEnd twice.
        var teaserEndFired = false;
        function _fireTeaserEnd() {
            // tool._removed (set in the Q.beforeRemove hook below) guards
            // against a STALE tool instance from a column that's since been
            // replaced/closed still firing this — confirmed live: Q/columns
            // doesn't necessarily tear down a replaced column's tools
            // synchronously (or at all, in a push-alongside layout), and
            // videoEl.pause() below don't retroactively stop a 'timeupdate'
            // that's already in flight from before this tool was torn down
            // — a shared clip's Safecloud/video tool kept running in the
            // background after the viewer navigated to the full episode in
            // its place, and once its stopAt boundary was reached, popped
            // the "end of clip" dialog on top of the now-unrelated full-
            // episode page.
            if (teaserEndFired || tool._removed) { return; }
            teaserEndFired = true;
            videoEl.pause();
            Q.handle(state.onTeaserEnd, tool);
        }

        Q.Safecloud.Client.stream(manifest, capability, {
            at:           state.at || 0,
            videoElement: videoEl,
            onTeaserEnd: _fireTeaserEnd
        }).then(function (handle) {
            tool._handle = handle;
            tool.setStatus('', '');
            $te.find('.Safecloud_video_wrap').show();
            Q.handle(state.onLoad, tool, [handle]);

            // Q's multi-column UI (Q/columns push()) keeps a previous
            // column's DOM and tools alive when a new column is pushed
            // alongside it, rather than destroying them — so navigating
            // from one Safecloud clip to another left the FIRST clip's
            // video tool (and its _prefetchLoop) fully alive and still
            // fetching in the background. Confirmed live: two different
            // videoIds streaming concurrently, both hammering the shared
            // Q.Safecloud.Jets connection until requests started timing
            // out for both, killing playback on both. _prefetchLoop's own
            // tick() already skips fetching further segments whenever the
            // video element is paused (see its videoElement.paused check)
            // — pausing playback the moment this tool's element scrolls or
            // gets covered out of view is enough to make that existing
            // guard kick in, so a background/covered column stops
            // competing for bandwidth entirely instead of needing its own
            // separate stop/resume plumbing.
            if ('IntersectionObserver' in window) {
                tool._visibilityObserver = new IntersectionObserver(function (entries) {
                    var entry = entries[entries.length - 1];
                    if (!entry.isIntersecting && !videoEl.paused) {
                        videoEl.pause();
                    }
                }, { threshold: 0 });
                tool._visibilityObserver.observe(tool.element);
            }

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
                // Clears whatever the start-stall watchdog above showed if
                // this fires later than startStallMs (e.g. the Drop
                // reconnected on its own after the "isn't starting" message
                // was already shown) — otherwise that error text would sit
                // there indefinitely even once playback genuinely recovers.
                if (!tool._everPlayed) { tool.setStatus('', ''); }
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

            // Nothing wired the native <video controls> scrub bar (or any
            // other direct currentTime jump) to handle.seek() before this —
            // confirmed live: clicking the timeline ahead of what's been
            // prefetched left _prefetchLoop to notice the jump only
            // passively, on its own next ~1s tick (via its "current >
            // frontier" catch-up), which just abandons everything between
            // the old and new position rather than fetching it, AND never
            // tells the service worker to reset/prune its segment cache
            // (that's what the explicit 'seek' postMessage is for) — so
            // hls.js's own request for a segment in that abandoned gap
            // 503'd with nothing ever going to arrive for it. 'seeking'
            // fires for both a user drag and a programmatic currentTime
            // set, so this covers handle.seek() callers too (calling
            // seek() twice for the same jump is harmless — it's cheap and
            // idempotent).
            videoEl.addEventListener('seeking', function () {
                if (tool._handle && tool._handle.seek) {
                    tool._handle.seek(videoEl.currentTime);
                }
            });

            if (state.stopAt) {
                videoEl.addEventListener('timeupdate', function () {
                    if (videoEl.currentTime >= state.stopAt) {
                        _fireTeaserEnd();
                    }
                });
            }

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
                var diagnostics = {
                    readyState:     videoEl.readyState,
                    networkState:   videoEl.networkState,
                    documentHidden: (typeof document !== 'undefined') && document.hidden,
                    prefetch:       handle.stats ? handle.stats() : null
                };
                console.warn('Safecloud/video: playback never started within '
                    + (state.startStallMs / 1000) + 's of calling play() — '
                    + 'likely the Drop storing this content is slow or unreachable. '
                    + JSON.stringify(diagnostics));
                // Until now this only logged to console — clearing the
                // "Starting…" status as soon as Q.Safecloud.Client.stream()'s
                // setup promise resolved (which happens immediately, well
                // before any actual segment arrives) left NOTHING visible in
                // the UI when the underlying fetch loop can't get any data
                // at all (e.g. "No Drops available to serve this content" —
                // a real, reachable failure, not a slow-but-working one):
                // just the native <video> element's own indefinite loading
                // spinner, with no indication anything had actually gone
                // wrong or that it wouldn't eventually resolve on its own.
                tool.setStatus(
                    Q.getObject('video.StartStalled', tool.text)
                        || 'Playback isn’t starting — this content may be temporarily unavailable.',
                    'error'
                );
                Q.handle(state.onStall, tool, [{ phase: 'start', diagnostics: diagnostics }]);
            }, state.startStallMs || 10000);
            videoEl.addEventListener('pause', function () {
                tool._clearPlayInterval();
            });

            // Browsers (Chrome especially) block unmuted autoplay without
            // an established Media Engagement Index for this origin — a
            // fresh/incognito profile always fails this, silently rejecting
            // play() and leaving the element paused forever. Since nothing
            // caught that rejection before, videoElement.paused just stayed
            // true — and _prefetchLoop's own tick() deliberately defers
            // fetching entirely while paused (unless prefetchWhenPaused),
            // so NO chunk ever got fetched at all: confirmed live via
            // Q.Safecloud.Jets.connectionStats() showing only the one
            // index-track request, zero for any data segment. Autoplay
            // muted is allowed everywhere; retry that way rather than
            // leaving the viewer stuck on an endless spinner with no
            // indication anything needs a click.
            videoEl.play().catch(function () {
                videoEl.muted = true;
                return videoEl.play();
            }).catch(function (err) {
                console.warn('Safecloud/video: autoplay (even muted) was blocked — '
                    + 'playback will need an explicit tap/click on the controls.', err);
            });
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

    // Milliseconds — matches Q/video's own getCurrentPosition() exactly
    // (Math.floor(currentTime * 1000)), NOT videoEl.currentTime's native
    // seconds. Media/clip/preview.js's "create a clip" composer feeds this
    // straight into Q.displayDuration() and Q/clip's setPosition(), both
    // of which — like Q/video's callers throughout this codebase — assume
    // milliseconds; confirmed live: returning seconds here made every
    // clip-boundary time display as "00:00" regardless of the real
    // position (Q.displayDuration divides by 1000 internally, so a ~65s
    // position read as 0.065s and floored to zero), even though the
    // underlying Q_clip_position value it was computed from was correct.
    getCurrentPosition: function () {
        var v = $(this.element).find('.Safecloud_video_el')[0];
        return v ? Math.floor(v.currentTime * 1000) : 0;
    },
    getDuration: function () {
        var v = $(this.element).find('.Safecloud_video_el')[0];
        return (v && isFinite(v.duration)) ? v.duration : 0;
    },

    _clearPlayInterval: function () {
        if (this._playIntervalId) {
            clearInterval(this._playIntervalId);
            this._playIntervalId = null;
        }
    },

    Q: {
        beforeRemove: function () {
            this._removed = true;
            this._clearPlayInterval();
            clearTimeout(this._startStallTimer);
            if (this._visibilityObserver) { this._visibilityObserver.disconnect(); }
            if (this._handle) { try { this._handle.stop(); } catch(e) {} }
            // Without this, a still-playing (merely detached/covered, not
            // actually stopped) <video> element keeps firing 'timeupdate'
            // on itself indefinitely — see _fireTeaserEnd's own comment on
            // what that caused live. Pausing is what actually stops those
            // events; _removed above is the belt-and-suspenders backstop
            // for whatever's already in flight at the moment this runs.
            var v = $(this.element).find('.Safecloud_video_el')[0];
            if (v) { try { v.pause(); } catch (e) {} }
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
