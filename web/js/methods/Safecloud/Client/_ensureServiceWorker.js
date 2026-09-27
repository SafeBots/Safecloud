/**
 * Q.Safecloud.Client._ensureServiceWorker — register and wait for the HLS SW.
 *
 * Registers /SafecloudServiceWorker.js with scope '/'.
 * The Safecloud plugin installer symlinks this file from
 * APP_WEB_DIR/SafecloudServiceWorker.js → Q/plugins/Safecloud/js/Safecloud/sw.js
 * so the script's natural max scope is '/' without needing a
 * Service-Worker-Allowed header. This is required because pages outside the
 * plugin path (e.g. /clip/...) use the Safecloud/video tool, which needs the
 * SW to intercept their fetches for decrypted HLS segments.
 *
 * Idempotent — caches the promise; repeat calls resolve immediately.
 */

Q.exports(function (Q, _) {
    var _registration = null;
    var _promise      = null;

    return function Q_Safecloud_Client__ensureServiceWorker() {
        if (_promise) { return _promise; }

        if (!('serviceWorker' in navigator)) {
            _promise = Promise.reject(new Error(
                'Q.Safecloud.Client._ensureServiceWorker: Service Workers not supported'
            ));
            return _promise;
        }

        var swUrl = Q.url('SafecloudServiceWorker.js');

        // Forward the SW's own diagnostic messages (sw.js's _notifyClients)
        // into this page's console — a service worker's console is a
        // separate devtools context almost nobody opens, so without this,
        // a fetch the SW couldn't serve (session not found, segment not
        // yet available) left zero trace anywhere the page-side stall/
        // hls.js diagnostics could see. Attached once, before register()
        // resolves, so nothing that arrives during activation is missed.
        navigator.serviceWorker.addEventListener('message', function (event) {
            var msg = event.data;
            if (!msg || msg.type !== 'Q.Safecloud.sw.diagnostic') { return; }
            console.info('Q.Safecloud.sw: ' + msg.event + ' ' + JSON.stringify(msg));
        });

        // Q.js's own core service worker (Q_Uri::serviceWorkerURL() =
        // baseUrl() + '/Q-ServiceWorker', registered with no explicit scope
        // — see Q.ServiceWorker.start()) defaults to scope '/' too, the
        // exact same scope this file now uses (moved here from a
        // plugin-subdirectory scope specifically to fix a
        // Service-Worker-Allowed error — see git history). Two different
        // scripts can't both control scope '/' at once: whichever
        // registered (and activated) FIRST wins control of a given page
        // until the other's skipWaiting()+clients.claim() (sw.js has both)
        // fires a controllerchange. On a fresh/incognito load, Q's own core
        // SW is registered unconditionally during app init — well before
        // this ever runs — so `navigator.serviceWorker.controller` is
        // already truthy by the time we get here, but it's THE WRONG
        // WORKER. Checking mere truthiness (as this used to) treated that
        // as "ready," let hls.js issue its manifest fetch, and Q's own core
        // SW — which has no idea what safecloud-hls.local means — let it
        // fall through to the real network: confirmed live as
        // net::ERR_NAME_NOT_RESOLVED (plus Chrome's "local network access"
        // prompt, triggered by the .local TLD heuristic on that now-real
        // request). Must compare scriptURL, not just check for *a* controller.
        function _isOurs() {
            var c = navigator.serviceWorker.controller;
            return !!(c && c.scriptURL === swUrl);
        }

        // Resolves with true once sw.js (specifically) controls the page,
        // or false if the 8s timeout below elapsed without that happening
        // — callers must check this instead of just
        // `navigator.serviceWorker.controller` truthiness, which is also
        // true whenever Q's own core SW controls the page instead (see
        // _isOurs()'s comment above).
        _promise = navigator.serviceWorker.register(swUrl, { scope: '/' })
            .then(function (registration) {
                _registration = registration;

                // Already controlling the page (our own script specifically). Resolve immediately.
                if (_isOurs()) {
                    return true;
                }

                // Otherwise wait for OUR registration specifically to take
                // control — sw.js's own install/activate handlers call
                // skipWaiting()+clients.claim(), so once it's actually
                // installed this fires promptly; re-check identity on every
                // controllerchange rather than resolving on the first one,
                // since Q's core SW updating itself also fires this event
                // without ever making sw.js the controller.
                return new Promise(function (resolve) {
                    // Resolve after a timeout so streaming isn't blocked
                    // forever if sw.js genuinely never takes control.
                    //
                    // 3000ms was too tight: demo.js calls this at page load as
                    // a warm-up (fire-and-forget), and _streamSW re-calls it
                    // (idempotent, same cached promise) right when playback
                    // is actually requested — but a FAST/small upload (e.g.
                    // ~10MB / 18 chunks) can finish encrypting+uploading in
                    // well under 3s, meaning register→install→activate→
                    // clients.claim() genuinely hadn't finished yet, this
                    // promise gave up right on schedule, and playback fell
                    // back to the (non-HLS) blob path — confirmed live: the
                    // exact "SW not controlling page, falling back" log line
                    // fired for a fast upload even with the warm-up call in
                    // place. Slow uploads (which is why the race was ever
                    // survivable at all before) had accidentally been giving
                    // this enough head start; fast ones hadn't. 8000ms
                    // covers realistic activation latency with margin, at
                    // the cost of a longer wait only in the rare case the SW
                    // truly never takes control.
                    var timer = setTimeout(function () { resolve(_isOurs()); }, 8000);

                    navigator.serviceWorker.addEventListener('controllerchange', function onCC() {
                        if (!_isOurs()) { return; }
                        navigator.serviceWorker.removeEventListener('controllerchange', onCC);
                        clearTimeout(timer);
                        resolve(true);
                    });

                    // If already activated and controlling (our script specifically), resolve immediately
                    var sw = registration.installing || registration.waiting || registration.active;
                    if (sw && sw.state === 'activated' && _isOurs()) {
                        clearTimeout(timer);
                        resolve(true);
                    }
                });
            });

        return _promise;
    };
});
