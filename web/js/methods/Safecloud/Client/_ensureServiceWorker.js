/**
 * Q.Safecloud.Client._ensureServiceWorker — register and wait for the HLS SW.
 *
 * Registers {{Safecloud}}/js/Safecloud/sw.js with scope '/'.
 * Requires the SW file to be served with: Service-Worker-Allowed: /
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

        var swUrl = Q.url('{{Safecloud}}/js/Safecloud/sw.js');

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

        _promise = navigator.serviceWorker.register(swUrl, { scope: '/' })
            .then(function (registration) {
                _registration = registration;

                // If already controlling the page, resolve immediately
                if (navigator.serviceWorker.controller) {
                    return;
                }

                // Otherwise wait for it to take control
                return new Promise(function (resolve) {
                    // Already active on another tab? controllerchange may never fire.
                    // Resolve after a timeout so streaming isn't blocked.
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
                    var timer = setTimeout(resolve, 8000);

                    navigator.serviceWorker.addEventListener('controllerchange', function onCC() {
                        navigator.serviceWorker.removeEventListener('controllerchange', onCC);
                        clearTimeout(timer);
                        resolve();
                    });

                    // If already activated and controlling, resolve immediately
                    var sw = registration.installing || registration.waiting || registration.active;
                    if (sw && sw.state === 'activated' && navigator.serviceWorker.controller) {
                        clearTimeout(timer);
                        resolve();
                    }
                });
            });

        return _promise;
    };
});
