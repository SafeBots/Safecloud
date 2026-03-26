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
                    var timer = setTimeout(resolve, 3000);

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
