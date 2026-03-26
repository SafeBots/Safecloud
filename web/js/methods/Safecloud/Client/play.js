/**
 * Q.Safecloud.Client.play — start playback and return a live handle.
 * Thin wrapper over stream() with seek-as-option ergonomics.
 * options.at → seek position in seconds (default 0).
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_play(videoManifest, capability, options) {
        options = Q.extend({}, options || {});
        if (options.at && options.at > 0) {
            var at = options.at;
            delete options.at;
            return Q.Safecloud.Client.stream(videoManifest, capability, options)
                .then(function (handle) {
                    handle.seek(at);
                    return handle;
                });
        }
        return Q.Safecloud.Client.stream(videoManifest, capability, options);
    };
});
