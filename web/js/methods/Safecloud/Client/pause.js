/**
 * Q.Safecloud.Client.pause — suspend an active streaming handle.
 * Equivalent to handle.pause().  Both forms are supported.
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_pause(handle) {
        if (handle && typeof handle.pause === 'function') {
            handle.pause();
        }
    };
});
