/**
 * Q.Safecloud.Jets.checkAvailable — lightweight pre-flight check for whether
 * any Drop is currently online to serve a given rootCid, WITHOUT actually
 * fetching content (no grants/access/payment checks, no chunk transfer).
 *
 * Meant for callers that need to know playback could succeed BEFORE
 * committing to something irreversible — e.g. a paywall charging credits —
 * so they don't charge a user only to hit "No Drops available" once they
 * actually try to play the video.
 *
 * Emits Safecloud/subtree/checkAvailable with { rootCid }.
 *
 * @param {String} rootCid
 * @param {Function} [callback]  (err, { available: Boolean })
 * @return {Q.Promise}
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_checkAvailable(rootCid, callback) {
        return _.emit('Safecloud/subtree/checkAvailable', { rootCid: rootCid })
            .then(function (result) {
                if (callback) { callback(null, result); }
                return result;
            })
            .catch(function (err) {
                // Treat a check failure (timeout, disconnected Jet, etc.) as
                // "unknown" rather than "definitely unavailable" — the caller
                // decides how to handle that; we don't want a flaky check to
                // permanently block a legitimate purchase.
                if (callback) { callback(err); }
                throw err;
            });
    };
});
