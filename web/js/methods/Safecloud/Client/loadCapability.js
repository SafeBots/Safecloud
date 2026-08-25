/**
 * Q.Safecloud.Client.loadCapability — load { manifest, capability } by rootCid.
 *
 * Returns null when nothing is saved (callers fall back to URL-provided keys
 * or show an "access needed" state).
 *
 * @param {String}   rootCid
 * @param {Function} [callback]
 * @return {Promise<{ rootCid, manifest, capability, savedAt }|null>}
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_loadCapability(rootCid, callback) {
        var _promise = rootCid
            ? _.clientDbGet(_.CLIENT_STORES.capabilities, rootCid)
            : Promise.resolve(null);
        if (!callback) { return _promise; }
        _promise.then(function (r) { callback(null, r); }, function (e) { callback(e); });
    };
});
