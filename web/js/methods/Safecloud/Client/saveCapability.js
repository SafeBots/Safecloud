/**
 * Q.Safecloud.Client.saveCapability — persist { manifest, capability } by rootCid.
 *
 * Enables:
 *   - refresh-safe playback (demo page, share-link arrivals)
 *   - iframe embeds in a pristine environment: the embed page calls
 *     Client.loadCapability(rootCid) and streams with no keys in the URL
 *
 * The capability contains decryption secrets — it never leaves this origin's
 * IndexedDB. Callers decide which origin (e.g. a sandboxed player origin)
 * should hold it.
 *
 * @param {String}   rootCid
 * @param {Object}   data      { manifest, capability }
 * @param {Function} [callback]
 * @return {Promise<void>}
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_saveCapability(rootCid, data, callback) {
        var _promise;
        if (!rootCid || !data || !data.manifest) {
            _promise = Promise.reject(new Error(
                'Q.Safecloud.Client.saveCapability: rootCid and data.manifest required'));
        } else {
            _promise = _.clientDbPut(_.CLIENT_STORES.capabilities, rootCid, {
                rootCid:    rootCid,
                manifest:   data.manifest,
                capability: data.capability || null,
                savedAt:    Date.now()
            });
        }
        if (!callback) { return _promise; }
        _promise.then(function () { callback(null); }, function (e) { callback(e); });
    };
});
