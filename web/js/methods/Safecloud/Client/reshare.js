/**
 * Q.Safecloud.Client.reshare — become a temporary Drop.
 * Stores received encrypted chunks in local IndexedDB via Q.Safecloud.Drops.put,
 * then announces the updated inventory to Jets via Q.Safecloud.Jets.dropAnnounce.
 * Never decrypts — only operates on already-encrypted chunks.
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_reshare(chunks, options, callback) {
        if (typeof options === 'function') {
            callback = options;
            options  = {};
        }
        options = options || {};

        var _promise = Q.Safecloud.Drops.put(chunks, {
            authorizations: options.authorizations,
            payments:       options.payments
        }).then(function (putResult) {
            var stored = (putResult.results || []).filter(function (r) { return r && r.cid; }).length;

            return Q.Safecloud.Drops.getProllyRoot().then(function (prollyRoot) {
                return Q.Safecloud.Drops.getBloomFilter().then(function (bloomFilter) {
                    return Q.Safecloud.Jets.dropAnnounce({
                        storage:     { GB: Q.Config.get(['Safecloud', 'drop', 'storageGB'], 10) },
                        used:        0, // Drops.put tracks this internally
                        prollyRoot:  prollyRoot,
                        bloomFilter: bloomFilter || null
                    });
                });
            }).then(function () {
                var result = { announced: stored };
                if (callback) { callback(null, result); }
                return result;
            });
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
