/**
 * Q.Safecloud.Drops.getBloomFilter — return serialised Bloom filter (base64).
 * Returns in-memory copy if valid; rebuilds from IndexedDB lru store otherwise.
 * Returns null if no chunks are stored.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_getBloomFilter(callback) {
        var Bloom = Q.Data && Q.Data.Bloom;

        // Valid in-memory filter — serialize and return
        if (_._state.bloomFilter && Bloom && typeof _._state.bloomFilter.serialize === 'function') {
            var b64 = _._state.bloomFilter.serialize();
            if (callback) { callback(null, b64); }
            return Promise.resolve(b64);
        }

        // Rebuild from all CID keys in the lru store
        var _promise = _.openDB().then(function (db) {
            return new Promise(function (resolve, reject) {
                var tx  = db.transaction(_.STORES.lru, 'readonly');
                var req = tx.objectStore(_.STORES.lru).getAllKeys();
                req.onsuccess = function (e) { resolve(e.target.result || []); };
                req.onerror   = function (e) { reject(e.target.error); };
            });
        }).then(function (cids) {
            return _.buildBloom(cids);
        }).then(function (b64) {
            if (callback) { callback(null, b64); }
            return b64;
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
