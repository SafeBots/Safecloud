/**
 * Q.Safecloud.Drops.reset — clear all IndexedDB stores and announce reset.
 * Preserves delegation claim and session keypairs (those survive resets).
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_reset(callback) {
        var _promise = _.openDB().then(function (db) {
            return new Promise(function (resolve, reject) {
                var tx = db.transaction(
                    [_.STORES.chunks, _.STORES.lru, _.STORES.log, _.STORES.tokens],
                    'readwrite'
                );
                [_.STORES.chunks, _.STORES.lru, _.STORES.log, _.STORES.tokens].forEach(function (s) {
                    tx.objectStore(s).clear();
                });
                tx.oncomplete = function () { resolve(); };
                tx.onerror    = function (e) { reject(e.target.error); };
            });
        }).then(function () {
            // Reset all inventory state; preserve identity state
            // Clear sessionStorage wipe-detection hint so next init() doesn't
            // false-positive as an external wipe
            try { sessionStorage.removeItem('Q.Safecloud.Drops.lastRoot'); } catch(e) {}
            _._state.prollyRoot   = null;
            _._state.prevRoot     = null;
            _._state.pendingDiff  = null;
            _._state.bloomFilter  = null;
            _._state.usedBytes    = 0;
            _._state.prollyStore  = null; // rebuilt lazily
            _._state._dbPromise   = null; // reopen to pick up cleared stores

            // Only announce if registered with a Jet (dropId known)
            if (!_._state.dropId) { return Promise.resolve(); }
            return Q.Safecloud.Drops.announce('reset');
        }).then(function () {
            if (callback) { callback(null); }
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
