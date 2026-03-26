/**
 * Q.Safecloud.Drops.announce — build, sign, log and send a Safecloud/drop/announce.
 *
 * The entry is signed using _.canonicalJSON (Q.Data.canonicalize, RFC 8785)
 * over the entry with the signature field absent — matching the Jet's
 * verification logic.
 *
 * Sequence:
 *   1. Build entry from _._state
 *   2. Sign with P-256 session key → base64 r‖s
 *   3. Append to IndexedDB log (autoIncrement seq)
 *   4. Call Q.Safecloud.Jets.dropAnnounce
 *   5. Clear pendingDiff, update prevRoot
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_announce(reason, callback) {
        var now      = _.nowSec();
        var prevRoot = _._state.prevRoot   || null;
        var newRoot  = _._state.prollyRoot || null;
        var diff     = _._state.pendingDiff || null;

        // Collect bloom for cold/reset cases before building the payload
        var needsBloom = (reason === 'reset' || !newRoot);
        var bloomPromise = needsBloom
            ? Q.Safecloud.Drops.getBloomFilter()
            : Promise.resolve(null);

        var _promise = bloomPromise.then(function (bloomFilter) {
            // Build the announce payload — this is what we sign and send to the Jet.
            // The Jet's verifyAnnounce verifies this exact payload (minus signature).
            var announcePayload = {
                dropId:      _._state.dropId,
                timestamp:   now,
                storage:     { GB: Q.Config.get(['Safecloud', 'drop', 'storageGB'], 10) },
                used:        _._state.usedBytes || 0,
                prevRoot:    prevRoot,
                prollyRoot:  newRoot,
                diff:        diff,
                reason:      reason || null,
                bloomFilter: bloomFilter || null
            };

            // Sign the announce payload (without signature field) ✓
            var signPromise = _._state.sessionKey
                ? _.signAnnounce(announcePayload, _._state.sessionKey)
                : Promise.resolve(null);

            return signPromise.then(function (signature) {
                announcePayload.signature = signature;

                // Update in-memory state BEFORE persisting
                _._state.prevRoot    = newRoot;
                _._state.pendingDiff = null;

                // Append to IndexedDB log (log entry mirrors the announce payload)
                return _.openDB().then(function (db) {
                    var logEntry = {
                        timestamp: now,
                        prevRoot:  prevRoot,
                        newRoot:   newRoot,
                        diff:      diff,
                        reason:    reason || null,
                        signature: signature
                    };
                    return new Promise(function (resolve, reject) {
                        var tx  = db.transaction(_.STORES.log, 'readwrite');
                        var req = tx.objectStore(_.STORES.log).add(logEntry);
                        req.onsuccess = function () { resolve(); };
                        req.onerror   = function (e) { reject(e.target.error); };
                    });
                }).then(function () {
                    return Q.Safecloud.Jets.dropAnnounce(announcePayload);
                });
            });
        }).then(function () {
            if (callback) { callback(null); }
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
