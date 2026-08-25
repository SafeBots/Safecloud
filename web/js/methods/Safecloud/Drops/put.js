/**
 * Q.Safecloud.Drops.put — store encrypted chunks in IndexedDB.
 *
 * Per-chunk:
 *   1. Compute CID from concat(ciphertext bytes, tag bytes) via _.cidFromData
 *   2. Skip if already present (deduplication — update LRU access time only)
 *   3. Evict LRU chunks if quota exceeded (announce-before-evict protocol)
 *   4. Write to chunks + lru stores
 *
 * After batch:
 *   5. applyDiff → newRoot
 *   6. Append signed log entry + announce('stored')
 *   7. Update in-memory Bloom filter (add-only; rebuild on eviction)
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_put(chunks, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var MAX_BYTES = Q.Config.get(['Safecloud', 'drop', 'storageGB'], 10) * 1024 * 1024 * 1024;

        var _promise = _.openDB().then(function (db) {
            var results   = [];
            var batchDiff = [];

            // Process chunks sequentially to keep quota accounting consistent
            function next(i) {
                if (i >= chunks.length) { return Promise.resolve(); }
                var chunk = chunks[i];

                // Decode bytes for CID computation: SHA-256(ciphertext || tag)
                var ct  = Q.Data.fromBase64(chunk.ciphertext);
                var tg  = Q.Data.fromBase64(chunk.tag);
                var buf = new Uint8Array(ct.length + tg.length);
                buf.set(ct, 0);
                buf.set(tg, ct.length);

                return _.cidFromData(buf.buffer).then(function (computedCid) {
                    var cid = chunk.cid || computedCid;

                    // Reject if caller supplied a CID that doesn't match
                    if (chunk.cid && chunk.cid !== computedCid) {
                        results.push({ cid: chunk.cid, stored: false });
                        return next(i + 1);
                    }

                    // Deduplication check
                    return _idbGet(db, _.STORES.chunks, _.chunkKey(cid))
                        .then(function (existing) {
                            if (existing) {
                                // Already stored — just refresh LRU
                                return _idbPut(db, _.STORES.lru, {
                                    cid:          cid,
                                    size:         existing.size || ct.length,
                                    lastAccessed: _.nowSec()
                                }).then(function () {
                                    results.push({ cid: cid, stored: true, iv: chunk.iv, size: existing.size });
                                    return next(i + 1);
                                });
                            }

                            var chunkSize = chunk.size || ct.length;

                            // Quota check — evict before writing
                            return _evictIfNeeded(db, chunkSize, MAX_BYTES).then(function () {
                                var now = _.nowSec();
                                var record = {
                                    cid:        cid,
                                    iv:         chunk.iv,
                                    ciphertext: chunk.ciphertext,
                                    tag:        chunk.tag,
                                    size:       chunkSize,
                                    storedAt:   now
                                };
                                var lruRecord = { cid: cid, size: chunkSize, lastAccessed: now };

                                // Write chunk and lru in one transaction
                                return new Promise(function (resolve, reject) {
                                    var tx = db.transaction([_.STORES.chunks, _.STORES.lru], 'readwrite');
                                    tx.objectStore(_.STORES.chunks).put(record);
                                    tx.objectStore(_.STORES.lru).put(lruRecord);
                                    tx.oncomplete = function () { resolve(); };
                                    tx.onerror    = function (e) { reject(e.target.error); };
                                });
                            }).then(function () {
                                _._state.usedBytes    = (_._state.usedBytes    || 0) + chunkSize;
                                _._state.storedChunks = (_._state.storedChunks || 0) + 1;
                                _.logActivity('put', { bytes: chunkSize });
                                batchDiff.push({ cid: cid, added: true });

                                // Incremental Bloom update (add-only — eviction rebuilds)
                                var Bloom = Q.Data && Q.Data.Bloom;
                                if (_._state.bloomFilter && Bloom &&
                                    typeof _._state.bloomFilter.add === 'function') {
                                    _._state.bloomFilter.add(cid);
                                } else {
                                    _._state.bloomFilter = null; // will rebuild on next get
                                }

                                results.push({ cid: cid, stored: true, iv: chunk.iv, size: chunkSize });
                                return next(i + 1);
                            });
                        });
                });
            }

            return next(0).then(function () {
                if (!batchDiff.length) {
                    return { results: results };
                }
                // Update Prolly root and announce
                var prevRoot = _._state.prollyRoot;
                return _.applyDiff(prevRoot, batchDiff).then(function (newRoot) {
                    _._state.prevRoot    = prevRoot;
                    _._state.prollyRoot  = newRoot;
                    _._state.pendingDiff = batchDiff;
                    return Q.Safecloud.Drops.announce('stored').catch(function () {});
                }).then(function () {
                    return { results: results };
                });
            });
        });

        if (!callback) { return _promise; }
        _promise.then(function (r) { callback(null, r); })
                .catch(function (e) { callback(e); });
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    function _idbGet(db, storeName, key) {
        return new Promise(function (resolve, reject) {
            var tx  = db.transaction(storeName, 'readonly');
            var req = tx.objectStore(storeName).get(key);
            req.onsuccess = function (e) { resolve(e.target.result || null); };
            req.onerror   = function (e) { reject(e.target.error); };
        });
    }

    function _idbPut(db, storeName, value) {
        return new Promise(function (resolve, reject) {
            var tx  = db.transaction(storeName, 'readwrite');
            var req = tx.objectStore(storeName).put(value);
            req.onsuccess = function () { resolve(); };
            req.onerror   = function (e) { reject(e.target.error); };
        });
    }

    function _evictIfNeeded(db, needed, maxBytes) {
        // Read all LRU records sorted by lastAccessed (ascending = oldest first)
        return new Promise(function (resolve, reject) {
            var tx    = db.transaction(_.STORES.lru, 'readonly');
            var index = tx.objectStore(_.STORES.lru).index('lastAccessed');
            var req   = index.openCursor(); // ascending by default
            var all   = [], used = 0;
            req.onsuccess = function (e) {
                var cur = e.target.result;
                if (cur) {
                    all.push(cur.value);
                    used += cur.value.size || 0;
                    cur.continue();
                } else {
                    resolve({ used: used, lru: all });
                }
            };
            req.onerror = function (e) { reject(e.target.error); };
        }).then(function (info) {
            if (info.used + needed <= maxBytes) { return; }

            var toEvict = [], freed = 0;
            for (var i = 0; i < info.lru.length; i++) {
                if (info.used - freed + needed <= maxBytes) { break; }
                toEvict.push(info.lru[i]);
                freed += info.lru[i].size || 0;
            }
            if (!toEvict.length) { return; }

            // Announce-before-evict: sign + send announce with eviction diff FIRST
            var evictDiff = toEvict.map(function (r) { return { cid: r.cid, added: false }; });
            var prevRoot  = _._state.prollyRoot;

            return _.applyDiff(prevRoot, evictDiff).then(function (newRoot) {
                _._state.prevRoot    = prevRoot;
                _._state.prollyRoot  = newRoot;
                _._state.pendingDiff = evictDiff;
                _._state.bloomFilter = null; // must rebuild after eviction
                return Q.Safecloud.Drops.announce('eviction').catch(function () {});
            }).then(function () {
                // Safe to delete now — Jet has the updated root
                return new Promise(function (resolve, reject) {
                    var tx = db.transaction([_.STORES.chunks, _.STORES.lru], 'readwrite');
                    toEvict.forEach(function (r) {
                        tx.objectStore(_.STORES.chunks).delete(_.chunkKey(r.cid));
                        tx.objectStore(_.STORES.lru).delete(_.lruKey(r.cid));
                        _._state.usedBytes = Math.max(0, (_._state.usedBytes || 0) - (r.size || 0));
                    });
                    tx.oncomplete = function () { resolve(); };
                    tx.onerror    = function (e) { reject(e.target.error); };
                });
            });
        });
    }
});
