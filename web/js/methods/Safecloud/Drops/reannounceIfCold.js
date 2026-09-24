/**
 * Q.Safecloud.Drops.reannounceIfCold — full re-announce of everything this
 * Drop already has stored, if (and only if) the Jet just told us it has no
 * coverage record for this Drop ("cold").
 *
 * The Jet's Router._cidCoverage map (which rootCid GETs are actually routed
 * against) only ever learns about a CID from an announce's diff — nothing
 * walks the Prolly tree to reconstruct it server-side, and it's 100%
 * in-memory, so it's wiped by every Jet restart. Without resending the full
 * inventory after a cold registration, any content this Drop already stored
 * beforehand becomes permanently unroutable via GET ("No Drops available")
 * even though the chunks are still sitting right here in IndexedDB — nothing
 * short of a brand new PUT would ever tell the Jet about them again.
 *
 * Shared by both places a Drop can (re)register with the Jet:
 *   - Drops.init()'s own explicit registration (the original, user-triggered path)
 *   - Jets/connect.js's automatic re-registration after a socket reconnect —
 *     confirmed live as the actual gap: a Drop tab left open across a Jet
 *     restart auto-reconnects and auto-re-registers its identity, but used to
 *     silently discard the ack (including this exact cold flag) and never
 *     resent its content, permanently orphaning it until a fresh put() or a
 *     hard reload of that tab happened to go through Drops.init() instead.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_reannounceIfCold(cold) {
        if (!cold) { return Promise.resolve(); }
        return _.openDB().then(function (db) {
            return new Promise(function (resolve, reject) {
                var tx  = db.transaction(_.STORES.lru, 'readonly');
                var req = tx.objectStore(_.STORES.lru).getAllKeys();
                req.onsuccess = function (e) { resolve(e.target.result || []); };
                req.onerror   = function (e) { reject(e.target.error); };
            });
        }).then(function (cids) {
            if (cids.length) {
                _._state.pendingDiff = cids.map(function (cid) {
                    return { cid: cid, added: true };
                });
            }
            // Q.Safecloud.Drops.announce() handles signing, logging and sending.
            return Q.Safecloud.Drops.announce('cold');
        }).catch(function (err) {
            console.warn('Safecloud/Drops/reannounceIfCold: FAILED — '
                + 'previously stored content may be unroutable until the next put(): '
                + (err && err.stack || err));
        });
    };
});
