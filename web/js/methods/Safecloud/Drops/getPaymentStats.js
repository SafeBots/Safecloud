/**
 * Q.Safecloud.Drops.getPaymentStats — payment-token statistics from IndexedDB.
 *
 * Complements the synchronous getStats(): safebuxEarned there is a served-MB
 * *estimate*; this reads the actual unredeemed tokens the Drop can claim.
 *
 * @method getPaymentStats
 * @param {Function} [callback]
 * @return {Promise<{
 *   tokens        {Number}   unredeemed token count
 *   totalWei      {String}   sum of token stm.max (decimal string)
 *   totalSbux     {Number}   totalWei / 1e6 (Safebux has 6 decimals)
 *   thresholdWei  {String}   claim threshold in wei
 *   claimable     {Boolean}  totalWei >= thresholdWei && tokens > 0
 * }>}
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_getPaymentStats(callback) {
        var threshold = String(_.jetInfo(['drop', 'claimThresholdSafebux'],
            ['Safecloud', 'drop', 'claimThresholdSafebux'], '100000'));

        var _promise = _.openDB().then(function (db) {
            return new Promise(function (resolve, reject) {
                var tx    = db.transaction(_.STORES.tokens, 'readonly');
                var index = tx.objectStore(_.STORES.tokens).index('redeemed');
                var req   = index.getAll(IDBKeyRange.only(false));
                req.onsuccess = function (e) { resolve(e.target.result || []); };
                req.onerror   = function (e) { reject(e.target.error); };
            });
        }).then(function (records) {
            // Watermark semantics: claims per (payer, line) are cumulative
            // ceilings, not additive amounts. Claimable = the LATEST
            // watermark per channel, summed across channels. (On-chain spent
            // reduces this further; the direct claim path checks that.)
            var channels = {};
            records.forEach(function (r) {
                var stm = r && r.token && r.token.stm;
                if (!stm || !stm.max) { return; }
                var key = String(stm.payer || '').toLowerCase()
                    + ':' + String(stm.line || '0');
                try {
                    var m = BigInt(stm.max);
                    if (!channels[key] || m > channels[key]) { channels[key] = m; }
                } catch (e) {}
            });
            var total = 0n;
            Object.keys(channels).forEach(function (k) { total += channels[k]; });
            var result = {
                tokens:       records.length,
                totalWei:     total.toString(),
                totalSbux:    Number(total) / 1e6,
                thresholdWei: threshold,
                claimable:    records.length > 0 && total >= BigInt(threshold)
            };
            if (callback) { callback(null, result); }
            return result;
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
