/**
 * Q.Safecloud.Jets.dropRegister — register this browser tab as a Drop.
 * Fetches prollyRoot and (if cold) bloomFilter from Q.Safecloud.Drops.
 * Stores dropId and registration info for reconnect.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_dropRegister(info, callback) {
        if (typeof info === 'function') { callback = info; info = {}; }
        info = info || {};

        // Fetch current Prolly state from Drops
        var _promise = Q.Safecloud.Drops.getProllyRoot().then(function (prollyRoot) {
            var needsBloom = !prollyRoot; // cold = no root
            var bloomPromise = needsBloom
                ? Q.Safecloud.Drops.getBloomFilter()
                : Promise.resolve(null);

            return bloomPromise.then(function (bloomFilter) {
                var payload = {
                    dropId:           info.dropId      || ('drop-' + Q.clientId()),
                    clientId:         Q.clientId(),
                    evmAddress:       info.evmAddress  || null,
                    delegation:       info.delegation  || null,
                    publicKey:        info.publicKey   || null,
                    storage:          info.storage     || { GB: Q.Config.get(['Safecloud', 'drop', 'storageGB'], 10) },
                    prollyRoot:       prollyRoot,
                    bloomFilter:      bloomFilter,
                    // Drop announces minimum Safebux wei per chunk it will accept.
                    // Jet skips this Drop if offerPrice < minPerChunkWei.
                    // Drops with higher uptime/reliability set higher reservations.
                    // Default: same as protocol floor (Safecloud.safebux.perChunkWei).
                    minPerChunkWei:   info.minPerChunkWei
                                      || Q.Config.get(['Safecloud', 'drop', 'minPerChunkWei'],
                                             Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], '1000'))
                };

                // Store for reconnect
                _._state.dropInfo = payload;

                return _.emit('Safecloud/drop/register', payload).then(function (ack) {
                    if (ack && ack.dropId) {
                        _._state.dropId = ack.dropId;
                        // Persist dropId in sessionStorage for stability across reconnects
                        try { sessionStorage.setItem('Q.Safecloud.Client.dropId', ack.dropId); } catch(e) {}
                    }
                    if (callback) { callback(null, ack); }
                    return ack;
                });
            });
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
