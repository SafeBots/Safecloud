/**
 * Q.Safecloud.Jets.connect — connect to the Jet server. Idempotent.
 *
 * Uses Q.Socket.connect('/Safecloud/cloud', url). Registers all inbound Drop push
 * event handlers on first connection. Re-registers the Drop on reconnect
 * if _._state.dropInfo is set.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_connect(callback) {
        var url = _.jetUrl();

        // Already connected — resolve immediately
        if (_._state.connected && _._state.qs) {
            if (callback) { callback(null, _._state.qs); }
            return Promise.resolve(_._state.qs);
        }

        // If a connect is already in flight, piggyback on it
        if (_._state.connectingPromise) {
            if (!callback) { return _._state.connectingPromise; }
            _._state.connectingPromise.then(function (qs) { callback(null, qs); })
                                      .catch(function (e)  { callback(e); });
            return _._state.connectingPromise;
        }

        _._state.connectingPromise = new Promise(function (resolve, reject) {
            Q.Socket.connect('/Safecloud/cloud', url, function (err, qs) {
                if (err) {
                    _._state.connectingPromise = null;
                    _.scheduleReconnect();
                    return reject(err);
                }

                _._state.qs               = qs;
                _._state.connected        = true;
                _._state.reconnectAttempt = 0;
                _._state.connectingPromise = null;

                // Wire up inbound Drop push events (idempotent — guards with flag)
                if (!qs._safeHandlersWired) {
                    qs._safeHandlersWired = true;
                    _wireDropHandlers(qs);
                }

                // Drain queued calls
                _.drainQueue();

                // Re-register as Drop if we were registered before disconnect
                if (_._state.dropInfo) {
                    // Re-register with fresh Prolly state, not stale dropInfo
                    Q.Safecloud.Jets.dropRegister({
                        evmAddress:  _._state.dropInfo.evmAddress,
                        delegation:  _._state.dropInfo.delegation,
                        publicKey:   _._state.dropInfo.publicKey,
                        storage:     _._state.dropInfo.storage
                        // prollyRoot and bloomFilter fetched fresh by dropRegister
                    }).catch(function () {});
                }

                Q.Safecloud.Jets.onConnect.handle(qs);
                resolve(qs);

            }, {
                // Auth token from Q capability if available
                auth: Q.capability ? { capability: JSON.stringify(Q.capability) } : {}
            });

            // Listen for disconnect on the namespace socket
            Q.Socket.onEvent('disconnect', '/Safecloud/cloud', url).add(function () {
                _._state.connected = false;
                _._state.qs        = null;
                Q.Safecloud.Jets.onDisconnect.handle();
                _.scheduleReconnect();
            });

        });

        if (callback) {
            _._state.connectingPromise
                .then(function (qs) { callback(null, qs); })
                .catch(function (e)  { callback(e); });
        }
        return _._state.connectingPromise;
    };

    // ── Wire inbound Drop push handlers ────────────────────────────────────

    function _wireDropHandlers(qs) {
        // Fetch the Jet's payment/network info once per connection. Non-fatal:
        // older Jets without this event just leave info null (config fallback).
        try {
            qs.socket.emit('Safecloud/jet/info', {}, function (err, info) {
                if (!err && info) {
                    Q.Safecloud.Jets.info = info;
                    if (info.evmAddress) {
                        Q.Safecloud.Jets.jetEvmAddress = info.evmAddress;
                    }
                    Q.handle(Q.Safecloud.Jets.onInfo, Q.Safecloud.Jets, [info]);
                }
            });
        } catch (e) { /* ignore — info stays null */ }

        // Safecloud/drop/put — Jet pushes chunks to store
        Q.Socket.onEvent('Safecloud/drop/put', '/Safecloud/cloud', qs.url).set(function (payload, ack) { Q.Safecloud.Jets.onDropPut.handle(payload, ack); }, 'Safecloud.drop');

        // Safecloud/drop/get — Jet requests chunks
        Q.Socket.onEvent('Safecloud/drop/get', '/Safecloud/cloud', qs.url).set(function (payload, ack) { Q.Safecloud.Jets.onDropGet.handle(payload, ack); }, 'Safecloud.drop');

        // Safecloud/drop/challenge — proof-of-storage spot-check
        Q.Socket.onEvent('Safecloud/drop/challenge', '/Safecloud/cloud', qs.url).set(function (payload, ack) { Q.Safecloud.Jets.onDropChallenge.handle(payload, ack); }, 'Safecloud.drop');

        // Safecloud/drop/slashed — notification after on-chain slash
        Q.Socket.onEvent('Safecloud/drop/slashed', '/Safecloud/cloud', qs.url).set(function (payload) { Q.Safecloud.Jets.onDropSlashed.handle(payload); }, 'Safecloud.drop');

        // Default handlers — added only once per module load, not per connect
        if (!_._state._defaultHandlersWired) {
            _._state._defaultHandlersWired = true;
        Q.Safecloud.Jets.onDropPut.add(function (payload, ack) {
            Q.Safecloud.Drops.put(payload.chunks || [], payload.options || {})
                .then(function (r) {
                    // Pass stored field directly — put.js now sets it on every entry
                    var results = (r.results || []).map(function (x) {
                        if (!x) { return { stored: false }; }
                        return { cid: x.cid, stored: !!x.stored };
                    });
                    ack && ack(null, { results: results });
                }).catch(function (e) {
                    ack && ack({ error: { code: 'InternalError', message: e.message } });
                });
        });

        Q.Safecloud.Jets.onDropGet.add(function (payload, ack) {
            Q.Safecloud.Drops.get(payload.cids || [], { paymentToken: payload.paymentToken })
                .then(function (r) { ack && ack(null, r); })
                .catch(function (e) {
                    ack && ack({ error: { code: 'InternalError', message: e.message } });
                });
        });

        Q.Safecloud.Jets.onDropChallenge.add(function (payload, ack) {
            // Return the actual chunk so Jet can verify SHA-256(ciphertext||tag) === cid
            try {
                var ds = Q.Safecloud.Drops._ && Q.Safecloud.Drops._._state;
                if (ds) {
                    ds.challenges = (ds.challenges || 0) + 1;
                    ds.activity.push({ t: Date.now(), kind: 'challenge' });
                    if (ds.activity.length > 50) { ds.activity.shift(); }
                }
            } catch (e) { /* stats only */ }
            Q.Safecloud.Drops.get([payload.cid], {})
                .then(function (r) {
                    ack && ack(null, r.chunks[0] || null);
                }).catch(function () {
                    ack && ack(null, null);
                });
        });

        Q.Safecloud.Jets.onDropSlashed.add(function (payload) {
            // Emit a Q.Event that the application can listen to
            Q.log('Q.Safecloud.Drops: slashed — ' + (payload && payload.reason), 'Safecloud');
        });
        } // _defaultHandlersWired
    }
});
