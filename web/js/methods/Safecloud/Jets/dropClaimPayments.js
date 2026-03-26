/**
 * Q.Safecloud.Jets.dropClaimPayments — relay accumulated payment tokens to Jet
 * for on-chain execution (Jet covers gas).
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_dropClaimPayments(payload, callback) {
        if (typeof payload === 'function') { callback = payload; payload = {}; }
        payload = Q.extend({ dropId: _._state.dropId }, payload);
        var _promise = _.emit('Safecloud/drop/claimPayments', payload).then(function (result) {
            if (callback) { callback(null, result); }
            return result;
        });
        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
