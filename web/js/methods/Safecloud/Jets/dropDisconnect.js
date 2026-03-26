/**
 * Q.Safecloud.Jets.dropDisconnect — signal intentional Drop shutdown to the Jet.
 * Clears dropId from sessionStorage after successful ack.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_dropDisconnect(callback) {
        var payload = { dropId: _._state.dropId };
        var _promise = _.emit('Safecloud/drop/disconnect', payload).then(function (result) {
            _._state.dropId   = null;
            _._state.dropInfo = null;
            try { sessionStorage.removeItem('Q.Safecloud.Client.dropId'); } catch(e) {}
            if (callback) { callback(null, result); }
            return result;
        });
        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
