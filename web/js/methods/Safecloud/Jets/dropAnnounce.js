/**
 * Q.Safecloud.Jets.dropAnnounce — send Safecloud/drop/announce to the Jet.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_dropAnnounce(info, callback) {
        if (typeof info === 'function') { callback = info; info = {}; }
        var _promise = _.emit('Safecloud/drop/announce', info).then(function (result) {
            if (callback) { callback(null, result); }
            return result;
        });
        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
