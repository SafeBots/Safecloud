/**
 * Q.Safecloud.Client.download — thin ergonomic wrapper over fetch().
 * If options.save is true, triggers a browser download dialog and returns null.
 * Otherwise returns the Blob.
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_download(manifest, capability, options, callback) {
        if (typeof options === 'function') {
            callback = options;
            options  = {};
        }
        options = options || {};
        var save = options.save;

        var _promise = Q.Safecloud.Client.fetch(manifest, capability, options)
            .then(function (blob) {
                if (save) {
                    var url = URL.createObjectURL(blob);
                    var a   = document.createElement('a');
                    a.href  = url;
                    a.download = manifest.name || 'download';
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(function () {
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    }, 100);
                    if (callback) { callback(null, null); }
                    return null;
                }
                if (callback) { callback(null, blob); }
                return blob;
            });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
