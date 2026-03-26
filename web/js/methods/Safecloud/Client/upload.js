/**
 * Q.Safecloud.Client.upload — thin ergonomic wrapper over store().
 * Accepts a File or { data, name, type } object.
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_upload(file, options, callback) {
        if (typeof options === 'function') {
            callback = options;
            options  = {};
        }
        // Allow plain File objects from <input type="file">
        if (file instanceof File) {
            file = { data: file, name: file.name, type: file.type };
        }
        return Q.Safecloud.Client.store(file, options || {}, callback);
    };
});
