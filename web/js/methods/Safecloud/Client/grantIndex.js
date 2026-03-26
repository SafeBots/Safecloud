/**
 * Q.Safecloud.Client.grantIndex — produce a grant for the index track only.
 *
 * Thin wrapper over grant(manifest, rootKey, { indexOnly: true }, callback).
 * Recipients can decrypt track/index (chapters, initSegment, codec, duration)
 * but cannot decrypt any data track chunks.
 *
 * Use case: teasers and previews — let someone see what's in a file
 * without granting access to the actual content.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_grantIndex(manifest, rootKey, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        return Q.Safecloud.Client.grant(
            manifest, rootKey,
            Q.extend({}, options || {}, { indexOnly: true }),
            callback
        );
    };
});
