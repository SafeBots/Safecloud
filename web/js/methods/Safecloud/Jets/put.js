/**
 * Q.Safecloud.Jets.put — upload encrypted chunks for a subtree by link path.
 *
 * Emits Safecloud/subtree/put with { chunks, link, grants, payments }.
 * The link path identifies where in the tree these chunks belong.
 *
 * @param {Object} subtree
 *   subtree.chunks   Array    — encrypted chunk objects { cid, iv, ciphertext, tag, size, tags }
 *   subtree.link     Array    — link path, e.g. ["track","data"] or ["track","index"]
 *   subtree.grants   Array    — OCP Role A grant objects authorizing this upload
 * @param {Object} [options]
 *   options.payments       Array
 *   options.publisherId    String
 *   options.streamName     String
 *   options.onProgress     fn(stored, total)
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_put(subtree, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var payload = {
            chunks:   subtree.chunks  || [],
            link:     subtree.link    || ['track', 'data'],
            // Strip encryption secrets — Jet only needs statement+proof for authorization.
            grants:   (subtree.grants || []).map(function (g) {
                return { link: g.link, statement: g.statement, proof: g.proof, start: g.start, end: g.end };
            }),
            payments: options.payments || []
        };
        if (subtree.treeN)     { payload.treeN     = subtree.treeN; }
        if (subtree.treeDepth) { payload.treeDepth = subtree.treeDepth; }
        if (subtree.rootCid)   { payload.rootCid   = subtree.rootCid; }

        if (options.publisherId) { payload.publisherId = options.publisherId; }
        if (options.streamName)  { payload.streamName  = options.streamName; }

        var _promise = _.emit('Safecloud/subtree/put', payload).then(function (result) {
            if (result && result.results) {
                result.results.forEach(function (r, i) {
                    if (!r || !r.stored) { return; }
                    _.cloudStats.chunksUploaded++;
                    var src = payload.chunks[i];
                    if (src && src.size) { _.cloudStats.bytesUploaded += src.size; }
                    else if (src && src.ciphertext) {
                        _.cloudStats.bytesUploaded +=
                            Math.floor(src.ciphertext.length * 3 / 4);
                    }
                });
            }
            if (options.onProgress && result && result.results) {
                var stored = result.results.filter(function (r) { return r && r.stored; }).length;
                options.onProgress(stored, result.results.length);
            }
            // Check that at least one Drop confirmed each chunk — if every chunk
            // has stored:false, reject so the caller knows the upload failed
            if (result && result.results && result.results.length > 0) {
                var allFailed = result.results.every(function (r) { return !r || !r.stored; });
                if (allFailed) {
                    throw new Error('Q.Safecloud.Jets.put: no Drops stored any chunks (quota full or unavailable)');
                }
            }
            if (callback) { callback(null, result); }
            return result;
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
