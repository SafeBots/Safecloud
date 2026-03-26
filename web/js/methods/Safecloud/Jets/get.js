/**
 * Q.Safecloud.Jets.get — fetch encrypted chunks for a subtree by link path.
 *
 * Emits Safecloud/subtree/get with { rootCid, link, grants, payments }.
 * The server routes by link path, returns chunks with Merkle proofs attached.
 * Null entries in result.chunks mean unavailable — not an error, retry or try another Jet.
 *
 * @param {Object} subtree
 *   subtree.rootCid  String   — manifest rootCid
 *   subtree.link     Array    — link path, e.g. ["track","data","0","1"]
 *   subtree.grants   Array    — OCP Role A grant objects (secret stripped)
 * @param {Object} [options]
 *   options.payments       Array
 *   options.publisherId    String
 *   options.streamName     String
 *   options.onProgress     fn(received, total)
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_get(subtree, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        // Strip encryption secrets — Jet only needs statement+proof for access verification.
        // Never send grant.secret to the server (it's the decryption key).
        var strippedGrants = (subtree.grants || []).map(function (g) {
            return { link: g.link, statement: g.statement, proof: g.proof, start: g.start, end: g.end };
        });

        var payload = {
            rootCid:  subtree.rootCid,
            link:     subtree.link    || ['track', 'data'],
            grants:   strippedGrants,
            payments: options.payments || []
        };

        if (options.publisherId) { payload.publisherId = options.publisherId; }
        if (options.streamName)  { payload.streamName  = options.streamName; }

        var _promise = _.emit('Safecloud/subtree/get', payload).then(function (result) {
            if (options.onProgress && result && result.chunks) {
                var received = result.chunks.filter(function (c) { return c !== null; }).length;
                options.onProgress(received, result.chunks.length);
            }
            if (callback) { callback(null, result); }
            return result;
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
