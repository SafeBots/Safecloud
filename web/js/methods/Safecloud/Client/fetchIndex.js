/**
 * Q.Safecloud.Client.fetchIndex — fetch and decrypt the index track.
 *
 * The index track CID is NOT stored in the manifest.
 * It is found by navigating the Merkle tree: Merkle.getNode(rootCid, ["track","index"])
 *
 * Key derivation: deriveByPath(encryptionRoot, ["track","index"], context)
 * Same root as data track, different first path segment label.
 *
 * Returns the decrypted index object (parsed JSON), or null if no index track.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_fetchIndex(manifest, capability, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        // Check whether this manifest has an index track
        var hasIndexTrack = manifest.tracks && manifest.tracks.indexOf('index') >= 0;
        if (!hasIndexTrack) {
            if (callback) { callback(null, null); }
            return Promise.resolve(null);
        }

        var indexLinkPath = ['track', 'index'];

        // ── Resolve the index track key ───────────────────────────────────────
        var keyPromise;
        if (capability.rootKey) {
            var rkBytes = (typeof capability.rootKey === 'string')
                ? Q.Data.fromBase64(capability.rootKey)
                : capability.rootKey;
            keyPromise = _.deriveEncryptionRoot(rkBytes).then(function (encDel) {
                return _.deriveByPath(encDel.secret, indexLinkPath, '{}');
            }).then(function (idxDel) {
                return idxDel.secret;
            });
        } else if (capability.indexGrant) {
            var g = capability.indexGrant;
            keyPromise = Promise.resolve(
                (typeof g.secret === 'string')
                    ? Q.Data.fromBase64(g.secret) : g.secret
            );
        } else {
            // Check grants array for an index track grant
            var indexGrant = (capability.grants || []).find(function (gr) {
                if (!gr || !gr.link) { return false; }
                return gr.link[0] === 'track' && gr.link[1] === 'index';
            });
            if (indexGrant) {
                keyPromise = Promise.resolve(
                    (typeof indexGrant.secret === 'string')
                        ? Q.Data.fromBase64(indexGrant.secret) : indexGrant.secret
                );
            } else {
                var e = new Error(
                    'Q.Safecloud.Client.fetchIndex: capability must have rootKey, indexGrant, ' +
                    'or a grant with link ["track","index"]'
                );
                if (callback) { callback(e); return; }
                return Promise.reject(e);
            }
        }

        var _promise = keyPromise.then(function (indexKeyBytes) {
            // Find the index track CID from the Merkle tree
            // If Q.Data.Merkle.getNode is available use it; otherwise fall back
            // to the old indexCid manifest field for backward compat
            var indexCidPromise;
            if (Q.Data.Merkle.getNode && typeof Q.Data.Merkle.getNode === 'function') {
                indexCidPromise = Q.Data.Merkle.getNode(manifest.rootCid, indexLinkPath);
            } else if (manifest.indexCid) {
                indexCidPromise = Promise.resolve(manifest.indexCid);
            } else {
                return Promise.reject(new Error(
                    'Q.Safecloud.Client.fetchIndex: Q.Data.Merkle.getNode not available ' +
                    'and manifest.indexCid not set'
                ));
            }

            return indexCidPromise.then(function (indexCid) {
                if (!indexCid) {
                    if (callback) { callback(null, null); }
                    return null;
                }

                // Fetch the index chunk from Jets using its CID and link path
                return Q.Safecloud.Jets.get({
                    rootCid: manifest.rootCid,
                    link:    indexLinkPath,
                    grants:  capability.indexGrant ? [capability.indexGrant]
                           : (capability.grants   || []).filter(function (gr) {
                               return gr && gr.link && gr.link[0] === 'track' && gr.link[1] === 'index';
                             })
                }, {
                    authorizations: options.authorizations,
                    payments:       options.payments
                }).then(function (result) {
                    var chunk = result.chunks && result.chunks[0];
                    if (!chunk) {
                        throw new Error('Q.Safecloud.Client.fetchIndex: index chunk unavailable');
                    }

                    // AAD = "safecloud.track.index" (no rootCid — keep it path-stable)
                    var aad = new TextEncoder().encode('safecloud.track.index');

                    return Q.Data.importKey(indexKeyBytes).then(function (cryptoKey) {
                        return Q.Data.decrypt(cryptoKey, chunk.iv, chunk.ciphertext, {
                            tag:        chunk.tag,
                            additional: aad
                        });
                    }).then(function (plaintext) {
                        var text  = new TextDecoder().decode(plaintext);
                        var index = JSON.parse(text);
                        if (callback) { callback(null, index); }
                        return index;
                    });
                });
            });
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
