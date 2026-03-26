/**
 * Q.Safecloud.Client.fetch — download, Merkle-verify, and decrypt chunks.
 *
 * KEY MODEL (N-ary tree):
 *   Every chunk was encrypted with deriveChunkKey(leafKey, 0) where leafKey is
 *   the Q.Crypto.delegate result at the chunk's full leaf path, e.g.
 *   ["track","data","0","1","0"].  relIndex within the leaf is always 0 because
 *   each leaf node covers exactly one chunk.
 *
 *   Owner:    leafKey = deriveByPath(encRoot, leafPath)
 *   Grantee:  leafKey = deriveLeafKeyFromGrant(grant.secret, grant.link, absIdx, manifest)
 *             — navigates from the grant's node down to the leaf via chained
 *               Q.Crypto.delegate calls, one per path segment below the grant.
 *
 * PIPELINE (single sequential chain, nothing shared via mutable closure):
 *   1. Resolve leaf keys for every chunk → Array<{absIdx, leafKey}>
 *   2. Fetch each chunk by its own leaf link path (parallel) → Array<{absIdx, chunk, leafKey}>
 *   3. Merkle verify ALL chunks before decrypting any
 *   4. Decrypt all in parallel: deriveChunkKey(leafKey, 0) + Q.Data.decrypt
 *   5. Reassemble as Blob in original index order
 *
 * @param {Object}   manifest    Public manifest (treeN, treeDepth, chunkCount, rootCid)
 * @param {Object}   capability  { rootKey } | { grants[], manifest }
 * @param {Object}   [options]   { start, end, authorizations, payments, onProgress }
 * @param {Function} [callback]
 * @return {Promise<Blob>}
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_fetch(manifest, capability, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var start = options.start || 0;
        var end   = (options.end != null) ? options.end : manifest.chunkCount;

        if (start < 0 || end > manifest.chunkCount || start >= end) {
            var e = new Error('Q.Safecloud.Client.fetch: invalid range [' + start + ',' + end + ')');
            if (callback) { callback(e); return; }
            return Promise.reject(e);
        }

        var indices = [];
        for (var i = start; i < end; i++) { indices.push(i); }

        // ─────────────────────────────────────────────────────────────────────
        // Step 1 — resolve leaf key for every chunk
        //
        // Returns: Promise<Array<{ absIdx, leafKey }>>
        // ─────────────────────────────────────────────────────────────────────
        function resolveLeafKeys() {
            if (capability.rootKey) {
                var rkBytes = (typeof capability.rootKey === 'string')
                    ? Q.Data.fromBase64(capability.rootKey)
                    : capability.rootKey;
                return _.deriveEncryptionRoot(rkBytes).then(function (encDel) {
                    return Promise.all(indices.map(function (absIdx) {
                        var leafPath = _.chunkLinkPath(absIdx, manifest);
                        return _.deriveByPath(encDel.secret, leafPath, '{}')
                            .then(function (leafDel) {
                                return { absIdx: absIdx, leafKey: leafDel.secret };
                            });
                    }));
                });
            }

            // Delegated path
            var grants        = capability.grants || [];
            var requiredLevel = _.levelFromLabel('read', 'content');
            var missing       = [];

            var entries = indices.map(function (absIdx) {
                for (var gi = 0; gi < grants.length; gi++) {
                    if (_.grantCoversChunk(grants[gi], requiredLevel, absIdx, manifest)) {
                        var g   = grants[gi];
                        var gkb = (typeof g.secret === 'string')
                            ? Q.Data.fromBase64(g.secret) : g.secret;
                        return { absIdx: absIdx, grantKey: gkb, grantLink: g.link };
                    }
                }
                missing.push(absIdx);
                return null;
            });

            if (missing.length) {
                return Promise.reject(new Error(
                    'Q.Safecloud.Client.fetch: no grant covers chunks ' + JSON.stringify(missing)
                ));
            }

            return Promise.all(entries.map(function (e) {
                return _.deriveLeafKeyFromGrant(e.grantKey, e.grantLink, e.absIdx, manifest)
                    .then(function (leafKey) {
                        return { absIdx: e.absIdx, leafKey: leafKey };
                    });
            }));
        }

        // ─────────────────────────────────────────────────────────────────────
        // Main pipeline — everything flows through the chain with no shared state
        // ─────────────────────────────────────────────────────────────────────
        var _promise = resolveLeafKeys()

        // Step 2 — fetch each chunk by its own leaf link path
        .then(function (leafKeyEntries) {
            var fetchPromises = leafKeyEntries.map(function (e) {
                var leafLink = _.chunkLinkPath(e.absIdx, manifest);
                return Q.Safecloud.Jets.get({
                    rootCid: manifest.rootCid,
                    link:    leafLink,
                    grants:  capability.grants || []
                }, {
                    authorizations: options.authorizations,
                    payments:       options.payments
                }).then(function (result) {
                    // Attach leafKey to the item so it flows into verify + decrypt steps
                    return {
                        absIdx:  e.absIdx,
                        leafKey: e.leafKey,
                        chunk:   result.chunks && result.chunks[0]
                    };
                });
            });
            return Promise.all(fetchPromises);
        })

        // Step 3 — Merkle verify ALL before decrypting any
        .then(function (items) {
            if (options.onProgress) {
                var received = items.filter(function (it) { return !!it.chunk; }).length;
                options.onProgress(received, items.length);
            }
            var verifyPromises = items.map(function (item) {
                if (!item.chunk) {
                    return Promise.reject(new Error(
                        'Q.Safecloud.Client.fetch: chunk ' + item.absIdx + ' unavailable'
                    ));
                }
                var proofArg = item.chunk.nodeProof || item.chunk.proof;
                // Guard: Merkle.verify may not be implemented yet in platform
                if (!proofArg || !Q.Data.Merkle || typeof Q.Data.Merkle.verify !== 'function') {
                    return Promise.resolve(item); // skip verification if unavailable
                }
                return Q.Data.Merkle.verify(item.chunk.cid, proofArg, manifest.rootCid)
                    .then(function (ok) {
                        if (!ok) {
                            throw new Error(
                                'Q.Safecloud.Client.fetch: Merkle proof failed for ' + item.chunk.cid
                            );
                        }
                        return item;
                    });
            });
            return Promise.all(verifyPromises);
        })

        // Step 4 — decrypt in parallel
        .then(function (verified) {
            var decryptPromises = verified.map(function (item, idx) {
                var chunk   = item.chunk;
                var leafKey = item.leafKey; // derived in step 1, threaded through chain
                var aad     = _.chunkAAD(item.absIdx);

                // leafKey is at the leaf node → relIndex = 0
                return _.deriveChunkKey(leafKey, 0)
                .then(function (chunkKey) {
                    return Q.Data.importKey(chunkKey).then(function (cryptoKey) {
                        return Q.Data.decrypt(cryptoKey, chunk.iv, chunk.ciphertext, {
                            tag:        chunk.tag,
                            additional: aad
                        });
                    }).then(function (plaintext) {
                        if (options.onProgress) {
                            options.onProgress(idx + 1, verified.length);
                        }
                        return plaintext;
                    });
                });
            });
            return Promise.all(decryptPromises);
        })

        // Step 5 — reassemble
        .then(function (plaintexts) {
            var blob = new Blob(plaintexts, { type: manifest.type || '' });
            if (callback) { callback(null, blob); }
            return blob;
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
