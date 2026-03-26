/**
 * Q.Safecloud.Client.grant — produce a capability for one or more subtree nodes.
 *
 * LINK PATH MODEL:
 *   Grants are now link-path based, not {start,end} range based.
 *   A grant at path ["track","data","0","1"] covers all chunks in that subtree.
 *   Non-contiguous access = array of grants at different paths.
 *
 * Single-manifest form:
 *   grant(manifest, rootKey, { linkPaths, readLevel, exp }, callback)
 *
 * Multi-version form:
 *   grant(null, null, { videoManifest, videoKey, ... }, callback)
 *
 * Index-only form:
 *   grant(manifest, rootKey, { indexOnly: true }, callback)
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_grant(manifest, rootKey, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        if (!manifest && !rootKey && options.videoManifest) {
            return _grantMultiVersion(options, callback);
        }
        if (options.indexOnly) {
            return _grantIndex(manifest, rootKey, options, callback);
        }

        var rkBytes = (typeof rootKey === 'string')
            ? Q.Data.fromBase64(rootKey) : rootKey;

        // Default: grant the full data track root (covers all chunks)
        var linkPaths  = options.linkPaths  || [['track', 'data']];
        var readLevel  = options.readLevel  || 'content';
        var writeLevel = options.writeLevel || null;
        var adminLevel = options.adminLevel || null;
        var format     = options.format     || 'ES256';
        var exp        = options.exp        || null;

        var readLevelNum = _.levelFromLabel('read',  readLevel  || 'content');
        var writeLevelNum = writeLevel ? _.levelFromLabel('write', writeLevel) : 0;
        var adminLevelNum = adminLevel ? _.levelFromLabel('admin', adminLevel) : 0;

        var _promise = Promise.all([
            _.deriveEncryptionRoot(rkBytes),
            _.deriveAccessRootBytes(rkBytes)
        ]).then(function (roots) {
            var encRoot = roots[0].secret;
            var accRoot = roots[1].secret;

            var grantPromises = linkPaths.map(function (linkPath) {
                // Build the full context for the tip delegation
                var ctxObj = {
                    rootCid:    manifest.rootCid,
                    link:       linkPath,
                    readLevel:  readLevelNum,
                    writeLevel: writeLevelNum,
                    adminLevel: adminLevelNum
                };
                if (exp) { ctxObj.exp = exp; }
                var tipContext = JSON.stringify(ctxObj);

                // Derive encryption subtreeKey at this path (with full context at tip)
                // Encryption tree: always use '{}' context — rootCid is unknown
                // at encryption time and must not affect the derived key.
                var encKeyPromise = _.deriveByPath(encRoot, linkPath, '{}');

                // Access tree: full tipContext binds the grant to rootCid, level, expiry
                var accessProofPromise = _.deriveByAccessPath(accRoot, linkPath, tipContext);

                return Promise.all([encKeyPromise, accessProofPromise])
                    .then(function (results) {
                        var encDel    = results[0]; // encryption key at tip
                        var accessDel = results[1]; // access proof at tip

                        // Compute leaf range covered by this path (for consumer reference)
                        var range = _.leafRangeForPath(linkPath, manifest);

                        return {
                            link:         linkPath,
                            secret:       Q.Data.toBase64(encDel.secret),
                            statement:    accessDel.statement,
                            proof:        accessDel.proof,
                            // Convenience fields for consumers
                            start:        range.start,
                            end:          range.end
                        };
                    });
            });

            return Promise.all(grantPromises);
        }).then(function (grants) {
            var result = {
                rootCid:    manifest.rootCid,
                grants:     grants,
                manifest:   manifest,
                readLevel:  readLevel,
                writeLevel: writeLevel,
                adminLevel: adminLevel
            };
            if (callback) { callback(null, result); }
            return result;
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };

    // ── Index track grant ─────────────────────────────────────────────────────

    function _grantIndex(manifest, rootKey, options, callback) {
        var rkBytes = (typeof rootKey === 'string')
            ? Q.Data.fromBase64(rootKey) : rootKey;
        var exp         = options.exp || null;
        var readLevelNum = _.levelFromLabel('read', options.readLevel || 'content');

        var linkPath = ['track', 'index'];
        var ctxObj   = { rootCid: manifest.rootCid, link: linkPath, readLevel: readLevelNum };
        if (exp) { ctxObj.exp = exp; }
        var tipContext = JSON.stringify(ctxObj);

        var _p = Promise.all([
            _.deriveEncryptionRoot(rkBytes),
            _.deriveAccessRootBytes(rkBytes)
        ]).then(function (roots) {
            return Promise.all([
                _.deriveByPath(roots[0].secret, linkPath, '{}'),          // enc: no tipContext
                _.deriveByAccessPath(roots[1].secret, linkPath, tipContext)  // access: full context
            ]);
        }).then(function (results) {
            var encDel    = results[0];
            var accessDel = results[1];
            var result = {
                rootCid:    manifest.rootCid,
                indexGrant: {
                    link:      linkPath,
                    secret:    Q.Data.toBase64(encDel.secret),
                    statement: accessDel.statement,
                    proof:     accessDel.proof
                },
                manifest: manifest
            };
            if (callback) { callback(null, result); }
            return result;
        });

        if (!callback) { return _p; }
        _p.catch(function (err) { callback(err); });
    }

    // ── Multi-version grant ───────────────────────────────────────────────────

    function _grantMultiVersion(options, callback) {
        var vm        = options.videoManifest;
        var videoKey  = options.videoKey;
        var labels    = options.versions || (vm.versions || []).map(function (v) { return v.label; });
        var timeStart = options.timeStart || 0;
        var timeEnd   = options.timeEnd   || vm.duration;
        var cdur      = vm.chunkDuration;

        var vkBytes = (typeof videoKey === 'string')
            ? Q.Data.fromBase64(videoKey) : videoKey;

        // Convert time range → minimal set of link paths covering those chunks.
        // _pathsCoveringRange computes this precisely via subtree greedy selection.
        var chunkStart = Math.floor(timeStart / cdur);

        var vp = labels.map(function (label) {
            var vi = vm.versions.find(function (v) { return v.label === label; });
            if (!vi) { return Promise.resolve(null); }
            var vmanifest = vi.manifest;
            var chunkEnd  = Math.min(Math.ceil(timeEnd / cdur), vmanifest.chunkCount);

            // Find the smallest set of subtree paths covering [chunkStart, chunkEnd)
            var linkPaths = _pathsCoveringRange(chunkStart, chunkEnd, vmanifest);

            return _.deriveVersionKey(vkBytes, label).then(function (vDel) {
                return Q.Safecloud.Client.grant(vmanifest, vDel.secret, {
                    linkPaths:  linkPaths,
                    readLevel:  options.readLevel  || 'content',
                    writeLevel: options.writeLevel || null,
                    adminLevel: options.adminLevel || null,
                    format:     options.format     || 'ES256',
                    exp:        options.exp        || null
                });
            }).then(function (gr) {
                return { label: label, grants: gr.grants, manifest: vmanifest };
            });
        });

        var _p = Promise.all(vp).then(function (vgs) {
            var versionsMap = {};
            vgs.forEach(function (vg) {
                if (vg) { versionsMap[vg.label] = { grants: vg.grants, manifest: vg.manifest }; }
            });
            var result = {
                type:      'safecloud.videocapability',
                timeStart: timeStart,
                timeEnd:   timeEnd,
                versions:  versionsMap
            };
            if (callback) { callback(null, result); }
            return result;
        });

        if (!callback) { return _p; }
        _p.catch(function (err) { callback(err); });
    }

    /**
     * Find the minimal set of link paths whose union covers [chunkStart, chunkEnd).
     * Uses a greedy approach: take the largest subtree that fits within the range.
     * Falls back to the root path if the range covers most of the tree.
     */
    function _pathsCoveringRange(chunkStart, chunkEnd, manifest) {
        if (chunkStart <= 0 && chunkEnd >= manifest.chunkCount) {
            return [['track', 'data']]; // whole tree
        }
        var treeN     = manifest.treeN     || 2;
        var treeDepth = manifest.treeDepth || 1;
        var paths     = [];

        function collect(path, nodeStart, nodeSize, depth) {
            var nodeEnd = nodeStart + nodeSize;
            // No overlap
            if (nodeEnd <= chunkStart || nodeStart >= chunkEnd) { return; }
            // Fully covered
            if (nodeStart >= chunkStart && nodeEnd <= chunkEnd) {
                paths.push(path.slice());
                return;
            }
            // Partial overlap — recurse into children
            if (depth >= treeDepth) {
                paths.push(path.slice()); // leaf
                return;
            }
            var childSize = nodeSize / treeN;
            for (var i = 0; i < treeN; i++) {
                path.push(String(i));
                collect(path, nodeStart + i * childSize, childSize, depth + 1);
                path.pop();
            }
        }

        var totalLeaves = Math.pow(treeN, treeDepth);
        collect(['track', 'data'], 0, totalLeaves, 0);
        return paths.length > 0 ? paths : [['track', 'data']];
    }
});
