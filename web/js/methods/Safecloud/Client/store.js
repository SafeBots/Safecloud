/**
 * Q.Safecloud.Client.store — encrypt a file and upload it via Jets.
 *
 * TREE MODEL:
 *   - Chunks are arranged in an N-ary Merkle tree under track/data
 *   - The optional index is a single chunk under track/index
 *   - rootCid = Merkle root over [trackDataRoot, trackIndexRoot]
 *   - Encryption keys are derived by chaining Q.Crypto.delegate down link paths
 *   - Keys are derived per subtree node so any link path can later be granted
 *
 * PIPELINE:
 *   1.  Resolve rootKey
 *   2.  deriveEncryptionRoot + deriveAccessRootBytes (parallel)
 *   3.  internalKeypair for both roots
 *   4.  blobToBuffer → chunkify
 *   5.  Compute treeN, treeDepth from chunk count
 *   6.  Encrypt all chunks in parallel (each uses its leaf subtreeKey)
 *   7.  Build N-ary Merkle tree: buildTree({data: cids, index: [idxCid]}, treeN)
 *   8.  Encrypt index track (if options.index provided)
 *   9.  Compute rootCid from combined track roots
 *   10. Derive subtree keys for each internal node (for Jets.put grants)
 *   11. Binding proof (Q.Crypto.sign over encPub + accPub + rootCid)
 *   12. Jets.put for data track + index track
 *   13. buildManifest → return
 */

Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_store(file, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var chunkSize = options.chunkSize || Q.Safecloud.Client.defaultChunkSize;
        var treeN     = options.treeN     || 2;

        // ── Step 1: resolve rootKey ───────────────────────────────────────
        var rootKeyPromise;
        if (options.videoKey) {
            if (!options.version) {
                var e1 = new Error('Q.Safecloud.Client.store: options.version required with videoKey');
                if (callback) { callback(e1); return; }
                return Promise.reject(e1);
            }
            var vkBytes = (typeof options.videoKey === 'string')
                ? Q.Data.fromBase64(options.videoKey) : options.videoKey;
            rootKeyPromise = _.deriveVersionKey(vkBytes, options.version)
                .then(function (d) { return d.secret; });
        } else if (options.key) {
            var rawKey = (typeof options.key === 'string')
                ? Q.Data.fromBase64(options.key) : options.key;
            rootKeyPromise = Promise.resolve(rawKey);
        } else {
            var fresh = new Uint8Array(32);
            crypto.getRandomValues(fresh);
            rootKeyPromise = Promise.resolve(fresh);
        }

        console.warn('Safecloud/store: step 1 — rootKey resolving...');
        var _promise = rootKeyPromise.then(function (rootKey) {
            console.warn('Safecloud/store: step 1 done — rootKey resolved');

            // ── Steps 2–3: derive roots and keypairs ──────────────────────
            return Promise.all([
                _.deriveEncryptionRoot(rootKey),
                _.deriveAccessRootBytes(rootKey)
            ]).then(function (roots) {
                console.warn('Safecloud/store: step 2 done — encRoot/accRoot derived');
                var encRoot = roots[0].secret;
                var accRoot = roots[1].secret;

                return Promise.all([
                    Q.Crypto.internalKeypair({ secret: encRoot, format: 'ES256' }),
                    Q.Crypto.internalKeypair({ secret: accRoot, format: 'ES256' })
                ]).then(function (keypairs) {
                    console.warn('Safecloud/store: step 3 done — encKP/accKP derived');
                    var encKP = keypairs[0];
                    var accKP = keypairs[1];

                    // ── Step 4: Blob → chunks ────────────────────────────
                    return _.blobToBuffer(file.data).then(function (buffer) {
                        console.warn('Safecloud/store: step 4 done — blob read, ' + buffer.byteLength + ' bytes');
                        var chunkBuffers = _.chunkify(buffer, options.chunkBoundaries || chunkSize);
                        var chunkCount   = chunkBuffers.length;
                        var fileSize     = buffer.byteLength;
                        console.warn('Safecloud/store: step 5 — ' + chunkCount + ' chunks to encrypt');

                        // ── Step 5: compute tree shape ────────────────────
                        var tp        = _.treeParams(chunkCount, treeN);
                        var treeDepth = tp.treeDepth;

                        // Derive leaf key for each chunk directly.
                        // Each chunk's leaf path is chunkLinkPath(absIdx, manifest).
                        // We derive lazily per-chunk inside encPromises using deriveByPath.
                        // No need to pre-derive all internal nodes.

                            // Helper: get the leaf subtreeKey for a chunk at absIndex
                            function leafKeyForChunk(absIndex) {
                                var leafPath = _.chunkLinkPath(absIndex, {
                                    treeN: treeN, treeDepth: treeDepth,
                                    chunkCount: chunkCount
                                });
                                return _.deriveByPath(encRoot, leafPath, '{}')
                                    .then(function (del) {
                                        return { subtreeKey: del.secret, leafPath: leafPath };
                                    });
                            }

                            // ── Step 6: encrypt all chunks in parallel ────
                            var encPromises = chunkBuffers.map(function (buf, relIdx) {
                                var absIdx = relIdx;

                                // relIndex within leaf subtree is always 0
                                // (each leaf covers exactly one chunk)
                                return leafKeyForChunk(absIdx).then(function (lk) {
                                return Promise.all([
                                    _.deriveChunkKey(lk.subtreeKey, 0),
                                    _.deriveChunkIV(lk.subtreeKey, 0)
                                ]).then(function (kv) {
                                    return Q.Data.importKey(kv[0]).then(function (cryptoKey) {
                                        return Q.Data.encrypt(cryptoKey, buf, {
                                            iv:         kv[1],
                                            additional: _.chunkAAD(absIdx)
                                        });
                                    }).then(function (enc) {
                                        return _.chunkCid(enc.ciphertext, enc.tag)
                                            .then(function (cid) {
                                                return {
                                                    cid:        cid,
                                                    iv:         enc.iv,
                                                    ciphertext: enc.ciphertext,
                                                    tag:        enc.tag,
                                                    size:       buf.byteLength,
                                                    tags:       file.tags || [],
                                                    leafPath:   lk.leafPath
                                                };
                                            });
                                    });
                                }); // Promise.all([chunkKey, chunkIV])
                                }); // leafKeyForChunk.then
                            }); // encChunks.map

                            return Promise.all(encPromises).then(function (encChunks) {
                                console.warn('Safecloud/store: step 6 done — all ' + encChunks.length + ' chunks encrypted');
                                var dataCids = encChunks.map(function (c) { return c.cid; });

                                // ── Step 7: build N-ary Merkle tree ──────
                                // Q.Data.Merkle.buildTree builds an N-ary tree and
                                // returns { rootCid, trackRoots }
                                // If buildTree is not yet available, fall back to flat build
                                var trackCids = { data: dataCids };
                                var hasIndex  = !!options.index;
                                var tracks    = ['data'];
                                if (hasIndex) { tracks.push('index'); }

                                // ── Step 8: encrypt index track ───────────
                                var indexPromise = Promise.resolve(null);
                                if (hasIndex) {
                                    // Index key is derived via path ["track","index"]
                                    var idxDelSecret;
                                    indexPromise = _.deriveByPath(encRoot, ['track', 'index'], '{}')
                                        .then(function (idxDel) {
                                            idxDelSecret = idxDel.secret;
                                            // Q.Data.canonicalize is a lazily-loaded Q.Method: on
                                            // its very first call in a page's lifetime (before its
                                            // script has fetched), the shim returns a bare Promise
                                            // instead of the real string. TextEncoder.encode()
                                            // silently coerces any non-string argument via
                                            // String(...), so an unawaited Promise here would
                                            // encrypt the literal text "[object Promise]" as the
                                            // entire index track — permanently, since this runs
                                            // once at upload time. Must await it like everything
                                            // else derived from a Q.Data/Q.Crypto method.
                                            return Q.Data.canonicalize(options.index);
                                        }).then(function (canonical) {
                                            var idxPlaintext = new TextEncoder().encode(canonical);
                                            return Q.Data.importKey(idxDelSecret)
                                                .then(function (k) {
                                                    // AAD binds ciphertext to the track/index path
                                                    // rootCid not known yet — use placeholder,
                                                    // will be fixed once rootCid is computed
                                                    return Q.Data.encrypt(k, idxPlaintext, {
                                                        additional: new TextEncoder().encode(
                                                            'safecloud.track.index'
                                                        )
                                                    });
                                                }).then(function (enc) {
                                                    return _.chunkCid(enc.ciphertext, enc.tag)
                                                        .then(function (cid) {
                                                            return { enc: enc, cid: cid };
                                                        });
                                                });
                                        });
                                }

                                return indexPromise.then(function (indexFork) {
                                    console.warn('Safecloud/store: step 8 done — index track ' + (hasIndex ? 'encrypted' : 'skipped'));
                                    if (indexFork) { trackCids.index = [indexFork.cid]; }

                                    // Build the actual Merkle root.
                                    // Q.Data.Merkle.buildTree (N-ary, multi-track) was never
                                    // implemented anywhere in the platform — only the flat
                                    // build/verify/proof methods exist — so this always fell
                                    // through to the "build" branch below. That branch is
                                    // itself async (Q.Data.Merkle.build returns a Q.Promise,
                                    // since it hashes via SubtleCrypto), but the old code
                                    // assigned its return value directly to rootCid without
                                    // awaiting it. rootCid was a Promise object for the rest
                                    // of this function ("[object Promise]" when logged), which
                                    // is why the manifest, binding proof, and Jets.put all
                                    // carried a broken rootCid, and playback later failed with
                                    // "rootCid required".
                                    var allCids = dataCids.concat(indexFork ? [indexFork.cid] : []);
                                    var rootCidPromise;
                                    if (Q.Data.Merkle.buildTree) {
                                        rootCidPromise = Promise.resolve(Q.Data.Merkle.buildTree(trackCids, treeN))
                                            .then(function (treeResult) { return treeResult.rootCid; });
                                    } else if (Q.Data.Merkle.build) {
                                        rootCidPromise = Promise.resolve(Q.Data.Merkle.build(allCids));
                                    } else {
                                        // Platform Merkle not yet available — derive a stable rootCid
                                        // by hashing all leaf CIDs deterministically
                                        var joinedCids = allCids.join('|');
                                        // Use SubtleCrypto synchronously is not possible, so use a
                                        // deterministic djb2 hash as the provisional root identifier
                                        var h = 5381;
                                        for (var ci = 0; ci < joinedCids.length; ci++) {
                                            h = ((h << 5) + h) ^ joinedCids.charCodeAt(ci);
                                            h = h >>> 0; // keep unsigned 32-bit
                                        }
                                        rootCidPromise = Promise.resolve(
                                            'bprovisional' + h.toString(16).padStart(8,'0') + allCids.length.toString(16)
                                        );
                                    }

                                    return rootCidPromise.then(function (rootCid) {

                                    console.warn('Safecloud/store: step 7 done — rootCid computed: ' + rootCid);

                                    // ── Step 9: binding proof ─────────────
                                    var encPubB64 = Q.Data.toBase64(encKP.publicKey);
                                    var accPubB64 = Q.Data.toBase64(accKP.publicKey);
                                    var bindingMsg = {
                                        encryptionRootPublicKey: encPubB64,
                                        accessRootPublicKey:     accPubB64,
                                        rootCid:                 rootCid
                                    };

                                    return Q.Crypto.sign({
                                        secret:      encRoot,
                                        message:     bindingMsg,
                                        primaryType: 'SafecloudBinding',
                                        domain:      {},
                                        types: {
                                            SafecloudBinding: [
                                                { name: 'encryptionRootPublicKey', type: 'string' },
                                                { name: 'accessRootPublicKey',     type: 'string' },
                                                { name: 'rootCid',                 type: 'string' }
                                            ]
                                        },
                                        format: 'ES256'
                                    }).then(function (bindingProof) {
                                        console.warn('Safecloud/store: step 9 done — binding proof signed. '
                                            + 'Calling Jets.put for ' + encChunks.length + ' data chunk(s)...');

                                        // ── Steps 10-11: upload via Jets ──
                                        // Upload grants are empty — server allows anonymous
                                        // uploads (rootCid not yet known at grant time).
                                        // Ownership is proved by the binding proof in the manifest.
                                        //
                                        // The data and index tracks upload in parallel below, but
                                        // each is its own sequential batch loop inside Jets.put —
                                        // Promise.all rejecting the moment ONE of them fails doesn't
                                        // stop the other's loop from continuing on its own. Confirmed
                                        // live: the (single-chunk) index track had zero Drops accept
                                        // it and rejected immediately, while the 69-chunk data track
                                        // — completely unaware — kept uploading and advancing the
                                        // progress bar most of the way to completion, well after
                                        // "Upload failed" had already been shown. putAborted is
                                        // shared between them: the moment either one rejects, the
                                        // other's next batch (checked via Jets.put's isAborted
                                        // option) stops instead of running to completion.
                                        var putAborted = false;
                                        function _markPutAborted(err) { putAborted = true; throw err; }

                                        var putPromises = [
                                            Q.Safecloud.Jets.put({
                                                chunks: encChunks.map(function (c) {
                                                    return {
                                                        cid:        c.cid,
                                                        iv:         c.iv,
                                                        ciphertext: c.ciphertext,
                                                        tag:        c.tag,
                                                        size:       c.size,
                                                        tags:       c.tags
                                                    };
                                                }),
                                                link:      ['track', 'data'],
                                                treeN:     treeN,
                                                treeDepth: treeDepth,
                                                rootCid:   rootCid,
                                                grants:    []
                                            }, {
                                                authorizations: options.authorizations,
                                                payments:       options.payments,
                                                onProgress:     options.onProgress,
                                                isAborted:      function () { return putAborted; }
                                            }).catch(_markPutAborted)
                                        ];

                                        if (indexFork) {
                                            putPromises.push(Q.Safecloud.Jets.put({
                                                chunks: [{
                                                    cid:        indexFork.cid,
                                                    iv:         indexFork.enc.iv,
                                                    ciphertext: indexFork.enc.ciphertext,
                                                    tag:        indexFork.enc.tag,
                                                    size:       0,
                                                    tags:       ['safecloud.track.index']
                                                }],
                                                link:    ['track', 'index'],
                                                rootCid: rootCid,
                                                grants:  []
                                            }, {
                                                authorizations: options.authorizations,
                                                payments:       options.payments,
                                                isAborted:      function () { return putAborted; }
                                            }).catch(_markPutAborted));
                                        }

                                        return Promise.all(putPromises).then(function () {
                                            console.warn('Safecloud/store: steps 10-11 done — Jets.put resolved for all tracks. '
                                                + 'Encrypting+uploading metadata...');
                                            // ── Step 12a: metadata fork ───────────────────────────
                                            // Encrypt and upload a single metadata chunk at track/meta.
                                            // Contains pricing, creator info, and content metadata.
                                            // Readable by anyone with the meta subtree key (Jets, Clouds).
                                            // Never sent to Drops (they enforce their own minPerChunkWei).
                                            var metaObj = {
                                                perChunkWei:    options.perChunkWei    || Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], '1000'),
                                                creatorAddress: options.creatorAddress || null,
                                                incomeContract: options.incomeContract || null,
                                                split:          options.split          || { drop: 6000, jet: 2000, creator: 1500, protocol: 500 },
                                                title:          file.name              || '',
                                                description:    options.description    || '',
                                                type:           file.type              || '',
                                                size:           fileSize,
                                                created:        Math.floor(Date.now() / 1000)
                                            };
                                            // Collapse revenue into metaObj for backwards compat
                                            if (options.revenue) {
                                                Q.extend(metaObj, options.revenue);
                                            }

                                            var metaBytes = new TextEncoder().encode(JSON.stringify(metaObj));

                                            // Derive meta track key: encRoot → HKDF("safecloud.track.meta")
                                            var metaUploadPromise = Q.Crypto.delegate({
                                                rootSecret: encRoot,
                                                label:      'safecloud.track.meta',
                                                context:    '{}',
                                                format:     'ES256'
                                            }).then(function (metaDel) {
                                                return Promise.all([
                                                    _.deriveChunkKey(metaDel.secret, 0),
                                                    _.deriveChunkIV(metaDel.secret, 0)
                                                ]).then(function (kv) {
                                                    return Q.Data.importKey(kv[0]).then(function (cryptoKey) {
                                                        return Q.Data.encrypt(cryptoKey, metaBytes.buffer, {
                                                            iv:         kv[1],
                                                            additional: _.chunkAAD(0)
                                                        });
                                                    }).then(function (enc) {
                                                        return _.chunkCid(enc.ciphertext, enc.tag)
                                                            .then(function (metaCid) {
                                                                return Q.Safecloud.Jets.put({
                                                                    chunks: [{
                                                                        cid:        metaCid,
                                                                        iv:         enc.iv,
                                                                        ciphertext: enc.ciphertext,
                                                                        tag:        enc.tag,
                                                                        size:       metaBytes.length,
                                                                        // Price tag: Jet reads this to enforce
                                                                        // pricing without decrypting the chunk.
                                                                        // format: "safecloud.price:{wei}"
                                                                        tags:       [
                                                                            'safecloud.track.meta',
                                                                            'safecloud.price:' + metaObj.perChunkWei
                                                                        ]
                                                                    }],
                                                                    link:    ['track', 'meta'],
                                                                    rootCid: rootCid,
                                                                    grants:  []
                                                                }, {
                                                                    skipPayment: true
                                                                }).then(function () {
                                                                    return metaCid;
                                                                });
                                                            });
                                                    });
                                                });
                                            });

                                            // ── Step 12: manifest ─────────
                                            return metaUploadPromise.then(function (metaCid) {
                                            console.warn('Safecloud/store: step 12a done — metadata uploaded, metaCid: ' + metaCid);
                                            var manifest = _.buildManifest({
                                                rootCid:                 rootCid,
                                                treeN:                   treeN,
                                                treeDepth:               treeDepth,
                                                chunkCount:              chunkCount,
                                                chunkSize:               chunkSize,
                                                size:                    fileSize,
                                                name:                    file.name || '',
                                                type:                    file.type || (file.data && file.data.type) || '',
                                                tracks:                  tracks,
                                                encryptionRootPublicKey: encPubB64,
                                                accessRootPublicKey:     accPubB64,
                                                bindingProof: {
                                                    statement: bindingMsg,
                                                    proof:     bindingProof
                                                },
                                                jurisdiction:  options.jurisdiction  || null,
                                                aiAttestation: options.aiAttestation || null,
                                                revenue:       options.revenue       || null,
                                                // indexCid — CID of the encrypted index-track chunk.
                                                // Q.Data.Merkle.getNode (the "find it by navigating
                                                // the tree" approach Protocol.md describes) isn't
                                                // implemented anywhere, so fetchIndex.js's documented
                                                // fallback field is the only working path today.
                                                indexCid:      indexFork ? indexFork.cid : null,
                                                // metaCid — CID of the encrypted metadata chunk
                                                // Contains perChunkWei, creatorAddress, incomeContract, split
                                                metaCid:       metaCid               || null,
                                                // perChunkWei summary — plaintext for Cloud convenience
                                                perChunkWei:   metaObj.perChunkWei   || null
                                            });

                                            var result = {
                                                manifest: manifest,
                                                rootKey:  Q.Data.toBase64(rootKey)
                                            };
                                            console.warn('Safecloud/store: step 12 done — manifest built, store() complete');
                                            if (callback) { callback(null, result); }
                                            return result;
                                            }); // metaUploadPromise.then
                                        });
                                    });
                                    }); // rootCidPromise.then
                                });
                            });
                    });
                });
            });
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
