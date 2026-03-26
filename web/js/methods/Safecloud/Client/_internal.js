/**
 * Q.Safecloud.Client — shared internal helpers (_).
 *
 * Loaded once and passed as _ to every Client method file.
 *
 * THREE PARALLEL TREES FROM ONE ROOT:
 *
 *   Merkle tree (bottom up from ciphertext — public, cacheable)
 *   Encryption key tree (top down via chained Q.Crypto.delegate — Cloud only)
 *   Access level tree (top down via chained Q.Crypto.delegate — Jets enforce)
 *
 * The same LINK PATH array navigates all three:
 *   ["track","data","0","1"] → Merkle node / encryption subtreeKey / access grant
 *
 * DELEGATION CHAIN:
 *   encryptionRoot
 *     → delegate("safecloud.track.data")    → trackDataKey
 *         → delegate("safecloud.node.0")    → subtree_0
 *             → delegate("safecloud.node.1") → subtree_0_1 (leaf subtreeKey)
 *   leaf: derive("safecloud.chunk.key.i") → chunkKey[i]  (Q.Data.derive, not delegate)
 *         derive("safecloud.chunk.iv.i")  → chunkIV[i]
 *
 * Platform API facts:
 *   Q.Data.encrypt(key, plaintext, opts) → Promise<{iv, ciphertext, tag}> all base64
 *   Q.Data.decrypt(key, ivB64, ciphertextB64, opts) → Promise<Uint8Array>
 *     opts.tag = base64 tag; opts.additional = Uint8Array AAD
 *   Q.Data.importKey(keyBytes, algo) → Promise<CryptoKey>
 *   Q.Data.derive(seed, label, opts) → Promise<Uint8Array>
 *   Q.Data.canonicalize(obj) → canonical JSON string (RFC 8785)
 *   Q.Crypto.delegate(opts) → Promise<{label,context,secret,statement,proof}>
 *   Q.Crypto.sign(opts) → Promise<{format,signature,signatureHex,publicKey,...}>
 *   Q.Crypto.internalKeypair(opts) → Promise<{format,privateKey,publicKey,[address]}>
 */

Q.exports(function (Q) {

    var _ = {};

    // ─────────────────────────────────────────────────────────────────────
    // 1. LABELS — all HKDF domain-separation labels
    // ─────────────────────────────────────────────────────────────────────

    _.LABELS = {
        // Root derivations (Q.Crypto.delegate, called once per operation)
        encryptionRoot: 'safecloud.encryption.root',
        accessRoot:     'safecloud.access.root',
        version:        function (v)    { return 'safecloud.version.' + v; },

        // Track labels — first delegation level below encryptionRoot / accessRoot
        // Used for the first path segment: ["track", <name>]
        track:          function (name) { return 'safecloud.track.' + name; },
        accessTrack:    function (name) { return 'safecloud.access.track.' + name; },

        // Subtree node labels — used for each path segment below track level
        // Used for segments: ["track", <name>, "0", "1", ...]
        node:           function (seg)  { return 'safecloud.node.' + seg; },
        accessNode:     function (seg)  { return 'safecloud.access.node.' + seg; },

        // Chunk-level labels (Q.Data.derive only — O(N), never delegated)
        chunkKey:       function (i)    { return 'safecloud.chunk.key.' + i; },
        chunkIV:        function (i)    { return 'safecloud.chunk.iv.'  + i; }
    };

    // ─────────────────────────────────────────────────────────────────────
    // 2. base32 — RFC 4648 lowercase multibase 'b'
    // ─────────────────────────────────────────────────────────────────────

    _.base32 = function (bytes) {
        var alpha  = 'abcdefghijklmnopqrstuvwxyz234567';
        var result = '', bits = 0, value = 0;
        for (var i = 0; i < bytes.length; i++) {
            value = (value << 8) | bytes[i]; bits += 8;
            while (bits >= 5) { bits -= 5; result += alpha[(value >>> bits) & 0x1f]; }
        }
        if (bits > 0) { result += alpha[(value << (5 - bits)) & 0x1f]; }
        return result;
    };

    // ─────────────────────────────────────────────────────────────────────
    // 3. digestToCid — CIDv1 from 32-byte SHA-256
    // ─────────────────────────────────────────────────────────────────────

    _.digestToCid = function (digest) {
        var header = new Uint8Array([0x01, 0x55, 0x12, 0x20]);
        var full   = new Uint8Array(header.length + digest.length);
        full.set(header, 0); full.set(digest, header.length);
        return 'b' + _.base32(full);
    };

    // ─────────────────────────────────────────────────────────────────────
    // 4. chunkAAD — AES-GCM Additional Authenticated Data
    //    Uses ABSOLUTE index — prevents chunk-swap attacks
    // ─────────────────────────────────────────────────────────────────────

    _.chunkAAD = function (absIndex) {
        return new TextEncoder().encode('safecloud.chunk:' + absIndex);
    };

    // ─────────────────────────────────────────────────────────────────────
    // 5. blobToBuffer
    // ─────────────────────────────────────────────────────────────────────

    _.blobToBuffer = function (blob) {
        // Accept ArrayBuffer/Uint8Array directly (no FileReader needed)
        if (blob instanceof ArrayBuffer) {
            return Promise.resolve(blob);
        }
        if (blob instanceof Uint8Array) {
            return Promise.resolve(blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength));
        }
        // Blob or File — use FileReader
        return new Promise(function (resolve, reject) {
            var reader     = new FileReader();
            reader.onload  = function (e) { resolve(e.target.result); };
            reader.onerror = function (e) { reject(e.target.error); };
            reader.readAsArrayBuffer(blob);
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 6. chunkify
    // ─────────────────────────────────────────────────────────────────────

    _.chunkify = function (buffer, chunkSize) {
        var total = buffer.byteLength, chunks = [];
        if (total === 0) { return [buffer.slice(0, 0)]; }
        for (var off = 0; off < total; off += chunkSize) {
            chunks.push(buffer.slice(off, Math.min(off + chunkSize, total)));
        }
        return chunks;
    };

    // ─────────────────────────────────────────────────────────────────────
    // 7. levelFromLabel / parseLabel / verifyCapability
    //    Used for fast local access-level checks (no crypto)
    // ─────────────────────────────────────────────────────────────────────

    _.levelFromLabel = function (type, word) {
        var key = type.toUpperCase() + '_LEVEL';
        if (Q.Streams && Q.Streams[key] && Q.Streams[key][word] !== undefined) {
            return Q.Streams[key][word];
        }
        var defaults = {
            READ_LEVEL:  { none: 0, see: 10, content: 23, max: 40 },
            WRITE_LEVEL: { none: 0, post: 20, max: 40 },
            ADMIN_LEVEL: { none: 0, invite: 20, manage: 30, close: 40, max: 40 }
        };
        return (defaults[key] && defaults[key][word] !== undefined) ? defaults[key][word] : 0;
    };

    /**
     * Check whether a grant's link path covers a given absolute chunk index.
     * The grant covers a chunk if its link path is a prefix of (or equal to)
     * the chunk's position path in the tree — i.e. the grant's subtree contains
     * that chunk leaf.
     *
     * For the fast local guard we check:
     *   grant.statement.context.link is ancestor-or-equal of chunkPath(chunkIndex)
     *   grant.statement.context.readLevel >= required
     *   exp not exceeded
     *
     * Full cryptographic verification is on Jets.
     */
    _.grantCoversChunk = function (grant, requiredReadLevel, absIndex, manifest) {
        if (!grant || !grant.statement) { return false; }
        var ctx;
        try { ctx = JSON.parse(grant.statement.context); } catch (e) { return false; }
        if (!ctx.link || !Array.isArray(ctx.link)) { return false; }
        if (ctx.rootCid && ctx.rootCid !== manifest.rootCid) { return false; }
        if (ctx.exp && ctx.exp > 0 && Math.floor(Date.now() / 1000) > ctx.exp) { return false; }
        if (typeof ctx.readLevel === 'number' && ctx.readLevel < requiredReadLevel) { return false; }

        // Check whether the link path covers this chunk.
        // We know the chunk's position in the tree from its absIndex + treeN + treeDepth.
        var chunkPath = _.chunkLinkPath(absIndex, manifest);
        return _isAncestorOrEqual(ctx.link, chunkPath);
    };

    /**
     * Return the full link path to a leaf chunk at absIndex in the data track.
     * e.g. for binary tree depth 3, chunk 5: ["track","data","1","0","1"]
     */
    _.chunkLinkPath = function (absIndex, manifest) {
        var treeN     = manifest.treeN     || 2;
        var treeDepth = manifest.treeDepth || Math.max(1, Math.ceil(Math.log(manifest.chunkCount || 1) / Math.log(treeN)));
        var path      = ['track', 'data'];
        var n         = Math.pow(treeN, treeDepth); // total leaves in padded tree
        var idx       = absIndex;
        for (var d = 0; d < treeDepth; d++) {
            n = n / treeN;
            path.push(String(Math.floor(idx / n)));
            idx = idx % n;
        }
        return path;
    };

    // Whether pathA is an ancestor-or-equal prefix of pathB
    function _isAncestorOrEqual(pathA, pathB) {
        if (pathA.length > pathB.length) { return false; }
        for (var i = 0; i < pathA.length; i++) {
            if (String(pathA[i]) !== String(pathB[i])) { return false; }
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────
    // 8. buildManifest — updated for N-ary tree fields
    // ─────────────────────────────────────────────────────────────────────

    _.buildManifest = function (p) {
        return {
            v:                       Q.Safecloud.Client.manifestVersion,
            rootCid:                 p.rootCid,
            treeN:                   p.treeN     || 2,
            treeDepth:               p.treeDepth || 1,
            chunkCount:              p.chunkCount,
            chunkSize:               p.chunkSize,
            size:                    p.size,
            name:                    p.name,
            type:                    p.type,
            tracks:                  p.tracks    || ['data'],
            created:                 Math.floor(Date.now() / 1000),
            encryptionRootPublicKey: p.encryptionRootPublicKey,
            accessRootPublicKey:     p.accessRootPublicKey,
            bindingProof:            p.bindingProof,
            jurisdiction:            p.jurisdiction  || null,
            aiAttestation:           p.aiAttestation || null
        };
    };

    // ─────────────────────────────────────────────────────────────────────
    // 9. Root key derivations (Q.Crypto.delegate, called once per operation)
    // ─────────────────────────────────────────────────────────────────────

    _.deriveEncryptionRoot = function (rootKey) {
        return Q.Crypto.delegate({
            rootSecret: rootKey,
            label:      _.LABELS.encryptionRoot,
            context:    '{}',
            format:     'ES256'
        });
    };

    _.deriveAccessRootBytes = function (rootKey) {
        return Q.Crypto.delegate({
            rootSecret: rootKey,
            label:      _.LABELS.accessRoot,
            context:    '{}',
            format:     'ES256'
        });
    };

    _.deriveVersionKey = function (videoKey, versionLabel) {
        return Q.Crypto.delegate({
            rootSecret: videoKey,
            label:      _.LABELS.version(versionLabel),
            context:    '{}',
            format:     'ES256'
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 10. deriveByPath — CORE: chains Q.Crypto.delegate down a link path
    //
    //   linkPath = ["track","data","0","1"]
    //   Step 1: label = LABELS.track("data")  → delegate(parentKey, label, '{}')
    //   Step 2: label = LABELS.node("0")      → delegate(step1.secret, label, '{}')
    //   Step 3: label = LABELS.node("1")      → delegate(step2.secret, label, tipContext)
    //   Returns full delegation result { secret, statement, proof } at the tip.
    //
    //   tipContext: '{}' at store time (rootCid unknown); full JSON at grant time.
    //   The path MUST start with "track" as the second element after skipping
    //   the literal "track" segment. First segment below the track level uses
    //   LABELS.track(name); all deeper segments use LABELS.node(segment).
    // ─────────────────────────────────────────────────────────────────────

    _.deriveByPath = function (parentKey, linkPath, tipContext) {
        // linkPath must be at least ["track", <name>]
        if (!linkPath || linkPath.length < 2 || linkPath[0] !== 'track') {
            return Promise.reject(new Error('deriveByPath: linkPath must start with ["track",...]'));
        }
        tipContext = tipContext || '{}';

        // Build the sequence of (label, context) pairs
        // Segment 0 is always "track" — skip it, it's the root prefix
        // Segment 1 is the track name: LABELS.track(name)
        // Segments 2+ are node IDs: LABELS.node(seg)
        var steps = [];
        for (var i = 1; i < linkPath.length; i++) {
            var label   = (i === 1)
                ? _.LABELS.track(linkPath[i])
                : _.LABELS.node(linkPath[i]);
            var context = (i === linkPath.length - 1) ? tipContext : '{}';
            steps.push({ label: label, context: context });
        }

        // Chain delegate calls sequentially
        return steps.reduce(function (prev, step) {
            return prev.then(function (current) {
                return Q.Crypto.delegate({
                    rootSecret: current.secret || current,
                    label:      step.label,
                    context:    step.context,
                    format:     'ES256'
                });
            });
        }, Promise.resolve({ secret: parentKey }));
    };

    // ─────────────────────────────────────────────────────────────────────
    // 11. deriveByAccessPath — same as deriveByPath but for access level tree
    //     Uses LABELS.accessTrack / LABELS.accessNode
    // ─────────────────────────────────────────────────────────────────────

    _.deriveByAccessPath = function (accessRoot, linkPath, tipContext) {
        if (!linkPath || linkPath.length < 2 || linkPath[0] !== 'track') {
            return Promise.reject(new Error('deriveByAccessPath: linkPath must start with ["track",...]'));
        }
        tipContext = tipContext || '{}';

        var steps = [];
        for (var i = 1; i < linkPath.length; i++) {
            var label   = (i === 1)
                ? _.LABELS.accessTrack(linkPath[i])
                : _.LABELS.accessNode(linkPath[i]);
            var context = (i === linkPath.length - 1) ? tipContext : '{}';
            steps.push({ label: label, context: context });
        }

        return steps.reduce(function (prev, step) {
            return prev.then(function (current) {
                return Q.Crypto.delegate({
                    rootSecret: current.secret || current,
                    label:      step.label,
                    context:    step.context,
                    format:     'ES256'
                });
            });
        }, Promise.resolve({ secret: accessRoot }));
    };

    // ─────────────────────────────────────────────────────────────────────
    // 12. deriveSubtreeKey — convenience: deriveByPath with no tip context
    //     Used at store() time when rootCid is not yet known.
    // ─────────────────────────────────────────────────────────────────────

    _.deriveSubtreeKey = function (encryptionRoot, linkPath) {
        return _.deriveByPath(encryptionRoot, linkPath, '{}');
    };


    // ─────────────────────────────────────────────────────────────────────
    // 14. treeParams — compute treeN and treeDepth from chunk count
    // ─────────────────────────────────────────────────────────────────────

    _.treeParams = function (chunkCount, treeN) {
        treeN = treeN || 2;
        if (chunkCount <= 0) { return { treeN: treeN, treeDepth: 1 }; }
        var depth = Math.ceil(Math.log(chunkCount) / Math.log(treeN));
        return { treeN: treeN, treeDepth: Math.max(1, depth) };
    };

    // ─────────────────────────────────────────────────────────────────────
    // 15. leafRangeForPath — given a link path, return {start, end} of
    //     absolute chunk indices covered by that subtree node.
    //     This is the inverse of chunkLinkPath.
    // ─────────────────────────────────────────────────────────────────────

    _.leafRangeForPath = function (linkPath, manifest) {
        var treeN     = manifest.treeN     || 2;
        var treeDepth = manifest.treeDepth || 1;
        var total     = Math.pow(treeN, treeDepth); // padded leaf count

        // linkPath = ["track","data","0","1",...]
        // segments below "track","data" are node indices
        var nodeSegs = linkPath.slice(2); // e.g. ["0","1"]
        var start    = 0;
        var width    = total;
        for (var i = 0; i < nodeSegs.length; i++) {
            width = width / treeN;
            start = start + parseInt(nodeSegs[i], 10) * width;
        }
        // Clamp to actual chunk count
        var end = Math.min(start + width, manifest.chunkCount);
        start   = Math.min(start, manifest.chunkCount);
        return { start: Math.floor(start), end: Math.floor(end) };
    };

    // ─────────────────────────────────────────────────────────────────────
    // 16. Chunk key / IV — Q.Data.derive (O(N), never delegated)
    // ─────────────────────────────────────────────────────────────────────

    _.deriveChunkKey = function (subtreeKey, relIndex) {
        return Q.Data.derive(subtreeKey, _.LABELS.chunkKey(relIndex), { size: 32 });
    };

    _.deriveChunkIV = function (subtreeKey, relIndex) {
        return Q.Data.derive(subtreeKey, _.LABELS.chunkIV(relIndex), { size: 12 });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 17. chunkCid — SHA-256(ciphertext || tag) → CIDv1
    //     Must match Drops._internal.cidFromData exactly.
    // ─────────────────────────────────────────────────────────────────────

    _.chunkCid = function (ciphertextB64, tagB64) {
        var ct = Q.Data.fromBase64(ciphertextB64);
        var tg = Q.Data.fromBase64(tagB64);
        var combined = new Uint8Array(ct.length + tg.length);
        combined.set(ct, 0); combined.set(tg, ct.length);
        return Q.Data.digest('SHA-256', combined).then(function (digest) {
            return _.digestToCid(digest);
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 18. deriveLeafKeyFromGrant — navigate from grant node down to chunk leaf
    //
    //   Given a grant whose secret is at grant.link (e.g. ["track","data"]),
    //   navigate down to the leaf node for absIdx, then return that leaf key.
    //   relIdx within the leaf is always 0 (each leaf = one chunk).
    //
    //   This is needed because Q.Crypto.delegate is chained per path segment:
    //     grant at ["track","data"] → secret = trackDataKey
    //     chunk 5 leaf path = ["track","data","0","1","0"]
    //     segsBelow = ["0","1","0"]
    //     navigate: trackDataKey → node.0 → node.1 → node.0 = leafKey
    //     chunkKey = derive(leafKey, "safecloud.chunk.key.0")
    //
    //   For a grant already at the leaf (segsBelow is empty), returns grantSecret directly.
    // ─────────────────────────────────────────────────────────────────────

    _.deriveLeafKeyFromGrant = function (grantSecret, grantLink, absIdx, manifest) {
        var leafPath  = _.chunkLinkPath(absIdx, manifest);
        var grantDepth = grantLink ? grantLink.length : 2;
        var segsBelow  = leafPath.slice(grantDepth);  // path segments below the grant node

        if (!segsBelow.length) {
            // Grant is already at the leaf
            return Promise.resolve(grantSecret);
        }

        // Chain Q.Crypto.delegate once per segment below the grant node
        return segsBelow.reduce(function (prev, seg) {
            return prev.then(function (currentKey) {
                return Q.Crypto.delegate({
                    rootSecret: currentKey,
                    label:      _.LABELS.node(seg),
                    context:    '{}',
                    format:     'ES256'
                }).then(function (d) { return d.secret; });
            });
        }, Promise.resolve(grantSecret));
    };


    return _;
});
