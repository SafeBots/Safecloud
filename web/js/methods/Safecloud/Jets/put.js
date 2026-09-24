/**
 * Q.Safecloud.Jets.put — upload encrypted chunks for a subtree by link path.
 *
 * Splits subtree.chunks into several Safecloud/subtree/put emits instead of
 * sending the whole track in one socket.io message — a single emit for an
 * entire large video (potentially hundreds of megabytes of base64 ciphertext)
 * risked exceeding the Jet's socket.io maxHttpBufferSize (50MB, see
 * local/app.json), which simply dropped/failed the upload with no way to
 * recover short of raising that limit again for the next larger file. Each
 * batch is budgeted by the chunks' plaintext byte size (base64 encoding and
 * JSON framing inflate that by roughly a third on the wire, already
 * accounted for in BATCH_BYTES_DEFAULT), not by chunk count, since chunk
 * sizes vary a lot (index/meta chunks are tiny; video fragment-based chunks
 * from buildVideoIndex.js can run several MB each).
 *
 * Batches for the same link path are sent sequentially, each carrying
 * chunkOffset/totalChunks so the Jet can place them at the right position
 * in its per-link CID index (classes/Safecloud/Jets.js's _handleSubtreePut)
 * regardless of how many emits the upload was split into — the Jet's index
 * update is idempotent per (rootCid, link, offset), so a retried batch never
 * corrupts an already-stored one.
 *
 * @param {Object} subtree
 *   subtree.chunks   Array    — encrypted chunk objects { cid, iv, ciphertext, tag, size, tags }
 *   subtree.link     Array    — link path, e.g. ["track","data"] or ["track","index"]
 *   subtree.grants   Array    — OCP Role A grant objects authorizing this upload
 * @param {Object} [options]
 *   options.payments       Array
 *   options.publisherId    String
 *   options.streamName     String
 *   options.onProgress     fn(stored, total) — called after each batch, not just at the end
 *   options.batchBytes     Number — override the per-emit byte budget (default 6MB of plaintext)
 *   options.isAborted      fn() => Boolean — checked before each batch; when store.js uploads
 *     several tracks in parallel (data + index) via Promise.all and one of them fails outright,
 *     nothing else stops the others' sequential batch loops on its own — confirmed live: the tiny
 *     index track had zero Drops accept it while the 69-chunk data track kept right on going,
 *     progress bar and all, well after the overall upload had already been reported as failed.
 */
Q.exports(function (Q, _) {
    // Kept well under the Jet's 50MB maxHttpBufferSize even after base64 +
    // JSON overhead (~1.4x), leaving headroom for other concurrent traffic
    // on the same socket (other tracks' batches, playback requests, etc).
    var BATCH_BYTES_DEFAULT = 6 * 1024 * 1024;
    // Also cap chunk count per emit regardless of size, so a track made of
    // many tiny chunks doesn't turn into one giant JSON array either.
    var BATCH_CHUNKS_MAX = 128;
    // Mirrors the Jet's own PUT_TIMEOUT_PER_CHUNK_MS scaling (classes/Safecloud/Jets.js)
    // so a big batch isn't held to the same fixed timeout as a single chunk.
    var BATCH_TIMEOUT_BASE_MS     = 20000;
    var BATCH_TIMEOUT_PER_CHUNK_MS = 500;

    function chunkByteSize(c) {
        if (!c) { return 0; }
        if (c.size) { return c.size; }
        if (c.ciphertext && c.ciphertext.length) {
            return Math.floor(c.ciphertext.length * 3 / 4);
        }
        return 0;
    }

    function makeBatches(chunks, batchBytes) {
        var batches = [];
        var current = [];
        var currentBytes = 0;
        chunks.forEach(function (c) {
            var size = chunkByteSize(c);
            if (current.length && (currentBytes + size > batchBytes || current.length >= BATCH_CHUNKS_MAX)) {
                batches.push(current);
                current = [];
                currentBytes = 0;
            }
            current.push(c);
            currentBytes += size;
        });
        if (current.length || !batches.length) { batches.push(current); }
        return batches;
    }

    return function Q_Safecloud_Jets_put(subtree, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var allChunks = subtree.chunks || [];
        var link      = subtree.link   || ['track', 'data'];
        // Strip encryption secrets — Jet only needs statement+proof for authorization.
        var grants    = (subtree.grants || []).map(function (g) {
            return { link: g.link, statement: g.statement, proof: g.proof, start: g.start, end: g.end };
        });
        var payments   = options.payments || [];
        var batchBytes = options.batchBytes || BATCH_BYTES_DEFAULT;
        var totalChunks = allChunks.length;

        var batches = makeBatches(allChunks, batchBytes);
        var offset = 0;
        var mergedResults = [];
        var storedSoFar = 0;

        function putBatch(batchChunks) {
            var batchOffset = offset;
            var payload = {
                chunks:      batchChunks,
                link:        link,
                grants:      grants,
                payments:    payments,
                chunkOffset: batchOffset,
                totalChunks: totalChunks
            };
            if (subtree.treeN)     { payload.treeN     = subtree.treeN; }
            if (subtree.treeDepth) { payload.treeDepth = subtree.treeDepth; }
            if (subtree.rootCid)   { payload.rootCid   = subtree.rootCid; }
            if (options.publisherId) { payload.publisherId = options.publisherId; }
            if (options.streamName)  { payload.streamName  = options.streamName; }

            var timeoutMs = Math.max(
                BATCH_TIMEOUT_BASE_MS, batchChunks.length * BATCH_TIMEOUT_PER_CHUNK_MS
            );

            return _.emit('Safecloud/subtree/put', payload, timeoutMs).then(function (result) {
                var results = (result && result.results) || [];
                results.forEach(function (r, i) {
                    if (!r || !r.stored) { return; }
                    _.cloudStats.chunksUploaded++;
                    var src = batchChunks[i];
                    if (src && src.size) { _.cloudStats.bytesUploaded += src.size; }
                    else if (src && src.ciphertext) {
                        _.cloudStats.bytesUploaded +=
                            Math.floor(src.ciphertext.length * 3 / 4);
                    }
                });
                mergedResults = mergedResults.concat(results);
                storedSoFar += results.filter(function (r) { return r && r.stored; }).length;
                if (options.onProgress) { options.onProgress(storedSoFar, totalChunks); }
                offset += batchChunks.length;
            });
        }

        // Sequential on purpose: keeps at most one batch's ciphertext in
        // flight at a time, which is the entire point of batching — running
        // every batch in parallel would just reassemble the same memory/
        // buffer spike this refactor exists to avoid.
        var _promise = batches.reduce(function (p, batchChunks) {
            return p.then(function () {
                if (options.isAborted && options.isAborted()) {
                    throw new Error('Q.Safecloud.Jets.put: aborted (a sibling track failed)');
                }
                return putBatch(batchChunks);
            });
        }, Promise.resolve()).then(function () {
            // Check that at least one Drop confirmed each chunk — if every chunk
            // has stored:false, reject so the caller knows the upload failed
            if (mergedResults.length > 0) {
                var allFailed = mergedResults.every(function (r) { return !r || !r.stored; });
                if (allFailed) {
                    throw new Error('Q.Safecloud.Jets.put: no Drops stored any chunks (quota full or unavailable)');
                }
            }
            var result = { results: mergedResults };
            if (callback) { callback(null, result); }
            return result;
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
