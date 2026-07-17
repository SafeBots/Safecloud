/**
 * Q.Safecloud.Client.fetchMeta — fetch and decrypt the metadata fork for a manifest.
 *
 * The metadata fork is a single encrypted chunk stored at track/meta.
 * It contains plaintext-equivalent JSON readable by any entity with the meta subtree key:
 *   {
 *     perChunkWei:    String   — publisher-set price per chunk (in Safebux wei)
 *     creatorAddress: String   — content creator EVM address
 *     incomeContract: String   — IncomeContract address for batched royalty distribution
 *     split: {                 — basis points (must sum to 10000)
 *       drop:     Number,      — Drop storage/bandwidth share
 *       jet:      Number,      — Jet routing share
 *       creator:  Number,      — Creator royalty share
 *       protocol: Number       — Protocol treasury share
 *     },
 *     title:          String   — optional content title
 *     description:    String   — optional content description
 *   }
 *
 * The metadata key is derived from the same HKDF root as the data key:
 *   encryptionRoot → HKDF("safecloud.track.meta") → metaKey
 *
 * This key is separate from the data track key — granting meta access does not
 * grant data access and vice versa. Jets receive the meta key to enforce pricing.
 * Drops never receive the meta key (they don't need to know the price, only that
 * payment was sufficient — enforced by their own minPerChunkWei reservation).
 *
 * @param {Object} manifest    — manifest from Client.store()
 * @param {String} rootKey     — base64 root key (from store() result.rootKey)
 * @param {Object} [options]
 * @return {Promise<Object>}   — decrypted metadata object
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Client_fetchMeta(manifest, rootKey, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        if (!manifest || !manifest.metaCid) {
            var err = new Error('Q.Safecloud.Client.fetchMeta: manifest has no metaCid');
            if (callback) { callback(err); return; }
            return Promise.reject(err);
        }

        var rootKeyBytes = (typeof rootKey === 'string')
            ? Q.Data.fromBase64(rootKey) : rootKey;

        var _promise = _.deriveEncryptionRoot(rootKeyBytes).then(function (encRoot) {
            // Derive the meta track key — same pattern as data track
            return Q.Crypto.delegate({
                rootSecret: encRoot.secret,
                label:      'safecloud.track.meta',
                context:    '{}',
                format:     'ES256'
            });
        }).then(function (metaDel) {
            // The meta chunk uses relative index 0 (single chunk per meta track)
            return Promise.all([
                _.deriveChunkKey(metaDel.secret, 0),
                _.deriveChunkIV(metaDel.secret, 0)
            ]).then(function (kv) {
                // Fetch the raw encrypted meta chunk from Jets
                return Q.Safecloud.Jets.get({
                    rootCid: manifest.rootCid,
                    link:    ['track', 'meta'],
                    grants:  options.grants || [],
                    manifest: manifest
                }, {
                    skipPayment: true  // meta fetch is free — it's how you learn the price
                }).then(function (result) {
                    var chunk = result && result.chunks && result.chunks[0];
                    if (!chunk) {
                        throw new Error('Q.Safecloud.Client.fetchMeta: meta chunk not found');
                    }

                    // Decrypt with meta leaf key
                    return Q.Data.importKey(kv[0]).then(function (cryptoKey) {
                        return Q.Data.decrypt(cryptoKey, chunk.iv, chunk.ciphertext, {
                            tag:        chunk.tag,
                            additional: _.chunkAAD(0)
                        });
                    }).then(function (plaintext) {
                        var json = new TextDecoder().decode(plaintext);
                        var meta;
                        try { meta = JSON.parse(json); } catch (e) {
                            throw new Error('Q.Safecloud.Client.fetchMeta: invalid metadata JSON');
                        }
                        if (callback) { callback(null, meta); }
                        return meta;
                    });
                });
            });
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };
});
