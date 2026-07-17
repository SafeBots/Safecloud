/**
 * Q.Safecloud.Drops.get — serve encrypted chunks from IndexedDB.
 *
 * 1. If paymentToken present: verify Jet Safebux balance (1-hour cache).
 *    Return all-null if insufficient.
 * 2. Store payment token in tokens store (dedup by SHA-256 of canonical JSON).
 * 3. Read each CID from chunks store; update LRU lastAccessed.
 * 4. Return { chunks: [{cid, iv, ciphertext, tag}|null] }
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_get(cids, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var paymentToken = options.paymentToken || null;

        var _promise = _checkBalance(paymentToken, cids.length).then(function (ok) {
            if (!ok) {
                var nulls = cids.map(function () { return null; });
                if (callback) { callback(null, { chunks: nulls }); }
                return { chunks: nulls };
            }

            return _.openDB().then(function (db) {
                // Store token for later claiming (idempotent)
                return _storeToken(db, paymentToken).then(function () {
                    var now = _.nowSec();

                    var chunkPromises = cids.map(function (cid) {
                        return new Promise(function (resolve, reject) {
                            var tx  = db.transaction(_.STORES.chunks, 'readonly');
                            var req = tx.objectStore(_.STORES.chunks).get(_.chunkKey(cid));
                            req.onsuccess = function (e) { resolve(e.target.result || null); };
                            req.onerror   = function (e) { reject(e.target.error); };
                        }).then(function (chunk) {
                            if (!chunk) { return null; }
                            // Update LRU in a separate transaction (read + write LRU only)
                            var tx2 = db.transaction(_.STORES.lru, 'readwrite');
                            tx2.objectStore(_.STORES.lru).put({
                                cid: cid, size: chunk.size || 0, lastAccessed: now
                            });
                            return {
                                cid:        chunk.cid,
                                iv:         chunk.iv,
                                ciphertext: chunk.ciphertext,
                                tag:        chunk.tag
                            };
                        });
                    });

                    return Promise.all(chunkPromises).then(function (chunks) {
                        // Accumulate real served-bytes stats.
                        // Rate comes from config so the dashboard matches the
                        // actual token economics (see Safecloud.drop.sbuxPerMB).
                        var SBUX_PER_MB = _.jetInfo(['drop', 'sbuxPerMB'],
                            ['Safecloud', 'drop', 'sbuxPerMB'], 0.02);
                        chunks.forEach(function (ch) {
                            if (!ch) { return; }
                            // ciphertext is base64; estimate plaintext size from length
                            var bytes = ch.ciphertext
                                ? Math.floor(ch.ciphertext.length * 3 / 4)
                                : 0;
                            _._state.servedBytes  += bytes;
                            _._state.servedChunks += 1;
                            _._state.safebuxEarned += (bytes / 1048576) * SBUX_PER_MB;
                            _.logActivity('get', { bytes: bytes,
                                paid: !!(paymentToken && paymentToken.sig
                                     && paymentToken.sig.length) });
                        });
                        var result = { chunks: chunks };
                        if (callback) { callback(null, result); }
                        return result;
                    });
                });
            });
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };

    // ── Balance check ──────────────────────────────────────────────────────

    function _checkBalance(paymentToken, chunkCount) {
        if (!paymentToken || !paymentToken.stm) { return Promise.resolve(true); }
        var stm      = paymentToken.stm;
        var jetEVM   = stm.payer;

        // ── Drop's own 402 enforcement ────────────────────────────────────────
        // Drop rejects if the payment token max < minPerChunkWei × chunkCount.
        // This enforces the Drop's own price reservation, independently of the Jet.
        // Drop doesn't know the content — it only knows what price it will accept.
        var minPerChunk = Q.Config.get(['Safecloud', 'drop', 'minPerChunkWei'],
            Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], '1000'));
        if (minPerChunk && chunkCount > 0) {
            // Watermark semantics: stm.max is the payer's CUMULATIVE channel
            // ceiling. The per-batch due rides on the envelope as `amount`;
            // compare the reservation against that (fall back to max for
            // legacy tokens without the hint).
            var tokenMax  = BigInt(paymentToken.amount || stm.max || '0');
            var minTotal  = BigInt(minPerChunk) * BigInt(chunkCount);
            if (tokenMax < minTotal) {
                // Payment below Drop's reservation — reject with 402-equivalent
                // The null result causes the Jet to try another Drop
                return Promise.resolve(false);
            }
        }
        var cacheKey = _.balanceCacheKey(jetEVM) + ':' + (stm.token || '').toLowerCase();
        var ttl      = _.jetInfo(null, ['Safecloud', 'drop', 'balanceCacheTtlMs'], 3600000);
        var perChunk = _.jetInfo(['safebux', 'perChunkWei'],
                           ['Safecloud', 'safebux', 'perChunkWei'], '1000');
        var required = BigInt(perChunk) * BigInt(chunkCount);

        var cached = _._state.balanceCache[cacheKey];
        if (cached && (Date.now() - cached.cachedAt) < ttl) {
            return Promise.resolve(cached.balance >= required);
        }

        // Lazy-load the vendored ethers bundle; if it can't load, fail open
        // (same posture as an RPC error — the Drop serves rather than stalls).
        return Q.Safecloud.ensureEthers().then(function () {
            return _checkOnChain();
        }).catch(function () { return true; });

        function _checkOnChain() {
        // Resolve RPC URL from Users.web3.chains (hex chainId) with CAIP-2 → hex conversion
        var chainId = stm.chainId || 'eip155:56';
        var hexId   = chainId.indexOf('eip155:') === 0
            ? '0x' + parseInt(chainId.slice(7), 10).toString(16)
            : chainId;
        var chainConf = Q.Config.get(['Users', 'web3', 'chains', hexId], null);
        var rpcUrl    = (chainConf && (chainConf.rpcUrl || chainConf.publicRPC)) ||
                        Q.Config.get(['Safecloud', 'evm', 'provider', hexId],
                            'https://bsc-dataseed.binance.org/');

        var provider = new ethers.JsonRpcProvider(rpcUrl);

        // Use availableToday() if the Safebux contract supports it (velocity limit),
        // otherwise fall back to balanceOf (fail-open — Drop earns nothing if Jet can't pay)
        var safebuxAddr = stm.token;
        var SAFEBUX_ABI = [
            'function availableToday(address) view returns (uint256)',
            'function balanceOf(address) view returns (uint256)'
        ];
        var contract = new ethers.Contract(safebuxAddr, SAFEBUX_ABI, provider);

        return contract.availableToday(jetEVM).then(function (available) {
            _._state.balanceCache[cacheKey] = { balance: available, cachedAt: Date.now() };
            return available >= required;
        }).catch(function () {
            // availableToday not available — fall back to balanceOf
            return contract.balanceOf(jetEVM).then(function (balance) {
                _._state.balanceCache[cacheKey] = { balance: balance, cachedAt: Date.now() };
                return balance >= required;
            }).catch(function () {
                return true; // fail open
            });
        });
        } // _checkOnChain
    }

    // ── Token storage ──────────────────────────────────────────────────────

    function _storeToken(db, token) {
        if (!token) { return Promise.resolve(); }
        // Hash with Q.Data.canonicalize (RFC 8785) for deterministic dedup key
        var canonical = Q.Data.canonicalize(token);
        var encoded   = new TextEncoder().encode(canonical);
        return Q.Data.digest('SHA-256', encoded).then(function (hashBytes) {
            var tokenHash = Q.Data.toBase64(hashBytes);
            return new Promise(function (resolve) {
                var tx  = db.transaction(_.STORES.tokens, 'readwrite');
                var req = tx.objectStore(_.STORES.tokens).add({
                    tokenHash:  tokenHash,
                    token:      token,
                    receivedAt: _.nowSec(),
                    redeemed:   false
                });
                // Ignore ConstraintError — already stored is fine
                req.onsuccess = function () { resolve(); };
                req.onerror   = function () { resolve(); };
            });
        });
    }
});
