/**
 * Q.Safecloud.Drops.claimPayments — claim accumulated Safebux payment tokens.
 *
 * Two paths:
 *   options.direct = true  → paymentsExecute directly via ethers.js (Drop pays gas)
 *   options.direct = false → relay via Safecloud/drop/claimPayments event (Jet pays gas)
 *
 * Token dedup key uses Q.Data.canonicalize (RFC 8785) for deterministic hashing.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_claimPayments(options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        var threshold = Q.Config.get(['Safecloud', 'drop', 'claimThresholdSafebux'], '100000');
        var batchSize = Q.Config.get(['Safecloud', 'drop', 'claimBatchSize'], 10);
        var OC_ADDR   = Q.Config.get(['Safecloud', 'openclaiming', 'address'], '0x99996a51cc950d9822D68b83fE1Ad97B32Cd9999');

        var _promise = _.openDB().then(function (db) {
            // Load all unredeemed tokens
            return new Promise(function (resolve, reject) {
                var tx    = db.transaction(_.STORES.tokens, 'readonly');
                var index = tx.objectStore(_.STORES.tokens).index('redeemed');
                var req   = index.getAll(IDBKeyRange.only(false)); // redeemed === false
                req.onsuccess = function (e) { resolve(e.target.result || []); };
                req.onerror   = function (e) { reject(e.target.error); };
            }).then(function (tokenRecords) {
                // Filter to tokens matching configured Safebux token and chainId
                var acceptedToken   = Q.Config.get(['Safecloud', 'safebux', 'address'], null);
                var acceptedChainId = Q.Config.get(['Safecloud', 'safebux', 'chainId'], 'eip155:56');
                if (acceptedToken) {
                    tokenRecords = tokenRecords.filter(function (r) {
                        var stm = r && r.token && r.token.stm;
                        if (!stm) { return false; }
                        var tokenMatch = stm.token && stm.token.toLowerCase() === acceptedToken.toLowerCase();
                        var chainMatch = !stm.chainId || stm.chainId === acceptedChainId;
                        return tokenMatch && chainMatch;
                    });
                }
                if (!tokenRecords.length) {
                    if (callback) { callback(null, { claimed: 0, txHashes: [] }); }
                    return { claimed: 0, txHashes: [] };
                }

                // Check if total value exceeds threshold (unless forced)
                if (!options.force) {
                    var totalMax = tokenRecords.reduce(function (sum, tr) {
                        var max = tr.token && tr.token.stm && tr.token.stm.max;
                        return sum + (max ? BigInt(max) : 0n);
                    }, 0n);
                    if (totalMax < BigInt(threshold)) {
                        if (callback) { callback(null, { claimed: 0, txHashes: [] }); }
                        return { claimed: 0, txHashes: [] };
                    }
                }

                var tokens = tokenRecords.map(function (tr) { return tr.token; });

                if (options.direct) {
                    return _claimDirect(db, tokens, tokenRecords, OC_ADDR);
                } else {
                    return _claimRelay(db, tokens, tokenRecords);
                }
            });
        });

        if (!callback) { return _promise; }
        _promise.then(function (r) { callback(null, r); })
                .catch(function (err) { callback(err); });
    };

    // ── Direct path — Drop calls OpenClaiming.paymentsExecute ───────────────

    function _claimDirect(db, tokens, records, OC_ADDR) {
        if (typeof ethers === 'undefined') {
            return Promise.reject(new Error('ethers.js required for direct claiming'));
        }

        var dropEVM  = _._state.evmAddress;
        var chainId  = Q.Config.get(['Safecloud', 'safebux', 'chainId'], 'eip155:56');
        var hexId    = chainId.indexOf('eip155:') === 0
            ? '0x' + parseInt(chainId.slice(7), 10).toString(16)
            : chainId;
        var chainConf = Q.Config.get(['Users', 'web3', 'chains', hexId], null);
        var rpcUrl   = (chainConf && (chainConf.rpcUrl || chainConf.publicRPC)) ||
                       Q.Config.get(['Safecloud', 'evm', 'provider', hexId],
                           'https://bsc-dataseed.binance.org/');
        var perChunk = Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], '1000');

        // The Drop's secp256k1 private key would be in _._state.evmPrivateKey
        // (derived from the delegation ceremony — not stored as raw bytes)
        if (!_._state.evmPrivateKey) {
            return Promise.reject(new Error(
                'Q.Safecloud.Drops.claimPayments: evmPrivateKey not set — use relay path'
            ));
        }

        var provider = new ethers.JsonRpcProvider(rpcUrl);
        var _pkHex   = _._state.evmPrivateKey;
        var signer   = new ethers.Wallet(_pkHex.startsWith('0x') ? _pkHex : '0x' + _pkHex, provider);
        var OC_ABI   = [
            'function paymentsExecute(' +
            '(address payer,address token,bytes32 recipientsHash,uint256 max,' +
            'uint256 line,uint256 nbf,uint256 exp) payment,' +
            'address[] recipients, bytes signature, address recipient,' +
            'uint256 amount, address incomeContract) external'
        ];
        var contract = new ethers.Contract(OC_ADDR, OC_ABI, signer);
        var txHashes = [];
        var perChunkBig = BigInt(perChunk);

        // Batch tokens
        var batches = [];
        for (var i = 0; i < tokens.length; i += batchSize) {
            batches.push(tokens.slice(i, i + batchSize));
        }

        return batches.reduce(function (prev, batch) {
            return prev.then(function () {
                return batch.reduce(function (p2, token) {
                    return p2.then(function () {
                        if (!token || !token.stm) { return; }
                        var stm = token.stm;
                        // Skip unsigned tokens (Phase 3 stubs from Jet have sig:[])
                        if (!token.sig || !token.sig[0]) { return; }
                        var sigBytes = ethers.getBytes(
                            '0x' + Q.Data.toHex(Q.Data.fromBase64(token.sig[0]))
                        );
                        var amount = stm.max !== '0'
                            ? BigInt(stm.max)
                            : perChunkBig;

                        return contract.paymentsExecute(
                            {
                                payer:          stm.payer,
                                token:          stm.token,
                                recipientsHash: stm.recipientsHash,
                                max:            BigInt(stm.max),
                                line:           BigInt(stm.line || 0),
                                nbf:            BigInt(stm.nbf || 0),
                                exp:            BigInt(stm.exp || 0)
                            },
                            [dropEVM],
                            sigBytes,
                            dropEVM,
                            amount,
                            ethers.ZeroAddress
                        ).then(function (tx) {
                            txHashes.push(tx.hash);
                            return tx.wait();
                        });
                    });
                }, Promise.resolve());
            });
        }, Promise.resolve()).then(function () {
            return _markRedeemed(db, records).then(function () {
                return { claimed: tokens.length, txHashes: txHashes };
            });
        });
    }

    // ── Relay path — Jet submits on-chain, covering gas ──────────────────────

    function _claimRelay(db, tokens, records) {
        return Q.Safecloud.Jets.dropClaimPayments({
            dropId:        _._state.dropId,
            paymentTokens: tokens,
            signature:     null // TODO: sign with EIP-712 session key
        }).then(function (result) {
            var txHash = result && result.txHash;
            return _markRedeemed(db, records).then(function () {
                return { claimed: tokens.length, txHashes: txHash ? [txHash] : [] };
            });
        });
    }

    function _markRedeemed(db, records) {
        return new Promise(function (resolve, reject) {
            var tx    = db.transaction(_.STORES.tokens, 'readwrite');
            var store = tx.objectStore(_.STORES.tokens);
            records.forEach(function (r) {
                store.put(Q.extend({}, r, { redeemed: true }));
            });
            tx.oncomplete = function () { resolve(); };
            tx.onerror    = function (e) { reject(e.target.error); };
        });
    }
});
