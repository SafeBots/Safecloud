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
        var OC_ADDR   = Q.Config.get(['Safecloud', 'openclaiming', 'address'], '0x99999febd42cad798fe10ab0b1c563002fc99999');

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
        // Build the relay request struct — Drop signs this to prove ownership
        // of the payment tokens and authorize the Jet to submit on its behalf.
        var relayRequest = {
            dropId:        _._state.dropId,
            paymentTokens: tokens,
            nonce:         Math.floor(Date.now() / 1000), // replay protection
            dropEVM:       _._state.evmAddress
        };

        // Sign the relay request with the Drop's EVM private key (secp256k1 EIP-712).
        // The Jet verifies this signature before submitting on-chain.
        return _signRelayRequest(relayRequest).then(function (sig) {
            relayRequest.signature = sig;
            return Q.Safecloud.Jets.dropClaimPayments(relayRequest);
        }).then(function (result) {
            var txHash = result && result.txHash;
            if (!txHash) {
                // Jet returned null txHash — relay not yet implemented server-side
                // or Jet wallet not configured. Return without marking redeemed.
                return { claimed: 0, txHashes: [] };
            }
            return _markRedeemed(db, records).then(function () {
                return { claimed: tokens.length, txHashes: [txHash] };
            });
        });
    }

    /**
     * Sign a relay request with the Drop's EVM private key (EIP-712).
     *
     * The relay request struct is:
     *   {
     *     dropId:        string,
     *     dropEVM:       address,
     *     nonce:         uint256,
     *     tokenCount:    uint256
     *   }
     *
     * Domain: OpenClaiming contract, same chainId as payment tokens.
     * The Jet recovers the signer and verifies it matches drop.evmAddress.
     *
     * @param {Object} req  relay request object
     * @return {Promise<String>}  hex signature
     */
    function _signRelayRequest(req) {
        if (typeof ethers === 'undefined') {
            return Promise.resolve(null);
        }
        if (!_._state.evmPrivateKey) {
            return Promise.resolve(null);
        }

        var chainId  = Q.Config.get(['Safecloud', 'safebux', 'chainId'], 'eip155:56');
        var chainNum = chainId.indexOf('eip155:') === 0
            ? parseInt(chainId.slice(7), 10) : parseInt(chainId, 10);
        var ocAddr   = Q.Config.get(['Safecloud', 'openclaiming', 'address'],
                           '0x99999febd42cad798fe10ab0b1c563002fc99999');

        var domain = {
            name:              'OpenClaiming',
            version:           '1',
            chainId:           chainNum,
            verifyingContract: ocAddr
        };

        var types = {
            RelayRequest: [
                { name: 'dropId',     type: 'string'  },
                { name: 'dropEVM',    type: 'address' },
                { name: 'nonce',      type: 'uint256' },
                { name: 'tokenCount', type: 'uint256' }
            ]
        };

        var value = {
            dropId:     req.dropId     || '',
            dropEVM:    req.dropEVM    || ethers.ZeroAddress,
            nonce:      BigInt(req.nonce      || 0),
            tokenCount: BigInt(req.paymentTokens ? req.paymentTokens.length : 0)
        };

        try {
            var pk     = _._state.evmPrivateKey;
            var wallet = new ethers.Wallet(pk.startsWith('0x') ? pk : '0x' + pk);
            return wallet.signTypedData(domain, types, value).catch(function () {
                return null;
            });
        } catch (e) {
            return Promise.resolve(null);
        }
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
