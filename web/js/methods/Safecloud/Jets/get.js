/**
 * Q.Safecloud.Jets.get — fetch encrypted chunks for a subtree by link path.
 *
 * Emits Safecloud/subtree/get with { rootCid, link, grants, payments }.
 * The server routes by link path, returns chunks with Merkle proofs attached.
 * Null entries in result.chunks mean unavailable — not an error, retry or try another Jet.
 *
 * PAYMENT SIGNING (Cloud as payer):
 *   The Cloud authorises payment to the Jet for routing/serving chunks.
 *   If Q.Safecloud.Jets.evmPrivateKey is set (derived from WebAuthn PRF in Cloud.init),
 *   a signed EIP-712 Payment token is attached to every subtree/get request.
 *   The Jet verifies this signature before routing.
 *
 *   The Jet separately signs its own payment tokens to Drops (server-side, Jets.js).
 *   Two separate payment flows:  Cloud → Jet → Drop
 *
 * @param {Object} subtree
 *   subtree.rootCid  String   — manifest rootCid
 *   subtree.link     Array    — link path, e.g. ["track","data","0","1"]
 *   subtree.grants   Array    — OCP Role A grant objects (secret stripped)
 *   subtree.manifest Object   — manifest (for chunkCount)
 * @param {Object} [options]
 *   options.payments       Array    — pre-built payment tokens (override auto-sign)
 *   options.publisherId    String
 *   options.streamName     String
 *   options.onProgress     fn(received, total)
 *   options.skipPayment    Boolean  — true to skip payment token (free content)
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Jets_get(subtree, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        // Strip encryption secrets — Jet only needs statement+proof for access verification.
        // Never send grant.secret to the server (it's the decryption key).
        var strippedGrants = (subtree.grants || []).map(function (g) {
            return {
                link:      g.link,
                statement: g.statement,
                proof:     g.proof,
                start:     g.start,
                end:       g.end
            };
        });

        // ── Payment token (Cloud as payer) ────────────────────────────────────
        // If caller provides payments, use them directly.
        // Otherwise, auto-build and sign a payment token from the Cloud's EVM key.
        var paymentsPromise;

        if (options.payments && options.payments.length) {
            // Caller supplied pre-built tokens (e.g. from a purchased capability)
            paymentsPromise = Promise.resolve(options.payments);

        } else if (options.skipPayment) {
            // Explicitly skipping (public/free content)
            paymentsPromise = Promise.resolve([]);

        } else {
            // Auto-sign: Cloud pays the Jet for this request
            paymentsPromise = _buildCloudPayment(subtree, options);
        }

        var _promise = paymentsPromise.then(function (payments) {
            var payload = {
                rootCid:  subtree.rootCid,
                link:     subtree.link    || ['track', 'data'],
                grants:   strippedGrants,
                payments: payments
            };

            if (options.publisherId)         { payload.publisherId = options.publisherId; }
            if (options.streamName)          { payload.streamName  = options.streamName; }
            // Forward revenue metadata so Jet can route creator royalties
            if (subtree.manifest && subtree.manifest.revenue) {
                payload.revenue = subtree.manifest.revenue;
            }

            return _.emit('Safecloud/subtree/get', payload).then(function (result) {
                if (options.onProgress && result && result.chunks) {
                    var received = result.chunks.filter(function (c) { return c !== null; }).length;
                    options.onProgress(received, result.chunks.length);
                }
                if (callback) { callback(null, result); }
                return result;
            });
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };

    // ── Build and sign a Cloud→Jet payment token ──────────────────────────────

    /**
     * Construct and EIP-712 sign a Payment token from the Cloud's EVM keypair.
     *
     * The Cloud's EVM private key lives in Q.Safecloud.Jets.cloudEvmPrivateKey,
     * set by Cloud.init() after WebAuthn PRF key derivation (same pattern as Drops/init.js).
     *
     * If no key is available, returns [] (unsigned, Jet accepts if requirePayment:false).
     *
     * @param {Object} subtree
     * @param {Object} options
     * @return {Promise<Array>}  array of one signed payment token, or []
     * @private
     */
    function _buildCloudPayment(subtree, options) {
        // Cloud EVM private key — set by Cloud.init() after WebAuthn PRF derivation
        var privKey = Q.Safecloud.Jets.cloudEvmPrivateKey || null;

        var safebuxAddr = Q.Config.get(['Safecloud', 'safebux', 'address'], null);
        var jetEVM      = Q.Safecloud.Jets.jetEvmAddress  ||
                          Q.Config.get(['Safecloud', 'jet', 'address'], null);
        var chainId     = Q.Config.get(['Safecloud', 'safebux', 'chainId'], 'eip155:56');
        var ocAddress   = Q.Config.get(['Safecloud', 'openclaiming', 'address'],
                              '0x99999febd42cad798fe10ab0b1c563002fc99999');
        var perChunk    = Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], '1000');

        // Estimate chunk count from manifest or use a ceiling
        var chunkCount  = (subtree.manifest && subtree.manifest.chunkCount) || 256;

        // Use publisher-set price from manifest metadata if available.
        // The manifest carries perChunkWei from the metadata fork summary.
        // If not present, use the config floor.
        if (subtree.manifest && subtree.manifest.perChunkWei) {
            perChunk = subtree.manifest.perChunkWei;
        }

        var maxWei      = String(BigInt(perChunk) * BigInt(chunkCount));

        // Can't sign without key, safebux address, or jet address — return unsigned
        if (!privKey || !safebuxAddr || !jetEVM || typeof ethers === 'undefined') {
            return Promise.resolve([]);
        }

        var chainIdNum = chainId.indexOf('eip155:') === 0
            ? parseInt(chainId.slice(7), 10)
            : parseInt(chainId, 10);

        // recipientsHash = keccak256(abi.encode([jetEVM]))
        // The Cloud authorises payment to exactly this Jet
        var jetAddrBytes  = ethers.getBytes(ethers.zeroPadValue(jetEVM, 32));
        var abiEncoded    = new Uint8Array(96);
        // offset = 32
        abiEncoded[31]  = 32;
        // length = 1
        abiEncoded[63]  = 1;
        // padded address (last 32 bytes)
        abiEncoded.set(jetAddrBytes, 64);
        var recipientsHash = ethers.keccak256(abiEncoded);

        var stm = {
            payer:          null,       // filled after wallet is constructed
            token:          safebuxAddr,
            max:            maxWei,
            line:           0,
            nbf:            0,
            exp:            Math.floor(Date.now() / 1000) + 3600, // 1-hour window
            chainId:        chainIdNum,
            recipientsHash: recipientsHash,
            contract:       ocAddress
        };

        var domain = {
            name:              'OpenClaiming',
            version:           '1',
            chainId:           chainIdNum,
            verifyingContract: ocAddress
        };

        var types = {
            Payment: [
                { name: 'payer',          type: 'address' },
                { name: 'token',          type: 'address' },
                { name: 'max',            type: 'uint256' },
                { name: 'line',           type: 'uint256' },
                { name: 'nbf',            type: 'uint256' },
                { name: 'exp',            type: 'uint256' },
                { name: 'recipientsHash', type: 'bytes32' },
                { name: 'contract',       type: 'address' }
            ]
        };

        try {
            var wallet = new ethers.Wallet(privKey);
            stm.payer  = wallet.address;

            var value = {
                payer:          wallet.address,
                token:          stm.token,
                max:            BigInt(stm.max),
                line:           BigInt(stm.line),
                nbf:            BigInt(stm.nbf),
                exp:            BigInt(stm.exp),
                recipientsHash: stm.recipientsHash,
                contract:       stm.contract
            };

            return wallet.signTypedData(domain, types, value).then(function (sigHex) {
                return [{
                    stm: stm,
                    sig: [{ format: 'EIP712', signature: sigHex }]
                }];
            }).catch(function (err) {
                Q.log('Q.Safecloud.Jets.get: payment signing failed: ' + err, 'Safecloud');
                return [];
            });

        } catch (err) {
            Q.log('Q.Safecloud.Jets.get: wallet construction failed: ' + err, 'Safecloud');
            return Promise.resolve([]);
        }
    }
});
