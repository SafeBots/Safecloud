/**
 * Q.Safecloud.Jets.get — fetch encrypted chunks for a subtree by link path.
 *
 * Emits Safecloud/subtree/get with { rootCid, link, grants, payments }.
 * The server routes by link path, returns chunks with Merkle proofs attached.
 * Null entries in result.chunks mean unavailable — not an error, retry or try another Jet.
 *
 * PAYMENT SIGNING (Cloud as payer):
 *   The Cloud authorises payment to the Jet for routing/serving chunks.
 *   If Q.Safecloud.Jets.cloudEvmPrivateKey is set (see Jets/_internal.js — apps derive
 *   it via WebAuthn PRF and assign it after Q.Safecloud.Drops.init-style key ceremony),
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
                if (result && result.chunks) {
                    result.chunks.forEach(function (c) {
                        if (!c) { return; }
                        _.cloudStats.chunksFetched++;
                        if (c.ciphertext) {
                            // base64 → approximate raw bytes
                            _.cloudStats.bytesFetched +=
                                Math.floor(c.ciphertext.length * 3 / 4);
                        }
                    });
                }
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
        // ── Sponsored path ────────────────────────────────────────────────
        // If the embedding site provides a sponsor endpoint (options or
        // config Safecloud.sponsorUrl), request a token signed by the SITE
        // as payer. The viewer signs nothing and appears nowhere on-chain.
        var sponsorUrl = (options && options.sponsorUrl) ||
            Q.Config.get(['Safecloud', 'sponsorUrl'], null);
        if (sponsorUrl) {
            var viewerId = (options && options.viewerId) ||
                Q.Users.loggedInUserId() || Q.sessionId() || 'anon';
            return fetch(sponsorUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    viewerId: viewerId,
                    policy: subtree && subtree.manifest &&
                        subtree.manifest.revenue &&
                        subtree.manifest.revenue.policy || undefined
                })
            }).then(function (r) {
                if (!r.ok) { throw new Error('sponsor ' + r.status); }
                return r.json();
            }).then(function (env) {
                return (env && env.stm && env.sig) ? [env] : [];
            }).catch(function () {
                // Sponsorship exhausted or unavailable → self-pay fallback
                return _selfSignedPayment(subtree, options);
            });
        }
        return _selfSignedPayment(subtree, options);
    }

    function _selfSignedPayment(subtree, options) {
        // Cloud EVM private key — set by Cloud.init() after WebAuthn PRF derivation.
        //
        // PRIVACY (stated precisely):
        //   SPONSORSHIP is the anonymity mechanism. A sponsored viewer never
        //   appears on-chain at all — the sponsor is the payer, and the
        //   viewer resolves only to an opaque line number hash(viewerId)
        //   that only the sponsor can preimage. No funding transaction
        //   exists to cluster.
        //   PER-CONTENT KEYS (below) are COMPARTMENTALIZATION, not
        //   anonymity: childPriv = keccak256(basePriv || rootCid) gives
        //   children that share no key material, so a leaked child exposes
        //   one content's channel, not a viewing history — but a self-payer
        //   funding several children from one wallet links them at the
        //   funding hop (common-funder clustering). Self-paying is
        //   pseudonymous; sponsored viewing is anonymous.
        var privKey = Q.Safecloud.Jets.cloudEvmPrivateKey || null;
        if (privKey && subtree && subtree.manifest && subtree.manifest.rootCid) {
            try {
                privKey = ethers.keccak256(ethers.concat([
                    ethers.getBytes(privKey),
                    ethers.toUtf8Bytes('safecloud.payer.'
                        + subtree.manifest.rootCid)
                ]));
            } catch (ePriv) { /* fall back to base key */ }
        }

        // Settings arrive from the Jet itself via 'Safecloud/jet/info'
        // (fetched on connect); browser Q.Config is only a fallback.
        //
        // {App}bux: a manifest may denominate its revenue in its own token
        // (manifest.revenue.token) — any ERC-20+permit produced by the
        // SafebuxFactory or compatible. The Jet advertises which tokens it
        // accepts in jet/info (acceptedTokens); tokens it doesn't accept
        // get rejected at verification with PaymentRequired carrying the
        // acceptable set (x402 negotiation).
        var manifestToken = subtree && subtree.manifest &&
            subtree.manifest.revenue && subtree.manifest.revenue.token || null;
        var safebuxAddr = manifestToken ||
                          _.paymentSetting(['safebux', 'address'],
                              ['Safecloud', 'safebux', 'address'], null);
        var jetEVM      = Q.Safecloud.Jets.jetEvmAddress ||
                          _.paymentSetting(['evmAddress'],
                              ['Safecloud', 'jet', 'address'], null);
        var chainId     = _.paymentSetting(['safebux', 'chainId'],
                              ['Safecloud', 'safebux', 'chainId'], 'eip155:56');
        var ocAddress   = _.paymentSetting(['openclaiming', 'address'],
                              ['Safecloud', 'openclaiming', 'address'],
                              // PLACEHOLDER fallback — real address comes from
                              // config after deployment
                              '0x99999febd42cad798fe10ab0b1c563002fc99999');
        var perChunk    = _.paymentSetting(['safebux', 'perChunkWei'],
                              ['Safecloud', 'safebux', 'perChunkWei'], '1000');

        // Can't sign without key, safebux address, or jet address — return unsigned
        if (!privKey || !safebuxAddr || !jetEVM) {
            return Promise.resolve([]);
        }

        // Lazy-load the vendored ethers bundle only when actually signing
        return _.ensureEthers().then(function () {
            return _signCloudPayment(privKey, safebuxAddr, jetEVM, chainId,
                ocAddress, perChunk, subtree);
        }).catch(function (err) {
            Q.log('Q.Safecloud.Jets.get: ethers unavailable, unsigned request: '
                + err, 'Safecloud');
            return [];
        });
    }

    function _signCloudPayment(privKey, safebuxAddr, jetEVM, chainId,
                               ocAddress, perChunk, subtree) {
        var chunkCount = (subtree.manifest && subtree.manifest.chunkCount) || 256;
        if (subtree.manifest && subtree.manifest.perChunkWei) {
            perChunk = subtree.manifest.perChunkWei;
        }
        var maxWei = String(BigInt(perChunk) * BigInt(chunkCount));

        var chainIdNum = chainId.indexOf('eip155:') === 0
            ? parseInt(chainId.slice(7), 10)
            : parseInt(chainId, 10);

        // recipientsHash = keccak256(abi.encode([addr])) — single recipient.
        // The viewer's signature binds WHO can ever claim each token.
        function _recipientsHash(addr) {
            var addrBytes  = ethers.getBytes(ethers.zeroPadValue(addr, 32));
            var abiEncoded = new Uint8Array(96);
            abiEncoded[31] = 32;   // offset
            abiEncoded[63] = 1;    // length
            abiEncoded.set(addrBytes, 64);
            return ethers.keccak256(abiEncoded);
        }

        // hashPolicy = keccak256(abi.encode(payees,fractions,dynamicBps,
        // dynamicConstraint,targets)) — byte-exact vs OpenClaiming.hashPolicy.
        function _hashPolicy(pol) {
            return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
                ['address[]', 'uint256[]', 'uint256', 'bytes32', 'address[]'],
                [pol.payees,
                 pol.fractions.map(function (f) { return BigInt(f); }),
                 BigInt(pol.dynamicBps || 0),
                 pol.dynamicConstraint || ethers.ZeroHash,
                 pol.targets || []]));
        }

        // ── Incentive enforcement (see README "Incentives") ──────────────────
        // PREFERRED: single policy token. When the manifest carries
        // revenue.policy, the viewer signs ONE token whose recipientsHash is
        // keccak256(abi.encode(Policy)). The rail itself then splits every
        // settlement atomically — the author's 90% is paid in the same
        // transaction as the server's share, enforced on-chain. The serving
        // node fills the policy's dynamic slot at settlement (dynamicPayee),
        // so the token is valid at ANY Jet the constraint admits. The
        // plaintext policy rides on the envelope (stm.policy — transport
        // metadata; the signed hash binds it, so tampering just breaks
        // signature verification).
        //
        // FALLBACK: dual tokens (infra + author) for manifests without a
        // policy. Colluding infrastructure can withhold the author token but
        // never redirect it.
        var revenue   = subtree.manifest && subtree.manifest.revenue;
        var policy    = revenue && revenue.policy;
        var income    = revenue && revenue.incomeContract;
        var creatorBP = (revenue && revenue.split &&
            typeof revenue.split.creator === 'number')
            ? revenue.split.creator : 9000;   // default 90% creator (server SPLIT_CREATOR_BP)

        var totalWei  = BigInt(maxWei);
        var authorWei = income ? (totalWei * BigInt(creatorBP)) / 10000n : 0n;
        var infraWei  = totalWei - authorWei;

        // ── WATERMARK CHANNEL (OpenClaiming line semantics) ──────────────────
        // On-chain, lines[payer][line].spent is CUMULATIVE, and every claim's
        // max is checked against it. Claims are therefore monotonic vouchers
        // on a channel, not independent budgets: only the payer's LATEST
        // (highest-max) claim per line matters; older ones die as spending
        // passes their ceiling. So each request advances one per-payer
        // watermark on line 0 (always open on-chain — no lineOpen needed for
        // gasless payers), and both tokens carry the SAME new ceiling. The
        // per-request shares ride on the envelopes as `amount` hints; the
        // settler executes deltas. Settlement order: infra first, then the
        // author token covers the remainder up to the watermark.
        _.line0Watermark = _.line0Watermark || '0';
        var prevW = BigInt(_.line0Watermark);
        var newW  = prevW + totalWei;
        _.line0Watermark = String(newW);

        var nowSec = Math.floor(Date.now() / 1000);
        var stm;
        if (policy && policy.payees && policy.fractions) {
            // Single policy token — the split is enforced by the rail.
            stm = {
                payer:          null,
                token:          safebuxAddr,
                max:            String(newW),
                line:           0,
                nbf:            0,
                exp:            nowSec + 30 * 86400,
                chainId:        chainIdNum,          // transport metadata
                recipientsHash: _hashPolicy(policy),
                contract:       ocAddress,           // signed field
                policy:         policy               // plaintext for validation
                                                     // and settlement (unsigned;
                                                     // hash-bound)
            };
        } else {
            stm = {
            payer:          null,       // filled after wallet is constructed
            token:          safebuxAddr,
            max:            String(newW),
            line:           0,
            nbf:            0,
            exp:            nowSec + 30 * 86400, // channel claims live long
            chainId:        chainIdNum,          // transport metadata
            recipientsHash: _recipientsHash(jetEVM),
            contract:       ocAddress            // signed field (rail checks == address(this))
            };
        }
        // Author-share token: same watermark, same line 0, recipient set
        // bound to the IncomeContract/splitter. Redirect-proof; settled for
        // its envelope `amount` after the infra share.
        var authorStm = (!policy && income && authorWei > 0n) ? {
            payer:          null,
            token:          safebuxAddr,
            max:            String(newW),
            line:           0,
            nbf:            0,
            exp:            nowSec + 30 * 86400,
            chainId:        chainIdNum,
            recipientsHash: _recipientsHash(income),
            contract:       ocAddress
        } : null;

        // EIP-712 — byte-exact against OpenClaiming.sol:
        // domain name "OpenClaiming"; struct
        // Payment(address payer,address token,bytes32 recipientsHash,
        //         uint256 max,uint256 line,uint256 nbf,uint256 exp,
        //         address contract).
        // The signed 'contract' field is validated == address(this) by the
        // rail — a wallet-visible deployment binding.
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
                { name: 'recipientsHash', type: 'bytes32' },
                { name: 'max',            type: 'uint256' },
                { name: 'line',           type: 'uint256' },
                { name: 'nbf',            type: 'uint256' },
                { name: 'exp',            type: 'uint256' },
                { name: 'contract',       type: 'address' }
            ]
        };

        try {
            var wallet = new ethers.Wallet(privKey);

            function _signOne(s, amountHint) {
                s.payer = wallet.address;
                var value = {
                    payer:          wallet.address,
                    token:          s.token,
                    recipientsHash: s.recipientsHash,
                    max:            BigInt(s.max),
                    line:           BigInt(s.line),
                    nbf:            BigInt(s.nbf),
                    exp:            BigInt(s.exp),
                    contract:       ocAddress
                };
                return wallet.signTypedData(domain, types, value)
                .then(function (sigHex) {
                    _.cloudStats.paymentsSigned++;
                    if (amountHint) { _.addPaidWei(amountHint); }
                    return { stm: s,
                        amount: amountHint || null,  // this request's share
                        sig: [{ format: 'EIP712', signature: sigHex }] };
                });
            }

            var signing = [_signOne(stm, String(infraWei))];
            if (authorStm) {
                signing.push(_signOne(authorStm, String(authorWei)));
            }

            return Promise.all(signing).then(function (tokens) {
                // Honest players retain author tokens so the author-side
                // tooling can collect them even if infrastructure withholds
                // the relay. Best-effort persistence.
                if (authorStm && tokens[1]) {
                    _persistAuthorToken(subtree, tokens[1]);
                }
                return tokens;
            }).catch(function (err) {
                Q.log('Q.Safecloud.Jets.get: payment signing failed: ' + err, 'Safecloud');
                return [];
            });

        } catch (err) {
            Q.log('Q.Safecloud.Jets.get: wallet construction failed: ' + err, 'Safecloud');
            return Promise.resolve([]);
        }
    }

    // Keep a copy of each author-share token in this origin's IndexedDB
    // (Safecloud.Client / authorTokens). @private
    function _persistAuthorToken(subtree, tokenEnv) {
        try {
            var req = indexedDB.open('Safecloud.Client', 1);
            req.onupgradeneeded = function () {
                var db = req.result;
                ['capabilities', 'session', 'swSessions', 'authorTokens']
                .forEach(function (n) {
                    if (!db.objectStoreNames.contains(n)) {
                        db.createObjectStore(n);
                    }
                });
            };
            req.onsuccess = function () {
                try {
                    var db  = req.result;
                    if (!db.objectStoreNames.contains('authorTokens')) { return; }
                    var key = (subtree.rootCid || 'unknown') + ':' + Date.now()
                        + ':' + Math.random().toString(36).slice(2, 8);
                    db.transaction('authorTokens', 'readwrite')
                      .objectStore('authorTokens')
                      .put({ rootCid: subtree.rootCid, token: tokenEnv,
                             at: Date.now() }, key);
                } catch (e) { /* best-effort */ }
            };
        } catch (e) { /* best-effort */ }
    }
});
