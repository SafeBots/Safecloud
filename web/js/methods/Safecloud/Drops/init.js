/**
 * Q.Safecloud.Drops.init — initialise the Drop.
 *
 * Sequence:
 *   1. _.openDB() — open IndexedDB, create stores if needed
 *   2. Read latest log entry to rehydrate Prolly root
 *   3. Detect wipe (sessionStorage hint vs empty log)
 *   4. Check delegation claim — run Q.Crypto.delegate ceremony if expired/missing
 *   5. Replay diff log to rebuild in-memory Prolly store
 *   6. Q.Safecloud.Jets.dropRegister(...)
 *   7. If cold: build Bloom filter + Q.Safecloud.Jets.dropAnnounce
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_init(options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        // Set Jet URL before any socket operations
        if (options.jetUrl) {
            Q.Safecloud.Jets.url = options.jetUrl;
        }

        var SESSION_KEY = 'Q.Safecloud.Drops.lastRoot';

        var _promise = _.openDB().then(function (db) {

            // Step 2: read latest log entry
            return new Promise(function (resolve, reject) {
                var tx    = db.transaction(_.STORES.log, 'readonly');
                var store = tx.objectStore(_.STORES.log);
                // Open cursor in descending order over numeric keys only
                // (meta entries use string keys and must not be treated as log entries)
                var req   = store.openCursor(IDBKeyRange.upperBound(Number.MAX_SAFE_INTEGER), 'prev');
                req.onsuccess = function (e) {
                    resolve(e.target.result ? e.target.result.value : null);
                };
                req.onerror = function (e) { reject(e.target.error); };
            }).then(function (latestEntry) {

                // Step 3: wipe detection
                var hintRoot = sessionStorage.getItem(SESSION_KEY);
                var logEmpty = !latestEntry;
                var wiped    = logEmpty && hintRoot && hintRoot !== 'null';

                if (latestEntry) {
                    if (latestEntry.reason === 'reset') {
                        _._state.prollyRoot = null;
                    } else {
                        _._state.prollyRoot = latestEntry.newRoot || null;
                    }
                } else {
                    _._state.prollyRoot = null;
                }
                _._state.prevRoot = _._state.prollyRoot;

                // Step 4: delegation claim — check IndexedDB session store or run ceremony
                return _ensureDelegation(db, options).then(function (delegation) {

                    // Step 5: replay full log to rebuild in-memory Prolly store
                    return _replayLog(db).then(function () {

                        // If wipe detected, register first then announce reset
                        var registerPromise = Q.Safecloud.Jets.dropRegister({
                            evmAddress:  _._state.evmAddress,
                            delegation:  delegation,
                            publicKey:   _._state.sessionKeyPub,
                            storage:     { GB: Q.Config.get(['Safecloud', 'drop', 'storageGB'], 10) }
                            // prollyRoot and bloomFilter fetched fresh by dropRegister
                        });

                        return registerPromise.then(function (ack) {
                            _._state.dropId    = ack && ack.dropId;
                            _._state._initTime = Date.now();
                            sessionStorage.setItem(SESSION_KEY, _._state.prollyRoot || 'null');

                            var cold = (ack && ack.cold) || !_._state.prollyRoot;

                            if (wiped) {
                                // Send reset announce before anything else
                                _._state.pendingDiff = null;
                                return Q.Safecloud.Drops.announce('reset').then(function () {
                                    return _finishInit(db, cold);
                                });
                            }
                            return _finishInit(db, cold);
                        });
                    });
                });
            });
        }).then(function () {
            if (callback) { callback(null); }
        });

        if (!callback) { return _promise; }
        _promise.catch(function (err) { callback(err); });
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Finish init: if cold, build Bloom filter and send announce.
     */
    function _finishInit(db, cold) {
        if (!cold) { return Promise.resolve(); }
        // On cold start, send a signed announce so Jet gets our bloom filter.
        // Q.Safecloud.Drops.announce() handles signing, logging and sending.
        // pendingDiff is null (nothing changed), bloom is built inside announce().
        return Q.Safecloud.Drops.announce('cold').catch(function () {});
    }

    /**
     * Replay the full log to rebuild the in-memory Prolly store from scratch.
     * O(log entries) — typically small.
     */
    function _replayLog(db) {
        return new Promise(function (resolve, reject) {
            var tx    = db.transaction(_.STORES.log, 'readonly');
            var req   = tx.objectStore(_.STORES.log).getAll();
            req.onsuccess = function (e) { resolve(e.target.result || []); };
            req.onerror   = function (e) { reject(e.target.error); };
        }).then(function (entries) {
            // Filter to numeric-seq entries only, sort ascending
            entries = entries.filter(function (e) { return typeof e.seq === 'number'; });
            entries.sort(function (a, b) { return a.seq - b.seq; });

            return entries.reduce(function (prev, entry) {
                return prev.then(function (root) {
                    if (entry.reason === 'reset' || !entry.diff) {
                        return null; // reset wipes tree
                    }
                    return _.applyDiff(root, entry.diff);
                });
            }, Promise.resolve(null));
        }).then(function (replayedRoot) {
            // Trust the log replay result — even null (after a reset entry)
            // A null result means the tree was explicitly reset; set it to null.
            _._state.prollyRoot = replayedRoot;
            _._state.prevRoot   = replayedRoot;
        });
    }

    /**
     * Ensure the Drop has a stable hardware-bound identity via WebAuthn PRF.
     *
     * WebAuthn PRF extension gives us 32 bytes of stable output keyed by the
     * device's hardware credential — same output every time, never extractable,
     * runs non-interactively after first registration (no UI prompt).
     *
     * Derivation:
     *   WebAuthn PRF("safecloud.drop.session") → 32-byte stable secret
     *     → Q.Crypto.internalKeypair(secret, 'EIP712') → Drop EVM address (stable)
     *     → Q.Crypto.internalKeypair(secret, 'ES256')  → P-256 signing key (stable)
     *
     * Registration (first time): creates a platform authenticator credential
     * stored in the OS keychain / Secure Enclave.
     * Authentication (subsequent): retrieves PRF output silently.
     *
     * Falls back to _generateAnonymousSession() if WebAuthn PRF is unavailable
     * (older browsers) — anonymous Drop can store/serve but has no on-chain identity.
     *
     * Credential ID is persisted in IndexedDB so the same credential is used
     * across page loads without prompting the user again.
     */
    function _ensureDelegation(db, options) {
        var DELEG_KEY = 'Q.Safecloud.Drops.delegation';
        var CRED_KEY  = 'Q.Safecloud.Drops.credentialId';

        // If session keys are already in memory this page session, reuse them
        if (_._state.sessionKey && _._state.evmAddress) {
            try {
                var cached = JSON.parse(sessionStorage.getItem(DELEG_KEY) || 'null');
                var now    = Math.floor(Date.now() / 1000);
                if (cached && cached.exp && cached.exp > now) {
                    return Promise.resolve(cached.claim);
                }
            } catch(e) {}
        }

        // WebAuthn PRF label — domain-separated, fixed string
        var PRF_LABEL = new TextEncoder().encode('safecloud.drop.session');

        // Check WebAuthn + PRF support
        if (!window.PublicKeyCredential ||
            !PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
            return _generateAnonymousSession();
        }

        return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then(function (available) {
            if (!available) { return _generateAnonymousSession(); }

            // Try to load credential ID from IndexedDB.
            // If IDB is wiped, credential ID is gone too — correct: start fresh.
            // On a new device without iCloud sync, IDB is empty → new identity.
            return _idbGetDelegation(db).then(function (storedCredId) {
                if (storedCredId) {
                    // Known credential — authenticate silently
                    return _webAuthnGet(storedCredId, PRF_LABEL);
                }
                // No stored credential ID — could be a new device where an
                // iCloud/Google-synced passkey already exists.
                // Try a discoverable credential get first (no allowCredentials filter):
                // if a synced credential exists, the OS will surface it without
                // creating a duplicate.
                return _webAuthnGetDiscoverable(PRF_LABEL)
                    .then(function (result) {
                        if (result && result.prfOutput) {
                            // Found a synced credential — cache its ID locally
                            return _idbPutDelegation(db, result.credentialId)
                                .then(function () { return result; });
                        }
                        // No existing credential — register a fresh one
                        return _webAuthnCreate(PRF_LABEL).then(function (result) {
                            return _idbPutDelegation(db, result.credentialId)
                                .then(function () { return result; });
                        });
                    })
                    .catch(function () {
                        // Discoverable get cancelled/failed — register fresh
                        return _webAuthnCreate(PRF_LABEL).then(function (result) {
                            return _idbPutDelegation(db, result.credentialId)
                                .then(function () { return result; });
                        });
                    });
            });
        })
        .then(function (result) {
            if (!result || !result.prfOutput) {
                // PRF not supported by this authenticator — fall back
                return _generateAnonymousSession();
            }
            return _deriveSessionFromPrf(result.prfOutput);
        })
        .catch(function (err) {
            // User cancelled, or authenticator error — fall back to anonymous
            Q.log('Q.Safecloud.Drops: WebAuthn failed (' + err.message + '), using anonymous session', 'Safecloud');
            return _generateAnonymousSession();
        });
    }

    /**
     * Register a new WebAuthn platform credential with PRF extension enabled.
     * Called once per device. Stores credential in OS keychain / Secure Enclave.
     *
     * @return {Promise<{ credentialId: Uint8Array, prfOutput: Uint8Array }>}
     */
    function _webAuthnCreate(prfLabel) {
        var challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);

        // Derive a stable user ID from the app origin so the same credential
        // is re-used across reinstalls on the same device where possible.
        // Stable user.id derived from app + logged-in user if available.
        // This is the key to cross-device deduplication: if the same user.id
        // credential already exists in iCloud Keychain / Google Password Manager
        // on a new device, the authenticator returns the existing credential
        // rather than creating a new one — so PRF output stays the same.
        var userHandle = ((Q.info && Q.info.app) || location.hostname);
        var loggedInId = Q.Users && Q.Users.loggedInUser && Q.Users.loggedInUser()
            ? Q.Users.loggedInUser().id : null;
        if (loggedInId) { userHandle += ':' + loggedInId; }
        userHandle += ':safecloud-drop';

        // Hash to exactly 32 bytes (IDB user.id max is 64 bytes, but 32 is clean)
        var userIdPromise = crypto.subtle.digest(
            'SHA-256', new TextEncoder().encode(userHandle)
        ).then(function (h) { return new Uint8Array(h); });

        return userIdPromise.then(function (userId) {
        return navigator.credentials.create({
            publicKey: {
                challenge:        challenge,
                rp:               { name: 'Safecloud Drop', id: location.hostname },
                user:             {
                    id:          userId,
                    name:        userHandle,
                    displayName: 'Safecloud Drop'
                },
                pubKeyCredParams: [
                    { type: 'public-key', alg: -7  }, // ES256 (P-256)
                    { type: 'public-key', alg: -257 } // RS256 fallback
                ],
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    userVerification:        'preferred',
                    residentKey:             'required'  // required for cross-device sync
                },
                extensions: {
                    prf: { eval: { first: prfLabel } }
                }
            }
        }).then(function (cred) {
            if (!cred) { return { credentialId: null, prfOutput: null }; }
            var ext    = cred.getClientExtensionResults();
            var prfOut = ext && ext.prf && ext.prf.results && ext.prf.results.first;
            return {
                credentialId: new Uint8Array(cred.rawId),
                prfOutput:    prfOut ? new Uint8Array(prfOut) : null
            };
        });
        }); // userIdPromise
    }

    /**
     * Authenticate with an existing WebAuthn credential and get PRF output.
     * Runs non-interactively if the platform supports silent authentication
     * (userVerification: 'discouraged' skips biometric prompt on most platforms).
     *
     * @param  {Uint8Array} credentialId
     * @param  {Uint8Array} prfLabel
     * @return {Promise<{ credentialId: Uint8Array, prfOutput: Uint8Array }>}
     */
    function _webAuthnGet(credentialId, prfLabel) {
        var challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);

        return navigator.credentials.get({
            publicKey: {
                challenge:       challenge,
                rpId:            location.hostname,
                allowCredentials: [{
                    type: 'public-key',
                    id:   credentialId
                }],
                userVerification: 'discouraged', // silent where possible
                extensions: {
                    prf: { eval: { first: prfLabel } }
                }
            }
        }).then(function (assertion) {
            if (!assertion) { return { credentialId: credentialId, prfOutput: null }; }
            var ext    = assertion.getClientExtensionResults();
            var prfOut = ext && ext.prf && ext.prf.results && ext.prf.results.first;
            return {
                credentialId: credentialId,
                prfOutput:    prfOut ? new Uint8Array(prfOut) : null
            };
        });
    }

    /**
     * Attempt a discoverable credential get — no allowCredentials filter.
     * Used on a new device to find any synced credential (iCloud / Google PM)
     * without knowing its credential ID in advance.
     *
     * The OS shows a credential picker if multiple passkeys exist for this rpId.
     * Returns null rather than throwing if no credential is found.
     *
     * @param  {Uint8Array} prfLabel
     * @return {Promise<{ credentialId, prfOutput }|null>}
     */
    function _webAuthnGetDiscoverable(prfLabel) {
        var challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);

        return navigator.credentials.get({
            publicKey: {
                challenge:        challenge,
                rpId:             location.hostname,
                // No allowCredentials → discoverable / resident key lookup
                userVerification: 'preferred',
                extensions: {
                    prf: { eval: { first: prfLabel } }
                }
            }
        }).then(function (assertion) {
            if (!assertion) { return null; }
            var ext    = assertion.getClientExtensionResults();
            var prfOut = ext && ext.prf && ext.prf.results && ext.prf.results.first;
            return {
                credentialId: new Uint8Array(assertion.rawId),
                prfOutput:    prfOut ? new Uint8Array(prfOut) : null
            };
        }).catch(function () { return null; });
    }

    /**
     * Derive stable Drop identity from WebAuthn PRF output.
     * The 32-byte PRF output is hardware-bound and deterministic —
     * same credential → same PRF output → same EVM address and session key.
     *
     * @param  {Uint8Array} prfOutput  32 bytes from WebAuthn PRF extension
     * @return {Promise<Object|null>}  OCP delegation claim, or null
     */
    function _deriveSessionFromPrf(prfOutput) {
        var expDays = Q.Config.get(['Safecloud', 'drop', 'sessionExpDays'], 30);
        var exp     = Math.floor(Date.now() / 1000) + expDays * 86400;

        // Domain-separate the PRF output via Q.Crypto.delegate before deriving
        // keypairs. This keeps the key derivation consistent with the rest of
        // Safecloud's derivation chain, and means the raw PRF bytes are never
        // used directly as a private key scalar.
        //
        // PRF("safecloud.drop.session")  →  rawSecret
        //   delegate(rawSecret, 'safecloud.drop.identity')  →  identitySecret
        //     internalKeypair(identitySecret, 'EIP712')  →  stable EVM address
        //     internalKeypair(identitySecret, 'ES256')   →  stable P-256 signing key
        return Q.Crypto.delegate({
            rootSecret: prfOutput,
            label:      'safecloud.drop.identity',
            context:    '{}',
            format:     'ES256'
        }).then(function (del) {
            return Promise.all([
                Q.Crypto.internalKeypair({ secret: del.secret, format: 'EIP712' }),
                Q.Crypto.internalKeypair({ secret: del.secret, format: 'ES256' })
            ]);
        }).then(function (kps) {
            var evmKP  = kps[0];
            var p256KP = kps[1];

            _._state.evmAddress    = evmKP.address;
            _._state.evmPrivateKey = Q.Data.toHex(evmKP.privateKey);
            _._state.sessionKeyPub = Q.Data.toBase64(p256KP.publicKey);

            return _importP256PrivateKey(p256KP.privateKey).then(function (cryptoKey) {
                _._state.sessionKey = cryptoKey;

                // OCP delegation claim — self-issued, signed with P-256 session key.
                // iss = EVM address (on-chain identity), key[] = ES256 SPKI URI.
                // Q.Crypto.OpenClaim.sign handles SPKI wrapping, canonicalization,
                // and key[]+sig[] population. Jets verifies with OpenClaim.verify.
                var claim = {
                    ocp: 1,
                    iss: 'data:key/eip712,' + evmKP.address,
                    sub: 'safecloud:drop-session',
                    stm: {
                        sessionKeyES256:  _._state.sessionKeyPub,
                        sessionKeyEIP712: evmKP.address,
                        exp:              exp,
                        bound:            'webauthn-prf'
                    },
                    key: [],
                    sig: []
                };

                return Q.Crypto.OpenClaim.sign(claim, del.secret)
                    .then(function (signedClaim) {
                        sessionStorage.setItem('Q.Safecloud.Drops.delegation', JSON.stringify({
                            exp:   exp,
                            claim: signedClaim
                        }));
                        return signedClaim;
                    });
            });
        });
    }

    // ── Credential ID persistence in meta store ──────────────────────────────
    // The credential ID is not secret — it's just an opaque handle that tells
    // the authenticator which credential to use to produce the PRF output.
    // Without the hardware (Secure Enclave / TPM), it's useless.
    //
    // Stored in the 'meta' IDB store (separate from log/chunks) so:
    //   - It doesn't interfere with log replay or Prolly root detection
    //   - It survives reset() — on reset we wipe chunks but keep WebAuthn identity
    //     so the same EVM address is reused for the fresh Drop
    //   - If the entire DB is wiped externally, credential ID is gone too:
    //     fresh Drop with new identity (correct behavior)

    function _idbGetDelegation(db) {
        return new Promise(function (resolve) {
            try {
                var tx  = db.transaction(_.STORES.meta, 'readonly');
                var req = tx.objectStore(_.STORES.meta).get('webauthn-credential');
                req.onsuccess = function (e) {
                    var row = e.target.result;
                    resolve(row && row.value ? new Uint8Array(row.value) : null);
                };
                req.onerror = function () { resolve(null); };
            } catch(e) { resolve(null); }
        });
    }

    function _idbPutDelegation(db, credentialId) {
        if (!credentialId) { return Promise.resolve(); }
        return new Promise(function (resolve) {
            try {
                var tx  = db.transaction(_.STORES.meta, 'readwrite');
                var req = tx.objectStore(_.STORES.meta).put({
                    key:   'webauthn-credential',
                    value: Array.from(credentialId)
                });
                req.onsuccess = function () { resolve(); };
                req.onerror   = function () { resolve(); };
            } catch(e) { resolve(); }
        });
    }

    /**
     * Generate anonymous session (no WebAuthn) — Drop can store/serve
     * but has no on-chain identity for payments or staking.
     * Used as fallback when WebAuthn PRF is unavailable.
     */
    function _generateAnonymousSession() {
        // Persist seed in localStorage so identity survives page reloads.
        var ANON_KEY = 'Q.Safecloud.Drop.anonSeed';
        var seed;
        try {
            var stored = localStorage.getItem(ANON_KEY);
            if (stored) {
                seed = Q.Data.fromBase64(stored);
            } else {
                seed = new Uint8Array(32);
                crypto.getRandomValues(seed);
                localStorage.setItem(ANON_KEY, Q.Data.toBase64(seed));
            }
        } catch (e) {
            // localStorage unavailable (private browsing strict mode) — ephemeral
            seed = new Uint8Array(32);
            crypto.getRandomValues(seed);
        }

        return Promise.all([
            Q.Crypto.internalKeypair({ secret: seed, format: 'ES256' }),
            Q.Crypto.internalKeypair({ secret: seed, format: 'EIP712' })
        ]).then(function (kps) {
            var p256KP = kps[0];
            var evmKP  = kps[1];

            _._state.evmAddress    = evmKP.address;
            _._state.evmPrivateKey = Q.Data.toHex(evmKP.privateKey);
            _._state.sessionKeyPub = Q.Data.toBase64(p256KP.publicKey);

            return _importP256PrivateKey(p256KP.privateKey).then(function (cryptoKey) {
                _._state.sessionKey = cryptoKey;
                return null; // no delegation claim for anonymous session
            });
        });
    }

    /**
     * Import a raw 32-byte P-256 private key scalar into a WebCrypto CryptoKey
     * for ECDSA signing. WebCrypto requires PKCS8 DER format.
     */
    function _importP256PrivateKey(rawScalar) {
        var PKCS8_HEADER = new Uint8Array([
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06,
            0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
            0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
            0x01, 0x04, 0x20
        ]);
        var pkcs8 = new Uint8Array(PKCS8_HEADER.length + rawScalar.length);
        pkcs8.set(PKCS8_HEADER, 0);
        pkcs8.set(rawScalar, PKCS8_HEADER.length);
        return crypto.subtle.importKey(
            'pkcs8', pkcs8.buffer,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false, ['sign']
        );
    }

});
