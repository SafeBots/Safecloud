/**
 * Q.Safecloud.Client.init — establish the Cloud's payer identity.
 *
 * Micropayments key chain (mirrors Drops/init.js, distinct domain label):
 *   WebAuthn PRF("safecloud.cloud.session") → 32-byte stable secret
 *     → Q.Crypto.internalKeypair(secret, 'EIP712') → Cloud EVM keypair
 *     → Q.Safecloud.Jets.cloudEvmPrivateKey / cloudEvmAddress
 *
 * After init, Jets.get() auto-signs an EIP-712 Payment token on every
 * subtree/get (see Jets/get.js _buildCloudPayment). The label differs from
 * the Drop's ("safecloud.drop.session"), so the same authenticator yields
 * separate payer and earner identities — clean accounting when one browser
 * is both.
 *
 * The WebAuthn credential ID persists in IndexedDB (Safecloud.Client /
 * session), so subsequent visits — including iframe embeds in a pristine
 * environment — re-derive the same key with a silent assertion.
 *
 * Fallbacks, in order:
 *   options.privateKey        — use directly (dev/test, or wallet-derived)
 *   WebAuthn PRF              — the normal path (needs a user gesture the
 *                               first time; silent afterwards)
 *   anonymous                 — resolves { evmAddress: null, anonymous: true };
 *                               requests go unsigned (Jet accepts them only
 *                               when requirePayment is false)
 *
 * @param {Object}   [options]
 *   @param {String}  [options.privateKey]  hex EVM private key to use directly
 *   @param {Boolean} [options.interactive=true]  allow the create() prompt if
 *                    no credential exists yet; false = silent-only, fall back
 *                    to anonymous rather than prompting
 * @param {Function} [callback]
 * @return {Promise<{ evmAddress: String|null, anonymous: Boolean }>}
 */

Q.exports(function (Q, _) {
    var _initPromise = null;

    return function Q_Safecloud_Client_init(options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        // Already established (this page load, or by a direct key earlier)
        if (Q.Safecloud.Jets.cloudEvmPrivateKey && Q.Safecloud.Jets.cloudEvmAddress) {
            var done = Promise.resolve({
                evmAddress: Q.Safecloud.Jets.cloudEvmAddress, anonymous: false
            });
            if (callback) { done.then(function (r) { callback(null, r); }); }
            return done;
        }

        if (options.privateKey) {
            _initPromise = _fromPrivateKey(options.privateKey);
        } else if (!_initPromise) {
            _initPromise = _ceremony(options).catch(function (err) {
                _initPromise = null;   // allow retry after e.g. cancelled prompt
                throw err;
            });
        }

        var _promise = _initPromise;
        if (!callback) { return _promise; }
        _promise.then(function (r) { callback(null, r); },
                      function (e) { callback(e); });
    };

    // ── Direct key path ────────────────────────────────────────────────────────

    function _fromPrivateKey(pkHex) {
        pkHex = String(pkHex);
        if (pkHex.indexOf('0x') !== 0) { pkHex = '0x' + pkHex; }
        return Q.Safecloud.ensureEthers().then(function (ethers) {
            var wallet = new ethers.Wallet(pkHex);
            Q.Safecloud.Jets.cloudEvmPrivateKey = pkHex;
            Q.Safecloud.Jets.cloudEvmAddress    = wallet.address;
            return { evmAddress: wallet.address, anonymous: false };
        });
    }

    // ── WebAuthn PRF ceremony ──────────────────────────────────────────────────

    var PRF_LABEL = new TextEncoder().encode('safecloud.cloud.session');
    var CRED_KEY  = 'cloud.webauthn.credentialId';

    function _ceremony(options) {
        var interactive = options.interactive !== false;

        var prfSupported = window.PublicKeyCredential
            && navigator.credentials
            && typeof navigator.credentials.get === 'function';
        if (!prfSupported) { return _anonymous('WebAuthn unavailable'); }

        return _.clientDbGet(_.CLIENT_STORES.session, CRED_KEY)
        .catch(function () { return null; })
        .then(function (storedCredId) {
            if (storedCredId) {
                // Silent re-derivation with the known credential
                return _webAuthnGet(new Uint8Array(storedCredId), PRF_LABEL)
                    .catch(function () { return { prfOutput: null }; });
            }
            if (!interactive) { return { prfOutput: null }; }
            // First run: try discoverable credentials (may already exist via
            // keychain sync), else create one.
            return _webAuthnGetDiscoverable(PRF_LABEL)
                .then(function (r) {
                    if (r && r.prfOutput) { return _persistCred(r); }
                    return _webAuthnCreate(PRF_LABEL).then(_persistCred);
                })
                .catch(function () {
                    return _webAuthnCreate(PRF_LABEL).then(_persistCred)
                        .catch(function () { return { prfOutput: null }; });
                });
        })
        .then(function (r) {
            if (!r || !r.prfOutput) {
                return _anonymous('PRF unavailable or declined');
            }
            return Q.Crypto.internalKeypair({
                secret: r.prfOutput,
                format: 'EIP712'
            }).then(function (kp) {
                var pk = (typeof kp.privateKey === 'string')
                    ? kp.privateKey : Q.Data.toHex(kp.privateKey);
                if (pk.indexOf('0x') !== 0) { pk = '0x' + pk; }
                Q.Safecloud.Jets.cloudEvmPrivateKey = pk;
                Q.Safecloud.Jets.cloudEvmAddress    = kp.address;
                Q.log('Q.Safecloud.Client.init: payer identity ' + kp.address, 'Safecloud');
                return { evmAddress: kp.address, anonymous: false };
            });
        });
    }

    function _persistCred(r) {
        if (r && r.credentialId) {
            return _.clientDbPut(_.CLIENT_STORES.session, CRED_KEY,
                Array.prototype.slice.call(r.credentialId))
                .catch(function () { /* persistence is best-effort */ })
                .then(function () { return r; });
        }
        return Promise.resolve(r);
    }

    function _anonymous(reason) {
        Q.log('Q.Safecloud.Client.init: anonymous payer (' + reason + ')', 'Safecloud');
        return Promise.resolve({ evmAddress: null, anonymous: true });
    }

    // ── WebAuthn primitives (same shapes as Drops/init.js, cloud rp name) ─────

    function _webAuthnCreate(prfLabel) {
        var challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);

        var userHandle = ((Q.info && Q.info.app) || location.hostname);
        var loggedInId = Q.Users && Q.Users.loggedInUser && Q.Users.loggedInUser()
            ? Q.Users.loggedInUser().id : null;
        if (loggedInId) { userHandle += ':' + loggedInId; }
        userHandle += ':safecloud-cloud';

        return crypto.subtle.digest('SHA-256', new TextEncoder().encode(userHandle))
        .then(function (h) {
            return navigator.credentials.create({
                publicKey: {
                    challenge:        challenge,
                    rp:               { name: 'Safecloud', id: location.hostname },
                    user: {
                        id:          new Uint8Array(h),
                        name:        userHandle,
                        displayName: 'Safecloud'
                    },
                    pubKeyCredParams: [
                        { type: 'public-key', alg: -7   },
                        { type: 'public-key', alg: -257 }
                    ],
                    authenticatorSelection: {
                        authenticatorAttachment: 'platform',
                        userVerification:        'preferred',
                        residentKey:             'required'
                    },
                    extensions: { prf: { eval: { first: prfLabel } } }
                }
            });
        }).then(function (cred) {
            if (!cred) { return { credentialId: null, prfOutput: null }; }
            var ext    = cred.getClientExtensionResults();
            var prfOut = ext && ext.prf && ext.prf.results && ext.prf.results.first;
            return {
                credentialId: new Uint8Array(cred.rawId),
                prfOutput:    prfOut ? new Uint8Array(prfOut) : null
            };
        });
    }

    function _webAuthnGet(credentialId, prfLabel) {
        var challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);
        return navigator.credentials.get({
            publicKey: {
                challenge:        challenge,
                rpId:             location.hostname,
                allowCredentials: [{ type: 'public-key', id: credentialId }],
                userVerification: 'discouraged',
                extensions:       { prf: { eval: { first: prfLabel } } }
            }
        }).then(_extract(credentialId));
    }

    function _webAuthnGetDiscoverable(prfLabel) {
        var challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);
        return navigator.credentials.get({
            publicKey: {
                challenge:        challenge,
                rpId:             location.hostname,
                userVerification: 'discouraged',
                extensions:       { prf: { eval: { first: prfLabel } } }
            }
        }).then(function (assertion) {
            if (!assertion) { return { credentialId: null, prfOutput: null }; }
            var ext    = assertion.getClientExtensionResults();
            var prfOut = ext && ext.prf && ext.prf.results && ext.prf.results.first;
            return {
                credentialId: new Uint8Array(assertion.rawId),
                prfOutput:    prfOut ? new Uint8Array(prfOut) : null
            };
        });
    }

    function _extract(credentialId) {
        return function (assertion) {
            if (!assertion) { return { credentialId: credentialId, prfOutput: null }; }
            var ext    = assertion.getClientExtensionResults();
            var prfOut = ext && ext.prf && ext.prf.results && ext.prf.results.first;
            return {
                credentialId: credentialId,
                prfOutput:    prfOut ? new Uint8Array(prfOut) : null
            };
        };
    }
});
