/**
 * Q.Safecloud.Client.recoverSplitKey — recover rootKey from split entropy.
 *
 * The viewer has:
 *   - Token + mask from the URL fragment (Channel 1)
 *   - Passphrase from out-of-band (Channel 2: voice, QR, message)
 *
 * Recovery:
 *   derived  = HKDF(salt=rootCid, IKM=token||passphrase, info="safecloud.splitkey.v1")
 *   rootKey  = derived XOR mask
 *
 * Neither the URL alone (no passphrase → can't compute derived) nor the
 * passphrase alone (no token or mask → can't compute anything) is sufficient.
 *
 * @method recoverSplitKey
 * @param {String} rootCid     Content identifier (from URL query string)
 * @param {String} tokenHex    Hex-encoded token (from URL fragment 'st=')
 * @param {String} maskB64     Base64-encoded mask (from URL fragment 'sm=')
 * @param {String} passphrase  Mnemonic words separated by hyphens (from Channel 2)
 * @param {Function} [callback] fn(err, rootKeyBase64)
 * @return {Promise<String>} rootKey as base64
 */
Q.exports(function (Q, _) {

    var SPLIT_INFO = 'safecloud.splitkey.v1';

    return function Q_Safecloud_Client_recoverSplitKey(rootCid, tokenHex, maskB64, passphrase, callback) {
        if (!rootCid || !tokenHex || !maskB64 || !passphrase) {
            var err = new Error('recoverSplitKey: all four parameters required');
            if (callback) { return callback(err); }
            return Promise.reject(err);
        }

        // Decode inputs
        var token = new Uint8Array(tokenHex.match(/.{2}/g).map(function (h) {
            return parseInt(h, 16);
        }));
        var mask  = Q.Data.fromBase64(maskB64);
        var passphraseBytes = new TextEncoder().encode(passphrase);

        // Reconstruct IKM = token || passphraseBytes
        var ikm = new Uint8Array(token.length + passphraseBytes.length);
        ikm.set(token, 0);
        ikm.set(passphraseBytes, token.length);

        // Derive the same intermediate key the sender computed
        var _promise = Q.Data.derive(ikm, SPLIT_INFO, {
            size: 32,
            salt: new TextEncoder().encode(rootCid)
        }).then(function (derivedBytes) {
            // rootKey = derived XOR mask
            var rootKeyBytes = new Uint8Array(32);
            for (var j = 0; j < 32; j++) {
                rootKeyBytes[j] = derivedBytes[j] ^ mask[j];
            }
            return Q.Data.toBase64(rootKeyBytes);
        });

        if (callback) {
            _promise.then(function (rk) { callback(null, rk); })
                    .catch(function (e) { callback(e); });
        }
        return _promise;
    };
});
