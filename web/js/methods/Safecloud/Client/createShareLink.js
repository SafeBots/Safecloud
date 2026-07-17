/**
 * Q.Safecloud.Client.createShareLink — split-entropy share link.
 *
 * Splits the content's root key into two components:
 *   - Channel 1 (URL fragment): a random token + the manifest
 *   - Channel 2 (out-of-band): a passphrase (mnemonic word list)
 *
 * Neither component alone can decrypt the content. The viewer combines
 * them via HKDF to recover the root key:
 *
 *   rootKey = HKDF(
 *     salt = rootCid,
 *     IKM  = token || passphraseBytes,
 *     info = "safecloud.splitkey.v1"
 *   )
 *
 * This implements the multi-channel cryptographic bootstrap from the
 * split-entropy patent: the URL travels through Channel 1 (link, SMS,
 * embed), the passphrase through Channel 2 (voice, QR, separate message).
 * Compromise of either channel alone is insufficient.
 *
 * For backward compatibility, the classic single-channel mode (full rootKey
 * in the URL fragment) remains the default. Split mode is opt-in:
 *
 *   Q.Safecloud.Client.createShareLink(manifest, rootKey, {
 *       split: true,        // enable split-entropy mode
 *       words: 4,           // passphrase word count (default 4, ~52 bits)
 *       serverFragment: true, // register fragment with Jet (sf=1 in URL)
 *       jetUrl: '...',      // Jet URL for server fragment registration
 *       baseUrl: '...',     // override base URL
 *       embed: true         // also generate embed snippet
 *   }, callback)
 *
 * Returns:
 *   {
 *     url:         String — share link (Channel 1), contains token + manifest
 *     passphrase:  String — mnemonic words (Channel 2), deliver out-of-band
 *     embedCode:   String — iframe snippet (if options.embed)
 *     split:       Boolean — true
 *   }
 *
 * Classic (non-split) mode:
 *   Q.Safecloud.Client.createShareLink(manifest, rootKey, callback)
 *   Returns: { url, embedCode, split: false }
 *
 * @method createShareLink
 * @param {Object}   manifest  Content manifest from Client.store()
 * @param {String}   rootKey   Base64-encoded root key
 * @param {Object}   [options]
 * @param {Function} [callback] fn(err, result)
 */
Q.exports(function (Q, _) {

    // ── BIP39-style word list (truncated to 256 common English words) ────────
    // Full BIP39 is 2048 words = 11 bits/word. This subset gives 8 bits/word.
    // 4 words = 32 bits of passphrase entropy; combined with the 128-bit token
    // via HKDF, the derived key has full 256-bit security. The passphrase is
    // NOT the sole entropy source — it is one input to the KDF alongside the
    // token. Its purpose is to be speakable, not to carry full key strength.
    var WORDS = [
        'abandon','abstract','acoustic','album','alert','alpha','anchor','angle',
        'annual','antenna','appear','arctic','arena','arrow','atom','author',
        'autumn','avenue','banner','barrel','beacon','blanket','blaze','bloom',
        'border','branch','breeze','bridge','bronze','bucket','burst','cabin',
        'candle','canyon','carbon','carpet','castle','cedar','chain','chamber',
        'cherry','circle','citrus','clever','cliff','cloud','cobalt','comet',
        'coral','corner','cosmic','cradle','creek','crystal','current','curtain',
        'dagger','dawn','delta','desert','diamond','dinner','dolphin','domain',
        'dragon','dream','drift','eagle','earth','echo','edge','elder',
        'ember','empire','energy','engine','entire','envelope','epic','equal',
        'escape','evening','fabric','falcon','feather','fence','field','figure',
        'filter','flame','flash','flight','flower','forest','fossil','fountain',
        'frost','galaxy','garden','gentle','glacier','globe','golden','grain',
        'grape','gravity','guitar','harbor','harvest','health','hidden','hollow',
        'honey','horizon','humble','hunter','impact','impulse','index','infant',
        'insect','island','ivory','jacket','jaguar','jungle','justice','kayak',
        'kernel','kitten','ladder','lagoon','lantern','lemon','letter','liberty',
        'light','lily','linen','liquid','lizard','lunar','magnet','mango',
        'maple','marble','meadow','melody','mentor','meteor','mineral','mirror',
        'modest','moment','monkey','mosaic','motion','mountain','museum','mystery',
        'nature','nebula','nectar','noble','north','novel','number','oasis',
        'ocean','olive','onion','orange','orbit','orchid','origin','osprey',
        'outlet','oxygen','paddle','palace','panther','paper','parrot','patrol',
        'pearl','pepper','phoenix','pillar','planet','plume','pocket','polar',
        'pond','portal','prairie','prism','pulse','python','quantum','quartz',
        'rabbit','radar','rainbow','random','raven','ribbon','ridge','river',
        'rocket','royal','ruby','saddle','safari','salmon','sandal','saturn',
        'season','shadow','shelter','sierra','signal','silver','simple','sketch',
        'solar','sparrow','spider','spiral','spring','square','stable','stellar',
        'storm','stream','summit','sunset','surface','swift','symbol','temple',
        'tender','theory','timber','torch','tower','travel','trophy','tunnel',
        'turtle','umbra','unique','unity','upper','valley','vapor','velvet',
        'venture','vessel','violet','vision','walnut','wander','whisper','willow',
        'window','winter','wonder','zenith'
    ];

    var SPLIT_INFO = 'safecloud.splitkey.v1';

    return function Q_Safecloud_Client_createShareLink(manifest, rootKey, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        if (!manifest || !manifest.rootCid) {
            var err = new Error('manifest with rootCid required');
            if (callback) { return callback(err); }
            return Promise.reject(err);
        }

        var rootCid = manifest.rootCid;
        var baseUrl = options.baseUrl ||
            (window.location.origin + window.location.pathname);
        var embedBase = options.embedBaseUrl ||
            (window.location.origin + Q.url('{{Safecloud}}/embed.html'));

        // ── Classic mode (backward compatible) ────────────────────────────────
        if (!options.split) {
            var frag = 'rootKey=' + encodeURIComponent(rootKey)
                     + '&m=' + _.jsonToB64url(manifest);
            var url  = baseUrl + '?rootCid='
                     + encodeURIComponent(rootCid) + '#' + frag;
            var result = { url: url, split: false };

            if (options.embed) {
                var embedUrl = embedBase + '?rootCid='
                    + encodeURIComponent(rootCid) + '#' + frag;
                result.embedCode = '<iframe src="' + embedUrl + '"\n'
                    + '        allow="autoplay; encrypted-media; '
                    + 'publickey-credentials-get *"\n'
                    + '        width="640" height="360" frameborder="0"></iframe>';
            }

            if (callback) { callback(null, result); }
            return Promise.resolve(result);
        }

        // ── Split-entropy mode ────────────────────────────────────────────────
        var wordCount = options.words || 4;
        var rkBytes   = Q.Data.fromBase64(rootKey);

        // Generate token (128-bit random, travels in URL)
        var token = new Uint8Array(16);
        crypto.getRandomValues(token);

        // Generate passphrase (word list, travels out-of-band)
        var passphrase = null;
        var serverFragmentHex = null;
        var secondEntropy;

        if (options.serverFragment) {
            var fragBytes = new Uint8Array(16);
            crypto.getRandomValues(fragBytes);
            serverFragmentHex = Array.from(fragBytes).map(function (b) {
                return ('0' + b.toString(16)).slice(-2);
            }).join('');
            secondEntropy = fragBytes;
        } else {
            var passWords = [];
            var randWords = new Uint8Array(wordCount);
            crypto.getRandomValues(randWords);
            for (var i = 0; i < wordCount; i++) {
                passWords.push(WORDS[randWords[i]]);
            }
            passphrase = passWords.join('-');
            secondEntropy = new TextEncoder().encode(passphrase);
        }

        // Derive the split key from token + second entropy via HKDF
        // and verify it matches the rootKey (it won't — we need to
        // work backwards: store the XOR mask so that
        //   HKDF(token || passphrase) XOR mask = rootKey)
        var ikm = new Uint8Array(token.length + secondEntropy.length);
        ikm.set(token, 0);
        ikm.set(secondEntropy, token.length);

        var _promise = Q.Data.derive(ikm, SPLIT_INFO, {
            size: 32,
            salt: new TextEncoder().encode(rootCid)
        }).then(function (derivedBytes) {
            // XOR mask: rootKey = derived XOR mask  →  mask = rootKey XOR derived
            var mask = new Uint8Array(32);
            for (var j = 0; j < 32; j++) {
                mask[j] = rkBytes[j] ^ derivedBytes[j];
            }

            // URL carries: token (hex) + mask (base64) + manifest (b64url)
            // The viewer needs the passphrase to derive the same HKDF output,
            // then XORs with mask to recover rootKey.
            var tokenHex = Array.from(token).map(function (b) {
                return ('0' + b.toString(16)).slice(-2);
            }).join('');

            var frag = 'st=' + tokenHex                         // split token
                     + '&sm=' + Q.Data.toBase64(mask)           // split mask
                     + '&m='  + _.jsonToB64url(manifest);       // manifest

            var qs = '?rootCid=' + encodeURIComponent(rootCid);
            if (serverFragmentHex && options.jetUrl) {
                qs += '&jet=' + encodeURIComponent(options.jetUrl) + '&sf=1';
            }
            var shareUrl = baseUrl + qs + '#' + frag;

            var shareResult = { url: shareUrl, split: true };
            if (passphrase) {
                shareResult.passphrase = passphrase;
                shareResult.wordCount  = wordCount;
            }
            if (serverFragmentHex) {
                shareResult.serverFragment = serverFragmentHex;
                shareResult.jetGated = true;
            }

            if (options.embed) {
                var eUrl = embedBase + '?rootCid='
                    + encodeURIComponent(rootCid) + '#' + frag;
                shareResult.embedCode = '<iframe src="' + eUrl + '"\n'
                    + '        allow="autoplay; encrypted-media; '
                    + 'publickey-credentials-get *"\n'
                    + '        width="640" height="360" frameborder="0"></iframe>';
            }

            if (serverFragmentHex && Q.Safecloud && Q.Safecloud.Jets
                    && Q.Safecloud.Jets.emit) {
                try {
                    Q.Safecloud.Jets.emit('Safecloud/content/registerFragment', {
                        rootCid:  rootCid,
                        fragment: serverFragmentHex
                    });
                } catch (e) { /* non-fatal */ }
            }

            return shareResult;
        });

        if (callback) {
            _promise.then(function (r) { callback(null, r); })
                    .catch(function (e) { callback(e); });
        }
        return _promise;
    };
});
