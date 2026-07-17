'use strict';
/**
 * Safecloud demo page.
 * plugins/Safecloud/web/js/pages/demo.js
 *
 * End-to-end wiring:
 *   upload (Safecloud/upload) → onStore(manifest, rootKey)
 *     → Safecloud/video.startStream()            — plays via SW HLS
 *     → Client.saveCapability()                  — refresh-safe, embed-ready
 *     → share link  ?rootCid=…#rootKey=…&m=…     — manifest travels in the
 *                                                  fragment, never to servers
 *     → embed snippet (embed.html iframe)        — see README "Embedding"
 *
 * Share-link arrival: fragment manifest+key start playback immediately and
 * are persisted; later visits (or the embed) need only the rootCid.
 */
Q.page('Safecloud/demo', function () {

    var jetUrl  = Q.getObject('Safecloud.demo.jetUrl',  Q.plugins) || Q.nodeUrl();
    var rootCid = Q.getObject('Safecloud.demo.rootCid', Q.plugins) || null;

    // Fragment: rootKey + manifest live in the hash only — never sent to server
    // Two modes:
    //   Classic:       #rootKey=...&m=...
    //   Split-entropy: #st=<tokenHex>&sm=<maskB64>&m=...
    //     (viewer must provide passphrase from Channel 2 to recover rootKey)
    var fragKey = null, fragManifest = null;
    var _splitToken = null, _splitMask = null;
    if (window.location.hash) {
        window.location.hash.slice(1).split('&').forEach(function (part) {
            var i = part.indexOf('=');
            var k = i < 0 ? part : part.slice(0, i);
            var v = i < 0 ? ''   : decodeURIComponent(part.slice(i + 1));
            if (k === 'st') { _splitToken = v; }
            if (k === 'sm') { _splitMask  = v; }
            if (k === 'rootKey') { fragKey = v; }
            if (k === 'm')       { fragManifest = _b64urlToJSON(v); }
        });
    }
    if (!rootCid && fragManifest) { rootCid = fragManifest.rootCid; }

    if (Q.Safecloud && Q.Safecloud.Jets) {
        Q.Safecloud.Jets.url = jetUrl;
    }

    // ── First user gesture: init this tab as a Drop AND establish the payer ──
    // Both need a gesture for WebAuthn. The demo is self-contained: the
    // uploader is their own storage node, and their own micropayment payer.
    var _identitiesInitialized = false;
    function _tryInitIdentities() {
        if (_identitiesInitialized || !Q.Safecloud) { return; }
        _identitiesInitialized = true;
        Q.Safecloud.Drops.init({ jetUrl: jetUrl }, function (err) {
            if (err) {
                _identitiesInitialized = false; // allow retry
                console.warn('Safecloud/demo: Drop auto-init:', err.message || err);
            }
        });
        Q.Safecloud.Client.init({ interactive: true }, function (err, r) {
            if (!err && r && r.evmAddress) {
                console.log('Safecloud/demo: payer identity', r.evmAddress);
            }
        });
    }
    $(document).one(Q.Pointer.fastclick + '.Safecloud_demo_ids', _tryInitIdentities);

    // ── Wire upload → video after both tools activate ─────────────────────────
    var _wireAttempts = 0;
    function _wireTools() {
        var uploadEl = document.querySelector('#Safecloud_demo_page .Safecloud_upload_tool');
        var videoEl  = document.querySelector('#Safecloud_demo_page .Q_video_tool, '
                     + '#Safecloud_demo_page .Safecloud_video_tool');
        var uploadTool = uploadEl && Q.Tool.from(uploadEl, 'Safecloud/upload');
        var videoTool  = videoEl  && (Q.Tool.from(videoEl, 'Safecloud/video')
                                   || Q.Tool.from(videoEl, 'Q/video'));

        if (!uploadTool || !videoTool) {
            if (++_wireAttempts < 20) { setTimeout(_wireTools, 200); }
            return;
        }

        uploadTool.state.onStore.add(function (manifest, key) {
            videoTool.startStream(manifest, { rootKey: key }, { jetUrl: jetUrl });
            Q.Safecloud.Client.saveCapability(manifest.rootCid, {
                manifest: manifest, capability: { rootKey: key }
            }).catch(function () {});
            _showShareLink(manifest, key);
        }, 'Safecloud/demo');

        // ── Share-link arrival ─────────────────────────────────────────────────
        function _playFromFragment() {
            if (!fragManifest || !fragKey) { return; }
            var cid = rootCid || fragManifest.rootCid;
            videoTool.startStream(fragManifest, { rootKey: fragKey },
                { jetUrl: jetUrl });
            Q.Safecloud.Client.saveCapability(cid, {
                manifest: fragManifest, capability: { rootKey: fragKey }
            }).catch(function () {});
            _showShareLink(fragManifest, fragKey);
        }

        if (_splitToken && _splitMask && fragManifest && !fragKey
                && Q.Safecloud && Q.Safecloud.Client && Q.Safecloud.Client.recoverSplitKey) {
            // Split-entropy mode: viewer has token+mask from URL but needs
            // the passphrase from Channel 2 (voice, QR, separate message).
            var _passInput = prompt(
                'This content requires a passphrase (provided separately).\n'
                + 'Enter the passphrase words separated by hyphens:');
            if (_passInput) {
                Q.Safecloud.Client.recoverSplitKey(
                    rootCid || (fragManifest && fragManifest.rootCid),
                    _splitToken, _splitMask, _passInput.trim()
                ).then(function (rk) {
                    fragKey = rk;
                    _playFromFragment();
                }).catch(function () {
                    videoTool.setStatus(
                        'Incorrect passphrase — cannot decrypt.', 'error');
                });
            } else {
                videoTool.setStatus(
                    'Passphrase required to access this content.', 'error');
            }
        } else if (rootCid && fragManifest && fragKey) {
            _playFromFragment();
        } else if (rootCid) {
            // No fragment — maybe this browser already holds the capability
            Q.Safecloud.Client.loadCapability(rootCid, function (err, saved) {
                if (!err && saved && saved.manifest && saved.capability) {
                    videoTool.startStream(saved.manifest, saved.capability,
                        { jetUrl: jetUrl });
                } else {
                    videoTool.setStatus(
                        'No key for this content on this device — '
                        + 'open the full share link once.', 'error');
                }
            });
        }

        _startPayerStrip();
    }
    _wireTools();

    // ── Share link + embed snippet ─────────────────────────────────────────────

    function _showShareLink(manifest, key) {
        var frag = 'rootKey=' + encodeURIComponent(key)
                 + '&m=' + _jsonToB64url(manifest);
        var url = window.location.origin + window.location.pathname
            + '?rootCid=' + encodeURIComponent(manifest.rootCid)
            + '#' + frag;
        var el = document.getElementById('Safecloud_demo_share_url');
        if (el) { el.value = url; }

        var embedUrl = window.location.origin
            + Q.url('{{Safecloud}}/embed.html')
            + '?rootCid=' + encodeURIComponent(manifest.rootCid)
            + '#' + frag;
        var embedEl = document.getElementById('Safecloud_demo_embed_code');
        if (embedEl) {
            embedEl.value = '<iframe src="' + embedUrl + '"\n'
                + '        allow="autoplay; encrypted-media; '
                + 'publickey-credentials-get *"\n'
                + '        width="640" height="360" frameborder="0"></iframe>';
        }
        var share = document.getElementById('Safecloud_demo_share');
        if (share) { share.style.display = ''; }
    }

    // ── Live payer strip (Cloud dashboard) ─────────────────────────────────────

    var _stripTimer = null;
    function _startPayerStrip() {
        var col = document.querySelector('#Safecloud_demo_page .Safecloud_demo_video_col');
        if (!col || document.getElementById('Safecloud_demo_payer')) { return; }
        var div = document.createElement('div');
        div.id = 'Safecloud_demo_payer';
        div.className = 'Safecloud_demo_payer';
        col.appendChild(div);
        _stripTimer = setInterval(function () {
            if (!Q.Safecloud || !Q.Safecloud.Jets ||
                typeof Q.Safecloud.Jets.getCloudStats !== 'function') { return; }
            var s = Q.Safecloud.Jets.getCloudStats();
            div.textContent =
                'Fetched ' + s.fetchedMB.toFixed(2) + ' MB · '
                + 'Uploaded ' + s.uploadedMB.toFixed(2) + ' MB · '
                + s.paymentsSigned + ' payment token'
                + (s.paymentsSigned === 1 ? '' : 's')
                + (s.paymentsSigned
                    ? ' (' + s.paidSbux.toFixed(6) + ' SBUX authorised)'
                    : '')
                + (s.payerAddress
                    ? ' · payer ' + s.payerAddress.slice(0, 8) + '…'
                    : ' · unsigned (free mode)');
        }, 1000);
    }

    // ── Copy buttons ───────────────────────────────────────────────────────────

    $(document).on('click.Safecloud_demo', '.Safecloud_demo_copy', function () {
        var target = document.getElementById(this.getAttribute('data-copy'));
        if (!target || !target.value) { return; }
        var $btn = $(this), was = $btn.text();
        var done = function () {
            $btn.text('Copied!');
            setTimeout(function () { $btn.text(was); }, 2000);
        };
        if (navigator.clipboard) {
            navigator.clipboard.writeText(target.value).then(done);
        } else {
            target.select();
            done();
        }
    });

    // ── base64url helpers ──────────────────────────────────────────────────────

    function _jsonToB64url(obj) {
        var b64 = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
        return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function _b64urlToJSON(s) {
        try {
            s = s.replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4) { s += '='; }
            return JSON.parse(decodeURIComponent(escape(atob(s))));
        } catch (e) { return null; }
    }

    return function () {
        $(document).off(Q.Pointer.fastclick + '.Safecloud_demo_ids');
        $(document).off('click.Safecloud_demo');
        if (_stripTimer) { clearInterval(_stripTimer); }
        _identitiesInitialized = false;
        var uploadEl = document.querySelector('#Safecloud_demo_page .Safecloud_upload_tool');
        var uploadTool = uploadEl && Q.Tool.from(uploadEl, 'Safecloud/upload');
        if (uploadTool) {
            uploadTool.state.onStore.remove('Safecloud/demo');
        }
    };

}, 'Safecloud/demo');
