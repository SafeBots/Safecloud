'use strict';
/**
 * Safecloud demo page.
 * plugins/Safecloud/web/js/pages/demo.js
 *
 * Connects the Safecloud/upload and Safecloud/video tools:
 * when upload completes, hands the manifest + rootKey to the player.
 *
 * Also handles the share link (rootCid in QS, rootKey in hash).
 */
Q.page('Safecloud/demo', function () {

    var jetUrl  = Q.getObject('Safecloud.demo.jetUrl',  Q.plugins) || Q.nodeUrl();
    var rootCid = Q.getObject('Safecloud.demo.rootCid', Q.plugins) || null;

    // rootKey lives in URL hash only — never sent to server
    var rootKey = null;
    if (window.location.hash) {
        window.location.hash.slice(1).split('&').forEach(function (part) {
            var kv = part.split('=');
            if (kv[0] === 'rootKey') { rootKey = decodeURIComponent(kv[1]); }
        });
    }

    // Set Jet URL globally so both tools use it
    if (Q.Safecloud && Q.Safecloud.Jets) {
        Q.Safecloud.Jets.url = jetUrl;
    }

    // Auto-initialize this tab as a Drop when the user first interacts with the upload zone.
    // This ensures we have a user gesture for WebAuthn, and makes the demo self-contained:
    // uploader IS their own Drop — no need to open a separate /safecloud/drop tab.
    var _dropInitialized = false;
    function _tryInitDrop() {
        if (_dropInitialized || !Q.Safecloud || !Q.Safecloud.Drops) { return; }
        _dropInitialized = true;
        Q.Safecloud.Drops.init({ jetUrl: jetUrl }, function (err) {
            if (err) {
                // Non-fatal — upload still works if another Drop tab is open
                _dropInitialized = false; // allow retry
                console.warn('Safecloud/demo: Drop auto-init:', err.message || err);
            }
        });
    }
    // Trigger Drop init on first click anywhere on the demo page (user gesture)
    $(document).one(Q.Pointer.fastclick + '.Safecloud_demo_drop_init', _tryInitDrop);

    // Wire upload → video after both tools are activated.
    // Q activates tools async; poll until both are ready, then connect them.
    var _wireAttempts = 0;
    function _wireTools() {
        var uploadEl = document.querySelector('#Safecloud_demo_page .Safecloud_upload_tool');
        var videoEl  = document.querySelector('#Safecloud_demo_page .Safecloud_video_tool');
        var uploadTool = uploadEl && Q.Tool.from(uploadEl, 'Safecloud/upload');
        var videoTool  = videoEl  && Q.Tool.from(videoEl,  'Safecloud/video');

        if (!uploadTool || !videoTool) {
            if (++_wireAttempts < 20) { setTimeout(_wireTools, 200); }
            return;
        }

        // Wire: upload complete → start playback + show share link
        uploadTool.state.onStore.add(function (manifest, key) {
            videoTool.startStream(manifest, { rootKey: key });
            _showShareLink(manifest.rootCid, key);
        }, 'Safecloud/demo');

        // If arriving via share link with rootKey in hash, show hint
        if (rootCid && rootKey) {
            videoTool.setStatus('Share link loaded. Paste the manifest JSON to play.', '');
        }
    }
    _wireTools();

    // Copy-to-clipboard
    $(document).on('click', '#Safecloud_demo_copy_btn', function () {
        var url = document.getElementById('Safecloud_demo_share_url').value;
        if (!url) return;
        var $btn = $(this);
        if (navigator.clipboard) {
            navigator.clipboard.writeText(url).then(function () {
                $btn.text('Copied!');
                setTimeout(function () { $btn.text('Copy'); }, 2000);
            });
        } else {
            // Fallback: select the input
            document.getElementById('Safecloud_demo_share_url').select();
        }
    });

    function _showShareLink(cid, key) {
        var url = window.location.origin + window.location.pathname
            + '?rootCid=' + encodeURIComponent(cid)
            + '#rootKey=' + encodeURIComponent(key);
        document.getElementById('Safecloud_demo_share_url').value = url;
        document.getElementById('Safecloud_demo_share').style.display = '';
    }

    return function () {
        // page teardown
        // Remove the Drop init gesture listener if it hasn't fired yet
        $(document).off(Q.Pointer.fastclick + '.Safecloud_demo_drop_init');
        _dropInitialized = false;
        // Remove upload→video wiring
        var uploadEl = document.querySelector('#Safecloud_demo_page .Safecloud_upload_tool');
        var uploadTool = uploadEl && Q.Tool.from(uploadEl, 'Safecloud/upload');
        if (uploadTool) {
            uploadTool.state.onStore.remove('Safecloud/demo');
        }
        // Remove clipboard button handler
        $(document).off('click', '#Safecloud_demo_copy_btn');
    };

}, 'Safecloud/demo');
