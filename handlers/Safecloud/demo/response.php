<?php
/**
 * Safecloud demo page — encrypted upload and playback.
 *
 * URL:   /safecloud/demo
 * Fills: content slot
 *
 * Optional query params:
 *   ?rootCid=…   — CID of previously stored file
 *   #rootKey=…   — owner's root key (in hash, never sent to server)
 */
function Safecloud_demo_response($params)
{
    Q_Response::addScript('{{Safecloud}}/js/Safecloud.js', 'head');
    Q_Response::addStylesheet('{{Safecloud}}/css/Safecloud.css');

    $jetUrl  = Q_Config::get('Safecloud', 'jetUrl', Q_Request::baseUrl());
    $rootCid = Q::ifset($_GET, 'rootCid', null);

    Q_Response::setScriptData('Q.plugins.Safecloud.demo.jetUrl',  $jetUrl);
    if ($rootCid) {
        Q_Response::setScriptData('Q.plugins.Safecloud.demo.rootCid', $rootCid);
        // rootKey intentionally NOT read server-side; lives in URL hash only
    }

    $text = Q_Text::get('Safecloud/content');
    Q_Response::setSlot('title', Q::ifset($text, 'demo', 'pageTitle', 'Safecloud Demo'));

    if (Q_Request::slotName('content')) {
        Q_Response::setSlot('content',
            Q::view('Safecloud/content/demo.php', compact('text', 'jetUrl', 'rootCid'))
        );
    }

    return true;
}
