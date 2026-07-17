<?php
/**
 * Safecloud Drop node dashboard page.
 *
 * URL:   /safecloud/drop
 * Fills: content slot
 *
 * Renders the Safecloud/drop tool into a simple content page.
 * No login required — Drop derives its identity via WebAuthn PRF.
 */
function Safecloud_drop_response($params)
{
    Q_Response::addScript('{{Safecloud}}/js/Safecloud.js', 'head');
    Q_Response::addScript('{{Safecloud}}/js/pages/drop.js');
    Q_Response::addStylesheet('{{Safecloud}}/css/Safecloud.css');
    Q_Response::addStylesheet('{{Safecloud}}/css/pages/drop.css');

    $jetUrl = Q_Config::get('Safecloud', 'jetUrl', Q_Request::baseUrl());
    Q_Response::setScriptData('Q.plugins.Safecloud.drop.jetUrl', $jetUrl);

    $text = Q_Text::get('Safecloud/content');
    Q_Response::setSlot('title', Q::ifset($text, 'drop', 'PageTitle', 'Safecloud Drop'));

    if (Q_Request::slotName('content')) {
        Q_Response::setSlot('content',
            Q::view('Safecloud/content/drop.php', compact('text', 'jetUrl'))
        );
    }

    return true;
}
