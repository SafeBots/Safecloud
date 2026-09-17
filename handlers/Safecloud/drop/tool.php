<?php

/**
 * Safecloud Drop node dashboard. Handles WebAuthn PRF init, live stats
 * polling, and Safebux claim UI. See web/js/tools/drop.js.
 * @param {array} $options
 * @param {string} [$options.jetUrl] Jet server URL. Defaults to Q.nodeUrl().
 * @param {integer} [$options.pollMs] Stats poll interval in ms.
 */
function Safecloud_drop_tool($options)
{
	Q_Response::addStylesheet('{{Safecloud}}/css/tools/drop.css', 'Safecloud');
	Q_Response::addScript('{{Safecloud}}/js/tools/drop.js', 'Safecloud');
	Q_Response::setToolOptions($options);
	return '';
}
