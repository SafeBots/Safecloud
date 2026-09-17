<?php

/**
 * Encrypted video/audio player. Passes a native <video> element to
 * Q.Safecloud.Client.stream(), which sets its src to an HLS URL served by
 * the Safecloud service worker. See web/js/tools/video.js.
 * @param {array} $options
 * @param {array} [$options.manifest] Manifest from Q.Safecloud.Client.store().
 * @param {array} [$options.capability] { rootKey } or { grants }.
 * @param {string} [$options.jetUrl] Jet server URL.
 * @param {integer} [$options.at] Start position in seconds.
 */
function Safecloud_video_tool($options)
{
	Q_Response::addStylesheet('{{Safecloud}}/css/tools/video.css', 'Safecloud');
	Q_Response::addScript('{{Safecloud}}/js/tools/video.js', 'Safecloud');
	Q_Response::setToolOptions($options);
	return '';
}
