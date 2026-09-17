<?php

/**
 * Encrypted file upload widget. Drag-drop or click to select, encrypts in
 * the browser, and stores the result via Jets. See web/js/tools/upload.js.
 * @param {array} $options
 * @param {string} [$options.jetUrl] Jet server URL.
 * @param {integer} [$options.chunkSize] Bytes per chunk.
 * @param {boolean} [$options.multiple] Allow multiple file uploads.
 * @param {string} [$options.accept] File input accept string.
 */
function Safecloud_upload_tool($options)
{
	Q_Response::addStylesheet('{{Safecloud}}/css/tools/upload.css', 'Safecloud');
	Q_Response::addScript('{{Safecloud}}/js/tools/upload.js', 'Safecloud');
	Q_Response::setToolOptions($options);
	return '';
}
