<?php
/**
 * Safecloud plugin.
 *
 * Decentralised encrypted storage network:
 *   - Client  (browser) — encrypts/decrypts, manages manifests, HLS streaming
 *   - Jets    (Node.js) — socket.io routing servers, chunk fan-out
 *   - Drops   (browser) — IndexedDB storage nodes, earn Safebux tokens
 *
 * @module Safecloud
 */
class Safecloud
{
    /**
     * Used by Q_Response::addScript('{{Safecloud}}/js/...') etc.
     */
    static $loaded = false;

    /**
     * Called by Q framework when the plugin is loaded.
     */
    static function Q_init()
    {
        // Register base URL alias {{Safecloud}}
        // (Q framework picks this up automatically from the plugin directory)

        // Add default config from config/plugin.json if not already set
        Q_Config::load(PLUGINS_DIR . DS . 'Safecloud' . DS . 'config' . DS . 'plugin.json');

        self::$loaded = true;
    }

    /**
     * Called before every request.
     * Adds the Safecloud browser plugin JS to every page automatically.
     */
    static function Q_responseExtras()
    {
        Q_Response::addScript('{{Safecloud}}/js/Safecloud.js', 'head');
        Q_Response::addStylesheet('{{Safecloud}}/css/Safecloud.css');
    }
}
