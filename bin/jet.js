#!/usr/bin/env node
'use strict';

/**
 * bin/jet.js — Standalone Safecloud Jet entry point
 *
 * Boots the Jet server without the Qbix Q.inc platform dependency.
 * Provides a real (not stub) Q shim that:
 *   - reads local/app.json for config
 *   - creates a real Express + socket.io server for Q.listen()
 *   - provides Q.require('Users') → Users.Socket.listen() backed by socket.io
 *   - intercepts require('Q') and require('Q/*') via Module._load
 *
 * Usage:
 *   node bin/jet.js [--config path/to/app.json] [--port 8080]
 *
 * Environment variables:
 *   SAFECLOUD_PORT      override listen port (default 8080 or config value)
 *   SAFECLOUD_CONFIG    path to app.json config file (default ./local/app.json)
 *   SAFECLOUD_DIR       working directory for Q.app.DIR (default process.cwd())
 */

var Module   = require('module');
var path     = require('path');
var fs       = require('fs');
var http     = require('http');
var https    = require('https');
var events   = require('events');

// ─── Parse CLI args ───────────────────────────────────────────────────────────
var argv = process.argv.slice(2);
var argConfig = null;
var argPort   = null;
for (var i = 0; i < argv.length; i++) {
    if (argv[i] === '--config' && argv[i + 1]) { argConfig = argv[++i]; }
    else if (argv[i] === '--port' && argv[i + 1]) { argPort = parseInt(argv[++i], 10); }
    else if (argv[i].startsWith('--config=')) { argConfig = argv[i].slice(9); }
    else if (argv[i].startsWith('--port='))   { argPort = parseInt(argv[i].slice(7), 10); }
}

// ─── Locate app root ─────────────────────────────────────────────────────────
var APP_DIR = process.env.SAFECLOUD_DIR || process.cwd();

// ─── Load config ─────────────────────────────────────────────────────────────
var configPath = process.env.SAFECLOUD_CONFIG
    || argConfig
    || path.join(APP_DIR, 'local', 'app.json');

var configStore = {};

// Merge the default plugin.json first (lowest priority)
try {
    var pluginJsonPath = path.join(__dirname, '..', 'config', 'plugin.json');
    var pluginRaw = fs.readFileSync(pluginJsonPath, 'utf8');
    var pluginJson = JSON.parse(pluginRaw);
    // plugin.json wraps everything under top-level keys — flatten it
    configStore = JSON.parse(JSON.stringify(pluginJson));
} catch (e) {
    // plugin.json not found — use empty defaults; Jets.js has its own defaults
}

// Then overlay local/app.json (highest priority)
try {
    var rawText = fs.readFileSync(configPath, 'utf8');
    // Strip // line comments and /* block comments (jsonc style)
    var cleaned = rawText
        .replace(/\/\/[^\n]*/g, '')
        .replace(/\/\*[\s\S]*?\*\//g, '');
    var appJson = JSON.parse(cleaned);
    // Deep-merge appJson over configStore
    deepMerge(configStore, appJson);
    console.log('[Safecloud] Loaded config from ' + configPath);
} catch (e) {
    if (e.code !== 'ENOENT') {
        console.warn('[Safecloud] Warning: could not parse ' + configPath + ': ' + e.message);
    } else {
        console.log('[Safecloud] No config at ' + configPath + ' — using defaults');
    }
}

/** Recursively merge src into dst (mutates dst). */
function deepMerge(dst, src) {
    if (!src || typeof src !== 'object') { return; }
    Object.keys(src).forEach(function (k) {
        var sv = src[k];
        if (sv && typeof sv === 'object' && !Array.isArray(sv)
                && dst[k] && typeof dst[k] === 'object' && !Array.isArray(dst[k])) {
            deepMerge(dst[k], sv);
        } else {
            dst[k] = sv;
        }
    });
}

// ─── Q.Config ────────────────────────────────────────────────────────────────
var QConfig = {
    /**
     * get(keys, defaultValue)
     * Walk the config store following the key path; return defaultValue if any
     * segment is missing.  Mirrors Qbix Q.Config.get() semantics exactly.
     */
    get: function (keys, def) {
        var o = configStore;
        for (var i = 0; i < keys.length; i++) {
            if (o == null || typeof o !== 'object') { return def; }
            o = o[keys[i]];
        }
        return (o === undefined || o === null) ? def : o;
    },

    /**
     * set(keys, value)
     * Write a value into the config store by key path.
     */
    set: function (keys, value) {
        var o = configStore;
        for (var i = 0; i < keys.length - 1; i++) {
            if (o[keys[i]] == null || typeof o[keys[i]] !== 'object') {
                o[keys[i]] = {};
            }
            o = o[keys[i]];
        }
        o[keys[keys.length - 1]] = value;
    }
};

// ─── Determine listen host/port ───────────────────────────────────────────────
var listenPort = argPort
    || parseInt(process.env.SAFECLOUD_PORT, 10) || 0
    || QConfig.get(['Safecloud', 'node', 'port'], 0)
    || QConfig.get(['Q', 'node', 'port'], 8080);

var listenHost = QConfig.get(['Safecloud', 'node', 'host'],
    QConfig.get(['Q', 'node', 'host'], '0.0.0.0'));

// ─── Create Express + HTTP server + socket.io ─────────────────────────────────
var express    = require('express');
var socketIo   = require('socket.io');

var app        = express();
var httpsCfg   = QConfig.get(['Q', 'node', 'https'], false) || false;

var rawServer;
if (httpsCfg && httpsCfg.key && httpsCfg.cert) {
    try {
        rawServer = https.createServer({
            key:  fs.readFileSync(httpsCfg.key),
            cert: fs.readFileSync(httpsCfg.cert),
            ca:   httpsCfg.ca ? fs.readFileSync(httpsCfg.ca) : undefined
        }, app);
        console.log('[Safecloud] HTTPS server created');
    } catch (e) {
        console.warn('[Safecloud] HTTPS config failed (' + e.message + '), falling back to HTTP');
        rawServer = http.createServer(app);
    }
} else {
    rawServer = http.createServer(app);
}

var io = new socketIo.Server(rawServer, {
    cors: { origin: '*', methods: ['GET', 'POST'] }
});

// Shared server object returned by Q.listen() — cached so repeated calls get same instance
var serverResult = {
    http:     rawServer,
    io:       io,
    attached: {
        express: app,
        io:      io
    }
};

// ─── Users.Socket shim ───────────────────────────────────────────────────────
// Jets.js calls Users.Socket.listen({host, port, https}) and expects:
//   { io: <socket.io Server> }
// We share the already-created io instance.
var UsersSocket = {
    listen: function (opts) {
        // Options already reflected in the server we created; ignore them.
        return { io: io };
    }
};
var Users = {
    Socket: UsersSocket
};

// ─── Q.makeEventEmitter ──────────────────────────────────────────────────────
function makeEventEmitter(obj) {
    var emitter = new events.EventEmitter();
    emitter.setMaxListeners(100);
    obj.on   = emitter.on.bind(emitter);
    obj.off  = emitter.off.bind(emitter);
    obj.once = emitter.once.bind(emitter);
    obj.emit = emitter.emit.bind(emitter);
    obj.removeListener       = emitter.removeListener.bind(emitter);
    obj.removeAllListeners   = emitter.removeAllListeners.bind(emitter);
    obj.addListener          = emitter.addListener.bind(emitter);
    return obj;
}

// ─── Q.getObject ─────────────────────────────────────────────────────────────
function getObject(keys, from) {
    var o = from;
    for (var i = 0; i < keys.length; i++) {
        if (o == null || typeof o !== 'object') { return undefined; }
        o = o[keys[i]];
    }
    return o;
}

// ─── Q.Crypto stubs (real openssl is used by Jets itself via ethers/crypto) ──
// These stubs satisfy the self-attachment checks in Jets.js.
// The real crypto work in Jets.js is done directly by ethers.js / Node crypto.
var QCrypto = {
    OpenClaim: {
        verify: async function () { return { ok: false, reason: 'not implemented in standalone mode' }; },
        EVM: {
            verify: async function () { return { ok: false, reason: 'not implemented in standalone mode' }; }
        }
    }
};

// ─── Q.Data stub ─────────────────────────────────────────────────────────────
// Q.Data.canonicalize is used by OpenClaim; provide a minimal implementation.
var QData = {
    canonicalize: function (obj) {
        return JSON.stringify(obj);
    },
    // Prolly tree — used for inventory reconciliation; stub returns empty store
    Prolly: {}
};

// ─── Q shim object ───────────────────────────────────────────────────────────
var Q = {
    Config: QConfig,

    app: { DIR: APP_DIR },

    log: function (msg, tag) {
        var prefix = tag ? '[' + tag + '] ' : '[Safecloud] ';
        console.log(prefix + msg);
    },

    // Q.extend — mirrors Object.assign but returns the first argument
    extend: function (target) {
        for (var i = 1; i < arguments.length; i++) {
            var src = arguments[i];
            if (src && typeof src === 'object') {
                Object.assign(target, src);
            }
        }
        return target;
    },

    getObject: getObject,
    makeEventEmitter: makeEventEmitter,

    // Q.listen([opts]) — returns the shared server result regardless of options.
    // Jets.js calls this multiple times (with and without {host,port}); we give
    // back the same object every time so Express routes don't collide.
    listen: function (opts) {
        return serverResult;
    },

    // Q.require(pluginName) — used for 'Users' and 'Streams'
    require: function (pluginName) {
        if (pluginName === 'Users') { return Users; }
        throw new Error('Q.require: plugin not available in standalone mode: ' + pluginName);
    },

    // Populated by Jets.js itself (var Safecloud_Jets = Q.Safecloud.Jets = ...)
    Safecloud: {},

    Crypto: QCrypto,
    Data:   QData,
    Assets: {},
    Socket: {},

    // Empty plugin registry — enough to avoid "Q.plugins is undefined" errors
    plugins: {}
};

// ─── Module._load intercept ───────────────────────────────────────────────────
// Jets.js does `var Q = require('Q')` at the top level, and later:
//   if (!Q.Data)              Q.Data = require('Q/Data');
//   if (!Q.Crypto)            Q.Crypto = require('Q/Crypto');
//   if (!Q.Crypto.OpenClaim)  require('Q/Crypto/OpenClaim');
//   if (!Q.Crypto.OpenClaim.EVM) try { require('Q/Crypto/OpenClaim/EVM'); } catch {}
// We intercept all of these before they hit Node's real resolver.
var _origLoad = Module._load;
Module._load = function (request, parent, isMain) {
    switch (request) {
        case 'Q':
            return Q;

        case 'Q/Data':
            // Self-attach to Q.Data and return the object
            Q.Data = QData;
            return QData;

        case 'Q/Crypto':
            Q.Crypto = QCrypto;
            return QCrypto;

        case 'Q/Crypto/OpenClaim':
            Q.Crypto.OpenClaim = QCrypto.OpenClaim;
            return QCrypto.OpenClaim;

        case 'Q/Crypto/OpenClaim/EVM':
            Q.Crypto.OpenClaim.EVM = QCrypto.OpenClaim.EVM;
            return QCrypto.OpenClaim.EVM;

        default:
            return _origLoad.call(this, request, parent, isMain);
    }
};

// ─── Start the server, then boot Jets ────────────────────────────────────────
console.log('[Safecloud] Starting Jet server on ' + listenHost + ':' + listenPort);

rawServer.listen(listenPort, listenHost, function () {
    var addr = rawServer.address();
    console.log('[Safecloud] Jet listening on ' + addr.address + ':' + addr.port);

    // Update config with the actual port (in case 0 was specified)
    QConfig.set(['Safecloud', 'node', 'port'], addr.port);
    QConfig.set(['Q', 'node', 'port'], addr.port);

    // Now load Jets and start it. require() triggers Module._load so Q is injected.
    try {
        var Jets = require('../classes/Safecloud/Jets');
        Jets.listen();
        console.log('[Safecloud] Jet server ready');
    } catch (e) {
        console.error('[Safecloud] Failed to start Jets:', e.message);
        console.error(e.stack);
        process.exit(1);
    }
});

rawServer.on('error', function (e) {
    console.error('[Safecloud] Server error:', e.message);
    process.exit(1);
});

// Graceful shutdown
['SIGTERM', 'SIGINT'].forEach(function (sig) {
    process.on(sig, function () {
        console.log('[Safecloud] Shutting down (' + sig + ')...');
        rawServer.close(function () {
            process.exit(0);
        });
        // Force-close after 5s
        setTimeout(function () { process.exit(0); }, 5000).unref();
    });
});
