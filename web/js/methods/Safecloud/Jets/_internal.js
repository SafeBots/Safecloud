/**
 * Q.Safecloud.Jets (browser client) — shared internal state and helpers.
 *
 * Loaded once via Q.Method.define (options.require: "_internal").
 * Passed as _ to every Jets method file.
 *
 * All socket.io communication goes through _state.qs (Q.Socket instance).
 * Queued calls made before connect() resolves are drained automatically.
 */

Q.exports(function (Q) {

    var _ = {};

    // ─────────────────────────────────────────────────────────────────────
    // Shared state
    // ─────────────────────────────────────────────────────────────────────

    _._state = {
        qs:               null,    // Q.Socket — set after connect
        connected:        false,
        queue:            [],      // pending { fn } waiting for connection
        reconnectAttempt: 0,
        reconnectTimer:   null,
        dropId:           null,    // from Safecloud/drop/register ack
        dropInfo:         null,    // last registration payload for reconnect
        connectingPromise:      null,  // in-flight connect Promise
        _defaultHandlersWired:  false  // prevents duplicate handler registration
    };

    // ── Cloud EVM payment signing state ──────────────────────────────────────
    // Set by Cloud.init() after WebAuthn PRF key derivation, same pattern as Drops/init.js.
    // Used by Jets/get.js to sign Cloud→Jet payment tokens.
    //
    // Usage in Cloud.init() (or wherever the Cloud derives its identity):
    //
    //   Q.Crypto.internalKeypair({ secret: identitySecret, format: 'EIP712' })
    //       .then(function (evmKP) {
    //           Q.Safecloud.Jets.cloudEvmPrivateKey = Q.Data.toHex(evmKP.privateKey);
    //           Q.Safecloud.Jets.cloudEvmAddress    = evmKP.address;
    //       });
    //
    // These are module-level properties on Q.Safecloud.Jets (not on _._state)
    // so they survive across method file invocations and are readable from Jets/get.js.
    if (!Q.Safecloud.Jets.cloudEvmPrivateKey) { Q.Safecloud.Jets.cloudEvmPrivateKey = null; }
    if (!Q.Safecloud.Jets.cloudEvmAddress)    { Q.Safecloud.Jets.cloudEvmAddress    = null; }
    if (!Q.Safecloud.Jets.jetEvmAddress)      { Q.Safecloud.Jets.jetEvmAddress      = null; }

    // ── Jet-published payment/network info ────────────────────────────────────
    // Populated by connect.js from the 'Safecloud/jet/info' socket event, so the
    // browser never depends on PHP exposing plugin config. Shape mirrors the
    // server handler in classes/Safecloud/Jets.js (_handleJetInfo).
    if (!Q.Safecloud.Jets.info) { Q.Safecloud.Jets.info = null; }

    /**
     * Read a payment-related setting: Jet-published info first, then browser
     * Q.Config (if the app exposed it), then the supplied default.
     * @param {Array}  infoPath   path within Q.Safecloud.Jets.info
     * @param {Array}  configPath path for Q.Config.get fallback
     * @param {*}      def
     */
    _.paymentSetting = function (infoPath, configPath, def) {
        var v = Q.getObject(infoPath, Q.Safecloud.Jets.info);
        if (v !== undefined && v !== null) { return v; }
        if (configPath && Q.Config && Q.Config.get) {
            return Q.Config.get(configPath, def);
        }
        return def;
    };

    // ── Cloud payer statistics (for in-tab dashboards) ────────────────────────
    _.cloudStats = {
        chunksFetched:  0,
        bytesFetched:   0,
        chunksUploaded: 0,
        bytesUploaded:  0,
        paymentsSigned: 0,
        paidWei:        '0'   // decimal string (BigInt-safe accumulation)
    };
    // Cumulative line-0 watermark for this payer (see Jets/get.js).
    // In-memory per page load; when Safebux + OC are live, recover across
    // sessions from OpenClaiming.lines(payer, 0).spent before first signing.
    _.line0Watermark = '0';

    _.addPaidWei = function (wei) {
        try {
            _.cloudStats.paidWei = String(BigInt(_.cloudStats.paidWei) + BigInt(wei));
        } catch (e) { /* keep counter consistent even on bad input */ }
    };

    // ── ensureEthers — lazy-load the vendored ethers UMD bundle ───────────────
    // ethers is only needed when payments or on-chain reads are configured, so
    // it is not part of the base page weight. Served from this plugin (no CDN).
    var _ethersPromise = null;
    _.ensureEthers = function () {
        if (typeof ethers !== 'undefined') { return Promise.resolve(ethers); }
        if (_ethersPromise) { return _ethersPromise; }
        _ethersPromise = new Promise(function (resolve, reject) {
            Q.addScript(Q.url('{{Safecloud}}/js/ethers/ethers.umd.min.js'), function (err) {
                if (err || typeof ethers === 'undefined') {
                    _ethersPromise = null;
                    return reject(err || new Error('ethers failed to load'));
                }
                resolve(ethers);
            });
        });
        return _ethersPromise;
    };
    // Cross-namespace access (Drops methods receive their own _, not this one)
    if (!Q.Safecloud.ensureEthers) { Q.Safecloud.ensureEthers = _.ensureEthers; }

    // ─────────────────────────────────────────────────────────────────────
    // jetUrl — resolve the Jet server URL
    // ─────────────────────────────────────────────────────────────────────

    _.jetUrl = function () {
        return Q.Safecloud.Jets.url || Q.nodeUrl();
    };

    // ─────────────────────────────────────────────────────────────────────
    // withSocket — run fn(qs) immediately if connected, else queue
    // ─────────────────────────────────────────────────────────────────────

    _.withSocket = function (fn) {
        if (_._state.connected && _._state.qs) {
            return fn(_._state.qs);
        }
        // Queue and ensure connect is in progress
        var p = new Promise(function (resolve, reject) {
            _._state.queue.push(function () {
                Promise.resolve(fn(_._state.qs)).then(resolve).catch(reject);
            });
        });
        // Trigger connect if not already started
        if (!_._state.connectingPromise) {
            Q.Safecloud.Jets.connect();
        }
        return p;
    };

    // ─────────────────────────────────────────────────────────────────────
    // drainQueue — called after successful connect
    // ─────────────────────────────────────────────────────────────────────

    _.drainQueue = function () {
        var q = _._state.queue.slice();
        _._state.queue = [];
        q.forEach(function (fn) { fn(); });
    };

    // ─────────────────────────────────────────────────────────────────────
    // scheduleReconnect — exponential backoff with ±30% jitter
    // ─────────────────────────────────────────────────────────────────────

    _.scheduleReconnect = function () {
        if (_._state.reconnectTimer) { return; }
        var attempt = _._state.reconnectAttempt;
        var baseMs  = Math.min(500 * Math.pow(2, attempt), 30000);
        var jitter  = baseMs * 0.3 * (Math.random() * 2 - 1);
        var delay   = Math.round(baseMs + jitter);

        _._state.reconnectTimer = setTimeout(function () {
            _._state.reconnectTimer   = null;
            _._state.reconnectAttempt = attempt + 1;
            _._state.connectingPromise = null;
            Q.Safecloud.Jets.connect();
        }, delay);
    };

    // ─────────────────────────────────────────────────────────────────────
    // emit — emit a socket event and return a Promise resolving with the ack
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Emit eventName with payload; resolve/reject on ack.
     * Ack convention: ack(errOrNull, result) or ack({ error: {...} })
     */
    _.emit = function (eventName, payload) {
        return _.withSocket(function (qs) {
            return new Promise(function (resolve, reject) {
                qs.socket.emit(eventName, payload, function (errOrResult, result) {
                    // Handle both (err, result) and ({ error }) ack shapes
                    if (errOrResult && errOrResult.error) {
                        return reject(new Error(
                            errOrResult.error.message || JSON.stringify(errOrResult.error)
                        ));
                    }
                    if (errOrResult && !(result !== undefined)) {
                        // Single-argument ack with success object
                        return resolve(errOrResult);
                    }
                    if (errOrResult) {
                        return reject(typeof errOrResult === 'string'
                            ? new Error(errOrResult) : errOrResult);
                    }
                    resolve(result);
                });
            });
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // ab2b64 / b642ab — ArrayBuffer ↔ base64 for socket.io transport
    // ─────────────────────────────────────────────────────────────────────

    _.ab2b64 = function (buf) {
        return Q.Data.toBase64(new Uint8Array(buf));
    };

    _.b642ab = function (b64) {
        return Q.Data.fromBase64(b64).buffer;
    };

    return _;
});
