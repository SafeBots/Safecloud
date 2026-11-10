/**
 * safecloud-embed.js — Drop-in embed shim for Safecloud streams.
 *
 * Usage:
 *   <script src="https://your-jet/safecloud-embed.js"></script>
 *   <script>
 *     var sc = Safecloud.connect({
 *       jetUrl:      'https://your-jet',
 *       publisherId: 'userId123',
 *       streamName:  'mydoc',
 *       token:       'optional-bearer-token',
 *       onReady:     function()     { console.log('connected'); },
 *       onMessage:   function(msg)  { console.log('message', msg); },
 *       onHistory:   function(msgs) { console.log('history', msgs); },
 *       onError:     function(err)  { console.error('error', err); }
 *     });
 *
 *     // Post a message into the stream
 *     sc.post('text', 'Hello world');
 *
 *     // Event-listener style (chainable)
 *     sc.on('message', function(msg) { ... });
 *
 *     // Clean up
 *     sc.disconnect();
 *   </script>
 *
 * How it works:
 *   1. Creates a hidden sandboxed iframe pointed at <jetUrl>/safecloud/embed-bridge.html
 *   2. On iframe load, sends safecloud:init via postMessage to the bridge
 *   3. Bridge connects to socket.io (same origin as Jet), subscribes to the stream,
 *      fetches history, and relays all events back via postMessage
 *   4. Posts from the outer page are forwarded by the bridge to POST /Streams/message
 *
 * No dependencies.  ES5-compatible.
 */
;(function (win, doc) {
    'use strict';

    if (win.Safecloud && win.Safecloud.connect) return; // already loaded

    if (!win.Safecloud) win.Safecloud = {};

    /**
     * connect(opts) → handle
     *
     * opts:
     *   jetUrl      {string}   base URL of the Jet, e.g. "https://jet.example.com"
     *   publisherId {string?}  publisher/user id (default '')
     *   streamName  {string}   stream name (required)
     *   token       {string?}  Bearer token for authenticated streams
     *   historyLimit{number?}  how many past messages to fetch on connect (default 50)
     *   onReady     {fn?}      called when bridge is connected and history delivered
     *   onMessage   {fn?}      called with each new real-time message object
     *   onHistory   {fn?}      called once with array of historical message objects
     *   onError     {fn?}      called with error string
     *
     * handle:
     *   .on(event, fn)              — subscribe to 'ready'|'message'|'history'|'error'
     *   .post(type, content, extra) — post a message to the stream
     *   .disconnect()               — clean up iframe and listeners
     */
    win.Safecloud.connect = function (opts) {
        if (!opts || typeof opts.streamName !== 'string' || !opts.streamName) {
            throw new Error('Safecloud.connect: streamName is required');
        }
        if (!opts.jetUrl) {
            throw new Error('Safecloud.connect: jetUrl is required');
        }

        // ── Normalise jetUrl (strip trailing slash) ──────────────────────────
        var jetBase   = opts.jetUrl.replace(/\/+$/, '');
        // Derive jet origin (scheme + host + optional port)
        var jetOrigin = jetBase.replace(/(https?:\/\/[^/]+).*/, '$1');

        var bridgeId  = 'sc-' + Math.random().toString(36).slice(2, 10);
        var handlers  = {};
        var ready     = false;
        var pending   = [];
        var iframe    = null;

        // ── Create hidden sandboxed iframe ───────────────────────────────────
        iframe = doc.createElement('iframe');
        iframe.id  = bridgeId;
        iframe.src = jetBase + '/embed-bridge.html';
        iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
        iframe.style.cssText = [
            'position:absolute',
            'width:1px',
            'height:1px',
            'top:-9999px',
            'left:-9999px',
            'border:0',
            'opacity:0',
            'pointer-events:none'
        ].join(';');

        doc.body.appendChild(iframe);

        // ── postMessage helpers ───────────────────────────────────────────────
        function _sendToFrame(msg) {
            if (iframe && iframe.contentWindow) {
                iframe.contentWindow.postMessage(msg, jetOrigin);
            }
        }

        function _emit(event, data) {
            var fns = handlers[event] || [];
            for (var i = 0; i < fns.length; i++) {
                try { fns[i](data); } catch (e) { /* don't let handler errors break the bridge */ }
            }
        }

        // ── Inbound messages from bridge ──────────────────────────────────────
        function _onMsg(ev) {
            // Only accept messages from the jet origin
            if (ev.origin !== jetOrigin) return;
            var d = ev.data;
            if (!d || d.scBridgeId !== bridgeId) return;

            switch (d.type) {
                case 'safecloud:ready':
                    ready = true;
                    _emit('ready');
                    if (opts.onReady) opts.onReady();
                    // flush queued posts
                    for (var i = 0; i < pending.length; i++) _sendToFrame(pending[i]);
                    pending = [];
                    break;

                case 'safecloud:history':
                    _emit('history', d.messages);
                    if (opts.onHistory) opts.onHistory(d.messages);
                    break;

                case 'safecloud:message':
                    _emit('message', d.message);
                    if (opts.onMessage) opts.onMessage(d.message);
                    break;

                case 'safecloud:error':
                    _emit('error', d.error);
                    if (opts.onError) opts.onError(d.error);
                    break;

                // Bridge asks for the init params (fires when iframe already loaded
                // before we attached the listener — race-condition safety)
                case 'safecloud:needsInit':
                    _sendInit();
                    break;
            }
        }

        function _sendInit() {
            _sendToFrame({
                type:         'safecloud:init',
                scBridgeId:   bridgeId,
                publisherId:  opts.publisherId || '',
                streamName:   opts.streamName,
                token:        opts.token        || null,
                historyLimit: opts.historyLimit || 50
            });
        }

        win.addEventListener('message', _onMsg);
        iframe.addEventListener('load', _sendInit);

        // ── Public handle ─────────────────────────────────────────────────────
        var handle = {
            /**
             * Subscribe to bridge events.
             * event: 'ready' | 'message' | 'history' | 'error'
             */
            on: function (event, fn) {
                if (!handlers[event]) handlers[event] = [];
                handlers[event].push(fn);
                return this;
            },

            /**
             * Post a message to the stream.
             * type    — message type string (e.g. 'text', 'Safecloud/yjs', …)
             * content — string or JSON-stringifiable object
             * extra   — optional extra fields merged into the message payload
             */
            post: function (type, content, extra) {
                var msg = {
                    type:       'safecloud:post',
                    scBridgeId: bridgeId,
                    msgType:    type   || 'text',
                    content:    (typeof content === 'string') ? content : JSON.stringify(content || ''),
                    extra:      extra  || {}
                };
                if (ready) {
                    _sendToFrame(msg);
                } else {
                    pending.push(msg);
                }
                return this;
            },

            /**
             * Send an ephemeral (non-persisted) event to other connected clients,
             * e.g. typing indicators, cursor positions.
             * type    — event type string (e.g. 'typing', 'cursor')
             * content — JSON-stringifiable payload
             */
            ephemeral: function (type, content) {
                var msg = {
                    type:       'safecloud:ephemeral',
                    scBridgeId: bridgeId,
                    msgType:    type    || '',
                    content:    (typeof content === 'string') ? content : JSON.stringify(content || '')
                };
                if (ready) {
                    _sendToFrame(msg);
                } else {
                    pending.push(msg);
                }
                return this;
            },

            /** Tear down the bridge: remove iframe and event listener. */
            disconnect: function () {
                // Tell the bridge to unsubscribe cleanly
                if (ready) {
                    _sendToFrame({ type: 'safecloud:disconnect', scBridgeId: bridgeId });
                }
                // Give bridge a moment to send unsubscribe, then remove
                var _iframe = iframe;
                setTimeout(function () {
                    if (_iframe && _iframe.parentNode) _iframe.parentNode.removeChild(_iframe);
                }, 300);
                win.removeEventListener('message', _onMsg);
                iframe    = null;
                handlers  = {};
                pending   = [];
                ready     = false;
            }
        };

        return handle;
    };

}(window, document));
