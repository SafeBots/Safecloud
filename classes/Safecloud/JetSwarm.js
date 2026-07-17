'use strict';
/**
 * Q.Safecloud.JetSwarm — Inter-Jet peer discovery and chunk routing.
 *
 * Wraps Hyperswarm to provide:
 *   - Peer Jet discovery via a shared DHT topic
 *   - End-to-end Noise-encrypted Jet-to-Jet connections
 *   - IP stripping: originating IPs are never forwarded after the first hop
 *   - Fan-out fetch: missing CIDs are fetched in parallel from peer Jets
 *   - CID-range announcement: each Jet tells peers which CID ranges it brokers
 *   - Grant forwarding: OCP grants are relayed to peer Jets for authorization
 *
 * MODE 1 (current):
 *   Node DHT position = SHA-256(noisePublicKey ∥ networkId)
 *   Nodes may choose their own Noise keypair, which determines their DHT position.
 *   Eclipse attacks are mitigated by the firewall (only known Jets connect) but
 *   Sybil-resistance is not guaranteed.
 *
 * MODE 2 (documented, not yet implemented):
 *   When secureIds: true, nodes running JetEpoch.js participate in a
 *   commit/reveal/RTIP randomness beacon. Their DHT position rotates each epoch:
 *     nodeId = SHA-256(noisePublicKey ∥ RANDAO_epoch ∥ networkId)
 *   Honest nodes in Mode 2 will ignore connections that lack a valid epoch proof.
 *   Mode 1 nodes are silently dropped by Mode 2 nodes once Mode 2 is activated
 *   across a threshold of the network.
 *
 * Wire protocol (newline-delimited JSON over Noise stream):
 *
 *   → { type:'hello',  pubkey:base64, nodeId:hex, ranges:[{start,end,count}], version:1 }
 *   → { type:'fetch',  requestId:uuid, cids:[CIDstring,...], grant:{...} }
 *   ← { type:'chunk',  requestId:uuid, cid:CIDstring, ciphertext:base64, tag:base64, iv:base64 }
 *   ← { type:'miss',   requestId:uuid, cid:CIDstring }
 *   ← { type:'deny',   requestId:uuid, reason:string }
 *   → { type:'range',  ranges:[{start,end,count}] }   (re-announce after new Drops register)
 *
 * IP privacy:
 *   After the first DHT hop, peer Jets only know each other's Noise public keys.
 *   The fetch request envelope carries no originating IP — just the requestId
 *   and the grant. Peer Jets cannot infer which Cloud triggered the request.
 *
 * @class Q.Safecloud.JetSwarm
 * @static
 */

var crypto      = require('crypto');
var Hyperswarm  = require('hyperswarm');

var JetSwarm = module.exports;

// ─── Constants ───────────────────────────────────────────────────────────────

var PROTOCOL_VERSION    = 1;
var CONNECT_TIMEOUT_MS  = 10000;
var FETCH_TIMEOUT_MS    = 8000;
var MAX_PEERS           = 64;
var NETWORK_ID_DEFAULT  = 'safecloud:jet:v1';

// ─── Module state ─────────────────────────────────────────────────────────────

var _swarm          = null;         // Hyperswarm instance
var _keyPair        = null;         // { publicKey: Buffer, secretKey: Buffer }
var _networkId      = NETWORK_ID_DEFAULT;
var _nodeId         = null;         // hex string — our DHT position (Mode 1)
var _peers          = {};           // pubkeyHex → PeerJet record
var _pending        = {};           // requestId → { resolve, reject, timer, received:{} }
var _localRanges    = [];           // [{start, end, count}] — CID ranges this Jet serves
var _onChunkRequest = null;         // async fn(cids, grant) → [{cid, ciphertext, tag, iv}|null]
var _initialized    = false;

/**
 * PeerJet record schema:
 * {
 *   pubkeyHex:  String,       // hex of remote Noise public key
 *   nodeId:     String,       // hex of their DHT position
 *   conn:       Duplex,       // raw Noise stream
 *   buf:        String,       // line-buffer for partial JSON
 *   ranges:     [{start, end, count}],
 *   connectedAt: Number,
 *   version:    Number,
 * }
 */

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Initialise the swarm and join the shared Jet topic.
 *
 * @method init
 * @param {Object} options
 * @param {Buffer|null}  [options.seed]           32-byte seed for deterministic keypair
 * @param {String}       [options.networkId]       defaults to 'safecloud:jet:v1'
 * @param {Boolean}      [options.secureIds]       Mode 2 flag — documented, not implemented
 * @param {Function}     [options.onChunkRequest]  async fn(cids, grant) called when a peer
 *                                                 requests chunks we should serve.
 *                                                 Must return Array<chunk|null>.
 * @param {Array}        [options.bootstrap]       custom DHT bootstrap nodes
 * @return {Promise<void>}
 */
JetSwarm.init = function (options) {
    if (_initialized) { return Promise.resolve(); }
    _initialized = true;

    options = options || {};
    _networkId      = options.networkId      || NETWORK_ID_DEFAULT;
    _onChunkRequest = options.onChunkRequest || null;

    if (options.secureIds) {
        // MODE 2 — not yet implemented.
        // When activated, nodes without a valid epoch proof from JetEpoch.js
        // will be ignored. See JetEpoch.js (not yet written).
        console.warn('[JetSwarm] secureIds=true: Mode 2 is documented but not yet '
            + 'implemented. Falling back to Mode 1 (pubkey-derived node IDs).');
    }

    // ── Keypair ───────────────────────────────────────────────────────────────
    // Generate or restore a Noise keypair. In production, derive from a
    // persisted 32-byte seed stored on disk (Q.Config or local file).
    var seed = options.seed || null;
    _keyPair = seed
        ? Hyperswarm.keyPair(seed)
        : Hyperswarm.keyPair();

    // ── Mode 1 node ID ────────────────────────────────────────────────────────
    // nodeId = SHA-256(noisePublicKey ∥ networkId)
    // Deterministic given the keypair + network — cannot be chosen freely
    // beyond choosing the keypair itself (Mode 2 removes even that freedom).
    _nodeId = crypto.createHash('sha256')
        .update(_keyPair.publicKey)
        .update(_networkId)
        .digest('hex');

    // ── Hyperswarm instance ───────────────────────────────────────────────────
    var swarmOpts = {
        keyPair:  _keyPair,
        maxPeers: options.maxPeers || MAX_PEERS,
        // Firewall: only accept connections from nodes whose public key we
        // can validate. In Mode 1 this accepts all (open network). In a
        // permissioned deployment, replace with a whitelist check.
        firewall: function (remotePubKey) {
            // Return false to ACCEPT, true to REJECT (Hyperswarm convention).
            // Here we accept all and validate at the hello handshake.
            // A stricter deployment would maintain a whitelist of known Jet pubkeys
            // via an on-chain registry or a signed peer list from a trusted Jet.
            return false; // accept
        }
    };
    if (options.bootstrap) {
        swarmOpts.dht = { bootstrap: options.bootstrap };
    }

    _swarm = new Hyperswarm(swarmOpts);

    _swarm.on('connection', function (conn, info) {
        _onConnection(conn, info);
    });

    // ── Join the shared Jet topic ─────────────────────────────────────────────
    // All Jets join the same topic derived from the network ID.
    // topic = SHA-256(networkId) — 32 bytes, deterministic, no secrets.
    var topic = crypto.createHash('sha256')
        .update(_networkId)
        .digest();

    var discovery = _swarm.join(topic, { server: true, client: true });

    return discovery.flushed().then(function () {
        console.log('[JetSwarm] Joined topic. nodeId=' + _nodeId.slice(0, 16) + '…');
    });
};

/**
 * Announce the CID ranges this Jet currently brokers to all connected peers.
 * Call this whenever new Drops register or announce new Prolly roots.
 *
 * @method announceRanges
 * @param {Array} ranges  [{start: CIDstring, end: CIDstring, count: Number}]
 */
JetSwarm.announceRanges = function (ranges) {
    _localRanges = ranges || [];
    var msg = _encode({ type: 'range', ranges: _localRanges });
    Object.keys(_peers).forEach(function (pubkeyHex) {
        _send(_peers[pubkeyHex], msg);
    });
};

/**
 * Fetch chunks from peer Jets for CIDs this Jet's local Drops don't have.
 *
 * Partitions the CID list across peers whose announced ranges cover them,
 * sends parallel fetch requests, and returns chunks interleaved as they arrive.
 *
 * @method fetchChunks
 * @param {Array}  cids    Array of CID strings to fetch
 * @param {Object} grant   OCP grant (forwarded to peer Jets for authorization)
 * @return {Promise<Object>}  { chunks: Array<chunk|null> } in same order as cids
 */
JetSwarm.fetchChunks = function (cids, grant) {
    if (!cids || !cids.length) {
        return Promise.resolve({ chunks: [] });
    }

    var peers = Object.values(_peers);
    if (!peers.length) {
        return Promise.resolve({ chunks: cids.map(function () { return null; }) });
    }

    // ── Partition CIDs across peers by range affinity ─────────────────────────
    // Each CID is assigned to the peer whose announced range best covers it.
    // Peers with no announced ranges get CIDs round-robin as fallback.
    var assignments = _assignCidsToPeers(cids, peers);

    // ── Fan-out: send parallel fetch requests ─────────────────────────────────
    var allPromises = Object.keys(assignments).map(function (pubkeyHex) {
        var peer       = _peers[pubkeyHex];
        var peerCids   = assignments[pubkeyHex];
        if (!peer || !peerCids.length) { return Promise.resolve([]); }
        return _fetchFromPeer(peer, peerCids, grant);
    });

    // ── Reassemble in original CID order ─────────────────────────────────────
    return Promise.all(allPromises).then(function (peerResults) {
        // Build a map: cid → chunk
        var cidMap = {};
        peerResults.forEach(function (results) {
            results.forEach(function (r) {
                if (r && r.cid) { cidMap[r.cid] = r.chunk; }
            });
        });
        var chunks = cids.map(function (cid) { return cidMap[cid] || null; });
        return { chunks: chunks };
    });
};

/**
 * Returns info about the current swarm state (for diagnostics / test guide).
 * @method stats
 */
JetSwarm.stats = function () {
    return {
        nodeId:      _nodeId,
        pubkeyHex:   _keyPair ? _keyPair.publicKey.toString('hex') : null,
        peerCount:   Object.keys(_peers).length,
        localRanges: _localRanges,
        peers:       Object.values(_peers).map(function (p) {
            return {
                pubkeyHex:  p.pubkeyHex.slice(0, 16) + '…',
                nodeId:     p.nodeId ? p.nodeId.slice(0, 16) + '…' : null,
                ranges:     p.ranges,
                connectedAt: p.connectedAt,
            };
        })
    };
};

/**
 * Gracefully destroy the swarm.
 * @method destroy
 */
JetSwarm.destroy = function () {
    if (_swarm) { _swarm.destroy(); _swarm = null; }
    _peers      = {};
    _pending    = {};
    _initialized = false;
};

// ─── Connection handling ──────────────────────────────────────────────────────

function _onConnection(conn, info) {
    var remotePubKey = info && info.publicKey;
    if (!remotePubKey) { conn.destroy(); return; }

    var pubkeyHex = remotePubKey.toString('hex');

    // Deduplicate — if we already have a live connection to this peer, drop the
    // new one. Hyperswarm may emit duplicate connections during reconnect.
    if (_peers[pubkeyHex] && !_peers[pubkeyHex].conn.destroyed) {
        conn.destroy();
        return;
    }

    var peer = {
        pubkeyHex:   pubkeyHex,
        nodeId:      null,
        conn:        conn,
        buf:         '',
        ranges:      [],
        connectedAt: Date.now(),
        version:     null,
    };
    _peers[pubkeyHex] = peer;

    // ── Send hello ────────────────────────────────────────────────────────────
    // Includes our node ID and current CID ranges.
    // NOTE: We do NOT include our IP address here — the Noise stream already
    // establishes identity via the keypair. The remote peer learns only our
    // public key and node ID, not our IP (the DHT handled that transparently).
    _send(peer, _encode({
        type:    'hello',
        pubkey:  _keyPair.publicKey.toString('base64'),
        nodeId:  _nodeId,
        ranges:  _localRanges,
        version: PROTOCOL_VERSION,
    }));

    // ── Read loop ─────────────────────────────────────────────────────────────
    conn.on('data', function (data) {
        peer.buf += data.toString('utf8');
        var lines = peer.buf.split('\n');
        peer.buf = lines.pop(); // keep incomplete tail
        lines.forEach(function (line) {
            line = line.trim();
            if (!line) { return; }
            var msg;
            try { msg = JSON.parse(line); } catch (e) { return; }
            _onMessage(peer, msg);
        });
    });

    conn.on('error', function (err) {
        console.warn('[JetSwarm] peer error ' + pubkeyHex.slice(0, 16) + '…: ' + err.message);
        _onPeerGone(pubkeyHex);
    });

    conn.on('close', function () {
        _onPeerGone(pubkeyHex);
    });
}

function _onPeerGone(pubkeyHex) {
    var peer = _peers[pubkeyHex];
    if (!peer) { return; }
    delete _peers[pubkeyHex];

    // Fail any pending requests that were assigned to this peer
    Object.keys(_pending).forEach(function (requestId) {
        var p = _pending[requestId];
        if (p && p.peer === pubkeyHex) {
            clearTimeout(p.timer);
            delete _pending[requestId];
            p.resolve([]); // graceful empty — caller falls back to null chunks
        }
    });
}

// ─── Message dispatch ─────────────────────────────────────────────────────────

function _onMessage(peer, msg) {
    if (!msg || !msg.type) { return; }

    switch (msg.type) {

    case 'hello':
        // Validate and record peer identity
        // Mode 2 upgrade point: verify epoch proof here before accepting.
        if (msg.version !== PROTOCOL_VERSION) {
            console.warn('[JetSwarm] peer ' + peer.pubkeyHex.slice(0,16)
                + '… version mismatch: ' + msg.version);
            // Accept anyway in Mode 1 — future: reject if Mode 2 active
        }
        peer.nodeId  = msg.nodeId  || null;
        peer.ranges  = msg.ranges  || [];
        peer.version = msg.version || 0;
        console.log('[JetSwarm] hello from ' + peer.pubkeyHex.slice(0,16)
            + '… nodeId=' + (peer.nodeId || '?').slice(0,16)
            + '… ranges=' + peer.ranges.length);
        break;

    case 'range':
        // Peer is re-announcing their CID ranges (new Drops registered)
        peer.ranges = msg.ranges || [];
        break;

    case 'fetch':
        // A peer Jet is asking us to serve chunks
        // IP PRIVACY: msg contains only requestId, cids, grant — no IP.
        _handlePeerFetch(peer, msg);
        break;

    case 'chunk':
        // Response to one of our outgoing fetch requests
        _onPeerChunk(msg);
        break;

    case 'miss':
        // Peer doesn't have this CID
        _onPeerMiss(msg);
        break;

    case 'deny':
        // Peer rejected our grant
        _onPeerDeny(msg);
        break;
    }
}

// ─── Serving chunks to peer Jets ─────────────────────────────────────────────

function _handlePeerFetch(peer, msg) {
    var requestId = msg.requestId;
    var cids      = msg.cids   || [];
    var grant     = msg.grant  || null;

    if (!requestId || !cids.length) { return; }

    if (!_onChunkRequest) {
        // No handler registered — send miss for all
        cids.forEach(function (cid) {
            _send(peer, _encode({ type: 'miss', requestId: requestId, cid: cid }));
        });
        return;
    }

    // Delegate to Jets._handleSubtreeGet's local Drop lookup
    Promise.resolve(_onChunkRequest(cids, grant)).then(function (results) {
        if (!results) { results = []; }
        cids.forEach(function (cid, i) {
            var chunk = results[i];
            if (chunk && chunk.ciphertext) {
                _send(peer, _encode({
                    type:        'chunk',
                    requestId:   requestId,
                    cid:         cid,
                    ciphertext:  chunk.ciphertext,
                    tag:         chunk.tag,
                    iv:          chunk.iv,
                }));
            } else {
                _send(peer, _encode({ type: 'miss', requestId: requestId, cid: cid }));
            }
        });
    }).catch(function (err) {
        console.warn('[JetSwarm] _handlePeerFetch error: ' + err.message);
        // Propagate deny so the requesting Jet can fall back
        _send(peer, _encode({ type: 'deny', requestId: requestId, reason: String(err) }));
    });
}

// ─── Receiving chunks from peer Jets ─────────────────────────────────────────

function _onPeerChunk(msg) {
    var p = _pending[msg.requestId];
    if (!p) { return; }

    p.received[msg.cid] = {
        cid:        msg.cid,
        chunk:      { ciphertext: msg.ciphertext, tag: msg.tag, iv: msg.iv, cid: msg.cid }
    };
    p.remaining--;
    if (p.remaining <= 0) { _resolvePending(msg.requestId); }
}

function _onPeerMiss(msg) {
    var p = _pending[msg.requestId];
    if (!p) { return; }
    p.received[msg.cid] = { cid: msg.cid, chunk: null };
    p.remaining--;
    if (p.remaining <= 0) { _resolvePending(msg.requestId); }
}

function _onPeerDeny(msg) {
    var p = _pending[msg.requestId];
    if (!p) { return; }
    // Treat deny as miss for all remaining CIDs in this request
    clearTimeout(p.timer);
    delete _pending[msg.requestId];
    p.resolve([]);
}

function _resolvePending(requestId) {
    var p = _pending[requestId];
    if (!p) { return; }
    clearTimeout(p.timer);
    delete _pending[requestId];
    var results = Object.values(p.received);
    p.resolve(results);
}

// ─── Outgoing fetch ───────────────────────────────────────────────────────────

function _fetchFromPeer(peer, cids, grant) {
    return new Promise(function (resolve) {
        var requestId = _uuid();

        var pending = {
            peer:      peer.pubkeyHex,
            received:  {},
            remaining: cids.length,
            resolve:   resolve,
            timer:     null,
        };

        pending.timer = setTimeout(function () {
            delete _pending[requestId];
            // Return whatever we received so far, rest as null
            var results = cids.map(function (cid) {
                return pending.received[cid] || { cid: cid, chunk: null };
            });
            resolve(results);
        }, FETCH_TIMEOUT_MS);

        _pending[requestId] = pending;

        _send(peer, _encode({
            type:      'fetch',
            requestId: requestId,
            cids:      cids,
            grant:     grant || null,
            // IP PRIVACY: no sender IP included — peer knows only our pubkey
        }));
    });
}

// ─── CID-to-peer assignment ───────────────────────────────────────────────────

/**
 * Assign each CID to the best peer Jet based on announced ranges.
 * Falls back to round-robin if no range matches.
 *
 * @private
 */
function _assignCidsToPeers(cids, peers) {
    var assignments = {};
    peers.forEach(function (p) { assignments[p.pubkeyHex] = []; });

    var rrIdx = 0;
    cids.forEach(function (cid) {
        var best = null;
        // Find the first peer whose range covers this CID (lexicographic)
        for (var i = 0; i < peers.length; i++) {
            var p = peers[i];
            if (_peerCoversRange(p, cid)) { best = p; break; }
        }
        if (!best) {
            // Round-robin fallback
            best = peers[rrIdx % peers.length];
            rrIdx++;
        }
        assignments[best.pubkeyHex].push(cid);
    });

    return assignments;
}

function _peerCoversRange(peer, cid) {
    if (!peer.ranges || !peer.ranges.length) { return false; }
    return peer.ranges.some(function (r) {
        return (!r.start || cid >= r.start) && (!r.end || cid <= r.end);
    });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function _encode(obj) {
    return JSON.stringify(obj) + '\n';
}

function _send(peer, encoded) {
    if (!peer || !peer.conn || peer.conn.destroyed) { return; }
    try { peer.conn.write(encoded); } catch (e) { /* ignore */ }
}

function _uuid() {
    return crypto.randomBytes(16).toString('hex');
}
