"use strict";
/* jshint node:true */
/**
 * Q.Safecloud.Router — pluggable routing layer for Q.Safecloud.Jets.
 *
 * Responsibilities:
 *   - Hyperswarm peer discovery  (topic = SHA-256("safecloud-jets"))
 *   - Pairwise Jet-to-Jet auth   (safecloud.jet.hello + session delegation)
 *   - Second-level Prolly tree   (union of all connected Drops' CIDs)
 *   - Jet-to-Jet Prolly sync     (on hello — exchange secondLevelRoot)
 *   - Weighted Drop selection    (stake × reliability × availableStorage)
 *   - Relay fallback             (GET /Safecloud/cloud/relay/{rootCid}?link=... with Noise bearer token)
 *   - CoC gossip                 (flood over hyperswarm Noise connections)
 *   - Request coalescing         (in-flight deduplication per CID)
 *
 * Replace this object before Q.Safecloud.listen() to plug in a different strategy:
 *   Q.Safecloud.Router = require('./Router.Kademlia');
 *   Q.Safecloud.listen();
 *
 * Public interface (called by Q.Safecloud.Jets):
 *   Router.init(options)                    → Promise<void>
 *   Router.selectForGet(cid, options)       → Promise<drop|null>
 *   Router.selectForPut(cids, options)      → Promise<Array<drop>>
 *   Router.relayGet(subtree, options)       → Promise<{chunks}|null>
 *   Router.announce(rootCid, event)         → void
 *   Router.gossipCoC(coc)                   → void
 *   Router.peerJets()                       → Array<{evmAddress,url,stake}>
 *   Router.onDropRegistered(drop, root)     → void   [lifecycle hook]
 *   Router.onDropAnnounce(drop, diff)       → void   [lifecycle hook]
 *   Router.onDropDisconnected(drop)         → void   [lifecycle hook]
 *
 * @class Q.Safecloud.Router
 * @static
 */

var Q      = require('Q');
var crypto = require('crypto');
// https — lazy require when relay is implemented (Phase 4)

// Hyperswarm — lazy to avoid hard dependency when Router is replaced
var _hyperswarm = null;
function _getHyperswarm() {
    if (_hyperswarm) { return _hyperswarm; }
    try {
        _hyperswarm = require('hyperswarm');
    } catch (e) {
        throw new Error('Q.Safecloud.Router requires hyperswarm. npm install hyperswarm. ' + e.message);
    }
    return _hyperswarm;
}

// ethers — lazy, only needed for delegation signing/verification (swarm mode)
var _ethers = null;
function _getEthers() {
    if (_ethers) { return _ethers; }
    try {
        _ethers = require('ethers');
    } catch (e) {
        throw new Error('Q.Safecloud.Router requires ethers for swarm mode. npm install ethers. ' + e.message);
    }
    return _ethers;
}

/**
 * EIP-712 typed data for the safecloud.jet.hello session delegation (v1).
 * MUST be identical on the signing side (_buildJetDelegation) and the
 * verifying side (_verifyDelegation). Documented in Protocol.md under
 * "Connection authentication and session key delegation".
 *
 * The delegation binds the Jet's EVM wallet to its hyperswarm Noise static
 * public key, so a captured delegation cannot be replayed over a different
 * Noise connection (see Attacks.md 1.2).
 * @private
 */
var DELEGATION_DOMAIN = { name: 'Safecloud', version: '1' };
var DELEGATION_TYPES  = {
    JetSessionDelegation: [
        { name: 'iss',              type: 'string'  },
        { name: 'sub',              type: 'string'  },
        { name: 'sessionKeyEIP712', type: 'address' },
        { name: 'noisePublicKey',   type: 'string'  },
        { name: 'nbf',              type: 'uint256' },
        { name: 'exp',              type: 'uint256' }
    ]
};

Q.makeEventEmitter(Safecloud_Router);
module.exports = Safecloud_Router;

function Safecloud_Router() {}

// ─────────────────────────────────────────────────────────────────────────────
// Private state
// ─────────────────────────────────────────────────────────────────────────────

/** @private evmAddress → { conn, url, evmAddress, stake, secondLevelRoot, delegation } */
var _peers = {};

/** @private rootCid → Set<dropId>  — all Drops holding this rootCid */
var _cidCoverage = {};

/** @private dropId → Number [0,1]  exponential moving average reliability */
var _reliabilityScore = {};

/** @private cid → Promise<chunk>   in-flight coalescing */
var _inflight = {};

/** @private cocHash → CoC object */
var _cocStore = {};

/** @private Set of evmAddresses known to be corrupt */
var _corruptActors = {};

/** @private in-memory Prolly store for the second-level (Jet-union) tree */
var _jetProllyStore = null;

/** @private String|null — second-level Prolly root */
var _jetProllyRoot = null;

/** @private peerEVM → Set<rootCid>  — topics we have subscribed to them for */
var _subscriptions = {};

/** @private rootCid → Array<{jetEVM, dropCount, latencyMs, lastSeen}> */
var _peerRoutes = {};

/** @private evmAddress → { balance: BigInt, cachedAt: Number } */
var _balanceCache = {};

/** @private hyperswarm instance */
var _swarm = null;

/** @private Whether init() has been called */
var _initialized = false;

/** @private Options passed to init() */
var _options = {};

/** @private hex of this Jet's Noise static public key — set by init() */
var _noisePublicKeyHex = null;

// ─── Constants ────────────────────────────────────────────────────────────────

var RELAY_TOKEN_WINDOW_SEC  = 300;  // 5-minute token validity window
var MAX_COC_HOPS            = 7;
var RELIABILITY_INITIAL     = 0.5;
var RELIABILITY_SUCCESS_W   = 0.1;
var RELIABILITY_FAIL_W      = 0.1;
var RELIABILITY_RECONNECT   = 0.25;
var WEIGHTED_SELECT_TOP_N   = 3;
var REPLICATION_DEFAULT     = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers — implement first (no deps on other Router methods)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Derive a short-lived relay bearer token from the Noise handshake shared
 * secret.  Uses conn.handshakeHash (NOT remotePublicKey — that's public).
 * Both sides derive the same value independently.
 *
 * @method _deriveRelayToken
 * @private
 * @param {Buffer}  sharedSecret  conn.handshakeHash  (32 bytes)
 * @param {String}  localEVM      This Jet's BSC address
 * @param {String}  remoteEVM     Peer Jet's BSC address
 * @param {Number}  [windowSec]   Token window in seconds (default 300)
 * @return {String}  hex HMAC token
 */
Safecloud_Router._deriveRelayToken = function (sharedSecret, localEVM, remoteEVM, windowSec) {
    windowSec = windowSec || RELAY_TOKEN_WINDOW_SEC;
    var window = Math.floor(Date.now() / 1000 / windowSec);
    return crypto.createHmac('sha256',
            Buffer.concat([sharedSecret, Buffer.from('safecloud.relay.auth')]))
        .update(localEVM + ':' + remoteEVM + ':' + window)
        .digest('hex');
};

/**
 * Derive a deterministic Ed25519 / Curve25519 Noise keypair from the Jet's
 * EVM private key.  Stable across restarts — same key → same hyperswarm identity.
 *
 * @method _deriveNoiseKeypair
 * @private
 * @param {Buffer|String} evmPrivateKey  Raw 32-byte private key or hex string
 * @return {{ publicKey: Buffer, secretKey: Buffer }}
 */
Safecloud_Router._deriveNoiseKeypair = function (evmPrivateKey) {
    var privBuf = Buffer.isBuffer(evmPrivateKey)
        ? evmPrivateKey
        : Buffer.from(evmPrivateKey.replace(/^0x/i, ''), 'hex');
    var seed = crypto.createHash('sha256')
        .update(privBuf)
        .update(Buffer.from('safecloud.noise'))
        .digest();
    // hypercore-crypto.keyPair(seed) → { publicKey, secretKey }
    // PLATFORM: hypercore-crypto
    try {
        var hcCrypto = require('hypercore-crypto');
        return hcCrypto.keyPair(seed);
    } catch (e) {
        throw new Error('Q.Safecloud.Router requires hypercore-crypto. npm install hypercore-crypto. ' + e.message);
    }
};

/**
 * Verify a safecloud.jet.hello delegation claim.
 * Returns true if the wallet signature is valid, not expired, and iss matches evmAddress.
 *
 * @method _verifyDelegation
 * @private
 * @param {Object} hello  safecloud.jet.hello message
 * @return {Promise<Boolean>}
 */
Safecloud_Router._verifyDelegation = function (hello, conn) {
    if (!hello || !hello.delegation || !hello.evmAddress) {
        return Promise.resolve(false);
    }
    var d = hello.delegation;
    if (!d.stm || !d.stm.exp) { return Promise.resolve(false); }
    var now = Math.floor(Date.now() / 1000);
    if (now > d.stm.exp) { return Promise.resolve(false); }
    if (d.stm.nbf && now < d.stm.nbf) { return Promise.resolve(false); }
    var evm = hello.evmAddress.toLowerCase();
    if (!d.iss || String(d.iss).toLowerCase().indexOf(evm) < 0) {
        return Promise.resolve(false);
    }

    // ── Noise-key binding (anti-replay across connections) ────────────────────
    // The delegation names the Noise static public key it was issued for.
    // A delegation captured from one connection is useless on another
    // (Attacks.md 1.2). Enforced whenever the connection handle is available.
    if (conn && conn.remotePublicKey) {
        var remoteHex = Buffer.isBuffer(conn.remotePublicKey)
            ? conn.remotePublicKey.toString('hex')
            : String(conn.remotePublicKey);
        if (!d.stm.noisePublicKey ||
            String(d.stm.noisePublicKey).toLowerCase() !== remoteHex.toLowerCase()) {
            return Promise.resolve(false);
        }
    }

    // ── Signature verification ─────────────────────────────────────────────────
    // Preferred: the platform OCP verifier, if this Q build ships it — it
    // handles arbitrary platform-issued delegation claims (e.g. from
    // Q.Crypto.delegate). Fallback: direct EIP-712 recovery over the
    // JetSessionDelegation typed data that _buildJetDelegation signs.
    var allowUnverified = Q.Config.get(
        ['Safecloud', 'swarm', 'allowUnverifiedDelegations'], false);

    if (!d.sig || !d.sig.length) {
        return Promise.resolve(!!allowUnverified);
    }

    var sig0   = d.sig[0];
    var sigHex = (sig0 && (sig0.signature || sig0)) || null;

    if (d.ocp === 1 && Q.Crypto && Q.Crypto.OpenClaim &&
        typeof Q.Crypto.OpenClaim.verify === 'function') {
        return Promise.resolve(Q.Crypto.OpenClaim.verify(d, { minValid: 1 }))
        .then(function (ok) {
            if (ok) { return true; }
            return _verifyDelegationEIP712(d, evm, sigHex);
        }).catch(function () {
            return _verifyDelegationEIP712(d, evm, sigHex);
        });
    }
    return Promise.resolve(_verifyDelegationEIP712(d, evm, sigHex));
};

/**
 * Direct EIP-712 recovery over the JetSessionDelegation typed data.
 * Recovered signer must equal the hello's evmAddress.
 * @private
 * @return {Boolean}
 */
function _verifyDelegationEIP712(d, evm, sigHex) {
    if (!sigHex) { return false; }
    try {
        var ethers = _getEthers();
        var value = {
            iss:              String(d.iss),
            sub:              String(d.sub || 'safecloud:session-delegation'),
            sessionKeyEIP712: d.stm.sessionKeyEIP712 || ethers.ZeroAddress,
            noisePublicKey:   String(d.stm.noisePublicKey || ''),
            nbf:              BigInt(d.stm.nbf || 0),
            exp:              BigInt(d.stm.exp || 0)
        };
        var recovered = ethers.verifyTypedData(
            DELEGATION_DOMAIN, DELEGATION_TYPES, value, sigHex);
        return recovered.toLowerCase() === evm;
    } catch (e) {
        return false;
    }
}

/**
 * Build and sign the JetSessionDelegation claim this Jet presents in
 * safecloud.jet.hello. Signed once per session by the Jet's EVM wallet;
 * bound to this Jet's Noise static public key.
 *
 * @method _buildJetDelegation
 * @private
 * @param {String|Buffer} evmPrivateKey   Safecloud.wallet.privateKey
 * @param {String}        noisePublicKeyHex
 * @return {Promise<Object>}  OCP-shaped delegation claim
 */
Safecloud_Router._buildJetDelegation = function (evmPrivateKey, noisePublicKeyHex) {
    var ethers = _getEthers();
    var pkHex  = Buffer.isBuffer(evmPrivateKey)
        ? '0x' + evmPrivateKey.toString('hex')
        : (String(evmPrivateKey).indexOf('0x') === 0
            ? String(evmPrivateKey) : '0x' + String(evmPrivateKey));
    var wallet = new ethers.Wallet(pkHex);
    var now    = Math.floor(Date.now() / 1000);
    var stm    = {
        sessionKeyEIP712: wallet.address,
        noisePublicKey:   String(noisePublicKeyHex || ''),
        nbf:              now - 60,
        exp:              now + 30 * 86400   // 30-day session (Protocol.md)
    };
    var value = {
        iss:              'data:key/eip712,' + wallet.address.toLowerCase(),
        sub:              'safecloud:session-delegation',
        sessionKeyEIP712: stm.sessionKeyEIP712,
        noisePublicKey:   stm.noisePublicKey,
        nbf:              BigInt(stm.nbf),
        exp:              BigInt(stm.exp)
    };
    return wallet.signTypedData(DELEGATION_DOMAIN, DELEGATION_TYPES, value)
    .then(function (sigHex) {
        return {
            ocp: 1,
            iss: value.iss,
            sub: value.sub,
            stm: stm,
            key: [value.iss],
            sig: [{ format: 'EIP712', signature: sigHex }]
        };
    });
};

/**
 * Compute a routing weight for a Drop.
 * weight = stakedSafebux × reliabilityScore × availableStorage
 *
 * @method _weightDrop
 * @private
 * @param {Object} drop   Drop record from Q.Safecloud.Jets.drops
 * @return {Number}
 */
Safecloud_Router._weightDrop = function (drop) {
    var reliability = _reliabilityScore[drop.dropId] !== undefined
        ? _reliabilityScore[drop.dropId]
        : RELIABILITY_INITIAL;

    // Stake: read from balance cache if available, otherwise assume 1
    var cached = _balanceCache[drop.evmAddress || ''];
    var stake  = cached ? Number(cached.balance / BigInt('1000000000000000000')) : 1;

    // Available storage
    var storageGB  = (drop.storage && drop.storage.GB) || 0;
    var usedGB     = (drop.used || 0) / (1024 * 1024 * 1024);
    var available  = Math.max(0, storageGB - usedGB);

    return stake * reliability * available;
};

/**
 * Weighted-random selection of up to N drops from a list,
 * proportional to their weights.  Zero-weight drops are excluded.
 *
 * @method _weightedRandomSelect
 * @private
 * @param {Array}  drops   Array of drop records
 * @param {Number} n       Maximum count to return
 * @return {Array}
 */
Safecloud_Router._weightedRandomSelect = function (drops, n) {
    var weighted = drops.map(function (d) {
        return { drop: d, weight: Safecloud_Router._weightDrop(d) };
    }).filter(function (w) { return w.weight > 0; });

    if (!weighted.length) {
        // Fallback: return first n with equal probability
        return drops.slice(0, n);
    }

    var selected = [];
    var pool     = weighted.slice();

    for (var i = 0; i < n && pool.length > 0; i++) {
        var total = pool.reduce(function (s, w) { return s + w.weight; }, 0);
        var rand  = Math.random() * total;
        var cum   = 0;
        var idx   = pool.length - 1;
        for (var j = 0; j < pool.length; j++) {
            cum += pool[j].weight;
            if (rand < cum) { idx = j; break; }
        }
        selected.push(pool[idx].drop);
        pool.splice(idx, 1);
    }
    return selected;
};

/**
 * Update reliability EMA for a Drop after a serve attempt.
 *
 * @method _updateReliability
 * @private
 * @param {String}  dropId
 * @param {Boolean} success
 */
Safecloud_Router._updateReliability = function (dropId, success) {
    var score = _reliabilityScore[dropId] !== undefined
        ? _reliabilityScore[dropId]
        : RELIABILITY_INITIAL;
    var w = success ? RELIABILITY_SUCCESS_W : RELIABILITY_FAIL_W;
    _reliabilityScore[dropId] = (1 - w) * score + w * (success ? 1 : 0);
};

/**
 * Apply a peer Prolly diff to _peerRoutes (external routing table).
 * Does NOT merge into the local second-level tree — peer CIDs are tracked
 * separately for relay decisions.
 *
 * @method _applyPeerDiff
 * @private
 * @param {String} peerEVM
 * @param {Array}  diff    [{cid, dropEVM, added}]
 */
Safecloud_Router._applyPeerDiff = function (peerEVM, diff) {
    diff.forEach(function (entry) {
        var rootCid = entry.cid; // in the second-level tree, key IS the rootCid
        if (!_peerRoutes[rootCid]) { _peerRoutes[rootCid] = []; }
        if (entry.added) {
            // Upsert peer route
            var existing = _peerRoutes[rootCid].find(function (r) { return r.jetEVM === peerEVM; });
            if (existing) {
                existing.lastSeen = Date.now();
            } else {
                _peerRoutes[rootCid].push({
                    jetEVM:    peerEVM,
                    dropCount: 1,
                    latencyMs: 9999,
                    lastSeen:  Date.now()
                });
            }
        } else {
            _peerRoutes[rootCid] = _peerRoutes[rootCid].filter(function (r) {
                return r.jetEVM !== peerEVM;
            });
        }
    });
};

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle hooks — called by Q.Safecloud.Jets on Drop events
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Called when a Drop registers (first time or reconnect).
 * Merges the Drop's CIDs into the second-level Prolly tree.
 *
 * @method onDropRegistered
 * @param {Object}      drop
 * @param {String|null} prollyRoot  Drop's reported Prolly root
 */
Safecloud_Router.onDropRegistered = function (drop, prollyRoot) {
    if (!prollyRoot) { return; }
    // Mark coverage; actual CIDs come via the diff log on announce
    _reliabilityScore[drop.dropId] = _reliabilityScore[drop.dropId] !== undefined
        ? Math.max(0, _reliabilityScore[drop.dropId] - RELIABILITY_RECONNECT)
        : RELIABILITY_INITIAL;
};

/**
 * Called when a Drop sends a Safecloud/drop/announce with a diff.
 * Updates _cidCoverage and the second-level Prolly tree.
 *
 * @method onDropAnnounce
 * @param {Object} drop
 * @param {Array}  diff  [{cid, added}]
 */
Safecloud_Router.onDropAnnounce = function (drop, diff) {
    if (!diff) { return; }
    diff.forEach(function (entry) {
        var rootCid = entry.cid;
        if (entry.added) {
            if (!_cidCoverage[rootCid]) { _cidCoverage[rootCid] = {}; }
            _cidCoverage[rootCid][drop.dropId] = true;
            // Emit 'available' on 0→1 transition
            if (Object.keys(_cidCoverage[rootCid]).length === 1) {
                Safecloud_Router.announce(rootCid, 'available');
            }
        } else {
            if (_cidCoverage[rootCid]) {
                delete _cidCoverage[rootCid][drop.dropId];
                // Emit 'unavailable' on 1→0 transition
                if (Object.keys(_cidCoverage[rootCid]).length === 0) {
                    delete _cidCoverage[rootCid];
                    Safecloud_Router.announce(rootCid, 'unavailable');
                }
            }
        }
    });
    // TODO Phase 4: update second-level Prolly tree incrementally
};

/**
 * Called when a Drop disconnects (transport close, not grace expiry).
 * Removes all CID coverage for this Drop.
 *
 * @method onDropDisconnected
 * @param {Object} drop
 */
Safecloud_Router.onDropDisconnected = function (drop) {
    var dropId = drop.dropId;
    Object.keys(_cidCoverage).forEach(function (rootCid) {
        if (_cidCoverage[rootCid] && _cidCoverage[rootCid][dropId]) {
            delete _cidCoverage[rootCid][dropId];
            if (Object.keys(_cidCoverage[rootCid]).length === 0) {
                delete _cidCoverage[rootCid];
                Safecloud_Router.announce(rootCid, 'unavailable');
            }
        }
    });
};

// ─────────────────────────────────────────────────────────────────────────────
// Public interface — called by Q.Safecloud.Jets
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Select a single Drop to serve a GET request for the given CID.
 * Checks _inflight for coalescing first.  Returns null if no suitable Drop found
 * (Jets will then call relayGet).
 *
 * @method selectForGet
 * @param {String} cid
 * @param {Object} [options]  { exclude: Array<dropId> }
 * @return {Promise<Object|null>}  drop record or null
 */
Safecloud_Router.selectForGet = function (cid, options) {
    options = options || {};
    var exclude = options.exclude || [];

    var coverage = _cidCoverage[cid];
    if (!coverage || !Object.keys(coverage).length) {
        return Promise.resolve(null);
    }

    var candidates = Object.keys(coverage)
        .filter(function (dropId) {
            return exclude.indexOf(dropId) < 0 &&
                   !_corruptActors[Q.Safecloud.Jets.drops[dropId] && Q.Safecloud.Jets.drops[dropId].evmAddress] &&
                   Q.Safecloud.Jets.drops[dropId] &&
                   !Q.Safecloud.Jets.drops[dropId].offlineSince;
        })
        .map(function (dropId) { return Q.Safecloud.Jets.drops[dropId]; })
        .filter(Boolean);

    var selected = Safecloud_Router._weightedRandomSelect(candidates, 1);
    return Promise.resolve(selected[0] || null);
};

/**
 * Select Drops to receive a PUT request.
 * Filters by Bloom filter (skip Drops that already have the CID).
 *
 * @method selectForPut
 * @param {Array}  cids
 * @param {Object} [options]  { replicationFactor }
 * @return {Promise<Array<Object>>}  array of drop records
 */
Safecloud_Router.selectForPut = function (cids, options) {
    options = options || {};
    var rf   = options.replicationFactor || REPLICATION_DEFAULT;
    var online = Object.keys(Q.Safecloud.Jets.drops)
        .map(function (id) { return Q.Safecloud.Jets.drops[id]; })
        .filter(function (d) { return d && !d.offlineSince && !_corruptActors[d.evmAddress]; });

    // Bloom filter pre-filter: skip Drops that already have the CID
    // PLATFORM: Q.Data.Bloom.test(filter, cid)
    var Bloom = Q.Data && Q.Data.Bloom;
    var filtered = online.filter(function (d) {
        if (!Bloom || !d.bloomFilter) { return true; }
        return !cids.every(function (cid) {
            return Bloom.test(d.bloomFilter, cid);
        });
    });

    var selected = Safecloud_Router._weightedRandomSelect(filtered, rf);
    return Promise.resolve(selected);
};

/**
 * Relay a GET request to a peer Jet when local Drops have no coverage.
 * Returns { chunks } on success, null when all peers exhausted.
 *
 * @method relayGet
 * @param {Object} subtree   { rootCid, link, grants }
 * @param {Object} [options] { payments, exclude: Array<jetEVM> }
 * @return {Promise<{chunks: Array}|null>}
 */
Safecloud_Router.relayGet = function (subtree, options) {
    // PLATFORM: Phase 4 — Noise bearer token + HTTPS relay + payment token
    // Stub: return null (no relay in v1 basic)
    return Promise.resolve(null);
};

/**
 * Broadcast a first/last Drop availability event to all peer Jets.
 * Constructs a safecloud:drop-availability OCP claim and gossips it.
 *
 * @method announce
 * @param {String} rootCid
 * @param {String} event    'available' | 'unavailable'
 */
Safecloud_Router.announce = function (rootCid, event) {
    // TODO Phase 4: sign OCP claim, gossip over Noise connections
    Q.log('Q.Safecloud.Router.announce: ' + event + ' ' + rootCid, 'Safecloud');
};

/**
 * Validate, deduplicate, store, and flood a Proof of Corruption claim.
 *
 * @method gossipCoC
 * @param {Object} coc  OCP safecloud:corruption claim envelope
 */
Safecloud_Router.gossipCoC = function (coc) {
    if (!coc || !coc.stm || !coc.sig) { return; }

    var cocHash = crypto.createHash('sha256')
        .update(JSON.stringify(coc))
        .digest('hex');

    if (_cocStore[cocHash]) { return; } // already seen
    _cocStore[cocHash] = coc;

    // ── Verify before acting ───────────────────────────────────────────────────
    // An unverified CoC must never change routing state: otherwise any peer
    // could grief an honest Drop off the network with one fabricated message.
    // The claim is stored above for forensics either way; the corrupt-actor
    // mark and event fire only after Q.Crypto.OpenClaim.verify succeeds.
    var subjectEVM = coc.stm && coc.stm.subjectEVM;
    if (!subjectEVM) { return; }

    var verifier = (Q.Crypto && Q.Crypto.OpenClaim &&
        typeof Q.Crypto.OpenClaim.verify === 'function')
        ? Q.Crypto.OpenClaim.verify(coc, { minValid: 1 })
        : false;

    Promise.resolve(verifier).then(function (ok) {
        if (!ok) {
            Q.log('Q.Safecloud.Router: unverified CoC recorded (no action) for '
                + subjectEVM, 'Safecloud');
            return;
        }
        _corruptActors[subjectEVM.toLowerCase()] = true;
        Safecloud_Router.emit('corruptActorDetected', subjectEVM, coc);
        Q.log('Q.Safecloud.Router: corrupt actor detected: ' + subjectEVM, 'Safecloud');
    }).catch(function () {
        Q.log('Q.Safecloud.Router: CoC verification error (no action) for '
            + subjectEVM, 'Safecloud');
    });

    // Flood to peers (decrement hopCount)
    // TODO Phase 4: gossip over Noise connections
};

/**
 * Return a snapshot of currently-connected peer Jets.
 *
 * @method peerJets
 * @return {Array<{evmAddress: String, url: String, stake: BigInt}>}
 */
Safecloud_Router.peerJets = function () {
    return Object.keys(_peers).map(function (evm) {
        var p = _peers[evm];
        var cached = _balanceCache[evm];
        return {
            evmAddress: evm,
            url:        p.url,
            stake:      cached ? cached.balance : BigInt(0)
        };
    });
};

// ─────────────────────────────────────────────────────────────────────────────
// Hyperswarm message handlers  (called from _onConnection)
// ─────────────────────────────────────────────────────────────────────────────

function _handleHello(conn, hello) {
    Safecloud_Router._verifyDelegation(hello, conn).then(function (ok) {
        if (!ok) {
            Q.log('Q.Safecloud.Router: rejected hello from ' + hello.evmAddress + ' (invalid delegation)', 'Safecloud');
            conn.destroy();
            return;
        }
        var evm = hello.evmAddress.toLowerCase();
        if (_peers[evm] && _peers[evm].conn !== conn) {
            // Deduplicate connections
            _peers[evm].conn = conn;
        } else if (!_peers[evm]) {
            _peers[evm] = { conn: conn, url: hello.url, evmAddress: evm,
                            secondLevelRoot: hello.secondLevelRoot || null };
        }

        // Prolly root sync
        if (hello.secondLevelRoot && hello.secondLevelRoot !== _jetProllyRoot) {
            _sendMessage(conn, {
                type:   'safecloud.prolly.diff',
                myRoot: _jetProllyRoot
            });
        }

        Q.log('Q.Safecloud.Router: peer hello accepted: ' + evm + ' @ ' + hello.url, 'Safecloud');
        Safecloud_Router.emit('peerConnected', _peers[evm]);
    });
}

function _handleAvailability(msg) {
    if (!msg || !msg.coc) { return; }
    var stm = msg.coc && msg.coc.stm;
    if (!stm || !stm.rootCid) { return; }
    var rootCid = stm.rootCid;
    var jetEVM  = stm.jetEVM;
    if (stm.event === 'available') {
        if (!_peerRoutes[rootCid]) { _peerRoutes[rootCid] = []; }
        var existing = _peerRoutes[rootCid].find(function (r) { return r.jetEVM === jetEVM; });
        if (!existing) {
            _peerRoutes[rootCid].push({ jetEVM: jetEVM, dropCount: stm.dropCount || 1,
                                        latencyMs: 9999, lastSeen: Date.now() });
        } else {
            existing.dropCount = stm.dropCount || existing.dropCount;
            existing.lastSeen  = Date.now();
        }
    } else {
        if (_peerRoutes[rootCid]) {
            _peerRoutes[rootCid] = _peerRoutes[rootCid].filter(function (r) { return r.jetEVM !== jetEVM; });
        }
    }
}

function _handleProllyDiff(conn, msg) {
    // TODO Phase 4: compute diff between msg.myRoot and _jetProllyRoot, respond
    _sendMessage(conn, {
        type: 'safecloud.prolly.diff.response',
        diff: []
    });
}

function _handleProllyDiffResponse(conn, msg) {
    if (!msg || !msg.diff) { return; }
    var peerEVM = _connToEVM(conn);
    if (peerEVM) { Safecloud_Router._applyPeerDiff(peerEVM, msg.diff); }
}

function _handleCoC(msg) {
    Safecloud_Router.gossipCoC(msg && msg.coc);
}

function _handleSubscribe(conn, msg) {
    // TODO Phase 4: register pairwise subscription
}

// ─────────────────────────────────────────────────────────────────────────────
// Hyperswarm connection handler
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Top-level handler for every new hyperswarm Noise connection.
 * Sends hello, then dispatches incoming messages.
 *
 * @method _onConnection
 * @private
 */
function _onConnection(conn, info) {
    Q.log('Q.Safecloud.Router: hyperswarm connection from peer', 'Safecloud');

    // Attach framing BEFORE the (async) hello send, so a fast peer's first
    // frame is never lost while our delegation is being prepared.
    _attachFraming(conn);

    // Send hello with a fresh (re-signed if near expiry) session delegation
    var jetEVM = Q.Config.get(['Safecloud', 'jet', 'address'], null);
    var jetUrl = Q.Config.get(['Safecloud', 'jet', 'url'], null);

    _freshDelegation().then(function (delegation) {
        _sendMessage(conn, {
            type:            'safecloud.jet.hello',
            url:             jetUrl,
            version:         1,
            evmAddress:      jetEVM,
            delegation:      delegation,
            secondLevelRoot: _jetProllyRoot
        });
    }).catch(function (err) {
        Q.log('Q.Safecloud.Router: could not prepare hello delegation: '
            + err, 'Safecloud');
    });

    conn.on('error', function (err) {
        Q.log('Q.Safecloud.Router: Noise connection error: ' + err, 'Safecloud');
    });
    conn.on('close', function () {
        var evm = _connToEVM(conn);
        if (evm) {
            delete _peers[evm];
            Safecloud_Router.emit('peerDisconnected', evm);
        }
    });
}

/**
 * Return the current session delegation, re-signing when absent or within
 * one hour of expiry. Caches on _options.delegation (which init() may have
 * pre-populated, or an app may have supplied explicitly).
 * @private
 * @return {Promise<Object|null>}
 */
function _freshDelegation() {
    var d   = _options.delegation;
    var now = Math.floor(Date.now() / 1000);
    if (d && d.stm && d.stm.exp && (d.stm.exp - now) > 3600) {
        return Promise.resolve(d);
    }
    var evmPrivKey = Q.Config.get(['Safecloud', 'wallet', 'privateKey'], null);
    if (!evmPrivKey || !_noisePublicKeyHex) {
        return Promise.resolve(d || null);
    }
    return Safecloud_Router._buildJetDelegation(evmPrivKey, _noisePublicKeyHex)
    .then(function (fresh) {
        _options.delegation = fresh;
        return fresh;
    });
}

function _attachFraming(conn) {
    // Read length-prefixed JSON frames
    _frameConn(conn, function (msg) {
        if (!msg || !msg.type) { return; }
        switch (msg.type) {
            case 'safecloud.jet.hello':
                _handleHello(conn, msg);
                break;
            case 'safecloud:drop-availability':
                _handleAvailability(msg);
                break;
            case 'safecloud.prolly.diff':
                _handleProllyDiff(conn, msg);
                break;
            case 'safecloud.prolly.diff.response':
                _handleProllyDiffResponse(conn, msg);
                break;
            case 'safecloud.coc':
                _handleCoC(msg);
                break;
            case 'safecloud.subscribe':
            case 'safecloud.unsubscribe':
                _handleSubscribe(conn, msg);
                break;
            default:
                // Ignore unknown message types
                break;
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Q.Safecloud.Router.init()
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Initialise the Router: set up hyperswarm, derive noise keypair, join topic.
 * Called by Q.Safecloud.Jets.listen() after the socket server starts.
 *
 * @method init
 * @param {Object} [options]
 * @return {Promise<void>}
 */
Safecloud_Router.init = function (options) {
    if (_initialized) { return Promise.resolve(); }
    _initialized = true;
    _options = options || {};

    var evmPrivKey = Q.Config.get(['Safecloud', 'wallet', 'privateKey'], null);
    if (!evmPrivKey) {
        Q.log('Q.Safecloud.Router.init: no wallet privateKey configured — hyperswarm disabled', 'Safecloud');
        return Promise.resolve();
    }

    var Hyperswarm;
    try {
        Hyperswarm = _getHyperswarm();
    } catch (e) {
        Q.log('Q.Safecloud.Router.init: ' + e.message + ' — peer discovery disabled', 'Safecloud');
        return Promise.resolve();
    }

    var noiseKeypair = Safecloud_Router._deriveNoiseKeypair(evmPrivKey);
    _noisePublicKeyHex = noiseKeypair.publicKey.toString('hex');

    // Sign the session delegation once up front (unless the app supplied one),
    // so the first hello never races the signer.
    var delegationReady = _options.delegation
        ? Promise.resolve(_options.delegation)
        : Safecloud_Router._buildJetDelegation(evmPrivKey, _noisePublicKeyHex)
            .then(function (d) { _options.delegation = d; return d; })
            .catch(function (err) {
                Q.log('Q.Safecloud.Router.init: delegation signing failed: '
                    + err + ' — hellos will be unsigned', 'Safecloud');
                return null;
            });

    return delegationReady.then(function () {
        _swarm = new Hyperswarm({ keyPair: noiseKeypair });

        var topic = crypto.createHash('sha256')
            .update('safecloud-jets')
            .digest();

        var discovery = _swarm.join(topic, { server: true, client: true });

        _swarm.on('connection', _onConnection);

        return discovery.flushed().then(function () {
            Q.log('Q.Safecloud.Router: hyperswarm announced on safecloud-jets topic', 'Safecloud');
        }).catch(function (err) {
            Q.log('Q.Safecloud.Router.init: hyperswarm error: ' + err, 'Safecloud');
        });
    });
};

// ─────────────────────────────────────────────────────────────────────────────
// Framing helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Length-prefix frame encoder/decoder for Noise duplex streams.
 * 4-byte big-endian length + UTF-8 JSON body.
 *
 * @method _frameConn
 * @private
 * @param {Stream}   conn
 * @param {Function} onMessage  called with each decoded message object
 */
function _frameConn(conn, onMessage) {
    var buf = Buffer.alloc(0);
    conn.on('data', function (chunk) {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
            var len = buf.readUInt32BE(0);
            if (buf.length < 4 + len) { break; }
            var body = buf.slice(4, 4 + len);
            buf      = buf.slice(4 + len);
            try {
                onMessage(JSON.parse(body.toString('utf8')));
            } catch (e) {
                Q.log('Q.Safecloud.Router: frame parse error: ' + e, 'Safecloud');
            }
        }
    });
}

/**
 * Send a length-prefixed JSON message over a Noise connection.
 *
 * @method _sendMessage
 * @private
 * @param {Stream} conn
 * @param {Object} msg
 */
function _sendMessage(conn, msg) {
    try {
        var body = Buffer.from(JSON.stringify(msg), 'utf8');
        var len  = Buffer.alloc(4);
        len.writeUInt32BE(body.length, 0);
        conn.write(Buffer.concat([len, body]));
    } catch (e) {
        Q.log('Q.Safecloud.Router._sendMessage error: ' + e, 'Safecloud');
    }
}

/**
 * Look up the EVM address for a connection.
 * @private
 */
function _connToEVM(conn) {
    return Object.keys(_peers).find(function (evm) {
        return _peers[evm].conn === conn;
    }) || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Q.Safecloud.Router events
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Emitted when a peer Jet's hello is accepted.
 * @event peerConnected
 * @param {Object} peer  { evmAddress, url, conn, ... }
 */

/**
 * Emitted when a peer Jet's Noise connection closes.
 * @event peerDisconnected
 * @param {String} evmAddress
 */

/**
 * Emitted when a valid CoC identifies a corrupt actor.
 * @event corruptActorDetected
 * @param {String} evmAddress
 * @param {Object} coc
 */
