"use strict";
/* jshint node:true */
/**
 * Q.Safecloud.Jets — Jet server (Node.js).
 *
 * Exposes:
 *   Q.Safecloud.Jets.listen(options)          — start HTTP + socket.io
 *   Q.Safecloud.Jets.callDrop(drop,...)       — emit to a Drop socket, await ack
 *   Q.Safecloud.Jets.selectDrops(cids, opts)  — delegate to Q.Safecloud.Router
 *   Q.Safecloud.Jets.verifySubtreeGrant(...)  — OCP Role A verification
 *   Q.Safecloud.Jets.verifyStreamAccess(...)  — Streams read-level gate
 *   Q.Safecloud.Jets.buildMerkleProofs(...)   — attach proofs to get responses
 *   Q.Safecloud.Jets._checkPayerBalance(...)  — ERC-20 balance pre-screen
 *   Q.Safecloud.Jets._evmProvider(chainId)    — lazy ethers provider
 *   Q.Safecloud.Jets._reconcileDropInventory  — Prolly tree reconciliation
 *   Q.Safecloud.Jets._attachBloomFilter       — deserialise + cache Bloom filter
 *
 * Internal state (module-private):
 *   Q.Safecloud.Drops            — dropId → drop record
 *   _socketToDropId       — socketId → dropId
 *   _dropProllyStores     — dropId → in-memory Prolly node store
 *   _providers            — chainId → ethers.JsonRpcProvider
 *   _balanceCache         — chainId → payer → token → { balance, cachedAt }
 *   _cidIndex             — rootCid → { linkPath → Array<cidString> }  (from PUT)
 *
 * @class Q.Safecloud.Jets
 * @static
 */

var Q         = require('Q');
var ethers    = require('ethers');
var crypto    = require('crypto');
var express   = require('express');

// Server-side Safe layer helpers (same plugin, sibling files)
var Safecloud_Client = require('./Client');
var Safecloud_Drops  = require('./Drops');
var JetSwarm         = require('./JetSwarm');

// Q.Crypto.OpenClaim.EVM — load lazily so Jets works without it (Phase 3)
try {
    var _OCPEvm = Q.Crypto.OpenClaim.EVM;
    if (Q.Crypto && !Q.Crypto.OpenClaim) { Q.Crypto.OpenClaim = {}; }
    if (Q.Crypto && Q.Crypto.OpenClaim)  { Q.Crypto.OpenClaim.EVM = _OCPEvm; }
} catch(e) {
    // Q.Crypto.OpenClaim.EVM not available — payment sig verification skipped
}

// Platform dependencies — loaded lazily where noted
// var Streams = Q.require('Streams');  // lazy: only when streamId present

Q.makeEventEmitter(Safecloud_Jets);
module.exports = Safecloud_Jets;

// ─────────────────────────────────────────────────────────────────────────────
// Constructor / namespace object
// ─────────────────────────────────────────────────────────────────────────────

function Safecloud_Jets() {}

/**
 * Registry of currently-connected Drops.
 * Key: dropId  Value: drop record (schema below)
 *
 * Drop record schema:
 * {
 *   dropId:        String,
 *   socketId:      String,          // socket.io id — changes on reconnect
 *   socket:        Object,          // raw socket.io socket
 *   clientId:      String|null,
 *   userId:        String|null,     // null for anonymous Drops
 *   evmAddress:    String|null,     // BSC wallet address
 *   delegation:    Object|null,     // OCP safecloud:session-delegation claim
 *   publicKey:     String|null,     // base64 P-256 public key (65-byte raw or 91-byte SPKI)
 *   storage:       { GB: Number },
 *   used:          Number,          // bytes currently occupied
 *   prollyRoot:    String|null,     // Drop's last announced Prolly root
 *   bloomFilter:   Object|null,     // deserialized Bloom filter (in-memory)
 *   reliabilityScore: Number,       // [0,1] EMA
 *   offlineSince:  Number|null,     // Date.now() when last disconnected
 *   registeredAt:  Number,          // Date.now()
 *   reconnectedAt: Number           // Date.now()
 * }
 *
 * @property {Object} drops
 * @static
 */
Safecloud_Jets.drops = {};

// ─── Module-private state ─────────────────────────────────────────────────────

/** @private socketId → dropId */
var _socketToDropId = {};

/** @private dropId → { get(hash)->node|null, put(hash,node)->void } */
var _dropProllyStores = {};


/** @private chainId (CAIP-2) → ethers.JsonRpcProvider */
var _providers = {};

/** @private Jet EVM wallet — used to sign payment tokens sent to Drops */
var _jetWallet = null;

/**
 * Initialise (or return cached) the Jet's ethers.Wallet for payment signing.
 * The private key is read from Safecloud.jet.privateKey in config.
 * If not configured, payment tokens remain unsigned (Phase 3 fallback).
 * @private
 */
function _getJetWallet() {
    if (_jetWallet) { return _jetWallet; }
    var privKey = Q.Config.get(['Safecloud', 'jet', 'privateKey'], null);
    if (!privKey) { return null; }
    try {
        _jetWallet = new ethers.Wallet(privKey);
        return _jetWallet;
    } catch (e) {
        Q.log('Q.Safecloud.Jets: invalid jet.privateKey — payment tokens will be unsigned: '
            + e.message, 'Safecloud');
        return null;
    }
}

/**
 * Sign an EIP-712 Payment struct and return the { stm, sig } OCP envelope.
 *
 * EIP-712 domain + types mirror OpenClaiming.sol Payment struct exactly.
 * The payer is the Jet's EVM address (jetWallet.address).
 * The payee (recipients) is the Drop's EVM address.
 *
 * @param {Object} stm     Payment statement (unsigned)
 * @param {String} dropEVM Drop's EVM address (the payee / recipient)
 * @return {Promise<{stm, sig}>|{stm, sig}>}  signed OCP envelope, or stub if no wallet
 * @private
 */
function _signPaymentToken(stm, dropEVM) {
    var wallet = _getJetWallet();
    if (!wallet || typeof ethers === 'undefined') {
        // No wallet configured — return unsigned stub (Drop will skip sig check)
        return Promise.resolve({ stm: stm, sig: [] });
    }

    var ocAddress = stm.contract ||
        Q.Config.get(['Users', 'web3', 'contracts', 'Safecloud/openclaiming',
            _chainIdToHex(stm.chainId || SAFEBUX_CHAIN)], OC_ADDRESS);

    // keccak256(abi.encode([dropEVM])) — the recipientsHash
    var dropAddrBytes  = Buffer.from(dropEVM.toLowerCase().replace(/^0x/i,'').padStart(40,'0'), 'hex');
    var dropAddrPadded = Buffer.concat([Buffer.alloc(12, 0), dropAddrBytes]);
    var abiEncoded     = Buffer.concat([
        Buffer.from('0000000000000000000000000000000000000000000000000000000000000020', 'hex'),
        Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex'),
        dropAddrPadded
    ]);
    var recipientsHash = ethers.keccak256(abiEncoded);

    // EIP-712 domain — must match OpenClaiming.sol constructor
    var domain = {
        name:              'OpenClaiming',
        version:           '1',
        chainId:           typeof stm.chainId === 'number'
                               ? stm.chainId
                               : parseInt((stm.chainId || SAFEBUX_CHAIN).replace('eip155:', ''), 10),
        verifyingContract: ocAddress
    };

    // EIP-712 types — must match OpenClaiming.sol Payment struct
    var types = {
        Payment: [
            { name: 'payer',          type: 'address' },
            { name: 'token',          type: 'address' },
            { name: 'max',            type: 'uint256' },
            { name: 'line',           type: 'uint256' },
            { name: 'nbf',            type: 'uint256' },
            { name: 'exp',            type: 'uint256' },
            { name: 'recipientsHash', type: 'bytes32' },
            { name: 'contract',       type: 'address' }
        ]
    };

    // Values — must exactly match on-chain struct
    var value = {
        payer:          wallet.address,
        token:          stm.token          || ethers.ZeroAddress,
        max:            BigInt(stm.max     || '0'),
        line:           BigInt(stm.line    || '0'),
        nbf:            BigInt(stm.nbf     || '0'),
        exp:            BigInt(stm.exp     || '0'),
        recipientsHash: recipientsHash,
        contract:       ocAddress
    };

    // Update stm with computed fields
    var signedStm = Object.assign({}, stm, {
        payer:          wallet.address,
        recipientsHash: recipientsHash,
        contract:       ocAddress
    });

    return wallet.signTypedData(domain, types, value).then(function (sigHex) {
        // OCP sig array: [ { format: 'EIP712', signature: hex } ]
        return {
            stm: signedStm,
            sig: [{ format: 'EIP712', signature: sigHex }]
        };
    }).catch(function (err) {
        Q.log('Q.Safecloud.Jets: payment signing failed: ' + err.message, 'Safecloud');
        return { stm: signedStm, sig: [] };
    });
}

/**
 * Balance cache.
 * _balanceCache[chainId][payerAddress][tokenAddress] = { balance: BigInt, cachedAt: Number }
 * @private
 */
var _balanceCache = {};

/**
 * CID index.
 * _cidIndex[rootCid][linkPath] = Array<String>  — CIDs for a given link path, from PUT.
 * e.g. _cidIndex["bafy..."]["track/data"] = [cid0, cid1, ...]
 * Lost on Jet restart; clients retry. Required by buildMerkleProofs().
 * @private
 */
var _cidIndex = {};

/** @private Grace-period sweep interval handle */
var _graceSweepInterval = null;

/** @private Cached listen() result for idempotency */
var _listenResult = null;

// ─── Constants ───────────────────────────────────────────────────────────────

var GRACE_MS_DEFAULT          = 60000;
var BALANCE_CACHE_TTL_DEFAULT = 3600000;
var CALL_DROP_TIMEOUT_DEFAULT = 10000;
var REPLICATION_DEFAULT       = 2;
var PER_CHUNK_WEI_DEFAULT     = '1000';

// ── Safebux is the ONLY accepted payment token for Safecloud ─────────────────
// All payments (Cloud→Jet and Jet→Drop) must be denominated in Safebux.
// The token address is set at deploy time via Safecloud.safebux.address config.
// The chain is BSC mainnet (eip155:56) initially; additional chains added as
// OpenClaiming is deployed there (currently: BSC + Ethereum).
// OC_ADDRESS: canonical OpenClaiming contract (same on all EVM chains)
var OC_ADDRESS                = '0x99999febd42cad798fe10ab0b1c563002fc99999';
var SAFEBUX_CHAIN             = 'eip155:56';   // BSC mainnet default

// Revenue split defaults (basis points out of 10000):
//   SPLIT_DROP:     60% — storage and bandwidth (Drop earns this)
//   SPLIT_JET:      20% — routing (Jet retains this)
//   SPLIT_CREATOR:  15% — content royalty (sent to manifest.revenue.incomeContract)
//   SPLIT_PROTOCOL:  5% — protocol treasury / Safebux buyback
// These are defaults. manifest.revenue.split overrides per-channel.
var SPLIT_DROP_BP             = 6000;
var SPLIT_JET_BP              = 2000;
var SPLIT_CREATOR_BP          = 1500;
var SPLIT_PROTOCOL_BP         =  500;
var SPLIT_TOTAL_BP            = 10000;

// Protocol treasury — receives SPLIT_PROTOCOL_BP share
// Set to Safebots treasury address before mainnet launch
var PROTOCOL_TREASURY         = Q.Config.get(
    ['Safecloud', 'safebux', 'treasury'],
    '0x0000000000000000000000000000000000000000'
);

var ERC20_ABI = [
    'function balanceOf(address) view returns (uint256)',
    'function availableToday(address) view returns (uint256)',
    'function allowance(address owner, address spender) view returns (uint256)'
];

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — implement first (no dependencies on public methods)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Return (or create) an in-memory Prolly node store for a Drop.
 * The store is a plain { hash: node } object wrapped with promise-returning
 * get/put, matching the interface expected by Q.Data.Prolly.
 *
 * @method _storeForDrop
 * @private
 * @param {String} dropId
 * @return {{ get: Function, put: Function }}
 */
Safecloud_Jets._storeForDrop = function (dropId) {
    if (!_dropProllyStores[dropId]) {
        var nodes = {};
        _dropProllyStores[dropId] = {
            get: function (hash) { return Promise.resolve(nodes[hash] || null); },
            put: function (hash, node) { nodes[hash] = node; return Promise.resolve(); }
        };
    }
    return _dropProllyStores[dropId];
};

/**
 * Lazy-initialise (and cache) an ethers.JsonRpcProvider for a CAIP-2 chainId.
 *
 * Config path: Q.Config.get(['Safecloud', 'evm', 'provider', chainId], defaultRpcUrl)
 *
 * @method _evmProvider
 * @private
 * @param {String} chainId  CAIP-2 string, e.g. 'eip155:56'
 * @return {ethers.JsonRpcProvider}
 */
/**
 * Convert CAIP-2 chainId ('eip155:56') to hex ('0x38') for Users.web3.chains lookup.
 * Accepts either format and returns hex.
 */
function _chainIdToHex(chainId) {
    if (typeof chainId === 'string' && chainId.indexOf('eip155:') === 0) {
        var num = parseInt(chainId.slice(7), 10);
        return '0x' + num.toString(16);
    }
    return chainId; // already hex or numeric string
}

/**
 * Convert hex chainId ('0x38') to CAIP-2 ('eip155:56').
 */
function _chainIdToCaip2(chainId) {
    if (typeof chainId === 'string' && chainId.indexOf('0x') === 0) {
        return 'eip155:' + parseInt(chainId, 16);
    }
    return chainId;
}

Safecloud_Jets._evmProvider = function (chainId) {
    var caip2 = _chainIdToCaip2(chainId);
    if (_providers[caip2]) { return _providers[caip2]; }

    var hexId = _chainIdToHex(chainId);

    // Read from Users.web3.chains[hexId].rpcUrl, fall back to publicRPC
    var chainConf = Q.Config.get(['Users', 'web3', 'chains', hexId], null);
    var rpcUrl = (chainConf && (chainConf.rpcUrl || chainConf.publicRPC)) || null;

    // Also accept explicit override at ['Safecloud', 'evm', 'provider', hexId]
    rpcUrl = Q.Config.get(['Safecloud', 'evm', 'provider', hexId], rpcUrl);

    if (!rpcUrl) {
        throw new Error('Q.Safecloud.Jets._evmProvider: no RPC URL for chainId ' + chainId +
            '. Configure Users.web3.chains.' + hexId + '.rpcUrl');
    }
    _providers[caip2] = new ethers.JsonRpcProvider(rpcUrl);
    return _providers[caip2];
};

/**
 * Pre-screen payer ERC-20 (or native) balance before accepting a payment token.
 * Results are cached per (chainId, payer, token) for up to balanceCacheTtlMs.
 *
 * This is advisory — the definitive check is on-chain at paymentsExecute().
 * Returns true if balance >= amount (BigInt comparison).
 *
 * @method _checkPayerBalance
 * @private
 * @param {String} payer      EVM address
 * @param {String} token      ERC-20 address, or address(0) for native coin
 * @param {String} amount     Token units as a decimal string
 * @param {String} chainId    CAIP-2 string
 * @return {Promise<Boolean>}
 */
/**
 * Pre-flight check for a payment token using OpenClaiming.lineAvailable().
 *
 * Calls lineAvailable(payer, line, claimMax) on the OpenClaiming contract —
 * a pure view function that returns how much is still collectable on this
 * specific payment line, accounting for the line's max and already-spent amount.
 *
 * This is the correct check because:
 * - balanceOf can be drained by other transactions (TOCTOU)
 * - lineAvailable reflects the line.max ceiling minus line.spent
 * - line.spent only increases when paymentsExecute is called on THIS token
 * - So lineAvailable represents what can actually still be collected
 *
 * For line 0 (DEFAULT_LINE) with claimMax > 0, returns claimMax minus what
 * has already been spent on this line.
 *
 * Falls back to balanceOf if OpenClaiming contract is unreachable.
 *
 * @method _checkPayerBalance
 * @param {String} payer     EVM address
 * @param {String} token     ERC-20 token address
 * @param {String} amount    Required amount as decimal string
 * @param {String} chainId   CAIP-2 string
 * @param {Number} [line=0]  OpenClaiming line id (default = DEFAULT_LINE)
 * @param {String} [claimMax='0'] Payment token's max field (0 = unlimited)
 */
Safecloud_Jets._checkPayerBalance = function (payer, token, amount, chainId, line, claimMax) {
    var ttl  = Q.Config.get(['Safecloud', 'drop', 'balanceCacheTtlMs'], BALANCE_CACHE_TTL_DEFAULT);
    var now  = Date.now();
    var lineId    = (line != null) ? line : 0;
    var maxField  = claimMax || '0';
    var cacheKey  = payer + ':' + lineId + ':' + maxField;

    var cached = Q.getObject([chainId, payer, cacheKey], _balanceCache);
    if (cached && (now - cached.cachedAt) < ttl) {
        return Promise.resolve(cached.balance >= BigInt(amount));
    }

    var provider  = Safecloud_Jets._evmProvider(chainId);
    var hexId     = _chainIdToHex(chainId);
    // Look up OC contract address from Users.web3.contracts (same pattern as Users plugin)
    var ocAddress = Q.Config.get(['Users', 'web3', 'contracts', 'Safecloud/openclaiming', hexId],
                   Q.Config.get(['Safecloud', 'openclaiming', 'address', hexId],
                   Q.Config.get(['Safecloud', 'openclaiming', 'address'], OC_ADDRESS)));

    // OpenClaiming.lineAvailable(address account, uint256 line, uint256 claimMax)
    //   → uint256  (remaining collectable amount on this line)
    var OC_ABI_LINE = [
        'function lineAvailable(address account, uint256 line, uint256 claimMax) view returns (uint256)'
    ];
    var ocContract = new ethers.Contract(ocAddress, OC_ABI_LINE, provider);

    return ocContract.lineAvailable(payer, BigInt(lineId), BigInt(maxField))
        .then(function (available) {
            if (!_balanceCache[chainId]) { _balanceCache[chainId] = {}; }
            if (!_balanceCache[chainId][payer]) { _balanceCache[chainId][payer] = {}; }
            _balanceCache[chainId][payer][cacheKey] = { balance: available, cachedAt: now };
            return available >= BigInt(amount);
        })
        .catch(function () {
            // Fallback: try availableToday on token contract, then raw balanceOf
            var erc20 = new ethers.Contract(token, ERC20_ABI, provider);
            return erc20.availableToday(payer).then(function (avail) {
                if (!_balanceCache[chainId]) { _balanceCache[chainId] = {}; }
                if (!_balanceCache[chainId][payer]) { _balanceCache[chainId][payer] = {}; }
                _balanceCache[chainId][payer][cacheKey] = { balance: avail, cachedAt: now };
                return avail >= BigInt(amount);
            }).catch(function () {
                return erc20.balanceOf(payer).then(function (bal) {
                    return bal >= BigInt(amount);
                });
            });
        });
};

/**
 * Emit a socket.io event to a Drop and await the ack.
 * Rejects after timeoutMs (default 10 000 ms).
 *
 * @method callDrop
 * @param {Object} drop        Drop record (must have .socket)
 * @param {String} method      Socket event name, e.g. 'Safecloud/drop/get'
 * @param {Object} payload     Payload to send
 * @param {Number} [timeoutMs] Default 10 000
 * @return {Promise<Object>}   Resolves with ack result, rejects on timeout/error
 */
Safecloud_Jets.callDrop = function (drop, method, payload, timeoutMs) {
    timeoutMs = timeoutMs || CALL_DROP_TIMEOUT_DEFAULT;
    if (!drop || !drop.socket) {
        return Promise.reject(new Error('Q.Safecloud.Jets.callDrop: drop has no socket (disconnected?)'));
    }
    return new Promise(function (resolve, reject) {
        var timer = setTimeout(function () {
            reject(new Error('Q.Safecloud.Jets.callDrop: timeout waiting for ' + method + ' from ' + drop.dropId));
        }, timeoutMs);

        try {
            drop.socket.emit(method, payload, function (err, result) {
                clearTimeout(timer);
                if (err) { return reject(typeof err === 'object' && err.error ? new Error(err.error.message) : err); }
                resolve(result);
            });
        } catch(e) {
            clearTimeout(timer);
            reject(e);
        }
    });
};

/**
 * Select Drops to serve a request.
 * v1: round-robin over online Drops (offlineSince === null).
 * Delegates to Q.Safecloud.Router.selectForGet / selectForPut when Router is set.
 *
 * @method selectDrops
 * @param {Array}  cids
 * @param {Object} [options]  { replicationFactor, exclude, forGet }
 * @return {Promise<Array>}   Array of drop records
 */
/**
 * _dropOfferPrice — reliability-adjusted per-chunk offer price for a Drop.
 * High-reliability Drops (score→1.0) get the full publisher price.
 * Lower-reliability Drops get less, which may fall below their minPerChunkWei.
 * Formula: offerPrice = publisherPrice × (0.5 + 0.5 × reliabilityScore)
 * Score 1.0 → 100% of publisher price
 * Score 0.5 → 75% of publisher price
 * Score 0.0 → 50% of publisher price
 * @param {Object} drop           Drop record
 * @param {String} publisherPrice perChunkWei from manifest metadata
 * @return {BigInt}
 * @private
 */
function _dropOfferPrice(drop, publisherPrice) {
    var pubWei = BigInt(publisherPrice || PER_CHUNK_WEI_DEFAULT);
    var score  = typeof drop.reliabilityScore === 'number'
        ? Math.min(1, Math.max(0, drop.reliabilityScore)) : 0.5;
    var factor = 0.5 + 0.5 * score;
    return BigInt(Math.floor(Number(pubWei) * factor));
}

Safecloud_Jets.selectDrops = function (cids, options) {
    options = options || {};
    if (options.forGet && Q.Safecloud.Router && Q.Safecloud.Router.selectForGet) {
        var cid = cids[0]; // primary CID for get
        return Q.Safecloud.Router.selectForGet(cid, options).then(function (drop) {
            return drop ? [drop] : [];
        });
    }
    if (!options.forGet && Q.Safecloud.Router && Q.Safecloud.Router.selectForPut) {
        return Q.Safecloud.Router.selectForPut(cids, options);
    }

    // v1 fallback: round-robin with price filter
    var rf             = options.replicationFactor || REPLICATION_DEFAULT;
    var exclude        = options.exclude || [];
    var publisherPrice = options.publisherPrice || PER_CHUNK_WEI_DEFAULT;

    var online  = Object.keys(Safecloud_Jets.drops).filter(function (id) {
        var d = Safecloud_Jets.drops[id];
        if (d.offlineSince !== null) { return false; }
        if (exclude.indexOf(id) >= 0) { return false; }
        // Price filter: only route to Drops whose minPerChunkWei <= offerPrice
        var offer    = _dropOfferPrice(d, publisherPrice);
        var minPrice = BigInt(d.minPerChunkWei || PER_CHUNK_WEI_DEFAULT);
        return offer >= minPrice;
    });
    // Shuffle for load distribution, then take up to rf unique drops
    var shuffled = online.slice().sort(function () { return Math.random() - 0.5; });
    var selected = shuffled.slice(0, Math.min(rf, shuffled.length))
                           .map(function (id) { return Safecloud_Jets.drops[id]; });
    return Promise.resolve(selected);
};

/**
 * Verify that OCP Role A grants cover a subtree identified by link path.
 *
 * For a GET request: verifies grants cover the requested link path.
 * For a PUT request: verifies grants authorize writing to the link path.
 *
 * Each grant must satisfy:
 *   1. grant.statement.label starts with 'safecloud.'
 *   2. ctx.link is an ancestor-or-equal of requestedLink
 *   3. ctx.rootCid === rootCid (if rootCid provided)
 *   4. ctx.exp not exceeded
 *   5. ctx.readLevel >= required (for GET)
 *   6. ECDSA signature valid
 *
 * Also accepts legacy grants with ctx.start/ctx.end for backward compatibility.
 *
 * Returns { ok: true } or { ok: false, unauthorized: [link], reason: String }
 *
 * @method verifySubtreeGrant
 * @param {Array}       grants          OCP Role A grant objects (secret stripped)
 * @param {String|null} rootCid         Merkle root; null on upload
 * @param {Array}       requestedLink   Link path, e.g. ["track","data","0","1"]
 * @param {Object|null} manifest        Manifest object (for link coverage checks)
 * @return {Promise<{ok: Boolean, unauthorized: Array, reason: String}>}
 */
Safecloud_Jets.verifySubtreeGrant = function (grants, rootCid, requestedLink, manifest) {
    if (!grants || !grants.length) {
        // No grants — allow if content is configured as public (requirePayment:false)
        // Otherwise reject. Grants are required for access-controlled content.
        var _requirePayment = Q.Config.get(['Safecloud', 'requirePayment'], false);
        if (!_requirePayment) {
            return Promise.resolve({ ok: true });
        }
        return Promise.resolve({
            ok: false,
            unauthorized: [requestedLink],
            reason: 'No grants provided'
        });
    }

    var now = Math.floor(Date.now() / 1000);

    // Find candidates: grants whose link covers requestedLink
    var candidates = grants.filter(function (grant) {
        if (!grant || !grant.statement || !grant.proof) { return false; }
        var stmt = grant.statement;
        if (!stmt.label || stmt.label.indexOf('safecloud.') !== 0) { return false; }
        var ctx;
        try { ctx = JSON.parse(stmt.context); } catch (e) { return false; }
        if (rootCid && ctx.rootCid && ctx.rootCid !== rootCid) { return false; }
        if (ctx.exp && ctx.exp > 0 && now > ctx.exp) { return false; }

        // Link path coverage check (new model)
        if (ctx.link && Array.isArray(ctx.link)) {
            return _isAncestorOrEqual(ctx.link, requestedLink);
        }
        // Legacy: ctx.start/ctx.end — accept if requestedLink is data track
        if (typeof ctx.start === 'number' && typeof ctx.end === 'number') {
            return requestedLink[0] === 'track' && requestedLink[1] === 'data';
        }
        return false;
    });

    if (!candidates.length) {
        return Promise.resolve({
            ok: false,
            unauthorized: [requestedLink],
            reason: 'No grant covers link path ' + JSON.stringify(requestedLink)
        });
    }

    // Try each candidate cryptographically
    function tryCandidates(ci) {
        if (ci >= candidates.length) {
            return Promise.resolve({
                ok: false,
                unauthorized: [requestedLink],
                reason: 'Grant crypto verification failed for ' + JSON.stringify(requestedLink)
            });
        }
        // For link-based grants pass a representative chunk index from the subtree
        var repIndex = manifest ? _leafRangeStart(requestedLink, manifest) : 0;
        return Safecloud_Client.verifyGrant(candidates[ci], rootCid, repIndex, manifest)
            .then(function (ok) {
                if (ok) { return { ok: true }; }
                return tryCandidates(ci + 1);
            });
    }

    return tryCandidates(0);
};

// ── Server-side tree helpers ──────────────────────────────────────────────────

function _isAncestorOrEqual(pathA, pathB) {
    if (!pathA || pathA.length > pathB.length) { return false; }
    for (var i = 0; i < pathA.length; i++) {
        if (String(pathA[i]) !== String(pathB[i])) { return false; }
    }
    return true;
}

function _chunkLinkPath(absIndex, manifest) {
    var treeN     = (manifest && manifest.treeN)     || 2;
    var treeDepth = (manifest && manifest.treeDepth) ||
                    Math.max(1, Math.ceil(Math.log((manifest && manifest.chunkCount) || 1) / Math.log(treeN)));
    var path = ['track', 'data'];
    var n    = Math.pow(treeN, treeDepth);
    var idx  = absIndex;
    for (var d = 0; d < treeDepth; d++) {
        n = n / treeN;
        path.push(String(Math.floor(idx / n)));
        idx = idx % n;
    }
    return path;
}

function _leafRangeStart(linkPath, manifest) {
    var treeN     = (manifest && manifest.treeN)     || 2;
    var treeDepth = (manifest && manifest.treeDepth) || 1;
    var total     = Math.pow(treeN, treeDepth);
    var nodeSegs  = linkPath.slice(2);
    var start     = 0, width = total;
    for (var i = 0; i < nodeSegs.length; i++) {
        width = width / treeN;
        start = start + parseInt(nodeSegs[i], 10) * width;
    }
    return Math.floor(start);
}


/**
 * Check Streams read/admin access for a Cloud user on a specific stream.
 * Anonymous users (userId === null) pass unconditionally.
 *
 * @method verifyStreamAccess
 * @param {String|null} userId
 * @param {String}      publisherId
 * @param {String}      streamName
 * @param {String}      level       Streams level word, e.g. 'content', 'invite'
 * @param {Function}    callback    fn(err, Boolean)
 */
Safecloud_Jets.verifyStreamAccess = function (userId, publisherId, streamName, level, callback) {
    if (!userId) {
        // Anonymous — OCP grants are the sole gate
        return callback(null, true);
    }
    // PLATFORM: Q.require('Streams') — lazy to avoid loading if Streams not installed
    var Streams;
    try { Streams = Q.require('Streams'); } catch (e) {
        // Streams plugin not installed — skip check
        return callback(null, true);
    }
    Streams.fetchOne(userId, publisherId, streamName, function (err, stream) {
        if (err || !stream) { return callback(null, false); }
        var method = (level === 'invite' || level === 'manage' || level === 'close')
            ? 'testAdminLevel'
            : 'testReadLevel';
        stream[method](level, function (err2, allowed) {
            callback(err2 || null, !!allowed);
        });
    });
};

/**
 * Build Merkle inclusion proofs for a requested chunk range.
 * Requires _cidIndex[rootCid] to be populated (set during PUT).
 * Returns null proofs if the index is missing (Jet restart scenario).
 *
 * @method buildMerkleProofs
 * @param {String} rootCid
 * @param {Array}  requestedCids  CID strings in the requested order
 * @param {Number} start          First absolute chunk index
 * @return {Promise<Array>}       Array of proof arrays [{hex, side}] | null per chunk
 */
/**
 * Build Merkle inclusion proofs for a set of CIDs within a link path subtree.
 *
 * Uses Q.Data.Merkle.nodeProof(rootCid, linkPath) when available (N-ary tree).
 * Falls back to Q.Data.Merkle.proof(leaves, index) for flat trees.
 * Returns null proofs if the index is missing (Jet restart scenario).
 *
 * @method buildMerkleProofs
 * @param {String} rootCid
 * @param {Array}  requestedCids   CID strings in subtree order
 * @param {Array}  link            Link path, e.g. ["track","data","0"]
 * @return {Promise<Array>}        Array of proof objects | null per chunk
 */
Safecloud_Jets.buildMerkleProofs = function (rootCid, requestedCids, link) {
    var Merkle = Q.Data && Q.Data.Merkle;
    if (!Merkle) {
        return Promise.resolve(requestedCids.map(function () { return null; }));
    }

    // Prefer N-ary nodeProof if available
    if (typeof Merkle.nodeProof === 'function') {
        return Promise.all(requestedCids.map(function (cid, relIdx) {
            // Look up the actual leaf link path for this CID via the _cidIndex
            // so we can request the correct proof path.
            // For leaf-level requests (link IS the leaf), use link directly.
            // For subtree requests, compute leaf path from absolute chunk position.
            var flatCids = _cidIndex[rootCid] && _cidIndex[rootCid]['track/data'];
            var absIdx   = flatCids ? flatCids.indexOf(cid) : -1;
            var leafLink;
            if (absIdx >= 0) {
                // Build leaf path from absolute index using _cidIndex tree params
                var tN = (_cidIndex[rootCid]['_treeN'])     || 2;
                var tD = (_cidIndex[rootCid]['_treeDepth']) || 1;
                var tc = flatCids.length;
                leafLink = _chunkLinkPath(absIdx, { treeN: tN, treeDepth: tD, chunkCount: tc });
            } else {
                leafLink = link; // fallback: use link as-is (likely already a leaf)
            }
            return Merkle.nodeProof(rootCid, leafLink)
                .catch(function () { return null; });
        }));
    }

    // Fallback: flat proof against the data track CID array
    var linkKey = (link || ['track','data']).join('/');
    var leaves  = _cidIndex[rootCid] && _cidIndex[rootCid][linkKey];
    if (!leaves || typeof Merkle.proof !== 'function') {
        return Promise.resolve(requestedCids.map(function () { return null; }));
    }
    return Promise.all(requestedCids.map(function (cid, relIdx) {
        return Merkle.proof(leaves, relIdx).catch(function () { return null; });
    }));
};

/**
 * Compare Drop's reported Prolly root against the Jet's stored root.
 * Emits 'dropColdSync', 'dropSync', or nothing.
 *
 * @method _reconcileDropInventory
 * @private
 * @param {Object} drop        Drop record
 * @param {String|null} prollyRoot  Root reported by Drop
 * @return {void}
 */
Safecloud_Jets._reconcileDropInventory = function (drop, prollyRoot) {
    var store = Safecloud_Jets._storeForDrop(drop.dropId);

    if (!drop.prollyRoot) {
        // Jet has no prior state for this Drop — cold sync
        drop.prollyRoot = prollyRoot;
        Safecloud_Jets.emit('dropColdSync', drop, prollyRoot);
        return;
    }
    if (drop.prollyRoot === prollyRoot) {
        // Roots match — no action needed
        return;
    }
    // Roots differ — compute diff via Q.Data.Prolly
    // PLATFORM: Q.Data.Prolly.diff(rootA, rootB, store)
    var Prolly = Q.Data && Q.Data.Prolly;
    if (!Prolly || typeof Prolly.diff !== 'function') {
        drop.prollyRoot = prollyRoot;
        Safecloud_Jets.emit('dropColdSync', drop, prollyRoot);
        return;
    }
    Prolly.diff(drop.prollyRoot, prollyRoot, store).then(function (changes) {
        drop.prollyRoot = prollyRoot;
        Safecloud_Jets.emit('dropSync', drop, changes);
    }).catch(function (err) {
        Q.log('Q.Safecloud.Jets._reconcileDropInventory: Prolly.diff error: ' + err, 'Safecloud');
        drop.prollyRoot = prollyRoot;
        Safecloud_Jets.emit('dropColdSync', drop, prollyRoot);
    });
};

/**
 * Deserialise a base64 Bloom filter and store it on the drop record.
 *
 * @method _attachBloomFilter
 * @private
 * @param {Object} drop
 * @param {String} bloomFilterB64  base64 serialised Bloom filter
 * @return {void}
 */
Safecloud_Jets._attachBloomFilter = function (drop, bloomFilterB64) {
    // PLATFORM: Q.Data.Bloom — deserialise
    var Bloom = Q.Data && Q.Data.Bloom;
    if (!Bloom || typeof Bloom.deserialize !== 'function') {
        drop.bloomFilter = null;
        return;
    }
    try {
        drop.bloomFilter = Bloom.deserialize(bloomFilterB64);
        Safecloud_Jets.emit('dropBloom', drop, drop.bloomFilter);
    } catch (e) {
        drop.bloomFilter = null;
        Q.log('Q.Safecloud.Jets._attachBloomFilter: deserialise error: ' + e, 'Safecloud');
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// PHP → Node internal message handler
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Handle POST /Q/node messages from PHP.
 * Registered by listen() on server.attached.express.
 *
 * Handled methods:
 *   Safecloud/drop/slash          — slash a Drop's stake
 *   Safecloud/payment/collect     — relay payment tokens to Assets plugin
 *
 * @method _requestHandler
 * @private
 */
function Safecloud_Jets_request_handler(req, res, next) {
    if (!req.internal || !req.validated) { return next(); }
    var parsed = req.body;
    if (!parsed || !parsed['Q/method']) { return next(); }

    switch (parsed['Q/method']) {

        case 'Safecloud/drop/slash': {
            var dropId = parsed.dropId;
            var reason = parsed.reason || 'Proof of Corruption';
            var drop   = Safecloud_Jets.drops[dropId];
            if (drop && drop.socket) {
                drop.socket.emit('Safecloud/drop/slashed', { reason: reason });
            }
            Safecloud_Jets.emit('dropSlash', drop || { dropId: dropId }, { reason: reason });
            res.json({ ok: true });
            break;
        }

        case 'Safecloud/payment/collect': {
            // PLATFORM: Q.Assets.OpenClaim — delegated to PHP/Assets plugin
            // Jets just acknowledge receipt; Assets plugin does the on-chain call.
            Q.log('Safecloud/payment/collect received for drop: ' + parsed.dropId, 'Safecloud');
            res.json({ ok: true });
            break;
        }

        default:
            return next();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Q.Safecloud.Jets.listen()
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Start the Jet server.
 *
 * Sequence:
 *   1. Q.listen() → Express server (or reuse existing)
 *   2. Register POST /Q/node handler
 *   3. Users.Socket.listen() → socket.io server on /Safecloud/ namespace
 *   4. Register HTTP routes: GET /Safecloud/cloud/chunk/:cid, GET /Safecloud/cloud/subtree/:rootCid, PUT /Safecloud/cloud/subtree
 *   5. Start grace-period sweep interval
 *   6. Initialise Q.Safecloud.Router (hyperswarm peer discovery)
 *
 * Idempotent — returns cached result on repeat calls.
 *
 * @method listen
 * @static
 * @param {Object} [options]
 * @return {{ internal: Object, socket: Object }}
 */
Safecloud_Jets.listen = function (options) {
    if (_listenResult) { return _listenResult; }

    options = Q.extend({}, Safecloud_Jets.listen.options, options);

    // ── 1. Internal HTTP server ───────────────────────────────────────────────
    var server = Q.listen();
    server.attached.express.post('/Q/node', Safecloud_Jets_request_handler);

    // ── 2. socket.io via Users.Socket.listen ─────────────────────────────────
    var Users;
    try { Users = Q.require('Users'); } catch (e) {
        throw new Error('Q.Safecloud.Jets.listen: requires the Users plugin. ' + e.message);
    }
    var socket = Users.Socket.listen(options);

    // ── 3. /Safecloud/ namespace handlers ──────────────────────────────────────────
    socket.io.of('/Safecloud/cloud').on('connection', function (client) {
        // client.capability — set by Q.Socket middleware (userId may be null for anon Drops)
        var userId = client.capability && client.capability.userId || null;

        Q.log('Safecloud client connected: ' + client.id + (userId ? ' user:' + userId : ' (anon)'), 'Safecloud');

        // ── Drop registration ─────────────────────────────────────────────────
        client.on('Safecloud/drop/register', function (payload, ack) {
            _handleDropRegister(client, userId, payload, ack);
        });

        // ── Drop inventory announce ───────────────────────────────────────────
        client.on('Safecloud/drop/announce', function (payload, ack) {
            _handleDropAnnounce(client, payload, ack);
        });

        // ── Drop intentional disconnect ───────────────────────────────────────
        client.on('Safecloud/drop/disconnect', function (payload, ack) {
            _handleDropDisconnect(client, payload, ack);
        });

        // ── Drop payment claim relay ──────────────────────────────────────────
        client.on('Safecloud/drop/claimPayments', function (payload, ack) {
            _handleDropClaimPayments(client, payload, ack);
        });

        // ── Cloud: subtree upload ─────────────────────────────────────────────
        client.on('Safecloud/subtree/put', function (payload, ack) {
            _handleSubtreePut(client, userId, payload, ack);
        });

        // ── Cloud: subtree download ───────────────────────────────────────────
        client.on('Safecloud/subtree/get', function (payload, ack) {
            _handleSubtreeGet(client, userId, payload, ack);
        });

        // ── Explicit proof-of-storage challenge ───────────────────────────────
        client.on('Safecloud/chunk/challenge', function (payload, ack) {
            var cid = payload && payload.cid;
            if (!cid) { return ack && ack({ error: { code: 'BadRequest', message: 'cid required' } }); }

            var _selectedDrops = [];
            Safecloud_Jets.selectDrops([cid], { forGet: true }).then(function (drops) {
                _selectedDrops = drops;
                if (!drops.length) { return ack && ack(null, null); }
                return Safecloud_Jets.callDrop(drops[0], 'Safecloud/drop/challenge', { cid: cid });
            }).then(function (chunk) {
                if (!chunk) { return ack && ack(null, null); }
                var valid = Safecloud_Drops.verifyChallengeResponse(cid, chunk);
                if (!valid) {
                    var drop0 = _selectedDrops[0];
                    Q.log('Q.Safecloud.Jets: challenge CID mismatch from Drop ' + (drop0 && drop0.dropId), 'Safecloud');
                    Safecloud_Jets.emit('dropChallengeFail', drop0, cid);
                }
                ack && ack(null, valid ? chunk : null);
            }).catch(function (err) {
                ack && ack({ error: { code: 'InternalError', message: String(err) } });
            });
        });

        // ── Transport disconnect ──────────────────────────────────────────────
        client.on('disconnect', function () {
            _handleClientDisconnect(client);
        });
    });

    // ── 4. HTTP routes ────────────────────────────────────────────────────────
    var app = server.attached.express;
    _registerHttpRoutes(app);

    // ── 5. Grace-period sweep ─────────────────────────────────────────────────
    var graceMs = Q.Config.get(['Safecloud', 'drop', 'offlineGraceMs'], GRACE_MS_DEFAULT);
    _graceSweepInterval = setInterval(function () {
        var now = Date.now();
        Object.keys(Safecloud_Jets.drops).forEach(function (dropId) {
            var drop = Safecloud_Jets.drops[dropId];
            if (drop.offlineSince && (now - drop.offlineSince) > graceMs) {
                Safecloud_Jets.emit('dropDisconnect', drop);
                if (Q.Safecloud.Router && typeof Q.Safecloud.Router.onDropDisconnected === 'function') {
                    Q.Safecloud.Router.onDropDisconnected(drop);
                }
                delete Safecloud_Jets.drops[dropId];
                delete _dropProllyStores[dropId];
                Q.log('Q.Safecloud.Jets: grace expired, evicted Drop ' + dropId, 'Safecloud');
            }
        });
    }, graceMs);

    // ── 6. Router + JetSwarm ─────────────────────────────────────────────────
    _initSwarm(options);

    _listenResult = { internal: server, socket: socket };
    return _listenResult;
};

Safecloud_Jets.listen.options = {};

// ─────────────────────────────────────────────────────────────────────────────
// Socket event handlers  (private — called from listen())
// ─────────────────────────────────────────────────────────────────────────────

function _handleDropRegister(client, userId, payload, ack) {
    if (!payload || !payload.dropId) {
        return ack && ack({ error: { code: 'BadRequest', message: 'dropId required' } });
    }

    var dropId      = payload.dropId;
    var evmAddress  = payload.evmAddress || null;
    var delegation  = payload.delegation || null;
    var publicKey   = payload.publicKey || null;
    var storage     = payload.storage || { GB: 0 };
    var prollyRoot  = payload.prollyRoot || null;
    var bloomFilter = payload.bloomFilter || null;

    // Verify delegation claim if present using Q.Crypto.OpenClaim.verify.
    // Delegation is a self-issued OCP claim: iss=EVM addr, key=[ES256 SPKI URI], sig=[P-256].
    // Q.Crypto.OpenClaim.verify handles key URI resolution, canonicalization, and ES256 check.
    var _afterDelegationCheck = function () {
        _registerDrop(client, userId, payload, ack,
            dropId, evmAddress, delegation, publicKey, storage, prollyRoot, bloomFilter);
    };

    if (delegation && delegation.key && delegation.key.length && delegation.sig && delegation.sig[0]) {
        var stm      = delegation.stm || {};
        var nowSec   = Math.floor(Date.now() / 1000);
        var claimExp = stm.exp || 0;
        if (claimExp && claimExp < nowSec) {
            return ack && ack({ error: { code: 'Unauthorized', message: 'Delegation claim expired' } });
        }
        if (stm.sessionKeyES256 && publicKey && stm.sessionKeyES256 !== publicKey) {
            return ack && ack({ error: { code: 'Unauthorized', message: 'Session key mismatch' } });
        }
        if (stm.sessionKeyEIP712 && evmAddress &&
            stm.sessionKeyEIP712.toLowerCase() !== evmAddress.toLowerCase()) {
            return ack && ack({ error: { code: 'Unauthorized', message: 'EVM address mismatch' } });
        }
        Q.Crypto.OpenClaim.verify(delegation).then(function (ok) {
            if (!ok) {
                return ack && ack({ error: { code: 'Unauthorized', message: 'Invalid delegation signature' } });
            }
            _afterDelegationCheck();
        }).catch(function () {
            ack && ack({ error: { code: 'Unauthorized', message: 'Delegation verification failed' } });
        });
    } else {
        _afterDelegationCheck();
    }
    return; // rest of handler runs inside _registerDrop
}

function _registerDrop(client, userId, payload, ack,
    dropId, evmAddress, delegation, publicKey, storage, prollyRoot, bloomFilter) {

    var minStake = Q.Config.get(['Safecloud', 'drop', 'minStakeSafebux'], '0');
    var cold     = false;

    var existing = Safecloud_Jets.drops[dropId];
    var isReconnect = !!existing;

    var drop = existing || {};
    Q.extend(drop, {
        dropId:           dropId,
        socketId:         client.id,
        socket:           client,
        clientId:         payload.clientId || null,
        userId:           userId,
        evmAddress:       evmAddress,
        delegation:       delegation,
        publicKey:        publicKey,
        storage:          storage,
        used:             payload.used || 0,
        offlineSince:     null,
        registeredAt:     drop.registeredAt || Date.now(),
        reconnectedAt:    Date.now(),
        reliabilityScore: existing ? Math.max(0, existing.reliabilityScore - 0.25) : 0.5,
        // Drop's minimum acceptable price per chunk in Safebux wei.
        // Set by Drop at registration. Jet skips if offerPrice < minPerChunkWei.
        minPerChunkWei:   payload.minPerChunkWei
                          || (existing && existing.minPerChunkWei)
                          || Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT)
    });

    _socketToDropId[client.id] = dropId;
    Safecloud_Jets.drops[dropId] = drop;

    // Prolly reconciliation
    var jetHasRoot = !!(existing && existing.prollyRoot);
    if (!jetHasRoot) {
        cold = true;
        drop.prollyRoot = prollyRoot;
    } else {
        Safecloud_Jets._reconcileDropInventory(drop, prollyRoot);
    }

    // Bloom filter — attach if cold or first contact
    if (bloomFilter) {
        Safecloud_Jets._attachBloomFilter(drop, bloomFilter);
    }

    if (isReconnect) {
        Safecloud_Jets.emit('dropReconnect', drop);
    } else {
        Safecloud_Jets.emit('dropRegister', drop);
    }

    // Notify Router
    if (Q.Safecloud.Router && typeof Q.Safecloud.Router.onDropRegistered === 'function') {
        Q.Safecloud.Router.onDropRegistered(drop, prollyRoot);
    }

    ack && ack(null, { dropId: dropId, cold: cold, minStake: minStake });
}

function _handleDropAnnounce(client, payload, ack) {
    if (!payload || !payload.dropId) {
        return ack && ack({ error: { code: 'BadRequest', message: 'dropId required' } });
    }
    var dropId = payload.dropId;
    var drop   = Safecloud_Jets.drops[dropId];
    if (!drop) {
        return ack && ack({ error: { code: 'NotFound', message: 'Drop not registered' } });
    }
    // Verify this socket owns the dropId — prevent any socket from forging announces
    if (drop.socketId && drop.socketId !== client.id) {
        return ack && ack({ error: { code: 'Unauthorized', message: 'Socket does not own this dropId' } });
    }

    // Verify announce signature — P-256 over canonical JSON of announce payload.
    // Reject if signature is present but invalid (prevents spoofed Prolly roots).
    // If no signature and no public key, accept with reduced trust (open mode).
    if (payload.signature && drop.publicKey) {
        var pubKeyBytes = Buffer.from(drop.publicKey, 'base64');
        var announceOk;
        try {
            announceOk = Safecloud_Drops.verifyAnnounce(payload, pubKeyBytes);
        } catch (e) {
            announceOk = false;
        }
        if (!announceOk) {
            Q.log('Q.Safecloud.Jets: announce signature INVALID from ' + dropId
                + ' — rejecting announce', 'Safecloud');
            return ack && ack({
                error: { code: 'Unauthorized', message: 'Invalid announce signature' }
            });
        }
    } else if (!payload.signature && drop.publicKey) {
        // Drop has a registered public key but sent no signature — reject.
        // This prevents a compromised/replayed session from spoofing announces.
        Q.log('Q.Safecloud.Jets: announce missing signature from registered Drop '
            + dropId + ' — rejecting', 'Safecloud');
        return ack && ack({
            error: { code: 'Unauthorized', message: 'Announce signature required for registered Drops' }
        });
    }

    drop.storage  = payload.storage  || drop.storage;
    drop.used     = payload.used != null ? payload.used : drop.used;

    if (payload.reason === 'reset') {
        drop.prollyRoot = null;
        if (drop.bloomFilter) { drop.bloomFilter = null; }
        Safecloud_Jets.emit('dropAnnounce', drop);
        return ack && ack(null);
    }

    var newRoot  = payload.prollyRoot  || null;
    var diff     = payload.diff        || null;
    var bloom    = payload.bloomFilter || null;

    if (bloom) { Safecloud_Jets._attachBloomFilter(drop, bloom); }

    Safecloud_Jets._reconcileDropInventory(drop, newRoot);

    // Notify Router of diff
    if (diff && Q.Safecloud.Router && typeof Q.Safecloud.Router.onDropAnnounce === 'function') {
        Q.Safecloud.Router.onDropAnnounce(drop, diff);
    }

    Safecloud_Jets.emit('dropAnnounce', drop);
    ack && ack(null);
}

function _handleDropDisconnect(client, payload, ack) {
    var dropId = payload && payload.dropId;
    if (dropId && Safecloud_Jets.drops[dropId]) {
        var drop = Safecloud_Jets.drops[dropId];
        // Verify this socket owns the dropId
        if (drop.socketId && drop.socketId !== client.id) {
            return ack && ack({ error: { code: 'Unauthorized', message: 'Socket does not own this dropId' } });
        }
        Safecloud_Jets.emit('dropDisconnect', drop);
        delete Safecloud_Jets.drops[dropId];
        delete _dropProllyStores[dropId];
        delete _socketToDropId[client.id];

        if (Q.Safecloud.Router && typeof Q.Safecloud.Router.onDropDisconnected === 'function') {
            Q.Safecloud.Router.onDropDisconnected(drop);
        }
    }
    ack && ack(null);
}

function _handleDropClaimPayments(client, payload, ack) {
    var dropId = payload && payload.dropId;
    var drop   = dropId && Safecloud_Jets.drops[dropId];

    // Verify socket owns the dropId
    if (drop && drop.socketId && drop.socketId !== client.id) {
        return ack && ack({ error: { code: 'Unauthorized', message: 'Socket does not own this dropId' } });
    }
    if (!drop) {
        return ack && ack({ error: { code: 'NotFound', message: 'Drop not registered' } });
    }

    var tokens    = payload.paymentTokens || [];
    var signature = payload.signature     || null;
    var dropEVM   = drop.evmAddress       || (payload.dropEVM);
    var nonce     = payload.nonce         || 0;

    if (!tokens.length) {
        return ack && ack(null, { txHash: null, reason: 'no tokens' });
    }

    // ── Verify Drop's relay request signature ─────────────────────────────────
    // Drop signed: { dropId, dropEVM, nonce, tokenCount } with its EVM private key.
    // Jet verifies the signer matches drop.evmAddress before relaying.
    var sigVerifyPromise = (signature && dropEVM && typeof ethers !== 'undefined')
        ? _verifyRelaySignature(payload, dropEVM, signature)
        : Promise.resolve(!Q.Config.get(['Safecloud', 'requirePayment'], false));

    sigVerifyPromise.then(function (sigOk) {
        if (!sigOk) {
            return ack && ack({ error: { code: 'Unauthorized', message: 'Invalid relay request signature' } });
        }

        Q.log('Q.Safecloud.Jets: relaying ' + tokens.length + ' payment tokens for Drop ' + dropId, 'Safecloud');

        // ── Submit on-chain via Jet wallet ────────────────────────────────────
        var wallet = _getJetWallet();
        if (!wallet || typeof ethers === 'undefined') {
            Q.log('Q.Safecloud.Jets: no Jet wallet configured — cannot relay', 'Safecloud');
            return ack && ack(null, { txHash: null, reason: 'no_jet_wallet' });
        }

        var chainId  = Q.Config.get(['Safecloud', 'safebux', 'chainId'], SAFEBUX_CHAIN);
        var hexId    = chainId.indexOf('eip155:') === 0
            ? '0x' + parseInt(chainId.slice(7), 10).toString(16) : chainId;
        var chainConf = Q.Config.get(['Users', 'web3', 'chains', hexId], null);
        var rpcUrl   = (chainConf && (chainConf.rpcUrl || chainConf.publicRPC))
            || Q.Config.get(['Safecloud', 'evm', 'provider', hexId],
                   'https://bsc-dataseed.binance.org/');

        var provider = new ethers.JsonRpcProvider(rpcUrl);
        var signer   = wallet.connect(provider);
        var OC_ABI   = [
            'function paymentsExecute(' +
            '(address payer,address token,bytes32 recipientsHash,uint256 max,' +
            'uint256 line,uint256 nbf,uint256 exp) payment,' +
            'address[] recipients, bytes signature, address recipient,' +
            'uint256 amount, address incomeContract) external'
        ];
        var contract  = new ethers.Contract(OC_ADDRESS, OC_ABI, signer);
        var txHashes  = [];
        var batchSize = Q.Config.get(['Safecloud', 'drop', 'claimBatchSize'], 10);
        var perChunk  = Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT);

        // Process tokens sequentially in batches
        var validTokens = tokens.filter(function (t) {
            return t && t.stm && t.sig && t.sig[0];
        });

        if (!validTokens.length) {
            return ack && ack(null, { txHash: null, reason: 'no_signed_tokens' });
        }

        var batches = [];
        for (var bi = 0; bi < validTokens.length; bi += batchSize) {
            batches.push(validTokens.slice(bi, bi + batchSize));
        }

        batches.reduce(function (prev, batch) {
            return prev.then(function () {
                return batch.reduce(function (p2, token) {
                    return p2.then(function () {
                        var stm      = token.stm;
                        var sigHex   = token.sig[0].signature || token.sig[0];
                        var sigBytes;
                        try {
                            sigBytes = ethers.getBytes(
                                sigHex.startsWith('0x') ? sigHex : '0x' + sigHex
                            );
                        } catch (e) { return; }

                        var amount = BigInt(stm.max || perChunk);
                        var incomeAddr = token.incomeContract || ethers.ZeroAddress;

                        return contract.paymentsExecute(
                            {
                                payer:          stm.payer,
                                token:          stm.token,
                                recipientsHash: stm.recipientsHash || ethers.ZeroHash,
                                max:            BigInt(stm.max     || '0'),
                                line:           BigInt(stm.line    || '0'),
                                nbf:            BigInt(stm.nbf     || '0'),
                                exp:            BigInt(stm.exp     || '0')
                            },
                            [dropEVM],
                            sigBytes,
                            dropEVM,
                            amount,
                            incomeAddr
                        ).then(function (tx) {
                            txHashes.push(tx.hash);
                            return tx.wait();
                        }).catch(function (err) {
                            Q.log('Q.Safecloud.Jets: paymentsExecute error for token: ' + err.message, 'Safecloud');
                        });
                    });
                }, Promise.resolve());
            });
        }, Promise.resolve()).then(function () {
            Q.log('Q.Safecloud.Jets: relay complete, ' + txHashes.length + ' txs for ' + dropId, 'Safecloud');
            ack && ack(null, {
                txHash:   txHashes[0]  || null,
                txHashes: txHashes,
                claimed:  txHashes.length
            });
        }).catch(function (err) {
            Q.log('Q.Safecloud.Jets: relay failed for ' + dropId + ': ' + err, 'Safecloud');
            ack && ack({ error: { code: 'InternalError', message: String(err) } });
        });

    }).catch(function (err) {
        ack && ack({ error: { code: 'InternalError', message: String(err) } });
    });
}

/**
 * Verify a Drop's relay request EIP-712 signature.
 * Recovers the signer and checks it matches drop.evmAddress.
 * @param {Object} payload    relay request payload
 * @param {String} dropEVM    expected Drop EVM address
 * @param {String} signature  hex signature from Drop
 * @return {Promise<Boolean>}
 * @private
 */
function _verifyRelaySignature(payload, dropEVM, signature) {
    try {
        var chainId  = Q.Config.get(['Safecloud', 'safebux', 'chainId'], SAFEBUX_CHAIN);
        var chainNum = chainId.indexOf('eip155:') === 0
            ? parseInt(chainId.slice(7), 10) : parseInt(chainId, 10);
        var ocAddr   = Q.Config.get(['Safecloud', 'openclaiming', 'address'], OC_ADDRESS);

        var domain = {
            name:              'OpenClaiming',
            version:           '1',
            chainId:           chainNum,
            verifyingContract: ocAddr
        };
        var types = {
            RelayRequest: [
                { name: 'dropId',     type: 'string'  },
                { name: 'dropEVM',    type: 'address' },
                { name: 'nonce',      type: 'uint256' },
                { name: 'tokenCount', type: 'uint256' }
            ]
        };
        var value = {
            dropId:     payload.dropId     || '',
            dropEVM:    dropEVM,
            nonce:      BigInt(payload.nonce      || 0),
            tokenCount: BigInt((payload.paymentTokens || []).length)
        };

        var recovered = ethers.verifyTypedData(domain, types, value, signature);
        return Promise.resolve(recovered.toLowerCase() === dropEVM.toLowerCase());
    } catch (e) {
        return Promise.resolve(false);
    }
}

function _handleSubtreePut(client, userId, payload, ack) {
    var grants      = payload.grants      || [];
    var payments    = payload.payments    || [];
    var chunks      = payload.chunks      || [];
    var link        = payload.link        || ['track', 'data'];
    var publisherId = payload.publisherId || null;
    var streamName  = payload.streamName  || null;

    // 1. OCP Role A grant verification (link-path model)
    // On upload, rootCid is not yet known — grants are optional for new uploads.
    // If grants are provided (re-upload / authorized write), verify them.
    var uploadGrantPromise = grants.length
        ? Safecloud_Jets.verifySubtreeGrant(grants, null, link, null)
        : Promise.resolve({ ok: true });

    uploadGrantPromise.then(function (grantResult) {
        if (!grantResult.ok) {
            return ack && ack({
                error: {
                    code:         'NotAuthorized',
                    message:      grantResult.reason,
                    details:      { unauthorized: grantResult.unauthorized, grantIssues: grantResult.grantIssues }
                }
            });
        }

        // 2. Streams access check (if streamId provided)
        Safecloud_Jets.verifyStreamAccess(userId, publisherId, streamName, 'post', function (err, allowed) {
            if (!allowed) {
                return ack && ack({
                    error: { code: 'NotAuthorized', message: 'Streams write access denied',
                             details: { unauthorized: [link] } }
                });
            }

            // 3. Payment pre-screen
            _checkPayments(payments, chunks.length).then(function (payOk) {
                if (!payOk) {
                    return ack && ack({ error: { code: 'PaymentRequired', message: 'Insufficient balance' } });
                }

                // 4. Store CID index keyed by rootCid + link path
                if (chunks.length > 0) {
                    var cids = chunks.map(function (c) { return c.cid; });
                    // rootCid: from payload directly (new uploads pass it explicitly),
                    // or fall back to extracting from grant context (re-uploads with grants)
                    var rootCid = payload.rootCid || null;
                    if (!rootCid && grants[0] && grants[0].statement) {
                        try { rootCid = JSON.parse(grants[0].statement.context).rootCid; } catch(e) {}
                    }
                    if (rootCid) {
                        if (!_cidIndex[rootCid]) { _cidIndex[rootCid] = {}; }
                        _cidIndex[rootCid][link.join('/')] = cids;
                        // Store treeN if provided so GET can resolve leaf link ranges
                        if (payload.treeN)     { _cidIndex[rootCid]['_treeN']     = payload.treeN; }
                        if (payload.treeDepth) { _cidIndex[rootCid]['_treeDepth'] = payload.treeDepth; }

                        // Cache metadata for price enforcement.
                        // When track/meta is uploaded, store the metaCid and any
                        // price hint from chunk tags.
                        if (link.join('/') === 'track/meta' && chunks[0]) {
                            _cidIndex[rootCid]['_metaCid'] = chunks[0].cid;
                            var metaTags2 = chunks[0].tags || [];
                            metaTags2.forEach(function (tag) {
                                if (typeof tag === 'string' && tag.startsWith('safecloud.price:')) {
                                    _cidIndex[rootCid]['_perChunkWei'] = tag.slice(16);
                                }
                            });
                        }
                    }
                }

                // 5. Fan-out to Drops
                Safecloud_Jets.selectDrops(chunks.map(function(c){return c.cid;}), {
                    replicationFactor: Q.Config.get(['Safecloud', 'put', 'replicationFactor'], REPLICATION_DEFAULT)
                }).then(function (drops) {
                    if (!drops.length) {
                        return ack && ack({ error: { code: 'ServiceUnavailable', message: 'No Drops available' } });
                    }
                    var putPromises = drops.map(function (drop) {
                        return Safecloud_Jets.callDrop(drop, 'Safecloud/drop/put', { chunks: chunks, options: {} })
                            .catch(function () { return { results: [] }; });
                    });
                    return Promise.all(putPromises).then(function (results) {
                        // Merge results — a chunk is "stored" if at least one Drop confirmed it
                        var merged = chunks.map(function (c, i) {
                            var stored = results.some(function (r) {
                                return r && r.results && r.results[i] && r.results[i].stored;
                            });
                            return { cid: c.cid, stored: stored };
                        });
                        ack && ack(null, { results: merged });
                    });
                });

            }).catch(function (err) {
                Q.log('Q.Safecloud.Jets._handleSubtreePut payment error: ' + err, 'Safecloud');
                ack && ack({ error: { code: 'PaymentRequired', message: String(err) } });
            });
        });

    }).catch(function (err) {
        Q.log('Q.Safecloud.Jets._handleSubtreePut: ' + err, 'Safecloud');
        ack && ack({ error: { code: 'InternalError', message: String(err) } });
    });
}

function _handleSubtreeGet(client, userId, payload, ack) {
    var grants      = payload.grants      || [];
    var payments    = payload.payments    || [];
    var rootCid     = payload.rootCid;
    var link        = payload.link        || ['track', 'data'];
    var publisherId = payload.publisherId || null;
    var streamName  = payload.streamName  || null;

    if (!rootCid) {
        return ack && ack({ error: { code: 'BadRequest', message: 'rootCid required' } });
    }

    // 1. Grant verification — build manifest stub from _cidIndex for accurate repIndex
    var _mStub = null;
    if (_cidIndex[rootCid]) {
        var _tn = _cidIndex[rootCid]['_treeN'];
        var _td = _cidIndex[rootCid]['_treeDepth'];
        var _dc = (_cidIndex[rootCid]['track/data'] || []).length;
        if (_tn || _td || _dc) {
            _mStub = { treeN: _tn || 2, treeDepth: _td || 1, chunkCount: _dc };
        }
    }
    Safecloud_Jets.verifySubtreeGrant(grants, rootCid, link, _mStub).then(function (grantResult) {
        if (!grantResult.ok) {
            return ack && ack({
                error: {
                    code:    'NotAuthorized',
                    message: grantResult.reason,
                    details: { unauthorized: grantResult.unauthorized, grantIssues: grantResult.grantIssues }
                }
            });
        }

        // 2. Streams read access
        Safecloud_Jets.verifyStreamAccess(userId, publisherId, streamName, 'content', function (err, allowed) {
            if (!allowed) {
                return ack && ack({
                    error: { code: 'NotAuthorized', message: 'Streams read access denied',
                             details: { unauthorized: [link] } }
                });
            }

            // 3. Payment pre-screen
            // Determine chunk count from the _cidIndex for this link
            // Resolve CIDs: the link may be a leaf path not directly indexed.
            // Look up the flat data track CIDs and slice by the link's chunk range.
            var linkKey     = link.join('/');
            var directCids  = (_cidIndex[rootCid] && _cidIndex[rootCid][linkKey]);
            var linkCids;
            if (directCids && directCids.length) {
                // Exact match (e.g. link = ["track","data"] stored directly)
                linkCids = directCids;
            } else {
                // Resolve leaf/subtree link via flat data track array + range calculation
                var flatCids = (_cidIndex[rootCid] && _cidIndex[rootCid]['track/data']) || [];
                if (flatCids.length && link[0] === 'track' && link[1] === 'data') {
                    // Compute which absolute chunk indices this link covers
                    var treeN_    = (_cidIndex[rootCid] && _cidIndex[rootCid]['_treeN']) || 2;
                    var dataLen   = flatCids.length;
                    var treeDepth_ = (_cidIndex[rootCid]['_treeDepth'])
                        || Math.max(1, Math.ceil(Math.log(Math.max(dataLen, 2)) / Math.log(treeN_)));
                    var range_    = _leafRangeStart(link, { treeN: treeN_, treeDepth: treeDepth_, chunkCount: dataLen });
                    var nodeSegsLen_ = link.length - 2; // segments below "track/data"
                    var rangeEnd_ = Math.min(range_ + Math.pow(treeN_, Math.max(0, treeDepth_ - nodeSegsLen_)), dataLen);
                    linkCids = flatCids.slice(range_, Math.max(range_ + 1, Math.ceil(rangeEnd_)));
                } else if (link[0] === 'track' && link[1] === 'index') {
                    linkCids = (_cidIndex[rootCid] && _cidIndex[rootCid]['track/index']) || [];
                } else {
                    linkCids = [];
                }
            }
            // If no CIDs found for this link path, the content hasn't been
            // uploaded to this Jet yet (or Jet restarted and lost _cidIndex)
            if (!linkCids.length && rootCid) {
                return ack && ack({ error: { code: 'NotFound',
                    message: 'No CIDs found for rootCid/link — content not indexed on this Jet' } });
            }
            var chunkCount = linkCids.length || 1;
            _checkPayments(payments, chunkCount).then(function (payOk) {
                if (!payOk) {
                    return ack && ack({ error: { code: 'PaymentRequired', message: 'Insufficient balance' } });
                }

                // 3b. Per-chunk price enforcement from manifest metadata.
                // Publisher set perChunkWei in track/meta chunk at upload time.
                // Jet cached it in _cidIndex during subtree/put of track/meta.
                // If Cloud's payment token max < perChunkWei × chunkCount → 402.
                var perChunkWei = _getManifestPrice(rootCid);
                var requiredWei = BigInt(perChunkWei) * BigInt(chunkCount);
                if (payments.length && requiredWei > BigInt(0)) {
                    var payerMax = payments.reduce(function (sum, p) {
                        if (!p || !p.stm) { return sum; }
                        return sum + BigInt(p.stm.max || '0');
                    }, BigInt(0));
                    if (payerMax < requiredWei) {
                        return ack && ack({
                            error: {
                                code:    'PaymentRequired',
                                message: 'Payment below publisher price',
                                details: {
                                    required:    String(requiredWei),
                                    provided:    String(payerMax),
                                    perChunkWei: perChunkWei,
                                    chunkCount:  chunkCount
                                }
                            }
                        });
                    }
                }

                // Pass publisherPrice into _fetchFromDrops for Drop routing + offer price
                payload._publisherPrice = perChunkWei;

                // 4. Fetch from Drops — look up CIDs by rootCid + link path
                var cids = linkCids;

                // 4+5. Fetch from local Drops, fall back to JetSwarm on miss,
                //       then attach Merkle proofs and ack.
                // Attach revenue metadata for creator royalty routing
                var _revenue = payload.revenue || null;
                if (_revenue) { payload._revenue = _revenue; }
                _handleSubtreeGet_step4(cids, payload, grants[0] || null, ack,
                    function _attachProofsAndAck(chunks) {
                        return Safecloud_Jets.buildMerkleProofs(rootCid, cids, link)
                            .then(function (proofs) {
                                var result = chunks.map(function (chunk, i) {
                                    if (!chunk) { return null; }
                                    return Q.extend({}, chunk, { proof: proofs[i] || null });
                                });
                                ack && ack(null, { chunks: result });
                            });
                    }
                );

            }).catch(function (err) {
                ack && ack({ error: { code: 'PaymentRequired', message: String(err) } });
            });
        });

    }).catch(function (err) {
        Q.log('Q.Safecloud.Jets._handleSubtreeGet: ' + err, 'Safecloud');
        ack && ack({ error: { code: 'InternalError', message: String(err) } });
    });
}


// ─────────────────────────────────────────────────────────────────────────────
// JetSwarm integration helpers
// ─────────────────────────────────────────────────────────────────────────────

function _initSwarm(options) {
    // ── 6a. Existing Router ───────────────────────────────────────────────────
    if (Q.Safecloud.Router && typeof Q.Safecloud.Router.init === 'function') {
        Q.Safecloud.Router.init(options).catch(function (err) {
            Q.log('Q.Safecloud.Router.init error: ' + err, 'Safecloud');
        });
    }

    // ── 6b. JetSwarm ─────────────────────────────────────────────────────────
    var swarmEnabled = Q.Config.get(['Safecloud', 'swarm', 'enabled'], true);
    if (!swarmEnabled) { return; }

    var seedHex   = Q.Config.get(['Safecloud', 'swarm', 'seed'], null);
    var seed      = seedHex ? Buffer.from(seedHex, 'hex') : null;
    if (!seed) {
        Q.log('Q.Safecloud.Jets: WARNING — no Safecloud.swarm.seed configured. '
            + 'Jet DHT identity will change on restart. Set Safecloud.swarm.seed '
            + 'to a persistent 32-byte hex string in local/app.json.', 'Safecloud');
    }

    var bootstrap = Q.Config.get(['Safecloud', 'swarm', 'bootstrap'], null);
    var networkId = Q.Config.get(['Safecloud', 'swarm', 'networkId'], 'safecloud:jet:v1');
    var secureIds = Q.Config.get(['Safecloud', 'swarm', 'secureIds'], false);

    JetSwarm.init({
        seed:        seed,
        networkId:   networkId,
        secureIds:   secureIds,
        bootstrap:   bootstrap || undefined,
        onChunkRequest: function (cids, grant) {
            return Safecloud_Jets.selectDrops(cids, { forGet: true }).then(function (drops) {
                if (!drops.length) { return cids.map(function () { return null; }); }
                return Promise.all(cids.map(function (cid) {
                    var drop = drops[0];
                    return Safecloud_Jets.callDrop(drop, 'Safecloud/drop/get', { cids: [cid] })
                        .then(function (res) {
                            return (res && res.chunks && res.chunks[0]) || null;
                        })
                        .catch(function () { return null; });
                }));
            });
        }
    }).then(function () {
        _refreshSwarmRanges();
        Q.log('Q.Safecloud.Jets: JetSwarm ready — ' + JSON.stringify(JetSwarm.stats()), 'Safecloud');
    }).catch(function (err) {
        Q.log('Q.Safecloud.Jets: JetSwarm init error: ' + err, 'Safecloud');
    });

    Safecloud_Jets.on('dropBloom',      function () { _refreshSwarmRanges(); });
    Safecloud_Jets.on('dropColdSync',   function () { _refreshSwarmRanges(); });
    Safecloud_Jets.on('dropDisconnect', function () { _refreshSwarmRanges(); });
}

function _refreshSwarmRanges() {
    var totalChunks = 0;
    Object.values(Safecloud_Jets.drops || {}).forEach(function (drop) {
        if (drop.used) { totalChunks += Math.ceil(drop.used / (256 * 1024)); }
    });
    JetSwarm.announceRanges(
        totalChunks > 0 ? [{ start: null, end: null, count: totalChunks }] : []
    );
}

function _handleSubtreeGet_step4(cids, payload, grant, ack, _attachProofsAndAck) {
    var swarmEnabled = Q.Config.get(['Safecloud', 'swarm', 'enabled'], true);

    Safecloud_Jets.selectDrops(cids, { forGet: true }).then(function (drops) {
        if (drops.length) {
            // Pass revenue through payload for royalty routing
            if (payload && payload._revenue) { payload.revenue = payload._revenue; }
            return _fetchFromDrops(drops, cids, payload).then(function (chunks) {
                if (!chunks) { return; }
                if (!chunks.every(function (ch) { return !ch; })) {
                    return _attachProofsAndAck(chunks);
                }
                if (!swarmEnabled) {
                    return ack && ack({ error: { code: 'ServiceUnavailable',
                        message: 'No Drops returned the requested chunks' } });
                }
                return _swarmFallback(cids, grant, ack, _attachProofsAndAck);
            });
        }

        if (!swarmEnabled) {
            return ack && ack({ error: { code: 'ServiceUnavailable',
                message: 'No Drops available to serve this content' } });
        }
        var stats = JetSwarm.stats();
        if (!stats.peerCount) {
            return ack && ack({ error: { code: 'ServiceUnavailable',
                message: 'No Drops available and no peer Jets connected' } });
        }
        return _swarmFallback(cids, grant, ack, _attachProofsAndAck);

    }).catch(function (err) {
        Q.log('Q.Safecloud.Jets._handleSubtreeGet fetch error: ' + err, 'Safecloud');
        ack && ack({ error: { code: 'InternalError', message: String(err) } });
    });
}

/**
 * Return the publisher-set perChunkWei for a rootCid.
 * @param {String} rootCid
 * @return {String}
 * @private
 */
function _getManifestPrice(rootCid) {
    if (!rootCid || !_cidIndex[rootCid]) {
        return Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT);
    }
    return _cidIndex[rootCid]['_perChunkWei']
        || Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT);
}

function _swarmFallback(cids, grant, ack, _attachProofsAndAck) {
    Q.log('Q.Safecloud.Jets: local miss on ' + cids.length + ' CIDs — trying JetSwarm', 'Safecloud');
    JetSwarm.fetchChunks(cids, grant).then(function (result) {
        var chunks = result.chunks;
        if (!chunks || chunks.every(function (ch) { return !ch; })) {
            return ack && ack({ error: { code: 'ServiceUnavailable',
                message: 'No local Drops or peer Jets could serve the requested chunks' } });
        }
        return _attachProofsAndAck(chunks);
    }).catch(function (err) {
        Q.log('Q.Safecloud.Jets: JetSwarm fallback error: ' + err, 'Safecloud');
        ack && ack({ error: { code: 'InternalError', message: String(err) } });
    });
}

function _handleClientDisconnect(client) {
    var dropId = _socketToDropId[client.id];
    delete _socketToDropId[client.id];
    if (!dropId || !Safecloud_Jets.drops[dropId]) { return; }

    var drop = Safecloud_Jets.drops[dropId];
    drop.offlineSince = Date.now();
    // Update reliability score for reconnect penalty (applied on re-registration)
    Safecloud_Jets.emit('dropOffline', drop);
    Q.log('Q.Safecloud.Jets: Drop offline: ' + dropId, 'Safecloud');
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP routes
// ─────────────────────────────────────────────────────────────────────────────

function _registerHttpRoutes(app) {
    // x402 single-chunk fetch for external clients
    app.get('/Safecloud/cloud/chunk/:cid', function (req, res) {
        _handleHttpChunkGet(req, res);
    });

    // Batch subtree fetch — link path encoded as query param: ?link=track/data/0/1
    app.get('/Safecloud/cloud/subtree/:rootCid', function (req, res) {
        _handleHttpSubtreeGet(req, res);
    });

    // Batch subtree upload
    app.put('/Safecloud/cloud/subtree', function (req, res) {
        _handleHttpSubtreePut(req, res);
    });

    // Jet-to-Jet relay
    app.get('/Safecloud/cloud/relay/:rootCid', function (req, res) {
        _handleHttpRelayGet(req, res);
    });
}

function _handleHttpChunkGet(req, res) {
    var cid = req.params.cid;
    var paymentSig = req.headers['payment-signature'];

    if (!paymentSig) {
        // x402 — return payment requirements
        var perChunkWei = Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT);
        var walletAddr  = Q.Config.get(['Safecloud', 'jet', 'address'], '0x0000000000000000000000000000000000000000');
        var safebuxAddr = Q.Config.get(['Safecloud', 'safebux', 'address'], '0x0000000000000000000000000000000000000000');
        var requirements = {
            scheme:            'exact',
            network:           SAFEBUX_CHAIN,
            maxAmountRequired: perChunkWei,
            resource:          'https://' + req.hostname + req.originalUrl,
            description:       'Safecloud chunk retrieval',
            mimeType:          'application/octet-stream',
            payTo:             walletAddr,
            token:             safebuxAddr,
            extra:             { name: 'Safecloud', version: '1' }
        };
        res.status(402)
           .set('PAYMENT-REQUIRED', Buffer.from(JSON.stringify(requirements)).toString('base64'))
           .set('Content-Type', 'application/json')
           .json({ error: { code: 'PaymentRequired', message: 'Payment required' } });
        return;
    }

    // Verify payment signature header
    var ocpEnvelope;
    try {
        ocpEnvelope = JSON.parse(Buffer.from(paymentSig, 'base64').toString('utf8'));
    } catch (e) {
        return res.status(402).json({ error: { code: 'PaymentRequired', message: 'Invalid PAYMENT-SIGNATURE' } });
    }

    var payment  = ocpEnvelope.stm || {};
    var chainId  = payment.chainId || SAFEBUX_CHAIN;
    var perChunk = Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT);

    // Verify EIP-712 payment signature before checking balance
    var sigPromise = (ocpEnvelope.sig && ocpEnvelope.sig.length &&
                      Q.Crypto && Q.Crypto.OpenClaim && Q.Crypto.OpenClaim.EVM)
        ? Q.Crypto.OpenClaim.EVM.verify(
            Object.assign({}, payment, {
                contract: payment.contract ||
                    Q.Config.get(['Users', 'web3', 'contracts', 'Safecloud/openclaiming',
                        _chainIdToHex(payment.chainId || SAFEBUX_CHAIN)], OC_ADDRESS)
            }),
            ocpEnvelope.sig[0],
            payment.payer
          ).catch(function () { return false; })
        : (ocpEnvelope.sig && ocpEnvelope.sig.length && typeof ethers !== 'undefined'
            ? (function () {
                // ethers-based EIP-712 fallback verification
                try {
                    var stm4     = ocpEnvelope.stm || {};
                    var chainN4  = typeof stm4.chainId === 'number'
                        ? stm4.chainId
                        : parseInt((stm4.chainId || SAFEBUX_CHAIN).replace('eip155:',''), 10);
                    var ocAddr4  = stm4.contract || OC_ADDRESS;
                    var domain4  = { name:'OpenClaiming', version:'1',
                                     chainId: chainN4, verifyingContract: ocAddr4 };
                    var types4   = { Payment: [
                        { name:'payer', type:'address' }, { name:'token', type:'address' },
                        { name:'max',   type:'uint256' }, { name:'line',  type:'uint256' },
                        { name:'nbf',   type:'uint256' }, { name:'exp',   type:'uint256' },
                        { name:'recipientsHash', type:'bytes32' },
                        { name:'contract', type:'address' }
                    ]};
                    var value4   = {
                        payer:          stm4.payer,
                        token:          stm4.token          || ethers.ZeroAddress,
                        max:            BigInt(stm4.max     || '0'),
                        line:           BigInt(stm4.line    || '0'),
                        nbf:            BigInt(stm4.nbf     || '0'),
                        exp:            BigInt(stm4.exp     || '0'),
                        recipientsHash: stm4.recipientsHash || ethers.ZeroHash,
                        contract:       ocAddr4
                    };
                    var sig4hex = ocpEnvelope.sig[0].signature || ocpEnvelope.sig[0];
                    var recovered4 = ethers.verifyTypedData(domain4, types4, value4, sig4hex);
                    return Promise.resolve(
                        recovered4.toLowerCase() === (stm4.payer || '').toLowerCase()
                    );
                } catch (e) { return Promise.resolve(false); }
              })()
            : Promise.resolve(!Q.Config.get(['Safecloud', 'requirePayment'], false)));

    sigPromise.then(function (sigOk) {
        if (!sigOk) {
            return res.status(402).json({ error: {
                code: 'PaymentRequired', message: 'Invalid payment signature'
            }});
        }
    return Safecloud_Jets._checkPayerBalance(
                payment.payer, payment.token, perChunk, chainId,
                payment.line || 0,
                String(payment.max || 0)
            )
        .then(function (ok) {
            if (!ok) {
                return res.status(402).json({ error: {
                    code: 'PaymentRequired', message: 'Insufficient balance',
                    details: { payer: payment.payer, required: perChunk }
                }});
            }
            // Fetch chunk from Drop
            var cid = req.params.cid;
            // Search _cidIndex for this CID across all rootCids and link paths
            var cidKnown = Object.values(_cidIndex).some(function(linkMap) {
                return typeof linkMap === 'object' && Object.values(linkMap).some(function(arr) {
                    return Array.isArray(arr) && arr.indexOf(cid) >= 0;
                });
            });
            if (!cidKnown) {
                return res.status(404).json({ error: { code: 'NotFound', message: 'CID not found' } });
            }
            return Safecloud_Jets.selectDrops([cid], { forGet: true }).then(function (drops) {
                if (!drops.length) {
                    return res.status(404).json({ error: { code: 'NotFound', message: 'No Drop has this CID' } });
                }
                return Safecloud_Jets.callDrop(drops[0], 'Safecloud/drop/get', {
                    cids: [cid], options: {}, paymentToken: ocpEnvelope
                }).then(function (result) {
                    var chunk = result && result.chunks && result.chunks[0];
                    if (!chunk) {
                        return res.status(404).json({ error: { code: 'NotFound', message: 'Chunk unavailable' } });
                    }
                    var ctBytes  = Buffer.from(chunk.ciphertext, 'base64');
                    var tagBytes = Buffer.from(chunk.tag, 'base64');
                    var body     = Buffer.concat([ctBytes, tagBytes]);

                    // Range request support (for Safari <video> probe)
                    var rangeHeader = req.headers['range'];
                    if (rangeHeader) {
                        var match = rangeHeader.match(/bytes=(\d*)-(\d*)/);
                        if (match) {
                            var rStart = match[1] !== '' ? parseInt(match[1]) : 0;
                            var rEnd   = match[2] !== '' ? parseInt(match[2]) : body.length - 1;
                            rEnd = Math.min(rEnd, body.length - 1);
                            res.status(206)
                               .set('Content-Range', 'bytes ' + rStart + '-' + rEnd + '/' + body.length)
                               .set('Content-Type', 'application/octet-stream')
                               .set('Cache-Control', 'public, max-age=31536000, immutable')
                               .send(body.slice(rStart, rEnd + 1));
                            return;
                        }
                    }
                    res.status(200)
                       .set('Content-Type', 'application/octet-stream')
                       .set('Cache-Control', 'public, max-age=31536000, immutable')
                       .send(body);
                });
            });
        }).catch(function (err) {
            res.status(500).json({ error: { code: 'InternalError', message: String(err) } });
        });
    }).catch(function (err) { // sigPromise
        res.status(500).json({ error: { code: 'InternalError', message: String(err) } });
    });
}

function _parseOcpParam(b64url) {
    if (!b64url) { return []; }
    try {
        var json = Buffer.from(b64url, 'base64').toString('utf8');
        var val  = JSON.parse(json);
        return Array.isArray(val) ? val : [val];
    } catch (e) { return []; }
}

function _handleHttpSubtreeGet(req, res) {
    var rootCid  = req.params.rootCid;
    // link is passed as ?link=track/data/0/1 (slash-separated path segments)
    var linkStr  = req.query.link || 'track/data';
    var link     = linkStr.split('/').filter(Boolean);
    var grants   = _parseOcpParam(req.query.g);
    var payments = _parseOcpParam(req.query.p);
    var streamRaw = req.query.s;
    var publisherId = null, streamName = null;
    if (streamRaw) {
        try {
            var sp = Buffer.from(streamRaw, 'base64').toString('utf8').split('\t');
            publisherId = sp[0]; streamName = sp[1];
        } catch(e) {}
    }
    var userId = null;

    _handleSubtreeGet(
        { capability: { userId: userId } },
        userId,
        { rootCid: rootCid, link: link, grants: grants, payments: payments,
          publisherId: publisherId, streamName: streamName },
        function (errOrResult, result) {
            if (errOrResult && errOrResult.error) {
                var code = errOrResult.error.code;
                var status = code === 'NotAuthorized' ? 403 : code === 'PaymentRequired' ? 402 : 500;
                return res.status(status).json(errOrResult);
            }
            var data = result || errOrResult;
            res.status(200)
               .set('Content-Type', 'application/json')
               .set('Cache-Control', 'public, max-age=31536000, immutable')
               .json(data);
        }
    );
}

function _handleHttpSubtreePut(req, res) {
    var body     = req.body || {};
    var userId   = null;
    _handleSubtreePut(
        { capability: { userId: userId } },
        userId,
        body,
        function (errOrResult, result) {
            if (errOrResult && errOrResult.error) {
                var code = errOrResult.error.code;
                var status = code === 'NotAuthorized' ? 403 : code === 'PaymentRequired' ? 402 : 500;
                return res.status(status).json(errOrResult);
            }
            res.status(200).json(result || errOrResult);
        }
    );
}

function _handleHttpRelayGet(req, res) {
    // Validated by Noise bearer token — handled in Phase 4 (Router integration)
    var authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: { code: 'Unauthorized', message: 'Bearer token required' } });
    }
    res.status(501).json({ error: { code: 'NotImplemented', message: 'Relay: Phase 4' } });
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Pre-screen all payment tokens in a request.  Returns true if all pass. */
function _checkPayments(payments, chunkCount) {
    if (!payments || !payments.length) {
        var requirePayment = Q.Config.get(['Safecloud', 'requirePayment'], false);
        return Promise.resolve(!requirePayment);
    }
    var perChunkWei = Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT);
    var totalWei    = BigInt(perChunkWei) * BigInt(chunkCount);
    var jetWallet   = Q.Config.get(['Safecloud', 'jet', 'address'], null);

    var checks = payments.map(function (p) {
        if (!p) { return Promise.resolve(false); }
        // Payment token is OCP envelope: { stm: {...}, sig: [...] }
        var stm = p.stm || p;
        var payer   = stm.payer;
        var token   = stm.token;
        var chainId = stm.chainId || SAFEBUX_CHAIN;
        if (!payer || !token) { return Promise.resolve(false); }

        // Safebux is the ONLY accepted payment token — reject all others.
        // Token address must be configured. If not yet deployed, reject all.
        var acceptedToken = Q.Config.get(['Safecloud', 'safebux', 'address'], null);
        if (!acceptedToken) {
            // Safebux not yet deployed — accept all if requirePayment:false
            var req = Q.Config.get(['Safecloud', 'requirePayment'], false);
            return Promise.resolve(!req);
        }
        if (token.toLowerCase() !== acceptedToken.toLowerCase()) {
            return Promise.resolve(false); // wrong token — only Safebux accepted
        }
        // Accept BSC + any chain where OpenClaiming is deployed
        var acceptedChains = Q.Config.get(['Safecloud', 'safebux', 'chains'],
            [SAFEBUX_CHAIN, 'eip155:1']); // BSC + Ethereum
        var chainMatch = Array.isArray(acceptedChains)
            ? acceptedChains.indexOf(chainId) >= 0
            : (chainId === acceptedChains);
        if (!chainMatch) {
            return Promise.resolve(false); // wrong chain
        }

        // Validate time bounds
        var nowSec = Math.floor(Date.now() / 1000);
        if (stm.nbf && BigInt(stm.nbf) > BigInt(nowSec)) { return Promise.resolve(false); }
        if (stm.exp && stm.exp > 0 && BigInt(stm.exp) < BigInt(nowSec)) { return Promise.resolve(false); }

        // Validate recipientsHash includes this Jet's address
        // keccak256(abi.encode([jetAddress])) must match stm.recipientsHash
        // If recipientsHash is all-zeros it means "open" — accepted for Phase 3
        var jetAddr = jetWallet ? jetWallet.toLowerCase().replace(/^0x/i,'') : null;
        if (jetAddr && stm.recipientsHash &&
            stm.recipientsHash !== '0x' + '00'.repeat(32)) {
            // Compute keccak256(abi.encode([jetAddress])) matching Solidity paymentsHashRecipients()
            // abi.encode(address[]) = offset(32) + length(32) + padded_address(32)
            try {
                var addrBytes  = Buffer.from(jetAddr.padStart(40, '0'), 'hex');
                var addrPadded = Buffer.concat([Buffer.alloc(12, 0), addrBytes]); // 32 bytes
                var abiEncoded = Buffer.concat([
                    Buffer.from('0000000000000000000000000000000000000000000000000000000000000020', 'hex'), // offset
                    Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex'), // length=1
                    addrPadded                                                                              // element
                ]);
                var keccakHex  = ethers.keccak256(abiEncoded).replace(/^0x/i,'').toLowerCase();
                var actualHash = stm.recipientsHash.replace(/^0x/i,'').toLowerCase();
                if (keccakHex !== actualHash) {
                    return Promise.resolve(false); // Jet not in recipients
                }
            } catch(e) { /* skip recipients check on error */ }
        }

        // 1. Verify the EIP-712 payment signature — proves payer authorized the payment
        var sigVerifyPromise;
        if (p.sig && p.sig.length && Q.Crypto && Q.Crypto.OpenClaim && Q.Crypto.OpenClaim.EVM) {
            var EVM = Q.Crypto.OpenClaim.EVM;
            var sig = p.sig[0];
            sigVerifyPromise = EVM.verify(
                Object.assign({}, stm, {
                    chainId:  stm.chainId,
                    contract: stm.contract ||
                        Q.Config.get(['Users', 'web3', 'contracts', 'Safecloud/openclaiming',
                            _chainIdToHex(stm.chainId || SAFEBUX_CHAIN)], OC_ADDRESS)
                }),
                sig,
                payer
            ).catch(function () { return false; });
        } else if (p.sig && p.sig.length && ethers && p.sig[0] && p.sig[0].signature) {
            // OCP module not loaded but ethers is available — verify EIP-712 sig directly
            // using ethers.verifyTypedData (equivalent to on-chain ecrecover)
            var sig0     = p.sig[0];
            var ocAddress2 = stm.contract ||
                Q.Config.get(['Users', 'web3', 'contracts', 'Safecloud/openclaiming',
                    _chainIdToHex(stm.chainId || SAFEBUX_CHAIN)], OC_ADDRESS);
            var chainIdNum2 = typeof stm.chainId === 'number'
                ? stm.chainId
                : parseInt((stm.chainId || SAFEBUX_CHAIN).replace('eip155:',''), 10);

            var domain2 = {
                name:              'OpenClaiming',
                version:           '1',
                chainId:           chainIdNum2,
                verifyingContract: ocAddress2
            };
            var types2 = {
                Payment: [
                    { name: 'payer',          type: 'address' },
                    { name: 'token',          type: 'address' },
                    { name: 'max',            type: 'uint256' },
                    { name: 'line',           type: 'uint256' },
                    { name: 'nbf',            type: 'uint256' },
                    { name: 'exp',            type: 'uint256' },
                    { name: 'recipientsHash', type: 'bytes32' },
                    { name: 'contract',       type: 'address' }
                ]
            };
            var value2 = {
                payer:          stm.payer,
                token:          stm.token          || ethers.ZeroAddress,
                max:            BigInt(stm.max      || '0'),
                line:           BigInt(stm.line     || '0'),
                nbf:            BigInt(stm.nbf      || '0'),
                exp:            BigInt(stm.exp      || '0'),
                recipientsHash: stm.recipientsHash || ethers.ZeroHash,
                contract:       ocAddress2
            };
            try {
                var recovered = ethers.verifyTypedData(domain2, types2, value2, sig0.signature);
                sigVerifyPromise = Promise.resolve(
                    recovered.toLowerCase() === payer.toLowerCase()
                );
            } catch (e) {
                sigVerifyPromise = Promise.resolve(false);
            }
        } else {
            // No sig at all — accept if requirePayment is false (open content)
            var requirePayment2 = Q.Config.get(['Safecloud', 'requirePayment'], false);
            sigVerifyPromise = Promise.resolve(!requirePayment2);
        }

        return sigVerifyPromise.then(function (sigOk) {
            if (!sigOk) { return false; }
            // 2. Check lineAvailable >= totalWei on the OpenClaiming contract.
            // lineAvailable(payer, line, claimMax) reflects line.max - line.spent,
            // which is the definitive pre-flight check — not balanceOf.
            return Safecloud_Jets._checkPayerBalance(
                payer, token, String(totalWei), chainId,
                stm.line || 0,      // OpenClaiming line id
                String(stm.max || 0) // payment token's max field
            );
        });
    });

    return Promise.all(checks).then(function (results) {
        return results.some(function (ok) { return ok; });
    });
}

/** Fetch chunks from an ordered list of drops, with fallback. */
function _fetchFromDrops(drops, cids, payload) {
    if (!cids.length) { return Promise.resolve([]); }

    var jetEVM      = Q.Config.get(['Safecloud', 'jet', 'address'], null);
        var safebuxAddr = Q.Config.get(['Safecloud', 'safebux', 'address'], null);
    var perChunk    = Q.Config.get(['Safecloud', 'safebux', 'perChunkWei'], PER_CHUNK_WEI_DEFAULT);

    // Build and sign a payment token for the Drop.
    // The Jet is the payer — it authorises payment from its Safebux balance.
    // The Drop is the payee — its EVM address goes into recipientsHash.
    // We sign per-Drop so each token's recipientsHash names exactly one recipient.
    // If no Jet wallet is configured, tokens are unsigned (Drop accepts if requirePayment:false).

    function tryDrop(index) {
        if (index >= drops.length) {
            return Promise.resolve(new Array(cids.length).fill(null));
        }
        var drop     = drops[index];
        var dropEVM  = drop.evmAddress || ethers.ZeroAddress;

        // Build unsigned stm first, then sign with Jet wallet (per-Drop recipientsHash)
        // Reliability-adjusted offer price for this Drop
        var offerPrice = _dropOfferPrice(drop, (payload && payload._publisherPrice) || perChunk);
        var stm = (jetEVM && safebuxAddr) ? {
            payer:    jetEVM,
            token:    safebuxAddr,
            max:      String(offerPrice * BigInt(cids.length)),
            line:     0,
            nbf:      0,
            exp:      Math.floor(Date.now() / 1000) + 3600, // 1-hour window
            chainId:  SAFEBUX_CHAIN.indexOf('eip155:') === 0
                          ? parseInt(SAFEBUX_CHAIN.slice(7), 10)
                          : SAFEBUX_CHAIN,
            contract: Q.Config.get(['Users', 'web3', 'contracts',
                          'Safecloud/openclaiming', _chainIdToHex(SAFEBUX_CHAIN)], OC_ADDRESS)
        } : null;

        var tokenPromise = stm
            ? _signPaymentToken(stm, dropEVM)
            : Promise.resolve(null);

        return tokenPromise.then(function (paymentToken) {
            return Safecloud_Jets.callDrop(drop, 'Safecloud/drop/get', {
                cids:         cids,
                options:      {},
                paymentToken: paymentToken
            });
        }).then(function (result) {
            if (result && result.chunks) {
                // ── Creator royalty ───────────────────────────────────────────
                // On successful serve, route creator + protocol shares to
                // IncomeContract (fire-and-forget, non-blocking).
                var revenue = payload && payload.revenue;
                if (revenue && revenue.incomeContract && jetEVM && safebuxAddr) {
                    _payCreatorRoyalty(
                        revenue, cids.length, perChunk,
                        jetEVM, safebuxAddr
                    ).catch(function (err) {
                        Q.log('Q.Safecloud.Jets: royalty payment error: ' + err, 'Safecloud');
                    });
                }
                return result.chunks;
            }
            return tryDrop(index + 1);
        }).catch(function () {
            return tryDrop(index + 1);
        });
    }

    return tryDrop(0);
}

/**
 * Pay creator royalty and protocol treasury share via IncomeContract.
 *
 * Called fire-and-forget after a successful Drop serve.
 * The Jet retains SPLIT_JET_BP of the per-chunk payment and routes:
 *   SPLIT_CREATOR_BP  → manifest.revenue.incomeContract (creator)
 *   SPLIT_PROTOCOL_BP → PROTOCOL_TREASURY
 *
 * Uses Safebux ERC-20 transfer (not OpenClaiming) since these are
 * outgoing distributions from the Jet's own balance.
 *
 * Revenue splits from manifest.revenue.split override defaults if present:
 *   { drop: 6000, jet: 2000, creator: 1500, protocol: 500 } (basis points)
 *
 * @param {Object} revenue        manifest.revenue { creatorAddress, incomeContract, split }
 * @param {Number} chunkCount     number of chunks served
 * @param {String} perChunkWei    Safebux wei per chunk (total, pre-split)
 * @param {String} jetEVM         Jet's EVM address (signer)
 * @param {String} safebuxAddr    Safebux ERC-20 contract address
 * @return {Promise<void>}
 * @private
 */
function _payCreatorRoyalty(revenue, chunkCount, perChunkWei, jetEVM, safebuxAddr) {
    var wallet = _getJetWallet();
    if (!wallet || typeof ethers === 'undefined') { return Promise.resolve(); }
    if (!revenue || !revenue.incomeContract) { return Promise.resolve(); }

    // Resolve split — manifest overrides defaults
    var split     = revenue.split || {};
    var creatorBP = typeof split.creator  === 'number' ? split.creator  : SPLIT_CREATOR_BP;
    var protoBP   = typeof split.protocol === 'number' ? split.protocol : SPLIT_PROTOCOL_BP;

    var totalWei    = BigInt(perChunkWei) * BigInt(chunkCount);
    var creatorWei  = totalWei * BigInt(creatorBP)  / BigInt(SPLIT_TOTAL_BP);
    var protocolWei = totalWei * BigInt(protoBP)    / BigInt(SPLIT_TOTAL_BP);

    if (creatorWei <= BigInt(0) && protocolWei <= BigInt(0)) { return Promise.resolve(); }

    // Determine chain + provider
    var chainId = Q.Config.get(['Safecloud', 'safebux', 'chainId'], SAFEBUX_CHAIN);
    var provider = Safecloud_Jets._evmProvider(chainId);
    if (!provider) { return Promise.resolve(); }

    var signer = wallet.connect(provider);

    // IncomeContract: distribute(address token, address[] recipients, uint256[] amounts)
    // or fallback to direct ERC-20 transfer if no incomeContract ABI
    var INCOME_ABI = [
        'function distribute(address token, address[] calldata recipients, uint256[] calldata amounts)'
    ];
    var ERC20_TRANSFER_ABI = [
        'function transfer(address to, uint256 amount) returns (bool)'
    ];

    var incomeAddr = revenue.incomeContract;
    var treasury   = PROTOCOL_TREASURY;

    // Build recipients list — skip zero addresses and zero amounts
    var recipients = [], amounts = [];
    if (creatorWei > BigInt(0) && revenue.creatorAddress
            && revenue.creatorAddress !== ethers.ZeroAddress) {
        recipients.push(incomeAddr); // route via IncomeContract for batching
        amounts.push(creatorWei);
    }
    if (protocolWei > BigInt(0) && treasury !== ethers.ZeroAddress) {
        recipients.push(treasury);
        amounts.push(protocolWei);
    }
    if (!recipients.length) { return Promise.resolve(); }

    // Try IncomeContract.distribute first (batches internally for creator)
    // Fall back to direct ERC-20 transfer per recipient
    var incomeContract = new ethers.Contract(incomeAddr, INCOME_ABI, signer);
    var sbux = new ethers.Contract(safebuxAddr, ERC20_TRANSFER_ABI, signer);

    return incomeContract.distribute(
        safebuxAddr,
        [revenue.creatorAddress],
        [creatorWei]
    ).then(function () {
        // Protocol treasury gets direct transfer
        if (protocolWei > BigInt(0) && treasury !== ethers.ZeroAddress) {
            return sbux.transfer(treasury, protocolWei);
        }
    }).catch(function () {
        // IncomeContract not available or reverted — fall back to direct transfers
        var transfers = [];
        if (creatorWei > BigInt(0) && revenue.creatorAddress) {
            transfers.push(sbux.transfer(revenue.creatorAddress, creatorWei));
        }
        if (protocolWei > BigInt(0) && treasury !== ethers.ZeroAddress) {
            transfers.push(sbux.transfer(treasury, protocolWei));
        }
        return Promise.all(transfers);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Q.Safecloud.Jets events (mirrors Users pattern)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Emitted when a new Drop connects and registers for the first time.
 * @event dropRegister
 * @param {Object} drop
 */

/**
 * Emitted when a known Drop reconnects (dropId seen before).
 * @event dropReconnect
 * @param {Object} drop
 */

/**
 * Emitted when a Drop sends a Safecloud/drop/announce message.
 * @event dropAnnounce
 * @param {Object} drop
 */

/**
 * Emitted when a Drop's socket disconnects (within grace period).
 * @event dropOffline
 * @param {Object} drop
 */

/**
 * Emitted when a Drop's grace period expires and it is evicted.
 * @event dropDisconnect
 * @param {Object} drop
 */

/**
 * Emitted after Prolly diff reconciliation when roots differ.
 * @event dropSync
 * @param {Object} drop
 * @param {Array}  changes  [{cid, added}]
 */

/**
 * Emitted when the Jet has no prior Prolly state for a Drop.
 * @event dropColdSync
 * @param {Object}      drop
 * @param {String|null} prollyRoot
 */

/**
 * Emitted when a Drop's Bloom filter is attached or updated.
 * @event dropBloom
 * @param {Object} drop
 * @param {Object} bloomFilter  deserialized filter
 */

/**
 * Emitted when the challenge failure threshold is reached for a Drop.
 * @event dropChallengeFail
 * @param {Object} drop
 * @param {String} cid
 */

/**
 * Emitted when PHP confirms a Drop has been slashed.
 * @event dropSlash
 * @param {Object} drop
 * @param {Object} payload  { reason }
 */
