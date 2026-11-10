'use strict';
/**
 * RightsManagement.js — Safecloud 4.0 rights management backend.
 *
 * Provides:
 *   • SQLite-backed root key persistence  (survives Jet restarts)
 *   • Creator authentication on registerRootKey  (Ed25519 sig over {rootCid, rootKey, ts})
 *   • Publisher registry  (POST /Safecloud/registerPublisher)
 *   • publisherAuth token verification  (Ed25519 offline verify)
 *   • Origin header gating at key issuance
 *   • Append-only grant chain  (GET/POST /Safecloud/chain/:rootCid)
 *   • Rate limiting per (publisherId, userId) using a sliding-window token bucket
 *
 * Design principles:
 *   • Drop-in upgrade over Jets.js _rootKeyStore — same get/set API surface
 *   • Uses Safecloud's own DB/ layer (no extra deps)
 *   • All errors carry statusCode so callers can res.status(err.statusCode)
 *   • Stateless across restarts except for the DB
 */

var crypto = require('crypto');
var path   = require('path');
var DB     = require('./DB/Database');
var JetKey = require('./JetKey');

// ─── Schema ───────────────────────────────────────────────────────────────────
// Three tables in one SQLite-compatible DB:
//
//   root_keys        — persisted root keys + access models
//   publishers       — registered publisher Ed25519 public keys + allowed origins
//   grant_chain      — append-only Merkle log of grant/accept/negotiate/revoke
//   rate_limit       — sliding-window token-bucket state per (publisher, userId)

var SCHEMA = [
    // ── author_certs (Safecloud 4.1) ─────────────────────────────────────────
    // Publisher certs issued by content authors (OCP claims signed with Ed25519).
    // Replaces self-registration: a publisher is trusted only when an author has
    // issued them a cert.  Revoked certs (active=0) are refused at key issuance.
    'CREATE TABLE IF NOT EXISTS author_certs (' +
        'id              INTEGER PRIMARY KEY AUTOINCREMENT,' +
        'author_pub_hex  TEXT NOT NULL,' +   // hex 32-byte Ed25519 pub key of issuing author
        'publisher_id    TEXT NOT NULL,' +   // e.g. "apps.acme.com"
        'root_cid        TEXT,' +            // NULL = all roots for this author
        'issued_at       INTEGER NOT NULL,' +
        'expires_at      INTEGER,' +         // NULL = no expiry
        'claim_json      TEXT NOT NULL,' +   // the full signed OCP claim JSON
        'active          INTEGER NOT NULL DEFAULT 1' + // 0 = revoked
    ')',

    'CREATE INDEX IF NOT EXISTS idx_author_certs_author ON author_certs(author_pub_hex)',
    'CREATE INDEX IF NOT EXISTS idx_author_certs_publisher ON author_certs(publisher_id, active)',

    'CREATE TABLE IF NOT EXISTS root_keys (' +
        'root_cid    TEXT PRIMARY KEY,' +
        'root_key    TEXT NOT NULL,' +           // base64(32 bytes)
        'access_model TEXT,' +                   // JSON
        'creator_id  TEXT,' +                    // userId who registered it
        'registered_at INTEGER NOT NULL' +       // Unix ms
    ')',

    'CREATE TABLE IF NOT EXISTS publishers (' +
        'publisher_id TEXT PRIMARY KEY,' +       // e.g. "apps.acme.com"
        'pub_key_hex  TEXT NOT NULL,' +          // hex 32-byte Ed25519 pub key
        'allowed_origins TEXT,' +               // JSON array of allowed Origin values
        'registered_at INTEGER NOT NULL' +
    ')',

    'CREATE TABLE IF NOT EXISTS grant_chain (' +
        'id          INTEGER PRIMARY KEY AUTOINCREMENT,' +
        'root_cid    TEXT NOT NULL,' +
        'entry_type  TEXT NOT NULL,' +           // grant | accept | negotiate | revoke
        'granter     TEXT NOT NULL,' +           // userId issuing the grant
        'grantee     TEXT NOT NULL,' +           // userId receiving it
        'terms       TEXT,' +                    // JSON (accessModel, expiry, reshare, etc.)
        'prev_hash   TEXT NOT NULL,' +           // sha256(previous entry for this rootCid), '' for genesis
        'sig         TEXT,' +                    // hex Ed25519 sig by Jet over (root_cid|id|entry_type|granter|grantee|terms|prev_hash)
        'created_at  INTEGER NOT NULL' +
    ')',

    'CREATE INDEX IF NOT EXISTS idx_grant_chain_root ON grant_chain(root_cid, id)',

    'CREATE TABLE IF NOT EXISTS rate_limit (' +
        'bucket_key  TEXT PRIMARY KEY,' +        // "publisherId:userId"
        'tokens      REAL NOT NULL,' +           // current bucket level
        'last_refill INTEGER NOT NULL' +         // Unix ms of last calculation
    ')',

    // Payment replay protection — record every used nonce until it expires.
    // exp mirrors the token's own exp field so entries self-expire.
    'CREATE TABLE IF NOT EXISTS used_nonces (' +
        'nonce       TEXT PRIMARY KEY,' +        // random token nonce
        'publisher   TEXT NOT NULL,' +           // publisherId that issued the token
        'exp         INTEGER NOT NULL' +         // Unix ms — matches token exp
    ')',

    'CREATE INDEX IF NOT EXISTS idx_used_nonces_exp ON used_nonces(exp)',

    // ── delegations (OCP Delegation Extension) ──────────────────────────────
    // Author-signed delegations granting a publisher (identified by domain)
    // access to the author's content, with optional rate limits, geo
    // restrictions, IP allowlists, and depth limits.
    'CREATE TABLE IF NOT EXISTS delegations (' +
        'id              INTEGER PRIMARY KEY AUTOINCREMENT,' +
        'author_pub_hex  TEXT NOT NULL,' +       // hex Ed25519 pub key of issuing author
        'domains_json    TEXT NOT NULL,' +        // JSON array of publisher domains
        'root_cid        TEXT,' +                 // NULL = all roots for this author
        'label           TEXT NOT NULL,' +        // scoping string
        'limits_json     TEXT,' +                 // JSON array of {quantity: N, per: "day"|...}
        'geo_json        TEXT,' +                 // JSON {includeCountries:[]} or {excludeCountries:[]}
        'allow_ips_json  TEXT,' +                 // JSON array of CIDR/wildcard/exact IPs
        'max_depth       INTEGER,' +              // NULL = unlimited
        'claim_json      TEXT NOT NULL,' +        // the full signed OCP delegation claim
        'issued_at       INTEGER NOT NULL,' +     // Unix seconds
        'expires_at      INTEGER,' +              // NULL = no expiry
        'revocable       INTEGER NOT NULL DEFAULT 1,' + // 0 = irrevocable until expires_at
        'active          INTEGER NOT NULL DEFAULT 1,' + // 0 = revoked
        'webhook_url     TEXT' +                  // publisher's webhook for revocation notices
    ')',

    'CREATE INDEX IF NOT EXISTS idx_delegations_author ON delegations(author_pub_hex)',
    'CREATE INDEX IF NOT EXISTS idx_delegations_active ON delegations(active, expires_at)',

    // Domain lookup index — maps domain strings to delegation IDs for fast
    // Origin-header resolution. One row per domain per delegation.
    'CREATE TABLE IF NOT EXISTS delegation_domains (' +
        'domain          TEXT NOT NULL,' +
        'delegation_id   INTEGER NOT NULL,' +
        'FOREIGN KEY (delegation_id) REFERENCES delegations(id)' +
    ')',

    'CREATE INDEX IF NOT EXISTS idx_deleg_domains ON delegation_domains(domain, delegation_id)',

    // Aggregate consumption tracking — one row per delegation per period per
    // quantity type. No per-viewer tracking; limits are global per delegation.
    'CREATE TABLE IF NOT EXISTS delegation_usage (' +
        'delegation_id   INTEGER NOT NULL,' +
        'period_key      TEXT NOT NULL,' +        // "2026-11" for month, "2026-11-08" for day, etc.
        'quantity        TEXT NOT NULL,' +         // "minutes", "videos", etc.
        'consumed        REAL NOT NULL DEFAULT 0,' +
        'PRIMARY KEY (delegation_id, period_key, quantity)' +
    ')',
];

// ─── Default config ───────────────────────────────────────────────────────────

var DEFAULTS = {
    // Rate limiting: 20 key requests per minute per (publisher, userId)
    rateLimitCapacity:   20,
    rateLimitRefillRate: 20 / 60000, // tokens per ms
    // publisherAuth tokens: max age 24h
    publisherAuthMaxAgeMs: 86400000,
};

// ─── RightsManagement ─────────────────────────────────────────────────────────

function RightsManagement(options) {
    options = options || {};
    this._cfg = Object.assign({}, DEFAULTS, options);
    this._db  = null;
    // In-memory LRU for hot root-key reads (avoids DB read on every chunk request)
    this._cache = Object.create(null); // rootCid → {key, accessModel}
    this._cacheSize = 0;
    this._cacheMax  = options.cacheMax || 5000;
}

/**
 * Open (or create) the rights database.
 * Must be called before any other method.
 *
 * @param {string} dbPath  Path to the DB directory (e.g. "local/rights.db")
 */
RightsManagement.prototype.open = function (dbPath) {
    if (this._db) return;
    this._db = new DB(dbPath);
    for (var i = 0; i < SCHEMA.length; i++) {
        this._db.exec(SCHEMA[i]);
    }
};

RightsManagement.prototype.close = function () {
    if (this._db) { this._db.close(); this._db = null; }
};

// ─── Root key persistence ─────────────────────────────────────────────────────

/**
 * Register a root key with optional creator auth.
 *
 * If `creatorAuth` is supplied it must be a JSON-parseable string:
 *   { userId, rootCid, rootKeyB64, ts, sig }
 * where sig is hex Ed25519 over SHA-256(`${userId}|${rootCid}|${rootKeyB64}|${ts}`)
 * signed by the client's Ed25519 key, and `creatorPubKeyHex` must be provided
 * in options (looked up from the caller's session).
 *
 * @param {object} opts
 *   rootCid {string}
 *   rootKey {Buffer}  32-byte key
 *   accessModel {object}
 *   creatorId  {string}  userId
 *   creatorAuth {string|null}  signed auth payload
 *   creatorPubKeyHex {string|null}  hex Ed25519 pub key of creator
 * @returns {boolean}  true if newly registered, false if already exists (idempotent)
 */
RightsManagement.prototype.registerRootKey = function (opts) {
    var rootCid     = opts.rootCid;
    var keyBuf      = opts.rootKey;
    var accessModel = opts.accessModel || null;
    var creatorId   = opts.creatorId   || null;
    var creatorAuth = opts.creatorAuth || null;
    var creatorPubKeyHex = opts.creatorPubKeyHex || null;

    // ── Creator auth (optional but enforced when pubKey is known) ─────────────
    if (creatorPubKeyHex) {
        if (!creatorAuth) {
            var e1 = new Error('registerRootKey: creatorAuth required when creator pub key is known');
            e1.statusCode = 403;
            throw e1;
        }
        var authObj;
        try { authObj = typeof creatorAuth === 'string' ? JSON.parse(creatorAuth) : creatorAuth; }
        catch (pe) {
            var e2 = new Error('registerRootKey: creatorAuth JSON parse failed');
            e2.statusCode = 400;
            throw e2;
        }
        // Validate timestamp freshness (5 minute window)
        var now = Date.now();
        if (!authObj.ts || Math.abs(now - authObj.ts) > 300000) {
            var e3 = new Error('registerRootKey: creatorAuth timestamp expired or missing');
            e3.statusCode = 401;
            throw e3;
        }
        // Verify signature
        var payload  = authObj.userId + '|' + authObj.rootCid + '|' + authObj.rootKeyB64 + '|' + authObj.ts;
        var hashBuf  = crypto.createHash('sha256').update(payload, 'utf8').digest();
        var valid    = JetKey.verify(hashBuf, authObj.sig, creatorPubKeyHex);
        if (!valid) {
            var e4 = new Error('registerRootKey: creatorAuth signature invalid');
            e4.statusCode = 403;
            throw e4;
        }
        // Ensure rootCid matches
        if (authObj.rootCid !== rootCid) {
            var e5 = new Error('registerRootKey: creatorAuth rootCid mismatch');
            e5.statusCode = 400;
            throw e5;
        }
    }

    // ── Persist ───────────────────────────────────────────────────────────────
    var existing = this._db.prepare(
        'SELECT root_cid FROM root_keys WHERE root_cid = ?'
    ).get(rootCid);
    if (existing) return false; // idempotent — already registered

    this._db.prepare(
        'INSERT INTO root_keys (root_cid, root_key, access_model, creator_id, registered_at) VALUES (?, ?, ?, ?, ?)'
    ).run(
        rootCid,
        keyBuf.toString('base64'),
        accessModel ? JSON.stringify(accessModel) : null,
        creatorId,
        Date.now()
    );

    // Update cache
    this._cacheSet(rootCid, { key: keyBuf, accessModel: accessModel });
    return true;
};

/**
 * Retrieve a root key record.
 * Returns { key: Buffer(32), accessModel: object|null } or null if not found.
 */
RightsManagement.prototype.getRootKey = function (rootCid) {
    var hit = this._cache[rootCid];
    if (hit) return hit;

    var row = this._db.prepare(
        'SELECT root_key, access_model FROM root_keys WHERE root_cid = ?'
    ).get(rootCid);
    if (!row) return null;

    var entry = {
        key:         Buffer.from(row.root_key, 'base64'),
        accessModel: row.access_model ? JSON.parse(row.access_model) : null,
    };
    this._cacheSet(rootCid, entry);
    return entry;
};

// LRU eviction by size (simple oldest-key eviction)
RightsManagement.prototype._cacheSet = function (key, val) {
    if (!this._cache[key]) {
        if (this._cacheSize >= this._cacheMax) {
            var evict = Object.keys(this._cache)[0];
            delete this._cache[evict];
            this._cacheSize--;
        }
        this._cacheSize++;
    }
    this._cache[key] = val;
};

// ─── Publisher registry ───────────────────────────────────────────────────────

/**
 * Register a publisher with its Ed25519 public key and allowed origins.
 *
 * The registration payload must be signed by the publisher's private key:
 *   sig over SHA-256(`${publisherId}|${pubKeyHex}|${ts}|${originsJson}`)
 *
 * @param {object} opts
 *   publisherId     {string}   e.g. "apps.acme.com"
 *   pubKeyHex       {string}   hex 32-byte Ed25519 pub key
 *   allowedOrigins  {string[]} e.g. ["https://acme.com", "https://app.acme.com"]
 *   ts              {number}   Unix ms of signature
 *   sig             {string}   hex Ed25519 sig by publisher
 */
RightsManagement.prototype.registerPublisher = function (opts) {
    var publisherId    = opts.publisherId;
    var pubKeyHex      = opts.pubKeyHex;
    var allowedOrigins = opts.allowedOrigins || [];
    var ts             = opts.ts;
    var sig            = opts.sig;

    if (!publisherId || !pubKeyHex || !sig || !ts) {
        var e = new Error('registerPublisher: publisherId, pubKeyHex, sig, ts required');
        e.statusCode = 400;
        throw e;
    }
    // Validate timestamp freshness (10 minute window for registration)
    if (Math.abs(Date.now() - ts) > 600000) {
        var e2 = new Error('registerPublisher: ts expired');
        e2.statusCode = 401;
        throw e2;
    }
    // Verify sig
    var originsJson = JSON.stringify(allowedOrigins);
    var payload     = publisherId + '|' + pubKeyHex + '|' + ts + '|' + originsJson;
    var hashBuf     = crypto.createHash('sha256').update(payload, 'utf8').digest();
    if (!JetKey.verify(hashBuf, sig, pubKeyHex)) {
        var e3 = new Error('registerPublisher: signature invalid');
        e3.statusCode = 403;
        throw e3;
    }

    // Upsert — check existence first (DB engine doesn't support INSERT OR REPLACE)
    var existing = this._db.prepare(
        'SELECT publisher_id FROM publishers WHERE publisher_id = ?'
    ).get(publisherId);
    if (existing) {
        // NOTE: DB engine binds WHERE params first, then SET params
        this._db.prepare(
            'UPDATE publishers SET pub_key_hex = ?, allowed_origins = ?, registered_at = ? WHERE publisher_id = ?'
        ).run(publisherId, pubKeyHex, originsJson, Date.now());
    } else {
        this._db.prepare(
            'INSERT INTO publishers (publisher_id, pub_key_hex, allowed_origins, registered_at) VALUES (?, ?, ?, ?)'
        ).run(publisherId, pubKeyHex, originsJson, Date.now());
    }

    return true;
};

/**
 * Look up a publisher record.
 * Returns { publisherId, pubKeyHex, allowedOrigins } or null.
 */
RightsManagement.prototype.getPublisher = function (publisherId) {
    var row = this._db.prepare(
        'SELECT pub_key_hex, allowed_origins FROM publishers WHERE publisher_id = ?'
    ).get(publisherId);
    if (!row) return null;
    return {
        publisherId:    publisherId,
        pubKeyHex:      row.pub_key_hex,
        allowedOrigins: row.allowed_origins ? JSON.parse(row.allowed_origins) : [],
    };
};

// ─── publisherAuth token verification ────────────────────────────────────────

/**
 * Verify a publisherAuth token submitted with a /Safecloud/key request.
 *
 * Token format: base64(JSON({ publisher, userId, rootCid, nbf, exp, nonce }))
 * The publisher's Ed25519 key must be in the publisher registry.
 *
 * Also enforces:
 *   • token not expired
 *   • rootCid matches the request
 *   • if `requestOrigin` is provided, it must be in publisher's allowedOrigins
 *
 * @param {string} tokenB64         base64-encoded token
 * @param {string} expectedRootCid  the rootCid being requested
 * @param {string} [requestOrigin]  value of Origin header from request
 * @returns {{ publisher, userId, rootCid, nonce }}
 */
RightsManagement.prototype.verifyPublisherAuth = function (tokenB64, expectedRootCid, requestOrigin) {
    var tokenJson;
    try { tokenJson = Buffer.from(tokenB64, 'base64').toString('utf8'); }
    catch (pe) {
        var e1 = new Error('publisherAuth: base64 decode failed');
        e1.statusCode = 400;
        throw e1;
    }

    var token;
    try { token = JSON.parse(tokenJson); }
    catch (je) {
        var e2 = new Error('publisherAuth: JSON parse failed');
        e2.statusCode = 400;
        throw e2;
    }

    var required = ['publisher', 'userId', 'rootCid', 'nbf', 'exp', 'nonce', 'sig'];
    for (var i = 0; i < required.length; i++) {
        if (token[required[i]] == null) {
            var e3 = new Error('publisherAuth: missing field ' + required[i]);
            e3.statusCode = 400;
            throw e3;
        }
    }

    // Time check
    var now = Date.now();
    if (now < token.nbf || now > token.exp) {
        var e4 = new Error('publisherAuth: token expired or not yet valid');
        e4.statusCode = 401;
        throw e4;
    }

    // rootCid check
    if (token.rootCid !== expectedRootCid) {
        var e5 = new Error('publisherAuth: rootCid mismatch');
        e5.statusCode = 403;
        throw e5;
    }

    // Look up publisher
    var pub = this.getPublisher(token.publisher);
    if (!pub) {
        var e6 = new Error('publisherAuth: unknown publisher ' + token.publisher);
        e6.statusCode = 403;
        throw e6;
    }

    // Origin check
    if (requestOrigin && pub.allowedOrigins.length > 0) {
        if (pub.allowedOrigins.indexOf(requestOrigin) === -1) {
            var e7 = new Error('publisherAuth: origin ' + requestOrigin + ' not allowed for publisher ' + token.publisher);
            e7.statusCode = 403;
            throw e7;
        }
    }

    // Verify Ed25519 sig over token body (everything except sig itself)
    var sigValue = token.sig;
    var body     = { publisher: token.publisher, userId: token.userId, rootCid: token.rootCid,
                     nbf: token.nbf, exp: token.exp, nonce: token.nonce };
    var bodyStr  = JSON.stringify(body);
    var hashBuf  = crypto.createHash('sha256').update(bodyStr, 'utf8').digest();
    if (!JetKey.verify(hashBuf, sigValue, pub.pubKeyHex)) {
        var e8 = new Error('publisherAuth: signature invalid');
        e8.statusCode = 403;
        throw e8;
    }

    // ── Payment replay protection ─────────────────────────────────────────────
    // Periodically clean expired nonces, then reject any nonce seen before.
    this._cleanupNonces();
    var usedNonce = this._db.prepare('SELECT nonce FROM used_nonces WHERE nonce = ?').get(token.nonce);
    if (usedNonce) {
        var e9 = new Error('publisherAuth: nonce already used (replay detected)');
        e9.statusCode = 409;
        throw e9;
    }
    this._db.prepare(
        'INSERT INTO used_nonces (nonce, publisher, exp) VALUES (?, ?, ?)'
    ).run(token.nonce, token.publisher, token.exp);

    return { publisher: token.publisher, userId: token.userId,
             rootCid: token.rootCid, nonce: token.nonce };
};

// ─── Nonce cleanup ────────────────────────────────────────────────────────────

/**
 * Delete expired nonces from the used_nonces table.
 * Called automatically from verifyPublisherAuth (at most once per minute).
 */
RightsManagement.prototype._cleanupNonces = function () {
    var now = Date.now();
    if (!this._lastNonceCleanup || now - this._lastNonceCleanup > 60000) {
        this._db.prepare('DELETE FROM used_nonces WHERE exp < ?').run(now);
        this._lastNonceCleanup = now;
    }
};

// ─── Admin list / delete helpers (used by ControlPanel) ──────────────────────

/**
 * List registered root key records (no key material returned).
 * @param {object} [opts]  { limit?, offset? }
 * @returns {object[]}
 */
RightsManagement.prototype.listRoots = function (opts) {
    opts = opts || {};
    var limit  = Math.min(opts.limit  || 100, 1000);
    var offset = opts.offset || 0;
    var rows = this._db.prepare(
        'SELECT root_cid, access_model, creator_id, registered_at' +
        ' FROM root_keys ORDER BY registered_at DESC LIMIT ? OFFSET ?'
    ).all(limit, offset);
    return rows.map(function (r) {
        return {
            rootCid:      r.root_cid,
            accessModel:  r.access_model ? JSON.parse(r.access_model) : null,
            creatorId:    r.creator_id,
            registeredAt: r.registered_at,
        };
    });
};

/**
 * List registered publishers.
 * @param {object} [opts]  { limit?, offset? }
 * @returns {object[]}
 */
RightsManagement.prototype.listPublishers = function (opts) {
    opts = opts || {};
    var limit  = Math.min(opts.limit  || 100, 1000);
    var offset = opts.offset || 0;
    var rows = this._db.prepare(
        'SELECT publisher_id, pub_key_hex, allowed_origins, registered_at' +
        ' FROM publishers ORDER BY registered_at DESC LIMIT ? OFFSET ?'
    ).all(limit, offset);
    return rows.map(function (r) {
        return {
            publisherId:    r.publisher_id,
            pubKeyHex:      r.pub_key_hex,
            allowedOrigins: r.allowed_origins ? JSON.parse(r.allowed_origins) : [],
            registeredAt:   r.registered_at,
        };
    });
};

/**
 * Remove a publisher from the registry.
 * @param {string} publisherId
 * @returns {boolean}  true if a row was deleted
 */
RightsManagement.prototype.deregisterPublisher = function (publisherId) {
    var res = this._db.prepare('DELETE FROM publishers WHERE publisher_id = ?').run(publisherId);
    return res.changes > 0;
};

/**
 * List rate-limit bucket states.
 * @param {object} [opts]  { limit?, offset? }
 * @returns {object[]}
 */
RightsManagement.prototype.listRateLimits = function (opts) {
    opts = opts || {};
    var limit  = Math.min(opts.limit  || 200, 1000);
    var offset = opts.offset || 0;
    var rows = this._db.prepare(
        'SELECT bucket_key, tokens, last_refill' +
        ' FROM rate_limit ORDER BY last_refill DESC LIMIT ? OFFSET ?'
    ).all(limit, offset);
    return rows.map(function (r) {
        return {
            bucketKey:  r.bucket_key,
            tokens:     r.tokens,
            lastRefill: r.last_refill,
        };
    });
};

/**
 * Reset a rate-limit bucket (removes the row; next request starts fresh).
 * @param {string} bucketKey  "publisherId:userId"
 * @returns {boolean}
 */
RightsManagement.prototype.resetRateLimit = function (bucketKey) {
    var res = this._db.prepare('DELETE FROM rate_limit WHERE bucket_key = ?').run(bucketKey);
    return res.changes > 0;
};

/**
 * List recently recorded nonces.
 * @param {object} [opts]  { limit?, offset? }
 * @returns {object[]}
 */
RightsManagement.prototype.listUsedNonces = function (opts) {
    opts = opts || {};
    var limit  = Math.min(opts.limit  || 100, 1000);
    var offset = opts.offset || 0;
    var now    = Date.now();
    var rows = this._db.prepare(
        'SELECT nonce, publisher, exp FROM used_nonces WHERE exp >= ?' +
        ' ORDER BY exp DESC LIMIT ? OFFSET ?'
    ).all(now, limit, offset);
    return rows.map(function (r) {
        return { nonce: r.nonce, publisher: r.publisher, exp: r.exp };
    });
};

// ─── Grant chain ──────────────────────────────────────────────────────────────

/**
 * Append a grant chain entry for a rootCid.
 *
 * @param {object} opts
 *   rootCid    {string}
 *   entryType  {string}  'grant' | 'accept' | 'negotiate' | 'revoke'
 *   granter    {string}  userId
 *   grantee    {string}  userId
 *   terms      {object|null}
 * @returns {object}  the new entry (with id, prevHash, sig)
 */
RightsManagement.prototype.appendGrantEntry = function (opts) {
    var rootCid   = opts.rootCid;
    var entryType = opts.entryType;
    var granter   = opts.granter;
    var grantee   = opts.grantee;
    var terms     = opts.terms || null;

    var VALID_TYPES = { grant: 1, accept: 1, negotiate: 1, revoke: 1 };
    if (!VALID_TYPES[entryType]) {
        var e = new Error('grant chain: invalid entryType ' + entryType);
        e.statusCode = 400;
        throw e;
    }

    // Get the prev_hash (SHA-256 of the sig payload of the last entry for this rootCid)
    var last = this._db.prepare(
        'SELECT id, sig FROM grant_chain WHERE root_cid = ? ORDER BY id DESC LIMIT 1'
    ).get(rootCid);
    var prevHash = last ? crypto.createHash('sha256').update(last.sig || '', 'utf8').digest('hex') : '';

    var termsJson  = terms ? JSON.stringify(terms) : null;
    var now        = Date.now();

    // We need the id before signing — use a transaction to get it atomically
    var self = this;
    var newId;
    var txn = this._db.transaction(function () {
        var ins = self._db.prepare(
            'INSERT INTO grant_chain (root_cid, entry_type, granter, grantee, terms, prev_hash, sig, created_at)' +
            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        ).run(rootCid, entryType, granter, grantee, termsJson, prevHash, '', now);
        newId = ins.lastInsertRowid;

        // Sign the entry with the Jet key
        var sigPayload = [rootCid, newId, entryType, granter, grantee, termsJson || '', prevHash].join('|');
        var sig        = JetKey.sign(sigPayload);

        // NOTE: DB engine binds WHERE params first, then SET params
        self._db.prepare('UPDATE grant_chain SET sig = ? WHERE id = ?').run(newId, sig);
        return sig;
    });
    var sig = txn();

    return { id: newId, rootCid: rootCid, entryType: entryType,
             granter: granter, grantee: grantee, terms: terms,
             prevHash: prevHash, sig: sig, createdAt: now };
};

/**
 * Read grant chain entries for a rootCid.
 *
 * @param {string} rootCid
 * @param {object} [opts]  { afterId?, limit? }
 * @returns {object[]}
 */
RightsManagement.prototype.getGrantChain = function (rootCid, opts) {
    opts = opts || {};
    var afterId = opts.afterId || 0;
    var limit   = Math.min(opts.limit || 100, 1000);

    var rows = this._db.prepare(
        'SELECT id, entry_type, granter, grantee, terms, prev_hash, sig, created_at' +
        ' FROM grant_chain WHERE root_cid = ? AND id > ? ORDER BY id ASC LIMIT ?'
    ).all(rootCid, afterId, limit);

    return rows.map(function (r) {
        return {
            id:        r.id,
            rootCid:   rootCid,
            entryType: r.entry_type,
            granter:   r.granter,
            grantee:   r.grantee,
            terms:     r.terms ? JSON.parse(r.terms) : null,
            prevHash:  r.prev_hash,
            sig:       r.sig,
            createdAt: r.created_at,
        };
    });
};

// ─── Rate limiting ────────────────────────────────────────────────────────────

/**
 * Sliding-window token bucket rate limiter.
 * Returns true if the request is allowed, false if rate-limited.
 *
 * @param {string} publisherId
 * @param {string} userId
 * @returns {boolean}
 */
RightsManagement.prototype.checkRateLimit = function (publisherId, userId) {
    var key      = publisherId + ':' + userId;
    var cap      = this._cfg.rateLimitCapacity;
    var refill   = this._cfg.rateLimitRefillRate; // tokens per ms
    var now      = Date.now();

    var row = this._db.prepare('SELECT tokens, last_refill FROM rate_limit WHERE bucket_key = ?').get(key);
    var tokens, lastRefill;
    if (row) {
        var elapsed = now - row.last_refill;
        tokens      = Math.min(cap, row.tokens + elapsed * refill);
        lastRefill  = now;
    } else {
        tokens     = cap - 1; // first request consumes one token
        lastRefill = now;
        this._db.prepare('INSERT INTO rate_limit (bucket_key, tokens, last_refill) VALUES (?, ?, ?)').run(key, tokens, lastRefill);
        return true;
    }

    if (tokens < 1) {
        // Persist current state without decrementing
        // NOTE: DB engine binds WHERE params first, then SET params
        this._db.prepare('UPDATE rate_limit SET tokens = ?, last_refill = ? WHERE bucket_key = ?').run(key, tokens, now);
        return false;
    }
    // Consume one token
    // NOTE: DB engine binds WHERE params first, then SET params
    this._db.prepare('UPDATE rate_limit SET tokens = ?, last_refill = ? WHERE bucket_key = ?').run(key, tokens - 1, now);
    return true;
};

// ─── Express route registration ───────────────────────────────────────────────

/**
 * Register 4.0+ rights management routes on an Express app.
 *
 * Routes added:
 *   POST /Safecloud/registerPublisher  — DEPRECATED (4.1); returns 410 Gone
 *   GET  /Safecloud/chain/:rootCid
 *   POST /Safecloud/chain/:rootCid
 *
 * As of Safecloud 4.1 the self-registration flow is replaced by the author
 * cert model: publishers become trusted when a content author issues them an
 * OCP publisher cert via POST /Safecloud/author/panel/api/cert.
 *
 * @param {object} app  Express app
 * @param {RightsManagement} rm
 */
RightsManagement.registerRoutes = function (app, rm) {
    // ── POST /Safecloud/registerPublisher ─────────────────────────────────────
    // DEPRECATED in Safecloud 4.1 — self-registration is replaced by author certs.
    // Publishers must now obtain a signed cert from the content author via the
    // AuthorPanel (/Safecloud/author/panel) and present it at key-issuance time.
    app.post('/Safecloud/registerPublisher', function (req, res) {
        res.status(410).json({
            error: {
                code:    'SelfRegistrationDeprecated',
                message: 'Self-registration is no longer accepted (Safecloud 4.1). ' +
                         'Publishers must obtain an author-signed cert via the author panel ' +
                         'at /Safecloud/author/panel and present it at key-issuance time.',
            },
        });
    });

    // ── GET /Safecloud/chain/:rootCid ─────────────────────────────────────────
    app.get('/Safecloud/chain/:rootCid', function (req, res) {
        try {
            var afterId = parseInt(req.query.afterId) || 0;
            var limit   = parseInt(req.query.limit)   || 100;
            var entries = rm.getGrantChain(req.params.rootCid, { afterId: afterId, limit: limit });
            res.json({ entries: entries });
        } catch (err) {
            res.status(err.statusCode || 500).json({ error: { code: 'ChainError', message: err.message } });
        }
    });

    // ── POST /Safecloud/chain/:rootCid ────────────────────────────────────────
    // Append a grant chain entry.  Caller must be authenticated (checked by Jets).
    app.post('/Safecloud/chain/:rootCid', function (req, res) {
        var body = req.body || {};
        try {
            var entry = rm.appendGrantEntry({
                rootCid:   req.params.rootCid,
                entryType: body.entryType,
                granter:   body.granter,
                grantee:   body.grantee,
                terms:     body.terms || null,
            });
            res.json({ entry: entry });
        } catch (err) {
            res.status(err.statusCode || 400).json({ error: { code: 'ChainError', message: err.message } });
        }
    });
};

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = RightsManagement;
