/**
 * Q.Safecloud.Drops — shared internal helpers (_).
 *
 * Uses Q.IndexedDB.open (platform wrapper) instead of raw indexedDB.open.
 * Uses Q.Data.canonicalize for RFC 8785 canonical JSON.
 * Uses Q.Crypto.OpenClaim.canonicalize when canonicalising OCP claim objects
 * (strips sig field before hashing, per the OCP spec).
 *
 * Shared state is on _._state and survives across method file invocations
 * because this module is loaded once.
 */

Q.exports(function () {

    var _ = {};

    // ─────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────

    _.DB_NAME  = 'Q.Safecloud.Drops';
    _.STORES   = {
        chunks: 'chunks',
        lru:    'lru',
        log:    'log',
        tokens: 'tokens',
        meta:   'meta'    // key-value store for Drop config (e.g. WebAuthn credential ID)
    };

    // ─────────────────────────────────────────────────────────────────────
    // Shared in-memory state
    // ─────────────────────────────────────────────────────────────────────

    _._state = {
        prollyRoot:   null,   // String|null — current Prolly root
        prevRoot:     null,   // String|null — root before last batch
        pendingDiff:  null,   // Array|null  — diff for next announce
        prollyStore:  null,   // { get, put } — in-memory Prolly node store
        bloomFilter:  null,   // deserialized Bloom filter object
        dropId:       null,   // String
        sessionKey:   null,   // CryptoKey (P-256 private, non-extractable)
        sessionKeyPub: null,  // base64 P-256 SPKI public key
        evmAddress:   null,   // String — BSC EVM address
        evmPrivateKey: null,  // String — hex-encoded secp256k1 private key
        usedBytes:    0,      // Number — bytes currently stored
        balanceCache: {},     // evmAddress → { balance: BigInt, cachedAt: Number }
        _dbPromise:   null,   // cached IDBDatabase promise
        servedBytes:   0,     // total bytes served via GET
        servedChunks:  0,     // total chunks served via GET
        storedChunks:  0,     // total chunks written via PUT
        safebuxEarned: 0,     // SBUX at Safecloud.drop.sbuxPerMB per MB served
        challenges:    0,     // proof-of-storage challenges answered
        activity:      [],    // ring buffer of recent events (dashboards)
        _initTime:     null   // set to Date.now() in init()
    };

    /**
     * Record a dashboard activity event. Ring buffer capped at 50.
     * @param {String} kind  'put' | 'get' | 'challenge' | 'claim' | 'announce' | ...
     * @param {Object} [data]
     */
    _.logActivity = function (kind, data) {
        var a = _._state.activity;
        a.push(Q.extend({ t: Date.now(), kind: kind }, data || {}));
        if (a.length > 50) { a.splice(0, a.length - 50); }
    };

    /**
     * Jet-published info first (Q.Safecloud.Jets.info), Q.Config fallback.
     */
    _.jetInfo = function (infoPath, configPath, def) {
        var v = Q.getObject(infoPath, Q.Safecloud.Jets && Q.Safecloud.Jets.info);
        if (v !== undefined && v !== null) { return v; }
        if (configPath && Q.Config && Q.Config.get) {
            return Q.Config.get(configPath, def);
        }
        return def;
    };

    // Lazily initialised in-memory Prolly store
    function _getProllyStore() {
        if (!_._state.prollyStore) {
            var nodes = {};
            _._state.prollyStore = {
                get: function (h) { return Promise.resolve(nodes[h] || null); },
                put: function (h, n) { nodes[h] = n; return Promise.resolve(); }
            };
        }
        return _._state.prollyStore;
    }
    // Exposed so Drops/init.js's full-log replay can share the same
    // in-memory node store instead of duplicating this lazy-init logic.
    _.getProllyStore = _getProllyStore;

    // ─────────────────────────────────────────────────────────────────────
    // 2. nowSec
    // ─────────────────────────────────────────────────────────────────────

    _.nowSec = function () { return Math.floor(Date.now() / 1000); };

    // ─────────────────────────────────────────────────────────────────────
    // 3. canonicalJSON — RFC 8785 / JCS via Q.Data.canonicalize
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Produce a canonical JSON string per RFC 8785.
     * Delegates to Q.Data.canonicalize (inline RFC 8785 implementation,
     * byte-identical to PHP Q_Data::canonicalize).
     *
     * For OCP claim objects (which have a sig field), callers should use
     * Q.Crypto.OpenClaim.canonicalize(claim) instead — it strips sig first.
     * _.canonicalJSON is for non-OCP objects (announce entries, token hashes).
     *
     * Always returns a Promise, even though Q.Data.canonicalize's own
     * implementation is synchronous once loaded — Q.Method's lazy-load shim
     * returns a plain Promise instead of the real string on a method's very
     * first call in a page's lifetime (before its script has been fetched),
     * and every caller here used to assume a synchronous string back. On a
     * cold Drop (its very first Q.Data.* call ever, right after registering,
     * before any upload has "warmed" Q.Data), that Promise got passed
     * straight into TextEncoder().encode(...), which stringifies non-string
     * input via .toString() — silently signing the literal text
     * "[object Promise]" instead of the real payload, so the server's
     * signature check always failed with "Invalid announce signature".
     * Wrapping in Promise.resolve() makes both the already-loaded (string)
     * and not-yet-loaded (Promise) cases resolve correctly either way.
     */
    _.canonicalJSON = function (obj) {
        return Promise.resolve(Q.Data.canonicalize(obj));
    };

    // ─────────────────────────────────────────────────────────────────────
    // 4. cidFromData — SHA-256(ciphertext || tag) → CIDv1
    // ─────────────────────────────────────────────────────────────────────

    /** RFC 4648 base32 lowercase, no padding. */
    _._base32 = function (bytes) {
        var alpha = 'abcdefghijklmnopqrstuvwxyz234567';
        var out = '', bits = 0, val = 0;
        for (var i = 0; i < bytes.length; i++) {
            val = (val << 8) | bytes[i]; bits += 8;
            while (bits >= 5) { bits -= 5; out += alpha[(val >>> bits) & 0x1f]; }
        }
        if (bits > 0) { out += alpha[(val << (5 - bits)) & 0x1f]; }
        return out;
    };

    /**
     * CIDv1 for a raw (ciphertext || tag) ArrayBuffer.
     * Must be byte-identical to Cloud._internal.chunkCid.
     */
    _.cidFromData = function (buffer) {
        return Q.Data.digest('SHA-256', buffer).then(function (digest) {
            var header = new Uint8Array([0x01, 0x55, 0x12, 0x20]);
            var full   = new Uint8Array(header.length + digest.length);
            full.set(header, 0);
            full.set(digest, header.length);
            return 'b' + _._base32(full);
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 5–7. Key helpers (pure pass-throughs in v1)
    // ─────────────────────────────────────────────────────────────────────

    _.chunkKey        = function (cid) { return cid; };
    _.lruKey          = function (cid) { return cid; };
    _.balanceCacheKey = function (addr) { return (addr || '').toLowerCase(); };

    // ─────────────────────────────────────────────────────────────────────
    // 8. openDB — uses Q.IndexedDB.open platform wrapper
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Open (or reuse) each object store via Q.IndexedDB.open.
     * Returns Promise<{ chunks, lru, log, tokens }> — one IDBDatabase per store
     * (Q.IndexedDB.open is per storeName).
     *
     * We use a single underlying database; Q.IndexedDB.open handles version
     * upgrades and connection reuse automatically.
     */
    _.openDB = function () {
        if (_._state._dbPromise) { return _._state._dbPromise; }

        // Open each store through the platform wrapper.
        // All four share the same dbName so they land in the same IDB database.
        var stores = [
            { name: _.STORES.chunks, params: {
                keyPath: 'cid'
            }},
            { name: _.STORES.lru, params: {
                keyPath: 'cid',
                indexes: [['lastAccessed', 'lastAccessed', { unique: false }]]
            }},
            { name: _.STORES.log, params: {
                keyPath:       'seq',
                autoIncrement: true,
                indexes:       [['seq', 'seq', { unique: true }]]
            }},
            { name: _.STORES.tokens, params: {
                keyPath: 'tokenHash',
                indexes: [['redeemed', 'redeemed', { unique: false }]]
            }},
            { name: _.STORES.meta, params: {
                keyPath: 'key'       // simple key-value: { key, value }
            }}
        ];

        // Open stores ONE AT A TIME, not in parallel. Q.IndexedDB.open's
        // "store missing -> close -> reopen at version+1" bootstrap runs as
        // an independent, uncached sequence per storeName (different names
        // are different Q.getter cache keys even though they share dbName).
        // Firing all 5 at once means 5 concurrent connections to the same
        // physical database each independently closing/reopening it —
        // exactly the recipe for "InvalidStateError: The database
        // connection is closing" on one store while another is mid-bump.
        // Sequential opens let each version bump fully settle before the
        // next store's Q.IndexedDB.open call ever opens a connection.
        var lastDb = null;
        var chain = stores.reduce(function (prev, s) {
            return prev.then(function () {
                return new Promise(function (resolve, reject) {
                    Q.IndexedDB.open(_.DB_NAME, s.name, s.params, function (err, db) {
                        if (err) { reject(err); } else { lastDb = db; resolve(db); }
                    });
                });
            });
        }, Promise.resolve());

        _._state._dbPromise = chain.then(function () {
            return lastDb;
        }).catch(function (err) {
            _._state._dbPromise = null; // allow retry
            throw err;
        });

        return _._state._dbPromise;
    };

    // ─────────────────────────────────────────────────────────────────────
    // 9. applyDiff — update Prolly root incrementally
    // ─────────────────────────────────────────────────────────────────────

    _.applyDiff = function (root, diff) {
        if (!diff || !diff.length) { return Promise.resolve(root); }
        var Prolly = Q.Data && Q.Data.Prolly;
        if (!Prolly) { return Promise.resolve(root); }
        var store = _getProllyStore();

        // Prolly.set/.delete do real synchronous hashing work per CID
        // (nodeHash/buildLeaves/digest, building/updating a Merkle tree) —
        // chaining many of these via plain .then() never yields to the
        // browser's paint/input loop, since promise callbacks run as
        // microtasks that drain before rendering gets a turn. A Drop with
        // a large accumulated diff log (this runs once per log entry during
        // Drops.init()'s full-log replay) can freeze the tab for many
        // seconds as a result. Yield back to the event loop periodically —
        // time-boxed rather than every iteration, so small diffs aren't
        // slowed down by yield overhead — to keep the tab responsive.
        var lastYield = Date.now();
        function maybeYield(value) {
            var now = Date.now();
            if (now - lastYield < 16) { return value; }
            lastYield = now;
            return new Promise(function (resolve) {
                setTimeout(function () { resolve(value); }, 0);
            });
        }

        return diff.reduce(function (prev, entry) {
            return prev.then(function (cur) {
                var next = entry.added
                    ? Prolly.set(cur, entry.cid, entry.cid, store)
                    : Prolly.delete(cur, entry.cid, store);
                return next.then(maybeYield);
            });
        }, Promise.resolve(root));
    };

    // ─────────────────────────────────────────────────────────────────────
    // 10. buildBloom
    // ─────────────────────────────────────────────────────────────────────

    _.buildBloom = function (cids) {
        if (!cids || !cids.length) { return Promise.resolve(null); }
        var Bloom = Q.Data && Q.Data.Bloom;
        if (!Bloom || typeof Bloom.fromElements !== 'function') { return Promise.resolve(null); }
        return Promise.resolve().then(function () {
            var filter = Bloom.fromElements(cids);
            _._state.bloomFilter = filter;
            return (filter && typeof filter.serialize === 'function')
                ? filter.serialize() : null;
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 11. signAnnounce — P-256 ECDSA over canonical JSON of entry
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Signs the announce entry (with signature field absent).
     * Returns base64 raw r‖s (IEEE P1363, 64 bytes from WebCrypto ECDSA).
     */
    _.signAnnounce = function (entry, sessionKey) {
        return _.canonicalJSON(entry).then(function (canonical) {
            var payload = new TextEncoder().encode(canonical);
            return crypto.subtle.sign(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                sessionKey,
                payload
            );
        }).then(function (sigBuf) {
            return Q.Data.toBase64(new Uint8Array(sigBuf));
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 12. verifyAnnounce — used in tests; Drops sign, Jets verify
    // ─────────────────────────────────────────────────────────────────────

    _.verifyAnnounce = function (entry, publicKey) {
        var copy = Q.extend({}, entry);
        delete copy.signature;
        return _.canonicalJSON(copy).then(function (canonical) {
            var payload  = new TextEncoder().encode(canonical);
            var sigBytes = Q.Data.fromBase64(entry.signature);
            return crypto.subtle.verify(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                publicKey,
                sigBytes,
                payload
            );
        });
    };

    return _;
});
