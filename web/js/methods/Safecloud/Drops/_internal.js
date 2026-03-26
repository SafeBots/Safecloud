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

Q.exports(function (Q) {

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
        safebuxEarned: 0,     // 0.02 SBUX per MB served
        _initTime:     null   // set to Date.now() in init()      // simulated: 0.02 SBUX per MB served
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
     */
    _.canonicalJSON = function (obj) {
        return Q.Data.canonicalize(obj);
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

        // Open all stores; each call returns the same underlying IDBDatabase
        var opens = stores.map(function (s) {
            return new Promise(function (resolve, reject) {
                Q.IndexedDB.open(_.DB_NAME, s.name, s.params, function (err, db) {
                    if (err) { reject(err); } else { resolve(db); }
                });
            });
        });

        _._state._dbPromise = Promise.all(opens).then(function (dbs) {
            // All dbs are the same IDBDatabase instance (Q.IndexedDB.open caches per dbName)
            return dbs[0];
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

        return diff.reduce(function (prev, entry) {
            return prev.then(function (cur) {
                return entry.added
                    ? Prolly.insert(cur, { key: entry.cid, value: entry.cid }, store)
                    : Prolly.delete(cur, entry.cid, store);
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
        var payload = new TextEncoder().encode(_.canonicalJSON(entry));
        return crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            sessionKey,
            payload
        ).then(function (sigBuf) {
            return Q.Data.toBase64(new Uint8Array(sigBuf));
        });
    };

    // ─────────────────────────────────────────────────────────────────────
    // 12. verifyAnnounce — used in tests; Drops sign, Jets verify
    // ─────────────────────────────────────────────────────────────────────

    _.verifyAnnounce = function (entry, publicKey) {
        var copy = Q.extend({}, entry);
        delete copy.signature;
        var payload  = new TextEncoder().encode(_.canonicalJSON(copy));
        var sigBytes = Q.Data.fromBase64(entry.signature);
        return crypto.subtle.verify(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            publicKey,
            sigBytes,
            payload
        );
    };

    return _;
});
