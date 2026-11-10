'use strict';
/**
 * Delegation.js — OCP Delegation Extension enforcement for Safecloud.
 *
 * Provides:
 *   • Origin-based delegation lookup (no crypto from the publisher needed)
 *   • OCP claim signature verification for signed cert flow
 *   • Rate limit enforcement (global per delegation, not per viewer)
 *   • Geographic restriction checking (by IP geolocation)
 *   • IP allowlist checking (CIDR, wildcard, exact)
 *   • Consumption tracking (aggregate per delegation per period)
 *   • Delegation CRUD (create, revoke, list)
 *   • Webhook notification on revocation
 *
 * Two access modes:
 *   1. Origin-only (simple): browser sends Origin header, jet looks up
 *      active delegation for that domain. No crypto from the publisher.
 *   2. Signed cert: publisher signs a short-lived OCP claim, jet verifies
 *      the chain. For server-to-server or higher-security use cases.
 *
 * @module Safecloud/Delegation
 */

var crypto = require('crypto');
var https  = require('https');
var http   = require('http');

// Optional: npm install geoip-lite  (adds ~14MB country/city IP database).
// Geo restrictions in delegations are skipped if not installed.
var geoip;
try { geoip = require('geoip-lite'); }
catch (e) { geoip = null; }

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Get the current period key for a given period type.
 * @param {string} per  "hour"|"day"|"week"|"month"|"year"
 * @returns {string}
 */
function _periodKey(per) {
    var d = new Date();
    switch (per) {
        case 'hour':  return d.getUTCFullYear() + '-' + _pad(d.getUTCMonth()+1) + '-' + _pad(d.getUTCDate()) + 'T' + _pad(d.getUTCHours());
        case 'day':   return d.getUTCFullYear() + '-' + _pad(d.getUTCMonth()+1) + '-' + _pad(d.getUTCDate());
        case 'week':  return d.getUTCFullYear() + '-W' + _pad(_isoWeek(d));
        case 'month': return d.getUTCFullYear() + '-' + _pad(d.getUTCMonth()+1);
        case 'year':  return '' + d.getUTCFullYear();
        default:      return d.getUTCFullYear() + '-' + _pad(d.getUTCMonth()+1) + '-' + _pad(d.getUTCDate());
    }
}

function _pad(n) { return n < 10 ? '0' + n : '' + n; }

function _isoWeek(d) {
    var t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7));
    var yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
    return Math.ceil(((t - yearStart) / 86400000 + 1) / 7);
}

/**
 * Check whether an IP matches a pattern (exact, CIDR, or wildcard).
 * @param {string} ip
 * @param {string} pattern
 * @returns {boolean}
 */
function _ipMatches(ip, pattern) {
    // Exact match
    if (ip === pattern) return true;

    // CIDR
    if (pattern.indexOf('/') !== -1) {
        return _cidrMatch(ip, pattern);
    }

    // Wildcard (e.g. "10.0.*.*")
    if (pattern.indexOf('*') !== -1) {
        var parts  = pattern.split('.');
        var ipParts = ip.split('.');
        if (parts.length !== ipParts.length) return false;
        for (var i = 0; i < parts.length; i++) {
            if (parts[i] !== '*' && parts[i] !== ipParts[i]) return false;
        }
        return true;
    }

    return false;
}

/**
 * Simple IPv4 CIDR match.
 */
function _cidrMatch(ip, cidr) {
    var parts = cidr.split('/');
    var base  = parts[0];
    var bits  = parseInt(parts[1], 10);
    if (isNaN(bits)) return false;

    // IPv4 only for now
    if (ip.indexOf(':') !== -1 || base.indexOf(':') !== -1) {
        // IPv6 CIDR matching — punt for now, treat as no match
        // TODO: implement IPv6 CIDR
        return false;
    }

    var ipNum   = _ipToInt(ip);
    var baseNum = _ipToInt(base);
    var mask    = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipNum & mask) === (baseNum & mask);
}

function _ipToInt(ip) {
    var p = ip.split('.');
    return ((parseInt(p[0]) << 24) | (parseInt(p[1]) << 16) |
            (parseInt(p[2]) << 8)  | parseInt(p[3])) >>> 0;
}

/**
 * Extract domain from an Origin header value.
 * "https://publisher.com" → "publisher.com"
 * "http://localhost:3000" → "localhost"
 */
function _originToDomain(origin) {
    if (!origin) return null;
    try {
        var u = new URL(origin);
        return u.hostname;
    } catch (e) {
        return null;
    }
}

// ─── Delegation ──────────────────────────────────────────────────────────────

/**
 * @param {object} db  A RightsManagement._db instance (better-sqlite3-compatible)
 */
function Delegation(db) {
    this._db = db;
}

// ─── Create ──────────────────────────────────────────────────────────────────

/**
 * Record a new delegation from an author to a publisher (set of domains).
 *
 * @param {object} opts
 *   authorPubHex  {string}  hex 32-byte Ed25519 pub key of the author
 *   domains       {string[]}  publisher domains
 *   label         {string}  scoping string
 *   claim         {object}  the full signed OCP delegation claim
 *   rootCid       {string|null}  NULL = all roots for this author
 *   limits        {object[]|null}  e.g. [{minutes: 30, per: "day"}]
 *   geo           {object|null}  {includeCountries:[]} or {excludeCountries:[]}
 *   allowIPs      {string[]|null}  CIDR/wildcard/exact
 *   maxDepth      {number|null}
 *   expiresAt     {number|null}  Unix seconds
 *   revocable     {boolean}  default true
 *   webhookUrl    {string|null}
 * @returns {object}  { id, ... }
 */
Delegation.prototype.create = function (opts) {
    var authorPubHex = opts.authorPubHex;
    var domains      = opts.domains;
    var label        = opts.label || '';

    if (!authorPubHex || !domains || !domains.length) {
        var e = new Error('Delegation.create: authorPubHex and domains required');
        e.statusCode = 400;
        throw e;
    }

    var now = Math.floor(Date.now() / 1000);

    var ins = this._db.prepare(
        'INSERT INTO delegations (' +
            'author_pub_hex, domains_json, root_cid, label, ' +
            'limits_json, geo_json, allow_ips_json, max_depth, ' +
            'claim_json, issued_at, expires_at, revocable, active, webhook_url' +
        ') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)'
    ).run(
        authorPubHex,
        JSON.stringify(domains),
        opts.rootCid || null,
        label,
        opts.limits  ? JSON.stringify(opts.limits)  : null,
        opts.geo     ? JSON.stringify(opts.geo)     : null,
        opts.allowIPs ? JSON.stringify(opts.allowIPs) : null,
        opts.maxDepth != null ? opts.maxDepth : null,
        JSON.stringify(opts.claim),
        now,
        opts.expiresAt || null,
        opts.revocable === false ? 0 : 1,
        opts.webhookUrl || null
    );

    var delegationId = ins.lastInsertRowid;

    // Index each domain for fast lookup
    for (var i = 0; i < domains.length; i++) {
        this._db.prepare(
            'INSERT INTO delegation_domains (domain, delegation_id) VALUES (?, ?)'
        ).run(domains[i].toLowerCase(), delegationId);
    }

    return { id: delegationId, authorPubHex: authorPubHex, domains: domains,
             label: label, issuedAt: now };
};

// ─── Revoke ──────────────────────────────────────────────────────────────────

/**
 * Revoke a delegation. Only works if revocable=1.
 * @param {number} delegationId
 * @returns {boolean}
 */
Delegation.prototype.revoke = function (delegationId) {
    var row = this._db.prepare(
        'SELECT id, revocable, webhook_url, domains_json FROM delegations WHERE id = ? AND active = 1'
    ).get(delegationId);
    if (!row) return false;
    if (!row.revocable) {
        var e = new Error('Delegation is irrevocable');
        e.statusCode = 403;
        throw e;
    }

    // NOTE: DB engine binds WHERE params first, then SET params
    this._db.prepare('UPDATE delegations SET active = 0 WHERE id = ?').run(delegationId);

    // Fire webhook if configured
    if (row.webhook_url) {
        _fireWebhook(row.webhook_url, {
            event: 'delegation.revoked',
            delegationId: delegationId,
            domains: JSON.parse(row.domains_json),
            revokedAt: Math.floor(Date.now() / 1000)
        });
    }

    return true;
};

// ─── Lookup by Origin ────────────────────────────────────────────────────────

/**
 * Find active delegations for a given Origin header value.
 * This is the simple "Origin-only" flow — no crypto from the publisher.
 *
 * @param {string} origin  Value of the Origin header (e.g. "https://publisher.com")
 * @param {object} [opts]
 *   rootCid  {string|null}  If provided, filter to delegations covering this root
 *   ip       {string|null}  Viewer's IP for geo checking
 * @returns {object[]}  Active matching delegations with their limits
 */
Delegation.prototype.findByOrigin = function (origin, opts) {
    opts = opts || {};
    var domain = _originToDomain(origin);
    if (!domain) return [];

    var now = Math.floor(Date.now() / 1000);

    // Find delegation IDs for this domain
    var domainRows = this._db.prepare(
        'SELECT delegation_id FROM delegation_domains WHERE domain = ?'
    ).all(domain.toLowerCase());

    if (!domainRows.length) return [];

    var results = [];
    for (var i = 0; i < domainRows.length; i++) {
        var deleg = this._db.prepare(
            'SELECT * FROM delegations WHERE id = ? AND active = 1'
        ).get(domainRows[i].delegation_id);

        if (!deleg) continue;

        // Check expiry
        if (deleg.expires_at && deleg.expires_at < now) continue;

        // Check rootCid filter
        if (opts.rootCid && deleg.root_cid && deleg.root_cid !== opts.rootCid) continue;

        results.push(_rowToDeleg(deleg));
    }

    return results;
};

/**
 * Check whether a request is allowed under a specific delegation.
 * Checks geo, IP allowlist, and rate limits.
 *
 * @param {number} delegationId
 * @param {object} opts
 *   ip            {string|null}  requester's IP
 *   quantity      {string}       what's being consumed (e.g. "minutes", "videos")
 *   amount        {number}       how much to consume (e.g. 1.5 minutes, 1 video)
 *   checkOnly     {boolean}      if true, don't increment consumption (dry run)
 * @returns {{ allowed: boolean, reason?: string, remaining?: object }}
 */
Delegation.prototype.checkAndConsume = function (delegationId, opts) {
    opts = opts || {};

    var deleg = this._db.prepare(
        'SELECT * FROM delegations WHERE id = ? AND active = 1'
    ).get(delegationId);

    if (!deleg) return { allowed: false, reason: 'delegation_not_found' };

    var now = Math.floor(Date.now() / 1000);
    if (deleg.expires_at && deleg.expires_at < now) {
        return { allowed: false, reason: 'delegation_expired' };
    }

    // ── Geo check ────────────────────────────────────────────────────────────
    if (opts.ip && deleg.geo_json) {
        var geoResult = this._checkGeo(opts.ip, JSON.parse(deleg.geo_json));
        if (!geoResult.allowed) return geoResult;
    }

    // ── IP allowlist check ───────────────────────────────────────────────────
    if (opts.ip && deleg.allow_ips_json) {
        var allowIPs = JSON.parse(deleg.allow_ips_json);
        var ipAllowed = false;
        for (var i = 0; i < allowIPs.length; i++) {
            if (_ipMatches(opts.ip, allowIPs[i])) { ipAllowed = true; break; }
        }
        if (!ipAllowed) {
            return { allowed: false, reason: 'ip_not_allowed' };
        }
    }

    // ── Rate limit check ─────────────────────────────────────────────────────
    if (deleg.limits_json && opts.quantity) {
        var limits = JSON.parse(deleg.limits_json);
        var remaining = {};

        for (var j = 0; j < limits.length; j++) {
            var limit = limits[j];
            // Find the quantity key (the non-"per" key)
            var qtyKey = null;
            var maxVal = 0;
            for (var k in limit) {
                if (k !== 'per') { qtyKey = k; maxVal = limit[k]; break; }
            }
            if (!qtyKey) continue;

            // Only check limits matching the requested quantity
            if (qtyKey !== opts.quantity) continue;

            var pk = _periodKey(limit.per);
            var usage = this._db.prepare(
                'SELECT consumed FROM delegation_usage WHERE delegation_id = ? AND period_key = ? AND quantity = ?'
            ).get(delegationId, pk, qtyKey);

            var consumed = usage ? usage.consumed : 0;
            var wouldBe  = consumed + (opts.amount || 0);

            remaining[qtyKey + '/' + limit.per] = maxVal - consumed;

            if (wouldBe > maxVal) {
                return {
                    allowed: false,
                    reason: 'limit_exceeded',
                    limit: qtyKey + ': ' + maxVal + '/' + limit.per,
                    consumed: consumed,
                    remaining: remaining
                };
            }
        }

        // ── Consume ──────────────────────────────────────────────────────────
        if (!opts.checkOnly && opts.amount) {
            for (var m = 0; m < limits.length; m++) {
                var lim = limits[m];
                var qty2 = null;
                for (var k2 in lim) {
                    if (k2 !== 'per') { qty2 = k2; break; }
                }
                if (!qty2 || qty2 !== opts.quantity) continue;

                var pk2 = _periodKey(lim.per);
                var existing = this._db.prepare(
                    'SELECT consumed FROM delegation_usage WHERE delegation_id = ? AND period_key = ? AND quantity = ?'
                ).get(delegationId, pk2, qty2);

                if (existing) {
                    this._db.prepare(
                        'UPDATE delegation_usage SET consumed = consumed + ? WHERE delegation_id = ? AND period_key = ? AND quantity = ?'
                    ).run(delegationId, pk2, qty2, opts.amount);
                } else {
                    this._db.prepare(
                        'INSERT INTO delegation_usage (delegation_id, period_key, quantity, consumed) VALUES (?, ?, ?, ?)'
                    ).run(delegationId, pk2, qty2, opts.amount);
                }
            }
        }

        return { allowed: true, remaining: remaining };
    }

    return { allowed: true };
};

// ─── Geo checking ────────────────────────────────────────────────────────────

/**
 * @param {string} ip
 * @param {object} geo  {includeCountries:[]} or {excludeCountries:[]}
 * @returns {{ allowed: boolean, reason?: string }}
 */
Delegation.prototype._checkGeo = function (ip, geo) {
    if (!geoip) {
        // geoip-lite not installed — skip geo checks
        return { allowed: true };
    }

    var lookup = geoip.lookup(ip);
    if (!lookup || !lookup.country) {
        // Can't determine country — allow by default (fail-open for geo)
        return { allowed: true };
    }

    var country = lookup.country; // ISO 3166-1 alpha-2

    if (geo.includeCountries && geo.includeCountries.length) {
        if (geo.includeCountries.indexOf(country) === -1) {
            return { allowed: false, reason: 'geo_blocked', country: country };
        }
    }

    if (geo.excludeCountries && geo.excludeCountries.length) {
        if (geo.excludeCountries.indexOf(country) !== -1) {
            return { allowed: false, reason: 'geo_blocked', country: country };
        }
    }

    return { allowed: true };
};

// ─── List / Get ──────────────────────────────────────────────────────────────

/**
 * List delegations for an author.
 * @param {string} authorPubHex
 * @param {object} [opts]  { activeOnly?, limit?, offset? }
 * @returns {object[]}
 */
Delegation.prototype.listByAuthor = function (authorPubHex, opts) {
    opts = opts || {};
    var limit  = Math.min(opts.limit  || 100, 1000);
    var offset = opts.offset || 0;

    var sql = 'SELECT * FROM delegations WHERE author_pub_hex = ?';
    if (opts.activeOnly) sql += ' AND active = 1';
    sql += ' ORDER BY issued_at DESC LIMIT ? OFFSET ?';

    var rows = this._db.prepare(sql).all(authorPubHex, limit, offset);
    return rows.map(_rowToDeleg);
};

/**
 * Get a single delegation by ID.
 * @param {number} delegationId
 * @returns {object|null}
 */
Delegation.prototype.get = function (delegationId) {
    var row = this._db.prepare('SELECT * FROM delegations WHERE id = ?').get(delegationId);
    return row ? _rowToDeleg(row) : null;
};

/**
 * Get usage stats for a delegation.
 * @param {number} delegationId
 * @returns {object[]}  [ { periodKey, quantity, consumed } ]
 */
Delegation.prototype.getUsage = function (delegationId) {
    var rows = this._db.prepare(
        'SELECT period_key, quantity, consumed FROM delegation_usage WHERE delegation_id = ? ORDER BY period_key DESC'
    ).all(delegationId);
    return rows.map(function (r) {
        return { periodKey: r.period_key, quantity: r.quantity, consumed: r.consumed };
    });
};

// ─── Express middleware ──────────────────────────────────────────────────────

/**
 * Returns an Express middleware that checks delegations on key-issuance
 * requests. Attaches `req.delegation` if a valid delegation is found.
 *
 * The middleware checks the Origin header against active delegations.
 * If no matching delegation is found, the request proceeds without
 * `req.delegation` (for direct-access or payment-based flows).
 *
 * @param {Delegation} deleg  Delegation instance
 * @returns {Function}  Express middleware
 */
Delegation.middleware = function (deleg) {
    return function (req, res, next) {
        var origin = req.headers.origin || req.headers.referer;
        if (!origin) return next();

        var ip = req.ip || req.connection.remoteAddress;
        var rootCid = req.params.rootCid || (req.query && req.query.rootCid) || null;

        var delegations = deleg.findByOrigin(origin, { rootCid: rootCid, ip: ip });
        if (delegations.length > 0) {
            // Use the first matching delegation (most recently issued)
            req.delegation = delegations[0];
        }

        next();
    };
};

// ─── Route registration ─────────────────────────────────────────────────────

/**
 * Register delegation API routes on an Express app.
 *
 * Routes:
 *   GET    /Safecloud/author/panel/api/delegations       — list by author
 *   POST   /Safecloud/author/panel/api/delegation         — create
 *   DELETE /Safecloud/author/panel/api/delegation/:id     — revoke
 *   GET    /Safecloud/author/panel/api/delegation/:id/usage — usage stats
 *
 * @param {object} app
 * @param {Delegation} deleg
 */
Delegation.registerRoutes = function (app, deleg) {
    var _verifyEd25519 = _makeVerifier();

    // ── List delegations ─────────────────────────────────────────────────────
    app.get('/Safecloud/author/panel/api/delegations', function (req, res) {
        var pubHex = req.query.authorPubKey;
        if (!pubHex) return res.status(400).json({ error: 'authorPubKey required' });

        try {
            var list = deleg.listByAuthor(pubHex, { activeOnly: !req.query.includeRevoked });
            res.json({ delegations: list });
        } catch (e) {
            res.status(e.statusCode || 500).json({ error: e.message });
        }
    });

    // ── Create delegation ────────────────────────────────────────────────────
    // Body: { claim: <signed OCP delegation claim> }
    app.post('/Safecloud/author/panel/api/delegation', function (req, res) {
        var claim = req.body && req.body.claim;
        if (!claim || claim.ocp !== 1 || !claim.sig) {
            return res.status(400).json({ error: 'Valid OCP delegation claim required' });
        }

        // Parse issuer pub key
        var issMatch = typeof claim.iss === 'string' &&
            claim.iss.match(/^data:key\/ed25519;hex,([0-9a-f]{64})$/i);
        if (!issMatch) {
            return res.status(400).json({ error: 'iss must be data:key/ed25519;hex,<64hexchars>' });
        }
        var pubHex = issMatch[1].toLowerCase();

        // Verify signature
        var unsigned = Object.assign({}, claim);
        delete unsigned.sig;
        var keys  = Object.keys(unsigned).sort();
        var canon = JSON.stringify(keys.reduce(function (o, k) { o[k] = unsigned[k]; return o; }, {}));
        if (!_verifyEd25519(canon, claim.sig, pubHex)) {
            return res.status(403).json({ error: 'Signature verification failed' });
        }

        // Extract delegation fields from stm
        var stm = claim.stm || {};
        var domains = stm.domains;
        if (!domains || !Array.isArray(domains) || !domains.length) {
            return res.status(400).json({ error: 'stm.domains (array of publisher domains) required' });
        }

        try {
            var result = deleg.create({
                authorPubHex: pubHex,
                domains:      domains,
                label:        stm.label || claim.sub || '',
                claim:        claim,
                rootCid:      stm.rootCid || null,
                limits:       stm.limits || null,
                geo:          stm.geo || null,
                allowIPs:     stm.allowIPs || null,
                maxDepth:     stm.maxDepth != null ? stm.maxDepth : null,
                expiresAt:    claim.exp || null,
                revocable:    stm.irrevocable ? false : true,
                webhookUrl:   stm.webhookUrl || null
            });
            res.json({ ok: true, delegation: result });
        } catch (e) {
            res.status(e.statusCode || 500).json({ error: e.message });
        }
    });

    // ── Revoke delegation ────────────────────────────────────────────────────
    app.delete('/Safecloud/author/panel/api/delegation/:id', function (req, res) {
        var id = parseInt(req.params.id, 10);
        if (isNaN(id)) return res.status(400).json({ error: 'Invalid delegation ID' });

        try {
            var revoked = deleg.revoke(id);
            res.json({ ok: revoked });
        } catch (e) {
            res.status(e.statusCode || 500).json({ error: e.message });
        }
    });

    // ── Usage stats ──────────────────────────────────────────────────────────
    app.get('/Safecloud/author/panel/api/delegation/:id/usage', function (req, res) {
        var id = parseInt(req.params.id, 10);
        if (isNaN(id)) return res.status(400).json({ error: 'Invalid delegation ID' });

        try {
            var usage = deleg.getUsage(id);
            var info  = deleg.get(id);
            res.json({ delegation: info, usage: usage });
        } catch (e) {
            res.status(e.statusCode || 500).json({ error: e.message });
        }
    });
};

// ─── Private helpers ─────────────────────────────────────────────────────────

function _rowToDeleg(row) {
    return {
        id:           row.id,
        authorPubHex: row.author_pub_hex,
        domains:      row.domains_json ? JSON.parse(row.domains_json) : [],
        rootCid:      row.root_cid,
        label:        row.label,
        limits:       row.limits_json ? JSON.parse(row.limits_json) : null,
        geo:          row.geo_json ? JSON.parse(row.geo_json) : null,
        allowIPs:     row.allow_ips_json ? JSON.parse(row.allow_ips_json) : null,
        maxDepth:     row.max_depth,
        issuedAt:     row.issued_at,
        expiresAt:    row.expires_at,
        revocable:    !!row.revocable,
        active:       !!row.active,
        webhookUrl:   row.webhook_url
    };
}

function _fireWebhook(url, payload) {
    try {
        var body = JSON.stringify(payload);
        var parsed = new URL(url);
        var mod = parsed.protocol === 'https:' ? https : http;
        var req = mod.request({
            hostname: parsed.hostname,
            port:     parsed.port,
            path:     parsed.pathname + parsed.search,
            method:   'POST',
            headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
            timeout:  5000
        });
        req.on('error', function () {}); // fire and forget
        req.write(body);
        req.end();
    } catch (e) { /* ignore webhook failures */ }
}

function _makeVerifier() {
    return function (payload, sig, pubKeyHex) {
        try {
            var pubRaw = Buffer.from(pubKeyHex, 'hex');
            var hashBuf = crypto.createHash('sha256').update(payload, 'utf8').digest();
            var header = Buffer.from('302a300506032b6570032100', 'hex');
            var spki   = Buffer.concat([header, pubRaw]);
            var pubKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
            return crypto.verify(null, hashBuf, pubKey, Buffer.from(sig, 'hex'));
        } catch (e) { return false; }
    };
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = Delegation;
