'use strict';
/**
 * ControlPanel.js — Safecloud 3.8 admin control panel.
 *
 * Mounts an Express middleware that provides:
 *
 *   GET  /Safecloud/admin/           → HTML single-page control panel
 *   GET  /Safecloud/admin/api/roots         → list registered rootCids
 *   GET  /Safecloud/admin/api/roots/:cid    → single root + grant chain
 *   GET  /Safecloud/admin/api/publishers    → list publishers
 *   PUT  /Safecloud/admin/api/publishers    → register/update publisher (proxied)
 *   DELETE /Safecloud/admin/api/publishers/:id → deregister publisher
 *   GET  /Safecloud/admin/api/chain/:cid    → grant chain for a rootCid
 *   POST /Safecloud/admin/api/chain/:cid    → append a grant chain entry
 *   GET  /Safecloud/admin/api/rate-limits   → list rate-limit buckets
 *   DELETE /Safecloud/admin/api/rate-limits/:bucket → reset a bucket
 *   GET  /Safecloud/admin/api/nonces        → list active (non-expired) nonces
 *   GET  /Safecloud/admin/api/stats         → aggregate counts
 *
 * Usage (in Jets.js listen()):
 *   var ControlPanel = require('./ControlPanel');
 *   ControlPanel.registerRoutes(app, rm, { adminToken: 'secret' });
 *
 * @module ControlPanel
 */

// ─── Admin HTML (single-page control panel) ───────────────────────────────────

/* eslint-disable max-len */
var ADMIN_HTML = '<!doctype html>\n<html lang="en">\n<head>\n' +
'<meta charset="utf-8">\n' +
'<meta name="viewport" content="width=device-width,initial-scale=1">\n' +
'<title>Safecloud Control Panel</title>\n' +
'<style>\n' +
':root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--danger:#f85149;--success:#3fb950;--warn:#d29922}\n' +
'@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--surface:#ffffff;--border:#d0d7de;--text:#1f2328;--muted:#636c76;--accent:#0969da;--danger:#cf222e;--success:#1a7f37;--warn:#9a6700}}\n' +
'*{box-sizing:border-box;margin:0;padding:0}\n' +
'body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}\n' +
'header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;gap:16px}\n' +
'header h1{font-size:1rem;font-weight:600;color:var(--text)}\n' +
'header .pill{background:var(--accent);color:#fff;border-radius:9999px;padding:2px 10px;font-size:.75rem;font-weight:600}\n' +
'.main{max-width:1100px;margin:0 auto;padding:24px 16px}\n' +
'.tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:20px}\n' +
'.tab{padding:8px 16px;border:none;border-radius:6px 6px 0 0;background:transparent;color:var(--muted);cursor:pointer;font-size:.875rem;font-weight:500}\n' +
'.tab.active{color:var(--accent);border-bottom:2px solid var(--accent)}\n' +
'.tab:hover:not(.active){color:var(--text)}\n' +
'.panel{display:none}.panel.active{display:block}\n' +
'.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}\n' +
'.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}\n' +
'.stat{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px}\n' +
'.stat .n{font-size:1.6rem;font-weight:700;line-height:1}\n' +
'.stat .l{color:var(--muted);font-size:.8rem;margin-top:4px}\n' +
'table{width:100%;border-collapse:collapse}\n' +
'th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:var(--muted);font-weight:500;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}\n' +
'td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle}\n' +
'tr:last-child td{border-bottom:none}\n' +
'.mono{font-family:ui-monospace,monospace;font-size:.8rem}\n' +
'.badge{display:inline-block;padding:1px 8px;border-radius:9999px;font-size:.75rem;font-weight:600}\n' +
'.badge-green{background:rgba(63,185,80,.15);color:var(--success)}\n' +
'.badge-red{background:rgba(248,81,73,.15);color:var(--danger)}\n' +
'.badge-blue{background:rgba(88,166,255,.15);color:var(--accent)}\n' +
'.badge-yellow{background:rgba(210,153,34,.15);color:var(--warn)}\n' +
'button.action{padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;font-size:.8rem}\n' +
'button.action:hover{color:var(--danger);border-color:var(--danger)}\n' +
'button.action.ok:hover{color:var(--success);border-color:var(--success)}\n' +
'.empty{padding:24px;text-align:center;color:var(--muted)}\n' +
'.err{color:var(--danger);padding:8px 12px;background:rgba(248,81,73,.1);border-radius:6px;margin-bottom:12px}\n' +
'.toolbar{display:flex;align-items:center;gap:8px;margin-bottom:12px}\n' +
'.toolbar input{flex:1;padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:.875rem}\n' +
'.toolbar button{padding:6px 14px;border-radius:6px;border:none;background:var(--accent);color:#fff;cursor:pointer;font-size:.875rem}\n' +
'.toolbar button:hover{opacity:.85}\n' +
'.sub{font-size:.75rem;color:var(--muted)}\n' +
'details summary{cursor:pointer;color:var(--accent);font-size:.8rem}\n' +
'details pre{margin-top:6px;background:var(--bg);padding:8px;border-radius:4px;font-size:.75rem;overflow-x:auto}\n' +
/* ── tab description block ── */
'.desc{font-size:.85rem;color:var(--muted);margin-bottom:16px;line-height:1.6;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px}\n' +
'.desc strong{color:var(--text)}\n' +
/* ── CSS tooltip ── */
'[data-tip]{position:relative;cursor:help}\n' +
'[data-tip]::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#1f2937;color:#f1f5f9;padding:5px 9px;border-radius:5px;font-size:.75rem;line-height:1.4;white-space:normal;text-align:left;width:220px;pointer-events:none;opacity:0;z-index:100;transition:opacity .15s;border:1px solid #374151;box-shadow:0 4px 12px rgba(0,0,0,.4)}\n' +
'[data-tip]:hover::after,[data-tip]:focus-within::after,.tip-on::after{opacity:1!important}\n' +
'th[data-tip]{padding-right:18px}\n' +
'@media(prefers-color-scheme:light){[data-tip]::after{background:#1e293b;color:#f8fafc}}\n' +
'</style>\n' +
'</head>\n' +
'<body>\n' +
'<header>\n' +
'  <span style="font-size:1.3rem">⬡</span>\n' +
'  <h1>Safecloud Control Panel</h1>\n' +
'  <span class="pill">3.8</span>\n' +
'  <span id="hstatus" style="margin-left:auto;font-size:.8rem;color:var(--muted)">loading…</span>\n' +
'</header>\n' +
'<div class="main">\n' +
'  <div class="stats" id="stats"></div>\n' +
'  <div class="tabs">\n' +
'    <button class="tab active" data-tab="roots">Roots</button>\n' +
'    <button class="tab" data-tab="publishers">Publishers</button>\n' +
'    <button class="tab" data-tab="chain">Grant Chain</button>\n' +
'    <button class="tab" data-tab="rate">Rate Limits</button>\n' +
'    <button class="tab" data-tab="nonces">Nonces</button>\n' +
'  </div>\n' +
'  <div id="tab-desc" class="desc"></div>\n' +
'\n' +
'  <div id="roots" class="panel active">\n' +
'    <div class="card">\n' +
'      <div class="toolbar"><span style="color:var(--muted);font-size:.85rem">Registered content roots</span>' +
'<button onclick="loadRoots()">↻ Refresh</button></div>\n' +
'      <div id="roots-err"></div>\n' +
'      <div id="roots-body"></div>\n' +
'    </div>\n' +
'  </div>\n' +
'\n' +
'  <div id="publishers" class="panel">\n' +
'    <div class="card">\n' +
'      <div class="toolbar"><span style="color:var(--muted);font-size:.85rem">Registered publishers</span>' +
'<button onclick="loadPublishers()">↻ Refresh</button></div>\n' +
'      <div id="pub-err"></div>\n' +
'      <div id="pub-body"></div>\n' +
'    </div>\n' +
'  </div>\n' +
'\n' +
'  <div id="chain" class="panel">\n' +
'    <div class="card">\n' +
'      <div class="toolbar">\n' +
'        <input id="chain-cid" placeholder="rootCid…" />\n' +
'        <button onclick="loadChain()">Load chain</button>\n' +
'      </div>\n' +
'      <div id="chain-err"></div>\n' +
'      <div id="chain-body"></div>\n' +
'    </div>\n' +
'  </div>\n' +
'\n' +
'  <div id="rate" class="panel">\n' +
'    <div class="card">\n' +
'      <div class="toolbar"><span style="color:var(--muted);font-size:.85rem">Rate-limit buckets</span>' +
'<button onclick="loadRate()">↻ Refresh</button></div>\n' +
'      <div id="rate-err"></div>\n' +
'      <div id="rate-body"></div>\n' +
'    </div>\n' +
'  </div>\n' +
'\n' +
'  <div id="nonces" class="panel">\n' +
'    <div class="card">\n' +
'      <div class="toolbar"><span style="color:var(--muted);font-size:.85rem">Active publisher-auth nonces (replay protection)</span>' +
'<button onclick="loadNonces()">↻ Refresh</button></div>\n' +
'      <div id="nonce-err"></div>\n' +
'      <div id="nonce-body"></div>\n' +
'    </div>\n' +
'  </div>\n' +
'</div>\n' +
'<script>\n' +
'var BASE = "/Safecloud/admin/api";\n' +
'function api(path,opts){return fetch(BASE+path,opts).then(function(r){return r.json()})}\n' +
'function ts(ms){if(!ms)return"—";return new Date(ms).toLocaleString()}\n' +
'function abbr(s,n){if(!s)return"—";return s.length>n?s.slice(0,n)+"…":s}\n' +
'\n' +
'var TAB_DESCS={\n' +
'  roots:"<strong>Content roots</strong> — every piece of content registered for access control, identified by its hash (CID). " +\n' +
'    "If a creator\'s content isn\'t listed here, no publisher can issue access tokens for it yet.",\n' +
'  publishers:"<strong>Publishers</strong> are the domains and apps allowed to sell or grant access to content. " +\n' +
'    "Each one proves domain ownership by signing its registration with a cryptographic key. " +\n' +
'    "<strong>Removing a publisher</strong> immediately blocks all new access tokens from that domain — existing unexpired tokens remain valid until they expire.",\n' +
'  chain:"<strong>Grant chain</strong> — an append-only audit log of every access grant and revoke for a content root. " +\n' +
'    "Paste a root CID below to load its full history. Entries are chained so the log cannot be altered after the fact.",\n' +
'  rate:"<strong>Rate limits</strong> — each active user has a token bucket tracking API call volume. " +\n' +
'    "Tokens drain on use and refill automatically over time. " +\n' +
'    "Hit <strong>Reset</strong> to unblock a legitimate user who hit the limit. " +\n' +
'    "Bucket capacity and refill rate are set in server config (<code>Safecloud.rights.rateLimitCapacity</code> / <code>rateLimitRefillRate</code>).",\n' +
'  nonces:"<strong>Nonces</strong> — every access token is single-use. After a token is verified, its nonce is recorded here to prevent replay attacks. " +\n' +
'    "Entries expire automatically when the original token expires. " +\n' +
'    "A <strong>409 error</strong> on the client means the token has already been used — its nonce will appear in this list.",\n' +
'};\n' +
'function setDesc(tab){var el=document.getElementById("tab-desc");if(el)el.innerHTML=TAB_DESCS[tab]||""}\n' +
'// Tab switching\n' +
'document.querySelectorAll(".tab").forEach(function(t){\n' +
'  t.addEventListener("click",function(){\n' +
'    document.querySelectorAll(".tab").forEach(function(x){x.classList.remove("active")})\n' +
'    document.querySelectorAll(".panel").forEach(function(x){x.classList.remove("active")})\n' +
'    t.classList.add("active")\n' +
'    document.getElementById(t.dataset.tab).classList.add("active")\n' +
'    setDesc(t.dataset.tab)\n' +
'  })\n' +
'})\n' +
'// Mobile: tap on [data-tip] element shows tooltip briefly\n' +
'document.addEventListener("click",function(e){\n' +
'  var el=e.target.closest("[data-tip]")\n' +
'  if(!el)return\n' +
'  el.classList.add("tip-on")\n' +
'  setTimeout(function(){el.classList.remove("tip-on")},2500)\n' +
'})\n' +
'\n' +
'// Stats\n' +
'function loadStats(){\n' +
'  api("/stats").then(function(d){\n' +
'    var el=document.getElementById("stats")\n' +
'    el.innerHTML=[\n' +
'      {n:d.roots,l:"Content roots",tip:"Pieces of content registered for access control"},\n' +
'      {n:d.publishers,l:"Publishers",tip:"Whitelisted domains that can issue access tokens"},\n' +
'      {n:d.grantEntries,l:"Grant entries",tip:"Total access grants and revokes logged across all roots"},\n' +
'      {n:d.rateBuckets,l:"Rate buckets",tip:"Active per-user rate-limit buckets (one per publisher:userId pair)"},\n' +
'      {n:d.activeNonces,l:"Active nonces",tip:"Single-use token IDs recorded to block replay attacks"},\n' +
'    ].map(function(s){return\'<div class="stat" data-tip="\'+s.tip+\'"><div class="n">\'+s.n+\'</div><div class="l">\'+s.l+"</div></div>"}).join("")\n' +
'    document.getElementById("hstatus").textContent=new Date().toLocaleTimeString()\n' +
'  })\n' +
'}\n' +
'\n' +
'// Roots\n' +
'function loadRoots(){\n' +
'  var err=document.getElementById("roots-err"),body=document.getElementById("roots-body")\n' +
'  err.innerHTML="";body.innerHTML=\'<div class="empty">loading…</div>\'\n' +
'  api("/roots").then(function(d){\n' +
'    if(!d.roots||!d.roots.length){body.innerHTML=\'<div class="empty">No roots registered</div>\';return}\n' +
'    body.innerHTML=\'<table><tr>\'+\n' +
'      \'<th data-tip="Content hash that uniquely identifies this piece of content. Creators register this when they upload.">Root CID</th>\'+\n' +
'      \'<th data-tip="The creator who registered this root. Only their signed auth tokens are accepted when access requires creator verification.">Creator</th>\'+\n' +
'      \'<th data-tip="Whether payment is required, and at what price. Set by the creator at registration time.">Access model</th>\'+\n' +
'      \'<th>Registered</th></tr>\'+\n' +
'      d.roots.map(function(r){return\'<tr><td class="mono">\'+abbr(r.rootCid,30)+\'</td><td class="mono">\'+\n' +
'        abbr(r.creatorId,20)+\'</td><td>\'+\n' +
'        (r.accessModel?\'<details><summary>view</summary><pre>\'+JSON.stringify(r.accessModel,null,2)+"</pre></details>":"—")+\'</td><td>\'+\n' +
'        ts(r.registeredAt)+"</td></tr>"}).join("")+"</table>"\n' +
'  }).catch(function(e){err.innerHTML=\'<div class="err">\'+e.message+"</div>"})\n' +
'}\n' +
'\n' +
'// Publishers\n' +
'function loadPublishers(){\n' +
'  var err=document.getElementById("pub-err"),body=document.getElementById("pub-body")\n' +
'  err.innerHTML="";body.innerHTML=\'<div class="empty">loading…</div>\'\n' +
'  api("/publishers").then(function(d){\n' +
'    if(!d.publishers||!d.publishers.length){body.innerHTML=\'<div class="empty">No publishers registered</div>\';return}\n' +
'    body.innerHTML=\'<table><tr>\'+\n' +
'      \'<th data-tip="The domain or app identifier the publisher registered with. This is what appears in access tokens they issue.">Publisher ID</th>\'+\n' +
'      \'<th data-tip="Ed25519 public key the publisher signed their registration with. Access tokens from this publisher must be signed by the matching private key.">Pub key</th>\'+\n' +
'      \'<th data-tip="Domains this publisher is allowed to serve from. Requests from other origins are rejected. Empty means any origin is accepted.">Allowed origins</th>\'+\n' +
'      \'<th>Registered</th>\'+\n' +
'      \'<th data-tip="Remove this publisher. New tokens from this domain will be rejected immediately. Tokens already issued remain valid until they expire.">Actions</th></tr>\'+\n' +
'      d.publishers.map(function(p){return\'<tr><td class="mono">\'+p.publisherId+\'</td><td class="mono">\'+\n' +
'        abbr(p.pubKeyHex,16)+\'</td><td>\'+\n' +
'        (p.allowedOrigins&&p.allowedOrigins.length?p.allowedOrigins.map(function(o){return\'<span class="badge badge-blue">\'+o+"</span>"}).join(" "):"any")+\n' +
'        \'</td><td>\'+ts(p.registeredAt)+\'</td><td><button class="action" onclick="deregisterPub(\\\'\'+p.publisherId+\'\\\')">Remove</button></td></tr>\'}).join("")+"</table>"\n' +
'  }).catch(function(e){err.innerHTML=\'<div class="err">\'+e.message+"</div>"})\n' +
'}\n' +
'function deregisterPub(id){\n' +
'  if(!confirm("Deregister publisher "+id+"?"))return\n' +
'  api("/publishers/"+encodeURIComponent(id),{method:"DELETE"}).then(function(d){\n' +
'    if(d.deregistered)loadPublishers(); else alert("Not found")\n' +
'  })\n' +
'}\n' +
'\n' +
'// Grant chain\n' +
'function loadChain(){\n' +
'  var cid=document.getElementById("chain-cid").value.trim()\n' +
'  if(!cid)return\n' +
'  var err=document.getElementById("chain-err"),body=document.getElementById("chain-body")\n' +
'  err.innerHTML="";body.innerHTML=\'<div class="empty">loading…</div>\'\n' +
'  api("/chain/"+encodeURIComponent(cid)).then(function(d){\n' +
'    if(!d.entries||!d.entries.length){body.innerHTML=\'<div class="empty">No chain entries for this rootCid</div>\';return}\n' +
'    body.innerHTML=\'<table><tr>\'+\n' +
'      \'<th>#</th>\'+\n' +
'      \'<th data-tip="grant = access given. revoke = access taken away. accept = grantee acknowledged. negotiate = terms counter-proposed.">Type</th>\'+\n' +
'      \'<th data-tip="Who issued this entry — usually the publisher domain that sold or revoked access.">Granter</th>\'+\n' +
'      \'<th data-tip="Who received or lost access — usually an end-user identifier.">Grantee</th>\'+\n' +
'      \'<th data-tip="Arbitrary JSON the granter attached: price paid, expiry date, access tier, etc.">Terms</th>\'+\n' +
'      \'<th>Created</th></tr>\'+\n' +
'      d.entries.map(function(e){var typeBadge={grant:"badge-green",accept:"badge-blue",negotiate:"badge-yellow",revoke:"badge-red"}[e.entryType]||"badge-blue";return\'<tr><td>\'+e.id+\'</td><td><span class="badge \'+typeBadge+\'">\'+e.entryType+\'</span></td><td class="mono">\'+abbr(e.granter,20)+\'</td><td class="mono">\'+abbr(e.grantee,20)+\'</td><td>\'+\n' +
'        (e.terms?\'<details><summary>view</summary><pre>\'+JSON.stringify(e.terms,null,2)+"</pre></details>":"—")+\'</td><td class="sub">\'+ts(e.createdAt)+"</td></tr>"}).join("")+"</table>"\n' +
'  }).catch(function(e){err.innerHTML=\'<div class="err">\'+e.message+"</div>"})\n' +
'}\n' +
'\n' +
'// Rate limits\n' +
'function loadRate(){\n' +
'  var err=document.getElementById("rate-err"),body=document.getElementById("rate-body")\n' +
'  err.innerHTML="";body.innerHTML=\'<div class="empty">loading…</div>\'\n' +
'  api("/rate-limits").then(function(d){\n' +
'    if(!d.buckets||!d.buckets.length){body.innerHTML=\'<div class="empty">No rate-limit buckets</div>\';return}\n' +
'    body.innerHTML=\'<table><tr>\'+\n' +
'      \'<th data-tip="Identified as publisher:userId. One bucket per user per publisher — publishers do not share buckets.">Bucket</th>\'+\n' +
'      \'<th data-tip="Remaining tokens out of the configured capacity. Green = healthy, yellow = getting low, red = nearly throttled.">Tokens</th>\'+\n' +
'      \'<th data-tip="When tokens were last added to this bucket. Tokens refill continuously at the configured rate.">Last refill</th>\'+\n' +
'      \'<th data-tip="Delete this bucket so the user immediately gets a full token allowance again.">Actions</th></tr>\'+\n' +
'      d.buckets.map(function(b){\n' +
'        var pct=Math.max(0,Math.min(100,b.tokens/d.capacity*100));var col=pct>50?"badge-green":pct>20?"badge-yellow":"badge-red"\n' +
'        return\'<tr><td class="mono">\'+b.bucketKey+\'</td><td><span class="badge \'+col+\'">\'+b.tokens.toFixed(1)+\'/\'+d.capacity+\'</span></td><td class="sub">\'+ts(b.lastRefill)+\'</td><td><button class="action ok" onclick="resetBucket(\\\'\'+encodeURIComponent(b.bucketKey)+\'\\\')">Reset</button></td></tr>\'\n' +
'      }).join("")+"</table>"\n' +
'  }).catch(function(e){err.innerHTML=\'<div class="err">\'+e.message+"</div>"})\n' +
'}\n' +
'function resetBucket(key){\n' +
'  api("/rate-limits/"+key,{method:"DELETE"}).then(function(d){\n' +
'    if(d.reset)loadRate(); else alert("Not found")\n' +
'  })\n' +
'}\n' +
'\n' +
'// Nonces\n' +
'function loadNonces(){\n' +
'  var err=document.getElementById("nonce-err"),body=document.getElementById("nonce-body")\n' +
'  err.innerHTML="";body.innerHTML=\'<div class="empty">loading…</div>\'\n' +
'  api("/nonces").then(function(d){\n' +
'    if(!d.nonces||!d.nonces.length){body.innerHTML=\'<div class="empty">No active nonces</div>\';return}\n' +
'    body.innerHTML=\'<table><tr>\'+\n' +
'      \'<th data-tip="Random value included in the access token. Recorded here after first use so the same token cannot be presented twice.">Nonce</th>\'+\n' +
'      \'<th data-tip="Which publisher issued the token containing this nonce.">Publisher</th>\'+\n' +
'      \'<th data-tip="When this entry will be automatically deleted — matches the expiry of the original access token.">Expires</th></tr>\'+\n' +
'      d.nonces.map(function(n){return\'<tr><td class="mono">\'+abbr(n.nonce,24)+\'</td><td class="mono">\'+n.publisher+\'</td><td class="sub">\'+ts(n.exp)+"</td></tr>"}).join("")+"</table>"\n' +
'  }).catch(function(e){err.innerHTML=\'<div class="err">\'+e.message+"</div>"})\n' +
'}\n' +
'\n' +
'loadStats();loadRoots();setDesc("roots")\n' +
'setInterval(loadStats,30000)\n' +
'</script>\n' +
'</body>\n' +
'</html>\n';
/* eslint-enable max-len */

// ─── Route registration ───────────────────────────────────────────────────────

/**
 * Register control panel routes on an Express app.
 *
 * @param {object} app              Express app
 * @param {RightsManagement} rm     Open RightsManagement instance
 * @param {object}  [opts]
 *   adminToken {string}  If set, every /Safecloud/admin/ request must carry
 *                        Authorization: Bearer <adminToken>.  Omit to disable
 *                        auth (dev mode / behind a firewall).
 */
ControlPanel.registerRoutes = function (app, rm, opts) {
    opts = opts || {};
    var adminToken = opts.adminToken || null;

    function auth(req, res, next) {
        if (!adminToken) return next();
        var hdr = req.headers.authorization || '';
        if (hdr === 'Bearer ' + adminToken) return next();
        return res.status(401).json({ error: { code: 'Unauthorized', message: 'Admin token required' } });
    }

    // ── Control panel HTML ────────────────────────────────────────────────────
    // Serve HTML from both /Safecloud/admin and /Safecloud/admin/ — avoid a
    // redirect route here because Express's non-strict matching causes the bare
    // path to match requests ending with / and loop back as 302.
    function serveHtml(req, res) {
        res.set('Content-Type', 'text/html').send(ADMIN_HTML);
    }
    app.get('/Safecloud/admin',  auth, serveHtml);
    app.get('/Safecloud/admin/', auth, serveHtml);

    // ── Stats ─────────────────────────────────────────────────────────────────
    app.get('/Safecloud/admin/api/stats', auth, function (req, res) {
        try {
            var roots        = rm.listRoots({ limit: 1 });  // just need count
            var publishers   = rm.listPublishers({ limit: 1 });
            var rateBuckets  = rm.listRateLimits({ limit: 1 });
            var nonces       = rm.listUsedNonces({ limit: 1 });

            // Get counts via the DB directly for efficiency
            var rootCount    = rm._db.prepare('SELECT COUNT(*) AS n FROM root_keys').get().n;
            var pubCount     = rm._db.prepare('SELECT COUNT(*) AS n FROM publishers').get().n;
            var chainCount   = rm._db.prepare('SELECT COUNT(*) AS n FROM grant_chain').get().n;
            var rateCount    = rm._db.prepare('SELECT COUNT(*) AS n FROM rate_limit').get().n;
            var nonceCount   = rm._db.prepare('SELECT COUNT(*) AS n FROM used_nonces WHERE exp >= ?').get(Date.now()).n;

            res.json({
                roots:        rootCount,
                publishers:   pubCount,
                grantEntries: chainCount,
                rateBuckets:  rateCount,
                activeNonces: nonceCount,
            });
        } catch (err) {
            res.status(500).json({ error: { code: 'StatsError', message: err.message } });
        }
    });

    // ── Roots ─────────────────────────────────────────────────────────────────
    app.get('/Safecloud/admin/api/roots', auth, function (req, res) {
        try {
            var limit  = Math.min(parseInt(req.query.limit)  || 100, 1000);
            var offset = parseInt(req.query.offset) || 0;
            res.json({ roots: rm.listRoots({ limit: limit, offset: offset }) });
        } catch (err) {
            res.status(500).json({ error: { code: 'RootsError', message: err.message } });
        }
    });

    app.get('/Safecloud/admin/api/roots/:cid', auth, function (req, res) {
        try {
            var cid   = req.params.cid;
            var rec   = rm.getRootKey(cid);
            if (!rec) return res.status(404).json({ error: { code: 'NotFound', message: 'rootCid not found' } });
            var chain = rm.getGrantChain(cid, { limit: 100 });
            res.json({
                rootCid:      cid,
                accessModel:  rec.accessModel,
                chain:        chain,
            });
        } catch (err) {
            res.status(500).json({ error: { code: 'RootDetailError', message: err.message } });
        }
    });

    // ── Publishers ────────────────────────────────────────────────────────────
    app.get('/Safecloud/admin/api/publishers', auth, function (req, res) {
        try {
            var limit  = Math.min(parseInt(req.query.limit)  || 100, 1000);
            var offset = parseInt(req.query.offset) || 0;
            res.json({ publishers: rm.listPublishers({ limit: limit, offset: offset }) });
        } catch (err) {
            res.status(500).json({ error: { code: 'PublishersError', message: err.message } });
        }
    });

    app.delete('/Safecloud/admin/api/publishers/:id', auth, function (req, res) {
        try {
            var ok = rm.deregisterPublisher(req.params.id);
            if (!ok) return res.status(404).json({ error: { code: 'NotFound', message: 'publisher not found' } });
            res.json({ deregistered: true, publisherId: req.params.id });
        } catch (err) {
            res.status(500).json({ error: { code: 'DeregisterError', message: err.message } });
        }
    });

    // ── Grant chain ───────────────────────────────────────────────────────────
    app.get('/Safecloud/admin/api/chain/:cid', auth, function (req, res) {
        try {
            var afterId = parseInt(req.query.afterId) || 0;
            var limit   = Math.min(parseInt(req.query.limit) || 100, 1000);
            var entries = rm.getGrantChain(req.params.cid, { afterId: afterId, limit: limit });
            res.json({ entries: entries });
        } catch (err) {
            res.status(500).json({ error: { code: 'ChainError', message: err.message } });
        }
    });

    app.post('/Safecloud/admin/api/chain/:cid', auth, function (req, res) {
        var body = req.body || {};
        try {
            var entry = rm.appendGrantEntry({
                rootCid:   req.params.cid,
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

    // ── Rate limits ───────────────────────────────────────────────────────────
    app.get('/Safecloud/admin/api/rate-limits', auth, function (req, res) {
        try {
            var limit    = Math.min(parseInt(req.query.limit) || 200, 1000);
            var offset   = parseInt(req.query.offset) || 0;
            var buckets  = rm.listRateLimits({ limit: limit, offset: offset });
            res.json({ buckets: buckets, capacity: rm._cfg.rateLimitCapacity });
        } catch (err) {
            res.status(500).json({ error: { code: 'RateLimitError', message: err.message } });
        }
    });

    app.delete('/Safecloud/admin/api/rate-limits/:bucket', auth, function (req, res) {
        try {
            var key = decodeURIComponent(req.params.bucket);
            var ok  = rm.resetRateLimit(key);
            if (!ok) return res.status(404).json({ error: { code: 'NotFound', message: 'bucket not found' } });
            res.json({ reset: true, bucketKey: key });
        } catch (err) {
            res.status(500).json({ error: { code: 'ResetError', message: err.message } });
        }
    });

    // ── Nonces ────────────────────────────────────────────────────────────────
    app.get('/Safecloud/admin/api/nonces', auth, function (req, res) {
        try {
            var limit  = Math.min(parseInt(req.query.limit) || 100, 1000);
            var offset = parseInt(req.query.offset) || 0;
            res.json({ nonces: rm.listUsedNonces({ limit: limit, offset: offset }) });
        } catch (err) {
            res.status(500).json({ error: { code: 'NoncesError', message: err.message } });
        }
    });
};

// ─── Constructor (ControlPanel is primarily a namespace) ──────────────────────

function ControlPanel() {}

module.exports = ControlPanel;
