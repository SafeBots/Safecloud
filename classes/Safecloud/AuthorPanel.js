'use strict';
/**
 * AuthorPanel.js — Safecloud author control panel.
 *
 * Mounts an Express middleware that provides:
 *
 *   GET  /Safecloud/author/panel         → HTML single-page author panel
 *   GET  /Safecloud/author/panel/api/roots       → content roots associated with an author pub key
 *   GET  /Safecloud/author/panel/api/certs       → author certs already issued
 *   POST /Safecloud/author/panel/api/cert        → record a signed author cert for a publisher
 *   DELETE /Safecloud/author/panel/api/cert/:id  → revoke a cert (sets active=0)
 *
 * Existing upload routes at POST /Safecloud/author/upload are unaffected.
 *
 * Usage (in Jets.js listen()):
 *   var AuthorPanel = require('./AuthorPanel');
 *   AuthorPanel.registerRoutes(app, rm);
 *
 * @module AuthorPanel
 */

var crypto = require('crypto');

// ─── Shared auth helper ───────────────────────────────────────────────────────

/**
 * Verify that `sig` (hex) is a valid Ed25519 signature over SHA-256(payload)
 * made by the key with the given pubKeyHex (hex 32-byte raw Ed25519 public key).
 *
 * Returns true/false without throwing.
 */
function _verifyEd25519(payload, sig, pubKeyHex) {
    try {
        var pubRaw  = Buffer.from(pubKeyHex, 'hex');
        var hashBuf = crypto.createHash('sha256').update(payload, 'utf8').digest();
        // Node expects the full SPKI DER header for Ed25519 (44 bytes total)
        var SPKI_PREFIX = Buffer.from('302a300506032b657003210000', 'hex');
        // The standard SPKI prefix for Ed25519 is 12 bytes: 302a300506032b6570032100
        // then 1 byte 0x00 and 32 bytes key — 12 + 1 + 32 = 45. Let's build it properly.
        var header = Buffer.from('302a300506032b6570032100', 'hex');
        var spki   = Buffer.concat([header, pubRaw]);
        var pubKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
        return crypto.verify(null, hashBuf, pubKey, Buffer.from(sig, 'hex'));
    } catch (e) { return false; }
}

// ─── Author Panel HTML ────────────────────────────────────────────────────────

/* eslint-disable max-len */
var PANEL_HTML = '<!doctype html>\n<html lang="en">\n<head>\n' +
'<meta charset="utf-8">\n' +
'<meta name="viewport" content="width=device-width,initial-scale=1">\n' +
'<title>Safecloud Author Panel</title>\n' +
'<style>\n' +
':root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--danger:#f85149;--success:#3fb950;--warn:#d29922}\n' +
'@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--surface:#ffffff;--border:#d0d7de;--text:#1f2328;--muted:#636c76;--accent:#0969da;--danger:#cf222e;--success:#1a7f37;--warn:#9a6700}}\n' +
'*{box-sizing:border-box;margin:0;padding:0}\n' +
'html,body{overflow-x:hidden;max-width:100vw}\n' +
'body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}\n' +
'header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:14px}\n' +
'header h1{font-size:1rem;font-weight:600}\n' +
'header .pill{background:var(--accent);color:#fff;border-radius:9999px;padding:2px 10px;font-size:.75rem;font-weight:600}\n' +
'.main{max-width:900px;margin:0 auto;padding:24px 16px}\n' +
'.tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:20px;overflow-x:auto}\n' +
'.tab{padding:8px 16px;border:none;border-radius:6px 6px 0 0;background:transparent;color:var(--muted);cursor:pointer;font-size:.875rem;font-weight:500;white-space:nowrap}\n' +
'.tab.active{color:var(--accent);border-bottom:2px solid var(--accent)}\n' +
'.tab:hover:not(.active){color:var(--text)}\n' +
'.panel{display:none}.panel.active{display:block}\n' +
'.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}\n' +
'.card h3{font-size:.875rem;font-weight:600;margin-bottom:12px;color:var(--text)}\n' +
'table{width:100%;border-collapse:collapse}\n' +
'th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:var(--muted);font-weight:500;font-size:.8rem}\n' +
'td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle;word-break:break-all}\n' +
'tr:last-child td{border-bottom:none}\n' +
'.mono{font-family:ui-monospace,monospace;font-size:.75rem}\n' +
'.badge{display:inline-block;padding:1px 8px;border-radius:9999px;font-size:.75rem;font-weight:600}\n' +
'.badge-green{background:rgba(63,185,80,.15);color:var(--success)}\n' +
'.badge-red{background:rgba(248,81,73,.15);color:var(--danger)}\n' +
'.badge-blue{background:rgba(88,166,255,.15);color:var(--accent)}\n' +
'.badge-yellow{background:rgba(210,153,34,.15);color:var(--warn)}\n' +
'button{padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;font-size:.875rem}\n' +
'button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}\n' +
'button.primary:hover{opacity:.85}\n' +
'button.danger{color:var(--danger);border-color:var(--danger)}\n' +
'button.danger:hover{background:rgba(248,81,73,.1)}\n' +
'button:disabled{opacity:.4;cursor:default}\n' +
'.form-row{margin-bottom:12px}\n' +
'.form-row label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px}\n' +
'.form-row input,.form-row select,.form-row textarea{width:100%;padding:7px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:.875rem;font-family:inherit}\n' +
'.form-row textarea{font-family:ui-monospace,monospace;font-size:.75rem;resize:vertical;min-height:80px}\n' +
'.form-row input:focus,.form-row select:focus,.form-row textarea:focus{outline:none;border-color:var(--accent)}\n' +
'.empty{padding:24px;text-align:center;color:var(--muted);font-size:.875rem}\n' +
'.msg{padding:8px 12px;border-radius:6px;margin-bottom:12px;font-size:.875rem}\n' +
'.msg-ok{background:rgba(63,185,80,.12);color:var(--success);border:1px solid rgba(63,185,80,.2)}\n' +
'.msg-err{background:rgba(248,81,73,.12);color:var(--danger);border:1px solid rgba(248,81,73,.2)}\n' +
'.desc{font-size:.85rem;color:var(--muted);margin-bottom:16px;line-height:1.6;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px}\n' +
'.key-box{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:ui-monospace,monospace;font-size:.75rem;word-break:break-all;margin-top:6px;line-height:1.6}\n' +
'.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}\n' +
'details summary{cursor:pointer;color:var(--accent);font-size:.8rem;user-select:none}\n' +
'details pre{margin-top:6px;background:var(--bg);padding:8px;border-radius:4px;font-size:.72rem;overflow-x:auto}\n' +
'</style>\n' +
'</head>\n<body>\n' +
'<header>\n' +
'  <h1>Safecloud Author Panel</h1>\n' +
'  <span class="pill">Author</span>\n' +
'  <span style="margin-left:auto;font-size:.8rem;color:var(--muted)" id="key-status">No keypair loaded</span>\n' +
'</header>\n' +
'<div class="main">\n' +
'  <div class="tabs">\n' +
'    <button class="tab active" data-tab="keypair">Keypair</button>\n' +
'    <button class="tab" data-tab="roots">My Content</button>\n' +
'    <button class="tab" data-tab="issue">Issue Cert</button>\n' +
'    <button class="tab" data-tab="certs">Issued Certs</button>\n' +
'  </div>\n' +
'\n' +
'  <!-- Keypair Tab -->\n' +
'  <div class="panel active" id="tab-keypair">\n' +
'    <div class="desc">Your <strong>author keypair</strong> is an Ed25519 key stored only in this browser. The <em>public key</em> is embedded in content you upload; the <em>private key</em> signs publisher certs. Never share your private key.</div>\n' +
'    <div id="kp-msg"></div>\n' +
'    <div class="card">\n' +
'      <h3>Public Key</h3>\n' +
'      <div class="key-box" id="pub-display">—</div>\n' +
'      <div class="actions">\n' +
'        <button class="primary" id="btn-gen">Generate New Keypair</button>\n' +
'        <button id="btn-import">Import Private Key</button>\n' +
'        <button id="btn-export">Export Private Key</button>\n' +
'        <button class="danger" id="btn-delete">Delete Keypair</button>\n' +
'      </div>\n' +
'    </div>\n' +
'    <div class="card" id="import-form" style="display:none">\n' +
'      <h3>Import Private Key</h3>\n' +
'      <div class="form-row"><label>Paste hex private key (64 hex chars)</label><input id="import-hex" type="password" placeholder="ed25519 private key hex..."></div>\n' +
'      <div class="actions"><button class="primary" id="btn-import-confirm">Import</button><button id="btn-import-cancel">Cancel</button></div>\n' +
'    </div>\n' +
'  </div>\n' +
'\n' +
'  <!-- My Content Tab -->\n' +
'  <div class="panel" id="tab-roots">\n' +
'    <div class="desc">Content roots associated with your public key. Each root CID identifies one piece of content you have published.</div>\n' +
'    <div id="roots-msg"></div>\n' +
'    <div id="roots-table"><div class="empty">Load keypair first, then refresh.</div></div>\n' +
'    <div class="actions"><button id="btn-load-roots">Refresh</button></div>\n' +
'  </div>\n' +
'\n' +
'  <!-- Issue Cert Tab -->\n' +
'  <div class="panel" id="tab-issue">\n' +
'    <div class="desc">Issue a <strong>publisher cert</strong> — a signed claim authorising a specific publisher to serve your content. The cert is an OCP claim signed with your private key. You can restrict it to one root CID or grant it across all your roots.</div>\n' +
'    <div id="issue-msg"></div>\n' +
'    <div class="card">\n' +
'      <div class="form-row"><label>Publisher ID (domain)</label><input id="f-pid" placeholder="publisher.example.com"></div>\n' +
'      <div class="form-row"><label>Root CID (leave blank for all roots)</label><input id="f-root" placeholder="bafyroots... (optional)"></div>\n' +
'      <div class="form-row"><label>Expires (days, 0 = no expiry)</label><input id="f-exp" type="number" min="0" value="365"></div>\n' +
'      <div class="form-row"><label>Notes (optional)</label><input id="f-notes" placeholder="e.g. distribution agreement 2026"></div>\n' +
'      <div class="actions">\n' +
'        <button class="primary" id="btn-issue">Sign & Submit</button>\n' +
'      </div>\n' +
'    </div>\n' +
'    <div id="cert-preview" style="display:none" class="card">\n' +
'      <h3>Signed Cert (JSON)</h3>\n' +
'      <details><summary>Show raw claim</summary><pre id="cert-json"></pre></details>\n' +
'      <div class="actions"><button id="btn-copy-cert">Copy JSON</button><button id="btn-dl-cert">Download .json</button></div>\n' +
'    </div>\n' +
'  </div>\n' +
'\n' +
'  <!-- Issued Certs Tab -->\n' +
'  <div class="panel" id="tab-certs">\n' +
'    <div class="desc">Publisher certs you have issued from this Jet. Revoked certs are marked inactive — publishers presenting a revoked cert will be refused.</div>\n' +
'    <div id="certs-msg"></div>\n' +
'    <div id="certs-table"><div class="empty">No certs recorded on this Jet.</div></div>\n' +
'    <div class="actions"><button id="btn-load-certs">Refresh</button></div>\n' +
'  </div>\n' +
'\n' +
'</div>\n' +
'<script>\n' +
'(function(){\n' +
'"use strict";\n' +
// ── Tab switching ──────────────────────────────────────────────────────────
'var tabs=document.querySelectorAll(".tab");\n' +
'tabs.forEach(function(t){\n' +
'  t.addEventListener("click",function(){\n' +
'    tabs.forEach(function(x){x.classList.remove("active");});\n' +
'    document.querySelectorAll(".panel").forEach(function(p){p.classList.remove("active");});\n' +
'    t.classList.add("active");\n' +
'    document.getElementById("tab-"+t.dataset.tab).classList.add("active");\n' +
'  });\n' +
'});\n' +
// ── Keypair state (localStorage) ──────────────────────────────────────────
'var _privHex=null,_pubHex=null;\n' +
'function _loadKp(){\n' +
'  try{var s=localStorage.getItem("sc_author_kp");if(!s)return;\n' +
'  var d=JSON.parse(s);_privHex=d.priv;_pubHex=d.pub;_refreshKpUi();}\n' +
'  catch(e){}\n' +
'}\n' +
'function _saveKp(){try{localStorage.setItem("sc_author_kp",JSON.stringify({priv:_privHex,pub:_pubHex}));}catch(e){}}\n' +
'function _clearKp(){_privHex=null;_pubHex=null;try{localStorage.removeItem("sc_author_kp");}catch(e){}}\n' +
'function _refreshKpUi(){\n' +
'  var el=document.getElementById("pub-display");\n' +
'  var st=document.getElementById("key-status");\n' +
'  if(_pubHex){el.textContent=_pubHex;st.textContent="Keypair loaded";st.style.color="var(--success)";}\n' +
'  else{el.textContent="—";st.textContent="No keypair loaded";st.style.color="";}\n' +
'}\n' +
// ── Generate keypair ───────────────────────────────────────────────────────
'document.getElementById("btn-gen").addEventListener("click",async function(){\n' +
'  if(_pubHex&&!confirm("Replace the existing keypair? The old private key cannot be recovered."))return;\n' +
'  var kp=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);\n' +
'  var privJwk=await crypto.subtle.exportKey("jwk",kp.privateKey);\n' +
'  var spki=await crypto.subtle.exportKey("spki",kp.publicKey);\n' +
// Raw Ed25519 pub is last 32 bytes of SPKI (44 bytes total)
'  var spkiArr=new Uint8Array(spki);\n' +
'  _pubHex=Array.from(spkiArr.slice(-32)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");\n' +
// Store private key as the raw 32-byte d (from JWK base64url → hex)
'  var privB64u=privJwk.d;\n' +
'  var privBin=atob(privB64u.replace(/-/g,"+").replace(/_/g,"/"));\n' +
'  _privHex=Array.from(privBin).map(function(c){return c.charCodeAt(0).toString(16).padStart(2,"0");}).join("");\n' +
'  _saveKp();_refreshKpUi();\n' +
'  _msg("kp-msg","Keypair generated. Keep the private key safe!","ok");\n' +
'});\n' +
// ── Export ─────────────────────────────────────────────────────────────────
'document.getElementById("btn-export").addEventListener("click",function(){\n' +
'  if(!_privHex){_msg("kp-msg","No keypair loaded.","err");return;}\n' +
'  var blob=new Blob([JSON.stringify({pub:_pubHex,priv:_privHex},null,2)],{type:"application/json"});\n' +
'  var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="safecloud-author-key.json";a.click();\n' +
'});\n' +
// ── Delete ─────────────────────────────────────────────────────────────────
'document.getElementById("btn-delete").addEventListener("click",function(){\n' +
'  if(!confirm("Delete keypair from browser? Make sure you have a backup."))return;\n' +
'  _clearKp();_refreshKpUi();\n' +
'});\n' +
// ── Import ─────────────────────────────────────────────────────────────────
'document.getElementById("btn-import").addEventListener("click",function(){\n' +
'  document.getElementById("import-form").style.display="";\n' +
'});\n' +
'document.getElementById("btn-import-cancel").addEventListener("click",function(){\n' +
'  document.getElementById("import-form").style.display="none";\n' +
'});\n' +
'document.getElementById("btn-import-confirm").addEventListener("click",async function(){\n' +
'  var hex=document.getElementById("import-hex").value.trim();\n' +
'  if(!/^[0-9a-f]{64}$/i.test(hex)){_msg("kp-msg","Invalid hex — must be 64 hex chars (32-byte Ed25519 private key).","err");return;}\n' +
'  try{\n' +
// Import from raw 32-byte d value as JWK
'    var d=btoa(Array.from(hex.match(/.{2}/g).map(function(h){return parseInt(h,16);})).map(function(c){return String.fromCharCode(c);}).join("")).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");\n' +
// We need the public key point too — but SubtleCrypto Ed25519 importKey with JWK "OKP" needs both d and x, or we can importKey from pkcs8
// The easiest: use raw format "raw" for public key then derive from private
// Actually for Ed25519 SubtleCrypto: import private key from "jwk" with d, derive public
// But subtle can't just import d alone without x — we need pkcs8 format or the full JWK with x
// Alternative: import from pkcs8 (which embeds d inside a DER structure)
// Let's build a minimal pkcs8 for Ed25519 from just d (32 bytes)
// PKCS8 structure for Ed25519 private key: 48 bytes total
// 302e 020100 300506032b6570 0422 0420 <32-byte-d>
'    var privBytes=hex.match(/.{2}/g).map(function(h){return parseInt(h,16);});\n' +
'    var pkcs8Header=[0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20];\n' +
'    var pkcs8=new Uint8Array(pkcs8Header.concat(privBytes));\n' +
'    var privKey=await crypto.subtle.importKey("pkcs8",pkcs8,{name:"Ed25519"},true,["sign"]);\n' +
'    var privJwk=await crypto.subtle.exportKey("jwk",privKey);\n' +
// Get the public key: for Ed25519 the x field in JWK is the public key
'    var xB64u=privJwk.x;\n' +
'    var xBin=atob(xB64u.replace(/-/g,"+").replace(/_/g,"/"));\n' +
'    _pubHex=Array.from(xBin).map(function(c){return c.charCodeAt(0).toString(16).padStart(2,"0");}).join("");\n' +
'    _privHex=hex.toLowerCase();\n' +
'    _saveKp();_refreshKpUi();\n' +
'    document.getElementById("import-form").style.display="none";\n' +
'    _msg("kp-msg","Keypair imported.","ok");\n' +
'  }catch(e){_msg("kp-msg","Import failed: "+e.message,"err");}\n' +
'});\n' +
// ── My Roots ───────────────────────────────────────────────────────────────
'document.getElementById("btn-load-roots").addEventListener("click",_loadRoots);\n' +
'async function _loadRoots(){\n' +
'  if(!_pubHex){_msg("roots-msg","Load a keypair first.","err");return;}\n' +
'  var r=await fetch("./panel/api/roots?authorPubKey="+encodeURIComponent(_pubHex));\n' +
'  var d=await r.json();if(!r.ok){_msg("roots-msg",d.error||"Error","err");return;}\n' +
'  var rows=d.roots;var el=document.getElementById("roots-table");\n' +
'  if(!rows||!rows.length){el.innerHTML=\'<div class="empty">No content roots found for this public key.</div>\';return;}\n' +
'  el.innerHTML=\'<table><thead><tr><th>Root CID</th><th>Access Model</th><th>Registered</th></tr></thead><tbody>\'+\n' +
'  rows.map(function(r){return\'<tr><td class="mono">\'+r.rootCid+\'</td><td>\'+\n' +
'  (r.accessModel?JSON.stringify(r.accessModel):"—")+\'</td><td>\'+new Date(r.registeredAt).toLocaleString()+\'</td></tr>\';}).join("")+\n' +
'  \'</tbody></table>\';\n' +
'}\n' +
// ── Issue Cert ─────────────────────────────────────────────────────────────
'var _lastCertJson=null;\n' +
'document.getElementById("btn-issue").addEventListener("click",async function(){\n' +
'  if(!_privHex||!_pubHex){_msg("issue-msg","Load a keypair first.","err");return;}\n' +
'  var pid=document.getElementById("f-pid").value.trim();\n' +
'  var root=document.getElementById("f-root").value.trim()||null;\n' +
'  var expDays=parseInt(document.getElementById("f-exp").value)||0;\n' +
'  var notes=document.getElementById("f-notes").value.trim()||null;\n' +
'  if(!pid){_msg("issue-msg","Publisher ID required.","err");return;}\n' +
'  var now=Math.floor(Date.now()/1000);\n' +
'  var exp=expDays>0?now+expDays*86400:0;\n' +
'  var stm={publisherId:pid};\n' +
'  if(root)stm.rootCid=root;\n' +
'  if(notes)stm.notes=notes;\n' +
'  var claim={ocp:1,iss:"data:key/ed25519;hex,"+_pubHex,sub:pid,stm:stm,nbf:now,exp:exp};\n' +
// Canonicalize (sorted keys) and sign
'  var keys=Object.keys(claim).sort();\n' +
'  var canon=JSON.stringify(keys.reduce(function(o,k){o[k]=claim[k];return o;},{}),"utf8");\n' +
'  try{\n' +
'    var privBytes2=_privHex.match(/.{2}/g).map(function(h){return parseInt(h,16);});\n' +
'    var pkcs8Header2=[0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20];\n' +
'    var pkcs8b2=new Uint8Array(pkcs8Header2.concat(privBytes2));\n' +
'    var pKey2=await crypto.subtle.importKey("pkcs8",pkcs8b2,{name:"Ed25519"},false,["sign"]);\n' +
// Hash the canonical bytes with SHA-256 first (matching OCP §3)
'    var hashBuf2=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canon));\n' +
'    var sigBuf2=await crypto.subtle.sign({name:"Ed25519"},pKey2,hashBuf2);\n' +
'    var sigHex2=Array.from(new Uint8Array(sigBuf2)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");\n' +
'    claim.sig=sigHex2;\n' +
'    _lastCertJson=JSON.stringify(claim,null,2);\n' +
'    document.getElementById("cert-json").textContent=_lastCertJson;\n' +
'    document.getElementById("cert-preview").style.display="";\n' +
// Submit to Jet
'    var resp=await fetch("./panel/api/cert",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({claim:claim})});\n' +
'    var rd=await resp.json();\n' +
'    if(!resp.ok){_msg("issue-msg","Cert signed but Jet rejected it: "+(rd.error||resp.status),"err");return;}\n' +
'    _msg("issue-msg","Cert issued and recorded (id "+rd.id+").","ok");\n' +
'  }catch(e){_msg("issue-msg","Signing failed: "+e.message,"err");}\n' +
'});\n' +
'document.getElementById("btn-copy-cert").addEventListener("click",function(){\n' +
'  if(!_lastCertJson)return;\n' +
'  navigator.clipboard.writeText(_lastCertJson).catch(function(){});\n' +
'});\n' +
'document.getElementById("btn-dl-cert").addEventListener("click",function(){\n' +
'  if(!_lastCertJson)return;\n' +
'  var blob=new Blob([_lastCertJson],{type:"application/json"});\n' +
'  var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="publisher-cert.json";a.click();\n' +
'});\n' +
// ── Issued Certs ───────────────────────────────────────────────────────────
'document.getElementById("btn-load-certs").addEventListener("click",_loadCerts);\n' +
'async function _loadCerts(){\n' +
'  if(!_pubHex){_msg("certs-msg","Load a keypair first.","err");return;}\n' +
'  var r=await fetch("./panel/api/certs?authorPubKey="+encodeURIComponent(_pubHex));\n' +
'  var d=await r.json();if(!r.ok){_msg("certs-msg",d.error||"Error","err");return;}\n' +
'  var rows=d.certs;var el=document.getElementById("certs-table");\n' +
'  if(!rows||!rows.length){el.innerHTML=\'<div class="empty">No certs recorded for this key.</div>\';return;}\n' +
'  el.innerHTML=\'<table><thead><tr><th>ID</th><th>Publisher</th><th>Root CID</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>\'+\n' +
'  rows.map(function(r){\n' +
'    var exp=r.expiresAt?new Date(r.expiresAt*1000).toLocaleDateString():"never";\n' +
'    var badge=r.active?\'<span class="badge badge-green">active</span>\':\'<span class="badge badge-red">revoked</span>\';\n' +
'    var revokeBtn=r.active?\'<button onclick="revokeCert(\'+r.id+\')" class="danger" style="padding:3px 10px;font-size:.8rem">Revoke</button>\':\'\';' +
'    return\'<tr><td class="mono">\'+r.id+\'</td><td>\'+r.publisherId+\'</td><td class="mono">\'+\n' +
'    (r.rootCid||"<em>all</em>")+\'</td><td>\'+exp+\'</td><td>\'+badge+\'</td><td>\'+revokeBtn+\'</td></tr>\';\n' +
'  }).join("")+\'</tbody></table>\';\n' +
'}\n' +
'window.revokeCert=async function(id){\n' +
'  if(!confirm("Revoke cert "+id+"? Publishers holding this cert will be refused."))return;\n' +
'  var r=await fetch("./panel/api/cert/"+id,{method:"DELETE"});\n' +
'  var d=await r.json();\n' +
'  if(!r.ok){_msg("certs-msg",d.error||"Error","err");return;}\n' +
'  _msg("certs-msg","Cert "+id+" revoked.","ok");_loadCerts();\n' +
'};\n' +
// ── Helpers ────────────────────────────────────────────────────────────────
'function _msg(id,text,kind){\n' +
'  var el=document.getElementById(id);\n' +
'  el.innerHTML=\'<div class="msg msg-\'+kind+\'">\'+text+\'</div>\';\n' +
'  setTimeout(function(){el.innerHTML="";},8000);\n' +
'}\n' +
'_loadKp();\n' +
'})();\n' +
'</script>\n' +
'</body>\n</html>\n';
/* eslint-enable max-len */

// ─── Route registration ───────────────────────────────────────────────────────

/**
 * Register author panel routes on an Express app.
 *
 * @param {object} app  Express app
 * @param {object} rm   RightsManagement instance
 */
AuthorPanel.registerRoutes = function (app, rm) {
    // ── GET /Safecloud/author/panel → HTML ────────────────────────────────────
    app.get('/Safecloud/author/panel', function (req, res) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(PANEL_HTML);
    });

    // ── GET /Safecloud/author/panel/api/roots?authorPubKey=hex ───────────────
    app.get('/Safecloud/author/panel/api/roots', function (req, res) {
        var pubHex = req.query.authorPubKey;
        if (!pubHex || !/^[0-9a-f]{64}$/i.test(pubHex)) {
            return res.status(400).json({ error: 'authorPubKey (64-hex Ed25519) required' });
        }
        try {
            var rows = rm._db.prepare(
                'SELECT root_cid, access_model, creator_id, registered_at FROM root_keys WHERE creator_id = ?'
            ).all(pubHex);
            res.json({ roots: rows.map(function (r) {
                return {
                    rootCid:      r.root_cid,
                    accessModel:  r.access_model ? JSON.parse(r.access_model) : null,
                    creatorId:    r.creator_id,
                    registeredAt: r.registered_at
                };
            }) });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // ── GET /Safecloud/author/panel/api/certs?authorPubKey=hex ───────────────
    app.get('/Safecloud/author/panel/api/certs', function (req, res) {
        var pubHex = req.query.authorPubKey;
        if (!pubHex || !/^[0-9a-f]{64}$/i.test(pubHex)) {
            return res.status(400).json({ error: 'authorPubKey (64-hex Ed25519) required' });
        }
        try {
            var rows = rm._db.prepare(
                'SELECT id, publisher_id, root_cid, issued_at, expires_at, active FROM author_certs WHERE author_pub_hex = ? ORDER BY id DESC'
            ).all(pubHex);
            res.json({ certs: rows.map(function (r) {
                return {
                    id:          r.id,
                    publisherId: r.publisher_id,
                    rootCid:     r.root_cid || null,
                    issuedAt:    r.issued_at,
                    expiresAt:   r.expires_at || null,
                    active:      r.active !== 0
                };
            }) });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // ── POST /Safecloud/author/panel/api/cert ─────────────────────────────────
    // Body: { claim: { ocp, iss, sub, stm, nbf, exp, sig } }
    // The claim is an OCP claim signed by the author's Ed25519 key.
    // iss = "data:key/ed25519;hex,<pubKeyHex>"
    // sub = publisherId
    // stm.publisherId = publisherId, stm.rootCid (optional)
    app.post('/Safecloud/author/panel/api/cert', function (req, res) {
        var claim = req.body && req.body.claim;
        if (!claim || claim.ocp !== 1 || !claim.sig) {
            return res.status(400).json({ error: 'Valid OCP claim required' });
        }

        // Parse issuer pub key
        var issMatch = typeof claim.iss === 'string' && claim.iss.match(/^data:key\/ed25519;hex,([0-9a-f]{64})$/i);
        if (!issMatch) {
            return res.status(400).json({ error: 'iss must be data:key/ed25519;hex,<64hexchars>' });
        }
        var pubHex = issMatch[1].toLowerCase();
        var pid    = typeof claim.sub === 'string' ? claim.sub : null;
        if (!pid) { return res.status(400).json({ error: 'sub (publisherId) required' }); }

        // Verify signature
        var unsigned = Object.assign({}, claim);
        delete unsigned.sig;
        var keys     = Object.keys(unsigned).sort();
        var canon    = JSON.stringify(keys.reduce(function (o, k) { o[k] = unsigned[k]; return o; }, {}));
        if (!_verifyEd25519(canon, claim.sig, pubHex)) {
            return res.status(403).json({ error: 'Signature verification failed' });
        }

        // Check expiry
        var now = Math.floor(Date.now() / 1000);
        if (claim.exp && claim.exp < now) {
            return res.status(400).json({ error: 'Cert is already expired' });
        }

        var rootCid   = (claim.stm && claim.stm.rootCid) || null;
        var issuedAt  = now;
        var expiresAt = claim.exp || null;
        var claimJson = JSON.stringify(claim);

        try {
            var ins = rm._db.prepare(
                'INSERT INTO author_certs (author_pub_hex, publisher_id, root_cid, issued_at, expires_at, claim_json, active)' +
                ' VALUES (?, ?, ?, ?, ?, ?, 1)'
            ).run(pubHex, pid, rootCid, issuedAt, expiresAt, claimJson);
            res.json({ ok: true, id: ins.lastInsertRowid });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });

    // ── DELETE /Safecloud/author/panel/api/cert/:id ───────────────────────────
    app.delete('/Safecloud/author/panel/api/cert/:id', function (req, res) {
        var id = parseInt(req.params.id, 10);
        if (!id) { return res.status(400).json({ error: 'Invalid cert id' }); }
        try {
            rm._db.prepare('UPDATE author_certs SET active = 0 WHERE id = ?').run(id);
            res.json({ ok: true, revoked: id });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    });
};

function AuthorPanel() {}

module.exports = AuthorPanel;
