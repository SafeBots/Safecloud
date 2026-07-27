/**
 * Split-entropy share-link key recovery. Mirrors the author's split (in
 * createShareLink) and the player's recoverSplitKey (web/player.js) using
 * REAL WebCrypto HKDF-SHA256. The safety property: recovered key === original
 * root key, exactly. A bug here means shared videos never decrypt.
 *
 * Scheme: rootKey = HKDF(token || passphrase, salt, 'safecloud.splitkey.v1') XOR mask
 *   - token: random, travels in the URL (#st=)
 *   - mask:  random, also in the URL (#sm=)  [link-only mode]
 *   - passphrase: optional, communicated out-of-band [passphrase mode]
 * Author picks mask = HKDF(token||pass) XOR rootKey so recovery is exact.
 */
const { webcrypto } = require('crypto');
const crypto = webcrypto;
let pass=0, fail=0;
function check(n,c){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n)); }

function toB64(u){ return Buffer.from(u).toString('base64'); }
function fromB64(s){ return new Uint8Array(Buffer.from(s,'base64')); }
function toHex(u){ return Buffer.from(u).toString('hex'); }

async function hkdf(ikm, infoStr, length) {
  const salt = new Uint8Array(32); // fixed salt (matches player: r[0])
  const info = new TextEncoder().encode(infoStr);
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt, info }, key, length*8);
  return new Uint8Array(bits);
}

// Author side: given rootKey + token + passphrase, compute the mask
async function authorSplit(rootKey, token, passphrase) {
  const passBytes = new TextEncoder().encode(passphrase || '');
  const ikm = new Uint8Array(token.length + passBytes.length);
  ikm.set(token, 0); ikm.set(passBytes, token.length);
  const derived = await hkdf(ikm, 'safecloud.splitkey.v1', 32);
  const mask = new Uint8Array(32);
  for (let i=0;i<32;i++) mask[i] = derived[i] ^ rootKey[i];  // mask = derived XOR rootKey
  return mask;
}

// Player side: recoverSplitKey (copied logic from web/player.js)
async function recoverSplitKey(tokenHex, maskB64, passphrase) {
  const token = new Uint8Array(tokenHex.match(/.{2}/g).map(h=>parseInt(h,16)));
  const mask = fromB64(maskB64);
  const passBytes = new TextEncoder().encode(passphrase || '');
  const ikm = new Uint8Array(token.length + passBytes.length);
  ikm.set(token, 0); ikm.set(passBytes, token.length);
  const derived = await hkdf(ikm, 'safecloud.splitkey.v1', 32);
  const rootKeyBytes = new Uint8Array(32);
  for (let j=0;j<32;j++) rootKeyBytes[j] = derived[j] ^ mask[j];
  return toB64(rootKeyBytes);
}

(async () => {
  // ── Link-only mode (no passphrase) ──
  const rootKey = crypto.getRandomValues(new Uint8Array(32));
  const token = crypto.getRandomValues(new Uint8Array(16));
  const mask = await authorSplit(rootKey, token, '');
  const recovered = await recoverSplitKey(toHex(token), toB64(mask), '');
  check('link-only: recovered key === original root key', recovered === toB64(rootKey));

  // ── Passphrase mode ──
  const rootKey2 = crypto.getRandomValues(new Uint8Array(32));
  const token2 = crypto.getRandomValues(new Uint8Array(16));
  const pass2 = 'correct horse battery staple';
  const mask2 = await authorSplit(rootKey2, token2, pass2);
  const rec2 = await recoverSplitKey(toHex(token2), toB64(mask2), pass2);
  check('passphrase: correct passphrase recovers exact key', rec2 === toB64(rootKey2));

  // ── Wrong passphrase must NOT recover the key ──
  const recWrong = await recoverSplitKey(toHex(token2), toB64(mask2), 'wrong passphrase');
  check('passphrase: wrong passphrase does NOT recover key', recWrong !== toB64(rootKey2));

  // ── Tampered token must NOT recover ──
  const badToken = crypto.getRandomValues(new Uint8Array(16));
  const recBadTok = await recoverSplitKey(toHex(badToken), toB64(mask2), pass2);
  check('tampered URL token does NOT recover key', recBadTok !== toB64(rootKey2));

  // ── Tampered mask must NOT recover ──
  const badMask = crypto.getRandomValues(new Uint8Array(32));
  const recBadMask = await recoverSplitKey(toHex(token2), toB64(badMask), pass2);
  check('tampered mask does NOT recover key', recBadMask !== toB64(rootKey2));

  // ── The actual decryption works with the recovered key (full loop) ──
  const plaintext = new TextEncoder().encode('the actual video bytes');
  const importedRoot = await crypto.subtle.importKey('raw', rootKey, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, importedRoot, plaintext);
  // Recover key, import, decrypt
  const recKeyBytes = fromB64(await recoverSplitKey(toHex(token), toB64(mask), ''));
  const recImported = await crypto.subtle.importKey('raw', recKeyBytes, 'AES-GCM', false, ['decrypt']);
  const dec = new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv }, recImported, ct));
  check('full loop: content encrypted with root key decrypts with recovered key',
    new TextDecoder().decode(dec) === 'the actual video bytes');

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
