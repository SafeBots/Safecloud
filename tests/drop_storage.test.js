/**
 * Drop storage: encrypted chunks in IndexedDB + watermark accumulation +
 * claim math — the logic behind drop-dashboard.html. Uses fake-indexeddb so
 * the browser storage layer runs in Node. Real AES-GCM via WebCrypto.
 *
 * What this covers: a Drop stores ciphertext it cannot read, accumulates the
 * latest watermark per payer, and computes claimable totals correctly.
 * What it can't cover: the actual Service Worker, the passkey (WebAuthn).
 */
require('fake-indexeddb/auto');
const { webcrypto } = require('crypto');
const crypto = webcrypto;

let pass = 0, fail = 0;
function check(n, c) { c ? (pass++, console.log('  \u2713', n)) : (fail++, console.log('  \u2717 FAIL:', n)); }

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('Q.Safecloud.Drops', 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      db.createObjectStore('chunks', { keyPath: 'cid' });
      db.createObjectStore('tokens', { autoIncrement: true });
      db.createObjectStore('meta');
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject(e.target.error);
  });
}
function put(db, store, val, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    const req = key !== undefined ? tx.objectStore(store).put(val, key) : tx.objectStore(store).put(val);
    req.onsuccess = () => resolve(); req.onerror = () => reject(req.error);
  });
}
function getAll(db, store) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(store, 'readonly').objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
  });
}

(async () => {
  const db = await idbOpen();

  // ── Drop stores an ENCRYPTED chunk it cannot read ──
  const plaintext = new TextEncoder().encode('secret video segment bytes');
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
  const cid = 'bafyChunk0';
  await put(db, 'chunks', { cid, ciphertext: Buffer.from(ct).toString('base64'),
    iv: Buffer.from(iv).toString('base64'), size: ct.length });

  const stored = await getAll(db, 'chunks');
  check('Drop stored the chunk', stored.length === 1 && stored[0].cid === cid);
  check('stored chunk is ciphertext (not readable plaintext)',
    Buffer.from(stored[0].ciphertext, 'base64').toString('utf8') !== 'secret video segment bytes');

  // The Drop, lacking the key, cannot decrypt (simulate: no key in its store)
  const meta = await getAll(db, 'meta');
  check('Drop holds no decryption key', meta.length === 0);

  // ── Watermark accumulation: latest max per payer ──
  const payerA = '0x' + 'a1'.repeat(20);
  const payerB = '0x' + 'b2'.repeat(20);
  // Tokens arrive out of order; dashboard must keep the HIGHEST per payer
  await put(db, 'tokens', { stm: { payer: payerA, max: '300' } });
  await put(db, 'tokens', { stm: { payer: payerA, max: '800' } });  // higher
  await put(db, 'tokens', { stm: { payer: payerA, max: '500' } });  // lower, ignore
  await put(db, 'tokens', { stm: { payer: payerB, max: '200' } });

  const tokens = await getAll(db, 'tokens');
  // Dashboard's exact accumulation logic
  const per = {};
  tokens.forEach(t => {
    const k = t.stm.payer.toLowerCase();
    if (!per[k] || BigInt(t.stm.max) > BigInt(per[k])) per[k] = t.stm.max;
  });
  let sum = 0n; Object.values(per).forEach(v => sum += BigInt(v));
  check('accumulates highest watermark per payer (A=800)', per[payerA.toLowerCase()] === '800');
  check('tracks multiple payers independently (B=200)', per[payerB.toLowerCase()] === '200');
  check('total accumulated = 1000 (800 + 200)', sum === 1000n);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
