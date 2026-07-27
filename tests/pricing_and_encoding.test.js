/**
 * Two pure-logic surfaces:
 *  A. _dropOfferPrice reliability curve (what a Drop gets paid) — exact
 *     values at score boundaries, monotonicity, and the min-price filter
 *     that decides whether a Drop is even offered the work.
 *  B. base64url manifest encode/decode round-trip (share links) — including
 *     unicode, and the URL-safety property (no +, /, = in output).
 */
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const PER_CHUNK_WEI_DEFAULT = '1000';

// ── A. Exact reliability curve from Jets.js ──
function dropOfferPrice(drop, publisherPrice) {
  const pubWei = BigInt(publisherPrice || PER_CHUNK_WEI_DEFAULT);
  const score = typeof drop.reliabilityScore === 'number'
    ? Math.min(1, Math.max(0, drop.reliabilityScore)) : 0.5;
  const factor = 0.5 + 0.5 * score;
  return BigInt(Math.floor(Number(pubWei) * factor));
}

section('A. Drop offer-price reliability curve');
check('score 1.0 → 100% of publisher price (1000)',
  dropOfferPrice({ reliabilityScore: 1.0 }, '1000') === 1000n);
check('score 0.5 → 75% (750)',
  dropOfferPrice({ reliabilityScore: 0.5 }, '1000') === 750n);
check('score 0.0 → 50% (500)',
  dropOfferPrice({ reliabilityScore: 0.0 }, '1000') === 500n);
check('missing score defaults to 0.5 → 750',
  dropOfferPrice({}, '1000') === 750n);
check('score clamps above 1.0 (1.5 treated as 1.0 → 1000)',
  dropOfferPrice({ reliabilityScore: 1.5 }, '1000') === 1000n);
check('score clamps below 0 (-0.3 treated as 0 → 500)',
  dropOfferPrice({ reliabilityScore: -0.3 }, '1000') === 500n);

// Monotonic: higher reliability never earns less
let mono = true, prev = 0n;
for (let s=0; s<=1.0001; s+=0.1) {
  const p = dropOfferPrice({ reliabilityScore: s }, '1000');
  if (p < prev) mono = false;
  prev = p;
}
check('offer price is monotonic non-decreasing in reliability', mono);

// The min-price filter (from selectDrops): a Drop is skipped if offer < its min
function dropAdmitted(drop, publisherPrice) {
  const offer = dropOfferPrice(drop, publisherPrice);
  const minPrice = BigInt(drop.minPerChunkWei || PER_CHUNK_WEI_DEFAULT);
  return offer >= minPrice;
}
check('reliable Drop (1.0) meeting full price is admitted',
  dropAdmitted({ reliabilityScore: 1.0, minPerChunkWei: '1000' }, '1000'));
check('flaky Drop (0.0, offered 500) demanding 800 is skipped',
  !dropAdmitted({ reliabilityScore: 0.0, minPerChunkWei: '800' }, '1000'));
check('flaky Drop (0.0, offered 500) accepting 400 is admitted',
  dropAdmitted({ reliabilityScore: 0.0, minPerChunkWei: '400' }, '1000'));

// ── B. base64url round-trip (share links) ──
section('B. base64url manifest encode/decode');
// Node polyfills for the browser btoa/atob the helper uses
global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
global.atob = (s) => Buffer.from(s, 'base64').toString('binary');
function jsonToB64url(obj) {
  const b64 = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
  return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlToJSON(s) {
  try { s = s.replace(/-/g,'+').replace(/_/g,'/'); while (s.length%4) s+='=';
    return JSON.parse(decodeURIComponent(escape(atob(s)))); } catch(e){ return null; }
}

const manifest = { rootCid:'bafyABC123', chunkCount:42, treeN:2, treeDepth:6,
  revenue:{ token:'0x'+'b0'.repeat(20), policy:{ payees:['0x'+'a1'.repeat(20)], fractions:[9000], dynamicBps:1000 } } };
const enc = jsonToB64url(manifest);
const dec = b64urlToJSON(enc);
check('manifest round-trips through base64url', JSON.stringify(dec) === JSON.stringify(manifest));
check('encoded form is URL-safe (no +, /, =)', !/[+/=]/.test(enc));

// Unicode content (titles, names)
const uni = { title:'日本語のビデオ 🎬', author:'Ünïcödé Nâmé', note:'emoji: 🔒🌐' };
check('unicode manifest round-trips exactly',
  JSON.stringify(b64urlToJSON(jsonToB64url(uni))) === JSON.stringify(uni));

// Corrupt input returns null (not a throw)
check('corrupt base64url returns null (no throw)', b64urlToJSON('!!!not-valid!!!') === null);
check('empty string handled gracefully', b64urlToJSON('') === null || typeof b64urlToJSON('') === 'object');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
