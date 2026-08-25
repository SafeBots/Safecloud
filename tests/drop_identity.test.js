/**
 * Drop identity determinism (WebAuthn PRF → stable EVM address).
 *
 * The exact chain uses Q.Crypto.delegate/internalKeypair (platform-only, not
 * loadable here), but the SAFETY INVARIANT it must satisfy is testable with
 * the equivalent derivation shape:
 *   sameseed PRF  → SAME address every time (identity survives data-clear)
 *   differentseed → DIFFERENT address (no collision between Drops)
 *   derived key   → valid, usable EVM signing key
 * This mirrors the derivation contract the platform functions must honor.
 */
const ethers = require('ethers');
const { webcrypto } = require('crypto');
const crypto = webcrypto;
let pass=0, fail=0;
function check(n,c){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n)); }

// Derivation shape: PRF → HKDF(domain-separated) → keccak → secp256k1 scalar → address
// (mirrors: delegate('safecloud.drop.identity') → internalKeypair('EIP712'))
async function deriveEvmFromPrf(prfOutput) {
  const salt = new Uint8Array(32);
  const info = new TextEncoder().encode('safecloud.drop.identity');
  const key = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits']);
  const identitySecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt, info }, key, 256));
  // Domain-separate EIP712 keypair (mirrors internalKeypair format:'EIP712')
  const scalar = ethers.keccak256(ethers.concat([identitySecret, ethers.toUtf8Bytes('EIP712')]));
  const wallet = new ethers.Wallet(scalar);
  return wallet.address;
}

(async () => {
  const prfA = crypto.getRandomValues(new Uint8Array(32)); // device A's passkey PRF
  const prfB = crypto.getRandomValues(new Uint8Array(32)); // device B's passkey PRF

  // ── Determinism: same PRF → same address, every time ──
  const a1 = await deriveEvmFromPrf(prfA);
  const a2 = await deriveEvmFromPrf(prfA);
  const a3 = await deriveEvmFromPrf(prfA);
  check('same passkey PRF derives identical EVM address (call 1==2)', a1 === a2);
  check('same passkey PRF derives identical EVM address (2==3)', a2 === a3);
  check('derived address is a valid checksummed EVM address', ethers.isAddress(a1));

  // ── This is the "clear browser data, keep identity" guarantee ──
  // Simulate a full state wipe: nothing cached, only the passkey remains.
  const afterWipe = await deriveEvmFromPrf(prfA);
  check('identity survives a full IndexedDB wipe (re-derives same address)', afterWipe === a1);

  // ── No collision: different passkeys → different addresses ──
  const b1 = await deriveEvmFromPrf(prfB);
  check('different passkey → different EVM address', b1 !== a1);

  // ── The derived key actually works (can sign) ──
  const salt = new Uint8Array(32);
  const info = new TextEncoder().encode('safecloud.drop.identity');
  const k = await crypto.subtle.importKey('raw', prfA, 'HKDF', false, ['deriveBits']);
  const idSecret = new Uint8Array(await crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt, info }, k, 256));
  const scalar = ethers.keccak256(ethers.concat([idSecret, ethers.toUtf8Bytes('EIP712')]));
  const wallet = new ethers.Wallet(scalar);
  const sig = await wallet.signMessage('drop-claim-test');
  check('derived key can sign, recovers to derived address',
    ethers.verifyMessage('drop-claim-test', sig) === a1);

  // ── Avalanche: a 1-bit PRF change yields a completely different address ──
  const prfNear = new Uint8Array(prfA); prfNear[0] ^= 0x01;
  const near = await deriveEvmFromPrf(prfNear);
  check('1-bit PRF change → different address (no weak derivation)', near !== a1);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
