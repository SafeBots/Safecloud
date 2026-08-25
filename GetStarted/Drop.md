# Get Started: become a Drop

A **Drop** is a browser tab that stores encrypted chunks and earns Safebux for
serving them. You provide storage and bandwidth; you get paid per chunk served.

The chunks are encrypted, so **you cannot read what you host**, and because
they're addressed by hash, **nobody can force you to host any *particular*
content** — you just hold ciphertext.

---

## Steps

1. **Open the Drop page** on the Jet you want to serve, e.g.
   `https://jet.example.com/drop`.

2. **Tap the passkey prompt.** Your device creates a WebAuthn credential and
   your EVM address is *derived from it* — the same address every session, with
   nothing secret stored on disk. Clear your browser data and the passkey
   re-derives the identical address on that device.

3. **That's it — you're serving.** Keep the tab open. Install it as a PWA or
   accept the Wake Lock prompt so the browser doesn't discard the tab.

---

## Seeing your earnings

Open `drop-dashboard.html` on the same origin. It shows:

- chunks currently stored,
- accumulated (unclaimed) Safebux,
- lifetime claimed earnings.

Tokens accumulate **off-chain**, so watching them cost nothing and require no
gas.

---

## Claiming your Safebux

When you pass the claim threshold, two options:

- **Direct** — claim from the dashboard yourself. Needs a few cents of BNB for
  gas.
- **Relay** — ask the Jet to submit the claim for you. The Jet pays the gas and
  settles on-chain per your agreement; you sign the request, the Jet relays it.

Either way the money moves through the OpenClaiming contract, which pays you the
exact amount your accumulated tokens authorize — no more, enforced on-chain.

---

## Good to know

- **Reputation matters.** Serve reliably and you're routed more work. Claim to
  have huge storage and then fail to serve, and the Jet demotes you fast — a
  non-serving Drop drops to a fraction of traffic within a handful of failures.
- **Your identity is the passkey.** Losing the device means losing that Drop
  identity; the earned balance is on-chain and tied to the derived address.
