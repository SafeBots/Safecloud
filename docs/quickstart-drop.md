# Become a Drop (1 minute)

A Drop stores encrypted chunks in the browser and earns Safebux for serving
them. Chunks are encrypted — you cannot read what you host, and nobody can
cherry-pick content.

## Steps

1. **Open the Drop page** on the Jet you want to serve
   (e.g. `https://jet.example.com/drop`).
2. **Tap the passkey prompt.** Your device creates a WebAuthn credential;
   your EVM address is *derived from it* — same address every session,
   nothing secret stored anywhere.
3. That's it. You're storing and serving. Keep the tab open (install as a
   PWA or allow the Wake Lock prompt to avoid tab discard).

## Seeing your earnings

Open `drop-dashboard.html` on the same origin: chunks stored, accumulated
(unclaimed) Safebux, and lifetime claimed earnings.

## Claiming

Tokens accumulate off-chain (no gas). When you pass the claim threshold:
- **Direct**: claim from the dashboard — needs a few cents of BNB, or
- **Relay**: ask the Jet to submit for you (it pays gas, per your agreement).

Your identity lives in the passkey. Clearing site data forgets the *state*
but the passkey re-derives the same address on the same device.
