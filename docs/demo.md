# Running a live demo (no blockchain)

Everything works except on-chain cash-out. Micropayments are real signed
tokens; dashboards show live earnings; sponsorship makes viewers walletless.
Allow ~20 minutes to rehearse.

## 1. Configure (once)

`local/app.json`:
```json
{ "Safecloud": {
    "requirePayment": true,
    "requireGrants": false,
    "sponsor": { "enabled": true, "maxWeiPerViewer": "100000" },
    "sponsorUrl": "/Safecloud/sponsor/token"
} }
```
No contract addresses — that's what puts it in signature-only mode.

## 2. Start the Jet

```
npm run jet
```
On first start it generates and saves a wallet and prints the address.
**You do not need to fund it** — nothing settles on-chain in this mode.

Verify: open `https://your-host/Safecloud/health` → `"signing": true`,
`"requirePayment": true`, `"sponsorUrl": "/Safecloud/sponsor/token"`.

## 3. Open the three tabs

1. **Drop** — `https://your-host/onboard-drop.html` → "Start serving" →
   tap the passkey. It's now storing and serving.
2. **Drop dashboard** — `https://your-host/drop-dashboard.html`. Keep it
   visible; this is where earnings climb live.
3. **Author/upload** — upload a short video through the Safecloud client
   (with a `revenue.policy` so the split shows). Grab the share link.

## 4. Run the arc

1. Open the share link in a fresh tab (or another device). It's the
   **viewer**.
2. Press play. The viewer requests a sponsor token automatically — it signs
   nothing, holds no wallet. The site (your Jet) is the payer.
3. Watch the **Drop dashboard**: "accumulated" climbs as chunks are served.
   These are real EIP-712 watermark tokens, verified cryptographically.
4. Open the **Jet dashboard** (`/Safecloud/dashboard`): the Drop appears,
   pending settlements count rises.
5. **The punchline**: keep watching until the sponsor cap
   (`maxWeiPerViewer`) is hit — the next token request returns HTTP 402,
   and the player falls back to asking the viewer to pay. That's the
   "free trial, then pay" funnel, live.

## 5. The one-line close

> "Every number you just saw climb is real signed value. The only thing
> the blockchain adds is where it cashes out — and that's one config line
> away."

To show that line: add `safebux.address` and `openclaiming.address` (from a
testnet deploy) and the same dashboards start settling on-chain, the
"claimed" figures move off "—".

## Gotchas

- **Don't restart the Jet mid-demo** — the upload index is in memory.
- **iPhone viewer**: iOS 17+. First play may need one reload (segments
  pre-warm on second visit).
- **Passphrase-protected share link**: have the 4 words ready; the link
  alone won't unlock it.
- Rehearse the whole arc once the day before. Your demo is then your
  second run, not your first.
