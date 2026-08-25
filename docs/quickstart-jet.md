# Run a Jet (5 minutes)

A Jet routes encrypted chunks between Drops and viewers, verifies payment
tokens, and settles micropayments on-chain. Permissionless — no registration.

**Two modes** (config only, no code change): *signature-only* runs with no
blockchain — payments are verified cryptographically, settlement is simply
skipped (great for demos and pilots; see `docs/demo.md`). *On-chain* adds
contract addresses and settlement activates (see `docs/deploy.md`). The
steps below are the same for both.

## Steps

1. **Install** (Node 18+):
   ```
   git clone <your-qbix-app> && cd <app> && npm install
   ```
2. **Start**:
   ```
   node server.js
   ```
   On first start the Jet **generates its own wallet**, saves it to
   `local/app.json` (mode 600), and prints the address. Back that file up.
3. **Fund** the printed address with **~0.01 BNB** (settlement gas).
4. **Verify**: open `https://your-host/Safecloud/health` — you should see
   `"signing": true` and your address. Dashboard: `/Safecloud/dashboard`.

## Config you may want (`local/app.json`)

```json
{ "Safecloud": {
    "requirePayment": true,
    "requireGrants": false,
    "safebux":      { "address": "0x…", "perChunkWei": "500" },
    "openclaiming": { "address": "0x…" },
    "sponsor": { "enabled": true, "maxWeiPerViewer": "100000" },
    "sponsorUrl": "/Safecloud/sponsor/token",
    "jet": { "minInfraBp": 500, "settleIntervalSec": 900 }
} }
```

- `requirePayment` — require a payment/sponsor token to fetch content
- `requireGrants` — require an access grant (private content); off = public
- `sponsor.enabled` — this server signs tokens for its viewers (web2 bridge)
- `minInfraBp` — reject policies paying infra less than this (bps of 10000)
- `settleIntervalSec` — auto-settlement cadence (0 disables)
- Omit `safebux`/`openclaiming` entirely → signature-only (no-chain) mode
- Faucet (testnet only): `"faucet": { "enabled": true, "wei": "1000000" }`

Earnings are one call away: `receivedTotal(safebux, jetAddress)` on
OpenClaiming — the dashboard shows it.
