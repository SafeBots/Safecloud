# Run a Jet (5 minutes)

A Jet routes encrypted chunks between Drops and viewers, verifies payment
tokens, and settles micropayments on-chain. Permissionless — no registration.

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
    "safebux":      { "address": "0x…", "perChunkWei": "500" },
    "openclaiming": { "address": "0x…" },
    "jet": { "minInfraBp": 500, "settleIntervalSec": 900 }
} }
```

- `minInfraBp` — reject policies paying infra less than this (bps of 10000)
- `settleIntervalSec` — auto-settlement cadence (0 disables)
- Faucet (testnet only): `"faucet": { "enabled": true, "wei": "1000000" }`

Earnings are one call away: `receivedTotal(safebux, jetAddress)` on
OpenClaiming — the dashboard shows it.
