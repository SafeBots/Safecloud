# Get Started: run a Jet

A **Jet** is the coordinator. It routes encrypted chunks between Drops and
viewers, verifies each payment token cryptographically, and settles
micropayments on-chain. It's permissionless — you don't register with anyone,
you just run one.

You never see plaintext (chunks are encrypted end-to-end) and you can't
cherry-pick or censor content (you route ciphertext addressed by hash).

---

## Two modes, one setup

The steps are identical; the difference is pure config.

- **Signature-only (no blockchain).** Payments are *verified* cryptographically
  but settlement is skipped. Perfect for demos and pilots — a full circuit runs
  with no chain, no gas, no contract addresses. Omit `safebux` and
  `openclaiming` from config and you're in this mode.
- **On-chain.** Add the two contract addresses and settlement activates. Same
  code, same circuit — money now moves.

---

## Steps

1. **Install** (Node 18+):
   ```bash
   git clone <your-qbix-app> && cd <app> && npm install
   ```

2. **Start:**
   ```bash
   npm run jet
   ```
   On first start the Jet **generates its own wallet**, writes it to
   `local/app.json` (file mode 600), and prints the address. **Back that file
   up** — it is the Jet's identity and its earnings account.

3. **Fund** the printed address with **~0.01 BNB** for settlement gas
   *(on-chain mode only — skip for signature-only)*.

4. **Verify:** open `https://your-host/Safecloud/health`. You want:
   ```json
   { "signing": true, "jetAddress": "0x…", "gasLow": false }
   ```
   `signing: true` means the wallet bootstrapped. Live view of connected Drops:
   `/Safecloud/dashboard`.

---

## Config you'll actually touch (`local/app.json`)

```json
{ "Safecloud": {
    "requirePayment": true,
    "requireGrants": false,
    "safebux":      { "address": "0x…", "chainId": "eip155:97", "perChunkWei": "500" },
    "openclaiming": { "address": "0x…" },
    "sponsor": { "enabled": true, "maxWeiPerViewer": "100000" },
    "sponsorUrl": "/Safecloud/sponsor/token",
    "jet": { "minInfraBp": 500, "settleIntervalSec": 900 },
    "router": { "maxClaimedGB": 65536 },
    "faucet": { "enabled": true, "wei": "1000000", "perIpPerDay": 3 }
} }
```

| Key | What it does |
|---|---|
| `requirePayment` | require a payment/sponsor token before serving content |
| `requireGrants` | require an access grant (private content); `false` = public |
| `safebux` / `openclaiming` | **omit both** for signature-only mode |
| `sponsor.enabled` | this server signs tokens for its own viewers (see Publisher) |
| `minInfraBp` | reject policies paying infrastructure less than this (bps of 10000) |
| `settleIntervalSec` | auto-settlement cadence in seconds (`0` disables) |
| `router.maxClaimedGB` | cap on a Drop's *claimed* storage, so no one can claim an absurd figure to capture routing |
| `faucet` | testnet convenience — **turn off for mainnet** |

---

## Your earnings

One call on the OpenClaiming contract: `receivedTotal(safebux, jetAddress)`.
That's public chain state — the dashboard just reads it for you. You earn the
infrastructure share (the dynamic slot) of every policy you settle, paid in the
same atomic transaction as the author.

---

## Health check meanings

- `signing: false` → no wallet yet; check `local/app.json` is writable.
- `gasLow: true` → fund the Jet address (on-chain mode).
- Both addresses null but `signing: true` → you're in signature-only mode
  (fine for a demo).
