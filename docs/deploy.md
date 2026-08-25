# Deploying on-chain (production)

Signature-only mode → full settlement. The only thing that changes is
config; the running code is identical.

## 1. Deploy the contracts (BSC, testnet first)

Both compile with **`viaIR: true`**, optimizer on, solc 0.8.24. Neither
takes constructor arguments; neither has admin roles.

1. **OpenClaiming** (`contracts/OpenClaiming.sol`) — the settlement rail.
   Deploy, verify source, note the address.
2. **Safebux** via `SafebuxFactory.produce("Safebux", "SBUX", <multisig>)`.
   Then `addMinter(<distributor>)` for whatever hands out Safebux.

## 2. Configure

`local/app.json`:
```json
{
  "Safecloud": {
    "requirePayment": true,
    "safebux":      { "address": "0x<SBUX>", "chainId": "eip155:56",
                      "perChunkWei": "500" },
    "openclaiming": { "address": "0x<OCP>" },
    "jet": { "settleIntervalSec": 900, "minInfraBp": 500 }
  },
  "Users": { "web3": { "contracts": {
    "Safecloud/openclaiming": { "0x38": "0x<OCP>" }
  } } }
}
```
Setting `safebux.address` is what flips the Jet from signature-only to
on-chain — settlement, the faucet, and Drop-line opening all activate.

## 3. Fund the Jet

Send the Jet's address (printed on first start, or in
`local/app.json → Safecloud.jet.address`) **~0.01 BNB** for settlement gas.

For channel float, hold enough Safebux to cover ~one settlement interval of
Drop payouts (see the working-capital note in `docs/quickstart-jet.md`).

## 4. Testnet faucet (optional)

```json
"Safecloud": { "faucet": { "enabled": true, "wei": "1000000", "perIpPerDay": 3 } }
```
Lets new viewers get starter Safebux from the Jet's balance. **Testnet
only** — turn off for mainnet.

## 5. Verify the circuit

1. `/Safecloud/health` → `signing: true`, addresses populated,
   `gasLow: false`.
2. Upload → share → watch → the Drop dashboard's "claimed" figure moves off
   "—" after the first settlement (or the cron's first tick).
3. Check the settlement transaction on BscScan: creator and infra paid in
   one transaction.

## 6. Mainnet

Repeat 1–5 on BSC mainnet. Turn the faucet off. Establish a real Safebux
acquisition path (DEX pool or onramp) so viewers can buy in.

## Platform note

The platform `Q.Crypto.OpenClaim.EVM` module needs three edits to verify
the canonical token format natively (payments domain → `OpenClaiming`, add
the `contract` field; actions domain + `invoker` field). Until then the Jet
falls back to its own byte-exact ethers verifier — correct, just an extra
step. See `references/README.md`.
