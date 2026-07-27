# Safecloud

Decentralized, encrypted, pay-per-chunk streaming and storage. Creators keep
90%. Infrastructure can't read what it serves. Viewers are private by default.

Four roles, each turnkey:

| Role | What they do | Setup |
|------|-------------|-------|
| **Viewer** | Watches content | Click a link. Nothing to install. |
| **Drop** | Stores & serves encrypted chunks, earns | Open a page, tap a passkey. |
| **Jet** | Routes chunks, verifies & settles payments | `node server.js`, fund one address. |
| **Author** | Uploads content, sets revenue split | Upload, share the link. |

Onboarding pages (open in a browser): `web/onboard-viewer.html`,
`web/onboard-drop.html`, `web/onboard-jet.html`. Per-role quickstarts:
the `GetStarted/` guides (Jet, Drop, Author, Publisher). Running a live demo without a blockchain:
`docs/demo.md`.

---

## Two run modes

Safecloud runs in one of two modes, chosen entirely by config — no code
change, no rebuild.

### Signature-only mode (demo / pilot — no blockchain)

Micropayments are cryptographic: every payment is a signed EIP-712 token,
verified with no chain, no gas, no deployed contract. Only *settlement*
(cashing tokens out) touches a blockchain, and settlement is fire-and-forget
— it simply doesn't run until you configure a chain.

In this mode: viewers watch, sponsors pay, Drops accumulate real signed
watermarks, dashboards show live earnings. The only thing that doesn't happen
is on-chain cash-out (dashboards show "—" for the claimed figure).

```json
{ "Safecloud": {
    "requirePayment": true,
    "sponsor": { "enabled": true, "maxWeiPerViewer": "100000" },
    "sponsorUrl": "/Safecloud/sponsor/token"
} }
```

That's the whole config. `node server.js`, and everything works except
cash-out. See `docs/demo.md` for the full runbook.

### On-chain mode (production)

Add the deployed contract addresses and settlement begins automatically.

```json
{ "Safecloud": {
    "requirePayment": true,
    "safebux":      { "address": "0x…", "perChunkWei": "500" },
    "openclaiming": { "address": "0x…" },
    "jet": { "settleIntervalSec": 900, "minInfraBp": 500 }
} }
```

Deploy checklist: `docs/deploy.md`.

---

## The three config flags that matter

- **`requirePayment`** — gates *who paid*. A valid payment token (or sponsor
  token) is required to fetch content. Uploads are never gated by this.
- **`requireGrants`** — gates *who may see* (access control for private
  content). Off by default: public content needs no grants even with
  `requirePayment: true`.
- **`sponsor.enabled`** — lets this server sign payment tokens on behalf of
  its viewers (the web2 bridge). Viewers then watch without wallets, and are
  invisible on-chain.

These are independent. Public paid content: `requirePayment: true`,
`requireGrants: false`. Private free content: the reverse. Both, or neither.

---

## How the money works

- **Consumption** (streaming): viewer (or their sponsor) pays. Creator keeps
  **90%**, enforced on-chain — infrastructure literally cannot collect its
  share without paying the creator in the same transaction. Infra ~8%,
  protocol ~2%.
- **Storage** (backup/archive): the owner pays to store their own data. No
  creator royalty — 100% to infrastructure.

Same hardware serves both. Chunks are encrypted and indistinguishable, so
Jets and Drops can't cherry-pick lucrative content — they can only set a
price.

## Privacy

- **Viewers**: sponsored viewing is anonymous — the sponsor is the payer,
  and the viewer resolves only to an opaque channel number only the sponsor
  can decode. Self-payers get per-content payment identities
  (compartmentalization, not full anonymity — see the privacy note in
  `GetStarted/Author.md`).
- **Drops**: fully anonymous — passkey-derived address, outbound-only, host
  ciphertext they can't read.
- **Authors**: pseudonymous on-chain; identified by their content and
  cash-out in practice.
- **Jets**: pseudonymous wallet; a reachable domain/IP is the visible part.

## Testing

```bash
npm run test:everything
```
- 3 unit suites + 21 integration suites (**381 assertions**) — no chain, no browser
- `npm run test:evm` — compiles the real `OpenClaiming.sol` and settles real
  signed tokens on a local EVM (**23 assertions**), proving the plugin's
  EIP-712 format is byte-identical to the deployed contract's

Deployment sequence with verification gates: see the operator runbook
shipped alongside this plugin (`NEXT-STEPS.md`).

## Status

All roles turnkey. Signature-only mode runs today with zero blockchain.
On-chain mode needs two contracts deployed (`contracts/OpenClaiming.sol`,
`contracts/Safebux.sol`) and their addresses in config. See `docs/deploy.md`.
