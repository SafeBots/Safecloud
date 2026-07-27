# Get Started: sponsor viewers as a Publisher

A **Publisher** is a website that wants its visitors to watch Safecloud content
*without* each visitor needing a wallet, tokens, or any crypto onboarding. The
site pays on their behalf — a web2 bridge over the web3 rail.

This is also the **viewer-anonymity mechanism**: a sponsored viewer never
appears on-chain. The settlement records the *sponsor* as payer against an
opaque line number that only the sponsor can map back to a visitor.

---

## How it works

1. A visitor loads your page and starts a video.
2. Your site calls its own Jet's sponsor endpoint, which signs a payment token
   as **payer = your site**, on a line derived from an opaque visitor id
   (`keccak(visitorId)` — the Jet never learns who the visitor is).
3. The viewer streams using that token. On-chain, the payer is your site; the
   visitor's address appears nowhere.
4. When a visitor exhausts their per-viewer cap, the endpoint returns **402**
   and the client can fall back to self-pay (if the viewer *does* have a wallet)
   or you raise the cap.

---

## Enable it on your Jet

In `local/app.json`:

```json
{ "Safecloud": {
    "sponsor": { "enabled": true, "maxWeiPerViewer": "100000" },
    "sponsorUrl": "/Safecloud/sponsor/token"
} }
```

- `enabled` — turn sponsorship on.
- `maxWeiPerViewer` — the per-visitor spending cap. Past it, the endpoint
  returns `402` with the amount granted so far.

The Jet must have a wallet (it does, from first boot) — that wallet is the
payer. If sponsorship is on but no wallet is configured, the endpoint returns a
clean `503 { "error": "no sponsor wallet" }` rather than failing silently.

---

## Request a token

```
POST /Safecloud/sponsor/token
{ "viewerId": "<your opaque id for this visitor>", "maxWei": "5000" }
```

- `viewerId` — any stable string you use to identify the visitor to *yourself*.
  It's hashed into the on-chain line; the Jet and chain never see the raw value.
- `maxWei` — how much you're authorizing for this call (optional; capped by
  `maxWeiPerViewer`).

Returns a signed payment token the client attaches when fetching chunks.
Over-cap requests get `402` with `granted` so you know where the visitor stands.

---

## What this buys you

- **Zero-friction viewers** — no wallet, no tokens, no signup to watch.
- **Bounded cost** — every visitor is capped; you can't be drained.
- **Visitor privacy** — sponsored viewers resolve only to opaque line numbers
  you control; they never touch the chain.
- **Graceful downgrade** — at the cap, the client cleanly falls back to self-pay
  or stops, with a clear `402`, never a crash or a leaked error.

---

## Safety notes

- Keep the consumer path one-directional: sponsor *into* viewing, don't build a
  cash-out from sponsored balances. That keeps Safebux a closed-loop service
  credit rather than something that looks like stored value.
- The sponsor endpoint validates its inputs — a bad `maxWei` gets a `400`, not a
  server error, and never leaks internals.
