# Publish a video (3 minutes)

Your content is encrypted before upload. Infrastructure cannot read it,
and the revenue split you choose is enforced by the payment rail itself —
nobody collects unless you're paid in the same transaction.

## Steps

1. **Upload** through the Safecloud client:
   ```js
   Q.Safecloud.Client.store(file, { revenue: { policy: {
       payees: [yourAddress], fractions: [9000],
       dynamicBps: 1000, dynamicConstraint: ZERO32, targets: []
   } } })
   ```
   (90% you / 10% infrastructure is the default — adjust in the share panel.)
2. **Share.** The share panel gives you a link, an iframe embed snippet, and
   optionally a split-entropy passphrase (link alone is not enough to watch —
   tell viewers the 4 words separately).
3. **Get paid.** Viewers stream; every settled payment splits atomically per
   your policy. Lifetime earnings: `receivedTotal(safebux, yourAddress)` —
   no dashboards required, it's public chain state.

## Optional

- **Vesting/anti-cycling**: set `targets: [vestingContract]` to route your
  own share through a lockup.
- **Sponsored viewers**: your site can sign payment tokens as payer so new
  viewers stream instantly, capped per viewer, revocable any time — and
  invisible on-chain: sponsorship is the viewer-anonymity mechanism (viewers
  resolve only to opaque line numbers the sponsor can decode).
