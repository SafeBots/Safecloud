# Get Started: publish as an Author

An **Author** uploads content and sets the revenue split. Your content is
encrypted before it leaves the browser — infrastructure never sees plaintext —
and the split you choose is **enforced by the payment rail itself**: no party
collects unless you are paid in the very same transaction.

---

## Steps

1. **Upload** through the Safecloud client:
   ```js
   Q.Safecloud.Client.store(file, { revenue: { policy: {
       payees:     [yourAddress],
       fractions:  [9000],          // 90% to you
       dynamicBps: 1000,            // 10% to infrastructure (Jet + Drops)
       dynamicConstraint: ZERO32,
       targets:    []
   } } });
   ```
   90 / 10 is the default; adjust it in the share panel.

2. **Share.** The share panel gives you:
   - a **link**,
   - an **iframe embed** snippet,
   - optionally a **split-entropy passphrase** — the link alone won't play the
     video; you tell viewers the four words separately, out of band.

3. **Get paid.** Viewers stream; every settled payment splits **atomically**
   per your policy. Your lifetime earnings are public chain state:
   `receivedTotal(safebux, yourAddress)` — no dashboard required.

---

## The revenue policy, briefly

| Field | Meaning |
|---|---|
| `payees` / `fractions` | who gets paid and what share (bps of 10000) |
| `dynamicBps` | the infrastructure share — filled by whichever Jet/Drops served |
| `dynamicConstraint` | restricts who may fill the dynamic slot (`ZERO32` = any) |
| `targets` | optional routing of your own share (e.g. through a vesting contract) |

`fractions` + `dynamicBps` must sum to 10000. The Jet rejects a policy that
underpays infrastructure below its configured `minInfraBp`, so set a realistic
infra share (the 1000 bps default is safe).

---

## Options worth knowing

- **Split-entropy sharing.** Choose a passphrase and the decryption key is split
  between the URL and the words you speak aloud. Whoever holds only the link
  cannot watch.
- **Vesting / anti-cycling.** Set `targets: [vestingContract]` to route your own
  share through a lockup.
- **Sponsored viewers.** A website can pay on a viewer's behalf so first-time
  visitors watch instantly — see the **Publisher** guide. From your side nothing
  changes; you're still paid your full share per your policy.

---

## What you never have to trust

You don't trust the Jet, the Drops, or the website to pay you. The split is in
the signed policy, and the OpenClaiming contract enforces it in one transaction:
either everyone in the policy is paid their exact fraction, or the settlement
doesn't happen.
