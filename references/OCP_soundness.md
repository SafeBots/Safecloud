# OCP Payments — soundness analysis

*Scope: is the OpenClaiming Protocol `payments` extension sound as a general
mechanism — not just for Safecloud? The bar Greg set: **a payment authorized
to the wrong party should only ever harm the party who authorized it.** This
doc games that out against the actual deployed contract
(`references/OpenClaiming.sol`), states what v1 payments can and cannot do,
and marks the boundary where a protocol like Safecloud — which needs to
enforce a payment to a THIRD party — runs past what v1 can guarantee.*

---

## 1. What the contract actually is

Strip the extensions away and OCP `payments` is one sentence: **the payer
signs an EIP-712 authorization; anyone may present it; the contract verifies
the signature, checks a cumulative per-channel ceiling, and moves the payer's
own ERC-20 to a recipient the payer committed to.** Everything else — lines,
pre-flight views, multisig — is refinement on that sentence.

The signed `Payment` struct is:

    Payment(address payer, address token, bytes32 recipientsHash,
            uint256 max, uint256 line, uint256 nbf, uint256 exp)

and the three facts that make it sound as a *payer-authorization* device:

1. **`payer` is inside the signed struct**, and `_paymentsValidate` reverts
   with `PayerMismatch` unless the recovered signer equals `payer`. So the
   only person who can authorize spending of an address's tokens is that
   address itself (or its co-signers under `paymentsExecuteSignatures`). No
   third party can manufacture a debit against you.

2. **`recipientsHash` is inside the signed struct**, and execution reverts
   (`PaymentRecipientsHashMismatch` / `InvalidRecipient`) unless the presented
   recipient is a member of the exact set the payer hashed. So the payer
   binds *where the money can go* at signing time. A relayer chooses *which*
   member and *when*, but cannot add a member.

3. **Funds are the payer's own** — `transferFrom(payer, recipient, amount)`
   pulls the payer's balance under the payer's own allowance. The contract
   never custodies anything; it cannot be drained because it holds nothing.

From those three, the invariant Greg wanted **holds for the payer**: a
signature you produce can only move *your* tokens, only to a recipient *you*
named, only up to a ceiling *you* set, only in a window *you* set. If you sign
something foolish, the blast radius is your own balance. Nobody else's.

---

## 2. The deputy question, answered

Greg's framing: *OCP is a trusted deputy — the paying contract trusts the
protocol about who signed what. Can it get confused?*

A confused deputy is an authority that uses **its own** privilege on behalf of
a caller who lacks that privilege, because it conflates "who asked" with "what
may be done." The classic shape: caller supplies a target, deputy acts with
deputy's authority on that target.

OCP `payments` is **not** that shape, for a structural reason: **OCP has no
authority of its own to be tricked into lending.** It holds no funds, owns no
allowances, and holds no privileged role on the token. Every debit is drawn
from the *payer's* balance under the *payer's* allowance, gated by the
*payer's* signature. OCP is a pure verifier-executor: it proves a fact
(this digest was signed by this payer) and mechanically applies the
consequence the payer pre-authorized. There is no ambient privilege for a
third party to borrow. The "deputy" carries no keys.

**"But the payer can sign against their own interest."** Yes — and this is the
crux. If a viewer signs a token whose `recipientsHash` names some party, and
that turns out to be a bad idea, OCP will faithfully execute it. Is that a
confused deputy? **No.** The deputy is not confused; it did exactly and only
what the authorizing party told it to, using only that party's own resources.
"I authorized a transfer I now regret" is not privilege escalation — it is an
authenticated instruction the signer had every right to give. A signature
device that refused to execute self-disadvantageous-but-valid instructions
would be substituting its own judgment for the signer's, which is a *worse*
property, not a better one. The whole point of Safecloud having the
self-interested parties (viewer, jet, drop) each sign their own pairwise
micropayments is that **nobody is ever asked to sign against their interest**;
each signature advances the signer's own transaction. OCP validating those is
sound precisely *because* each party is authorizing its own spend.

So: **OCP `payments` cannot be a confused deputy in the direct-transfer path**,
because it has no borrowable authority. The one place a *forwarding* authority
does exist — the `incomeContract` path — is analyzed in §5, and it is
correctly fenced.

---

## 3. Lines: the one piece of shared, mutable state

Everything above is per-signature. The only *stateful* thing OCP keeps is
`lines[payer][line] → {max, spent, open}`, and `spent` is **cumulative** and
**monotonic**: every execution does `lines[payer][line].spent += amount`, and
every claim's `max` is checked against the running `spent`. This is the
watermark-channel model the plugin now signs against.

Soundness consequences worth stating plainly:

- **`spent` only ever increases, and only by amounts the payer authorized on
  that payer's own line.** No one can inflate another payer's `spent`, because
  writing to `lines[payer][*]` only happens inside an execution that passed
  the `payer == signer` check.

- **A claim is a *ceiling voucher on a channel*, not a bearer note for a fixed
  sum.** Two claims on the same `(payer, line)` with maxes 100 and 150 do not
  authorize 250 of spend — they authorize spend *up to 150 total*, and once
  `spent` passes 100 the first is dead. This is the single most important
  semantic to get right off-chain: **only the latest (highest-max) claim per
  channel is live**, and settlement amount is `lineAvailable`, not the claim's
  face `max`. Treating claims as additive is the classic integration bug (it
  over-counts claimable revenue and issues transactions that revert). The
  plugin's `claimPayments` and `getPaymentStats` were both corrected to
  latest-per-channel.

- **Line 0 is always open and uncapped-by-line; lines ≥ 1 require the payer
  (or the payer contract's Ownable owner) to `lineOpen` first.** This is what
  makes channels *isolatable*: a payer can put counterparty A on line 1 and
  counterparty B on line 2 and cap each independently. It is also the source
  of the transient-party UX question (§6).

There is **one asymmetry to be aware of** (not a vulnerability, but a sharp
edge): `lineAvailable` for line 0 returns `claimMax` **without** subtracting
`spent`, whereas *execution* on line 0 fully enforces `max − spent`. So the
line-0 pre-flight view is optimistic; the settlement-time truth is the public
`lines(payer, 0)` getter. Off-chain code should read `lines(payer,0).spent`
directly rather than trusting the line-0 `lineAvailable` return. Documented at
the Jets pre-flight call site.

---

## 4. What v1 payments soundly supports (the green zone)

Because the invariant holds *for the payer*, any flow where **the party who
needs protection is the payer** is fully sound on v1, no additions:

- **Ordinary person-to-person / person-to-merchant payment.** I sign, I pay,
  I chose the recipient. A relayer can submit it (gasless for me) but cannot
  redirect or inflate it. Expiry and not-before bound the window.

- **Metered / streaming spend to a known counterparty.** One long-lived
  watermark claim on a dedicated line; the counterparty settles the growing
  `spent` as service is delivered. This is exactly Safecloud's jet→drop and
  viewer→jet channels. Sound because *the payer is the one exposed* — the
  counterparty can only ever collect up to what the payer watermarked.

- **Treasury / multisig disbursement.** `paymentsExecuteSignatures` counts
  unique valid signatures against `minValid`. A group authorizes its own
  spend; no member can move funds alone; a relayer submits the bundle. Sound
  for the same reason — the *payers* (the multisig set) are the exposed party
  and they collectively authorized it.

- **Budget-capped agents.** Open a line with a hard `max`, hand an agent
  claims on it; the agent can spend up to the cap and no further, and you can
  `lineClose` it. The cap is enforced on-chain against cumulative `spent`.

In every one of these, "authorized to the wrong party only harms the
authorizer" is satisfied *because the authorizer is the party the mechanism is
protecting.* v1 is sound and sufficient here.

---

## 5. The `incomeContract` path — the only forwarding authority, and it's fenced

There is exactly one place OCP acts as more than a transfer executor: when
`incomeContract != 0`, `_paymentsTransfer` does **not** move tokens — it
EIP-2771-forwards `IncomeContract.pay(recipient, amount)` **as the payer**
(payer's address appended to calldata; IncomeContract's `_msgSender()` reads
it back). For this to do anything, three preconditions must already hold,
all outside OCP's gift:

1. the IncomeContract must have registered OCP as its `trustedForwarder`,
2. the payer must be a registered **manager** on that IncomeContract, and
3. the IncomeContract must already be funded / configured.

Is *this* a confused-deputy risk? Walk it: OCP forwards a call *as the payer*,
using the payer's signed authorization, to a contract that has independently
decided to trust OCP as a forwarder and the payer as a manager. OCP is not
lending *its own* authority — it is faithfully relaying the *payer's* identity,
which the payer authenticated by signing. The IncomeContract's own
`canManage` check is what gates the effect, and it resolves to the payer. So
the authority exercised is the payer's, the resource is the IncomeContract the
payer manages, and the trigger is the payer's signature. **Still sound: the
authorizer is the exposed party.** The fence is that all three preconditions
are set by the parties who'd be harmed, not by a claimant.

Note this path is **irrelevant to Safecloud** and the plugin always passes
`address(0)`. It matters here only to answer the general soundness question:
even OCP's one forwarding power is correctly bound to the payer's identity.

---

## 6. Where a THIRD-PARTY-enforcement protocol runs past v1 (the boundary)

Now the honest limit. Safecloud does not only want "the viewer's own tokens
are safe." It wants: **when a viewer pays a jet, the author's cut is paid
too, and no jet/drop collusion can strip it.** That is a claim about
protecting a party *other than the signer* — the author is not the payer.

v1 gives us exactly one tool for third-party enforcement, and it is a good
one but it has a hard edge:

- **What v1 CAN do:** because `recipientsHash` is signed, the payer can commit
  that a token is redeemable *only* by a specific address — e.g. a splitter
  contract, or the IncomeContract. Colluding infrastructure can then *decline
  to settle* that token, but can **never redirect** it: there is no signature
  that sends those funds anywhere else. This converts "author paid iff
  infrastructure is honest about destination" into "author paid iff anyone
  ever settles this token, and if settled it can only go to the committed
  recipient." That is the entire basis of Safecloud's design, and it is sound.

- **What v1 CANNOT do:** it cannot make settlement of the author's cut
  *atomic with* the infrastructure being paid, **at the protocol level**,
  because the Payment struct has no field that says "and fractions must split
  thus" or "and you must also pay X." OCP executes one `(recipient, amount)`
  per call against one channel. Fractions, mandatory co-payees, and
  "pay-A-only-if-B" are **not expressible in the signed payload.**

Safecloud closes this gap *off the rail* in two composable ways, neither of
which requires OCP to change:

1. **Signed dual tokens (shipped v1 design).** The viewer signs the infra
   token *and* the author token in the same request, both at the same
   watermark. Redirection is impossible (recipientsHash). Withholding is
   possible but self-punishing under the cumulative-line model: burning the
   author's channel headroom raises the shared `spent` and reduces the
   colluder's own collectable infra claim. "Withhold" costs the withholder.

2. **A caller-side splitter (RevenueSplitter).** Make the splitter the *sole*
   signed recipient and let it *call* `paymentsExecute` and distribute the
   measured delta atomically in one tx. Now fractions ARE enforced — by the
   splitter, which OCP treats as an ordinary recipient. Atomicity is
   recovered in the contract that sits *in front of* the rail, leaving the
   rail untouched. (See `SPEC.md`.)

The residual limit even after both: **full collusion of viewer + jet + drop =
watching for free.** That is the analog hole — the viewer's player simply
never signs anything. No on-chain mechanism can force a party to author a
payment for a service it has decided to steal. The achievable guarantee, and
the one Safecloud actually reaches, is: *whenever any honest viewer's player
signs a payment at all, the author's committed cut is unstealable and
unredirectable.* The trust question collapses from "are all these
uncontrolled infrastructure parties honest?" to "is the one artifact I
distribute — the player — honest at signing time?" That is the strongest
place the trust can sit on v1, and it is a *design* achievement layered on
the rail, not a *protocol* guarantee the rail provides.

- **The transient-party UX edge (not a soundness gap).** Encoding a dynamic
  payee as a named line (`line = uint160(addr)`) needs the *payer* to have
  opened that line. Fine when the payer is a persistent, gas-holding party
  (the jet opens its drops' lines at registration — drops stay transient and
  register nothing). Awkward when the payer is a gasless viewer, who would
  have to `lineOpen` per content. Options: sponsor that gas, keep viewers on
  line 0 as a single-counterparty channel, or (v2) let a payer-signed line id
  count as implicit consent to open. This is friction, not unsoundness — an
  unopened line fails *closed* (`LineNotOpen`), never open.

---

## 7. Verdict

Against Greg's bar — *a payment authorized to the wrong party only harms the
authorizer* — **v1 OCP `payments` is sound**, and soundly so for a precise
reason: it has no authority of its own to be tricked into lending. Every
debit is the payer's own tokens, to a payer-committed recipient, under a
payer-set ceiling, gated by the payer's own signature; even the lone
forwarding path (`incomeContract`) exercises only the payer's identity into a
contract that independently opted to trust it. Signing against one's own
interest is authenticated instruction, not a confused deputy. When every
party acts in self-interest — which Safecloud's pairwise-signing structure
guarantees, since no one is ever asked to sign against themselves — there are
no serious attacks: no redirection, no inflation, no cross-payer contamination,
no drain (nothing is custodied).

The **boundary** is equally precise and worth stating without hedging: v1
enforces *destination* (via signed `recipientsHash`) but cannot enforce
*composition* — mandatory fractions, co-payees, or all-or-nothing settlement
across parties — because the signed payload has no field for it. Protocols
that must protect a **non-signing third party** (Safecloud's author) therefore
cannot get *atomic* protection from the bare rail; they recover it by
committing to a caller-side splitter as the sole recipient, or accept the
weaker-but-real "unstealable if ever settled" guarantee of signed dual tokens.
Both sit in front of the rail and need no redeploy.

Griefing that is costly to the griefer (burning a shared line to deny a
counterparty, at the price of one's own headroom) is **out of scope for v1 by
decision** — it is self-punishing and therefore not an economically rational
attack, and closing it is a v2 concern (see `OCP_v2_design.md`). What v1 does
*not* leave open is any attack that profits the attacker at another party's
expense. That asymmetry — self-harm possible, other-harm not — is exactly the
soundness property requested.
