# OCP `payments` v2 — design proposal

*Goal (Greg's words, consolidated): expand the signed payload with **optional**
fields that pin things down per recipient — fractions, contracts to call —
so that (a) the split is enforced **in the contract**, not by an external
splitter; (b) a claimant may supply an `incomeContract`/target **only when the
signed payload allows it**; (c) griefing attacks are removed; and (d) we bake
enough in that Safecloud needs no side-car splitter, while never having to
redeploy again. One more vanity address is acceptable.*

This is a **v2 rail** — a new immutable deployment at a new well-known
address, coexisting with v1 (different domain → different digests → no
interference). It is not urgent; v1 + the caller-side splitter already ship a
sound system. v2 buys **atomic, protocol-level** split enforcement and retires
the side-car. Below is the design, the rationale against the deployed v1, and
the migration.

---

## 1. Design principle: optional pins, default-free

The load-bearing idea from Greg: **every new field is optional, and when
omitted the claimant is free to supply it; when present it is enforced.** This
is what lets one rail serve both "simple gasless person-to-person payment"
(sign nothing extra) and "enforce this 85/15 split atomically across these two
contracts" (pin it all) — without two code paths diverging in trust.

Concretely, v2 keeps the entire v1 `Payment` semantics as the zero-case and
adds a single optional commitment: a hash of a **distribution policy**. If the
policy hash is zero, v2 behaves exactly like v1 (one recipient, one amount,
one channel). If non-zero, execution must be accompanied by the plaintext
policy, must hash-match, and the contract itself performs the split and the
calls.

---

## 2. The v2 signed struct

    PaymentV2(
        address payer,
        address token,
        bytes32 recipientsHash,   // unchanged: set of addresses ever allowed
        uint256 max,              // unchanged: cumulative channel ceiling
        uint256 line,             // unchanged: channel id
        uint256 nbf,
        uint256 exp,
        bytes32 policyHash        // NEW. 0 = v1 behavior. else = keccak(Policy)
    )

    // Presented at execution alongside the signature when policyHash != 0.
    // Not signed field-by-field; bound by policyHash = keccak256(abi.encode(policy)).
    struct Policy {
        // Static split, frozen by the signature:
        address[] payees;         // each MUST be a member of recipientsHash's set
        uint256[] fractions;      // bps, sum == 10000 (or sum + dynamicBps == 10000)

        // Optional single dynamic payee the CLAIMANT supplies at execute time:
        uint256   dynamicBps;     // 0 disables the dynamic slot
        bytes32   dynamicConstraint; // 0 = any address; else a rule the supplied
                                     // payee must satisfy (see §4)

        // Optional per-payee target contract to CALL instead of plain transfer:
        //   targets[i] == address(0)  → plain ERC-20 transfer to payees[i]
        //   targets[i] != address(0)  → call targets[i].pay(payees[i], share)
        //                                forwarded as payer (EIP-2771), i.e. the
        //                                v1 incomeContract path, but PINNED and
        //                                per-payee instead of one global arg.
        address[] targets;        // length == payees.length (or empty = all plain)
    }

Everything new is inside `Policy`, and `Policy` is bound by one 32-byte
`policyHash` in the signed struct. The wallet still shows the signer a clean
typed `PaymentV2`; the policy is displayable alongside. The digest cost is one
extra word.

---

## 3. What v2 enforces that v1 could not

### (a) Fractions, in the contract

When `policyHash != 0`, `paymentsExecute` (v2) pulls the settled `amount` from
the channel exactly as v1 does, then **splits it in-contract** by
`fractions[]`, transferring/`pay()`-ing each `payees[i]` its share in the same
transaction. No external splitter. The split is frozen by the signature —
neither claimant nor any infrastructure party can alter proportions, because
changing any byte of `Policy` changes `policyHash` and fails the match.

This is the direct answer to "fractions enforced in the contract": the rail
itself is now the splitter, but **only when the payer opted in** by signing a
non-zero `policyHash`. Payers who don't need it pay v1 gas and v1 simplicity.

### (b) `incomeContract`/targets, pinned per recipient

v1's `incomeContract` is a single unsigned global argument — the claimant
picks it freely (sound, but unconstrained). v2 moves it **into the signed
policy, per payee**, as `targets[]`. Two gains:

- **Pinned when the payer wants determinism:** "the author's 15% MUST go
  through *this* IncomeContract (vesting/lockup), the publisher's 5% is a
  plain transfer." The claimant cannot reroute the author's share around the
  vesting contract, because the target is in the signed hash.

- **Claimant-supplied when the payer allows it:** if `targets` is empty (or a
  given entry is `address(0)`), that payee is a plain transfer — or, for the
  *dynamic* slot, the claimant supplies the address under `dynamicConstraint`.
  This is exactly Greg's "allow claimant-supplied `incomeContract` when the
  signed payload allows it": absence = permission, presence = pin.

### (c) Dynamic payee, signed-in as a constrained slot

Safecloud's core need — "pay whichever jet/drop actually served, and don't let
it be redirected" — becomes a first-class, *bounded* slot. The claimant fills
`dynamicPayee` at execute time; the contract checks it against
`dynamicConstraint` (§4) and pays it `dynamicBps`. Because the *fraction* and
the *constraint* are signed, the served party gets exactly its cut and nothing
about the split can be gamed. This is strictly better than v1's
`line = uint160(addr)` trick, which had no fraction enforcement and abused the
channel id to carry an address.

---

## 4. Removing griefing (the v1 gap this closes on purpose)

`OCP_soundness.md` established that v1's residual issue is **self-punishing
griefing**: under one shared line, a colluder can burn a counterparty's
channel headroom at the cost of its own. Not economically rational, but not
*prevented*. v2 removes it by construction in two ways:

1. **Per-policy settlement is all-or-nothing across payees.** Because one v2
   execution pays *every* payee atomically from one pulled amount, there is no
   "settle mine, withhold yours" move available *within a policy-bound
   payment*. The infra share and the author share are the same transaction or
   neither. Withholding degrades to "don't settle at all," which strands the
   withholder's own share too — the honest-viewer-ever-pays guarantee becomes
   "honest viewer ever pays ⇒ *all* committed parties paid, atomically."

2. **Separate channels per counterparty, cheaply.** v2 pairs with a lineOpen
   ergonomics fix (below) so that each (payer, counterparty) can live on its
   own line without gas friction. Burning one channel's headroom then cannot
   touch another's — the shared-line coupling that made griefing *possible*
   (even if self-harming) is gone. A griefer can only ever affect the exact
   channel it is a party to.

The `dynamicConstraint` field is the tool for the remaining "wrong dynamic
payee" worry: it lets the payer bound *who* may fill the dynamic slot without
naming them. Candidate encodings (pick at implementation):

- `0` → any non-zero address (Safecloud's default; the served node is
  whoever the honest player reached).
- a Merkle root → supplied payee must prove membership (e.g. a registry of
  vetted jets).
- a factory address → supplied payee must be a contract the factory
  produced (provenance, like the splitter's own pre-flight check but pushed
  on-chain).

All optional; `0` preserves the permissionless-serving property Safecloud
wants.

---

## 5. The lineOpen ergonomics fix (transient/gasless payers)

The one v1 UX edge worth fixing in v2 (see `OCP_soundness.md` §6): a named
line (`line ≥ 1`) requires the *payer* to `lineOpen` first, which is friction
for gasless viewers. v2 resolves it with **implicit opens under signed
authority**:

> A v2 payment whose signature is valid and whose `line ≥ 1` is treated as the
> payer's authorization to *open that line on first use* with `max` taken from
> the claim (or unlimited if the payer sets a v2 flag). No separate `lineOpen`
> transaction, no gas from the payer.

Rationale: v1 keeps `lineOpen` separate because line policy (the `max`) is set
by a different actor at a different time than spending. But a payer who signs a
claim *naming* a line is, by that signature, consenting to that line existing.
Folding the open into first execution is safe *because it is still the payer's
signature that authorizes it* — no third party can open a line on your behalf,
since opening rides on your signed claim. This keeps transient drops and
gasless viewers both zero-transaction while preserving channel isolation, and
it makes the per-counterparty-line anti-grief design (§4.2) actually ergonomic.

(Jets can still pre-open drops' lines if they want the line to exist *before*
the first payment — both paths coexist.)

---

## 6. What stays exactly as v1 (deliberately)

- **Payer-authorization invariant.** `payer` signed, recovered signer must
  equal it, funds are the payer's own. Untouched — it is the soundness bedrock
  (`OCP_soundness.md` §2). v2 adds enforcement *on top of* self-authorization,
  never around it.
- **`recipientsHash` as the destination commitment.** Still signed, still the
  set of allowed addresses. Policy `payees` and any `dynamicPayee` MUST be
  members — the contract checks membership, so `recipientsHash` remains the
  outer envelope and `Policy` a refinement inside it. (A payer can set
  `recipientsHash` over exactly the policy's payees plus the dynamic slot's
  allowed set.)
- **Cumulative watermark lines.** Same accounting; still the right primitive
  for metered streaming. v2 changes *ergonomics* (implicit open) and *coupling*
  (per-counterparty lines), not the monotonic-`spent` model.
- **Multisig, pre-flight, low-s, expiry/nbf, CEI ordering.** All carried over.
- **No custody.** v2 still holds nothing; it splits the amount it pulls within
  the same transaction and never retains a balance. (If a `pay()`/transfer to
  one payee fails, v2 should follow the splitter's pay-or-accrue: credit an
  `owed[]` bucket and expose `withdraw`, so one payee's velocity-limited token
  can't brick the whole atomic split. This is the one piece of splitter logic
  that migrates *into* the rail.)

---

## 7. Why this retires the side-car splitter

With v2, the RevenueSplitter's entire job — sole-recipient, call
`paymentsExecute`, split the delta, pay-or-accrue — becomes native to the rail
under a signed `policyHash`. Safecloud then signs **one** v2 token per hop
with a `Policy` (author-hop: static author/publisher/treasury + dynamic jet;
jet-hop: static jet/investors + dynamic drop), and the rail does the split
atomically. No factory, no per-instance policy contract, no provenance
pre-flight (the policy is in the signature, not in a deployed instance's
storage). The splitter was always explicitly the **v1 no-redeploy workaround**;
v2 is the version where it is unnecessary.

What the splitter still teaches v2: **pay-or-accrue** (velocity-limited tokens)
and **fractions frozen at authorization** (no mutable split) are both folded
in above. Nothing learned is lost.

---

## 8. Migration & coexistence

- **Deploy v2 at a new vanity address**, new domain name
  (`OpenClaiming.payments.v2` or a fresh separator) → v1 and v2 digests can
  never collide, so both rails run simultaneously and clients opt in per token.
- **Safebux ships with EIP-2612 permit regardless** (it isn't deployed yet):
  this is a token decision, orthogonal to v1-vs-v2, and it is what keeps fresh
  WebAuthn payers gasless on *either* rail (permit + execute in one tx). Do
  this now; it is the highest-leverage single change and costs nothing to defer
  the rest.
- **Plugin path:** the signing sites already centralized for the beta.3
  conformance fix are the same sites that would gain a `policyHash` branch.
  When v2 lands, the browser signer emits one policy-bound token instead of
  the dual tokens; the jet→drop signer emits one policy-bound token instead of
  the named-line watermark token; `claimPayments`/settlement calls v2
  `paymentsExecute` with the plaintext policy. The watermark-channel settlement
  logic stays (v2 keeps cumulative lines).
- **Order of operations, recommended:** (1) ship Safebux-with-permit and the
  v1 dual-token/splitter system as-is — it is sound; (2) build v2 unhurried,
  audit the in-contract split and the implicit-open logic hardest (they are the
  only genuinely new trust surface); (3) migrate Safecloud to v2 and retire the
  splitter; (4) keep v1 live forever for everything already using it.

---

## 9. Open questions for implementation

1. **Policy encoding vs. gas.** `abi.encode(Policy)` with three parallel
   arrays is clean but not cheap to hash/verify for many payees. For the
   2–4-payee Safecloud case it is negligible; if v2 is meant to scale to
   large splits, consider a Merkle-of-payees policy where each settlement
   proves one payee. Recommend starting with the flat encoding (simplicity,
   auditability) and adding a Merkle variant only if a real large-split use
   case appears.
2. **`dynamicConstraint` expressiveness.** Start with `0 = any` and a Merkle
   root option; defer factory-provenance-on-chain unless needed. Each addition
   is signed-optional, so this can grow without a redeploy *within* v2 only if
   designed as an enum-with-data now — otherwise it is itself a v3 concern.
   Decide the enum surface up front.
3. **Partial-settlement semantics under a policy.** v1 lets a claimant settle
   any `amount ≤ available`. Under a policy, does a partial settlement split
   proportionally (simplest, recommended) or must it settle the whole
   watermark delta? Proportional keeps the streaming model intact and is the
   natural reading.
4. **Reentrancy surface of per-payee `targets` calls.** Multiple forwarded
   `pay()` calls in one tx widen the surface vs. v1's single transfer. CEI is
   already the pattern (update `spent` before external calls); add an explicit
   `nonReentrant` and settle the pay-or-accrue bookkeeping before any external
   call, mirroring the splitter.
