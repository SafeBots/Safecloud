# references/

Ground-truth sources this plugin must stay byte-compatible with.

- `OpenClaiming.sol` — the canonical OpenClaiming Protocol contract
  (address set post-deployment in `local/app.json` under
  `Users.web3.contracts["Safecloud/openclaiming"]`). Every EIP-712
  signing and verifying site in this plugin (browser signer in
  `web/js/methods/Safecloud/Jets/get.js`, jet→drop signer and all
  verifiers in `classes/Safecloud/Jets.js`, drop self-claim in
  `web/js/methods/Safecloud/Drops/claimPayments.js`) must match its
  NAME_HASH ("OpenClaiming"), PAYMENTS_TYPEHASH (8-field Payment struct
  ending with the signed `contract` address, validated == address(this)),
  and line-accounting semantics (cumulative watermark channels; line 0
  always open; lines ≥ 1 auto-open on first signed execution and stay
  closed only after an explicit lineClose). `recipientsHash` carries
  either keccak256(abi.encode(address[])) — plain payments — or
  keccak256(abi.encode(Policy)) — enforced splits with fractions,
  a constrained dynamic payee, and per-payee custody hooks. The two
  encodings cannot collide. `test/recipientsHash.test.js` reconstructs
  the contract's digest from these constants and asserts byte-exact
  equality with what the plugin signs — run it after touching any
  signing code.

- `OCP_soundness.md`, `OCP_v2_design.md` — historical design and
  security-analysis documents from the protocol's development. The design
  doc's "policyHash field" approach was superseded by recipientsHash
  overloading (one field, two encodings) so the signed struct stayed at
  8 fields and existing platform signers need no struct changes.

Planned canonical home for the contract, alongside the platform verifier
that must also match it:

    Q/classes/Q/Crypto/OpenClaim/EVM/contract.sol

(next to eip712.js, so the verifier and its ground truth live together —
the platform module needs three edits to match: payments domain name
'OpenClaiming.payments' → 'OpenClaiming', add the 8th `contract` field to
PAYMENT_TYPES, and for actions: domain → 'OpenClaiming' plus the `invoker`
field between `delay` and `nbf`).
