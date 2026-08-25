# On-chain tests (real EVM, no testnet needed)

`npm run test:evm` — compiles the **actual** `references/OpenClaiming.sol`
with solc (optimizer + `viaIR`), deploys it to an in-process EVM, and settles
**real EIP-712 tokens signed by the same code the browser and Jet use**.

This closes the last untested seam: whether a token the plugin signs is
accepted by the contract's `ecrecover` and splits funds correctly on chain.

## What it proves

| Check | Result |
|---|---|
| Contract compiles, optimizer + viaIR | 14,172 bytes (EIP-170 limit 24,576) |
| Plugin typehash == deployed `PAYMENTS_TYPEHASH` | byte-identical |
| Plugin digest == deployed `paymentsDigest()` | byte-identical |
| Plugin `recipientsHash` == `paymentsHashRecipients()` | match |
| Plugin `policyHash` == `hashPolicy()` | match |
| `paymentsExecute` accepts a plugin-signed token | ~146k gas |
| `paymentsExecutePolicy` atomic split | ~237k gas, author +90%, Jet +10%, exact |
| Watermark replay | transfers nothing more |
| Tampered `max` | rejected on chain |
| Token bound to another deployment | rejected on chain |
| Sponsored token (opaque line) | settles; viewer never the payer |

## Gas reference (local EVM, optimizer on)

- deploy OpenClaiming: **3,133,717**
- `paymentsExecute`: **~146,000**
- `paymentsExecutePolicy` (1 payee + dynamic): **~237,000**

Use these to sanity-check testnet numbers — they should be within ~10%.
