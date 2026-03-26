# Assets/Web3 — Micropayment Verification Layer

## The Problem

Currently Jets.js does payment verification inline:
- `_checkPayments` reads `p.stm.payer`, calls `_checkPayerBalance`
- No EIP-712 signature verification (until this fix)
- Balance-only check can be replayed across requests
- Every plugin that wants x402 micropayments duplicates this logic

The Calendars pattern (using `Assets_Credits::getPaymentsInfo`) is the right model:
the Assets plugin owns payment knowledge, other plugins call into it.

## Proposed: `Assets/Web3` module (JS + PHP)

### `Assets/Web3.js` (Node.js server module)

Single responsibility: verify and account an OCP payment token.

```
Assets.Web3.verifyPayment(token, options)
  → Promise<{ ok, reason, payer, amount, chainId }>
```

Checks, in order:
1. `token.stm` structure present
2. `nbf <= now <= exp`
3. EIP-712 signature on `token.stm` valid against `token.stm.payer`
4. Payer balance >= `options.required` (cached, TTL configurable)
5. Optionally: `recipients` hash matches `options.recipients`

```
Assets.Web3.verifyPaymentHeader(req, options)
  → Promise<{ ok, reason, ... }>
```

For HTTP x402 flows — reads `PAYMENT-SIGNATURE` header, base64-decodes,
calls `verifyPayment`. Used by any plugin's express handler.

### `Assets/Web3.php`

```
Assets_Web3::verifyPayment($token, $options)
Assets_Web3::verifySignature($stm, $sig, $expectedPayer)  // ecrecover
Assets_Web3::getBalance($address, $tokenContract, $chainId) // RPC call + cache
```

## How Safecloud should use it

Jets.js `_checkPayments`:
```js
var Assets = require('Assets');
return Assets.Web3.verifyPayment(p, {
    required: String(totalWei),
    recipients: [jetWalletAddress]  // optional: check recipientsHash
})
.then(function(r) { return r.ok; });
```

The `PAYMENT-SIGNATURE` x402 handler:
```js
Assets.Web3.verifyPaymentHeader(req, { required: perChunk })
.then(function(r) {
    if (!r.ok) return res.status(402).json({...});
    // proceed
});
```

## How Calendars could use it

Instead of `Assets_Credits::getPaymentsInfo` (which knows about credits),
a lower-level `Assets_Web3::verifyPayment($token, $options)` could verify
on-chain tokens directly — useful for services where users pay in Safebux
or other ERC-20 tokens without going through the credits system.

The Calendars `going()` flow already has the right structure:
- Phase 1: check if paid → `Assets_Credits::getPaymentsInfo`
- Phase 2: charge → `Assets::pay(...)`

A `Assets_Web3` layer sits BELOW `Assets_Credits`, handling raw on-chain
verification. `Assets_Credits` calls `Assets_Web3` when the payment source
is a blockchain token rather than an internal credit balance.

## Implementation order

1. `Assets/Web3.js` — Node.js, wraps `Q.Crypto.OpenClaim.EVM` + ethers.js
2. `Assets/Web3.php` — PHP, wraps `Q_Crypto_OpenClaim_EVM` + web3.php/Guzzle  
3. Update Safecloud Jets.js to use `Assets.Web3.verifyPayment`
4. Update Safecloud Jets.js `_evmProvider` to use `Assets.Web3._provider`
5. Consider: Calendars plugin's streaming payment path via Safebux tokens

The key invariant: **payment logic lives in Assets, not in the consuming plugin**.
