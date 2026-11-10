# Safecloud — OCP Messaging and Trustless Trading

This document specifies how OCP Messaging over Safecloud functions as a general-purpose encrypted messaging protocol that also supports trustless peer-to-peer trading — including token crowdfunding under Regulation S and secondary resales. It covers the protocol design, the message envelope, the settlement layer, the compliance integration, and the legal analysis for why the protocol avoids exchange, broker-dealer, and money-transmitter classification.

Read `Protocol.md` before this document. This document extends the Safecloud protocol with a messaging layer (Edge 6) and a settlement layer (Edge 7). It does not modify any existing edge.

**Notation:** Alice = sender / seller. Bob = recipient / buyer. Jet = routing node. Drop = storage node doubling as a messaging endpoint. "Intent" = a signed, parameterized offer. "Accept" = a countersignature committing to that offer. Settlement = atomic on-chain execution of a matched intent/accept pair.

---

## Table of Contents

- [Design goals](#design-goals)
- [Architecture overview](#architecture-overview)
- [Edge 6 — Messaging (Drop ↔ Jet ↔ Drop)](#edge-6--messaging-drop--jet--drop)
  - [Mailbox registration](#mailbox-registration)
  - [Message envelope format](#message-envelope-format)
  - [Message types](#message-types)
  - [Transport: WebSocket, HTTP, and Web Push](#transport-websocket-http-and-web-push)
  - [Timing attack mitigations](#timing-attack-mitigations)
  - [Steganographic mailboxes](#steganographic-mailboxes)
- [Edge 7 — Trustless settlement (EVM)](#edge-7--trustless-settlement-evm)
  - [Intent structure (EIP-712)](#intent-structure-eip-712)
  - [Accept structure](#accept-structure)
  - [Settlement contract](#settlement-contract)
  - [Nonce management and cancellation](#nonce-management-and-cancellation)
  - [Attestation-gated settlement](#attestation-gated-settlement)
- [Discovery](#discovery)
  - [Direct messaging](#direct-messaging)
  - [Group mailboxes](#group-mailboxes)
  - [Public intents](#public-intents)
  - [Attestation-gated groups](#attestation-gated-groups)
- [Regulation S token crowdfunding](#regulation-s-token-crowdfunding)
  - [Issuance flow](#issuance-flow)
  - [Distribution compliance period](#distribution-compliance-period)
  - [Secondary resales](#secondary-resales)
- [Legal analysis](#legal-analysis)
  - [Not an exchange](#not-an-exchange)
  - [Not a broker-dealer](#not-a-broker-dealer)
  - [Not a money transmitter](#not-a-money-transmitter)
  - [The structural defense](#the-structural-defense)
  - [Comparison to Uniswap](#comparison-to-uniswap)
  - [Comparison to Tornado Cash](#comparison-to-tornado-cash)
  - [First Amendment and code as speech](#first-amendment-and-code-as-speech)
  - [Jurisdiction considerations](#jurisdiction-considerations)
- [Technical roadmap](#technical-roadmap)
  - [Phase 1 — Mailbox primitives](#phase-1--mailbox-primitives)
  - [Phase 2 — OCP message envelope](#phase-2--ocp-message-envelope)
  - [Phase 3 — Settlement contracts](#phase-3--settlement-contracts)
  - [Phase 4 — Compliance and attestations](#phase-4--compliance-and-attestations)
  - [Phase 5 — Timing resistance and cover traffic](#phase-5--timing-resistance-and-cover-traffic)
  - [Phase 6 — Client UX](#phase-6--client-ux)
- [Attack vectors](#attack-vectors)

---

## Design goals

1. **Single primitive.** Every interaction — chat, file transfer, trading intent, payment — is an encrypted blob routed by a Jet between public keys. The Jet cannot distinguish message types.

2. **Structural privacy.** The protocol does not rely on policy ("we don't look at messages") but on cryptographic structure ("we cannot look at messages"). End-to-end encryption means the Jet holds ciphertext and no key. Even under subpoena, a Jet can produce only encrypted blobs and public keys. See `Flagging.md` for the client-side content scanning layer that complements this design.

3. **Trustless settlement.** Trades settle atomically on-chain via a generic escrow contract that verifies EIP-712 signatures and executes `transferFrom` calls. No custodian, no intermediary, no ability for any party to seize or freeze assets mid-trade.

4. **Protocol, not product.** The message envelope is an open standard. Any client that implements it can participate. Jets are independent operators. Settlement contracts are immutable. No single entity operates the system.

5. **Steganographic messaging.** Messaging is indistinguishable from storage operations. A Drop fetching its mail looks identical to a Client fetching video chunks. A sender depositing a message looks identical to an uploader storing content.

6. **Timing resistance.** For paranoid users, HTTP polling with constant-rate requests, padded responses, and cover traffic prevents timing-based correlation of mailbox identities.

---

## Architecture overview

The messaging and trading layers sit on top of Safecloud's existing storage network:

```
  Layer 0: Safecloud Storage    — Jets route encrypted chunks between Clouds/Drops
  Layer 1: OCP Messaging        — Standardized encrypted message envelope (this doc)
  Layer 2: Discovery            — Out-of-band; NOT part of the protocol
  Layer 3: Settlement           — Generic EIP-712 escrow contracts on any EVM chain
  Layer 4: Compliance           — Optional OpenClaiming attestations (Reg S, accreditation)
```

Layer 0 is specified in `Protocol.md`. This document specifies Layers 1, 3, and 4. Layer 2 is explicitly outside the protocol — discovery happens through out-of-band channels, group chats, public posts, or social connections. The protocol routes messages; it does not match parties.

---

## Edge 6 — Messaging (Drop ↔ Jet ↔ Drop)

### Mailbox registration

A Drop registers one or more mailbox public keys with a Jet. Each mailbox is an independent identity — the Jet cannot link mailboxes belonging to the same Drop unless the Drop reveals the connection.

Mailbox keys are derived from the Drop's root secret via `Q.Crypto.delegate`:

```
rootSecret
  → delegate("mailbox/0") → keypair₀   (registered on Jet A)
  → delegate("mailbox/1") → keypair₁   (registered on Jet B)
  → delegate("mailbox/2") → keypair₂   (registered on Jet C)
  → delegate("notify")    → keypair_n  (SW decryption key for push payloads)
```

Registration extends the existing `Safecloud/drop/register` event:

```
Drop → Jet:  Safecloud/drop/register {
  pubkey:      hex,          // mailbox public key (X25519 or secp256k1)
  delegation:  OCP_envelope, // proves pubkey derives from a valid root
  storage:     { ... },      // existing storage commitment (optional)
  mailbox:     true,         // NEW: this registration accepts messages
  pushEndpoint: { ... }      // NEW: optional Web Push subscription
}
```

A registration with `mailbox: true` tells the Jet to store inbound messages for this pubkey and deliver them when the Drop connects (via WebSocket) or on demand (via HTTP GET). A registration without `mailbox` behaves exactly as today — storage only.

The Jet stores inbound messages in a per-pubkey queue, pruned by TTL (configurable, default 7 days) and size (configurable, default 1 MB). Messages beyond the limit are dropped oldest-first. The Jet cannot read the messages — it stores opaque blobs.

### Message envelope format

Every OCP message on the wire uses the same binary envelope. The Jet sees the envelope header (routing fields) but not the payload (encrypted).

```
OCP Message Envelope (binary, big-endian):

Offset  Size   Field
─────── ────── ─────────────────────────────────────────────
0       1      version          0x01
1       32     recipientPubkey  destination mailbox public key
33      32     ephemeralPubkey  sender's one-time X25519 key for DH
65      4      payloadLen       length of encrypted payload (uint32)
69      var    encryptedPayload NaCl secretbox (XSalsa20-Poly1305)
                                 key = X25519(ephemeral, recipient)
                                 nonce = first 24 bytes of SHA-256(ephemeral ∥ recipient)
var     0-var  padding          random bytes to next 1024-byte boundary
var     64     senderSig        Ed25519 or secp256k1 signature over
                                 SHA-256(version ∥ recipient ∥ ephemeral ∥ encrypted)
                                 OPTIONAL: omit (zero-fill) for anonymous sends
var     var    paymentProof     OCP payment token covering relay cost
                                 (existing format per Protocol.md §OCP Role B)
```

**Padding:** Every envelope is padded to a multiple of 1024 bytes. This prevents the Jet (or a network observer) from inferring message type or content length from packet size. A 50-byte chat message and a 900-byte trading intent both produce 1024-byte envelopes. Larger payloads pad to 2048, 3072, etc.

**Encrypted payload (after decryption by recipient):**

```json
{
  "v": 1,
  "type": "chat",
  "payload": { ... },
  "replyTo": "hex pubkey for replies (optional)",
  "nonce": "random 16 bytes, hex (dedup)",
  "ts": 1697500000
}
```

### Message types

The `type` field is visible only to sender and recipient after decryption. The Jet never sees it.

| Type | Purpose | Payload |
|------|---------|---------|
| `chat` | Plain text or structured message | `{ text, media: [cid, ...], metadata }` |
| `intent` | Signed trading offer (OCP/EIP-712) | `{ claim, signature }` — see Edge 7 |
| `accept` | Countersignature accepting an intent | `{ intentHash, claim, signature }` |
| `cancel` | Revoke an outstanding intent | `{ intentHash, onChainTxHash }` |
| `ack` | Delivery/read confirmation | `{ ref: nonce_of_original }` |
| `file` | CID reference to stored content | `{ cid, mimeType, name, size, keyPath }` |
| `attestation` | Compliance credential | `{ credential, issuer, claims }` |
| `ping` | Keepalive / cover traffic | `{}` (empty, indistinguishable from real messages) |

Adding new types does not require protocol changes — the Jet is type-agnostic. Clients ignore types they don't understand.

### Transport: WebSocket, HTTP, and Web Push

The same message envelope travels over three transports. The choice is the Drop's — the Jet supports all three simultaneously for every registered mailbox.

**WebSocket (low latency, online delivery):**

```
Sender → Jet:   Safecloud/mailbox/submit  { envelope: base64 }
Jet → Recipient: Safecloud/mailbox/deliver { envelope: base64 }
```

When the recipient is connected via WebSocket, the Jet delivers immediately. If the recipient is offline, the Jet queues the message.

**HTTP (timing-resistant, poll-based):**

```
GET /safecloud/mailbox/{pubkeyHex}
Authorization: OCP-Sig {signature over timestamp+pubkey, proving key ownership}
→ 200 { envelopes: [base64, ...], cursor: "..." }
   (padded to fixed response size regardless of message count)
→ 204 (no messages — response body is random padding, same size as 200)

DELETE /safecloud/mailbox/{pubkeyHex}/{cursor}
→ 200 (acknowledge receipt, Jet may prune delivered messages)
```

The response is always padded to a fixed size (default 64 KB). An empty mailbox and a full mailbox produce identical response sizes on the wire. The `cursor` enables pagination for mailboxes with many pending messages.

**Web Push (offline wake-up):**

When a Drop registered a `pushEndpoint`, the Jet sends a Web Push notification to wake the Drop. The push payload is encrypted to the Drop's `notify` key (derived via `delegate("notify")`) and contains only a signal — not the message itself:

```json
{
  "type": "mailbox",
  "pubkey": "hex (which mailbox has messages)",
  "count": 3,
  "premium": false
}
```

The Drop's service worker decrypts this, optionally shows a user notification ("You have 3 new messages"), and reconnects via WebSocket or polls via HTTP to retrieve the actual messages.

If the Drop is the last one holding needed chunks, the push can include `"premium": true` with an offer amount, signaling that coming online now earns a premium payment.

### Timing attack mitigations

For users who need resistance to timing-based correlation:

1. **Constant-rate HTTP polling.** The Drop polls every N minutes (configurable, default 15) regardless of whether messages are expected. Traffic analysis sees a flat signal.

2. **Padded responses.** Every HTTP response is padded to a fixed size. Empty and full mailboxes are indistinguishable on the wire.

3. **Cover traffic.** The Drop periodically sends `ping` type messages (encrypted random data) to its own mailboxes and to decoy pubkeys. These are indistinguishable from real messages to the Jet and to network observers.

4. **Batched retrieval.** The Drop fetches messages from multiple mailboxes and also fetches regular Safecloud content (video chunks, stored files) in the same HTTP session. The Jet cannot distinguish mailbox polling from content serving.

5. **Jittered multi-Jet polling.** When a Drop has mailboxes on multiple Jets, it polls them at different times with random jitter. No two Jets see correlated access patterns.

6. **Delayed WebSocket delivery.** The Jet can be configured to batch-deliver messages at regular intervals (e.g., every 30 seconds) rather than immediately. This adds latency but breaks the "message arrived, Drop received 50ms later" correlation. This is opt-in via a `deliveryInterval` field in the mailbox registration.

7. **Tor/VPN compatibility.** HTTP polling works over Tor or any VPN. The Jet sees a Tor exit node, not the Drop's IP. Combined with padded responses and constant-rate polling, this provides strong anonymity.

### Steganographic mailboxes

A mailbox is indistinguishable from a storage node. The `Safecloud/drop/register` event already carries a `pubkey` and announces CID ranges. Adding `mailbox: true` is optional metadata — a Drop can receive messages on any registered pubkey whether or not it explicitly declared mailbox support, because the submit/deliver events work on any pubkey the Jet has in its routing table.

This means messaging is hidden inside the normal storage protocol:

- A message submission (`Safecloud/mailbox/submit`) looks like a chunk PUT from the Jet's perspective — an encrypted blob addressed to a pubkey.
- A message retrieval (`GET /safecloud/mailbox/{pubkey}`) looks like a chunk GET — an encrypted blob fetched by key.
- The message envelope uses the same encryption (NaCl/ECIES) and the same padding (1024-byte boundaries) as chunk storage.

A Jet serving a million chunk requests per day, of which 500 are mailbox operations, has no way to distinguish the 500. The messaging layer is steganographically hidden inside the storage layer.

---

## Edge 7 — Trustless settlement (EVM)

### Intent structure (EIP-712)

A trading intent is an EIP-712 typed-data message signed by the offerer. It is self-contained — the recipient can verify it without contacting any server, and either party can submit it to the settlement contract.

```
domain: {
  name: "OCP-Settlement",
  version: "1",
  chainId: <target chain>,
  verifyingContract: <settlement contract address>
}

types: {
  Intent: [
    { name: "offerer",       type: "address" },
    { name: "offerAsset",    type: "address" },  // ERC-20 contract (or 0x0 for native)
    { name: "offerAmount",   type: "uint256" },
    { name: "askAsset",      type: "address" },
    { name: "askAmount",     type: "uint256" },
    { name: "counterparty",  type: "address" },  // 0x0 = open offer (anyone can accept)
    { name: "expiry",        type: "uint256" },  // block.timestamp ceiling
    { name: "nonce",         type: "uint256" },  // per-offerer monotonic
    { name: "attestations",  type: "bytes32[]" } // required attestation hashes (optional)
  ]
}
```

**`counterparty` field:** When set to a specific address, only that address can accept the intent. This prevents front-running — even if an attacker intercepts the signed intent, they cannot submit it with a different counterparty. When set to `0x0`, the intent is an open offer and anyone can accept (first valid on-chain submission wins).

**`attestations` field:** An array of attestation hashes that the counterparty must present at settlement time. For Reg S compliance, this would include the hash of a non-US-person attestation. The settlement contract checks that the counterparty has a valid attestation matching each hash. Empty array = no attestation required.

### Accept structure

An accept is a countersignature over the intent hash:

```
types: {
  Accept: [
    { name: "intentHash",  type: "bytes32" },  // EIP-712 hash of the Intent
    { name: "acceptor",    type: "address" },
    { name: "attestations", type: "bytes32[]" } // acceptor's attestation hashes
  ]
}
```

The acceptor signs this with their key. The combination of (intent + intent signature + accept + accept signature) is a complete bilateral agreement, submittable to the settlement contract by either party.

### Settlement contract

The settlement contract is a generic, immutable, non-upgradeable smart contract deployed on any EVM chain. It has no owner, no admin key, no pause function, and no trading-specific logic beyond signature verification and atomic transfer.

```solidity
contract OCPSettlement {

    mapping(address => mapping(uint256 => bool)) public usedNonces;

    // Optional: attestation registry
    IAttestationRegistry public attestationRegistry;

    function settle(
        Intent calldata intent,
        bytes calldata intentSig,
        Accept calldata accept,
        bytes calldata acceptSig,
        bytes[] calldata attestationProofs  // optional
    ) external {
        // 1. Verify intent signature
        address offerer = _recoverEIP712(intent, intentSig);
        require(offerer == intent.offerer, "bad intent sig");

        // 2. Verify accept signature
        address acceptor = _recoverEIP712(accept, acceptSig);
        require(acceptor == accept.acceptor, "bad accept sig");

        // 3. Counterparty check (front-running prevention)
        require(
            intent.counterparty == address(0) || intent.counterparty == acceptor,
            "wrong counterparty"
        );

        // 4. Expiry check
        require(block.timestamp <= intent.expiry, "intent expired");

        // 5. Nonce check (replay prevention)
        require(!usedNonces[offerer][intent.nonce], "nonce used");
        usedNonces[offerer][intent.nonce] = true;

        // 6. Intent hash linkage
        require(accept.intentHash == _hashIntent(intent), "hash mismatch");

        // 7. Attestation checks (if required)
        if (intent.attestations.length > 0) {
            for (uint i = 0; i < intent.attestations.length; i++) {
                require(
                    attestationRegistry.verify(acceptor, intent.attestations[i], attestationProofs[i]),
                    "attestation failed"
                );
            }
        }
        if (accept.attestations.length > 0) {
            for (uint i = 0; i < accept.attestations.length; i++) {
                require(
                    attestationRegistry.verify(offerer, accept.attestations[i], attestationProofs[i]),
                    "attestation failed"
                );
            }
        }

        // 8. Atomic transfer
        _transfer(intent.offerAsset, offerer, acceptor, intent.offerAmount);
        _transfer(intent.askAsset, acceptor, offerer, intent.askAmount);

        emit Settled(offerer, acceptor, intent.offerAsset, intent.offerAmount,
                     intent.askAsset, intent.askAmount, intent.nonce);
    }

    function cancelNonce(uint256 nonce) external {
        usedNonces[msg.sender][nonce] = true;
        emit NonceCancelled(msg.sender, nonce);
    }

    function _transfer(address asset, address from, address to, uint256 amount) internal {
        if (asset == address(0)) {
            // Native token — must be sent with the transaction
            // (omitted for brevity; requires msg.value handling)
        } else {
            IERC20(asset).transferFrom(from, to, amount);
        }
    }
}
```

**Key properties:**

- **No owner.** The contract has no admin, no upgrade path, no kill switch. Once deployed, it is immutable.
- **No order book.** The contract does not store, match, or display orders. It verifies two pre-existing signatures and executes a transfer.
- **No custody.** The contract never holds assets. It calls `transferFrom` — the assets move directly from seller to buyer and vice versa in the same transaction. Both parties must have pre-approved the contract via `ERC20.approve()`.
- **No price logic.** The contract does not determine, suggest, or constrain prices. The price is whatever the two parties agreed to in their signed messages.
- **Atomic.** Both transfers succeed or both revert. No partial execution, no stuck state.

### Nonce management and cancellation

Each offerer has a nonce space. Nonces are uint256 — there is no requirement that they be sequential. The offerer can use any unused nonce for each new intent.

To cancel an outstanding intent before it expires, the offerer calls `cancelNonce(nonce)`. This marks the nonce as used, preventing any future settlement with that nonce. The on-chain cancellation costs gas but provides certainty — no one can settle against a cancelled intent.

Off-chain cancellation (sending a `cancel` type message to the counterparty) is cheaper but not trustless — the counterparty could ignore it and submit the settlement transaction before the on-chain cancellation confirms. For high-value intents, on-chain cancellation is recommended.

### Attestation-gated settlement

The settlement contract optionally integrates with an attestation registry — a separate contract that stores and verifies attestation credentials. An attestation is a signed claim by a third-party verifier (KYC provider, government e-ID system, or accreditation service) asserting a fact about a wallet address.

For Regulation S compliance, the relevant attestation is: "the holder of wallet address 0xABC is a non-US person as of date D, verified by provider P." The attestation is:

- **Issued** by a third-party verifier who performs the actual identity check
- **Held** by the user in their wallet (self-sovereign — the verifier doesn't know what the user does with it)
- **Presented** at settlement time as a proof alongside the intent/accept signatures
- **Verified** by the attestation registry contract (checks issuer signature, expiry, and that the attested address matches the counterparty)

The settlement contract does not perform KYC. It checks a mathematical proof that someone else did. The "someone else" is the attestation issuer, who is a regulated entity (KYC provider) operating under their own compliance obligations.

---

## Discovery

Discovery — how parties find each other — is explicitly outside the protocol. This is the central legal defense: the protocol routes messages between known endpoints; it does not bring together buyers and sellers. Discovery happens through mechanisms the protocol does not provide, control, or intermediate.

### Direct messaging

Alice knows Bob's mailbox public key (exchanged out-of-band: in person, via QR code, through another platform). Alice sends Bob a message (or an intent) directly. Pure peer-to-peer. No discovery mechanism involved.

### Group mailboxes

A community creates a shared secret. All members derive the same symmetric key from this secret. Messages posted to a group CID (a Safecloud content address used as a bulletin board) are encrypted with this symmetric key. Any member can decrypt; the Jet sees only encrypted blobs written to a CID — identical to normal content storage.

An intent posted to a group mailbox is visible to all members. Any member can accept. The Jet does not know the group exists, does not know its members, and cannot read the messages.

Group creation, membership management, and secret distribution are out-of-band operations. The protocol provides the encrypted storage; the social layer provides the group.

### Public intents

A seller posts a signed intent on a public channel — their website, a forum, social media, a blog post. The intent includes the seller's mailbox public key for replies. Anyone who sees it can send an `accept` message through OCP Messaging.

The intent is self-contained and self-verifying. The recipient's client can display it as a structured offer with an Accept button. No trust in the channel that carried it — the EIP-712 signature proves authenticity.

### Attestation-gated groups

A group can require members to present an attestation (e.g., non-US person, accredited investor) before receiving the group decryption key. The attestation check can happen:

- **Client-side:** A group admin verifies the attestation and shares the group key via encrypted direct message. The Jet is not involved.
- **Smart contract:** A contract holds the group key (encrypted to a threshold of admin keys) and releases it only to wallets with valid attestations. The Jet is not involved.

In either case, the gating mechanism operates outside the messaging protocol. The protocol routes encrypted bytes; the attestation check determines who holds the decryption key.

---

## Regulation S token crowdfunding

This section describes how OCP Messaging and the settlement layer support token crowdfunding under U.S. Regulation S (Rule 903/904), with secondary resales under Section 4(a)(1). This is a description of how the protocol enables a legal structure — not legal advice. Issuers should consult securities counsel.

### Issuance flow

1. **Issuer deploys token contract** on an EVM chain with transfer restrictions: a 40-day (Category 1/2) or 6-month (Category 3) distribution compliance period (DCP) during which transfers are blocked except to wallets with valid non-US attestations.

2. **Issuer creates offering materials** — pitch deck, whitepaper, terms — and optionally hosts them on Safecloud (served by Drops, available globally, no single server to take down).

3. **Interested buyers contact issuer** via OCP Messaging (encrypted, routed through Jets). The issuer's mailbox public key is published on the offering page.

4. **Buyer presents attestation** (non-US person, verified by a third-party KYC provider) via an `attestation` type message. The issuer's client verifies the attestation locally.

5. **Issuer sends signed Intent** to the qualified buyer: "I offer N tokens at price P, requiring attestation X."

6. **Buyer sends Accept** with their own signature.

7. **Either party submits** both signatures to the settlement contract. The contract verifies the intent, the accept, the attestation, and executes the atomic swap (tokens for payment).

8. **Token contract enforces DCP.** During the compliance period, the token's `transfer` function checks that the recipient has a valid non-US attestation. This is enforced at the contract level — the issuer doesn't need to manually approve transfers.

### Distribution compliance period

During the DCP:

- Transfers are restricted to wallets with valid attestations (enforced by the token contract)
- The issuer takes no directed selling efforts into the US (this is an issuer obligation, not a protocol feature)
- Offering materials may include legends ("these securities have not been registered under the Securities Act") — these can be embedded in the token contract's metadata
- The settlement contract's attestation check ensures that every on-chain transfer during the DCP involves a verified non-US buyer

### Secondary resales

After the DCP ends:

- The token contract lifts transfer restrictions (or reduces them — the issuer can choose to require attestations indefinitely)
- Token holders can resell under Section 4(a)(1) — the "ordinary trading" exemption for persons who are not issuers, underwriters, or dealers
- Resales happen the same way as the initial purchase: the seller posts an intent (directly, to a group, or publicly), the buyer accepts, and both submit to the settlement contract
- The issuer is not involved in secondary resales. The protocol does not connect the issuer to secondary market activity

**The independence test:** Under Section 2(a)(11), an "underwriter" is someone who buys "with a view to distribution" or participates in a distribution on behalf of the issuer. A secondary buyer who purchases tokens for their own account, holds them, and later resells independently is not an underwriter. The protocol's structure reinforces independence — the issuer has no mechanism to coordinate, direct, or control secondary sales through the protocol, because the protocol is peer-to-peer encrypted messaging.

---

## Legal analysis

**This section is not legal advice.** It is an analysis of how the protocol's technical architecture interacts with US securities and financial regulation. Issuers, operators, and users should consult their own counsel.

### Not an exchange

Under Section 3(a)(1) of the Exchange Act, an "exchange" is "any organization, association, or group of persons... which constitutes, maintains, or provides a marketplace or facilities for bringing together purchasers and sellers of securities."

The OCP Messaging protocol does not constitute, maintain, or provide a marketplace:

- **No order book.** The protocol does not collect, display, rank, or match orders. It routes encrypted blobs between public keys.
- **No price discovery.** The protocol does not determine, suggest, or publish prices. Prices are negotiated bilaterally by the parties.
- **No matching.** The protocol does not pair buyers with sellers. Parties find each other through out-of-band channels.
- **No execution.** The protocol does not execute trades. Settlement happens on-chain via a generic escrow contract that any party can call.
- **No market data.** The protocol does not aggregate or publish trade data, volume, or pricing information.

A Jet routes encrypted bytes. It does not know whether a byte is a chat message, a file reference, or a trading intent. It cannot read the messages. It cannot identify which messages are trading-related. It has less information about the messages it carries than a postal service has about the letters it delivers — at least the postal service can read the envelope.

The SEC's 2022 proposed expansion of the exchange definition (Release No. 34-94062) would cover "communication protocol systems" that bring together trading interest. Even under this broader reading, OCP Messaging would not qualify: it does not bring together trading interest because it cannot identify trading interest. The messages are encrypted. The Jet routes by public key, not by content type or trading parameters.

### Not a broker-dealer

Under Section 3(a)(4), a "broker" is "any person engaged in the business of effecting transactions in securities for the account of others." Under Section 3(a)(5), a "dealer" is someone who buys and sells securities for their own account as a regular business.

A Jet is neither:

- **Not effecting transactions.** A Jet delivers encrypted messages. It does not submit settlement transactions, does not call smart contracts, does not move tokens. The parties submit their own signatures to the settlement contract.
- **Not for the account of others.** A Jet does not act on behalf of any party. It does not hold assets, does not have discretion over trades, does not advise on trades.
- **Not buying or selling.** A Jet does not trade. Its revenue comes from message relay fees (micropayments for bandwidth), not from trading commissions or spreads.

A Jet's relationship to trading on its network is analogous to an ISP's relationship to e-commerce on its network. The ISP carries TCP packets that happen to include Amazon purchase confirmations. The ISP is not a broker-dealer. The Jet carries encrypted blobs that happen to include trading intents. The Jet is not a broker-dealer.

### Not a money transmitter

Under FinCEN's regulations (31 CFR § 1010.100(ff)(5)), a money transmitter is someone who "accepts currency, funds, or other value that substitutes for currency from one person and transmits currency, funds, or other value that substitutes for currency to another person" or "is engaged in the transfer of funds."

The settlement contract moves tokens directly from seller to buyer via `transferFrom`. No intermediary — not the Jet, not the protocol developers, not any third party — ever holds, controls, or has access to the tokens. The tokens move from one wallet to another in a single atomic transaction. This is analogous to handing cash directly from buyer to seller — the protocol is the room where they meet, not the cashier.

Additionally, encrypted messaging that happens to carry trading intents is not money transmission. Money transmission requires the transmitter to accept and transmit value. A Jet accepts and transmits encrypted bytes. It cannot access, divert, or withhold the value represented in those bytes because it cannot decrypt them.

### The structural defense

The protocol's legal defense is not based on promises, policies, or terms of service. It is based on the mathematical properties of the system:

1. **End-to-end encryption.** The Jet holds ciphertext. It has no decryption key. It cannot read messages. This is not a choice — it is a consequence of X25519 key agreement with ephemeral keys. The Jet literally does not have the information needed to decrypt.

2. **No metadata leakage.** Message envelopes are padded to fixed sizes. Message types are inside the encrypted payload. The Jet cannot distinguish a chat message from a trading intent from cover traffic.

3. **Generic infrastructure.** The settlement contract verifies signatures and executes transfers. It has no trading-specific logic. It is an escrow — the same contract could settle a payroll disbursement, a charitable donation, or a bet between friends.

4. **Independent operation.** Jets are independent operators running open-source software. There is no central coordination, no shared order book, no aggregated market data. Each Jet is an independent encrypted message relay.

5. **Immutable contracts.** The settlement contracts have no owner, no admin key, no upgrade mechanism. Once deployed, they cannot be modified, paused, or controlled by any party.

This is the difference between a policy defense ("we don't look at messages") and a structural defense ("we cannot look at messages"). The former can be changed; the latter cannot. A court evaluating whether the protocol "provides a marketplace" must contend with the fact that the protocol mathematically cannot identify, much less organize, the marketplace activity it allegedly provides.

The structural defense is complemented by a reasonable-measures defense: the reference implementation includes client-side content classifiers that scan content before encryption, and Jets require proof-of-scan before relaying messages. The protocol developers took affirmative steps to prevent misuse while preserving end-to-end encryption. See `Flagging.md` for the full design — classifier injection, reputation-gated distribution, passive storage scanning, and the anti-griefing mechanism.

### Comparison to Uniswap

Uniswap is the closest precedent for decentralized trading protocol liability. The comparison favors OCP Messaging:

| Dimension | Uniswap | OCP Messaging |
|-----------|---------|---------------|
| Price discovery | AMM curve determines price | No price mechanism; bilateral negotiation |
| Matching | Implicit — every trade matches against a liquidity pool | None — parties exchange signed messages directly |
| Execution | Protocol executes swaps | Generic escrow verifies signatures |
| Visibility | All trades public on-chain | Negotiation encrypted; only settlement on-chain |
| Purpose | Single-purpose trading protocol | General-purpose encrypted messaging |
| Liquidity | Requires LPs to lock capital in pools | No pools, no locked capital |
| On-chain footprint | Swap transactions identifiable as trades | Settlement transactions indistinguishable from any `transferFrom` pair |

The SEC investigated Uniswap Labs and settled (2024) over the front-end — the website that provided the UI for interacting with the Uniswap protocol. The protocol itself (the immutable smart contracts) was not charged. The settlement established that the front-end operator has obligations even if the protocol doesn't.

For OCP Messaging, the equivalent "front-end" would be a chat client that displays intents with an Accept button. But unlike Uniswap's front-end (which shows token pairs, prices, and liquidity — clearly a trading interface), an OCP Messaging client is a chat app. It displays messages. Some messages happen to contain signed intents. The client renders them as structured offers because it can decrypt them, but the client is not a trading platform — it's a messenger that understands a message format.

### Comparison to Tornado Cash

The Tornado Cash prosecution (US v. Roman Storm, SDNY; Netherlands v. Alexey Pertsev) is often cited as a precedent for prosecuting protocol developers. The comparison is unfavorable to the prosecution's theory when applied to OCP Messaging:

1. **Jurisdiction.** Pertsev was convicted in the Netherlands, which lacks the US First Amendment's "code is speech" protection. The Dutch court applied Dutch anti-money-laundering law, which does not require the same level of intent as US law. Storm's US case (SDNY) was still pending as of mid-2025 and involves different legal standards.

2. **Single-purpose vs. general-purpose.** Tornado Cash had one function: mixing cryptocurrency to obscure its origin. OCP Messaging is a general-purpose encrypted messaging protocol with legitimate uses (chat, file sharing, notifications, coordination) that also happens to support trading. The "substantial non-infringing uses" doctrine (Sony v. Universal, 1984) is directly relevant.

3. **Knowledge and facilitation.** The Tornado Cash developers were shown to have known about specific money laundering activity (Lazarus Group, North Korean hacking proceeds) and continued development. OCP Messaging developers structurally cannot know about any specific use — the messages are encrypted. You cannot knowingly facilitate something you cannot observe. Additionally, the reference implementation includes client-side content classifiers (see `Flagging.md`) — a reasonable measure the Tornado Cash developers never took.

4. **OFAC sanctions.** The Fifth Circuit (Van Loon v. Treasury, 2024) ruled that immutable smart contracts are not "property" under IEEPA and cannot be sanctioned by OFAC. This precedent protects the settlement contracts — even if OFAC wanted to sanction the settlement contract, the Fifth Circuit's ruling (binding in its circuit, persuasive elsewhere) says it can't.

5. **Active involvement.** The Tornado Cash developers actively maintained the protocol, operated relayers, and processed fees. OCP Messaging protocol developers deploy immutable contracts and publish an open standard. They do not operate Jets, do not process fees, do not maintain infrastructure. The protocol runs on independent operators' infrastructure.

### First Amendment and code as speech

Under US law, code is speech (Bernstein v. US DOJ, 9th Cir., 1996; Junger v. Daley, 6th Cir., 2000). Publishing an open-source messaging protocol is protected expression. Deploying immutable smart contracts is publishing code.

A prosecution theory that "publishing an encrypted messaging protocol that could be used for trading constitutes operating an exchange" would face strict scrutiny under the First Amendment. The protocol specification is a document. The smart contract source code is a document. The compiled bytecode is a transformation of that document. Deploying it to a blockchain is publishing it.

This does not mean the protocol's creators are immune from all liability. If they actively operate infrastructure (run Jets, process fees, provide a matching service), they may have obligations. But the protocol itself — the specification, the contracts, the message format — is speech.

### Jurisdiction considerations

The protocol is designed to operate across jurisdictions. Different considerations apply:

- **United States:** Strongest First Amendment protections. Exchange Act, broker-dealer, and money transmitter analysis as above. State money transmitter licenses may apply to Jet operators who facilitate value transfer — but a Jet that routes encrypted bytes without accessing value is more analogous to a VPN provider than a money transmitter.

- **European Union:** MiCA (Markets in Crypto-Assets Regulation, effective 2024-2025) regulates crypto-asset service providers. A Jet that routes encrypted messages may not be a "crypto-asset service provider" under MiCA because it does not provide custody, exchange, or transfer services. Analysis depends on how broadly member states interpret "transfer services."

- **United Kingdom:** The FCA regulates crypto-asset activities. Similar analysis to the EU — the question is whether encrypted message routing constitutes a regulated activity.

- **Offshore jurisdictions:** Many token issuances under Reg S originate from jurisdictions with lighter regulation (BVI, Cayman, Singapore). The protocol is jurisdiction-agnostic; the compliance layer (attestations) can be configured per-jurisdiction.

- **Sanctioned jurisdictions:** The protocol does not have a mechanism to block sanctioned jurisdictions at the protocol level (it can't — messages are encrypted, and IP addresses can be masked via Tor). Jet operators may choose to implement IP-level blocking as a business decision, but this is not a protocol feature. The OFAC analysis depends on whether the protocol is "property" (Fifth Circuit says no for immutable contracts) and whether the developer's publication constitutes "facilitation" (First Amendment defense).

---

## Technical roadmap

Implementation is divided into six phases, each deliverable independently. Later phases build on earlier ones but do not block unrelated development on the existing Safecloud storage protocol.

### Phase 1 — Mailbox primitives

**Goal:** Drops can register mailbox public keys with Jets and receive encrypted messages.

**Deliverables:**

1. **Extend `Safecloud/drop/register`** to accept `mailbox: true` and optional `pushEndpoint`. Server-side: add mailbox flag to the Drop's registration record in the Jet's routing table.

2. **New socket event: `Safecloud/mailbox/submit`** — sender submits an encrypted envelope to the Jet, addressed to a recipient pubkey. Jet validates payment proof, stores the envelope in the recipient's queue.

3. **New socket event: `Safecloud/mailbox/deliver`** — Jet pushes queued envelopes to the recipient when they connect via WebSocket. Delivered immediately if online; queued if offline.

4. **Mailbox storage on Jet** — per-pubkey FIFO queue with configurable TTL (default 7 days) and size limit (default 1 MB). Pruning policy: oldest messages dropped first when limit is exceeded. Storage is opaque — the Jet stores encrypted blobs.

5. **PRF-based mailbox key derivation on Drop** — `Q.Crypto.delegate(rootSecret, "mailbox/" + index)` produces a keypair. The Drop manages its own list of mailbox indices and which Jet each is registered on.

6. **Web Push integration** — when a mailbox has a `pushEndpoint` and the Drop is offline, the Jet sends a Web Push notification via the existing `Users.pushNotifications()` stack. Payload is encrypted to the Drop's `notify` key and contains only a signal (which pubkey has messages, count).

**Dependencies:** Existing Safecloud socket infrastructure, `Q.Crypto.delegate`, Users plugin Web Push stack.

**Estimated scope:** ~400 lines server-side (Jet mailbox queue + two socket events + push integration), ~200 lines client-side (mailbox registration + key derivation + message send/receive).

### Phase 2 — OCP message envelope

**Goal:** Standardize the encrypted message format so any client can interoperate.

**Deliverables:**

1. **Binary envelope spec** — the format described in [Message envelope format](#message-envelope-format). Implement as `Q.Safecloud.Message.encode(recipient, payload, senderKey)` and `Q.Safecloud.Message.decode(envelope, recipientKey)`.

2. **Padding implementation** — envelopes padded to 1024-byte boundaries. Encode adds random padding; decode strips it.

3. **Message type registry** — `chat`, `intent`, `accept`, `cancel`, `ack`, `file`, `attestation`, `ping`. Client-side dispatch: `onMessage` event routes to type-specific handlers.

4. **Reply threading** — `replyTo` field in the plaintext payload allows the recipient to respond to the sender's mailbox. The sender includes one of their mailbox pubkeys; the recipient encrypts the reply to that key.

5. **Deduplication** — the `nonce` field in the plaintext payload prevents duplicate processing. The recipient tracks seen nonces (in-memory set with TTL matching the Jet's message TTL).

**Dependencies:** Phase 1 (mailbox primitives), NaCl/libsodium for X25519 + XSalsa20-Poly1305.

**Estimated scope:** ~300 lines for envelope encode/decode, ~200 lines for message type dispatch and threading.

### Phase 3 — Settlement contracts

**Goal:** Deploy immutable settlement contracts on target EVM chains.

**Deliverables:**

1. **`OCPSettlement.sol`** — the contract described in [Settlement contract](#settlement-contract). Solidity, audited, deployed without proxy or admin key. Functions: `settle()`, `cancelNonce()`. Events: `Settled`, `NonceCancelled`.

2. **`IAttestationRegistry.sol`** — interface for attestation verification. The settlement contract calls `verify(address, bytes32, bytes)` on a pluggable registry. A no-op registry (always returns true) is deployed for chains that don't need attestation gating.

3. **`OCPAttestationRegistry.sol`** — reference implementation. Stores attestations as `(address subject, bytes32 claimHash, address issuer, uint256 expiry, bytes signature)`. Anyone can register an attestation; verification checks the issuer's signature and expiry.

4. **Client-side intent builder** — `Q.Safecloud.Trading.createIntent({ offerAsset, offerAmount, askAsset, askAmount, counterparty, expiry, attestations })` returns a signed EIP-712 intent.

5. **Client-side accept builder** — `Q.Safecloud.Trading.acceptIntent(intent, intentSig)` returns a signed EIP-712 accept.

6. **Client-side settlement submitter** — `Q.Safecloud.Trading.settle(intent, intentSig, accept, acceptSig, attestationProofs)` submits the settlement transaction.

7. **Deployment scripts** — Hardhat or Foundry scripts for deploying to target chains. Initial targets: the chains Intercoin already operates on (see `plugin.json` `safebux.chainId`).

**Dependencies:** Phase 2 (for intent/accept message types), ethers.js (already in Safecloud), OpenZeppelin (for `IERC20`, `ECDSA`).

**Estimated scope:** ~200 lines Solidity (settlement + registry), ~300 lines client-side (intent/accept/settle helpers), ~100 lines deployment scripts. Plus audit.

### Phase 4 — Compliance and attestations

**Goal:** Enable Reg S token issuance with on-chain compliance enforcement.

**Deliverables:**

1. **Attestation issuance integration** — client-side flow for obtaining a non-US-person attestation from a third-party KYC provider. The attestation is an EIP-712 signed claim: `{ subject: walletAddress, claim: "non-US-person", issuer: providerAddress, expiry: timestamp }`. The KYC provider performs the identity check; the client receives and stores the signed attestation.

2. **Token contract template** — an ERC-20 with transfer restrictions that integrate with the attestation registry. During the DCP, `transfer` and `transferFrom` check that the recipient has a valid non-US attestation. After the DCP, restrictions are lifted (or reduced to the issuer's preference). The template is configurable: DCP duration, required attestation types, and post-DCP policy.

3. **Issuer toolkit** — a client-side module for creating and managing a token offering via OCP Messaging. Functions: deploy token contract, set DCP parameters, publish offering materials to Safecloud, receive and verify buyer attestations, create and send intents, track settlement status.

4. **Attestation wallet** — client-side storage for the user's attestations. Attestations are stored locally (IndexedDB or equivalent) and presented on demand. The user controls which attestations to present to which counterparty — the protocol does not auto-disclose.

**Dependencies:** Phase 3 (settlement contracts + attestation registry), a third-party KYC provider with an API for issuing EIP-712 attestations.

**Estimated scope:** ~200 lines Solidity (token template), ~500 lines client-side (issuer toolkit + attestation wallet), plus KYC provider integration (varies by provider).

### Phase 5 — Timing resistance and cover traffic

**Goal:** Enable paranoid-mode messaging that resists timing analysis.

**Deliverables:**

1. **HTTP polling endpoint** — `GET /safecloud/mailbox/{pubkeyHex}` with signature-based auth, fixed-size padded responses, and cursor-based pagination. As described in [Transport: WebSocket, HTTP, and Web Push](#transport-websocket-http-and-web-push).

2. **Constant-rate poller** — client-side module that polls at configurable intervals with jitter. Runs in a service worker or background tab. Polls all registered mailboxes plus generates chaff requests to random pubkeys.

3. **Cover traffic generator** — client-side module that sends `ping` type messages at random intervals to the Drop's own mailboxes and to decoy pubkeys. Indistinguishable from real messages.

4. **Batched retrieval mixer** — when fetching mailbox messages via HTTP, the request also fetches regular Safecloud content (chunks the Drop is serving). The Jet sees one HTTP session with multiple GETs — some for mailboxes, some for content, indistinguishable.

5. **Tor integration guide** — documentation for routing HTTP mailbox polls through Tor. No code changes needed — the HTTP endpoint works with any HTTPS client, including `torsocks curl`.

**Dependencies:** Phase 1 (mailbox primitives), Phase 2 (message envelope with ping type).

**Estimated scope:** ~200 lines server-side (HTTP endpoint), ~300 lines client-side (poller + cover traffic + mixer), documentation.

### Phase 6 — Client UX

**Goal:** A usable messaging and trading interface built on top of the protocol layers.

**Deliverables:**

1. **Chat interface** — built as a Qbix tool (`Q.Safecloud.Chat`). Displays decrypted messages in a conversation view. Supports text, file references (with inline preview via Safecloud content fetch), and reply threading.

2. **Intent display** — when a message of type `intent` is received, the chat interface renders it as a structured offer card: asset, amount, price, expiry, with Accept and Decline buttons. Accept triggers the `acceptIntent` flow from Phase 3.

3. **Trading history** — client-side log of sent intents, received intents, accepted trades, and settlement status. Stored locally (the protocol has no server-side trade history because the server can't read the messages).

4. **Mailbox management UI** — view and manage registered mailboxes, see which Jets each is registered on, create new mailboxes, rotate keys.

5. **Attestation management UI** — view stored attestations, request new ones, present them to counterparties.

6. **Group chat** — create and join group mailboxes, manage membership, share group keys via encrypted direct messages.

**Dependencies:** All previous phases. Qbix tools framework.

**Estimated scope:** ~1500 lines (tools, templates, CSS). This is the largest phase but has no novel protocol work — it is UX over existing primitives.

---

## Attack vectors

This section catalogs attacks specific to the messaging and trading layers. See `Attacks.md` for attacks on the underlying storage protocol.

### Timing correlation by colluding Jets

**Attack:** Multiple Jets compare connection timestamps to correlate mailboxes belonging to the same Drop.

**Defense:** Phase 5 mitigations — constant-rate polling via HTTP, jittered multi-Jet access, Tor routing. The Drop never connects to multiple Jets simultaneously or in a predictable sequence.

**Residual risk:** 🟡 Medium. A sufficiently powerful adversary controlling many Jets can perform statistical correlation over long periods. Full defense requires Tor or VPN rotation.

### Intent front-running

**Attack:** Eve intercepts Alice's signed intent (e.g., from a group mailbox) and submits it to the settlement contract before Bob can accept.

**Defense:** The `counterparty` field. If Alice specified Bob's address, Eve cannot settle against the intent. If Alice left the counterparty open (0x0), front-running is possible by design — Alice accepted this risk by making an open offer.

**Residual risk:** 🟢 Low when `counterparty` is set. 🟡 Medium for open offers — mitigated by short expiry times.

### Griefing via nonce exhaustion

**Attack:** Eve sends many `accept` messages for Alice's open intent. Alice's client wastes resources verifying and discarding invalid accepts.

**Defense:** Rate limiting on the Jet (per-pubkey message rate limits), and client-side dedup (ignore accepts for already-settled or cancelled intents).

**Residual risk:** 🟢 Low. The cost of sending messages (micropayment per message) makes large-scale griefing expensive.

### Replay of settled intents

**Attack:** Eve replays a previously settled intent/accept pair.

**Defense:** On-chain nonce tracking. Once nonce N is used (settled or cancelled), the contract rejects any future settlement with that nonce. The nonce is per-offerer, so Eve cannot interfere with Alice's other intents.

**Residual risk:** 🟢 Resolved by contract logic.

### Attestation forgery

**Attack:** Eve forges a non-US attestation to participate in a Reg S offering.

**Defense:** Attestations are signed by a KYC provider's key. The attestation registry verifies the signature. Eve would need to compromise the KYC provider's signing key — the same attack that would compromise any certificate-based system.

**Residual risk:** 🟢 Low — same trust model as TLS certificates. Issuers can require attestations from multiple providers for higher assurance.

### Jet censorship

**Attack:** A Jet refuses to deliver messages to or from a specific pubkey.

**Defense:** The Drop has mailboxes on multiple Jets. Censorship by one Jet affects only the messages on that Jet. The Drop detects censorship by comparing message counts across mailboxes and rotates away from censoring Jets.

**Residual risk:** 🟢 Low when multiple Jets are used. 🟡 Medium for users relying on a single Jet.

### Settlement contract front-running (MEV)

**Attack:** A block producer sees a pending settlement transaction and front-runs it (e.g., buying the offered tokens before the settlement executes, or sandwiching the settlement).

**Defense:** The settlement contract is a fixed-price escrow, not an AMM. There is no price impact from the trade. A front-runner who buys the same token on an AMM before the settlement does not affect the settlement price. Sandwich attacks are ineffective because the settlement is not price-sensitive.

**Residual risk:** 🟢 Low. MEV is primarily a concern for AMM trades, not fixed-price OTC settlements.

### Malicious group admin

**Attack:** A group admin shares the group decryption key with unauthorized parties, allowing them to read group messages (including trading intents).

**Defense:** Group key rotation. When membership changes, the admin distributes a new group key to remaining members. Messages encrypted with the old key are still readable by anyone who had it, but new messages are not. This is a fundamental limitation of symmetric group encryption — identical to the risk in any group chat.

**Residual risk:** 🟡 Medium. Mitigated by key rotation and social trust in the group admin.
