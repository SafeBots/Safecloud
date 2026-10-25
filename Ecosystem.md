# Safecloud — Ecosystem Overview

## Table of Contents

- [Overview](#overview)
- [The stack](#the-stack)
- [Compute: SafecloudApps on Jets](#compute-safecloudapps-on-jets)
- [Storage: SafecloudDB and Drops](#storage-safeclouddb-and-drops)
- [The epoch protocol](#the-epoch-protocol)
  - [What an epoch is](#what-an-epoch-is)
  - [Bidirectional hash chains](#bidirectional-hash-chains)
  - [Epoch transitions](#epoch-transitions)
  - [Why one protocol](#why-one-protocol)
- [End-to-end encrypted chat](#end-to-end-encrypted-chat)
  - [Per-message keys](#per-message-keys)
  - [Group membership changes](#group-membership-changes)
  - [Transcript simulability](#transcript-simulability)
- [Content safety in E2E chat](#content-safety-in-e2e-chat)
  - [Pre-encryption scanning](#pre-encryption-scanning)
  - [Per-message key escrow](#per-message-key-escrow)
  - [Threshold ElGamal](#threshold-elgamal)
  - [Proof of escrow](#proof-of-escrow)
  - [Consent via consents.to](#consent-via-consentsto)
  - [Honest gaps](#honest-gaps)
- [Keychains](#keychains)
  - [Structure](#structure)
  - [Fork detection](#fork-detection)
  - [Recovery protocol](#recovery-protocol)
- [Delegated identity](#delegated-identity)
  - [How delegation works](#how-delegation-works)
  - [Brand and organizational delegation](#brand-and-organizational-delegation)
  - [Revocation as epoch transition](#revocation-as-epoch-transition)
- [Organizations and DAOs](#organizations-and-daos)
  - [Roles as hash chains](#roles-as-hash-chains)
  - [Governance](#governance)
  - [Comparison to on-chain DAOs](#comparison-to-on-chain-daos)
- [Neighborhood cameras](#neighborhood-cameras)
  - [Per-minute keys](#per-minute-keys)
  - [Threshold-gated decryption](#threshold-gated-decryption)
  - [Community governance](#community-governance)
- [How the pieces connect](#how-the-pieces-connect)
- [What this means for developers](#what-this-means-for-developers)
- [Attack surface summary](#attack-surface-summary)

---

## Overview

Safecloud is several things at once. It is an encrypted storage network (Drops hold ciphertext, Jets route and coordinate). It is a compute platform (Jets execute SafecloudApp WASM handlers, comparable to Cloudflare Workers). It is a database (SafecloudDB stores prolly trees as encrypted chunks). And it is a cryptographic identity and governance layer, where the same hash-chain protocol that provides forward and backward secrecy in chat also manages key lifecycles, organizational roles, device authorization, and threshold-gated access to surveillance footage.

This document ties those layers together. The individual pieces are documented elsewhere — Apps.md covers the WASM execution model, Protocol.md covers inter-node communication, Flagging.md covers content moderation for distributed storage, and README.md covers the storage primitives. This document is about the connections between them, and about the capabilities that emerge when those connections are drawn.

The central claim is that a single cryptographic primitive — a bidirectional hash chain with epoch-based membership transitions — unifies what would otherwise be separate systems for chat encryption, key management, identity delegation, organizational access control, and privacy-preserving surveillance. This is not a coincidence of API shape. The math is the same. The protocol is the same. The code paths share `Q.Crypto.delegate`, HKDF derivation via `Q.Data.derive`, and OCP grants verified by `Client.js verifyGrant`. What differs is the scope and the parameters. EpochProtocol.md provides the full implementation reference — data structures, algorithms, invariants, and failure modes — for anyone implementing, auditing, or extending the epoch protocol.

---

## The stack

```
┌─────────────────────────────────────────────────┐
│  Client applications (browser / native)         │
│  E2E encryption, scanning, key management       │
├─────────────────────────────────────────────────┤
│  SafecloudApps (WASM on Jets)                   │
│  Handlers, triggers, route handlers             │
│  Deterministic, sandboxed, auditable            │
├─────────────────────────────────────────────────┤
│  SafecloudDB (prolly trees on Drops)            │
│  Per-track HKDF-derived encryption keys         │
│  Keychains, chat state, org roles, audit logs   │
├─────────────────────────────────────────────────┤
│  Safecloud storage (encrypted chunks on Drops)  │
│  Content-addressed, replicated, incentivized    │
├─────────────────────────────────────────────────┤
│  OCP (auth) + Safebux (payment)                 │
│  Cryptographic delegation, micropayments        │
└─────────────────────────────────────────────────┘
```

Every layer is encrypted by default. Jets never see plaintext content. Drops never see plaintext content. Only the endpoints — the people and devices holding the right keys — can decrypt.

---

## Compute: SafecloudApps on Jets

SafecloudApps are WASM handlers stored at content addresses on Safecloud. When a request arrives at a Jet, the Jet loads the handler, provides it with the request payload and access to SafecloudDB, executes it in a metered sandbox, and returns a typed SafecloudEnvelope. The handler's WASM is public and deterministic — anyone can download it and verify what rules it enforces.

This is comparable to Cloudflare Workers in shape: stateless request handlers with access to a database, running at the edge, paid per invocation. The differences are that the compute nodes are permissionless (any operator can run a Jet), the storage is encrypted end-to-end (the Jet enforces access rules but cannot read the data it guards), and the execution is verifiable (SafecloudReceipts form a tamper-evident hash chain of what ran, what it read, and what it produced).

Apps.md documents the execution model, manifest format, host API, SafecloudEnvelope structure, SafecloudReceipt format, and SafecloudChain mechanics in full. The relevant point for this document is that SafecloudApps are the programmable layer on top of which everything else in this document runs. Keychains are SafecloudDB tracks. Chat state is SafecloudDB tracks. Organizational roles are SafecloudDB tracks. Threshold escrow workflows are SafecloudApp handlers. The epoch protocol described below is enforced by WASM handlers and recorded in SafecloudChains.

---

## Storage: SafecloudDB and Drops

SafecloudDB is the database layer. Under the hood it is prolly trees (SafecloudTree) stored as encrypted chunks (SafecloudStore) on Drops. Each track has its own HKDF-derived encryption key, so a handler that can read one track cannot read another unless it holds the relevant key.

Tracks are the unit of state for everything in this document. A keychain is a track. A chat conversation's message history is a track. An organization's role membership list is a track. A camera's key archive is a track. The prolly tree structure gives O(diff × log n) reconciliation between nodes that have been offline, and every root CID is an immutable snapshot — the entire history is available for audit.

The storage is incentivized: Drops earn Safebux for holding and serving chunks. Supply follows demand because serving is profitable. There is no central storage provider to rent capacity from or negotiate SLAs with.

---

## The epoch protocol

### What an epoch is

An epoch is a period during which a fixed set of participants shares a fixed set of keys. When the participant set changes — someone joins, someone leaves, someone's device is compromised, someone's role is revoked — the current epoch ends and a new one begins. The new epoch has new keys. Participants in the new epoch cannot derive keys from old epochs they weren't part of (backward secrecy). Participants from old epochs who were excluded from the new one cannot derive new-epoch keys (forward secrecy).

### Bidirectional hash chains

The mechanism is a pair of hash chains running in opposite directions:

- **Forward chain** (provides forward secrecy): `F_{k+1} = H(F_k)`. Each message's forward component is derived by hashing the previous one. An attacker who compromises a current key cannot reverse the hash to recover past keys.
- **Backward chain** (provides backward secrecy): `B_0` is the seed, `B_k = H^{n-k}(B_0)`. The seed is revealed only at the end of the epoch. Until then, participants receive backward-chain values one at a time, in order, and cannot jump ahead. An attacker who compromises a current key can compute forward along the backward chain (deriving past backward values), but those past values are combined with past forward values they cannot recover — so past message keys remain safe.

The per-message key is: `K_msg = HKDF(F_k || B_k)`.

This is non-interactive. No handshake is needed. No round trips. A participant who knows the current forward value and the current backward value can derive the current message key. Adding a participant means giving them the current F_k and B_k. Removing a participant means starting a new epoch (new F_0, new B_0) and distributing the new values only to remaining participants. The removed participant never learns the new epoch's chains.

### Epoch transitions

An epoch transition is:

1. The current epoch's backward seed `B_0` is revealed to all current participants (so they can decrypt any messages from this epoch they haven't yet received).
2. A new forward seed `F'_0` and backward seed `B'_0` are generated.
3. The new seeds are distributed to the new participant set (which may include new members and exclude removed ones).
4. A signed epoch-transition record is appended to the relevant hash chain (keychain, chat state, role membership — whatever scope this epoch belongs to).

This is O(1) for single membership changes. No per-message overhead scales with group size. No ratchet state to synchronize between devices.

### Why one protocol

The math above works identically regardless of what the "messages" are and who the "participants" are:

| Application | Epoch scope | Participants | "Message" | Transition trigger |
|---|---|---|---|---|
| E2E chat | Conversation | Chat members | A chat message | Member added/removed |
| Keychain | Identity | Devices | A key operation (add/rotate/revoke) | Device added/compromised |
| Organization role | Role | Role holders | A role action (grant/permission) | Member granted/revoked role |
| Camera footage | Camera-minute | Authorized viewers | A minute of footage | Viewer set changes |
| Recovery | Identity (new epoch) | Recovery participants | Recovery attestation | Recovery triggered |

The implementation shares `Q.Crypto.delegate` for key derivation, `Q.Data.derive` (HKDF) for chain advancement, and OCP grants (verified by `Client.js verifyGrant`) for membership proofs. Different parameters, same code.

---

## End-to-end encrypted chat

### Per-message keys

Chat messages are encrypted end-to-end between participants. The Jet never sees plaintext. Each message is encrypted under `K_msg = HKDF(F_k || B_k)` where F_k and B_k are the current positions on the forward and backward hash chains for this conversation's current epoch. The sender encrypts locally, sends ciphertext to the Jet, and the Jet routes it to recipients who decrypt locally.

### Group membership changes

When a member is added to a group conversation, they receive the current F_k and B_k. They can decrypt messages from that point forward. They cannot decrypt past messages (they don't have past forward-chain values, and knowing B_k does not help because past message keys require past F values they cannot derive).

When a member is removed, a new epoch begins. The remaining members receive new chain seeds. The removed member cannot derive new-epoch keys. This is O(1) — no per-message rekeying, no ratchet state proportional to group size.

### Transcript simulability

The protocol provides full transcript simulability: anyone who knows the conversation key can construct a valid-looking transcript attributing any content to any participant. This is the same deniability property as Signal's. No message carries cryptographic proof that a specific person sent it. A leaked transcript is circumstantial evidence, not cryptographic evidence. This is a feature, not a limitation — it protects participants from coerced disclosure and selective quoting.

---

## Content safety in E2E chat

E2E encryption means the Jet cannot scan message content. The Flagging.md content moderation system, which operates on content that passes through Jets during distribution, does not apply directly to chat messages that the Jet never decrypts. A different approach is needed.

### Pre-encryption scanning

The standard Safecloud client scans message content before encryption on the sender's device and after decryption on the recipient's device. The scanning uses the same classifier infrastructure as Flagging.md's pre-encryption scan. If the classifier flags content (particularly CSAM), the client takes action before the message is sent or after it is received.

The scan runs in the client. A modified client can skip it. This is addressed below.

### Per-message key escrow

When the client-side classifier flags a message, the client does not escrow the conversation key or any chain value. It escrows the specific per-message key `K_msg` for that one message, encrypted under a threshold public key `PK_threshold`. This limits exposure: even if the threshold group decrypts the escrow, they learn the content of one message, not the entire conversation history.

The escrow ciphertext is `Enc(PK_threshold, K_msg)` — a standard ElGamal encryption of the message key under the combined threshold public key.

### Threshold ElGamal

The threshold group is a set of n parties who performed distributed key generation (DKG) to produce a combined public key `PK_threshold`. No single party holds the full private key. To decrypt an escrowed `K_msg`, at least k of the n parties must produce partial decryptions, which are then combined to recover the plaintext key. This is pure cryptography — no TEE or Safebox is required.

The threshold group's composition is a governance decision. It could be a panel of community moderators, a set of legal officers, an external oversight board, or a mix. The k-of-n parameters determine how many must agree before any escrowed content is revealed. A SafecloudApp handler manages the request/approve/combine workflow and records every unlock in a SafecloudChain audit trail.

### Proof of escrow

For media messages (images, video), the Jet requires the sender to include the escrow ciphertext alongside the message ciphertext. The Jet can verify that the escrow is well-formed (a valid ElGamal ciphertext under `PK_threshold`) without knowing what key it encrypts. A sender who submits media without a valid escrow ciphertext has their message rejected by the Jet.

A sender who escrows garbage (encrypts a random value instead of the real `K_msg`) passes the well-formedness check. But when the threshold group later decrypts the escrow (triggered by a report or flag), the resulting key produces garbage when applied to the message ciphertext. This is detectable — the decrypted content will not parse as a valid message. Garbage escrow is therefore evidence of deliberate evasion, which is itself a policy violation.

### Consent via consents.to

Users of the standard Safecloud client consent to the escrow terms as part of using the service. This consent is recorded through consents.to — a third-party attestation service that provides timestamped, auditable consent records. The consent is: "I understand that if the client-side classifier flags a message I send, the per-message key for that specific message will be escrowed under threshold encryption, and a threshold group may decrypt it following the stated process."

This is opt-in in the sense that the user chose to use the standard client, which has this behavior. A user who objects can use a third-party client — which will not have the scanning or escrow — but will be unable to submit media messages (proof-of-escrow requirement) and may face reputation consequences if they're reported and no escrow exists to corroborate or dismiss the report.

### Honest gaps

Two willing bad actors using modified clients can exchange CSAM without triggering any of these mechanisms. The modified clients skip scanning, submit garbage escrow (or no escrow, for text-only messages), and the recipients willingly decrypt without client-side post-scan. This is the same gap that exists in Signal, Session, Threema, and every other E2E system. No cryptographic protocol can prevent two cooperating adversaries from communicating content between themselves. The goal is not perfection — it is raising the cost and leaving forensic traces (garbage escrow detection, reputation signals, the inability to send media without escrow) that make the platform a hostile environment for this activity compared to platforms with no measures at all.

---

## Keychains

### Structure

A keychain is a single-writer hash-chained log stored as a SafecloudDB track at `keychain/{pubkey-fingerprint}`. Each entry is a key lifecycle operation:

```json
{
  "op":        "rotate | add | revoke",
  "keyType":   "signing | encryption | threshold-share",
  "key":       "base64...",
  "prevHash":  "sha256:...",
  "recovery":  "base64...",
  "timestamp": 1697500000,
  "signature": "..."
}
```

Entries are signed by the keychain owner (using any current signing key) and hash-chained via `prevHash`. The chain is append-only from the writer's perspective. Readers verify the chain by walking `prevHash` links back to the genesis entry.

A keychain IS a hash chain with epochs. Adding a device key is joining the epoch. Rotating a key is an epoch transition. Revoking a key is excluding a participant from the next epoch. The same forward/backward chain math applies: after a key rotation, the old key cannot derive the new epoch's secrets. After a device is revoked, it cannot participate in future epochs.

### Fork detection

Because keychains are single-writer, a fork — two entries with the same `prevHash` — means one of two things: the writer's signing key was stolen, or the writer is equivocating (publishing different histories to different readers). Either way, the fork is detectable via gossip: any two readers who compare notes will discover the conflicting entries. A fork invalidates the entire keychain from the fork point forward.

No EVM, blockchain, or Safebox is required for fork detection. It is an inherent property of hash chains with gossip. The cost of forking is total: the forker loses their identity from the fork point onward and must go through the recovery protocol to re-establish a valid keychain.

### Recovery protocol

Recovery requires BOTH of two independent thresholds:

1. **M-of-N friend attestations**: M out of N pre-designated friends attest that the recovery is legitimate.
2. **A-of-B cold personal keys**: A out of B cold keys (hardware tokens, paper keys, keys in a safe deposit box) sign the recovery request.

Neither group alone can recover the identity. Friends alone cannot commandeer the account (preventing the "M friends conspire" attack). Cold keys alone cannot recover (preventing a thief who steals the safe deposit box from taking over). Both thresholds must be met simultaneously.

The recovery process:

1. **SOS posted**: An SOS entry is posted to the keychain, signed by any current key (even a compromised one — the point is to start the clock).
2. **72-hour window opens**: The network observes the SOS and begins a waiting period.
3. **Cold key signatures collected**: A-of-B cold keys sign the recovery request.
4. **Friend attestations collected**: M-of-N friends sign attestations confirming the recovery is legitimate.
5. **Both thresholds met**: A new keychain genesis is created. The old keychain is tombstoned from the SOS point forward.
6. **Counter-SOS**: If a competing SOS appears (indicating active key theft, where the attacker is also trying to "recover"), the keychain freezes. Resolution requires cold keys — the attacker is unlikely to have both the compromised online keys AND the cold keys.

Recovery is itself an epoch transition. The new keychain genesis starts a new epoch with new keys. The old epoch's keys remain valid for decrypting historical content but cannot be used for new operations.

---

## Delegated identity

### How delegation works

Safecloud already has `Q.Crypto.delegate`, which derives a child secret from a parent secret via HKDF and creates a signed OCP grant proving the parent authorized the child. Keychain entries are OCP grants — the same `Delegation` typed data structure verified by `Client.js verifyGrant`. This means delegation is not a new mechanism bolted onto the identity system; it is the identity system.

### Brand and organizational delegation

A brand or organization can delegate its identity to a manager or employee via an OCP grant recorded in the brand's keychain:

- The brand's keychain contains a delegation entry: "public key X is authorized to act as this brand in context Y."
- The delegate's messages carry the delegation proof in the message envelope.
- Recipients verify the delegation chain: the delegate's key was authorized by the brand's key, which is in the brand's keychain, which has a valid hash chain back to genesis.

The delegate acts as the brand in conversations, signs messages with their own key, and the delegation proof establishes the authority. No shared password. No shared private key. The delegate has a derived key that proves authorization without holding the brand's root secret.

### Revocation as epoch transition

Revoking a delegate is an epoch transition on the brand's keychain. A new entry records the revocation, a new epoch begins, and the revoked delegate's derived key can no longer be used for new operations. Existing messages signed during the delegation period remain verifiable — the delegation was valid when they were signed — but new messages from the revoked key will fail delegation chain verification because the keychain shows the delegation was revoked.

---

## Organizations and DAOs

### Roles as hash chains

The patent's multi-participant chat protocol maps directly to organizational role management. A "role" is a conversation. Granting a role is adding a member. Revoking a role is removing a member (epoch transition). The members of a role share the role's current epoch keys and can perform role-scoped actions.

```
org/acme/
  roles/
    admin        <- hash chain, members: [alice, bob]
    finance      <- hash chain, members: [alice, carol]
    support      <- hash chain, members: [dave, eve, frank]
    public       <- hash chain, members: [everyone]
  governance/
    board        <- hash chain, members: [alice, bob, carol]
```

Each role is a SafecloudDB track. The track contains the hash-chained epoch history for that role. The current epoch's participant list is the current set of role holders. Adding a member to the "admin" role is the same operation as adding a member to a chat group: distribute the current epoch keys to the new member, record the membership change. Removing a member is the same operation as removing a chat member: start a new epoch, distribute new keys to remaining members, record the transition.

### Governance

Governance is itself a role — a role whose actions require threshold approval. The "board" role in the example above might require 2-of-3 signatures for certain actions (adding a new admin, changing the governance rules, revoking a member). This is implemented via threshold signatures on epoch-transition records: an epoch transition in a governed role requires k-of-n signatures from the governance role's current members.

The governance role's own membership changes are governed by itself (or by a higher-level governance role, for organizations with layered governance). The base case — who governs the governors — bottoms out at the keychain level: the organization's root keychain, controlled by whoever holds the root keys, with recovery via the dual-threshold protocol described above.

### Comparison to on-chain DAOs

On-chain DAOs use smart contracts for role management and voting. This works but ties governance to a specific blockchain, requires gas for every action, and makes every governance action publicly visible on-chain.

Safecloud organizations use the epoch protocol for role management and threshold signatures for voting. This is chain-agnostic (no blockchain required, though one can be used for timestamping), free (no gas — operations are SafecloudDB writes), and private (role membership and governance actions are encrypted, visible only to participants). The trade-off is that ordering disputes are resolved by gossip and fork detection rather than by a global consensus mechanism. For most organizations, this is sufficient — governance disputes that require global consensus are rare, and when they occur, the fork-detection mechanism surfaces them for human resolution.

---

## Neighborhood cameras

The epoch protocol also solves community surveillance with privacy. A neighborhood can operate cameras on Safecloud without any central authority having access to the footage.

### Per-minute keys

Each camera encrypts its footage with a fresh symmetric key every minute. The per-minute key is derived via HKDF from the camera's root key and the minute timestamp. The encrypted footage is stored on Drops, like any other Safecloud content. The per-minute keys are not stored in plaintext anywhere.

### Threshold-gated decryption

Each per-minute key is escrowed under threshold ElGamal, the same mechanism used for chat content safety. To decrypt footage from a specific minute, a requester must:

1. Submit a request specifying the camera, the time range, and the reason.
2. Obtain k-of-n approvals from the threshold group (community board members, elected overseers, or a combination).
3. Each approving member produces a partial decryption.
4. The partial decryptions are combined to recover the per-minute key.
5. The requester decrypts the footage.

A SafecloudApp handler manages this workflow: accepting requests, routing approvals, combining partial decryptions, and recording every access in a SafecloudChain audit trail. Every decryption attempt is logged with who requested it, who approved it, what reason was given, and when it happened.

### Community governance

The community owns the governance of its camera network:

- **Who is in the threshold group** is decided by the community (election, appointment, rotation — whatever governance model the community adopts).
- **What k-of-n policy applies** is a community decision (stricter thresholds for residential cameras, looser for parking lots, etc.).
- **What reasons are acceptable** is a community policy, enforced socially through the audit trail (every reason is logged and reviewable).
- **What happens when someone abuses access** is visible in the audit trail. Bulk decryption attempts, suspicious reason patterns, and access outside stated policy are all detectable.

No Safebox or TEE is required. The security comes from threshold cryptography (no single party can decrypt alone) and the audit trail (every action is logged). The community's recourse against abuse is the same as any governance system: remove bad actors from the threshold group, which is an epoch transition.

---

## How the pieces connect

The layers are not independent. They compose:

1. **SafecloudApps run on Jets**, executing WASM handlers that read and write SafecloudDB tracks, producing SafecloudEnvelopes and SafecloudReceipts.

2. **Keychains are SafecloudDB tracks**, managed by SafecloudApp handlers that enforce the key lifecycle rules (add, rotate, revoke, recover).

3. **Chat conversations are SafecloudDB tracks**, with epoch state managed by the same protocol as keychains, and message routing handled by Jets.

4. **Organizational roles are SafecloudDB tracks**, with membership managed by the same epoch protocol, and governance enforced by threshold signatures on epoch transitions.

5. **Camera escrow workflows are SafecloudApp handlers**, using the same threshold ElGamal as chat content safety, with the same audit trail infrastructure.

6. **Content safety (Flagging.md) applies to content distributed through Jets** — uploads, streams, static content. **Chat content safety applies at the client level** — pre-encryption scanning, per-message key escrow, proof of escrow — because the Jet never sees chat plaintext.

7. **OCP grants are the universal auth mechanism.** A delegation from a brand to an employee uses the same `Q.Crypto.delegate` as a storage access grant from a file owner to a viewer. The types differ (role delegation vs. chunk access). The cryptography is identical.

8. **Safebux pays for everything.** Storage on Drops, compute on Jets, bandwidth for chat message routing, trigger executions. One payment rail, one incentive mechanism, one market.

The result is a platform where:

- A developer publishes WASM handlers and a static frontend. Any Jet can serve the app. The network scales because serving is profitable.
- An organization manages its roles, permissions, and governance through cryptographic epochs rather than a database table guarded by an admin password.
- A chat conversation has forward secrecy, backward secrecy, and deniability, with content safety measures that don't require anyone to hold a master decryption key.
- A community operates a camera network where nobody can access footage without threshold approval and an audit trail.
- Identity recovery doesn't depend on a company's customer support team. It depends on the dual-threshold protocol — friends who vouch for you AND cold keys that prove you planned for this.

---

## What this means for developers

A developer building on Safecloud gets:

**Cloudflare Workers parity.** WASM handlers on Jets, SafecloudDB for state, triggers for scheduled and event-driven execution, route handlers for dynamic HTTP responses. The developer writes handlers, publishes them at a CID, and any Jet can execute them. No deploy pipeline. No server provisioning. No scaling configuration.

**E2E encryption by default.** The storage layer is encrypted. The database layer is encrypted. Chat is encrypted end-to-end. The developer does not need to implement encryption — it is the platform's default mode. Access control is key release, enforced by the developer's WASM handlers.

**Cryptographic identity and auth.** OCP claims replace JWTs, API keys, and OAuth tokens. Delegation chains replace role tables. Keychain verification replaces "check if the session cookie is valid." The developer does not manage a user database — users bring their own keychains.

**Organizational primitives.** Role management, governance, threshold approvals, delegation — these are platform features, not things the developer builds from scratch. A developer building a project management tool does not need to implement RBAC. The epoch protocol already provides it.

**Content safety infrastructure.** The flagging system, reputation system, threshold escrow, and audit trail are platform services. A developer building a messaging app does not need to build a trust-and-safety team's entire backend. The platform provides the scanning, escrow, and reporting infrastructure. The developer's WASM handlers define app-specific policy on top of it.

---

## Attack surface summary

Every system described here has known attack surfaces. They are documented in detail in Attacks.md (sections 10–11 cover the epoch protocol and E2E chat specifically), EpochProtocol.md (implementation reference for the bidirectional hash-chain protocol), and Flagging.md. This is a summary of the honest gaps and mitigations for the ecosystem as a whole.

| Attack | Mitigation | Honest gap |
|---|---|---|
| Modified client skips scanning | Proof-of-escrow for media; reputation gating for text | Two cooperating bad actors with modified clients can exchange text without escrow. Same as Signal. |
| Fake escrow (garbage key) | Detectable when threshold decryption is triggered — garbage key produces garbage plaintext | Only detectable after the fact, when someone triggers decryption. Proactive detection requires a TEE (Safebox, v2). |
| Threshold group collusion | Rate limits on decryption requests, public audit trail, community governance of threshold membership | A colluding threshold group with k members can decrypt anything. Mitigation is social (accountability via audit trail) not cryptographic. |
| Authority coercion of threshold members | Approvals are permanently signed records (like a warrant — creates a paper trail) | A sufficiently coercive authority can compel k members. The audit trail ensures this is visible. |
| Key share theft (threshold member) | DKG key refresh — reshare without changing the public key | Window of vulnerability between theft and refresh. |
| Keychain fork (key theft) | Fork detection via gossip invalidates the forked chain | Attacker may act during the window between fork and detection. |
| Recovery by friend collusion | Requires BOTH M-of-N friends AND A-of-B cold keys | Attacker who steals both friend keys and cold keys can take over. Physical security of cold keys is outside protocol scope. |
| Organizational role abuse | Audit trail, governance thresholds, epoch transitions for revocation | An insider with a valid role can act within that role's scope until revoked. Same as any access control system. |
| Jet misbehavior (dropping messages, selective routing) | SafecloudReceipts and SafecloudChains provide verifiable execution history; clients can use multiple Jets | A Jet can selectively delay or drop messages. Mitigation is redundancy and detection, not prevention. |
