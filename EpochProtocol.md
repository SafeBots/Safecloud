# Safecloud — Epoch Protocol Reference

This document specifies the bidirectional hash-chain epoch protocol that underlies chat encryption, keychains, organizational role management, delegated identity, and threshold-gated camera footage in Safecloud. Ecosystem.md describes what the epoch protocol does and why one protocol suffices for all these applications. This document describes how it works at the implementation level — the data structures, the algorithms, the invariants, and the failure modes.

Read Ecosystem.md first for motivation and architecture. Read this document when you need to implement, audit, or extend the epoch protocol.

---

## Table of Contents

- [Core primitives](#core-primitives)
  - [Hash chains](#hash-chains)
  - [Key derivation](#key-derivation)
  - [Epoch state](#epoch-state)
- [Epoch lifecycle](#epoch-lifecycle)
  - [Epoch creation](#epoch-creation)
  - [Message key derivation](#message-key-derivation)
  - [Epoch transition](#epoch-transition)
  - [Backward seed reveal](#backward-seed-reveal)
- [Membership operations](#membership-operations)
  - [Adding a participant](#adding-a-participant)
  - [Removing a participant](#removing-a-participant)
  - [Batch membership changes](#batch-membership-changes)
- [Chain storage](#chain-storage)
  - [SafecloudDB track layout](#safeclouddb-track-layout)
  - [Epoch record format](#epoch-record-format)
  - [Membership record format](#membership-record-format)
- [Security invariants](#security-invariants)
  - [Forward secrecy](#forward-secrecy)
  - [Backward secrecy](#backward-secrecy)
  - [Non-interactivity](#non-interactivity)
  - [Transcript simulability](#transcript-simulability)
- [Scaling](#scaling)
  - [Small groups](#small-groups)
  - [Large groups and key trees](#large-groups-and-key-trees)
  - [Epoch transition cost](#epoch-transition-cost)
- [Application-specific parameters](#application-specific-parameters)
  - [Chat](#chat)
  - [Keychains](#keychains)
  - [Organizational roles](#organizational-roles)
  - [Camera footage](#camera-footage)
- [Implementation notes](#implementation-notes)
  - [Cryptographic dependencies](#cryptographic-dependencies)
  - [Determinism requirements](#determinism-requirements)
  - [Error handling](#error-handling)

---

## Core primitives

### Hash chains

The epoch protocol uses two hash chains running in opposite directions within each epoch.

**Forward chain.** The forward chain provides forward secrecy. Given a forward seed `F_0`, subsequent values are computed by iterated hashing:

```
F_0 = random(32)             // 256-bit random seed
F_1 = SHA-256(F_0)
F_2 = SHA-256(F_1)
...
F_k = SHA-256(F_{k-1})
```

The forward chain is one-way: knowing `F_k` does not reveal `F_{k-1}`. An attacker who compromises the current forward value cannot recover past forward values, and therefore cannot recover past message keys.

**Backward chain.** The backward chain provides backward secrecy (post-compromise security). Given a backward seed `B_0` and a maximum epoch length `n`, backward values are precomputed in reverse:

```
B_0 = random(32)             // 256-bit random seed (revealed at epoch end)
B_n = B_0
B_{n-1} = SHA-256(B_n)
B_{n-2} = SHA-256(B_{n-1})
...
B_k = SHA-256^{n-k}(B_0)
```

Participants receive backward values one at a time, in order: `B_1, B_2, ...`. A participant who knows `B_k` can compute `B_{k-1}, B_{k-2}, ...` (by hashing forward), but cannot compute `B_{k+1}` (cannot reverse the hash). This means a compromise of the current state reveals past backward values but not future ones. Combined with the forward chain (where past values are also unrecoverable), past message keys remain safe even under current-state compromise.

The backward seed `B_0` is revealed to all epoch participants when the epoch ends (during an epoch transition), allowing them to decrypt any messages from the epoch they missed.

### Key derivation

The per-message key combines both chain positions at index `k`:

```
K_msg = HKDF-SHA256(
    ikm  = F_k || B_k,
    salt = context_id,        // roomId, keychainId, roleId, etc.
    info = "safecloud-epoch-msg" || epoch_index || msg_index,
    len  = 32
)
```

The `context_id` binds the derived key to a specific scope (a chat room, a keychain, an organizational role). The `epoch_index` and `msg_index` in the `info` parameter ensure that even if two contexts happen to share the same chain values (which should never happen with proper random seeding), the derived keys are different.

In Safecloud's implementation this is `Q.Data.derive(F_k || B_k, salt, info)`, which wraps HKDF-SHA256.

### Epoch state

An epoch is the combination of:

```json
{
    "epochIndex": 3,
    "forwardSeed": "base64...",
    "backwardChainEnd": "base64...",
    "maxLength": 10000,
    "members": ["pubkey1", "pubkey2", "pubkey3"],
    "createdAt": 1697500000,
    "createdBy": "pubkey1",
    "prevEpochHash": "sha256:...",
    "signature": "..."
}
```

- `epochIndex`: monotonically increasing counter, starting at 0.
- `forwardSeed`: `F_0` for this epoch. Each participant receives this encrypted under their public key.
- `backwardChainEnd`: `B_1` for this epoch (the first backward value participants can use). `B_0` (the seed) is withheld until the epoch ends.
- `maxLength`: maximum number of messages in this epoch before a mandatory transition. Limits the precomputation required for the backward chain.
- `members`: public keys of all participants in this epoch.
- `prevEpochHash`: SHA-256 of the previous epoch record, forming a hash chain of epochs.
- `signature`: signed by the participant who initiated the epoch transition.

---

## Epoch lifecycle

### Epoch creation

When a new context is created (a chat room, a keychain, an organizational role), the creator initializes epoch 0:

1. Generate `F_0 = random(32)` — the forward seed.
2. Generate `B_0 = random(32)` — the backward seed.
3. Compute `B_1 = SHA-256^{n-1}(B_0)` where `n = maxLength`. This is the first backward value participants will use. (In practice, the creator precomputes a table of backward values for the epoch, or computes them on demand.)
4. For each member, encrypt `(F_0, B_1)` under that member's public key and store the ciphertext in the epoch record.
5. Write the epoch record to SafecloudDB.
6. The epoch is now active. The chain position starts at `k = 1`.

### Message key derivation

When a participant wants to encrypt or decrypt message `k` in the current epoch:

1. Compute `F_k = SHA-256^k(F_0)`. (In practice, participants cache the current forward value and advance it by one hash per message.)
2. Retrieve `B_k`. For the sender, this means computing `SHA-256^{n-k}(B_0)` (or looking it up in the precomputed table). For recipients, `B_k` is either included alongside the ciphertext (for the current message) or derivable from a previously received `B_j` where `j > k` — but this reveals past backward values, which is acceptable because the forward chain still protects past message keys. In the standard protocol, the sender includes `B_k` alongside each message.
3. Compute `K_msg = HKDF(F_k || B_k, context_id, info)`.
4. Encrypt or decrypt the message content with `K_msg` using AES-256-GCM.

The sender advances `k` by one for each message. Recipients track the per-sender `k` to know which chain position to use for decryption.

### Epoch transition

An epoch transition occurs when:

- A member is added or removed (membership change).
- The chain position reaches `maxLength` (mandatory rotation).
- An administrator triggers a manual rotation (periodic security hygiene).
- A key compromise is detected (emergency rotation).

The transition procedure:

1. The initiator reveals `B_0` (the backward seed for the ending epoch) to all current members. This allows any member to decrypt messages from the ending epoch that they haven't yet received.
2. The initiator generates new seeds: `F'_0 = random(32)`, `B'_0 = random(32)`.
3. The initiator determines the new member set (same as current, plus any additions, minus any removals).
4. For each member in the new set, encrypt `(F'_0, B'_1)` under that member's public key.
5. Write the new epoch record to SafecloudDB with `epochIndex = previous + 1` and `prevEpochHash = SHA-256(previous epoch record)`.
6. The new epoch is now active.

Members excluded from the new epoch never receive the new seeds. They can decrypt the ending epoch's remaining messages (via the revealed `B_0`) but cannot derive any keys in the new epoch.

### Backward seed reveal

The backward seed `B_0` is the most sensitive value in each epoch. It must be revealed to all current epoch members during the transition, and to nobody else. The reveal is encrypted per-member, just like the initial seed distribution. After reveal, any member can compute every backward value in the epoch (`B_k = SHA-256^{n-k}(B_0)` for any k) and, combined with forward values they accumulated during the epoch, decrypt any message from that epoch.

This means that after an epoch ends, its messages are fully decryptable by anyone who was a member of that epoch and who retained their forward chain state. The forward chain is still needed — `B_0` alone does not yield message keys without the corresponding `F_k` values. A member who deleted their forward chain cache before the epoch ended cannot retroactively decrypt messages, even with `B_0`.

---

## Membership operations

### Adding a participant

Adding a participant mid-epoch does NOT require an epoch transition if the new member should only see future messages:

1. The adder encrypts the current chain position's values `(F_k, B_k)` under the new member's public key.
2. The new member is recorded in the membership track.
3. The new member can derive `K_msg` for messages from position `k` onward.

The new member cannot decrypt messages before position `k` because they lack `F_1, F_2, ..., F_{k-1}` (cannot reverse the forward chain) and, while they could compute `B_1, ..., B_{k-1}` from `B_k` (by hashing), the forward values are missing.

If the new member SHOULD see past messages (e.g., an auditor joining a role), an epoch transition is performed and the previous epoch's `B_0` and forward history are explicitly shared. This is a policy decision, not a protocol constraint.

### Removing a participant

Removing a participant REQUIRES an epoch transition:

1. A new epoch is created with the removed member excluded from the member set.
2. New seeds are generated and distributed only to remaining members.
3. The removed member retains keys for all epochs they participated in (they can still decrypt historical messages) but cannot derive keys for the new epoch.

This is the fundamental guarantee: removal is a hard cryptographic boundary. No revocation list to check, no online authority to contact, no race condition. The removed participant simply does not have the new epoch's seeds.

### Batch membership changes

Multiple additions and removals can be batched into a single epoch transition. This is more efficient than transitioning per change: one new seed pair, one round of per-member encryption, one epoch record. The resulting epoch reflects all changes atomically.

---

## Chain storage

### SafecloudDB track layout

Each epoch-managed context uses a consistent track namespace. The examples below use chat rooms; other applications substitute their own prefix.

```
rooms/{contextId}/meta
    key: "info"              → { name, created, currentEpoch, ... }
    key: "epoch/{index}"     → epoch record (see below)
    key: "epoch/{index}/B0"  → revealed backward seed (written at transition)

rooms/{contextId}/members
    key: {publicKey}         → { role, joinedEpoch, seeds: { ... } }

rooms/{contextId}/messages   (chat-specific)
    key: {timestamp}/{msgId} → { ciphertext, senderPubKey, epochIndex, msgIndex, B_k, escrow? }
```

The `seeds` field in the member record contains the epoch seeds encrypted under that member's public key. When a member comes online after an epoch transition, they read their member record to discover new epoch seeds.

### Epoch record format

```json
{
    "epochIndex": 3,
    "members": ["0x04abc...", "0x04def...", "0x04789..."],
    "maxLength": 10000,
    "createdAt": 1697500000,
    "createdBy": "0x04abc...",
    "prevEpochHash": "sha256:a1b2c3...",
    "transitionReason": "member-removed",
    "signature": "base64..."
}
```

The forward and backward seeds are NOT in the epoch record itself. They are stored encrypted per-member in the member records. The epoch record is the public metadata — who is in this epoch, when it started, why it started.

### Membership record format

```json
{
    "publicKey": "0x04abc...",
    "role": "admin",
    "joinedEpoch": 0,
    "currentEpochSeeds": {
        "F_0": "encrypted-base64...",
        "B_1": "encrypted-base64..."
    },
    "previousEpochB0": "encrypted-base64..."
}
```

Each member's seeds are encrypted under their own public key. Only they can decrypt them. The Jet (which runs the handler and writes to SafecloudDB) stores these ciphertexts but cannot read them — it does not hold any member's private key.

---

## Security invariants

### Forward secrecy

**Invariant**: Compromise of keys at position `k` does not reveal keys at positions `k+1, k+2, ...`.

**Mechanism**: The forward chain is one-way (`F_{k+1} = SHA-256(F_k)`). An attacker who obtains `F_k` can compute `F_{k+1}` — but `F_{k+1}` is the value the legitimate participants have already moved past. The attacker learns the key they already compromised, not future keys. Wait — this requires clarification. The forward chain DOES allow computing future forward values from a current one. The protection comes from the epoch transition: when a compromise is detected, an epoch transition generates a completely new `F'_0` unrelated to the old chain. Within an epoch, compromising `F_k` does reveal `F_{k+1}, F_{k+2}, ...` — the forward chain provides forward secrecy across epochs, not within a single epoch.

Within an epoch, forward secrecy relies on the backward chain: although `F_{k+1}` is computable from `F_k`, the corresponding `B_{k+1}` is NOT computable from `B_k` (it requires reversing SHA-256). So `K_{msg,k+1} = HKDF(F_{k+1} || B_{k+1})` remains unknown even to an attacker who knows `F_k` and `B_k`, because they lack `B_{k+1}`.

**Correction to simplified descriptions**: Forward secrecy within an epoch comes from the backward chain, not the forward chain. The forward chain prevents recovery of past keys (`F_{k-1}` from `F_k`). The backward chain prevents derivation of future keys (`B_{k+1}` from `B_k`). Together, compromise of position `k` reveals only `K_{msg,k}` — not past or future keys.

### Backward secrecy

**Invariant**: Compromise of keys at position `k` does not reveal keys at positions `k-1, k-2, ...`.

**Mechanism**: The forward chain is one-way in the forward direction. An attacker who knows `F_k` cannot compute `F_{k-1}` (preimage resistance). The backward chain values `B_{k-1}, B_{k-2}, ...` ARE computable from `B_k` (by hashing forward along the backward chain), but without the corresponding forward values, past message keys cannot be derived.

### Non-interactivity

**Invariant**: Key derivation requires no round trips between participants.

**Mechanism**: Given the current chain position `(F_k, B_k)`, any participant can independently compute `K_msg` without contacting any other participant or any server. The Jet routes ciphertext and public metadata (epoch index, message index); it does not participate in key derivation.

### Transcript simulability

**Invariant**: Anyone who knows the conversation key (the epoch seeds) can construct a valid-looking transcript attributing any content to any participant.

**Mechanism**: Message keys are symmetric (AES-256-GCM). There is no digital signature binding a message to a specific sender at the cryptographic level. The `senderPubKey` field in the message record is metadata, not a cryptographic proof. A holder of the epoch seeds can forge messages attributable to any member.

This is the same deniability property as Signal's. It is a deliberate design choice. Leaked transcripts are circumstantial, not cryptographic evidence.

---

## Scaling

### Small groups

For groups under ~100 members, the protocol operates directly as described. Epoch transitions encrypt new seeds under each member's public key individually. Cost is O(n) public-key encryptions per transition. With modern hardware, 100 X25519 encryptions complete in under 1ms.

### Large groups and key trees

For groups with 1000+ members, a key tree reduces epoch-transition cost from O(n) to O(log n):

1. Members are assigned leaves in a balanced binary tree.
2. Each internal node's key is the HKDF of its children's keys.
3. The root key encrypts the epoch seeds.
4. Each member can derive the root key by combining their leaf key with sibling keys along the path from their leaf to the root.
5. An epoch transition only needs to re-key the path from the changed member's leaf to the root — O(log n) nodes.

This is analogous to TreeKEM (used in MLS). The Safecloud implementation uses HKDF-SHA256 for node derivation rather than Diffie-Hellman, which is cheaper but provides weaker security against adaptive compromise (acceptable for the group sizes and threat model in Safecloud's target applications).

### Epoch transition cost

| Group size | Direct (O(n)) | Key tree (O(log n)) |
|---|---|---|
| 10 | 10 encryptions | Not needed |
| 100 | 100 encryptions | ~7 encryptions |
| 1,000 | 1,000 encryptions | ~10 encryptions |
| 10,000 | 10,000 encryptions | ~14 encryptions |

For groups under 100, the direct approach is simpler and fast enough. For groups above 100, the key tree is recommended.

---

## Application-specific parameters

### Chat

| Parameter | Value | Rationale |
|---|---|---|
| `maxLength` | 10,000 messages | Bounds precomputation; ~1 day for an active group |
| Automatic transition interval | 24 hours OR 10,000 messages | Limits exposure window |
| Context ID salt | `roomId` | Binds keys to a specific room |
| Escrow requirement | Media only | Text has no proof-of-escrow mechanism |
| K_msg info string | `"safecloud-epoch-msg" \|\| roomId \|\| msgIndex` | Per Apps.md |

### Keychains

| Parameter | Value | Rationale |
|---|---|---|
| `maxLength` | 1,000 operations | Key operations are infrequent |
| Automatic transition interval | 90 days | Regular rotation even without membership changes |
| Context ID salt | `keychain/{pubkey-fingerprint}` | Binds keys to a specific identity |
| Writer | Single (keychain owner) | Keychains are single-writer by design |

### Organizational roles

| Parameter | Value | Rationale |
|---|---|---|
| `maxLength` | 10,000 actions | Role actions are moderate frequency |
| Automatic transition interval | 30 days | Regular rotation |
| Context ID salt | `org/{orgId}/roles/{roleId}` | Binds keys to a specific role in a specific org |
| Governance threshold | k-of-n for governed roles | Epoch transitions require threshold approval |

### Camera footage

| Parameter | Value | Rationale |
|---|---|---|
| `maxLength` | 1,440 (minutes per day) | One key per minute, one epoch per day |
| Automatic transition interval | 24 hours | Daily rotation |
| Context ID salt | `camera/{cameraId}` | Binds keys to a specific camera |
| Threshold | k-of-n community board | Decryption requires community approval |

---

## Implementation notes

### Cryptographic dependencies

- **HKDF-SHA256**: `Q.Data.derive(ikm, salt, info)` — key derivation for chain values and message keys.
- **SHA-256**: `Q.Crypto.hash(data)` — hash chain advancement.
- **AES-256-GCM**: Message encryption/decryption using derived `K_msg`.
- **X25519 or ECIES**: Per-member seed encryption during epoch creation and transition.
- **ElGamal over Curve25519**: Threshold encryption for escrow (chat content safety, camera footage).

### Determinism requirements

When the epoch protocol is managed by SafecloudApp WASM handlers (which it is for chat rooms, organizational roles, and camera workflows), the handler must be deterministic. This means:

- Chain advancement uses `SHA-256`, which is deterministic.
- `HKDF` is deterministic given the same inputs.
- Random seed generation (`F_0`, `B_0`) uses `random_seed` from the WASM host API, which is deterministic per receipt chain (seeded from the previous receipt hash).
- Epoch transitions triggered by SafecloudApp triggers use chain logical time, not wall clock time.

Two Jets executing the same sequence of handler calls against the same SafecloudDB state produce identical epoch records and chain values.

### Error handling

**Missing backward value.** If a recipient receives a message with index `k` but has not yet received `B_k` (e.g., out-of-order delivery), the recipient buffers the ciphertext and decrypts it when the backward value arrives. Backward values for indices before `k` are derivable from `B_k`, so late delivery of a single backward value unblocks all prior buffered messages.

**Epoch transition during offline period.** When a member comes online after one or more epoch transitions, they retrieve their member record, which contains the new epoch seeds encrypted under their public key. They can then derive keys for all messages in the new epoch(s). For the epoch that ended while they were offline, the revealed `B_0` (stored at `epoch/{index}/B0`) allows them to decrypt any messages they missed.

**Double epoch transition.** If two epoch transitions are initiated concurrently (e.g., two admins remove different members at the same time), the SafecloudDB write ordering resolves the conflict. The first transition to be committed wins; the second must re-derive from the new state. SafecloudChain total ordering prevents ambiguity.

**Compromised forward state.** If an attacker obtains `F_k` and `B_k` for the current position, they can compute all future forward values in this epoch (`F_{k+1}, F_{k+2}, ...`). They cannot compute future backward values. So they can compute `K_msg` for position `k` only. Once the compromise is detected and an epoch transition occurs, the attacker loses access entirely (new seeds are unrelated to old chains). The protocol assumes compromises are detected and responded to with epoch transitions.
