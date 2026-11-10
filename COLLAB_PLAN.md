# Safecloud Collaborative Editing — Implementation Plan

## Existing foundation

- **SQLite Jet** (commit 26): Node.js Streams Jet backed by SQLite. Accepts `POST /Streams/message`, assigns ordinals, persists to SQLite.
- **`classes/Streams.js`** (Qbix/Streams): Socket.io server with `Streams/observe`, `Streams/neglect`, `Streams/ephemeral` handlers, `notifyParticipants` and `notifyObservers` fan-out already wired. Triggered by `Streams.Stream.emit('post', stream, msg)`.
- **`web/js/Streams.js`** (Qbix/Streams): Browser client with `Q.Socket`, `Streams.onMessage`, `Stream.observe`/`neglect`. Works with any stream type.
- **Q.Crypto / PQClaim / AttestationVerifier**: signing infrastructure already in the repo.

## The core simplification

After each SQLite commit, the Jet calls `Streams.Stream.emit('post', stream, msg)`. That single internal event triggers the existing socket fan-out in `classes/Streams.js` — `notifyParticipants` and `notifyObservers` handle delivery to all socket observers and subscribed participants. No additional socket code to write.

---

## Phase 1 — Jet: signing + hash chain

Add two columns to the messages table: `prev_hash TEXT` and `sig TEXT`.

On first startup, generate an Ed25519 (or ML-DSA-65 via PQClaim) keypair. Persist the private key encrypted at rest. Expose the public key in unencrypted stream metadata via a `Streams/epoch` message on start.

Inside each write transaction (between `BEGIN IMMEDIATE` and `COMMIT`):

1. Read `prev_hash` from the most recent row for this stream.
2. Compute `sig = Sign(key, epoch || ordinal || prev_hash || contentCID || byUserId || timestamp)`.
3. Insert including `prev_hash` and `sig`.
4. After `COMMIT`, emit `Streams.Stream.emit('post', stream, msg)`.

**Idempotency**: clients include an `idempotencyKey` (UUID) with each POST. The Jet checks for an existing row with that key before inserting. If found, returns the existing ordinal. Handles crash-after-commit-before-response without duplicate ordinals.

**Fork detection**: if the Jet ever receives two records with the same `(epoch, ordinal)` and different content, mark the stream as disputed, halt writes, and publish the two conflicting signed records as evidence.

---

## Phase 2 — Jet: epoch and succession

On startup, write a `Streams/epoch` message (unencrypted metadata only):

```json
{
  "epoch": 1,
  "jetPublicKey": "...",
  "successionList": ["jetA_keyHash", "jetB_keyHash"],
  "prevHash": "..."
}
```

**Canonical tiebreak**: Jets in the succession list are ranked by `lex(hash(public_key))`. If two Jets are simultaneously alive after a netsplit heals, the lower-ranked Jet defers to the higher-ranked one — deterministic, stateless, no coordination round needed. Handles the edge case where a previous Jet reappears within the timeout window.

**Succession**: when a standby Jet takes over, it reads `MAX(ordinal)` and `last_hash` from its own SQLite (populated via pull replication from the previous Jet), increments epoch, posts a new `Streams/epoch` message, and begins accepting writes.

**Pull replication**: on succession, the new Jet calls `GET /Streams/messages?after=N` on the previous Jet, verifies each record's `sig` against the previous Jet's public key and verifies `prev_hash` linkage, then inserts verified records into local SQLite before starting its own epoch.

---

## Phase 3 — `SafecloudYjsProvider.js`

A Yjs provider that maps a `Y.Doc` to a Safecloud encrypted Stream. One provider, works with TipTap, Milkdown, and Univer.

**Connect**:

1. Fetch all `Safecloud/docs/yjs` messages from the Stream since ordinal 0.
2. For each: verify `sig` against the epoch's known Jet public key and verify `prev_hash` linkage.
3. Decrypt the Drop (CID → encrypted blob → Yjs binary update).
4. Apply in ordinal order: `Y.applyUpdate(ydoc, update, this)`.
5. Subscribe to `Streams.onMessage('Safecloud/docs/yjs', ...)` for real-time updates going forward.

**Local changes**:

```
ydoc.on('update', (update, origin) => {
    if (origin === this) return;          // no echo
    pendingUpdates.push(update);
    scheduleFlush(300ms debounce);
});

flush():
    merged = Y.mergeUpdates(pendingUpdates);
    cid = await Safecloud.encryptDrop(merged, streamKey);
    POST /Streams/message { type: 'Safecloud/docs/yjs', content: cid, idempotencyKey: uuid() }
```

**Remote changes**: on `Streams/post` for `Safecloud/docs/yjs`: verify sig + hash chain, decrypt Drop, `Y.applyUpdate(ydoc, update, this)`.

**Awareness (cursors, presence, typing)**: use `Streams/ephemeral` (writeLevel 16). Send and receive Yjs awareness state via the existing ephemeral handler — non-persisted, no ordinals, high frequency. No changes to `classes/Streams.js` needed.

**New message type**: add `Safecloud/docs/yjs` to the Jet's `SAFECLOUD_TYPES`. Validation: content must be a valid CID. No semantic validation — Yjs semantics are on the client.

---

## Phase 4 — Editor bindings

All three editors accept a Yjs provider. One `SafecloudYjsProvider` instance serves all three.

- **TipTap**: `CollaborationExtension.configure({ provider: safecloudProvider })`
- **Milkdown**: `@milkdown/plugin-collab` with `safecloudProvider`
- **Univer**: pass provider to Univer's collab binding

Each editor uses Yjs internally for per-keystroke CRDT. The provider handles transport and persistence via Safecloud Streams. The two layers are independent.

---

## What is NOT built in this plan

- **Push replication** (standby Jet registers webhook on primary, receives records in real time). Pull replication on succession is sufficient for Phase 1–2.
- **Intercloud BFT** (Phase 3 of the sequencer stack — plugs in without touching the OT/provider layer).
- **`Streams::merge()` with rebase** — the OT pull+rebase model for semantic ops. Not needed for the Yjs collaboration flow; deferred until there is a concrete use case beyond WYSIWYG editing.
- **Trees as first-class primitive** — generalization of Stream to allow explicit DAG branching. Architecturally correct long-term direction; deferred until Phase 1 is shipped.
