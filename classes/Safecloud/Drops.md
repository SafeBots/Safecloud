# Q.Safecloud.Drops — Implementation Design Document

## Table of Contents

- [Part 1 — Key Design Decisions](#part-1--key-design-decisions)
  - [1.1 Responsibilities: Drops vs Jets vs Cloud](#11-responsibilities-drops-vs-jets-vs-cloud)
  - [1.2 IndexedDB schema — three object stores](#12-indexeddb-schema--three-object-stores)
  - [1.3 CID as the universal key](#13-cid-as-the-universal-key)
  - [1.4 LRU eviction — announce before evict](#14-lru-eviction--announce-before-evict)
  - [1.5 Prolly tree and diff log — O(changes) not O(data)](#15-prolly-tree-and-diff-log--ochanges-not-odata)
  - [1.6 Bloom filter — cold handshake compact encoding](#16-bloom-filter--cold-handshake-compact-encoding)
  - [1.7 Session keypair vs wallet keypair](#17-session-keypair-vs-wallet-keypair)
  - [1.8 Payment token accumulation and claiming](#18-payment-token-accumulation-and-claiming)
  - [1.9 Balance verification before serving](#19-balance-verification-before-serving)
  - [1.10 Challenge response — signing, not retrieving](#110-challenge-response--signing-not-retrieving)
  - [1.11 IndexedDB wipe — honest reset](#111-indexeddb-wipe--honest-reset)
  - [1.12 Pristine environment assumption](#112-pristine-environment-assumption)
- [Part 2 — External interfaces called by Drops](#part-2--external-interfaces-called-by-drops)
  - [Q.Safecloud.Jets.dropRegister](#qsafejetsdroppregister)
  - [Q.Safecloud.Jets.dropAnnounce](#qsafejetsdroppannounce)
  - [Q.Safecloud.Jets.dropDisconnect](#qsafejetsdroppddisconnect)
  - [Q.Safecloud.Jets.dropClaimPayments](#qsafejetsdroppclaimPayments)
  - [Q.Crypto.delegate](#qcryptodelegateoptions)
  - [Q.Data.Prolly](#qdataprolly)
  - [Q.Data.Bloom](#qdatabloom)
  - [ethers.js (browser)](#ethersjs-browser)
  - [Q.Safecloud.Drops Events (inbound from Jets.js client)](#qsafedrops-events-inbound-from-jetsjs-client)
- [Part 3 — _internal.js helpers](#part-3--_internaljs-helpers)
  - [_.DB_NAME, _.STORES](#_db_name-_stores)
  - [_.openDB()](#_opendb)
  - [_.cidFromData(buffer)](#_cidfromdatabuffer)
  - [_.chunkKey(cid)](#_chunkkeycid)
  - [_.lruKey(cid)](#_lrukeycid)
  - [_.nowSec()](#_nowsec)
  - [_.canonicalJSON(obj)](#_canonicaljsonobj)
  - [_.signAnnounce(entry, sessionKey)](#_signannounceentry-sessionkey)
  - [_.verifyAnnounce(entry)](#_verifyannounceentry)
  - [_.applyDiff(root, diff)](#_applydiffroot-diff)
  - [_.buildBloom(cids)](#_buildbloomcids)
  - [_.balanceCacheKey(evmAddress)](#_balancecachekeyevmaddress)
- [Part 4 — Public API](#part-4--public-api)
  - [Q.Safecloud.Drops.init(options)](#qsafedropsinitioptions)
  - [Q.Safecloud.Drops.put(chunks, options, callback)](#qsafedropsputchunks-options-callback)
  - [Q.Safecloud.Drops.get(cids, options, callback)](#qsafedropsgetcids-options-callback)
  - [Q.Safecloud.Drops.getProllyRoot(callback)](#qsafedropsgetprollyrootcallback)
  - [Q.Safecloud.Drops.getBloomFilter(callback)](#qsafedropsgetbloomfiltercallback)
  - [Q.Safecloud.Drops.announce(reason, callback)](#qsafedropsannouncereason-callback)
  - [Q.Safecloud.Drops.claimPayments(options, callback)](#qsafedropsclaimpaymentsoptions-callback)
  - [Q.Safecloud.Drops.reset(callback)](#qsafedropsresetcallback)
- [Part 5 — Inbound event handlers (wired by Jets.js client)](#part-5--inbound-event-handlers-wired-by-jetsjs-client)
  - [onDropPut(payload, ack)](#ondroppputpayload-ack)
  - [onDropGet(payload, ack)](#ondropgetpayload-ack)
  - [onDropChallenge(payload, ack)](#ondropchallengeypayload-ack)
  - [onDropSlashed(payload)](#ondropslashedpayload)
- [Part 6 — Implementation Order](#part-6--implementation-order)
- [Part 7 — What is NOT in Drops.js](#part-7--what-is-not-in-dropsjs)

---

This document is the authoritative spec for an LLM to implement `Q.Safecloud.Drops`
function by function, bottom-up. Every decision that could have gone another way
is explained. Read `Protocol.md` and `Jets.md` first for the broader
architecture. Read `Cloud.md` to understand what the chunks Drops store actually
contain (encrypted ciphertext — Drops never see plaintext).

---

## Part 1 — Key Design Decisions

### 1.1 Responsibilities: Drops vs Jets vs Cloud

**Q.Safecloud.Drops** (this file) is responsible for:
- Storing encrypted chunks in IndexedDB, keyed by CID
- Serving encrypted chunks on request from Jets (via the Jets client socket)
- Maintaining an LRU eviction index to manage storage quota
- Maintaining the Prolly tree inventory (via `Q.Data.Prolly`)
- Maintaining the append-only Prolly diff log (the forensic accountability record)
- Building and serialising a Bloom filter over stored CIDs for cold handshakes
- Accumulating OCP Role B payment tokens from Jets and initiating claims
- Verifying Jet Safebux balances before serving (independent check)
- Responding to proof-of-storage challenges from Jets
- Announcing inventory changes to Jets after every put/evict

**Q.Safecloud.Jets** (the socket client, `web/js/Safecloud/Jets.js`) is responsible for:
- The socket.io connection to the Jet server
- Routing incoming `Safecloud/drop/*` push events to Q.Safecloud.Drops handlers
- Sending `dropRegister`, `dropAnnounce`, `dropDisconnect`, `dropClaimPayments`
  messages on behalf of Drops

**Q.Safecloud.Client** is responsible for all encryption and decryption. Drops
never see plaintext. The chunks stored in IndexedDB are opaque ciphertext bytes.

**The key boundary rule:** Drops store and serve ciphertext. They verify that
they are being paid (Safebux balance check) and that their inventory commitments
are honest (signed Prolly diffs). They never decrypt anything.

---

### 1.2 IndexedDB schema — three object stores

All persistent state lives in one IndexedDB database: `Q.Safecloud.Drops`.

```
Database: Q.Safecloud.Drops  (version 1)
  ├── chunks        — ciphertext storage
  │     key:   CID string (e.g. 'bafy...')
  │     value: { cid, iv, ciphertext, tag, size, storedAt }
  │
  ├── lru           — eviction ordering
  │     key:   CID string
  │     value: { cid, size, lastAccessed }   // lastAccessed = Unix seconds
  │
  ├── log           — append-only Prolly diff log
  │     key:   seq (autoIncrement)
  │     value: { seq, timestamp, prevRoot, newRoot, diff, reason, signature }
  │
  └── tokens        — accumulated payment tokens
        key:   tokenHash (SHA-256 of canonical JSON of token)
        value: { tokenHash, token, receivedAt, redeemed }
```

**Why separate `chunks` and `lru`:** The LRU index is written on every access
(read), while chunks are written only on put. Separating them avoids re-writing
the full chunk payload on every get. The `chunks` store values are
write-once-read-many; `lru` values are updated frequently.

**Why `log` is autoIncrement:** The diff log is append-only. The `seq` field
is the monotonically increasing autoIncrement key. No updates, no deletes —
only appends. A Drop never mutates a log entry. (Log compaction, if needed
in v2, would only archive entries whose `prevRoot` predates the network's
memory window, and only after getting a Jet acknowledgment.)

**Why `tokens` store:** Payment tokens accumulate across many sessions. They
must survive page reloads and browser restarts. IndexedDB persistence is
required. The `tokenHash` key ensures idempotent inserts (re-receiving a
duplicate token does not double-count it).

---

### 1.3 CID as the universal key

CIDs are CIDv1 strings (`'bafy...'`, 59 characters) derived from
`SHA-256(ciphertext || tag)`. Two properties make them the correct key:

**Content-addressed:** Same ciphertext always produces same CID. If a Drop
stores the same chunk twice (deduplication from two different uploads of the
same content), it stores it once and the second write is a no-op (already
present check before any IndexedDB `put`).

**Globally unique:** Collisions are computationally infeasible (SHA-256).
CIDs can be used as IndexedDB keys, Bloom filter elements, Prolly tree keys,
and socket.io payload identifiers interchangeably.

`_.cidFromData(buffer)` is the only function that computes CIDs in Drops.
It must be byte-identical to `_.chunkCid(ciphertextB64, tagB64)` in Cloud
(same `ciphertext || tag` concatenation, same SHA-256, same CIDv1 encoding).
Any mismatch between Cloud's and Drop's CID computation causes `get` misses.

---

### 1.4 LRU eviction — announce before evict

When a `put` request would exceed the Drop's storage quota
(`Q.Config.get(['Safe', 'drop', 'storageGB'], 10) * 1024 ** 3` bytes), the
Drop must evict least-recently-used chunks before storing new ones.

**The announce-before-evict invariant is a protocol requirement:**

A Drop MUST append a log entry and send a `Safecloud/drop/announce` with its
new Prolly root (removing the evicted CIDs from the diff) BEFORE deleting
the evicted chunks from IndexedDB. If the Drop crashes between eviction and
announce, the old Prolly root remains in place — the next reconnect will
send the (wrong) old root, which would leave the Jet with a stale view.
However, if a challenge arrives before reconnect, the Drop will correctly
fail it (the chunks are gone), which is observable as an inconsistency
between announced root and challenge failure.

To avoid this race, the sequence is strictly:

```
1. Compute which CIDs to evict (LRU order, enough to free the required space)
2. Compute new Prolly root after eviction (without deleting yet)
3. Append log entry (prevRoot = current, newRoot = post-eviction, diff = evictions)
4. Sign and send Safecloud/drop/announce with the new root
5. Wait for ack from Jet
6. ONLY THEN delete evicted chunks from IndexedDB and LRU store
```

If step 4-5 fails (disconnect), retry on reconnect. The old chunks are still
present, so the old root is still valid — no inconsistency.

**LRU policy:** `lastAccessed` in the `lru` store is updated on every `get`.
Eviction picks the chunk with the smallest `lastAccessed`. Ties are broken by
smallest `size` — v1 uses smallest-first for simplicity and fairness across
chunk sizes. This maximises the number of distinct chunks freed per eviction
cycle. Future versions may switch to largest-first for faster byte recovery
when quota is tight.

---

### 1.5 Prolly tree and diff log — O(changes) not O(data)

The Prolly tree (maintained via `Q.Data.Prolly`) is the canonical inventory
representation. The diff log is the forensic accountability record.

**Prolly tree:** Maps `CID → CID` (key = CID string, value = CID string —
Prolly trees are key-value; using CID as both key and value is idiomatic for
a set). The tree root is a hex string. Two Drops with identical inventories
have identical Prolly roots.

The Drop does NOT maintain the Prolly tree in IndexedDB directly — it uses
`Q.Data.Prolly` as a pure function over its log state, recomputing the root
when needed. The current root is always the `newRoot` of the most recent log
entry (or null if the log is empty).

**Diff log:** Append-only. Each entry contains enough context to reconstruct
the full history from any starting point. A Jet holding a sequence of entries
can verify `apply(entry.prevRoot, entry.diff) == entry.newRoot` for each —
the Drop cannot lie about what changed.

The diff for a `put` batch: `entry.diff = [{ cid, added: true }, ...]` for
every CID successfully stored. The diff for an eviction batch:
`[{ cid, added: false }, ...]` for every CID evicted.

**Why not just recompute from IndexedDB on every announce?**

Recomputing the Prolly root from scratch over all stored CIDs is O(N) in
chunk count. A Drop with 100K chunks doing this on every put/evict would
be unusably slow. The diff log lets the Drop maintain the root incrementally:
each announce derives the new root from the previous root plus the diff —
O(changes * log N) via the Prolly tree structure.

---

### 1.6 Bloom filter — cold handshake compact encoding

On cold contact (first registration, or after a Jet restart), the Drop sends
a Bloom filter over all stored CIDs. The Jet uses this to quickly answer
"does this Drop likely have CID X?" before routing a `get` request to it,
without requiring the full CID list.

**Parameters:**
- Expected elements: number of stored chunks
- False positive rate: 1% (`Q.Config.get(['Safe', 'drop', 'bloomFPR'], 0.01)`)
- Storage: ~1.2 bytes/element. A Drop with 100K chunks uses ~120 KB.
- Hash functions: 7 (optimal for 1% FPR with the chosen bit count)

`Q.Data.Bloom.fromElements(cidStrings)` builds the filter.
`Q.Data.Bloom.serialize()` returns a base64 string for socket.io transport.

The Bloom filter is rebuilt from scratch by iterating the `chunks` store.
This is O(N) but only happens on cold contact — typically once per Jet restart,
not on every reconnect (warm reconnects send only the Prolly root).

**When to rebuild vs reuse:** The Bloom filter is held in memory. It is
updated incrementally on every put (add elements) and on every eviction
(rebuild, since Bloom filters don't support deletion). Rebuilding on eviction
is O(N) but evictions are infrequent relative to puts, so this is acceptable
for most Drops.

For large Drops (>100K chunks), eviction-triggered Bloom rebuilds may take
tens of milliseconds. Implementations MAY debounce or batch evictions to
amortise the rebuild cost — for example, accumulating a batch of evictions
and rebuilding once rather than once per evicted CID. The Bloom filter only
needs to be current before the next cold handshake, not after every eviction.

---

### 1.7 Session keypair vs wallet keypair

Drops maintain two keypairs, both stored in IndexedDB as non-extractable
`CryptoKey` objects:

**P-256 session keypair (ES256):**
- Derived via `Q.Crypto.delegate` from the wallet signature during the
  `Q.Crypto.delegate` ceremony
- Used for: signing Prolly diff log entries and announce messages
- Public key sent in `Safecloud/drop/register` as `delegation.stm.sessionKeyES256`
- Non-extractable: stored as `CryptoKey` in IndexedDB using the Web Crypto API
  `extractable: false` flag

**secp256k1 session keypair (EIP-712):**
- Also derived via `Q.Crypto.delegate` from the same wallet signature
- Used for: payment token claiming (on-chain EIP-712 signatures)
- EVM address derived as `last 20 bytes of keccak256(pubkey[1:])` = `dropEVMAddress`
- Sent as `evmAddress` in `Safecloud/drop/register`
- Non-extractable: stored as `CryptoKey` in IndexedDB

**The delegation claim:**
Both session keypairs are established in a single interactive `Q.Crypto.delegate`
ceremony when the user first sets up their Drop. The resulting OCP
`safecloud:session-delegation` claim is stored in IndexedDB and sent in every
`Safecloud/drop/register` message. It expires after
`Q.Config.get(['Safe', 'drop', 'sessionExpDays'], 30) * 86400` seconds.
On expiry, the Drop prompts the user for a new interactive wallet signature.

**Why non-extractable?**
The pristine environment guarantee (SafeBox attestation) ensures the JS code
signing with these keys is the audited implementation. `extractable: false`
adds a second layer: even if attacker JS runs in the same context, it cannot
read the raw key bytes. It can only call `sign()` on the key — and the
reference implementation only signs protocol-correct messages. See section 1.12.

---

### 1.8 Payment token accumulation and claiming

As the Drop serves chunks in response to `Safecloud/drop/get` events, each response
includes a `paymentToken` (OCP Role B envelope signed by the Jet). The Drop
accumulates these tokens in the `tokens` IndexedDB store.

**Deduplication:** Tokens are keyed by `tokenHash = SHA-256(canonicalJSON(token))`.
Re-receiving a token that was already stored is a no-op (idempotent insert).

**Claim trigger:** When accumulated unredeemed value exceeds
`Q.Config.get(['Safe', 'drop', 'claimThresholdSafebux'], '100000')` Safebux
wei, or when the user explicitly requests a claim, the Drop initiates
`claimPayments()`.

**Claiming paths:**

*Direct path (Drop has BNB for gas):*
The Drop calls `OpenClaiming.paymentsExecute()` directly from the browser
via ethers.js. For each accumulated token, the Drop passes:
- The Payment struct fields from `token.stm`
- `recipients = [dropEVMAddress]` (matches `stm.recipientsHash`)
- The Jet's EIP-712 signature from `token.sig[0]`
- `recipient = dropEVMAddress` (this Drop)
- `amount = chunks served × perChunkSafebux`
- `incomeContract = address(0)` (direct ERC-20 transferFrom)

*Relay path (no gas):*
The Drop sends `Safecloud/drop/claimPayments` to the Jet with the accumulated
tokens and its EVM address. The Jet relays to PHP → Assets plugin →
`paymentsExecute()`. The Drop may be charged a small fee for gas coverage.

**Partial redemption:** A single token may be redeemed in multiple
`paymentsExecute()` calls. `lines[payer][line].spent` tracks cumulative
spend; the token is exhausted when `spent >= stm.max`. The Drop tracks
`redeemed` per token in the `tokens` store.

**Post-claim cleanup:** After successful on-chain execution (txHash confirmed),
mark tokens as `redeemed: true` in IndexedDB. Do not delete immediately —
they serve as an audit trail for the current session. Periodically archive
tokens older than `Q.Config.get(['Safe', 'drop', 'tokenArchiveDays'], 90)` days.
Archived tokens MAY be deleted from IndexedDB after being persisted to external
storage (or after the archival window has passed), as they are no longer required
for protocol correctness. Redeemed tokens do not affect payment or CoC logic.

---

### 1.9 Balance verification before serving

Before serving any chunk in response to `Safecloud/drop/get`, the Drop independently
verifies that the Jet's Safebux balance is sufficient to cover the request.

The payment token's `stm.payer` is the Jet's EVM address. The Drop checks:
```js
safebux.balanceOf(jetEVMAddress) >= perChunkSafebux * cids.length
```

This check is cached in memory per `jetEVMAddress` with a 1-hour TTL
(`Q.Config.get(['Safe', 'drop', 'balanceCacheTtlMs'], 3600000)`).

**Why independent?** A compromised Jet could claim to have forwarded payment
while actually pocketing the tokens. By independently querying BSC, the Drop
ensures it is not serving for free regardless of what the Jet reports.

**This check is advisory, not definitive.** It prevents obvious underfunded
requests (Jet with zero Safebux cannot plausibly pay). The definitive
enforcement occurs on-chain during `paymentsExecute()` — `transferFrom` either
succeeds or reverts. A Drop that serves a request which later fails on-chain
simply doesn't get paid for that batch; this is an economic risk the Drop
accepts in exchange for not requiring on-chain confirmation before every serve.

**What if balance is insufficient?** The Drop returns `null` for all requested
chunks rather than serving without assured payment.

---

### 1.10 Proof of storage — silent spot-checks, not binary challenges

The primary mechanism for verifying that a Drop holds the chunks it claims
is **silent random `get` requests** issued by the Jet, indistinguishable from
real Cloud-originated requests. This is the correct design for several reasons:

**Why data-binding challenges don't work as binary pass/fail:**
The original design (`proof = keccak256(cid ‖ nonce ‖ chunk_first_32_bytes)`)
requires the Jet to know the chunk's first 32 bytes to verify the proof. The
Jet may not hold a copy — that's precisely why it relies on Drops. Spot-fetching
from another Drop to verify creates a circular dependency (that Drop may also
lie), and caching full chunks on the Jet defeats the purpose of distributed
storage.

**The silent spot-check model:**
Jets periodically issue `Safecloud/drop/get` requests for randomly selected CIDs
from the Drop's announced Prolly root, indistinguishable from real retrieval
requests. The Drop must return the correct chunk. The Jet verifies:

1. **CID integrity (self-verifying):** `SHA-256(returned_ciphertext || returned_tag)`
   must equal the requested CID. No external state needed — the CID is its own
   ground truth. A Drop serving garbage or a wrong chunk fails this check
   immediately.
2. **Presence:** If the Drop returns `null` for a CID that its current Prolly
   root implies it holds, and no eviction announce was sent removing it, this
   is an inventory inconsistency — logged against the Drop's reputation.

**Why this creates the right chilling effect:**
The Drop cannot distinguish a spot-check from a paying customer request. It
must serve correctly in all cases or risk being caught. The Drop is motivated
to stay honest not because it fears a single dramatic slash, but because any
random request could be a test, and patterns of failure deprioritize it in
routing.

**The explicit `Safecloud/drop/challenge` event:**
The `Safecloud/drop/challenge` event is retained as a lightweight explicit ping for
cases where the Jet wants to verify a specific CID without paying for it.
The Drop responds with the actual chunk data (not a hash-based proof). The
Jet verifies via CID recomputation.

A single failed challenge is **not directly slashable** — transient errors,
network hiccups, and race conditions between eviction and announce are all
legitimate reasons for a null response. What IS slashable is the pattern:
a Drop that repeatedly cannot serve CIDs its current signed Prolly root claims
it holds, with no corresponding eviction announces.

**CoC construction from patterns:**
The Jet accumulates a reputation record per Drop. A CoC can be constructed
from the diff log when:
- Drop signed `announce { prevRoot: R1, newRoot: R2, diff: [] }` (no change)
- Multiple `get` requests for CIDs reachable from R2 return null or wrong data
- No eviction announces were sent removing those CIDs between R2 and the failures

This pattern — consistent across multiple requests, with the signed announce as
the commitment — forms a self-contained CoC. The Jet needs only the signed
announce entries and the get failure records (timestamped) as evidence.

**v1 challenge-response format (simplified):**
```js
// event: 'Safecloud/drop/challenge' { cid: String }
// ack: { cid: String, iv: String, ciphertext: String, tag: String } | null
```

The Drop returns the actual chunk (or null if not found). No nonce, no OCP
signing ceremony, no hash-based proof. The Jet verifies CID integrity via
`SHA-256(ciphertext || tag) == cid`. Cheap, unambiguous, self-verifying.

If the chunk is not found and the Drop's current Prolly root implies it should
be there: the Jet logs the failure. If the Drop has already sent an eviction
announce for that CID, the null is consistent — not a failure.

---

### 1.11 IndexedDB wipe — honest reset

If the browser's storage is cleared (user clears site data, browser evicts
storage under pressure, `Q.Safecloud.Drops.reset()` is called explicitly), all
chunk data and the diff log are lost.

The Drop MUST immediately send `Safecloud/drop/announce` with:
```js
{
  reason: "reset",
  prollyRoot: null,
  diff: null,
  prevRoot: <last known root before wipe, if available>
}
```

A reset is **not slashable** — "I lost everything" is not a contradiction of
any prior signed claim. The Jet treats the Drop as cold and re-syncs via
Bloom filter on the next non-null announce.

**The honest signal principle:** Failing to send a reset and instead asserting
a stale Prolly root IS slashable (the subsequent challenge failure contradicts
the claimed root). The reference implementation detects the wipe at startup
(IndexedDB open returns empty database) and immediately sends a reset announce
before accepting any new `Safecloud/drop/put` requests.

**Detection:** On `init()`, the Drop opens the database and reads the most
recent log entry. If the log is empty but `Q.Safecloud.Drops._sessionData` indicates
a prior session had a non-null Prolly root (stored in sessionStorage as a hint),
the Drop infers a wipe and sends a reset announce.

---

### 1.12 Pristine environment assumption

The Drop's session keys are non-extractable (`extractable: false` in Web Crypto
API), which prevents raw key bytes from being read by JavaScript. However,
malicious JavaScript running in the same context can still call `sign()` on
the non-extractable key with arbitrary payloads. This means:

**A malicious server could ship JS that:**
- Signs a false challenge response proving possession of a chunk the Drop
  doesn't hold (manufacturing a false proof — only useful for the attacker,
  not for framing the Drop)
- Signs a false Prolly diff log entry claiming the Drop evicted a chunk it
  still holds, then allows a challenge to fail — creating a valid CoC against
  the Drop's own stake
- Silently signs payment tokens with modified amounts, directing funds to
  wrong recipients

The `extractable: false` guarantee is therefore insufficient on its own.
Drops MUST run in a SafeBox-attested environment (`safebox.org`) where:

1. The AMI hash is published and TPM-measured at boot
2. The JS bundle hash is in the SafeBox attestation claim
3. Users or their user agents can verify the attestation before the Drop
   begins signing anything

See Protocol.md § Pristine environment requirement and SafeBox attestation
for the full trust chain. Drops.js implementations outside this environment
are possible but carry reduced trust and receive lower routing priority from
Jets that check attestation claims.

---

## Part 2 — External interfaces called by Drops

These are the bottom of the Drops dependency tree. Every external call is
listed here before implementation.

---

### `Q.Safecloud.Jets.dropRegister(info, callback)` → Promise

```
info: {
  evmAddress:  String,   // canonical BSC EVM address
  delegation:  Object,   // OCP safecloud:session-delegation claim
  publicKey:   String,   // base64 P-256 SPKI (session key)
  storage:     { GB: Number },
  prollyRoot:  String|null,
  bloomFilter: String|null   // base64; sent when prollyRoot is null or Jet is cold
}
Returns: Promise<{ dropId: String, cold: Boolean, minStake: String }>
Called by: Q.Safecloud.Drops.init(), after session keypair ceremony
```

---

### `Q.Safecloud.Jets.dropAnnounce(info, callback)` → Promise

```
info: {
  dropId:     String,
  storage:    { GB: Number },
  used:       Number,        // bytes currently occupied
  prevRoot:   String|null,
  prollyRoot: String|null,
  diff:       Array<{ cid: String, added: Boolean }>|null,
  reason:     String|null,   // "stored"|"eviction"|"reset"
  signature:  String         // base64 P-256 sig over canonical JSON of announce
}
Returns: Promise
Called by: Q.Safecloud.Drops.announce()
```

---

### `Q.Safecloud.Jets.dropDisconnect(callback)` → Promise

```
Called by: Q.Safecloud.Drops.shutdown()
```

---

### `Q.Safecloud.Jets.dropClaimPayments(payload, callback)` → Promise

```
payload: {
  dropId:        String,
  paymentTokens: Array,    // accumulated OCP Role B tokens
  signature:     String    // base64 OCP claim signed with Drop EIP-712 session key
}
Returns: Promise<{ txHash: String|null }>
Called by: Q.Safecloud.Drops.claimPayments() (relay path)
```

---

### `Q.Crypto.delegate(options)` → Promise\<Object\>

```
options.rootSecret: Uint8Array   — wallet-derived secret
options.label:      String       — 'safecloud.session'
options.context:    String       — JSON: { exp: Number }
options.format:     ['ES256', 'EIP712']
Returns: OCP safecloud:session-delegation claim
Called by: Q.Safecloud.Drops.init() on first run or session expiry
```

Used once per session (30-day default) to establish the Drop's two session
keypairs from a single interactive wallet signature.

---

### `Q.Data.Prolly`

```js
Q.Data.Prolly.build(entries, store, callback)
// entries: Array<{ key: String, value: String }>  (CID → CID)
// Returns: Promise<String>  (hex root)
// Called by: _rebuildProllyRoot()

Q.Data.Prolly.insert(root, entry, store, callback)
// entry: { key: String, value: String }
// Returns: Promise<String>  (new root after insert)
// Called by: _.applyDiff() for added entries

Q.Data.Prolly.delete(root, key, store, callback)
// Returns: Promise<String>  (new root after delete)
// Called by: _.applyDiff() for removed entries

Q.Data.Prolly.has(root, key, store, callback)
// Returns: Promise<Boolean>
// Called by: Jet-side reputation checks (not by Drops directly in v1)
```

The Prolly store used by Drops is an in-memory object `{ hash: node }`.
It is rebuilt from the diff log on startup (replay all log entries from
the last known root). The store itself is not persisted — only the diff
log is. On startup, replay is O(log entries since last compaction), which
is typically small.

---

### `Q.Data.Bloom`

```js
Q.Data.Bloom.fromElements(elements)
// elements: Array<String>   (CID strings)
// Returns: { filter: ArrayBuffer, serialize() -> String (base64) }
// Called by: getBloomFilter()

Q.Data.Bloom.test(filter, element)
// filter: deserialized Bloom filter (held in memory)
// Returns: Boolean
// NOT called by Drops directly — Jets uses this on the server side
```

---

### ethers.js (browser)

```js
// Balance check before serving:
const provider = new ethers.JsonRpcProvider(
    Q.Config.get(['Safe', 'evm', 'provider', 'eip155:56'], BSC_RPC_URL)
);
const safebux = new ethers.Contract(
    Q.Config.get(['Safe', 'safebux', 'address']),
    ['function balanceOf(address) view returns (uint256)'],
    provider
);
const balance = await safebux.balanceOf(jetEVMAddress);  // BigInt

// Payment claiming (direct path):
const signer   = new ethers.Wallet(dropSecp256k1PrivateKey, provider);
const ocpContract = new ethers.Contract(
    '0x99996a51cc950d9822D68b83fE1Ad97B32Cd9999',
    OC_ABI,
    signer
);
await ocpContract.paymentsExecute(payment, recipients, sig, recipient, amount, ZeroAddress);
```

---

### Q.Safecloud.Drops Events (inbound from Jets.js client)

The Jets client (`web/js/Safecloud/Jets.js`) registers these on `Q.Safecloud.Jets`:

```js
Q.Safecloud.Jets.onDropPut       = new Q.Event()  // (payload, ack)
Q.Safecloud.Jets.onDropGet       = new Q.Event()  // (payload, ack)
Q.Safecloud.Jets.onDropChallenge = new Q.Event()  // (payload, ack)
Q.Safecloud.Jets.onDropSlashed   = new Q.Event()  // (payload)
```

The handlers for these events are defined in Drops.js (Part 5) and wired
to the events in the default handler setup section of Jets.js. Drops.js does
not call Q.Safecloud.Jets.on() directly — the wiring is Jets.js's responsibility.
Drops.js exports the handler functions; Jets.js registers them.

---

## Part 3 — `_internal.js` helpers

Shared helpers passed as `_` to all Drops method files. Only call
`Q.Data.*`, `Q.Crypto.*`, `indexedDB`, and native browser APIs.

---

### `_.DB_NAME`, `_.STORES`

```js
_.DB_NAME = 'Q.Safecloud.Drops'
_.STORES = {
    chunks: 'chunks',   // { cid, iv, ciphertext, tag, size, storedAt }
    lru:    'lru',      // { cid, size, lastAccessed }
    log:    'log',      // { seq, timestamp, prevRoot, newRoot, diff, reason, signature }
    tokens: 'tokens'    // { tokenHash, token, receivedAt, redeemed }
}
```

---

### `_.openDB()` → Promise\<IDBDatabase\>

```
Calls: indexedDB.open(_.DB_NAME, 1)
Called by: init.js, put.js, get.js, announce.js, claimPayments.js
```

Opens (or creates) the IndexedDB database. On `onupgradeneeded`:
- Create `chunks` store with keyPath `'cid'`
- Create `lru` store with keyPath `'cid'`, index on `lastAccessed`
- Create `log` store with autoIncrement key, index on `seq`
- Create `tokens` store with keyPath `'tokenHash'`, index on `redeemed`

Caches the open database handle in `_._db`. Subsequent calls return the
cached handle (idempotent).

---

### `_.cidFromData(buffer)` → Promise\<String\>

```
Calls: crypto.subtle.digest('SHA-256', buffer), _.digestToCid
Called by: onDropPut handler (to verify received CIDs), get.js
```

Computes CIDv1 for a `ciphertext || tag` buffer. Must produce byte-identical
output to `_.chunkCid` in Cloud. Binary layout:
`[0x01][0x55][0x12][0x20][32-byte SHA-256]`, base32-encoded with `'b'` prefix.

`buffer` is the concatenation of raw ciphertext bytes and raw tag bytes
(both from base64-decoded fields in the chunk object).

---

### `_.chunkKey(cid)` → String

```
Calls: nothing (pure)
Called by: put.js, get.js
```

Returns the IndexedDB key for a chunk: just the CID string. A pass-through
in v1 — exists to allow future namespacing without touching call sites.

---

### `_.lruKey(cid)` → String

```
Calls: nothing (pure)
Called by: put.js, get.js (for LRU update)
```

Returns the IndexedDB key for an LRU record: just the CID string.
Same as `_.chunkKey` for now — kept separate because LRU and chunk stores
may diverge in v2 (e.g. if LRU is moved to a different storage backend).

---

### `_.nowSec()` → Number

```
Calls: Date.now()
Called by: put.js, get.js (for lastAccessed), announce.js (for timestamp)
```

Returns `Math.floor(Date.now() / 1000)`. Seconds, not milliseconds.

---

### `_.canonicalJSON(obj)` → String

```
Calls: JSON.stringify (with sorted keys)
Called by: _.signAnnounce, tokens store (tokenHash derivation)
```

RFC 8785 / JCS-compatible canonical JSON serialisation: keys sorted
lexicographically at all nesting levels, no whitespace. Required so that
signatures over announce entries and token hashes are deterministic
regardless of JS engine property ordering.

Implementation: recursive key sort + `JSON.stringify` with `replacer` that
sorts object keys. Strings, numbers, booleans, null are serialised as-is.

---

### `_.signAnnounce(entry, sessionKey)` → Promise\<String\>

```
entry:      Object — announce entry (before signature field)
sessionKey: CryptoKey — non-extractable P-256 private key
Calls: _.canonicalJSON, crypto.subtle.sign('ECDSA', sessionKey, ...)
Called by: announce.js
Returns: base64 signature string
```

Signs the announce entry with the Drop's P-256 session key. The signed
payload is `_.canonicalJSON(entry)` with the `signature` field absent.
Returns the base64 raw r‖s (IEEE P1363, 64 bytes) signature string.

---

### `_.verifyAnnounce(entry)` → Promise\<Boolean\>

```
entry: Object — full announce entry including signature
Calls: _.canonicalJSON, crypto.subtle.verify('ECDSA', publicKey, ...)
Called by: Used in tests; not called in production Drops code
           (Jets verify; Drops sign)
```

Verifies an announce entry's signature. The public key is recovered from
the entry's `stm.sessionKeyES256` (from the Drop's delegation claim stored
alongside the log). Exists primarily for testing and audit tooling.

---

### `_.applyDiff(root, diff)` → Promise\<String\>

```
root:   String|null   — current Prolly root
diff:   Array<{ cid: String, added: Boolean }>
Calls:  Q.Data.Prolly.insert (for added), Q.Data.Prolly.delete (for removed)
Called by: announce.js (to compute new root before appending log entry)
Returns: Promise<String>  — new Prolly root after applying diff
```

Applies a set of CID additions and removals to the current Prolly tree root.
Calls are chained sequentially (not parallel) to maintain tree consistency.
If `root` is null and `diff` contains only additions, builds from scratch via
`Q.Data.Prolly.build`.

The Prolly store used is `_.prollyStore` (in-memory, maintained across calls).

---

### `_.buildBloom(cids)` → Promise\<String\>

```
cids:   Array<String>  — all CID strings currently stored in IndexedDB
Calls:  Q.Data.Bloom.fromElements
Called by: getBloomFilter.js (on cold contact or after eviction rebuild)
Returns: base64-encoded Bloom filter string
```

Builds a Bloom filter over all stored CIDs and returns it serialised as
base64. Typically called after opening the database and reading all CIDs
from the `lru` store (faster than `chunks` since `lru` values are smaller).

---

### `_.balanceCacheKey(evmAddress)` → String

```
Calls: nothing (pure)
Called by: get.js (balance check cache)
```

Returns `evmAddress.toLowerCase()` — the cache key for the in-memory
balance cache. Lowercased to avoid case-sensitivity issues across different
EVM address encodings.

---

## Part 4 — Public API

These are the methods callable by Jets.js (via event handlers), Cloud.js
(via `reshare()`), and the application UI.

---

### `Q.Safecloud.Drops.init(options, callback)` → Promise

```
Calls (in order):
  _.openDB
  read most recent log entry (detect wipe)
  Q.Crypto.delegate (if no delegation claim or expired)
  Q.Safecloud.Jets.dropRegister
  [if cold: _.buildBloom, Q.Safecloud.Jets.dropAnnounce with bloom]
Called by: application startup, Q.Safecloud.Drops module load
```

Initialises the Drop. Opens IndexedDB, rehydrates in-memory Prolly state
by replaying the diff log, checks delegation claim validity, and registers
with the Jet.

**Parameters:**
- `options.wallet` — ethers.js Signer (or wallet provider) for the
  `Q.Crypto.delegate` ceremony. Required on first run or session expiry.
- `options.storageGB` — storage offer (default: config value)
- `options.jetUrl` — explicit Jet URL (default: `Q.nodeUrl()`)

**Startup sequence:**

1. `db = _.openDB()`
2. Read latest log entry from `log` store:
   - If log is empty: `prollyRoot = null`, `prevRoot = null`
   - If latest entry has `reason: "reset"`: `prollyRoot = null`
   - Otherwise: `prollyRoot = latestEntry.newRoot`
3. Replay log entries through `_.applyDiff` to rebuild `_.prollyStore`
   (the in-memory Prolly tree node cache)
4. Check delegation claim in IndexedDB:
   - If missing or `stm.exp` expired: run `Q.Crypto.delegate` ceremony
     (one interactive wallet signature) and store result
   - Else: load cached delegation claim and session keypairs
5. `Q.Safecloud.Jets.dropRegister({ evmAddress, delegation, publicKey, storage, prollyRoot, bloomFilter: null })`
6. If ack `cold: true`: build Bloom filter (`_.buildBloom(allCids)`) and
   send `Q.Safecloud.Jets.dropAnnounce` with the bloom filter and current root
7. Store `_dropId` from ack in sessionStorage

**Wipe detection:** Between steps 2 and 3, if sessionStorage has a hint that
a prior session had a non-null Prolly root (stored as `Q.Safecloud.Drops.lastRoot`)
but the log is empty, send a reset announce before registration:
```js
await Q.Safecloud.Jets.dropAnnounce({ reason: 'reset', prollyRoot: null, diff: null, ... });
```

---

### `Q.Safecloud.Drops.put(chunks, options, callback)` → Promise

```
chunks:  Array<{ iv: String, ciphertext: String, tag: String, size: Number, tags: Array }>
         // All strings are base64. cid may be included by caller; if absent,
         // computed internally by _.cidFromData.
options: { authorizations, payments }
Returns: Promise<{ results: Array<{ cid: String, iv: String, size: Number }|false> }>
Called by: onDropPut handler (from Jets push)
           Cloud.reshare() (for local storage)
```

Stores encrypted chunks in IndexedDB. Performs quota check, LRU eviction
if needed, and announces after each batch.

**Pipeline per chunk:**

1. Compute `cid = _.cidFromData(concat(fromBase64(ciphertext), fromBase64(tag)))`
   — verify against any `cid` field provided by caller; mismatch = reject that chunk
2. Check if CID already in `chunks` store — if present, skip (deduplication)
3. Check quota:
   - `usedBytes + chunk.size > maxBytes` → trigger LRU eviction before storing
   - Eviction: compute which CIDs to remove (LRU order), update Prolly root via
     `_.applyDiff`, append log entry, send `Safecloud/drop/announce` with evictions,
     await ack, then delete from `chunks` and `lru` stores
4. Write chunk to `chunks` store: `{ cid, iv, ciphertext, tag, size, storedAt: nowSec() }`
5. Write LRU record: `{ cid, size, lastAccessed: nowSec() }`
6. Collect all newly stored CIDs into a batch diff

After all chunks in the batch are processed (success or skip):
7. `newRoot = _.applyDiff(currentRoot, batchDiff)`
8. Append log entry: `{ seq: auto, timestamp: nowSec(), prevRoot: currentRoot, newRoot, diff: batchDiff, reason: 'stored', signature: await _.signAnnounce(...) }`
9. `Q.Safecloud.Jets.dropAnnounce({ prollyRoot: newRoot, diff: batchDiff, reason: 'stored', ... })`
10. Update `currentRoot = newRoot`

Return `{ results: [...] }` where each entry is `{ cid, iv, size }` on
success or `false` on failure.

---

### `Q.Safecloud.Drops.get(cids, options, callback)` → Promise

```
cids:    Array<String>
options: { paymentToken: Object|null }
Returns: Promise<{ chunks: Array<{ cid: String, iv: String, ciphertext: String, tag: String }|null> }>
Called by: onDropGet handler (from Jets push)
```

Serves stored chunks. Updates LRU timestamps. Verifies Jet balance if
`paymentToken` is present.

**Pipeline:**

1. If `options.paymentToken` is present:
   - Check in-memory balance cache for `jetEVMAddress`:
     - If stale or missing: `balance = await safebux.balanceOf(jetEVMAddress)`
     - Cache result with `_.nowSec()` as timestamp
   - If `balance < perChunkSafebux * cids.length`: return all nulls
2. Store payment token: `tokens.put({ tokenHash: SHA256(canonicalJSON(token)), token, receivedAt: nowSec(), redeemed: false })`
3. For each CID:
   - `chunk = await db.transaction('chunks').get(cid)`
   - If not found: push `null` to results
   - If found: push `{ cid, iv, ciphertext, tag }` to results
   - Update LRU: `lru.put({ cid, size: chunk.size, lastAccessed: nowSec() })`
4. Return `{ chunks: results }`

**Note:** LRU updates are done in a separate transaction from chunk reads,
for performance. A crash between read and LRU update leaves the LRU slightly
stale — acceptable since LRU ordering is approximate anyway.

---

### `Q.Safecloud.Drops.getProllyRoot(callback)` → Promise\<String|null\>

```
Returns: current Prolly root from in-memory state (no DB read needed)
Called by: Q.Safecloud.Jets.dropRegister (via Jets.js client), Q.Safecloud.Jets.dropAnnounce
```

Returns `_state.prollyRoot` — the `newRoot` of the most recent log entry
held in memory. O(1). Does not read IndexedDB.

---

### `Q.Safecloud.Drops.getBloomFilter(callback)` → Promise\<String|null\>

```
Calls: _.buildBloom (if _bloomFilter is null or stale)
Returns: base64 Bloom filter string, or null if no chunks stored
Called by: Q.Safecloud.Jets.dropRegister (on cold contact)
```

Returns the in-memory Bloom filter if available. If the filter was
invalidated by an eviction, rebuilds it by reading all CIDs from the
`lru` store. Returns `null` if `chunks` store is empty.

The filter is held in `_state.bloomFilter` (in-memory). It is:
- **Updated** (elements added) on every successful `put` — O(1) per element
- **Rebuilt** (from scratch) on every eviction — O(N) but infrequent
- **Invalidated and rebuilt** on `init()` if the Jet signals cold contact

---

### `Q.Safecloud.Drops.announce(reason, callback)` → Promise

```
reason: 'stored'|'eviction'|'reset'
Calls:  _.signAnnounce, Q.Safecloud.Jets.dropAnnounce
Called by: put.js (after batch store), LRU eviction path, reset.js
```

Constructs and sends a signed announce. The diff and Prolly root are taken
from `_state` (the in-memory current state). Should not normally be called
directly — `put()` calls it automatically after each batch.

May be called manually by the application to force a sync with the Jet
(e.g. after a connectivity gap where the Jet missed previous announces).

---

### `Q.Safecloud.Drops.claimPayments(options, callback)` → Promise

```
options.direct: Boolean   // true = call OpenClaiming directly; false = relay via Jet
options.force:  Boolean   // true = claim even if below threshold
Calls:
  db.transaction('tokens').getAll (filter redeemed: false)
  [direct path:] ethers.Wallet.signMessage, ocpContract.paymentsExecute
  [relay path:]  Q.Safecloud.Jets.dropClaimPayments
Called by: application UI, threshold check in onDropGet
```

Initiates a Safebux claim for all unredeemed accumulated payment tokens.

**Direct path pipeline:**

1. Load all tokens with `redeemed: false` from `tokens` store
2. For each token in batches of `Q.Config.get(['Safe', 'drop', 'claimBatchSize'], 10)`:
   - Build Payment struct from `token.stm`
   - `recipients = [dropEVMAddress]`
   - `sig = ethers.getBytes(Buffer.from(token.sig[0], 'base64'))` — Jet's sig
   - `amount = token.stm.max == '0' ? perChunkSafebux : BigInt(token.stm.max)`
   - Call `ocpContract.paymentsExecute(payment, recipients, sig, dropEVMAddress, amount, ZeroAddress)`
   - On success: `db.transaction('tokens').put({ ...token, redeemed: true })`
3. Return `{ claimed: Number, txHashes: Array<String> }`

**Relay path pipeline:**

1. Load all tokens with `redeemed: false`
2. Build OCP claim signed with Drop's EIP-712 session key
3. `Q.Safecloud.Jets.dropClaimPayments({ dropId, paymentTokens, signature })`
4. On ack with `txHash`: mark tokens as redeemed

---

### `Q.Safecloud.Drops.reset(callback)` → Promise

```
Calls: _.openDB, IDBDatabase.deleteObjectStore (or clear all stores),
       Q.Safecloud.Jets.dropAnnounce (reset)
Called by: application UI, init.js (on detected wipe)
```

Clears all IndexedDB data, resets in-memory state, and announces a reset
to the Jet. Does NOT clear the delegation claim or session keypairs —
those are in a separate IndexedDB store (`Q.Safecloud.Drops.session`) and must
survive resets to avoid forcing a new interactive wallet signature.

After reset, the Drop is in a fresh state: empty `chunks`, `lru`, `log`,
and `tokens` stores. A new `init()` call (without wallet interaction) will
re-register with the Jet as a new cold Drop.

---

## Part 5 — Inbound event handlers (wired by Jets.js client)

These functions are exported from Drops.js and registered by Jets.js as
handlers on `Q.Safecloud.Jets.onDropPut`, `onDropGet`, `onDropChallenge`, and
`onDropSlashed`. They are not public methods — they are the socket event
response functions.

---

### `onDropPut(payload, ack)` → void

```
payload: { chunks: Array<{ cid, iv, ciphertext, tag, size, tags }>, options: Object }
ack:     function({ results: Array<{ cid, stored: Boolean }> })
Calls:   Q.Safecloud.Drops.put
```

Routes incoming `Safecloud/drop/put` events to `put()`. Converts the ack format:
`put()` returns `Array<{ cid, iv, size }|false>`; this handler converts to
`Array<{ cid, stored: Boolean }>` for the Jet's ack format.

---

### `onDropGet(payload, ack)` → void

```
payload: { cids: Array<String>, options: Object, paymentToken: Object|null }
ack:     function({ chunks: Array<{ cid, iv, ciphertext, tag }|null> })
Calls:   Q.Safecloud.Drops.get
```

Routes incoming `Safecloud/drop/get` events to `get()`. If `paymentToken` is
present and balance check fails, acks with all-null chunks rather than an
error — the Jet handles null entries as "unavailable" and tries another Drop.

---

### `onDropChallenge(payload, ack)` → void

```
payload: { cid: String }
ack:     function({ cid, iv, ciphertext, tag }|null)
Calls:   db.transaction('chunks').get(cid)
```

Responds to an explicit storage ping from the Jet. Returns the actual chunk
so the Jet can verify CID integrity via `SHA-256(ciphertext || tag) == cid`.
No nonce, no OCP signing ceremony, no hash-based proof — the CID is its own
ground truth.

**Pipeline:**

1. `chunk = await db.get('chunks', cid)` — retrieve from IndexedDB
2. If not found: ack `null`
   - Not a protocol violation if an eviction announce was already sent
   - Logged by the Jet against this Drop's reputation if Prolly root implies
     the CID should be present and no eviction was announced
3. If found: ack `{ cid, iv, ciphertext, tag }`
   - Jet verifies: `SHA-256(fromBase64(ciphertext) ‖ fromBase64(tag)) == cid`
   - Also update LRU: `lru.put({ cid, size: chunk.size, lastAccessed: nowSec() })`
     (explicit challenges count as accesses — prevents the Jet from keeping
     chunks alive via challenges that the Drop itself never serves)

A single null response is not slashable. The Jet tracks patterns: repeated
null responses for CIDs in the current signed Prolly root, combined with no
eviction announces, form the evidentiary basis for a CoC. See section 1.10.

---

### `onDropSlashed(payload)` → void

```
payload: { reason: String }
Calls:   Q.Safecloud.Drops Events: 'slashed'
```

Receives notification that this Drop's stake has been slashed. In the
reference implementation: fires `Q.Safecloud.Drops.emit('slashed', payload)`,
logs the reason, and optionally displays a warning in the UI. The Drop
does not automatically stop operating — the application layer decides
whether to cease offering storage (typical: stop, prompt user to review).

---

## Part 6 — Implementation Order

Each step only calls things already listed above it.

1. `_.DB_NAME`, `_.STORES` — pure constants
2. `_.nowSec()` — pure
3. `_.canonicalJSON(obj)` — pure
4. `_.cidFromData(buffer)` — calls `crypto.subtle.digest`, internal base32
5. `_.chunkKey(cid)` — pure pass-through
6. `_.lruKey(cid)` — pure pass-through
7. `_.balanceCacheKey(evmAddress)` — pure
8. `_.openDB()` — IndexedDB open + schema creation
9. `_.applyDiff(root, diff)` — calls `Q.Data.Prolly`; needs `_.openDB` for store
10. `_.buildBloom(cids)` — calls `Q.Data.Bloom.fromElements`
11. `_.signAnnounce(entry, sessionKey)` — calls `_.canonicalJSON`, `crypto.subtle.sign`
12. `_.verifyAnnounce(entry)` — calls `_.canonicalJSON`, `crypto.subtle.verify`
13. `Q.Safecloud.Drops.getProllyRoot()` — O(1) in-memory read
14. `Q.Safecloud.Drops.getBloomFilter()` — calls `_.buildBloom` if needed
15. `Q.Safecloud.Drops.announce(reason)` — calls `_.signAnnounce`, `Q.Safecloud.Jets.dropAnnounce`
16. `Q.Safecloud.Drops.put(chunks, options)` — calls `_.openDB`, `_.cidFromData`, `_.applyDiff`, `announce`
17. `Q.Safecloud.Drops.get(cids, options)` — calls `_.openDB`, balance check (ethers.js)
18. `onDropPut(payload, ack)` — calls `Q.Safecloud.Drops.put`
19. `onDropGet(payload, ack)` — calls `Q.Safecloud.Drops.get`
20. `onDropChallenge(payload, ack)` — calls `_.openDB` only (returns chunk, no signing)
21. `onDropSlashed(payload)` — event emit only
22. `Q.Safecloud.Drops.claimPayments(options)` — calls `_.openDB`, ethers.js
23. `Q.Safecloud.Drops.reset()` — calls `_.openDB`, `announce` (reset)
24. `Q.Safecloud.Drops.init(options)` — calls all of the above; registers with Jet

---

## Part 7 — What is NOT in Drops.js

- **Chunk encryption or decryption** — Cloud only. Drops store and serve opaque
  ciphertext bytes. The `iv`, `ciphertext`, and `tag` fields are stored as
  received and returned as-is. No SubtleCrypto AES operations occur in Drops.

- **Merkle tree building or verification** — Cloud builds the Merkle tree from
  CIDs; Jets builds Merkle proofs from the `_cidIndex`; Drops are not involved
  in Merkle operations. A Drop's CID is a content address, not a Merkle leaf
  in the Drop's own data structure.

- **Key derivation** — Cloud only. Drops never hold or derive encryption keys.
  The session keypairs are identity/signing keys, not encryption keys.

- **OCP Role A grant verification** — Jets server only. Drops do not check
  whether the requestor is authorised to access specific content; they only
  check whether they are being paid (OCP Role B) by the Jet that is asking them.

- **Socket.io connection management** — Jets.js client only. Drops do not
  manage socket connections directly; all socket communication goes through
  `Q.Safecloud.Jets.*` methods.

- **Prolly tree building on the Jet side** — Jets server maintains its own
  Prolly trees per Drop. Drops build their own Prolly tree over their own
  inventory. These are the same data by construction (if the Drop is honest)
  but maintained independently.

- **On-chain balance submission** — Drops only read balances (pre-screen) and
  optionally submit claims. The authoritative balance enforcement is on-chain
  at `paymentsExecute()` time.

- **Content routing** — selecting which Drop stores or serves which CID is
  the Jet's responsibility (`Q.Safecloud.Router`). Drops respond to requests; they
  don't decide what they store beyond accepting or rejecting based on quota.

- **Hyperswarm or Jet-to-Jet communication** — Drops communicate only with
  their connected Jet via socket.io. Peer discovery, DHT, and Jet relay are
  entirely outside the Drops layer.

- **Safebux token contract deployment or management** — Drops only read
  balances and execute payment claims. Token governance, minting, and the
  graduation lockup schedule are in the Safebux ERC-20 contract on BSC.
