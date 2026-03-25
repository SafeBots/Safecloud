# SafeCloud — Attack Surface and Security Analysis

This document catalogs every attack class identified against the SafeCloud
protocol: identity attacks, storage accountability attacks, payment exploits,
routing manipulation, CoC abuse, network-level attacks, economic game-theory
attacks, and cryptographic edge cases. Each entry states the attacker's goal,
the mechanism, the outcome, and the protocol's defense. Where a defense is
incomplete or depends on an off-chain assumption, that is noted explicitly.

Read `Protocol.md`, `Cloud.md`, `Jets.md`, `Drops.md`, and `Routing.md`
before this document. This document does not restate architecture — it
assumes familiarity and focuses on adversarial analysis.

**Notation:** Mallory = attacker. Alice, Bob = honest participants.
"Succeeds" means the attacker achieves their goal. "Fails" means the
protocol prevents it. "Partial" means the attack has a reduced but real
effect. Ratings: 🔴 High risk, 🟡 Medium risk, 🟢 Low risk / resolved.

---

## Table of Contents

1. [Identity and Impersonation Attacks](#1-identity-and-impersonation-attacks)
2. [Storage Accountability Attacks](#2-storage-accountability-attacks)
3. [Payment Exploitation](#3-payment-exploitation)
4. [Routing Manipulation](#4-routing-manipulation)
5. [Proof of Corruption Abuse](#5-proof-of-corruption-abuse)
6. [Network-Level Attacks](#6-network-level-attacks)
7. [Economic and Game-Theory Attacks](#7-economic-and-game-theory-attacks)
8. [Cryptographic Edge Cases](#8-cryptographic-edge-cases)
9. [Trusted Environment Attacks](#9-trusted-environment-attacks)
10. [Cross-Cutting Observations](#10-cross-cutting-observations)

---

## 1. Identity and Impersonation Attacks

---

### 1.1 Delegation claim forgery 🟢

**Goal:** Mallory registers as Bob's EVM address without Bob's private key.

**Mechanism:** Mallory sends `Safe/drop/register` or `safecloud.jet.hello`
with `evmAddress = Bob` and a fabricated delegation claim.

**Outcome:** Fails. The `safecloud:session-delegation` OCP claim must be
signed by the wallet key of the stated `iss` address. Mallory does not have
Bob's EVM private key. The receiving Jet recovers the signer from the EIP-712
signature and verifies it matches `evmAddress`. The claim is rejected.

**Defense:** EIP-712 wallet signature in delegation claim. Any entity without
the private key cannot produce a valid signature.

---

### 1.2 Delegation claim replay 🟢

**Goal:** Mallory captures Bob's `safecloud:session-delegation` claim from
one session and reuses it in a later session to impersonate Bob.

**Mechanism:** Mallory intercepts or steals the delegation OCP claim (e.g.
from network traffic or a memory dump) and presents it as her own.

**Outcome:** Fails in practice. The delegation claim carries `stm.exp`
(default 30-day expiry). If Mallory replays after expiry, the Jet rejects
it. If Mallory replays within the validity window, she has a live credential
for Bob's session key — but using it would require also having the corresponding
P-256 and secp256k1 session private keys, which are non-extractable `CryptoKey`
objects in Bob's IndexedDB. The claim without the private keys is useless for
signing.

**Residual risk:** If Mallory has read access to Bob's device (IndexedDB
contents + non-extractable keys), she has full session access — but this is
device compromise, not protocol attack.

**Defense:** Short session expiry + non-extractable session keys.

---

### 1.3 Session key extraction via malicious JavaScript 🟡

**Goal:** Mallory ships malicious JS to a Drop that calls `sign()` on the
non-extractable session keys with attacker-chosen payloads, effectively
forging protocol messages.

**Mechanism:** Mallory compromises the JS bundle served to the Drop (e.g.
by compromising the CDN, DNS hijacking, or serving from a non-attested origin).
The malicious JS does not extract the key bytes — it calls `cryptoKey.sign()`
directly on arbitrary messages.

**Outcome:** Succeeds if SafeBox attestation is not verified. `extractable:
false` prevents key byte extraction but does not prevent `sign()` calls from
within the same execution context. Malicious JS can sign fabricated Prolly
diffs, false announces, or fraudulent challenge responses — all attributable
to the Drop's legitimate session key.

**Defense:** SafeBox-attested environment. The JS bundle hash is in the Nitro
attestation claim at `safebox.org/.well-known/safecloud-attestation.json`.
Jets verify attestation before granting full routing priority to a Drop.
Non-attested Drops receive reduced weight.

**Residual risk:** If the user does not verify attestation, or uses a
non-SafeBox environment, this attack is fully viable. The protocol requires
the pristine environment assumption; it cannot cryptographically enforce it
from the outside.

---

### 1.4 SafeBox attestation spoofing 🟡

**Goal:** Mallory operates a non-attested server but presents a fake
attestation claim to deceive peer Jets into treating her Drops as
fully trusted.

**Mechanism:** Mallory fabricates an OCP `safecloud:environment-attestation`
claim signed by her own key (not the SafeBox operator key) and publishes it
at her server's `.well-known/` endpoint.

**Outcome:** Partial. The attestation claim is signed by `SafeBox-operator-EVM`
— a well-known public key. Mallory cannot forge a signature under that key.
However, if peer Jets do not verify the signing key against the known SafeBox
operator address, they may accept the fake attestation.

**Defense:** Jets MUST verify that the attestation claim's `iss` matches the
hardcoded SafeBox operator EVM address. New SafeBox operators must be announced
and accepted by the network (a social/governance process, not a protocol
mechanism). Unknown attestation signers must be treated as unattested.

**Recommendation:** Hardcode the SafeBox operator EVM address as a protocol
constant alongside the OpenClaiming contract address.

---

### 1.5 EVM address namespace collision (different chains) 🟢

**Goal:** Mallory uses an EVM address on another chain where she has the
private key, to impersonate a high-stake participant whose same address on
BSC is controlled by someone else.

**Mechanism:** EVM addresses are the same format across chains. If Alice has
high stake at `0xABCD...` on BSC but Mallory controls `0xABCD...` on Ethereum,
Mallory could try to use Ethereum-signed claims to impersonate BSC-Alice.

**Outcome:** Fails. All OCP claims in SafeCloud include chain-specific domain
separation in EIP-712 signatures (`chainId` in the domain separator). A
signature valid on Ethereum's `eip155:1` does not verify against BSC's
`eip155:56`. The protocol is BSC-canonical for identity and stake; Ethereum
signatures are not accepted.

**Defense:** EIP-712 domain separator includes `chainId = 56` (BSC). No
cross-chain signature confusion is possible.

---

### 1.6 MITM relay impersonation 🟢

**Goal:** MalloryDrop (connected to Jet1) and MalloryJet (connected to Drop2)
form a relay, allowing Mallory to intercept traffic and impersonate either end.

**Full analysis:** See Protocol.md § MITM relay and § Can MalloryJet get an
honest Drop2 slashed?

**Summary:** Mallory cannot impersonate Drop2 to Jet1 (no Drop2 private key).
Mallory cannot manufacture a CoC against Drop2 (challenge responses are
deterministic; challenge for missing CID is not contradictory). The one real
harm is economic extraction: Mallory earns from Jet1 while underpaying Drop2.
Mitigation: latency-based routing priority deprioritizes high-latency relays.

---

## 2. Storage Accountability Attacks

---

### 2.1 LRU eviction flooding 🟡

**Goal:** MalloryJet fills Drop2's storage quota with garbage chunks, forcing
Drop2 to LRU-evict legitimate previously-announced chunks. Mallory then
challenges Drop2 for an evicted chunk to manufacture a CoC.

**Mechanism:**
1. MalloryJet sends large volume of `Safe/drop/put` requests
2. Drop2's storage fills; LRU evicts old chunks
3. If Drop2 evicts without re-announcing (violating the announce-before-evict rule),
   Mallory can file a CoC: old announce claims CID Y present, challenge fails

**Outcome:** Partial. If Drop2 faithfully implements announce-before-evict,
the CoC is invalid — the new Prolly root explicitly removes CID Y before
eviction, so no contradiction exists. If Drop2 violates the rule (evicts
silently), the CoC is structurally valid, but this is a genuine protocol
violation by Drop2, not a wrongful slash.

**Defense:** Announce-before-evict is a protocol requirement. Honest Drops
running the reference implementation satisfy it automatically. CoC validation
must check temporal consistency: the announce predating the challenge must
be the most recent announce as of challenge time.

**Residual risk:** A Drop running broken or non-reference code that evicts
without announcing is genuinely vulnerable. Jets should rate-limit `put`
requests per Drop to slow flooding attacks.

**Recommendation:** Jets MUST rate-limit `Safe/drop/put` per connected Drop
(e.g. `Q.Config.get(['Safe', 'drop', 'maxPutRatePerSec'], 10)`). This bounds
the storage flooding surface.

---

### 2.2 Selective non-announcement (silent eviction) 🟡

**Goal:** Drop evicts chunks it no longer wants to store, omits the announce,
and hopes no challenge arrives for those CIDs before the omission is detected.

**Mechanism:** Drop silently deletes CIDs from IndexedDB without updating its
Prolly root or sending a diff announce. The Jet's view of the Drop's inventory
is stale.

**Outcome:** Partial. The Drop will fail random spot-check `get` requests for
the silently-evicted CIDs. If the Jet accumulates a pattern of "CID in
announced root, serve returns null, no eviction announce sent," this is CoC
material. The attack only works if the Drop is lucky enough that the evicted
CIDs are never requested during the window of inconsistency.

**Defense:** Silent random spot-checks (indistinguishable from real requests)
create a stochastic detection mechanism. The longer the inconsistency persists,
the higher the probability of detection. The Jet does not need to prove the
Drop is dishonest in any single interaction — a pattern across multiple
requests + signed announce constitutes sufficient CoC evidence.

**Economic consequence:** The Drop earns payment for serving chunks it no
longer holds. When challenged, it fails. This is a form of fraud — the Drop
is accepting payment for a service it cannot render.

---

### 2.3 Garbage chunk acceptance without verification 🟢

**Goal:** MalloryJet pushes chunks with incorrect CID labels (CID does not
match `SHA-256(ciphertext || tag)`). Drop stores them, announces them, and
later fails to serve valid content for those CIDs.

**Mechanism:** Mallory sends chunks where `cid` is crafted to be a CID of
some valuable content, but the `ciphertext || tag` bytes are garbage.

**Outcome:** Fails as an attack against Drop2. The protocol does not require
Drops to verify CID correctness on put — they are not trusted to compute
cryptographic proofs. However, the `Safe/drop/challenge` response returns the
actual chunk bytes, and the receiving Jet verifies `SHA-256(ciphertext || tag)
== cid`. Garbage chunks fail CID verification. This damages the Jet's
reliability record for routing, not Drop2's stake.

The Drop cannot be slashed for storing data as instructed and returning it
faithfully. The protocol's security for content integrity rests on Cloud's
Merkle verification (`fetch()` verifies every chunk against the manifest
rootCid before decryption) — Drops are not in the integrity chain.

**Residual concern:** A garbage-flooded Drop wastes storage quota on useless
data. Combined with 2.1 (LRU flood), this is a denial-of-service against
the Drop's storage capacity. Rate-limiting `put` requests is the mitigation.

---

### 2.4 Crash between announce-ack and delete 🟢

**Goal:** Not an attack — this is a protocol edge case. The Drop sends an
eviction announce, receives the Jet's ack, then crashes before actually
deleting the evicted chunks from IndexedDB.

**Outcome:** On restart, the Drop's IndexedDB still contains chunks its
Prolly root says it evicted. This is over-delivery: the Drop has more than
it claims. No contradiction exists — the Prolly root says the CIDs are gone,
and indeed if challenged for those CIDs, the Drop returns null (because its
in-memory state reflects the announced root, not the stale IndexedDB entries).

Wait — this is subtler: if the Drop reads from IndexedDB on startup to
reconstruct its state, it will find chunks that the log says were evicted. The
reference implementation MUST reconcile by reading the latest log entry as
authoritative, not the raw IndexedDB contents.

**Defense:** On `init()`, the Drop replays the diff log to determine the
current Prolly root, then trusts that root. Chunks in IndexedDB that are not
in the current Prolly root are treated as orphaned and should be cleaned up
lazily. They do not affect the announced state.

---

### 2.5 Announce sequence number manipulation 🟢

**Goal:** Mallory (with a compromised Drop) sends announces out of order —
a high-seq announce with a fraudulent root, then a lower-seq announce with
an honest root — attempting to confuse the Jet's Prolly state.

**Mechanism:** Drop signs and sends announces with manipulated `seq` fields.

**Outcome:** Fails. The Jet maintains its own Prolly tree, which it updates
by verifying `apply(prevRoot, diff) == prollyRoot` for each announce. An
out-of-order announce that does not chain correctly from the Jet's current
known root is rejected. The `seq` field is informational; the cryptographic
chain is `prevRoot → diff → newRoot`.

---

### 2.6 Prolly root preimage collision 🟢

**Goal:** Mallory crafts a set of CIDs that hash to a specific Prolly root
she wants to claim, without actually holding those CIDs.

**Mechanism:** Find a CID set S such that `ProllyTree(S) == target_root`,
where `target_root` is some useful root (e.g. a high-reputation Drop's root).

**Outcome:** Computationally infeasible. Prolly tree nodes are SHA-256 hashes;
finding a preimage requires breaking SHA-256. This is a non-attack.

---

## 3. Payment Exploitation

---

### 3.1 Jet balance drain before claim 🟡

**Goal:** MalloryJet issues valid OCP Role B payment tokens to Drop, Drop
serves chunks, then MalloryJet drains its SafeBux balance before Drop
submits the claim. `paymentsExecute()` fails; Drop served for free.

**Mechanism:**
1. MalloryJet accumulates a large debt to Drop via valid payment tokens
2. Before Drop reaches the claim threshold, MalloryJet transfers all its
   SafeBux to another address (or spends it on other claims)
3. Drop submits claim; `transferFrom` reverts because balance is zero

**Outcome:** Partial. The Drop's pre-service balance check catches this for
any request where the balance is already insufficient. But the balance check
is a snapshot (1-hour cache) and is not atomic with `paymentsExecute()`. A
Jet can pass the pre-check and then drain its balance between the check and
the claim submission.

**Defense layers:**
1. Drop's 1-hour cache: catches Jets that drained hours ago
2. `paymentsExecute()` on-chain: definitive — if balance is gone, claim fails
3. Economic: Drop earns nothing from a draining Jet; once detected, the
   Drop's reliability tracking records failures and routes away

**Recommended mitigation:** Drops SHOULD enforce a safety margin: check that
`balance >= N × expected_cost` where `N = Q.Config.get(['Safe', 'drop', 'balanceMargin'], 2)`.
A 2× margin means the Jet must drain more than half its balance between
pre-check and claim, reducing the window of opportunity.

**Recommended mitigation 2:** Drops SHOULD claim frequently rather than
waiting for the full threshold. Frequent small claims reduce the exposure
window. `claimThresholdSafebux` should be set conservatively.

**Economic constraint:** The graduated lockup means a Jet cannot drain its
entire balance instantly — only the unlocked fraction is transferable. A Jet
that has earned and locked SafeBux has a persistently slashable stake,
reducing the incentive for this attack.

---

### 3.2 Payment token replay (Drop overclaims) 🟢

**Goal:** Drop calls `paymentsExecute()` more times than justified, claiming
more SafeBux than the actual service provided.

**Mechanism:** Payment tokens have no nonce and are reusable until `stm.max`
is exhausted via accumulated `spent`. Drop calls `paymentsExecute(amount)` in
a loop until the token ceiling is reached.

**Outcome:** Bounded. The contract tracks `lines[payer][line].spent` and
enforces `spent <= max`. The Drop cannot extract more than `stm.max` total
from any single token, regardless of how many times it calls `paymentsExecute`.
Over-claiming is capped by the token ceiling.

**Residual concern:** If `stm.max = 0` (unlimited), the Drop can extract
unboundedly from the payer's balance (capped only by the payer's actual
balance and `ERC20.allowance`). Jets MUST set `stm.max` to a finite value
equal to the expected cost of the services covered by that token. `stm.max = 0`
should never be used in SafeCloud payment tokens.

---

### 3.3 Payment token theft (eavesdropping) 🟢

**Goal:** Mallory intercepts an OCP Role B payment token in transit between
Jet and Drop and claims it herself.

**Mechanism:** Mallory reads the payment token from network traffic and
submits it to `paymentsExecute()` with `recipient = mallory_address`.

**Outcome:** Fails. `stm.recipientsHash = keccak256(abi.encode([dropEVMAddress]))`.
The contract verifies that the `recipients` array passed to `paymentsExecute`
hashes to `stm.recipientsHash`. Mallory cannot change the recipient address
without invalidating the hash. The token can only be claimed by the Drop
whose address was committed by the Jet at signing time.

---

### 3.4 Cross-token balance confusion 🟢

**Goal:** Drop accumulates tokens from multiple Jets, submits them all at
once, and attempts to double-count by submitting the same token under
different `line` values.

**Mechanism:** Drop modifies `stm.line` in the Payment struct before calling
`paymentsExecute()`.

**Outcome:** Fails. The `line` field is part of the EIP-712 Payment struct
and is included in the signed hash. Modifying `stm.line` after signing
invalidates the Jet's EIP-712 signature. The contract rejects the claim with
`PayerMismatch` or `InvalidSignature`.

---

### 3.5 Relay payment withholding (Jet A doesn't pay Jet B) 🟡

**Goal:** Jet A relays a request to Jet B but does not include a valid
payment token in the relay request, receiving Jet B's service for free.

**Mechanism:** Jet A omits `X-OCP-Payment` header from the relay request,
or provides a token with an insufficient balance.

**Outcome:** Partial. Jet B performs the same balance pre-check on Jet A
as a Drop performs on a Jet. If Jet A's SafeBux balance is insufficient, Jet
B returns 402 and does not serve. If Jet A's balance passes pre-check but
the token is undervalued, Jet B serves and the claim for underpayment may
be disputed — Jet B earns less than expected.

**Defense:** Jet B tracks Jet A's payment history via reliability scoring.
A Jet A that consistently underpays or withholds payments gets removed from
Jet B's routing table. Jet B stops accepting relay from Jet A.

**Recommendation:** The relay protocol MUST specify a minimum payment amount
per chunk (same `perChunkSafebux` config used for Cloud→Jet payments). Jet B
should reject relay requests whose payment token's `stm.max` is below
`minRelayPayment × chunkCount`.

---

### 3.6 Payment token front-running on BSC 🟡

**Goal:** Mallory observes a Drop's pending `paymentsExecute()` transaction
in the BSC mempool and front-runs it by submitting the same token first,
draining the `spent` ceiling before the Drop's transaction is included.

**Mechanism:** The Drop's `paymentsExecute()` call is visible in the mempool.
Mallory copies the calldata and submits with a higher gas price. If Mallory's
transaction is included first, `spent` is advanced; the Drop's transaction
may fail or extract less than expected.

**Outcome:** Only possible if Mallory knows the Drop's EVM address (to
construct a valid `recipients` array). More critically: the token's `recipient`
field must match the Drop's address — Mallory cannot redirect the payment to
herself. The worst outcome is that Mallory "claims on behalf of" the Drop —
the SafeBux still goes to the Drop, just slightly earlier than the Drop intended.
This is not economically harmful to the Drop.

**Residual concern:** If the token is structured so that part of the payment
goes to a claimant (future DAO/commission feature), front-running could
redirect that portion. In v1 with direct `transferFrom` to the Drop, this is
not exploitable.

---

### 3.7 Payer approves insufficient allowance 🟢

**Goal:** Payer (Cloud client or application server) approves only a tiny
ERC-20 allowance to the OpenClaiming contract, so `transferFrom` fails when
Jets try to claim.

**Mechanism:** Before signing payment tokens, payer calls
`SAFEBUX.approve(OC_ADDRESS, smallAmount)`. Payment tokens are valid but
uncollectable.

**Outcome:** This is the payer's economic loss — they signed tokens they
cannot honor. Jets detect this during balance/allowance pre-check and reject
further payment tokens from this payer. The payer's content becomes
unavailable through Jets that enforce payment. This is not an attack against
Jets or Drops — it's the payer shooting themselves in the foot.

---

## 4. Routing Manipulation

---

### 4.1 Bloom filter inflation 🟡

**Goal:** Drop sends a Bloom filter claiming to hold many CIDs it does not
actually have, attracting routing traffic it cannot serve.

**Mechanism:** Drop constructs a Bloom filter with all bits set (or with
elements for popular CIDs it knows exist but doesn't hold). Jet routes
requests to this Drop based on false positive Bloom hits.

**Outcome:** Partial. The Drop receives requests, returns null (chunks not
in IndexedDB), and the Jet records failed serves. Reliability score drops.
After enough failures, the Drop's routing weight approaches zero and it
stops receiving requests. No stake is slashed — this is an annoyance and
bandwidth waste, not a slashable offense (no contradictory signed claims).

**Defense:** Reliability scoring is the primary defense. A Drop that
consistently returns null for Bloom-matched requests is efficiently
deprioritized. Jets SHOULD track per-Drop false-positive rates and reduce
routing priority for Drops exceeding a threshold
(`Q.Config.get(['Safe', 'drop', 'maxBloomFPR'], 0.05)`).

**Recommendation:** If a Drop's observed false-positive rate significantly
exceeds the theoretical 1% FPR, Jets should flag it for increased spot-checking
and apply a penalty multiplier to its routing weight.

---

### 4.2 False routing announcement (Jet claims coverage it doesn't have) 🟡

**Goal:** MalloryJet gossips `safecloud:routing-announcement` claiming it can
route for a `rootCid` that none of its Drops hold, attracting relay traffic
it cannot serve.

**Mechanism:** Mallory signs a routing announcement without a legitimate Drop
co-signature, or with a Drop co-signature over a stale Prolly root.

**Outcome:** Partial. Routing announcements require Drop co-signature.
Without a legitimate Drop signing that it holds the rootCid, the announcement
cannot be constructed. If Mallory controls a Drop and signs a false announcement,
the Drop will fail spot-check requests for those CIDs — same as 4.1.

Peer Jets that relay through MalloryJet and receive null responses update
their `_peerRoutes` reliability for MalloryJet. After enough failures,
MalloryJet is removed from routing tables.

---

### 4.3 Availability event spoofing 🟡

**Goal:** MalloryJet sends false `safecloud:drop-availability` events claiming
a popular `rootCid` is available when it isn't, attracting Cloud clients.

**Mechanism:** Mallory signs a `safecloud:drop-availability { event: "available", rootCid: X }`
claim without any Drop holding X.

**Outcome:** Partial. Cloud clients routed through MalloryJet make requests
that return null chunks. MalloryJet earns payment tokens from Cloud for
services it cannot render — but those tokens may never be claimable if
Mallory's balance is insufficient (see 3.1). Reliability score degrades.
The real harm is latency for Cloud clients — they waste request time on a
Jet that can't serve.

**Defense:** Cloud clients track which Jets reliably serve their requests.
A Jet with high null-return rates for requested rootCids is eventually
deprioritized by Cloud's routing configuration.

---

### 4.4 Sybil Drop attack 🟢

**Goal:** Mallory registers many low- or zero-stake Drops to capture a
majority of routing decisions from Jet1.

**Mechanism:** Mallory creates N Drop identities (each a different EVM address
and session keypair), all with zero SafeBux stake.

**Outcome:** Fails at scale. Routing weight = `stakedSafebux × reliability ×
availableStorage`. Zero-stake Drops receive near-zero weight. To capture
significant routing share, Mallory must stake real SafeBux across all her Drops.
Each unit of routing share requires proportional stake — Sybil attacks require
Mallory to lock real economic value.

**Residual concern:** New legitimate Drops also start with zero stake and
low priority. The system has a bootstrapping period for honest new participants.
The minimum stake threshold
(`Q.Config.get(['Safe', 'drop', 'minStakeSafebux'], '0')`) can be set
by operators to require some minimum skin in the game before any routing occurs.

---

### 4.5 Routing table poisoning via fake Prolly diffs 🟢

**Goal:** MalloryJet sends falsified `safecloud.prolly.diff.response` messages
to Jet1, claiming to have inventory it doesn't hold, and polluting Jet1's
`_peerRoutes`.

**Mechanism:** During second-level Prolly sync, MalloryJet responds with a
fabricated diff claiming coverage for rootCids that none of MalloryJet's
Drops hold.

**Outcome:** Partial. Jet1 routes relay requests to MalloryJet for those
rootCids and receives null responses. Reliability tracking for MalloryJet
degrades. However, because relay routing decisions also consider latency and
dropCount from `safecloud:drop-availability` events, false diff claims that
are not corroborated by availability events raise no availability count and
receive lower priority anyway.

**Defense:** Prolly diff responses are validated by checking `apply(myRoot,
diff) == peerRoot`. If the diff is inconsistent with the peer's advertised
second-level root, it is rejected. False claims that are self-consistent
(Mallory controls a coherent false Prolly tree) are caught via serve failures.

---

### 4.6 Latency-based routing poisoning 🟡

**Goal:** Mallory creates a Drop with artificially fast response times during
initial reliability measurement (e.g. by pre-caching the queried CIDs and
serving from memory), establishing a high reliability score. Once the score
is high, Mallory starts responding slowly or selectively.

**Mechanism:** During the initial scoring period, Mallory pre-loads specific
CIDs from the network into a fast cache. Once her Drop has a `reliabilityScore`
near 1.0, she switches to slow/unreliable serving for all other CIDs.

**Outcome:** Partial. Reliability scoring is an exponential moving average —
it decays relatively quickly after the initial gaming period. With
`score = 0.9 * score + 0.1 * success`, a Drop that served perfectly for
100 requests then starts failing degrades from 1.0 to below 0.5 within
~7 failures. The attack provides a brief window of inflated trust.

**Defense:** The EMA decay rate is inherently self-correcting. The scoring
is per-Drop, so gaming one score doesn't help Mallory's other Drops.
Optional enhancement: weight recent interactions more heavily than old ones
(shorter half-life) at the cost of more volatility for legitimately fluctuating
Drops.

---

### 4.7 Request coalescing abuse 🟡

**Goal:** Mallory (as a Jet operator or rogue Cloud client) triggers many
simultaneous requests for the same CID to exploit the inflight coalescing map
in `Safe.Router`, causing the coalesced promise to be resolved with attacker-
controlled content.

**Mechanism:** Mallory issues N concurrent requests for CID X. The Router
coalesces them to one Drop request. If Mallory also controls the Drop serving
the response, she can return incorrect bytes for CID X — all N waiters receive
the same bad response.

**Outcome:** Fails at the integrity layer. All coalesced responses are
verified by the Jet via `SHA-256(ciphertext || tag) == cid` before being
returned to callers. A corrupted response fails CID verification and is
discarded. The Drop's reliability score degrades for the verified failure.

**Defense:** CID self-verification is the authoritative check. Coalescing is
safe because every resolved value is independently verified before dispatch
to callers.

---

## 5. Proof of Corruption Abuse

---

### 5.1 Frivolous CoC spam 🟢

**Goal:** Mallory files many bogus CoCs against honest participants,
consuming network bandwidth, disrupting routing, and extracting others'
time verifying invalid claims.

**Mechanism:** Mallory sends CoC messages with fabricated or non-contradictory
evidence to all peer Jets.

**Outcome:** Limited. Each CoC requires a deposit of `minClaimantStake`
SafeBux that is lost if the CoC is adjudicated as frivolous. Spam is
economically bounded by Mallory's stake. Peer Jets verify CoC evidence
before forwarding — non-validating CoCs are dropped immediately and do not
propagate further.

**Defense:** Stake deposit per CoC. Peer Jets validate before forwarding
(hop count limits propagation). A Mallory who cannot pass the validation
check at the first hop gets zero propagation.

---

### 5.2 Forged CoC evidence 🟢

**Goal:** Mallory constructs a CoC against Alice with forged OCP signatures
that appear to be Alice's but are not.

**Mechanism:** Mallory fabricates two signed claims purportedly from Alice's
P-256 session key showing a contradiction.

**Outcome:** Fails. ECP-256 signatures cannot be forged without the private
key. Any honest node verifying the evidence recovers the signer from the
ECDSA signature and checks it against Alice's registered session public key.
Forged signatures produce different recovered addresses. Mallory's CoC is
rejected as invalid and Mallory loses her deposit.

---

### 5.3 Timing-window CoC (stale announce + future challenge) 🟡

**Goal:** Mallory waits for Alice's Drop to send an announce (claiming CID Y),
then arranges for Alice's Drop to evict CID Y via storage flooding (2.1),
then issues a challenge for CID Y before Alice can re-announce, constructing
a valid-looking CoC from the old announce and the challenge failure.

**Mechanism:** This is attack 2.1 combined with a timing window.

**Outcome:** Partially mitigated. The announce-before-evict protocol
requirement means Alice's Drop should announce the eviction BEFORE deleting
CID Y. If Alice's implementation is correct, the Prolly root is updated before
eviction, making the old announce irrelevant as CoC evidence.

The residual window: between the eviction announce and the actual deletion,
there is a brief period where the new root says CID Y is gone but the chunks
still exist in IndexedDB. During this window, if Mallory challenges for CID Y,
Alice returns the chunk (still present) — no challenge failure, no CoC.

The attack only works against a Drop that violates announce-before-evict.

**Recommendation:** CoC validation MUST enforce temporal consistency: the
signed announce used as evidence must be the most recent announce from that
Drop as of the challenge time. An announce that was superseded by a newer
announce before the challenge was issued is not valid CoC evidence.

---

### 5.4 CoC evidence exfiltration for stalking 🟡

**Goal:** Mallory collects signed Prolly diff log entries gossiped alongside
CoCs to build a detailed history of a Drop's storage behavior — not to slash
it, but to surveil its activity and infer what content it stores.

**Mechanism:** CoC evidence bundles contain signed announces with CID diffs.
A party receiving many CoCs involving a specific Drop accumulates a rich
history of that Drop's inventory changes over time.

**Outcome:** Partial. The CIDs in Prolly diffs are of encrypted chunks —
they reveal what ciphertext the Drop holds but not the content. Without the
subtreeKey (which is never in any OCP claim), the CIDs are opaque identifiers.
However, if Mallory already has the subtreeKey for some content (as a
legitimate viewer), she can correlate CIDs to determine whether a specific
Drop holds specific files.

**Residual concern:** This is a privacy leak, not a security failure. The
protocol does not promise content privacy at the network routing layer —
CIDs are observable by any routing participant. Privacy of content requires
content key privacy (OCP Role A grants), which is maintained.

---

### 5.5 CoC flood to suppress legitimate slashing 🟡

**Goal:** Mallory's corrupt Drops are about to be slashed via legitimate CoCs.
Mallory floods the network with many valid-looking but slightly incorrect
CoCs to fill peers' `_cocStore` caches and hit hop limits, preventing the
legitimate CoCs from propagating.

**Mechanism:** Mallory generates many CoCs with valid signatures and valid
evidence (non-contradictory but structurally well-formed), saturating the
gossip bandwidth.

**Outcome:** Partial. Each CoC requires stake. Flooding at scale is
economically expensive. The hop limit (7 hops) bounds propagation regardless
of volume. Legitimate CoCs against Mallory's own Drops will still propagate
across the network within 7 hops.

**Defense:** `_cocStore` deduplication (by content hash) prevents the same
CoC from being re-forwarded. Different CoCs from Mallory consume her stake.
The network converges on the legitimate CoCs because honest nodes apply
consistent validation and will not forward Mallory's invalid ones.

---

## 6. Network-Level Attacks

---

### 6.1 Hyperswarm eclipse attack 🟡

**Goal:** Mallory controls enough DHT nodes to ensure that when Jet1 joins
the `safecloud-jets` topic, all or most of its discovered peers are Mallory's
Jet nodes. Jet1 sees a false view of the network.

**Mechanism:** Mallory operates many hyperswarm nodes positioned to intercept
Jet1's DHT queries and return only Mallory-controlled peers.

**Outcome:** Partial. Jet1 sees only MalloryJets in its routing table. For
content held by honest Drops connected to honest Jets, Jet1 cannot route
requests. Mallory can offer her own content and earn payment. She cannot
actively harm Jet1's existing Drops (which connect outbound to Jet1, not
through the DHT).

**Defense:** Hyperswarm provides some eclipse resistance via the DHT's
routing table diversity. Beyond that: SafeCloud operators can hardcode known
trusted Jet peer addresses as fallback bootstrap nodes
(`Q.Config.get(['Safe', 'router', 'bootstrapPeers'], [])`). Multiple bootstrap
sources reduce eclipse risk.

**Long-term mitigation:** Jet1's reliability tracking for peer Jets exposes
a MalloryJet that consistently returns empty relay responses. Over time,
Mallory-only routing tables are discovered and peers are deprioritized.

---

### 6.2 Noise connection spoofing 🟢

**Goal:** Mallory intercepts a hyperswarm connection between Jet A and Jet B
and injects false messages.

**Mechanism:** Mallory positions herself as a network-level MITM on the TCP/UDP
path between Jet A and Jet B.

**Outcome:** Fails. The hyperswarm connection is Noise-encrypted. A network-
level MITM can see that a connection exists but cannot read or inject messages
without the Noise session keys. The Noise handshake provides mutual
authentication — both endpoints must have the correct keypair. An injected
message would fail Noise decryption/authentication.

---

### 6.3 Challenge flood (DoS) 🟡

**Goal:** MalloryJet floods Drop2 with `Safe/drop/challenge` events, consuming
Drop2's CPU and IndexedDB read bandwidth.

**Mechanism:** MalloryJet sends hundreds or thousands of challenge events per
second to Drop2.

**Outcome:** Partial. Drop2's IndexedDB reads are relatively cheap for hit
CIDs. However, a high-volume flood is a genuine denial-of-service risk,
preventing Drop2 from serving legitimate requests.

**Defense:** The v1 challenge handler is a simple IndexedDB read + response.
Drops SHOULD rate-limit incoming challenge events per connected Jet:
`Q.Config.get(['Safe', 'drop', 'maxChallengeRatePerSec'], 5)`. Exceeding the
rate limit causes the Drop to return null and log the Jet as abusive.

---

### 6.4 BSC RPC provider manipulation 🟡

**Goal:** Mallory controls or compromises the BSC JSON-RPC endpoint that Jets
and Drops use for balance checks, serving manipulated balance responses.

**Mechanism:** Mallory DNS-hijacks the configured RPC URL, or operates the
configured node dishonestly, returning inflated balances for Mallory's
addresses.

**Outcome:** Partial. If Mallory controls the RPC endpoint, she can make
Drops believe her Jets have sufficient SafeBux balance even when they don't.
Drops serve her requests; claims later fail on the real chain.

**Defense:** Drops SHOULD use multiple independent RPC providers and require
consistent responses (quorum across N providers before trusting the result).
`Q.Config.get(['Safe', 'evm', 'providers', 'eip155:56'], [rpc1, rpc2, rpc3])`.
A single provider is a trusted third party; N providers with quorum reduces
that trust assumption.

---

### 6.5 Network partition exploitation 🟡

**Goal:** Mallory partitions the SafeCloud Jet network during a CoC gossip
event, ensuring that the CoC propagates to only part of the network. Half the
network slashes Alice; the other half doesn't — Alice operates in the un-slashed
partition.

**Mechanism:** Mallory operates network infrastructure between regions and
drops hyperswarm connections during CoC propagation.

**Outcome:** Partial. CoC propagation is eventually consistent, not immediate.
A partition delays but doesn't prevent propagation once connectivity is
restored. The slash itself happens on-chain at claim time — if Alice tries
to claim from the un-slashed partition, the CoC evidence can still be submitted
before her transaction is included (mempool observation + front-running the
slash).

**Defense:** The on-chain slash is the definitive action. Network-level partitions
can delay gossip but cannot prevent an honest participant with a valid CoC from
submitting it on-chain when Alice's claim transaction is visible in the mempool.

---

## 7. Economic and Game-Theory Attacks

---

### 7.1 Free-rider (serve without staking) 🟡

**Goal:** Alice operates a Drop with zero SafeBux stake, earns payment for
serving, and never builds stake — enjoying the network's benefits without
contributing collateral.

**Mechanism:** Alice connects to Jets, serves chunks, earns payment tokens,
claims them, immediately transfers unlocked SafeBux out of her address.

**Outcome:** Partial. The graduated lockup means Alice cannot instantly
liquidate earnings — a percentage is locked per period. Over time, as she
continuously operates, her locked balance accumulates to a meaningful stake
even without intentional staking. The routing weight formula
(`stakedSafebux × reliability × storage`) gives Alice lower weight than
staked Drops. She earns but earns less per request.

**Defense:** Routing weight penalizes unstaked Drops. The graduated lockup
passively accumulates stake from ongoing service. If `minStakeSafebux` is
set by operators, zero-stake Drops receive no routing at all — they can earn
nothing until they stake something first.

---

### 7.2 Jet margin squeeze (underpaying Drops) 🟡

**Goal:** MalloryJet earns SafeBux from Cloud at the standard rate but pays
Drops far below the market rate, maximizing its margin. Drops are economically
coerced because MalloryJet is the only Jet in the local network.

**Mechanism:** MalloryJet constructs payment tokens with `stm.max` set to
far below the standard `perChunkSafebux`. Drops check the balance pre-screen
but not the token's `max` value explicitly.

**Outcome:** Partial. The Drop receives and stores the payment token, then
attempts to claim. The claim succeeds but for a reduced amount. The Drop's
total earnings are lower than expected. If all available Jets underpay, Drops
have limited recourse.

**Defense:** Drops SHOULD verify `stm.max >= minPerChunkSafebux ×
requestedChunkCount` before serving and return null for tokens that undervalue
the service. This is analogous to the balance check — a pre-serve value check.

**Market defense:** If MalloryJet consistently underpays, Drops will
preferentially connect to other Jets. In a competitive market, Drops have
the option to disconnect from underpricing Jets and wait for better-paying
connections. The Drop's right to simply stop serving is the fundamental market
defense.

---

### 7.3 Jet cartel (collude to exclude Drops) 🟡

**Goal:** All Jets in the network agree to only route through Drops that pay
a "routing fee" back to Jets (a kickback scheme). Honest Drops that refuse
are excluded.

**Mechanism:** Jets gossip over hyperswarm that Drops who pay kickbacks receive
higher routing priority, enforcing this norm among themselves.

**Outcome:** Partial. This is a coordination problem, not a protocol attack.
Jets individually have no protocol-level mechanism to collude — routing weight
computation is local and unverifiable by peers. A Jet that devotes some
routing weight to honest Drops will outperform cartel Jets by having more
reliable storage. New Jets can enter the market and offer fair prices to
Drops, attracting inventory.

**Defense:** Protocol competition. Honest Jets that fairly pay Drops attract
more Drops, serve more content, and earn more from Cloud clients. The cartel's
advantage is self-limiting.

---

### 7.4 Graduated lockup gaming 🟡

**Goal:** Mallory earns SafeBux honestly for a period, building a large locked
stake. She then immediately starts behaving corruptly (false announces, etc.),
knowing it will take time for a CoC to be filed and her stake to be slashed.
She races to unlock and transfer as much as possible before the slash.

**Mechanism:** Mallory accumulates locked SafeBux. At time T, she turns
corrupt. The lockup rate is, say, 10%/day. She can unlock 10% per day for
the next N days before a CoC catches up with her.

**Outcome:** Partial. The race between CoC filing and lockup expiration
determines how much Mallory escapes with. The faster the network detects and
gossips a CoC, the less Mallory can extract.

**Mitigation:** Fast CoC propagation (7-hop flood gossip) minimizes the window.
Honest Jets that have already accumulated evidence (failed serves, inconsistent
announces) should file CoCs promptly rather than waiting.

**Design note:** The graduated lockup is designed to prevent instant liquidation
— even with 10%/day, Mallory cannot escape with more than the unlocked portion
at any given time. The locked portion remains slashable regardless of Mallory's
transfer attempts (locked tokens cannot be transferred).

---

### 7.5 Stake concentration and routing monopoly 🟡

**Goal:** A well-funded actor (Mallory or an institution) accumulates massive
SafeBux stake across many Drops, capturing the majority of routing weight and
effectively controlling content availability and prices.

**Mechanism:** Mallory buys a dominant fraction of the SafeBux supply and
distributes it across her Drop infrastructure.

**Outcome:** Partial. This is a resource-intensive attack with no protocol
exploits — Mallory must hold real economic value. If Mallory's Drops serve
honestly, she earns proportionally and the network is fine (high-stake Drops
are desirable). If she uses her routing dominance to censor content or
overcharge, alternative Jets can route around her Drops, and new low-cost
Drops from other operators compete.

**Systemic concern:** SafeBux supply concentration is a tokenomics concern,
not a protocol attack. The protocol itself is neutral — high-stake actors who
serve honestly are beneficial; the same actors who serve dishonestly face
CoC and slash. The market and tokenomics design need to address distribution.

---

### 7.6 SafeBux price manipulation 🟡

**Goal:** Mallory manipulates the SafeBux token price on exchanges to harm
the economics of honest participants.

**Mechanism:** Large buy/sell orders to crash SafeBux price, making stored
chunks economically worthless for honest Drops, or inflating price to make
Cloud payments prohibitively expensive.

**Outcome:** This is a tokenomics/market attack, not a protocol attack. The
protocol is denominated in SafeBux wei — the absolute number of tokens doesn't
change. What changes is the USD value of participants' stakes and earnings.

**Defense:** Off-protocol. Tokenomics design, exchange listing policies, and
protocol fee adjustments are the appropriate mitigations. The protocol spec
cannot address market manipulation.

---

## 8. Cryptographic Edge Cases

---

### 8.1 CID collision 🟢

**Goal:** Mallory crafts two different `(ciphertext, tag)` payloads that
produce the same CID, allowing her to substitute one for the other.

**Mechanism:** Find `(c1, t1) ≠ (c2, t2)` such that
`SHA-256(c1 || t1) == SHA-256(c2 || t2)`.

**Outcome:** Computationally infeasible. Finding a SHA-256 collision requires
approximately `2^128` operations (birthday bound). This is not a practical
attack.

---

### 8.2 P-256 weak nonce (ECDSA signing) 🟢

**Goal:** Extract the P-256 session private key by exploiting weak or reused
nonces in ECDSA signing.

**Mechanism:** If the Drop signs two messages with the same ECDSA nonce k,
the private key can be computed from the two signatures. This is a well-known
ECDSA vulnerability.

**Outcome:** Fails with correct implementation. The Web Crypto API
(`SubtleCrypto.sign`) generates cryptographically secure random nonces
internally. The application does not control the nonce. Reuse is not possible
through the standard API.

**Residual concern:** If Mallory controls the OS random number generator (via
a system compromise), she could potentially predict nonces. This is a system-
level attack, not a protocol attack.

---

### 8.3 EIP-712 cross-domain replay 🟢

**Goal:** Mallory captures a valid EIP-712 signature from one context
(e.g. signing a payment token on the SafeCloud test network) and replays it
on the mainnet.

**Mechanism:** Payment token signed with `chainId = eip155:97` (BSC testnet)
is submitted to the BSC mainnet contract.

**Outcome:** Fails. The EIP-712 domain separator includes `chainId`. A
signature valid for `eip155:97` does not verify for `eip155:56`. The on-chain
contract's `paymentsDomainSeparator()` uses `block.chainid` which is fixed
per deployment.

---

### 8.4 Prolly tree node store collision 🟢

**Goal:** Two different CID sets produce the same Prolly tree root, allowing
a Drop to claim a different inventory than it holds.

**Mechanism:** Find two CID sets S1 ≠ S2 such that `ProllyTree(S1) ==
ProllyTree(S2)`.

**Outcome:** Computationally infeasible. Prolly tree nodes are SHA-256
hashes of their contents. A root collision requires a SHA-256 preimage attack.
Not practical.

---

### 8.5 Canonical JSON ambiguity in OCP signatures 🟡

**Goal:** Mallory exploits ambiguity in the canonical JSON serialization
(RFC 8785 / JCS) to produce two representations of the same OCP claim that
have different byte sequences, one of which validates and one of which doesn't.

**Mechanism:** Unicode normalization, floating-point representation, or
whitespace variations in JSON create two serializations with different hashes.
Mallory signs one and presents the other.

**Outcome:** Requires implementation errors. If all participants use the same
JCS library with correct implementation, this does not occur. The risk is in
hand-rolled canonicalization that doesn't fully implement RFC 8785.

**Defense:** All OCP signing and verification MUST use the same
`Q.canonicalJSON()` function (RFC 8785 compliant, recursively sorted keys,
no whitespace, standard Unicode). Tests MUST cover known edge cases:
Unicode characters, large integers, null values, nested objects.

---

## 9. Trusted Environment Attacks

---

### 9.1 Supply chain attack on the SafeBox AMI 🔴

**Goal:** Mallory compromises the build pipeline that produces the SafeBox AMI
and injects malicious code into the JS bundle. The Nitro attestation is still
valid (it attests the compromised AMI), but the JS is malicious.

**Mechanism:** Mallory gains write access to the build repository or CI/CD
pipeline, injects JS that exfiltrates session keys or signs fraudulent claims.
The AMI hash in the attestation matches the compromised build.

**Outcome:** Succeeds if the compromise is undetected. The Nitro attestation
is valid (it correctly attests the running code — the problem is the code
itself is compromised). Users verifying the attestation find it valid. All
signing done by Drops using that compromised environment is attacker-controlled.

**Defense:** The deterministic reproducible build pipeline means any third
party can rebuild the AMI from source and compare hashes. If the repository
is public and the build is reproducible, the compromised build would produce
a different hash from independent builds, alerting auditors. M-of-N auditor
key model: the bundle hash must be co-signed by N independent auditors before
the protocol trusts it.

**This is the highest-risk attack in the system.** It requires compromising
the build infrastructure, but if successful, it undermines the entire trusted
environment assumption. The mitigation is operational security of the build
pipeline and reproducible builds with independent verification.

---

### 9.2 Rogue SafeBox operator 🔴

**Goal:** The SafeBox operator themselves acts maliciously — signing attestation
claims for malicious bundles they control, or selectively de-attesting honest
participants.

**Mechanism:** The SafeBox operator is a trusted third party. If they are
compromised or go rogue, they can sign attestations for any JS bundle,
including malicious ones.

**Outcome:** Succeeds if the operator is the sole trusted attestor. All
attestation trust flows through the operator's key.

**Defense:** M-of-N auditor model. The bundle hash must be co-signed by M
of N independent auditors, not just the SafeBox operator. Any participant
can become an auditor by staking SafeBux and signing bundles they have
independently verified. The set of trusted auditors is configured by each
Jet operator independently. No single rogue auditor can endorse a malicious
bundle if the threshold is > 1.

**This is a governance/trust design question** that must be resolved before
mainnet. The v1 spec correctly identifies SafeBox attestation as a
requirement; the M-of-N auditor model is the production-grade solution.

---

### 9.3 Browser side-channel on non-extractable keys 🟡

**Goal:** Mallory uses a browser side-channel (timing attack, Spectre/Meltdown,
or similar) to extract non-extractable CryptoKey material from the Drop's
browser session.

**Mechanism:** Non-extractable `CryptoKey` objects prevent direct memory
reads via JavaScript. However, CPU speculation attacks (Spectre) may allow
reading memory that should be inaccessible to JavaScript.

**Outcome:** Theoretically possible in unpatched browsers. Modern browsers
have mitigated Spectre-class attacks with site isolation, reduced timer
resolution, and cross-origin isolation headers. A SafeBox-served application
with correct security headers (`Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Embedder-Policy: require-corp`) prevents the shared memory
access that Spectre exploits.

**Defense:** Correct security headers on the SafeBox-served application.
Browser patches for Spectre mitigations. These are standard web security
practices, not SafeCloud-specific.

---

## 10. Cross-Cutting Observations

---

### 10.1 The protocol's fundamental security model

The SafeCloud security model rests on three independent assumptions:

1. **Cryptographic:** SHA-256, P-256 ECDSA, secp256k1 ECDSA, and AES-256-GCM
   are computationally secure against the attacker. This is a standard
   assumption shared by all practical cryptographic systems.

2. **Economic:** Every participant with stake has more to lose from dishonesty
   than to gain. Stake creates skin in the game; graduated lockup ensures
   residual collateral exists even after earnings. This holds as long as the
   cost of misbehavior (slashable stake) exceeds the gain. For well-staked
   participants, the protocol is strongly incentive-compatible.

3. **Environmental:** Drops run in SafeBox-attested environments. Without
   this, the non-extractable key guarantee is the only protection against
   rogue JS — which is insufficient (see attack 1.3). This is the protocol's
   most fragile assumption in v1 and the most important to harden.

---

### 10.2 What the protocol handles well

- **Identity theft is essentially impossible.** EIP-712 wallet signatures,
  non-extractable session keys, and Noise-encrypted peer connections combine
  to make impersonation require possession of private key material that never
  leaves the owner's device.

- **Storage fraud is detectable and slashable.** The append-only diff log
  combined with random spot-checks creates a self-tightening accountability
  mechanism. Dishonest Drops are not instantly detected, but their stake is
  at risk from the moment they start lying.

- **Payment exploits are bounded.** No payment token can be redirected to a
  different recipient (recipientsHash), and no token can exceed its stated
  ceiling (spent tracking). The only timing risk is the balance drain window,
  which is partially mitigated by frequent claiming and safety margins.

- **CoC forgery is impossible without key compromise.** Manufactured evidence
  requires forging ECDSA signatures. The deposit requirement bounds spam.

- **The marketplace is adversarially stable.** Every participant's best
  rational strategy is honest service: it maximizes earnings, builds stake,
  and avoids slash. Defection is costly and eventually detected.

---

### 10.3 What requires operational care

| Risk | Required Action |
|------|----------------|
| Supply chain (9.1) | Reproducible builds + M-of-N auditor co-signing |
| Rogue SafeBox operator (9.2) | M-of-N auditor model for attestation |
| Balance drain race (3.1) | Safety margin check + frequent claiming |
| LRU flood (2.1) | Rate-limit `put` per Drop; announce-before-evict |
| BSC RPC manipulation (6.4) | Multi-provider quorum for balance checks |
| Canonical JSON (8.5) | Single shared JCS implementation, tested edge cases |

---

### 10.4 Attacks that are not attacks (intentional design)

- **Drop strategic partial storage (storing only popular chunks):** This is
  rational market behavior. The protocol does not require Drops to store all
  content indiscriminately. Drops optimize their storage portfolio for earnings.

- **Jet routing preference for high-stake Drops:** This is the intended
  incentive mechanism. High-stake Drops earn more because they have more to
  lose — they are more trustworthy counterparties.

- **Cloud clients using application-server-side payment signing:** Legitimate
  design pattern (SaaS paying on behalf of users). The protocol is intentionally
  agnostic about who signs payment tokens.

- **Drops claiming frequently to reduce exposure:** Rational economic
  behavior that also improves protocol security. Frequent claiming should
  be documented as a best practice.

- **Jets routing around underperforming peers:** Intended protocol behavior.
  The market routes around failure.
