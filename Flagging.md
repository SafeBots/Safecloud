# Safecloud — Content Flagging and Reputation

This document specifies how Safecloud provides responsible content scanning without breaking end-to-end encryption. The design covers two layers: the storage/distribution layer (client-side classifiers injected by Jets, proof-of-scan requirements for content relay, passive scanning of stored content, and a reputation system that limits distribution of flagged material) and the E2E chat layer (client-side scanning of message plaintext, per-message key escrow under threshold ElGamal, and proof-of-escrow requirements for media messages).

Read `Protocol.md`, `Trading.md`, and `EpochProtocol.md` before this document. The flagging layer does not modify the encryption or routing protocol. For the storage/distribution layer, it adds a pre-encryption scanning step on the client (Drop) and a reputation signal that affects content distribution across the network. For E2E chat, it adds client-side scanning, per-message key escrow under threshold encryption, and proof-of-escrow enforcement at the Jet (see also `Ecosystem.md` §Content safety in E2E chat and `Apps.md` §Rooms and E2E encrypted chat). See also [AdaptiveStreamer.md](AdaptiveStreamer.md) (adaptive drop selection, serving policy, micropayment ramping).

**Notation:** Drop = storage/messaging client. Jet = routing node. Classifier = AI model or hash-matching function distributed by Jets to Drops. Flag = a classifier's assertion that content matches known-bad material. Reputation = a per-pubkey score that determines content distribution priority.

---

## Table of Contents

- [Design goals](#design-goals)
- [Architecture overview](#architecture-overview)
- [Classifier models](#classifier-models)
  - [Available scanning tools](#available-scanning-tools)
  - [Model distribution](#model-distribution)
  - [Model size and bandwidth](#model-size-and-bandwidth)
- [Pre-encryption scanning](#pre-encryption-scanning)
  - [Proof-of-scan](#proof-of-scan)
  - [What the Jet verifies](#what-the-jet-verifies)
- [Passive storage scanning](#passive-storage-scanning)
  - [Random frame sampling](#random-frame-sampling)
  - [Retrospective scanning](#retrospective-scanning)
- [Flagging protocol](#flagging-protocol)
  - [Flag structure](#flag-structure)
  - [Corroboration](#corroboration)
  - [Verification by random jury](#verification-by-random-jury)
- [Reputation system](#reputation-system)
  - [Reputation accrual](#reputation-accrual)
  - [Reputation-gated distribution](#reputation-gated-distribution)
  - [Shadowban gradient](#shadowban-gradient)
- [Anti-griefing](#anti-griefing)
  - [Sybil flag attack](#sybil-flag-attack)
  - [Deterministic verification](#deterministic-verification)
  - [Stake-based flagging](#stake-based-flagging)
  - [Flag weight by Drop reputation](#flag-weight-by-drop-reputation)
- [Chilling effects](#chilling-effects)
  - [Routing uncertainty](#routing-uncertainty)
  - [Reputation as reach limiter](#reputation-as-reach-limiter)
- [The fork defense](#the-fork-defense)
- [Scope expansion resistance](#scope-expansion-resistance)
  - [The lever problem](#the-lever-problem)
  - [Why this lever is weak](#why-this-lever-is-weak)
  - [Classifier CID pinned per release](#classifier-cid-pinned-per-release)
- [E2E chat content safety](#e2e-chat-content-safety)
  - [Why chat is different](#why-chat-is-different)
  - [Client-side scanning for chat](#client-side-scanning-for-chat)
  - [Per-message key escrow](#per-message-key-escrow)
  - [Threshold ElGamal decryption](#threshold-elgamal-decryption)
  - [Proof of escrow for media](#proof-of-escrow-for-media)
  - [Garbage escrow detection](#garbage-escrow-detection)
  - [Consent and opt-in structure](#consent-and-opt-in-structure)
  - [Honest gaps](#honest-gaps)
  - [Interaction with the reputation system](#interaction-with-the-reputation-system)
- [Attack vectors](#attack-vectors)
- [Legal interaction with Trading.md](#legal-interaction-with-tradingmd)

---

## Design goals

1. **Scan before encryption, not after.** The classifier runs on the Drop, on plaintext, before the content is encrypted and submitted to the network. The Jet never decrypts anything. End-to-end encryption is preserved on the wire.

2. **Deterministic and auditable.** The classifier models are open-source, distributed as content-addressed chunks, and produce deterministic output. Given the same content and the same model, any node produces the same result. This enables independent verification of flags.

3. **Reputation, not censorship.** Flagged content is not deleted or blocked. The uploader's pseudonymous reputation degrades, which reduces the distribution of their content across the network. The content technically remains at its CID — it just stops being replicated, served quickly, or prioritized.

4. **Anti-griefing by design.** False flags are detected through random jury verification. Sybil flag attacks fail because the classifier output is deterministic — a modified classifier produces a different result hash, and the jury catches it.

5. **Chilling effects over perfect detection.** The system does not aim to catch every bad actor. It aims to create sufficient uncertainty that uploading harmful content to this network is risky. The uploader doesn't know which Drops will scan their content, when, or whether a flag will surface. The threat of detection is continuous.

6. **The fork is the fork's problem.** Anyone can fork the open-source Jet software and remove the proof-of-scan requirement. That fork is a separate network. The reference implementation includes scanning. Deliberate removal of safety features is evidence of intent — the forker's, not the protocol developer's.

---

## Architecture overview

```
Content lifecycle with flagging:

  Author                   Drop (client)              Jet               Network
  ──────                   ────────────               ───               ───────
  creates content    →     classifier scans           
                           plaintext before     →     Jet checks         
                           encryption                 proof-of-scan  →  content distributed
                                                                        based on uploader
                                                                        reputation

                           passively samples
                           stored chunks       →     flags submitted →  corroboration +
                           over time                                    jury verification →
                                                                        reputation update
```

The classifier runs on the Drop as privileged code — it has access to plaintext before encryption and to stored chunks that the Drop is serving. The Jet distributes the classifier model and verifies that the Drop ran it (proof-of-scan). The network propagates flags and adjusts reputation scores through corroboration and jury verification.

---

## Classifier models

### Available scanning tools

The reference implementation uses existing, maintained scanning tools. No custom training is required.

**Hash matching (known material):**

| Tool | Source | What it does | License |
|------|--------|--------------|---------|
| PDQ | [Meta ThreatExchange](https://github.com/facebook/ThreatExchange/tree/main/pdq) | Perceptual image hashing — matches near-duplicates even after cropping, recoloring, compression. 256-bit hash per image. | BSD |
| VPDQ | [Meta ThreatExchange](https://github.com/facebook/ThreatExchange/tree/main/vpdq) | PDQ extended to video — produces a sequence of frame hashes for visual similarity matching across video content. | BSD |
| TMK+PDQF | [Meta ThreatExchange](https://github.com/facebook/ThreatExchange/tree/main/tmk) | Temporal matching for video — matches video clips even when re-encoded, trimmed, or watermarked. | BSD |
| Perception | [Thorn](https://github.com/thorn-oss/perception) | Python wrapper around PDQ, pHash, dHash, and other perceptual hash algorithms. Provides a unified API for computing and comparing hashes. | Apache 2.0 |
| Hasher-Matcher-Actioner (HMA) | [Meta](https://github.com/facebook/ThreatExchange/tree/main/hasher-matcher-actioner) | Complete pipeline: hash content, match against databases, trigger actions. Designed for integration with NCMEC and GIFCT hash lists. | BSD |
| GIFCT hash database | [GIFCT](https://gifct.org) | Shared database of hashes of known terrorist and violent extremist content. Accessed through GIFCT membership and the Hash-Sharing Database API. | Membership required |
| NCMEC hash lists | [NCMEC](https://www.missingkids.org) via [Technology Coalition](https://technologycoalition.org) | Canonical database of known CSAM hashes (PhotoDNA and PDQ formats). Access requires application through the Technology Coalition. | Application required |

Hash matching against known material has near-zero false positives. The content either matches a known hash or it doesn't. This is the mandatory, high-confidence component of the scanning pipeline. The PDQ, VPDQ, TMK, Perception, and HMA components are fully open source and can be compiled into the Drop binary. The hash databases (GIFCT, NCMEC) require membership agreements — the protocol developer applies once and distributes the hash lists as part of the classifier bundle.

**Classifiers (novel content):**

| Tool | Source | What it does | Size |
|------|--------|--------------|------|
| NSFWjs | [infinitered/nsfwjs](https://github.com/infinitered/nsfwjs) | NSFW image classification into 5 categories (Drawing, Hentai, Neutral, Porn, Sexy). TensorFlow.js, runs in browser or Node. MobileNet v2 backbone. | ~3 MB (quantized) |
| Detoxify | [unitaryai/detoxify](https://github.com/unitaryai/detoxify) | Text toxicity detection — toxic, severe toxic, obscene, threat, insult, identity attack. Based on BERT/RoBERTa fine-tuned on Jigsaw datasets. Ships three model sizes. | 420 MB (original), 1.3 GB (unbiased), ~500 MB (multilingual) |
| Altitude | [Jigsaw](https://github.com/jigsaw-code/altitude) | Web-based triage tool for terrorist/extremist content. Integrates directly with the GIFCT Hash-Sharing Database and Terrorist Content Analytics Platform. Docker-based. | Server-side (not bundled) |
| Perspective API | [Jigsaw/Google](https://github.com/conversationai/perspectiveapi) | Scores text for toxicity, threat, insult, profanity, identity attack. Production API, not a downloadable model — useful as a reference but requires network access. | API only |
| Hate speech classifiers | Various on [Hugging Face](https://huggingface.co/models?search=hate+speech) | Fine-tuned BERT/DistilBERT models for hate speech and offensive language. Many are small enough to run on-device. | 65-250 MB |
| Intel Toxic Prompt RoBERTa | [Intel](https://huggingface.co/Intel/toxic-prompt-roberta) | RoBERTa-based model for detecting toxic and harmful text prompts. | ~480 MB |

For the Drop's classifier bundle, the practical choices are:

- **Must-have (hash matching):** PDQ + VPDQ + hash database. Pure algorithms with no ML inference cost. The hash functions are a few MB of compiled code; the hash database is 10-50 MB depending on NCMEC/GIFCT list size.
- **Must-have (image classification):** NSFWjs. Small, fast, runs in TensorFlow.js or can be compiled to WASM. 3 MB quantized model.
- **Should-have (text classification):** A distilled hate-speech/threat classifier. DistilBERT-based models from Hugging Face run at 65-130 MB and can be quantized to INT8 for ~30 MB. Detoxify's original model is 420 MB, which is large for a client bundle — a distilled or quantized variant is better for Drops.
- **Nice-to-have (server-side):** Altitude for Jet-side triage when flags accumulate, connecting to GIFCT's hash-sharing API. This runs at the Jet, not the Drop.

Classifiers for novel content have higher false-positive rates than hash matching. They are used as a secondary signal — a classifier flag alone does not trigger reputation consequences. It contributes to a score that, combined with hash matches or corroboration from multiple independent Drops, may trigger consequences.

### Model distribution

Classifier models are distributed as regular Safecloud content — content-addressed chunks fetched by CID. The Jet pins the current model CID and announces it to Drops during registration. The Drop fetches the model chunks like any other content.

```
Jet → Drop (during registration):
  Safecloud/drop/register response {
    ...existing fields...
    classifierCID: "bafy...",     // CID of current classifier model bundle
    classifierVersion: "1.2.0",  // semantic version for compatibility
    hashDatabaseCID: "bafy...",  // CID of current hash database
    hashDatabaseVersion: "2024-10-15"
  }
```

Model updates are new CIDs. The Jet announces updated CIDs; the Drop fetches them on its normal sync cycle. No special update mechanism — just new content on the existing CDN.

The model bundle is a single content-addressed archive containing:
- The PDQ hash function (~1 MB)
- The current hash database (10-50 MB, depending on NCMEC/GIFCT list size)
- The NSFW classifier (~3 MB)
- Optional: text classifier, age estimator
- A manifest listing the components and their versions

Total bundle size: **20-70 MB** depending on which optional components are included and the current hash database size.

### Model size and bandwidth

For context on whether the model download is significant:

- A single 1080p video chunk: 2-8 MB
- A typical video served by a Drop: 500 MB - 2 GB
- A Drop's daily bandwidth for content serving: 1-50 GB
- The classifier model bundle: 20-70 MB (one-time download, updated incrementally)

The model download is equivalent to a few video chunks. For a Drop that serves gigabytes of content daily, it's noise. The download is indistinguishable from any other content fetch — it's a set of CIDs retrieved from the network, the same as fetching a video or a document.

Hash database updates are incremental — new hashes appended, published as a diff CID. A daily update is typically kilobytes.

---

## Pre-encryption scanning

### Proof-of-scan

Before encrypting and submitting content (a message, a file, a chunk), the Drop runs the classifier on the plaintext content. The classifier produces a deterministic result: a scan report containing the content hash, the classifier version, the result (clean/flagged + classification details), and a signature.

```
ScanReport {
  contentHash:      SHA-256 of the plaintext content
  classifierCID:    CID of the classifier model used
  result:           "clean" | "flagged"
  classifications:  [{ type: "pdq_match", hash: "...", confidence: 1.0 }, ...]
  timestamp:        unix timestamp
  dropSignature:    Drop's signature over the above fields
}
```

The Drop includes the `ScanReport` (or a compact hash of it) in the message envelope or chunk upload. The Jet verifies that:

1. The `classifierCID` matches the current (or recent) model version
2. The `dropSignature` is valid for the Drop's registered pubkey
3. The report exists (the Drop didn't skip scanning)

The Jet does **not** verify the scan result itself — it can't, because it doesn't have the plaintext. It verifies that the Drop claims to have scanned. The actual verification happens through the corroboration and jury mechanism described below.

### What the Jet verifies

The proof-of-scan is a claim, not a guarantee. The Drop controls its own execution environment and could forge a "clean" report for any content. The Jet's verification is a lightweight check that keeps honest Drops honest and creates a paper trail for dishonest ones.

The real enforcement comes from three other mechanisms:

1. **Passive storage scanning** — other Drops that store the same content will independently scan it and flag discrepancies
2. **Jury verification** — when flags accumulate, randomly selected Drops re-scan and verify
3. **Reputation consequences** — a Drop that consistently produces "clean" reports for content that other Drops flag loses reputation as a scanner, which affects its standing on the network

This is defense in depth. No single mechanism is airtight. Together, they make systematic evasion expensive and detectable.

---

## Passive storage scanning

### Random frame sampling

Drops are already storing and serving content — video chunks, images, documents. The classifier runs passively in the background, sampling stored content at random intervals.

For video content, the Drop decodes a random still frame from a random stored chunk and runs the hash matcher and NSFW classifier on it. For images, it runs directly on the stored image. For text content (messages stored as chunks), it runs the text classifier.

The sampling rate is configurable (default: one sample per minute while the Drop is online). At this rate, a Drop storing 10,000 chunks samples each chunk roughly once per week. Content stored for months gets sampled many times.

The sampling is invisible to the content uploader. They don't know when their content will be sampled, which Drop will sample it, or whether the sample will hit a frame that triggers a match. The uncertainty is the deterrent.

### Retrospective scanning

When the hash database is updated (new known-bad hashes added), previously clean content may now match. The Drop's passive scanning will eventually hit the newly-flagged content during its random sampling cycle.

This means the scanning is not just a one-time ingress check. It's continuous and improves over time as hash databases grow. Content uploaded before a particular hash was identified can still be flagged weeks or months later.

The retrospective property is important for CSAM, where new material is constantly being identified and added to hash databases. A Drop that stored clean-looking content last month may discover it matches a hash that was added yesterday.

---

## Flagging protocol

### Flag structure

When a classifier flags content, the Drop submits a flag to its Jet:

```
Flag {
  cid:              content-addressed ID of the flagged content
  classifierCID:    CID of the classifier model used
  resultHash:       deterministic hash of the classifier's full output
  classification:   "pdq_match" | "nsfw_high" | "text_extremism" | ...
  confidence:       0.0 - 1.0
  dropPubkey:       the flagging Drop's public key
  dropSignature:    signature over the above fields
  stake:            Safebux amount staked on this flag (see anti-griefing)
}
```

The `resultHash` is the critical field for anti-griefing. Because the classifier is deterministic, any Drop running the same classifier on the same content must produce the same `resultHash`. A Drop that modifies the classifier or fabricates a flag will produce a different hash — detectable by the jury.

### Corroboration

A single flag does not trigger reputation consequences. The Jet tracks flags per CID and waits for corroboration:

- **PDQ hash match (confidence 1.0):** Requires corroboration from 2 additional independent Drops (3 total). PDQ has near-zero false positives, so a low threshold is safe.
- **NSFW classifier (confidence > 0.9):** Requires corroboration from 4 additional independent Drops (5 total). Higher threshold because classifiers have higher false-positive rates.
- **Text classifier:** Requires corroboration from 4 additional independent Drops. Same rationale.
- **Mixed signals (some Drops flag, others don't):** Triggers jury verification (see below).

"Independent" means: different Drop pubkeys, registered at different times, with independent reputation histories. The Jet checks for Sybil patterns (correlated registration times, identical IP ranges, always-correlated flag patterns).

### Verification by random jury

When flags on a CID reach the corroboration threshold — or when flags are contradicted by other Drops that scanned the same content without flagging — the Jet triggers a jury verification.

The Jet selects N Drops (default: 7) at random from the set of established Drops (minimum reputation threshold, minimum age on the network) that store or can fetch the flagged CID. These Drops are the jury.

```
Jet → Jury Drop:
  Safecloud/flag/verify {
    cid: "...",
    classifierCID: "bafy...",
    deadline: timestamp
  }

Jury Drop → Jet:
  Safecloud/flag/verdict {
    cid: "...",
    resultHash: "...",          // deterministic classifier output
    classification: "clean" | "pdq_match" | ...,
    dropSignature: "..."
  }
```

The Jet collects verdicts and applies majority rule:

- **Majority confirms flag:** The flag stands. Reputation consequences apply to the content uploader. The flagging Drops get their stakes returned.
- **Majority contradicts flag:** The flag is false. The flagging Drops lose their stakes. The flagging Drops' scanner-reputation decreases (distinct from content-reputation — this tracks reliability as a scanner).
- **Split verdict:** Inconclusive. No reputation consequences for anyone. The CID is marked for future re-verification when more Drops have sampled it.

The jury mechanism ensures that a single malicious Drop (or a cluster of Sybil Drops) cannot grief legitimate uploaders. The griefer's modified classifier produces a different `resultHash` than the jury's standard classifiers, and the discrepancy is caught immediately.

---

## Reputation system

### Reputation accrual

Every pseudonymous identity (pubkey) on the network has a reputation score. Reputation starts at a baseline (not zero — new users can participate, just with limited reach) and changes based on network behavior:

**Increases reputation:**
- Storing and reliably serving content over time (the Drop's primary economic function)
- Earning Safebux through micropayments for storage and bandwidth
- Accurate flagging (flags corroborated by jury)
- Serving on juries (participating in verification)

**Decreases reputation:**
- Content flagged and corroborated by jury
- False flags submitted (contradicted by jury — attacker loses stake and reputation)
- Unreliable serving (content unavailable when requested, high error rate)

Reputation accrues slowly and degrades quickly for flagged content. Building reputation requires sustained legitimate participation — weeks or months of storing and serving. Losing reputation from flagged content is fast — a single corroborated CSAM flag can drop reputation to near-zero.

### Reputation-gated distribution

Reputation directly maps to content distribution across the network:

| Reputation tier | Replication | Serving priority | Reach |
|----------------|-------------|-----------------|-------|
| High (established, clean history) | Content replicated to many Drops for redundancy | Served quickly, prioritized in Jet routing | Full network reach |
| Medium (new user, or minor flag history) | Content replicated to fewer Drops | Normal serving priority | Moderate reach |
| Low (flagged content, degraded trust) | Content stored only on original Drops, not replicated | Low priority, slow serving | Minimal reach |
| Near-zero (corroborated CSAM/terrorism flag) | Existing replicas deprioritized and eventually pruned | Actively deprioritized | Effectively zero |

The mapping from reputation to distribution is continuous, not stepped. The tiers above are illustrative. In practice, reputation is a floating-point score and distribution parameters are smooth functions of that score.

### Shadowban gradient

Reputation consequences are not communicated to the user. There is no "your content has been flagged" notification, no "your reputation is low" warning, no "you have been banned" message.

The user's experience degrades gradually and silently:
- Content uploads still succeed (the Drop accepts them)
- But fewer other Drops replicate the content
- Content serves more slowly
- Fewer people see it (because fewer Drops serve it, and Jets deprioritize routing)
- The user may perceive the network as "slow" or "unreliable" for their content specifically

This is the honeypot property. A bad actor uploading harmful content believes it's being distributed. It isn't. They continue uploading, accumulating more evidence, while their reach shrinks to near-zero. They don't know to switch identities because nothing explicitly tells them they've been caught.

If they do eventually notice the degradation and create a new identity, the new identity starts at baseline reputation — low reach, limited distribution. They need to build reputation through legitimate participation before they can reach anyone again.

---

## Anti-griefing

### Sybil flag attack

**Attack:** Eve spins up 50 Drops with modified classifiers that flag everything. She targets Alice's content. The corroboration threshold is met because 50 Drops all flag the same CID.

**Defense:** The classifier is deterministic. Eve's modified classifier produces a different `resultHash` than the standard classifier. When the jury verifies, the jury's standard classifiers produce the correct `resultHash`. Eve's 50 Drops all produced a different hash — they're clearly running non-standard code.

Result: Eve's 50 Drops lose their stakes, lose reputation, and are marked as unreliable scanners. Alice's content is unaffected.

### Deterministic verification

The core anti-griefing property: given the same input and the same classifier, every honest node produces the same output. This is verifiable because:

1. The classifier model is content-addressed (CID). Any modification changes the CID.
2. The classifier output includes a `resultHash` — a hash of the full output. Any modification to the classifier logic changes the `resultHash`.
3. The jury runs the standard classifier (identified by the correct CID) and compares `resultHash` values. Mismatches identify dishonest nodes.

This is possible because the classifiers used (PDQ hash matching, pre-trained neural networks) are deterministic functions. The same image through the same PDQ implementation produces the same hash. The same image through the same NSFW classifier produces the same confidence score (within floating-point precision, handled by rounding to a fixed number of decimal places before hashing).

### Stake-based flagging

A Drop that submits a flag stakes a small amount of Safebux (configurable, default: the cost of a few hours of storage). This stake is:

- **Returned** if the flag is corroborated by the jury (the Drop was right)
- **Returned with a small reward** if the flag leads to a reputation consequence for the uploader (the Drop performed a public service)
- **Forfeit** if the flag is contradicted by the jury (the Drop was wrong or malicious)

The stake makes griefing expensive. Submitting 100 false flags costs 100 stakes. Each false flag is caught by the jury and the stake is lost. The griefer loses Safebux and reputation simultaneously.

The stake amount is calibrated to be trivial for a legitimate Drop that occasionally flags genuinely bad content (one or two stakes outstanding at a time) and expensive for a griefer attempting mass false flagging (hundreds of stakes at risk).

### Flag weight by Drop reputation

Not all flags are equal. A flag from a high-reputation Drop that has been on the network for months, with a history of accurate flags, carries more weight toward the corroboration threshold than a flag from a new Drop with no history.

Specifically, a flag contributes a `weight` toward corroboration:

```
weight = base_weight × reputation_multiplier × age_multiplier

where:
  base_weight = 1.0
  reputation_multiplier = min(drop_reputation / median_reputation, 3.0)
  age_multiplier = min(days_on_network / 30, 2.0)
```

A brand-new Drop with zero reputation contributes almost nothing to corroboration. A Drop that's been active for 6 months with high reputation contributes up to 6x a base weight. This means a griefer who spins up 50 new Drops gets 50 × ~0 = ~0 effective weight. They'd need to build reputation across all 50 Drops over months before their flags matter — and maintaining 50 legitimate Drops is expensive.

---

## Chilling effects

### Routing uncertainty

When a user uploads content to Safecloud, they don't choose which Drops store it. The network routes content to available Drops based on capacity, geography, and redundancy requirements. Some of those Drops run classifiers. The uploader doesn't know which ones.

Even if some Drops on the network have stripped the classifier (forked software), the uploader can't be sure their content won't land on a Drop that has it. The probability that at least one storing Drop runs a classifier increases with the number of replicas — and popular content has more replicas.

The uncertainty is the deterrent. A bad actor who uploads CSAM doesn't know whether:
- The Drop storing their content runs a classifier
- The classifier will sample the right frame
- When the sampling will happen (could be today, could be next week)
- Whether the content will be replicated to another Drop that runs a classifier

The optimal strategy for a risk-averse bad actor is: don't upload to this network. The optimal strategy for a risk-seeking bad actor is: upload and find out. The network handles the second case through flagging and reputation.

### Reputation as reach limiter

Reputation creates a natural barrier to viral distribution of harmful content. Even if harmful content slips through the initial scanning (the classifier misses it, or it's uploaded through a non-scanning Drop), its reach is bounded by the uploader's reputation.

A new anonymous identity starts at baseline reputation. It can store content, but the content won't be widely replicated. To reach thousands of people, the identity needs high reputation, which requires months of legitimate participation and Safebux earned through real economic contribution.

This means the worst case for a harmful upload is: the content exists at a CID, stored on a few Drops, accessible to people who specifically request it by CID. It doesn't "go viral." It doesn't get pushed to new users. It doesn't appear in any feed or recommendation. Its distribution is limited to people who already know the CID — which means the network isn't the discovery vector.

Compare to the status quo: on centralized platforms, harmful content can go viral in minutes before moderation catches it. On Safecloud, harmful content from a new identity has near-zero organic reach from the start.

---

## The fork defense

The protocol is open source. Anyone can fork the Jet software and remove the proof-of-scan requirement. This is by design and is the strongest argument in the protocol developer's legal defense.

When someone forks the Jet to remove scanning:

1. **They're operating a separate network.** Their forked Jet can peer only with other forked Jets (standard Jets reject connections from Drops without proof-of-scan). The forked network is isolated.

2. **The fork is affirmative action.** Removing the scanning requirement requires deliberate code modification. The commit diff is evidence of intent. The protocol developer can point to the safety feature and the forker's deliberate removal of it.

3. **The protocol developer's reference implementation includes scanning.** The published protocol spec mandates proof-of-scan. The reference Jet requires it. The reference Drop includes the classifier. Removing it is the forker's choice, not a gap in the protocol.

4. **The fork doesn't invalidate the protocol developer's position.** "Someone forked our protocol and removed safety features" is the same as "someone forked Linux and built malware with it." The existence of the fork does not create liability for the original developer.

This is the legal floor. The protocol developer has taken reasonable measures (built scanning into the reference implementation, required proof-of-scan in the protocol, distributed classifiers to Drops). Anyone who removes those measures has made a deliberate choice to operate unsafely. That choice is theirs.

---

## Scope expansion resistance

### The lever problem

Any scanning infrastructure is a potential lever for government-compelled scope expansion. If a government can say "update your classifier to also detect X," the same mechanism built to catch CSAM can be repurposed to catch political dissent, protest coordination, journalism, or anything else. This is the core objection to client-side scanning in the policy debate — not that scanning for CSAM is wrong, but that the scanning mechanism, once built, can be pointed at anything.

Safecloud's design makes this lever weaker than it would be in a centralized system. It does not eliminate the lever — no technical design can fully prevent legal compulsion — but it raises the cost of scope expansion to the point where it requires coordinated global action rather than a single court order.

### Why this lever is weak

**Jets are like Bitcoin miners.** Anyone can run a Jet. No registration, no license, no permission. If a government compels Jet operators in its jurisdiction to push an expanded classifier, users migrate to Jets in other jurisdictions. The Jet operator who complies loses Drops (and the Safebux revenue they generate) to competitors who don't. The same economic dynamic that prevents Bitcoin mining pools from adopting unpopular consensus rules prevents Jets from adopting unpopular classifiers.

**The classifier is open source and auditable.** The model is content-addressed and distributed as a CID. Anyone can download it, inspect it, and publish exactly what it scans for. A classifier that checks for political keywords alongside CSAM hashes is trivially detectable. Security researchers, journalists, and civil liberties organizations can audit any release. There is no "we added a feature but it's classified" — the model is the model, and its behavior is deterministic and reproducible.

**Drops choose their Jets.** A Drop that objects to its Jet's classifier can switch to another Jet. The Jet cannot force a Drop to run a particular model — it can only refuse to relay messages from Drops that don't run its model. So the worst a compromised Jet can do is lose its users. The Drop operator (or their automated policy) decides which classifier versions to accept.

**Collective refusal works.** To expand the scanning scope across the whole network, a government would need to compel every Jet operator globally — or at least every Jet operator in enough jurisdictions that users have nowhere else to go. This is the same coordination problem that makes global Bitcoin regulation hard. A single jurisdiction's order affects only the Jets in that jurisdiction. Users in other jurisdictions are unaffected. Users in the affected jurisdiction can use VPNs to reach Jets elsewhere.

### Classifier CID pinned per release

The classifier model CID is pinned in each software release, not pushed dynamically by a signing key. This is a deliberate design choice that limits the scope expansion lever.

With a signing key, whoever holds the key can sign any model at any time. The trust relationship is open-ended: "I trust this key to sign classifiers" means trusting every future decision by the key holder. If a government compels the key holder to sign an expanded model, every Drop that trusts the key automatically accepts the expansion.

With a CID pinned per release, the trust relationship is specific: "I trust this release, which includes this exact classifier." An expanded classifier requires a new release. Drop operators choose whether to upgrade, the same way Bitcoin node operators choose whether to adopt a new Bitcoin Core release. If a release ships a classifier that scans for political speech, operators don't upgrade. The network stays on the old release. The expanded scope fails to deploy because of collective refusal, not because of a technical lock.

This means the scope expansion attack path is: compel the protocol developer to ship a new release with an expanded classifier → hope that a majority of Jet and Drop operators upgrade to it → deal with the fact that the release is open source and everyone can see what was added. Each step is a public action that triggers scrutiny. Compare this to a signing-key model where expansion is silent and automatic.

The tradeoff is that legitimate classifier updates (new NCMEC hashes, improved CSAM detection) also require a new release and voluntary adoption. This is acceptable — hash database updates are incremental and delivered as data (new CIDs appended to the hash list), not code changes. The classifier code itself changes rarely. When it does, the update follows the same release cycle as any other open-source project: changelog, review, adoption.

---

## E2E chat content safety

The sections above describe flagging for content that passes through Jets during distribution — file uploads, video streams, static content stored on Drops. Jets can require proof-of-scan because they route the content and can enforce policy at the relay point.

Chat messages are different. The Jet routes ciphertext without decrypting it. The flagging infrastructure described above — passive storage scanning, corroboration, jury verification — does not apply to chat, because no Drop stores the plaintext and no Jet can inspect it. A separate mechanism is needed for E2E encrypted conversations, as specified in Ecosystem.md and implemented by the room handlers in Apps.md.

### Why chat is different

In the storage/distribution layer, content passes through multiple nodes. Any Drop storing a copy can scan it. Multiple independent Drops can corroborate a flag. The jury can re-scan and verify. This redundancy is the foundation of the reputation system's accuracy.

In E2E chat, the only nodes that see plaintext are the sender's client and the recipients' clients. The Jet sees only ciphertext. There are no independent Drops scanning the same plaintext. There is no jury that can re-verify a flag by running the classifier independently, because no jury member has the plaintext.

This means the chat content safety system cannot rely on the same corroboration and jury mechanisms. It uses a different approach: client-side scanning combined with per-message key escrow under threshold encryption.

### Client-side scanning for chat

The standard Safecloud client runs the same classifier infrastructure (PDQ, NSFW, text classifiers) on chat messages. The scan runs at two points:

1. **Before encryption on the sender's device.** The classifier processes the plaintext message or media before the client encrypts it with the per-message key `K_msg` derived from the epoch's forward and backward chains (see EpochProtocol.md).

2. **After decryption on the recipient's device.** The classifier processes the decrypted content. This catches content that evaded the sender's scan (if the sender used a modified client) and provides a second independent classification.

The classifier models are the same ones described in the [Classifier models](#classifier-models) section — PDQ hash matching, NSFWjs for images, text toxicity classifiers. The client fetches them by CID the same way a Drop does.

A modified client can skip the scan entirely. The system handles this through the escrow mechanism rather than trying to enforce scanning on uncontrolled client software.

### Per-message key escrow

When the client-side classifier flags a message, the client escrows the per-message key `K_msg` for that specific message under a threshold public key `PK_threshold`. The escrow ciphertext is:

```
Enc(PK_threshold, K_msg)
```

The escrow is granular: only the flagged message's key is escrowed, not the conversation key, not the epoch's forward or backward chain seeds, not any other message's key. Even if the threshold group later decrypts the escrow, they learn the content of one message. The rest of the conversation remains encrypted.

This is the connection to the epoch protocol: each message has its own key `K_msg = HKDF(F_k || B_k, context_id, info)` derived from the current position in the bidirectional hash chains. Escrowing `K_msg` does not reveal `F_k` or `B_k` — it is a one-way derivation. The threshold group cannot reverse the HKDF to recover chain values and decrypt other messages.

### Threshold ElGamal decryption

The public key `PK_threshold` is produced by distributed key generation (DKG) across n parties. No single party holds the full private key. Decrypting an escrowed `K_msg` requires at least k of the n parties to produce partial decryptions, which are then combined to recover the key. This is standard threshold ElGamal — no TEE or Safebox is required.

The threshold group's composition is a governance decision:

- **Community moderator panel:** For open chat rooms, the threshold group might be elected moderators.
- **Legal/compliance officers:** For organizational deployments, the threshold group might be a legal team.
- **External oversight board:** For maximum independence, the threshold group might include external parties with no operational relationship to the platform.
- **Mixed:** Any combination, with the k-of-n parameters determining how many must agree.

A SafecloudApp handler manages the workflow: accepting unlock requests, routing approval requests to threshold members, combining partial decryptions, and recording every action in a SafecloudChain audit trail. Every unlock is a permanent, signed record — who requested it, who approved it, what reason was given, and when it happened.

### Proof of escrow for media

For media messages (images, video), the Jet enforces a structural requirement: the `send-media` room handler (see Apps.md) requires a valid escrow ciphertext alongside the message ciphertext. The handler verifies that the escrow is a well-formed ElGamal ciphertext under `PK_threshold` without knowing what key it encrypts.

A sender who submits a media message without a valid escrow ciphertext has the message rejected. The Jet does not need to decrypt anything to enforce this — it checks the mathematical structure of the escrow (a valid point on the curve, correct format) without learning the escrowed value.

For text messages, no escrow is required at the protocol level. Text-only messages pass through without proof of escrow. This is a deliberate trade-off: requiring escrow for every text message would add overhead and raise the stakes of threshold group governance, while the primary content safety concern (CSAM, violent imagery) is media, not text. Text toxicity is handled by the client-side classifier at send and receive time, with reporting and reputation as the enforcement mechanism rather than escrow.

### Garbage escrow detection

A sender using a modified client can submit a well-formed escrow ciphertext that encrypts a random value instead of the real `K_msg`. This passes the Jet's well-formedness check because the Jet verifies format, not content.

The garbage escrow is detectable only when the threshold group decrypts it — triggered by a report, a flag from a recipient's post-scan classifier, or a legal process. The decrypted "key" is applied to the message ciphertext, and the result is garbage (does not parse as a valid message, does not decompress as a valid image). This is evidence of deliberate evasion.

Garbage escrow detection is post-hoc, not proactive. It cannot prevent the message from being sent or read. It creates a forensic trace: the sender produced a deliberately invalid escrow, which is itself a policy violation. Combined with the report that triggered the decryption attempt, it provides evidence of intentional circumvention.

A future version could use a TEE-based Safebox to verify at submission time that the escrowed value actually decrypts the message ciphertext, turning garbage escrow detection from post-hoc to real-time. This requires trusting the TEE's attestation — a trade-off that v1 avoids.

### Consent and opt-in structure

Users of the standard Safecloud client consent to the escrow behavior as part of using the service. The consent is recorded through consents.to — a third-party attestation service that provides timestamped, auditable consent records. The consent statement is specific: the user acknowledges that flagged messages will have their per-message key escrowed, and that a threshold group may decrypt it under a stated process.

The consent is opt-in in the sense that the user chose the standard client. A user who objects to escrow can use a third-party client. That client will not scan or escrow. The consequences:

- **Media messages will be rejected.** The `send-media` handler requires proof of escrow. No escrow, no media.
- **Reputation signals apply.** If the user is reported and no escrow exists to corroborate or dismiss the report, the absence of escrow is itself a signal.
- **Text-only participation is unrestricted.** A non-escrowing client can still send and receive text messages in rooms.

This structure preserves user choice while making the platform structurally hostile to the use case the content safety system targets: distribution of harmful media in chat.

### Honest gaps

Two willing bad actors using modified clients can exchange harmful content without triggering any of these mechanisms. Their clients skip scanning, submit garbage escrow (or no escrow for text), and the recipients willingly decrypt without post-scan. Neither party reports the other.

This is the same gap that exists in Signal, Session, Threema, and every other E2E system. No cryptographic protocol prevents two cooperating adversaries from communicating between themselves. The defense is not against willing cooperation — it is against:

- **Unwitting recipients** who receive harmful content and whose client post-scans it.
- **One-to-many distribution** where at least some recipients are honest and will trigger a report.
- **Media distribution** where the Jet's proof-of-escrow requirement forces even modified clients to produce an escrow ciphertext (real or garbage), creating a forensic record.
- **Platform attractiveness** — the combination of client scanning, mandatory media escrow, reputation signals, and garbage escrow detection makes the platform a worse choice for systematic distribution of harmful content than platforms with no measures at all.

For a detailed analysis of the attack surface for E2E chat content safety, see Attacks.md section 11.

### Interaction with the reputation system

The chat content safety system feeds into the same reputation system described in [Reputation system](#reputation-system), but through different signals:

| Signal | Source | Effect |
|--------|--------|--------|
| Recipient post-scan flag | Recipient's client-side classifier flags decrypted content | Contributes to sender's reputation score, same as a storage-layer flag |
| User report | Recipient manually reports a message | Triggers threshold group review; confirmed reports affect sender's reputation |
| Garbage escrow detection | Threshold decryption produces garbage | Sender's reputation takes a significant hit (evidence of deliberate evasion) |
| Missing escrow for media | Sender's message rejected by `send-media` handler | No reputation effect (message was never delivered), but the rejection is logged |
| Threshold unlock | k-of-n approvers decrypt an escrowed key | No direct reputation effect, but the decrypted content may reveal violations that affect reputation |

The reputation effect of chat-originated flags follows the same gradient as storage-layer flags: reputation degrades gradually, distribution shrinks, and the user experiences a silent reduction in reach rather than an explicit ban. The shadowban properties described in [Shadowban gradient](#shadowban-gradient) apply equally to chat — a user whose reputation degrades sees their messages delivered more slowly, their media messages scrutinized more carefully, and their room creation requests deprioritized.

---

## Attack vectors

### Classifier evasion (adversarial examples)

**Attack:** The classifier models are shipped to clients. An attacker reverse-engineers the model and crafts adversarial content that evades detection — images that look like CSAM to humans but don't trigger the classifier, or modified versions that avoid hash matching.

**Defense:** PDQ is a perceptual hash — minor modifications (cropping, recoloring, compression) still match. Evading PDQ requires substantial alteration of the image, at which point it may no longer serve the attacker's purpose. For classifier evasion (adversarial ML), the secondary nature of the classifier means it's not the only defense — reputation, routing uncertainty, and the chilling effect all remain.

**Residual risk:** 🟡 Medium. Determined attackers can evade ML classifiers. Hash matching is harder to evade but only catches known material. The system accepts this limitation — it aims for chilling effects, not perfect detection.

### Proof-of-scan forgery

**Attack:** A Drop forges a "clean" scan report for harmful content, submitting it to the Jet with a valid signature.

**Defense:** The forgery works for initial submission (the Jet can't verify without plaintext). But other Drops that store the same content will passively scan it and flag it. The jury will corroborate. The original Drop's "clean" report is contradicted, the uploader's reputation drops, and the original Drop's scanner-reputation drops (it signed off on content that was later flagged).

**Residual risk:** 🟢 Low over time. The forgery provides a temporary window — the content is distributed before passive scanning catches it. The window is bounded by the sampling rate and the number of Drops that replicate the content.

### Jury manipulation

**Attack:** An attacker builds many high-reputation Drops over months, then uses them to dominate jury selections and systematically contradict legitimate flags.

**Defense:** Jury selection is random from the full pool of established Drops, weighted by reputation. Dominating juries requires controlling a large fraction of the total established Drop population — not just having a few high-reputation nodes. The cost of building and maintaining enough high-reputation Drops to dominate random jury selection on a large network is prohibitively high.

**Residual risk:** 🟢 Low on a large network. 🟡 Medium on a small or early-stage network with few established Drops. The jury size (N) can be increased as the network grows.

### Model poisoning

**Attack:** An attacker compromises the classifier model distribution — either by operating a Jet that announces a backdoored model CID, or by publishing a release with a modified classifier.

**Defense:** The classifier CID is pinned in the release. Drops verify that the Jet's announced classifier CID matches the CID in the software release they're running. A Jet that announces a different CID is immediately detectable — the Drop rejects it and can report the discrepancy. Compromising the release itself requires compromising the build and distribution pipeline, which is the same threat model as any open-source software distribution system (npm, apt, etc.) and is publicly auditable.

**Residual risk:** 🟢 Low. Requires compromising the open-source release pipeline, which is subject to the same scrutiny as any widely-used open-source project.

### Timing of passive scan evasion

**Attack:** An attacker uploads content, waits for one scan pass (hoping for a clean result), then quickly distributes the CID to recipients before additional scans occur.

**Defense:** Scanning is random and continuous — the attacker doesn't know when the first scan will happen or when subsequent ones will. The content is scanned on every Drop that stores it, not just the original uploader's Drop. Even if the first scan is clean (no match at the time), retrospective scanning will flag it when the hash database updates. And reputation-gated distribution means a new identity can't distribute quickly anyway.

**Residual risk:** 🟢 Low for known material (hash matching is instant and doesn't depend on timing). 🟡 Medium for novel material that isn't yet in hash databases.

### Government-compelled scope expansion

**Attack:** A government compels the protocol developer to add political speech detection, protest coordination keywords, or dissident identification to the classifier. The scanning infrastructure built for CSAM is repurposed as a surveillance tool.

**Defense:** See the [Scope expansion resistance](#scope-expansion-resistance) section. The classifier CID is pinned per release (no signing key that can silently push updates). The classifier is open source (expansion is publicly visible). Jets are permissionless (users migrate away from compliant Jets). Drops choose their Jets (no forced adoption). Collective refusal blocks deployment of an unpopular classifier, the same way Bitcoin nodes block unpopular consensus changes.

**Residual risk:** 🟡 Medium. The technical defenses raise the cost of scope expansion but cannot prevent it if a sufficiently powerful coalition of governments acts in concert. The defense is economic and social (collective refusal by operators), not cryptographic. In practice, the open-source auditability and permissionless Jet entry make undetected scope expansion very difficult — the realistic threat is overt, publicly debated expansion, which is subject to political and legal challenge.

---

## Legal interaction with Trading.md

The flagging system strengthens the legal defenses described in `Trading.md`:

**Tornado Cash distinction:** The Tornado Cash developers were criticized for not implementing available compliance measures. Safecloud's reference implementation includes client-side content classifiers, proof-of-scan requirements, a reputation system, and per-message key escrow with threshold decryption for chat — reasonable measures that demonstrate good faith across both the storage and chat layers. This is the "we did something" defense that Tornado Cash lacked.

**Structural defense preserved:** The flagging system operates entirely client-side. The Jet never decrypts content. End-to-end encryption is intact. The structural defense ("the Jet cannot see messages") remains true. The flagging system adds a pre-encryption scanning layer, not a decryption capability.

**Reasonable measures without liability creep:** The classifier is open-source and based on third-party tools (PDQ, NCMEC hashes). The protocol developer distributes the model and requires proof-of-scan. False negatives are limitations of the technology, not negligence by the developer. The developer's obligation is to ship and maintain the scanning tools — not to guarantee perfect detection.

**Fork defense:** Deliberate removal of the scanning requirement is evidence of the forker's intent, not a gap in the protocol developer's design. The protocol spec mandates proof-of-scan. The reference implementation includes it. The developer has taken the affirmative step.
