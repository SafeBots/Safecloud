# Safecloud — Content Flagging and Reputation

This document specifies how Safecloud provides responsible content scanning without breaking end-to-end encryption. The design covers three layers: (1) client-side WASM scanning — the native Safecloud approach, where the standard client bundles whitelisted classifier WASM (content-addressed by CID) and scans plaintext before encryption, requiring no Safebox or TEE infrastructure; (2) Safebox chaperone scanning — an attested Safecloud client running inside a Safebox TEE that joins rooms or receives scoped grants to stored content, providing retrospective scanning and heavy-model classification that lightweight clients cannot perform; and (3) E2E chat safety — client-side scanning of message plaintext combined with per-message key escrow under threshold ElGamal and proof-of-escrow requirements for media messages.

Read `Protocol.md`, `Trading.md`, and `EpochProtocol.md` before this document. The flagging layer does not modify the encryption or routing protocol. For the storage/distribution layer, it adds a pre-encryption scanning step on the client and a reputation signal that affects content distribution across the network. For stored content, it adds Safebox-based passive scanning via attested TEE clients that receive scoped grants to decrypt and classify ciphertext (see also the Safebox Attestation Protocol for the trust chain). For E2E chat, it adds client-side scanning, per-message key escrow under threshold encryption, and proof-of-escrow enforcement at the Jet (see also `Ecosystem.md` §Content safety in E2E chat and `Apps.md` §Rooms and E2E encrypted chat). See also [AdaptiveStreamer.md](AdaptiveStreamer.md) (adaptive drop selection, serving policy, micropayment ramping).

**Notation:** Drop = storage node (holds ciphertext, never has decryption keys). Jet = routing node (routes ciphertext, never decrypts). Client = any node that holds decryption keys (the uploading author, a recipient, or a Safebox chaperone with a scoped grant). Classifier = AI model or hash-matching function, compiled to WASM and distributed by CID. Flag = a classifier's assertion that content matches known-bad material. Reputation = a per-pubkey score that determines content distribution priority.

---

## Table of Contents

- [Design goals](#design-goals)
- [Architecture overview](#architecture-overview)
- [Who has plaintext](#who-has-plaintext)
- [Classifier models](#classifier-models)
  - [Available scanning tools](#available-scanning-tools)
  - [Classifier WASM compilation](#classifier-wasm-compilation)
  - [Model distribution](#model-distribution)
  - [Model size and bandwidth](#model-size-and-bandwidth)
- [Layer 1 — Client-side WASM scanning](#layer-1--client-side-wasm-scanning)
  - [Pre-encryption scanning](#pre-encryption-scanning)
  - [Proof-of-scan](#proof-of-scan)
  - [What the Jet verifies](#what-the-jet-verifies)
  - [Whitelisted classifier hashes](#whitelisted-classifier-hashes)
- [Layer 2 — Safebox chaperone scanning](#layer-2--safebox-chaperone-scanning)
  - [Why clients cannot scan stored ciphertext](#why-clients-cannot-scan-stored-ciphertext)
  - [Safebox as attested client](#safebox-as-attested-client)
  - [Attestation-gated room admission](#attestation-gated-room-admission)
  - [Scoped grants for stored content](#scoped-grants-for-stored-content)
  - [Retrospective scanning](#retrospective-scanning)
  - [Periodic re-attestation and ejection](#periodic-re-attestation-and-ejection)
  - [Heavy-model scanning](#heavy-model-scanning)
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
  - [Bilateral client-side scanning for chat](#bilateral-client-side-scanning-for-chat)
  - [Batched chaperone delivery](#batched-chaperone-delivery)
  - [Severity-tiered deniability](#severity-tiered-deniability)
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

1. **Scan before encryption, not after.** The classifier runs on the client, on plaintext, before the content is encrypted and submitted to the network. Neither the Jet nor the Drop ever decrypts anything. End-to-end encryption is preserved on the wire.

2. **Deterministic and auditable.** The classifier models are open-source, compiled to WASM, and distributed as content-addressed chunks. Given the same content and the same model, any node produces the same result. This enables independent verification of flags.

3. **Reputation, not censorship.** Flagged content is not deleted or blocked. The uploader's pseudonymous reputation degrades, which reduces the distribution of their content across the network. The content technically remains at its CID — it just stops being replicated, served quickly, or prioritized.

4. **Anti-griefing by design.** False flags are detected through random jury verification. Sybil flag attacks fail because the classifier output is deterministic — a modified classifier produces a different result hash, and the jury catches it.

5. **Chilling effects over perfect detection.** The system does not aim to catch every bad actor. It aims to create sufficient uncertainty that uploading harmful content to this network is risky. The uploader doesn't know whether a Safebox chaperone will later scan their stored content, when, or whether a flag will surface. The threat of detection is continuous.

6. **The fork is the fork's problem.** Anyone can fork the open-source Jet software and remove the proof-of-scan requirement. That fork is a separate network. The reference implementation includes scanning. Deliberate removal of safety features is evidence of intent — the forker's, not the protocol developer's.

7. **Two layers, complementary.** Client-side WASM scanning is the fast, zero-infrastructure path — every standard client scans its own content before encryption. Safebox chaperone scanning is the thorough path — an attested TEE client handles retrospective scanning of stored content, heavy classifiers that don't fit on mobile devices, and independent verification that doesn't trust the uploading client. Neither layer alone is sufficient; together they cover the upload-time and post-storage gaps.

---

## Architecture overview

```
Content lifecycle with flagging:

  Author (Client)          Drop (storage)             Jet               Network
  ───────────────          ──────────────             ───               ───────
  classifier scans
  plaintext before   →     receives and stores  →     Jet checks
  encryption               ciphertext                 proof-of-scan  →  content distributed
                                                                        based on uploader
                                                                        reputation

  Safebox chaperone        Drop serves ciphertext
  (attested Client)        to authorized clients →    flags submitted → corroboration +
  receives grant,                                                       jury verification →
  decrypts in TEE,                                                      reputation update
  scans plaintext
```

The classifier runs on the client as WASM — the standard client scans plaintext before encryption and includes a proof-of-scan in the upload. The Jet verifies that the client claims to have scanned (proof-of-scan). For stored content, a Safebox chaperone — an attested Safecloud client running inside a TEE — receives scoped grants to decrypt and classify ciphertext that Drops are serving. The chaperone proves what code it is running via the Safebox Attestation Protocol, so other participants can verify the scanner is genuine before granting access. The network propagates flags and adjusts reputation scores through corroboration and jury verification.

---

## Who has plaintext

Understanding which nodes have plaintext is essential to understanding where scanning can happen. In Safecloud, end-to-end encryption means:

| Node | Has plaintext? | Why |
|------|---------------|-----|
| **Author (uploading client)** | Yes | Created the content. Scans before encrypting. |
| **Recipient (downloading client)** | Yes | Holds decryption keys or grants. Scans after decrypting. |
| **Safebox chaperone** | Yes, scoped | An attested client that receives a time-limited, read-only grant. Decrypts inside the TEE enclave. Plaintext never leaves the enclave. |
| **Drop** | No | Stores and serves ciphertext. Has no decryption keys. Cannot scan. |
| **Jet** | No | Routes ciphertext. Has no decryption keys. Cannot scan. |

This table determines the scanning architecture. The uploading client scans its own content (Layer 1). The Safebox chaperone scans stored content by receiving grants (Layer 2). Drops and Jets never scan content — they verify that scanning happened (proof-of-scan) and propagate flags, but they never see plaintext.

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

Hash matching against known material has near-zero false positives. The content either matches a known hash or it doesn't. This is the mandatory, high-confidence component of the scanning pipeline. The PDQ, VPDQ, TMK, Perception, and HMA components are fully open source and can be compiled to WASM for client-side execution. The hash databases (GIFCT, NCMEC) require membership agreements — the protocol developer applies once and distributes the hash lists as part of the classifier bundle.

**Classifiers (novel content):**

| Tool | Source | What it does | Size |
|------|--------|--------------|------|
| NSFWjs | [infinitered/nsfwjs](https://github.com/infinitered/nsfwjs) | NSFW image classification into 5 categories (Drawing, Hentai, Neutral, Porn, Sexy). TensorFlow.js, runs in browser or Node. MobileNet v2 backbone. | ~3 MB (quantized) |
| Detoxify | [unitaryai/detoxify](https://github.com/unitaryai/detoxify) | Text toxicity detection — toxic, severe toxic, obscene, threat, insult, identity attack. Based on BERT/RoBERTa fine-tuned on Jigsaw datasets. Ships three model sizes. | 420 MB (original), 1.3 GB (unbiased), ~500 MB (multilingual) |
| Altitude | [Jigsaw](https://github.com/jigsaw-code/altitude) | Web-based triage tool for terrorist/extremist content. Integrates directly with the GIFCT Hash-Sharing Database and Terrorist Content Analytics Platform. Docker-based. | Server-side (not bundled) |
| Perspective API | [Jigsaw/Google](https://github.com/conversationai/perspectiveapi) | Scores text for toxicity, threat, insult, profanity, identity attack. Production API, not a downloadable model — useful as a reference but requires network access. | API only |
| Hate speech classifiers | Various on [Hugging Face](https://huggingface.co/models?search=hate+speech) | Fine-tuned BERT/DistilBERT models for hate speech and offensive language. Many are small enough to run on-device. | 65-250 MB |
| Intel Toxic Prompt RoBERTa | [Intel](https://huggingface.co/Intel/toxic-prompt-roberta) | RoBERTa-based model for detecting toxic and harmful text prompts. | ~480 MB |

For the client's classifier bundle, the practical choices are tiered by where the classifier runs:

**Tier 1 — Standard client (browser tab, mobile app).** Must fit in memory alongside the application. Target: under 50 MB total.
- **Must-have (hash matching):** PDQ + VPDQ + hash database. Pure algorithms with no ML inference cost. The hash functions are a few MB of compiled WASM; the hash database is 10-50 MB depending on NCMEC/GIFCT list size.
- **Must-have (image classification):** NSFWjs. Small, fast, compiled to WASM. 3 MB quantized model.
- **Should-have (text classification):** A distilled hate-speech/threat classifier. DistilBERT-based models from Hugging Face run at 65-130 MB and can be quantized to Q4_0 for ~15-30 MB. Practical on desktop clients; tight on mobile.

**Tier 2 — Safebox chaperone (server-grade TEE).** No memory constraint beyond the instance size. Can run the full classifier stack plus heavier models.
- Everything in Tier 1, plus:
- **Full text classifiers:** Detoxify (420 MB original), Intel toxic-prompt RoBERTa (480 MB), multilingual models (1.3 GB).
- **Small LLMs:** Via the U inference WASM bridge, a quantized 1-3B parameter model (Q4_0, 600 MB - 1.5 GB) can run semantic analysis that hash matching and fixed classifiers miss. See [Classifier WASM compilation](#classifier-wasm-compilation).
- **Altitude:** Jet-side triage when flags accumulate, connecting to GIFCT's hash-sharing API.

Classifiers for novel content have higher false-positive rates than hash matching. They are used as a secondary signal — a classifier flag alone does not trigger reputation consequences. It contributes to a score that, combined with hash matches or corroboration from multiple independent clients, may trigger consequences.

### Classifier WASM compilation

Classifier models are compiled to WebAssembly for deterministic, sandboxed execution on both standard clients and Safebox chaperones. The U language's WASM compilation paths (see U's WASM.md) provide three routes:

1. **Direct WAT emitter** — for pure-algorithm classifiers (PDQ hash computation, perceptual hashing). The U compiler emits standalone `.wasm` modules with no runtime dependency. These are small, fast, and fully deterministic.

2. **Emscripten C→WASM** — for ML classifiers that need the C runtime (NSFWjs inference, BERT-based text classifiers). Compiled with `-DU_WASM -msimd128` for WASM SIMD 128-bit acceleration. The `+V` modifier gives real SIMD in the loop body; only cross-core parallelism is lost in the WASM build.

3. **Inference WASM bridge** — for LLM-based scanning on Safebox chaperones. The `u_wasm_bridge.c` module exports functions for loading GGUF models, tokenization, prefill, and token-by-token generation. WebGPU acceleration (via `navigator.gpu` in browser, or `wgpu-native` in server contexts) handles the matmul. Practical for quantized models up to 3B parameters on server hardware; up to 1B on desktop with WebGPU.

All classifier WASM binaries are content-addressed by CID. The same binary runs identically on every client, producing deterministic output for deterministic verification. The CID is pinned in the Safecloud release (see [Classifier CID pinned per release](#classifier-cid-pinned-per-release)), so clients and Safebox chaperones run the same auditable code.

### Model distribution

Classifier models are distributed as regular Safecloud content — content-addressed chunks fetched by CID. The Jet pins the current model CID and announces it to clients during registration. The client fetches the model chunks like any other content.

```
Jet → Client (during registration):
  Safecloud/client/register response {
    ...existing fields...
    classifierCID: "bafy...",     // CID of current classifier model bundle
    classifierVersion: "1.2.0",  // semantic version for compatibility
    hashDatabaseCID: "bafy...",  // CID of current hash database
    hashDatabaseVersion: "2024-10-15"
  }
```

Model updates are new CIDs. The Jet announces updated CIDs; the client fetches them on its normal sync cycle. No special update mechanism — just new content on the existing CDN.

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
- A client's daily bandwidth for content serving: 1-50 GB
- The classifier model bundle: 20-70 MB (one-time download, updated incrementally)

The model download is equivalent to a few video chunks. For a client that serves gigabytes of content daily, it's noise. The download is indistinguishable from any other content fetch — it's a set of CIDs retrieved from the network, the same as fetching a video or a document.

Hash database updates are incremental — new hashes appended, published as a diff CID. A daily update is typically kilobytes.

---

## Layer 1 — Client-side WASM scanning

The standard Safecloud client bundles the whitelisted classifier WASM (content-addressed by CID) and scans all plaintext content before encryption. This is the native Safecloud scanning path — it requires no Safebox, no TEE, and no infrastructure beyond the client itself. Every upload is scanned; every scan produces a deterministic, verifiable report.

### Pre-encryption scanning

Before encrypting and submitting content (a message, a file, a chunk), the client runs the Tier 1 classifier bundle on the plaintext. The classifier produces a deterministic result: a scan report containing the content hash, the classifier version, the result (clean/flagged + classification details), and a signature.

```
ScanReport {
  contentHash:      SHA-256 of the plaintext content
  classifierCID:    CID of the classifier model used
  result:           "clean" | "flagged"
  classifications:  [{ type: "pdq_match", hash: "...", confidence: 1.0 }, ...]
  timestamp:        unix timestamp
  clientSignature:  client's signature over the above fields
}
```

The client includes the `ScanReport` (or a compact hash of it) in the message envelope or chunk upload. This is the proof-of-scan — it travels with the content from client to Jet.

### Proof-of-scan

The proof-of-scan is a claim, not a guarantee. The client controls its own execution environment and could forge a "clean" report for any content. The Jet's verification is a lightweight check that keeps honest clients honest and creates a paper trail for dishonest ones.

The Jet verifies that:

1. The `classifierCID` matches the current (or recent) whitelisted model version
2. The `clientSignature` is valid for the client's registered pubkey
3. The report exists (the client didn't skip scanning)

The Jet does **not** verify the scan result itself — it can't, because it doesn't have the plaintext. It verifies that the client claims to have scanned. The actual verification happens through Safebox chaperone scanning (Layer 2) and the corroboration and jury mechanism described below.

### What the Jet verifies

The real enforcement comes from three mechanisms:

1. **Safebox chaperone scanning** — an attested Safecloud client running in a TEE independently scans stored content and flags discrepancies with the original scan report (see [Layer 2](#layer-2--safebox-chaperone-scanning))
2. **Jury verification** — when flags accumulate, randomly selected clients with access to the content re-scan and verify
3. **Reputation consequences** — a client that consistently produces "clean" reports for content that chaperones or other clients flag loses reputation as a scanner, which affects its standing on the network

This is defense in depth. No single mechanism is airtight. Together, they make systematic evasion expensive and detectable.

### Whitelisted classifier hashes

The client does not trust arbitrary classifier code. The classifier WASM binary is identified by its content-addressed CID, and the client maintains a whitelist of accepted CIDs. The whitelist is updated through the normal Safecloud release cycle — a new release pins new CIDs, and the client accepts only those CIDs.

This is the same mechanism described in [Classifier CID pinned per release](#classifier-cid-pinned-per-release), applied at the client level. The client verifies that the classifier it is running matches a CID from its whitelist before producing a scan report. A classifier with an unknown CID is rejected — the client will not run it and will not produce a scan report signed with its key.

The whitelist serves two purposes: it prevents a compromised Jet from pushing a backdoored classifier (the client rejects unknown CIDs), and it ensures that all honest clients on the same release produce identical scan results for identical content (they are all running the same deterministic WASM binary).

---

## Layer 2 — Safebox chaperone scanning

### Why clients cannot scan stored ciphertext

Layer 1 scans content at upload time, on the uploading client. But Drops store only ciphertext — they have no decryption keys and cannot scan what they are serving. Once content is encrypted and stored, the uploading client is the only entity that ever saw the plaintext. If that client used a modified WASM bundle, skipped scanning, or uploaded content that wasn't yet in hash databases, Layer 1 missed it.

Retrospective scanning — re-scanning stored content when hash databases update or when heavier classifiers become available — requires an entity that can (a) obtain decryption keys for stored content, (b) decrypt it, and (c) run classifiers on the plaintext. No standard client has standing to decrypt arbitrary stored content, and no Drop has keys to decrypt anything. A different kind of participant is needed.

### Safebox as attested client

A Safebox chaperone is a standard Safecloud client running inside a Safebox TEE (Trusted Execution Environment). It is not a special node type — it is a regular client that happens to run in an enclave where the code is attested and the plaintext is hardware-isolated. From the protocol's perspective, it joins rooms and receives grants the same way any client does. The difference is that it can prove what code it is running.

The chaperone runs the Tier 2 classifier stack: everything in Tier 1, plus full-size text classifiers (Detoxify at 420 MB, multilingual models at 1.3 GB), and small LLMs (1-3B parameters, quantized) via the U inference WASM bridge. These models are too large for a mobile client but trivial for a server-grade TEE instance.

The chaperone's plaintext isolation guarantee: content is decrypted inside the enclave, scanned, and the plaintext is discarded. The scan report (content hash, classifier CID, result, chaperone signature) exits the enclave. The plaintext does not. This guarantee is enforced by the TEE hardware, not by a policy promise — a compromised host OS cannot extract plaintext from the enclave.

### Attestation-gated room admission

Before a chaperone can access any content, it must prove that it is genuine — running blessed scanner code inside a real TEE, not a modified binary on commodity hardware. The proof uses the Safebox Attestation Protocol:

1. **Chaperone calls `POST /assert`** on its local Safebox System component. This produces an OCP `safebox_announce` claim: the chaperone's Ed25519 public key, a fresh TPM quote binding the claim to current PCR measurements, the `imageRootHash` of the running code, and a 600-second expiry.

2. **Chaperone sends the OCP claim to the Jet's room `join` handler.** The claim travels as part of the standard room-join handshake, with `role: "scanner"`.

3. **The Jet (or any relying party) calls `verifyAnnounce(claim, { blessedImages, maxAttestationAgeSec })`** — a pure-crypto verification that checks:
   - The `imageRootHash` is in the set of blessed scanner images (published and auditable)
   - The TPM quote is valid and fresh (`now - issuedAt ≤ 600` seconds)
   - The EK certificate chain roots to the expected cloud provider's CA
   - PCR measurements match the blessed set for this image (the code hasn't been tampered with)
   - The Ed25519 signature over the claim is valid

4. **On success, the chaperone is admitted** to the room with scanner role. It receives epoch keys and can begin scanning. Other participants can independently verify the same OCP claim — verification is stateless pure crypto, requiring no TPM and no System component.

For additional assurance, the Jet can route the claim through the Safenet verification layer (`POST /safenet/v1/attestation/verify`), which enriches raw attestation with transparency log lookup (is this claim recorded?), deployment provenance (image hash → git commit → auditable source), fleet context (how many Safeboxes are running this image?), and OCP grant policy evaluation.

### Scoped grants for stored content

For content stored on Drops (not live chat), the chaperone receives time-limited, read-only grants scoped to specific CIDs or content ranges. A grant is an OCP claim issued by the content owner (or by the Jet on behalf of the network's scanning policy) that authorizes the chaperone's attested pubkey to decrypt specific ciphertext.

The grant specifies:
- Which CIDs the chaperone may decrypt
- A time window (e.g., 1 hour) after which the grant expires
- Read-only access (the chaperone cannot modify, re-encrypt, or redistribute the content)
- The `requireAttestation` field, which mandates that the chaperone present a fresh attestation when exercising the grant

The chaperone fetches the ciphertext from a Drop (the same way any client fetches content), decrypts it inside the enclave using the granted key material, runs the Tier 2 classifier stack, and produces a signed scan report. The Drop never knows that a scan happened — it served ciphertext to an authorized client, the same as any other fetch.

### Retrospective scanning

When the hash database is updated (new known-bad hashes added), previously clean content may now match. The chaperone's continuous scanning cycle will flag content that was clean when uploaded but matches a hash added since.

This is the property that Layer 1 cannot provide. A client-side scan at upload time is a snapshot — it checks against the hash database as it existed at that moment. The chaperone's scanning is continuous and improves over time as hash databases grow. Content uploaded before a particular hash was identified can still be flagged weeks or months later.

The scanning is invisible to the content uploader. They don't know whether a chaperone has been granted access to their stored content, when the scan will happen, or whether the scan will hit a frame that triggers a match against a newly-added hash. The uncertainty is the deterrent.

For video content, the chaperone decodes random still frames from stored chunks and runs the hash matcher and classifiers. For images, it runs directly on the decrypted image. For text content, it runs the full Tier 2 text classifier stack (which includes models too large for the standard client). The sampling rate is configurable (default: one sample per minute while the chaperone is active). At this rate, a chaperone scanning 10,000 chunks samples each chunk roughly once per week. Content stored for months gets sampled many times.

### Periodic re-attestation and ejection

Attestation is not a one-time check. The chaperone must produce a fresh `POST /assert` assertion every 600 seconds (the attestation window defined by `maxAttestationAgeSec` in the OCP grant). Each assertion includes a fresh TPM quote binding the current PCR state — proving that the chaperone's code has not been modified since admission.

If the chaperone fails to re-attest within the window:
- Its room membership is revoked (the Jet ejects it from any rooms it has joined)
- Its epoch membership is revoked (it loses access to current epoch keys)
- Any outstanding grants are invalidated
- It must re-attest from scratch to regain access

This prevents a "attest once, then swap the code" attack. The 600-second window means that even if an attacker could somehow extract keys from a TEE, the window of exposure is bounded. The re-attestation is lightweight — a TPM quote and an Ed25519 signature, not a full registration — so the overhead is negligible for a server-grade instance.

### Heavy-model scanning

The chaperone's Tier 2 classifier stack includes models that standard clients cannot run: full-size text classifiers (420 MB+), multilingual toxicity models (1.3 GB), and small LLMs (1-3B parameters quantized to Q4_0, 600 MB - 1.5 GB) via the U inference WASM bridge.

These heavy models provide capabilities that Tier 1 hash matching and small classifiers miss:
- **Semantic analysis** — a small LLM can assess whether text describes illegal activity, grooming patterns, or threats, catching content that keyword matching and fixed classifiers miss
- **Cross-language detection** — multilingual models (e.g., Detoxify multilingual at 1.3 GB) handle content in languages that the standard client's distilled models don't cover well
- **Context-aware image analysis** — models larger than NSFWjs can distinguish edge cases (medical imagery, art, news photography) that small classifiers misclassify
- **Novel content detection** — hash matching only catches known material; LLM-based classification catches novel harmful content that has not yet been hashed and distributed to databases

The heavy-model scan runs after the lightweight Tier 1 checks. Content that passes hash matching and the small classifiers is not assumed clean — it is queued for the chaperone's Tier 2 pass. Content that fails Tier 1 checks is flagged immediately without waiting for Tier 2 confirmation, though the chaperone's independent Tier 2 scan serves as corroboration for the jury mechanism.

---

## Flagging protocol

### Flag structure

When a classifier flags content, the scanning entity (client or Safebox chaperone) submits a flag to the Jet:

```
Flag {
  cid:              content-addressed ID of the flagged content
  classifierCID:    CID of the classifier model used
  resultHash:       deterministic hash of the classifier's full output
  classification:   "pdq_match" | "nsfw_high" | "text_extremism" | ...
  confidence:       0.0 - 1.0
  scannerPubkey:    the flagging entity's public key (client or chaperone)
  scannerSignature: signature over the above fields
  stake:            Safebux amount staked on this flag (see anti-griefing)
}
```

The `resultHash` is the critical field for anti-griefing. Because the classifier is deterministic, any entity running the same classifier on the same content must produce the same `resultHash`. An entity that modifies the classifier or fabricates a flag will produce a different hash — detectable by the jury.

### Corroboration

A single flag does not trigger reputation consequences. The Jet tracks flags per CID and waits for corroboration:

- **PDQ hash match (confidence 1.0):** Requires corroboration from 2 additional independent scanners (3 total). PDQ has near-zero false positives, so a low threshold is safe.
- **NSFW classifier (confidence > 0.9):** Requires corroboration from 4 additional independent scanners (5 total). Higher threshold because classifiers have higher false-positive rates.
- **Text classifier:** Requires corroboration from 4 additional independent scanners. Same rationale.
- **Mixed signals (some scanners flag, others don't):** Triggers jury verification (see below).

"Independent" means: different pubkeys (client or chaperone), registered at different times, with independent reputation histories. The Jet checks for Sybil patterns (correlated registration times, identical IP ranges, always-correlated flag patterns). A Safebox chaperone's flag carries additional weight because its attestation proves it ran unmodified classifier code.

### Verification by random jury

When flags on a CID reach the corroboration threshold — or when flags are contradicted by other scanners that processed the same content without flagging — the Jet triggers a jury verification.

The Jet selects N scanners (default: 7) at random from the set of established clients and chaperones (minimum reputation threshold, minimum age on the network) that have access to the flagged CID. These scanners are the jury.

```
Jet → Jury scanner:
  Safecloud/flag/verify {
    cid: "...",
    classifierCID: "bafy...",
    deadline: timestamp
  }

Jury scanner → Jet:
  Safecloud/flag/verdict {
    cid: "...",
    resultHash: "...",          // deterministic classifier output
    classification: "clean" | "pdq_match" | ...,
    scannerSignature: "..."
  }
```

The Jet collects verdicts and applies majority rule:

- **Majority confirms flag:** The flag stands. Reputation consequences apply to the content uploader. The flagging scanners get their stakes returned.
- **Majority contradicts flag:** The flag is false. The flagging scanners lose their stakes. Their scanner-reputation decreases (distinct from content-reputation — this tracks reliability as a scanner).
- **Split verdict:** Inconclusive. No reputation consequences for anyone. The CID is marked for future re-verification when more scanners have processed it.

The jury mechanism ensures that a single malicious scanner (or a cluster of Sybil entities) cannot grief legitimate uploaders. The griefer's modified classifier produces a different `resultHash` than the jury's standard classifiers, and the discrepancy is caught immediately.

---

## Reputation system

### Reputation accrual

Every pseudonymous identity (pubkey) on the network has a reputation score. Reputation starts at a baseline (not zero — new users can participate, just with limited reach) and changes based on network behavior:

**Increases reputation:**
- Storing and reliably serving content over time (for Drops: the primary economic function)
- Earning Safebux through micropayments for storage and bandwidth
- Accurate flagging (flags corroborated by jury)
- Serving on juries (participating in verification)
- For Safebox chaperones: consistent, attested scanning with corroborated results

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

**Attack:** Eve spins up 50 clients with modified classifiers that flag everything. She targets Alice's content. The corroboration threshold is met because 50 scanners all flag the same CID.

**Defense:** The classifier is deterministic. Eve's modified classifier produces a different `resultHash` than the standard classifier. When the jury verifies, the jury's standard classifiers produce the correct `resultHash`. Eve's 50 scanners all produced a different hash — they're clearly running non-standard code.

Result: Eve's 50 identities lose their stakes, lose reputation, and are marked as unreliable scanners. Alice's content is unaffected.

### Deterministic verification

The core anti-griefing property: given the same input and the same classifier, every honest node produces the same output. This is verifiable because:

1. The classifier model is content-addressed (CID). Any modification changes the CID.
2. The classifier output includes a `resultHash` — a hash of the full output. Any modification to the classifier logic changes the `resultHash`.
3. The jury runs the standard classifier (identified by the correct CID) and compares `resultHash` values. Mismatches identify dishonest nodes.

This is possible because the classifiers used (PDQ hash matching, pre-trained neural networks) are deterministic functions. The same image through the same PDQ implementation produces the same hash. The same image through the same NSFW classifier produces the same confidence score (within floating-point precision, handled by rounding to a fixed number of decimal places before hashing).

### Stake-based flagging

A scanner that submits a flag stakes a small amount of Safebux (configurable, default: the cost of a few hours of storage). This stake is:

- **Returned** if the flag is corroborated by the jury (the scanner was right)
- **Returned with a small reward** if the flag leads to a reputation consequence for the uploader (the scanner performed a public service)
- **Forfeit** if the flag is contradicted by the jury (the scanner was wrong or malicious)

The stake makes griefing expensive. Submitting 100 false flags costs 100 stakes. Each false flag is caught by the jury and the stake is lost. The griefer loses Safebux and reputation simultaneously.

The stake amount is calibrated to be trivial for a legitimate scanner that occasionally flags genuinely bad content (one or two stakes outstanding at a time) and expensive for a griefer attempting mass false flagging (hundreds of stakes at risk).

### Flag weight by Drop reputation

Not all flags are equal. A flag from a high-reputation scanner that has been on the network for months, with a history of accurate flags, carries more weight toward the corroboration threshold than a flag from a new identity with no history.

Specifically, a flag contributes a `weight` toward corroboration:

```
weight = base_weight × reputation_multiplier × age_multiplier × attestation_multiplier

where:
  base_weight = 1.0
  reputation_multiplier = min(scanner_reputation / median_reputation, 3.0)
  age_multiplier = min(days_on_network / 30, 2.0)
  attestation_multiplier = 1.5 if scanner is an attested Safebox chaperone, else 1.0
```

A brand-new identity with zero reputation contributes almost nothing to corroboration. A scanner that's been active for 6 months with high reputation contributes up to 6x a base weight (9x for an attested chaperone). This means a griefer who spins up 50 new identities gets 50 × ~0 = ~0 effective weight. They'd need to build reputation across all 50 identities over months before their flags matter — and maintaining 50 legitimate identities is expensive.

---

## Chilling effects

### Routing uncertainty

When a user uploads content to Safecloud, scanning happens at two layers. Layer 1: the standard client scans before encryption — the uploader's own client runs the classifier WASM on plaintext. Layer 2: a Safebox chaperone may later receive a grant to decrypt and re-scan the stored ciphertext with heavier models.

The uploader doesn't control either layer. A modified client can skip Layer 1, but the uploader can't prevent a chaperone from scanning the stored content later. The uploader doesn't know whether a chaperone has been granted access, when it will scan, or whether the scan will use an updated hash database that didn't exist at upload time.

The uncertainty is the deterrent. A bad actor who uploads CSAM doesn't know whether:
- A Safebox chaperone will scan their stored content
- The chaperone will run a heavier classifier that the client-side scan couldn't
- When the scan will happen (could be today, could be next month)
- Whether a hash database update will retroactively flag content that was clean at upload time

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

1. **They're operating a separate network.** Their forked Jet can peer only with other forked Jets (standard Jets reject connections from clients without proof-of-scan). The forked network is isolated.

2. **The fork is affirmative action.** Removing the scanning requirement requires deliberate code modification. The commit diff is evidence of intent. The protocol developer can point to the safety feature and the forker's deliberate removal of it.

3. **The protocol developer's reference implementation includes scanning.** The published protocol spec mandates proof-of-scan. The reference Jet requires it. The reference Drop includes the classifier. Removing it is the forker's choice, not a gap in the protocol.

4. **The fork doesn't invalidate the protocol developer's position.** "Someone forked our protocol and removed safety features" is the same as "someone forked Linux and built malware with it." The existence of the fork does not create liability for the original developer.

This is the legal floor. The protocol developer has taken reasonable measures (built scanning into the reference implementation, required proof-of-scan in the protocol, distributed classifiers to clients). Anyone who removes those measures has made a deliberate choice to operate unsafely. That choice is theirs.

---

## Scope expansion resistance

### The lever problem

Any scanning infrastructure is a potential lever for government-compelled scope expansion. If a government can say "update your classifier to also detect X," the same mechanism built to catch CSAM can be repurposed to catch political dissent, protest coordination, journalism, or anything else. This is the core objection to client-side scanning in the policy debate — not that scanning for CSAM is wrong, but that the scanning mechanism, once built, can be pointed at anything.

Safecloud's design makes this lever weaker than it would be in a centralized system. It does not eliminate the lever — no technical design can fully prevent legal compulsion — but it raises the cost of scope expansion to the point where it requires coordinated global action rather than a single court order.

### Why this lever is weak

**Jets are like Bitcoin miners.** Anyone can run a Jet. No registration, no license, no permission. If a government compels Jet operators in its jurisdiction to push an expanded classifier, users migrate to Jets in other jurisdictions. The Jet operator who complies loses clients (and the Safebux revenue they generate) to competitors who don't. The same economic dynamic that prevents Bitcoin mining pools from adopting unpopular consensus rules prevents Jets from adopting unpopular classifiers.

**The classifier is open source and auditable.** The model is content-addressed and distributed as a CID. Anyone can download it, inspect it, and publish exactly what it scans for. A classifier that checks for political keywords alongside CSAM hashes is trivially detectable. Security researchers, journalists, and civil liberties organizations can audit any release. There is no "we added a feature but it's classified" — the model is the model, and its behavior is deterministic and reproducible.

**Clients choose their Jets.** A client that objects to its Jet's classifier can switch to another Jet. The Jet cannot force a client to run a particular model — it can only refuse to relay messages from clients that don't run its model. So the worst a compromised Jet can do is lose its users. The client operator (or their automated policy) decides which classifier versions to accept.

**Collective refusal works.** To expand the scanning scope across the whole network, a government would need to compel every Jet operator globally — or at least every Jet operator in enough jurisdictions that users have nowhere else to go. This is the same coordination problem that makes global Bitcoin regulation hard. A single jurisdiction's order affects only the Jets in that jurisdiction. Users in other jurisdictions are unaffected. Users in the affected jurisdiction can use VPNs to reach Jets elsewhere.

### Classifier CID pinned per release

The classifier model CID is pinned in each software release, not pushed dynamically by a signing key. This is a deliberate design choice that limits the scope expansion lever.

With a signing key, whoever holds the key can sign any model at any time. The trust relationship is open-ended: "I trust this key to sign classifiers" means trusting every future decision by the key holder. If a government compels the key holder to sign an expanded model, every client that trusts the key automatically accepts the expansion.

With a CID pinned per release, the trust relationship is specific: "I trust this release, which includes this exact classifier." An expanded classifier requires a new release. Operators choose whether to upgrade, the same way Bitcoin node operators choose whether to adopt a new Bitcoin Core release. If a release ships a classifier that scans for political speech, operators don't upgrade. The network stays on the old release. The expanded scope fails to deploy because of collective refusal, not because of a technical lock.

This means the scope expansion attack path is: compel the protocol developer to ship a new release with an expanded classifier → hope that a majority of Jet and Drop operators upgrade to it → deal with the fact that the release is open source and everyone can see what was added. Each step is a public action that triggers scrutiny. Compare this to a signing-key model where expansion is silent and automatic.

The tradeoff is that legitimate classifier updates (new NCMEC hashes, improved CSAM detection) also require a new release and voluntary adoption. This is acceptable — hash database updates are incremental and delivered as data (new CIDs appended to the hash list), not code changes. The classifier code itself changes rarely. When it does, the update follows the same release cycle as any other open-source project: changelog, review, adoption.

---

## E2E chat content safety

The sections above describe flagging for content that passes through Jets during distribution — file uploads, video streams, static content stored on Drops. Layer 1 (client-side WASM scanning) applies at upload time. Layer 2 (Safebox chaperone scanning) applies to stored content via scoped grants.

Chat messages are different. They are ephemeral — the Jet routes ciphertext without decrypting it, and chat messages are typically not stored as content chunks on Drops. The Layer 1 and Layer 2 mechanisms described above don't fully apply to chat. A separate mechanism combines client-side scanning with per-message key escrow, batched chaperone delivery, and tiered deniability, as specified in Ecosystem.md and implemented by the room handlers in Apps.md.

### Why chat is different

In the storage/distribution layer, content passes through multiple nodes. The uploading client scans at upload time (Layer 1), and a Safebox chaperone can later scan stored copies (Layer 2). Multiple independent scanners can corroborate a flag. The jury can re-scan and verify. This redundancy is the foundation of the reputation system's accuracy.

In E2E chat, the only nodes that see plaintext are the sender's client and the recipients' clients. The Jet sees only ciphertext. There are no stored content chunks for a Safebox chaperone to scan via Layer 2 grants. There is no jury that can re-verify a flag by running the classifier independently, because no jury member has the plaintext.

This means the chat content safety system cannot rely on the same corroboration and jury mechanisms. It uses a different approach: bilateral client-side scanning, batched delivery to a Safebox chaperone for Tier 2 classification, severity-tiered deniability, and per-message key escrow under threshold encryption.

### Bilateral client-side scanning for chat

The standard Safecloud client runs the same Tier 1 classifier infrastructure (PDQ, NSFW, text classifiers) on chat messages. The scan is bilateral — it runs at two points:

1. **Before encryption on the sender's device.** The classifier processes the plaintext message or media before the client encrypts it with the per-message key `K_msg` derived from the epoch's forward and backward chains (see EpochProtocol.md).

2. **After decryption on the recipient's device.** The classifier processes the decrypted content. This catches content that evaded the sender's scan (if the sender used a modified client) and provides a second independent classification.

The bilateral property is the defense against modified clients. A malicious sender can suppress their own client-side scan, but they cannot suppress the recipient's scan. As long as one side runs unmodified code, flagged content is detected. The only escape is if both sender and recipient collude — both running patched clients that suppress flags. Colluding pairs are the hard case for any scanning system, not specific to this design (see [Honest gaps](#honest-gaps)).

The classifier models are the same ones described in the [Classifier models](#classifier-models) section — PDQ hash matching, NSFWjs for images, text toxicity classifiers. The client fetches them by CID from the network.

### Batched chaperone delivery

Flagged chat messages are not handled exclusively by the escrow mechanism. They are also delivered to a Safebox chaperone for Tier 2 classification, following the same "log n at write time, log n at read time" split used throughout the architecture:

- **Write time (client side):** The Tier 1 WASM classifier runs on each message. Most messages are clean and never leave the client. Flagged messages accumulate in a local buffer.

- **Read time (chaperone side):** Every ~10 minutes (aligned with the 600-second re-attestation interval), each client flushes its buffer to the room's Safebox chaperone. The buffer contents are shuffled before delivery — no ordering, no timing information. The chaperone runs Tier 2 classifiers on the pre-screened subset.

The chaperone sees only the flagged subset, not the full message stream. This minimizes the chaperone's exposure to plaintext and limits the scanning overhead — the chaperone processes a small fraction of total messages, concentrated on the content that the client-side classifier found concerning.

The 10-minute batch window is not a detection bottleneck. Authorities do not act on minute-level timescales, and the delay is invisible to room participants. The batching serves privacy: it decouples individual messages from their send timestamps, defeating timing-based sender attribution.

### Severity-tiered deniability

Chat messages in Safecloud carry a deniability property similar to Signal's: within a room of N participants, any participant could have authored any message. The chaperone's presence affects this property, and the protocol manages the tradeoff through severity tiers.

Each client-side scan produces a severity classification alongside the clean/flagged result:

| Tier | Criteria | What reaches the chaperone | Deniability |
|------|----------|---------------------------|-------------|
| **Clean** | No client flags the message | Nothing — the chaperone never sees it | Full. The message is invisible to any entity outside the room. |
| **Light flag** | Borderline NSFW, uncertain text classification, low-confidence match | Content only — no sender attribution, shuffled in the batch | Preserved. The chaperone sees content but cannot attribute it to a sender. Room-level action only (warning, policy flag). |
| **Heavy flag** | PDQ hash match against known CSAM (confidence ~1.0), high-confidence match on serious categories | Content + sender attribution | Sacrificed. The severity warrants individual attribution. The moral logic: you don't get cryptographic cover for distributing known child abuse material. |

The vast majority of messages are clean and never reach the chaperone. The tiered structure means deniability loss is proportional to the severity of the violation. A borderline NSFW image in a group chat doesn't expose the sender. A known CSAM hash match does.

**Who determines the severity tier?** The client-side WASM classifier produces the severity classification as part of its deterministic output. Because the WASM binary is content-addressed and whitelisted, an unmodified client's tier assignment is trustworthy. A modified client could downgrade a heavy flag to a light flag to preserve its sender's deniability — but the bilateral scanning property handles this: the recipient's unmodified client independently classifies the same content and may assign a higher severity tier. If either client assigns a heavy flag, the content reaches the chaperone with attribution.

**Deniability in chaperoned rooms — honest limitations:** In a 2-person room with a chaperone, deniability is weak regardless of severity tier. The chaperone knows one of two people sent each flagged message, and even without explicit attribution, the options are trivially narrowed. In larger rooms, light-flag deniability is meaningful — the chaperone sees content from N participants, shuffled and unattributed. Users who need full deniability (no chaperone exposure at all) should use rooms without a chaperone enabled, with the understanding that they lose Tier 2 scanning coverage.

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

**Attack:** A client forges a "clean" scan report for harmful content, submitting it to the Jet with a valid signature.

**Defense:** The forgery works for initial submission (the Jet can't verify without plaintext). But a Safebox chaperone that later receives a grant to scan the stored content will independently flag it. The chaperone's flag carries high weight because its attestation proves it ran unmodified classifier code. The jury will corroborate. The original client's "clean" report is contradicted, the uploader's reputation drops, and the original client's scanner-reputation drops (it signed off on content that was later flagged).

**Residual risk:** 🟢 Low over time. The forgery provides a temporary window — the content is distributed before the chaperone scans it. The window is bounded by the chaperone's sampling rate and the grant cycle.

### Jury manipulation

**Attack:** An attacker builds many high-reputation identities over months, then uses them to dominate jury selections and systematically contradict legitimate flags.

**Defense:** Jury selection is random from the full pool of established scanners, weighted by reputation. Dominating juries requires controlling a large fraction of the total established scanner population — not just having a few high-reputation nodes. The cost of building and maintaining enough high-reputation identities to dominate random jury selection on a large network is prohibitively high. Safebox chaperones on the jury carry extra weight because their attestation proves unmodified code, making them harder to co-opt.

**Residual risk:** 🟢 Low on a large network. 🟡 Medium on a small or early-stage network with few established scanners. The jury size (N) can be increased as the network grows.

### Model poisoning

**Attack:** An attacker compromises the classifier model distribution — either by operating a Jet that announces a backdoored model CID, or by publishing a release with a modified classifier.

**Defense:** The classifier CID is pinned in the release. Clients verify that the Jet's announced classifier CID matches the CID in the software release they're running. A Jet that announces a different CID is immediately detectable — the client rejects it and can report the discrepancy. Compromising the release itself requires compromising the build and distribution pipeline, which is the same threat model as any open-source software distribution system (npm, apt, etc.) and is publicly auditable.

**Residual risk:** 🟢 Low. Requires compromising the open-source release pipeline, which is subject to the same scrutiny as any widely-used open-source project.

### Timing of chaperone scan evasion

**Attack:** An attacker uploads content, hoping to distribute the CID to recipients before a Safebox chaperone scans the stored copy.

**Defense:** The attacker doesn't know when the chaperone will scan or whether it already has a grant. The chaperone's scanning is random and continuous — it samples stored content at random intervals across its grant window. Even if the first scan is clean (no match at the time), retrospective scanning will flag it when the hash database updates. And reputation-gated distribution means a new identity can't distribute quickly anyway.

**Residual risk:** 🟢 Low for known material (hash matching is instant and doesn't depend on timing). 🟡 Medium for novel material that isn't yet in hash databases.

### Government-compelled scope expansion

**Attack:** A government compels the protocol developer to add political speech detection, protest coordination keywords, or dissident identification to the classifier. The scanning infrastructure built for CSAM is repurposed as a surveillance tool.

**Defense:** See the [Scope expansion resistance](#scope-expansion-resistance) section. The classifier CID is pinned per release (no signing key that can silently push updates). The classifier is open source (expansion is publicly visible). Jets are permissionless (users migrate away from compliant Jets). Clients choose their Jets (no forced adoption). Collective refusal blocks deployment of an unpopular classifier, the same way Bitcoin nodes block unpopular consensus changes.

**Residual risk:** 🟡 Medium. The technical defenses raise the cost of scope expansion but cannot prevent it if a sufficiently powerful coalition of governments acts in concert. The defense is economic and social (collective refusal by operators), not cryptographic. In practice, the open-source auditability and permissionless Jet entry make undetected scope expansion very difficult — the realistic threat is overt, publicly debated expansion, which is subject to political and legal challenge.

---

## Legal interaction with Trading.md

The flagging system strengthens the legal defenses described in `Trading.md`:

**Tornado Cash distinction:** The Tornado Cash developers were criticized for not implementing available compliance measures. Safecloud's reference implementation includes client-side content classifiers, proof-of-scan requirements, a reputation system, and per-message key escrow with threshold decryption for chat — reasonable measures that demonstrate good faith across both the storage and chat layers. This is the "we did something" defense that Tornado Cash lacked.

**Structural defense preserved:** The flagging system operates entirely client-side. The Jet never decrypts content. End-to-end encryption is intact. The structural defense ("the Jet cannot see messages") remains true. The flagging system adds a pre-encryption scanning layer, not a decryption capability.

**Reasonable measures without liability creep:** The classifier is open-source and based on third-party tools (PDQ, NCMEC hashes). The protocol developer distributes the model and requires proof-of-scan. False negatives are limitations of the technology, not negligence by the developer. The developer's obligation is to ship and maintain the scanning tools — not to guarantee perfect detection.

**Fork defense:** Deliberate removal of the scanning requirement is evidence of the forker's intent, not a gap in the protocol developer's design. The protocol spec mandates proof-of-scan. The reference implementation includes it. The developer has taken the affirmative step.
