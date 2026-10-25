# Safecloud Release Notes

## 2.0 — Foundation

The initial documentation release. Establishes the core architecture: encrypted chunk storage on Drops, routing through Jets, HLS video streaming via service worker, micropayments via ERC-20 tokens with EIP-712 signatures, identity via hash-chained keychains with dual-threshold recovery.

**Core docs:** README.md (storage primitives, key hierarchy, OCP, micropayments — 9,900 words), Apps.md (SafecloudApps WASM execution model, handlers, triggers, outbound endpoints — 5,100 words), Attacks.md (threat model — 8,000 words), Ecosystem.md (keychains, organizations, how layers unify — 4,800 words), Flagging.md (content moderation, reputation, threshold escrow — 6,000 words), LLM.md (coding primer — 1,000 words), Protocol.md (wire protocol), Trading.md (trading and mailbox primitives), Qbix.md/QbixPHP.md (platform integration).

**Code:** Client.js (store, fetch, grant, reshare, HLS streaming), service worker for HLS, Jet routing, Drop storage, demo pages, vendored ethers v6.17.0, payment signing and verification, test suite.

## 2.1 — SafecloudApps expansion

Major expansion of the SafecloudApps documentation.

**Apps.md** grew from 5,100 to 7,900 words (+2,800). New coverage: SafecloudDB tracks with per-track HKDF encryption, handler lifecycle and fuel metering, SafecloudChain (hash-chained receipts for deterministic replay), trigger system (cron-based and event-based), outbound endpoints (declared HTTP calls with schema validation and rate limits), rooms and E2E encrypted chat (epoch-based key management, room handlers, offline delivery), attack vectors table.

## 2.2 — Epoch protocol and expanded threat model

**New file: EpochProtocol.md** (3,200 words). Standalone implementation reference for the bidirectional hash-chain epoch protocol: forward chain for forward secrecy, backward chain for post-compromise security, epoch transitions, scope table (chat, keychains, organizations, camera feeds, recovery).

**Attacks.md** grew from 8,000 to 11,500 words (+3,500). Expanded threat model covering SafecloudApp-specific attack vectors: malicious WASM, Jet execution lies, chain tampering, resource exhaustion, trigger abuse, outbound endpoint abuse, epoch key compromise, garbage escrow, modified chat clients.

## 2.3 — Content safety deepening

**Flagging.md** grew from 6,000 to 7,800 words (+1,800). Expanded coverage of the three-layer content safety model: client-side WASM scanning (proof-of-scan, whitelisted classifier CIDs), Safebox chaperone scanning (attestation-gated admission, scoped grants, retrospective scanning, periodic re-attestation), E2E chat content safety (bilateral scanning, batched chaperone delivery, severity-tiered deniability, per-message key escrow under threshold ElGamal).

## 2.4 — README consolidation

**README.md** grew from 9,900 to 11,000 words (+1,100). Consolidated and clarified the core protocol documentation: storage primitives, key hierarchy, OCP delegation, micropayment flows, Jet-to-Jet authentication, Drop lifecycle.

## 2.5 — LLM primer expansion

**LLM.md** grew from 1,000 to 2,000 words (+1,000). Expanded the coding primer with additional API surface coverage, common mistakes table, and cross-references to companion docs.

## 2.6 — Adaptive streaming

**New file: AdaptiveStreamer.md** — design document for adaptive Drop selection during striped downloads: parallel probing, EMA-based throughput tracking, tier classification (Fast/Marginal/Slow), Drop-side serving policy (`serveWhen`, battery/connection monitoring, pause/resume), micropayment ramping (unsigned intent → signed settlement, per-drop watermark channels).

**New code: AdaptiveStreamer.js** — client-side implementation of the adaptive streaming algorithm. Test suite in `tests/adaptive_streamer.test.js`.

**LLM.md** grew by 280 words. New section 18 covering AdaptiveStreamer API and Drop-side serving policy.

**README.md** grew by 480 words. Integration of adaptive streaming into the main protocol documentation.

Minor wording updates across Apps.md, Attacks.md, Ecosystem.md, EpochProtocol.md, Flagging.md (each ~10 words).

## 2.7 — Flagging and moderation expansion

**Flagging.md** grew from 7,800 to 10,700 words (+2,900). Major expansion of the content moderation framework: detailed reputation mechanics, stake-based flagging, jury selection algorithms, anti-griefing measures, corroboration requirements, shadowban gradient.

**LLM.md** grew by 120 words. Updated content safety section cross-references.

## 2.8 — Unified architecture

The conceptual release. Introduces the unifying three-layer model and revises the chat architecture for metadata protection.

**New file: Architecture.md** (~3,500 words). Documents the unified architecture: **Safecloud = pull** (content-addressed encrypted storage, retrieval by CID), **Intercloud = push** (event propagation along rails, watchers, epochs), **Safebox = trust** (attested TEE compute, push notification gateway, confidential workloads). The three layers form a loop: content enters Safecloud → events propagate through Intercloud → safebots in Safeboxes process → curated notifications push to users → users pull content by CID, decrypt in player.

Also covers: three-tier WASM (Jet-side, client-side, Safebox) with host API tables, tree API replacing flat KV, WAL + checkpoint to Drops, revised chat model, SafecloudApp deployment, and comparisons to Cloudflare Workers, Pear/Hyperswarm, and Signal.

**Tree API** — generalized storage replacing flat `safedb_*` KV: `tree_create`, `tree_append`, `tree_get`, `tree_put`, `tree_range`, `tree_delete`, `tree_root`, `tree_checkpoint`, `tree_hydrate`. KV functions remain as aliases. WAL on local disk for crash recovery, async checkpoint to Drops for failover.

**Revised chat architecture** — designed to prevent metadata leakage:
- Rooms are Merkle trees (append-only log of encrypted blobs), not Jet-routed message tracks.
- WebRTC mesh for real-time delivery; Jet as TURN relay only.
- 2-hop onion routing for persistence: sender → 2 intermediate Jets → destination Jet. Traffic is indistinguishable from inter-Jet chunk replication.
- No sender pubkey in envelope (deniability). No wall-clock timestamp — monotonic tree position index for ordering.
- Safebox push gateway for notifications: TEE-attested, holds VAPID keys, enforces per-user rate limits via OCP claims.

**SafecloudApp deployment** — CLI via npm (`@safecloud/cli`), zip upload, web dashboard (itself a SafecloudApp). Access control via OCP Actions Extension with owner/deployer/admin roles and M-of-N multisig.

**Standard includes** — `/@safecloud/client.js`, `drop.js`, `app.js`, `app.css` served from hosting Jet. Pinned versions. Iframe `?css=` for custom styling.

**Updated docs:** Apps.md (tree API, revised rooms, deployment, standard includes, updated attack vectors), LLM.md (architecture summary, rooms section), CHANGELOG.md.
