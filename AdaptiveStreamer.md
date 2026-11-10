# Adaptive Drop Selection for Striped Downloads

Companion document to [README.md](README.md) (storage layer), [Ecosystem.md](Ecosystem.md) (architecture), and [Apps.md](Apps.md) (WASM handlers). Covers the algorithm by which a Cloud client selects, measures, and re-ranks the Drops it downloads from in parallel ("striped download"), the drop-side serving policy that lets a Drop operator control when their tab actually serves, and the micropayment ramping that ties payment to delivered bytes rather than promised ones.

**Other companion documents:** [EpochProtocol.md](EpochProtocol.md) (E2E chat key rotation), [Flagging.md](Flagging.md) (content moderation), [Attacks.md](Attacks.md) (threat model), [LLM.md](LLM.md) (LLM coding primer).

---

## 1. Problem statement

A Safecloud download fetches chunks from multiple Drops in parallel (striped download). Drops are browser tabs on volunteer machines whose network quality varies from gigabit fibre to a phone on a metered cellular connection. The client cannot inspect BGP routes, run traceroute, or measure anything about the link except by observing actual transfer performance. A good selection algorithm must:

1. Start wide — try many Drops concurrently so the first chunks arrive fast.
2. Measure throughput per Drop using the only signal available: how many bytes arrived in how many milliseconds.
3. Cull slow Drops quickly — stop requesting from the bottom performers before they waste bandwidth and micropayments.
4. Respect the Drop's own policy — a Drop operator who said "serve only on wifi" should not receive requests when their device falls back to cellular.
5. Pay only for what is used — micropayment watermarks advance only when a chunk has been received and verified, not when it was requested.

## 2. Architecture overview

```
Cloud client (browser)
  └── AdaptiveStreamer
        ├── probeAll(drops)        → initial parallel probe
        ├── rankDrops()            → throughput-weighted ranking
        ├── cullSlow()             → drop the bottom tier
        ├── fetchStripe(chunks)    → assign chunks to ranked Drops
        └── rampPayment(drop,chunk)→ advance watermark after receipt

Jet server
  └── selectForGet / selectForPut  (Router.js — existing)
        └── now incorporates drop.servingPolicy filter

Drop (browser tab)
  └── servingPolicy advertisement
        ├── connectionType         → wifi | cellular | ethernet | unknown
        ├── serveWhen              → wifi-only | always | plugged-only
        ├── maxConcurrent          → how many parallel serve requests
        └── effectiveType          → slow-2g | 2g | 3g | 4g (Navigator.connection)
```

The AdaptiveStreamer lives entirely on the Cloud client. The Jet and Drop changes are small: the Drop advertises its serving policy; the Jet forwards it; the client respects it.

## 3. Initial probe phase

When a download starts, the client knows which Drops hold the target content (CID coverage, maintained by Router.js's `_cidCoverage` map). The probe works as follows:

1. **Request the first chunk from every candidate Drop simultaneously.** Each request is a standard `Safecloud/subtree/get` with `link` pointing at chunk 0 (or the first chunk in the requested range). The Jet fans out to all Drops rather than picking one.
2. **Time each response.** For each Drop, record `{ dropId, startMs, endMs, bytes }`. The probe chunk is small (one chunk, typically 256 KB), so the measurement captures connection setup + first-byte latency + transfer time for a representative payload.
3. **Compute throughput.** `throughputBps = bytes / ((endMs - startMs) / 1000)`. If a Drop does not respond within `probeTimeoutMs` (default 8000), its throughput is 0.
4. **Immediately use the first chunk that arrives.** The probe is not wasted work — the fastest responder's chunk goes straight into the download pipeline. The others are discarded (the chunk is deduplicated by CID).

```javascript
// Pseudocode — actual implementation in AdaptiveStreamer.js
var probes = candidateDrops.map(function (drop) {
    var t0 = performance.now();
    return Jets.get({ rootCid, link: chunkLink(0), drops: [drop.dropId] })
        .then(function (result) {
            return {
                dropId: drop.dropId,
                throughputBps: result.bytes / ((performance.now() - t0) / 1000),
                latencyMs: performance.now() - t0,
                chunk: result.chunks[0]
            };
        })
        .catch(function () {
            return { dropId: drop.dropId, throughputBps: 0, latencyMs: Infinity, chunk: null };
        });
});
```

## 4. Ranking and culling

After the probe, Drops are sorted by throughput. The algorithm divides them into three tiers:

| Tier | Definition | Action |
|------|-----------|--------|
| **Fast** | throughput >= 50% of the best Drop's throughput | Keep; assign chunks in throughput-weighted round-robin |
| **Marginal** | throughput >= 10% of best | Keep on standby; re-promote if a Fast drop degrades |
| **Slow** | throughput < 10% of best, or timed out | Remove from candidate set; do not request further chunks |

The 50%/10% thresholds are configurable (`Safecloud.adaptive.fastThreshold`, `Safecloud.adaptive.marginalThreshold`). They are ratios rather than absolute numbers so the algorithm adapts to the overall network quality of the swarm — a session where all Drops are on mobile connections still converges to the best available subset.

### 4.1 Continuous re-ranking

After the initial probe, every completed chunk fetch updates the Drop's exponential moving average (EMA) throughput:

```
ema[drop] = (1 - alpha) * ema[drop] + alpha * thisChunkThroughput
```

`alpha` defaults to 0.3 — recent measurements weigh heavily so a Drop that degrades (e.g. its wifi drops to cellular mid-download) is detected within 2–3 chunks. After each EMA update, the tier classification is re-evaluated. A Fast drop whose EMA falls below the marginal threshold is demoted; a Marginal drop whose EMA recovers is promoted.

### 4.2 Chunk assignment

Chunks are assigned to Fast-tier Drops in proportion to their throughput:

```
assignmentWeight[drop] = ema[drop] / sum(ema[fastDrops])
```

A Drop with 2x the throughput of another gets roughly 2x the chunks. The scheduler maintains a per-Drop in-flight count capped at `maxConcurrentPerDrop` (default 3) to avoid overwhelming a single tab.

## 5. Drop-side serving policy

A Drop operator controls when their browser tab serves content. The policy is set at Drop init time and advertised in the `Safecloud/drop/register` message:

```javascript
await Q.Safecloud.Drops.init({
    maxStorage: 500 * 1024 * 1024,
    evmAddress: '0x...',
    servingPolicy: {
        serveWhen: 'wifi-only',   // 'always' | 'wifi-only' | 'plugged-only'
        maxConcurrent: 4,          // max parallel chunk serves
        minBatteryPct: 20          // pause serving below this battery level
    }
});
```

### 5.1 Connection monitoring

The Drop continuously monitors its own connection using the Network Information API (`navigator.connection`):

| Field | Source | Used for |
|-------|--------|----------|
| `type` | `navigator.connection.type` | wifi / cellular / ethernet / bluetooth / none |
| `effectiveType` | `navigator.connection.effectiveType` | slow-2g / 2g / 3g / 4g |
| `downlink` | `navigator.connection.downlink` | estimated Mbps (bandwidth the browser thinks it has) |
| `saveData` | `navigator.connection.saveData` | user has enabled data saver |

When the connection changes (the `change` event on `navigator.connection`), the Drop re-evaluates whether it should be serving:

- **wifi-only** (default for laptops): Serve when `type === 'wifi'` or `type === 'ethernet'`. Stop serving if `type` transitions to `cellular`. This covers the case the user described — a laptop whose wifi drops and falls back to a mobile hotspot.
- **always**: Serve on any connection. Suitable for always-on machines or users who don't mind cellular data usage.
- **plugged-only**: Serve when the Battery API reports `charging === true`. Useful for phones left plugged in as dedicated Drops.

When a Drop stops serving (policy violation), it sends a `Safecloud/drop/pause` message to its Jet. The Jet immediately removes the Drop from routing candidates. When the condition clears, the Drop sends `Safecloud/drop/resume` and is re-added — but with its reliability score reduced by `RELIABILITY_RECONNECT` (0.25), the same penalty as a full reconnect, so it must earn its way back into the Fast tier.

### 5.2 Data saver and metered connections

If `navigator.connection.saveData` is true or the connection is metered, the Drop should not serve by default. The user can override this in their serving policy by setting `serveWhen: 'always'`, but the default protects casual Drop operators from unexpected cellular bills.

## 6. Micropayment ramping

The existing watermark payment model (README.md §21) advances a cumulative watermark on each request. For adaptive striped downloads, the ramping changes in two ways:

### 6.1 Pay after receipt, not on request

In the existing model, the Cloud signs a payment token before sending the `subtree/get` request. For adaptive downloads, the payment is split into two phases:

1. **Intent token (unsigned):** The initial request carries a payment intent — the Cloud's address and the current watermark — but no signature. The Jet/Drop serves the chunk on trust (bounded by `maxUnpaidChunks`, default 3).
2. **Settlement token (signed):** After the chunk is received and Merkle-verified, the Cloud signs a watermark advance covering all chunks received so far. The next request carries this signed token, settling the previous batch.

This means a Drop that never delivers a chunk never gets paid. A Drop that delivers 5 of 8 requested chunks gets paid for 5. The watermark only advances for verified deliveries.

### 6.2 Per-drop watermark channels

Instead of a single watermark line shared across all Drops, the adaptive model uses per-drop payment lines:

```
line 0: Jet infrastructure payment (existing)
line 1: Drop A — watermark for chunks served by Drop A
line 2: Drop B — watermark for chunks served by Drop B
...
```

Each Drop has its own monotonic watermark. This prevents a slow Drop from being subsidized by a fast one — each Drop's earnings are proportional to the chunks it actually delivered. The Jet settles each line independently.

### 6.3 Ramping schedule

For a new, untested Drop, the Cloud limits financial exposure:

| Phase | Chunks | Max unpaid |
|-------|--------|-----------|
| **Probe** | 1 | 1 chunk (intent only, no signature until delivered) |
| **Ramp-up** | 2–10 | 3 chunks ahead |
| **Steady state** | 11+ | 8 chunks ahead |
| **Trusted** | After 100 chunks with zero failures | 16 chunks ahead |

The `maxUnpaid` window is the maximum number of chunks the Cloud will request from a Drop without having received a signed settlement for the previous batch. A Drop that starts dropping chunks or slowing down gets fewer outstanding requests, which naturally throttles both bandwidth waste and payment risk.

## 7. Integration with existing code

### 7.1 Client.fetch changes

`Client.fetch` gains an `adaptive: true` option (default for files with `chunkCount > 16`). When enabled, the fetch pipeline delegates chunk retrieval to `AdaptiveStreamer` instead of requesting all chunks in a single `Promise.all`:

```javascript
var blob = await Q.Safecloud.Client.fetch(manifest, capability, {
    adaptive: true,               // enable adaptive drop selection
    maxParallelDrops: 8,          // probe up to 8 Drops initially
    onDropStats: function(stats) { /* per-drop throughput callback */ }
});
```

### 7.2 _prefetchLoop changes

The video prefetch loop already operates chunk-by-chunk, making it a natural fit. The `_frontier` variable already tracks which chunks have been requested. The change is that `_fetchSeg` routes through `AdaptiveStreamer.assignDrop(segIndex)` instead of letting the Jet pick a Drop at random for each request.

### 7.3 Router.selectForGet changes

`Router.selectForGet` gains an optional `drops` parameter. When the Cloud requests specific Drops (because AdaptiveStreamer ranked them), the Router respects that preference rather than doing its own weighted-random selection. The Router still applies safety filters (corrupt actor exclusion, offline checks, serving policy compliance).

### 7.4 Jets.get protocol extension

The `Safecloud/subtree/get` message gains optional fields:

```javascript
{
    rootCid: '...',
    link: [...],
    grants: [...],
    payments: [...],
    // New fields for adaptive selection:
    preferDrops: ['dropId1', 'dropId2'],  // client's preferred Drops
    paymentIntent: { payer: '0x...', watermark: '1000' }  // unsigned intent
}
```

## 8. Failure modes and recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Drop goes offline mid-download | Chunk timeout (8s default) | Reassign pending chunks to next-best Drop; demote to Slow |
| Drop switches to cellular | `Safecloud/drop/pause` message | Remove from candidates; reassign; re-add on `resume` |
| All Drops are slow | All throughputs below `minAcceptableBps` (default 50 KB/s) | Fall back to Jet relay (`Router.relayGet`); warn user |
| Drop serves corrupt chunks | Merkle verification fails | Remove from candidates permanently (CoC); do not pay |
| Drop serves correct chunks slowly | EMA drops below marginal threshold | Demote; reduce in-flight cap to 1; eventually cull |
| Payment dispute | Drop claims non-payment; Cloud claims non-delivery | On-chain settlement: watermark proves exactly which chunks were paid for |

## 9. Privacy considerations

Adaptive selection reveals per-Drop throughput to the Cloud client. This is not a new information leak — the client already knows which Drops serve which chunks. However, the continuous EMA tracking creates a more detailed performance profile of each Drop's network connection over time. Mitigations:

- Throughput data is ephemeral — held in memory for the duration of the download, not persisted.
- The client does not report per-Drop throughput to the Jet or any third party.
- Drop operators can see their own serving statistics in the drop dashboard but cannot see how other Drops performed.

## 10. Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `Safecloud.adaptive.enabled` | `null` (auto: true when chunkCount > 16) | Enable adaptive drop selection |
| `Safecloud.adaptive.probeTimeoutMs` | `8000` | Max time to wait for probe response |
| `Safecloud.adaptive.fastThreshold` | `0.5` | Ratio of best throughput to qualify as Fast |
| `Safecloud.adaptive.marginalThreshold` | `0.1` | Ratio of best throughput to qualify as Marginal |
| `Safecloud.adaptive.emaAlpha` | `0.3` | EMA smoothing factor for throughput |
| `Safecloud.adaptive.maxConcurrentPerDrop` | `3` | Max in-flight chunks per Drop |
| `Safecloud.adaptive.maxUnpaidChunks` | `3` | Max chunks requested before settlement |
| `Safecloud.adaptive.minAcceptableBps` | `51200` | 50 KB/s — below this, fall back to relay |
| `Safecloud.adaptive.maxParallelDrops` | `8` | Max Drops to probe simultaneously |
| `Safecloud.drop.serveWhen` | `'wifi-only'` | Default serving policy for new Drops |
| `Safecloud.drop.minBatteryPct` | `20` | Pause serving below this battery percentage |
| `Safecloud.drop.maxConcurrent` | `4` | Max parallel chunk serves per Drop |
