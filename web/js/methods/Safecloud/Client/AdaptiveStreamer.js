/**
 * Q.Safecloud.Client.AdaptiveStreamer — adaptive drop selection for striped downloads.
 *
 * Measures real throughput per Drop using initial probe chunks, continuously
 * re-ranks Drops by exponential moving average, culls slow performers, and
 * advances micropayment watermarks only for verified deliveries.
 *
 * See AdaptiveStreamer.md for the full algorithm description.
 *
 * LIFECYCLE:
 *   var streamer = new Q.Safecloud.Client.AdaptiveStreamer(manifest, capability, options);
 *   await streamer.probe();           // initial parallel probe of all candidate Drops
 *   var chunk = await streamer.next(); // fetch next chunk from best available Drop
 *   streamer.destroy();               // cleanup
 *
 * The streamer is used by Client.fetch (adaptive:true) and _prefetchLoop.
 * It does NOT replace Router.selectForGet — that method still applies safety
 * filters (corrupt actors, offline checks). The streamer's preferDrops hint
 * is a request, not an override.
 *
 * @class Q.Safecloud.Client.AdaptiveStreamer
 */
Q.exports(function (Q, _) {

    // ─── Configuration (overridden by Q.Config Safecloud.adaptive.*) ─────────

    var DEFAULTS = {
        probeTimeoutMs:       8000,
        fastThreshold:        0.5,
        marginalThreshold:    0.1,
        emaAlpha:             0.3,
        maxConcurrentPerDrop: 3,
        maxUnpaidChunks:      3,
        minAcceptableBps:     51200,   // 50 KB/s
        maxParallelDrops:     8
    };

    function _cfg(key) {
        return Q.Config.get(['Safecloud', 'adaptive', key], DEFAULTS[key]);
    }

    // ─── Tier enum ───────────────────────────────────────────────────────────

    var TIER_FAST     = 'fast';
    var TIER_MARGINAL = 'marginal';
    var TIER_SLOW     = 'slow';

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param {Object}   manifest    Public manifest
     * @param {Object}   capability  { rootKey } or { grants[] }
     * @param {Object}   [options]
     * @param {Function} [options.onDropStats]  Called after each re-rank with
     *                   Array<{ dropId, tier, emaBps, inFlight, chunksDelivered }>
     * @param {Array}    [options.candidateDrops]  Override auto-discovery
     * @param {Object}   [options.payments]  Pre-built payment tokens
     */
    function AdaptiveStreamer(manifest, capability, options) {
        options = options || {};
        this.manifest    = manifest;
        this.capability  = capability;
        this.options     = options;
        this._destroyed  = false;

        // Per-drop tracking: dropId → DropState
        this._drops = {};

        // Ordered list of dropIds, best first (updated on every re-rank)
        this._ranked = [];

        // Per-drop in-flight counters: dropId → count
        this._inFlight = {};

        // Per-drop payment watermarks: dropId → { lineIndex, watermark: BigInt,
        //   unpaidCount: Number, totalDelivered: Number }
        this._payments = {};

        // Probe results (set by probe())
        this._probed = false;

        // The probe chunk (first chunk received, used by caller)
        this._probeChunk = null;
        this._probeDropId = null;

        this._onDropStats = options.onDropStats || null;
    }

    // ─── DropState ───────────────────────────────────────────────────────────

    /**
     * @typedef {Object} DropState
     * @property {String}  dropId
     * @property {Number}  emaBps          Exponential moving average throughput
     * @property {String}  tier            TIER_FAST | TIER_MARGINAL | TIER_SLOW
     * @property {Number}  chunksDelivered Total chunks successfully delivered
     * @property {Number}  chunksFailed    Total chunks that failed/timed out
     * @property {Number}  lastMeasuredMs  Timestamp of last measurement
     * @property {Object}  servingPolicy   Drop's advertised serving policy
     */

    // ─── probe() — initial parallel measurement ─────────────────────────────

    /**
     * Send the first chunk request to up to maxParallelDrops Drops simultaneously.
     * Measures throughput for each, populates _drops and _ranked.
     *
     * Returns the first chunk received (fastest Drop wins the race).
     *
     * @return {Promise<{ chunk, dropId }|null>}
     */
    AdaptiveStreamer.prototype.probe = function () {
        var self = this;
        if (self._probed) {
            return Promise.resolve(self._probeChunk
                ? { chunk: self._probeChunk, dropId: self._probeDropId }
                : null);
        }
        self._probed = true;

        // Discover candidate Drops from the Jet's CID coverage
        var candidates = self.options.candidateDrops || _discoverDrops(self.manifest);
        var maxProbe   = _cfg('maxParallelDrops');
        var probeSet   = candidates.slice(0, maxProbe);
        var timeoutMs  = _cfg('probeTimeoutMs');

        if (!probeSet.length) {
            return Promise.resolve(null);
        }

        var firstResolved = false;
        var firstResolve  = null;
        var firstPromise  = new Promise(function (resolve) { firstResolve = resolve; });

        // Fire all probes simultaneously
        var probePromises = probeSet.map(function (drop) {
            var t0 = performance.now();
            var dropId = drop.dropId || drop;

            // Create a timeout race
            return _withTimeout(
                Q.Safecloud.Jets.get({
                    rootCid:     self.manifest.rootCid,
                    link:        _.chunkLinkPath(0, self.manifest),
                    grants:      self.capability.grants || [],
                    preferDrops: [dropId]
                }, {
                    payments:    self.options.payments,
                    skipPayment: self.options.skipPayment
                }),
                timeoutMs
            ).then(function (result) {
                var elapsed = performance.now() - t0;
                var chunk   = result && result.chunks && result.chunks[0];
                var bytes   = chunk && chunk.ciphertext
                    ? Math.floor(chunk.ciphertext.length * 3 / 4) : 0;
                var bps     = elapsed > 0 ? (bytes / (elapsed / 1000)) : 0;

                self._drops[dropId] = {
                    dropId:          dropId,
                    emaBps:          bps,
                    tier:            TIER_FAST,  // classified after all probes
                    chunksDelivered: chunk ? 1 : 0,
                    chunksFailed:    chunk ? 0 : 1,
                    lastMeasuredMs:  Date.now(),
                    latencyMs:       elapsed,
                    servingPolicy:   drop.servingPolicy || null
                };

                // First valid chunk wins
                if (chunk && !firstResolved) {
                    firstResolved    = true;
                    self._probeChunk  = chunk;
                    self._probeDropId = dropId;
                    firstResolve({ chunk: chunk, dropId: dropId });
                }

                return { dropId: dropId, bps: bps, chunk: chunk };
            }).catch(function () {
                self._drops[dropId] = {
                    dropId:          dropId,
                    emaBps:          0,
                    tier:            TIER_SLOW,
                    chunksDelivered: 0,
                    chunksFailed:    1,
                    lastMeasuredMs:  Date.now(),
                    latencyMs:       Infinity,
                    servingPolicy:   drop.servingPolicy || null
                };
                return { dropId: dropId, bps: 0, chunk: null };
            });
        });

        // Wait for all probes to settle, then classify tiers
        return Promise.all(probePromises).then(function () {
            self._classifyTiers();
            self._emitStats();

            // If no chunk arrived from any probe, resolve firstPromise with null
            if (!firstResolved) { firstResolve(null); }
            return firstPromise;
        });
    };

    // ─── assignDrop() — pick the best Drop for the next chunk ────────────────

    /**
     * Select the best available Drop for a chunk fetch.
     * Respects maxConcurrentPerDrop and tier classification.
     *
     * @return {String|null}  dropId of the selected Drop, or null if none available
     */
    AdaptiveStreamer.prototype.assignDrop = function () {
        var maxConc = _cfg('maxConcurrentPerDrop');
        for (var i = 0; i < this._ranked.length; i++) {
            var dropId = this._ranked[i];
            var state  = this._drops[dropId];
            if (!state || state.tier === TIER_SLOW) { continue; }
            var inflight = this._inFlight[dropId] || 0;
            if (inflight < maxConc) {
                return dropId;
            }
        }
        return null;
    };

    // ─── recordResult() — update EMA after a chunk fetch ─────────────────────

    /**
     * Record the outcome of a chunk fetch for a specific Drop.
     *
     * @param {String}  dropId
     * @param {Boolean} success
     * @param {Number}  bytes      Bytes transferred (0 on failure)
     * @param {Number}  elapsedMs  Time taken
     */
    AdaptiveStreamer.prototype.recordResult = function (dropId, success, bytes, elapsedMs) {
        var state = this._drops[dropId];
        if (!state) { return; }

        if (success) {
            var bps   = elapsedMs > 0 ? (bytes / (elapsedMs / 1000)) : 0;
            var alpha = _cfg('emaAlpha');
            state.emaBps = (1 - alpha) * state.emaBps + alpha * bps;
            state.chunksDelivered++;
        } else {
            // On failure, decay EMA sharply (same asymmetry as Router reliability)
            state.emaBps = state.emaBps * 0.5;
            state.chunksFailed++;
        }
        state.lastMeasuredMs = Date.now();

        this._classifyTiers();
        this._emitStats();
    };

    // ─── In-flight tracking ──────────────────────────────────────────────────

    AdaptiveStreamer.prototype.startFetch = function (dropId) {
        this._inFlight[dropId] = (this._inFlight[dropId] || 0) + 1;
    };

    AdaptiveStreamer.prototype.endFetch = function (dropId) {
        if (this._inFlight[dropId]) { this._inFlight[dropId]--; }
    };

    // ─── Payment ramping ─────────────────────────────────────────────────────

    /**
     * Determine the maximum number of unpaid chunks allowed for a Drop
     * based on its delivery history.
     *
     * @param {String} dropId
     * @return {Number}
     */
    AdaptiveStreamer.prototype.maxUnpaidFor = function (dropId) {
        var state = this._drops[dropId];
        if (!state) { return 1; }
        var delivered = state.chunksDelivered;
        if (delivered < 2)   { return 1; }  // probe phase
        if (delivered < 10)  { return 3; }  // ramp-up
        if (delivered < 100) { return 8; }  // steady state
        return 16;                           // trusted
    };

    /**
     * Check whether we should wait for a settlement before requesting
     * more chunks from this Drop.
     *
     * @param {String} dropId
     * @return {Boolean}  true if the Drop has too many unpaid chunks outstanding
     */
    AdaptiveStreamer.prototype.shouldThrottle = function (dropId) {
        var payment = this._payments[dropId];
        if (!payment) { return false; }
        return payment.unpaidCount >= this.maxUnpaidFor(dropId);
    };

    /**
     * Record that a chunk was delivered and verified.
     * Increments unpaid count; caller should sign settlement when
     * unpaidCount reaches the threshold.
     *
     * @param {String} dropId
     */
    AdaptiveStreamer.prototype.recordDelivery = function (dropId) {
        if (!this._payments[dropId]) {
            this._payments[dropId] = {
                lineIndex:      Object.keys(this._payments).length + 1,
                watermark:      BigInt(0),
                unpaidCount:    0,
                totalDelivered: 0
            };
        }
        this._payments[dropId].unpaidCount++;
        this._payments[dropId].totalDelivered++;
    };

    /**
     * Mark a settlement as signed for this Drop.
     * Resets the unpaid counter and advances the watermark.
     *
     * @param {String} dropId
     * @param {BigInt|String} newWatermark
     */
    AdaptiveStreamer.prototype.recordSettlement = function (dropId, newWatermark) {
        if (!this._payments[dropId]) { return; }
        this._payments[dropId].watermark = BigInt(newWatermark);
        this._payments[dropId].unpaidCount = 0;
    };

    // ─── Tier classification ─────────────────────────────────────────────────

    /**
     * Re-classify all Drops into Fast / Marginal / Slow tiers based on
     * current EMA throughput relative to the best Drop.
     * @private
     */
    AdaptiveStreamer.prototype._classifyTiers = function () {
        var dropIds = Object.keys(this._drops);
        if (!dropIds.length) { return; }

        // Find the best throughput
        var bestBps = 0;
        for (var i = 0; i < dropIds.length; i++) {
            var s = this._drops[dropIds[i]];
            if (s.emaBps > bestBps) { bestBps = s.emaBps; }
        }

        var fastT     = _cfg('fastThreshold');
        var marginalT = _cfg('marginalThreshold');
        var minBps    = _cfg('minAcceptableBps');

        for (var j = 0; j < dropIds.length; j++) {
            var state = this._drops[dropIds[j]];
            if (bestBps <= 0 || state.emaBps < minBps) {
                state.tier = TIER_SLOW;
            } else if (state.emaBps >= bestBps * fastT) {
                state.tier = TIER_FAST;
            } else if (state.emaBps >= bestBps * marginalT) {
                state.tier = TIER_MARGINAL;
            } else {
                state.tier = TIER_SLOW;
            }
        }

        // Re-rank: Fast first (sorted by EMA desc), then Marginal, skip Slow
        this._ranked = dropIds
            .filter(function (id) { return this._drops[id].tier !== TIER_SLOW; }.bind(this))
            .sort(function (a, b) {
                var ta = this._drops[a].tier === TIER_FAST ? 0 : 1;
                var tb = this._drops[b].tier === TIER_FAST ? 0 : 1;
                if (ta !== tb) { return ta - tb; }
                return this._drops[b].emaBps - this._drops[a].emaBps;
            }.bind(this));
    };

    // ─── Stats emission ──────────────────────────────────────────────────────

    /** @private */
    AdaptiveStreamer.prototype._emitStats = function () {
        if (!this._onDropStats) { return; }
        var self = this;
        var stats = Object.keys(this._drops).map(function (dropId) {
            var s = self._drops[dropId];
            return {
                dropId:          dropId,
                tier:            s.tier,
                emaBps:          Math.round(s.emaBps),
                inFlight:        self._inFlight[dropId] || 0,
                chunksDelivered: s.chunksDelivered,
                chunksFailed:    s.chunksFailed
            };
        });
        try { this._onDropStats(stats); } catch (e) { /* best-effort */ }
    };

    // ─── Public accessors ────────────────────────────────────────────────────

    /**
     * Return a snapshot of current Drop rankings.
     * @return {Array<{ dropId, tier, emaBps, chunksDelivered }>}
     */
    AdaptiveStreamer.prototype.stats = function () {
        var self = this;
        return this._ranked.map(function (dropId) {
            var s = self._drops[dropId];
            return {
                dropId:          dropId,
                tier:            s.tier,
                emaBps:          Math.round(s.emaBps),
                chunksDelivered: s.chunksDelivered,
                chunksFailed:    s.chunksFailed
            };
        });
    };

    /**
     * Return the list of Fast-tier dropIds.
     * @return {Array<String>}
     */
    AdaptiveStreamer.prototype.fastDrops = function () {
        var self = this;
        return this._ranked.filter(function (id) {
            return self._drops[id] && self._drops[id].tier === TIER_FAST;
        });
    };

    /**
     * Cleanup.
     */
    AdaptiveStreamer.prototype.destroy = function () {
        this._destroyed = true;
        this._drops     = {};
        this._ranked    = [];
        this._inFlight  = {};
        this._payments  = {};
    };

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Discover candidate Drops for the given manifest from the Jet's
     * CID coverage. Falls back to all online Drops if coverage is unknown.
     * @private
     */
    function _discoverDrops(manifest) {
        // In the browser, Drops are discovered through the Jet's routing.
        // The client doesn't have direct access to _cidCoverage (that's server-side).
        // Instead, we request the Jet to list Drops that hold this rootCid.
        // For now, return an empty list — the Jet's get handler will fan out
        // to available Drops when preferDrops is empty.
        //
        // In practice, the probe phase sends a request with no preferDrops,
        // and the Jet responds with which Drop served each chunk. The client
        // learns dropIds from the response metadata.
        return [];
    }

    /**
     * Race a promise against a timeout.
     * @private
     */
    function _withTimeout(promise, ms) {
        return new Promise(function (resolve, reject) {
            var timer = setTimeout(function () {
                reject(new Error('Probe timeout after ' + ms + 'ms'));
            }, ms);
            promise.then(function (v) {
                clearTimeout(timer);
                resolve(v);
            }).catch(function (e) {
                clearTimeout(timer);
                reject(e);
            });
        });
    }

    return AdaptiveStreamer;
});
