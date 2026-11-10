/**
 * Q.Safecloud.Chat.dag — DAG thread walker for chat messages.
 *
 * INNOVATION 9 — DAG Threading:
 *   Each message carries parentIds[] pointing to parent messages.  This forms
 *   a Directed Acyclic Graph (DAG) rather than a linear thread, allowing
 *   concurrent messages from multiple participants to be represented faithfully
 *   without forced linearization.
 *
 * This module provides utilities to work with the DAG:
 *   - roots(nodes)       — messages with no parents (conversation starters)
 *   - tips(nodes)        — messages not referenced as parent by any other node
 *   - topoSort(nodes)    — Kahn's topological sort, timestamp tie-breaking
 *   - thread(nodes)      — linear "best thread" via latest-tip + earliest-parent walk
 *   - fetchAll(cids, epochKey, epochIndex, options, callback)
 *                        — fetch all messages in a set, build DAG, return nodes
 *
 * Usage:
 *   var dag = Q.Safecloud.Chat.dag;
 *   var roots = dag.roots(nodes);
 *   var sorted = dag.topoSort(nodes);
 *   dag.fetchAll(cidList, epochKey, epochIndex, {drops}, callback)
 */

Q.exports(function (Q) {
    var Receive = Q.Safecloud.Chat.receive;

    // ── Pure helpers (no Q calls needed) ─────────────────────────────────────

    /**
     * roots(nodes) → string[]
     * Returns CIDs of messages that have no parents (conversation roots).
     */
    function roots(nodes) {
        return nodes
            .filter(function (n) { return !n.parentIds || n.parentIds.length === 0; })
            .map(function (n) { return n.cid; });
    }

    /**
     * tips(nodes) → string[]
     * Returns CIDs of messages that are not referenced as a parent by any
     * other message in the set (the "frontier" of the conversation).
     */
    function tips(nodes) {
        var referenced = {};
        nodes.forEach(function (n) {
            (n.parentIds || []).forEach(function (pid) { referenced[pid] = true; });
        });
        return nodes
            .filter(function (n) { return !referenced[n.cid]; })
            .map(function (n) { return n.cid; });
    }

    /**
     * topoSort(nodes) → Node[]
     * Kahn's topological sort over the DAG.  Tie-breaks by timestamp ascending.
     * Throws if a cycle is detected (should not happen in a valid chat).
     *
     * Each node must have: { cid, parentIds: string[], timestamp: number }
     * Returns the sorted array of nodes (not mutated).
     */
    function topoSort(nodes) {
        var byId   = {};
        var inDeg  = {};
        var children = {};   // parent cid → [child node]

        nodes.forEach(function (n) {
            byId[n.cid]      = n;
            inDeg[n.cid]     = 0;
            children[n.cid]  = [];
        });

        nodes.forEach(function (n) {
            (n.parentIds || []).forEach(function (pid) {
                if (!byId[pid]) { return; }  // parent not in set — ignore
                inDeg[n.cid]++;
                children[pid].push(n);
            });
        });

        // Initial queue: nodes with in-degree 0, sorted by timestamp
        var queue = nodes
            .filter(function (n) { return inDeg[n.cid] === 0; })
            .sort(function (a, b) { return a.timestamp - b.timestamp; });

        var result = [];
        while (queue.length > 0) {
            var node = queue.shift();
            result.push(node);
            var kids = (children[node.cid] || []).slice().sort(function (a, b) {
                return a.timestamp - b.timestamp;
            });
            kids.forEach(function (child) {
                inDeg[child.cid]--;
                if (inDeg[child.cid] === 0) {
                    // Insert into queue maintaining timestamp order
                    var inserted = false;
                    for (var i = 0; i < queue.length; i++) {
                        if (child.timestamp < queue[i].timestamp) {
                            queue.splice(i, 0, child);
                            inserted = true;
                            break;
                        }
                    }
                    if (!inserted) { queue.push(child); }
                }
            });
        }

        if (result.length !== nodes.length) {
            throw new Error('Chat.dag.topoSort: cycle detected in DAG');
        }
        return result;
    }

    /**
     * thread(nodes) → Node[]
     * Returns a linear "primary thread" through the DAG:
     *   Start from the latest-timestamp tip, walk backwards through earliest parents.
     * Useful for displaying a single main thread when branches exist.
     * Returns nodes in forward order (oldest first).
     */
    function thread(nodes) {
        if (!nodes || nodes.length === 0) { return []; }

        var byId = {};
        nodes.forEach(function (n) { byId[n.cid] = n; });

        // Find the tip with the highest timestamp
        var tipCids = tips(nodes);
        var latestTip = tipCids.reduce(function (best, cid) {
            var n = byId[cid];
            if (!best || (n && n.timestamp > best.timestamp)) { return n; }
            return best;
        }, null);

        if (!latestTip) { return nodes.slice(); }

        // Walk backwards from the tip, always picking the parent with the
        // lowest timestamp (earliest parent = "main line")
        var path = [];
        var visited = {};
        var cur = latestTip;
        while (cur && !visited[cur.cid]) {
            visited[cur.cid] = true;
            path.unshift(cur);
            var parents = (cur.parentIds || [])
                .map(function (pid) { return byId[pid]; })
                .filter(Boolean)
                .sort(function (a, b) { return a.timestamp - b.timestamp; });
            cur = parents[0] || null;
        }
        return path;
    }

    // ── Q-wired: fetch a set of CIDs, decrypt, build annotated nodes ──────────

    /**
     * fetchAll(cids, epochKey, epochIndex, options, callback)
     *
     * Fetches all messages in `cids`, decrypts each with the given epoch key,
     * and returns an array of annotated node objects ready for DAG operations:
     *   { cid, parentIds, timestamp, envelope }
     *
     * Missing CIDs (not found in Drops) are silently skipped.
     *
     * options:
     *   drops {Object} — override Drops module (for testing)
     *   onProgress {Function(done, total)} — progress callback
     *
     * callback(err, nodes)
     */
    function fetchAll(cids, epochKey, epochIndex, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        options = options || {};

        if (!cids || cids.length === 0) { return callback(null, []); }

        var total   = cids.length;
        var done    = 0;
        var results = [];
        var failed  = null;
        var pending = total;

        cids.forEach(function (cid) {
            Receive(cid, epochKey, epochIndex, { drops: options.drops }, function (err, env) {
                if (failed) { return; }  // already errored

                if (!err && env) {
                    results.push({
                        cid:       cid,
                        parentIds: env.parentIds || [],
                        timestamp: env.timestamp || 0,
                        envelope:  env
                    });
                }
                // Silently skip missing (env === null) or decrypt errors for now
                // (a later epoch key may be needed; caller handles via forward chain)

                done++;
                if (options.onProgress) { options.onProgress(done, total); }

                if (--pending === 0) {
                    callback(null, results);
                }
            });
        });
    }

    return {
        roots:    roots,
        tips:     tips,
        topoSort: topoSort,
        thread:   thread,
        fetchAll: fetchAll
    };
});
