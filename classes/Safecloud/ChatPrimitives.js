/**
 * Safecloud.ChatPrimitives — Pure functions for chat key-tree primitives.
 *
 * This module has ZERO dependencies on Q, the browser, or any external library.
 * Every function here is a pure JS function so it can be tested directly in
 * Node.js without any shims.
 *
 * These are the same algorithms implemented in Client/_internal.js as _.timePath,
 * _.isoWeek, _.timePathsForRange, _.dagAddParents, etc.  The _internal.js versions
 * call Q.Crypto.delegate; this module only computes label paths and DAG structure
 * so we can verify the math independently of the crypto layer.
 *
 * Consumers outside of tests should call the Q-wired versions in _internal.js.
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// LABEL CONSTANTS (must stay in sync with _internal.js _.LABELS)
// ─────────────────────────────────────────────────────────────────────────────

var LABELS = {
    encryptionRoot: 'safecloud.encryption.root',
    accessRoot:     'safecloud.access.root',
    chatRoot:       'safecloud.chat',
    timeRoot:       'safecloud.chat.time',
    topicRoot:      'safecloud.chat.topic',

    chatThread: function (id)  { return 'safecloud.chat.thread.' + id; },
    epoch:      function (i)   { return 'safecloud.chat.epoch.'  + i;  },
    timeYear:   function (y)   { return 'safecloud.time.year.'   + y;  },
    timeQuarter:function (q)   { return 'safecloud.time.quarter.'+ q;  },
    timeMonth:  function (m)   { return 'safecloud.time.month.'  + String(m).padStart(2, '0'); },
    timeWeek:   function (w)   { return 'safecloud.time.week.'   + String(w).padStart(2, '0'); },
    timeDay:    function (d)   { return 'safecloud.time.day.'    + String(d).padStart(2, '0'); },
    topic:      function (seg) { return 'safecloud.topic.'       + seg; }
};

// ─────────────────────────────────────────────────────────────────────────────
// ISO-8601 WEEK NUMBER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * isoWeek(date) → Number 1–53
 * Returns the ISO 8601 week number for the given Date (UTC).
 * Week 1 is the first week that contains a Thursday.
 * Monday is the first day of the week.
 */
function isoWeek(date) {
    var d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
    var day = d.getUTCDay() || 7;        // Sunday(0) → 7
    d.setUTCDate(d.getUTCDate() + 4 - day);
    var yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
}

// ─────────────────────────────────────────────────────────────────────────────
// TIME PATH
// ─────────────────────────────────────────────────────────────────────────────

/**
 * timePath(date, granularity) → Array<string>
 *
 * Returns the ordered list of HKDF labels needed to derive the key for
 * the given date at the specified granularity.  Granularity choices:
 *   'year', 'quarter', 'month', 'week', 'day'  (default: 'day')
 *
 * The first element is always LABELS.timeRoot ('safecloud.chat.time').
 * Each subsequent element is the label for that calendar level.
 *
 * Example:
 *   timePath(new Date('2026-03-15'), 'month')
 *   → ['safecloud.chat.time',
 *       'safecloud.time.year.2026',
 *       'safecloud.time.quarter.1',
 *       'safecloud.time.month.03']
 */
function timePath(date, granularity) {
    granularity = granularity || 'day';
    var d  = (date instanceof Date) ? date : new Date(date);
    var y  = d.getUTCFullYear();
    var m  = d.getUTCMonth() + 1;         // 1–12
    var q  = Math.ceil(m / 3);            // 1–4
    var dy = d.getUTCDate();              // 1–31
    var w  = isoWeek(d);

    var path = [LABELS.timeRoot, LABELS.timeYear(y)];

    if (granularity === 'year')    { return path; }
    path.push(LABELS.timeQuarter(q));
    if (granularity === 'quarter') { return path; }

    // ISO weeks span month boundaries, so week branches directly from quarter.
    // Month branches from quarter independently (a parallel sub-tree).
    if (granularity === 'week') {
        path.push(LABELS.timeWeek(w));
        return path;
    }

    path.push(LABELS.timeMonth(m));
    if (granularity === 'month')   { return path; }
    // 'day' — append day of month (within month path, not week path)
    path.push(LABELS.timeDay(dy));
    return path;
}

// ─────────────────────────────────────────────────────────────────────────────
// TIME PATHS FOR RANGE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * timePathsForRange(startDate, endDate, granularity) → Array<Array<string>>
 *
 * Returns the de-duplicated list of time paths (at the given granularity)
 * covering every calendar unit between startDate and endDate (inclusive).
 *
 * This is the temporal equivalent of _pathsCoveringRange in grant.js.
 * For monthly granularity it returns one path per month spanned.
 * For daily granularity it returns one path per day spanned.
 */
function timePathsForRange(startDate, endDate, granularity) {
    granularity = granularity || 'day';
    var paths = [];
    var cursor = new Date(Date.UTC(
        startDate.getUTCFullYear(),
        startDate.getUTCMonth(),
        startDate.getUTCDate()
    ));
    var end = new Date(Date.UTC(
        endDate.getUTCFullYear(),
        endDate.getUTCMonth(),
        endDate.getUTCDate()
    ));

    var seen = {};
    while (cursor <= end) {
        var p   = timePath(cursor, granularity);
        var key = p.join('|');
        if (!seen[key]) {
            seen[key] = true;
            paths.push(p);
        }
        cursor.setUTCDate(cursor.getUTCDate() + 1);
    }
    return paths;
}

// ─────────────────────────────────────────────────────────────────────────────
// TOPIC PATH
// ─────────────────────────────────────────────────────────────────────────────

/**
 * topicPath(segments) → Array<string>
 *
 * Returns the ordered list of HKDF labels needed to derive the key for a
 * topic path.  First element is LABELS.topicRoot.
 *
 * Example:
 *   topicPath(['engineering', 'backend'])
 *   → ['safecloud.chat.topic', 'safecloud.topic.engineering', 'safecloud.topic.backend']
 */
function topicPath(segments) {
    if (!segments || !segments.length) {
        throw new Error('topicPath: segments must be non-empty array');
    }
    return [LABELS.topicRoot].concat(
        segments.map(function (seg) { return LABELS.topic(seg); })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG OPERATIONS (Innovation 9 — DAG threading)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * DagNode — a lightweight immutable node in the message DAG.
 *
 * {
 *   cid:       string        — content-addressed ID (SHA-256 of ciphertext)
 *   parentIds: Array<string> — CIDs of parent messages (empty for roots)
 *   timestamp: Number        — Unix ms (UTC)
 * }
 */

/**
 * dagRoots(nodes) → Array<string>
 * Returns CIDs of nodes with no parents (conversation starters).
 */
function dagRoots(nodes) {
    var allParents = {};
    nodes.forEach(function (n) {
        (n.parentIds || []).forEach(function (p) { allParents[p] = true; });
    });
    return nodes
        .filter(function (n) { return !(n.parentIds && n.parentIds.length); })
        .map(function (n) { return n.cid; });
}

/**
 * dagTips(nodes) → Array<string>
 * Returns CIDs of nodes that are not the parent of any other node.
 * These are the "latest" messages — the heads of the DAG.
 */
function dagTips(nodes) {
    var allParents = {};
    nodes.forEach(function (n) {
        (n.parentIds || []).forEach(function (p) { allParents[p] = true; });
    });
    return nodes
        .filter(function (n) { return !allParents[n.cid]; })
        .map(function (n) { return n.cid; });
}

/**
 * dagTopoSort(nodes) → Array<DagNode>
 *
 * Topological sort (Kahn's algorithm).  Parents always come before children.
 * Ties within the same depth are broken by timestamp (ascending).
 * Throws if the graph contains a cycle.
 */
function dagTopoSort(nodes) {
    var byId   = {};
    var inDeg  = {};
    var children = {};

    nodes.forEach(function (n) {
        byId[n.cid]      = n;
        inDeg[n.cid]     = inDeg[n.cid] || 0;
        children[n.cid]  = children[n.cid] || [];
    });

    nodes.forEach(function (n) {
        (n.parentIds || []).forEach(function (p) {
            inDeg[n.cid] = (inDeg[n.cid] || 0) + 1;
            if (!children[p]) { children[p] = []; }
            children[p].push(n.cid);
        });
    });

    // Initial queue: nodes with no unresolved parents
    var queue = nodes
        .filter(function (n) { return !inDeg[n.cid]; })
        .sort(function (a, b) { return a.timestamp - b.timestamp; });

    var result = [];
    while (queue.length) {
        var node = queue.shift();
        result.push(node);
        (children[node.cid] || []).forEach(function (childId) {
            inDeg[childId]--;
            if (inDeg[childId] === 0) {
                queue.push(byId[childId]);
                queue.sort(function (a, b) { return a.timestamp - b.timestamp; });
            }
        });
    }

    if (result.length !== nodes.length) {
        throw new Error('dagTopoSort: cycle detected in DAG');
    }
    return result;
}

/**
 * dagThread(nodes) → Array<DagNode>
 *
 * Returns a linear "best thread" through the DAG.  Where the DAG branches
 * (merge commits or concurrent messages), the branch with the earliest tip
 * timestamp is preferred.  This matches the transcript a deniable chat client
 * would display as the "main" thread.
 */
function dagThread(nodes) {
    var sorted = dagTopoSort(nodes);
    if (!sorted.length) { return []; }

    var byId = {};
    sorted.forEach(function (n) { byId[n.cid] = n; });

    // Walk from the last node back to a root following the first (earliest) parent
    var tips   = dagTips(nodes);
    // Pick the tip with the latest timestamp as the "end" of the thread
    var tip = tips.reduce(function (best, cid) {
        var n = byId[cid];
        return (!best || (n && n.timestamp > best.timestamp)) ? n : best;
    }, null);

    if (!tip) { return sorted; }

    var thread = [];
    var visited = {};
    var current = tip;
    while (current) {
        if (visited[current.cid]) { break; }
        visited[current.cid] = true;
        thread.push(current);
        // Follow first (earliest) parent
        var parentIds = current.parentIds || [];
        current = parentIds.length
            ? byId[parentIds[0]]
            : null;
    }
    thread.reverse();
    return thread;
}

// ─────────────────────────────────────────────────────────────────────────────
// FORWARD CHAIN HELPERS (Innovation 2.5)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * forwardChainMessage(epochKey, nextEpochKeyEncrypted, metadata) → Object
 *
 * Constructs a forward-chain message object — a special encrypted control
 * message that tells holders of epoch key N where to find epoch key N+1.
 * The actual encryption is done by the caller using the existing Drops/Streams
 * infrastructure; this function just builds the plaintext payload.
 *
 * {
 *   type:                'Safecloud/chat/forwardChain',
 *   epochIndex:          Number,       — current epoch (N)
 *   nextEpochIndex:      Number,       — next epoch (N+1)
 *   nextEpochKeyCid:     string,       — CID of the Drop containing epoch key N+1
 *   threadId:            string,       — thread this forward chain belongs to
 *   timestamp:           Number        — Unix ms
 * }
 */
function forwardChainMessage(epochIndex, nextEpochKeyCid, threadId) {
    return {
        type:            'Safecloud/chat/forwardChain',
        epochIndex:      epochIndex,
        nextEpochIndex:  epochIndex + 1,
        nextEpochKeyCid: nextEpochKeyCid,
        threadId:        threadId,
        timestamp:       Date.now()
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE ENVELOPE (Innovation 6 — transcript simulability / deniability)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * messageEnvelope(text, threadId, epochIndex, parentIds, senderHint) → Object
 *
 * Builds the plaintext message envelope before encryption.
 * No per-message signatures — deniability comes from the shared symmetric
 * epoch key: any holder could have produced this ciphertext.
 *
 * The senderHint is advisory only and NOT cryptographically authenticated;
 * recipients trust it only as long as they trust the epoch key was not leaked.
 *
 * {
 *   type:        'Safecloud/chat/message',
 *   threadId:    string,
 *   epochIndex:  Number,
 *   parentIds:   Array<string>,   — CIDs of parent messages (DAG edges)
 *   text:        string,
 *   senderHint:  string | null,   — advisory sender identifier (not signed)
 *   timestamp:   Number           — Unix ms
 * }
 */
function messageEnvelope(text, threadId, epochIndex, parentIds, senderHint) {
    return {
        type:       'Safecloud/chat/message',
        threadId:   threadId,
        epochIndex: epochIndex,
        parentIds:  parentIds || [],
        text:       text,
        senderHint: senderHint || null,
        timestamp:  Date.now()
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
    LABELS:             LABELS,
    isoWeek:            isoWeek,
    timePath:           timePath,
    timePathsForRange:  timePathsForRange,
    topicPath:          topicPath,
    dagRoots:           dagRoots,
    dagTips:            dagTips,
    dagTopoSort:        dagTopoSort,
    dagThread:          dagThread,
    forwardChainMessage: forwardChainMessage,
    messageEnvelope:    messageEnvelope
};
