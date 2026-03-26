/**
 * Q.Safecloud.Drops.getProllyRoot — return current Prolly root from in-memory state.
 * O(1) — no IndexedDB read needed.
 */
Q.exports(function (Q, _) {
    return function Q_Safecloud_Drops_getProllyRoot(callback) {
        var root = _._state.prollyRoot;
        if (callback) { callback(null, root); }
        return Promise.resolve(root);
    };
});
