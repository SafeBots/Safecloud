"use strict";
/**
 * Repo — versioned directory with branch/merge/diff, built on TreeStore.
 *
 * A repo consists of:
 *   - A working tree (KV mode) — the current file state
 *   - A commit log (append-only) — history of snapshots
 *   - A branches tree (KV mode) — branch names → commit CIDs
 *
 * Each commit records the working tree's root CID, parent commit(s),
 * author, message, and timestamp.
 *
 * Git analog: versioned file trees with branching and merging.
 *
 * @module data/Repo
 */

class Repo {
    /**
     * @param {TreeStore} store
     * @param {string} name
     * @param {object} [opts]
     * @param {string} [opts.author] — default author for commits
     */
    constructor(store, name, opts) {
        this._store = store;
        this._name = name;
        this._author = (opts && opts.author) || 'anonymous';

        // Working tree: current file state
        const wt = store.createTree('repo:' + name + ':worktree', { mode: 'kv' });
        this._worktreeId = wt.treeId;

        // Commit log: append-only history
        const cl = store.createTree('repo:' + name + ':commits', { mode: 'append' });
        this._commitsId = cl.treeId;

        // Branches: name → { commitIndex, treeCid }
        const br = store.createTree('repo:' + name + ':branches', { mode: 'kv' });
        this._branchesId = br.treeId;

        this._currentBranch = 'main';
        this._headCommitIndex = -1;
    }

    /**
     * Add (stage) a file.
     * @param {string} path
     * @param {*} content — any serialisable value
     */
    add(path, content) {
        this._store.put(this._worktreeId, path, content);
    }

    /**
     * Remove a file from the working tree.
     * @param {string} path
     * @returns {boolean}
     */
    remove(path) {
        return this._store.delete(this._worktreeId, path);
    }

    /**
     * Get a file from the working tree.
     * @param {string} path
     * @returns {*} content or null
     */
    getFile(path) {
        const result = this._store.get(this._worktreeId, path);
        return result ? result.value : null;
    }

    /**
     * List files in the working tree.
     * @param {string} [prefix]
     * @returns {Array<{ path: string, content: * }>}
     */
    listFiles(prefix) {
        const opts = {};
        if (prefix) {
            opts.gte = prefix;
            opts.lt = prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
        }
        return this._store.range(this._worktreeId, opts).map(e => ({ path: e.key, content: e.value }));
    }

    /**
     * Create a commit from the current working tree state.
     * @param {string} message
     * @param {object} [opts]
     * @param {string} [opts.author]
     * @param {Array<number>} [opts.parents] — override parent commit indexes (for merges)
     * @returns {{ commitIndex: number, treeCid: string, commitsCid: string }}
     */
    commit(message, opts) {
        const treeCid = this._store.checkpoint(this._worktreeId);
        const parents = (opts && opts.parents)
            ? opts.parents
            : (this._headCommitIndex >= 0 ? [this._headCommitIndex] : []);

        const commit = {
            treeCid: treeCid,
            parents: parents,
            message: message,
            author: (opts && opts.author) || this._author,
            timestamp: Date.now()
        };

        const { index } = this._store.append(this._commitsId, commit);
        this._headCommitIndex = index;

        // Update branch pointer
        this._store.put(this._branchesId, this._currentBranch, {
            commitIndex: index,
            treeCid: treeCid
        });

        return {
            commitIndex: index,
            treeCid: treeCid,
            commitsCid: this._store.root(this._commitsId)
        };
    }

    /**
     * Get commit history.
     * @param {object} [opts]
     * @param {number} [opts.limit] — max commits to return
     * @returns {Array<{ index: number, treeCid: string, parents: number[], message: string, author: string, timestamp: number }>}
     */
    log(opts) {
        const limit = (opts && opts.limit) || undefined;
        const commits = [];
        let idx = this._headCommitIndex;
        while (idx >= 0) {
            const result = this._store.get(this._commitsId, idx);
            if (!result) break;
            commits.push({ index: idx, ...result.value });
            if (limit && commits.length >= limit) break;
            // Follow first parent (linear history)
            idx = result.value.parents.length > 0 ? result.value.parents[0] : -1;
        }
        return commits;
    }

    /**
     * Diff two commits (by their tree CIDs).
     * Both commits must have been checkpointed.
     * @param {string} treeCidA
     * @param {string} treeCidB
     * @returns {Array<{ path: string, type: string, before: *, after: * }>}
     */
    diff(treeCidA, treeCidB) {
        const changes = this._store.diff(treeCidA, treeCidB);
        return changes.map(c => ({
            path: c.key,
            type: c.before === null ? 'added' : c.after === null ? 'removed' : 'modified',
            before: c.before,
            after: c.after
        }));
    }

    /**
     * Create a new branch at the current HEAD.
     * @param {string} name
     */
    branch(name) {
        const treeCid = this._store.checkpoint(this._worktreeId);
        this._store.put(this._branchesId, name, {
            commitIndex: this._headCommitIndex,
            treeCid: treeCid
        });
    }

    /**
     * Switch to a branch, restoring its working tree state.
     * @param {string} name
     */
    checkout(name) {
        const result = this._store.get(this._branchesId, name);
        if (!result) throw new Error(`Branch not found: ${name}`);

        const branchInfo = result.value;
        this._currentBranch = name;
        this._headCommitIndex = branchInfo.commitIndex;

        // Restore working tree from the branch's tree CID
        const { treeId } = this._store.hydrate(branchInfo.treeCid);
        this._worktreeId = treeId;
    }

    /**
     * List all branches.
     * @returns {Array<{ name: string, commitIndex: number, treeCid: string }>}
     */
    getBranches() {
        const entries = this._store.range(this._branchesId, {});
        return entries.map(e => ({
            name: e.key,
            commitIndex: e.value.commitIndex,
            treeCid: e.value.treeCid
        }));
    }

    /**
     * Get the current branch name.
     * @returns {string}
     */
    get currentBranch() {
        return this._currentBranch;
    }

    /**
     * Get the current HEAD commit index.
     * @returns {number}
     */
    get head() {
        return this._headCommitIndex;
    }

    /**
     * Merge another branch into the current branch.
     * Uses last-writer-wins by default. Returns conflicts for manual resolution
     * when strategy is 'manual'.
     *
     * @param {string} branchName — source branch
     * @param {object} [opts]
     * @param {string} [opts.strategy='lww'] — 'lww' (last-writer-wins) or 'manual'
     * @param {string} [opts.message]
     * @returns {{ commitIndex: number, conflicts: Array<{ path: string, ours: *, theirs: * }> }}
     */
    merge(branchName, opts) {
        const strategy = (opts && opts.strategy) || 'lww';
        const branchResult = this._store.get(this._branchesId, branchName);
        if (!branchResult) throw new Error(`Branch not found: ${branchName}`);

        const theirTreeCid = branchResult.value.treeCid;
        const theirCommitIndex = branchResult.value.commitIndex;
        const ourTreeCid = this._store.checkpoint(this._worktreeId);

        // Get both trees' contents
        const { treeId: theirTreeId } = this._store.hydrate(theirTreeCid);
        const theirFiles = this._store.range(theirTreeId, {});

        // Find the common ancestor (simplified: first shared parent in commit log)
        // For now, just diff ours vs theirs directly
        const changes = this._store.diff(ourTreeCid, theirTreeCid);

        const conflicts = [];

        for (const change of changes) {
            if (strategy === 'lww') {
                // Last writer wins: take theirs if they changed it
                if (change.after !== null) {
                    this._store.put(this._worktreeId, change.key, change.after);
                } else {
                    this._store.delete(this._worktreeId, change.key);
                }
            } else if (strategy === 'manual') {
                // Report conflicts for files that exist in both
                if (change.before !== null && change.after !== null) {
                    conflicts.push({
                        path: change.key,
                        ours: change.before,
                        theirs: change.after
                    });
                } else if (change.after !== null) {
                    // Added on their side, take it
                    this._store.put(this._worktreeId, change.key, change.after);
                } else {
                    // Deleted on their side
                    conflicts.push({
                        path: change.key,
                        ours: change.before,
                        theirs: null
                    });
                }
            }
        }

        // If no unresolved conflicts, create a merge commit
        if (conflicts.length === 0 || strategy === 'lww') {
            const message = (opts && opts.message)
                || `Merge branch '${branchName}' into ${this._currentBranch}`;
            const result = this.commit(message, {
                parents: [this._headCommitIndex, theirCommitIndex]
            });
            return { commitIndex: result.commitIndex, conflicts: [] };
        }

        return { commitIndex: -1, conflicts };
    }

    /**
     * Resolve a merge conflict by choosing a value.
     * @param {string} path
     * @param {*} resolvedValue
     */
    resolve(path, resolvedValue) {
        this._store.put(this._worktreeId, path, resolvedValue);
    }
}

module.exports = Repo;
