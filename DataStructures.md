# Data Structures

Safecloud 2.9 introduces five high-level data structures built on the `tree_*` host API. Each structure composes a small number of Merkle trees (KV and append-only) to provide familiar abstractions — directories, event logs, version-controlled repositories, indexed databases, and mutable name resolution — with content-addressed storage, checkpoint/hydrate portability, and cryptographic diffs.

All five structures are part of the Safecloud SDK. They run client-side (Tier 2) or inside SafecloudApps (Tier 1). They do not require any new Jet-side primitives — they are built entirely on `tree_create`, `tree_put`, `tree_get`, `tree_range`, `tree_delete`, `tree_append`, `tree_root`, `tree_checkpoint`, `tree_hydrate`, and `tree_diff`.

## TreeStore

The reference implementation of the `tree_*` host API. In production, Jets implement these functions natively. The JS TreeStore is for testing, local development, and the `safecloud dev` emulator.

Two modes per tree:

- **KV mode.** Ordered key-value store. Keys are strings, values are arbitrary JSON-serializable objects. Range queries with `gte`, `gt`, `lt`, `lte`, `limit`, `reverse`.
- **Append mode.** Append-only log. Values are appended and addressed by integer index. Supports `subscribe` for live tail.

Every mutation changes the tree's root CID — a SHA-256 hash of the tree's serialized state, prefixed with `bafy`. This is the Merkle property: two trees with the same root CID contain the same data.

**Checkpoint** serializes a tree's state to the chunk store (Drops in production). **Hydrate** reconstructs a tree from its root CID. **Diff** compares two checkpointed states and returns an array of `{ key, before, after }` changes.

```javascript
const TreeStore = require('safecloud/data/TreeStore');
const store = new TreeStore();
const { treeId } = store.createTree('my-tree', { mode: 'kv' });
store.put(treeId, 'key', { some: 'value' });
const rootCid = store.checkpoint(treeId);
// Later, on any Jet:
const { treeId: restored } = store.hydrate(rootCid);
```

## Directory

Static folder — an IPFS/IPLD analog. A directory is a KV tree where keys are slash-delimited paths and values are file manifests (`{ cid, size, type }`). File content is stored separately in the chunk store. The root CID of the tree is the permanent address of the entire directory.

Directories are immutable snapshots. To publish an update, store a new directory and update the name pointer (see NameResolver).

```javascript
const Directory = require('safecloud/data/Directory');
const dir = new Directory(store);

// Store files
const { rootCid, manifest } = dir.store({
    'index.html': { content: '<h1>Hello</h1>', type: 'text/html' },
    'style.css':  { content: 'body { margin: 0; }', type: 'text/css' }
});

// Fetch manifest
const { files } = dir.fetch(rootCid);

// Get a single file's content
const html = dir.getFile(rootCid, 'index.html');

// List files by prefix
const cssFiles = dir.list(rootCid, 'css/');

// Diff two snapshots
const changes = dir.diff(rootCidV1, rootCidV2);
// → [{ path: 'index.html', type: 'modified', before: {...}, after: {...} }]
```

## Feed

Append-only event log — a Hypercore/Kafka analog. A feed wraps an append-mode tree with a convenience API. Use feeds for event sourcing, audit trails, deploy logs, activity streams.

```javascript
const Feed = require('safecloud/data/Feed');
const feed = new Feed(store, 'deploy-log');

feed.append({ action: 'deploy', site: 'example.com', version: 'v2.1' });
feed.append({ action: 'rollback', site: 'example.com', version: 'v2.0' });

feed.length;          // 2
feed.get(0);          // { action: 'deploy', ... }
feed.range({ gte: 0, limit: 10 });

// Live tail
const unsub = feed.subscribe(entry => console.log('new event:', entry));

// Checkpoint and restore
const rootCid = feed.checkpoint();
const restored = Feed.fromCheckpoint(store, rootCid);
```

## Repo

Versioned directory with branch/merge/diff — a Git analog. A repo manages three internal trees: a working tree (KV), a commit log (append-only), and a branches tree (KV). Commits snapshot the working tree's root CID along with parent references, author, message, and timestamp.

```javascript
const Repo = require('safecloud/data/Repo');
const repo = new Repo(store, 'my-site', { author: 'alice' });

// Stage and commit
repo.add('index.html', '<h1>v1</h1>');
repo.add('style.css', 'body { margin: 0; }');
const c1 = repo.commit('initial commit');
// → { commitIndex: 0, treeCid: 'bafy...', commitsCid: 'bafy...' }

// Modify and commit
repo.add('index.html', '<h1>v2</h1>');
const c2 = repo.commit('update homepage');

// History and diff
repo.log();           // newest-first
repo.diff(c1.treeCid, c2.treeCid);
// → [{ path: 'index.html', type: 'modified', before: '<h1>v1</h1>', after: '<h1>v2</h1>' }]

// Branching
repo.branch('feature');
repo.checkout('feature');
repo.add('feature.html', '<h1>New Feature</h1>');
repo.commit('add feature page');

// Merge (last-writer-wins by default)
repo.checkout('main');
const result = repo.merge('feature');
// → { commitIndex: 3, conflicts: [] }

// Manual merge for conflict detection
const result = repo.merge('other-branch', { strategy: 'manual' });
if (result.conflicts.length > 0) {
    for (const c of result.conflicts) {
        repo.resolve(c.path, mergedValue);
    }
    repo.commit('resolved conflicts');
}

// Convenience accessors
repo.listFiles();                  // all paths in the working tree
repo.getBranches();                // all branch names
repo.currentBranch;                // current branch name (property)
repo.head;                         // index of the latest commit, or -1 (property)
repo.remove('old-file.html');      // delete a file from the working tree
```

**Merge strategies:**
- `lww` (default): last-writer-wins. The incoming branch's version of any conflicting file overwrites the current branch's version.
- `manual`: reports conflicts as `{ path, ours, theirs }` without overwriting. The caller resolves each conflict with `repo.resolve(path, value)` and then commits.

## Database

Indexed KV store with version history — a Dolt analog. A database manages a primary KV tree, per-field index trees, and a commit log. Indexes use the key format `String(indexValue) + '\0' + primaryKey` — the null byte separator ensures clean range-query boundaries.

```javascript
const Database = require('safecloud/data/Database');
const db = new Database(store, 'users', {
    fields: { name: 'string', role: 'string', email: 'string' },
    indexes: ['role']
});

// CRUD
db.put('user:alice', { name: 'Alice', role: 'admin', email: 'alice@example.com' });
db.get('user:alice');     // { name: 'Alice', role: 'admin', ... }
db.delete('user:alice');
db.count();               // number of records
db.scan({ limit: 10 });   // all records, ordered by primary key

// Index queries
db.query('role', { eq: 'admin' });                    // exact match
db.query('role', { gte: 'admin', lt: 'member' });     // range
db.query('role', { eq: 'member', limit: 5, reverse: true });

// Dynamic index management
db.addIndex('email');     // builds from existing data
db.dropIndex('email');
db.getIndexes();          // ['role']

// Versioning
const c1 = db.commit('initial load');
db.put('user:dave', { name: 'Dave', role: 'member' });
const c2 = db.commit('added dave');

db.log();                 // commit history, newest-first
db.diff(0, 1);            // changes between commits
db.rollback(0);           // restore to a previous commit
```

Indexes are automatically maintained on `put` and `delete`. Updating a record removes the old index entries and adds new ones.

## NameResolver

Mutable name-to-CID resolution — an IPNS analog. A NameResolver wraps a KV tree where keys are names and values are records containing the target CID, a monotonically increasing sequence number (prevents rollback), the owner identity, and a timestamp.

```javascript
const NameResolver = require('safecloud/data/NameResolver');
const resolver = new NameResolver(store, { owner: 'alice' });

resolver.update('my-website', rootCidV1);   // → { seq: 1 }
resolver.update('my-website', rootCidV2);   // → { seq: 2 }

resolver.resolve('my-website');
// → { target: rootCidV2, seq: 2, owner: 'alice', updatedAt: 1729... }

resolver.list();                            // all names
resolver.list({ prefix: 'my-' });           // filtered
resolver.remove('my-website');

// Checkpoint and restore
const rootCid = resolver.checkpoint();
const restored = NameResolver.fromCheckpoint(store, rootCid);
```

## Cross-structure workflows

The structures compose naturally. A typical deployment pipeline:

1. **Repo** manages the source files with versioned commits and branches.
2. **Directory** publishes a commit's working tree as an immutable, content-addressed folder.
3. **NameResolver** maps a human-readable name to the directory's root CID, updating on each deploy.
4. **Feed** logs each deployment as an append-only event for audit.
5. **Database** tracks deployment status with indexed queries (by site, by status).

Each structure checkpoints independently to Drops. Any Jet can hydrate any structure from its root CID, making the entire stack portable across Jet failures.

## Interoperability

The data structures are concept-compatible with established ecosystems:

| Safecloud | Analog | Compatibility |
|---|---|---|
| Directory | IPFS/IPLD | CID format uses same multihash convention. A bridge can serve a Safecloud directory over the IPFS gateway protocol. |
| Feed | Hypercore/Kafka | Append-only semantics, subscribe for live tail. A feed replicator SafecloudApp can bridge to Hypercore peers. |
| Repo | Git | Commit, branch, merge, diff. A Git HTTP bridge SafecloudApp can serve a repo via the smart HTTP protocol (`git clone`, `git push`). |
| Database | Dolt/SQLite | Indexed KV with commit/rollback/diff. A SQL adapter SafecloudApp can layer SQL parsing (via SQLite-WASM) over the Database API. |
| NameResolver | IPNS | Mutable pointer with sequence number. A gateway SafecloudApp can resolve names via HTTP (`GET /resolve/:name`). |

## Wire format

All data flows through the TreeStore. The on-disk format is:

- **CID:** `bafy` + first 56 hex characters of `SHA-256(JSON.stringify(state))`, where state keys are sorted at every nesting level for deterministic serialization.
- **Checkpoint format:** JSON-serialized tree state, stored in the chunk store keyed by root CID. KV trees store `{ mode: 'kv', name, entries: {...} }`. Append trees store `{ mode: 'append', name, log: [{ index, value, cid }, ...] }`.
- **Index key format:** `String(indexValue) + '\0' + primaryKey` — the null byte ensures that a range query on an index value never bleeds into adjacent values.

In production, the chunk store is Drops (content-addressed encrypted storage). In testing and the `safecloud dev` emulator, it is an in-memory `ChunkStore` instance.
