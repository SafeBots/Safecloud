"use strict";
/**
 * Safecloud 2.9 — Data Structures Test Battery
 *
 * Tests TreeStore, Directory, Feed, Repo, Database, and NameResolver
 * end to end. Pure Node.js, no external test framework.
 */

const path = require('path');
const { TreeStore, Directory, Feed, Repo, Database, NameResolver } = require(path.join(__dirname, '..', 'data'));

let pass = 0, fail = 0, section = '';
function check(name, condition, detail) {
    if (condition) {
        pass++;
        console.log('  ✓', name);
    } else {
        fail++;
        console.log('  ✗ FAIL:', name, detail ? ('— ' + detail) : '');
    }
}
function heading(s) {
    section = s;
    console.log('\n\x1b[1m' + s + '\x1b[0m');
}

// ════════════════════════════════════════════════════════════════
heading('TreeStore — KV mode');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const { treeId } = store.createTree('test-kv', { mode: 'kv' });

    check('createTree returns treeId', typeof treeId === 'number');

    // put and get
    store.put(treeId, 'alpha', { value: 1 });
    store.put(treeId, 'beta', { value: 2 });
    store.put(treeId, 'gamma', { value: 3 });

    const r = store.get(treeId, 'beta');
    check('get returns put value', r && r.value && r.value.value === 2);

    check('get missing key returns null', store.get(treeId, 'missing') === null);

    // range
    const all = store.range(treeId, {});
    check('range {} returns all entries', all.length === 3);
    check('range is sorted', all[0].key === 'alpha' && all[1].key === 'beta' && all[2].key === 'gamma');

    const partial = store.range(treeId, { gte: 'beta', lt: 'gamma' });
    check('range gte/lt filters correctly', partial.length === 1 && partial[0].key === 'beta');

    const limited = store.range(treeId, { limit: 2 });
    check('range limit works', limited.length === 2);

    const reversed = store.range(treeId, { reverse: true });
    check('range reverse works', reversed[0].key === 'gamma' && reversed[2].key === 'alpha');

    // delete
    store.delete(treeId, 'beta');
    check('delete removes key', store.get(treeId, 'beta') === null);
    check('delete preserves others', store.get(treeId, 'alpha') !== null);

    // root CID changes on mutation
    const cid1 = store.root(treeId);
    store.put(treeId, 'delta', { value: 4 });
    const cid2 = store.root(treeId);
    check('root CID changes on put', cid1 !== cid2);
    check('root CID starts with bafy', cid1.startsWith('bafy'));

    // size
    check('size() counts entries', store.size(treeId) === 3); // alpha, gamma, delta
})();

// ════════════════════════════════════════════════════════════════
heading('TreeStore — Append mode');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const { treeId } = store.createTree('test-append', { mode: 'append' });

    // append and get
    const r0 = store.append(treeId, 'first');
    const r1 = store.append(treeId, 'second');
    const r2 = store.append(treeId, 'third');

    check('append returns sequential indexes', r0.index === 0 && r1.index === 1 && r2.index === 2);
    check('get by index works', store.get(treeId, 1).value === 'second');
    check('get out of range returns null', store.get(treeId, 99) === null);
    check('length() returns count', store.length(treeId) === 3);

    // range on append
    const range = store.range(treeId, { gte: 1, lt: 3 });
    check('range on append-mode tree', range.length === 2 && range[0].value === 'second');

    // subscribe
    const received = [];
    const unsub = store.subscribe(treeId, (entry) => received.push(entry));
    store.append(treeId, 'fourth');
    store.append(treeId, 'fifth');
    check('subscribe receives appends', received.length === 2 && received[0].value === 'fourth');

    unsub();
    store.append(treeId, 'sixth');
    check('unsubscribe stops notifications', received.length === 2);
})();

// ════════════════════════════════════════════════════════════════
heading('TreeStore — Checkpoint / Hydrate');
// ════════════════════════════════════════════════════════════════

(function () {
    const chunks = new TreeStore.ChunkStore();
    const store1 = new TreeStore(chunks);

    // KV checkpoint/hydrate
    const { treeId: kv1 } = store1.createTree('persist-kv', { mode: 'kv' });
    store1.put(kv1, 'x', 100);
    store1.put(kv1, 'y', 200);
    const rootCid = store1.checkpoint(kv1);
    check('checkpoint returns CID', rootCid.startsWith('bafy'));

    // Hydrate on a different TreeStore (simulating failover to another Jet)
    const store2 = new TreeStore(chunks);
    const { treeId: kv2 } = store2.hydrate(rootCid);
    check('hydrate restores KV data', store2.get(kv2, 'x').value === 100 && store2.get(kv2, 'y').value === 200);

    // Append checkpoint/hydrate
    const { treeId: log1 } = store1.createTree('persist-log', { mode: 'append' });
    store1.append(log1, 'entry-0');
    store1.append(log1, 'entry-1');
    const logCid = store1.checkpoint(log1);

    const { treeId: log2 } = store2.hydrate(logCid);
    check('hydrate restores append log', store2.get(log2, 0).value === 'entry-0' && store2.get(log2, 1).value === 'entry-1');
    check('hydrate preserves length', store2.length(log2) === 2);

    // Hydrate with bad CID
    let threw = false;
    try { store2.hydrate('bafy_nonexistent'); } catch (e) { threw = true; }
    check('hydrate with bad CID throws', threw);
})();

// ════════════════════════════════════════════════════════════════
heading('TreeStore — Diff');
// ════════════════════════════════════════════════════════════════

(function () {
    const chunks = new TreeStore.ChunkStore();
    const store = new TreeStore(chunks);

    const { treeId } = store.createTree('diff-kv', { mode: 'kv' });
    store.put(treeId, 'a', 1);
    store.put(treeId, 'b', 2);
    store.put(treeId, 'c', 3);
    const cidA = store.checkpoint(treeId);

    store.put(treeId, 'b', 99);   // modified
    store.delete(treeId, 'c');     // removed
    store.put(treeId, 'd', 4);    // added
    const cidB = store.checkpoint(treeId);

    const changes = store.diff(cidA, cidB);
    check('diff detects modification', changes.some(c => c.key === 'b' && c.before === 2 && c.after === 99));
    check('diff detects removal', changes.some(c => c.key === 'c' && c.before === 3 && c.after === null));
    check('diff detects addition', changes.some(c => c.key === 'd' && c.before === null && c.after === 4));
    check('diff skips unchanged', !changes.some(c => c.key === 'a'));
    check('diff same CID returns empty', store.diff(cidA, cidA).length === 0);

    // Append diff
    const { treeId: logId } = store.createTree('diff-log', { mode: 'append' });
    store.append(logId, 'x');
    store.append(logId, 'y');
    const logCidA = store.checkpoint(logId);
    store.append(logId, 'z');
    const logCidB = store.checkpoint(logId);

    const logChanges = store.diff(logCidA, logCidB);
    check('append diff shows new entries', logChanges.length === 1 && logChanges[0].after === 'z');
})();

// ════════════════════════════════════════════════════════════════
heading('Directory — static folders');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const dir = new Directory(store);

    const { rootCid, manifest } = dir.store({
        'index.html': { content: '<h1>Hello</h1>', type: 'text/html' },
        'css/style.css': { content: 'body { color: red; }', type: 'text/css' },
        'css/reset.css': { content: '* { margin: 0; }', type: 'text/css' },
        'img/logo.png': { content: Buffer.from([0x89, 0x50, 0x4e, 0x47]), type: 'image/png' },
        'README.md': { content: '# Test', type: 'text/markdown' }
    });

    check('store returns rootCid', rootCid.startsWith('bafy'));
    check('manifest has all files', Object.keys(manifest).length === 5);
    check('manifest has CIDs and sizes', manifest['index.html'].cid && manifest['index.html'].size === 14);

    // fetch
    const { files } = dir.fetch(rootCid);
    check('fetch recovers all files', Object.keys(files).length === 5);
    check('fetch has correct metadata', files['css/style.css'].type === 'text/css');

    // getFile
    const content = dir.getFile(rootCid, 'index.html');
    check('getFile returns content', content && content.toString() === '<h1>Hello</h1>');
    check('getFile missing returns null', dir.getFile(rootCid, 'missing.txt') === null);

    // list with prefix
    const cssFiles = dir.list(rootCid, 'css/');
    check('list with prefix filters', cssFiles.length === 2);
    check('list entries have path and type', cssFiles[0].path === 'css/reset.css' && cssFiles[0].type === 'text/css');

    const allFiles = dir.list(rootCid);
    check('list without prefix returns all', allFiles.length === 5);

    // diff
    const { rootCid: rootCid2 } = dir.store({
        'index.html': { content: '<h1>Updated</h1>', type: 'text/html' },
        'css/style.css': { content: 'body { color: red; }', type: 'text/css' },
        'css/reset.css': { content: '* { margin: 0; }', type: 'text/css' },
        'img/logo.png': { content: Buffer.from([0x89, 0x50, 0x4e, 0x47]), type: 'image/png' },
        'js/app.js': { content: 'console.log("hi")', type: 'text/javascript' }
    });

    const changes = dir.diff(rootCid, rootCid2);
    check('dir diff detects modified file', changes.some(c => c.path === 'index.html' && c.type === 'modified'));
    check('dir diff detects added file', changes.some(c => c.path === 'js/app.js' && c.type === 'added'));
    check('dir diff detects removed file', changes.some(c => c.path === 'README.md' && c.type === 'removed'));
})();

// ════════════════════════════════════════════════════════════════
heading('Feed — append-only event log');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const feed = new Feed(store, 'events');

    check('new feed has length 0', feed.length === 0);

    feed.append({ type: 'user.created', userId: 'alice' });
    feed.append({ type: 'user.created', userId: 'bob' });
    feed.append({ type: 'post.created', postId: 'p1', author: 'alice' });

    check('feed length is 3', feed.length === 3);
    check('feed.get(0) returns first entry', feed.get(0).type === 'user.created' && feed.get(0).userId === 'alice');
    check('feed.get(2) returns third entry', feed.get(2).type === 'post.created');
    check('feed.get(99) returns null', feed.get(99) === null);

    // range
    const last2 = feed.range({ gte: 1, limit: 2 });
    check('feed range works', last2.length === 2 && last2[0].value.userId === 'bob');

    // subscribe
    const received = [];
    const unsub = feed.subscribe(entry => received.push(entry));
    feed.append({ type: 'post.created', postId: 'p2', author: 'bob' });
    check('feed subscribe receives new entry', received.length === 1 && received[0].value.postId === 'p2');
    unsub();
    feed.append({ type: 'post.deleted', postId: 'p1' });
    check('feed unsubscribe works', received.length === 1);

    // checkpoint and restore
    const rootCid = feed.checkpoint();
    const restored = Feed.fromCheckpoint(store, rootCid);
    check('restored feed has same length', restored.length === 5);
    check('restored feed has same data', restored.get(0).type === 'user.created');
    check('restored feed rootCid matches', restored.rootCid === feed.rootCid);
})();

// ════════════════════════════════════════════════════════════════
heading('Repo — versioned directories');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const repo = new Repo(store, 'my-site', { author: 'alice' });

    // Initial commit
    repo.add('index.html', '<h1>v1</h1>');
    repo.add('style.css', 'body { font: sans-serif; }');
    const c1 = repo.commit('initial commit');
    check('first commit returns index 0', c1.commitIndex === 0);
    check('first commit has treeCid', c1.treeCid.startsWith('bafy'));

    // Second commit
    repo.add('index.html', '<h1>v2</h1>');
    repo.add('about.html', '<h1>About</h1>');
    const c2 = repo.commit('add about page');
    check('second commit index is 1', c2.commitIndex === 1);
    check('treeCid changed', c1.treeCid !== c2.treeCid);

    // Log
    const history = repo.log();
    check('log has 2 commits', history.length === 2);
    check('log is newest-first', history[0].index === 1 && history[1].index === 0);
    check('log has messages', history[0].message === 'add about page');
    check('log has author', history[0].author === 'alice');

    // Diff
    const diffs = repo.diff(c1.treeCid, c2.treeCid);
    check('diff shows modified file', diffs.some(d => d.path === 'index.html' && d.type === 'modified'));
    check('diff shows added file', diffs.some(d => d.path === 'about.html' && d.type === 'added'));
    check('diff does not show unchanged', !diffs.some(d => d.path === 'style.css'));

    // Branching
    repo.branch('feature');
    const branches = repo.getBranches();
    check('branches include main and feature', branches.length === 2);
    check('current branch is main', repo.currentBranch === 'main');

    // Checkout and modify
    repo.checkout('feature');
    check('checkout switches branch', repo.currentBranch === 'feature');
    repo.add('feature.html', '<h1>Feature</h1>');
    repo.add('index.html', '<h1>v3-feature</h1>');
    const c3 = repo.commit('feature work');

    // Switch back to main
    repo.checkout('main');
    check('main still has v2 index', repo.getFile('index.html') === '<h1>v2</h1>');
    check('main does not have feature.html', repo.getFile('feature.html') === null);

    // Merge (last-writer-wins)
    const mergeResult = repo.merge('feature');
    check('merge creates a commit', mergeResult.commitIndex >= 0);
    check('merge has no conflicts (lww)', mergeResult.conflicts.length === 0);
    check('merge brought feature.html', repo.getFile('feature.html') === '<h1>Feature</h1>');
    check('merge took feature index.html (lww)', repo.getFile('index.html') === '<h1>v3-feature</h1>');

    // Merge commit has two parents
    const mergeLog = repo.log({ limit: 1 });
    check('merge commit has 2 parents', mergeLog[0].parents.length === 2);

    // Remove
    repo.remove('about.html');
    check('remove deletes file', repo.getFile('about.html') === null);

    // listFiles
    const files = repo.listFiles();
    check('listFiles shows remaining files', files.length >= 2);
})();

// ════════════════════════════════════════════════════════════════
heading('Repo — manual merge with conflicts');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const repo = new Repo(store, 'conflict-test');

    repo.add('shared.txt', 'original');
    repo.commit('initial');

    // Branch and diverge
    repo.branch('dev');

    // Modify on main
    repo.add('shared.txt', 'main version');
    repo.commit('main edit');

    // Modify on dev
    repo.checkout('dev');
    repo.add('shared.txt', 'dev version');
    repo.commit('dev edit');

    // Go back to main and merge with manual strategy
    repo.checkout('main');
    const result = repo.merge('dev', { strategy: 'manual' });
    check('manual merge reports conflicts', result.conflicts.length > 0);
    check('conflict has path and both versions', result.conflicts[0].path === 'shared.txt' &&
        result.conflicts[0].ours === 'main version' && result.conflicts[0].theirs === 'dev version');

    // Resolve
    repo.resolve('shared.txt', 'resolved version');
    const c = repo.commit('resolved conflict');
    check('resolved conflict commits', c.commitIndex >= 0);
    check('resolved value is correct', repo.getFile('shared.txt') === 'resolved version');
})();

// ════════════════════════════════════════════════════════════════
heading('Database — indexed KV with versioning');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const db = new Database(store, 'users', {
        fields: { name: 'string', role: 'string', email: 'string' },
        indexes: ['role']
    });

    // put and get
    db.put('user:alice', { name: 'Alice', role: 'admin', email: 'alice@example.com' });
    db.put('user:bob', { name: 'Bob', role: 'member', email: 'bob@example.com' });
    db.put('user:carol', { name: 'Carol', role: 'admin', email: 'carol@example.com' });
    db.put('user:dave', { name: 'Dave', role: 'member', email: 'dave@example.com' });

    check('get returns record', db.get('user:alice').name === 'Alice');
    check('get missing returns null', db.get('user:zara') === null);
    check('count is 4', db.count() === 4);

    // query by index
    const admins = db.query('role', { eq: 'admin' });
    check('query eq finds admins', admins.length === 2);
    check('query eq returns records', admins.every(r => r.value.role === 'admin'));

    const members = db.query('role', { eq: 'member' });
    check('query eq finds members', members.length === 2);

    // scan
    const allRecords = db.scan();
    check('scan returns all records', allRecords.length === 4);
    check('scan excludes _schema', !allRecords.some(r => r.key === '_schema'));

    // update a record — indexes should update
    db.put('user:bob', { name: 'Bob', role: 'admin', email: 'bob@example.com' });
    const adminsAfter = db.query('role', { eq: 'admin' });
    check('index updates on record update', adminsAfter.length === 3);
    const membersAfter = db.query('role', { eq: 'member' });
    check('old index entry removed on update', membersAfter.length === 1);

    // delete
    db.delete('user:dave');
    check('delete removes record', db.get('user:dave') === null);
    check('count after delete', db.count() === 3);
    const membersPostDelete = db.query('role', { eq: 'member' });
    check('delete removes from index', membersPostDelete.length === 0);

    // add index dynamically
    db.addIndex('email');
    const byEmail = db.query('email', { eq: 'alice@example.com' });
    check('dynamic index works', byEmail.length === 1 && byEmail[0].value.name === 'Alice');

    // getIndexes
    const idxs = db.getIndexes();
    check('getIndexes lists all', idxs.includes('role') && idxs.includes('email'));

    // drop index
    db.dropIndex('email');
    let threw = false;
    try { db.query('email', { eq: 'alice@example.com' }); } catch (e) { threw = true; }
    check('dropIndex removes index', threw);

    // versioning — commit
    const c1 = db.commit('initial data');
    check('commit returns commitIndex', c1.commitIndex === 0);
    check('commit returns primaryCid', c1.primaryCid.startsWith('bafy'));

    // mutate and commit again
    db.put('user:eve', { name: 'Eve', role: 'member', email: 'eve@example.com' });
    const c2 = db.commit('added eve');
    check('second commit', c2.commitIndex === 1);

    // log
    const history = db.log();
    check('log has 2 commits', history.length === 2);
    check('log has messages', history[0].message === 'added eve');

    // diff
    const diffs = db.diff(0, 1);
    check('diff shows added record', diffs.some(d => d.key === 'user:eve' && d.type === 'added'));
    check('diff excludes unchanged records', !diffs.some(d => d.key === 'user:alice'));

    // rollback
    db.rollback(0);
    check('rollback restores state', db.get('user:eve') === null);
    check('rollback preserves existing records', db.get('user:alice').name === 'Alice');

    // index still works after rollback
    const adminsRollback = db.query('role', { eq: 'admin' });
    check('indexes work after rollback', adminsRollback.length === 3);
})();

// ════════════════════════════════════════════════════════════════
heading('Database — range queries on index');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const db = new Database(store, 'products', {
        fields: { name: 'string', category: 'string', price: 'number' },
        indexes: ['category']
    });

    db.put('p1', { name: 'Widget A', category: 'electronics', price: 29 });
    db.put('p2', { name: 'Widget B', category: 'electronics', price: 49 });
    db.put('p3', { name: 'Book C', category: 'books', price: 15 });
    db.put('p4', { name: 'Gadget D', category: 'electronics', price: 99 });
    db.put('p5', { name: 'Book E', category: 'books', price: 22 });

    const electronics = db.query('category', { eq: 'electronics' });
    check('category query finds electronics', electronics.length === 3);

    const books = db.query('category', { eq: 'books' });
    check('category query finds books', books.length === 2);

    // Range query on category
    const ranged = db.query('category', { gte: 'books', lt: 'electronics' });
    check('range query gte/lt on index', ranged.length === 2 && ranged.every(r => r.value.category === 'books'));
})();

// ════════════════════════════════════════════════════════════════
heading('NameResolver — mutable pointers');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();
    const resolver = new NameResolver(store, { owner: 'alice' });

    // create
    const r1 = resolver.update('my-website', 'bafy_root_v1');
    check('create name returns seq 1', r1.seq === 1);

    // resolve
    const resolved = resolver.resolve('my-website');
    check('resolve returns target', resolved.target === 'bafy_root_v1');
    check('resolve returns seq', resolved.seq === 1);
    check('resolve returns owner', resolved.owner === 'alice');

    // update
    const r2 = resolver.update('my-website', 'bafy_root_v2');
    check('update bumps seq', r2.seq === 2);
    check('resolve after update', resolver.resolve('my-website').target === 'bafy_root_v2');

    // multiple names
    resolver.update('my-app', 'bafy_app_v1');
    resolver.update('my-docs', 'bafy_docs_v1');

    // list
    const all = resolver.list();
    check('list returns all names', all.length === 3);

    // list with prefix
    const myDocs = resolver.list({ prefix: 'my-d' });
    check('list with prefix filters', myDocs.length === 1 && myDocs[0].name === 'my-docs');

    // remove
    resolver.remove('my-docs');
    check('resolve removed name returns null', resolver.resolve('my-docs') === null);
    check('list after remove', resolver.list().length === 2);

    // checkpoint and restore
    const rootCid = resolver.checkpoint();
    const restored = NameResolver.fromCheckpoint(store, rootCid);
    check('restored resolver has same names', restored.resolve('my-website').target === 'bafy_root_v2');
    check('restored resolver has correct seq', restored.resolve('my-website').seq === 2);
})();

// ════════════════════════════════════════════════════════════════
heading('Integration — cross-structure workflow');
// ════════════════════════════════════════════════════════════════

(function () {
    // Scenario: build a website repo, publish directories, register names,
    // log events, track in a database.

    const chunks = new TreeStore.ChunkStore();
    const store = new TreeStore(chunks);

    // 1. Create a repo for the website source
    const repo = new Repo(store, 'website', { author: 'dev-team' });
    repo.add('index.html', '<h1>My Site v1</h1>');
    repo.add('style.css', 'body { margin: 0; }');
    const c1 = repo.commit('initial website');

    // 2. Publish as a static directory
    const dir = new Directory(store);
    const { rootCid: dirCid1 } = dir.store({
        'index.html': { content: '<h1>My Site v1</h1>', type: 'text/html' },
        'style.css': { content: 'body { margin: 0; }', type: 'text/css' }
    });

    // 3. Register a name pointing to the directory
    const names = new NameResolver(store, { owner: 'admin' });
    names.update('mysite.safecloud', dirCid1);

    // 4. Log the deployment
    const feed = new Feed(store, 'deploy-log');
    feed.append({
        action: 'deploy',
        site: 'mysite.safecloud',
        dirCid: dirCid1,
        commitIndex: c1.commitIndex,
        timestamp: Date.now()
    });

    // 5. Track in a database
    const db = new Database(store, 'deployments', {
        fields: { site: 'string', dirCid: 'string', status: 'string' },
        indexes: ['site', 'status']
    });
    db.put('deploy:1', { site: 'mysite.safecloud', dirCid: dirCid1, status: 'live' });

    // Verify the full chain
    const resolvedCid = names.resolve('mysite.safecloud').target;
    check('name resolves to directory CID', resolvedCid === dirCid1);

    const files = dir.fetch(resolvedCid).files;
    check('directory has published files', Object.keys(files).length === 2);

    const deployLog = feed.get(0);
    check('deploy log records event', deployLog.action === 'deploy');

    const liveDeployments = db.query('status', { eq: 'live' });
    check('database tracks deployment', liveDeployments.length === 1);

    // 6. Update: new version
    repo.add('index.html', '<h1>My Site v2</h1>');
    repo.add('about.html', '<h1>About</h1>');
    const c2 = repo.commit('v2 with about page');

    const { rootCid: dirCid2 } = dir.store({
        'index.html': { content: '<h1>My Site v2</h1>', type: 'text/html' },
        'style.css': { content: 'body { margin: 0; }', type: 'text/css' },
        'about.html': { content: '<h1>About</h1>', type: 'text/html' }
    });

    names.update('mysite.safecloud', dirCid2);
    feed.append({ action: 'deploy', site: 'mysite.safecloud', dirCid: dirCid2, commitIndex: c2.commitIndex });
    db.put('deploy:1', { site: 'mysite.safecloud', dirCid: dirCid2, status: 'live' });

    // Verify update chain
    check('name now points to v2', names.resolve('mysite.safecloud').target === dirCid2);
    check('name seq is 2', names.resolve('mysite.safecloud').seq === 2);
    check('deploy log has 2 entries', feed.length === 2);

    // Diff between versions
    const dirDiff = dir.diff(dirCid1, dirCid2);
    check('dir diff shows added about.html', dirDiff.some(d => d.path === 'about.html' && d.type === 'added'));
    check('dir diff shows modified index.html', dirDiff.some(d => d.path === 'index.html' && d.type === 'modified'));

    // Repo diff
    const repoDiff = repo.diff(c1.treeCid, c2.treeCid);
    check('repo diff matches directory diff', repoDiff.length >= 2);
})();

// ════════════════════════════════════════════════════════════════
heading('Edge cases');
// ════════════════════════════════════════════════════════════════

(function () {
    const store = new TreeStore();

    // Empty tree operations
    const { treeId } = store.createTree('empty', { mode: 'kv' });
    check('range on empty tree returns []', store.range(treeId, {}).length === 0);
    check('root of empty tree is valid CID', store.root(treeId).startsWith('bafy'));

    // Invalid mode
    let threw = false;
    try { store.createTree('bad', { mode: 'graph' }); } catch (e) { threw = true; }
    check('invalid mode throws', threw);

    // Append on KV tree
    threw = false;
    try { store.append(treeId, 'nope'); } catch (e) { threw = true; }
    check('append on KV tree throws', threw);

    // Put on append tree
    const { treeId: logId } = store.createTree('log', { mode: 'append' });
    threw = false;
    try { store.put(logId, 'key', 'nope'); } catch (e) { threw = true; }
    check('put on append tree throws', threw);

    // Large-ish tree
    const { treeId: bigId } = store.createTree('big', { mode: 'kv' });
    for (let i = 0; i < 1000; i++) {
        store.put(bigId, `key:${String(i).padStart(4, '0')}`, { i });
    }
    check('1000-entry tree size', store.size(bigId) === 1000);
    const ranged = store.range(bigId, { gte: 'key:0500', lt: 'key:0510' });
    check('range on 1000-entry tree', ranged.length === 10 && ranged[0].value.i === 500);

    // Feed with structured values
    const feed = new Feed(store, 'structured');
    feed.append({ nested: { deep: { value: 42 } } });
    check('feed preserves nested structures', feed.get(0).nested.deep.value === 42);

    // Database with no initial schema
    const db = new Database(store, 'schemaless');
    db.put('k1', { x: 1 });
    check('schemaless db works', db.get('k1').x === 1);
    db.addIndex('x');
    const found = db.query('x', { eq: 1 });
    check('dynamic index on existing data', found.length === 1);

    // Repo with no commits — log should be empty
    const repo = new Repo(store, 'empty-repo');
    check('empty repo log is empty', repo.log().length === 0);
    check('empty repo head is -1', repo.head === -1);
})();

// ════════════════════════════════════════════════════════════════
// Summary
// ════════════════════════════════════════════════════════════════

console.log(`\n\x1b[1m${'═'.repeat(50)}\x1b[0m`);
console.log(`\x1b[1m${pass} passed, ${fail} failed\x1b[0m`);
if (fail > 0) {
    console.log('\x1b[31mSome tests failed!\x1b[0m');
}
process.exit(fail ? 1 : 0);
