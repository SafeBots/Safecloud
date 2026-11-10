# Safecloud 4.0

Safecloud 4.0 is the collaboration release. It turns Safecloud from a storage-and-streaming network into a Google Suite alternative: real-time collaborative editing, folder-based access control with inheritance, and a pure-JS database engine replacing the native SQLite dependency.

For storage, streaming, payments, and cryptography, see the [README](README.md). This document covers what 4.0 adds.

## What's new

### Collaborative editors (Univer + CodeMirror + Slides)

`collab.html` is a multi-mode collaborative editor backed by Yjs CRDTs and Safecloud encrypted Streams.

| Mode | Engine | Sync model |
|------|--------|------------|
| **Docs** | Univer Docs 1.3.1 | `Y.Map('doc')['snapshot']` — full body JSON, debounced 300ms, last-write-wins |
| **Sheets** | Univer Sheets 1.3.1 | `Y.Map('cells')` keyed `"row:col"` — cell-level granularity, bidirectional |
| **Markdown** | CodeMirror 5 | `Y.Text('content')` — character-level CRDT, true concurrent editing |
| **Slides** | Custom engine | `Y.Map('slides')` — per-slide JSON, presentation mode |

The Univer editors are bundled as a single 12MB IIFE (`web/js/univer-bundle.js`) built via esbuild from `web/collab-src/`. The bundle exposes `UniverBundle.createUniverSheets(containerId, ydoc, opts)` and `UniverBundle.createUniverDocs(containerId, ydoc, opts)`. React 18 and rxjs are bundled inside; nothing leaks to the global scope.

All four modes share the same `SafecloudYjsProvider` transport, which encrypts every Yjs update before it leaves the browser and stores the CID in a Streams message. Real-time sync uses socket.io push; catch-up on reconnect replays from the last known ordinal.

### DocStore — the Google Suite layer

`DocStore.js` wraps SafecloudYjsProvider with three additions that make the system practical for document management:

**Periodic snapshots.** Every 60 seconds (or N updates), DocStore encodes the full Y.Doc state, encrypts it, and stores the snapshot CID in the stream's `attributes` field alongside the ordinal it covers. On reconnect, the provider loads the snapshot and replays only the delta since `snapshot_ordinal` — not the full history from ordinal 0. This keeps reconnect time constant regardless of document age.

**Document index.** A per-publisher index stream (`docs/index`) lists all document streams with their titles, types, and creation times. `DocStore.listDocs(jetUrl, publisherId)` reads it; `DocStore.createDoc(jetUrl, publisherId, { docId, title, type })` appends to it.

**Metadata.** Title, MIME type, and participant list are stored as stream attributes and kept in sync with the index.

### Streams access enforcement

Safecloud 4.0 adds a three-axis access control system to the Streams server, mirroring the level model from [Qbix Streams](https://github.com/Qbix/Streams). Every route is now gated.

**READ_LEVEL** — what you can see:

| Level | Value | Meaning |
|-------|-------|---------|
| `none` | 0 | Stream existence is hidden (404, not 403) |
| `see` | 10 | Knows the stream exists |
| `teaser` | 15 | Title and thumbnail, no content |
| `relations` | 20 | Which streams this one relates to |
| `content` | 23 | Full document body |
| `fields` | 25 | Extra attribute fields |
| `participants` | 30 | Participant list and counts |
| `messages` | 35 | Full message history |
| `max` | 40 | No restriction |

**WRITE_LEVEL** — what you can do:

| Level | Value | Meaning |
|-------|-------|---------|
| `none` | 0 | No write access |
| `join` | 10 | Subscribe / become participant |
| `vote` | 13 | Cast a vote |
| `suggest` | 15 | Suggest edits |
| `ephemeral` | 16 | Transient messages (cursors, presence) |
| `contribute` | 18 | Comment |
| `fork` | 19 | Fork the stream |
| `post` | 20 | Append a message |
| `relate` | 23 | Put this file in a folder |
| `relations` | 25 | Manage relations |
| `edit` | 30 | Modify stream content/attributes |
| `closePending` | 35 | Mark stream as close-pending |
| `close` | 40 | Close / archive |

**ADMIN_LEVEL** — who you can grant access to:

| Level | Value | Meaning |
|-------|-------|---------|
| `none` | 0 | No admin access |
| `tell` | 10 | Tell others about the stream |
| `share` | 15 | Generate share links |
| `invite` | 20 | Grant access rows to specific users |
| `manage` | 30 | Change ACL defaults, inheritAccess |
| `own` | 40 | Full ownership |

**Access calculation** (`calculateAccess(byUserId, stream)`): takes the MAX of stream public defaults, direct access rows, and the `inheritAccess` chain (recursive, with per-axis caps and cycle detection). The publisher of a stream always gets 40/40/40.

**Route enforcement:**

| Route | Guard |
|-------|-------|
| `GET /stream` | readLevel ≥ see (10); returns 404 below that; strips fields above caller's level |
| `POST /stream` | Open; creator auto-granted 40/40/40 in access table |
| `POST /message` | writeLevel ≥ post (20) |
| `GET /message`, `GET /messages` | readLevel ≥ messages (35) |
| `POST /subscribe` | writeLevel ≥ join (10) |
| `PATCH /stream` | writeLevel ≥ edit (30) for content; adminLevel ≥ manage (30) for ACLs |
| `POST /access` | adminLevel ≥ invite (20); can't grant more than you have |
| `DELETE /access` | adminLevel ≥ invite (20) |
| `GET /access` | adminLevel ≥ invite (20) |
| `POST /relate` | writeLevel ≥ relate (23) |
| `DELETE /relate` | adminLevel ≥ manage (30) |

Full documentation with diagrams: [`web/streams-access.html`](web/streams-access.html)

### inheritAccess — folder → file access cascade

When a file stream is put into a folder, the client can request that access on the folder cascade into the file. The file stream's `inheritAccess` JSON column stores an array of parent entries:

```json
[
  ["alice", "docs/files-finance"],
  ["alice", "docs/files-shared", [40, 20, 0]]
]
```

Each entry is `[publisherId, streamName]` or `[publisherId, streamName, [readCap, writeCap, adminCap]]`. Caps default to 40 (uncapped) when omitted. When `calculateAccess` runs on the file, it recursively computes the caller's access on each parent and applies the caps, then takes the max across all sources.

A direct access row on the file always participates in the MAX. To restrict a user below what inheritance would give, remove them from the parent's access entirely.

`POST /relate` creates the relationship and optionally appends the inheritAccess entry:

```json
POST /Streams/relate
{
  "publisherId":   "alice",
  "streamName":    "docs/file-q3",
  "toPublisherId": "alice",
  "toStreamName":  "docs/files-finance",
  "inheritAccess": true,
  "caps":          [40, 20, 0]
}
```

### SafeDB migration — no more native dependencies

Streams.js now uses SafeDB (`classes/Safecloud/DB/`) instead of better-sqlite3. SafeDB is a pure-JavaScript columnar database engine with a better-sqlite3-compatible API:

- `new Database(path)`, `db.prepare(sql).run/get/all()`, `db.exec(sql)`, `db.transaction(fn)` — same interface, drop-in replacement
- Per-column file storage: each table is a directory, each column is a separate JSON file. Hot columns stay in OS page cache; cold columns are evicted.
- MySQL wire protocol server: any MySQL client (PHP PDO, Python, Go, Grafana) can query Streams tables over TCP port 3306
- Zero native compilation: no node-gyp, no Python, no C compiler. `npm install` just works on any platform, any architecture.

**New SafeDB features added for this migration:**

| Feature | Description |
|---------|-------------|
| `INSERT IGNORE INTO` | Silently skips rows that conflict on primary key |
| `ON DUPLICATE KEY UPDATE` | Upserts: on PK conflict, applies SET clauses. Supports `VALUES(col)` (MySQL) and `excluded.col` (SQLite) syntax, plus arithmetic (`count = count + 1`) |
| `ALTER TABLE ADD COLUMN` | Adds a column with a default value, backfills all existing rows, updates the live schema immediately |
| UPDATE param fix | SET params are now correctly consumed before WHERE params |

The Streams data directory changes from a single `local/streams.db` SQLite file to a `local/streams.sc/` directory containing `catalog.json` and per-table column files. Existing deployments need a one-time migration (import the SQLite data via the MySQL wire protocol or a script).

## Safecloud 3.8

Released 2026-11-05. See [CHANGELOG.md](CHANGELOG.md) for full details.

**Payment replay protection.** `RightsManagement.verifyPublisherAuth()` now rejects replay attacks. Every `publisherAuth` token carries a `nonce`; on first successful verification the nonce is recorded in a `used_nonces` table. A second request with the same token returns 409 Conflict. Expired nonces are cleaned up automatically.

**Admin control panel.** New single-page HTML admin UI at `/Safecloud/admin/` with a JSON API. Gives operators a live dashboard for rights-management state: registered roots, publishers, grant chains, rate-limit buckets, and used nonces. Optional bearer-token auth via `Safecloud.admin.token`. WebAuthn passkey authentication for admin sessions.

**Admin routes:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/Safecloud/admin/` | HTML SPA |
| GET | `/Safecloud/admin/api/stats` | Aggregate counts |
| GET | `/Safecloud/admin/api/roots` | Root list |
| GET | `/Safecloud/admin/api/roots/:cid` | Root detail + grant chain |
| GET/DELETE | `/Safecloud/admin/api/publishers` | Publisher list / deregister |
| GET/POST | `/Safecloud/admin/api/chain/:cid` | Grant chain read / append |
| GET/DELETE | `/Safecloud/admin/api/rate-limits` | Rate-limit buckets |
| GET | `/Safecloud/admin/api/nonces` | Active nonces |

## Test suite

```
node tests/streams_safedb.test.js    # 26 tests — access, inheritAccess, upserts, WAL, transactions
node tests/db/run_all.js             # 192 tests — full SafeDB engine coverage
```

## Version history

| Version | Focus |
|---------|-------|
| **4.0** | Collaborative editors, Streams access enforcement, inheritAccess, SafeDB migration |
| **3.8** | Payment replay protection, admin control panel |
| **3.7** | MySQL wire protocol for SafeDB |
| **3.6** | SafeDB columnar storage engine |
| **3.5** | Adaptive drop selection, EMA ranking |
| **3.4** | Pluggable storage backends (S3, Filesystem, Arweave, Filecoin, WebDAV, Rclone) |
| **3.3** | IPFS/IPNS pinning integration |
| **3.2** | Persistent SafecloudDB, Jet HTTP file serving, ML-DSA-65 governance attestation |
| **3.1** | PQClaim ML-DSA-65 scanner authorization |
| **3.0** | TEE attestation (6 providers), content moderation |
| **2.x** | Safebux micropayments, OCP authorization/payment verification |
| **1.x** | Core storage network: chunking, encryption, Merkle proofs, Drop/Jet/Cloud |
