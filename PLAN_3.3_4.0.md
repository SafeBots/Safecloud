# Safecloud 3.3 and 4.0 — Release Plan

## Safecloud 3.3 — IPFS/IPNS Support

### Goal

Add optional IPFS pinning and IPNS publishing to Safecloud Jets. A node operator opts in via config; if the option is absent or `enabled: false`, the release is byte-for-byte identical in behaviour to 3.2. Nothing in the existing attestation, Drop, Swarm, or WasmRunner paths changes.

IPFS gives Safecloud nodes interoperability with the broader content-addressed ecosystem and a path to earn Safebux for serving pinned content. IPNS gives mutable, human-readable names to content that changes over time (Drop indices, stream heads, node identity).

### What changes

**Config** — new optional section under `Safecloud` in `config/plugin.json`:

```
Safecloud.ipfs
  enabled          false (default — entire feature is a no-op when absent or false)
  mode             "external" | "pinning-service"  (no embedded node in 3.3)
  apiUrl           IPFS HTTP API base, e.g. http://127.0.0.1:5001
  gatewayUrl       IPFS gateway base, e.g. http://127.0.0.1:8080
  pinningService
    endpoint       null  (Pinata, web3.storage, etc.)
    key            null
  requireSafebux   false  (true = reject unauthenticated gateway requests — future)
  sbuxPerGB        0      (accounting rate, no enforcement until requireSafebux is true)
```

**New classes**

`classes/Safecloud/Ipfs.js` — core module. Loaded only when `ipfs.enabled` is true. Methods: `connect()`, `add(buffer|stream)` → CID, `pin(cid)`, `unpin(cid)`, `pins()` → list, `cat(cid)` → stream (proxies gateway), `status(cid)` → pin status. Chooses between direct IPFS HTTP API (`mode: "external"`) and a pinning service REST API (`mode: "pinning-service"`). Does not start or manage an IPFS process — the operator runs kubo (or equivalent) separately, or uses a hosted pinning service.

`classes/Safecloud/Ipns.js` — IPNS key management. Methods: `createKey(name)`, `publish(name, cid)`, `resolve(name)` → CID, `listKeys()`. Keys are generated via the IPFS node's key API and stored locally in `safecloud_ipns` (see Storage below). IPNS publish is fire-and-forget with optional callback; resolution goes through the IPFS node's DHT.

**New Jets handlers** (registered in `Jets.js` only when `ipfs.enabled` is true)

| Handler | Route | Purpose |
|---|---|---|
| `Jets/IpfsPin.js` | `POST /ipfs/pin` | Pin a CID. Body: `{ cid }`. Returns pin record. |
| `Jets/IpfsUnpin.js` | `DELETE /ipfs/pin/:cid` | Unpin a CID. |
| `Jets/IpfsPins.js` | `GET /ipfs/pins` | List all pinned CIDs with status and size. |
| `Jets/IpfsUpload.js` | `POST /ipfs/upload` | Accept file/buffer, add to IPFS, auto-pin, return CID. |
| `Jets/IpfsGateway.js` | `GET /ipfs/:cid` and `GET /ipns/:name` | Proxy content from IPFS gateway. Records bytes served for Safebux accounting. For `/ipns/:name`, resolves to CID first. |
| `Jets/IpnsPublish.js` | `POST /ipns/publish` | Publish `{ name, cid }` under an IPNS key. Creates key if it doesn't exist. |
| `Jets/IpnsResolve.js` | `GET /ipns/resolve/:name` | Resolve IPNS name to current CID. |

**Storage** — two new SQLite tables, created in `data/safecloud.db` on first boot when IPFS is enabled. Same file used by the existing Drop accounting if any.

`safecloud_pins (cid TEXT PRIMARY KEY, pinnedAt TEXT, status TEXT, sizeBytes INTEGER, safebuxEarned TEXT, notes TEXT)`

`safecloud_ipns (name TEXT PRIMARY KEY, peerId TEXT, currentCid TEXT, updatedAt TEXT)`

**Drops integration** (optional, additive)

`Drops.js` gains a `pinToIpfs` option (default false). When true and `Ipfs` is connected, adding content to a Drop also calls `Ipfs.pin(cid)` and stores the IPFS CID alongside the Drop's native CID. No change to Drop behaviour when the option is absent.

**Safebux accounting (stub)**

`IpfsGateway.js` records bytes served per CID in `safecloud_pins.safebuxEarned`. No enforcement yet — `requireSafebux: false` means all requests are served free. The accounting rows are there so the operator can see what they're serving and what they would earn when the payment layer ships (4.x or later).

### What does NOT change in 3.3

- Attestation stack (3.2 unchanged)
- WasmRunner and SafecloudApp execution (unchanged)
- Drop storage and Swarm mesh (unchanged)
- All existing config keys (unchanged; IPFS section is purely additive)
- Existing tests all pass without an IPFS node present

### New tests

- Unit: `Ipfs.js` with a mock HTTP API — add, pin, unpin, list, cat
- Unit: `Ipns.js` with mock — createKey, publish, resolve
- Integration: full round-trip against a local kubo instance (optional, skipped in CI without `IPFS_API_URL` set)
- Jest: gateway handler serves bytes, accounting row written
- Jest: all existing tests pass with `ipfs.enabled: false` (the default)

### New docs

`IPFS.md` — operator guide: how to install kubo alongside Safecloud, how to configure a pinning service, what IPNS names look like, Safebux accounting overview.

---

## Safecloud 4.0 — Qbix Streams (Option 2)

### Goal

Make Safecloud a first-class Qbix Streams server. A Safecloud node can host Streams for one or more publishers, speak the Q.js HTTP and socket.io protocol that Qbix clients already use (`/action.php/Streams/*`, socket.io `/Q` namespace), and federate with Qbix PHP servers via the existing Streams subscription and notification system.

Storage is SQLite (via the `better-sqlite3` adapter that already exists in the platform JS codebase) rather than SafecloudDB, making this a pragmatic Option 2 port rather than a ground-up native redesign (Option 3 remains the long-term target for Drops-native storage).

This is a major version because it adds a new runtime dependency (`better-sqlite3`) and a significant new capability surface. It is still additive and backward-compatible: `Safecloud.streams.enabled: false` (the default) leaves 3.x behaviour unchanged.

### What changes

**New dependency**

`better-sqlite3` — synchronous SQLite bindings for Node.js. Already used by the Qbix Platform JS ORM layer; adding it here pulls that layer in as shared infrastructure.

**Config** — new optional section:

```
Safecloud.streams
  enabled       false (default)
  db            "./data/streams.db"
  nodeUrl       null  (the socket.io node URL advertised to clients, e.g. https://node.example.com)
  publisherIds  []    (list of publisherIds this node is authoritative for; empty = accept all)
```

**Ported ORM classes** (copied from `Qbix/Platform`, no modification needed)

```
classes/Db.js
classes/Db/Row.js
classes/Db/Query.js
classes/Db/Sqlite.js
classes/Db/Query/Sqlite.js
classes/Base/Streams/Stream.js
classes/Base/Streams/Message.js
classes/Base/Streams/Participant.js
classes/Streams/Stream.js
classes/Streams/Message.js
classes/Streams/Participant.js
```

These are stable; the only file that needs modification is `Streams/Message.js` (see below).

**Schema**

`classes/Streams/schema.sqlite.sql` — the four core tables: `streams_stream`, `streams_message`, `streams_message_total`, `streams_participant`. Derived from the existing Qbix PHP migrations, translated once to SQLite DDL. Applied on first boot when Streams is enabled and the db file does not yet exist.

**`Message.post()` rewrite** — the one gap

The existing `Streams/Message.js` uses a MySQL multi-statement query with session variables (`@Streams_messageCount`) for the atomic ordinal-increment transaction. This does not work with SQLite. Replacement is a `better-sqlite3` synchronous transaction (~30 lines) doing: lock stream row, read current messageCount, insert message at `messageCount+1`, upsert `streams_message_total`, update stream row. Everything else in `Message.js` is untouched.

**`classes/Safecloud/Streams.js`** — Safecloud Streams initializer

Loaded only when `streams.enabled` is true. Responsibilities:

- Calls `Db.setConnection('Streams', { dsn: 'sqlite://' + config.streams.db })` to wire the ORM to the SQLite file.
- Runs the schema migration if the db file is new.
- Calls `Streams.listen({ nodeUrl: config.streams.nodeUrl }, app)` where `app` is Safecloud's existing Express instance — this attaches socket.io `/Q` namespace and the `Streams/Stream/join`, `Streams/Stream/leave`, `Streams/Message/post` socket events.
- Registers the HTTP route handlers below.

**New Jets handlers** (registered only when `streams.enabled` is true)

| Handler | Route | Purpose |
|---|---|---|
| `Jets/StreamsGet.js` | `GET /action.php/Streams/get` | Fetch one or more streams. Calls `Streams.fetch()` with ACL check. |
| `Jets/StreamsMessage.js` | `POST /action.php/Streams/message` | Post a message. Calls the rewritten `Message.post()`. |
| `Jets/StreamsCreate.js` | `POST /action.php/Streams/create` | Create a stream. Calls `Stream.save()` via ORM. |
| `Jets/StreamsSubscribe.js` | `POST /action.php/Streams/subscribe` | Join/leave participant. Calls `Participant.save()`. |
| `Jets/StreamsBatch.js` | `POST /action.php/Streams/batch` | Batch fetch multiple streams. Returns `{publisherId, streamName, messageCount, updatedTime}` tuples. Also serves as the federation checkpoint endpoint. |

**Users stub**

Safecloud 4.0 does not implement the full Qbix Users stack. Instead it maps Safecloud identity (the node's signing key, or a client token issued by the Jet) to a Qbix-compatible `userId` string. For V1 this is sufficient to authenticate message posters and stream owners. A full Users implementation (profile, avatar, friends graph) is deferred.

**Client-side federation**

`Q.baseUrl.routers[]` configuration example ships in `Qbix.md` and in a new `docs/StreamsFederation.md`. Clients add a router that returns the Safecloud node URL for any `publisherId` in the configured set. No change to Q.js itself.

**IPFS integration** (conditional on 3.3 being enabled)

When both `streams.enabled` and `ipfs.enabled` are true:

- Stream content blobs (the `content` field of messages) are stored on IPFS; the IPFS CID is written into the message's `instructions` field alongside the plaintext.
- Stream icon and cover assets are auto-pinned on `Stream.create()`.
- On each `Message.post()`, `Ipns.publish(publisherId + '/' + streamName, latestCid)` is called to update the IPNS pointer for the stream. This gives each stream a stable `ipns://{publisherId}/{streamName}` address that resolves to its current head.

Neither feature is required; the Streams stack works without IPFS. The calls are gated on `Ipfs.isConnected()`.

### Backward compatibility

- All 3.x config, attestation, Drop, Swarm, and WasmRunner behaviour unchanged.
- `streams.enabled: false` (the default) means none of the new classes are loaded, `better-sqlite3` is not required (it is an optional peer dependency), and no new routes are registered.
- Existing Qbix PHP servers are unaffected; the new handlers speak the same HTTP and socket.io protocol they already use, so clients can talk to either server transparently.

### New tests

- Unit: `Message.post()` transaction — concurrent posts on the same stream produce strictly increasing ordinals with no gaps.
- Unit: `Streams.fetch()` with ACL — readLevel enforcement, missing stream returns null.
- Unit: `StreamsBatch.js` — returns correct `messageCount` and `updatedTime` per stream.
- Integration: full round-trip — create stream, post 10 messages, verify ordinals, fetch via batch.
- Integration: socket.io — client joins, receives push on post.
- Integration: federation checkpoint — two nodes exchange batch tuples, identify divergence.
- All existing 3.x tests pass with `streams.enabled: false`.

### New docs

`docs/StreamsFederation.md` — how to configure `Q.baseUrl.routers[]`, what the batch checkpoint endpoint returns, how to set up a Safecloud node as a Streams server for a set of publisherIds.

Update `Qbix.md` with the Streams-specific config options and the Users stub behaviour.

---

## Safecloud 3.4 — S3-Compatible Storage Backend

### Goal

Add an S3-compatible Drop storage backend alongside the existing IndexedDB browser store. A single S3 adapter — using the AWS SDK's standard endpoint/credentials interface — unlocks every major object storage provider in one release. Operators point a config section at their preferred provider; Safebux economics and the encrypted-chunk protocol are unchanged.

### What changes

**New dependency**

`@aws-sdk/client-s3` — the AWS v3 modular SDK. Small footprint; only `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, and `ListObjectsV2` are used.

**Config** — new optional section under `Safecloud.storage`:

```
Safecloud.storage
  backend        "indexeddb"  (default — IndexedDB browser store, existing behaviour)
  s3
    endpoint     null   (omit for AWS; set for any S3-compatible provider)
    region       "us-east-1"
    bucket       null
    accessKeyId  null
    secretAccessKey  null
    forcePathStyle   false  (true for MinIO and most self-hosted)
```

When `backend` is `"indexeddb"` or omitted, 3.3 behaviour is unchanged. When `backend` is `"s3"`, the Drop layer stores and retrieves chunks via the S3 API instead of IndexedDB. The chunk key is the CID (SHA-256 hex), consistent with the existing store layout.

**New class** `classes/Safecloud/Storage/S3.js` — implements the same interface as the IndexedDB store: `get(cid)`, `put(cid, buf)`, `has(cid)`, `delete(cid)`, `list(prefix)`. Loaded only when `storage.backend` is `"s3"`.

**`Drops.js` adapter hook** — `Drops.js` currently hard-wires to IndexedDB. The refactor extracts a one-method storage interface (`store.get/put/has/delete/list`) and injects the configured backend. No change to the proof-of-storage challenge logic, reputation tracking, or Safebux accounting.

### Supported providers (one config, all of these)

| Provider | Notes |
|---|---|
| **AWS S3** | Reference implementation; omit `endpoint` |
| **Cloudflare R2** | No egress fees — best economics for a public storage network |
| **Backblaze B2** | $0.01/GB egress, cheapest of the traditional CDN-backed providers |
| **Wasabi** | No egress fees, $7/TB/month flat |
| **DigitalOcean Spaces** | $0.02/GB/month + $0.01/GB egress; good brand recognition |
| **Storj DCS** | Decentralized, S3-compatible, end-to-end encrypted at the provider layer |
| **Filebase** | S3 API, IPFS-pinned backend — natural complement to 3.3 |
| **MinIO** | Self-hosted; `forcePathStyle: true` |
| **Google Cloud Storage** | Via GCS S3 interoperability endpoint |
| **Oracle Object Storage** | S3-compatible |
| **Linode / Akamai Object Storage** | S3-compatible |
| **Vultr Object Storage** | S3-compatible |

Cloudflare R2 and Wasabi are the recommended defaults for operators who want zero egress costs. Filebase is the natural pick for operators who also enable 3.3 IPFS, since Filebase pins every object to IPFS automatically.

### What does NOT change in 3.4

- IPFS/IPNS from 3.3 (unchanged; IPFS is content-addressed pinning, S3 is chunk storage — orthogonal)
- Attestation, Swarm, WasmRunner, Streams (unchanged)
- Browser-Drop behaviour (`backend: "indexeddb"`, the default)
- Safebux accounting and proof-of-storage challenges (backend-agnostic)

### New tests

- Unit: S3 backend round-trips a chunk (`get`/`put`/`has`/`delete`) against a MinIO test container.
- Unit: `Drops.js` storage interface works with both IndexedDB mock and S3 mock.
- Integration: full upload-then-serve cycle against a live Cloudflare R2 bucket (optional, gated on `R2_ENDPOINT` env var in CI).
- All existing tests pass with `storage.backend` absent.

### New docs

`docs/storage-backends.md` — operator guide covering each provider: endpoint format, required IAM/API permissions (only object read/write, no bucket management), and a worked example config for R2, B2, and MinIO.

---

## Safecloud 3.5 — Additional Storage Protocols

### Goal

Round out the storage backend ecosystem beyond S3 to cover decentralized-native protocols (Arweave, Filecoin) and the self-hosted NAS market (WebDAV, local filesystem). Each new backend is an optional peer dependency and a separate class under `classes/Safecloud/Storage/`.

### What changes

**New backends**

`Storage/Filesystem.js` — local filesystem store. Chunks written as `{storageDir}/{cid[0:2]}/{cid}.bin` (two-level directory sharding to avoid inode limits). Zero external dependencies. Enables Raspberry Pi, home server, and bare-metal operator onboarding — the simplest possible path from zero to earning Safebux.

`Storage/WebDAV.js` — WebDAV client using `webdav` (npm). Covers Nextcloud, ownCloud, Box, any NAS with WebDAV support. Lets existing self-hosters plug their storage directly into Safecloud without migrating to S3.

`Storage/Arweave.js` — Arweave upload via `arweave` npm package. Pay-once permanent storage; the CID is stored as an Arweave transaction tag so retrieval is by Arweave TXID → CID index. Best fit for archival content where the operator wants "store once, serve forever" economics with no ongoing storage cost. New config sub-section: `storage.arweave.keyfile` path.

`Storage/Filecoin.js` — Filecoin deal creation via the Estuary or web3.storage HTTP API (both expose a standard `/upload` endpoint). Filecoin is the incentivized storage layer that pairs with IPFS (from 3.3); content pinned via the 3.3 IPFS adapter can be durably backed to Filecoin here. New config: `storage.filecoin.endpoint`, `storage.filecoin.key`.

**Rclone fallback** — `Storage/Rclone.js` shells out to `rclone` (if installed) for anything not covered above. Rclone supports 40+ backends including Azure Blob, Google Drive, SFTP, S3-compatible stores not in the tested list, and many others. This is an escape hatch, not a primary path — no npm dependency, just a subprocess call with a config-defined remote name.

**Config** — new `backend` values: `"filesystem"`, `"webdav"`, `"arweave"`, `"filecoin"`, `"rclone"`. Each has its own sub-section mirroring the S3 pattern above.

### What does NOT change in 3.5

Everything from 3.3 and 3.4. The storage interface is already abstracted in 3.4; 3.5 is purely additive backends behind the same interface.

### New tests

- Unit: filesystem backend — shard path calculation, read-after-write, delete.
- Unit: WebDAV backend with a mock WebDAV server (express-webdav).
- Integration: Arweave against the public devnet (gated on `ARWEAVE_KEY` in CI).
- Integration: Filecoin against web3.storage staging (gated on `WEB3_STORAGE_KEY` in CI).

### New docs

Update `docs/storage-backends.md` with the new backends and a decision matrix:

| I want… | Use |
|---|---|
| Cheapest egress | R2 or Wasabi |
| Self-hosted, simplest | Filesystem |
| Self-hosted NAS/Nextcloud | WebDAV |
| Permanent archival | Arweave |
| Decentralized + IPFS | Filecoin via Filebase or web3.storage |
| Something not on this list | Rclone |

---

## Safecloud 3.6 — Binary Releases via GitHub Actions

### Goal

Publish single-file native binaries for every major platform so an operator can download one file and run it — no Node installation, no `npm install`, no build tools. The trust model is: Safecloud is open-source, the build workflow is in the repo, and GitHub Actions' OIDC attestation lets anyone verify that the binary on the release page was produced from the tagged source commit and nothing else.

### Build tooling

Node 21+ ships `node --experimental-sea-config` (Single Executable Applications), which bundles a Node app and the Node runtime into one binary. As of Node 22 the SEA API is stable. No third-party bundler needed — the CI workflow uses the Node version it ships to build itself.

Fallback: if SEA produces an unacceptably large binary for any target, the maintained `@yao-pkg/pkg` fork (the community continuation of Vercel's deprecated `pkg`) is the alternative. Decision deferred to when the first CI run reveals binary sizes.

### Target matrix

| Target | Runner | Output filename |
|---|---|---|
| Linux x64 | `ubuntu-latest` | `safecloud-jet-linux-x64` |
| Linux arm64 | `ubuntu-24.04-arm` | `safecloud-jet-linux-arm64` |
| macOS x64 (Intel) | `macos-13` | `safecloud-jet-macos-x64` |
| macOS arm64 (Apple Silicon) | `macos-latest` | `safecloud-jet-macos-arm64` |
| Windows x64 | `windows-latest` | `safecloud-jet-windows-x64.exe` |

### Workflow

`.github/workflows/release.yml` — triggers on `push` to a tag matching `v*.*.*`. Steps per target:

1. Checkout at the tagged commit.
2. Install Node (the version in `engines.node`).
3. `npm ci --production`.
4. Build the SEA blob and inject it into the Node binary.
5. Strip debug symbols (Linux/macOS).
6. Upload artifact.

After all matrix jobs: a `release` job collects the five binaries, computes `sha256sum` for each, writes a `checksums.txt`, and publishes a GitHub Release with all six files attached.

**GitHub Actions artifact attestation** — the workflow calls `actions/attest-build-provenance` on each binary before upload. This writes an OIDC-signed provenance statement to GitHub's public transparency log. Any operator can run `gh attestation verify safecloud-jet-linux-x64 --repo qbix/safecloud` and get a machine-readable proof that the file came from the tagged workflow run on the tagged commit. No trust in Safebots Inc. required — trust in GitHub's signing infrastructure, which is the same trust model as any Homebrew formula or apt package from a major distro.

**Code-signing (deferred)** — macOS notarization and Windows Authenticode signing require Apple and Microsoft certificates and add CI complexity. These are desirable for 3.6.x but not blocking for the initial 3.6.0 drop; the provenance attestation covers the core trust claim in the meantime.

### New docs

`docs/install.md` — one-page install guide. Three paths: download binary (recommended for operators), `npm install -g safecloud` (for developers), `docker run` (for container deployments — Dockerfile also added in 3.6). The page leads with the binary path and the attestation verification command.

---

## Version sequence

| Version | Ships |
|---|---|
| 3.2.0 | ML-DSA-65 attestation (current) |
| **3.3.0** | Optional IPFS/IPNS support (additive) |
| **3.4.0** | S3-compatible Drop storage backend — AWS, R2, B2, Wasabi, MinIO, Storj, Filebase, GCS, and more |
| **3.5.0** | Additional storage protocols — local filesystem, WebDAV, Arweave, Filecoin, Rclone fallback |
| **3.6.0** | GitHub Actions binary releases — Linux x64/arm64, macOS Intel/Apple Silicon, Windows x64; provenance attestation; Dockerfile |
| **4.0.0** | Qbix Streams over SQLite (optional, additive); `better-sqlite3` as optional peer dep |
