# Safecloud Storage Backends

Safecloud 3.4+ introduces a pluggable server-side storage backend for Jets.
By default, chunks are stored in browser-based **IndexedDB** inside each Drop
node (the original behaviour). When a Jet is configured with a different
backend, all chunk I/O is routed through a local synthetic Drop (`__local_s3__`)
that talks directly to the backend — no socket.io round-trips, no changes to
the Safebux accounting, challenge, or slash logic.

---

## Quick-pick decision matrix

| Situation | Recommended backend |
|-----------|---------------------|
| Raspberry Pi / home server | **filesystem** |
| Nextcloud / ownCloud / NAS | **webdav** |
| AWS / Cloudflare R2 / Backblaze B2 / MinIO | **s3** |
| Any of 40+ providers (Google Drive, Dropbox, OneDrive, SFTP, …) | **rclone** |
| Pay-once permanent storage | **arweave** |
| Filecoin long-term deals | **filecoin** |
| Develop / test only | **indexeddb** (default) |

---

## Configuration

Set `Safecloud.storage.backend` in your plugin config (or override with
`Q.Config.set`):

```json
{
  "Safecloud": {
    "storage": {
      "backend": "filesystem",
      "filesystem": {
        "storageDir": "/var/safecloud/chunks"
      }
    }
  }
}
```

---

## Backends

### `indexeddb` (default)

No config needed.  Chunks are stored in each Drop's browser-based IndexedDB.
Ideal for development and browser-hosted Drops.  Not suitable for production
Jets that need persistence across process restarts.

---

### `filesystem`

Stores chunks as files under a local directory.  Two-level directory sharding
avoids inode limits on large stores:

```
{storageDir}/{cid[0..1]}/{cid}.bin
```

**Zero external dependencies** — uses only Node.js built-ins.  Great for
Raspberry Pi and home-server deployments.

#### Config keys

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `filesystem.storageDir` | string | `null` | **Required.** Absolute path to the root storage directory. Created if absent. |

#### Example

```json
{
  "Safecloud": {
    "storage": {
      "backend": "filesystem",
      "filesystem": {
        "storageDir": "/var/safecloud/chunks"
      }
    }
  }
}
```

---

### `s3`

Stores chunks as S3 objects.  Supports AWS S3, Cloudflare R2, Backblaze B2,
MinIO, and any S3-compatible provider.

#### Required npm dependency

```bash
npm install @aws-sdk/client-s3
```

#### Config keys

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `s3.endpoint` | string \| null | `null` | Custom endpoint URL; omit for AWS S3 |
| `s3.region` | string | `"us-east-1"` | AWS region; set `"auto"` for Cloudflare R2 |
| `s3.bucket` | string | `null` | **Required** |
| `s3.accessKeyId` | string | `null` | **Required** |
| `s3.secretAccessKey` | string | `null` | **Required** |
| `s3.forcePathStyle` | boolean | `false` | Set `true` for MinIO and other self-hosted providers |

#### Required IAM / API permissions

The Jet only needs **object-level** read/write on the bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
        "s3:HeadObject", "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

#### Provider examples

**Cloudflare R2** (zero egress fees)

```json
{
  "s3": {
    "endpoint": "https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
    "region": "auto",
    "bucket": "safecloud-chunks",
    "accessKeyId": "<R2_ACCESS_KEY_ID>",
    "secretAccessKey": "<R2_SECRET_ACCESS_KEY>"
  }
}
```

**Backblaze B2**

```json
{
  "s3": {
    "endpoint": "https://s3.us-west-004.backblazeb2.com",
    "region": "us-west-004",
    "bucket": "safecloud-chunks",
    "accessKeyId": "<B2_KEY_ID>",
    "secretAccessKey": "<B2_APPLICATION_KEY>"
  }
}
```

**MinIO (self-hosted)**

```json
{
  "s3": {
    "endpoint": "http://localhost:9000",
    "region": "us-east-1",
    "bucket": "safecloud-chunks",
    "accessKeyId": "minioadmin",
    "secretAccessKey": "minioadmin",
    "forcePathStyle": true
  }
}
```

---

### `webdav`

Stores chunks on any WebDAV server — Nextcloud, ownCloud, Box, Synology NAS,
Apache mod_dav, and others.

#### Required npm dependency

```bash
npm install webdav
```

#### Config keys

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `webdav.url` | string | `null` | **Required.** WebDAV server root URL |
| `webdav.username` | string | `null` | **Required.** Username or app-password |
| `webdav.password` | string | `null` | **Required.** Password or app-token |
| `webdav.basePath` | string | `"/safecloud"` | Remote path prefix |

#### Example (Nextcloud)

```json
{
  "Safecloud": {
    "storage": {
      "backend": "webdav",
      "webdav": {
        "url": "https://nextcloud.example.com/remote.php/dav/files/safecloud-user",
        "username": "safecloud-user",
        "password": "<APP_PASSWORD>",
        "basePath": "/safecloud"
      }
    }
  }
}
```

> **Tip:** Use Nextcloud app passwords (Settings → Security → App passwords)
> rather than your main account password.

---

### `arweave`

Stores chunks on the Arweave permaweb.  Pay once, stored forever.
Each chunk is submitted as an Arweave transaction tagged with
`safecloud-cid = <cid>`.

#### Required npm dependency

```bash
npm install arweave
```

#### Config keys

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `arweave.keyfile` | string | `null` | **Required.** Path to Arweave JWK wallet JSON file |
| `arweave.host` | string | `"arweave.net"` | Gateway host |
| `arweave.port` | number | `443` | Gateway port |
| `arweave.protocol` | string | `"https"` | `"https"` or `"http"` |
| `arweave.timeout` | number | `20000` | Request timeout ms |

#### Example

```json
{
  "Safecloud": {
    "storage": {
      "backend": "arweave",
      "arweave": {
        "keyfile": "/etc/safecloud/arweave-wallet.json",
        "host": "arweave.net",
        "port": 443,
        "protocol": "https"
      }
    }
  }
}
```

#### Notes

- `delete()` is a **no-op** — Arweave data is permanent.
- Transactions take ~2 minutes to confirm before `get()` / `has()` will find them.
- Wallet must hold AR tokens to cover transaction fees (≈ $0.01–0.10 per MB).
- For development, use [`arlocal`](https://github.com/textury/arlocal) as a local
  Arweave testnet: `npx arlocal` then set `host: "localhost"`, `port: 1984`,
  `protocol: "http"`.

---

### `filecoin`

Stores chunks via the web3.storage (Storacha) HTTP API, which creates
Filecoin storage deals.  A local JSON index maps each Safecloud CID to the
corresponding IPFS CID returned by the upload API.

#### Required npm dependency: none

Uses Node.js built-in `http`/`https` modules.

#### Config keys

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `filecoin.key` | string | `null` | **Required.** web3.storage API bearer token |
| `filecoin.indexDir` | string | `null` | **Required.** Local dir for the CID index JSON |
| `filecoin.endpoint` | string | `"https://api.web3.storage"` | Upload API base URL |
| `filecoin.gatewayUrl` | string | `"https://w3s.link/ipfs"` | IPFS gateway for retrieval |

#### Example

```json
{
  "Safecloud": {
    "storage": {
      "backend": "filecoin",
      "filecoin": {
        "endpoint": "https://api.web3.storage",
        "key": "<WEB3_STORAGE_TOKEN>",
        "indexDir": "/var/safecloud/fc-index"
      }
    }
  }
}
```

#### Notes

- `delete()` removes the **local index entry** only; existing Filecoin deals
  cannot be cancelled.
- The `indexDir` is critical — losing it means losing the mapping from your
  CIDs to IPFS CIDs (retrieval becomes impossible).  Back it up.
- Retrieval latency depends on IPFS propagation; cold retrieval from sealed
  Filecoin sectors can take minutes.

---

### `rclone`

Delegates chunk storage to the `rclone` binary, which supports **40+
cloud storage providers** including Google Drive, Dropbox, OneDrive, SFTP,
Azure Blob, and many others.  This is the escape hatch for providers not
natively supported.

#### Required: rclone binary

Install rclone and configure a named remote with `rclone config`.

```bash
# macOS
brew install rclone

# Linux
curl https://rclone.org/install.sh | sudo bash

# Configure a remote
rclone config
```

#### Config keys

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `rclone.remote` | string | `null` | **Required.** Rclone remote name (from `rclone config`) |
| `rclone.basePath` | string | `"safecloud"` | Path within the remote |
| `rclone.rclonePath` | string | `"rclone"` | Full path to the rclone binary if not in PATH |
| `rclone.timeout` | number | `30000` | Per-command timeout ms |

#### Example (Google Drive)

```bash
rclone config  # create a remote named "gdrive"
```

```json
{
  "Safecloud": {
    "storage": {
      "backend": "rclone",
      "rclone": {
        "remote": "gdrive",
        "basePath": "safecloud-chunks"
      }
    }
  }
}
```

#### Example (SFTP)

```bash
rclone config  # create a remote named "myserver"
```

```json
{
  "Safecloud": {
    "storage": {
      "backend": "rclone",
      "rclone": {
        "remote": "myserver",
        "basePath": "safecloud"
      }
    }
  }
}
```

#### Notes

- Each `put` / `get` spawns an `rclone` subprocess.  For high-throughput
  scenarios, use a native backend (s3, filesystem, webdav) instead.
- Chunks are sharded: `{remote}:{basePath}/{cid[0..1]}/{cid}.bin`

---

## Running the tests

### Unit tests (no external credentials needed)

```bash
node tests/storage_backends.test.js   # Filesystem + WebDAV mock
node tests/storage_s3.test.js         # S3 mock + optional live
```

### Live integration tests

Set environment variables before running:

**Filesystem** — no env vars needed; tests use OS temp dirs automatically.

**S3 (any provider)**
```bash
export R2_ENDPOINT=https://<ACCOUNT_ID>.r2.cloudflarestorage.com
export R2_REGION=auto
export R2_ACCESS_KEY_ID=<key>
export R2_SECRET_ACCESS_KEY=<secret>
export R2_BUCKET=safecloud-test
node tests/storage_s3.test.js
```

**WebDAV** — no live integration test yet; mock covers the interface fully.

**Arweave**
```bash
# Run arlocal for a free local testnet
npx arlocal &
# Generate a test wallet: node -e "require('arweave').init({}).wallets.generate().then(k => require('fs').writeFileSync('/tmp/arkey.json', JSON.stringify(k)))"
export ARWEAVE_KEYFILE=/tmp/arkey.json
export ARWEAVE_HOST=localhost
export ARWEAVE_PORT=1984
export ARWEAVE_PROTOCOL=http
node tests/storage_backends.test.js
```

**Filecoin**
```bash
export WEB3_STORAGE_KEY=<token from app.web3.storage>
node tests/storage_backends.test.js
```

**Rclone**
```bash
rclone config   # create a remote named e.g. "test-remote"
export RCLONE_REMOTE=test-remote
node tests/storage_backends.test.js
```

---

## Security notes

- **Never commit credentials.** Use environment variables or a secrets manager.
- The Jet only reads credentials at startup; they are never forwarded to clients.
- Chunks are **always encrypted at rest** — the ciphertext+IV+tag envelope is
  opaque to the storage backend.
- For S3/WebDAV/Filecoin, restrict API tokens to the minimum required bucket/path.
- For Arweave, secure your JWK wallet file — anyone with it can spend your AR tokens.
- For Rclone, keep the rclone config file (`~/.config/rclone/rclone.conf`)
  readable only by the Jet process (`chmod 600`).
