# Safecloud Storage Backends

Safecloud 3.4 introduces a pluggable server-side storage backend for Jets.
By default, chunks are stored in browser-based **IndexedDB** inside each Drop
node (the original behaviour). When a Jet is configured with a different
backend, all chunk I/O is routed through a local synthetic Drop (`__local_s3__`)
that talks directly to the backend — no socket.io round-trips, no changes to
the Safebux accounting, challenge, or slash logic.

---

## Configuration

Set `Safecloud.storage.backend` in your plugin config (or override with
`Q.Config.set`):

```json
{
  "Safecloud": {
    "storage": {
      "backend": "s3",
      "s3": {
        "endpoint":        "https://<account>.r2.cloudflarestorage.com",
        "region":          "auto",
        "bucket":          "my-safecloud-bucket",
        "accessKeyId":     "<key-id>",
        "secretAccessKey": "<secret>",
        "forcePathStyle":  false
      }
    }
  }
}
```

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `backend` | `"indexeddb"` \| `"s3"` | `"indexeddb"` | Storage backend to use |
| `localGB` | number | `1000` | Hint for IndexedDB-based Drops (ignored by S3 backend) |
| `s3.endpoint` | string \| null | `null` | Custom endpoint URL; omit for AWS S3 |
| `s3.region` | string | `"us-east-1"` | AWS region; set `"auto"` for Cloudflare R2 |
| `s3.bucket` | string | `null` | **Required** when `backend` is `"s3"` |
| `s3.accessKeyId` | string | `null` | **Required** |
| `s3.secretAccessKey` | string | `null` | **Required** |
| `s3.forcePathStyle` | boolean | `false` | Set `true` for MinIO and other self-hosted providers |

---

## Required npm dependency

The S3 backend uses the official AWS SDK v3 client:

```bash
npm install @aws-sdk/client-s3
```

If the package is missing, Safecloud logs an error and refuses to start with
`backend: "s3"`.

---

## Required IAM / API permissions

The Jet only needs **object-level** read/write on the bucket. Bucket
management permissions are **not** required and should not be granted.

Minimum permission set (AWS IAM policy example):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:HeadObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-safecloud-bucket",
        "arn:aws:s3:::my-safecloud-bucket/*"
      ]
    }
  ]
}
```

For providers that use token-based policies rather than AWS IAM (R2, B2, etc.),
see the provider-specific sections below.

---

## Provider examples

### Cloudflare R2

R2 is the recommended provider: zero egress fees, S3-compatible API, global
replication.

1. Create a bucket in the Cloudflare dashboard → **R2 → Create bucket**.
2. Create an API token: **R2 → Manage R2 API Tokens → Create API Token**.
   - Permissions: **Object Read & Write** on the specific bucket.
   - You do **not** need Admin Read or Bucket Create/Delete.
3. Copy the **Account ID** from your R2 dashboard.

```json
{
  "Safecloud": {
    "storage": {
      "backend": "s3",
      "s3": {
        "endpoint":        "https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
        "region":          "auto",
        "bucket":          "safecloud-chunks",
        "accessKeyId":     "<R2_ACCESS_KEY_ID>",
        "secretAccessKey": "<R2_SECRET_ACCESS_KEY>",
        "forcePathStyle":  false
      }
    }
  }
}
```

Environment variables for CI / Docker:

```bash
R2_ENDPOINT=https://<ACCOUNT_ID>.r2.cloudflarestorage.com
R2_REGION=auto
R2_BUCKET=safecloud-chunks
R2_ACCESS_KEY_ID=<key>
R2_SECRET_ACCESS_KEY=<secret>
```

---

### Backblaze B2

B2 uses an S3-compatible API endpoint per region.

1. Create a bucket: **B2 Cloud Storage → Create a Bucket**.
   - File type: **Private**.
2. Create an application key: **App Keys → Add a New Application Key**.
   - Restrict to the bucket you just created.
   - Capabilities: `readFiles`, `writeFiles`, `deleteFiles`, `listBuckets`,
     `listFiles`.

```json
{
  "Safecloud": {
    "storage": {
      "backend": "s3",
      "s3": {
        "endpoint":        "https://s3.us-west-004.backblazeb2.com",
        "region":          "us-west-004",
        "bucket":          "safecloud-chunks",
        "accessKeyId":     "<B2_KEY_ID>",
        "secretAccessKey": "<B2_APPLICATION_KEY>",
        "forcePathStyle":  false
      }
    }
  }
}
```

> **Tip:** The S3-compatible endpoint looks like
> `https://s3.<region>.backblazeb2.com`. Find your region in the bucket's
> *Endpoint* column in the B2 dashboard.

---

### MinIO (self-hosted)

MinIO works well for development, on-premises deployments, and air-gapped
environments.

Start MinIO (Docker):

```bash
docker run -d \
  -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  --name minio \
  quay.io/minio/minio server /data --console-address ":9001"
```

Create a bucket and access key via the MinIO Console (`http://localhost:9001`)
or with the `mc` CLI:

```bash
mc alias set local http://localhost:9000 minioadmin minioadmin
mc mb local/safecloud-chunks
mc admin user add local safecloud-svc safecloud-secret
mc admin policy attach local readwrite --user safecloud-svc
```

Safecloud config:

```json
{
  "Safecloud": {
    "storage": {
      "backend": "s3",
      "s3": {
        "endpoint":        "http://localhost:9000",
        "region":          "us-east-1",
        "bucket":          "safecloud-chunks",
        "accessKeyId":     "safecloud-svc",
        "secretAccessKey": "safecloud-secret",
        "forcePathStyle":  true
      }
    }
  }
}
```

> **Important:** `forcePathStyle: true` is required for MinIO and most
> self-hosted providers that don't support virtual-hosted-style bucket URLs.

---

## Running the integration tests

The test suite in `tests/storage_s3.test.js` runs automatically against the
mock S3 client. To additionally run the live integration tests against a real
S3-compatible bucket, export these environment variables before running:

```bash
# Cloudflare R2
export R2_ENDPOINT=https://<ACCOUNT_ID>.r2.cloudflarestorage.com
export R2_REGION=auto
export R2_ACCESS_KEY_ID=<key>
export R2_SECRET_ACCESS_KEY=<secret>
export R2_BUCKET=safecloud-test

# Backblaze B2
export R2_ENDPOINT=https://s3.us-west-004.backblazeb2.com
export R2_REGION=us-west-004
# ... same key vars

# MinIO
export R2_ENDPOINT=http://localhost:9000
export R2_REGION=us-east-1
export R2_FORCE_PATH_STYLE=true
# ... same key vars

node tests/storage_s3.test.js
```

The live tests write a single timestamped test object, assert it round-trips
correctly, then delete it. They leave no permanent data in the bucket.

---

## Security notes

- **Never commit credentials.** Use environment variables or a secrets manager.
- The Jet only reads the `secretAccessKey` at startup; it is never sent to
  clients over socket.io.
- Chunks stored in S3 are always encrypted at rest (the ciphertext+tag+iv
  envelope is opaque to the storage layer).
- Use bucket-level access policies to ensure only the Jet's service account
  can read or write chunk objects.
- For R2 and B2, restrict API tokens to the specific bucket; do not grant
  account-wide permissions.
