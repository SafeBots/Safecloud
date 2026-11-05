"use strict";
/* jshint node:true */
/**
 * Q.Safecloud.Storage.S3 — S3-compatible storage backend for Safecloud Drops.
 *
 * Implements the Safecloud storage interface:
 *   get(cid)          → Promise<Buffer|null>
 *   put(cid, buf)     → Promise<void>
 *   has(cid)          → Promise<Boolean>
 *   delete(cid)       → Promise<void>
 *   list(prefix)      → Promise<String[]>  (array of CID keys)
 *
 * Chunk key: the SHA-256 hex CID string (same layout as the existing IndexedDB
 * store). The value is an opaque Buffer — callers (Drops.js) are responsible
 * for serialisation/deserialisation of the IV+ciphertext+tag envelope.
 *
 * Supported providers (all speak S3 API):
 *   - AWS S3              (omit `endpoint`)
 *   - Cloudflare R2       (endpoint: https://<account>.r2.cloudflarestorage.com)
 *   - Backblaze B2        (endpoint: https://s3.<region>.backblazeb2.com)
 *   - Wasabi              (endpoint: https://s3.wasabisys.com)
 *   - DigitalOcean Spaces (endpoint: https://<region>.digitaloceanspaces.com)
 *   - Storj DCS           (endpoint: https://gateway.storjshare.io)
 *   - Filebase            (endpoint: https://s3.filebase.com)
 *   - MinIO               (endpoint: http://localhost:9000, forcePathStyle: true)
 *   - GCS interop         (endpoint: https://storage.googleapis.com)
 *   - Oracle OCI          (endpoint: https://<ns>.compat.objectstorage.<region>.oraclecloud.com)
 *
 * Config keys (all under Safecloud.storage.s3):
 *   endpoint         String|null  — custom S3 endpoint (omit for AWS)
 *   region           String       — default "us-east-1"
 *   bucket           String       — required
 *   accessKeyId      String       — required
 *   secretAccessKey  String       — required
 *   forcePathStyle   Boolean      — default false (set true for MinIO, self-hosted)
 *
 * @class Q.Safecloud.Storage.S3
 * @static
 */

var S3Storage = module.exports = {};

/** @private S3Client instance (set by init()) */
S3Storage._client = null;

/** @private Bucket name (set by init()) */
S3Storage._bucket = null;

/** @private Whether init() has been called successfully */
S3Storage._ready = false;

/**
 * Initialise the S3 client with provider config.
 *
 * @method init
 * @param {Object} config  Safecloud.storage.s3 config object
 * @throws {Error} if required fields are missing
 */
S3Storage.init = function (config) {
    config = config || {};

    if (!config.bucket) {
        throw new Error('Safecloud.Storage.S3: `bucket` is required');
    }
    if (!config.accessKeyId || !config.secretAccessKey) {
        throw new Error('Safecloud.Storage.S3: `accessKeyId` and `secretAccessKey` are required');
    }

    var S3Client, PutObjectCommand, GetObjectCommand,
        HeadObjectCommand, DeleteObjectCommand, ListObjectsV2Command;
    try {
        var s3mod = require('@aws-sdk/client-s3');
        S3Client             = s3mod.S3Client;
        PutObjectCommand     = s3mod.PutObjectCommand;
        GetObjectCommand     = s3mod.GetObjectCommand;
        HeadObjectCommand    = s3mod.HeadObjectCommand;
        DeleteObjectCommand  = s3mod.DeleteObjectCommand;
        ListObjectsV2Command = s3mod.ListObjectsV2Command;
    } catch (e) {
        throw new Error('Safecloud.Storage.S3: @aws-sdk/client-s3 is not installed. '
            + 'Run: npm install @aws-sdk/client-s3');
    }

    var clientConfig = {
        region: config.region || 'us-east-1',
        credentials: {
            accessKeyId:     config.accessKeyId,
            secretAccessKey: config.secretAccessKey
        }
    };

    if (config.endpoint) {
        clientConfig.endpoint = config.endpoint;
    }
    if (config.forcePathStyle) {
        clientConfig.forcePathStyle = true;
    }

    S3Storage._client = new S3Client(clientConfig);
    S3Storage._bucket = config.bucket;

    // Store command constructors for use in methods
    S3Storage._cmd = {
        Put:    PutObjectCommand,
        Get:    GetObjectCommand,
        Head:   HeadObjectCommand,
        Delete: DeleteObjectCommand,
        List:   ListObjectsV2Command
    };

    S3Storage._ready = true;
};

/**
 * Store a chunk buffer under its CID key.
 *
 * @method put
 * @param {String} cid  CID string (used as S3 object key)
 * @param {Buffer} buf  Raw chunk bytes (IV+ciphertext+tag envelope)
 * @return {Promise<void>}
 */
S3Storage.put = function (cid, buf) {
    if (!S3Storage._ready) {
        return Promise.reject(new Error('Safecloud.Storage.S3: not initialised'));
    }
    if (typeof cid !== 'string' || !cid) {
        return Promise.reject(new Error('Safecloud.Storage.S3.put: cid must be a non-empty string'));
    }
    if (!Buffer.isBuffer(buf)) {
        return Promise.reject(new Error('Safecloud.Storage.S3.put: buf must be a Buffer'));
    }

    var cmd = new S3Storage._cmd.Put({
        Bucket:      S3Storage._bucket,
        Key:         cid,
        Body:        buf,
        ContentType: 'application/octet-stream'
    });

    return S3Storage._client.send(cmd).then(function () {
        // void
    });
};

/**
 * Retrieve a chunk buffer by CID.
 *
 * @method get
 * @param {String} cid
 * @return {Promise<Buffer|null>}  null when the key does not exist
 */
S3Storage.get = function (cid) {
    if (!S3Storage._ready) {
        return Promise.reject(new Error('Safecloud.Storage.S3: not initialised'));
    }
    if (typeof cid !== 'string' || !cid) {
        return Promise.reject(new Error('Safecloud.Storage.S3.get: cid must be a non-empty string'));
    }

    var cmd = new S3Storage._cmd.Get({
        Bucket: S3Storage._bucket,
        Key:    cid
    });

    return S3Storage._client.send(cmd).then(function (response) {
        // Body is a readable stream (Node.js) or web-stream depending on environment
        return _streamToBuffer(response.Body);
    }).catch(function (err) {
        // S3 returns NoSuchKey (or NotFound for some providers) for missing keys
        if (err && (err.name === 'NoSuchKey' || err.name === 'NotFound'
                || err.$metadata && err.$metadata.httpStatusCode === 404)) {
            return null;
        }
        throw err;
    });
};

/**
 * Check whether a CID exists in the bucket without downloading it.
 *
 * @method has
 * @param {String} cid
 * @return {Promise<Boolean>}
 */
S3Storage.has = function (cid) {
    if (!S3Storage._ready) {
        return Promise.reject(new Error('Safecloud.Storage.S3: not initialised'));
    }
    if (typeof cid !== 'string' || !cid) {
        return Promise.reject(new Error('Safecloud.Storage.S3.has: cid must be a non-empty string'));
    }

    var cmd = new S3Storage._cmd.Head({
        Bucket: S3Storage._bucket,
        Key:    cid
    });

    return S3Storage._client.send(cmd).then(function () {
        return true;
    }).catch(function (err) {
        if (err && (err.name === 'NotFound' || err.name === 'NoSuchKey'
                || err.$metadata && err.$metadata.httpStatusCode === 404)) {
            return false;
        }
        throw err;
    });
};

/**
 * Delete a chunk by CID. No-ops if the key does not exist.
 *
 * @method delete
 * @param {String} cid
 * @return {Promise<void>}
 */
S3Storage.delete = function (cid) {
    if (!S3Storage._ready) {
        return Promise.reject(new Error('Safecloud.Storage.S3: not initialised'));
    }
    if (typeof cid !== 'string' || !cid) {
        return Promise.reject(new Error('Safecloud.Storage.S3.delete: cid must be a non-empty string'));
    }

    var cmd = new S3Storage._cmd.Delete({
        Bucket: S3Storage._bucket,
        Key:    cid
    });

    return S3Storage._client.send(cmd).then(function () {
        // void
    });
};

/**
 * List CID keys in the bucket, optionally filtered by prefix.
 *
 * @method list
 * @param {String} [prefix='']  Key prefix filter
 * @return {Promise<String[]>}  Array of matching CID keys
 */
S3Storage.list = function (prefix) {
    if (!S3Storage._ready) {
        return Promise.reject(new Error('Safecloud.Storage.S3: not initialised'));
    }

    prefix = (typeof prefix === 'string') ? prefix : '';

    // Collect all pages (S3 paginates at 1000 keys per request)
    function _collect(continuationToken, accumulated) {
        var params = {
            Bucket: S3Storage._bucket,
            Prefix: prefix,
            MaxKeys: 1000
        };
        if (continuationToken) {
            params.ContinuationToken = continuationToken;
        }

        var cmd = new S3Storage._cmd.List(params);
        return S3Storage._client.send(cmd).then(function (response) {
            var keys = (response.Contents || []).map(function (obj) { return obj.Key; });
            var all  = accumulated.concat(keys);

            if (response.IsTruncated && response.NextContinuationToken) {
                return _collect(response.NextContinuationToken, all);
            }
            return all;
        });
    }

    return _collect(null, []);
};

/**
 * Reset internal state (for testing only).
 * @private
 */
S3Storage._reset = function () {
    S3Storage._client = null;
    S3Storage._bucket = null;
    S3Storage._cmd    = null;
    S3Storage._ready  = false;
};

// ─── Private helpers ──────────────────────────────────────────────────────────

/**
 * Collect a Node.js Readable stream (or web ReadableStream) into a Buffer.
 * @private
 */
function _streamToBuffer(stream) {
    if (!stream) { return Promise.resolve(null); }

    // Node.js Readable (returned by the AWS SDK in Node environments)
    if (typeof stream.pipe === 'function' || typeof stream[Symbol.asyncIterator] === 'function') {
        return new Promise(function (resolve, reject) {
            var chunks = [];
            stream.on('data', function (chunk) { chunks.push(chunk); });
            stream.on('end',  function () { resolve(Buffer.concat(chunks)); });
            stream.on('error', reject);
        });
    }

    // Web ReadableStream (Deno, edge environments)
    if (typeof stream.getReader === 'function') {
        var reader = stream.getReader();
        var chunks = [];
        function _read() {
            return reader.read().then(function (result) {
                if (result.done) {
                    return Buffer.concat(chunks.map(function (c) { return Buffer.from(c); }));
                }
                chunks.push(result.value);
                return _read();
            });
        }
        return _read().then(function (buf) { return buf; });
    }

    // Already a Buffer or Uint8Array (mock environments)
    if (Buffer.isBuffer(stream) || stream instanceof Uint8Array) {
        return Promise.resolve(Buffer.isBuffer(stream) ? stream : Buffer.from(stream));
    }

    return Promise.reject(new Error('Safecloud.Storage.S3: unrecognised Body type from S3 response'));
}
