'use strict';
/**
 * AMD SEV-SNP raw attestation report verifier.
 *
 * Wire format: 1184-byte binary report (SEV-SNP ABI spec, section 7.3).
 * Signature:   ECDSA P-384 (ES384) over SHA-384 of report bytes [0x000..0x29F].
 * Root of trust: VCEK certificate (chip-unique) → AMD root CA.
 *
 * Report layout (offsets in hex, all little-endian):
 *   0x000  version          u32     (should be 2)
 *   0x004  guest_svn        u32
 *   0x008  policy           u64     (bitfield)
 *   0x010  family_id        16B
 *   0x020  image_id         16B
 *   0x030  vmpl             u32
 *   0x034  signature_algo   u32     (1 = ECDSA P-384)
 *   0x038  platform_version u64
 *   0x040  platform_info    u64
 *   0x048  flags            u32
 *   0x04C  reserved0        u32
 *   0x050  report_data      64B     ← caller-supplied data (we use for scannerCID)
 *   0x090  measurement      48B     ← SHA-384 of guest firmware+kernel+initrd
 *   0x0C0  host_data        32B
 *   0x0E0  id_key_digest    48B
 *   0x110  author_key_digest 48B
 *   0x140  report_id        32B
 *   0x160  report_id_ma     32B
 *   0x180  reported_tcb     u64
 *   0x188  reserved1        24B
 *   0x1A0  chip_id          64B
 *   0x1E0  reserved2        192B
 *   0x2A0  signature        144B (r=72B, s=72B, each zero-padded to 72B)
 *   0x330  reserved3        (rest of 1184B)
 *
 * Signed bytes: [0x000 .. 0x29F] (672 bytes), i.e. everything before the signature.
 *
 * @module Attestation/providers/SEV_SNP
 */

var crypto    = require('crypto');
var certchain = require('../util/certchain');

var REPORT_SIZE      = 1184;
var SIGNED_END       = 0x2A0;   // 672 bytes
var SIG_OFFSET       = 0x2A0;
var SIG_COMPONENT    = 72;      // each of r, s is 72 bytes (P-384 = 48B, padded to 72 here)
var REPORT_DATA_OFF  = 0x050;
var REPORT_DATA_LEN  = 64;
var MEASUREMENT_OFF  = 0x090;
var MEASUREMENT_LEN  = 48;
var CHIP_ID_OFF      = 0x1A0;
var CHIP_ID_LEN      = 64;

/**
 * Verify a raw AMD SEV-SNP attestation report.
 *
 * @param {Buffer} report         1184-byte raw report.
 * @param {Buffer} vcekCertDER    VCEK certificate (DER), chip-unique.
 * @param {Buffer} amdRootDER     AMD root CA certificate (DER).
 * @param {Object} [opts]
 * @param {boolean} [opts.skipChain]  Skip cert chain check (for unit tests with mock key).
 * @returns {{ provider, version, measurement, reportData, scannerCID, chipId }}
 * @throws on any verification failure.
 */
function verify(report, vcekCertDER, amdRootDER, opts) {
    opts = opts || {};

    if (!Buffer.isBuffer(report) || report.length < REPORT_SIZE) {
        throw new Error('sev_snp: report must be a Buffer of at least ' + REPORT_SIZE + ' bytes');
    }

    var version   = report.readUInt32LE(0x000);
    if (version !== 2) {
        throw new Error('sev_snp: unexpected report version ' + version + ' (expected 2)');
    }

    var sigAlgo = report.readUInt32LE(0x034);
    if (sigAlgo !== 1) {
        throw new Error('sev_snp: unsupported signature algorithm ' + sigAlgo + ' (expected 1 = ECDSA P-384)');
    }

    // Extract ECDSA signature: r (72B) and s (72B), each P-384 value zero-padded.
    // We need the P-384 portion (last 48 bytes of each 72-byte field — or
    // first 48B; AMD zero-pads on the RIGHT to 72B, not the left).
    // Actually AMD pads on the RIGHT to 72B in the raw report: r is in [0..47],
    // bytes [48..71] are zero padding.
    var rPadded = report.slice(SIG_OFFSET,                SIG_OFFSET + SIG_COMPONENT);
    var sPadded = report.slice(SIG_OFFSET + SIG_COMPONENT, SIG_OFFSET + 2 * SIG_COMPONENT);
    var r = rPadded.slice(0, 48);
    var s = sPadded.slice(0, 48);

    // P1363 format: r || s, each exactly 48 bytes (no DER wrapping).
    var sigP1363 = Buffer.concat([r, s]);

    // Signed portion of the report.
    var signedBytes = report.slice(0, SIGNED_END);

    // Get the VCEK public key (P-384) — either from the cert chain or directly.
    var pubKey;
    if (opts.skipChain && opts.vcekKey) {
        // Test path: caller passes key directly, skip chain verification.
        pubKey = opts.vcekKey;
    } else {
        // Production path: verify cert chain, extract leaf key.
        pubKey = certchain.verifyCertChain([vcekCertDER], amdRootDER);
    }

    var ok = crypto.verify('sha384', signedBytes,
        { key: pubKey, dsaEncoding: 'ieee-p1363' }, sigP1363);
    if (!ok) throw new Error('sev_snp: report signature verification failed');

    var reportData  = report.slice(REPORT_DATA_OFF,  REPORT_DATA_OFF  + REPORT_DATA_LEN);
    var measurement = report.slice(MEASUREMENT_OFF,  MEASUREMENT_OFF  + MEASUREMENT_LEN);
    var chipId      = report.slice(CHIP_ID_OFF,      CHIP_ID_OFF      + CHIP_ID_LEN);

    // Convention: first 64 bytes of report_data carry the scanner CID (UTF-8, null-padded).
    var scannerCID = reportData.toString('utf8').replace(/\0/g, '').trim() || null;

    return {
        provider:    'sev_snp',
        version,
        measurement,
        reportData,
        scannerCID,
        chipId
    };
}

module.exports = { verify };
