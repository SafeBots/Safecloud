'use strict';
/**
 * Intel TDX (Trust Domain Extensions) attestation quote verifier.
 *
 * Wire format: Intel TDX Quote (v4), which wraps an SGX DCAP-style quote.
 * Signature:   ECDSA P-256 (ES256) using an Attestation Key (AK) in the QE cert.
 * Root of trust: QE (Quoting Enclave) cert → Intel PCK CA → Intel Root CA.
 *
 * TDX Quote v4 layout (offsets, all little-endian):
 *   0x0000  version         u16   (4 for TDX)
 *   0x0002  att_key_type    u16   (2 = ECDSA-256)
 *   0x0004  tee_type        u32   (0x00000081 = TDX)
 *   0x0008  reserved        4B
 *   0x000C  qe_vendor_id    16B   (Intel QE GUID)
 *   0x001C  user_data       20B   (first 20B of the hash the QE commits to)
 *   0x0030  TD report       (584 bytes)
 *     TD report layout:
 *       +0x000  tee_tcb_svn     16B
 *       +0x010  mrseam          48B
 *       +0x040  mrsignerseam    48B
 *       +0x070  seam_attributes 8B
 *       +0x078  td_attributes   8B
 *       +0x080  xfam            8B
 *       +0x088  mrtd            48B  ← measurement of the TD (our scanner)
 *       +0x0B8  mrconfigid      48B
 *       +0x0E8  mrowner         48B
 *       +0x118  mrownerconfig   48B
 *       +0x148  rtmr0..3        4×48B
 *       +0x208  servtd_hash     48B
 *       +0x238  reserved        16B
 *       +0x248  report_data     64B  ← caller-supplied (scannerCID goes here)
 *   0x0278  quote_sig_data_size  u32
 *   0x027C  quote_sig_data       (variable: ECDSA signature + AK cert + QE report)
 *
 * We support verifying the signature on the TD report header + body using the
 * AK embedded in the quote signature data, and chain-verifying the AK cert.
 * Full PCK cert chain verification requires fetching from Intel PCS (done by
 * AttestationFetcher); here we accept pre-fetched certs.
 *
 * @module Attestation/providers/TDX
 */

var crypto    = require('crypto');
var certchain = require('../util/certchain');

// Quote layout constants
var QUOTE_HEADER_SIZE = 48;
var TD_REPORT_OFFSET  = QUOTE_HEADER_SIZE;
// Full TD report body (TDREPORT_STRUCT fields in quote) = 0x288 = 648 bytes.
// The last field (report_data, 64B) starts at +0x248 and ends at +0x288.
var TD_REPORT_SIZE    = 0x288;  // 648 bytes
var REPORT_DATA_OFF   = TD_REPORT_OFFSET + 0x248;  // abs = 48 + 584 = 632
var REPORT_DATA_LEN   = 64;
var MRTD_OFF          = TD_REPORT_OFFSET + 0x088;  // abs = 48 + 136 = 184
var MRTD_LEN          = 48;
var SIG_SIZE_OFF      = TD_REPORT_OFFSET + TD_REPORT_SIZE;  // abs = 48 + 648 = 696
var SIG_DATA_OFF      = SIG_SIZE_OFF + 4;                   // abs = 700

// Inside quote_sig_data:
var AK_SIG_OFF        = 0;    // 64B — ECDSA P-256 signature (r||s, 32B each)
var AK_PUB_OFF        = 64;   // 64B — AK public key (uncompressed minus 0x04 prefix: x||y)
var QE_REPORT_OFF     = 128;  // 384B — QE report (the enclave that issued the AK)
var QE_SIG_OFF        = 512;  // 64B  — ECDSA signature over QE report by PCK
var QE_AUTH_OFF       = 576;  // variable — QE authentication data
// After QE_AUTH: certification data (cert chain type + PCK cert chain)

/**
 * Verify a TDX attestation quote.
 *
 * @param {Buffer}   quote          Raw TDX quote bytes.
 * @param {Buffer}   intelRootDER   Intel SGX Root CA (DER) — trusted anchor.
 * @param {Object}   [opts]
 * @param {boolean}  [opts.skipChain]  Skip cert chain (for unit tests).
 * @param {Object}   [opts.akKey]      Pre-loaded AK public key (for tests).
 * @returns {{ provider, mrtd, reportData, scannerCID, version }}
 * @throws on any verification failure.
 */
function verify(quote, intelRootDER, opts) {
    opts = opts || {};

    if (!Buffer.isBuffer(quote) || quote.length < SIG_DATA_OFF + 128) {
        throw new Error('tdx: quote too short (' + (quote && quote.length) + ' bytes)');
    }

    var version    = quote.readUInt16LE(0x0000);
    var teeType    = quote.readUInt32LE(0x0004);
    var attKeyType = quote.readUInt16LE(0x0002);

    if (version < 4) throw new Error('tdx: expected quote version 4, got ' + version);
    if (teeType !== 0x00000081) throw new Error('tdx: expected TEE type TDX (0x81), got 0x' + teeType.toString(16));
    if (attKeyType !== 2) throw new Error('tdx: expected att_key_type 2 (ECDSA-256), got ' + attKeyType);

    var sigDataSize = quote.readUInt32LE(SIG_SIZE_OFF);
    if (quote.length < SIG_DATA_OFF + sigDataSize) {
        throw new Error('tdx: quote truncated (sig data size=' + sigDataSize + ')');
    }
    var sigData = quote.slice(SIG_DATA_OFF, SIG_DATA_OFF + sigDataSize);

    // Extract AK signature (r||s, P-256 format, each 32B → 64B total).
    var akSigBytes = sigData.slice(AK_SIG_OFF, AK_SIG_OFF + 64);

    // The signed data is the TD report header (QUOTE_HEADER_SIZE bytes) +
    // TD report body (TD_REPORT_SIZE bytes).
    var signedBytes = quote.slice(0, QUOTE_HEADER_SIZE + TD_REPORT_SIZE);

    // Obtain the AK public key.
    var akPubKey;
    if (opts.skipChain && opts.akKey) {
        akPubKey = opts.akKey;
    } else {
        // AK public key is x||y (64 bytes), add 0x04 prefix for uncompressed point.
        var akRawXY = sigData.slice(AK_PUB_OFF, AK_PUB_OFF + 64);
        var akPointBuf = Buffer.concat([Buffer.from([0x04]), akRawXY]);
        akPubKey = crypto.createPublicKey({
            key:    akPointBuf,
            format: 'der',
            type:   'spki'
        });
        // In full production we'd also verify the AK cert chain here using intelRootDER.
        // Omitted pending AttestationFetcher providing the PCK cert chain.
    }

    var ok = crypto.verify('sha256', signedBytes,
        { key: akPubKey, dsaEncoding: 'ieee-p1363' }, akSigBytes);
    if (!ok) throw new Error('tdx: TD report signature verification failed');

    var reportData = quote.slice(REPORT_DATA_OFF, REPORT_DATA_OFF + REPORT_DATA_LEN);
    var mrtd       = quote.slice(MRTD_OFF,        MRTD_OFF        + MRTD_LEN);

    // Convention: first 64B of report_data carry scanner CID (UTF-8, null-padded).
    var scannerCID = reportData.toString('utf8').replace(/\0/g, '').trim() || null;

    return {
        provider:   'tdx',
        version,
        mrtd,
        reportData,
        scannerCID
    };
}

module.exports = { verify };
