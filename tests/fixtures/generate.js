'use strict';
/**
 * Generate mock attestation fixtures for all six providers.
 *
 * Run once to create the fixture files:
 *   node tests/fixtures/generate.js
 *
 * Each fixture is a signed document + the key/cert needed to verify it.
 * All signing keys are generated fresh — these are NOT real attestation docs.
 * Tests swap the trusted root for the fixture's own generated cert.
 */

var crypto = require('crypto');
var path   = require('path');
var fs     = require('fs');
var cbor   = require('../../classes/Safecloud/Attestation/util/cbor');
var jwt    = require('../../classes/Safecloud/Attestation/util/jwt');
var cose   = require('../../classes/Safecloud/Attestation/util/cose');

var SCANNER_CID = 'bafybeigtest1234scannercidfixture';
var NOW         = Math.floor(Date.now() / 1000);

// ── Helpers ───────────────────────────────────────────────────────────────────

function writeFixture(dir, name, data) {
    var p = path.join(__dirname, dir, name);
    if (Buffer.isBuffer(data)) {
        fs.writeFileSync(p, data);
    } else {
        fs.writeFileSync(p, typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    }
}

function generateKeyPair(type, opts) {
    var kp = crypto.generateKeyPairSync(type, opts);
    return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

// Generate a minimal self-signed X.509 certificate (DER).
// Node.js 15.6+ X509Certificate doesn't generate certs; we use a compact
// hand-built DER for testing — just enough structure for our certchain verifier.
// In tests we skip the chain and pass the key directly, so this only needs to
// be parseable as a cert whose public key matches our generated key.
function makeSelfSignedCert(keyPair, name) {
    // Use Node's built-in generateCertificate if available (Node 22+), or
    // fall back to a raw DER template approach using the public key SPKI bytes.
    // For our tests we skip chain validation and pass the key directly, so
    // we only need a cert whose publicKey is our keypair's publicKey.
    // We build a minimal DER by encoding an SPKI structure as a placeholder.
    // Real cert generation belongs in scripts/fetch-trust-roots.js (uses openssl).
    try {
        // Try generateCertificate (experimental, Node.js 22+)
        var cert = crypto.X509Certificate && crypto.X509Certificate.prototype.publicKey
            ? _buildMinimalCert(keyPair, name)
            : null;
        return cert;
    } catch (e) {
        return _buildMinimalCert(keyPair, name);
    }
}

function _buildMinimalCert(keyPair, _name) {
    // Export the public key as DER SPKI, then wrap it in a fake X.509 DER.
    // The certchain verifier uses X509Certificate(der).publicKey, so it must
    // be a real parseable cert. Since Node doesn't ship a cert generator, we
    // use openssl via child_process if available, or skip cert tests otherwise.
    try {
        var { execSync } = require('child_process');
        var tmpKey  = path.join(require('os').tmpdir(), 'fixture-key-' + Date.now() + '.pem');
        var tmpCert = path.join(require('os').tmpdir(), 'fixture-cert-' + Date.now() + '.der');
        // Write private key to temp file.
        fs.writeFileSync(tmpKey, keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
        // Generate self-signed cert.
        execSync('openssl req -new -x509 -key ' + tmpKey +
            ' -out ' + tmpCert + ' -outform DER -days 3650' +
            ' -subj "/CN=fixture" -nodes 2>/dev/null');
        var der = fs.readFileSync(tmpCert);
        fs.unlinkSync(tmpKey);
        fs.unlinkSync(tmpCert);
        return der;
    } catch (e) {
        return null; // openssl not available — tests that need a cert will skip chain check
    }
}

// Sign `data` with a private key using the given algorithm; return ieee-p1363 sig.
function signIEEE(data, privateKey, hash) {
    return crypto.sign(hash, Buffer.isBuffer(data) ? data : Buffer.from(data),
        { key: privateKey, dsaEncoding: 'ieee-p1363' });
}

// Build a JWT signed with ES256 or RS256.
function makeJWT(payload, privateKey, alg, extra) {
    var header   = Object.assign({ alg: alg, kid: 'fixture-key-1', typ: 'JWT' }, extra || {});
    var hdrB64   = jwt.base64urlEncode(Buffer.from(JSON.stringify(header)));
    var payB64   = jwt.base64urlEncode(Buffer.from(JSON.stringify(payload)));
    var input    = hdrB64 + '.' + payB64;
    var sigBytes;
    if (alg === 'ES256') {
        sigBytes = signIEEE(input, privateKey, 'sha256');
    } else if (alg === 'RS256') {
        sigBytes = crypto.sign('sha256', Buffer.from(input), privateKey);
    } else {
        throw new Error('makeJWT: unsupported alg ' + alg);
    }
    return input + '.' + jwt.base64urlEncode(sigBytes);
}

// ── Nitro fixture ─────────────────────────────────────────────────────────────

function generateNitro() {
    var kp       = generateKeyPair('ec', { namedCurve: 'P-384' });
    var certDER  = makeSelfSignedCert(kp, 'nitro-leaf');

    // Build the Nitro attestation payload (CBOR map).
    var pcrs = {};
    for (var i = 0; i < 16; i++) {
        pcrs[i] = crypto.randomBytes(48);
    }
    var payload = cbor.encodeCBOR({
        module_id:   'i-fixture-module-0000',
        timestamp:   Date.now(),
        digest:      'SHA384',
        pcrs:        pcrs,
        certificate: certDER || Buffer.alloc(0),
        cabundle:    [],
        user_data:   Buffer.from(SCANNER_CID, 'utf8'),
        nonce:       crypto.randomBytes(32)
    });

    // Build protected headers: { 1: -35 } (alg = ES384)
    var protectedMap  = cbor.encodeCBOR({ 1: -35 });
    var sigStructure  = cbor.encodeCBOR(['Signature1', protectedMap, Buffer.alloc(0), payload]);
    var sig           = signIEEE(sigStructure, kp.privateKey, 'sha384');
    var coseSign1     = cbor.encodeCBOR([protectedMap, {}, payload, sig]);

    // Export public key as JWK for the fixture.
    var pubJWK = kp.publicKey.export({ format: 'jwk' });

    writeFixture('nitro', 'doc.bin', coseSign1);
    writeFixture('nitro', 'signing-key.jwk.json', pubJWK);
    if (certDER) writeFixture('nitro', 'leaf-cert.der', certDER);
    console.log('nitro: generated');
}

// ── GCP fixture ───────────────────────────────────────────────────────────────

function generateGCP() {
    var kp     = generateKeyPair('rsa', { modulusLength: 2048, publicExponent: 65537 });
    var pubJWK = kp.publicKey.export({ format: 'jwk' });
    pubJWK.kid = 'fixture-key-1';
    pubJWK.alg = 'RS256';

    var payload = {
        iss:   'https://confidentialcomputing.googleapis.com',
        aud:   'https://verifier.safecloud.test',
        sub:   'fixture-workload',
        iat:   NOW,
        exp:   NOW + 3600,
        eat_nonce: 'test-nonce-gcp-' + Date.now(),
        dbgstat: 'disabled-since-boot',
        hwmodel: 'GCP_AMD_SEV',
        swname: 'CONFIDENTIAL_SPACE',
        submods: {
            container: {
                image_digest:    'sha256:fixture' + crypto.randomBytes(16).toString('hex'),
                image_reference: 'us-docker.pkg.dev/safecloud/scanner:v1'
            }
        },
        user_data: SCANNER_CID
    };

    var token = makeJWT(payload, kp.privateKey, 'RS256');
    var jwks  = { keys: [pubJWK] };

    writeFixture('gcp', 'token.jwt', token);
    writeFixture('gcp', 'jwks.json', jwks);
    console.log('gcp: generated');
}

// ── Azure fixture ─────────────────────────────────────────────────────────────

function generateAzure() {
    var kp     = generateKeyPair('rsa', { modulusLength: 2048, publicExponent: 65537 });
    var pubJWK = kp.publicKey.export({ format: 'jwk' });
    pubJWK.kid = 'fixture-key-1';
    pubJWK.alg = 'RS256';

    var payload = {
        iss:   'https://sharedeus2.eus2.attest.azure.net',
        aud:   'https://verifier.safecloud.test',
        iat:   NOW,
        exp:   NOW + 3600,
        nonce: 'azure-nonce-' + Date.now(),
        'x-ms-ver':              '1.0',
        'x-ms-attestation-type': 'sevsnpvm',
        'x-ms-compliance-status':'azure-compliant-cvm',
        'x-ms-runtime': {
            'user-data': Buffer.from(SCANNER_CID, 'utf8').toString('base64')
        },
        'x-ms-sevsnpvm-guestsvn':      0,
        'x-ms-sevsnpvm-launchmeasurement': crypto.randomBytes(48).toString('base64')
    };

    var token = makeJWT(payload, kp.privateKey, 'RS256');
    var jwks  = { keys: [pubJWK] };

    writeFixture('azure', 'token.jwt', token);
    writeFixture('azure', 'jwks.json', jwks);
    console.log('azure: generated');
}

// ── OCI fixture ───────────────────────────────────────────────────────────────

function generateOCI() {
    var kp     = generateKeyPair('ec', { namedCurve: 'P-256' });
    var pubJWK = kp.publicKey.export({ format: 'jwk' });
    pubJWK.kid = 'fixture-key-1';
    pubJWK.alg = 'ES256';

    var payload = {
        iss: 'https://veraison.example.com',
        iat: NOW,
        exp: NOW + 3600,
        eat_nonce: 'oci-nonce-' + Date.now(),
        'ear.status': 'affirming',
        user_data:   SCANNER_CID,
        submods: {
            'CCA_SSD_PLATFORM': {
                'ear.appraisal-policy-id': 'policy:fixture',
                'ear.trustworthiness-vector': {}
            }
        }
    };

    var token = makeJWT(payload, kp.privateKey, 'ES256');
    var jwks  = { keys: [pubJWK] };

    writeFixture('oci', 'token.jwt', token);
    writeFixture('oci', 'veraison-key.jwk.json', jwks);
    console.log('oci: generated');
}

// ── SEV-SNP fixture ───────────────────────────────────────────────────────────

function generateSEVSNP() {
    var kp     = generateKeyPair('ec', { namedCurve: 'P-384' });
    var pubJWK = kp.publicKey.export({ format: 'jwk' });

    // Build a 1184-byte report buffer.
    var report = Buffer.alloc(1184, 0);
    report.writeUInt32LE(2, 0x000);           // version = 2
    report.writeUInt32LE(1, 0x034);           // sig_algo = 1 (ECDSA P-384)

    // report_data (64B at 0x050): scanner CID, null-padded.
    var cidBuf = Buffer.alloc(64, 0);
    Buffer.from(SCANNER_CID, 'utf8').copy(cidBuf);
    cidBuf.copy(report, 0x050);

    // measurement (48B at 0x090): random.
    crypto.randomBytes(48).copy(report, 0x090);

    // chip_id (64B at 0x1A0): random.
    crypto.randomBytes(64).copy(report, 0x1A0);

    // Sign bytes [0x000..0x29F].
    var signedBytes = report.slice(0, 0x2A0);
    var sig         = signIEEE(signedBytes, kp.privateKey, 'sha384');
    // r and s are the first and second 48 bytes; AMD pads each to 72 bytes.
    // Our sig is ieee-p1363: r(48)||s(48) = 96 bytes.
    var r48 = sig.slice(0, 48);
    var s48 = sig.slice(48, 96);
    r48.copy(report, 0x2A0, 0, 48);          // r in [0x2A0..0x2CF]
    s48.copy(report, 0x2A0 + 72, 0, 48);    // s in [0x2E8..0x317]

    writeFixture('sev_snp', 'report.bin', report);
    writeFixture('sev_snp', 'vcek-key.jwk.json', pubJWK);
    console.log('sev_snp: generated');
}

// ── TDX fixture ───────────────────────────────────────────────────────────────

function generateTDX() {
    var kp     = generateKeyPair('ec', { namedCurve: 'P-256' });
    var pubJWK = kp.publicKey.export({ format: 'jwk' });

    // Minimal TDX quote v4: header (48B) + TD report (648B) + sig_size (4B) + sig_data.
    // TD_REP_SIZE = 0x288 = 648: report_data (64B) is at +0x248..+0x288, last field.
    var HEADER_SIZE   = 48;
    var TD_REP_SIZE   = 648;  // 0x288
    var AK_SIG_SIZE   = 64;   // r(32)||s(32)
    var AK_PUB_SIZE   = 64;   // x(32)||y(32)
    var DUMMY_SIG_TRAILING = 128;  // minimal trailing sig data
    var sigDataSize   = AK_SIG_SIZE + AK_PUB_SIZE + DUMMY_SIG_TRAILING;
    var quoteSize     = HEADER_SIZE + TD_REP_SIZE + 4 + sigDataSize;

    var quote = Buffer.alloc(quoteSize, 0);

    // Header
    quote.writeUInt16LE(4, 0x0000);            // version = 4
    quote.writeUInt16LE(2, 0x0002);            // att_key_type = 2 (ECDSA-256)
    quote.writeUInt32LE(0x00000081, 0x0004);   // tee_type = TDX

    // TD report: mrtd at +0x088
    var MRTD_ABS = HEADER_SIZE + 0x088;
    crypto.randomBytes(48).copy(quote, MRTD_ABS);

    // TD report: report_data at +0x248
    var RD_ABS = HEADER_SIZE + 0x248;
    var cidBuf = Buffer.alloc(64, 0);
    Buffer.from(SCANNER_CID, 'utf8').copy(cidBuf);
    cidBuf.copy(quote, RD_ABS);

    // sig_data_size
    var SIG_SIZE_ABS = HEADER_SIZE + TD_REP_SIZE;
    quote.writeUInt32LE(sigDataSize, SIG_SIZE_ABS);

    // Sign header + TD report.
    var signedBytes = quote.slice(0, HEADER_SIZE + TD_REP_SIZE);
    var sig         = signIEEE(signedBytes, kp.privateKey, 'sha256');
    // r(32)||s(32) = 64 bytes
    var SIG_ABS = SIG_SIZE_ABS + 4;
    sig.copy(quote, SIG_ABS, 0, 64);

    // AK public key: x(32)||y(32) right after the sig.
    var raw = kp.publicKey.export({ type: 'spki', format: 'der' });
    // SPKI for P-256: DER wraps a BIT STRING containing 0x04 || x(32) || y(32).
    // The uncompressed point starts at a fixed offset in the SPKI DER.
    // Find the 0x04 byte (uncompressed point marker) and copy the 64 bytes after it.
    var marker = -1;
    for (var i = 0; i < raw.length - 65; i++) {
        if (raw[i] === 0x04) { marker = i; break; }
    }
    if (marker >= 0) {
        raw.copy(quote, SIG_ABS + 64, marker + 1, marker + 65);
    }

    writeFixture('tdx', 'quote.bin', quote);
    writeFixture('tdx', 'ak-key.jwk.json', pubJWK);
    console.log('tdx: generated');
}

// ── Main ──────────────────────────────────────────────────────────────────────

generateNitro();
generateGCP();
generateAzure();
generateOCI();
generateSEVSNP();
generateTDX();
console.log('\nAll fixtures written to tests/fixtures/{provider}/');
