<?php
/**
 * OCP — OpenClaiming Protocol verifier (PHP, standalone).
 *
 * Zero-dependency. Requires PHP 8.1+ with the sodium extension (enabled by
 * default in modern PHP builds).
 *
 * Usage:
 *   require_once 'ocp.php';
 *
 *   $result = OCP::verify($claimJson);
 *   if (!$result['ok']) {
 *       http_response_code(403);
 *       echo $result['error'];
 *       exit;
 *   }
 *   $pub = $result['pub'];   // issuer's public key (hex)
 *   $sub = $result['sub'];   // subject
 *   $stm = $result['stm'];   // statements (array)
 *
 * @version 1.0
 * @see https://openclaiming.org/spec
 */
class OCP
{
    // ── Claim format ───────────────────────────────────────────────────────────

    /**
     * Parse and verify an OCP claim.
     *
     * Accepts a JSON string or a pre-decoded array/object.
     *
     * Returns:
     *   ['ok' => true,  'pub' => <hex>, 'sub' => <string>, 'stm' => <array>, 'claim' => <array>]
     *   ['ok' => false, 'error' => <string>]
     */
    public static function verify(string|array $input): array
    {
        // ── 1. Decode ──────────────────────────────────────────────────────────
        if (is_string($input)) {
            $claim = json_decode($input, true);
            if ($claim === null) {
                return ['ok' => false, 'error' => 'OCP: JSON parse failed'];
            }
        } else {
            $claim = (array) $input;
        }

        // ── 2. Required fields ─────────────────────────────────────────────────
        if (!isset($claim['ocp']) || $claim['ocp'] !== 1) {
            return ['ok' => false, 'error' => 'OCP: ocp field must equal 1'];
        }
        if (empty($claim['iss'])) {
            return ['ok' => false, 'error' => 'OCP: iss field required'];
        }
        if (empty($claim['sig'])) {
            return ['ok' => false, 'error' => 'OCP: sig field required'];
        }

        // ── 3. Parse issuer (§1 — iss URI) ────────────────────────────────────
        // iss = "data:key/ed25519;hex,<64 hex chars>"
        if (!preg_match('/^data:key\/ed25519;hex,([0-9a-f]{64})$/i', $claim['iss'], $m)) {
            return ['ok' => false, 'error' => 'OCP: iss must be data:key/ed25519;hex,<64hexchars>'];
        }
        $pubHex = strtolower($m[1]);
        $pubBin = hex2bin($pubHex);

        // ── 4. Temporal validation (§1 — nbf / exp) ───────────────────────────
        $now = time();
        if (!empty($claim['nbf']) && $claim['nbf'] > $now + 300) {
            // Allow 5-minute clock skew
            return ['ok' => false, 'error' => 'OCP: claim not yet valid (nbf)'];
        }
        if (!empty($claim['exp']) && $claim['exp'] < $now) {
            return ['ok' => false, 'error' => 'OCP: claim expired (exp)'];
        }

        // ── 5. Canonicalize (§2) ───────────────────────────────────────────────
        // Remove sig, sort keys alphabetically, JSON-encode.
        $unsigned = $claim;
        unset($unsigned['sig']);
        ksort($unsigned);
        $canon = json_encode($unsigned, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($canon === false) {
            return ['ok' => false, 'error' => 'OCP: canonicalization failed'];
        }

        // ── 6. Hash (§3) ───────────────────────────────────────────────────────
        // SHA-256 of the UTF-8 canonical bytes.
        $hash = hash('sha256', $canon, true);

        // ── 7. Verify signature (§3 — Ed25519) ────────────────────────────────
        $sigBin = hex2bin($claim['sig']);
        if ($sigBin === false || strlen($sigBin) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return ['ok' => false, 'error' => 'OCP: sig must be 64-byte (128 hex chars) Ed25519 signature'];
        }
        if (!sodium_crypto_sign_verify_detached($sigBin, $hash, $pubBin)) {
            return ['ok' => false, 'error' => 'OCP: signature verification failed'];
        }

        // ── 8. Return verified claim data ──────────────────────────────────────
        return [
            'ok'    => true,
            'pub'   => $pubHex,
            'sub'   => $claim['sub']  ?? null,
            'stm'   => $claim['stm']  ?? [],
            'nbf'   => $claim['nbf']  ?? null,
            'exp'   => $claim['exp']  ?? null,
            'claim' => $claim,
        ];
    }

    // ── Helper: check a publisher cert ────────────────────────────────────────

    /**
     * Verify that a claim is a valid publisher cert for the given publisher ID
     * and optionally a specific root CID.
     *
     * @param string|array $claimJson  OCP claim (JSON or decoded array)
     * @param string $publisherId      expected sub / stm.publisherId
     * @param string|null $rootCid    if set, cert must cover this root (or all roots)
     * @return array  same as verify()
     */
    public static function verifyPublisherCert(string|array $claimJson, string $publisherId, ?string $rootCid = null): array
    {
        $result = self::verify($claimJson);
        if (!$result['ok']) {
            return $result;
        }
        $stm = (array) $result['stm'];

        // sub must match publisherId
        $sub = $result['sub'] ?? ($stm['publisherId'] ?? null);
        if ($sub !== $publisherId) {
            return ['ok' => false, 'error' => 'OCP: cert sub does not match expected publisher'];
        }

        // If rootCid is required, cert must cover it (or be a wildcard cert)
        if ($rootCid !== null) {
            $certRoot = $stm['rootCid'] ?? null;
            if ($certRoot !== null && $certRoot !== $rootCid) {
                return ['ok' => false, 'error' => 'OCP: cert rootCid does not cover this content'];
            }
        }

        return $result;
    }
}
