# Attestation Trust Roots

This directory holds pinned root CA certificates and verifier keys for each TEE provider. They are committed to the repository and loaded by `TrustStore.js` at runtime.

## Files

| File | Provider | Source | Algorithm |
|---|---|---|---|
| `nitro-root.der` | AWS Nitro | https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip | ECDSA P-384 |
| `amd-root.der` | AMD SEV-SNP | https://kdsintf.amd.com/vlek/v1/Milan/cert_chain (root cert) | ECDSA P-384 |
| `intel-root.der` | Intel TDX | https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.der | RSA-3072 |

## Populating

Run the fetch script (requires curl or the `gh` CLI):

```bash
node scripts/fetch-trust-roots.js
```

Or fetch manually and verify the SHA-256 fingerprint matches the vendor's published value before committing.

## OCI/Veraison

The Veraison verifier public key is region-specific and changes with key rotation. It is fetched at verify time by `AttestationFetcher.js` and passed into `OCI.verify()` — nothing is pinned here for OCI.

## GCP / Azure

GCP and Azure use JWKS endpoints with rotating keys. `AttestationFetcher.js` fetches and caches them. The issuer URLs are pinned in `TrustStore.js`.
