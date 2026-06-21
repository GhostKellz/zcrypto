# FIPS Posture

This document describes which zcrypto algorithms are FIPS-approved and backed by
Zig's standard library (`std.crypto`) versus which are experimental, non-FIPS, or
unsupported. zcrypto does not ship hand-rolled implementations of these
primitives; the FIPS-approved set below delegates to `std.crypto`.

## Approved & stdlib-backed

| Algorithm | FIPS | Backing | Status |
|-----------|------|---------|--------|
| ML-KEM-768 | 203 | `std.crypto.kem.ml_kem` | First-class. Keygen / encapsulate / decapsulate round-trips tested. |
| ML-DSA-65 | 204 | `std.crypto.sign.mldsa` | First-class. Sign / verify + tamper-detection tested. |
| ECDSA P-256 (SHA-256) | 186 | `std.crypto.sign.ecdsa` | Used for TLS CertificateVerify signing/verification (DER). |
| ECDSA P-384 (SHA-384) | 186 | `std.crypto.sign.ecdsa` | Used for TLS CertificateVerify signing/verification (DER). |
| Ed25519 | 186-5 | `std.crypto.sign.Ed25519` | Signature primitive + TLS CertificateVerify. |
| SHA-256 / SHA-384 / SHA-512 | 180-4 | `std.crypto.hash.sha2` | Hashing / HKDF. |
| AES-256-GCM | 197 / SP 800-38D | `std.crypto.aead.aes_gcm` | AEAD. |
| HKDF (SHA-256/384) | SP 800-56C | `std.crypto.kdf.hkdf` | TLS/QUIC key schedule. |

The hybrid constructions (X25519 + ML-KEM-768 for key exchange, Ed25519 +
ML-DSA-65 for signatures) combine an approved post-quantum primitive with a
classical one for defense-in-depth. Each half is stdlib-backed.

## Experimental / non-FIPS

| Algorithm | Notes |
|-----------|-------|
| Blockchain / ZKP / enterprise helpers | Gated behind `-Dexperimental-crypto=true`. Research surfaces, not FIPS-validated, not part of the stable contract. APIs may change while v1.0.x hardens the stable core. |
| ChaCha20-Poly1305 | Safe and widely used, but not a FIPS-approved AEAD. Available for QUIC/TLS interop where negotiated. |

## Unsupported

| Algorithm | Reason |
|-----------|--------|
| SLH-DSA (FIPS 205) | No `std.crypto` backend exists. zcrypto will not ship a hand-rolled SPHINCS+; the former placeholder has been removed. For post-quantum signatures use ML-DSA-65 (FIPS 204). |
| RSA / RSA-PSS (FIPS 186) | No safe stdlib implementation. TLS CertificateVerify returns `error.UnsupportedKeyType` for RSA keys. May be revisited only via an audited library. |

## TLS CertificateVerify support matrix

The TLS 1.3 CertificateVerify path (`tls_server.zig` / `tls_client.zig`) supports:

- `ed25519` (0x0807)
- `ecdsa_secp256r1_sha256` (0x0403)
- `ecdsa_secp384r1_sha384` (0x0503)

RSA schemes (e.g. `rsa_pss_rsae_sha256`, 0x0804) and any other key type return
`error.UnsupportedKeyType` rather than silently producing an invalid or fake
signature.

## Scope caveat

zcrypto's verified role is cryptographic primitives plus QUIC crypto helpers. The
standalone TLS 1.3 record/handshake stack is experimental and not interop-verified
against external implementations; treat it as a building block, not a turnkey TLS
endpoint.
