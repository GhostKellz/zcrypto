# Test Vectors

This directory contains official test vectors from various RFC specifications and standards to ensure zcrypto implementations are correct and compatible.

## Available Test Vectors

### RFC 2104 (HMAC)
- HMAC-SHA256 test vectors
- HMAC-SHA512 test vectors

### RFC 5869 (HKDF)
- HKDF-SHA256 test vectors
- HKDF-SHA512 test vectors

### RFC 9106 (Argon2)
- Argon2id test vectors

### RFC 8032 (Ed25519)
- Ed25519 signature test vectors

### RFC 7748 (X25519)
- X25519 key exchange test vectors

### NIST Test Vectors
- AES-GCM test vectors
- secp256r1 (P-256) test vectors

### Bitcoin Test Vectors
- secp256k1 test vectors
- BIP-39 mnemonic test vectors
- BIP-32 HD wallet test vectors
- BIP-44 derivation path test vectors

## Usage

Test vectors are used in the test suites to verify that zcrypto implementations match the official specifications. Current v1.0.5 coverage is embedded directly in module tests so vectors stay close to the APIs they validate:

- `src/hash.zig`: SHA-256, SHA-384, SHA-512, Blake2b-512, and RFC 4231 HMAC vectors.
- `src/kdf.zig`: RFC 5869 HKDF-SHA256 and PBKDF2-HMAC-SHA256 vectors.
- `src/sym.zig`: NIST AES-GCM vectors plus negative AEAD decrypt coverage.
- `src/asym.zig`: RFC 8032 Ed25519 and RFC 7748 X25519 vectors.

## Sources

Test vectors are sourced from:
- IETF RFC specifications
- NIST cryptographic standards
- Bitcoin BIP specifications
- Industry standard test suites
