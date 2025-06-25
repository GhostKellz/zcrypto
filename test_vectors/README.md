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

Test vectors are used in the test suites to verify that zcrypto implementations match the official specifications. Each module includes comprehensive tests using these vectors.

## Sources

Test vectors are sourced from:
- IETF RFC specifications
- NIST cryptographic standards
- Bitcoin BIP specifications
- Industry standard test suites