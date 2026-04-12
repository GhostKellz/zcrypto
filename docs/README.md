# zcrypto Documentation

**zcrypto v1.0.0** - Modular cryptography library for Zig with a stable core API and explicit experimental feature gates

## Quick Navigation

### Getting Started
- [Quick Start](getting-started/quick-start.md) - Get started in 5 minutes
- [Build Configuration](getting-started/build-config.md) - Feature flags and modular builds

### API Reference
- [Core API](api/core.md) - Hash, symmetric, asymmetric, KDF, random
- [Full Reference](api/reference.md) - Full API surface, including experimental modules

### Features
- [Feature Overview](features/README.md) - Modular feature system
- [TLS/QUIC](features/tls.md) - TLS 1.3 and QUIC crypto

### Examples
- [Basic Usage](examples/basic.md) - Simple encryption/decryption
- [Examples Overview](examples/README.md) - All code examples

### Contributing
- [Contributing Guide](contributing/README.md) - Development guidelines

## Module Overview

| Module | Description |
|--------|-------------|
| `zcrypto.hash` | SHA-2/3, Blake2/3, SHAKE, HMAC |
| `zcrypto.sym` | AES-GCM, ChaCha20-Poly1305 |
| `zcrypto.asym` | Ed25519, X25519, secp256k1/r1 |
| `zcrypto.pq` | Experimental post-quantum APIs |
| `zcrypto.kdf` | HKDF, PBKDF2, Argon2 |
| `zcrypto.zkp` | Experimental proof-system APIs |
| `zcrypto.quic` | QUIC cryptographic helpers |

## Build Sizes

| Configuration | Size | Use Case |
|---------------|------|----------|
| Core only | ~3MB | Embedded/IoT |
| Core + TLS | ~12MB | Web servers |
| Core + Blockchain | ~18MB | Blockchain nodes |
| Full features | ~35MB | Enterprise |

## Links

- [GitHub](https://github.com/ghostkellz/zcrypto)
- [Issues](https://github.com/ghostkellz/zcrypto/issues)
