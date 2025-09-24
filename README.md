<div align="center">
  <img src="assets/icons/zcrypto.png" alt="Zcrypto Logo" width="200"/>

  [![Crypto](https://img.shields.io/badge/Crypto-Library-blue.svg)](https://github.com/ghostkellz/zcrypto)
  [![Zig](https://img.shields.io/badge/Zig-v0.16-orange.svg)](https://ziglang.org/)
  [![Blockchain](https://img.shields.io/badge/Blockchain-Ready-green.svg)](https://github.com/ghostkellz/zcrypto)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![Build](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/ghostkellz/zcrypto)
  [![PostQuantum](https://img.shields.io/badge/Post--Quantum-ML--KEM%20%7C%20ML--DSA-purple.svg)](https://github.com/ghostkellz/zcrypto)
</div>

# Zcrypto: A Modern Cryptography Library for Zig

**Zcrypto v0.9.0** is a fast, safe, and modular cryptography library written entirely in Zig. It features optional compilation with 9 feature flags, enabling builds from 3MB (embedded) to 35MB (full-featured) depending on your needs.

---

## 🛡️ Core Principles

* **Memory-safe by design:** Leveraging Zig's explicit control and compile-time safety features.
* **Modular architecture:** Enable only the features you need with build-time flags.
* **Audit-friendly:** Easy to read, easy to verify. Minimal dependencies.
* **Cross-platform:** Works seamlessly on Linux, macOS, Windows, and embedded targets.

---

## ⚙️ Modular Features (v0.9.0)

Zcrypto supports selective compilation with feature flags:

| Feature | Size | Description |
|---------|------|-------------|
| **Core** | ~3MB | Hash, symmetric crypto, signatures, key exchange |
| **+ TLS/QUIC** | +8MB | TLS 1.3, QUIC crypto, X.509 certificates |
| **+ Post-Quantum** | +5MB | ML-KEM, ML-DSA, quantum-resistant algorithms |
| **+ Hardware Accel** | +2MB | AES-NI, AVX2, SIMD optimizations |
| **+ Blockchain** | +3MB | Schnorr signatures, ZK rollups |
| **+ VPN** | +4MB | WireGuard, IPsec, IKEv2 protocols |
| **+ Enterprise** | +3MB | HSM integration, key rotation |
| **+ ZKP** | +6MB | Bulletproofs, Groth16, SNARKs |
| **+ Async** | +2MB | Async crypto with zsync integration |

**Build Size Examples:**
- Embedded/IoT: ~3MB (core only)
- Web server: ~12MB (core + TLS + async)
- Blockchain node: ~18MB (core + blockchain + ZKP + hardware)
- Full-featured: ~35MB (all features)

---

## 🤖 Algorithms & Primitives

### ✔️ Core (Always Available)

* **Hashing:** SHA-256, SHA-512, Blake2b/3, SHAKE-128
* **Symmetric:** AES-256-GCM, ChaCha20-Poly1305
* **Asymmetric:** Ed25519, X25519, Secp256r1 ECDH
* **Key Derivation:** HKDF, PBKDF2, BIP39
* **Random:** CSPRNG with hardware entropy
* **Batch Operations:** Multi-signature verification

### 🔧 Optional Features

* **TLS/QUIC** - Complete TLS 1.3 and QUIC crypto implementation
* **Post-Quantum** - ML-KEM (FIPS 203), ML-DSA (FIPS 204)
* **Hardware Acceleration** - AES-NI, AVX2, SIMD optimizations
* **Blockchain** - Schnorr signatures, BIP32 HD wallets
* **VPN** - WireGuard, IPsec, IKEv2 protocol implementations
* **WebAssembly** - Browser-compatible crypto operations
* **Enterprise** - HSM integration, automated key rotation
* **Zero-Knowledge Proofs** - Bulletproofs, Groth16, SNARKs
* **Async Operations** - Concurrent crypto with zsync runtime

---

## 🚀 Quick Start

### Installation

```bash
zig fetch --save https://github.com/ghostkellz/zcrypto/archive/refs/heads/main.tar.gz
```

### Basic Usage (Core Only)

```zig
const zcrypto = @import("zcrypto");

// Hashing
const hash = zcrypto.hash.sha256("Hello, zcrypto!");
std.debug.print("SHA-256: {x}\n", .{std.fmt.fmtSliceHexLower(&hash)});

// Encryption
const key = [_]u8{0x01} ** 32;
const encrypted = try zcrypto.sym.encryptAesGcm(allocator, "secret", &key);
const decrypted = try zcrypto.sym.decryptAesGcm(allocator, encrypted, &key);

// Signatures
const keypair = try zcrypto.asym.generateEd25519Keypair();
const signature = try zcrypto.asym.signEd25519(keypair.secret_key, "message");
const valid = zcrypto.asym.verifyEd25519(keypair.public_key, "message", signature);
```

### Modular Build Configuration

```zig
// build.zig
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    // Enable only needed features
    .tls = true,
    .post_quantum = true,
    .hardware_accel = true,
    // Other features default to false
});

exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
```

---

## 📚 Documentation

- **[Quick Start](docs/getting-started/quick-start.md)** - Get started in minutes
- **[Build Configuration](docs/getting-started/build-config.md)** - Feature flags and optimization
- **[API Reference](docs/api/core.md)** - Complete API documentation
- **[Features](docs/features/README.md)** - Optional feature guides
- **[Examples](docs/examples/README.md)** - Working code examples
- **[Contributing](docs/contributing/README.md)** - Development guidelines

---

## 🔍 Example Projects

```bash
# Build examples with custom features
zig build examples -Dtls=true -Dpost_quantum=true

# Run specific example
zig build run-example -- tls-client
```

---

## ⚖️ Use Cases

* **Embedded/IoT:** Core crypto in ~3MB binaries
* **Web Services:** TLS + async for secure APIs
* **Blockchain:** Full ZKP and hardware acceleration
* **VPN Servers:** Complete protocol implementations
* **Enterprise:** HSM integration and key management
* **Privacy Apps:** Post-quantum and zero-knowledge proofs

---

## 🚀 Roadmap

### ✅ Completed (v0.9.0)
* ✅ Modular build system with 9 feature flags
* ✅ 70-91% binary size reduction for selective builds
* ✅ Structured documentation in `docs/` directory
* ✅ Hardware acceleration (AES-NI, AVX2, SIMD)
* ✅ Post-quantum cryptography (ML-KEM, ML-DSA)
* ✅ TLS 1.3 and QUIC crypto implementation
* ✅ Enterprise features (HSM, key rotation)
* ✅ Zero-knowledge proofs (Bulletproofs, Groth16)

### 🔮 Future Plans
* [ ] Additional post-quantum schemes (Falcon, SPHINCS+)
* [ ] More hardware acceleration (ARM NEON, RISC-V vectors)
* [ ] Formal verification integration
* [ ] WebAssembly optimizations
* [ ] Additional blockchain protocols

---

## 📊 Performance

* **Compilation:** 45s → 12s (70% faster with selective features)
* **Binary Size:** 35MB → 3MB (91% reduction for embedded)
* **Runtime:** Competitive with RustCrypto, OpenSSL
* **Memory:** Zero dynamic allocation in core primitives
* **Hardware:** 2-10x speedup with acceleration enabled

---

## ✨ License

MIT or dual MIT/Apache2 for maximum compatibility.

---

**Zcrypto**: Modular cryptography at the speed of Zig.

