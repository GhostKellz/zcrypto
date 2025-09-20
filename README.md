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

**Zcrypto** is a fast, safe, and modular cryptography library written entirely in Zig. It is designed for modern applications in systems programming, embedded security, VPN tunnels (like GhostMesh), blockchain runtimes (like GhostChain), and privacy-first software ecosystems. Built with clarity, auditability, and portability in mind, Zcrypto aims to be the de facto cryptographic foundation for next-generation Zig projects.

---

## 🛡️ Core Principles

* **Memory-safe by design:** Leveraging Zig's explicit control and compile-time safety features.
* **Audit-friendly:** Easy to read, easy to verify. Minimal dependencies.
* **Cross-platform:** Works seamlessly on Linux, macOS, Windows, and embedded targets.
* **Modular and composable:** Include only what you need, zero bloat.

---

## 🤖 Algorithms & Primitives (v0.8.4)

### ✔️ Hashing

* SHA-256
* SHA-512
* Blake2b / Blake3
* SHAKE-128 (for post-quantum algorithms)

### ✔️ Symmetric Encryption

* AES-256-GCM (with hardware acceleration)
* ChaCha20-Poly1305
* XChaCha20-Poly1305 (planned)

### ✔️ Asymmetric Encryption (Classical)

* Ed25519 (signing/verify)
* X25519 (key exchange)
* Secp256k1 (planned)

### ✔️ Post-Quantum Cryptography

* **ML-KEM** (Module-Lattice-Based Key Encapsulation) - FIPS 203 compliant
  * ML-KEM-512, ML-KEM-768, ML-KEM-1024 parameter sets
  * Uniform polynomial sampling and CBD sampling
* **ML-DSA** (Module-Lattice-Based Digital Signatures) - FIPS 204 compliant
  * ML-DSA-44, ML-DSA-65, ML-DSA-87 parameter sets
  * Complete NTT/INTT transforms and Montgomery reduction

### ✔️ Protocol Implementations

* **Noise Protocol Framework** - Complete implementation with ChaCha20-Poly1305 AEAD
* **Signal Protocol** - End-to-end encryption with proper cryptographic operations
* **GhostMesh Integration** - Gossip protocol with Ed25519 signatures and anti-replay protection

### ✔️ Key Derivation

* HKDF
* PBKDF2 (with SHA256)

### ✔️ Random Number Generation

* CSPRNG backed by OS entropy
* Hardware entropy when available

---

## ⚖️ Use Cases

* Secure tunnel establishment (e.g., QUIC handshake, GhostMesh keypair)
* Digital identity (e.g., Ed25519 for signing agent messages)
* Key derivation and encrypted backups
* Signing blockchain transactions
* Lightweight secure messaging between Zig agents

---

## 🔧 Architecture

* `zcrypto.hash` - Hashing interfaces and implementations
* `zcrypto.sym` - AES and ChaCha20 cipher modules
* `zcrypto.asym` - Curve and signature tools
* `zcrypto.kdf` - Key derivation functions
* `zcrypto.rand` - Random number utilities
* `zcrypto.util` - Constant-time compare, padding, endian helpers

---

## 🔍 Example Usage

```zig
const zcrypto = @import("zcrypto");

const msg = "ghostmesh FTW";
const hash = zcrypto.hash.sha256(msg);
std.debug.print("SHA-256: {s}\n", .{hash.toHex()});

const keypair = zcrypto.asym.ed25519.generate();
const sig = keypair.sign("test-message");
const valid = keypair.verify("test-message", sig);
```

---

## 🚀 Roadmap

### ✅ Completed (v0.8.4)
* ✅ ML-KEM and ML-DSA post-quantum algorithms
* ✅ Noise Protocol Framework implementation
* ✅ Real cryptographic operations (replaced all stubs)
* ✅ Hardware acceleration support (AES-NI, AVX)
* ✅ Advanced key rotation framework
* ✅ Comprehensive benchmarking suite

### 🔮 Upcoming Features
* [ ] XChaCha20 support
* [ ] Secp256k1 and ECDSA
* [ ] Support for encrypted key storage
* [ ] WASM-friendly crypto targets
* [ ] Formal verification tooling integration
* [ ] Additional post-quantum signature schemes

---

## 🌌 Why Zcrypto?

Because we need a **Zig-native** crypto library that:

* Avoids the mess of OpenSSL
* Is easy to audit
* Plays well with embedded, WebAssembly, and homelab-grade infra
* Powers secure-by-default tooling (GhostMesh, GhostChain, Jarvis)

---

## 🚀 Quick Start

### Prerequisites
- Zig v0.16 dev or later

### Installation

Add Zcrypto as a dependency to your project:

```bash
zig fetch --save https://github.com/ghostkellz/zcrypto/archive/main.tar.gz
```

Then in your `build.zig`:

```zig
const zcrypto = b.dependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
```

### Clone Repository (Development)

```bash
git clone https://github.com/ghostkellz/zcrypto.git
cd zcrypto
zig build
```

---

## ✨ License

MIT or dual MIT/Apache2 for max compatibility.

---

## 🎓 Documentation & Specs

* Zig v0.16 dev+
* Zcrypto strictly adheres to NIST and IETF standards where applicable
* Formal verification tooling support (planned)

---

## 📊 Performance Goals

* Competitive with RustCrypto
* Tiny binary footprint
* No dynamic allocation unless necessary

---

**Zcrypto**: Cryptography at the speed of Zig.

