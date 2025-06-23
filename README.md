# Zcrypto: A Modern Cryptography Library for Zig

**Zcrypto** is a fast, safe, and modular cryptography library written entirely in Zig. It is designed for modern applications in systems programming, embedded security, VPN tunnels (like GhostMesh), blockchain runtimes (like GhostChain), and privacy-first software ecosystems. Built with clarity, auditability, and portability in mind, Zcrypto aims to be the de facto cryptographic foundation for next-generation Zig projects.

---

## 🛡️ Core Principles

* **Memory-safe by design:** Leveraging Zig's explicit control and compile-time safety features.
* **Audit-friendly:** Easy to read, easy to verify. Minimal dependencies.
* **Cross-platform:** Works seamlessly on Linux, macOS, Windows, and embedded targets.
* **Modular and composable:** Include only what you need, zero bloat.

---

## 🤖 Algorithms & Primitives (v0.1)

### ✔️ Hashing

* SHA-256
* SHA-512
* Blake2b / Blake3

### ✔️ Symmetric Encryption

* AES-256-GCM
* ChaCha20-Poly1305
* XChaCha20-Poly1305 (planned)

### ✔️ Asymmetric Encryption

* Ed25519 (signing/verify)
* Curve25519 (key exchange)
* Secp256k1 (planned)

### ✔️ Key Derivation

* HKDF
* PBKDF2 (with SHA256)

### ✔️ Random Number Generation

* CSPRNG backed by OS entropy
* DRBG fallback (planned)

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

* [ ] XChaCha20 support
* [ ] Secp256k1 and ECDSA
* [ ] Support for encrypted key storage
* [ ] WASM-friendly crypto targets
* [ ] zcrypto-bench microbenchmark tool

---

## 🌌 Why Zcrypto?

Because we need a **Zig-native** crypto library that:

* Avoids the mess of OpenSSL
* Is easy to audit
* Plays well with embedded, WebAssembly, and homelab-grade infra
* Powers secure-by-default tooling (GhostMesh, GhostChain, Jarvis)

---

## ✨ License

MIT or dual MIT/Apache2 for max compatibility.

---

## 🎓 Documentation & Specs

* Zig v0.15+
* Zcrypto strictly adheres to NIST and IETF standards where applicable
* Formal verification tooling support (planned)

---

## 📊 Performance Goals

* Competitive with RustCrypto
* Tiny binary footprint
* No dynamic allocation unless necessary

---

**Zcrypto**: Cryptography at the speed of Zig.

