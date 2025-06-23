# zcrypto Documentation

`zcrypto` is a high-performance cryptography module for [Zig](https://ziglang.org) designed to support TLS 1.3, QUIC handshake derivations, and modern public-key cryptography. It bridges low-level crypto primitives from `std.crypto` with high-level APIs suitable for secure networking, blockchain, and identity use cases.

---

## 📚 Modules Overview

### `zcrypto/tls.zig`

QUIC/TLS-specific key derivation and encryption routines.

* `derive_initial_secrets(cid: []const u8, is_client: bool) -> Secrets`
  Derives client/server initial secrets from connection ID (per RFC 9001).

* `hkdf_expand_label(secret: []const u8, label: []const u8, length: usize) -> []u8`
  Implements TLS 1.3 HKDF label expansion.

* `encrypt_aes_gcm(key: []const u8, nonce: []const u8, plaintext: []const u8, aad: []const u8) -> Ciphertext`
  AES-128-GCM authenticated encryption with associated data.

* `decrypt_aes_gcm(...) -> ?[]u8`
  Decrypts ciphertext and verifies tag. Returns null on failure.

### `zcrypto/sign.zig`

Ed25519 digital signatures and key generation.

* `generate_keypair() -> (pubkey: [32]u8, privkey: [64]u8)`
  Generates a new Ed25519 keypair.

* `sign(message: []const u8, privkey: []const u8) -> [64]u8`
  Signs a message using the Ed25519 private key.

* `verify(message: []const u8, signature: []const u8, pubkey: []const u8) -> bool`
  Verifies an Ed25519 signature.

### `zcrypto/random.zig`

Secure random generation (backed by `std.crypto.random`)

* `fill(buf: []u8)`
  Fills a buffer with secure random bytes.

* `random_bytes(n: usize) -> []u8`
  Returns a fresh random byte slice.

### `zcrypto/hash.zig`

SHA-256, SHA-512, and Blake2b support.

* `sha256(data: []const u8) -> [32]u8`
* `sha512(data: []const u8) -> [64]u8`
* `blake2b(data: []const u8) -> [64]u8`

---

## 🔐 QUIC Integration

`zcrypto` is designed to work natively with `zquic` for TLS 1.3 handshakes and traffic protection:

* Use `derive_initial_secrets()` in your `initial_crypto.zig`
* Plug into `tokioZ`'s waker-based event loop
* Encrypt/decrypt frames using `encrypt_aes_gcm()`

---

## 🧪 Testing

Run full tests:

```bash
zig build test
```

Includes:

* HKDF vector tests
* AES-GCM test vectors
* Ed25519 sign/verify tests

---

## 🔧 Planned Additions

* ✅ Ed25519 (complete)
* ✅ AES-GCM (complete)
* 🔄 ECDSA (in progress)
* 🔄 ChaCha20-Poly1305
* 🔄 Certificate parsing
* 🔄 Key exchange (X25519)
* 🔄 PQC experiments (optional feature)

---

## 💡 Usage Example

```zig
const zcrypto = @import("zcrypto/tls.zig");
const secrets = zcrypto.derive_initial_secrets(cid, true);
const encrypted = zcrypto.encrypt_aes_gcm(secrets.key, secrets.nonce, payload, aad);
```

For signatures:

```zig
const sig = @import("zcrypto/sign.zig");
const keys = sig.generate_keypair();
const s = sig.sign(msg, keys.privkey);
const ok = sig.verify(msg, s, keys.pubkey);
```

---

## 🛡️ Security Notes

* All cryptographic functions are memory-safe by design
* Zeroing of secret keys after use is encouraged
* AES-GCM enforces strict tag length and nonce validation

---

## 👣 Dependencies

* Zig `0.15.0-dev` minimum
* Uses only `std.crypto` (no external libs)

---

## 🧩 Integrations

* 🔗 `zquic` — for QUIC handshake/traffic protection
* 🔗 `tokioZ` — for async I/O-secure channels
* 🔗 `ghostctl` — secure identity, SSH/GPG, auth helpers

---

## 👨‍💻 Author

Created by [@ghostkellz](https://github.com/ghostkellz) for the GhostMesh & Zion stack.
