# zcrypto v0.2.0 Documentation

`zcrypto` is a comprehensive, high-performance cryptography library for [Zig](https://ziglang.org) designed for modern applications including TLS 1.3, QUIC, blockchain, wallets, and secure networking. It provides production-ready implementations of all major cryptographic primitives with clean, consistent APIs.

---

## 📚 Complete Module Reference

### `zcrypto.hash` - Cryptographic Hashing

Fast, secure hash functions with streaming support.

**Basic Hashing:**
```zig
const hash = zcrypto.hash.sha256("Hello, World!");        // [32]u8
const hash512 = zcrypto.hash.sha512("data");              // [64]u8  
const blake = zcrypto.hash.blake2b("data");               // [64]u8
```

**HMAC Authentication:**
```zig
const hmac = zcrypto.hash.hmacSha256(message, key);       // [32]u8
const hmac512 = zcrypto.hash.hmacSha512(message, key);    // [64]u8
const hmac_blake = zcrypto.hash.hmacBlake2s(message, key); // [32]u8
```

**Streaming Hashing:**
```zig
var hasher = zcrypto.hash.Sha256.init();
hasher.update("chunk1");
hasher.update("chunk2");
const result = hasher.final(); // [32]u8
```

### `zcrypto.auth` - Message Authentication

Clean HMAC APIs with constant-time verification.

**One-Shot HMAC:**
```zig
const tag = zcrypto.auth.hmac.sha256(message, key);
const tag512 = zcrypto.auth.hmac.sha512(message, key);
const tag_blake = zcrypto.auth.hmac.blake2s(message, key);
```

**Secure Verification:**
```zig
const is_valid = zcrypto.auth.verifyHmacSha256(message, key, expected_tag);
const is_valid512 = zcrypto.auth.verifyHmacSha512(message, key, expected_tag);
```

**Streaming HMAC:**
```zig
var hasher = zcrypto.auth.HmacSha256.init(key);
hasher.update("large");
hasher.update("message");
const result = hasher.final();
```

### `zcrypto.sym` - Symmetric Encryption

Modern authenticated encryption with simplified APIs.

**AES-256-GCM (Recommended):**
```zig
const key = zcrypto.rand.generateKey(32);
const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key);
const decrypted = try zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key);
```

**ChaCha20-Poly1305 (High Performance):**
```zig
const key = zcrypto.rand.generateKey(32);
const ciphertext = try zcrypto.sym.encryptChaCha20(allocator, plaintext, &key);
const decrypted = try zcrypto.sym.decryptChaCha20(allocator, ciphertext, &key);
```

**Advanced APIs (Manual Nonce Control):**
```zig
const nonce = zcrypto.rand.nonce(12);
const result = try zcrypto.sym.encryptAes256Gcm(allocator, key, nonce, plaintext, aad);
const plaintext = try zcrypto.sym.decryptAes256Gcm(allocator, key, nonce, result.data, result.tag, aad);
```

### `zcrypto.asym` - Asymmetric Cryptography

Complete public-key cryptography suite.

**Ed25519 (Recommended for New Apps):**
```zig
const keypair = zcrypto.asym.ed25519.generate();
const signature = keypair.sign("message");
const valid = keypair.verify("message", signature);

// Standalone functions
const sig = zcrypto.asym.ed25519.sign("message", private_key);
const ok = zcrypto.asym.ed25519.verify("message", sig, public_key);
```

**X25519 Key Exchange:**
```zig
const alice = zcrypto.asym.x25519.generate();
const bob = zcrypto.asym.x25519.generate();
const alice_shared = try alice.dh(bob.public_key);
const bob_shared = try bob.dh(alice.public_key);
// alice_shared == bob_shared
```

**secp256k1 (Bitcoin/Ethereum):**
```zig
const keypair = zcrypto.asym.secp256k1.generate();
const message_hash = [_]u8{0xAB} ** 32; // SHA-256 of message
const signature = keypair.sign(message_hash);
const valid = keypair.verify(message_hash, signature);
```

**secp256r1 (NIST P-256):**
```zig
const keypair = zcrypto.asym.secp256r1.generate();
const signature = keypair.sign(message_hash);
const valid = keypair.verify(message_hash, signature);
```

### `zcrypto.kdf` - Key Derivation

Secure key derivation for passwords and key expansion.

**Argon2id (Recommended for Passwords):**
```zig
const key = try zcrypto.kdf.argon2id(allocator, password, salt, 32);
const stretched = try zcrypto.kdf.stretchPassword(allocator, password, salt, 32);
```

**HKDF (Key Expansion):**
```zig
const derived = try zcrypto.kdf.hkdfSha256(allocator, input_key, salt, info, 32);
const derived512 = try zcrypto.kdf.hkdfSha512(allocator, input_key, salt, info, 64);
```

**PBKDF2 (Legacy Compatibility):**
```zig
const key = try zcrypto.kdf.pbkdf2Sha256(allocator, password, salt, 600000, 32);
const legacy = try zcrypto.kdf.legacyStretchPassword(allocator, password, salt, 32);
```

**TLS 1.3 Key Derivation:**
```zig
const label_key = try zcrypto.kdf.hkdfExpandLabel(allocator, secret, "key", context, 32);
const app_key = try zcrypto.kdf.deriveKey(allocator, master_secret, "application", 32);
```

### `zcrypto.rand` - Secure Random Generation

Cryptographically secure random number generation.

**Fill Buffers:**
```zig
var buf: [32]u8 = undefined;
zcrypto.rand.fillBytes(&buf); // Documentation API
zcrypto.rand.fill(&buf);      // Legacy API
```

**Generate Keys and Salts:**
```zig
const key = zcrypto.rand.generateKey(32);     // AES-256 key
const salt = zcrypto.rand.generateSalt(16);   // 16-byte salt
const nonce = zcrypto.rand.nonce(12);         // GCM nonce
const iv = zcrypto.rand.iv(16);               // CBC IV
const session = zcrypto.rand.sessionId(24);   // Session ID
```

**Random Values:**
```zig
const bytes = try zcrypto.rand.randomBytes(allocator, 64);
const num = zcrypto.rand.randomU32();
const range_val = zcrypto.rand.randomRange(u8, 100);  // 0-99
const float_val = zcrypto.rand.randomFloat(f64);      // 0.0-1.0
```

### `zcrypto.util` - Cryptographic Utilities

Security-focused utility functions.

**Constant-Time Operations:**
```zig
const equal = zcrypto.util.constantTimeCompare(secret1, secret2);
const equal_legacy = zcrypto.util.constantTimeEqual(secret1, secret2);
const array_equal = zcrypto.util.constantTimeEqualArray([32]u8, hash1, hash2);
```

**Secure Memory:**
```zig
zcrypto.util.secureZero(sensitive_buffer);
```

**Encoding/Decoding:**
```zig
const hex = try zcrypto.util.toHex(allocator, bytes);
const bytes = try zcrypto.util.fromHex(allocator, hex_string);
const b64 = try zcrypto.util.base64Encode(allocator, data);
const data = try zcrypto.util.base64Decode(allocator, b64_string);
```

**PKCS#7 Padding:**
```zig
const padded = try zcrypto.util.pkcs7Pad(allocator, data, 16);
const unpadded = try zcrypto.util.pkcs7Unpad(allocator, padded);
```

**Endian Conversion:**
```zig
const val = zcrypto.util.readU32BE(bytes);
zcrypto.util.writeU32BE(value, bytes);
const val64 = zcrypto.util.readU64BE(bytes);
zcrypto.util.writeU64BE(value, bytes);
```

**XOR Operations:**
```zig
zcrypto.util.xorBytes(buffer_a, buffer_b); // In-place
const result = try zcrypto.util.xorBytesAlloc(allocator, a, b);
```

### `zcrypto.bip` - Bitcoin Standards

Complete Bitcoin BIP implementation for HD wallets.

**BIP-39 Mnemonic Phrases:**
```zig
// Generate mnemonic
const mnemonic = try zcrypto.bip.bip39.generate(allocator, .words_12);
defer mnemonic.deinit();

// Convert to seed
const seed = try mnemonic.toSeed(allocator, "optional passphrase");
defer allocator.free(seed);

// Or direct conversion
const seed2 = try zcrypto.bip.bip39.mnemonicToSeed(allocator, mnemonic_phrase, "");
defer allocator.free(seed2);
```

**BIP-32 HD Wallets:**
```zig
// Create master key
const master = zcrypto.bip.bip32.masterKeyFromSeed(seed);

// Derive child keys
const child = master.deriveChild(0);          // m/0
const grandchild = child.deriveChild(1);      // m/0/1
const hardened = master.deriveChild(0x80000000); // m/0' (hardened)
```

**BIP-44 Multi-Account Hierarchy:**
```zig
// Standard derivation paths
const btc_path = zcrypto.bip.bip44.bitcoinPath(0, 0, 0);    // m/44'/0'/0'/0/0
const eth_path = zcrypto.bip.bip44.ethereumPath(0, 0, 0);   // m/44'/60'/0'/0/0

// Derive keys
const btc_key = zcrypto.bip.bip44.deriveKey(master, btc_path);
const eth_key = zcrypto.bip.bip44.deriveKey(master, eth_path);

// Convert to cryptocurrency keypairs
const btc_keypair = btc_key.toSecp256k1KeyPair();
const eth_keypair = eth_key.toSecp256k1KeyPair(); // Ethereum also uses secp256k1
```

**Custom Derivation Paths:**
```zig
const custom_path = zcrypto.bip.bip44.DerivationPath{
    .coin_type = 42,     // Custom coin
    .account = 1,        // Account 1  
    .change = 0,         // Receiving addresses
    .address_index = 5,  // Address index 5
};
const custom_key = zcrypto.bip.bip44.deriveKey(master, custom_path);
```

### `zcrypto.tls` - TLS/QUIC Support

Specialized routines for modern protocols (existing functionality).

---

## 🔐 Security Best Practices

### Key Management
- **Never hardcode keys** in source code
- **Use secure key derivation** (HKDF, Argon2id)
- **Rotate keys regularly** in production
- **Clear sensitive data** with `secureZero()`

### Random Generation  
- **Always use zcrypto.rand** for cryptographic purposes
- **Never reuse nonces** with the same key
- **Use appropriate entropy** for your use case

### Timing Attack Prevention
- **Use constantTimeCompare()** for sensitive comparisons
- **Avoid branching** on secret values  
- **Use authenticated encryption** (AES-GCM, ChaCha20-Poly1305)

### Error Handling
- **Handle all crypto errors** properly
- **Don't leak information** through error messages
- **Fail securely** when operations fail

---

## 🧪 Testing

Run the complete test suite:

```bash
zig build test
```

Includes comprehensive tests for:
- ✅ RFC 2104 (HMAC) test vectors
- ✅ RFC 5869 (HKDF) test vectors  
- ✅ RFC 9106 (Argon2) compatibility
- ✅ RFC 8032 (Ed25519) test vectors
- ✅ RFC 7748 (X25519) test vectors
- ✅ NIST AES-GCM test vectors
- ✅ Bitcoin secp256k1 test vectors
- ✅ BIP-39/32/44 test vectors

---

## 🎯 Performance

zcrypto is optimized for performance:

**ChaCha20-Poly1305** for software-only environments
**AES-GCM** when hardware acceleration is available  
**Batch operations** supported for high throughput
**Memory-efficient** streaming APIs for large data

Benchmark with:
```bash
zig build bench  # (when available)
```

---

## 🧩 Integration Examples

### Secure Password Manager
```zig
const password_hash = try zcrypto.kdf.argon2id(allocator, password, salt, 32);
const encrypted = try zcrypto.sym.encryptAesGcm(allocator, secrets, &password_hash);
```

### Bitcoin Wallet
```zig
const mnemonic = try zcrypto.bip.bip39.generate(allocator, .words_24);
const seed = try mnemonic.toSeed(allocator, "");
const master = zcrypto.bip.bip32.masterKeyFromSeed(seed);
const btc_key = zcrypto.bip.bip44.deriveKey(master, zcrypto.bip.bip44.bitcoinPath(0, 0, 0));
const keypair = btc_key.toSecp256k1KeyPair();
```

### Secure Messaging
```zig
const alice = zcrypto.asym.x25519.generate();
const bob = zcrypto.asym.x25519.generate();
const shared = try alice.dh(bob.public_key);
const message_key = try zcrypto.kdf.hkdfSha256(allocator, &shared, "messaging", "encrypt", 32);
const encrypted = try zcrypto.sym.encryptChaCha20(allocator, message, &message_key);
```

---

## 👣 Dependencies

- **Zig 0.15.0-dev** minimum
- **std.crypto only** (no external dependencies)
- **Memory-safe** by design
- **Cross-platform** compatible

---

## 🔗 Project Integration

### Ready for Integration With:
- 🔗 **zwallet** — HD wallets, secure storage
- 🔗 **zsig** — Multi-algorithm signing  
- 🔗 **ghostbridge** — Secure cross-chain bridges
- 🔗 **zledger** — Cryptographic audit trails
- 🔗 **zquic** — QUIC handshake/traffic protection
- 🔗 **tokioZ** — Async secure channels

---

## 🚀 Version History

- **v0.2.0** - Major expansion: HMAC, Argon2id, secp256k1/r1, BIP standards, simplified APIs
- **v0.1.0** - Initial release: Basic hashing, Ed25519, X25519, AES-GCM, TLS support

---

## 👨‍💻 Author

Created by [@ghostkellz](https://github.com/ghostkellz) for the Ghostchain ecosystem.

**zcrypto is now the definitive cryptographic library for Zig** 🔐✨