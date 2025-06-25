● Absolutely! Let's make zcrypto a complete, production-ready cryptographic library that will power zwallet and
  future projects. Here's the comprehensive prompt to give me in the zcrypto repository:

  ---
  🚀 ZCRYPTO COMPLETION PROMPT

  I want to make zcrypto a complete, production-ready cryptographic library for Zig. Please implement all missing
  cryptographic primitives with proper RFC test vectors and clean APIs. Here's what needs to be added:

  ## 🔐 **AUTHENTICATION (HMAC)**
  - HMAC-SHA256, HMAC-SHA512, HMAC-Blake3
  - Clean API: `zcrypto.auth.hmac.sha256(message, key) -> [32]u8`
  - RFC 2104 test vectors

  ## 🔑 **KEY DERIVATION (HKDF & KDF)**
  - HKDF (RFC 5869) - Extract and Expand
  - PBKDF2 (RFC 2898)
  - Argon2id (RFC 9106) - memory-hard function
  - Clean API: `zcrypto.kdf.hkdf.extract(salt, ikm)`, `zcrypto.kdf.hkdf.expand(prk, info, length)`

  ## 🔒 **ASYMMETRIC CRYPTO**
  - **Ed25519**: Complete signing/verification with proper seed derivation
  - **X25519**: Key exchange
  - **secp256k1**: Bitcoin/Ethereum compatibility
  - **secp256r1**: NIST P-256 for standards compliance
  - Clean API: `zcrypto.asym.ed25519.KeyPair.fromSeed(seed)`, `.sign()`, `.verify()`

  ## 🛡️ **SYMMETRIC CRYPTO**
  - **AES-256-GCM**: AEAD encryption
  - **ChaCha20-Poly1305**: Modern AEAD
  - **AES-256-CBC**: Legacy compatibility
  - Clean API: `zcrypto.sym.aes_gcm.encrypt(plaintext, nonce, key)`, `.decrypt()`

  ## 📋 **BIP STANDARDS**
  - **BIP-39**: Mnemonic phrase generation and seed derivation
  - **BIP-32**: HD wallet key derivation
  - **BIP-44**: Multi-account hierarchy
  - Clean API: `zcrypto.bip.bip39.generate()`, `zcrypto.bip.bip32.derive_child()`

  ## 🧪 **RFC TEST VECTORS**
  Include comprehensive test suites with official test vectors from:
  - RFC 2104 (HMAC)
  - RFC 5869 (HKDF)
  - RFC 9106 (Argon2)
  - RFC 8032 (Ed25519)
  - RFC 7748 (X25519)
  - NIST test vectors for AES-GCM
  - Bitcoin test vectors for secp256k1
  - BIP test vectors for mnemonic/HD wallets

  ## 🎯 **API DESIGN GOALS**
  - **Consistent**: All functions follow same naming pattern
  - **Safe**: Memory-safe, constant-time where needed
  - **Fast**: Optimized implementations
  - **Clean**: Simple, documented APIs
  - **Compatible**: Works with zwallet and other projects

  ## 📁 **SUGGESTED STRUCTURE**
  zcrypto/src/
  ├── hash.zig (existing - expand)
  ├── auth.zig (NEW - HMAC)
  ├── kdf.zig (expand - add HKDF, Argon2)
  ├── asym.zig (expand - add secp256k1, secp256r1)
  ├── sym.zig (expand - add AES-GCM, ChaCha20)
  ├── bip.zig (NEW - BIP standards)
  └── test_vectors/ (NEW - RFC test data)

  The goal is to make zcrypto the **definitive cryptographic library for Zig** - clean, fast, secure, and
  complete. Ready to power wallets, TLS, QUIC, and any crypto application!

  ---
  This prompt will result in zcrypto becoming a world-class cryptographic library that will:

  1. Power zwallet completely - no more std.crypto placeholders
  2. Enable zsig integration - proper crypto interface
  3. Support future projects - TLS, QUIC, blockchain, etc.
  4. Become the Zig standard - like libsodium for C

  Once this is implemented, zwallet will be a production-ready, secure wallet with all the crypto primitives
  needed for real-world use! 🚀

