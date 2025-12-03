# zcrypto v0.9.5 API Reference

Complete API documentation for zcrypto - a comprehensive, high-performance **post-quantum ready** cryptography library for Zig.

---

## Module Overview

| Module | Description |
|--------|-------------|
| `zcrypto.hash` | Cryptographic hashing (SHA-2/3, Blake2/3, SHAKE) |
| `zcrypto.sym` | Symmetric encryption (AES-GCM, ChaCha20-Poly1305) |
| `zcrypto.asym` | Classical asymmetric crypto (Ed25519, X25519, secp256k1) |
| `zcrypto.pq` | Post-quantum cryptography (ML-KEM, ML-DSA) |
| `zcrypto.kdf` | Key derivation (HKDF, PBKDF2, Argon2) |
| `zcrypto.rand` | Secure random generation |
| `zcrypto.protocols` | High-level protocols (Signal, Noise, MLS) |
| `zcrypto.zkp` | Zero-knowledge proofs (Groth16, Bulletproofs) |
| `zcrypto.quic` | QUIC cryptography (including post-quantum) |

---

## `zcrypto.hash` - Cryptographic Hashing

Fast, secure hash functions with streaming support.

### Basic Hashing

```zig
const hash = zcrypto.hash.sha256("Hello, World!");           // [32]u8
const hash512 = zcrypto.hash.sha512("data");                 // [64]u8
const blake = zcrypto.hash.blake2b("data");                  // [64]u8
const sha3 = zcrypto.hash.sha3_256("data");                  // [32]u8
```

### HMAC Authentication

```zig
const hmac = zcrypto.hash.hmacSha256(message, key);          // [32]u8
const hmac512 = zcrypto.hash.hmacSha512(message, key);       // [64]u8
const hmac_blake = zcrypto.hash.hmacBlake2s(message, key);   // [32]u8
```

### Extendable Output Functions (XOF)

```zig
var shake_output: [64]u8 = undefined;
zcrypto.hash.shake128("input data", &shake_output);
zcrypto.hash.shake256("input data", &shake_output);
```

### Streaming Hashing

```zig
var hasher = zcrypto.hash.Sha256.init();
hasher.update("chunk1");
hasher.update("chunk2");
const result = hasher.final(); // [32]u8
```

---

## `zcrypto.sym` - Symmetric Encryption

Modern authenticated encryption with high-performance implementations.

### AES-256-GCM

```zig
const key = zcrypto.rand.generateKey(32);
var nonce: [12]u8 = undefined;
var tag: [16]u8 = undefined;
try zcrypto.sym.aes256_gcm_encrypt(plaintext, &key, &nonce, ciphertext, &tag);
try zcrypto.sym.aes256_gcm_decrypt(ciphertext, &key, &nonce, &tag, plaintext);
```

### ChaCha20-Poly1305

```zig
const key = zcrypto.rand.generateKey(32);
var nonce: [12]u8 = undefined;
var tag: [16]u8 = undefined;
try zcrypto.sym.chacha20_poly1305_encrypt(plaintext, &key, &nonce, ciphertext, &tag);
try zcrypto.sym.chacha20_poly1305_decrypt(ciphertext, &key, &nonce, &tag, plaintext);
```

---

## `zcrypto.asym` - Classical Asymmetric Cryptography

### Ed25519 Signatures

```zig
const keypair = try zcrypto.asym.ed25519.KeyPair.generate();
const signature = try keypair.sign("message");
const valid = try keypair.verify("message", signature);
```

### X25519 Key Exchange

```zig
const alice = try zcrypto.asym.x25519.KeyPair.generate();
const bob = try zcrypto.asym.x25519.KeyPair.generate();
const alice_shared = try alice.dh(bob.public_key);
const bob_shared = try bob.dh(alice.public_key);
// alice_shared == bob_shared
```

### secp256k1 (Bitcoin/Ethereum)

```zig
const keypair = try zcrypto.asym.secp256k1.KeyPair.generate();
const message_hash = [_]u8{0xAB} ** 32; // SHA-256 of message
const signature = try keypair.sign(message_hash);
const valid = try keypair.verify(message_hash, signature);
```

---

## `zcrypto.pq` - Post-Quantum Cryptography

NIST-standardized post-quantum algorithms for quantum-safe security.

### ML-KEM-768 (Key Encapsulation)

```zig
// Generate keypair
var seed: [32]u8 = undefined;
std.crypto.random.bytes(&seed);
const keypair = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.generate(seed);

// Encapsulation (by sender)
var enc_randomness: [32]u8 = undefined;
std.crypto.random.bytes(&enc_randomness);
const result = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(
    keypair.public_key,
    enc_randomness
);

// Decapsulation (by receiver)
const shared_secret = try keypair.decapsulate(result.ciphertext);
// result.shared_secret == shared_secret
```

### ML-DSA-65 (Digital Signatures)

```zig
// Generate keypair
var seed: [32]u8 = undefined;
std.crypto.random.bytes(&seed);
const keypair = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generate(seed);

// Sign message
const message = "Hello, Post-Quantum World!";
const signature = try keypair.sign(message);

// Verify signature
const valid = try keypair.verify(message, signature);
```

### Hybrid Classical + Post-Quantum

```zig
// Hybrid key exchange (X25519 + ML-KEM-768)
var shared_secret: [64]u8 = undefined;
try zcrypto.pq.hybrid.x25519_ml_kem_768_kex(
    &shared_secret,
    &classical_share,
    &pq_share,
    entropy
);

// Hybrid signatures (Ed25519 + ML-DSA-65)
const hybrid_keypair = try zcrypto.pq.hybrid.Ed25519_ML_DSA_65.KeyPair.generate(seed);
const hybrid_signature = try hybrid_keypair.sign("message");
const valid = try hybrid_keypair.verify("message", hybrid_signature);
```

---

## `zcrypto.protocols` - High-Level Protocols

### Signal Protocol (Secure Messaging)

```zig
// X3DH Key Agreement
const alice_identity = try zcrypto.protocols.signal.IdentityKeyPair.generate();
const alice_signed_prekey = try zcrypto.protocols.signal.SignedPreKeyPair.generate(0);
const alice_otk = try zcrypto.protocols.signal.OneTimeKeyPair.generate();

const shared_secret = try zcrypto.protocols.signal.x3dh(
    bob_identity.public_key,
    alice_signed_prekey.public_key,
    alice_otk.public_key
);

// Double Ratchet for message encryption
var ratchet = try zcrypto.protocols.signal.DoubleRatchet.init(shared_secret);
const encrypted_msg = try ratchet.encrypt("Hello, secure world!");
const decrypted_msg = try ratchet.decrypt(encrypted_msg);
```

### Noise Protocol Framework

```zig
// Noise_XX pattern
var initiator = try zcrypto.protocols.noise.NoiseSession.init(.XX, true);
var responder = try zcrypto.protocols.noise.NoiseSession.init(.XX, false);

// Handshake
const msg1 = try initiator.writeMessage(&[_]u8{});
const msg2 = try responder.readMessage(msg1);
const msg3 = try initiator.readMessage(msg2);

// Secure channel established
const encrypted = try initiator.encrypt("secure data");
const decrypted = try responder.decrypt(encrypted);
```

### MLS (Message Layer Security)

```zig
// Create group
var group = try zcrypto.protocols.mls.Group.create();
const member_keypair = try zcrypto.protocols.mls.MemberKeyPair.generate();

// Add member and send encrypted message
try group.addMember(member_keypair.public_key);
const encrypted_msg = try group.encrypt("Group message");
const decrypted_msg = try group.decrypt(encrypted_msg);
```

---

## `zcrypto.zkp` - Zero-Knowledge Proofs

### Groth16 zk-SNARKs

```zig
// Setup (done once per circuit)
const circuit = try zcrypto.zkp.groth16.Circuit.load("circuit.r1cs");
const setup = try zcrypto.zkp.groth16.setup(circuit);

// Prove
const witness = [_]u8{ /* private inputs */ };
const public_inputs = [_]u8{ /* public inputs */ };
const proof = try zcrypto.zkp.groth16.prove(setup.proving_key, witness);

// Verify
const valid = try zcrypto.zkp.groth16.verify(
    setup.verifying_key,
    proof,
    public_inputs
);
```

### Bulletproofs (Range Proofs)

```zig
// Prove value is in range [0, 2^32)
const value: u64 = 12345;
const range_proof = try zcrypto.zkp.bulletproofs.proveRange(value, 0, 0xFFFFFFFF);

// Verify range proof
const commitment = [_]u8{ /* commitment to value */ };
const valid = try zcrypto.zkp.bulletproofs.verifyRange(range_proof, &commitment);
```

---

## `zcrypto.quic` - QUIC Cryptography

### Standard QUIC Crypto

```zig
var quic_crypto = zcrypto.quic.QuicCrypto.init(.TLS_AES_256_GCM_SHA384);
const connection_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

// Derive initial keys
try quic_crypto.deriveInitialKeys(&connection_id);

// Encrypt QUIC packet
const encrypted_len = try quic_crypto.encryptPacket(
    .initial,
    false, // is_server
    packet_number,
    header,
    payload,
    output
);
```

### Post-Quantum QUIC

```zig
// Generate hybrid key share for QUIC ClientHello
var classical_share: [32]u8 = undefined;
var pq_share: [800]u8 = undefined; // ML-KEM-768 public key
const entropy = [_]u8{0x42} ** 64;

try zcrypto.quic.PostQuantumQuic.generateHybridKeyShare(
    &classical_share,
    &pq_share,
    &entropy
);

// Process on server side
var server_classical: [32]u8 = undefined;
var server_pq: [1088]u8 = undefined; // ML-KEM-768 ciphertext
var shared_secret: [64]u8 = undefined;

try zcrypto.quic.PostQuantumQuic.processHybridKeyShare(
    &classical_share,
    &pq_share,
    &server_classical,
    &server_pq,
    &shared_secret
);
```

---

## `zcrypto.kdf` - Key Derivation

### HKDF

```zig
const derived = try zcrypto.kdf.hkdfSha256(input_key, salt, info, 32);
const derived512 = try zcrypto.kdf.hkdfSha512(input_key, salt, info, 64);

// QUIC-specific key derivation
const quic_keys = try zcrypto.kdf.deriveQuicKeys(master_secret, label, 32);
```

### Post-Quantum Key Derivation

```zig
// Enhanced entropy mixing for PQ security
const pq_key = try zcrypto.kdf.derivePostQuantumKey(
    classical_secret,
    pq_secret,
    context,
    64
);
```

---

## `zcrypto.rand` - Secure Random Generation

```zig
// Fill buffer with random bytes
var buf: [32]u8 = undefined;
zcrypto.rand.fillBytes(&buf);

// Generate keys and nonces
const key = zcrypto.rand.generateKey(32);     // AES-256 key
const salt = zcrypto.rand.generateSalt(16);   // 16-byte salt
const nonce = zcrypto.rand.nonce(12);         // GCM nonce
```

---

## `zcrypto.util` - Cryptographic Utilities

### Constant-Time Operations

```zig
const equal = zcrypto.util.constantTimeCompare(secret1, secret2);
const array_equal = zcrypto.util.constantTimeEqualArray([32]u8, hash1, hash2);
```

### Secure Memory

```zig
zcrypto.util.secureZero(sensitive_buffer);
```

---

## Performance

| Operation | Throughput |
|-----------|------------|
| ML-KEM-768 keygen | >50,000 ops/sec |
| ML-KEM-768 encaps/decaps | >30,000 ops/sec |
| Hybrid key exchange | >25,000 ops/sec |
| ChaCha20-Poly1305 | >1.5 GB/sec |
| AES-256-GCM (AES-NI) | >2 GB/sec |
| Ed25519 signing | >100,000 ops/sec |
| PQ QUIC handshake | <2ms |

---

## Error Types

```zig
pub const Error = error{
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidCiphertext,
    DecryptionFailed,
    VerificationFailed,
    KeyGenerationFailed,
    OutOfMemory,
    UnsupportedAlgorithm,
};
```
