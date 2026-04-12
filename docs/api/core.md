# Core API Reference

Core cryptographic primitives available in all stable zcrypto builds.

## Hash Functions

### SHA-256

```zig
pub fn sha256(data: []const u8) [32]u8
```

Computes SHA-256 hash of input data.

**Parameters:**
- `data`: Input bytes to hash

**Returns:** 32-byte hash digest

**Example:**
```zig
const hash = zcrypto.hash.sha256("Hello, World!");
// hash = 0xa591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e38
```

### SHA-512

```zig
pub fn sha512(data: []const u8) [64]u8
```

Computes SHA-512 hash of input data.

**Parameters:**
- `data`: Input bytes to hash

**Returns:** 64-byte hash digest

### Blake2b

```zig
pub fn blake2b(data: []const u8) [64]u8
```

Computes a 64-byte Blake2b hash of the input data.

## Symmetric Encryption

### AES-GCM

```zig
pub fn encryptAesGcm(allocator: std.mem.Allocator, plaintext: []const u8, key: *const [32]u8) ![]u8
pub fn decryptAesGcm(allocator: std.mem.Allocator, ciphertext_with_nonce: []const u8, key: *const [32]u8) ![]u8
```

Authenticated encryption with AES-GCM.

**Parameters:**
- `allocator`: Memory allocator
- `plaintext/ciphertext`: Data to encrypt/decrypt
- `key`: 32-byte AES-256-GCM key

**Returns:** Encrypted ciphertext / decrypted plaintext

**Format:** `nonce(12) || ciphertext || tag(16)`

### ChaCha20-Poly1305

```zig
pub fn encryptChaCha20(allocator: std.mem.Allocator, plaintext: []const u8, key: *const [32]u8) ![]u8
pub fn decryptChaCha20(allocator: std.mem.Allocator, ciphertext_with_nonce: []const u8, key: *const [32]u8) ![]u8
```

Authenticated encryption with ChaCha20-Poly1305.

**Parameters:**
- `allocator`: Memory allocator
- `plaintext/ciphertext`: Data to encrypt/decrypt
- `key`: 32-byte ChaCha20-Poly1305 key

**Returns:** Encrypted ciphertext / decrypted plaintext

**Format:** `nonce(12) || ciphertext || tag(16)`

## Authentication

### HMAC-SHA256

```zig
pub fn hmacSha256(key: []const u8, data: []const u8) [32]u8
```

Computes HMAC-SHA256 of data with key.

**Parameters:**
- `key`: HMAC key (any length)
- `data`: Data to authenticate

**Returns:** 32-byte HMAC digest

### HMAC-SHA512

```zig
pub fn hmacSha512(key: []const u8, data: []const u8) [64]u8
```

Computes HMAC-SHA512 of data with key.

**Parameters:**
- `key`: HMAC key (any length)
- `data`: Data to authenticate

**Returns:** 64-byte HMAC digest

## Key Derivation

### HKDF-SHA256

```zig
pub fn hkdfSha256(allocator: std.mem.Allocator, ikm: []const u8, salt: []const u8, info: []const u8, out_len: usize) ![]u8
```

HKDF key derivation using SHA-256.

**Parameters:**
- `allocator`: Memory allocator
- `ikm`: Input keying material
- `salt`: Salt bytes
- `info`: Context-specific info string
- `out_len`: Desired output length

**Returns:** Derived key of specified length

### PBKDF2-SHA256

```zig
pub fn pbkdf2Sha256(password: []const u8, salt: []const u8, iterations: u32, out_len: usize) ![]u8
```

PBKDF2 key derivation using SHA-256.

**Parameters:**
- `password`: Password bytes
- `salt`: Salt bytes (16+ bytes recommended)
- `iterations`: Number of iterations (10000+ recommended)
- `out_len`: Desired output length

**Returns:** Derived key of specified length

## Random Generation

### Cryptographically Secure Random

```zig
pub fn randomBytes(allocator: std.mem.Allocator, len: usize) ![]u8
```

Generates cryptographically secure random bytes.

**Parameters:**
- `allocator`: Memory allocator
- `len`: Number of random bytes to generate

**Returns:** Random bytes

### Seeded Random (Deterministic)

```zig
pub fn seededRandomBytes(allocator: std.mem.Allocator, seed: []const u8, len: usize) ![]u8
```

Generates deterministic random bytes from seed.

**Parameters:**
- `allocator`: Memory allocator
- `seed`: Seed bytes
- `len`: Number of random bytes to generate

**Returns:** Deterministic random bytes

## Asymmetric Cryptography

### Ed25519

```zig
pub const Ed25519KeyPair = struct {
    public_key: [32]u8,
    private_key: [64]u8,
};

pub fn signEd25519(message: []const u8, private_key: [64]u8) ![64]u8
pub fn verifyEd25519(message: []const u8, signature: [64]u8, public_key: [32]u8) bool

pub const zcrypto.asym.ed25519 = struct {
    pub fn generate() KeyPair
}
```

Ed25519 digital signatures.

**Key Generation:**
- `zcrypto.asym.ed25519.generate()`: Generate new keypair

**Signing:**
- `private_key`: 64-byte private key
- `message`: Message to sign
- Returns: 64-byte signature

**Verification:**
- `message`: Original message
- `signature`: 64-byte signature
- `public_key`: 32-byte public key
- Returns: `true` if signature is valid

### X25519

```zig
pub const X25519KeyPair = struct {
    public_key: [32]u8,
    private_key: [32]u8,
};

pub fn dhX25519(private_key: [32]u8, public_key: [32]u8) ![32]u8

pub const zcrypto.asym.x25519 = struct {
    pub fn generate() KeyPair
    pub fn dh(private_key: [32]u8, public_key: [32]u8) ![32]u8
}
```

X25519 key exchange.

**Key Generation:**
- `zcrypto.asym.x25519.generate()`: Generate new keypair

**Key Exchange:**
- `private_key`: Your private key
- `public_key`: Peer's public key
- Returns: Shared secret

## Key Exchange

### ECDH (secp256r1)

```zig
pub const Secp256r1Keypair = struct {
    public_key: [64]u8, // uncompressed format
    secret_key: [32]u8,
};

pub fn generateSecp256r1Keypair() !Secp256r1Keypair
pub fn ecdhSecp256r1(shared_secret: [32]u8, public_key: [64]u8, secret_key: [32]u8) !void
```

ECDH key exchange using secp256r1 curve.

**Key Generation:**
- `generateSecp256r1Keypair()`: Generate new keypair

**Key Exchange:**
- `shared_secret`: Output buffer for shared secret
- `public_key`: Peer's public key (64 bytes, uncompressed)
- `secret_key`: Your secret key (32 bytes)

## Batch Operations

### Batch Verification

```zig
pub fn batchVerifyEd25519(allocator: std.mem.Allocator, items: []const BatchItem) !bool
```

Batch verification of multiple Ed25519 signatures.

**Parameters:**
- `allocator`: Memory allocator
- `items`: Array of batch verification items

**BatchItem:**
```zig
pub const BatchItem = struct {
    public_key: [32]u8,
    message: []const u8,
    signature: [64]u8,
};
```

**Returns:** `true` if all signatures are valid

### Batch Key Generation

```zig
pub fn batchGenerateEd25519Keypairs(allocator: std.mem.Allocator, count: usize) ![]Ed25519Keypair
```

Generate multiple Ed25519 keypairs efficiently.

**Parameters:**
- `allocator`: Memory allocator
- `count`: Number of keypairs to generate

**Returns:** Array of keypairs

## BIP32/BIP39

### BIP39 Mnemonic

```zig
pub fn generateBip39Mnemonic(allocator: std.mem.Allocator, entropy_bits: u11) ![]const u8
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: ?[]const u8) ![64]u8
```

BIP39 mnemonic generation and seed derivation.

**Parameters:**
- `entropy_bits`: Entropy bits (128, 160, 192, 224, 256)
- `mnemonic`: BIP39 mnemonic phrase
- `passphrase`: Optional passphrase

**Returns:** Mnemonic string / 64-byte seed

### BIP32 HD Keys

```zig
pub const Bip32Key = struct {
    key: [32]u8,
    chain_code: [32]u8,
    depth: u8,
    index: u32,
    parent_fingerprint: [4]u8,
};

pub fn deriveBip32Child(parent: Bip32Key, index: u32, hardened: bool) !Bip32Key
pub fn deriveBip32Path(root_key: [32]u8, chain_code: [32]u8, path: []const u32) !Bip32Key
```

BIP32 hierarchical deterministic key derivation.

**Parameters:**
- `parent`: Parent key structure
- `index`: Child index
- `hardened`: Whether to use hardened derivation
- `root_key`: Root private key
- `chain_code`: Root chain code
- `path`: Derivation path as array of indices

**Returns:** Derived child key

## Error Types

```zig
pub const Error = error{
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidCiphertext,
    InvalidPlaintext,
    InvalidOutputLength,
    InvalidInputLength,
    DecryptionFailed,
    VerificationFailed,
    KeyGenerationFailed,
    OutOfMemory,
    UnsupportedAlgorithm,
};
```

All functions return these error types as appropriate for their operations.
