# Core API Reference

Core cryptographic primitives available in all stable zcrypto builds.

## Memory Ownership

Any API that accepts a `std.mem.Allocator` and returns a slice returns
caller-owned memory unless the return type documents a `deinit` method. Free
returned slices with the same allocator that was passed to the function.

Examples:

- `sym.encryptAesGcm`, `sym.decryptAesGcm`, `sym.encryptChaCha20`, and
  `sym.decryptChaCha20` return caller-owned `[]u8`.
- `kdf.hkdfSha256`, `kdf.hkdfSha512`, `kdf.pbkdf2Sha256`,
  `rand.randomBytes`, and `util.*Alloc`/encoding helpers return caller-owned
  buffers.
- `async_crypto.AsyncCrypto` allocated results are owned by the caller and
  freed with the allocator passed to `AsyncCrypto.init`.
- Structured types such as `sym.Ciphertext`, `sym.ChaCha20Result`,
  `merkle.MerkleTree`, and TLS config/certificate objects expose `deinit`
  methods and should be cleaned up through those methods.

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
pub fn hmacSha256(message: []const u8, key: []const u8) [32]u8
```

Computes HMAC-SHA256 of data with key.

**Parameters:**
- `message`: Data to authenticate
- `key`: HMAC key (any length)

**Returns:** 32-byte HMAC digest

### HMAC-SHA512

```zig
pub fn hmacSha512(message: []const u8, key: []const u8) [64]u8
```

Computes HMAC-SHA512 of data with key.

**Parameters:**
- `message`: Data to authenticate
- `key`: HMAC key (any length)

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
pub fn pbkdf2Sha256(allocator: std.mem.Allocator, password: []const u8, salt: []const u8, iterations: u32, out_len: usize) ![]u8
```

PBKDF2 key derivation using SHA-256.

**Parameters:**
- `password`: Password bytes
- `salt`: Salt bytes (16+ bytes recommended)
- `iterations`: Number of iterations (10000+ recommended)
- `out_len`: Desired output length

**Returns:** Derived key of specified length

Caller owns the returned buffer and must free it with `allocator`.

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

Caller owns the returned buffer and must free it with `allocator`.

### Fixed-Size Random Arrays

```zig
pub fn randomArray(comptime size: usize) [size]u8
```

Generates a cryptographically secure fixed-size random byte array without heap
allocation.

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
    pub fn fromBytes(public_key: [32]u8, private_key: [64]u8) !KeyPair
    pub fn publicKey(private_key: [64]u8) ![32]u8
}
```

Ed25519 digital signatures.

**Key Generation:**
- `zcrypto.asym.ed25519.generate()`: Generate new keypair
- `zcrypto.asym.ed25519.fromBytes()`: Import a raw keypair and verify that the public key matches the private key
- `zcrypto.asym.ed25519.publicKey()`: Derive public key bytes from private key bytes

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
    pub fn fromBytes(public_key: [32]u8, private_key: [32]u8) !KeyPair
    pub fn publicKeyChecked(private_key: [32]u8) ![32]u8
}
```

X25519 key exchange.

**Key Generation:**
- `zcrypto.asym.x25519.generate()`: Generate new keypair
- `zcrypto.asym.x25519.fromBytes()`: Import a raw keypair and verify that the public key matches the private key
- `zcrypto.asym.x25519.publicKeyChecked()`: Derive public key bytes from private key bytes with explicit errors

**Key Exchange:**
- `private_key`: Your private key
- `public_key`: Peer's public key
- Returns: Shared secret

### ECDSA Key Import/Export

```zig
pub const zcrypto.asym.secp256r1 = struct {
    pub fn fromBytes(public_key: [33]u8, private_key: [32]u8) !KeyPair
    pub fn publicKey(private_key: [32]u8) ![33]u8
}

pub const zcrypto.asym.secp384r1 = struct {
    pub fn fromBytes(public_key: [49]u8, private_key: [48]u8) !KeyPair
    pub fn publicKey(private_key: [48]u8) ![49]u8
}
```

P-256 and P-384 public keys use compressed SEC1 encoding. `fromBytes()` derives
the public key from the private key and fails if the supplied public key does not
match. Returned private-key byte copies should be zeroed by the caller when no
longer needed.

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
pub fn verifyBatchEd25519(messages: []const []const u8, signatures: []const [64]u8, public_keys: []const [32]u8, allocator: std.mem.Allocator) ![]bool
pub fn verifyBatchSecp256k1(message_hashes: []const [32]u8, signatures: []const [64]u8, public_keys: []const [33]u8, allocator: std.mem.Allocator) ![]bool
pub fn verifyBatch(messages: []const []const u8, signatures: []const [64]u8, public_keys: []const []const u8, algorithm: batch.Algorithm, allocator: std.mem.Allocator) ![]bool
```

Batch verification returns a caller-owned `[]bool` with one result per input.
All input arrays must have matching lengths.

### Batch Signing And Hashing

```zig
pub fn signBatchEd25519(messages: []const []const u8, private_key: [64]u8, allocator: std.mem.Allocator) ![][64]u8
pub fn hashBatch(messages: []const []const u8, allocator: std.mem.Allocator) ![][32]u8
pub fn signInPlace(message: []const u8, private_key: [64]u8, signature: *[64]u8) !void
pub fn hashInPlace(message: []const u8, result: *[32]u8) void
```

Allocated batch results are caller-owned and must be freed with `allocator`.

## BIP32/BIP39

### BIP39 Mnemonic

```zig
pub fn bip39.generate(allocator: std.mem.Allocator, length: MnemonicLength) !Mnemonic
pub fn bip39.mnemonicToSeed(allocator: std.mem.Allocator, mnemonic: []const u8, passphrase: []const u8) ![]u8
```

BIP39 mnemonic generation and seed derivation.

**Parameters:**
- `entropy_bits`: Entropy bits (128, 160, 192, 224, 256)
- `mnemonic`: BIP39 mnemonic phrase
- `passphrase`: Optional passphrase

**Returns:** `Mnemonic` owns its word slices and must be released with
`mnemonic.deinit()`. `mnemonicToSeed` returns a caller-owned 64-byte seed buffer
that must be freed with `allocator`.

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
pub const CryptoError = error{
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidHmacKey,
    InvalidKeyFormat,
    InvalidKeySize,
    InvalidNonceSize,
    InvalidTagSize,
    DecryptionFailed,
    EncryptionFailed,
    InvalidInput,
};
```

`zcrypto.CryptoError` and `zcrypto.core.CryptoError` expose the shared stable
core error vocabulary. Individual modules may still expose narrower local error
sets for operation-specific failures; v1.0.5 tracks unifying those public return
contracts where doing so does not hide useful failure detail.
