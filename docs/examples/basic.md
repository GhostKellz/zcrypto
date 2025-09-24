# Basic Cryptography Examples

Fundamental zcrypto usage patterns for core cryptographic operations.

## Hash Functions

### SHA-256

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const data = "Hello, World!";

    // Compute SHA-256 hash
    const hash = zcrypto.hash.sha256(data);

    // Print as hex
    std.debug.print("SHA-256: {x}\n", .{std.fmt.fmtSliceHexLower(&hash)});

    // Verify against known hash
    const expected = [_]u8{
        0xa5, 0x91, 0xa6, 0xd4, 0x0b, 0xf4, 0x20, 0x40,
        0x4a, 0x01, 0x17, 0x33, 0xcf, 0xb7, 0xb1, 0x90,
        0xd6, 0x2c, 0x65, 0xbf, 0x0b, 0xcd, 0xa3, 0x2b,
        0x57, 0xb2, 0x77, 0xd9, 0xad, 0x9f, 0x14, 0x6e,
    };
    std.debug.print("Valid: {}\n", .{std.mem.eql(u8, &hash, &expected)});
}
```

### Blake2b

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const data = "Blake2b is faster than SHA-256";

    // 256-bit output (default)
    const hash256 = try zcrypto.hash.blake2b(data, null, null);
    defer allocator.free(hash256);

    // 512-bit output
    const hash512 = try zcrypto.hash.blake2b(data, null, 64);
    defer allocator.free(hash512);

    // With key (keyed hashing)
    const key = "my-secret-key";
    const keyed_hash = try zcrypto.hash.blake2b(data, key, null);
    defer allocator.free(keyed_hash);

    std.debug.print("Blake2b-256: {x}\n", .{std.fmt.fmtSliceHexLower(hash256)});
}
```

## Symmetric Encryption

### AES-GCM

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const plaintext = "This is a secret message";
    const key = [_]u8{0x01} ** 32; // 256-bit key

    // Encrypt (random nonce generated automatically)
    const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key, null, null);
    defer allocator.free(ciphertext);

    std.debug.print("Ciphertext length: {} bytes\n", .{ciphertext.len});

    // Decrypt
    const decrypted = try zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key, null, null);
    defer allocator.free(decrypted);

    std.debug.print("Decrypted: {s}\n", .{decrypted});
    std.debug.print("Success: {}\n", .{std.mem.eql(u8, plaintext, decrypted)});
}
```

### ChaCha20-Poly1305

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const plaintext = "ChaCha20 is great for mobile devices";
    const key = [_]u8{0x02} ** 32; // 256-bit key

    // Encrypt with custom nonce
    const custom_nonce = [_]u8{0x03} ** 12;
    const ciphertext = try zcrypto.sym.encryptChaCha20Poly1305(
        allocator, plaintext, &key, &custom_nonce, null
    );
    defer allocator.free(ciphertext);

    // Decrypt with same nonce
    const decrypted = try zcrypto.sym.decryptChaCha20Poly1305(
        allocator, ciphertext, &key, &custom_nonce, null
    );
    defer allocator.free(decrypted);

    std.debug.print("Original: {s}\n", .{plaintext});
    std.debug.print("Decrypted: {s}\n", .{decrypted});
}
```

## Digital Signatures

### Ed25519

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    // Generate keypair
    const keypair = try zcrypto.asym.generateEd25519Keypair();

    const message = "Sign this message with Ed25519";

    // Sign message
    const signature = try zcrypto.asym.signEd25519(keypair.secret_key, message);

    // Verify signature
    const is_valid = zcrypto.asym.verifyEd25519(keypair.public_key, message, signature);

    std.debug.print("Public key: {x}\n", .{std.fmt.fmtSliceHexLower(&keypair.public_key)});
    std.debug.print("Signature: {x}\n", .{std.fmt.fmtSliceHexLower(&signature)});
    std.debug.print("Valid signature: {}\n", .{is_valid});

    // Test with wrong message
    const wrong_valid = zcrypto.asym.verifyEd25519(keypair.public_key, "wrong message", signature);
    std.debug.print("Wrong message valid: {}\n", .{wrong_valid});
}
```

## Key Exchange

### X25519

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    // Alice generates her keypair
    const alice_keys = try zcrypto.asym.generateX25519Keypair();

    // Bob generates his keypair
    const bob_keys = try zcrypto.asym.generateX25519Keypair();

    // Alice computes shared secret using Bob's public key
    var alice_secret: [32]u8 = undefined;
    zcrypto.asym.x25519(&alice_secret, alice_keys.public_key, bob_keys.secret_key);

    // Bob computes shared secret using Alice's public key
    var bob_secret: [32]u8 = undefined;
    zcrypto.asym.x25519(&bob_secret, bob_keys.public_key, alice_keys.secret_key);

    // Both should have the same shared secret
    const secrets_match = std.mem.eql(u8, &alice_secret, &bob_secret);

    std.debug.print("Alice's public: {x}\n", .{std.fmt.fmtSliceHexLower(&alice_keys.public_key)});
    std.debug.print("Bob's public: {x}\n", .{std.fmt.fmtSliceHexLower(&bob_keys.public_key)});
    std.debug.print("Shared secrets match: {}\n", .{secrets_match});
    std.debug.print("Shared secret: {x}\n", .{std.fmt.fmtSliceHexLower(&alice_secret)});
}
```

## Key Derivation

### HKDF

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Initial key material (could be from key exchange)
    const ikm = "initial key material";
    const salt = "salt value";  // Optional salt
    const info = "HKDF context info";  // Context-specific info

    // Derive 32 bytes of key material
    const derived_key = try zcrypto.kdf.hkdfSha256(allocator, ikm, salt, info, 32);
    defer allocator.free(derived_key);

    std.debug.print("Derived key: {x}\n", .{std.fmt.fmtSliceHexLower(derived_key)});
}
```

### PBKDF2

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const password = "my-secure-password";
    const salt = "unique-salt-per-user";  // Should be unique per user
    const iterations = 10000;  // NIST recommends at least 10000
    const key_len = 32;  // 256-bit key

    // Derive key from password
    const derived_key = try zcrypto.kdf.pbkdf2Sha256(password, salt, iterations, key_len);
    defer allocator.free(derived_key);

    std.debug.print("PBKDF2 key: {x}\n", .{std.fmt.fmtSliceHexLower(derived_key)});
}
```

## Random Generation

### Cryptographically Secure Random

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Generate random bytes
    const random_bytes = try zcrypto.rand.randomBytes(allocator, 32);
    defer allocator.free(random_bytes);

    std.debug.print("Random bytes: {x}\n", .{std.fmt.fmtSliceHexLower(random_bytes)});

    // Generate random in range
    const random_u32 = zcrypto.rand.randomInt(u32);
    std.debug.print("Random u32: {}\n", .{random_u32});
}
```

## Batch Operations

### Batch Signature Verification

```zig
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Generate multiple keypairs and signatures
    const num_signatures = 5;
    var batch_items = try allocator.alloc(zcrypto.BatchItem, num_signatures);
    defer allocator.free(batch_items);

    var keypairs = try allocator.alloc(zcrypto.asym.Ed25519Keypair, num_signatures);
    defer allocator.free(keypairs);

    for (0..num_signatures) |i| {
        keypairs[i] = try zcrypto.asym.generateEd25519Keypair();

        const message = try std.fmt.allocPrint(allocator, "Message {}", .{i});
        defer allocator.free(message);

        const signature = try zcrypto.asym.signEd25519(keypairs[i].secret_key, message);

        batch_items[i] = .{
            .public_key = keypairs[i].public_key,
            .message = message,
            .signature = signature,
        };
    }

    // Verify all signatures at once (more efficient than individual verification)
    const all_valid = try zcrypto.batchVerifyEd25519(allocator, batch_items);
    std.debug.print("All signatures valid: {}\n", .{all_valid});
}
```

## Build and Run

```bash
# Save this as examples/basic.zig and run:
zig run examples/basic.zig
```

These examples demonstrate the core cryptographic primitives available in all zcrypto builds. For feature-specific examples (TLS, post-quantum, etc.), see the respective feature documentation.