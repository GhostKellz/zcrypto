# Basic Cryptography Examples

Fundamental zcrypto usage patterns for the stable v1.0.x core.

## Hashing

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() void {
    const digest = zcrypto.hash.sha256("Hello, zcrypto!");
    var hex: [64]u8 = undefined;
    std.debug.print("SHA-256: {s}\n", .{zcrypto.hash.toHex([32]u8, digest, &hex)});

    var blake = zcrypto.blake3.Blake3.init();
    blake.update("streamed ");
    blake.update("data");
    const blake_digest = blake.final();
    var blake_hex: [64]u8 = undefined;
    std.debug.print("Blake3: {s}\n", .{zcrypto.hash.toHex([32]u8, blake_digest, &blake_hex)});
}
```

## Symmetric Encryption

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const plaintext = "authenticated payload";

    var key = zcrypto.sym.Aes256GcmKey.random();
    defer key.zeroize();

    const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, key.asBytes());
    defer allocator.free(ciphertext);

    const decrypted = try zcrypto.sym.decryptAesGcm(allocator, ciphertext, key.asBytes());
    defer allocator.free(decrypted);

    std.debug.print("AES-GCM round trip: {}\n", .{std.mem.eql(u8, plaintext, decrypted)});
}
```

## ChaCha20-Poly1305

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const plaintext = "mobile-friendly AEAD";

    var key = zcrypto.sym.ChaCha20Poly1305Key.random();
    defer key.zeroize();

    const ciphertext = try zcrypto.sym.encryptChaCha20(allocator, plaintext, key.asBytes());
    defer allocator.free(ciphertext);

    const decrypted = try zcrypto.sym.decryptChaCha20(allocator, ciphertext, key.asBytes());
    defer allocator.free(decrypted);

    std.debug.print("ChaCha20-Poly1305 round trip: {}\n", .{std.mem.eql(u8, plaintext, decrypted)});
}
```

## Digital Signatures

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var keypair = try zcrypto.kex.Ed25519.generateKeypair();
    defer keypair.zeroize();

    const message = "message to sign";
    const signature = try zcrypto.kex.Ed25519.sign(keypair.private_key, message);
    const valid = try zcrypto.kex.Ed25519.verify(keypair.public_key, message, signature);

    std.debug.print("Ed25519 signature valid: {}\n", .{valid});
}
```

## Key Exchange

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var alice = try zcrypto.kex.X25519.generateKeypair();
    defer alice.zeroize();
    var bob = try zcrypto.kex.X25519.generateKeypair();
    defer bob.zeroize();

    const alice_secret = try zcrypto.kex.X25519.computeSharedSecret(alice.private_key, bob.public_key);
    const bob_secret = try zcrypto.kex.X25519.computeSharedSecret(bob.private_key, alice.public_key);

    std.debug.print("X25519 shared secret match: {}\n", .{
        zcrypto.util.constantTimeCompare(&alice_secret, &bob_secret),
    });
}
```

## Key Derivation

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const okm = try zcrypto.kdf.hkdfSha256(
        allocator,
        "input key material",
        "salt",
        "application context",
        32,
    );
    defer allocator.free(okm);

    std.debug.print("HKDF output length: {}\n", .{okm.len});
}
```

## HMAC Key Ownership

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var key = try zcrypto.auth.HmacKey.fromBytes(allocator, "hmac secret");
    defer key.deinit();

    const tag = zcrypto.auth.hmac.sha256("message", key.asBytes());
    const ok = zcrypto.auth.verifyHmacSha256("message", key.asBytes(), tag);

    std.debug.print("HMAC verified: {}\n", .{ok});
}
```

## Random Bytes

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const random = try zcrypto.rand.randomBytes(allocator, 32);
    defer allocator.free(random);

    std.debug.print("Generated {} random bytes\n", .{random.len});
}
```

## QUIC AEAD Helper

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    zcrypto.rand.fill(&key);
    zcrypto.rand.fill(&nonce);
    defer zcrypto.util.secureZero(&key);

    var packet = std.mem.zeroes([64]u8);
    const payload = packet[0..24];
    @memset(payload, 0x5a);

    var tag: [16]u8 = undefined;
    const aead = zcrypto.quic_crypto.QuicCrypto.AEAD.init(.aes_256_gcm, &key);
    _ = try aead.sealInPlace(&nonce, payload, "quic header", &tag);
    _ = try aead.openInPlace(&nonce, payload, "quic header", &tag);
}
```
