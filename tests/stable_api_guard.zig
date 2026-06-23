//! Compile-time and small runtime guards for the v1.0.x stable API surface.

const std = @import("std");
const zcrypto = @import("zcrypto");

test "stable root exports are present" {
    comptime {
        const stable_decls = .{
            "core",
            "CryptoError",
            "hash",
            "auth",
            "sym",
            "asym",
            "kdf",
            "rand",
            "util",
            "kex",
            "blake3",
            "merkle",
            "timing",
            "arena",
            "quic_crypto",
            "quic",
            "key_rotation",
            "version",
            "build_config",
        };

        for (stable_decls) |decl| {
            if (!@hasDecl(zcrypto, decl)) {
                @compileError("missing stable zcrypto root export: " ++ decl);
            }
        }
    }
}

test "stable function signatures are force referenced" {
    const sha256_fn: fn ([]const u8) [32]u8 = zcrypto.hash.sha256;
    const sha384_fn: fn ([]const u8) [48]u8 = zcrypto.hash.sha384;
    const rand_fill_fn: fn ([]u8) void = zcrypto.rand.fill;
    const zero_fn: fn ([]u8) void = zcrypto.util.secureZero;
    const ct_cmp_fn: fn ([]const u8, []const u8) bool = zcrypto.util.constantTimeCompare;
    const aes_encrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.encryptAesGcm;
    const aes_decrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.decryptAesGcm;
    const chacha_encrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.encryptChaCha20;
    const chacha_decrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.decryptChaCha20;

    _ = sha256_fn;
    _ = sha384_fn;
    _ = rand_fill_fn;
    _ = zero_fn;
    _ = ct_cmp_fn;
    _ = aes_encrypt_fn;
    _ = aes_decrypt_fn;
    _ = chacha_encrypt_fn;
    _ = chacha_decrypt_fn;

    comptime {
        if (!@hasDecl(zcrypto.blake3, "Blake3")) @compileError("missing zcrypto.blake3.Blake3");
        if (!@hasDecl(zcrypto.kdf, "hkdfSha256")) @compileError("missing zcrypto.kdf.hkdfSha256");
        if (!@hasDecl(zcrypto.kex, "X25519")) @compileError("missing zcrypto.kex.X25519");
        if (!@hasDecl(zcrypto.kex, "Ed25519")) @compileError("missing zcrypto.kex.Ed25519");
        if (!@hasDecl(zcrypto.asym, "ed25519")) @compileError("missing zcrypto.asym.ed25519");
        if (!@hasDecl(zcrypto.asym, "x25519")) @compileError("missing zcrypto.asym.x25519");
        if (!@hasDecl(zcrypto.sym, "Aes256GcmKey")) @compileError("missing zcrypto.sym.Aes256GcmKey");
        if (!@hasDecl(zcrypto.sym, "ChaCha20Poly1305Key")) @compileError("missing zcrypto.sym.ChaCha20Poly1305Key");
        if (!@hasDecl(zcrypto.auth, "HmacKey")) @compileError("missing zcrypto.auth.HmacKey");
        if (!@hasDecl(zcrypto.quic_crypto, "QuicCrypto")) @compileError("missing zcrypto.quic_crypto.QuicCrypto");
        if (!@hasDecl(zcrypto.quic, "QuicCrypto")) @compileError("missing zcrypto.quic.QuicCrypto");
    }
}

test "stable AEAD wrappers round trip and reject tampering" {
    const allocator = std.testing.allocator;
    const plaintext = "zcrypto stable AEAD guard";
    var key: [32]u8 = undefined;
    @memset(&key, 0x42);
    defer zcrypto.util.secureZero(&key);

    const aes_ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key);
    defer allocator.free(aes_ciphertext);

    const aes_plaintext = try zcrypto.sym.decryptAesGcm(allocator, aes_ciphertext, &key);
    defer allocator.free(aes_plaintext);
    try std.testing.expectEqualSlices(u8, plaintext, aes_plaintext);

    var tampered = try allocator.dupe(u8, aes_ciphertext);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(zcrypto.sym.SymError.DecryptionFailed, zcrypto.sym.decryptAesGcm(allocator, tampered, &key));

    const chacha_ciphertext = try zcrypto.sym.encryptChaCha20(allocator, plaintext, &key);
    defer allocator.free(chacha_ciphertext);

    const chacha_plaintext = try zcrypto.sym.decryptChaCha20(allocator, chacha_ciphertext, &key);
    defer allocator.free(chacha_plaintext);
    try std.testing.expectEqualSlices(u8, plaintext, chacha_plaintext);
}

test "stable key and kdf wrappers are callable" {
    const allocator = std.testing.allocator;

    const hkdf = try zcrypto.kdf.hkdfSha256(allocator, "ikm", "salt", "info", 32);
    defer allocator.free(hkdf);
    try std.testing.expectEqual(@as(usize, 32), hkdf.len);

    var random: [32]u8 = undefined;
    zcrypto.rand.fill(&random);

    var x25519_a = try zcrypto.kex.X25519.generateKeypair();
    defer x25519_a.zeroize();
    var x25519_b = try zcrypto.kex.X25519.generateKeypair();
    defer x25519_b.zeroize();

    const shared_a = try zcrypto.kex.X25519.computeSharedSecret(x25519_a.private_key, x25519_b.public_key);
    const shared_b = try zcrypto.kex.X25519.computeSharedSecret(x25519_b.private_key, x25519_a.public_key);
    try std.testing.expectEqualSlices(u8, &shared_a, &shared_b);

    var ed = try zcrypto.kex.Ed25519.generateKeypair();
    defer ed.zeroize();
    const sig = try zcrypto.kex.Ed25519.sign(ed.private_key, "message");
    try std.testing.expect(try zcrypto.kex.Ed25519.verify(ed.public_key, "message", sig));

    var aes_key = zcrypto.sym.Aes256GcmKey.random();
    defer aes_key.zeroize();
    const aes_copy = aes_key.bytesCopy();
    try std.testing.expectEqualSlices(u8, aes_key.asBytes(), &aes_copy);

    var chacha_key = zcrypto.sym.ChaCha20Poly1305Key.random();
    defer chacha_key.zeroize();
    const chacha_copy = chacha_key.bytesCopy();
    try std.testing.expectEqualSlices(u8, chacha_key.asBytes(), &chacha_copy);

    var hmac_key = try zcrypto.auth.HmacKey.fromBytes(allocator, "guard-hmac-key");
    defer hmac_key.deinit();
    const tag = zcrypto.auth.hmac.sha256("guard", hmac_key.asBytes());
    try std.testing.expect(zcrypto.auth.verifyHmacSha256("guard", hmac_key.asBytes(), tag));
}
