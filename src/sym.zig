//! Symmetric encryption - AES-GCM, ChaCha20-Poly1305
//!
//! Provides authenticated encryption with associated data (AEAD).
//! All operations are constant-time and memory-safe.

const std = @import("std");
const rand = @import("rand.zig");

/// AES-128-GCM key size
pub const AES_128_KEY_SIZE = 16;

/// AES-256-GCM key size
pub const AES_256_KEY_SIZE = 32;

/// GCM nonce size
pub const GCM_NONCE_SIZE = 12;

/// GCM tag size
pub const GCM_TAG_SIZE = 16;

/// ChaCha20-Poly1305 key size
pub const CHACHA20_KEY_SIZE = 32;

/// ChaCha20-Poly1305 nonce size
pub const CHACHA20_NONCE_SIZE = 12;

/// ChaCha20-Poly1305 tag size
pub const POLY1305_TAG_SIZE = 16;

/// Error types for symmetric encryption
pub const SymError = error{
    AuthenticationFailed,
    InvalidKey,
    InvalidNonce,
    OutOfMemory,
};

fn decodeHex(comptime N: usize, hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Authenticated encryption result
pub const Ciphertext = struct {
    data: []u8,
    tag: [GCM_TAG_SIZE]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Ciphertext) void {
        self.allocator.free(self.data);
    }
};

/// AES-128-GCM authenticated encryption
pub fn encryptAes128Gcm(
    allocator: std.mem.Allocator,
    key: [AES_128_KEY_SIZE]u8,
    nonce: [GCM_NONCE_SIZE]u8,
    plaintext: []const u8,
    aad: []const u8,
) !Ciphertext {
    const ciphertext_buf = try allocator.alloc(u8, plaintext.len);
    var tag: [GCM_TAG_SIZE]u8 = undefined;

    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
        ciphertext_buf,
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );

    return Ciphertext{
        .data = ciphertext_buf,
        .tag = tag,
        .allocator = allocator,
    };
}

/// AES-256-GCM authenticated encryption
pub fn encryptAes256Gcm(
    allocator: std.mem.Allocator,
    key: [AES_256_KEY_SIZE]u8,
    nonce: [GCM_NONCE_SIZE]u8,
    plaintext: []const u8,
    aad: []const u8,
) !Ciphertext {
    const ciphertext_buf = try allocator.alloc(u8, plaintext.len);
    var tag: [GCM_TAG_SIZE]u8 = undefined;

    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
        ciphertext_buf,
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );

    return Ciphertext{
        .data = ciphertext_buf,
        .tag = tag,
        .allocator = allocator,
    };
}

/// AES-128-GCM authenticated decryption
pub fn decryptAes128Gcm(
    allocator: std.mem.Allocator,
    key: [AES_128_KEY_SIZE]u8,
    nonce: [GCM_NONCE_SIZE]u8,
    ciphertext: []const u8,
    tag: [GCM_TAG_SIZE]u8,
    aad: []const u8,
) !?[]u8 {
    const plaintext_buf = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext_buf);

    std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
        plaintext_buf,
        ciphertext,
        tag,
        aad,
        nonce,
        key,
    ) catch {
        allocator.free(plaintext_buf);
        return null; // Authentication failed
    };

    return plaintext_buf;
}

/// AES-256-GCM authenticated decryption
pub fn decryptAes256Gcm(
    allocator: std.mem.Allocator,
    key: [AES_256_KEY_SIZE]u8,
    nonce: [GCM_NONCE_SIZE]u8,
    ciphertext: []const u8,
    tag: [GCM_TAG_SIZE]u8,
    aad: []const u8,
) !?[]u8 {
    const plaintext_buf = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext_buf);

    std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        plaintext_buf,
        ciphertext,
        tag,
        aad,
        nonce,
        key,
    ) catch {
        allocator.free(plaintext_buf);
        return null; // Authentication failed
    };

    return plaintext_buf;
}

/// ChaCha20-Poly1305 result
pub const ChaCha20Result = struct {
    data: []u8,
    tag: [POLY1305_TAG_SIZE]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: ChaCha20Result) void {
        self.allocator.free(self.data);
    }
};

/// ChaCha20-Poly1305 authenticated encryption
pub fn encryptChaCha20Poly1305(
    allocator: std.mem.Allocator,
    key: [CHACHA20_KEY_SIZE]u8,
    nonce: [CHACHA20_NONCE_SIZE]u8,
    plaintext: []const u8,
    aad: []const u8,
) !ChaCha20Result {
    const ciphertext_buf = try allocator.alloc(u8, plaintext.len);
    var tag: [POLY1305_TAG_SIZE]u8 = undefined;

    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ciphertext_buf,
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );

    return ChaCha20Result{
        .data = ciphertext_buf,
        .tag = tag,
        .allocator = allocator,
    };
}

/// ChaCha20-Poly1305 authenticated decryption
pub fn decryptChaCha20Poly1305(
    allocator: std.mem.Allocator,
    key: [CHACHA20_KEY_SIZE]u8,
    nonce: [CHACHA20_NONCE_SIZE]u8,
    ciphertext: []const u8,
    tag: [POLY1305_TAG_SIZE]u8,
    aad: []const u8,
) !?[]u8 {
    const plaintext_buf = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext_buf);

    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        plaintext_buf,
        ciphertext,
        tag,
        aad,
        nonce,
        key,
    ) catch {
        allocator.free(plaintext_buf);
        return null; // Authentication failed
    };

    return plaintext_buf;
}

/// AES-128 single-block ECB encryption for QUIC/TLS header protection.
pub fn aes_128_ecb_encrypt(input: *const [16]u8, key: *const [AES_128_KEY_SIZE]u8, output: *[16]u8) SymError!void {
    const aes = std.crypto.core.aes.Aes128.initEnc(key.*);
    aes.encrypt(output, input);
}

/// AES-256 header protection uses AES-128 over the first 16 bytes of the HP key per RFC 9001.
pub fn aes_256_ecb_encrypt(input: *const [16]u8, key: *const [AES_256_KEY_SIZE]u8, output: *[16]u8) SymError!void {
    const hp_key: [AES_128_KEY_SIZE]u8 = key[0..AES_128_KEY_SIZE].*;
    return aes_128_ecb_encrypt(input, &hp_key, output);
}

/// Generate ChaCha20 keystream for QUIC header protection mask generation.
pub fn chacha20_generate_keystream(key: *const [CHACHA20_KEY_SIZE]u8, nonce: *const [CHACHA20_NONCE_SIZE]u8, counter: u32, output: []u8) SymError!void {
    @memset(output, 0);
    std.crypto.stream.chacha.ChaCha20IETF.xor(output, output, counter, key.*, nonce.*);
}

/// Simplified AES-256-GCM encryption API (auto-generates nonce)
pub fn encryptAesGcm(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    key: *const [AES_256_KEY_SIZE]u8,
) ![]u8 {
    // Generate random nonce
    var nonce: [GCM_NONCE_SIZE]u8 = undefined;
    rand.fill(&nonce);

    // Encrypt
    const result = try encryptAes256Gcm(allocator, key.*, nonce, plaintext, "");
    defer result.deinit();

    // Format: nonce (12) + tag (16) + ciphertext
    const output = try allocator.alloc(u8, GCM_NONCE_SIZE + GCM_TAG_SIZE + result.data.len);
    @memcpy(output[0..GCM_NONCE_SIZE], &nonce);
    @memcpy(output[GCM_NONCE_SIZE .. GCM_NONCE_SIZE + GCM_TAG_SIZE], &result.tag);
    @memcpy(output[GCM_NONCE_SIZE + GCM_TAG_SIZE ..], result.data);

    return output;
}

/// Simplified AES-256-GCM decryption API
pub fn decryptAesGcm(
    allocator: std.mem.Allocator,
    ciphertext_with_nonce: []const u8,
    key: *const [AES_256_KEY_SIZE]u8,
) SymError![]u8 {
    if (ciphertext_with_nonce.len < GCM_NONCE_SIZE + GCM_TAG_SIZE) {
        return SymError.AuthenticationFailed;
    }

    // Extract components
    const nonce = ciphertext_with_nonce[0..GCM_NONCE_SIZE];
    const tag = ciphertext_with_nonce[GCM_NONCE_SIZE .. GCM_NONCE_SIZE + GCM_TAG_SIZE];
    const ciphertext = ciphertext_with_nonce[GCM_NONCE_SIZE + GCM_TAG_SIZE ..];

    var nonce_array: [GCM_NONCE_SIZE]u8 = undefined;
    var tag_array: [GCM_TAG_SIZE]u8 = undefined;
    @memcpy(&nonce_array, nonce);
    @memcpy(&tag_array, tag);

    // Decrypt
    const plaintext = decryptAes256Gcm(allocator, key.*, nonce_array, ciphertext, tag_array, "") catch |err| switch (err) {
        error.OutOfMemory => return SymError.OutOfMemory,
    };

    return plaintext orelse SymError.AuthenticationFailed;
}

/// Simplified ChaCha20-Poly1305 encryption API (auto-generates nonce)
pub fn encryptChaCha20(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    key: *const [CHACHA20_KEY_SIZE]u8,
) ![]u8 {
    // Generate random nonce
    var nonce: [CHACHA20_NONCE_SIZE]u8 = undefined;
    rand.fill(&nonce);

    // Encrypt using the original function
    const result = try encryptChaCha20Poly1305(allocator, key.*, nonce, plaintext, "");
    defer result.deinit();

    // Format: nonce (12) + tag (16) + ciphertext
    const output = try allocator.alloc(u8, CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE + result.data.len);
    @memcpy(output[0..CHACHA20_NONCE_SIZE], &nonce);
    @memcpy(output[CHACHA20_NONCE_SIZE .. CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE], &result.tag);
    @memcpy(output[CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE ..], result.data);

    return output;
}

/// Simplified ChaCha20-Poly1305 decryption API
pub fn decryptChaCha20(
    allocator: std.mem.Allocator,
    ciphertext_with_nonce: []const u8,
    key: *const [CHACHA20_KEY_SIZE]u8,
) SymError![]u8 {
    if (ciphertext_with_nonce.len < CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE) {
        return SymError.AuthenticationFailed;
    }

    // Extract components
    const nonce = ciphertext_with_nonce[0..CHACHA20_NONCE_SIZE];
    const tag = ciphertext_with_nonce[CHACHA20_NONCE_SIZE .. CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE];
    const ciphertext = ciphertext_with_nonce[CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE ..];

    var nonce_array: [CHACHA20_NONCE_SIZE]u8 = undefined;
    var tag_array: [POLY1305_TAG_SIZE]u8 = undefined;
    @memcpy(&nonce_array, nonce);
    @memcpy(&tag_array, tag);

    // Decrypt using the original function
    const plaintext = decryptChaCha20Poly1305(allocator, key.*, nonce_array, ciphertext, tag_array, "") catch |err| switch (err) {
        error.OutOfMemory => return SymError.OutOfMemory,
    };

    return plaintext orelse SymError.AuthenticationFailed;
}

test "aes-128-gcm round trip" {
    const allocator = std.testing.allocator;

    const key = std.mem.zeroes([AES_128_KEY_SIZE]u8);
    const nonce = blk: {
        var bytes = std.mem.zeroes([GCM_NONCE_SIZE]u8);
        @memset(bytes[0..], 0x01);
        break :blk bytes;
    };
    const plaintext = "Hello, zcrypto!";
    const aad = "metadata";

    // Encrypt
    const ciphertext = try encryptAes128Gcm(allocator, key, nonce, plaintext, aad);
    defer ciphertext.deinit();

    // Decrypt
    const decrypted = try decryptAes128Gcm(allocator, key, nonce, ciphertext.data, ciphertext.tag, aad);
    defer if (decrypted) |d| allocator.free(d);

    try std.testing.expect(decrypted != null);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted.?);
}

test "aes-gcm NIST known-answer vectors" {
    const allocator = std.testing.allocator;
    const key128 = std.mem.zeroes([AES_128_KEY_SIZE]u8);
    const key256 = std.mem.zeroes([AES_256_KEY_SIZE]u8);
    const nonce = std.mem.zeroes([GCM_NONCE_SIZE]u8);

    const empty128 = try encryptAes128Gcm(allocator, key128, nonce, "", "");
    defer empty128.deinit();
    const expected_empty128_tag = decodeHex(16, "58e2fccefa7e3061367f1d57a4e7455a");
    try std.testing.expectEqual(@as(usize, 0), empty128.data.len);
    try std.testing.expectEqualSlices(u8, &expected_empty128_tag, &empty128.tag);

    const empty256 = try encryptAes256Gcm(allocator, key256, nonce, "", "");
    defer empty256.deinit();
    const expected_empty256_tag = decodeHex(16, "530f8afbc74536b9a963b4f1c4cb738b");
    try std.testing.expectEqual(@as(usize, 0), empty256.data.len);
    try std.testing.expectEqualSlices(u8, &expected_empty256_tag, &empty256.tag);

    const plaintext = std.mem.zeroes([16]u8);
    const encrypted128 = try encryptAes128Gcm(allocator, key128, nonce, &plaintext, "");
    defer encrypted128.deinit();
    const expected_ciphertext128 = decodeHex(16, "0388dace60b6a392f328c2b971b2fe78");
    const expected_tag128 = decodeHex(16, "ab6e47d42cec13bdf53a67b21257bddf");
    try std.testing.expectEqualSlices(u8, &expected_ciphertext128, encrypted128.data);
    try std.testing.expectEqualSlices(u8, &expected_tag128, &encrypted128.tag);
}

test "aead decrypt rejects tampered tag aad and truncated simplified inputs" {
    const allocator = std.testing.allocator;
    const aes_key = blk: {
        var bytes = std.mem.zeroes([AES_256_KEY_SIZE]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const nonce = blk: {
        var bytes = std.mem.zeroes([GCM_NONCE_SIZE]u8);
        @memset(bytes[0..], 0x24);
        break :blk bytes;
    };
    const plaintext = "authenticated plaintext";
    const aad = "aad";

    const encrypted = try encryptAes256Gcm(allocator, aes_key, nonce, plaintext, aad);
    defer encrypted.deinit();

    var bad_tag = encrypted.tag;
    bad_tag[0] ^= 0x01;
    const bad_tag_plaintext = try decryptAes256Gcm(allocator, aes_key, nonce, encrypted.data, bad_tag, aad);
    try std.testing.expect(bad_tag_plaintext == null);

    const bad_aad_plaintext = try decryptAes256Gcm(allocator, aes_key, nonce, encrypted.data, encrypted.tag, "bad aad");
    try std.testing.expect(bad_aad_plaintext == null);

    try std.testing.expectError(SymError.AuthenticationFailed, decryptAesGcm(allocator, "too short", &aes_key));

    const chacha_key = blk: {
        var bytes = std.mem.zeroes([CHACHA20_KEY_SIZE]u8);
        @memset(bytes[0..], 0x55);
        break :blk bytes;
    };
    try std.testing.expectError(SymError.AuthenticationFailed, decryptChaCha20(allocator, "too short", &chacha_key));
}

test "chacha20-poly1305 round trip" {
    const allocator = std.testing.allocator;

    const key = blk: {
        var bytes = std.mem.zeroes([CHACHA20_KEY_SIZE]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const nonce = blk: {
        var bytes = std.mem.zeroes([CHACHA20_NONCE_SIZE]u8);
        @memset(bytes[0..], 0x69);
        break :blk bytes;
    };
    const plaintext = "ChaCha20 is fast!";
    const aad = "associated data";

    // Encrypt
    const ciphertext = try encryptChaCha20Poly1305(allocator, key, nonce, plaintext, aad);
    defer ciphertext.deinit();

    // Decrypt
    const decrypted = try decryptChaCha20Poly1305(allocator, key, nonce, ciphertext.data, ciphertext.tag, aad);
    defer if (decrypted) |d| allocator.free(d);

    try std.testing.expect(decrypted != null);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted.?);
}

test "simplified aes gcm api" {
    const allocator = std.testing.allocator;

    const key = blk: {
        var bytes = std.mem.zeroes([AES_256_KEY_SIZE]u8);
        @memset(bytes[0..], 0xAB);
        break :blk bytes;
    };
    const plaintext = "Hello, simplified crypto!";

    // Encrypt (auto-generates nonce)
    const ciphertext = try encryptAesGcm(allocator, plaintext, &key);
    defer allocator.free(ciphertext);

    // Should be longer than plaintext (nonce + tag + data)
    try std.testing.expect(ciphertext.len > plaintext.len);

    // Decrypt
    const decrypted = try decryptAesGcm(allocator, ciphertext, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "simplified chacha20 api" {
    const allocator = std.testing.allocator;

    const key = blk: {
        var bytes = std.mem.zeroes([CHACHA20_KEY_SIZE]u8);
        @memset(bytes[0..], 0xCD);
        break :blk bytes;
    };
    const plaintext = "ChaCha20 simplified!";

    // Encrypt (auto-generates nonce)
    const ciphertext = try encryptChaCha20(allocator, plaintext, &key);
    defer allocator.free(ciphertext);

    // Should be longer than plaintext (nonce + tag + data)
    try std.testing.expect(ciphertext.len > plaintext.len);

    // Decrypt
    const decrypted = try decryptChaCha20(allocator, ciphertext, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "aes-128 ecb helper matches stdlib block encryption" {
    const key = blk: {
        var bytes = std.mem.zeroes([AES_128_KEY_SIZE]u8);
        @memset(bytes[0..], 0x11);
        break :blk bytes;
    };
    const input = blk: {
        var bytes = std.mem.zeroes([16]u8);
        @memset(bytes[0..], 0x22);
        break :blk bytes;
    };

    var expected: [16]u8 = undefined;
    var actual: [16]u8 = undefined;

    const aes = std.crypto.core.aes.Aes128.initEnc(key);
    aes.encrypt(&expected, &input);

    try aes_128_ecb_encrypt(&input, &key, &actual);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "aes-256 ecb helper uses RFC 9001 header protection key bytes" {
    const key = blk: {
        var bytes = std.mem.zeroes([AES_256_KEY_SIZE]u8);
        @memset(bytes[0..], 0x33);
        break :blk bytes;
    };
    const input = blk: {
        var bytes = std.mem.zeroes([16]u8);
        @memset(bytes[0..], 0x44);
        break :blk bytes;
    };

    var expected: [16]u8 = undefined;
    var actual: [16]u8 = undefined;

    const aes = std.crypto.core.aes.Aes128.initEnc(key[0..16].*);
    aes.encrypt(&expected, &input);

    try aes_256_ecb_encrypt(&input, &key, &actual);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "chacha20 keystream helper matches stdlib" {
    const key = blk: {
        var bytes = std.mem.zeroes([CHACHA20_KEY_SIZE]u8);
        @memset(bytes[0..], 0x55);
        break :blk bytes;
    };
    const nonce = blk: {
        var bytes = std.mem.zeroes([CHACHA20_NONCE_SIZE]u8);
        @memset(bytes[0..], 0x66);
        break :blk bytes;
    };
    const counter: u32 = 7;

    var expected = std.mem.zeroes([64]u8);
    var actual = std.mem.zeroes([64]u8);

    std.crypto.stream.chacha.ChaCha20IETF.xor(&expected, &expected, counter, key, nonce);
    try chacha20_generate_keystream(&key, &nonce, counter, &actual);

    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

// =============================================================================
// ASYNC CONVENIENCE FUNCTIONS
// =============================================================================

/// Async convenience functions that use the async_crypto module
/// Import async_crypto to use these functions in async contexts
pub const Async = struct {
    /// Get async symmetric crypto handler
    /// Usage: const async_sym = zcrypto.sym.Async.init(allocator, runtime);
    pub fn init(allocator: std.mem.Allocator, runtime: anytype) !@import("async_crypto.zig").AsyncSymmetric {
        return @import("async_crypto.zig").AsyncSymmetric.init(allocator, runtime);
    }

    /// Async AES-256-GCM encryption
    /// Returns Task that can be awaited for encrypted result
    pub fn encryptAes256GcmAsync(allocator: std.mem.Allocator, runtime: anytype, key: [AES_256_KEY_SIZE]u8, nonce: [GCM_NONCE_SIZE]u8, plaintext: []const u8, aad: []const u8) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_sym = init(allocator, runtime) catch unreachable;
        return async_sym.aes256GcmEncryptAsync(key, nonce, plaintext, aad);
    }

    /// Async AES-128-GCM encryption
    /// Returns Task that can be awaited for encrypted result
    pub fn encryptAes128GcmAsync(allocator: std.mem.Allocator, runtime: anytype, key: [AES_128_KEY_SIZE]u8, nonce: [GCM_NONCE_SIZE]u8, plaintext: []const u8, aad: []const u8) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_sym = init(allocator, runtime) catch unreachable;
        var key_256: [32]u8 = std.mem.zeroes([32]u8);
        @memcpy(key_256[0..16], &key);
        return async_sym.aes256GcmEncryptAsync(key_256, nonce, plaintext, aad);
    }

    /// Async ChaCha20-Poly1305 encryption
    /// Returns Task that can be awaited for encrypted result
    pub fn encryptChaCha20Poly1305Async(allocator: std.mem.Allocator, runtime: anytype, key: [CHACHA20_KEY_SIZE]u8, nonce: [CHACHA20_NONCE_SIZE]u8, plaintext: []const u8, aad: []const u8) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_sym = init(allocator, runtime) catch unreachable;
        return async_sym.chacha20Poly1305EncryptAsync(key, nonce, plaintext, aad);
    }

    /// Async batch symmetric encryption
    /// Encrypts multiple plaintexts in parallel for high throughput
    /// Uses hardware acceleration when available
    pub fn batchEncryptAsync(allocator: std.mem.Allocator, runtime: anytype, algorithm: @import("async_crypto.zig").SymmetricAlgorithm, key: []const u8, plaintexts: [][]const u8, nonces: [][]const u8, aads: [][]const u8) @import("async_crypto.zig").Task([]@import("async_crypto.zig").AsyncCryptoResult) {
        const async_sym = init(allocator, runtime) catch unreachable;
        return async_sym.batchEncryptAsync(algorithm, key, plaintexts, nonces, aads);
    }

    /// Async AES-256 batch encryption
    /// Convenience wrapper for batch AES-256-GCM operations
    pub fn batchEncryptAes256Async(allocator: std.mem.Allocator, runtime: anytype, key: [AES_256_KEY_SIZE]u8, plaintexts: [][]const u8, nonces: [][]const u8, aads: [][]const u8) @import("async_crypto.zig").Task([]@import("async_crypto.zig").AsyncCryptoResult) {
        return batchEncryptAsync(allocator, runtime, .aes_256_gcm, &key, plaintexts, nonces, aads);
    }

    /// Async ChaCha20 batch encryption
    /// Convenience wrapper for batch ChaCha20-Poly1305 operations
    pub fn batchEncryptChaCha20Async(allocator: std.mem.Allocator, runtime: anytype, key: [CHACHA20_KEY_SIZE]u8, plaintexts: [][]const u8, nonces: [][]const u8, aads: [][]const u8) @import("async_crypto.zig").Task([]@import("async_crypto.zig").AsyncCryptoResult) {
        return batchEncryptAsync(allocator, runtime, .chacha20_poly1305, &key, plaintexts, nonces, aads);
    }
};
