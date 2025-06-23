//! Symmetric encryption - AES-GCM, ChaCha20-Poly1305
//!
//! Provides authenticated encryption with associated data (AEAD).
//! All operations are constant-time and memory-safe.

const std = @import("std");

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

test "aes-128-gcm round trip" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** AES_128_KEY_SIZE;
    const nonce = [_]u8{1} ** GCM_NONCE_SIZE;
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

test "chacha20-poly1305 round trip" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0x42} ** CHACHA20_KEY_SIZE;
    const nonce = [_]u8{0x69} ** CHACHA20_NONCE_SIZE;
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
