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
    @memcpy(output[GCM_NONCE_SIZE..GCM_NONCE_SIZE + GCM_TAG_SIZE], &result.tag);
    @memcpy(output[GCM_NONCE_SIZE + GCM_TAG_SIZE..], result.data);
    
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
    const tag = ciphertext_with_nonce[GCM_NONCE_SIZE..GCM_NONCE_SIZE + GCM_TAG_SIZE];
    const ciphertext = ciphertext_with_nonce[GCM_NONCE_SIZE + GCM_TAG_SIZE..];
    
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
    @memcpy(output[CHACHA20_NONCE_SIZE..CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE], &result.tag);
    @memcpy(output[CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE..], result.data);
    
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
    const tag = ciphertext_with_nonce[CHACHA20_NONCE_SIZE..CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE];
    const ciphertext = ciphertext_with_nonce[CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE..];
    
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

test "simplified aes gcm api" {
    const allocator = std.testing.allocator;
    
    const key = [_]u8{0xAB} ** AES_256_KEY_SIZE;
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
    
    const key = [_]u8{0xCD} ** CHACHA20_KEY_SIZE;
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
        var key_256: [32]u8 = [_]u8{0} ** 32;
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
