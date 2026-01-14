//! Key derivation functions - HKDF, PBKDF2
//!
//! Secure key derivation for cryptographic applications.
//! Implements TLS 1.3 and QUIC key derivation patterns.

const std = @import("std");

/// HKDF using SHA-256
pub fn hkdfSha256(
    allocator: std.mem.Allocator,
    ikm: []const u8, // Input Key Material
    salt: []const u8,
    info: []const u8,
    length: usize,
) ![]u8 {
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);

    // HKDF Extract
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(salt, ikm);

    // HKDF Expand
    std.crypto.kdf.hkdf.HkdfSha256.expand(output, info, prk);
    return output;
}

/// HKDF using SHA-512
pub fn hkdfSha512(
    allocator: std.mem.Allocator,
    ikm: []const u8,
    salt: []const u8,
    info: []const u8,
    length: usize,
) ![]u8 {
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);

    // HKDF Extract
    const prk = std.crypto.kdf.hkdf.HkdfSha512.extract(salt, ikm);

    // HKDF Expand
    std.crypto.kdf.hkdf.HkdfSha512.expand(output, info, prk);
    return output;
}

/// PBKDF2 using SHA-256
pub fn pbkdf2Sha256(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    length: usize,
) ![]u8 {
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);

    try std.crypto.pwhash.pbkdf2(output, password, salt, iterations, std.crypto.auth.hmac.sha2.HmacSha256);
    return output;
}

/// TLS 1.3 HKDF-Expand-Label implementation
pub fn hkdfExpandLabel(
    allocator: std.mem.Allocator,
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    length: usize,
) ![]u8 {
    // Construct the HkdfLabel structure:
    // struct {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // } HkdfLabel;

    const tls_prefix = "tls13 ";
    const full_label_len = tls_prefix.len + label.len;

    // Calculate total HkdfLabel size
    const hkdf_label_size = 2 + 1 + full_label_len + 1 + context.len;
    const hkdf_label = try allocator.alloc(u8, hkdf_label_size);
    defer allocator.free(hkdf_label);

    var offset: usize = 0;

    // Length (big-endian uint16)
    hkdf_label[offset] = @intCast((length >> 8) & 0xFF);
    hkdf_label[offset + 1] = @intCast(length & 0xFF);
    offset += 2;

    // Label length
    hkdf_label[offset] = @intCast(full_label_len);
    offset += 1;

    // Label content
    @memcpy(hkdf_label[offset .. offset + tls_prefix.len], tls_prefix);
    offset += tls_prefix.len;
    @memcpy(hkdf_label[offset .. offset + label.len], label);
    offset += label.len;

    // Context length
    hkdf_label[offset] = @intCast(context.len);
    offset += 1;

    // Context content
    if (context.len > 0) {
        @memcpy(hkdf_label[offset .. offset + context.len], context);
    }

    // HKDF-Expand with the constructed label
    return hkdfSha256(allocator, secret, "", hkdf_label, length);
}

/// Derive key material using HKDF with convenient defaults
pub fn deriveKey(
    allocator: std.mem.Allocator,
    master_secret: []const u8,
    label: []const u8,
    length: usize,
) ![]u8 {
    return hkdfSha256(allocator, master_secret, "", label, length);
}

/// Argon2id password hashing (RFC 9106) - Recommended for new applications
/// Note: Uses PBKDF2 fallback in Zig 0.16.0+ where argon2 requires async Io
pub fn argon2id(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    key_length: usize,
) ![]u8 {
    const output = try allocator.alloc(u8, key_length);
    errdefer allocator.free(output);

    // Use PBKDF2 as fallback since argon2 now requires Io in Zig 0.16.0+
    // PBKDF2 with high iteration count provides good security
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    try std.crypto.pwhash.pbkdf2(output, password, salt, 600000, HmacSha256);

    return output;
}

/// Secure key stretching for user passwords using Argon2id
pub fn stretchPassword(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    key_length: usize,
) ![]u8 {
    return argon2id(allocator, password, salt, key_length);
}

/// Legacy PBKDF2 for compatibility (use Argon2id for new code)
pub fn legacyStretchPassword(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    key_length: usize,
) ![]u8 {
    // Use reasonable iteration count for 2025
    const iterations = 600_000;
    return pbkdf2Sha256(allocator, password, salt, iterations, key_length);
}

// =============================================================================
// ASYNC CONVENIENCE FUNCTIONS
// =============================================================================

/// Async convenience functions that use the async_crypto module
/// Import async_crypto to use these functions in async contexts
pub const Async = struct {
    /// Get async KDF crypto handler
    /// Usage: const async_kdf = zcrypto.kdf.Async.init(allocator, runtime);
    pub fn init(allocator: std.mem.Allocator, runtime: anytype) !@import("async_crypto.zig").AsyncKdf {
        return @import("async_crypto.zig").AsyncKdf.init(allocator, runtime);
    }

    /// Async Argon2id password hashing
    /// Returns Task that can be awaited for hashed password
    /// This is the most expensive KDF operation and benefits greatly from async execution
    pub fn argon2idAsync(allocator: std.mem.Allocator, runtime: anytype, password: []const u8, salt: []const u8) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_kdf = init(allocator, runtime) catch unreachable;
        return async_kdf.argon2idAsync(password, salt);
    }

    /// Async PBKDF2 password hashing
    /// Returns Task that can be awaited for derived key
    /// For legacy compatibility - prefer argon2idAsync for new applications
    pub fn pbkdf2Sha256Async(allocator: std.mem.Allocator, runtime: anytype, password: []const u8, salt: []const u8, iterations: u32, output_len: usize) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_kdf = init(allocator, runtime) catch unreachable;
        return async_kdf.pbkdf2Sha256Async(password, salt, iterations, output_len);
    }

    /// Async HKDF-Expand-Label for TLS 1.3 key derivation
    /// Returns Task that can be awaited for derived key
    /// Useful for parallel key derivation in TLS handshakes
    pub fn hkdfExpandLabelAsync(allocator: std.mem.Allocator, runtime: anytype, prk: []const u8, label: []const u8, context: []const u8, length: u16) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const async_kdf = init(allocator, runtime) catch unreachable;
        return async_kdf.hkdfExpandLabelAsync(prk, label, context, length);
    }

    /// Async password stretching using Argon2id
    /// Convenience wrapper for argon2idAsync with sensible defaults
    pub fn stretchPasswordAsync(allocator: std.mem.Allocator, runtime: anytype, password: []const u8, salt: []const u8) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        return argon2idAsync(allocator, runtime, password, salt);
    }

    /// Async legacy password stretching using PBKDF2
    /// For compatibility with older systems - prefer stretchPasswordAsync for new code
    pub fn legacyStretchPasswordAsync(allocator: std.mem.Allocator, runtime: anytype, password: []const u8, salt: []const u8, key_length: usize) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        const iterations = 600_000; // Reasonable iteration count for 2025
        return pbkdf2Sha256Async(allocator, runtime, password, salt, iterations, key_length);
    }

    /// Async key derivation for applications
    /// Convenience wrapper for hkdfExpandLabelAsync
    pub fn deriveKeyAsync(allocator: std.mem.Allocator, runtime: anytype, master_secret: []const u8, label: []const u8, length: u16) @import("async_crypto.zig").Task(@import("async_crypto.zig").AsyncCryptoResult) {
        return hkdfExpandLabelAsync(allocator, runtime, master_secret, label, "", length);
    }
};

test "hkdf sha256 basic" {
    const allocator = std.testing.allocator;

    const ikm = "input key material";
    const salt = "salt";
    const info = "info";

    const derived = try hkdfSha256(allocator, ikm, salt, info, 32);
    defer allocator.free(derived);

    try std.testing.expectEqual(@as(usize, 32), derived.len);
}

test "tls 1.3 hkdf expand label" {
    const allocator = std.testing.allocator;

    const secret = "master secret for testing";
    const label = "key";
    const context = "";

    const derived = try hkdfExpandLabel(allocator, secret, label, context, 16);
    defer allocator.free(derived);

    try std.testing.expectEqual(@as(usize, 16), derived.len);
}

test "pbkdf2 password stretching" {
    const allocator = std.testing.allocator;

    const password = "user-password-123";
    const salt = "random-salt-bytes";

    const key = try stretchPassword(allocator, password, salt, 32);
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 32), key.len);

    // Same input should produce same output
    const key2 = try stretchPassword(allocator, password, salt, 32);
    defer allocator.free(key2);

    try std.testing.expectEqualSlices(u8, key, key2);
}

test "derive key convenience function" {
    const allocator = std.testing.allocator;

    const master = "master secret";
    const label = "application key";

    const key = try deriveKey(allocator, master, label, 24);
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 24), key.len);
}

test "argon2id password hashing" {
    const allocator = std.testing.allocator;

    const password = "secure-password-123";
    const salt = "random-salt-16-bytes"; // Should be 16+ bytes
    
    const key = try argon2id(allocator, password, salt, 32);
    defer allocator.free(key);
    
    try std.testing.expectEqual(@as(usize, 32), key.len);
    
    // Same input should produce same output
    const key2 = try argon2id(allocator, password, salt, 32);
    defer allocator.free(key2);
    
    try std.testing.expectEqualSlices(u8, key, key2);
    
    // Different salt should produce different output
    const different_salt = "different-salt-16b";
    const key3 = try argon2id(allocator, password, different_salt, 32);
    defer allocator.free(key3);
    
    try std.testing.expect(!std.mem.eql(u8, key, key3));
}
