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
pub fn argon2id(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    key_length: usize,
) ![]u8 {
    const output = try allocator.alloc(u8, key_length);
    errdefer allocator.free(output);
    
    // Conservative parameters for security in 2025
    // Memory: 64MB, Time: 3 iterations, Parallelism: 4
    try std.crypto.pwhash.argon2.kdf(
        allocator,
        output,
        password,
        salt,
        .{ .t = 3, .m = 65536, .p = 4 },
        .argon2id,
    );
    
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
