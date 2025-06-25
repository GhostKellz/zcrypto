//! Authentication - HMAC message authentication codes
//!
//! Provides secure message authentication using HMAC with various hash functions.
//! All functions are memory-safe and use constant-time implementations.

const std = @import("std");
const hash = @import("hash.zig");

/// HMAC-SHA256 computation with clean API
pub const hmac = struct {
    /// HMAC-SHA256: `zcrypto.auth.hmac.sha256(message, key) -> [32]u8`
    pub fn sha256(message: []const u8, key: []const u8) [32]u8 {
        return hash.hmacSha256(message, key);
    }

    /// HMAC-SHA512: `zcrypto.auth.hmac.sha512(message, key) -> [64]u8`
    pub fn sha512(message: []const u8, key: []const u8) [64]u8 {
        return hash.hmacSha512(message, key);
    }

    /// HMAC-Blake2s: `zcrypto.auth.hmac.blake2s(message, key) -> [32]u8`
    pub fn blake2s(message: []const u8, key: []const u8) [32]u8 {
        return hash.hmacBlake2s(message, key);
    }
};

/// Verify HMAC-SHA256 authentication tag in constant time
pub fn verifyHmacSha256(message: []const u8, key: []const u8, expected_tag: [32]u8) bool {
    const computed_tag = hmac.sha256(message, key);
    return std.crypto.utils.timingSafeEql([32]u8, computed_tag, expected_tag);
}

/// Verify HMAC-SHA512 authentication tag in constant time
pub fn verifyHmacSha512(message: []const u8, key: []const u8, expected_tag: [64]u8) bool {
    const computed_tag = hmac.sha512(message, key);
    return std.crypto.utils.timingSafeEql([64]u8, computed_tag, expected_tag);
}

/// Verify HMAC-Blake2s authentication tag in constant time
pub fn verifyHmacBlake2s(message: []const u8, key: []const u8, expected_tag: [32]u8) bool {
    const computed_tag = hmac.blake2s(message, key);
    return std.crypto.utils.timingSafeEql([32]u8, computed_tag, expected_tag);
}

/// Streaming HMAC-SHA256 for large messages
pub const HmacSha256 = struct {
    hasher: std.crypto.auth.hmac.sha2.HmacSha256,

    pub fn init(key: []const u8) HmacSha256 {
        return .{ .hasher = std.crypto.auth.hmac.sha2.HmacSha256.init(key) };
    }

    pub fn update(self: *HmacSha256, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn final(self: *HmacSha256) [32]u8 {
        var result: [32]u8 = undefined;
        self.hasher.final(&result);
        return result;
    }
};

/// Streaming HMAC-SHA512 for large messages
pub const HmacSha512 = struct {
    hasher: std.crypto.auth.hmac.sha2.HmacSha512,

    pub fn init(key: []const u8) HmacSha512 {
        return .{ .hasher = std.crypto.auth.hmac.sha2.HmacSha512.init(key) };
    }

    pub fn update(self: *HmacSha512, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn final(self: *HmacSha512) [64]u8 {
        var result: [64]u8 = undefined;
        self.hasher.final(&result);
        return result;
    }
};

test "hmac sha256 clean api" {
    const key = "secret-key-for-testing";
    const message = "Hello, authentication!";
    
    const tag = hmac.sha256(message, key);
    
    // Verify the tag
    const is_valid = verifyHmacSha256(message, key, tag);
    try std.testing.expect(is_valid);
    
    // Test with wrong key
    const wrong_key = "wrong-key-for-testing";
    const is_invalid = verifyHmacSha256(message, wrong_key, tag);
    try std.testing.expect(!is_invalid);
}

test "hmac sha512 clean api" {
    const key = "another-secret-key";
    const message = "SHA-512 HMAC test";
    
    const tag = hmac.sha512(message, key);
    const is_valid = verifyHmacSha512(message, key, tag);
    
    try std.testing.expect(is_valid);
}

test "hmac blake2s clean api" {
    const key = "blake2s-secret-key";
    const message = "Blake2s HMAC test";
    
    const tag = hmac.blake2s(message, key);
    const is_valid = verifyHmacBlake2s(message, key, tag);
    
    try std.testing.expect(is_valid);
}

test "streaming hmac sha256" {
    const key = "streaming-test-key";
    
    var hasher = HmacSha256.init(key);
    hasher.update("Hello, ");
    hasher.update("streaming ");
    hasher.update("HMAC!");
    const result = hasher.final();
    
    // Compare with one-shot HMAC
    const expected = hmac.sha256("Hello, streaming HMAC!", key);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "streaming hmac sha512" {
    const key = "sha512-streaming-key";
    
    var hasher = HmacSha512.init(key);
    hasher.update("Streaming ");
    hasher.update("SHA-512 ");
    hasher.update("HMAC test");
    const result = hasher.final();
    
    const expected = hmac.sha512("Streaming SHA-512 HMAC test", key);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}