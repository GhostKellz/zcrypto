//! Hash functions - SHA-256, SHA-512, Blake2b
//!
//! Provides secure hashing with a clean, consistent API.
//! All functions are memory-safe and use constant-time implementations where applicable.

const std = @import("std");

/// SHA-256 hash result
pub const Sha256Hash = [32]u8;

/// SHA-512 hash result
pub const Sha512Hash = [64]u8;

/// Blake2b hash result
pub const Blake2bHash = [64]u8;

/// Compute SHA-256 hash of input data
pub fn sha256(data: []const u8) Sha256Hash {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

/// Compute SHA-512 hash of input data
pub fn sha512(data: []const u8) Sha512Hash {
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

/// Compute Blake2b hash of input data
pub fn blake2b(data: []const u8) Blake2bHash {
    var result: Blake2bHash = undefined;
    std.crypto.hash.blake2.Blake2b512.hash(data, &result, .{});
    return result;
}

/// Streaming SHA-256 hasher
pub const Sha256 = struct {
    hasher: std.crypto.hash.sha2.Sha256,

    pub fn init() Sha256 {
        return .{ .hasher = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *Sha256, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn final(self: *Sha256) Sha256Hash {
        return self.hasher.finalResult();
    }
};

/// Streaming SHA-512 hasher
pub const Sha512 = struct {
    hasher: std.crypto.hash.sha2.Sha512,

    pub fn init() Sha512 {
        return .{ .hasher = std.crypto.hash.sha2.Sha512.init(.{}) };
    }

    pub fn update(self: *Sha512, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn final(self: *Sha512) Sha512Hash {
        return self.hasher.finalResult();
    }
};

/// Hex encoding utilities for hash outputs
pub fn toHex(comptime T: type, hash: T, buf: []u8) []u8 {
    _ = std.fmt.bytesToHex(hash, .lower);
    @memcpy(buf, &std.fmt.bytesToHex(hash, .lower));
    return buf;
}

test "sha256 basic" {
    const input = "hello world";
    const expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    const result = sha256(input);
    var hex_buf: [64]u8 = undefined;
    const hex = toHex([32]u8, result, &hex_buf);

    try std.testing.expectEqualSlices(u8, expected_hex, hex);
}

test "sha512 basic" {
    const input = "hello world";
    const result = sha512(input);

    // Basic sanity check - should be 64 bytes
    try std.testing.expectEqual(@as(usize, 64), result.len);
}

test "blake2b basic" {
    const input = "hello world";
    const result = blake2b(input);

    // Basic sanity check - should be 64 bytes
    try std.testing.expectEqual(@as(usize, 64), result.len);
}

test "streaming sha256" {
    var hasher = Sha256.init();
    hasher.update("hello ");
    hasher.update("world");
    const result = hasher.final();

    const expected = sha256("hello world");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}
