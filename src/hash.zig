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

/// SHA-384 hash result
pub const Sha384Hash = [48]u8;

/// HMAC-SHA256 result
pub const HmacSha256Hash = [32]u8;

/// HMAC-SHA512 result
pub const HmacSha512Hash = [64]u8;

/// HMAC-Blake3 result (using 32-byte output)
pub const HmacBlake3Hash = [32]u8;

/// Hash algorithms used by downstream protocol code.
pub const Algorithm = enum {
    sha256,
    sha384,
    sha512,
};

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

/// Compute SHA-384 hash of input data
pub fn sha384(data: []const u8) Sha384Hash {
    var result: Sha384Hash = undefined;
    std.crypto.hash.sha2.Sha384.hash(data, &result, .{});
    return result;
}

/// Compute Blake2b hash of input data
pub fn blake2b(data: []const u8) Blake2bHash {
    var result: Blake2bHash = undefined;
    std.crypto.hash.blake2.Blake2b512.hash(data, &result, .{});
    return result;
}

/// HMAC-SHA256 computation
pub fn hmacSha256(message: []const u8, key: []const u8) HmacSha256Hash {
    var result: HmacSha256Hash = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&result, message, key);
    return result;
}

/// HMAC-SHA512 computation
pub fn hmacSha512(message: []const u8, key: []const u8) HmacSha512Hash {
    var result: HmacSha512Hash = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&result, message, key);
    return result;
}

/// HMAC-Blake2s computation (32-byte output)
pub fn hmacBlake2s(message: []const u8, key: []const u8) HmacBlake3Hash {
    var result: HmacBlake3Hash = undefined;
    std.crypto.auth.hmac.Hmac(std.crypto.hash.blake2.Blake2s256).create(&result, message, key);
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

/// Streaming SHA-384 hasher
pub const Sha384 = struct {
    hasher: std.crypto.hash.sha2.Sha384,

    pub fn init() Sha384 {
        return .{ .hasher = std.crypto.hash.sha2.Sha384.init(.{}) };
    }

    pub fn update(self: *Sha384, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn final(self: *Sha384) Sha384Hash {
        return self.hasher.finalResult();
    }
};

/// Re-export Blake3 stream hasher from the dedicated module.
pub const Blake3 = @import("blake3.zig").Blake3;

/// Hex encoding utilities for hash outputs
pub fn toHex(comptime T: type, hash: T, buf: []u8) []u8 {
    _ = std.fmt.bytesToHex(hash, .lower);
    @memcpy(buf, &std.fmt.bytesToHex(hash, .lower));
    return buf;
}

fn decodeHex(comptime N: usize, hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "sha256 basic" {
    const input = "hello world";
    const expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    const result = sha256(input);
    var hex_buf: [64]u8 = undefined;
    const hex = toHex([32]u8, result, &hex_buf);

    try std.testing.expectEqualSlices(u8, expected_hex, hex);
}

test "hash known-answer vectors" {
    const sha256_empty = decodeHex(32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const sha256_abc = decodeHex(32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const sha384_abc = decodeHex(48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    const sha512_abc = decodeHex(64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    const blake2b_empty = decodeHex(64, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");

    try std.testing.expectEqualSlices(u8, &sha256_empty, &sha256(""));
    try std.testing.expectEqualSlices(u8, &sha256_abc, &sha256("abc"));
    try std.testing.expectEqualSlices(u8, &sha384_abc, &sha384("abc"));
    try std.testing.expectEqualSlices(u8, &sha512_abc, &sha512("abc"));
    try std.testing.expectEqualSlices(u8, &blake2b_empty, &blake2b(""));
}

test "sha512 basic" {
    const input = "hello world";
    const result = sha512(input);

    // Basic sanity check - should be 64 bytes
    try std.testing.expectEqual(@as(usize, 64), result.len);
}

test "sha384 basic" {
    const input = "hello world";
    const result = sha384(input);

    try std.testing.expectEqual(@as(usize, 48), result.len);
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

test "hmac sha256" {
    const key = "secret-key";
    const message = "Hello, HMAC!";

    const result = hmacSha256(message, key);

    // Test that we get a 32-byte result
    try std.testing.expectEqual(@as(usize, 32), result.len);

    // Test deterministic - same input should give same output
    const result2 = hmacSha256(message, key);
    try std.testing.expectEqualSlices(u8, &result, &result2);
}

test "hmac RFC 4231 test case 1" {
    const key = blk: {
        var bytes = std.mem.zeroes([20]u8);
        @memset(bytes[0..], 0x0b);
        break :blk bytes;
    };
    const message = "Hi There";
    const expected_sha256 = decodeHex(32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    const expected_sha512 = decodeHex(64, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

    try std.testing.expectEqualSlices(u8, &expected_sha256, &hmacSha256(message, &key));
    try std.testing.expectEqualSlices(u8, &expected_sha512, &hmacSha512(message, &key));
}

test "hmac sha512" {
    const key = "another-secret-key";
    const message = "Hello, HMAC-512!";

    const result = hmacSha512(message, key);

    try std.testing.expectEqual(@as(usize, 64), result.len);
}

test "hmac blake2s" {
    const key = "blake2s-secret";
    const message = "Blake2s HMAC test";

    const result = hmacBlake2s(message, key);

    try std.testing.expectEqual(@as(usize, 32), result.len);
}
