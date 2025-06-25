//! Cryptographic utilities
//!
//! Helper functions for constant-time operations, padding, endian conversion,
//! and other cryptographic utilities.

const std = @import("std");

/// Constant-time comparison of two byte slices (matches documentation API)
pub fn constantTimeCompare(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.len == 0) return true;

    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }
    return result == 0;
}

/// Constant-time comparison of two byte slices (legacy name)
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    return constantTimeCompare(a, b);
}

/// Constant-time comparison of two fixed-size arrays
pub fn constantTimeEqualArray(comptime T: type, a: T, b: T) bool {
    const bytes_a = std.mem.asBytes(&a);
    const bytes_b = std.mem.asBytes(&b);
    return constantTimeEqual(bytes_a, bytes_b);
}

/// Securely zero out memory
pub fn secureZero(buf: []u8) void {
    std.crypto.utils.secureZero(u8, buf);
}

/// PKCS#7 padding
pub fn pkcs7Pad(allocator: std.mem.Allocator, data: []const u8, block_size: usize) ![]u8 {
    if (block_size == 0 or block_size > 255) return error.InvalidBlockSize;

    const padding_len = block_size - (data.len % block_size);
    const padded = try allocator.alloc(u8, data.len + padding_len);

    @memcpy(padded[0..data.len], data);
    @memset(padded[data.len..], @intCast(padding_len));

    return padded;
}

/// PKCS#7 unpadding
pub fn pkcs7Unpad(allocator: std.mem.Allocator, padded_data: []const u8) ![]u8 {
    if (padded_data.len == 0) return error.InvalidPadding;

    const padding_len = padded_data[padded_data.len - 1];
    if (padding_len == 0 or padding_len > padded_data.len) return error.InvalidPadding;

    // Verify padding bytes
    const start = padded_data.len - padding_len;
    for (padded_data[start..]) |byte| {
        if (byte != padding_len) return error.InvalidPadding;
    }

    const unpadded = try allocator.alloc(u8, start);
    @memcpy(unpadded, padded_data[0..start]);
    return unpadded;
}

/// Convert bytes to hexadecimal string
pub fn toHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        const hex_chars = "0123456789abcdef";
        hex[i * 2] = hex_chars[byte >> 4];
        hex[i * 2 + 1] = hex_chars[byte & 0xF];
    }
    return hex;
}

/// Convert hexadecimal string to bytes
pub fn fromHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;

    const bytes = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(bytes);

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        bytes[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch return error.InvalidHexChar;
    }

    return bytes;
}

/// Base64 encode
pub fn base64Encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, data);
    return encoded;
}

/// Base64 decode
pub fn base64Decode(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, encoded);
    return decoded;
}

/// Convert big-endian bytes to u16
pub fn readU16BigEndian(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

/// Convert u16 to big-endian bytes
pub fn writeU16BigEndian(bytes: []u8, value: u16) void {
    std.mem.writeInt(u16, bytes[0..2], value, .big);
}

/// Convert big-endian bytes to u32
pub fn readU32BE(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

/// Convert u32 to big-endian bytes
pub fn writeU32BE(value: u32, bytes: []u8) void {
    std.mem.writeInt(u32, bytes[0..4], value, .big);
}

/// Convert big-endian bytes to u64
pub fn readU64BE(bytes: []const u8) u64 {
    return std.mem.readInt(u64, bytes[0..8], .big);
}

/// Convert u64 to big-endian bytes
pub fn writeU64BE(value: u64, bytes: []u8) void {
    std.mem.writeInt(u64, bytes[0..8], value, .big);
}

/// Convert u64 to big-endian bytes (alias for consistency)
pub fn writeU64BigEndian(bytes: []u8, value: u64) void {
    std.mem.writeInt(u64, bytes[0..8], value, .big);
}

/// XOR two byte arrays (result in first array)
pub fn xorBytes(a: []u8, b: []const u8) void {
    const len = @min(a.len, b.len);
    for (0..len) |i| {
        a[i] ^= b[i];
    }
}

/// XOR two byte arrays into a new array
pub fn xorBytesAlloc(allocator: std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    const len = @min(a.len, b.len);
    const result = try allocator.alloc(u8, len);

    for (0..len) |i| {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

test "constant time equal" {
    const a = "hello";
    const b = "hello";
    const c = "world";

    try std.testing.expect(constantTimeEqual(a, b));
    try std.testing.expect(!constantTimeEqual(a, c));
    try std.testing.expect(!constantTimeEqual(a, "hell")); // Different lengths
}

test "constant time compare api" {
    const a = "hello";
    const b = "hello";
    const c = "world";

    try std.testing.expect(constantTimeCompare(a, b));
    try std.testing.expect(!constantTimeCompare(a, c));
    try std.testing.expect(!constantTimeCompare(a, "hell")); // Different lengths
}

test "pkcs7 padding" {
    const allocator = std.testing.allocator;

    const data = "hello";
    const padded = try pkcs7Pad(allocator, data, 8);
    defer allocator.free(padded);

    // Should be padded to 8 bytes with 3 bytes of padding (value 3)
    try std.testing.expectEqual(@as(usize, 8), padded.len);
    try std.testing.expectEqualSlices(u8, "hello\x03\x03\x03", padded);

    // Unpad
    const unpadded = try pkcs7Unpad(allocator, padded);
    defer allocator.free(unpadded);

    try std.testing.expectEqualSlices(u8, data, unpadded);
}

test "hex encoding" {
    const allocator = std.testing.allocator;

    const data = "hello";
    const hex = try toHex(allocator, data);
    defer allocator.free(hex);

    try std.testing.expectEqualSlices(u8, "68656c6c6f", hex);

    const decoded = try fromHex(allocator, hex);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, data, decoded);
}

test "base64 encoding" {
    const allocator = std.testing.allocator;

    const data = "hello world";
    const encoded = try base64Encode(allocator, data);
    defer allocator.free(encoded);

    const decoded = try base64Decode(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, data, decoded);
}

test "endian conversion" {
    var buf: [4]u8 = undefined;
    writeU32BE(0x12345678, &buf);

    const val = readU32BE(&buf);
    try std.testing.expectEqual(@as(u32, 0x12345678), val);
}

test "xor operations" {
    const allocator = std.testing.allocator;

    const a = [_]u8{ 0x12, 0x34, 0x56 };
    const b = [_]u8{ 0xFF, 0x00, 0xAA };

    const result = try xorBytesAlloc(allocator, &a, &b);
    defer allocator.free(result);

    const expected = [_]u8{ 0x12 ^ 0xFF, 0x34 ^ 0x00, 0x56 ^ 0xAA };
    try std.testing.expectEqualSlices(u8, &expected, result);
}
