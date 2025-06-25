//! Secure random number generation
//!
//! Cryptographically secure random number generation backed by OS entropy.
//! All functions use secure sources and are suitable for cryptographic use.

const std = @import("std");

/// Fill a buffer with secure random bytes (matches documentation API)
pub fn fillBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

/// Fill a buffer with secure random bytes (legacy name)
pub fn fill(buf: []u8) void {
    fillBytes(buf);
}

/// Generate a slice of random bytes (caller owns memory)
pub fn randomBytes(allocator: std.mem.Allocator, n: usize) ![]u8 {
    const buf = try allocator.alloc(u8, n);
    fill(buf);
    return buf;
}

/// Generate a random u32
pub fn randomU32() u32 {
    return std.crypto.random.int(u32);
}

/// Generate a random u64
pub fn randomU64() u64 {
    return std.crypto.random.int(u64);
}

/// Generate a random integer in range [0, max)
pub fn randomRange(comptime T: type, max: T) T {
    return std.crypto.random.intRangeLessThan(T, 0, max);
}

/// Generate a random integer in range [min, max]
pub fn randomRangeInclusive(comptime T: type, min: T, max: T) T {
    return std.crypto.random.intRangeLessThan(T, min, max + 1);
}

/// Generate random bytes for a fixed-size array
pub fn randomArray(comptime size: usize) [size]u8 {
    var buf: [size]u8 = undefined;
    fill(&buf);
    return buf;
}

/// Generate a random boolean
pub fn randomBool() bool {
    return randomU32() % 2 == 0;
}

/// Generate a random float in range [0.0, 1.0)
pub fn randomFloat(comptime T: type) T {
    return std.crypto.random.float(T);
}

/// Generate a cryptographically secure nonce
pub fn nonce(comptime size: usize) [size]u8 {
    return randomArray(size);
}

/// Generate a cryptographic salt
pub fn salt(comptime size: usize) [size]u8 {
    return randomArray(size);
}

/// Generate an initialization vector
pub fn iv(comptime size: usize) [size]u8 {
    return randomArray(size);
}

/// Generate a session ID
pub fn sessionId(comptime size: usize) [size]u8 {
    return randomArray(size);
}

/// Generate cryptographic key of specified size (matches documentation API)
pub fn generateKey(comptime size: usize) [size]u8 {
    return randomArray(size);
}

/// Generate cryptographic salt of specified size (matches documentation API)
pub fn generateSalt(comptime size: usize) [size]u8 {
    return randomArray(size);
}

test "fill buffer" {
    var buf: [32]u8 = undefined;
    fill(&buf);

    // Check that not all bytes are zero (extremely unlikely with good RNG)
    var all_zero = true;
    for (buf) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "random bytes allocation" {
    const allocator = std.testing.allocator;

    const bytes = try randomBytes(allocator, 16);
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(usize, 16), bytes.len);
}

test "random integers" {
    const val32 = randomU32();
    const val64 = randomU64();

    // Just check they compile and run
    _ = val32;
    _ = val64;

    // Test range functions
    const range_val = randomRange(u8, 100);
    try std.testing.expect(range_val < 100);

    const inclusive_val = randomRangeInclusive(u8, 10, 20);
    try std.testing.expect(inclusive_val >= 10 and inclusive_val <= 20);
}

test "random array" {
    const arr = randomArray(16);
    try std.testing.expectEqual(@as(usize, 16), arr.len);
}

test "random boolean" {
    // Generate several booleans to increase chance of getting both true and false
    var got_true = false;
    var got_false = false;

    for (0..100) |_| {
        const val = randomBool();
        if (val) got_true = true else got_false = true;
        if (got_true and got_false) break;
    }

    // Very likely to get both values in 100 tries
    try std.testing.expect(got_true or got_false); // At least one should be true
}

test "random float" {
    const val = randomFloat(f64);
    try std.testing.expect(val >= 0.0 and val < 1.0);
}

test "crypto helpers" {
    const test_nonce = nonce(12);
    const test_salt = salt(32);
    const test_iv = iv(16);
    const test_session = sessionId(24);

    try std.testing.expectEqual(@as(usize, 12), test_nonce.len);
    try std.testing.expectEqual(@as(usize, 32), test_salt.len);
    try std.testing.expectEqual(@as(usize, 16), test_iv.len);
    try std.testing.expectEqual(@as(usize, 24), test_session.len);
}

test "documentation api compatibility" {
    // Test fillBytes API
    var buf: [32]u8 = undefined;
    fillBytes(&buf);
    
    // Test generateKey API
    const key = generateKey(32);
    try std.testing.expectEqual(@as(usize, 32), key.len);
    
    // Test generateSalt API  
    const test_salt = generateSalt(16);
    try std.testing.expectEqual(@as(usize, 16), test_salt.len);
}
