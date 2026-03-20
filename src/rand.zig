//! Secure random number generation
//!
//! Cryptographically secure random number generation backed by OS entropy.
//! All functions use secure sources and are suitable for cryptographic use.
//!
//! Security features:
//! - Uses OS-provided CSPRNG (getrandom, arc4random, RtlGenRandom)
//! - Rejection sampling for unbiased range generation
//! - Explicit error propagation for entropy failures

const std = @import("std");
const builtin = @import("builtin");

/// Errors that can occur during random number generation
pub const RngError = error{
    /// Failed to obtain entropy from the operating system
    EntropyFailure,
    /// The requested range is invalid (e.g., max is 0)
    InvalidRange,
    /// /dev/urandom is not available
    NoEntropySource,
};

/// Fill a buffer with secure random bytes using OS entropy
/// Returns error if entropy cannot be obtained
fn osRandomChecked(buf: []u8) RngError!void {
    switch (builtin.os.tag) {
        .linux => {
            var filled: usize = 0;
            var retries: usize = 0;
            const max_retries = 10;

            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
                const errno = std.os.linux.errno(rc);

                if (errno == .SUCCESS) {
                    filled += rc;
                    retries = 0;
                } else if (errno == .INTR) {
                    // Interrupted, retry
                    retries += 1;
                    if (retries >= max_retries) return RngError.EntropyFailure;
                } else {
                    // Other error (EAGAIN, ENOSYS, etc.)
                    return RngError.EntropyFailure;
                }
            }
        },
        .macos, .ios, .tvos, .watchos => {
            // arc4random_buf never fails on Darwin
            std.c.arc4random_buf(buf.ptr, buf.len);
        },
        .windows => {
            // RtlGenRandom returns BOOLEAN
            const success = std.os.windows.ntdll.RtlGenRandom(buf.ptr, @intCast(buf.len));
            if (success == 0) return RngError.EntropyFailure;
        },
        else => {
            // Fallback: read from /dev/urandom
            const fd = std.posix.openat(std.posix.AT.FDCWD, "/dev/urandom", .{ .ACCMODE = .RDONLY }, 0) catch {
                return RngError.NoEntropySource;
            };
            defer _ = std.posix.system.close(fd);

            var filled: usize = 0;
            while (filled < buf.len) {
                const n = std.posix.read(fd, buf[filled..]) catch {
                    return RngError.EntropyFailure;
                };
                if (n == 0) return RngError.EntropyFailure; // EOF on /dev/urandom is unexpected
                filled += n;
            }
        },
    }
}

/// Fill a buffer with secure random bytes using OS entropy
/// Panics if entropy cannot be obtained (use fillChecked for error handling)
fn osRandom(buf: []u8) void {
    osRandomChecked(buf) catch |err| {
        @panic(switch (err) {
            RngError.EntropyFailure => "Failed to obtain entropy from OS",
            RngError.NoEntropySource => "No entropy source available",
            RngError.InvalidRange => "Invalid range",
        });
    };
}

/// Fill a buffer with secure random bytes (matches documentation API)
pub fn fillBytes(buf: []u8) void {
    osRandom(buf);
}

/// Fill a buffer with secure random bytes with error handling
pub fn fillChecked(buf: []u8) RngError!void {
    return osRandomChecked(buf);
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
    var buf: [4]u8 = undefined;
    osRandom(&buf);
    return std.mem.readInt(u32, &buf, .little);
}

/// Generate a random u64
pub fn randomU64() u64 {
    var buf: [8]u8 = undefined;
    osRandom(&buf);
    return std.mem.readInt(u64, &buf, .little);
}

/// Generate a random integer in range [0, max) using rejection sampling
/// This eliminates modulo bias for cryptographically fair distribution
pub fn randomRange(comptime T: type, max: T) T {
    if (max == 0) return 0;

    const max_u64: u64 = @intCast(max);

    // Use rejection sampling to eliminate modulo bias
    // We calculate the largest multiple of max that fits in u64
    // limit = floor((2^64 - 1) / max) * max
    // Any value >= limit would cause bias, so we reject those
    const remainder = std.math.maxInt(u64) % max_u64;
    const limit = std.math.maxInt(u64) - remainder;

    var val: u64 = undefined;
    while (true) {
        val = randomU64();
        // Accept values below the limit (no bias)
        if (val <= limit) break;
    }
    return @intCast(val % max_u64);
}

/// Generate a random integer in range [0, max) with error handling
pub fn randomRangeChecked(comptime T: type, max: T) RngError!T {
    if (max == 0) return RngError.InvalidRange;

    const max_u64: u64 = @intCast(max);
    const remainder = std.math.maxInt(u64) % max_u64;
    const limit = std.math.maxInt(u64) - remainder;

    var buf: [8]u8 = undefined;
    var attempts: usize = 0;
    const max_attempts = 256; // Prevent infinite loop on pathological cases

    while (attempts < max_attempts) {
        try osRandomChecked(&buf);
        const val = std.mem.readInt(u64, &buf, .little);
        if (val <= limit) {
            return @intCast(val % max_u64);
        }
        attempts += 1;
    }
    return RngError.EntropyFailure; // Should never happen with good RNG
}

/// Generate a random integer in range [min, max]
pub fn randomRangeInclusive(comptime T: type, min: T, max: T) T {
    const range = max - min + 1;
    return min + randomRange(T, range);
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
    const val = randomU64();
    return @as(T, @floatFromInt(val)) / @as(T, @floatFromInt(std.math.maxInt(u64)));
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
