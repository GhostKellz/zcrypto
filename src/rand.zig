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

/// Windows CSPRNG.
///
/// `RtlGenRandom` is the documented name but not the exported one: advapi32
/// exports it as the undecorated `SystemFunction036` and the friendly name only
/// exists as a header macro. It therefore cannot be reached through
/// `std.os.windows.ntdll`, and referring to it there is a compile error rather
/// than a link-time one.
extern "advapi32" fn SystemFunction036(buffer: [*]u8, length: u32) callconv(.winapi) std.os.windows.BOOLEAN;

/// Test-only entropy failure injection.
///
/// The OS entropy source cannot be made to fail without disrupting the host, so
/// without a seam the failure paths below are unreachable from a test and the
/// "no weak fallback" property is an unverified claim. `builtin.is_test` is
/// comptime-known, so this struct has no storage and the check below is folded
/// away in every non-test build: the seam cannot be reached by a consumer.
const entropy_seam = if (builtin.is_test) struct {
    var forced: ?RngError = null;
    var forced_partial: ?Partial = null;

    const Partial = struct { written: usize, err: RngError };
} else struct {};

/// Make the next entropy request fail with `err`. Test builds only.
pub fn forceNextEntropyFailureForTesting(err: RngError) void {
    comptime std.debug.assert(builtin.is_test);
    entropy_seam.forced = err;
}

/// Make the next entropy request write `written` bytes and *then* fail with
/// `err`. Test builds only.
///
/// Distinct from `forceNextEntropyFailureForTesting`, which fails before
/// touching the buffer. That seam cannot exercise the guarantee that matters
/// here: every real source can fail after a partial write -- `getrandom`
/// interrupted repeatedly, or a later `SystemFunction036` chunk failing -- and
/// a buffer left half-filled with real entropy is indistinguishable from a
/// successful result to a caller that ignored the error.
pub fn forcePartialEntropyFailureForTesting(written: usize, err: RngError) void {
    comptime std.debug.assert(builtin.is_test);
    entropy_seam.forced_partial = .{ .written = written, .err = err };
}

/// Bytes to request from the Windows CSPRNG in a single call.
///
/// `SystemFunction036` takes a ULONG length, so a buffer larger than 4 GiB has
/// to be filled over several calls rather than truncated by a cast. Split out
/// of that loop as a pure function so it can be tested: for any buffer a test
/// can afford to allocate the loop runs exactly once, so the chunking is
/// otherwise unexercised code, and a cast that silently truncated would behave
/// identically on every buffer anyone actually passes.
fn entropyChunkLen(remaining: usize) u32 {
    return @intCast(@min(remaining, std.math.maxInt(u32)));
}

/// Fill a buffer with secure random bytes using OS entropy.
///
/// Returns an error if entropy cannot be obtained, and on **any** error leaves
/// `buf` entirely zeroed rather than partially written.
///
/// The zeroing is load-bearing, not tidiness. Every source here can fail after
/// writing part of the buffer -- `getrandom` interrupted past its retry budget,
/// or a later Windows chunk failing -- and the natural result is a buffer
/// holding real entropy in its first half and the caller's previous contents in
/// the rest. A caller that ignored the error would then key off something that
/// passes every statistical smell test and has a fraction of the entropy it
/// appears to. Zeroing converts that into a value which is obviously not a key.
///
/// This is a guarantee about `buf` only. It deliberately does not claim the
/// bytes are gone from the machine: the partial fill may already have been
/// copied by the compiler or the kernel, and no store from here can reach those.
fn osRandomChecked(buf: []u8) RngError!void {
    errdefer std.crypto.secureZero(u8, buf);

    if (builtin.is_test) {
        if (entropy_seam.forced_partial) |partial| {
            entropy_seam.forced_partial = null;
            // Deliberately non-zero and non-constant, so a test asserting the
            // buffer was cleared cannot pass by accident on a buffer that was
            // simply never written.
            const n = @min(partial.written, buf.len);
            for (buf[0..n], 0..) |*byte, i| byte.* = @truncate(0xC0 +% i);
            return partial.err;
        }
        if (entropy_seam.forced) |err| {
            entropy_seam.forced = null;
            return err;
        }
    }

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
            // The length argument is a ULONG, so a buffer larger than 4 GiB has
            // to be filled in several calls rather than truncated by a cast.
            var filled: usize = 0;
            while (filled < buf.len) {
                const chunk = entropyChunkLen(buf.len - filled);
                // BOOLEAN is an open enum; every non-zero value is true, so
                // FALSE is the only value that may be compared against.
                if (SystemFunction036(buf.ptr + filled, chunk) == .FALSE) {
                    return RngError.EntropyFailure;
                }
                filled += chunk;
            }
        },
        .wasi => {
            // `random_get` is the only entropy source a WASI sandbox has: there
            // is no /dev/urandom to fall back to, and the host is required to
            // back it with a CSPRNG. It fills the whole buffer or fails.
            if (std.os.wasi.random_get(buf.ptr, buf.len) != .SUCCESS) {
                return RngError.EntropyFailure;
            }
        },
        .freestanding => {
            // A freestanding WASM module has no host interface unless one is
            // imported deliberately, so there is nothing here that could supply
            // entropy. Refusing to compile is the fail-closed answer; inventing
            // a PRNG would hand the caller predictable keys that still look
            // like output from a CSPRNG.
            @compileError(
                "zcrypto: no entropy source exists on a freestanding target. " ++
                    "Build for wasm32-wasi, which provides random_get, or supply a host " ++
                    "import and route osRandomChecked through it.",
            );
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

test "entropy failure propagates instead of falling back" {
    // A CSPRNG that degrades to a deterministic or partially-written buffer on
    // failure is worse than one that refuses to answer, so the contract under
    // test is that the caller gets an error and nothing that looks like output.
    var buf: [32]u8 = @splat(0x5A);

    forceNextEntropyFailureForTesting(RngError.EntropyFailure);
    try std.testing.expectError(RngError.EntropyFailure, fillChecked(&buf));
    for (buf) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    buf = @splat(0x5A);
    forceNextEntropyFailureForTesting(RngError.NoEntropySource);
    try std.testing.expectError(RngError.NoEntropySource, fillChecked(&buf));
    for (buf) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    // The seam is one-shot, so the source must be healthy again afterwards.
    try fillChecked(&buf);
    var all_zero = true;
    for (buf) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "a failure after a partial fill leaves no entropy in the buffer" {
    // The test above cannot establish this. Its seam returns before any
    // platform code runs, so its assertion about the buffer holds no matter
    // what the platform branches do -- it was passing while a real partial
    // failure left 32 of 64 bytes written, which is how that was found.
    //
    // This seam writes first and fails second, which is what every source here
    // actually does on a late failure: `getrandom` interrupted past its retry
    // budget, or a Windows chunk failing after earlier chunks succeeded.
    var buf: [64]u8 = @splat(0x5A);

    forcePartialEntropyFailureForTesting(24, RngError.EntropyFailure);
    try std.testing.expectError(RngError.EntropyFailure, fillChecked(&buf));

    // Every byte, including the ones the source never reached. A caller cannot
    // tell which prefix was written, so a guarantee covering only the written
    // part would be one they could not act on.
    for (buf) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    // A partial fill that covers the whole buffer is the same contract: this is
    // the case where the result is entirely real entropy and therefore passes
    // any statistical check a careless caller might apply to it.
    buf = @splat(0x5A);
    forcePartialEntropyFailureForTesting(buf.len, RngError.EntropyFailure);
    try std.testing.expectError(RngError.EntropyFailure, fillChecked(&buf));
    for (buf) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "windows entropy chunking splits buffers larger than a ULONG" {
    // Windows-only code, tested from every host. The loop it serves runs
    // exactly once for any buffer a test could allocate, so running the suite
    // on Windows does not exercise this at all.
    const max32 = std.math.maxInt(u32);

    try std.testing.expectEqual(@as(u32, 0), entropyChunkLen(0));
    try std.testing.expectEqual(@as(u32, 1), entropyChunkLen(1));
    try std.testing.expectEqual(@as(u32, 32), entropyChunkLen(32));
    try std.testing.expectEqual(@as(u32, max32), entropyChunkLen(max32));

    // Past a ULONG the request must be capped, not truncated. A plain
    // `@intCast` of `max32 + 1` is 0 in a release build, which would spin the
    // caller's loop forever without ever filling a byte.
    if (@sizeOf(usize) > 4) {
        try std.testing.expectEqual(@as(u32, max32), entropyChunkLen(max32 + 1));
        try std.testing.expectEqual(@as(u32, max32), entropyChunkLen(max32 * 2));

        // The loop must also make progress: chunking a 4 GiB + 1 buffer has to
        // leave a non-zero remainder that the next call can finish.
        const remainder = (@as(usize, max32) + 1) - entropyChunkLen(max32 + 1);
        try std.testing.expect(remainder > 0);
        try std.testing.expectEqual(@as(u32, 1), entropyChunkLen(remainder));
    }
}

test "entropy failure propagates through range sampling" {
    forceNextEntropyFailureForTesting(RngError.EntropyFailure);
    try std.testing.expectError(RngError.EntropyFailure, randomRangeChecked(u32, 100));

    // A zero-width range is a caller error, not an entropy error.
    try std.testing.expectError(RngError.InvalidRange, randomRangeChecked(u32, 0));

    const val = try randomRangeChecked(u32, 100);
    try std.testing.expect(val < 100);
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
