//! Cryptographic utilities
//!
//! Helper functions for constant-time operations, padding, endian conversion,
//! timestamp utilities, and other cryptographic utilities.

const std = @import("std");
const builtin = @import("builtin");

// =============================================================================
// TIMESTAMP UTILITIES
// =============================================================================

/// Timestamp result containing seconds and nanoseconds
pub const Timestamp = struct {
    sec: i64,
    nsec: i64,

    /// Convert to nanoseconds since epoch
    pub fn toNanos(self: Timestamp) i128 {
        return @as(i128, self.sec) * std.time.ns_per_s + self.nsec;
    }

    /// Get Unix timestamp in seconds
    pub fn toUnixSeconds(self: Timestamp) i64 {
        return self.sec;
    }
};

extern "kernel32" fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *std.os.windows.FILETIME) callconv(.winapi) void;

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch.
const filetime_epoch_offset_s: i64 = 11_644_473_600;

/// Read the realtime clock.
///
/// The POSIX branch cannot be used unconditionally: on Windows
/// `std.posix.system.clock_gettime` resolves to the libc symbol, and because
/// this library does not link libc that is a compile error, not a fallback. It
/// is what stopped zcrypto building on Windows at all.
fn readRealtimeClock() ?Timestamp {
    switch (builtin.os.tag) {
        .windows => {
            var ft: std.os.windows.FILETIME = undefined;
            GetSystemTimeAsFileTime(&ft);
            // FILETIME counts 100 ns ticks; split before shifting the epoch so
            // the sub-second part stays correct for pre-1970 values.
            const ticks: i64 = @bitCast((@as(u64, ft.dwHighDateTime) << 32) | @as(u64, ft.dwLowDateTime));
            return Timestamp{
                .sec = @divFloor(ticks, 10_000_000) - filetime_epoch_offset_s,
                .nsec = @intCast(@mod(ticks, 10_000_000) * 100),
            };
        },
        .wasi => {
            // Same reason as Windows: on WASI `std.posix.system.clock_gettime`
            // is the libc symbol. `clock_time_get` is the sandbox's own import,
            // so it needs no libc. The host supplies the value, which means a
            // WASI runtime can report an arbitrary wall clock; see the host
            // import contract in docs before relying on it for expiry checks.
            var ns: std.os.wasi.timestamp_t = undefined;
            if (std.os.wasi.clock_time_get(.REALTIME, 1, &ns) != .SUCCESS) {
                return null;
            }
            return Timestamp{
                .sec = @intCast(ns / std.time.ns_per_s),
                .nsec = @intCast(ns % std.time.ns_per_s),
            };
        },
        else => {
            var ts: std.posix.timespec = undefined;
            const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
            if (std.posix.errno(rc) != .SUCCESS) {
                return null;
            }
            return Timestamp{ .sec = ts.sec, .nsec = ts.nsec };
        },
    }
}

/// Get current realtime timestamp
/// Returns null on error for use in contexts where errors can't be propagated
pub fn getTimestamp() ?Timestamp {
    return readRealtimeClock();
}

/// Get current realtime timestamp, returning error on failure
pub fn getTimestampOrError() !Timestamp {
    return readRealtimeClock() orelse error.ClockGetTimeFailed;
}

/// Get current Unix timestamp in seconds
pub fn getCurrentUnixTime() ?i64 {
    const ts = getTimestamp() orelse return null;
    return ts.sec;
}

// Both wall-clock nanosecond helpers that used to live here are gone, and the
// monotonic clock below replaces them. They were only ever used to measure
// durations, which the wall clock cannot do -- it can step between two reads --
// and `getTimestampNanosOrZero` made that worse by substituting 0 for a failed
// read: subtracting a good start from a zeroed end gave a negative value that
// `@intCast` to u64 turns into illegal behavior, and a zeroed start with a good
// end published the whole Unix epoch, about 56 years, as an elapsed time.
// Callers that want the current time still have `getTimestamp`/`getTimestampOrError`.

// =============================================================================
// MONOTONIC CLOCK
// =============================================================================

/// A point on the monotonic clock, for measuring elapsed time.
///
/// Deliberately a distinct type from `Timestamp` rather than an alias or a bare
/// integer. Its origin is unspecified and differs by platform and by boot, so a
/// value is meaningful only when subtracted from another taken on the same
/// machine in the same process. Sharing a representation with the wall clock
/// would make mixing the two a silent wrong answer instead of a type error.
pub const Instant = struct {
    ns: u64,

    /// Nanoseconds elapsed from `earlier` to `self`.
    ///
    /// Returns `error.ClockWentBackwards` rather than saturating to zero. The
    /// clock is specified not to go backwards, so a negative delta means the
    /// reading cannot be trusted -- and a caller dividing by it would publish a
    /// fabricated rate, which is the failure this whole clock exists to end.
    pub fn since(self: Instant, earlier: Instant) error{ClockWentBackwards}!u64 {
        if (self.ns < earlier.ns) return error.ClockWentBackwards;
        return self.ns - earlier.ns;
    }
};

/// Convert Windows performance-counter ticks to nanoseconds.
///
/// Split out of the Windows branch rather than inlined there so it can be
/// tested anywhere, including from a Linux host. The conversion has two paths
/// and any given machine only ever takes one of them: the Windows box this was
/// developed against reports exactly 10 MHz, so left inline the general path
/// would have shipped without ever having run.
///
/// `ticks * ns_per_s` cannot be evaluated directly -- at 10 MHz it exceeds u64
/// after about half an hour of uptime, which in a safe build is a panic in a
/// benchmark. Both paths below are the conversion `std.Io.Threaded` uses for
/// this clock: an exact multiply for the common frequency, and a 32-bit
/// fixed-point scale widened to u96 otherwise. The fixed-point path is lossy by
/// design and can land a nanosecond short of the true value; that is far below
/// the resolution of anything being measured here.
fn qpcTicksToNanos(ticks: u64, freq: u32) u64 {
    const common_freq = 10_000_000;
    if (freq == common_freq) {
        return ticks * (std.time.ns_per_s / common_freq);
    }
    const scale = @as(u64, std.time.ns_per_s << 32) / freq;
    return @intCast((@as(u96, ticks) * scale) >> 32);
}

/// Read the monotonic clock.
///
/// Written out per platform for the same reason as `readRealtimeClock` above:
/// this library does not link libc, and `std.posix.system.clock_gettime`
/// resolves to the libc symbol on Windows and WASI.
///
/// It is not simply forwarded to the standard library because there is nothing
/// to forward to. `std.time` in this toolchain is constants only -- no `Timer`,
/// no `Instant`, no `nanoTimestamp` -- and the API that replaced them,
/// `std.Io.Clock.now`, takes an `Io` instance. Requiring consumers to construct
/// an async runtime in order to time a loop is a heavier contract than this
/// library should impose, so the branches below mirror what `std.Io.Threaded`
/// does for this clock rather than depending on it.
fn readMonotonicClock() ?Instant {
    switch (builtin.os.tag) {
        .windows => {
            const win = std.os.windows;

            var raw_freq: win.LARGE_INTEGER = undefined;
            if (!win.ntdll.RtlQueryPerformanceFrequency(&raw_freq).toBool()) return null;
            const freq: u64 = @bitCast(raw_freq);
            // Divided by below, and narrowed to u32 for the fixed-point scale.
            const freq_u32 = std.math.cast(u32, freq) orelse return null;
            if (freq_u32 == 0) return null;

            var raw_ticks: win.LARGE_INTEGER = undefined;
            if (!win.ntdll.RtlQueryPerformanceCounter(&raw_ticks).toBool()) return null;
            const ticks: u64 = @bitCast(raw_ticks);

            return Instant{ .ns = qpcTicksToNanos(ticks, freq_u32) };
        },
        .wasi => {
            // As with the realtime branch, this is the sandbox's own import and
            // needs no libc. The host supplies the value; a runtime that does
            // not implement a monotonic clock reports the error rather than
            // this silently falling back to the wall clock.
            var ns: std.os.wasi.timestamp_t = undefined;
            if (std.os.wasi.clock_time_get(.MONOTONIC, 1, &ns) != .SUCCESS) return null;
            return Instant{ .ns = ns };
        },
        else => {
            var ts: std.posix.timespec = undefined;
            const rc = std.posix.system.clock_gettime(.MONOTONIC, &ts);
            if (std.posix.errno(rc) != .SUCCESS) return null;
            if (ts.sec < 0 or ts.nsec < 0) return null;
            const sec_ns = std.math.mul(u64, @intCast(ts.sec), std.time.ns_per_s) catch return null;
            return Instant{ .ns = std.math.add(u64, sec_ns, @intCast(ts.nsec)) catch return null };
        },
    }
}

/// Read the monotonic clock, or null if this platform's clock is unavailable.
pub fn getMonotonic() ?Instant {
    return readMonotonicClock();
}

/// Read the monotonic clock, returning an error on failure.
pub fn getMonotonicOrError() error{MonotonicClockUnavailable}!Instant {
    return readMonotonicClock() orelse error.MonotonicClockUnavailable;
}

/// A 64-bit counter that is synchronised between threads wherever threads exist.
///
/// `std.atomic.Value(u64)` is not portable. wasm32 without the `atomics` CPU
/// feature -- which is what `wasm32-wasi` is by default, and what this project's
/// WASM gate builds -- rejects `@atomicLoad` and `@atomicRmw` on anything wider
/// than 32 bits. Three counters in this tree used it directly, so the library
/// failed to compile for wasm32 the moment anything referenced them.
///
/// That went unnoticed for a specific and repeatable reason: `zig build
/// -Dtarget=wasm32-wasi` exited 0. Zig only analyses what is actually reached,
/// and the examples never touch these counters, so a green cross-compile said
/// nothing about them. Building the *tests* for wasm32 is what analyses the
/// whole library, and that is what the gate now does.
///
/// The predicate is `single_threaded`, not "does this target have 64-bit
/// atomics". Those are different questions, and only the first one licenses
/// dropping the synchronisation: with no second thread there is no race to
/// lose. A multi-threaded target that genuinely lacks 64-bit atomics still
/// fails to compile here, which is the correct outcome -- substituting a plain
/// load and store there would trade a build error for a real data race.
///
/// Ordering is `.monotonic` throughout. These counters carry no happens-before
/// relationship for any other memory; each is read and written for its own
/// value alone.
pub const Counter64 = struct {
    const Repr = if (builtin.single_threaded) u64 else std.atomic.Value(u64);

    raw: Repr,

    pub fn init(value: u64) Counter64 {
        return .{ .raw = if (builtin.single_threaded) value else Repr.init(value) };
    }

    pub fn load(self: *const Counter64) u64 {
        if (builtin.single_threaded) return self.raw;
        return self.raw.load(.monotonic);
    }

    /// Adds `operand` and returns the value from before the add, wrapping on
    /// overflow exactly as the atomic form does.
    pub fn fetchAdd(self: *Counter64, operand: u64) u64 {
        if (builtin.single_threaded) {
            const previous = self.raw;
            self.raw = previous +% operand;
            return previous;
        }
        return self.raw.fetchAdd(operand, .monotonic);
    }

    /// Returns null when the exchange succeeded, or the value actually found
    /// when it did not -- the same shape as `std.atomic.Value.cmpxchgWeak`, so
    /// a caller's retry loop reads identically on both targets.
    pub fn cmpxchgWeak(self: *Counter64, expected: u64, new: u64) ?u64 {
        if (builtin.single_threaded) {
            if (self.raw != expected) return self.raw;
            self.raw = new;
            return null;
        }
        return self.raw.cmpxchgWeak(expected, new, .monotonic, .monotonic);
    }
};

test "a counter observes its own writes" {
    var counter = Counter64.init(7);
    try std.testing.expectEqual(@as(u64, 7), counter.load());
    try std.testing.expectEqual(@as(u64, 7), counter.fetchAdd(3));
    try std.testing.expectEqual(@as(u64, 10), counter.load());
}

test "a compare-and-swap reports the value it found rather than swapping blindly" {
    var counter = Counter64.init(1);
    // A mismatched expectation must not write, and must hand back what is
    // really there so a retry loop can make progress instead of spinning.
    try std.testing.expectEqual(@as(?u64, 1), counter.cmpxchgWeak(99, 5));
    try std.testing.expectEqual(@as(u64, 1), counter.load());
    try std.testing.expectEqual(@as(?u64, null), counter.cmpxchgWeak(1, 5));
    try std.testing.expectEqual(@as(u64, 5), counter.load());
}

test "fetchAdd wraps rather than trapping, matching the atomic it replaces" {
    // The single-threaded branch is hand-written arithmetic, so the wrap is a
    // property of this code rather than of the builtin. Debug and ReleaseSafe
    // both trap on `+` overflow, so a plain `+` here would be a divergence
    // between the two representations that only shows up at saturation.
    var counter = Counter64.init(std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), counter.fetchAdd(2));
    try std.testing.expectEqual(@as(u64, 1), counter.load());
}

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

/// Zero a buffer with a store the optimizer is not permitted to delete.
///
/// Guarantees that the write to `buf` happens, and nothing beyond that. A plain
/// `@memset(buf, 0)` on a buffer nothing reads afterwards is a dead store the
/// optimizer may delete, which is exactly the shape of every key clear in this
/// library. `buf` is `[]volatile u8` -- ordinary `[]u8` coerces to it -- so
/// that guarantee is carried by the type rather than by convention.
///
/// It does not erase the secret from the machine. The value may already sit in
/// a register, a spill slot, a bounce buffer, a swap page, or a VM snapshot,
/// and a store to this address reaches none of them. See `timing.secureZero`,
/// which is the same primitive.
pub fn secureZero(buf: []volatile u8) void {
    std.crypto.secureZero(u8, buf);
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

// The monotonic clock's contract is what callers divide by, so each part of it
// is asserted rather than assumed. These tests are the same on every platform
// on purpose: `readMonotonicClock` is three separate hand-written branches, and
// a branch is only known to hold up its end once it has run on its own target.

test "monotonic clock is available" {
    // Not `if (getMonotonic()) |_| {}`: a platform whose clock cannot be read
    // must fail here rather than let every timing test below quietly pass by
    // never running. `getMonotonicOrError` is the seam callers use, so a
    // platform that reaches this and errors is one where they would too.
    _ = try getMonotonicOrError();
}

test "monotonic clock does not go backwards" {
    var previous = try getMonotonicOrError();
    for (0..1000) |_| {
        const current = try getMonotonicOrError();
        // Via `since`, which is the accessor callers use -- so this also
        // asserts that the success path never reports ClockWentBackwards.
        _ = try current.since(previous);
        previous = current;
    }
}

test "monotonic clock advances" {
    // A clock that reads the same value forever satisfies "does not go
    // backwards" and is still useless: it yields a zero delta, and a benchmark
    // dividing by it either traps or publishes a fabricated rate. That is the
    // defect this clock replaces, so resolution is asserted, not assumed.
    //
    // Spun rather than slept because this toolchain has no sleep primitive.
    // The cap is what keeps a stuck clock a failure instead of a hung test;
    // it is far above what any real clock needs, so it cannot flake on a slow
    // or loaded machine while still bounding the runtime.
    const start = try getMonotonicOrError();
    var elapsed: u64 = 0;
    for (0..100_000_000) |_| {
        elapsed = try (try getMonotonicOrError()).since(start);
        if (elapsed > 0) break;
    }
    try std.testing.expect(elapsed > 0);
}

test "qpc tick conversion covers both frequency paths" {
    // Runs on every host, not just Windows. That is the point: this is the one
    // piece of the Windows branch whose behaviour does not depend on Windows,
    // and the machine used to verify that branch reports exactly 10 MHz -- so
    // the general path is not covered by running the suite there, only here.

    // Common path: 10 MHz means one tick is exactly 100 ns.
    try std.testing.expectEqual(@as(u64, 100), qpcTicksToNanos(1, 10_000_000));
    try std.testing.expectEqual(@as(u64, std.time.ns_per_s), qpcTicksToNanos(10_000_000, 10_000_000));

    // Well past the point where `ticks * ns_per_s` would have exceeded u64
    // (about half an hour of uptime at this rate), to show the path taken is
    // the one that does not overflow rather than merely one that has not yet.
    const one_day_ticks: u64 = 86_400 * 10_000_000;
    try std.testing.expectEqual(@as(u64, 86_400) * std.time.ns_per_s, qpcTicksToNanos(one_day_ticks, 10_000_000));

    // General path, exact case: 1 MHz divides ns_per_s evenly.
    try std.testing.expectEqual(@as(u64, std.time.ns_per_s), qpcTicksToNanos(1_000_000, 1_000_000));

    // General path, inexact case: 3 MHz does not divide evenly, so the
    // fixed-point scale rounds. Asserted as a tight bound rather than an exact
    // value -- pinning the exact truncation would test the arithmetic's current
    // rounding rather than the property that matters, which is that a second
    // measures as a second.
    const three_mhz = qpcTicksToNanos(3_000_000, 3_000_000);
    try std.testing.expect(three_mhz <= std.time.ns_per_s);
    try std.testing.expect(std.time.ns_per_s - three_mhz <= 1_000);

    // A frequency that is not a round number at all, checked the same way.
    const odd = qpcTicksToNanos(3_579_545, 3_579_545);
    try std.testing.expect(odd <= std.time.ns_per_s);
    try std.testing.expect(std.time.ns_per_s - odd <= 1_000);
}

test "since rejects a backwards delta" {
    // Constructed directly: a real clock will not go backwards on demand, and
    // an error path that is never exercised is an error path that is not known
    // to work. Saturating to zero here instead of erroring is precisely the
    // silent-wrong-answer behaviour the type exists to prevent.
    const earlier = Instant{ .ns = 1_000 };
    const later = Instant{ .ns = 3_500 };

    try std.testing.expectEqual(@as(u64, 2_500), try later.since(earlier));
    try std.testing.expectError(error.ClockWentBackwards, earlier.since(later));

    // Equal readings are a zero delta, not an error: a clock is permitted to
    // report the same instant twice, and only a decrease is a contract breach.
    try std.testing.expectEqual(@as(u64, 0), try earlier.since(earlier));
}
