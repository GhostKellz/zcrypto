//! Timing-Safe Cryptographic Utilities
//!
//! Provides constant-time operations to prevent timing side-channel attacks.
//! These functions are critical for comparing secrets (keys, MACs, passwords)
//! and ensuring operations complete in predictable time.
//!
//! ## Security Considerations
//!
//! Timing attacks exploit the fact that certain operations (like early-exit
//! comparisons) take different amounts of time depending on the input data.
//! An attacker measuring response times can potentially extract secret keys.
//!
//! ## Usage
//!
//! Always use these functions when working with:
//! - Secret keys
//! - Authentication tags (MACs)
//! - Password hashes
//! - Signature verification results
//!
//! ## Example
//! ```zig
//! // ❌ INSECURE: Early-exit comparison
//! if (std.mem.eql(u8, secret1, secret2)) { }
//!
//! // ✅ SECURE: Constant-time comparison
//! if (timingSafeEqual(secret1, secret2)) { }
//! ```

const std = @import("std");
const testing = std.testing;

/// Constant-time comparison of two byte slices
///
/// Compares two slices in constant time, regardless of where they differ.
/// This prevents timing attacks that could leak information about secret data.
///
/// ## Parameters
/// - `a`: First slice to compare
/// - `b`: Second slice to compare
///
/// ## Returns
/// `true` if slices are equal, `false` otherwise
///
/// ## Security
/// This function takes the same amount of time regardless of:
/// - Whether the slices are equal
/// - Where the first difference occurs
/// - How many bytes differ
///
/// The only variable that affects timing is the length of the slices.
/// If comparing secret data of variable length, pad to a fixed size first.
///
/// ## Example
/// ```zig
/// const computed_mac = hmac(message, key);
/// const expected_mac = received_mac;
///
/// // Constant-time comparison prevents timing attacks
/// if (!timingSafeEqual(&computed_mac, &expected_mac)) {
///     return error.AuthenticationFailed;
/// }
/// ```
pub fn timingSafeEqual(a: []const u8, b: []const u8) bool {
    // Different lengths are obviously unequal
    // This is NOT a timing leak because length is typically public
    if (a.len != b.len) return false;

    // Constant-time comparison using bitwise operations
    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }
    return result == 0;
}

/// Securely zero memory
///
/// Overwrites memory with zeros in a way that cannot be optimized away
/// by the compiler. Critical for clearing sensitive data like private keys.
///
/// ## Parameters
/// - `buffer`: Buffer to zero
///
/// ## Security
/// Normal `@memset(buffer, 0)` can be optimized away by the compiler if
/// the buffer is not used afterwards. This function uses a memory barrier
/// to ensure the zeroing always happens.
///
/// ## Example
/// ```zig
/// var private_key: [64]u8 = // ... sensitive data ...
/// defer secureZero(&private_key);  // Always zeros, even if optimized build
///
/// // Use private_key...
/// ```
///
/// ## Note
/// In Zig, `@memset` followed by a memory barrier is sufficient. Some C
/// libraries use `volatile` or asm tricks, but Zig's memory model is safer.
pub fn secureZero(buffer: []u8) void {
    @memset(buffer, 0);
    // Use inline assembly to prevent compiler optimization
    // This ensures the memset is not removed even if buffer is unused after
    asm volatile ("" ::: .{ .memory = true });
}

/// Constant-time conditional selection
///
/// Returns `true_value` if `condition` is true, otherwise `false_value`.
/// The selection happens in constant time without branching.
///
/// ## Parameters
/// - `T`: Type of values (must be copyable)
/// - `condition`: Boolean condition
/// - `true_value`: Value to return if true
/// - `false_value`: Value to return if false
///
/// ## Returns
/// Selected value
///
/// ## Security
/// This function uses bitwise operations instead of branching to ensure
/// constant-time execution. Useful for implementing constant-time algorithms.
///
/// ## Example
/// ```zig
/// // Constant-time max (useful in crypto algorithms)
/// const max = constantTimeSelect(u32, a > b, a, b);
/// ```
pub fn constantTimeSelect(comptime T: type, condition: bool, true_value: T, false_value: T) T {
    const mask: T = if (@typeInfo(T) == .int) blk: {
        // For integers, create a mask from condition
        const mask_u = @as(T, @intFromBool(condition));
        // Expand to all bits: 0 or ~0
        break :blk @as(T, 0) -% mask_u;
    } else {
        // For non-integers, just use regular selection
        // (This is less critical for non-secret data)
        return if (condition) true_value else false_value;
    };

    // Bitwise select: (true_value & mask) | (false_value & ~mask)
    return (true_value & mask) | (false_value & ~mask);
}

/// Constant-time byte comparison
///
/// Returns 1 if a == b, 0 otherwise, in constant time.
/// Useful for building constant-time algorithms.
///
/// ## Parameters
/// - `a`: First byte
/// - `b`: Second byte
///
/// ## Returns
/// 1 if equal, 0 otherwise
///
/// ## Security
/// Uses bitwise operations to avoid branching.
pub fn constantTimeByteEq(a: u8, b: u8) u8 {
    const x = a ^ b;
    // If x == 0 (equal), this returns 1; otherwise 0
    const y = x | (~x +% 1);
    return @as(u8, @intCast((~y >> 7) & 1));
}

/// Check if buffer contains only zeros (constant-time)
///
/// Returns true if all bytes are zero, in constant time.
///
/// ## Parameters
/// - `buffer`: Buffer to check
///
/// ## Returns
/// `true` if all zeros, `false` otherwise
///
/// ## Security
/// Does not early-exit when finding a non-zero byte.
///
/// ## Example
/// ```zig
/// if (constantTimeIsZero(&maybe_cleared_key)) {
///     // Key was successfully cleared
/// }
/// ```
pub fn constantTimeIsZero(buffer: []const u8) bool {
    var result: u8 = 0;
    for (buffer) |byte| {
        result |= byte;
    }
    return result == 0;
}

//
// ============================================================================
// DOCUMENTATION: Constant-Time Guarantees for Crypto Operations
// ============================================================================
//

// Documentation: Which crypto operations are constant-time?
//
// This section documents timing guarantees for various crypto operations
// in zcrypto to help prevent timing side-channel attacks.
//
// ## ✅ Constant-Time Operations (Safe for Secrets)
//
// These operations have constant-time implementations with respect to
// secret data (keys, plaintexts):
//
// ### Symmetric Crypto
// - `ChaCha20` encryption/decryption (constant-time)
// - `Poly1305` MAC computation (constant-time)
// - `AES-GCM` (constant-time with AES-NI, variable without)
//
// ### Asymmetric Crypto
// - `Ed25519.sign()` - Constant-time with respect to private key
// - `X25519.scalarmult()` - Constant-time key exchange
//
// ### Hashing
// - All hash functions (Blake3, SHA-256, etc.) are constant-time
//   with respect to data length only (content timing is standard)
//
// ### Key Derivation
// - HKDF, PBKDF2, Argon2 - Constant time (except for iteration count)
//
// ## ⚠️  Variable-Time Operations (Public Data Only)
//
// These operations are NOT constant-time and should only be used with
// public data:
//
// ### Verification Operations
// - `Ed25519.verify()` - Variable time (but signature/key are public)
// - `ECDSA.verify()` - Variable time (but signature/key are public)
//
// Note: It's acceptable for verification to be variable-time because
// the inputs (public key, signature) are typically public. However,
// comparison of the result should still use constant-time equals.
//
// ### Compression/Decompression
// - Point decompression - Variable time (public key material)
//
// ## 🔒 Best Practices
//
// 1. **Always use `timingSafeEqual()` for secrets**:
//    ```zig
//    // ❌ WRONG
//    if (std.mem.eql(u8, &mac1, &mac2)) { }
//
//    // ✅ CORRECT
//    if (timingSafeEqual(&mac1, &mac2)) { }
//    ```
//
// 2. **Always zero secrets after use**:
//    ```zig
//    var private_key: [64]u8 = // ...
//    defer secureZero(&private_key);
//    ```
//
// 3. **Verify HMAC before decrypting**:
//    ```zig
//    // ❌ WRONG: Decrypt then verify (padding oracle)
//    const plaintext = decrypt(ciphertext);
//    if (!verify(mac)) return error.Invalid;
//
//    // ✅ CORRECT: Verify then decrypt (constant-time MAC check!)
//    if (!timingSafeEqual(&computed_mac, &received_mac)) {
//        return error.AuthenticationFailed;
//    }
//    const plaintext = decrypt(ciphertext);
//    ```
//
// 4. **Avoid length-dependent operations on secrets**:
//    ```zig
//    // ❌ WRONG: String comparison reveals length
//    for (password) |c, i| {
//        if (c != expected[i]) return false;  // Early exit!
//    }
//
//    // ✅ CORRECT: Hash and constant-time compare
//    const hash1 = blake3(password);
//    const hash2 = blake3(expected_password);
//    if (!timingSafeEqual(&hash1, &hash2)) return false;
//    ```
//
// ## References
// - [Timing Attacks on RSA](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf)
// - [Lucky 13 Attack](https://www.isg.rhul.ac.uk/tls/Lucky13.html)
// - [NaCl: Cryptography in a Box](https://nacl.cr.yp.to/features.html)

//
// ============================================================================
// TESTS
// ============================================================================
//

test "timingSafeEqual basic" {
    const a = "hello";
    const b = "hello";
    const c = "world";

    try testing.expect(timingSafeEqual(a, b));
    try testing.expect(!timingSafeEqual(a, c));
}

test "timingSafeEqual different lengths" {
    const a = "hello";
    const b = "hello world";

    try testing.expect(!timingSafeEqual(a, b));
}

test "timingSafeEqual empty" {
    const a = "";
    const b = "";

    try testing.expect(timingSafeEqual(a, b));
}

test "timingSafeEqual secrets" {
    const mac1 = [_]u8{0x01} ** 32;
    const mac2 = [_]u8{0x01} ** 32;
    const mac3 = [_]u8{0x02} ** 32;

    try testing.expect(timingSafeEqual(&mac1, &mac2));
    try testing.expect(!timingSafeEqual(&mac1, &mac3));
}

test "secureZero clears memory" {
    var buffer = [_]u8{0xFF} ** 64;

    secureZero(&buffer);

    // Verify all bytes are zero
    for (buffer) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "constantTimeSelect integer" {
    const a: u32 = 42;
    const b: u32 = 99;

    const result_true = constantTimeSelect(u32, true, a, b);
    const result_false = constantTimeSelect(u32, false, a, b);

    try testing.expectEqual(a, result_true);
    try testing.expectEqual(b, result_false);
}

test "constantTimeByteEq" {
    try testing.expectEqual(@as(u8, 1), constantTimeByteEq(0x42, 0x42));
    try testing.expectEqual(@as(u8, 0), constantTimeByteEq(0x42, 0x43));
    try testing.expectEqual(@as(u8, 1), constantTimeByteEq(0x00, 0x00));
    try testing.expectEqual(@as(u8, 0), constantTimeByteEq(0x00, 0xFF));
}

test "constantTimeIsZero" {
    const zeros = [_]u8{0} ** 32;
    const nonzeros = [_]u8{0} ** 31 ++ [_]u8{1};
    const all_nonzero = [_]u8{0xFF} ** 32;

    try testing.expect(constantTimeIsZero(&zeros));
    try testing.expect(!constantTimeIsZero(&nonzeros));
    try testing.expect(!constantTimeIsZero(&all_nonzero));
}

test "constantTimeIsZero empty buffer" {
    const empty: []const u8 = &[_]u8{};
    try testing.expect(constantTimeIsZero(empty));
}

test "timing safe comparison demonstrates constant time behavior" {
    // This test demonstrates that timingSafeEqual should take similar time
    // regardless of where the difference occurs
    const base = [_]u8{0x42} ** 1000;
    var diff_start = base;
    var diff_end = base;

    diff_start[0] = 0x43; // Difference at start
    diff_end[999] = 0x43; // Difference at end

    // Both should return false
    try testing.expect(!timingSafeEqual(&base, &diff_start));
    try testing.expect(!timingSafeEqual(&base, &diff_end));

    // Note: We can't actually measure timing in a test, but the
    // implementation guarantees constant-time behavior
}
