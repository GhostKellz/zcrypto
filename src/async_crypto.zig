//! Async cryptographic operations with zsync integration.
//!
//! This module targets the std.Io-backed `zsync` runtime surface used by
//! `zcrypto` (`Io`, `Future`, `Runtime`, and related integration helpers). The
//! operations below are zsync-compatible wrappers around direct crypto work,
//! rather than runtime-scheduled offload of long-running cryptographic tasks.

const std = @import("std");
const sym = @import("sym.zig");
const hash = @import("hash.zig");
const zsync = @import("zsync");

/// zsync Io interface for async operations
pub const Io = zsync.Io;
pub const Future = zsync.Future;

/// Async crypto context for zsync operations
pub const AsyncCrypto = struct {
    io: Io,
    allocator: std.mem.Allocator,

    pub fn init(io: Io, allocator: std.mem.Allocator) AsyncCrypto {
        return AsyncCrypto{
            .io = io,
            .allocator = allocator,
        };
    }

    /// zsync-compatible encryption wrapper using direct crypto calls.
    pub fn encryptAsync(self: AsyncCrypto, data: []const u8, key: []const u8) ![]u8 {
        if (key.len != 32) return error.InvalidKeySize;
        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, key[0..32]);
        return try sym.encryptAesGcm(self.allocator, data, &key_array);
    }

    /// zsync-compatible decryption wrapper using direct crypto calls.
    pub fn decryptAsync(self: AsyncCrypto, ciphertext: []const u8, key: []const u8) ![]u8 {
        if (key.len != 32) return error.InvalidKeySize;
        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, key[0..32]);
        return try sym.decryptAesGcm(self.allocator, ciphertext, &key_array);
    }

    /// zsync-compatible hashing wrapper using direct crypto calls.
    pub fn hashAsync(self: AsyncCrypto, data: []const u8) ![32]u8 {
        _ = self;
        return hash.sha256(data);
    }

    /// Encrypts each item in turn on the calling thread.
    ///
    /// Despite the name this is sequential: no zsync task is spawned and the
    /// items do not overlap. Cost is the sum of the items, not the maximum.
    pub fn batchEncryptAsync(self: AsyncCrypto, data_list: []const []const u8, key: []const u8) ![][]u8 {
        if (key.len != 32) return error.InvalidKeySize;
        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, key[0..32]);

        var results = try self.allocator.alloc([]u8, data_list.len);
        errdefer self.allocator.free(results);

        var initialized: usize = 0;
        errdefer {
            for (results[0..initialized]) |item| {
                self.allocator.free(item);
            }
        }

        for (data_list, 0..) |data, i| {
            results[i] = try sym.encryptAesGcm(self.allocator, data, &key_array);
            initialized += 1;
        }
        return results;
    }

    /// Encrypts `data`, ignoring `timeout_ms`.
    ///
    /// The parameter is accepted for source compatibility and has no effect:
    /// the call is not cancellable and never returns a timeout error. Do not
    /// use this to bound work or as a denial-of-service control — it provides
    /// neither. `encryptAsync` is equivalent and does not imply otherwise.
    ///
    /// A timeout is not merely unimplemented here, it is meaningless: the
    /// operation is a synchronous AES-GCM call on the calling thread with no
    /// blocking I/O to interrupt, so it runs to completion regardless. Honouring
    /// the parameter would require scheduling the work on a zsync task and
    /// cancelling it, which is outside this module's remit.
    pub fn encryptAsyncWithTimeout(self: AsyncCrypto, data: []const u8, key: []const u8, timeout_ms: u32) ![]u8 {
        _ = timeout_ms;
        return self.encryptAsync(data, key);
    }

    /// Hashes each item in turn on the calling thread.
    ///
    /// Sequential, like `batchEncryptAsync`: the name describes the API family,
    /// not the execution model.
    pub fn hashBatchAsync(self: AsyncCrypto, data_list: []const []const u8) ![][32]u8 {
        var results = try self.allocator.alloc([32]u8, data_list.len);

        for (data_list, 0..) |data, i| {
            results[i] = hash.sha256(data);
        }
        return results;
    }
};

/// Async result structure for crypto operations with performance metrics
pub const AsyncCryptoResult = struct {
    data: ?[]u8,
    error_message: ?[]const u8,
    /// Elapsed monotonic time, or null if the clock could not be read.
    ///
    /// Optional because whether the operation succeeded and whether it could be
    /// measured are independent facts, and a plain `u64` cannot say the second
    /// one failed. It previously held `end - start` over the wall clock with
    /// each read defaulting to 0 on failure, so a failed *start* read published
    /// the entire Unix epoch -- about 56 years -- as an execution time that a
    /// caller had no way to tell from a real measurement.
    execution_time_ns: ?u64,

    pub fn success_result(data: []u8, time_ns: ?u64) AsyncCryptoResult {
        return AsyncCryptoResult{
            .data = data,
            .error_message = null,
            .execution_time_ns = time_ns,
        };
    }

    pub fn error_result(message: []const u8, time_ns: ?u64) AsyncCryptoResult {
        return AsyncCryptoResult{
            .data = null,
            .error_message = message,
            .execution_time_ns = time_ns,
        };
    }
};

// =============================================================================
// TESTS
// =============================================================================

test "async crypto with zsync" {
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_data = "test data for zsync encryption";
    const test_key = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0xAB);
        break :blk bytes;
    };

    const encrypted = try async_crypto.encryptAsync(test_data, &test_key);
    defer std.testing.allocator.free(encrypted);

    try std.testing.expect(encrypted.len > test_data.len);

    const decrypted = try async_crypto.decryptAsync(encrypted, &test_key);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualStrings(test_data, decrypted);
}

test "batch async encryption" {
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_data = [_][]const u8{ "data1", "data2", "data3" };
    const test_key = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0xCD);
        break :blk bytes;
    };

    const encrypted_batch = try async_crypto.batchEncryptAsync(&test_data, &test_key);
    defer {
        for (encrypted_batch) |item| std.testing.allocator.free(item);
        std.testing.allocator.free(encrypted_batch);
    }

    try std.testing.expect(encrypted_batch.len == test_data.len);

    for (encrypted_batch, test_data) |encrypted, original| {
        try std.testing.expect(encrypted.len > original.len);

        const decrypted = try async_crypto.decryptAsync(encrypted, &test_key);
        defer std.testing.allocator.free(decrypted);
        try std.testing.expectEqualStrings(original, decrypted);
    }
}

test "async rejects invalid key sizes" {
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_data = [_][]const u8{ "data1", "data2" };
    const short_key = blk: {
        var bytes = std.mem.zeroes([31]u8);
        @memset(bytes[0..], 0x11);
        break :blk bytes;
    };

    try std.testing.expectError(error.InvalidKeySize, async_crypto.encryptAsync("data", &short_key));
    try std.testing.expectError(error.InvalidKeySize, async_crypto.decryptAsync("ciphertext", &short_key));
    try std.testing.expectError(error.InvalidKeySize, async_crypto.batchEncryptAsync(&test_data, &short_key));
    try std.testing.expectError(error.InvalidKeySize, async_crypto.encryptAsyncWithTimeout("data", &short_key, 50));
}

test "async decrypt rejects tampered ciphertext and wrong key" {
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_key = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x33);
        break :blk bytes;
    };
    const wrong_key = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x44);
        break :blk bytes;
    };

    const encrypted = try async_crypto.encryptAsync("authenticated data", &test_key);
    defer std.testing.allocator.free(encrypted);

    var tampered = try std.testing.allocator.dupe(u8, encrypted);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x80;

    try std.testing.expectError(error.DecryptionFailed, async_crypto.decryptAsync(tampered, &test_key));
    try std.testing.expectError(error.DecryptionFailed, async_crypto.decryptAsync(encrypted, &wrong_key));
}

test "async hash matches synchronous sha256" {
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_data = "hash me through async wrapper";

    const async_hash = try async_crypto.hashAsync(test_data);
    const sync_hash = hash.sha256(test_data);

    try std.testing.expectEqualSlices(u8, &sync_hash, &async_hash);
}

test "async hash batch" {
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_data = [_][]const u8{ "hash1", "hash2", "hash3" };

    const hashes = try async_crypto.hashBatchAsync(&test_data);
    defer std.testing.allocator.free(hashes);

    try std.testing.expect(hashes.len == test_data.len);

    for (hashes, test_data) |actual, data| {
        const expected = hash.sha256(data);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "encrypt with timeout" {
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_data = "timeout test data";
    const test_key = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0xEF);
        break :blk bytes;
    };

    const encrypted = try async_crypto.encryptAsyncWithTimeout(test_data, &test_key, 5000);
    defer std.testing.allocator.free(encrypted);

    try std.testing.expect(encrypted.len > test_data.len);
}

test "timeout parameter has no observable effect" {
    // Pins the documented behaviour: the timeout is ignored, so a zero timeout
    // must still return ciphertext rather than an error. If this ever starts
    // failing, the parameter became meaningful and the doc comment on
    // `encryptAsyncWithTimeout` is now wrong.
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();
    const async_crypto = AsyncCrypto.init(rt.io(), std.testing.allocator);
    const test_key: [32]u8 = @splat(0xEF);

    const with_zero = try async_crypto.encryptAsyncWithTimeout("same plaintext", &test_key, 0);
    defer std.testing.allocator.free(with_zero);
    const with_large = try async_crypto.encryptAsyncWithTimeout("same plaintext", &test_key, std.math.maxInt(u32));
    defer std.testing.allocator.free(with_large);

    try std.testing.expectEqual(with_zero.len, with_large.len);
}

fn batchEncryptUnderOom(allocator: std.mem.Allocator, io: Io) !void {
    const async_crypto = AsyncCrypto.init(io, allocator);
    const items = [_][]const u8{ "alpha", "beta", "gamma", "delta" };
    const key: [32]u8 = @splat(0x5A);

    const results = try async_crypto.batchEncryptAsync(&items, &key);
    defer {
        for (results) |item| allocator.free(item);
        allocator.free(results);
    }
}

test "batch encrypt frees partial results on allocation failure" {
    // `batchEncryptAsync` allocates the result slice, then one buffer per item.
    // A failure partway through must release the buffers already produced as
    // well as the slice itself. checkAllAllocationFailures re-runs the body
    // failing at every allocation index in turn and reports a leak at any of
    // them, which is the only way to exercise each errdefer separately.
    var rt = zsync.Runtime.init(std.testing.allocator, .{});
    defer rt.deinit();

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        batchEncryptUnderOom,
        .{rt.io()},
    );
}
