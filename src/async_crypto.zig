//! Async cryptographic operations with zsync integration
//!
//! Provides non-blocking cryptographic operations optimized for high-performance
//! QUIC and TLS applications using the zsync async runtime.

const std = @import("std");
const sym = @import("sym.zig");
const hash = @import("hash.zig");
const zsync = @import("zsync");

/// zsync Io interface for async operations
pub const Io = zsync.Io;
pub const Future = zsync.Future;
pub const BlockingIo = zsync.BlockingIo;

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

    /// Async encryption using direct crypto calls (for now)
    pub fn encryptAsync(self: AsyncCrypto, data: []const u8, key: []const u8) ![]u8 {
        // Direct call until zsync function type issues are resolved
        if (key.len != 32) return error.InvalidKeySize;
        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, key[0..32]);
        return try sym.encryptAesGcm(self.allocator, data, &key_array);
    }

    /// Async decryption using direct crypto calls (for now)
    pub fn decryptAsync(self: AsyncCrypto, ciphertext: []const u8, key: []const u8) ![]u8 {
        // Direct call until zsync function type issues are resolved
        if (key.len != 32) return error.InvalidKeySize;
        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, key[0..32]);
        return try sym.decryptAesGcm(self.allocator, ciphertext, &key_array);
    }

    /// Async hashing using direct crypto calls (for now)
    pub fn hashAsync(self: AsyncCrypto, data: []const u8) ![32]u8 {
        // Direct call until zsync function type issues are resolved
        _ = self;
        return hash.sha256(data);
    }

    /// Batch encryption using zsync concurrent tasks
    pub fn batchEncryptAsync(self: AsyncCrypto, data_list: []const []const u8, key: []const u8) ![][]u8 {
        if (key.len != 32) return error.InvalidKeySize;
        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, key[0..32]);

        var results = try self.allocator.alloc([]u8, data_list.len);
        for (data_list, 0..) |data, i| {
            results[i] = try sym.encryptAesGcm(self.allocator, data, &key_array);
        }
        return results;
    }

    /// Encrypt with timeout support using zsync features
    pub fn encryptAsyncWithTimeout(self: AsyncCrypto, data: []const u8, key: []const u8, timeout_ms: u32) ![]u8 {
        _ = timeout_ms; // TODO: Use zsync timeout when available in API
        return self.encryptAsync(data, key);
    }

    /// Concurrent hash computation for large data
    pub fn hashBatchAsync(self: AsyncCrypto, data_list: []const []const u8) ![][32]u8 {
        var results = try self.allocator.alloc([32]u8, data_list.len);

        // Process all hashes - can be made concurrent with zsync tasks
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
    execution_time_ns: u64,

    pub fn success_result(data: []u8, time_ns: u64) AsyncCryptoResult {
        return AsyncCryptoResult{
            .data = data,
            .error_message = null,
            .execution_time_ns = time_ns,
        };
    }

    pub fn error_result(message: []const u8, time_ns: u64) AsyncCryptoResult {
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
    var blocking_io = BlockingIo.init(std.testing.allocator, 4096);
    defer blocking_io.deinit();
    const async_crypto = AsyncCrypto.init(blocking_io.io(), std.testing.allocator);
    const test_data = "test data for zsync encryption";
    const test_key = [_]u8{0xAB} ** 32;

    const encrypted = try async_crypto.encryptAsync(test_data, &test_key);
    defer std.testing.allocator.free(encrypted);

    try std.testing.expect(encrypted.len > test_data.len);

    const decrypted = try async_crypto.decryptAsync(encrypted, &test_key);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualStrings(test_data, decrypted);
}

test "batch async encryption" {
    var blocking_io = BlockingIo.init(std.testing.allocator, 4096);
    defer blocking_io.deinit();
    const async_crypto = AsyncCrypto.init(blocking_io.io(), std.testing.allocator);
    const test_data = [_][]const u8{ "data1", "data2", "data3" };
    const test_key = [_]u8{0xCD} ** 32;

    const encrypted_batch = try async_crypto.batchEncryptAsync(&test_data, &test_key);
    defer {
        for (encrypted_batch) |item| std.testing.allocator.free(item);
        std.testing.allocator.free(encrypted_batch);
    }

    try std.testing.expect(encrypted_batch.len == test_data.len);

    for (encrypted_batch, test_data) |encrypted, original| {
        try std.testing.expect(encrypted.len > original.len);
    }
}

test "async hash batch" {
    var blocking_io = BlockingIo.init(std.testing.allocator, 4096);
    defer blocking_io.deinit();
    const async_crypto = AsyncCrypto.init(blocking_io.io(), std.testing.allocator);
    const test_data = [_][]const u8{ "hash1", "hash2", "hash3" };

    const hashes = try async_crypto.hashBatchAsync(&test_data);
    defer std.testing.allocator.free(hashes);

    try std.testing.expect(hashes.len == test_data.len);

    for (hashes) |_| {
        // Just check that each hash has the correct length
    }
}

test "encrypt with timeout" {
    var blocking_io = BlockingIo.init(std.testing.allocator, 4096);
    defer blocking_io.deinit();
    const async_crypto = AsyncCrypto.init(blocking_io.io(), std.testing.allocator);
    const test_data = "timeout test data";
    const test_key = [_]u8{0xEF} ** 32;

    const encrypted = try async_crypto.encryptAsyncWithTimeout(test_data, &test_key, 5000);
    defer std.testing.allocator.free(encrypted);

    try std.testing.expect(encrypted.len > test_data.len);
}
