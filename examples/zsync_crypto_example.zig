//! zcrypto async examples using zsync runtime
//!
//! This example demonstrates various asynchronous cryptographic operations
//! available in zcrypto, including integration with zsync runtime.

const std = @import("std");
const zcrypto = @import("zcrypto");
const zsync = @import("zsync");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== zcrypto zsync Integration Demo ===", .{});

    // Initialize zsync with BlockingIo for simplicity
    var io = zsync.BlockingIo.init(allocator);

    try runAsyncCryptoExamples(io.io(), allocator);
}

fn runAsyncCryptoExamples(io: zsync.Io, allocator: std.mem.Allocator) !void {
    const async_crypto = zcrypto.async_crypto.AsyncCrypto.init(io, allocator);
    const test_data = "Hello, zsync async crypto!";
    const key = [_]u8{0x12} ** 32;

    std.log.info("Testing async encryption...", .{});

    // Single async encryption
    const encrypted = try async_crypto.encryptAsync(test_data, &key);
    defer allocator.free(encrypted);
    std.log.info("Encrypted: {} bytes", .{encrypted.len});

    const decrypted = try async_crypto.decryptAsync(encrypted, &key);
    defer allocator.free(decrypted);
    std.log.info("Decrypted: {s}", .{decrypted});

    // Batch async operations
    std.log.info("Testing batch async encryption...", .{});
    const batch_data = [_][]const u8{
        "Batch item 1",
        "Batch item 2",
        "Batch item 3",
        "Batch item 4",
    };

    const batch_encrypted = try async_crypto.batchEncryptAsync(&batch_data, &key);
    defer {
        for (batch_encrypted) |item| allocator.free(item);
        allocator.free(batch_encrypted);
    }

    std.log.info("Batch encrypted {} items", .{batch_encrypted.len});

    // Async hashing
    const hash_result = try async_crypto.hashAsync(test_data);
    std.log.info("Hash: {any}", .{hash_result});

    std.log.info("=== zsync Demo Complete ===", .{});
}
