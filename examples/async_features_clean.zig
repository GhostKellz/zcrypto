//! Async Features Demo - Showcasing zcrypto's async capabilities
//!
//! This example demonstrates the asynchronous cryptographic features
//! available in zcrypto, including integration with zsync runtime.

const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("ZCrypto Async Features Demo\n");
    std.debug.print("==============================\n\n");

    // 1. Async crypto results and error handling
    try demoAsyncResults(allocator);

    std.debug.print("All async features demonstrated successfully!\n");
}

fn demoAsyncResults(allocator: std.mem.Allocator) !void {
    std.debug.print("Async Crypto Results\n");
    std.debug.print("-----------------------\n");

    // Create sample async results
    var test_data = [_]u8{ 'a', 's', 'y', 'n', 'c', '_', 't', 'e', 's', 't' };
    const success_result = zcrypto.async_crypto.AsyncCryptoResult.success_result(test_data[0..], 1500000 // 1.5ms processing time
    );

    const error_result = zcrypto.async_crypto.AsyncCryptoResult.error_result("Simulated async error", 750000 // 0.75ms before error
    );

    std.debug.print("Success result:\n");
    if (success_result.data) |data| {
        std.debug.print("  Data size: {} bytes\n", .{data.len});
    }
    std.debug.print("  Processing time: {d:.2} ms\n", .{@as(f64, @floatFromInt(success_result.execution_time_ns)) / 1_000_000.0});

    std.debug.print("Error result:\n");
    if (error_result.error_message) |msg| {
        std.debug.print("  Error: {s}\n", .{msg});
    }
    std.debug.print("  Time to error: {d:.2} ms\n", .{@as(f64, @floatFromInt(error_result.execution_time_ns)) / 1_000_000.0});

    _ = allocator; // For future use
    std.debug.print("\n");
}
