//! Async Features Demo - Showcasing zcrypto's async capabilities
//!
//! This example demonstrates the asynchronous cryptographic features
//! available in zcrypto, including integration with zsync runtime.

const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("ZCrypto Async Features Demo\n", .{});
    std.debug.print("==============================\n\n", .{});

    // 1. Async crypto results and error handling
    try demoAsyncResults(allocator);

    std.debug.print("All async features demonstrated successfully!\n", .{});
}

fn demoAsyncResults(allocator: std.mem.Allocator) !void {
    std.debug.print("Async Crypto Results\n", .{});
    std.debug.print("-----------------------\n", .{});

    // Create sample async results
    var test_data = [_]u8{ 'a', 's', 'y', 'n', 'c', '_', 't', 'e', 's', 't' };
    const success_result = zcrypto.async_crypto.AsyncCryptoResult.success_result(
        test_data[0..],
        1500000, // 1.5ms processing time
    );

    const error_result = zcrypto.async_crypto.AsyncCryptoResult.error_result(
        "Simulated async error",
        750000, // 0.75ms before error
    );

    std.debug.print("Success result:\n", .{});
    if (success_result.data) |data| {
        std.debug.print("  Data size: {} bytes\n", .{data.len});
    }
    printDuration("  Processing time", success_result.execution_time_ns);

    std.debug.print("Error result:\n", .{});
    if (error_result.error_message) |msg| {
        std.debug.print("  Error: {s}\n", .{msg});
    }
    printDuration("  Time to error", error_result.execution_time_ns);

    _ = allocator; // For future use
    std.debug.print("\n", .{});
}

/// Print an elapsed time, or say plainly that there is none.
///
/// Written out rather than unwrapped with `.?` because this is the example a
/// consumer copies: `execution_time_ns` is optional precisely so an unreadable
/// clock cannot be mistaken for a measurement, and demonstrating the unwrap
/// would teach the habit the type exists to prevent.
fn printDuration(label: []const u8, ns: ?u64) void {
    if (ns) |value| {
        std.debug.print("{s}: {d:.2} ms\n", .{ label, @as(f64, @floatFromInt(value)) / 1_000_000.0 });
    } else {
        std.debug.print("{s}: unavailable (clock could not be read)\n", .{label});
    }
}
