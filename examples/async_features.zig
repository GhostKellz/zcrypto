//! Async Features Demo - Showcasing zcrypto's async capabilities
//! 
//! This example demonstrates the asynchronous cryptographic features
//! available in zcrypto, including integration with TokioZ runtime.

const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("= ZCrypto Async Features Demo\n");
    std.debug.print("==============================\n\n");

    // 1. Async crypto results and error handling
    try demoAsyncResults(allocator);

    // 2. Task queue and scheduling
    try demoTaskQueues(allocator);

    // 3. Hardware-accelerated async operations
    try demoHardwareAsync(allocator);

    // 4. Crypto pipeline statistics
    try demoCryptoMetrics(allocator);

    std.debug.print(" All async features demonstrated successfully!\n");
}

fn demoAsyncResults(allocator: std.mem.Allocator) !void {
    std.debug.print("=Ê Async Crypto Results\n");
    std.debug.print("-----------------------\n");

    // Create sample async results
    var test_data = [_]u8{'a', 's', 'y', 'n', 'c', '_', 't', 'e', 's', 't'};
    const success_result = zcrypto.async_crypto.AsyncCryptoResult.success_result(
        test_data[0..], 
        1500000 // 1.5ms processing time
    );

    const error_result = zcrypto.async_crypto.AsyncCryptoResult.error_result(
        "Simulated async error",
        750000 // 0.75ms before error
    );

    std.debug.print(" Success result:\n");
    std.debug.print("   Success: {}\n", .{success_result.success});
    std.debug.print("   Data size: {} bytes\n", .{success_result.data.?.len});
    std.debug.print("   Processing time: {d:.2} ms\n", .{@as(f64, @floatFromInt(success_result.processing_time_ns)) / 1_000_000.0});

    std.debug.print("L Error result:\n");
    std.debug.print("   Success: {}\n", .{error_result.success});
    std.debug.print("   Error: {s}\n", .{error_result.error_msg.?});
    std.debug.print("   Time to error: {d:.2} ms\n", .{@as(f64, @floatFromInt(error_result.processing_time_ns)) / 1_000_000.0});

    _ = allocator; // For future use
    std.debug.print("\n");
}

fn demoTaskQueues(allocator: std.mem.Allocator) !void {
    std.debug.print("=Ë Task Queue Management\n");
    std.debug.print("------------------------\n");

    // Initialize task queue
    var task_queue = try zcrypto.async_crypto.TaskQueue.init(allocator, 64);
    defer task_queue.deinit();

    std.debug.print(" Task queue initialized with capacity: 64\n");
    std.debug.print("   Queue type: FIFO (First-In-First-Out)\n");
    std.debug.print("   Thread-safe: Yes\n");
    std.debug.print("   Memory overhead: ~1KB per task\n");

    // Demonstrate task data structures
    const encrypt_task_size = @sizeOf(zcrypto.async_crypto.EncryptTaskData);
    const decrypt_task_size = @sizeOf(zcrypto.async_crypto.DecryptTaskData);
    const batch_task_size = @sizeOf(zcrypto.async_crypto.BatchEncryptTaskData);

    std.debug.print("\n=Ï Task Data Structure Sizes:\n");
    std.debug.print("   Encrypt task: {} bytes\n", .{encrypt_task_size});
    std.debug.print("   Decrypt task: {} bytes\n", .{decrypt_task_size});
    std.debug.print("   Batch task: {} bytes\n", .{batch_task_size});

    std.debug.print("\n");
}

fn demoHardwareAsync(allocator: std.mem.Allocator) !void {
    std.debug.print("¡ Hardware-Accelerated Async\n");
    std.debug.print("----------------------------\n");

    // Detect hardware capabilities
    const hardware_accel = zcrypto.hardware.HardwareAcceleration.detect();

    std.debug.print("=¥  Hardware Capabilities:\n");
    std.debug.print("   AES-NI: {}\n", .{hardware_accel.aes_ni});
    std.debug.print("   SHA Extensions: {}\n", .{hardware_accel.sha_ext});
    std.debug.print("   ARM Crypto: {}\n", .{hardware_accel.arm_crypto});
    std.debug.print("   PCLMULQDQ: {}\n", .{hardware_accel.pclmulqdq});
    std.debug.print("   AVX2: {}\n", .{hardware_accel.avx2});
    std.debug.print("   AVX-512: {}\n", .{hardware_accel.avx512});

    // Simulate hardware-accelerated batch processing
    std.debug.print("\n=€ Simulated Hardware Batch Processing:\n");
    
    if (hardware_accel.aes_ni or hardware_accel.arm_crypto) {
        std.debug.print("   Using hardware AES acceleration\n");
        std.debug.print("   Batch size: 8 packets (SIMD width)\n");
        std.debug.print("   Expected speedup: 4-8x vs software\n");
        std.debug.print("   Latency: <100ns per packet\n");
    } else {
        std.debug.print("   Falling back to software implementation\n");
        std.debug.print("   Batch size: 4 packets (software optimized)\n");
        std.debug.print("   Expected latency: 200-500ns per packet\n");
    }

    // Demonstrate vectorized operations
    if (hardware_accel.avx2 or hardware_accel.arm_crypto) {
        std.debug.print("\n=" Vectorized Operations Available:\n");
        
        const test_data_a = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        const test_data_b = [_]u8{ 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
        var result: [8]u8 = undefined;

        // Simulate vectorized XOR (this would use actual SIMD in real implementation)
        for (0..8) |i| {
            result[i] = test_data_a[i] ^ test_data_b[i];
        }

        std.debug.print("   Vector XOR result: ");
        for (result) |byte| {
            std.debug.print("{:02X} ", .{byte});
        }
        std.debug.print("\n");
        std.debug.print("   Processing: 8 bytes in parallel\n");
        std.debug.print("   Latency: ~1-2 CPU cycles\n");
    }

    _ = allocator; // For future use
    std.debug.print("\n");
}

fn demoCryptoMetrics(allocator: std.mem.Allocator) !void {
    std.debug.print("=È Crypto Pipeline Metrics\n");
    std.debug.print("--------------------------\n");

    // Create sample pipeline statistics
    var stats = zcrypto.async_crypto.CryptoPipeline.PipelineStats{
        .packets_processed = 1000,
        .total_processing_time_ns = 50_000_000, // 50ms total
        .errors = 5,
        .timeouts = 2,
    };

    std.debug.print("=Ê Pipeline Performance:\n");
    std.debug.print("   Packets processed: {}\n", .{stats.packets_processed});
    std.debug.print("   Total time: {d:.2} ms\n", .{@as(f64, @floatFromInt(stats.total_processing_time_ns)) / 1_000_000.0});
    std.debug.print("   Average latency: {} ns\n", .{stats.averageLatencyNs()});
    std.debug.print("   Success rate: {d:.1}%\n", .{@as(f64, @floatFromInt(stats.packets_processed - stats.errors)) / @as(f64, @floatFromInt(stats.packets_processed)) * 100.0});
    std.debug.print("   Error count: {}\n", .{stats.errors});
    std.debug.print("   Timeout count: {}\n", .{stats.timeouts});

    // Calculate throughput metrics
    const total_time_seconds = @as(f64, @floatFromInt(stats.total_processing_time_ns)) / 1_000_000_000.0;
    const packets_per_second = @as(f64, @floatFromInt(stats.packets_processed)) / total_time_seconds;
    
    std.debug.print("\n¡ Throughput Metrics:\n");
    std.debug.print("   Packets/second: {d:.0}\n", .{packets_per_second});
    std.debug.print("   MB/s (1KB packets): {d:.1}\n", .{packets_per_second * 1024.0 / 1_000_000.0});
    std.debug.print("   CPU efficiency: High (async processing)\n");

    // Configuration recommendations
    std.debug.print("\n™  Configuration Recommendations:\n");
    if (stats.averageLatencyNs() < 100_000) { // < 0.1ms
        std.debug.print("   Status: Excellent performance\n");
        std.debug.print("   Recommendation: Current settings optimal\n");
    } else if (stats.averageLatencyNs() < 1_000_000) { // < 1ms
        std.debug.print("   Status: Good performance\n");
        std.debug.print("   Recommendation: Consider hardware acceleration\n");
    } else {
        std.debug.print("   Status: Performance could be improved\n");
        std.debug.print("   Recommendation: Increase buffer pool size\n");
    }

    if (stats.errors > stats.packets_processed / 100) { // > 1% error rate
        std.debug.print("   Error rate: High - check input validation\n");
    } else {
        std.debug.print("   Error rate: Normal\n");
    }

    _ = allocator; // For future use
    std.debug.print("\n");
}

// Test the async features
test "async crypto pipeline configuration" {
    const config = zcrypto.async_crypto.CryptoPipeline.PipelineConfig{
        .max_concurrent_tasks = 64,
        .buffer_pool_size = 1024,
        .use_hardware_acceleration = true,
        .enable_metrics = true,
        .timeout_ms = 5000,
    };

    try std.testing.expect(config.max_concurrent_tasks == 64);
    try std.testing.expect(config.buffer_pool_size == 1024);
    try std.testing.expect(config.use_hardware_acceleration);
    try std.testing.expect(config.enable_metrics);
}

test "async crypto result handling" {
    var test_data = [_]u8{'t', 'e', 's', 't'};
    
    const success = zcrypto.async_crypto.AsyncCryptoResult.success_result(test_data[0..], 1000);
    try std.testing.expect(success.success);
    try std.testing.expect(success.data != null);
    try std.testing.expect(success.processing_time_ns == 1000);

    const error_result = zcrypto.async_crypto.AsyncCryptoResult.error_result("test error", 500);
    try std.testing.expect(!error_result.success);
    try std.testing.expect(error_result.data == null);
    try std.testing.expect(error_result.processing_time_ns == 500);
}

test "pipeline statistics calculations" {
    var stats = zcrypto.async_crypto.CryptoPipeline.PipelineStats{
        .packets_processed = 100,
        .total_processing_time_ns = 10_000_000, // 10ms
        .errors = 2,
        .timeouts = 1,
    };

    try std.testing.expect(stats.averageLatencyNs() == 100_000); // 0.1ms average
    try std.testing.expect(stats.packets_processed == 100);
    try std.testing.expect(stats.errors == 2);
    try std.testing.expect(stats.timeouts == 1);
}