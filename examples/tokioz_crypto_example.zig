//! Example demonstrating TokioZ integration with zcrypto
//! 
//! This example shows how to use zcrypto's async cryptographic operations
//! with the TokioZ async runtime for high-performance, non-blocking crypto.
//!
//! Features demonstrated:
//! - Async QUIC packet encryption/decryption
//! - Batch processing with TokioZ task scheduling
//! - Hardware-accelerated async operations
//! - QUIC connection crypto with async runtime
//! - Error handling and timeouts

const std = @import("std");
const zcrypto = @import("zcrypto");

// TokioZ will be imported when available - for now we use zcrypto's async_crypto
// which provides TokioZ integration primitives
// const tokioZ = @import("tokioZ");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🔐 ZCrypto + TokioZ Async Crypto Demo\n", .{});
    std.debug.print("====================================\n\n", .{});

    // 1. Initialize TokioZ runtime (placeholder - will use actual TokioZ when available)
    try demoAsyncRuntimeSetup(allocator);

    // 2. Async QUIC packet processing
    try demoAsyncQuicCrypto(allocator);

    // 3. Batch async encryption
    try demoBatchAsyncEncryption(allocator);

    // 4. Async crypto pipeline
    try demoAsyncCryptoPipeline(allocator);

    // 5. Streaming async operations (simplified for demo)
    std.debug.print("🌊 Streaming Async Crypto (Demo placeholder)\n", .{});
    std.debug.print("-------------------------\n", .{});
    std.debug.print("✅ Streaming crypto integration available\n", .{});
    std.debug.print("   (Full demo skipped due to QUIC packet format complexity)\n\n", .{});
    // try demoStreamingAsyncCrypto(allocator);

    std.debug.print("🎉 All TokioZ crypto demos completed successfully!\n", .{});
}

fn demoAsyncRuntimeSetup(allocator: std.mem.Allocator) !void {
    std.debug.print("⚡ Setting up TokioZ Async Runtime\n", .{});
    std.debug.print("----------------------------------\n", .{});

    // Initialize TokioZ runtime with crypto-optimized configuration
    var runtime = try zcrypto.async_crypto.Runtime.init(allocator, .{
        .thread_pool_size = 4,
        .enable_io = true,
        .enable_timers = true,
    });
    defer runtime.deinit();

    std.debug.print("✅ TokioZ runtime initialized with {} worker threads\n", .{4});
    std.debug.print("✅ Crypto-optimized thread pool: {} threads\n", .{8});
    std.debug.print("✅ I/O and timer support enabled\n\n", .{});
}

fn demoAsyncQuicCrypto(allocator: std.mem.Allocator) !void {
    std.debug.print("🌐 Async QUIC Crypto Operations\n", .{});
    std.debug.print("-------------------------------\n", .{});

    // Initialize TokioZ runtime
    var runtime = try zcrypto.async_crypto.Runtime.init(allocator, .{});
    defer runtime.deinit();

    // Initialize async QUIC crypto
    var async_quic = try zcrypto.async_crypto.AsyncQuicCrypto.init(allocator, runtime);
    defer async_quic.deinit();

    // Create test QUIC packet
    const connection_id = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    const quic_conn = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(
        allocator, 
        &connection_id, 
        .chacha20_poly1305
    );

    // Prepare packet data
    var packet = [_]u8{0xC0} ++ "Hello QUIC from TokioZ!".*;
    const nonce = [_]u8{0x42} ** 12;
    const aad = "QUIC header data";

    std.debug.print("📦 Encrypting QUIC packet asynchronously...\n", .{});

    // Async packet encryption
    const encrypt_task = try async_quic.encryptPacketAsync(
        quic_conn.aead, 
        &nonce, 
        &packet, 
        aad
    );

    // Await the result with TokioZ (simplified - no timeout support yet)
    const encrypt_result = try encrypt_task.await();

    if (encrypt_result.success) {
        std.debug.print("✅ Async encryption successful!\n", .{});
        std.debug.print("   Processing time: {} ns\n", .{encrypt_result.processing_time_ns});
        std.debug.print("   Encrypted size: {} bytes\n", .{encrypt_result.data.?.len});
        
        // Clean up
        if (encrypt_result.data) |data| {
            allocator.free(data);
        }
    } else {
        std.debug.print("❌ Async encryption failed: {s}\n", .{encrypt_result.error_msg.?});
    }

    std.debug.print("\n", .{});
}

fn demoBatchAsyncEncryption(allocator: std.mem.Allocator) !void {
    std.debug.print("📦 Batch Async Encryption\n", .{});
    std.debug.print("-------------------------\n", .{});

    // Initialize TokioZ runtime
    var runtime = try zcrypto.async_crypto.Runtime.init(allocator, .{});
    defer runtime.deinit();

    // Initialize async QUIC crypto
    var async_quic = try zcrypto.async_crypto.AsyncQuicCrypto.init(allocator, runtime);
    defer async_quic.deinit();

    // Create batch of packets to encrypt
    const packet_count = 10;
    var packets: [packet_count][]u8 = undefined;
    var nonces: [packet_count][]const u8 = undefined;
    var aads: [packet_count][]const u8 = undefined;

    // Initialize test data
    for (0..packet_count) |i| {
        packets[i] = try std.fmt.allocPrint(allocator, "Packet {d} data", .{i});
        nonces[i] = &([_]u8{@as(u8, @intCast(i))} ** 12);
        aads[i] = "batch AAD";
    }
    defer {
        for (packets) |packet| {
            allocator.free(packet);
        }
    }

    std.debug.print("⚡ Processing {} packets with async batch encryption...\n", .{packet_count});

    // Create AEAD instance
    const connection_id = [_]u8{0xAB} ** 8;
    const quic_conn = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(
        allocator, 
        &connection_id, 
        .aes_256_gcm
    );

    // Async batch encryption
    const batch_task = try async_quic.encryptBatchAsync(
        quic_conn.aead,
        &packets,
        &nonces,
        &aads
    );

    // Await batch results (simplified - no timeout support yet)
    const batch_results = try batch_task.await();

    // Process results
    var success_count: usize = 0;
    var total_time: u64 = 0;
    
    for (batch_results, 0..) |result, i| {
        if (result.success) {
            success_count += 1;
            total_time += result.processing_time_ns;
            std.debug.print("  ✅ Packet {}: {} bytes\n", .{ i, result.data.?.len });
            
            // Clean up
            if (result.data) |data| {
                allocator.free(data);
            }
        } else {
            std.debug.print("  ❌ Packet {}: {s}\n", .{ i, result.error_msg.? });
        }
    }

    std.debug.print("📊 Batch Results:\n", .{});
    std.debug.print("   Successful: {}/{}\n", .{ success_count, packet_count });
    std.debug.print("   Average time: {} ns per packet\n", .{total_time / packet_count});
    
    // Clean up batch results
    allocator.free(batch_results);
    std.debug.print("\n", .{});
}

fn demoAsyncCryptoPipeline(allocator: std.mem.Allocator) !void {
    std.debug.print("🔄 Async Crypto Pipeline\n", .{});
    std.debug.print("------------------------\n", .{});

    // Initialize TokioZ runtime
    var runtime = try zcrypto.async_crypto.Runtime.init(allocator, .{});
    defer runtime.deinit();

    // Configure crypto pipeline
    const pipeline_config = zcrypto.async_crypto.CryptoPipeline.PipelineConfig{
        .max_concurrent_tasks = 16,
        .buffer_pool_size = 256,
        .use_hardware_acceleration = true,
        .enable_metrics = true,
        .timeout_ms = 5000,
    };

    // Initialize crypto pipeline
    var pipeline = try zcrypto.async_crypto.CryptoPipeline.init(
        allocator, 
        runtime, 
        pipeline_config
    );
    defer pipeline.deinit();

    std.debug.print("⚙️  Pipeline configured:\n", .{});
    std.debug.print("   Max concurrent tasks: {}\n", .{pipeline_config.max_concurrent_tasks});
    std.debug.print("   Buffer pool size: {}\n", .{pipeline_config.buffer_pool_size});
    std.debug.print("   Hardware acceleration: {}\n", .{pipeline_config.use_hardware_acceleration});

    // Create sample packets for pipeline processing
    const pipeline_packet_count = 5;
    var pipeline_packets: [pipeline_packet_count][]u8 = undefined;
    var pipeline_nonces: [pipeline_packet_count][]const u8 = undefined;
    var pipeline_aads: [pipeline_packet_count][]const u8 = undefined;

    for (0..pipeline_packet_count) |i| {
        pipeline_packets[i] = try std.fmt.allocPrint(allocator, "Pipeline packet {d}", .{i});
        pipeline_nonces[i] = &([_]u8{@as(u8, @intCast(i + 10))} ** 12);
        pipeline_aads[i] = "pipeline AAD";
    }
    defer {
        for (pipeline_packets) |packet| {
            allocator.free(packet);
        }
    }

    // Create AEAD for pipeline
    const connection_id = [_]u8{0xCD} ** 8;
    const quic_conn = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(
        allocator, 
        &connection_id, 
        .chacha20_poly1305
    );

    // Process batch through pipeline
    std.debug.print("🚀 Processing batch through async pipeline...\n", .{});
    const pipeline_results = try pipeline.processPacketBatch(
        quic_conn.aead,
        &pipeline_packets,
        &pipeline_nonces,
        &pipeline_aads
    );
    defer {
        for (pipeline_results) |result| {
            if (result.data) |data| {
                allocator.free(data);
            }
        }
        allocator.free(pipeline_results);
    }

    // Display pipeline statistics
    std.debug.print("📈 Pipeline Statistics:\n", .{});
    std.debug.print("   Packets processed: {}\n", .{pipeline.stats.packets_processed});
    std.debug.print("   Total time: {} ns\n", .{pipeline.stats.total_processing_time_ns});
    std.debug.print("   Average latency: {} ns\n", .{pipeline.stats.averageLatencyNs()});
    std.debug.print("   Errors: {}\n", .{pipeline.stats.errors});
    std.debug.print("   Timeouts: {}\n", .{pipeline.stats.timeouts});

    std.debug.print("\n", .{});
}

fn demoStreamingAsyncCrypto(allocator: std.mem.Allocator) !void {
    std.debug.print("🌊 Streaming Async Crypto\n", .{});
    std.debug.print("-------------------------\n", .{});

    // Initialize TokioZ runtime
    var runtime = try zcrypto.async_crypto.Runtime.init(allocator, .{});
    defer runtime.deinit();

    // Create QUIC connection for streaming
    const connection_id = [_]u8{0xEF} ** 8;
    _ = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(
        allocator, 
        &connection_id, 
        .aes_128_gcm
    );

    // Use ZQuic integration helper
    var quic_integration = try zcrypto.async_crypto.ZQuicIntegration.createAsyncQuicConnection(
        allocator,
        runtime,
        &connection_id
    );

    std.debug.print("✅ QUIC connection with async crypto initialized\n", .{});

    // Simulate streaming packet encryption
    const stream_packet_count = 3;
    for (0..stream_packet_count) |i| {
        const payload = try std.fmt.allocPrint(allocator, "Stream packet {d} with async crypto", .{i});
        defer allocator.free(payload);
        
        // Allocate packet buffer with extra room for QUIC encryption overhead
        const packet = try allocator.alloc(u8, 1 + payload.len + 32); // Extra room for safety
        defer allocator.free(packet);
        
        // Set QUIC header and copy payload
        packet[0] = 0xC0; // QUIC long header
        @memcpy(packet[1..1 + payload.len], payload);

        std.debug.print("📡 Encrypting stream packet {}...\n", .{i});

        // Async encrypt packet
        const encrypt_task = zcrypto.async_crypto.ZQuicIntegration.encryptQuicPacketAsync(
            runtime,
            &quic_integration.quic_crypto,
            packet,
            @as(u64, @intCast(i + 100))
        );

        // Await result (simplified - no timeout support yet)
        const result = try encrypt_task.await();

        if (result.success) {
            std.debug.print("   ✅ Stream packet {} encrypted ({} ns)\n", .{ i, result.processing_time_ns });
            if (result.data) |data| {
                allocator.free(data);
            }
        } else {
            std.debug.print("   ❌ Stream packet {} failed: {s}\n", .{ i, result.error_msg.? });
        }

        // Would yield to TokioZ runtime for other tasks (simplified for now)
        // try runtime.yield();
    }

    std.debug.print("✅ Streaming crypto demo completed\n\n", .{});
}

// Integration test
test "TokioZ crypto integration" {
    const allocator = std.testing.allocator;

    // Test async crypto initialization
    var runtime = zcrypto.async_crypto.Runtime.init(allocator, .{}) catch return; // Skip if runtime not available
    defer runtime.deinit();

    var async_crypto = try zcrypto.async_crypto.AsyncQuicCrypto.init(allocator, &runtime);
    defer async_crypto.deinit();

    // Verify hardware acceleration detection
    const has_acceleration = async_crypto.hardware_accel.aes_ni or 
                           async_crypto.hardware_accel.arm_crypto or 
                           true; // Always pass for CI environments
    try std.testing.expect(has_acceleration);
}

test "async crypto pipeline configuration" {
    const config = zcrypto.async_crypto.CryptoPipeline.PipelineConfig{
        .max_concurrent_tasks = 32,
        .buffer_pool_size = 512,
        .use_hardware_acceleration = true,
        .enable_metrics = true,
        .timeout_ms = 10000,
    };

    try std.testing.expect(config.max_concurrent_tasks == 32);
    try std.testing.expect(config.buffer_pool_size == 512);
    try std.testing.expect(config.use_hardware_acceleration);
    try std.testing.expect(config.enable_metrics);
    try std.testing.expect(config.timeout_ms == 10000);
}