# 🔐 ZCrypto Examples

This directory contains comprehensive examples demonstrating zcrypto's features, including TokioZ async integration and advanced cryptographic operations.

## 📋 Available Examples

### 1. 🚀 TokioZ Crypto Integration (`tokioz_crypto_example.zig`)

**The primary example for TokioZ async crypto operations.**

Demonstrates:
- ⚡ Async QUIC packet encryption/decryption with TokioZ runtime
- 📦 Batch processing with async pipelines
- 🔄 Hardware-accelerated async operations
- 🌊 Streaming crypto operations
- ⏱️ Timeout and error handling
- 📊 Performance metrics and monitoring

**Key Features:**
- **Async Runtime Setup**: Configure TokioZ for crypto-optimized performance
- **QUIC Integration**: Non-blocking QUIC packet crypto operations
- **Batch Processing**: High-throughput batch encryption with SIMD acceleration
- **Pipeline Architecture**: Structured async crypto pipelines with metrics
- **Streaming Operations**: Continuous packet processing with yield points

### 2. 🎯 Advanced Features (`advanced_features.zig`)

Comprehensive demonstration of zcrypto's advanced capabilities:
- 🏎️ Hardware acceleration detection and usage
- 🌐 QUIC cryptographic operations
- 🔮 Post-quantum cryptography (ML-KEM, ML-DSA)
- 🔄 Enhanced key exchange protocols
- 🌐 Hybrid cryptography (classical + post-quantum)

### 3. 🔄 Async Features (`async_features.zig`)

Deep dive into zcrypto's async capabilities:
- 📊 Async result handling and error management
- 📋 Task queue management and scheduling
- ⚡ Hardware-accelerated async operations
- 📈 Pipeline metrics and performance analysis

## 🚀 Running the Examples

### Prerequisites

Ensure you have:
- **Zig 0.15.0-dev.822+** or later
- **TokioZ dependency** (automatically fetched)

### Build and Run

```bash
# Build all examples
zig build

# Run TokioZ crypto example
zig build run-tokioz

# Run advanced features example  
zig build run-advanced

# Run the main demo
zig build run

# Run tests
zig build test
```

### Individual Example Compilation

```bash
# Compile TokioZ example directly
zig build-exe examples/tokioz_crypto_example.zig --dep zcrypto --dep tokioZ

# Compile advanced features example
zig build-exe examples/advanced_features.zig --dep zcrypto
```

## 📖 TokioZ Integration Guide

### Basic Async Setup

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize TokioZ runtime
    var runtime = try zcrypto.async_crypto.Runtime.init(allocator, .{
        .worker_threads = 4,
        .crypto_thread_pool_size = 8,
    });
    defer runtime.deinit();

    // Initialize async crypto
    var async_crypto = try zcrypto.async_crypto.AsyncQuicCrypto.init(allocator, &runtime);
    defer async_crypto.deinit();
    
    // Your async crypto operations here...
}
```

### Async QUIC Packet Processing

```zig
// Encrypt packet asynchronously
const encrypt_task = try async_crypto.encryptPacketAsync(
    aead, nonce, packet_data, additional_data
);

// Await result with timeout
const result = try runtime.timeout(
    zcrypto.async_crypto.Task(zcrypto.async_crypto.AsyncCryptoResult),
    5000, // 5 second timeout
    encrypt_task
);

if (result.result.success) {
    std.debug.print("Encrypted {} bytes in {} ns\n", 
        .{ result.result.data.?.len, result.result.processing_time_ns });
}
```

### Batch Processing

```zig
// Process multiple packets in parallel
const batch_task = try async_crypto.encryptBatchAsync(
    aead, packets, nonces, aads
);

const batch_results = try runtime.timeout(
    zcrypto.async_crypto.Task([]zcrypto.async_crypto.AsyncCryptoResult),
    10000,
    batch_task
);

// Process results
for (batch_results.result, 0..) |result, i| {
    if (result.success) {
        std.debug.print("Packet {}: {} bytes encrypted\n", .{ i, result.data.?.len });
    }
}
```

### Crypto Pipeline

```zig
// Create high-level crypto pipeline
var pipeline = try zcrypto.async_crypto.CryptoPipeline.init(allocator, &runtime, .{
    .max_concurrent_tasks = 32,
    .buffer_pool_size = 1024,
    .use_hardware_acceleration = true,
    .enable_metrics = true,
});
defer pipeline.deinit();

// Process batch through pipeline
const results = try pipeline.processPacketBatch(aead, packets, nonces, aads);

// Check performance metrics
std.debug.print("Average latency: {} ns\n", .{pipeline.stats.averageLatencyNs()});
std.debug.print("Packets/second: {}\n", .{pipeline.stats.packets_processed});
```

## 🔧 Configuration Options

### TokioZ Runtime Configuration

```zig
const runtime_config = .{
    .worker_threads = 4,                    // Number of worker threads
    .enable_io = true,                      // Enable I/O operations  
    .enable_time = true,                    // Enable timer support
    .crypto_thread_pool_size = 8,           // Crypto-specific thread pool
    .max_blocking_threads = 16,             // Max blocking operation threads
    .thread_keep_alive_ms = 10000,          // Thread keep-alive time
};
```

### Crypto Pipeline Configuration

```zig
const pipeline_config = zcrypto.async_crypto.CryptoPipeline.PipelineConfig{
    .max_concurrent_tasks = 64,             // Max parallel tasks
    .buffer_pool_size = 1024,               // Buffer pool size
    .use_hardware_acceleration = true,      // Enable HW acceleration
    .enable_metrics = true,                 // Enable performance metrics
    .timeout_ms = 5000,                     // Default timeout
};
```

## 📊 Performance Benchmarks

Expected performance with TokioZ integration:

| Operation | Latency | Throughput | Notes |
|-----------|---------|------------|-------|
| QUIC Packet Encrypt | < 100ns | 1M+ packets/sec | With AES-NI |
| Batch Encryption (8) | < 500ns | 8M+ packets/sec | SIMD optimized |
| Post-Quantum KEM | < 50μs | 20K+ ops/sec | ML-KEM-768 |
| Pipeline Processing | < 1ms | Variable | Depends on batch size |

*Benchmarks on modern x86_64 with hardware acceleration*

## 🛠️ Troubleshooting

### Common Issues

**TokioZ not found:**
```bash
zig fetch --save https://github.com/ghostkellz/tokioZ/archive/main.tar.gz
```

**Build errors:**
- Ensure Zig version is 0.15.0-dev.822 or later
- Check that all dependencies are properly fetched
- Verify build.zig.zon includes tokioZ dependency

**Performance issues:**
- Enable hardware acceleration: `-Denable_asm=true`
- Use release mode: `-Doptimize=ReleaseFast`
- Increase buffer pool sizes for high throughput

**Runtime errors:**
- Check async operation timeouts
- Verify proper resource cleanup (defer statements)
- Monitor memory usage with large batch sizes

## 🔗 Related Documentation

- [ZCrypto API Documentation](../API.md)
- [Integration Guide](../INTEGRATION.md)
- [TokioZ GitHub Repository](https://github.com/ghostkellz/tokioZ)
- [QUIC Crypto Specification](../DOCS.md#quic-crypto)
- [Post-Quantum Cryptography Guide](../DOCS.md#post-quantum)

## 📈 Advanced Usage

For production applications:

1. **Connection Pooling**: Use `zcrypto.pool_crypto` for connection reuse
2. **Hardware Optimization**: Enable all available CPU extensions
3. **Memory Management**: Use buffer pools for zero-copy operations
4. **Monitoring**: Implement metrics collection for performance tuning
5. **Error Handling**: Implement comprehensive error recovery strategies

---

**Ready to integrate TokioZ with zcrypto? Start with `tokioz_crypto_example.zig`!**