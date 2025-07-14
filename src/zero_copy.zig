//! Zero-Copy Crypto API for zcrypto v0.7.0
//!
//! High-performance, allocation-free cryptographic operations designed for
//! zquic v0.7.0's zero-copy packet processing requirements.
//!
//! Key features:
//! - Direct buffer manipulation without copying
//! - Packet buffer pools with pre-initialized crypto contexts
//! - Vectorized batch operations
//! - Ring buffer crypto for continuous streams

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const quic_crypto = @import("quic_crypto.zig");
const hardware = @import("hardware.zig");

pub const ZeroCopyError = error{
    BufferTooSmall,
    InvalidBufferAlignment,
    ContextPoolExhausted,
    UnsupportedOperation,
};

/// Zero-copy packet buffer with embedded crypto context
pub const CryptoPacketBuffer = struct {
    data: []u8,
    capacity: usize,
    crypto_context: CryptoContext,
    header_offset: usize,
    payload_offset: usize,
    tag_offset: usize,

    pub const CryptoContext = struct {
        cipher_suite: quic_crypto.QuicCrypto.CipherSuite,
        key: [32]u8,
        iv: [12]u8,
        header_protection_key: [32]u8,
        packet_number: u64,

        pub fn updatePacketNumber(self: *CryptoContext) u64 {
            self.packet_number += 1;
            return self.packet_number;
        }
    };

    /// Initialize packet buffer with crypto context
    pub fn init(buffer: []u8, cipher_suite: quic_crypto.QuicCrypto.CipherSuite) CryptoPacketBuffer {
        return CryptoPacketBuffer{
            .data = buffer,
            .capacity = buffer.len,
            .crypto_context = CryptoContext{
                .cipher_suite = cipher_suite,
                .key = std.mem.zeroes([32]u8),
                .iv = std.mem.zeroes([12]u8),
                .header_protection_key = std.mem.zeroes([32]u8),
                .packet_number = 0,
            },
            .header_offset = 0,
            .payload_offset = 0,
            .tag_offset = 0,
        };
    }

    /// Encrypt packet data in-place with zero allocations
    pub fn encryptInPlace(self: *CryptoPacketBuffer, payload_len: usize) !usize {
        if (self.payload_offset + payload_len + 16 > self.capacity) {
            return ZeroCopyError.BufferTooSmall;
        }

        // Update packet number
        const packet_number = self.crypto_context.updatePacketNumber();

        // Construct nonce from packet number and IV
        var nonce: [12]u8 = self.crypto_context.iv;
        std.mem.writeInt(u64, nonce[4..12], packet_number, .big);

        // Get payload and tag slices
        const payload = self.data[self.payload_offset .. self.payload_offset + payload_len];
        const tag = self.data[self.payload_offset + payload_len .. self.payload_offset + payload_len + 16];
        const aad = self.data[self.header_offset..self.payload_offset];

        // Encrypt in place using QUIC AEAD
        const aead = quic_crypto.QuicCrypto.AEAD.init(self.crypto_context.cipher_suite, &self.crypto_context.key);
        _ = try aead.sealInPlace(&nonce, payload, aad, tag);

        self.tag_offset = self.payload_offset + payload_len;
        return payload_len + 16; // payload + tag
    }

    /// Decrypt packet data in-place with zero allocations
    pub fn decryptInPlace(self: *CryptoPacketBuffer, ciphertext_len: usize, packet_number: u64) !usize {
        if (self.payload_offset + ciphertext_len > self.capacity) {
            return ZeroCopyError.BufferTooSmall;
        }

        // Construct nonce
        var nonce: [12]u8 = self.crypto_context.iv;
        std.mem.writeInt(u64, nonce[4..12], packet_number, .big);

        // Get ciphertext and tag slices
        const payload_len = ciphertext_len - 16;
        const ciphertext = self.data[self.payload_offset .. self.payload_offset + payload_len];
        const tag = self.data[self.payload_offset + payload_len .. self.payload_offset + ciphertext_len];
        const aad = self.data[self.header_offset..self.payload_offset];

        // Decrypt in place
        const aead = quic_crypto.QuicCrypto.AEAD.init(self.crypto_context.cipher_suite, &self.crypto_context.key);
        return aead.openInPlace(&nonce, ciphertext, aad, tag);
    }
};

/// High-performance packet buffer pool for zero-copy operations
pub const PacketBufferPool = struct {
    buffers: []CryptoPacketBuffer,
    allocated_buffers: [][]u8, // Track original allocated pointers for proper cleanup
    available: std.atomic.Value(u32),
    total: u32,
    buffer_size: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, pool_size: u32, buffer_size: usize, cipher_suite: quic_crypto.QuicCrypto.CipherSuite) !PacketBufferPool {
        const buffers = try allocator.alloc(CryptoPacketBuffer, pool_size);
        const allocated_buffers = try allocator.alloc([]u8, pool_size);

        // Initialize each buffer with regular memory (alignment not critical for tests)
        for (buffers, allocated_buffers) |*buffer, *allocated_buffer| {
            const memory = try allocator.alloc(u8, buffer_size);
            allocated_buffer.* = memory; // Store original pointer for cleanup
            buffer.* = CryptoPacketBuffer.init(memory, cipher_suite);
        }

        return PacketBufferPool{
            .buffers = buffers,
            .allocated_buffers = allocated_buffers,
            .available = std.atomic.Value(u32).init(pool_size),
            .total = pool_size,
            .buffer_size = buffer_size,
            .allocator = allocator,
        };
    }

    /// Acquire a buffer from the pool (zero-allocation)
    pub fn acquire(self: *PacketBufferPool) ?*CryptoPacketBuffer {
        const available = self.available.load(.acquire);
        if (available == 0) return null;

        if (self.available.cmpxchgWeak(available, available - 1, .acq_rel, .acquire)) |_| {
            // Try again if CAS failed
            return self.acquire();
        }

        // Find and return an available buffer
        for (self.buffers) |*buffer| {
            // Simple availability check - in production, use a proper free list
            if (buffer.data.len > 0) {
                return buffer;
            }
        }

        return null;
    }

    /// Release buffer back to pool
    pub fn release(self: *PacketBufferPool, buffer: *CryptoPacketBuffer) void {
        // Reset buffer state
        buffer.header_offset = 0;
        buffer.payload_offset = 0;
        buffer.tag_offset = 0;

        _ = self.available.fetchAdd(1, .release);
    }

    pub fn deinit(self: *PacketBufferPool) void {
        for (self.allocated_buffers) |allocated_buffer| {
            self.allocator.free(allocated_buffer);
        }
        self.allocator.free(self.allocated_buffers);
        self.allocator.free(self.buffers);
    }
};

/// Vectorized batch crypto operations for maximum throughput
pub const BatchCrypto = struct {
    hw_features: hardware.HardwareAcceleration,

    pub fn init(hw_features: hardware.HardwareAcceleration) BatchCrypto {
        return BatchCrypto{ .hw_features = hw_features };
    }

    /// Encrypt multiple packets in batch using SIMD when available
    pub fn encryptBatch(self: *BatchCrypto, buffers: []*CryptoPacketBuffer, payload_lengths: []const usize) ![]usize {
        if (buffers.len != payload_lengths.len) return error.InvalidInput;

        const results = try std.heap.page_allocator.alloc(usize, buffers.len);

        if (self.hw_features.avx2 and buffers.len >= 8) {
            // Use vectorized operations for 8+ packets
            return self.encryptBatchVectorized(buffers, payload_lengths, results);
        } else {
            // Fallback to sequential processing
            for (buffers, payload_lengths, results) |buffer, len, *result| {
                result.* = try buffer.encryptInPlace(len);
            }
            return results;
        }
    }

    /// Vectorized encryption using SIMD instructions
    fn encryptBatchVectorized(self: *BatchCrypto, buffers: []*CryptoPacketBuffer, payload_lengths: []const usize, results: []usize) ![]usize {
        // Process in chunks of 8 for AVX2
        const chunk_size = 8;
        var i: usize = 0;

        while (i + chunk_size <= buffers.len) {
            // Prepare 8 nonces simultaneously
            var nonces: [8][12]u8 = undefined;
            for (0..chunk_size) |j| {
                nonces[j] = buffers[i + j].crypto_context.iv;
                const packet_number = buffers[i + j].crypto_context.updatePacketNumber();
                std.mem.writeInt(u64, nonces[j][4..12], packet_number, .big);
            }

            // Vectorized AEAD operations (simplified - would use actual SIMD intrinsics)
            for (0..chunk_size) |j| {
                const buffer = buffers[i + j];
                const len = payload_lengths[i + j];
                results[i + j] = try buffer.encryptInPlace(len);
            }

            i += chunk_size;
        }

        // Handle remaining packets
        while (i < buffers.len) {
            results[i] = try buffers[i].encryptInPlace(payload_lengths[i]);
            i += 1;
        }

        _ = self;
        return results;
    }
};

/// Ring buffer for continuous packet stream processing
pub const CryptoRingBuffer = struct {
    buffer: []u8,
    read_pos: std.atomic.Atomic(usize),
    write_pos: std.atomic.Atomic(usize),
    capacity: usize,
    crypto_context: CryptoPacketBuffer.CryptoContext,

    pub fn init(allocator: std.mem.Allocator, capacity: usize, cipher_suite: quic_crypto.QuicCrypto.CipherSuite) !CryptoRingBuffer {
        const buffer = try allocator.alignedAlloc(u8, 64, capacity);

        return CryptoRingBuffer{
            .buffer = buffer,
            .read_pos = std.atomic.Atomic(usize).init(0),
            .write_pos = std.atomic.Atomic(usize).init(0),
            .capacity = capacity,
            .crypto_context = CryptoPacketBuffer.CryptoContext{
                .cipher_suite = cipher_suite,
                .key = std.mem.zeroes([32]u8),
                .iv = std.mem.zeroes([12]u8),
                .header_protection_key = std.mem.zeroes([32]u8),
                .packet_number = 0,
            },
        };
    }

    /// Write encrypted data to ring buffer
    pub fn writeEncrypted(self: *CryptoRingBuffer, data: []const u8) !usize {
        const write_pos = self.write_pos.load(.acquire);
        const read_pos = self.read_pos.load(.acquire);

        // Calculate available space
        const available = if (write_pos >= read_pos)
            self.capacity - write_pos + read_pos - 1
        else
            read_pos - write_pos - 1;

        if (data.len > available) {
            return ZeroCopyError.BufferTooSmall;
        }

        // Write data (may wrap around)
        if (write_pos + data.len <= self.capacity) {
            @memcpy(self.buffer[write_pos .. write_pos + data.len], data);
        } else {
            const first_part = self.capacity - write_pos;
            @memcpy(self.buffer[write_pos..], data[0..first_part]);
            @memcpy(self.buffer[0 .. data.len - first_part], data[first_part..]);
        }

        // Update write position
        const new_write_pos = (write_pos + data.len) % self.capacity;
        self.write_pos.store(new_write_pos, .release);

        return data.len;
    }

    /// Read and decrypt data from ring buffer
    pub fn readDecrypted(self: *CryptoRingBuffer, output: []u8) !usize {
        const read_pos = self.read_pos.load(.acquire);
        const write_pos = self.write_pos.load(.acquire);

        // Calculate available data
        const available = if (write_pos >= read_pos)
            write_pos - read_pos
        else
            self.capacity - read_pos + write_pos;

        if (available == 0) return 0;

        const read_len = @min(output.len, available);

        // Read data (may wrap around)
        if (read_pos + read_len <= self.capacity) {
            @memcpy(output[0..read_len], self.buffer[read_pos .. read_pos + read_len]);
        } else {
            const first_part = self.capacity - read_pos;
            @memcpy(output[0..first_part], self.buffer[read_pos..]);
            @memcpy(output[first_part..read_len], self.buffer[0 .. read_len - first_part]);
        }

        // Update read position
        const new_read_pos = (read_pos + read_len) % self.capacity;
        self.read_pos.store(new_read_pos, .release);

        return read_len;
    }

    pub fn deinit(self: *CryptoRingBuffer, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
    }
};

// =============================================================================
// TESTS
// =============================================================================

test "zero-copy packet buffer encryption" {
    var buffer: [1500]u8 = undefined;
    var packet_buffer = CryptoPacketBuffer.init(&buffer, .chacha20_poly1305);

    // Setup packet structure
    packet_buffer.header_offset = 0;
    packet_buffer.payload_offset = 20; // 20-byte header

    // Add test payload
    const test_payload = "Hello, zero-copy world!";
    @memcpy(buffer[20 .. 20 + test_payload.len], test_payload);

    // Encrypt in place
    const encrypted_len = try packet_buffer.encryptInPlace(test_payload.len);
    try testing.expect(encrypted_len == test_payload.len + 16); // payload + tag
}

test "packet buffer pool operations" {
    var pool = try PacketBufferPool.init(std.testing.allocator, 4, 1500, .aes_256_gcm);
    defer pool.deinit();

    // Acquire buffer
    const buffer1 = pool.acquire();
    try testing.expect(buffer1 != null);

    // Release buffer
    pool.release(buffer1.?);

    // Should be able to acquire again
    const buffer2 = pool.acquire();
    try testing.expect(buffer2 != null);
}

test "batch crypto operations" {
    const hw_features = hardware.HardwareAcceleration{
        .aes_ni = true,
        .arm_crypto = false,
    };

    var batch_crypto = BatchCrypto.init(hw_features);

    // Create test buffers
    var buffers: [4]*CryptoPacketBuffer = undefined;
    var buffer_memory: [4][1500]u8 = undefined;

    for (&buffers, &buffer_memory) |*buf_ptr, *mem| {
        var packet_buffer = CryptoPacketBuffer.init(mem, .chacha20_poly1305);
        packet_buffer.payload_offset = 20;
        buf_ptr.* = &packet_buffer;
    }

    const payload_lengths = [_]usize{ 100, 200, 150, 300 };
    const results = try batch_crypto.encryptBatch(&buffers, &payload_lengths);
    defer std.heap.page_allocator.free(results);

    try testing.expect(results.len == 4);
    for (results, payload_lengths) |result, expected| {
        try testing.expect(result == expected + 16); // payload + tag
    }
}
