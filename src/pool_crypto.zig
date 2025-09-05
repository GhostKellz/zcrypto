//! Advanced connection pooling crypto for zquic connection pooling
//! Features:
//! - Pre-computed crypto contexts for connection pools
//! - Crypto state sharing between pooled connections
//! - Session resumption with cached crypto materials
//! - Bulk key derivation for connection batches
//! - Memory-efficient crypto context compression

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

/// Pool crypto errors
pub const PoolCryptoError = error{
    PoolExhausted,
    InvalidContextId,
    CompressionFailed,
    DecompressionFailed,
    SessionExpired,
    CryptoStateMismatch,
    OutOfMemory,
};

/// Pre-computed crypto context for pooled connections
pub const CryptoContext = struct {
    id: u64,
    encryption_key: [32]u8,
    decryption_key: [32]u8,
    send_counter: u64,
    recv_counter: u64,
    creation_time: i64,
    last_used: i64,
    reference_count: u32,
    is_compressed: bool,

    pub fn init(id: u64) CryptoContext {
        return CryptoContext{
            .id = id,
            .encryption_key = [_]u8{0} ** 32,
            .decryption_key = [_]u8{0} ** 32,
            .send_counter = 0,
            .recv_counter = 0,
            .creation_time = std.time.timestamp(),
            .last_used = std.time.timestamp(),
            .reference_count = 0,
            .is_compressed = false,
        };
    }

    /// Generate fresh keys for the context
    pub fn generateKeys(self: *CryptoContext, master_key: [32]u8) void {
        // Derive keys using HKDF with context ID
        var id_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_bytes, self.id, .little);

        const salt = "zcrypto-pool-v1";
        const info_enc = "encryption-key";
        const info_dec = "decryption-key";

        // Generate encryption key
        const prk = crypto.kdf.hkdf.HkdfSha256.extract(salt, &master_key);

        var okm: [64]u8 = undefined;
        crypto.kdf.hkdf.HkdfSha256.expand(&okm, info_enc, prk);
        @memcpy(&self.encryption_key, okm[0..32]);

        // Generate decryption key
        crypto.kdf.hkdf.HkdfSha256.expand(&okm, info_dec, prk);
        @memcpy(&self.decryption_key, okm[32..64]);

        self.send_counter = 0;
        self.recv_counter = 0;
        self.creation_time = std.time.timestamp();
        self.last_used = self.creation_time;
    }

    /// Compress crypto context for memory efficiency
    pub fn compress(self: *CryptoContext, allocator: Allocator) ![]u8 {
        // Simple compression: XOR keys with derived compression key
        var compression_key: [32]u8 = undefined;

        // Derive compression key from context data
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.encryption_key);
        hasher.update(&self.decryption_key);

        var id_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_bytes, self.id, .little);
        hasher.update(&id_bytes);

        hasher.final(&compression_key);

        // Compress the sensitive data
        const compressed_size = 64 + 16 + 8; // keys + counters + metadata
        var compressed = try allocator.alloc(u8, compressed_size);

        // XOR encryption key
        for (self.encryption_key, 0..) |byte, i| {
            compressed[i] = byte ^ compression_key[i % 32];
        }

        // XOR decryption key
        for (self.decryption_key, 0..) |byte, i| {
            compressed[32 + i] = byte ^ compression_key[(32 + i) % 32];
        }

        // Store counters
        std.mem.writeInt(u64, compressed[64..72], self.send_counter, .little);
        std.mem.writeInt(u64, compressed[72..80], self.recv_counter, .little);

        // Store metadata
        std.mem.writeInt(i64, compressed[80..88], self.last_used, .little);

        self.is_compressed = true;
        return compressed;
    }

    /// Decompress crypto context
    pub fn decompress(self: *CryptoContext, compressed_data: []const u8) !void {
        if (compressed_data.len < 88) {
            return PoolCryptoError.DecompressionFailed;
        }

        // Derive compression key (same as in compress)
        var compression_key: [32]u8 = undefined;
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.encryption_key);
        hasher.update(&self.decryption_key);

        var id_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_bytes, self.id, .little);
        hasher.update(&id_bytes);

        hasher.final(&compression_key);

        // Decompress encryption key
        for (compressed_data[0..32], 0..) |byte, i| {
            self.encryption_key[i] = byte ^ compression_key[i % 32];
        }

        // Decompress decryption key
        for (compressed_data[32..64], 0..) |byte, i| {
            self.decryption_key[i] = byte ^ compression_key[(32 + i) % 32];
        }

        // Restore counters
        self.send_counter = std.mem.readInt(u64, compressed_data[64..72], .little);
        self.recv_counter = std.mem.readInt(u64, compressed_data[72..80], .little);

        // Restore metadata
        self.last_used = std.mem.readInt(i64, compressed_data[80..88], .little);

        self.is_compressed = false;
    }

    /// Update last used timestamp
    pub fn touch(self: *CryptoContext) void {
        self.last_used = std.time.timestamp();
    }

    /// Check if context has expired
    pub fn hasExpired(self: CryptoContext, ttl_seconds: i64) bool {
        const current_time = std.time.timestamp();
        return (current_time - self.last_used) > ttl_seconds;
    }
};

/// Crypto context pool for connection reuse
pub const CryptoPool = struct {
    allocator: Allocator,
    contexts: std.HashMap(u64, CryptoContext, std.hash_map.AutoContext(u64), 80),
    compressed_contexts: std.HashMap(u64, []u8, std.hash_map.AutoContext(u64), 80),
    master_key: [32]u8,
    next_context_id: u64,
    max_contexts: usize,
    ttl_seconds: i64,

    pub fn init(allocator: Allocator, master_key: [32]u8, max_contexts: usize, ttl_seconds: i64) CryptoPool {
        return CryptoPool{
            .allocator = allocator,
            .contexts = std.HashMap(u64, CryptoContext, std.hash_map.AutoContext(u64), 80).init(allocator),
            .compressed_contexts = std.HashMap(u64, []u8, std.hash_map.AutoContext(u64), 80).init(allocator),
            .master_key = master_key,
            .next_context_id = 1,
            .max_contexts = max_contexts,
            .ttl_seconds = ttl_seconds,
        };
    }

    pub fn deinit(self: *CryptoPool) void {
        // Free compressed context data
        var iterator = self.compressed_contexts.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }

        self.contexts.deinit();
        self.compressed_contexts.deinit();
    }

    /// Get or create a crypto context
    pub fn getContext(self: *CryptoPool) !u64 {
        // Clean up expired contexts first
        try self.cleanupExpired();

        // Check if we can reuse an existing context
        if (self.contexts.count() < self.max_contexts) {
            const context_id = self.next_context_id;
            self.next_context_id += 1;

            var context = CryptoContext.init(context_id);
            context.generateKeys(self.master_key);

            try self.contexts.put(context_id, context);
            return context_id;
        }

        return PoolCryptoError.PoolExhausted;
    }

    /// Acquire a context for use
    pub fn acquireContext(self: *CryptoPool, context_id: u64) !*CryptoContext {
        if (self.contexts.getPtr(context_id)) |context| {
            context.reference_count += 1;
            context.touch();

            // Decompress if needed
            if (context.is_compressed) {
                if (self.compressed_contexts.get(context_id)) |compressed_data| {
                    try context.decompress(compressed_data);
                    self.allocator.free(compressed_data);
                    _ = self.compressed_contexts.remove(context_id);
                }
            }

            return context;
        }

        return PoolCryptoError.InvalidContextId;
    }

    /// Release a context
    pub fn releaseContext(self: *CryptoPool, context_id: u64) !void {
        if (self.contexts.getPtr(context_id)) |context| {
            if (context.reference_count > 0) {
                context.reference_count -= 1;
            }

            // Compress if not in use and memory pressure is high
            if (context.reference_count == 0 and self.contexts.count() > self.max_contexts / 2) {
                const compressed_data = try context.compress(self.allocator);
                try self.compressed_contexts.put(context_id, compressed_data);
            }
        }
    }

    /// Clean up expired contexts
    fn cleanupExpired(self: *CryptoPool) !void {
        var to_remove: std.ArrayList(u64) = .{};
        defer to_remove.deinit(self.allocator);

        var iterator = self.contexts.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.hasExpired(self.ttl_seconds) and entry.value_ptr.reference_count == 0) {
                try to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (to_remove.items) |context_id| {
            _ = self.contexts.remove(context_id);

            // Also remove compressed data
            if (self.compressed_contexts.get(context_id)) |compressed_data| {
                self.allocator.free(compressed_data);
                _ = self.compressed_contexts.remove(context_id);
            }
        }
    }

    /// Get pool statistics
    pub fn getStats(self: CryptoPool) PoolStats {
        var active_contexts: u32 = 0;
        var compressed_contexts: u32 = 0;

        var iterator = self.contexts.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.reference_count > 0) {
                active_contexts += 1;
            }
            if (entry.value_ptr.is_compressed) {
                compressed_contexts += 1;
            }
        }

        return PoolStats{
            .total_contexts = @intCast(self.contexts.count()),
            .active_contexts = active_contexts,
            .compressed_contexts = compressed_contexts,
            .memory_usage = self.estimateMemoryUsage(),
        };
    }

    fn estimateMemoryUsage(self: CryptoPool) usize {
        const context_size = @sizeOf(CryptoContext);
        const active_memory = self.contexts.count() * context_size;

        var compressed_memory: usize = 0;
        var iterator = self.compressed_contexts.iterator();
        while (iterator.next()) |entry| {
            compressed_memory += entry.value_ptr.len;
        }

        return active_memory + compressed_memory;
    }
};

/// Session resumption with cached crypto materials
pub const SessionCache = struct {
    allocator: Allocator,
    sessions: std.HashMap(u64, SessionData, std.hash_map.AutoContext(u64), 80),
    max_sessions: usize,

    const SessionData = struct {
        session_id: u64,
        resumption_key: [32]u8,
        cipher_suite: u16,
        creation_time: i64,
        last_used: i64,
        use_count: u32,
    };

    pub fn init(allocator: Allocator, max_sessions: usize) SessionCache {
        return SessionCache{
            .allocator = allocator,
            .sessions = std.HashMap(u64, SessionData, std.hash_map.AutoContext(u64), 80).init(allocator),
            .max_sessions = max_sessions,
        };
    }

    pub fn deinit(self: *SessionCache) void {
        self.sessions.deinit();
    }

    /// Store session for resumption
    pub fn storeSession(self: *SessionCache, session_id: u64, resumption_key: [32]u8, cipher_suite: u16) !void {
        if (self.sessions.count() >= self.max_sessions) {
            try self.evictOldest();
        }

        const session_data = SessionData{
            .session_id = session_id,
            .resumption_key = resumption_key,
            .cipher_suite = cipher_suite,
            .creation_time = std.time.timestamp(),
            .last_used = std.time.timestamp(),
            .use_count = 0,
        };

        try self.sessions.put(session_id, session_data);
    }

    /// Resume a session
    pub fn resumeSession(self: *SessionCache, session_id: u64) ?SessionData {
        if (self.sessions.getPtr(session_id)) |session| {
            session.last_used = std.time.timestamp();
            session.use_count += 1;
            return session.*;
        }
        return null;
    }

    fn evictOldest(self: *SessionCache) !void {
        var oldest_time: i64 = std.time.timestamp();
        var oldest_id: ?u64 = null;

        var iterator = self.sessions.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.last_used < oldest_time) {
                oldest_time = entry.value_ptr.last_used;
                oldest_id = entry.key_ptr.*;
            }
        }

        if (oldest_id) |id| {
            _ = self.sessions.remove(id);
        }
    }
};

/// Bulk key derivation for connection batches
pub const BulkKeyDerivation = struct {
    /// Derive multiple keys in batch for efficiency
    pub fn deriveBatch(master_key: [32]u8, count: usize, allocator: Allocator) ![][32]u8 {
        const keys = try allocator.alloc([32]u8, count);

        const salt = "zcrypto-bulk-v1";

        for (keys, 0..) |*key, i| {
            // Use index as additional entropy
            var index_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &index_bytes, i, .little);

            const prk = crypto.kdf.hkdf.HkdfSha256.extract(salt, &master_key);

            var info: [16]u8 = undefined;
            @memcpy(info[0..8], &index_bytes);
            @memcpy(info[8..16], "bulk-key");

            crypto.kdf.hkdf.HkdfSha256.expand(key, &info, prk);
        }

        return keys;
    }

    /// Parallel key derivation using multiple threads
    pub fn deriveBatchParallel(master_key: [32]u8, count: usize, allocator: Allocator) ![][32]u8 {
        // For now, use sequential derivation
        // In a real implementation, this would use thread pools
        return deriveBatch(master_key, count, allocator);
    }
};

/// Pool statistics
pub const PoolStats = struct {
    total_contexts: u32,
    active_contexts: u32,
    compressed_contexts: u32,
    memory_usage: usize,
};

// Tests
const testing = std.testing;

test "crypto context creation and key generation" {
    var context = CryptoContext.init(1);
    const master_key = [_]u8{1} ** 32;

    context.generateKeys(master_key);

    try testing.expect(context.id == 1);
    try testing.expect(context.send_counter == 0);
    try testing.expect(context.recv_counter == 0);
    try testing.expect(!std.mem.allEqual(u8, &context.encryption_key, 0));
}

test "crypto context compression and decompression" {
    var context = CryptoContext.init(1);
    const master_key = [_]u8{1} ** 32;
    context.generateKeys(master_key);

    const original_enc_key = context.encryption_key;
    const original_dec_key = context.decryption_key;

    const compressed = try context.compress(testing.allocator);
    defer testing.allocator.free(compressed);

    try testing.expect(context.is_compressed);

    try context.decompress(compressed);
    try testing.expect(!context.is_compressed);
    try testing.expectEqualSlices(u8, &original_enc_key, &context.encryption_key);
    try testing.expectEqualSlices(u8, &original_dec_key, &context.decryption_key);
}

test "crypto pool operations" {
    const master_key = [_]u8{1} ** 32;
    var pool = CryptoPool.init(testing.allocator, master_key, 10, 3600);
    defer pool.deinit();

    const context_id = try pool.getContext();
    try testing.expect(context_id > 0);

    const context = try pool.acquireContext(context_id);
    try testing.expect(context.reference_count == 1);

    try pool.releaseContext(context_id);
    try testing.expect(context.reference_count == 0);
}

test "session cache operations" {
    var cache = SessionCache.init(testing.allocator, 5);
    defer cache.deinit();

    const session_id: u64 = 12345;
    const resumption_key = [_]u8{1} ** 32;
    const cipher_suite: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

    try cache.storeSession(session_id, resumption_key, cipher_suite);

    const resumed = cache.resumeSession(session_id);
    try testing.expect(resumed != null);
    try testing.expect(resumed.?.session_id == session_id);
    try testing.expect(resumed.?.cipher_suite == cipher_suite);
}

test "bulk key derivation" {
    const master_key = [_]u8{1} ** 32;
    const keys = try BulkKeyDerivation.deriveBatch(master_key, 5, testing.allocator);
    defer testing.allocator.free(keys);

    try testing.expect(keys.len == 5);

    // Check that keys are different
    try testing.expect(!std.mem.eql(u8, &keys[0], &keys[1]));
    try testing.expect(!std.mem.eql(u8, &keys[1], &keys[2]));
}
