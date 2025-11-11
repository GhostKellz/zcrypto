//! Arena Allocator Support for High-Performance Crypto
//!
//! Provides memory pool patterns for hot-path cryptographic operations.
//! Reduces allocation overhead in consensus loops, transaction processing,
//! and other high-frequency crypto workloads.
//!
//! ## Benefits
//!
//! - **Reduced Allocation Overhead**: Batch allocate/free for transaction batches
//! - **Improved Cache Locality**: Related allocations grouped together
//! - **Simplified Error Handling**: Single arena reset vs. individual frees
//! - **Lower GC Pressure**: Bulk deallocation (if Zig adds GC)
//!
//! ## Usage Patterns
//!
//! ### Pattern 1: Batch Transaction Processing
//! ```zig
//! var arena = std.heap.ArenaAllocator.init(base_allocator);
//! defer arena.deinit();
//!
//! for (transaction_batch) |tx| {
//!     const sig = try signWithArena(&arena, tx.data, private_key);
//!     // Use signature...
//! }
//! // All allocations freed at once
//! ```
//!
//! ### Pattern 2: Request-Scoped Crypto
//! ```zig
//! fn processRequest(request: Request, arena: *ArenaAllocator) !Response {
//!     const verified = try verifyBatchWithArena(arena, request.signatures);
//!     const hash = try hashWithArena(arena, request.data);
//!     // Arena cleaned up by caller
//! }
//! ```
//!
//! ### Pattern 3: Hot-Path Verification
//! ```zig
//! var arena = ArenaAllocator.init(allocator);
//! defer arena.deinit();
//!
//! while (consensus_running) {
//!     const batch = receive_gossip();
//!     _ = try verifyGossipBatch(&arena, batch);
//!     _ = arena.reset(.retain_capacity);  // Reuse memory
//! }
//! ```

const std = @import("std");
const asym = @import("asym.zig");
const hash_mod = @import("hash.zig");
const blake3_mod = @import("blake3.zig");
const batch_mod = @import("batch.zig");
const testing = std.testing;

/// Sign message using arena allocator
///
/// Equivalent to normal signing but uses arena for internal allocations.
/// Useful when processing batches of signatures that share lifetime.
///
/// ## Parameters
/// - `arena`: Arena allocator (memory freed when arena is reset/destroyed)
/// - `message`: Message to sign
/// - `private_key`: Ed25519 private key (64 bytes)
///
/// ## Returns
/// Signature allocated from arena
///
/// ## Example
/// ```zig
/// var arena = ArenaAllocator.init(allocator);
/// defer arena.deinit();
///
/// for (messages) |msg| {
///     const sig = try signWithArena(&arena, msg, private_key);
///     try signatures.append(sig);
/// }
/// // All signature allocations freed together
/// ```
pub fn signWithArena(
    arena: *std.heap.ArenaAllocator,
    message: []const u8,
    private_key: [64]u8,
) ![64]u8 {
    // Ed25519 signing doesn't actually need allocation
    // But this provides consistent API for arena usage
    _ = arena; // Not needed for Ed25519, but kept for API consistency
    return try asym.ed25519.sign(message, private_key);
}

/// Batch verify signatures using arena allocator
///
/// Verifies multiple signatures with allocations from arena.
/// Results are also allocated from arena.
///
/// ## Parameters
/// - `arena`: Arena allocator
/// - `messages`: Array of messages
/// - `signatures`: Array of signatures
/// - `public_keys`: Array of public keys
///
/// ## Returns
/// Array of verification results (allocated from arena)
///
/// ## Example
/// ```zig
/// var arena = ArenaAllocator.init(allocator);
/// defer arena.deinit();
///
/// const results = try verifyBatchWithArena(
///     &arena,
///     messages,
///     signatures,
///     public_keys,
/// );
/// // Use results...
/// // Arena cleanup frees results
/// ```
pub fn verifyBatchWithArena(
    arena: *std.heap.ArenaAllocator,
    messages: []const []const u8,
    signatures: []const [64]u8,
    public_keys: []const [32]u8,
) ![]bool {
    const allocator = arena.allocator();
    return try batch_mod.verifyBatchEd25519(
        messages,
        signatures,
        public_keys,
        allocator,
    );
}

/// Parallel batch verify using arena allocator
///
/// High-performance parallel verification with arena allocation.
///
/// ## Parameters
/// - `arena`: Arena allocator
/// - `messages`: Array of messages
/// - `signatures`: Array of signatures
/// - `public_keys`: Array of public keys
/// - `thread_count`: Number of threads (0 = auto-detect)
///
/// ## Returns
/// Array of verification results (allocated from arena)
///
/// ## Performance
/// - 4-8x speedup on multi-core systems
/// - Best for batches > 100 signatures
///
/// ## Example
/// ```zig
/// var arena = ArenaAllocator.init(allocator);
/// defer arena.deinit();
///
/// while (receiving_gossip) {
///     const batch = get_gossip_batch();
///     const results = try verifyBatchParallelWithArena(
///         &arena,
///         batch.messages,
///         batch.signatures,
///         batch.public_keys,
///         0,  // Auto-detect cores
///     );
///     process_results(results);
///     _ = arena.reset(.retain_capacity);  // Reuse memory
/// }
/// ```
pub fn verifyBatchParallelWithArena(
    arena: *std.heap.ArenaAllocator,
    messages: []const []const u8,
    signatures: []const [64]u8,
    public_keys: []const [32]u8,
    thread_count: usize,
) ![]bool {
    const allocator = arena.allocator();
    return try batch_mod.verifyBatchEd25519Parallel(
        messages,
        signatures,
        public_keys,
        thread_count,
        allocator,
    );
}

/// Hash multiple messages using arena allocator
///
/// Computes Blake3 hashes for multiple messages with results in arena.
///
/// ## Parameters
/// - `arena`: Arena allocator
/// - `messages`: Array of messages to hash
///
/// ## Returns
/// Array of hashes (allocated from arena)
///
/// ## Example
/// ```zig
/// var arena = ArenaAllocator.init(allocator);
/// defer arena.deinit();
///
/// const tx_hashes = try hashBatchWithArena(&arena, transactions);
/// // Build Merkle tree from hashes...
/// // Arena cleanup frees all hashes
/// ```
pub fn hashBatchWithArena(
    arena: *std.heap.ArenaAllocator,
    messages: []const []const u8,
) ![][32]u8 {
    const allocator = arena.allocator();
    return try batch_mod.hashBatch(messages, allocator);
}

/// Arena-based crypto workspace for hot-path operations
///
/// Provides a reusable workspace for high-frequency crypto operations.
/// Efficient for processing many transactions/blocks in a loop.
///
/// ## Example
/// ```zig
/// var workspace = try CryptoWorkspace.init(allocator);
/// defer workspace.deinit();
///
/// while (processing_transactions) {
///     const tx = get_next_transaction();
///
///     // All crypto ops use workspace arena
///     const verified = try workspace.verifyTransaction(tx);
///     const hash = workspace.hashTransaction(tx);
///
///     if (verified) {
///         commit_transaction(tx, hash);
///     }
///
///     workspace.reset();  // Reuse memory for next transaction
/// }
/// ```
pub const CryptoWorkspace = struct {
    arena: std.heap.ArenaAllocator,
    base_allocator: std.mem.Allocator,

    /// Initialize crypto workspace
    ///
    /// ## Parameters
    /// - `base_allocator`: Base allocator for arena
    ///
    /// ## Returns
    /// New crypto workspace
    pub fn init(base_allocator: std.mem.Allocator) CryptoWorkspace {
        return .{
            .arena = std.heap.ArenaAllocator.init(base_allocator),
            .base_allocator = base_allocator,
        };
    }

    /// Free all workspace memory
    pub fn deinit(self: *CryptoWorkspace) void {
        self.arena.deinit();
    }

    /// Reset workspace for reuse
    ///
    /// Frees all allocations but retains capacity for next use.
    ///
    /// ## Parameters
    /// - `mode`: Reset mode (.free_all or .retain_capacity)
    pub fn reset(self: *CryptoWorkspace) void {
        _ = self.arena.reset(.retain_capacity);
    }

    /// Get allocator for custom operations
    pub fn allocator(self: *CryptoWorkspace) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Sign message using workspace
    pub fn sign(
        self: *CryptoWorkspace,
        message: []const u8,
        private_key: [64]u8,
    ) ![64]u8 {
        return try signWithArena(&self.arena, message, private_key);
    }

    /// Verify batch using workspace
    pub fn verifyBatch(
        self: *CryptoWorkspace,
        messages: []const []const u8,
        signatures: []const [64]u8,
        public_keys: []const [32]u8,
    ) ![]bool {
        return try verifyBatchWithArena(
            &self.arena,
            messages,
            signatures,
            public_keys,
        );
    }

    /// Parallel batch verify using workspace
    pub fn verifyBatchParallel(
        self: *CryptoWorkspace,
        messages: []const []const u8,
        signatures: []const [64]u8,
        public_keys: []const [32]u8,
        thread_count: usize,
    ) ![]bool {
        return try verifyBatchParallelWithArena(
            &self.arena,
            messages,
            signatures,
            public_keys,
            thread_count,
        );
    }

    /// Hash batch using workspace
    pub fn hashBatch(
        self: *CryptoWorkspace,
        messages: []const []const u8,
    ) ![][32]u8 {
        return try hashBatchWithArena(&self.arena, messages);
    }

    /// Hash single message (no allocation needed)
    pub fn hash(self: *CryptoWorkspace, message: []const u8) [32]u8 {
        _ = self; // Not used for single hash
        return blake3_mod.blake3(message);
    }
};

//
// ============================================================================
// PERFORMANCE HELPERS
// ============================================================================
//

/// Pre-allocated crypto buffer pool
///
/// Provides fixed-size buffers for crypto operations without per-operation
/// allocation overhead. Useful for very hot paths.
///
/// ## Example
/// ```zig
/// var pool = try CryptoBufferPool.init(allocator, 1000);
/// defer pool.deinit();
///
/// while (processing) {
///     var buffer = try pool.acquire();
///     defer pool.release(buffer);
///
///     // Use buffer for crypto operation
///     const sig = sign_into_buffer(buffer, message, key);
/// }
/// ```
pub const CryptoBufferPool = struct {
    buffers: [][]u8,
    available: std.ArrayList(usize),
    buffer_size: usize,
    allocator: std.mem.Allocator,

    /// Initialize buffer pool
    ///
    /// ## Parameters
    /// - `allocator`: Allocator for buffers
    /// - `count`: Number of buffers
    /// - `buffer_size`: Size of each buffer (default: 1024 bytes)
    pub fn init(
        allocator: std.mem.Allocator,
        count: usize,
        buffer_size: usize,
    ) !CryptoBufferPool {
        const buffers = try allocator.alloc([]u8, count);
        errdefer allocator.free(buffers);

        var available: std.ArrayList(usize) = .{};
        errdefer available.deinit(allocator);

        // Pre-allocate all buffers
        for (buffers, 0..) |*buf, i| {
            buf.* = try allocator.alloc(u8, buffer_size);
            try available.append(allocator, i);
        }

        return CryptoBufferPool{
            .buffers = buffers,
            .available = available,
            .buffer_size = buffer_size,
            .allocator = allocator,
        };
    }

    /// Free all buffers
    pub fn deinit(self: *CryptoBufferPool) void {
        for (self.buffers) |buf| {
            self.allocator.free(buf);
        }
        self.allocator.free(self.buffers);
        self.available.deinit(self.allocator);
    }

    /// Acquire buffer from pool
    ///
    /// ## Returns
    /// Buffer slice (must be released after use)
    ///
    /// ## Errors
    /// Returns error.OutOfBuffers if pool is exhausted
    pub fn acquire(self: *CryptoBufferPool) ![]u8 {
        if (self.available.items.len == 0) {
            return error.OutOfBuffers;
        }

        const idx = self.available.pop() orelse return error.OutOfBuffers;
        return self.buffers[idx];
    }

    /// Release buffer back to pool
    ///
    /// ## Parameters
    /// - `buffer`: Buffer to release (must be from this pool)
    pub fn release(self: *CryptoBufferPool, buffer: []u8) void {
        // Find buffer index
        for (self.buffers, 0..) |buf, i| {
            if (buf.ptr == buffer.ptr) {
                self.available.append(self.allocator, i) catch unreachable;
                return;
            }
        }
    }
};

//
// ============================================================================
// TESTS
// ============================================================================
//

test "arena sign" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const keypair = asym.ed25519.generate();
    const message = "test message";

    const sig = try signWithArena(&arena, message, keypair.private_key);

    // Verify signature works
    const valid = asym.ed25519.verify(message, sig, keypair.public_key);
    try testing.expect(valid);
}

test "arena batch verify" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const count = 10;
    var messages = try testing.allocator.alloc([]const u8, count);
    defer {
        for (messages) |msg| testing.allocator.free(msg);
        testing.allocator.free(messages);
    }

    var signatures = try testing.allocator.alloc([64]u8, count);
    defer testing.allocator.free(signatures);

    var public_keys = try testing.allocator.alloc([32]u8, count);
    defer testing.allocator.free(public_keys);

    // Generate test data
    for (0..count) |i| {
        const keypair = asym.ed25519.generate();
        // Allocate separate buffer for each message
        const msg = try std.fmt.allocPrint(testing.allocator, "message{d}", .{i});
        messages[i] = msg;
        signatures[i] = try keypair.sign(msg);
        public_keys[i] = keypair.public_key;
    }

    const results = try verifyBatchWithArena(
        &arena,
        messages,
        signatures,
        public_keys,
    );

    // All should be valid
    for (results) |valid| {
        try testing.expect(valid);
    }
}

test "CryptoWorkspace basic" {
    var workspace = CryptoWorkspace.init(testing.allocator);
    defer workspace.deinit();

    const keypair = asym.ed25519.generate();
    const message = "test";

    const sig = try workspace.sign(message, keypair.private_key);
    const valid = asym.ed25519.verify(message, sig, keypair.public_key);
    try testing.expect(valid);
}

test "CryptoWorkspace reset and reuse" {
    var workspace = CryptoWorkspace.init(testing.allocator);
    defer workspace.deinit();

    // First batch
    {
        const hash1 = workspace.hash("data1");
        _ = hash1;
        workspace.reset();
    }

    // Second batch (reuses memory)
    {
        const hash2 = workspace.hash("data2");
        _ = hash2;
        workspace.reset();
    }

    // Should not leak memory (verified by deinit)
}

test "CryptoWorkspace batch operations" {
    var workspace = CryptoWorkspace.init(testing.allocator);
    defer workspace.deinit();

    const messages = &[_][]const u8{ "msg1", "msg2", "msg3" };
    const hashes = try workspace.hashBatch(messages);

    try testing.expectEqual(@as(usize, 3), hashes.len);
}

test "CryptoBufferPool" {
    var pool = try CryptoBufferPool.init(testing.allocator, 5, 1024);
    defer pool.deinit();

    // Acquire buffers
    var buf1 = try pool.acquire();
    var buf2 = try pool.acquire();

    try testing.expectEqual(@as(usize, 1024), buf1.len);
    try testing.expectEqual(@as(usize, 1024), buf2.len);

    // Release buffers
    pool.release(buf1);
    pool.release(buf2);

    // Can acquire again
    var buf3 = try pool.acquire();
    try testing.expectEqual(@as(usize, 1024), buf3.len);
}

test "CryptoBufferPool exhaustion" {
    var pool = try CryptoBufferPool.init(testing.allocator, 2, 64);
    defer pool.deinit();

    _ = try pool.acquire();
    _ = try pool.acquire();

    // Third acquire should fail
    const result = pool.acquire();
    try testing.expectError(error.OutOfBuffers, result);
}
