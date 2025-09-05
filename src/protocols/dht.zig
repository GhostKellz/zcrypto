//! DHT (Distributed Hash Table) Node ID Generation and Routing Security
//!
//! Provides secure node ID generation, proximity metrics, and cryptographic
//! verification for DHT-based routing systems like Kademlia.

const std = @import("std");
const asym = @import("../asym.zig");
const hash = @import("../hash.zig");
const rand = @import("../rand.zig");

/// DHT protocol errors
pub const DHTError = error{
    InvalidNodeId,
    InvalidPublicKey,
    InvalidDistance,
    InvalidRoutingTable,
    NodeNotFound,
    InvalidProof,
};

/// DHT configuration constants
pub const NODE_ID_SIZE = 32; // 256-bit node IDs
pub const MAX_ROUTING_TABLE_SIZE = 1000;
pub const BUCKET_SIZE = 20; // k-bucket size
pub const ALPHA = 3; // Concurrency parameter for lookups

/// DHT node identifier
pub const NodeId = [NODE_ID_SIZE]u8;

/// DHT node with cryptographic identity
pub const DHTNode = struct {
    id: NodeId,
    public_key: [32]u8,
    keypair: ?asym.Ed25519KeyPair, // Only present for local node
    
    /// Create new DHT node with generated identity
    pub fn init() DHTNode {
        const keypair = asym.generateEd25519();
        const node_id = generateNodeId(keypair.public_key);
        
        return DHTNode{
            .id = node_id,
            .public_key = keypair.public_key,
            .keypair = keypair,
        };
    }
    
    /// Create DHT node from existing keypair
    pub fn fromKeypair(keypair: asym.Ed25519KeyPair) DHTNode {
        const node_id = generateNodeId(keypair.public_key);
        
        return DHTNode{
            .id = node_id,
            .public_key = keypair.public_key,
            .keypair = keypair,
        };
    }
    
    /// Create remote DHT node (no private key)
    pub fn fromPublicKey(public_key: [32]u8) DHTNode {
        const node_id = generateNodeId(public_key);
        
        return DHTNode{
            .id = node_id,
            .public_key = public_key,
            .keypair = null,
        };
    }
    
    /// Calculate XOR distance to another node
    pub fn distanceTo(self: DHTNode, other: NodeId) NodeId {
        return xorDistance(self.id, other);
    }
    
    /// Check if this node is closer to target than other node
    pub fn isCloserTo(self: DHTNode, target: NodeId, other: NodeId) bool {
        const self_distance = self.distanceTo(target);
        const other_distance = xorDistance(other, target);
        return compareDistance(self_distance, other_distance) < 0;
    }
    
    /// Sign a message with this node's private key
    pub fn signMessage(self: DHTNode, message: []const u8) ![64]u8 {
        if (self.keypair) |keypair| {
            return try keypair.sign(message);
        } else {
            return DHTError.InvalidPublicKey;
        }
    }
    
    /// Verify a signature from this node
    pub fn verifySignature(self: DHTNode, message: []const u8, signature: [64]u8) bool {
        return asym.ed25519.verify(message, signature, self.public_key);
    }
    
    /// Clean up sensitive data
    pub fn deinit(self: *DHTNode) void {
        if (self.keypair) |*keypair| {
            keypair.zeroize();
        }
    }
};

/// DHT routing table entry
pub const RoutingEntry = struct {
    node: DHTNode,
    last_seen: u64, // Unix timestamp
    ping_count: u32,
    fail_count: u32,
    
    /// Check if entry is still valid
    pub fn isValid(self: RoutingEntry, current_time: u64, max_age: u64) bool {
        return (current_time - self.last_seen) <= max_age and self.fail_count < 3;
    }
    
    /// Update last seen timestamp
    pub fn touch(self: *RoutingEntry) void {
        self.last_seen = @intCast(std.time.timestamp());
        self.fail_count = 0;
    }
    
    /// Mark as failed
    pub fn markFailed(self: *RoutingEntry) void {
        self.fail_count += 1;
    }
};

/// K-bucket for routing table
pub const KBucket = struct {
    entries: std.ArrayList(RoutingEntry),
    allocator: std.mem.Allocator,
    
    /// Initialize k-bucket
    pub fn init(allocator: std.mem.Allocator) KBucket {
        return KBucket{
            .entries = .{},
            .allocator = allocator,
        };
    }
    
    /// Add or update node in bucket
    pub fn addNode(self: *KBucket, node: DHTNode) !void {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        
        // Check if node already exists
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, &entry.node.id, &node.id)) {
                // Update existing entry
                entry.touch();
                return;
            }
        }
        
        // Add new entry if bucket has space
        if (self.entries.items.len < BUCKET_SIZE) {
            try self.entries.append(self.allocator, RoutingEntry{
                .node = node,
                .last_seen = current_time,
                .ping_count = 0,
                .fail_count = 0,
            });
        } else {
            // Bucket is full, replace oldest entry
            var oldest_index: usize = 0;
            var oldest_time = self.entries.items[0].last_seen;
            
            for (self.entries.items, 0..) |entry, i| {
                if (entry.last_seen < oldest_time) {
                    oldest_time = entry.last_seen;
                    oldest_index = i;
                }
            }
            
            self.entries.items[oldest_index] = RoutingEntry{
                .node = node,
                .last_seen = current_time,
                .ping_count = 0,
                .fail_count = 0,
            };
        }
    }
    
    /// Remove node from bucket
    pub fn removeNode(self: *KBucket, node_id: NodeId) bool {
        for (self.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, &entry.node.id, &node_id)) {
                _ = self.entries.swapRemove(i);
                return true;
            }
        }
        return false;
    }
    
    /// Get closest nodes to target
    pub fn getClosestNodes(self: KBucket, target: NodeId, count: usize, results: []DHTNode) usize {
        const sorted_entries = self.entries.items;
        
        // Sort by distance to target
        std.sort.heap(RoutingEntry, sorted_entries, target, struct {
            fn lessThan(context: NodeId, a: RoutingEntry, b: RoutingEntry) bool {
                const dist_a = xorDistance(a.node.id, context);
                const dist_b = xorDistance(b.node.id, context);
                return compareDistance(dist_a, dist_b) < 0;
            }
        }.lessThan);
        
        const num_results = @min(count, sorted_entries.len);
        for (0..num_results) |i| {
            results[i] = sorted_entries[i].node;
        }
        
        return num_results;
    }
    
    /// Clean up expired entries
    pub fn cleanup(self: *KBucket, max_age: u64) void {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (!self.entries.items[i].isValid(current_time, max_age)) {
                _ = self.entries.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
    
    /// Clean up resources
    pub fn deinit(self: *KBucket) void {
        self.entries.deinit(self.allocator);
    }
};

/// DHT routing table
pub const RoutingTable = struct {
    buckets: [256]KBucket, // One bucket per bit position
    local_node: DHTNode,
    allocator: std.mem.Allocator,
    
    /// Initialize routing table
    pub fn init(allocator: std.mem.Allocator, local_node: DHTNode) RoutingTable {
        var table = RoutingTable{
            .buckets = undefined,
            .local_node = local_node,
            .allocator = allocator,
        };
        
        // Initialize all buckets
        for (0..256) |i| {
            table.buckets[i] = KBucket.init(allocator);
        }
        
        return table;
    }
    
    /// Add node to routing table
    pub fn addNode(self: *RoutingTable, node: DHTNode) !void {
        // Don't add ourselves
        if (std.mem.eql(u8, &node.id, &self.local_node.id)) {
            return;
        }
        
        const bucket_index = getBucketIndex(self.local_node.id, node.id);
        try self.buckets[bucket_index].addNode(node);
    }
    
    /// Remove node from routing table
    pub fn removeNode(self: *RoutingTable, node_id: NodeId) bool {
        const bucket_index = getBucketIndex(self.local_node.id, node_id);
        return self.buckets[bucket_index].removeNode(node_id);
    }
    
    /// Find closest nodes to target
    pub fn findClosestNodes(self: *RoutingTable, target: NodeId, count: usize, allocator: std.mem.Allocator) ![]DHTNode {
        var all_nodes: std.ArrayList(DHTNode) = .{};
        defer all_nodes.deinit(allocator);
        
        // Collect nodes from all buckets
        for (self.buckets) |bucket| {
            for (bucket.entries.items) |entry| {
                try all_nodes.append(allocator, entry.node);
            }
        }
        
        // Sort by distance to target
        std.sort.heap(DHTNode, all_nodes.items, target, struct {
            fn lessThan(context: NodeId, a: DHTNode, b: DHTNode) bool {
                const dist_a = xorDistance(a.id, context);
                const dist_b = xorDistance(b.id, context);
                return compareDistance(dist_a, dist_b) < 0;
            }
        }.lessThan);
        
        // Return closest nodes
        const num_results = @min(count, all_nodes.items.len);
        const results = try allocator.alloc(DHTNode, num_results);
        @memcpy(results, all_nodes.items[0..num_results]);
        
        return results;
    }
    
    /// Clean up expired entries
    pub fn cleanup(self: *RoutingTable, max_age: u64) void {
        for (&self.buckets) |*bucket| {
            bucket.cleanup(max_age);
        }
    }
    
    /// Get routing table statistics
    pub fn getStats(self: RoutingTable) struct { total_nodes: usize, active_buckets: usize } {
        var total_nodes: usize = 0;
        var active_buckets: usize = 0;
        
        for (self.buckets) |bucket| {
            const bucket_size = bucket.entries.items.len;
            if (bucket_size > 0) {
                total_nodes += bucket_size;
                active_buckets += 1;
            }
        }
        
        return .{ .total_nodes = total_nodes, .active_buckets = active_buckets };
    }
    
    /// Clean up resources
    pub fn deinit(self: *RoutingTable) void {
        for (&self.buckets) |*bucket| {
            bucket.deinit();
        }
    }
};

/// DHT lookup operation
pub const DHTLookup = struct {
    target: NodeId,
    closest_nodes: std.ArrayList(DHTNode),
    queried_nodes: std.HashMap(NodeId, void, std.hash_map.AutoContext(NodeId), std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    /// Initialize lookup
    pub fn init(allocator: std.mem.Allocator, target: NodeId) DHTLookup {
        return DHTLookup{
            .target = target,
            .closest_nodes = .{},
            .queried_nodes = std.HashMap(NodeId, void, std.hash_map.AutoContext(NodeId), std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Add nodes to lookup
    pub fn addNodes(self: *DHTLookup, nodes: []const DHTNode) !void {
        for (nodes) |node| {
            try self.closest_nodes.append(self.allocator, node);
        }
        
        // Sort by distance to target
        std.sort.heap(DHTNode, self.closest_nodes.items, self.target, struct {
            fn lessThan(context: NodeId, a: DHTNode, b: DHTNode) bool {
                const dist_a = xorDistance(a.id, context);
                const dist_b = xorDistance(b.id, context);
                return compareDistance(dist_a, dist_b) < 0;
            }
        }.lessThan);
        
        // Keep only closest nodes
        if (self.closest_nodes.items.len > BUCKET_SIZE) {
            self.closest_nodes.shrinkRetainingCapacity(BUCKET_SIZE);
        }
    }
    
    /// Get next nodes to query (returns slice of internal storage)
    pub fn getNextNodes(self: *DHTLookup, count: usize) []DHTNode {
        var result_count: usize = 0;
        
        // Find unqueried nodes and move them to front
        for (self.closest_nodes.items) |node| {
            if (!self.queried_nodes.contains(node.id)) {
                if (result_count >= count) break;
                if (result_count < self.closest_nodes.items.len) {
                    self.closest_nodes.items[result_count] = node;
                }
                result_count += 1;
            }
        }
        
        const actual_count = @min(result_count, count);
        return self.closest_nodes.items[0..actual_count];
    }
    
    /// Mark node as queried
    pub fn markQueried(self: *DHTLookup, node_id: NodeId) !void {
        try self.queried_nodes.put(node_id, {});
    }
    
    /// Check if lookup is complete
    pub fn isComplete(self: DHTLookup) bool {
        // Lookup is complete if we've queried all closest nodes
        for (self.closest_nodes.items) |node| {
            if (!self.queried_nodes.contains(node.id)) {
                return false;
            }
        }
        return true;
    }
    
    /// Get final results
    pub fn getResults(self: DHTLookup) []const DHTNode {
        return self.closest_nodes.items;
    }
    
    /// Clean up resources
    pub fn deinit(self: *DHTLookup) void {
        self.closest_nodes.deinit(self.allocator);
        self.queried_nodes.deinit();
    }
};

/// Node proof for cryptographic verification
pub const NodeProof = struct {
    node_id: NodeId,
    public_key: [32]u8,
    signature: [64]u8,
    timestamp: u64,
    
    /// Create proof for a node
    pub fn create(node: DHTNode, message: []const u8) !NodeProof {
        const timestamp = @as(u64, @intCast(std.time.timestamp()));
        
        // Create message to sign
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&node.id);
        hasher.update(&node.public_key);
        hasher.update(message);
        const timestamp_bytes = std.mem.toBytes(timestamp);
        hasher.update(&timestamp_bytes);
        var message_hash: [32]u8 = undefined;
        hasher.final(&message_hash);
        
        // Sign the message
        const signature = try node.signMessage(&message_hash);
        
        return NodeProof{
            .node_id = node.id,
            .public_key = node.public_key,
            .signature = signature,
            .timestamp = timestamp,
        };
    }
    
    /// Verify proof
    pub fn verify(self: NodeProof, message: []const u8, max_age: u64) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        
        // Check timestamp
        if (current_time - self.timestamp > max_age) {
            return false;
        }
        
        // Verify node ID matches public key
        const expected_id = generateNodeId(self.public_key);
        if (!std.mem.eql(u8, &self.node_id, &expected_id)) {
            return false;
        }
        
        // Verify signature
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.node_id);
        hasher.update(&self.public_key);
        hasher.update(message);
        const timestamp_bytes = std.mem.toBytes(self.timestamp);
        hasher.update(&timestamp_bytes);
        var message_hash: [32]u8 = undefined;
        hasher.final(&message_hash);
        
        return asym.ed25519.verify(&message_hash, self.signature, self.public_key);
    }
};

// Helper functions

/// Generate deterministic node ID from public key
pub fn generateNodeId(public_key: [32]u8) NodeId {
    return hash.sha256(@as([]const u8, &public_key));
}

/// Calculate XOR distance between two node IDs
pub fn xorDistance(a: NodeId, b: NodeId) NodeId {
    var result: NodeId = undefined;
    for (0..NODE_ID_SIZE) |i| {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

/// Compare two distances (returns -1, 0, or 1)
pub fn compareDistance(a: NodeId, b: NodeId) i8 {
    for (0..NODE_ID_SIZE) |i| {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/// Get bucket index for a node ID relative to local node
pub fn getBucketIndex(local_id: NodeId, node_id: NodeId) usize {
    const distance = xorDistance(local_id, node_id);
    
    // Find the position of the most significant bit
    for (0..NODE_ID_SIZE) |i| {
        if (distance[i] != 0) {
            const byte = distance[i];
            const bit_pos = @clz(byte);
            return (i * 8) + (7 - bit_pos);
        }
    }
    
    return 255; // Should never happen for different node IDs
}

/// Generate random node ID (for testing)
pub fn generateRandomNodeId() NodeId {
    var node_id: NodeId = undefined;
    rand.fill(&node_id);
    return node_id;
}

// Tests

test "node ID generation" {
    const keypair = asym.generateEd25519();
    const node_id = generateNodeId(keypair.public_key);
    
    // Node ID should be deterministic
    const node_id2 = generateNodeId(keypair.public_key);
    try std.testing.expectEqualSlices(u8, &node_id, &node_id2);
    
    // Different keys should produce different node IDs
    const keypair2 = asym.generateEd25519();
    const node_id3 = generateNodeId(keypair2.public_key);
    try std.testing.expect(!std.mem.eql(u8, &node_id, &node_id3));
}

test "XOR distance calculation" {
    const node1: NodeId = [_]u8{0x00} ** 32;
    const node2: NodeId = [_]u8{0xFF} ** 32;
    const node3: NodeId = [_]u8{0x00} ** 32;
    
    const dist1 = xorDistance(node1, node2);
    const dist2 = xorDistance(node1, node3);
    
    // Distance from node1 to node2 should be maximum
    try std.testing.expect(dist1[0] == 0xFF);
    
    // Distance from node1 to node3 should be zero
    try std.testing.expect(dist2[0] == 0x00);
}

test "DHT node creation and operations" {
    var node1 = DHTNode.init();
    defer node1.deinit();
    
    var node2 = DHTNode.init();
    defer node2.deinit();
    
    // Node IDs should be different
    try std.testing.expect(!std.mem.eql(u8, &node1.id, &node2.id));
    
    // Test distance calculation
    const distance = node1.distanceTo(node2.id);
    try std.testing.expect(!std.mem.eql(u8, &distance, &[_]u8{0} ** 32));
    
    // Test message signing and verification
    const message = "test message";
    const signature = try node1.signMessage(message);
    try std.testing.expect(node1.verifySignature(message, signature));
    try std.testing.expect(!node2.verifySignature(message, signature));
}

test "routing table operations" {
    const allocator = std.testing.allocator;
    
    var local_node = DHTNode.init();
    defer local_node.deinit();
    
    var routing_table = RoutingTable.init(allocator, local_node);
    defer routing_table.deinit();
    
    // Add some nodes
    var nodes: [10]DHTNode = undefined;
    for (0..10) |i| {
        nodes[i] = DHTNode.init();
        try routing_table.addNode(nodes[i]);
    }
    defer {
        for (&nodes) |*node| {
            node.deinit();
        }
    }
    
    // Check statistics
    const stats = routing_table.getStats();
    try std.testing.expect(stats.total_nodes == 10);
    try std.testing.expect(stats.active_buckets > 0);
    
    // Test closest nodes lookup
    const target = generateRandomNodeId();
    const closest = try routing_table.findClosestNodes(target, 5, allocator);
    defer allocator.free(closest);
    
    try std.testing.expect(closest.len <= 5);
    try std.testing.expect(closest.len <= 10);
}

test "DHT lookup operations" {
    const allocator = std.testing.allocator;
    
    var local_node = DHTNode.init();
    defer local_node.deinit();
    
    const target = generateRandomNodeId();
    var lookup = DHTLookup.init(allocator, target);
    defer lookup.deinit();
    
    // Add some nodes
    var nodes: [5]DHTNode = undefined;
    for (0..5) |i| {
        nodes[i] = DHTNode.init();
    }
    defer {
        for (&nodes) |*node| {
            node.deinit();
        }
    }
    
    try lookup.addNodes(&nodes);
    
    // Get nodes to query
    const next_nodes = lookup.getNextNodes(3);
    try std.testing.expect(next_nodes.len <= 3);
    
    // Mark nodes as queried
    for (next_nodes) |node| {
        try lookup.markQueried(node.id);
    }
    
    // Check completion status
    const is_complete = lookup.isComplete();
    try std.testing.expect(is_complete or next_nodes.len <= 3);
}

test "node proof creation and verification" {
    var node = DHTNode.init();
    defer node.deinit();
    
    const message = "proof test message";
    const proof = try NodeProof.create(node, message);
    
    // Verify proof
    try std.testing.expect(proof.verify(message, 3600)); // 1 hour max age
    
    // Wrong message should fail
    try std.testing.expect(!proof.verify("wrong message", 3600));
    
    // Test node ID consistency
    try std.testing.expectEqualSlices(u8, &proof.node_id, &node.id);
    try std.testing.expectEqualSlices(u8, &proof.public_key, &node.public_key);
}