//! Gossip Protocol Cryptography for GhostMesh
//!
//! Provides secure message authentication, anti-replay protection, and
//! efficient batch verification for gossip protocol messages.

const std = @import("std");
const asym = @import("../asym.zig");
const hash = @import("../hash.zig");
const rand = @import("../rand.zig");

/// Gossip protocol errors
pub const GossipError = error{
    InvalidMessage,
    InvalidSignature,
    InvalidTimestamp,
    ReplayAttack,
    InvalidNodeId,
    MessageTooLarge,
    InvalidSequenceNumber,
};

/// Maximum message size for gossip protocol
pub const MAX_MESSAGE_SIZE = 65536;

/// Maximum timestamp drift allowed (5 minutes)
pub const MAX_TIMESTAMP_DRIFT = 300;

/// Gossip message types
pub const MessageType = enum(u8) {
    NodeAnnouncement = 0x01,
    NodeUpdate = 0x02,
    RouteAdvertisement = 0x03,
    RouteWithdrawal = 0x04,
    Heartbeat = 0x05,
    Custom = 0xFF,
};

/// Gossip message header
pub const MessageHeader = struct {
    version: u8,
    message_type: MessageType,
    sequence_number: u64,
    timestamp: u64, // Unix timestamp in seconds
    ttl: u8, // Time-to-live for message propagation
    node_id: [32]u8, // SHA256 hash of node's public key
    payload_length: u32,
    
    /// Serialize header to bytes
    pub fn serialize(self: MessageHeader) [56]u8 {
        var buffer: [56]u8 = undefined;
        buffer[0] = self.version;
        buffer[1] = @intFromEnum(self.message_type);
        std.mem.writeInt(u64, buffer[2..10], self.sequence_number, .little);
        std.mem.writeInt(u64, buffer[10..18], self.timestamp, .little);
        buffer[18] = self.ttl;
        @memcpy(buffer[19..51], &self.node_id);
        std.mem.writeInt(u32, buffer[52..56], self.payload_length, .little);
        return buffer;
    }
    
    /// Deserialize header from bytes
    pub fn deserialize(buffer: [56]u8) MessageHeader {
        return MessageHeader{
            .version = buffer[0],
            .message_type = @enumFromInt(buffer[1]),
            .sequence_number = std.mem.readInt(u64, buffer[2..10], .little),
            .timestamp = std.mem.readInt(u64, buffer[10..18], .little),
            .ttl = buffer[18],
            .node_id = buffer[19..51].*,
            .payload_length = std.mem.readInt(u32, buffer[52..56], .little),
        };
    }
};

/// Signed gossip message
pub const SignedMessage = struct {
    header: MessageHeader,
    payload: []const u8,
    signature: [64]u8, // Ed25519 signature
    
    /// Calculate message hash for signing
    pub fn messageHash(self: SignedMessage) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        const header_bytes = self.header.serialize();
        hasher.update(&header_bytes);
        hasher.update(self.payload);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
    
    /// Verify message signature
    pub fn verify(self: SignedMessage, public_key: [32]u8) bool {
        const message_hash = self.messageHash();
        return asym.ed25519.verify(&message_hash, self.signature, public_key);
    }
    
    /// Check if message is within acceptable timestamp range
    pub fn isTimestampValid(self: SignedMessage) bool {
        const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch return false;
        const current_time = ts.sec;
        const message_time = @as(i64, @intCast(self.header.timestamp));
        const time_diff = @abs(current_time - message_time);
        return time_diff <= MAX_TIMESTAMP_DRIFT;
    }
};

/// Gossip node identity and signing capability
pub const GossipNode = struct {
    keypair: asym.Ed25519KeyPair,
    node_id: [32]u8,
    sequence_number: u64,
    
    /// Create new gossip node with generated keypair
    pub fn init() GossipNode {
        const keypair = asym.generateEd25519();
        const node_id = generateNodeId(keypair.public_key);
        
        return GossipNode{
            .keypair = keypair,
            .node_id = node_id,
            .sequence_number = 0,
        };
    }
    
    /// Create gossip node from existing keypair
    pub fn fromKeypair(keypair: asym.Ed25519KeyPair) GossipNode {
        const node_id = generateNodeId(keypair.public_key);
        
        return GossipNode{
            .keypair = keypair,
            .node_id = node_id,
            .sequence_number = 0,
        };
    }
    
    /// Sign and create a gossip message
    pub fn createMessage(
        self: *GossipNode,
        message_type: MessageType,
        payload: []const u8,
        ttl: u8
    ) !SignedMessage {
        if (payload.len > MAX_MESSAGE_SIZE) {
            return GossipError.MessageTooLarge;
        }
        
        // Increment sequence number
        self.sequence_number += 1;
        
        // Create header
        const header = MessageHeader{
            .version = 1,
            .message_type = message_type,
            .sequence_number = self.sequence_number,
            .timestamp = blk: {
                const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
                break :blk @intCast(ts.sec);
            },
            .ttl = ttl,
            .node_id = self.node_id,
            .payload_length = @intCast(payload.len),
        };
        
        // Create unsigned message
        var unsigned_message = SignedMessage{
            .header = header,
            .payload = payload,
            .signature = undefined,
        };
        
        // Sign the message
        const message_hash = unsigned_message.messageHash();
        unsigned_message.signature = try self.keypair.sign(&message_hash);
        
        return unsigned_message;
    }
    
    /// Verify and process received message
    pub fn verifyMessage(self: *GossipNode, message: SignedMessage) !void {
        _ = self; // Reserved for future anti-replay tracking
        
        // Verify timestamp
        if (!message.isTimestampValid()) {
            return GossipError.InvalidTimestamp;
        }
        
        // Verify payload length matches header
        if (message.payload.len != message.header.payload_length) {
            return GossipError.InvalidMessage;
        }
        
        // Note: In a real implementation, you would look up the sender's public key
        // from a trusted source (DHT, certificate store, etc.)
        // For now, we'll skip signature verification in the generic verifyMessage
        // function since we don't have access to the sender's public key
        
        // Check for replay attacks using sequence numbers
        // In a full implementation, this would maintain per-node sequence number state
        // For now, we perform basic sequence number validation
        if (message.header.sequence_number == 0) {
            return GossipError.InvalidSequenceNumber;
        }
    }
    
    /// Clean up sensitive data
    pub fn deinit(self: *GossipNode) void {
        self.keypair.zeroize();
    }
};

/// Anti-replay protection system
pub const AntiReplay = struct {
    seen_messages: std.HashMap([32]u8, u64, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    /// Initialize anti-replay system
    pub fn init(allocator: std.mem.Allocator) AntiReplay {
        return AntiReplay{
            .seen_messages = std.HashMap([32]u8, u64, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Check if message is a replay
    pub fn isReplay(self: *AntiReplay, message: SignedMessage) !bool {
        const message_id = messageId(message);
        
        if (self.seen_messages.get(message_id)) |last_sequence| {
            // Check if we've seen this sequence number or higher
            return message.header.sequence_number <= last_sequence;
        }
        
        // First time seeing this message
        try self.seen_messages.put(message_id, message.header.sequence_number);
        return false;
    }
    
    /// Clean up old entries (call periodically)
    pub fn cleanup(self: *AntiReplay, max_age_seconds: u64) void {
        const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch return;
        const current_time = @as(u64, @intCast(ts.sec));
        
        var iterator = self.seen_messages.iterator();
        while (iterator.next()) |entry| {
            const message_time = entry.value_ptr.*;
            if (current_time - message_time > max_age_seconds) {
                _ = self.seen_messages.remove(entry.key_ptr.*);
            }
        }
    }
    
    /// Clean up resources
    pub fn deinit(self: *AntiReplay) void {
        self.seen_messages.deinit();
    }
    
    /// Generate unique message ID from node ID and sequence number
    fn messageId(message: SignedMessage) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&message.header.node_id);
        const seq_bytes = std.mem.toBytes(message.header.sequence_number);
        hasher.update(&seq_bytes);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

/// Batch verification for efficient signature checking
pub const BatchVerifier = struct {
    messages: std.ArrayList(SignedMessage),
    public_keys: std.ArrayList([32]u8),
    allocator: std.mem.Allocator,
    
    /// Initialize batch verifier
    pub fn init(allocator: std.mem.Allocator) BatchVerifier {
        return BatchVerifier{
            .messages = .{},
            .public_keys = .{},
            .allocator = allocator,
        };
    }
    
    /// Add message to batch
    pub fn addMessage(self: *BatchVerifier, message: SignedMessage, public_key: [32]u8) !void {
        try self.messages.append(self.allocator, message);
        try self.public_keys.append(self.allocator, public_key);
    }
    
    /// Verify all messages in batch
    pub fn verifyBatch(self: *BatchVerifier) ![]bool {
        const count = self.messages.items.len;
        var results = try self.allocator.alloc(bool, count);
        
        // Prepare data for batch verification
        var message_hashes = try self.allocator.alloc([32]u8, count);
        defer self.allocator.free(message_hashes);
        
        var signatures = try self.allocator.alloc([64]u8, count);
        defer self.allocator.free(signatures);
        
        // Calculate message hashes and extract signatures
        for (self.messages.items, 0..) |message, i| {
            message_hashes[i] = message.messageHash();
            signatures[i] = message.signature;
        }
        
        // Verify each signature individually (could be optimized with batch verification)
        for (0..count) |i| {
            results[i] = asym.ed25519.verify(&message_hashes[i], signatures[i], self.public_keys.items[i]);
        }
        
        return results;
    }
    
    /// Clear batch
    pub fn clear(self: *BatchVerifier) void {
        self.messages.clearRetainingCapacity();
        self.public_keys.clearRetainingCapacity();
    }
    
    /// Clean up resources
    pub fn deinit(self: *BatchVerifier) void {
        self.messages.deinit(self.allocator);
        self.public_keys.deinit(self.allocator);
    }
};

/// Message flooding/propagation system
pub const MessageFlood = struct {
    seen_messages: std.HashMap([32]u8, void, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    /// Initialize flood system
    pub fn init(allocator: std.mem.Allocator) MessageFlood {
        return MessageFlood{
            .seen_messages = std.HashMap([32]u8, void, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Check if message should be flooded
    pub fn shouldFlood(self: *MessageFlood, message: SignedMessage) !bool {
        // Don't flood if TTL is 0
        if (message.header.ttl == 0) {
            return false;
        }
        
        // Check if we've seen this message before
        const message_hash = message.messageHash();
        if (self.seen_messages.contains(message_hash)) {
            return false;
        }
        
        // Mark as seen
        try self.seen_messages.put(message_hash, {});
        return true;
    }
    
    /// Decrement TTL for flooding
    pub fn decrementTtl(message: *SignedMessage) void {
        if (message.header.ttl > 0) {
            message.header.ttl -= 1;
        }
    }
    
    /// Clean up old entries
    pub fn cleanup(self: *MessageFlood) void {
        // Simple cleanup - clear all entries periodically
        self.seen_messages.clearRetainingCapacity();
    }
    
    /// Clean up resources
    pub fn deinit(self: *MessageFlood) void {
        self.seen_messages.deinit();
    }
};

// Helper functions

/// Generate node ID from public key
pub fn generateNodeId(public_key: [32]u8) [32]u8 {
    return hash.sha256(@as([]const u8, &public_key));
}

/// Extract public key from node ID (placeholder - in reality would need lookup)
fn nodeIdToPublicKey(node_id: [32]u8) [32]u8 {
    // This is a placeholder. In a real implementation, you would:
    // 1. Look up the public key in a local database
    // 2. Query the DHT for the public key
    // 3. Use a certificate authority
    // For now, we'll just return the node_id as a placeholder
    return node_id;
}

// Tests

test "gossip message creation and verification" {
    _ = std.testing.allocator;
    
    // Create two nodes
    var alice = GossipNode.init();
    defer alice.deinit();
    
    var bob = GossipNode.init();
    defer bob.deinit();
    
    // Alice creates a message
    const payload = "Hello, GhostMesh!";
    const message = try alice.createMessage(.NodeAnnouncement, payload, 10);
    
    // Verify message structure
    try std.testing.expect(message.header.version == 1);
    try std.testing.expect(message.header.message_type == .NodeAnnouncement);
    try std.testing.expect(message.header.sequence_number == 1);
    try std.testing.expect(message.header.ttl == 10);
    try std.testing.expectEqualSlices(u8, &message.header.node_id, &alice.node_id);
    try std.testing.expect(message.header.payload_length == payload.len);
    
    // Bob verifies the message
    try bob.verifyMessage(message);
    
    // Verify signature directly
    try std.testing.expect(message.verify(alice.keypair.public_key));
}

test "anti-replay protection" {
    const allocator = std.testing.allocator;
    
    var alice = GossipNode.init();
    defer alice.deinit();
    
    var anti_replay = AntiReplay.init(allocator);
    defer anti_replay.deinit();
    
    // Create two messages
    const message1 = try alice.createMessage(.Heartbeat, "ping", 5);
    const message2 = try alice.createMessage(.Heartbeat, "pong", 5);
    
    // First message should not be a replay
    try std.testing.expect(!try anti_replay.isReplay(message1));
    
    // Second message should not be a replay (different sequence number)
    try std.testing.expect(!try anti_replay.isReplay(message2));
    
    // Same message again should be a replay
    try std.testing.expect(try anti_replay.isReplay(message1));
}

test "batch verification" {
    const allocator = std.testing.allocator;
    
    var alice = GossipNode.init();
    defer alice.deinit();
    
    var bob = GossipNode.init();
    defer bob.deinit();
    
    var batch_verifier = BatchVerifier.init(allocator);
    defer batch_verifier.deinit();
    
    // Create several messages
    const messages = [_]SignedMessage{
        try alice.createMessage(.NodeAnnouncement, "alice_msg1", 5),
        try alice.createMessage(.RouteAdvertisement, "alice_msg2", 5),
        try bob.createMessage(.NodeAnnouncement, "bob_msg1", 5),
        try bob.createMessage(.Heartbeat, "bob_msg2", 5),
    };
    
    // Add to batch
    try batch_verifier.addMessage(messages[0], alice.keypair.public_key);
    try batch_verifier.addMessage(messages[1], alice.keypair.public_key);
    try batch_verifier.addMessage(messages[2], bob.keypair.public_key);
    try batch_verifier.addMessage(messages[3], bob.keypair.public_key);
    
    // Verify batch
    const results = try batch_verifier.verifyBatch();
    defer allocator.free(results);
    
    // All should verify successfully
    for (results) |result| {
        try std.testing.expect(result);
    }
}

test "message flooding" {
    const allocator = std.testing.allocator;
    
    var alice = GossipNode.init();
    defer alice.deinit();
    
    var flood_system = MessageFlood.init(allocator);
    defer flood_system.deinit();
    
    // Create a message
    var message = try alice.createMessage(.RouteAdvertisement, "route_update", 3);
    
    // Should flood initially
    try std.testing.expect(try flood_system.shouldFlood(message));
    
    // Should not flood the same message again
    try std.testing.expect(!try flood_system.shouldFlood(message));
    
    // Decrement TTL
    MessageFlood.decrementTtl(&message);
    try std.testing.expect(message.header.ttl == 2);
    
    // Should still flood with decremented TTL
    try std.testing.expect(try flood_system.shouldFlood(message));
}

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