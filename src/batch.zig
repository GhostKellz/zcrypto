//! Batch operations for high-performance cryptographic operations
//!
//! Provides batch signing, verification, and other crypto operations
//! to improve performance when processing multiple operations.

const std = @import("std");
const asym = @import("asym.zig");
const hash = @import("hash.zig");

/// Algorithm types for batch operations
pub const Algorithm = enum {
    ed25519,
    secp256k1,
    secp256r1,
};

/// Batch verify multiple Ed25519 signatures
pub fn verifyBatchEd25519(messages: []const []const u8, signatures: []const [64]u8, public_keys: []const [32]u8, allocator: std.mem.Allocator) ![]bool {
    if (messages.len != signatures.len or messages.len != public_keys.len) {
        return error.LengthMismatch;
    }
    
    var results = try allocator.alloc(bool, messages.len);
    
    for (messages, signatures, public_keys, 0..) |message, signature, pubkey, i| {
        results[i] = asym.ed25519.verify(message, signature, pubkey);
    }
    
    return results;
}

/// Batch verify multiple secp256k1 signatures 
pub fn verifyBatchSecp256k1(message_hashes: []const [32]u8, signatures: []const [64]u8, public_keys: []const [33]u8, allocator: std.mem.Allocator) ![]bool {
    if (message_hashes.len != signatures.len or message_hashes.len != public_keys.len) {
        return error.LengthMismatch;
    }
    
    var results = try allocator.alloc(bool, message_hashes.len);
    
    for (message_hashes, signatures, public_keys, 0..) |hash_msg, signature, pubkey, i| {
        results[i] = asym.secp256k1.verify(hash_msg, signature, pubkey);
    }
    
    return results;
}

/// Generic batch verification function
pub fn verifyBatch(messages: []const []const u8, signatures: []const [64]u8, public_keys: []const []const u8, algorithm: Algorithm, allocator: std.mem.Allocator) ![]bool {
    switch (algorithm) {
        .ed25519 => {
            // Convert public keys to [32]u8
            var ed25519_keys = try allocator.alloc([32]u8, public_keys.len);
            defer allocator.free(ed25519_keys);
            
            for (public_keys, 0..) |key, i| {
                if (key.len != 32) return error.InvalidKeySize;
                @memcpy(&ed25519_keys[i], key);
            }
            
            return verifyBatchEd25519(messages, signatures, ed25519_keys, allocator);
        },
        .secp256k1 => {
            // Hash messages first for secp256k1
            var message_hashes = try allocator.alloc([32]u8, messages.len);
            defer allocator.free(message_hashes);
            
            for (messages, 0..) |message, i| {
                message_hashes[i] = hash.sha256(message);
            }
            
            // Convert public keys to [33]u8
            var secp256k1_keys = try allocator.alloc([33]u8, public_keys.len);
            defer allocator.free(secp256k1_keys);
            
            for (public_keys, 0..) |key, i| {
                if (key.len != 33) return error.InvalidKeySize;
                @memcpy(&secp256k1_keys[i], key);
            }
            
            return verifyBatchSecp256k1(message_hashes, signatures, secp256k1_keys, allocator);
        },
        .secp256r1 => {
            // Similar to secp256k1 but with secp256r1 verification
            var message_hashes = try allocator.alloc([32]u8, messages.len);
            defer allocator.free(message_hashes);
            
            for (messages, 0..) |message, i| {
                message_hashes[i] = hash.sha256(message);
            }
            
            var results = try allocator.alloc(bool, messages.len);
            
            for (message_hashes, signatures, public_keys, 0..) |hash_msg, signature, pubkey, i| {
                if (pubkey.len != 33) {
                    results[i] = false;
                    continue;
                }
                var key_array: [33]u8 = undefined;
                @memcpy(&key_array, pubkey);
                results[i] = asym.secp256r1.verify(hash_msg, signature, key_array);
            }
            
            return results;
        },
    }
}

/// Batch sign multiple messages with the same Ed25519 key
pub fn signBatchEd25519(messages: []const []const u8, private_key: [64]u8, allocator: std.mem.Allocator) ![][64]u8 {
    var signatures = try allocator.alloc([64]u8, messages.len);
    
    for (messages, 0..) |message, i| {
        signatures[i] = try asym.ed25519.sign(message, private_key);
    }
    
    return signatures;
}

/// Batch hash multiple messages
pub fn hashBatch(messages: []const []const u8, allocator: std.mem.Allocator) ![][32]u8 {
    var hashes = try allocator.alloc([32]u8, messages.len);
    
    for (messages, 0..) |message, i| {
        hashes[i] = hash.sha256(message);
    }
    
    return hashes;
}

/// Zero-copy in-place signing (when signature buffer is provided)
pub fn signInPlace(message: []const u8, private_key: [64]u8, signature: *[64]u8) !void {
    signature.* = try asym.ed25519.sign(message, private_key);
}

/// Zero-copy in-place hash computation
pub fn hashInPlace(message: []const u8, result: *[32]u8) void {
    result.* = hash.sha256(message);
}

test "batch verification ed25519" {
    const allocator = std.testing.allocator;
    
    // Generate test data
    const keypair1 = asym.ed25519.generate();
    const keypair2 = asym.ed25519.generate();
    
    const messages = [_][]const u8{ "message1", "message2" };
    const signatures = [_][64]u8{
        try keypair1.sign(messages[0]),
        try keypair2.sign(messages[1]),
    };
    const public_keys = [_][32]u8{ keypair1.public_key, keypair2.public_key };
    
    const results = try verifyBatchEd25519(&messages, &signatures, &public_keys, allocator);
    defer allocator.free(results);
    
    try std.testing.expect(results[0]);
    try std.testing.expect(results[1]);
}

test "batch signing ed25519" {
    const allocator = std.testing.allocator;
    
    const keypair = asym.ed25519.generate();
    const messages = [_][]const u8{ "msg1", "msg2", "msg3" };
    
    const signatures = try signBatchEd25519(&messages, keypair.private_key, allocator);
    defer allocator.free(signatures);
    
    try std.testing.expectEqual(@as(usize, 3), signatures.len);
    
    // Verify each signature
    for (messages, signatures) |message, signature| {
        try std.testing.expect(asym.ed25519.verify(message, signature, keypair.public_key));
    }
}

test "zero-copy operations" {
    const keypair = asym.ed25519.generate();
    const message = "test message";
    
    // Test in-place signing
    var signature: [64]u8 = undefined;
    try signInPlace(message, keypair.private_key, &signature);
    
    try std.testing.expect(asym.ed25519.verify(message, signature, keypair.public_key));
    
    // Test in-place hashing
    var hash_result: [32]u8 = undefined;
    hashInPlace(message, &hash_result);
    
    const expected = hash.sha256(message);
    try std.testing.expectEqualSlices(u8, &expected, &hash_result);
}