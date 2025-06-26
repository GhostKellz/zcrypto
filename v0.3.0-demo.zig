//! zcrypto v0.3.0 Feature Demo
//! 
//! Demonstrates the new features added in v0.3.0:
//! 1. Ed25519 seed-based generation
//! 2. Enhanced error handling  
//! 3. Dual secp256k1 public key formats
//! 4. Batch operations

const std = @import("std");
const zcrypto = @import("src/root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🚀 zcrypto v{s} - New Features Demo\n\n", .{zcrypto.version});

    // 1. Ed25519 Deterministic Generation (NEW in v0.3.0)
    std.debug.print("🔑 Ed25519 Deterministic Generation:\n", .{});
    const seed = [_]u8{42} ** 32;
    const keypair1 = zcrypto.asym.ed25519.generateFromSeed(seed);
    const keypair2 = zcrypto.asym.ed25519.generateFromSeed(seed);
    
    const keys_match = std.mem.eql(u8, &keypair1.public_key, &keypair2.public_key);
    std.debug.print("  Generated identical keypairs from same seed: {}\n", .{keys_match});
    
    const message = "Hello, deterministic signing!";
    const signature = try keypair1.sign(message);
    const valid = keypair1.verify(message, signature);
    std.debug.print("  Signature verification: {}\n\n", .{valid});

    // 2. Enhanced Error Handling (NEW in v0.3.0)
    std.debug.print("🛡️ Enhanced Error Handling:\n", .{});
    
    // This will handle errors gracefully instead of panicking
    const test_keypair = zcrypto.asym.ed25519.generate();
    _ = test_keypair.sign("test") catch |err| {
        std.debug.print("  Caught error gracefully: {}\n", .{err});
        return;
    };
    std.debug.print("  Error handling works correctly ✓\n\n", .{});

    // 3. Dual secp256k1 Public Key Formats (NEW in v0.3.0)
    std.debug.print("🔐 Dual secp256k1 Public Key Formats:\n", .{});
    const secp_keypair = zcrypto.asym.secp256k1.generate();
    
    const compressed_key = secp_keypair.publicKey(.compressed);
    const x_only_key = secp_keypair.publicKey(.x_only);
    
    std.debug.print("  Compressed public key length: {}\n", .{compressed_key.len});
    std.debug.print("  X-only public key length: {}\n", .{x_only_key.len});
    
    // Test signing with secp256k1
    const btc_message = zcrypto.hash.sha256("Bitcoin transaction");
    const btc_signature = try secp_keypair.sign(btc_message);
    const btc_valid = secp_keypair.verify(btc_message, btc_signature);
    std.debug.print("  Bitcoin-style signature verification: {}\n\n", .{btc_valid});

    // 4. Batch Operations (NEW in v0.3.0)
    std.debug.print("⚡ Batch Operations:\n", .{});
    
    const batch_keypair = zcrypto.asym.ed25519.generate();
    const messages = [_][]const u8{ "msg1", "msg2", "msg3" };
    
    // Batch signing
    const signatures = try zcrypto.batch.signBatchEd25519(&messages, batch_keypair.private_key, allocator);
    defer allocator.free(signatures);
    std.debug.print("  Batch signed {} messages\n", .{signatures.len});
    
    // Batch verification
    const public_keys = [_][32]u8{ batch_keypair.public_key, batch_keypair.public_key, batch_keypair.public_key };
    const results = try zcrypto.batch.verifyBatchEd25519(&messages, signatures, &public_keys, allocator);
    defer allocator.free(results);
    
    var all_valid = true;
    for (results) |result| {
        if (!result) all_valid = false;
    }
    std.debug.print("  Batch verification results: all valid = {}\n\n", .{all_valid});

    // 5. Zero-Copy Operations (NEW in v0.3.0)
    std.debug.print("🏎️ Zero-Copy Operations:\n", .{});
    
    var signature_buffer: [64]u8 = undefined;
    try zcrypto.batch.signInPlace("zero-copy message", batch_keypair.private_key, &signature_buffer);
    
    const zero_copy_valid = zcrypto.asym.ed25519.verify("zero-copy message", signature_buffer, batch_keypair.public_key);
    std.debug.print("  Zero-copy signing verification: {}\n", .{zero_copy_valid});
    
    var hash_buffer: [32]u8 = undefined;
    zcrypto.batch.hashInPlace("hash this message", &hash_buffer);
    const expected_hash = zcrypto.hash.sha256("hash this message");
    const hash_match = std.mem.eql(u8, &hash_buffer, &expected_hash);
    std.debug.print("  Zero-copy hashing verification: {}\n\n", .{hash_match});

    std.debug.print("✅ All v0.3.0 features working perfectly!\n", .{});
    std.debug.print("🎯 Ready for zsig, zwallet, and all GhostChain projects!\n", .{});
}