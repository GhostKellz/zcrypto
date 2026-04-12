//! Example usage of zcrypto's optional features.

const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("zcrypto v{s} advanced features\n\n", .{zcrypto.version});

    try demoHardwareAcceleration();
    try demoQuicCrypto(allocator);
    try demoPostQuantumCrypto(allocator);
    try demoHybridCryptography(allocator);
}

fn demoHardwareAcceleration() !void {
    if (!zcrypto.build_config.hardware_accel_enabled) {
        std.debug.print("hardware acceleration: disabled\n", .{});
        return;
    }

    const features = zcrypto.hardware.HardwareAcceleration.detect();
    std.debug.print("hardware acceleration: aes_ni={}, avx2={}\n", .{ features.aes_ni, features.avx2 });

    const a = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const b = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var result: [4]u8 = undefined;
    zcrypto.hardware.SIMD.vectorizedXor(&a, &b, &result);
    std.debug.print("simd xor sample: {x}\n", .{result});
}

fn demoQuicCrypto(allocator: std.mem.Allocator) !void {
    const connection_id = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    var quic_conn = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(allocator, &connection_id, .chacha20_poly1305);

    var packet: [64]u8 = undefined;
    const payload = [_]u8{0x42} ** 32;
    @memcpy(packet[0..payload.len], &payload);
    @memset(packet[payload.len..], 0);

    const encrypted_len = try quic_conn.encryptPacket(packet[0..], payload.len, 42);
    std.debug.print("quic crypto: encrypted {} bytes\n", .{encrypted_len});
}

fn demoPostQuantumCrypto(allocator: std.mem.Allocator) !void {
    _ = allocator;

    if (!zcrypto.build_config.post_quantum_enabled) {
        std.debug.print("post-quantum crypto: disabled\n", .{});
        return;
    }

    const kem_keypair = try zcrypto.kyber.generateKeypair();
    const encap_result = try zcrypto.kyber.encapsulate(kem_keypair.public_key);
    _ = try zcrypto.kyber.decapsulate(kem_keypair.private_key, encap_result.ciphertext);

    const sig_keypair = try zcrypto.dilithium.generateKeypair();
    const message = "post-quantum signature test";
    const signature = try zcrypto.dilithium.sign(sig_keypair.private_key, message);
    const valid = try zcrypto.dilithium.verify(sig_keypair.public_key, message, signature);

    std.debug.print("post-quantum crypto: signature valid={}\n", .{valid});
}

fn demoHybridCryptography(allocator: std.mem.Allocator) !void {
    if (!zcrypto.build_config.post_quantum_enabled) {
        std.debug.print("hybrid crypto: disabled\n", .{});
        return;
    }

    const hybrid_sig_keypair = try zcrypto.post_quantum.HybridSignature.generateKeypair(allocator);
    const message = "hybrid classical + post-quantum signature";
    const signature = try zcrypto.post_quantum.HybridSignature.sign(allocator, hybrid_sig_keypair, message);
    defer allocator.free(signature);

    const valid = try zcrypto.post_quantum.HybridSignature.verify(hybrid_sig_keypair, message, signature);
    std.debug.print("hybrid crypto: signature valid={}\n", .{valid});
}

test "advanced features example compiles" {
    try std.testing.expect(true);
}
