//! Example usage of zcrypto's optional features.

const std = @import("std");
const builtin = @import("builtin");
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

    // Build-target features, not a runtime probe, and not what selects the
    // implementation. `std.crypto` publishes the AES answer that actually
    // applies, so print that next to it rather than implying the two agree.
    //
    // This line is the release gate's only record of which target a run was
    // built for: it is captured by the `smoke-runs` stage, and the same values
    // cannot be printed from a test body without the build runner reporting the
    // passing run as `failed command` (see tests/hardware_parity.zig). Keep the
    // full field list if this demo is edited.
    const features = zcrypto.hardware.HardwareAcceleration.detect();
    std.debug.print(
        "built for: arch={s} aes_ni={} sha_ext={} pclmulqdq={} avx2={} avx512={} arm_crypto={}" ++
            " | std.crypto aes hardware-backed: {}\n",
        .{
            @tagName(builtin.target.cpu.arch),
            features.aes_ni,
            features.sha_ext,
            features.pclmulqdq,
            features.avx2,
            features.avx512,
            features.arm_crypto,
            std.crypto.core.aes.has_hardware_support,
        },
    );

    const a = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const b = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var result: [4]u8 = undefined;
    try zcrypto.hardware.SIMD.vectorizedXor(&a, &b, &result);
    std.debug.print("simd xor sample: {x}\n", .{result});
}

fn demoQuicCrypto(allocator: std.mem.Allocator) !void {
    const connection_id = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    var quic_conn = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(allocator, &connection_id, .chacha20_poly1305);

    var packet: [64]u8 = undefined;
    const payload = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
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
