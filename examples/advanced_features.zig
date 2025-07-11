//! Example usage of zcrypto's advanced features
//! Demonstrates QUIC crypto, post-quantum algorithms, and hardware acceleration

const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🔐 ZCrypto v0.5.0 Advanced Features Demo\n");
    std.debug.print("=======================================\n\n");

    // 1. Hardware Acceleration Detection
    try demoHardwareAcceleration();

    // 2. QUIC Cryptographic Operations
    try demoQuicCrypto(allocator);

    // 3. Post-Quantum Cryptography
    try demoPostQuantumCrypto(allocator);

    // 4. Enhanced Key Exchange
    try demoEnhancedKeyExchange(allocator);

    // 5. Hybrid Cryptography
    try demoHybridCryptography(allocator);

    std.debug.print("🎉 All demos completed successfully!\n");
}

fn demoHardwareAcceleration() !void {
    std.debug.print("🏎️  Hardware Acceleration Detection\n");
    std.debug.print("-----------------------------------\n");

    const features = zcrypto.hardware.HardwareAcceleration.detect();

    std.debug.print("AES-NI support:        {}\n", .{features.aes_ni});
    std.debug.print("SHA extensions:        {}\n", .{features.sha_ext});
    std.debug.print("ARM Crypto:            {}\n", .{features.arm_crypto});
    std.debug.print("PCLMULQDQ:             {}\n", .{features.pclmulqdq});
    std.debug.print("AVX2:                  {}\n", .{features.avx2});
    std.debug.print("AVX-512:               {}\n", .{features.avx512});

    // Demo vectorized operations
    const a = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const b = [_]u8{ 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var result: [8]u8 = undefined;

    zcrypto.hardware.SIMD.vectorizedXor(&a, &b, &result);
    std.debug.print("Vectorized XOR result: ");
    for (result) |byte| {
        std.debug.print("{:02X} ", .{byte});
    }
    std.debug.print("\n\n");
}

fn demoQuicCrypto(allocator: std.mem.Allocator) !void {
    std.debug.print("⚡ QUIC Cryptographic Operations\n");
    std.debug.print("--------------------------------\n");

    // Initialize QUIC connection crypto
    const connection_id = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    var quic_conn = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(allocator, &connection_id, .chacha20_poly1305);

    std.debug.print("✅ QUIC connection initialized with ChaCha20-Poly1305\n");

    // Demo packet encryption
    var packet = [_]u8{0xC0} ++ [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x51, 0x55, 0x49, 0x43 }; // "Hello QUIC"
    const packet_number: u64 = 42;

    const encrypted_len = try quic_conn.encryptPacket(&packet, packet_number);
    std.debug.print("✅ Encrypted packet length: {} bytes\n", .{encrypted_len});

    // Demo HKDF key derivation
    const secret = [_]u8{0xAB} ** 32;
    var derived_key: [16]u8 = undefined;
    zcrypto.quic_crypto.QuicCrypto.HKDF.expandLabel(&secret, "quic key", "", &derived_key);

    std.debug.print("✅ Derived QUIC key: ");
    for (derived_key[0..8]) |byte| {
        std.debug.print("{:02X}", .{byte});
    }
    std.debug.print("...\n\n");
}

fn demoPostQuantumCrypto(allocator: std.mem.Allocator) !void {
    std.debug.print("🔮 Post-Quantum Cryptography\n");
    std.debug.print("-----------------------------\n");

    // ML-KEM-768 (Kyber) key exchange
    std.debug.print("🔑 ML-KEM-768 Key Exchange:\n");
    const kem_keypair = try zcrypto.kyber.generateKeypair();
    const encap_result = try zcrypto.kyber.encapsulate(kem_keypair.public_key);
    const decap_secret = try zcrypto.kyber.decapsulate(kem_keypair.private_key, encap_result.ciphertext);

    std.debug.print("   Public key size:    {} bytes\n", .{zcrypto.kyber.PUBLIC_KEY_SIZE});
    std.debug.print("   Ciphertext size:    {} bytes\n", .{zcrypto.kyber.CIPHERTEXT_SIZE});
    std.debug.print("   Shared secret:      ");
    for (decap_secret[0..8]) |byte| {
        std.debug.print("{:02X}", .{byte});
    }
    std.debug.print("...\n");

    // ML-DSA-65 (Dilithium) signatures
    std.debug.print("✍️  ML-DSA-65 Digital Signatures:\n");
    const sig_keypair = try zcrypto.dilithium.generateKeypair();
    const message = "Post-quantum signature test";
    const signature = try zcrypto.dilithium.sign(sig_keypair.private_key, message);
    const valid = try zcrypto.dilithium.verify(sig_keypair.public_key, message, signature);

    std.debug.print("   Signature size:     {} bytes\n", .{zcrypto.dilithium.SIGNATURE_SIZE});
    std.debug.print("   Verification:       {}\n", .{if (valid) "✅ Valid" else "❌ Invalid"});

    _ = allocator; // For future use
    std.debug.print("\n");
}

fn demoEnhancedKeyExchange(allocator: std.mem.Allocator) !void {
    std.debug.print("🔄 Enhanced Key Exchange\n");
    std.debug.print("------------------------\n");

    // X25519 key exchange
    std.debug.print("🌟 X25519 Elliptic Curve Diffie-Hellman:\n");
    const alice_x25519 = try zcrypto.x25519.generateKeypair();
    const bob_x25519 = try zcrypto.x25519.generateKeypair();

    const alice_shared = try zcrypto.x25519.computeSharedSecret(alice_x25519.private_key, bob_x25519.public_key);
    const bob_shared = try zcrypto.x25519.computeSharedSecret(bob_x25519.private_key, alice_x25519.public_key);

    const secrets_match = std.mem.eql(u8, &alice_shared, &bob_shared);
    std.debug.print("   Shared secrets match: {}\n", .{if (secrets_match) "✅ Yes" else "❌ No"});
    std.debug.print("   Secret (Alice):       ");
    for (alice_shared[0..8]) |byte| {
        std.debug.print("{:02X}", .{byte});
    }
    std.debug.print("...\n");

    // Ed25519 signatures with batch verification
    std.debug.print("📝 Ed25519 Batch Signatures:\n");
    const ed_keypair = try zcrypto.ed25519.generateKeypair();
    const messages = [_][]const u8{ "message 1", "message 2", "message 3" };

    var signatures: [3][64]u8 = undefined;
    for (messages, &signatures) |msg, *sig| {
        sig.* = try zcrypto.ed25519.sign(ed_keypair.private_key, msg);
    }

    const public_keys = [_][32]u8{ed_keypair.public_key} ** 3;
    const results = try zcrypto.ed25519.verifyBatch(&public_keys, &messages, &signatures);
    defer allocator.free(results);

    std.debug.print("   Batch verification:   ");
    for (results) |result| {
        std.debug.print("{} ", .{if (result) "✅" else "❌"});
    }
    std.debug.print("\n\n");
}

fn demoHybridCryptography(allocator: std.mem.Allocator) !void {
    std.debug.print("🌐 Hybrid Cryptography (Classical + Post-Quantum)\n");
    std.debug.print("-------------------------------------------------\n");

    // Hybrid key exchange for QUIC
    std.debug.print("🔗 Hybrid QUIC Key Exchange:\n");
    const alice_hybrid = try zcrypto.kex.QuicKeyExchange.generateKeypair(allocator, .hybrid_x25519_kyber768);
    const bob_hybrid = try zcrypto.kex.QuicKeyExchange.generateKeypair(allocator, .hybrid_x25519_kyber768);

    const alice_public_data = try zcrypto.kex.QuicKeyExchange.getPublicKeyData(allocator, alice_hybrid);
    defer allocator.free(alice_public_data);

    var bob_shared = try zcrypto.kex.QuicKeyExchange.performKeyExchange(allocator, bob_hybrid, alice_public_data);
    defer bob_shared.deinit();

    std.debug.print("   Public key size:      {} bytes\n", .{alice_public_data.len});
    std.debug.print("   Combined secret size: {} bytes\n", .{bob_shared.secret.len});
    std.debug.print("   Hybrid secret:        ");
    for (bob_shared.secret[0..8]) |byte| {
        std.debug.print("{:02X}", .{byte});
    }
    std.debug.print("...\n");

    // Hybrid signatures
    std.debug.print("✍️  Hybrid Digital Signatures:\n");
    const hybrid_sig_keypair = try zcrypto.post_quantum.HybridSignature.generateKeypair(allocator);
    const hybrid_message = "Hybrid classical + post-quantum signature";

    const hybrid_signature = try zcrypto.post_quantum.HybridSignature.sign(allocator, hybrid_sig_keypair, hybrid_message);
    defer allocator.free(hybrid_signature);

    const hybrid_valid = try zcrypto.post_quantum.HybridSignature.verify(hybrid_sig_keypair, hybrid_message, hybrid_signature);

    std.debug.print("   Signature size:       {} bytes\n", .{hybrid_signature.len});
    std.debug.print("   Verification:         {}\n", .{if (hybrid_valid) "✅ Valid" else "❌ Invalid"});

    std.debug.print("\n");
}

// Simple benchmark function
fn benchmark(comptime description: []const u8, comptime func: anytype, args: anytype) !void {
    const start = std.time.nanoTimestamp();
    const iterations = 1000;

    for (0..iterations) |_| {
        _ = try @call(.auto, func, args);
    }

    const end = std.time.nanoTimestamp();
    const total_time = end - start;
    const avg_time = @divFloor(total_time, iterations);

    std.debug.print("{s}: {} ns avg ({} iterations)\n", .{ description, avg_time, iterations });
}

test "zcrypto v0.5.0 integration test" {
    const allocator = std.testing.allocator;

    // Test QUIC crypto
    const connection_id = [_]u8{0x12} ** 8;
    const quic_conn = try zcrypto.quic_crypto.QuicConnection.initFromConnectionId(allocator, &connection_id, .aes_128_gcm);
    _ = quic_conn;

    // Test post-quantum crypto
    const kem_keypair = try zcrypto.kyber.generateKeypair();
    const encap_result = try zcrypto.kyber.encapsulate(kem_keypair.public_key);
    _ = try zcrypto.kyber.decapsulate(kem_keypair.private_key, encap_result.ciphertext);

    // Test enhanced key exchange
    const x25519_keypair = try zcrypto.x25519.generateKeypair();
    _ = try zcrypto.x25519.computeSharedSecret(x25519_keypair.private_key, x25519_keypair.public_key);

    // Test hardware acceleration
    const features = zcrypto.hardware.HardwareAcceleration.detect();
    _ = features;
}
