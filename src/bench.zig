//! Performance benchmarks for zcrypto
//!
//! Run with: zig run src/bench.zig

const std = @import("std");
const zcrypto = @import("zcrypto");
const builtin = @import("builtin");

const ITERATIONS = 10000;
const LARGE_DATA_SIZE = 1024 * 1024; // 1MB
const QUIC_HEADER_LEN = 5;
const QUIC_PAYLOAD_LEN = 64;

const MlKemKeyPair = if (zcrypto.build_config.post_quantum_enabled) zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.KeyPair else void;
const MlKemEncapsulation = if (zcrypto.build_config.post_quantum_enabled) zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.KeyPair.EncapsulationResult else void;
const MlDsaKeyPair = if (zcrypto.build_config.post_quantum_enabled) zcrypto.post_quantum.pq.ml_dsa.ML_DSA_65.KeyPair else void;

// Global test data
var large_data_buffer: [LARGE_DATA_SIZE]u8 = undefined;
var test_keypair: ?@import("zcrypto").asym.Ed25519KeyPair = null;
var test_signature: [64]u8 = undefined;
var test_message: []const u8 = undefined;
var x25519_alice: ?zcrypto.asym.Curve25519KeyPair = null;
var x25519_bob: ?zcrypto.asym.Curve25519KeyPair = null;
var test_aes_key: [16]u8 = undefined;
var test_nonce: [12]u8 = undefined;
var test_plaintext: []u8 = undefined;
var test_allocator: std.mem.Allocator = undefined;
var quic_crypto: ?zcrypto.quic.QuicCrypto = null;
var quic_packet_template: [QUIC_HEADER_LEN + QUIC_PAYLOAD_LEN + 16]u8 = undefined;
var quic_encrypted_template: [QUIC_HEADER_LEN + QUIC_PAYLOAD_LEN + 16]u8 = undefined;
var pq_ml_kem_keypair: ?MlKemKeyPair = null;
var pq_ml_kem_encapsulation: ?MlKemEncapsulation = null;
var pq_ml_dsa_keypair: ?MlDsaKeyPair = null;
var pq_ml_dsa_signature: [if (zcrypto.build_config.post_quantum_enabled) zcrypto.post_quantum.pq.ml_dsa.ML_DSA_65.SIGNATURE_SIZE else 1]u8 = undefined;

/// Cross-platform timestamp helper for current Zig dev builds
fn getTimestampNs() !i128 {
    var ts: std.posix.timespec = undefined;
    const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
    if (std.posix.errno(rc) != .SUCCESS) {
        return error.ClockGetTimeFailed;
    }
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

fn benchmark(comptime name: []const u8, iterations: u32, func: anytype) !void {
    const start_time = try getTimestampNs();

    for (0..iterations) |_| {
        try func();
    }

    const end_time = try getTimestampNs();
    const duration_ns = @as(f64, @floatFromInt(end_time - start_time));
    const duration_ms = duration_ns / 1_000_000.0;
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (duration_ns / 1_000_000_000.0);

    std.debug.print("{s}: {d:.2} ms ({d:.0} ops/sec)\n", .{ name, duration_ms, ops_per_sec });
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🏁 zcrypto Performance Benchmarks\n", .{});
    std.debug.print("Iterations: {d}\n\n", .{ITERATIONS});

    // Hash benchmarks
    std.debug.print("📝 Hash Functions:\n", .{});

    const test_data = "The quick brown fox jumps over the lazy dog";

    try benchmark("SHA-256 (small)", ITERATIONS, struct {
        fn run() !void {
            _ = zcrypto.hash.sha256(test_data);
        }
    }.run);

    try benchmark("SHA-512 (small)", ITERATIONS, struct {
        fn run() !void {
            _ = zcrypto.hash.sha512(test_data);
        }
    }.run);

    try benchmark("Blake2b (small)", ITERATIONS, struct {
        fn run() !void {
            _ = zcrypto.hash.blake2b(test_data);
        }
    }.run);

    try benchmark("Blake3 (small)", ITERATIONS, struct {
        fn run() !void {
            _ = zcrypto.blake3.blake3(test_data);
        }
    }.run);

    // Large data hashing
    zcrypto.rand.fill(&large_data_buffer);

    std.debug.print("\n📊 Large Data Hashing (1MB):\n", .{});

    try benchmark("SHA-256 (1MB)", 100, struct {
        fn run() !void {
            _ = zcrypto.hash.sha256(&large_data_buffer);
        }
    }.run);

    try benchmark("Blake3 (1MB)", 100, struct {
        fn run() !void {
            _ = zcrypto.blake3.blake3(&large_data_buffer);
        }
    }.run);

    // Signature benchmarks
    std.debug.print("\n✍️  Digital Signatures:\n", .{});

    test_keypair = zcrypto.asym.ed25519.generate();
    test_message = "Benchmark message for signing";
    test_signature = try test_keypair.?.sign(test_message);

    try benchmark("Ed25519 Sign", ITERATIONS, struct {
        fn run() !void {
            _ = test_keypair.?.sign(test_message) catch unreachable;
        }
    }.run);

    try benchmark("Ed25519 Verify", ITERATIONS, struct {
        fn run() !void {
            _ = test_keypair.?.verify(test_message, test_signature);
        }
    }.run);

    // Key generation benchmarks
    try benchmark("Ed25519 KeyGen", ITERATIONS / 10, struct {
        fn run() !void {
            var kp = zcrypto.asym.ed25519.generate();
            kp.zeroize();
        }
    }.run);

    try benchmark("X25519 KeyGen", ITERATIONS / 10, struct {
        fn run() !void {
            var kp = zcrypto.asym.x25519.generate();
            kp.zeroize();
        }
    }.run);

    x25519_alice = zcrypto.asym.x25519.generate();
    x25519_bob = zcrypto.asym.x25519.generate();
    try benchmark("X25519 DH", ITERATIONS, struct {
        fn run() !void {
            _ = zcrypto.asym.x25519.dh(x25519_alice.?.private_key, x25519_bob.?.public_key) catch unreachable;
        }
    }.run);

    // Symmetric encryption benchmarks
    std.debug.print("\n🔒 Symmetric Encryption:\n", .{});

    test_aes_key = zcrypto.rand.randomArray(16);
    test_nonce = zcrypto.rand.randomArray(12);
    test_plaintext = try allocator.alloc(u8, 1024); // 1KB
    defer allocator.free(test_plaintext);
    zcrypto.rand.fill(test_plaintext);
    test_allocator = allocator;

    try benchmark("AES-128-GCM Encrypt (1KB)", ITERATIONS / 10, struct {
        fn run() !void {
            const ciphertext = zcrypto.sym.encryptAes128Gcm(test_allocator, test_aes_key, test_nonce, test_plaintext, "") catch unreachable;
            ciphertext.deinit();
        }
    }.run);

    try benchmark("ChaCha20-Poly1305 Encrypt (1KB)", ITERATIONS / 10, struct {
        fn run() !void {
            const ciphertext = zcrypto.sym.encryptChaCha20Poly1305(test_allocator, zcrypto.rand.randomArray(32), test_nonce, test_plaintext, "") catch unreachable;
            ciphertext.deinit();
        }
    }.run);

    if (zcrypto.build_config.tls_enabled) {
        std.debug.print("\n🌐 QUIC Packet Protection:\n", .{});

        quic_crypto = zcrypto.quic.QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
        const cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        try quic_crypto.?.deriveInitialKeys(&cid);

        const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
        @memcpy(quic_packet_template[0..QUIC_HEADER_LEN], &header);
        @memcpy(quic_packet_template[QUIC_HEADER_LEN .. QUIC_HEADER_LEN + QUIC_PAYLOAD_LEN], large_data_buffer[0..QUIC_PAYLOAD_LEN]);
        @memset(quic_packet_template[QUIC_HEADER_LEN + QUIC_PAYLOAD_LEN ..], 0);
        quic_encrypted_template = quic_packet_template;
        _ = try zcrypto.quic.ZeroCopy.encryptInPlace(&quic_crypto.?, .initial, false, 1, &quic_encrypted_template, QUIC_HEADER_LEN);

        try benchmark("QUIC Packet Encrypt (64B)", ITERATIONS, struct {
            fn run() !void {
                var packet = quic_packet_template;
                _ = zcrypto.quic.ZeroCopy.encryptInPlace(&quic_crypto.?, .initial, false, 1, &packet, QUIC_HEADER_LEN) catch unreachable;
            }
        }.run);

        try benchmark("QUIC Packet Decrypt (64B)", ITERATIONS, struct {
            fn run() !void {
                var packet = quic_encrypted_template;
                _ = zcrypto.quic.ZeroCopy.decryptInPlace(&quic_crypto.?, .initial, false, 1, &packet, QUIC_HEADER_LEN) catch unreachable;
            }
        }.run);
    }

    if (zcrypto.build_config.post_quantum_enabled) {
        std.debug.print("\n🌌 Post-Quantum Operations:\n", .{});

        const Pq = zcrypto.post_quantum.pq;
        pq_ml_kem_keypair = try Pq.ml_kem.ML_KEM_768.KeyPair.generateRandom();
        var kem_randomness: [Pq.ml_kem.ML_KEM_768.SEED_SIZE]u8 = undefined;
        zcrypto.rand.fill(&kem_randomness);
        pq_ml_kem_encapsulation = try Pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(pq_ml_kem_keypair.?.public_key, kem_randomness);

        pq_ml_dsa_keypair = try Pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom();
        var dsa_randomness: [Pq.ml_dsa.ML_DSA_65.NOISE_SIZE]u8 = undefined;
        zcrypto.rand.fill(&dsa_randomness);
        pq_ml_dsa_signature = try pq_ml_dsa_keypair.?.sign(test_message, dsa_randomness);

        try benchmark("ML-KEM-768 KeyGen", 100, struct {
            fn run() !void {
                _ = Pq.ml_kem.ML_KEM_768.KeyPair.generateRandom() catch unreachable;
            }
        }.run);

        try benchmark("ML-KEM-768 Encaps", 100, struct {
            fn run() !void {
                var randomness: [Pq.ml_kem.ML_KEM_768.SEED_SIZE]u8 = undefined;
                zcrypto.rand.fill(&randomness);
                _ = Pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(pq_ml_kem_keypair.?.public_key, randomness) catch unreachable;
            }
        }.run);

        try benchmark("ML-KEM-768 Decaps", 100, struct {
            fn run() !void {
                _ = pq_ml_kem_keypair.?.decapsulate(pq_ml_kem_encapsulation.?.ciphertext) catch unreachable;
            }
        }.run);

        try benchmark("ML-DSA-65 Sign", 100, struct {
            fn run() !void {
                var randomness: [Pq.ml_dsa.ML_DSA_65.NOISE_SIZE]u8 = undefined;
                zcrypto.rand.fill(&randomness);
                _ = pq_ml_dsa_keypair.?.sign(test_message, randomness) catch unreachable;
            }
        }.run);

        try benchmark("ML-DSA-65 Verify", 100, struct {
            fn run() !void {
                _ = Pq.ml_dsa.ML_DSA_65.KeyPair.verify(pq_ml_dsa_keypair.?.public_key, test_message, pq_ml_dsa_signature) catch unreachable;
            }
        }.run);
    }

    // Random generation benchmarks
    std.debug.print("\n🎲 Random Generation:\n", .{});

    try benchmark("Random 32 bytes", ITERATIONS * 10, struct {
        fn run() !void {
            var rand_buf: [32]u8 = undefined;
            zcrypto.rand.fill(&rand_buf);
        }
    }.run);

    // Key derivation benchmarks
    std.debug.print("\n🔑 Key Derivation:\n", .{});

    const master_secret = "master-secret-for-benchmarking";
    try benchmark("HKDF (32 bytes)", ITERATIONS, struct {
        fn run() !void {
            const derived = zcrypto.kdf.deriveKey(test_allocator, master_secret, "bench-label", 32) catch unreachable;
            test_allocator.free(derived);
        }
    }.run);

    if (zcrypto.build_config.tls_enabled) {
        std.debug.print("\n🌐 QUIC/TLS Operations:\n", .{});

        const cid = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
        try benchmark("QUIC Initial Secrets", ITERATIONS, struct {
            fn run() !void {
                _ = zcrypto.tls.deriveInitialSecrets(&cid, true);
            }
        }.run);
    }

    std.debug.print("\n🏆 Benchmark completed!\n", .{});
}
