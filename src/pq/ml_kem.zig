//! ML-KEM wrappers backed by Zig stdlib implementations.
//!
//! This module exposes the project-local ML-KEM API shape used across zcrypto,
//! while delegating the actual KEM implementation to `std.crypto.kem.ml_kem`.

const std = @import("std");
const rand = @import("../rand.zig");
const pq = @import("../pq.zig");

fn expandSeed(comptime N: usize, seed: [32]u8) [N]u8 {
    var xof = std.crypto.hash.sha3.Shake256.init(.{});
    xof.update(&seed);

    var expanded: [N]u8 = undefined;
    xof.squeeze(&expanded);
    return expanded;
}

fn MlKemWrapper(comptime Mode: type) type {
    return struct {
        pub const PUBLIC_KEY_SIZE = Mode.PublicKey.encoded_length;
        pub const PRIVATE_KEY_SIZE = Mode.SecretKey.encoded_length;
        pub const CIPHERTEXT_SIZE = Mode.ciphertext_length;
        pub const SHARED_SECRET_SIZE = Mode.shared_length;
        pub const SEED_SIZE = 32;

        pub const KeyPair = struct {
            public_key: [PUBLIC_KEY_SIZE]u8,
            private_key: [PRIVATE_KEY_SIZE]u8,

            pub fn generate(seed: [SEED_SIZE]u8) pq.PQError!KeyPair {
                const deterministic_seed = expandSeed(Mode.seed_length, seed);
                const keypair = Mode.KeyPair.generateDeterministic(deterministic_seed) catch {
                    return pq.PQError.KeyGenFailed;
                };

                return .{
                    .public_key = keypair.public_key.toBytes(),
                    .private_key = keypair.secret_key.toBytes(),
                };
            }

            pub fn generateRandom() pq.PQError!KeyPair {
                var seed: [SEED_SIZE]u8 = undefined;
                rand.fill(&seed);
                return generate(seed);
            }

            pub const EncapsulationResult = struct {
                ciphertext: [CIPHERTEXT_SIZE]u8,
                shared_secret: [SHARED_SECRET_SIZE]u8,
            };

            pub fn fromBytes(public_key: []const u8, private_key: []const u8) pq.PQError!KeyPair {
                if (public_key.len != PUBLIC_KEY_SIZE) return pq.PQError.InvalidPublicKey;
                if (private_key.len != PRIVATE_KEY_SIZE) return pq.PQError.InvalidPrivateKey;

                const public_key_array: [PUBLIC_KEY_SIZE]u8 = public_key[0..PUBLIC_KEY_SIZE].*;
                const private_key_array: [PRIVATE_KEY_SIZE]u8 = private_key[0..PRIVATE_KEY_SIZE].*;

                _ = Mode.PublicKey.fromBytes(&public_key_array) catch return pq.PQError.InvalidPublicKey;
                _ = Mode.SecretKey.fromBytes(&private_key_array) catch return pq.PQError.InvalidPrivateKey;

                return .{
                    .public_key = public_key_array,
                    .private_key = private_key_array,
                };
            }

            pub fn encapsulate(public_key: [PUBLIC_KEY_SIZE]u8, randomness: [SEED_SIZE]u8) pq.PQError!EncapsulationResult {
                const pk = Mode.PublicKey.fromBytes(&public_key) catch {
                    return pq.PQError.InvalidPublicKey;
                };
                const result = pk.encapsDeterministic(&randomness);

                return .{
                    .ciphertext = result.ciphertext,
                    .shared_secret = result.shared_secret,
                };
            }

            pub fn encapsulateBytes(public_key: []const u8, randomness: [SEED_SIZE]u8) pq.PQError!EncapsulationResult {
                if (public_key.len != PUBLIC_KEY_SIZE) return pq.PQError.InvalidPublicKey;
                return encapsulate(public_key[0..PUBLIC_KEY_SIZE].*, randomness);
            }

            pub fn decapsulate(self: *const KeyPair, ciphertext: [CIPHERTEXT_SIZE]u8) pq.PQError![SHARED_SECRET_SIZE]u8 {
                const sk = Mode.SecretKey.fromBytes(&self.private_key) catch {
                    return pq.PQError.InvalidPrivateKey;
                };
                return sk.decaps(&ciphertext) catch {
                    return pq.PQError.DecapsFailed;
                };
            }

            pub fn decapsulateBytes(self: *const KeyPair, ciphertext: []const u8) pq.PQError![SHARED_SECRET_SIZE]u8 {
                if (ciphertext.len != CIPHERTEXT_SIZE) return pq.PQError.InvalidCiphertext;
                return self.decapsulate(ciphertext[0..CIPHERTEXT_SIZE].*);
            }
        };
    };
}

pub const ML_KEM_512 = MlKemWrapper(std.crypto.kem.ml_kem.MLKem512);
pub const ML_KEM_768 = MlKemWrapper(std.crypto.kem.ml_kem.MLKem768);
pub const ML_KEM_1024 = MlKemWrapper(std.crypto.kem.ml_kem.MLKem1024);

test "ML-KEM-768 key generation" {
    const seed = blk: {
        var bytes = std.mem.zeroes([ML_KEM_768.SEED_SIZE]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const keypair = try ML_KEM_768.KeyPair.generate(seed);

    var all_zero = true;
    for (keypair.public_key) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }

    try std.testing.expect(!all_zero);
}

test "ML-KEM-768 encapsulation and decapsulation derive same shared secret" {
    const seed = blk: {
        var bytes = std.mem.zeroes([ML_KEM_768.SEED_SIZE]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const randomness = blk: {
        var bytes = std.mem.zeroes([ML_KEM_768.SEED_SIZE]u8);
        @memset(bytes[0..], 0x24);
        break :blk bytes;
    };

    const keypair = try ML_KEM_768.KeyPair.generate(seed);
    const encap = try ML_KEM_768.KeyPair.encapsulate(keypair.public_key, randomness);
    const decap = try keypair.decapsulate(encap.ciphertext);

    try std.testing.expectEqualSlices(u8, &encap.shared_secret, &decap);
}

test "ML-KEM-768 byte helpers reject malformed lengths" {
    const seed = blk: {
        var bytes = std.mem.zeroes([ML_KEM_768.SEED_SIZE]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const randomness = blk: {
        var bytes = std.mem.zeroes([ML_KEM_768.SEED_SIZE]u8);
        @memset(bytes[0..], 0x24);
        break :blk bytes;
    };

    const keypair = try ML_KEM_768.KeyPair.generate(seed);
    _ = try ML_KEM_768.KeyPair.fromBytes(&keypair.public_key, &keypair.private_key);

    try std.testing.expectError(
        pq.PQError.InvalidPublicKey,
        ML_KEM_768.KeyPair.fromBytes(keypair.public_key[0 .. ML_KEM_768.PUBLIC_KEY_SIZE - 1], &keypair.private_key),
    );
    try std.testing.expectError(
        pq.PQError.InvalidPrivateKey,
        ML_KEM_768.KeyPair.fromBytes(&keypair.public_key, keypair.private_key[0 .. ML_KEM_768.PRIVATE_KEY_SIZE - 1]),
    );
    try std.testing.expectError(
        pq.PQError.InvalidPublicKey,
        ML_KEM_768.KeyPair.encapsulateBytes(keypair.public_key[0 .. ML_KEM_768.PUBLIC_KEY_SIZE - 1], randomness),
    );

    const encap = try ML_KEM_768.KeyPair.encapsulate(keypair.public_key, randomness);
    try std.testing.expectError(
        pq.PQError.InvalidCiphertext,
        keypair.decapsulateBytes(encap.ciphertext[0 .. ML_KEM_768.CIPHERTEXT_SIZE - 1]),
    );
}
