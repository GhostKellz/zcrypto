//! Post-Quantum Cryptography Module for zcrypto
//!
//! Implements NIST-standardized post-quantum algorithms:
//! - FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//! - FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//!
//! Provides hybrid classical+post-quantum operations for backwards compatibility
//! and defense-in-depth security against both classical and quantum attacks.

const std = @import("std");
const rand = @import("rand.zig");
const root = @import("root.zig");

/// Post-quantum cryptography errors
pub const PQError = error{
    InvalidCiphertext,
    InvalidSharedSecret,
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    KeyGenFailed,
    EncapsFailed,
    DecapsFailed,
    SignFailed,
    VerifyFailed,
    InvalidParameters,
    InsufficientEntropy,
};

/// NIST ML-KEM (formerly Kyber) - Key Encapsulation Mechanism
/// FIPS 203 compliant implementation
pub const ml_kem = @import("pq/ml_kem.zig");

/// NIST ML-DSA (formerly Dilithium) wrappers backed by Zig stdlib.
pub const ml_dsa = struct {
    fn MlDsaWrapper(comptime Mode: type) type {
        return struct {
            pub const PUBLIC_KEY_SIZE = Mode.PublicKey.encoded_length;
            pub const PRIVATE_KEY_SIZE = Mode.SecretKey.encoded_length;
            pub const SIGNATURE_SIZE = Mode.Signature.encoded_length;
            pub const SEED_SIZE = Mode.KeyPair.seed_length;
            pub const NOISE_SIZE = Mode.noise_length;

            pub const KeyPair = struct {
                public_key: [PUBLIC_KEY_SIZE]u8,
                private_key: [PRIVATE_KEY_SIZE]u8,

                pub fn generate(seed: [SEED_SIZE]u8) PQError!KeyPair {
                    const keypair = Mode.KeyPair.generateDeterministic(seed) catch {
                        return PQError.KeyGenFailed;
                    };

                    return .{
                        .public_key = keypair.public_key.toBytes(),
                        .private_key = keypair.secret_key.toBytes(),
                    };
                }

                pub fn generateRandom() PQError!KeyPair {
                    var seed: [SEED_SIZE]u8 = undefined;
                    rand.fill(&seed);
                    return generate(seed);
                }

                pub fn sign(self: *const KeyPair, message: []const u8, randomness: ?[NOISE_SIZE]u8) PQError![SIGNATURE_SIZE]u8 {
                    const secret_key = Mode.SecretKey.fromBytes(self.private_key) catch {
                        return PQError.InvalidPrivateKey;
                    };
                    const keypair = Mode.KeyPair.fromSecretKey(secret_key) catch {
                        return PQError.InvalidPrivateKey;
                    };
                    const signature = keypair.sign(message, randomness) catch {
                        return PQError.SignFailed;
                    };
                    return signature.toBytes();
                }

                pub fn verify(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) PQError!bool {
                    const public_key_struct = Mode.PublicKey.fromBytes(public_key) catch {
                        return PQError.InvalidPublicKey;
                    };
                    const signature_struct = Mode.Signature.fromBytes(signature) catch {
                        return PQError.InvalidSignature;
                    };

                    signature_struct.verify(message, public_key_struct) catch {
                        return false;
                    };
                    return true;
                }
            };
        };
    }

    pub const ML_DSA_44 = MlDsaWrapper(std.crypto.sign.mldsa.MLDSA44);
    pub const ML_DSA_65 = MlDsaWrapper(std.crypto.sign.mldsa.MLDSA65);
    pub const ML_DSA_87 = MlDsaWrapper(std.crypto.sign.mldsa.MLDSA87);
};

/// Hybrid Classical + Post-Quantum Cryptography
/// Combines classical algorithms with post-quantum for defense-in-depth
pub const hybrid = struct {
    /// Hybrid Key Exchange: X25519 + ML-KEM-768
    pub const X25519_ML_KEM_768 = struct {
        pub const CLASSICAL_PUBLIC_SIZE = 32; // X25519 public key
        pub const CLASSICAL_PRIVATE_SIZE = 32; // X25519 private key
        pub const PQ_PUBLIC_SIZE = ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE;
        pub const PQ_PRIVATE_SIZE = ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE;
        pub const PQ_CIPHERTEXT_SIZE = ml_kem.ML_KEM_768.CIPHERTEXT_SIZE;
        pub const SHARED_SECRET_SIZE = 64; // Combined classical + PQ secret

        pub const HybridKeyPair = struct {
            classical_public: [CLASSICAL_PUBLIC_SIZE]u8,
            classical_private: [CLASSICAL_PRIVATE_SIZE]u8,
            pq_public: [PQ_PUBLIC_SIZE]u8,
            pq_private: [PQ_PRIVATE_SIZE]u8,

            /// Generate hybrid key pair
            pub fn generate() PQError!HybridKeyPair {
                var keypair: HybridKeyPair = undefined;

                // Generate X25519 key pair
                var classical_seed: [32]u8 = undefined;
                rand.fill(&classical_seed);

                keypair.classical_private = classical_seed;
                // Use X25519 basepoint to generate public key manually
                const basepoint = [_]u8{9} ++ std.mem.zeroes([31]u8);
                keypair.classical_public = std.crypto.dh.X25519.scalarmult(classical_seed, basepoint) catch {
                    return PQError.KeyGenFailed;
                };

                // Generate ML-KEM-768 key pair
                var pq_seed: [32]u8 = undefined;
                rand.fill(&pq_seed);

                const ml_kem_keypair = ml_kem.ML_KEM_768.KeyPair.generate(pq_seed) catch {
                    return PQError.KeyGenFailed;
                };

                keypair.pq_public = ml_kem_keypair.public_key;
                keypair.pq_private = ml_kem_keypair.private_key;

                return keypair;
            }

            /// Perform hybrid key exchange
            pub fn exchange(self: *const HybridKeyPair, peer_classical: [CLASSICAL_PUBLIC_SIZE]u8, peer_pq_ciphertext: [PQ_CIPHERTEXT_SIZE]u8) PQError![SHARED_SECRET_SIZE]u8 {
                var shared_secret: [SHARED_SECRET_SIZE]u8 = undefined;

                // X25519 key exchange
                const classical_shared = std.crypto.dh.X25519.scalarmult(self.classical_private, peer_classical) catch {
                    return PQError.DecapsFailed;
                };

                // ML-KEM-768 decapsulation
                const ml_kem_keypair = ml_kem.ML_KEM_768.KeyPair{
                    .public_key = self.pq_public,
                    .private_key = self.pq_private,
                };

                const pq_shared = ml_kem_keypair.decapsulate(peer_pq_ciphertext) catch {
                    return PQError.DecapsFailed;
                };

                // Combine classical and post-quantum shared secrets
                var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
                hasher.update(&classical_shared);
                hasher.update(&pq_shared);
                hasher.final(&shared_secret);

                return shared_secret;
            }
        };
    };

    /// Hybrid Signature: Ed25519 + ML-DSA-65
    pub const Ed25519_ML_DSA_65 = struct {
        pub const CLASSICAL_PUBLIC_SIZE = 32; // Ed25519 public key
        pub const CLASSICAL_PRIVATE_SIZE = 64; // Ed25519 secret key encoding
        pub const PQ_PUBLIC_SIZE = ml_dsa.ML_DSA_65.PUBLIC_KEY_SIZE;
        pub const PQ_PRIVATE_SIZE = ml_dsa.ML_DSA_65.PRIVATE_KEY_SIZE;
        pub const CLASSICAL_SIG_SIZE = 64; // Ed25519 signature
        pub const PQ_SIG_SIZE = ml_dsa.ML_DSA_65.SIGNATURE_SIZE;
        pub const HYBRID_SIG_SIZE = CLASSICAL_SIG_SIZE + PQ_SIG_SIZE;

        pub const HybridKeyPair = struct {
            classical_public: [CLASSICAL_PUBLIC_SIZE]u8,
            classical_private: [CLASSICAL_PRIVATE_SIZE]u8,
            pq_public: [PQ_PUBLIC_SIZE]u8,
            pq_private: [PQ_PRIVATE_SIZE]u8,

            /// Generate hybrid signature key pair
            pub fn generate() PQError!HybridKeyPair {
                var keypair: HybridKeyPair = undefined;

                // Generate Ed25519 key pair
                var classical_seed: [32]u8 = undefined;
                rand.fill(&classical_seed);

                const ed25519_keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(classical_seed) catch {
                    return PQError.KeyGenFailed;
                };
                keypair.classical_public = ed25519_keypair.public_key.toBytes();
                keypair.classical_private = ed25519_keypair.secret_key.toBytes();

                // Generate ML-DSA-65 key pair
                var pq_seed: [32]u8 = undefined;
                rand.fill(&pq_seed);

                const ml_dsa_keypair = ml_dsa.ML_DSA_65.KeyPair.generate(pq_seed) catch {
                    return PQError.KeyGenFailed;
                };

                keypair.pq_public = ml_dsa_keypair.public_key;
                keypair.pq_private = ml_dsa_keypair.private_key;

                return keypair;
            }

            /// Create hybrid signature
            pub fn sign(self: *const HybridKeyPair, message: []const u8) PQError![HYBRID_SIG_SIZE]u8 {
                var hybrid_signature: [HYBRID_SIG_SIZE]u8 = undefined;

                // Create Ed25519 signature
                const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(self.classical_private) catch {
                    return PQError.InvalidPrivateKey;
                };
                const ed25519_keypair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
                    return PQError.InvalidPrivateKey;
                };

                const classical_sig = ed25519_keypair.sign(message, null) catch {
                    return PQError.SignFailed;
                };
                const classical_sig_bytes = classical_sig.toBytes();

                // Create ML-DSA-65 signature
                const ml_dsa_keypair = ml_dsa.ML_DSA_65.KeyPair{
                    .public_key = self.pq_public,
                    .private_key = self.pq_private,
                };

                var pq_randomness: [ml_dsa.ML_DSA_65.NOISE_SIZE]u8 = undefined;
                rand.fill(&pq_randomness);

                const pq_sig = ml_dsa_keypair.sign(message, pq_randomness) catch {
                    return PQError.SignFailed;
                };

                // Combine signatures
                @memcpy(hybrid_signature[0..CLASSICAL_SIG_SIZE], &classical_sig_bytes);
                @memcpy(hybrid_signature[CLASSICAL_SIG_SIZE..], &pq_sig);

                return hybrid_signature;
            }

            /// Verify hybrid signature
            pub fn verify(classical_public: [CLASSICAL_PUBLIC_SIZE]u8, pq_public: [PQ_PUBLIC_SIZE]u8, message: []const u8, signature: [HYBRID_SIG_SIZE]u8) PQError!bool {
                // Extract individual signatures
                const classical_sig = signature[0..CLASSICAL_SIG_SIZE];
                const pq_sig = signature[CLASSICAL_SIG_SIZE..];

                // Verify Ed25519 signature
                const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(classical_public) catch {
                    return false;
                };
                const ed25519_signature = std.crypto.sign.Ed25519.Signature.fromBytes(classical_sig.*);
                ed25519_signature.verify(message, public_key) catch {
                    return false;
                };

                // Verify ML-DSA-65 signature
                const pq_signature: [ml_dsa.ML_DSA_65.SIGNATURE_SIZE]u8 = pq_sig[0..ml_dsa.ML_DSA_65.SIGNATURE_SIZE].*;
                const ml_dsa_result = ml_dsa.ML_DSA_65.KeyPair.verify(pq_public, message, pq_signature) catch {
                    return false;
                };

                // Both signatures must be valid
                return ml_dsa_result;
            }
        };
    };
};

test "ML-KEM-768 encapsulate/decapsulate agree (FIPS 203)" {
    var seed: [ml_kem.ML_KEM_768.SEED_SIZE]u8 = undefined;
    @memset(&seed, 0x42);
    const keypair = try ml_kem.ML_KEM_768.KeyPair.generate(seed);

    var encap_rand: [ml_kem.ML_KEM_768.SEED_SIZE]u8 = undefined;
    @memset(&encap_rand, 0x17);
    const encap = try ml_kem.ML_KEM_768.KeyPair.encapsulate(keypair.public_key, encap_rand);

    const decap = try keypair.decapsulate(encap.ciphertext);
    try std.testing.expectEqualSlices(u8, &encap.shared_secret, &decap);
}

test "ML-DSA-65 sign/verify with tamper detection (FIPS 204)" {
    var seed: [ml_dsa.ML_DSA_65.SEED_SIZE]u8 = undefined;
    @memset(&seed, 0x24);
    const keypair = try ml_dsa.ML_DSA_65.KeyPair.generate(seed);

    const message = "zcrypto ML-DSA-65 round trip";
    var noise: [ml_dsa.ML_DSA_65.NOISE_SIZE]u8 = undefined;
    @memset(&noise, 0x55);
    const signature = try keypair.sign(message, noise);

    try std.testing.expect(try ml_dsa.ML_DSA_65.KeyPair.verify(keypair.public_key, message, signature));

    // Flip one signature byte → verification must fail closed.
    var tampered = signature;
    tampered[0] ^= 0xFF;
    try std.testing.expect(!try ml_dsa.ML_DSA_65.KeyPair.verify(keypair.public_key, message, tampered));

    // Different message → verification must fail.
    try std.testing.expect(!try ml_dsa.ML_DSA_65.KeyPair.verify(keypair.public_key, "other message", signature));
}

test "Hybrid X25519+ML-KEM-768 key exchange agrees" {
    const H = hybrid.X25519_ML_KEM_768;

    // Responder (Alice) hybrid keypair.
    const alice = try H.HybridKeyPair.generate();

    // Initiator (Bob): ephemeral X25519 + ML-KEM encapsulation to Alice's PQ key.
    var b_seed: [32]u8 = undefined;
    rand.fill(&b_seed);
    const basepoint = [_]u8{9} ++ std.mem.zeroes([31]u8);
    const b_classical_public = try std.crypto.dh.X25519.scalarmult(b_seed, basepoint);

    var encap_rand: [32]u8 = undefined;
    rand.fill(&encap_rand);
    const encap = try ml_kem.ML_KEM_768.KeyPair.encapsulate(alice.pq_public, encap_rand);

    // Alice derives the shared secret from Bob's public key + ciphertext.
    const alice_secret = try alice.exchange(b_classical_public, encap.ciphertext);

    // Bob derives the same shared secret independently (mirrors exchange()).
    const b_classical_shared = try std.crypto.dh.X25519.scalarmult(b_seed, alice.classical_public);
    var bob_secret: [H.SHARED_SECRET_SIZE]u8 = undefined;
    var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
    hasher.update(&b_classical_shared);
    hasher.update(&encap.shared_secret);
    hasher.final(&bob_secret);

    try std.testing.expectEqualSlices(u8, &alice_secret, &bob_secret);
}

test "Hybrid Ed25519+ML-DSA-65 sign/verify with tamper detection" {
    const H = hybrid.Ed25519_ML_DSA_65;
    const keypair = try H.HybridKeyPair.generate();

    const message = "zcrypto hybrid signature round trip";
    const signature = try keypair.sign(message);

    try std.testing.expect(try H.HybridKeyPair.verify(
        keypair.classical_public,
        keypair.pq_public,
        message,
        signature,
    ));

    // Tamper with the classical half → must fail (both halves required).
    var tampered = signature;
    tampered[0] ^= 0xFF;
    try std.testing.expect(!try H.HybridKeyPair.verify(
        keypair.classical_public,
        keypair.pq_public,
        message,
        tampered,
    ));
}
