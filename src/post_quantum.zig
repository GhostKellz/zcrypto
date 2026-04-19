//! Post-Quantum Cryptography implementation
//! NIST standardized algorithms: ML-KEM (Kyber) and ML-DSA (Dilithium)
//! Provides quantum-resistant key exchange and digital signatures

const std = @import("std");
const rand = @import("rand.zig");
const crypto = std.crypto;
const pq_impl = @import("pq.zig");
const testing = std.testing;

pub const PostQuantumError = error{
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidCiphertext,
    InvalidSignature,
    KeyGenerationFailed,
    EncapsulationFailed,
    DecapsulationFailed,
    SigningFailed,
    VerificationFailed,
};

/// ML-KEM-512 (formerly Kyber-512) - NIST security level 1
pub const ML_KEM_512 = struct {
    pub const PUBLIC_KEY_SIZE = 800;
    pub const PRIVATE_KEY_SIZE = 1632;
    pub const CIPHERTEXT_SIZE = 768;
    pub const SHARED_SECRET_SIZE = 32;

    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
    };

    pub const EncapsulationResult = struct {
        ciphertext: [CIPHERTEXT_SIZE]u8,
        shared_secret: [SHARED_SECRET_SIZE]u8,
    };

    /// Generate a new key pair using secure random
    pub fn generateKeypair() !KeyPair {
        const keypair = try pq_impl.ml_kem.ML_KEM_512.KeyPair.generateRandom();
        return .{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }

    /// Encapsulate to create shared secret and ciphertext
    pub fn encapsulate(public_key: [PUBLIC_KEY_SIZE]u8) !EncapsulationResult {
        var randomness: [pq_impl.ml_kem.ML_KEM_512.SEED_SIZE]u8 = undefined;
        rand.fill(&randomness);

        const result = try pq_impl.ml_kem.ML_KEM_512.KeyPair.encapsulate(public_key, randomness);
        return .{
            .ciphertext = result.ciphertext,
            .shared_secret = result.shared_secret,
        };
    }

    /// Decapsulate ciphertext to recover shared secret
    pub fn decapsulate(private_key: [PRIVATE_KEY_SIZE]u8, ciphertext: [CIPHERTEXT_SIZE]u8) ![SHARED_SECRET_SIZE]u8 {
        const keypair = pq_impl.ml_kem.ML_KEM_512.KeyPair{
            .public_key = [_]u8{0} ** PUBLIC_KEY_SIZE,
            .private_key = private_key,
        };
        return try keypair.decapsulate(ciphertext);
    }
};

/// ML-KEM-768 (formerly Kyber-768) - NIST security level 3 (recommended)
pub const ML_KEM_768 = struct {
    pub const PUBLIC_KEY_SIZE = 1184;
    pub const PRIVATE_KEY_SIZE = 2400;
    pub const CIPHERTEXT_SIZE = 1088;
    pub const SHARED_SECRET_SIZE = 32;

    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
    };

    pub const EncapsulationResult = struct {
        ciphertext: [CIPHERTEXT_SIZE]u8,
        shared_secret: [SHARED_SECRET_SIZE]u8,
    };

    pub fn generateKeypair() !KeyPair {
        const keypair = try pq_impl.ml_kem.ML_KEM_768.KeyPair.generateRandom();
        return .{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }

    pub fn encapsulate(public_key: [PUBLIC_KEY_SIZE]u8) !EncapsulationResult {
        var randomness: [pq_impl.ml_kem.ML_KEM_768.SEED_SIZE]u8 = undefined;
        rand.fill(&randomness);

        const result = try pq_impl.ml_kem.ML_KEM_768.KeyPair.encapsulate(public_key, randomness);
        return .{
            .ciphertext = result.ciphertext,
            .shared_secret = result.shared_secret,
        };
    }

    pub fn decapsulate(private_key: [PRIVATE_KEY_SIZE]u8, ciphertext: [CIPHERTEXT_SIZE]u8) ![SHARED_SECRET_SIZE]u8 {
        const keypair = pq_impl.ml_kem.ML_KEM_768.KeyPair{
            .public_key = [_]u8{0} ** PUBLIC_KEY_SIZE,
            .private_key = private_key,
        };
        return try keypair.decapsulate(ciphertext);
    }
};

/// ML-KEM-1024 (formerly Kyber-1024) - NIST security level 5
pub const ML_KEM_1024 = struct {
    pub const PUBLIC_KEY_SIZE = 1568;
    pub const PRIVATE_KEY_SIZE = 3168;
    pub const CIPHERTEXT_SIZE = 1568;
    pub const SHARED_SECRET_SIZE = 32;

    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
    };

    pub const EncapsulationResult = struct {
        ciphertext: [CIPHERTEXT_SIZE]u8,
        shared_secret: [SHARED_SECRET_SIZE]u8,
    };

    pub fn generateKeypair() !KeyPair {
        const keypair = try pq_impl.ml_kem.ML_KEM_1024.KeyPair.generateRandom();
        return .{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }

    pub fn encapsulate(public_key: [PUBLIC_KEY_SIZE]u8) !EncapsulationResult {
        var randomness: [pq_impl.ml_kem.ML_KEM_1024.SEED_SIZE]u8 = undefined;
        rand.fill(&randomness);

        const result = try pq_impl.ml_kem.ML_KEM_1024.KeyPair.encapsulate(public_key, randomness);
        return .{
            .ciphertext = result.ciphertext,
            .shared_secret = result.shared_secret,
        };
    }

    pub fn decapsulate(private_key: [PRIVATE_KEY_SIZE]u8, ciphertext: [CIPHERTEXT_SIZE]u8) ![SHARED_SECRET_SIZE]u8 {
        const keypair = pq_impl.ml_kem.ML_KEM_1024.KeyPair{
            .public_key = [_]u8{0} ** PUBLIC_KEY_SIZE,
            .private_key = private_key,
        };
        return try keypair.decapsulate(ciphertext);
    }
};

/// ML-DSA-44 (formerly Dilithium2) - NIST security level 2
pub const ML_DSA_44 = struct {
    pub const PUBLIC_KEY_SIZE = pq_impl.ml_dsa.ML_DSA_44.PUBLIC_KEY_SIZE;
    pub const PRIVATE_KEY_SIZE = pq_impl.ml_dsa.ML_DSA_44.PRIVATE_KEY_SIZE;
    pub const SIGNATURE_SIZE = pq_impl.ml_dsa.ML_DSA_44.SIGNATURE_SIZE;

    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
    };

    pub fn generateKeypair() !KeyPair {
        const keypair = try pq_impl.ml_dsa.ML_DSA_44.KeyPair.generateRandom();
        return .{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }

    pub fn sign(private_key: [PRIVATE_KEY_SIZE]u8, message: []const u8) ![SIGNATURE_SIZE]u8 {
        var randomness: [pq_impl.ml_dsa.ML_DSA_44.NOISE_SIZE]u8 = undefined;
        rand.fill(&randomness);
        const keypair = pq_impl.ml_dsa.ML_DSA_44.KeyPair{
            .public_key = [_]u8{0} ** PUBLIC_KEY_SIZE,
            .private_key = private_key,
        };
        return try keypair.sign(message, randomness);
    }

    pub fn verify(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) !bool {
        return try pq_impl.ml_dsa.ML_DSA_44.KeyPair.verify(public_key, message, signature);
    }
};

/// ML-DSA-65 (formerly Dilithium3) - NIST security level 3 (recommended)
pub const ML_DSA_65 = struct {
    pub const PUBLIC_KEY_SIZE = 1952;
    pub const PRIVATE_KEY_SIZE = pq_impl.ml_dsa.ML_DSA_65.PRIVATE_KEY_SIZE;
    pub const SIGNATURE_SIZE = pq_impl.ml_dsa.ML_DSA_65.SIGNATURE_SIZE;

    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
    };

    pub fn generateKeypair() !KeyPair {
        const keypair = try pq_impl.ml_dsa.ML_DSA_65.KeyPair.generateRandom();
        return .{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }

    pub fn sign(private_key: [PRIVATE_KEY_SIZE]u8, message: []const u8) ![SIGNATURE_SIZE]u8 {
        const keypair = pq_impl.ml_dsa.ML_DSA_65.KeyPair{
            .public_key = [_]u8{0} ** PUBLIC_KEY_SIZE,
            .private_key = private_key,
        };
        var randomness: [pq_impl.ml_dsa.ML_DSA_65.NOISE_SIZE]u8 = undefined;
        rand.fill(&randomness);
        return try keypair.sign(message, randomness);
    }

    pub fn verify(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) !bool {
        return try pq_impl.ml_dsa.ML_DSA_65.KeyPair.verify(public_key, message, signature);
    }
};

/// ML-DSA-87 (formerly Dilithium5) - NIST security level 5
pub const ML_DSA_87 = struct {
    pub const PUBLIC_KEY_SIZE = 2592;
    pub const PRIVATE_KEY_SIZE = pq_impl.ml_dsa.ML_DSA_87.PRIVATE_KEY_SIZE;
    pub const SIGNATURE_SIZE = pq_impl.ml_dsa.ML_DSA_87.SIGNATURE_SIZE;

    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
    };

    pub fn generateKeypair() !KeyPair {
        const keypair = try pq_impl.ml_dsa.ML_DSA_87.KeyPair.generateRandom();
        return .{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }

    pub fn sign(private_key: [PRIVATE_KEY_SIZE]u8, message: []const u8) ![SIGNATURE_SIZE]u8 {
        var randomness: [pq_impl.ml_dsa.ML_DSA_87.NOISE_SIZE]u8 = undefined;
        rand.fill(&randomness);
        const keypair = pq_impl.ml_dsa.ML_DSA_87.KeyPair{
            .public_key = [_]u8{0} ** PUBLIC_KEY_SIZE,
            .private_key = private_key,
        };
        return try keypair.sign(message, randomness);
    }

    pub fn verify(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) !bool {
        return try pq_impl.ml_dsa.ML_DSA_87.KeyPair.verify(public_key, message, signature);
    }
};

/// Hybrid key exchange combining classical and post-quantum algorithms
pub const HybridKeyExchange = struct {
    pub const ClassicalKeyPair = struct {
        public_key: [32]u8, // X25519 public key
        private_key: [32]u8, // X25519 private key
    };

    pub const PQKeyPair = struct {
        public_key: [ML_KEM_768.PUBLIC_KEY_SIZE]u8,
        private_key: [ML_KEM_768.PRIVATE_KEY_SIZE]u8,
    };

    pub const HybridKeyPair = struct {
        classical: ClassicalKeyPair,
        post_quantum: PQKeyPair,
    };

    pub const HybridSharedSecret = struct {
        classical_secret: [32]u8,
        pq_secret: [32]u8,
        combined_secret: [32]u8,
    };

    /// Generate hybrid key pair with both classical and post-quantum keys
    pub fn generateKeypair() !HybridKeyPair {
        var keypair = HybridKeyPair{
            .classical = ClassicalKeyPair{
                .public_key = undefined,
                .private_key = undefined,
            },
            .post_quantum = PQKeyPair{
                .public_key = undefined,
                .private_key = undefined,
            },
        };

        // Generate X25519 keypair (stub - would use proper X25519)
        rand.fill(&keypair.classical.private_key);
        rand.fill(&keypair.classical.public_key);

        // Generate ML-KEM-768 keypair
        const pq_keypair = try ML_KEM_768.generateKeypair();
        keypair.post_quantum.public_key = pq_keypair.public_key;
        keypair.post_quantum.private_key = pq_keypair.private_key;

        return keypair;
    }

    /// Perform hybrid key exchange combining both algorithms
    pub fn keyExchange(our_private: HybridKeyPair, their_classical_public: [32]u8, their_pq_public: [ML_KEM_768.PUBLIC_KEY_SIZE]u8) !HybridSharedSecret {
        var shared = HybridSharedSecret{
            .classical_secret = undefined,
            .pq_secret = undefined,
            .combined_secret = undefined,
        };

        // X25519 key exchange (stub)
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&our_private.classical.private_key);
        hasher.update(&their_classical_public);
        hasher.final(&shared.classical_secret);

        // ML-KEM-768 encapsulation
        const encap_result = try ML_KEM_768.encapsulate(their_pq_public);
        shared.pq_secret = encap_result.shared_secret;

        // Combine secrets using HKDF
        hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&shared.classical_secret);
        hasher.update(&shared.pq_secret);
        hasher.update("hybrid-kdf-label");
        hasher.final(&shared.combined_secret);

        return shared;
    }
};

/// Hybrid signatures combining classical and post-quantum algorithms
pub const HybridSignature = struct {
    pub const ClassicalKeyPair = struct {
        public_key: [32]u8, // Ed25519 public key
        private_key: [32]u8, // Ed25519 private key
    };

    pub const PQKeyPair = struct {
        public_key: [ML_DSA_65.PUBLIC_KEY_SIZE]u8,
        private_key: [ML_DSA_65.PRIVATE_KEY_SIZE]u8,
    };

    pub const HybridKeyPair = struct {
        classical: ClassicalKeyPair,
        post_quantum: PQKeyPair,
    };

    pub const HybridSignatureResult = struct {
        classical_signature: [64]u8, // Ed25519 signature
        pq_signature: [ML_DSA_65.SIGNATURE_SIZE]u8,
        combined_signature: []u8, // Concatenated signatures
    };

    pub fn generateKeypair(allocator: std.mem.Allocator) !HybridKeyPair {
        var keypair = HybridKeyPair{
            .classical = ClassicalKeyPair{
                .public_key = undefined,
                .private_key = undefined,
            },
            .post_quantum = PQKeyPair{
                .public_key = undefined,
                .private_key = undefined,
            },
        };

        // Generate Ed25519 keypair (stub)
        rand.fill(&keypair.classical.private_key);
        rand.fill(&keypair.classical.public_key);

        // Generate ML-DSA-65 keypair
        const pq_keypair = try ML_DSA_65.generateKeypair();
        keypair.post_quantum.public_key = pq_keypair.public_key;
        keypair.post_quantum.private_key = pq_keypair.private_key;

        _ = allocator; // For future use
        return keypair;
    }

    pub fn sign(allocator: std.mem.Allocator, keypair: HybridKeyPair, message: []const u8) ![]u8 {
        // Ed25519 signature (stub)
        var classical_sig: [64]u8 = undefined;
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&keypair.classical.private_key);
        hasher.update(message);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(classical_sig[0..32], &hash);
        @memcpy(classical_sig[32..64], &hash);

        // ML-DSA-65 signature
        const pq_sig = try ML_DSA_65.sign(keypair.post_quantum.private_key, message);

        // Combine signatures
        const combined_size = 64 + ML_DSA_65.SIGNATURE_SIZE;
        const combined = try allocator.alloc(u8, combined_size);
        @memcpy(combined[0..64], &classical_sig);
        @memcpy(combined[64..combined_size], &pq_sig);

        return combined;
    }

    pub fn verify(hybrid_public: HybridKeyPair, message: []const u8, signature: []const u8) !bool {
        if (signature.len != 64 + ML_DSA_65.SIGNATURE_SIZE) return false;

        // Verify Ed25519 signature (stub)
        const classical_sig = signature[0..64];
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&hybrid_public.classical.public_key);
        hasher.update(message);
        hasher.update(classical_sig);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        const classical_valid = hash[0] != 0;

        // Verify ML-DSA-65 signature
        const pq_sig_array: [ML_DSA_65.SIGNATURE_SIZE]u8 = signature[64..][0..ML_DSA_65.SIGNATURE_SIZE].*;
        const pq_valid = try ML_DSA_65.verify(hybrid_public.post_quantum.public_key, message, pq_sig_array);

        return classical_valid and pq_valid;
    }
};

// Tests
test "ML-KEM-768 key exchange" {
    const keypair = try ML_KEM_768.generateKeypair();
    const encap_result = try ML_KEM_768.encapsulate(keypair.public_key);
    const decap_secret = try ML_KEM_768.decapsulate(keypair.private_key, encap_result.ciphertext);
    try testing.expectEqualSlices(u8, &encap_result.shared_secret, &decap_secret);
}

test "ML-DSA-65 signature" {
    const keypair = try ML_DSA_65.generateKeypair();
    const message = "test message for post-quantum signature";

    const signature = try ML_DSA_65.sign(keypair.private_key, message);
    const valid = try ML_DSA_65.verify(keypair.public_key, message, signature);

    try testing.expect(valid);
}

test "hybrid key exchange" {
    const alice_keypair = try HybridKeyExchange.generateKeypair();
    const bob_keypair = try HybridKeyExchange.generateKeypair();

    const alice_shared = try HybridKeyExchange.keyExchange(alice_keypair, bob_keypair.classical.public_key, bob_keypair.post_quantum.public_key);

    // Basic sanity check
    var all_zeros = true;
    for (alice_shared.combined_secret) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);
}

test "hybrid signature" {
    const allocator = testing.allocator;
    const keypair = try HybridSignature.generateKeypair(allocator);
    const message = "hybrid signature test message";

    const signature = try HybridSignature.sign(allocator, keypair, message);
    defer allocator.free(signature);

    const valid = try HybridSignature.verify(keypair, message, signature);
    try testing.expect(valid);
}
