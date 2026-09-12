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
            .public_key = std.mem.zeroes([PUBLIC_KEY_SIZE]u8),
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
            .public_key = std.mem.zeroes([PUBLIC_KEY_SIZE]u8),
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
            .public_key = std.mem.zeroes([PUBLIC_KEY_SIZE]u8),
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
            .public_key = std.mem.zeroes([PUBLIC_KEY_SIZE]u8),
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
            .public_key = std.mem.zeroes([PUBLIC_KEY_SIZE]u8),
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
            .public_key = std.mem.zeroes([PUBLIC_KEY_SIZE]u8),
            .private_key = private_key,
        };
        return try keypair.sign(message, randomness);
    }

    pub fn verify(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) !bool {
        return try pq_impl.ml_dsa.ML_DSA_87.KeyPair.verify(public_key, message, signature);
    }
};

/// Hybrid key exchange: X25519 + ML-KEM-768.
///
/// The KEM half is not symmetric, so the two peers run different functions:
/// the initiator calls `initiate` and transmits the returned ciphertext, and
/// the responder calls `respond` with it. Both then hold the same
/// `combined_secret`.
///
/// History: `generateKeypair` used to fill the classical public key with random
/// bytes instead of deriving it from the private key, and the classical
/// "exchange" hashed our own private key together with the peer's public key
/// rather than performing a Diffie-Hellman — so two peers never agreed. The
/// single `keyExchange` entry point also encapsulated to the peer's ML-KEM key
/// and then discarded the ciphertext, leaving the peer no way to recover the
/// same secret. Its test asserted only that the result was not all zeros, which
/// is the one property that construction could satisfy; it never checked that
/// the two sides agreed.
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

    /// An initiator's shared secret plus the ciphertext the responder needs.
    pub const Initiation = struct {
        ciphertext: [ML_KEM_768.CIPHERTEXT_SIZE]u8,
        shared: HybridSharedSecret,
    };

    /// Generate a hybrid key pair: a real X25519 key pair and a real ML-KEM-768
    /// key pair.
    pub fn generateKeypair() !HybridKeyPair {
        var classical_private: [32]u8 = undefined;
        rand.fill(&classical_private);

        const basepoint = [_]u8{9} ++ std.mem.zeroes([31]u8);
        const classical_public = try crypto.dh.X25519.scalarmult(classical_private, basepoint);

        const pq_keypair = try ML_KEM_768.generateKeypair();

        return HybridKeyPair{
            .classical = .{
                .public_key = classical_public,
                .private_key = classical_private,
            },
            .post_quantum = .{
                .public_key = pq_keypair.public_key,
                .private_key = pq_keypair.private_key,
            },
        };
    }

    /// Initiator side: X25519 against the peer's classical key, ML-KEM-768
    /// encapsulation against the peer's KEM key.
    ///
    /// The returned ciphertext must be sent to the peer; without it the peer
    /// cannot derive the same secret.
    pub fn initiate(our_keypair: HybridKeyPair, their_classical_public: [32]u8, their_pq_public: [ML_KEM_768.PUBLIC_KEY_SIZE]u8) !Initiation {
        const classical_secret = try crypto.dh.X25519.scalarmult(our_keypair.classical.private_key, their_classical_public);
        const encap = try ML_KEM_768.encapsulate(their_pq_public);

        return Initiation{
            .ciphertext = encap.ciphertext,
            .shared = combine(classical_secret, encap.shared_secret),
        };
    }

    /// Responder side: X25519 against the peer's classical key, ML-KEM-768
    /// decapsulation of the ciphertext the initiator sent.
    pub fn respond(our_keypair: HybridKeyPair, their_classical_public: [32]u8, ciphertext: [ML_KEM_768.CIPHERTEXT_SIZE]u8) !HybridSharedSecret {
        const classical_secret = try crypto.dh.X25519.scalarmult(our_keypair.classical.private_key, their_classical_public);
        const pq_secret = try ML_KEM_768.decapsulate(our_keypair.post_quantum.private_key, ciphertext);

        return combine(classical_secret, pq_secret);
    }

    /// Concatenation combiner: both inputs are fixed-length, so no separator is
    /// needed to make the encoding unambiguous.
    fn combine(classical_secret: [32]u8, pq_secret: [32]u8) HybridSharedSecret {
        var ikm: [64]u8 = undefined;
        @memcpy(ikm[0..32], &classical_secret);
        @memcpy(ikm[32..64], &pq_secret);

        const combined = crypto.kdf.hkdf.HkdfSha256.extract("zcrypto-hybrid-x25519-mlkem768", &ikm);

        return HybridSharedSecret{
            .classical_secret = classical_secret,
            .pq_secret = pq_secret,
            .combined_secret = combined,
        };
    }
};

/// Hybrid signatures combining classical and post-quantum algorithms
pub const HybridSignature = struct {
    pub const ClassicalKeyPair = struct {
        public_key: [32]u8, // Ed25519 public key
        private_key: [64]u8, // Ed25519 secret key
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

        // Generate Ed25519 keypair
        var classical_seed: [32]u8 = undefined;
        rand.fill(&classical_seed);
        const classical_keypair = crypto.sign.Ed25519.KeyPair.generateDeterministic(classical_seed) catch {
            return PostQuantumError.KeyGenerationFailed;
        };
        keypair.classical.public_key = classical_keypair.public_key.toBytes();
        keypair.classical.private_key = classical_keypair.secret_key.toBytes();

        // Generate ML-DSA-65 keypair
        const pq_keypair = try ML_DSA_65.generateKeypair();
        keypair.post_quantum.public_key = pq_keypair.public_key;
        keypair.post_quantum.private_key = pq_keypair.private_key;

        _ = allocator; // For future use
        return keypair;
    }

    pub fn sign(allocator: std.mem.Allocator, keypair: HybridKeyPair, message: []const u8) ![]u8 {
        // Ed25519 signature
        const secret_key = crypto.sign.Ed25519.SecretKey.fromBytes(keypair.classical.private_key) catch {
            return PostQuantumError.InvalidPrivateKey;
        };
        const classical_keypair = crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
            return PostQuantumError.InvalidPrivateKey;
        };
        const classical_sig = classical_keypair.sign(message, null) catch {
            return PostQuantumError.SigningFailed;
        };
        const classical_sig_bytes = classical_sig.toBytes();

        // ML-DSA-65 signature
        const pq_sig = try ML_DSA_65.sign(keypair.post_quantum.private_key, message);

        // Combine signatures
        const combined_size = 64 + ML_DSA_65.SIGNATURE_SIZE;
        const combined = try allocator.alloc(u8, combined_size);
        @memcpy(combined[0..64], &classical_sig_bytes);
        @memcpy(combined[64..combined_size], &pq_sig);

        return combined;
    }

    pub fn verify(hybrid_public: HybridKeyPair, message: []const u8, signature: []const u8) !bool {
        if (signature.len != 64 + ML_DSA_65.SIGNATURE_SIZE) return false;

        // Verify Ed25519 signature
        const classical_sig = signature[0..64];
        const public_key = crypto.sign.Ed25519.PublicKey.fromBytes(hybrid_public.classical.public_key) catch {
            return false;
        };
        const classical_signature = crypto.sign.Ed25519.Signature.fromBytes(classical_sig[0..64].*);
        classical_signature.verify(message, public_key) catch return false;

        // Verify ML-DSA-65 signature
        const pq_sig_array: [ML_DSA_65.SIGNATURE_SIZE]u8 = signature[64..][0..ML_DSA_65.SIGNATURE_SIZE].*;
        const pq_valid = try ML_DSA_65.verify(hybrid_public.post_quantum.public_key, message, pq_sig_array);

        return pq_valid;
    }
};

// Tests
test "ML-KEM-768 key exchange" {
    const keypair = try ML_KEM_768.generateKeypair();
    const encap_result = try ML_KEM_768.encapsulate(keypair.public_key);
    const decap_secret = try ML_KEM_768.decapsulate(keypair.private_key, encap_result.ciphertext);
    try testing.expectEqualSlices(u8, &encap_result.shared_secret, &decap_secret);
}

test "ML-KEM implicit rejection: tampered ciphertext yields an unrelated secret, not an error" {
    // FIPS 203 decapsulation never reports failure: on an invalid ciphertext it
    // returns a pseudorandom secret derived from the private key's rejection
    // seed. Asserting `expectError` here would be wrong, and a future change
    // that made decapsulation fault on bad input would be a spec violation as
    // well as a decryption-failure oracle. This pins the correct contract.
    inline for (.{ ML_KEM_512, ML_KEM_768, ML_KEM_1024 }) |KEM| {
        const keypair = try KEM.generateKeypair();
        const encap = try KEM.encapsulate(keypair.public_key);

        var tampered = encap.ciphertext;
        tampered[0] ^= 0x01;

        const rejected = try KEM.decapsulate(keypair.private_key, tampered);
        try testing.expect(!std.mem.eql(u8, &encap.shared_secret, &rejected));
        try testing.expect(!std.mem.allEqual(u8, &rejected, 0));

        // Implicit rejection is deterministic in the private key and the
        // ciphertext, so the same bad ciphertext must give the same secret.
        const rejected_again = try KEM.decapsulate(keypair.private_key, tampered);
        try testing.expectEqualSlices(u8, &rejected, &rejected_again);
    }
}

test "ML-KEM decapsulation under the wrong private key does not recover the secret" {
    inline for (.{ ML_KEM_512, ML_KEM_768, ML_KEM_1024 }) |KEM| {
        const keypair = try KEM.generateKeypair();
        const other = try KEM.generateKeypair();
        const encap = try KEM.encapsulate(keypair.public_key);

        const wrong = try KEM.decapsulate(other.private_key, encap.ciphertext);
        try testing.expect(!std.mem.eql(u8, &encap.shared_secret, &wrong));
    }
}

test "ML-DSA-65 signature" {
    const keypair = try ML_DSA_65.generateKeypair();
    const message = "test message for post-quantum signature";

    const signature = try ML_DSA_65.sign(keypair.private_key, message);
    const valid = try ML_DSA_65.verify(keypair.public_key, message, signature);

    try testing.expect(valid);
}

test "ML-DSA rejects tampered signatures, messages, and keys" {
    inline for (.{ ML_DSA_44, ML_DSA_65, ML_DSA_87 }) |DSA| {
        const keypair = try DSA.generateKeypair();
        const other = try DSA.generateKeypair();
        const message = "post-quantum negative coverage";

        const signature = try DSA.sign(keypair.private_key, message);
        try testing.expect(try DSA.verify(keypair.public_key, message, signature));

        var tampered = signature;
        tampered[0] ^= 0x01;
        try testing.expect(!(DSA.verify(keypair.public_key, message, tampered) catch false));

        try testing.expect(!(DSA.verify(keypair.public_key, "different message", signature) catch false));
        try testing.expect(!(DSA.verify(other.public_key, message, signature) catch false));
    }
}

test "hybrid key exchange: both peers agree" {
    // The agreement assertion is the whole point. The previous implementation
    // could not satisfy it, and the previous test avoided asking for it.
    const alice = try HybridKeyExchange.generateKeypair();
    const bob = try HybridKeyExchange.generateKeypair();

    const init = try HybridKeyExchange.initiate(alice, bob.classical.public_key, bob.post_quantum.public_key);
    const bob_shared = try HybridKeyExchange.respond(bob, alice.classical.public_key, init.ciphertext);

    try testing.expectEqualSlices(u8, &init.shared.classical_secret, &bob_shared.classical_secret);
    try testing.expectEqualSlices(u8, &init.shared.pq_secret, &bob_shared.pq_secret);
    try testing.expectEqualSlices(u8, &init.shared.combined_secret, &bob_shared.combined_secret);

    try testing.expect(!std.mem.allEqual(u8, &init.shared.combined_secret, 0));
    // The combiner must actually mix: the output must not be either input.
    try testing.expect(!std.mem.eql(u8, &init.shared.combined_secret, &init.shared.classical_secret));
    try testing.expect(!std.mem.eql(u8, &init.shared.combined_secret, &init.shared.pq_secret));
}

test "hybrid key exchange: X25519 public key really derives from the private key" {
    // Guards the old stub, which filled the public key with random bytes.
    const kp = try HybridKeyExchange.generateKeypair();
    const basepoint = [_]u8{9} ++ std.mem.zeroes([31]u8);
    const derived = try crypto.dh.X25519.scalarmult(kp.classical.private_key, basepoint);
    try testing.expectEqualSlices(u8, &derived, &kp.classical.public_key);
}

test "hybrid key exchange: a third party does not learn the secret" {
    const alice = try HybridKeyExchange.generateKeypair();
    const bob = try HybridKeyExchange.generateKeypair();
    const eve = try HybridKeyExchange.generateKeypair();

    const init = try HybridKeyExchange.initiate(alice, bob.classical.public_key, bob.post_quantum.public_key);

    // Eve holds the ciphertext but not Bob's keys, so she cannot reach the
    // same secret. Her ML-KEM decapsulation succeeds via implicit rejection
    // and yields an unrelated value rather than an error.
    const eve_shared = try HybridKeyExchange.respond(eve, alice.classical.public_key, init.ciphertext);
    try testing.expect(!std.mem.eql(u8, &init.shared.combined_secret, &eve_shared.combined_secret));
    try testing.expect(!std.mem.eql(u8, &init.shared.pq_secret, &eve_shared.pq_secret));

    // Wrong classical peer key also breaks agreement.
    const wrong_classical = try HybridKeyExchange.respond(bob, eve.classical.public_key, init.ciphertext);
    try testing.expect(!std.mem.eql(u8, &init.shared.combined_secret, &wrong_classical.combined_secret));
}

test "hybrid key exchange: tampered ciphertext does not yield the initiator secret" {
    // ML-KEM implicit rejection means decapsulation returns a pseudorandom
    // secret rather than failing; the contract is that it differs, not that it
    // errors.
    const alice = try HybridKeyExchange.generateKeypair();
    const bob = try HybridKeyExchange.generateKeypair();

    const init = try HybridKeyExchange.initiate(alice, bob.classical.public_key, bob.post_quantum.public_key);

    var tampered = init.ciphertext;
    tampered[0] ^= 0x01;

    const bob_shared = try HybridKeyExchange.respond(bob, alice.classical.public_key, tampered);
    try testing.expect(!std.mem.eql(u8, &init.shared.pq_secret, &bob_shared.pq_secret));
    try testing.expect(!std.mem.eql(u8, &init.shared.combined_secret, &bob_shared.combined_secret));
}

test "hybrid signature" {
    const allocator = testing.allocator;
    const keypair = try HybridSignature.generateKeypair(allocator);
    const message = "hybrid signature test message";

    const signature = try HybridSignature.sign(allocator, keypair, message);
    defer allocator.free(signature);

    const valid = try HybridSignature.verify(keypair, message, signature);
    try testing.expect(valid);

    var tampered = try allocator.dupe(u8, signature);
    defer allocator.free(tampered);

    tampered[0] ^= 0xFF;
    try testing.expect(!try HybridSignature.verify(keypair, message, tampered));

    @memcpy(tampered, signature);
    tampered[64] ^= 0xFF;
    try testing.expect(!try HybridSignature.verify(keypair, message, tampered));

    try testing.expect(!try HybridSignature.verify(keypair, "different message", signature));
    try testing.expect(!try HybridSignature.verify(keypair, message, signature[0 .. signature.len - 1]));
}
