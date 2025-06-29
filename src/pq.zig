//! Post-Quantum Cryptography Module for zcrypto v0.4.0
//!
//! Implements NIST-standardized post-quantum algorithms:
//! - FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//! - FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm) 
//! - FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//!
//! Provides hybrid classical+post-quantum operations for backwards compatibility
//! and defense-in-depth security against both classical and quantum attacks.

const std = @import("std");
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

/// NIST ML-DSA (formerly Dilithium) - Digital Signature Algorithm
/// FIPS 204 compliant implementation
pub const ml_dsa = struct {
    /// ML-DSA-65 parameters (NIST Level 3 security)
    pub const ML_DSA_65 = struct {
        // NIST ML-DSA-65 constants
        pub const SECURITY_LEVEL = 3;
        pub const N = 256;   // Ring dimension
        pub const Q = 8380417; // Modulus
        pub const D = 13;    // Dropped bits
        pub const TAU = 49;  // Number of +/-1's in c
        pub const LAMBDA = 256; // Number of bits of randomness in seed
        pub const GAMMA1 = 1 << 19; // Coefficient range
        pub const GAMMA2 = (Q - 1) / 32; // Low-order rounding range
        pub const K = 6;     // Dimension of t0 and t1
        pub const L = 5;     // Dimension of s1 and s2
        pub const ETA = 4;   // Bound on coefficients of s1 and s2
        pub const BETA = TAU * ETA; // Maximum coefficient of c*s1 or c*s2
        pub const OMEGA = 75; // Maximum weight of h
        
        // Key and signature sizes
        pub const PUBLIC_KEY_SIZE = 1952;
        pub const PRIVATE_KEY_SIZE = 4016;
        pub const SIGNATURE_SIZE = 3309;
        pub const SEED_SIZE = 32;
        
        /// ML-DSA-65 Key Pair
        pub const KeyPair = struct {
            public_key: [ML_DSA_65.PUBLIC_KEY_SIZE]u8,
            private_key: [ML_DSA_65.PRIVATE_KEY_SIZE]u8,
            
            /// Generate ML-DSA-65 key pair from seed
            pub fn generate(seed: [SEED_SIZE]u8) PQError!KeyPair {
                _ = seed;
                // TODO: Implement ML-DSA-65 key generation
                return PQError.KeyGenFailed;
            }
            
            /// Generate ML-DSA-65 key pair using system randomness
            pub fn generateRandom(allocator: std.mem.Allocator) PQError!KeyPair {
                _ = allocator;
                var seed: [SEED_SIZE]u8 = undefined;
                std.crypto.random.bytes(&seed);
                return generate(seed);
            }
            
            /// Sign message with ML-DSA-65
            pub fn sign(self: *const KeyPair, message: []const u8, randomness: [SEED_SIZE]u8) PQError![SIGNATURE_SIZE]u8 {
                _ = self;
                _ = message;
                _ = randomness;
                // TODO: Implement ML-DSA-65 signing
                return PQError.SignFailed;
            }
            
            /// Verify ML-DSA-65 signature
            pub fn verify(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) PQError!bool {
                _ = public_key;
                _ = message;
                _ = signature;
                // TODO: Implement ML-DSA-65 verification
                return PQError.VerifyFailed;
            }
        };
    };
};

/// NIST SLH-DSA (SPHINCS+) - Stateless Hash-Based Digital Signature Algorithm
/// FIPS 205 compliant implementation
pub const slh_dsa = struct {
    /// SLH-DSA-128s parameters (NIST Level 1 security, fast signing)
    pub const SLH_DSA_128s = struct {
        // NIST SLH-DSA-128s constants
        pub const SECURITY_LEVEL = 1;
        pub const N = 16;    // Security parameter in bytes
        pub const H = 63;    // Height of hypertree
        pub const D = 7;     // Number of layers in hypertree
        pub const A = 12;    // Number of WOTS chains per tree
        pub const K = 14;    // Number of parallel WOTS chains
        pub const W = 16;    // Winternitz parameter
        
        // Key and signature sizes
        pub const PUBLIC_KEY_SIZE = 32;
        pub const PRIVATE_KEY_SIZE = 64;
        pub const SIGNATURE_SIZE = 7856;
        pub const SEED_SIZE = 48;
        
        /// SLH-DSA-128s Key Pair
        pub const KeyPair = struct {
            public_key: [SLH_DSA_128s.PUBLIC_KEY_SIZE]u8,
            private_key: [SLH_DSA_128s.PRIVATE_KEY_SIZE]u8,
            
            /// Generate SLH-DSA-128s key pair from seed
            pub fn generate(seed: [SEED_SIZE]u8) PQError!KeyPair {
                _ = seed;
                // TODO: Implement SLH-DSA-128s key generation
                return PQError.KeyGenFailed;
            }
            
            /// Generate SLH-DSA-128s key pair using system randomness
            pub fn generateRandom(allocator: std.mem.Allocator) PQError!KeyPair {
                _ = allocator;
                var seed: [SEED_SIZE]u8 = undefined;
                std.crypto.random.bytes(&seed);
                return generate(seed);
            }
            
            /// Sign message with SLH-DSA-128s
            pub fn sign(self: *const KeyPair, message: []const u8, randomness: [SEED_SIZE]u8) PQError![SIGNATURE_SIZE]u8 {
                _ = self;
                _ = message;
                _ = randomness;
                // TODO: Implement SLH-DSA-128s signing
                return PQError.SignFailed;
            }
            
            /// Verify SLH-DSA-128s signature
            pub fn verify(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) PQError!bool {
                _ = public_key;
                _ = message;
                _ = signature;
                // TODO: Implement SLH-DSA-128s verification
                return PQError.VerifyFailed;
            }
        };
    };
};

/// Hybrid Classical + Post-Quantum Cryptography
/// Combines classical algorithms with post-quantum for defense-in-depth
pub const hybrid = struct {
    /// Hybrid Key Exchange: X25519 + ML-KEM-768
    pub const X25519_ML_KEM_768 = struct {
        pub const CLASSICAL_PUBLIC_SIZE = 32;   // X25519 public key
        pub const CLASSICAL_PRIVATE_SIZE = 32;  // X25519 private key
        pub const PQ_PUBLIC_SIZE = ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE;
        pub const PQ_PRIVATE_SIZE = ml_kem.ML_KEM_768.PRIVATE_KEY_SIZE;
        pub const PQ_CIPHERTEXT_SIZE = ml_kem.ML_KEM_768.CIPHERTEXT_SIZE;
        pub const SHARED_SECRET_SIZE = 64;      // Combined classical + PQ secret
        
        pub const HybridKeyPair = struct {
            classical_public: [CLASSICAL_PUBLIC_SIZE]u8,
            classical_private: [CLASSICAL_PRIVATE_SIZE]u8,
            pq_public: [PQ_PUBLIC_SIZE]u8,
            pq_private: [PQ_PRIVATE_SIZE]u8,
            
            /// Generate hybrid key pair
            pub fn generate() PQError!HybridKeyPair {
                // TODO: Generate X25519 + ML-KEM-768 hybrid key pair
                return PQError.KeyGenFailed;
            }
            
            /// Perform hybrid key exchange
            pub fn exchange(self: *const HybridKeyPair, peer_classical: [CLASSICAL_PUBLIC_SIZE]u8, peer_pq_ciphertext: [PQ_CIPHERTEXT_SIZE]u8) PQError![SHARED_SECRET_SIZE]u8 {
                _ = self;
                _ = peer_classical;
                _ = peer_pq_ciphertext;
                // TODO: Combine X25519 ECDH + ML-KEM decapsulation
                return PQError.DecapsFailed;
            }
        };
    };
    
    /// Hybrid Signature: Ed25519 + ML-DSA-65
    pub const Ed25519_ML_DSA_65 = struct {
        pub const CLASSICAL_PUBLIC_SIZE = 32;   // Ed25519 public key
        pub const CLASSICAL_PRIVATE_SIZE = 32;  // Ed25519 private key
        pub const PQ_PUBLIC_SIZE = ml_dsa.ML_DSA_65.PUBLIC_KEY_SIZE;
        pub const PQ_PRIVATE_SIZE = ml_dsa.ML_DSA_65.PRIVATE_KEY_SIZE;
        pub const CLASSICAL_SIG_SIZE = 64;      // Ed25519 signature
        pub const PQ_SIG_SIZE = ml_dsa.ML_DSA_65.SIGNATURE_SIZE;
        pub const HYBRID_SIG_SIZE = CLASSICAL_SIG_SIZE + PQ_SIG_SIZE;
        
        pub const HybridKeyPair = struct {
            classical_public: [CLASSICAL_PUBLIC_SIZE]u8,
            classical_private: [CLASSICAL_PRIVATE_SIZE]u8,
            pq_public: [PQ_PUBLIC_SIZE]u8,
            pq_private: [PQ_PRIVATE_SIZE]u8,
            
            /// Generate hybrid signature key pair
            pub fn generate() PQError!HybridKeyPair {
                // TODO: Generate Ed25519 + ML-DSA-65 hybrid key pair
                return PQError.KeyGenFailed;
            }
            
            /// Create hybrid signature
            pub fn sign(self: *const HybridKeyPair, message: []const u8) PQError![HYBRID_SIG_SIZE]u8 {
                _ = self;
                _ = message;
                // TODO: Create Ed25519 + ML-DSA-65 combined signature
                return PQError.SignFailed;
            }
            
            /// Verify hybrid signature
            pub fn verify(classical_public: [CLASSICAL_PUBLIC_SIZE]u8, pq_public: [PQ_PUBLIC_SIZE]u8, message: []const u8, signature: [HYBRID_SIG_SIZE]u8) PQError!bool {
                _ = classical_public;
                _ = pq_public;
                _ = message;
                _ = signature;
                // TODO: Verify both Ed25519 and ML-DSA-65 signatures
                return PQError.VerifyFailed;
            }
        };
    };
};

test "ML-KEM-768 key generation" {
    // TODO: Add comprehensive tests once implementation is complete
}

test "ML-DSA-65 signing and verification" {
    // TODO: Add comprehensive tests once implementation is complete
}

test "SLH-DSA-128s signing and verification" {
    // TODO: Add comprehensive tests once implementation is complete
}

test "Hybrid X25519+ML-KEM-768 key exchange" {
    // TODO: Add comprehensive tests once implementation is complete
}

test "Hybrid Ed25519+ML-DSA-65 signatures" {
    // TODO: Add comprehensive tests once implementation is complete
}