//! zcrypto Post-Quantum Feature Module - ML-KEM and ML-DSA support
//!
//! Provides quantum-resistant cryptographic algorithms when enabled.

const std = @import("std");

// Re-export post-quantum modules
pub const post_quantum = @import("post_quantum.zig");
pub const pq = @import("pq.zig");

// Re-export main types for convenience
pub const ML_KEM_512 = post_quantum.ML_KEM_512;
pub const ML_KEM_768 = post_quantum.ML_KEM_768;
pub const ML_KEM_1024 = post_quantum.ML_KEM_1024;
pub const ML_DSA_44 = post_quantum.ML_DSA_44;
pub const ML_DSA_65 = post_quantum.ML_DSA_65;
pub const ML_DSA_87 = post_quantum.ML_DSA_87;
pub const kyber = post_quantum.ML_KEM_768;
pub const dilithium = post_quantum.ML_DSA_65;
pub const HybridSignature = post_quantum.HybridSignature;

// Post-quantum test suite
test {
    _ = post_quantum;
    _ = pq;
}
