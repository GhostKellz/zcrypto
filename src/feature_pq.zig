//! zcrypto Post-Quantum Feature Module - ML-KEM and ML-DSA support
//!
//! Provides quantum-resistant cryptographic algorithms when enabled.

const std = @import("std");

// Re-export post-quantum modules
pub const post_quantum = @import("post_quantum.zig");
pub const pq = @import("pq.zig");

// Re-export main types for convenience
pub const kyber = post_quantum.ML_KEM_768;
pub const dilithium = post_quantum.ML_DSA_65;
pub const HybridSignature = post_quantum.HybridSignature;

// Post-quantum test suite
test {
    _ = post_quantum;
    _ = pq;
}
