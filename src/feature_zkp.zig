//! zcrypto ZKP Feature Module - Zero-Knowledge Proofs
//!
//! Provides zero-knowledge proof cryptographic operations when enabled.

const std = @import("std");

// Re-export ZKP modules
pub const zkp = @import("zkp.zig");

// ZKP test suite
test {
    _ = zkp;
}
