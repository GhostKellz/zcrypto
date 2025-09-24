//! zcrypto Blockchain Feature Module - BLS signatures and Schnorr cryptography
//!
//! Provides blockchain-specific cryptographic algorithms when enabled.

const std = @import("std");

// Re-export blockchain modules
pub const blockchain_crypto = @import("blockchain_crypto.zig");
pub const bls = @import("bls.zig");
pub const schnorr = @import("schnorr.zig");

// Blockchain test suite
test {
    _ = blockchain_crypto;
    _ = bls;
    _ = schnorr;
}
