//! zcrypto Core Module - Essential cryptographic primitives
//!
//! This module contains the fundamental cryptographic building blocks that are
//! always available, regardless of feature flags. Includes basic hash functions,
//! symmetric encryption, authentication, key derivation, and random number generation.

const std = @import("std");

// Re-export standardized crypto errors
pub const CryptoError = error{
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidHmacKey,
    InvalidKeyFormat,
    InvalidKeySize,
    InvalidNonceSize,
    InvalidTagSize,
    DecryptionFailed,
    EncryptionFailed,
    InvalidInput,
};

// Core cryptographic modules (always available)
pub const hash = @import("hash.zig");
pub const sym = @import("sym.zig");
pub const auth = @import("auth.zig");
pub const kdf = @import("kdf.zig");
pub const rand = @import("rand.zig");
pub const util = @import("util.zig");
pub const bip = @import("bip.zig");
pub const batch = @import("batch.zig");
pub const asym = @import("asym.zig");
pub const kex = @import("kex.zig");
pub const errors = @import("errors.zig");

// Version information
pub const version = "0.9.8";

// Core crypto test suite
test {
    // Import all core module tests
    _ = hash;
    _ = sym;
    _ = auth;
    _ = kdf;
    _ = rand;
    _ = util;
    _ = bip;
    _ = batch;
    _ = asym;
    _ = kex;
    _ = errors;
}
