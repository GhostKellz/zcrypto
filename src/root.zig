//! zcrypto - A modern cryptography library for Zig
//!
//! Designed for high-performance, memory-safe cryptographic operations
//! with a focus on TLS 1.3, QUIC, and modern public-key cryptography.
const std = @import("std");
const build_options = @import("build_options");

/// Standardized crypto errors for consistent error handling
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
pub const auth = @import("auth.zig");
pub const sym = @import("sym.zig");
pub const asym = @import("asym.zig");
pub const kdf = @import("kdf.zig");
pub const rand = @import("rand.zig");
pub const util = @import("util.zig");
pub const bip = @import("bip.zig");
pub const batch = @import("batch.zig");
pub const kex = @import("kex.zig");

// Always available modules
pub const quic_crypto = @import("quic_crypto.zig");
pub const key_rotation = @import("key_rotation.zig");

// Feature modules (may be available based on build configuration)
// Note: These will be available if the corresponding features were enabled during build
pub const tls = if (build_options.enable_tls) @import("feature_tls.zig") else struct{}{};
pub const post_quantum = if (build_options.enable_post_quantum) @import("feature_pq.zig") else struct{}{};
pub const hardware = if (build_options.enable_hardware_accel) @import("feature_hw.zig") else struct{}{};
pub const blockchain_crypto = if (build_options.enable_blockchain) @import("feature_blockchain.zig") else struct{}{};
pub const vpn_crypto = if (build_options.enable_vpn) @import("feature_vpn.zig") else struct{}{};
pub const wasm_crypto = if (build_options.enable_wasm) @import("feature_wasm.zig") else struct{}{};
pub const formal = if (build_options.enable_enterprise) @import("feature_enterprise.zig") else struct{}{};
pub const zkp = if (build_options.enable_zkp) @import("feature_zkp.zig") else struct{}{};
pub const async_crypto = if (build_options.enable_async) @import("feature_async.zig") else struct{};

// Legacy compatibility aliases
pub const pq = if (build_options.enable_post_quantum) post_quantum else struct{}{};

// Convenience exports for common algorithms
pub const kyber = if (build_options.enable_post_quantum) post_quantum.kyber else struct{}{};
pub const dilithium = if (build_options.enable_post_quantum) post_quantum.dilithium else struct{}{};
pub const x25519 = kex.X25519;
pub const ed25519 = kex.Ed25519;

// Version information
pub const version = "0.9.1";

test {
    // Import all core module tests
    _ = hash;
    _ = auth;
    _ = sym;
    _ = asym;
    _ = kdf;
    _ = rand;
    _ = util;
    _ = bip;
    _ = batch;
    _ = quic_crypto;
    _ = key_rotation;

    // Feature modules (conditionally available)
    // Note: These tests will only run if the features were enabled during build
    if (build_options.enable_tls) _ = tls;
    if (build_options.enable_post_quantum) _ = post_quantum;
    if (build_options.enable_hardware_accel) _ = hardware;
    if (build_options.enable_blockchain) _ = blockchain_crypto;
    if (build_options.enable_vpn) _ = vpn_crypto;
    if (build_options.enable_wasm) _ = wasm_crypto;
    if (build_options.enable_enterprise) _ = formal;
    if (build_options.enable_zkp) _ = zkp;
    if (build_options.enable_async) _ = async_crypto;
}
