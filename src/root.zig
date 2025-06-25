//! zcrypto - A modern cryptography library for Zig
//!
//! Designed for high-performance, memory-safe cryptographic operations
//! with a focus on TLS 1.3, QUIC, and modern public-key cryptography.
const std = @import("std");

// Re-export all modules for clean API
pub const hash = @import("hash.zig");
pub const auth = @import("auth.zig");
pub const sym = @import("sym.zig");
pub const asym = @import("asym.zig");
pub const kdf = @import("kdf.zig");
pub const rand = @import("rand.zig");
pub const util = @import("util.zig");
pub const bip = @import("bip.zig");

// TLS/QUIC specific modules
pub const tls = @import("tls.zig");

// Version information
pub const version = "0.2.0";

test {
    // Import all module tests
    _ = hash;
    _ = auth;
    _ = sym;
    _ = asym;
    _ = kdf;
    _ = rand;
    _ = util;
    _ = bip;
    _ = tls;
}
