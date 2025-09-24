//! zcrypto WebAssembly Feature Module - WASM-specific optimizations
//!
//! Provides WebAssembly-compatible cryptographic operations when enabled.

const std = @import("std");

// Re-export WASM modules
pub const wasm_crypto = @import("wasm_crypto.zig");

// WASM test suite
test {
    _ = wasm_crypto;
}
