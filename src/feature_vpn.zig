//! zcrypto VPN Feature Module - VPN-specific cryptographic operations
//!
//! Provides VPN and network tunneling cryptographic features when enabled.

const std = @import("std");

// Re-export VPN modules
pub const vpn_crypto = @import("vpn_crypto.zig");
pub const zero_copy = @import("zero_copy.zig");
pub const pool_crypto = @import("pool_crypto.zig");

// VPN test suite
test {
    _ = vpn_crypto;
    _ = zero_copy;
    _ = pool_crypto;
}
