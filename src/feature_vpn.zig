//! zcrypto VPN Feature Module - VPN-specific cryptographic operations
//!
//! Provides VPN and network tunneling cryptographic features when enabled.
//!
//! # Peers are NOT authenticated
//!
//! `vpn_crypto` is an AEAD record layer, not a VPN protocol: there is no
//! handshake, no peer authentication, and no rekey negotiation.
//! `VpnTunnel.establishTunnel` performs a raw X25519 exchange, which agrees a
//! key with *whoever* is on the other end and says nothing about *who* that is.
//! An active attacker who can substitute public keys machine-in-the-middles the
//! tunnel completely. Authenticating the peer's static public key is the
//! caller's job.
//!
//! Repeated here rather than left in `vpn_crypto.zig` alone because this is the
//! file a consumer reaches first — the feature is exposed as
//! `zcrypto.vpn_crypto`, which is this module, and a reader who stops at its
//! doc comment would otherwise see only a description of what is provided.
//! See `src/vpn_crypto.zig` for the full contract, including the session
//! freshness the caller must supply.

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
