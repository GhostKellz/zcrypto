//! zcrypto TLS Feature Module - TLS 1.3 and QUIC support
//!
//! Provides TLS 1.3 and QUIC cryptographic operations when enabled.

const std = @import("std");

// Re-export TLS-related modules
pub const tls = @import("tls.zig");
pub const quic_crypto = @import("quic_crypto.zig");
pub const config = @import("tls_config.zig");
pub const client = @import("tls_client.zig");
pub const server = @import("tls_server.zig");
pub const record = @import("tls_record.zig");
/// Crypto performance profiling for a QUIC consumer's BBR congestion control.
/// Lives here rather than under the hardware feature because it is QUIC-facing;
/// it reads `hardware.HardwareAcceleration` as plain capability data, the same
/// way `zero_copy.zig` does from the VPN feature.
pub const bbr = @import("bbr_crypto.zig");

// Re-export main functions for convenience
pub const deriveInitialSecrets = tls.deriveInitialSecrets;
pub const Secrets = tls.Secrets;
pub const ConnectionId = tls.ConnectionId;
pub const KeySchedule = tls.KeySchedule;

/// The Finished MAC, and by RFC 8446 Section 4.2.11.2 the PSK binder too.
pub const verifyData = tls.verifyData;
pub const clientHelloBinderPrefix = tls.clientHelloBinderPrefix;
pub const clientHelloBinderTranscript = tls.clientHelloBinderTranscript;

// TLS-specific test suite
test {
    _ = tls;
    _ = quic_crypto;
    _ = config;
    _ = client;
    _ = server;
    _ = record;
    _ = bbr;
}
