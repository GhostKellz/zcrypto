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

// Re-export main functions for convenience
pub const deriveInitialSecrets = tls.deriveInitialSecrets;
pub const Secrets = tls.Secrets;
pub const ConnectionId = tls.ConnectionId;
pub const KeySchedule = tls.KeySchedule;

// TLS-specific test suite
test {
    _ = tls;
    _ = quic_crypto;
    _ = config;
    _ = client;
    _ = server;
    _ = record;
}
