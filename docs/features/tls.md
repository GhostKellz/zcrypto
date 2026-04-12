# TLS/QUIC Feature

TLS-related utilities and QUIC cryptographic helpers for transport protocols.

## Overview

The TLS feature currently provides transport-oriented support code, including:

- TLS handshake and record-layer building blocks
- QUIC initial secrets derivation
- X.509 parsing helpers and configuration types
- Client and server support code used by the current examples/tests

## API Reference

### TLS Client

```zig
const TlsClient = @import("zcrypto").tls.TlsClient;

pub fn connect(host: []const u8, port: u16) !TlsClient {
    var client = TlsClient.init();
    try client.connect(host, port);
    return client;
}
```

### TLS Server

```zig
const TlsServer = @import("zcrypto").tls.TlsServer;

pub fn startServer(cert_path: []const u8, key_path: []const u8) !TlsServer {
    const cert = try std.fs.readFileAlloc(allocator, cert_path);
    const key = try std.fs.readFileAlloc(allocator, key_path);

    var server = TlsServer.init(cert, key);
    try server.listen("0.0.0.0", 443);
    return server;
}
```

### QUIC Crypto

```zig
const quic = @import("zcrypto").quic;

// Derive initial secrets for QUIC connection
const connection_id = [_]u8{0x01, 0x02, 0x03, 0x04};
const secrets = quic.deriveInitialSecrets(&connection_id, true);

// Use in QUIC packet protection
const protected_packet = try quic.protectPacket(
    packet_data,
    &secrets.client_initial_secret,
    packet_number
);
```

### X.509 Certificates

```zig
const x509 = @import("zcrypto").x509;

// Parse certificate
const cert_data = try std.fs.readFileAlloc(allocator, "cert.pem");
const cert = try x509.parseCertificate(cert_data);

// Validate certificate chain
const trusted_certs = try loadTrustedCertificates();
const valid = try x509.validateCertificateChain(cert, trusted_certs);
```

## Configuration

Enable with `tls = true` in build.zig:

```zig
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    .tls = true,
});
```

## Examples

See `src/main.zig`, `src/tls_test.zig`, and the main build targets for current usage examples.

## Dependencies

- Core zcrypto primitives
- Optional: hardware acceleration for performance
