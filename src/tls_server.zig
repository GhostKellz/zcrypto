//! TLS Server Implementation
//!
//! Provides a high-level TLS server API for accepting secure connections
//! using TLS 1.3 with optional TLS 1.2 support.

const std = @import("std");
const tls = @import("tls.zig");
const tls_config = @import("tls_config.zig");
const tls_client = @import("tls_client.zig");
const hash = @import("hash.zig");
const rand = @import("rand.zig");
const sym = @import("sym.zig");
const kdf = @import("kdf.zig");
const util = @import("util.zig");
const asym = @import("asym.zig");
const security = @import("security.zig");
const net = std.Io.net;

/// TLS server listener
pub const TlsServer = struct {
    /// Configuration
    config: tls_config.TlsConfig,
    /// Underlying network listener
    listener: net.Server,
    /// Io runtime
    io_runtime: std.Io.Threaded,
    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize a new TLS server
    pub fn listen(allocator: std.mem.Allocator, address: []const u8, port: u16, config: tls_config.TlsConfig) !TlsServer {
        try config.validate();

        // Ensure server has certificates
        if (config.certificates == null or config.private_key == null) {
            return error.MissingServerCertificate;
        }

        var io_runtime = std.Io.Threaded.init(allocator, .{ .environ = .empty });
        const io = io_runtime.io();

        const addr = try net.IpAddress.parse(address, port);
        const listener = try addr.listen(io, .{
            .reuse_address = true,
        });

        return TlsServer{
            .config = config,
            .listener = listener,
            .io_runtime = io_runtime,
            .allocator = allocator,
        };
    }

    /// Accept a new TLS connection
    pub fn accept(self: *TlsServer) !TlsConnection {
        const io = self.io_runtime.io();
        const stream = try self.listener.accept(io);

        var tls_conn = TlsConnection{
            .config = self.config,
            .stream = stream,
            .io = io,
            .is_server = true,
            .handshake_state = .initial,
            .transcript = hash.Sha256.init(),
            .client_random = undefined,
            .server_random = undefined,
            .allocator = self.allocator,
        };

        // Perform handshake
        try tls_conn.handshake();

        return tls_conn;
    }

    /// Close the server
    pub fn close(self: *TlsServer) void {
        const io = self.io_runtime.io();
        self.listener.deinit(io);
        self.io_runtime.deinit();
    }

    /// Get the server's address
    pub fn getAddress(self: TlsServer) !net.IpAddress {
        return self.listener.local_address;
    }
};

/// TLS connection (used by both client and server)
pub const TlsConnection = struct {
    /// Configuration
    config: tls_config.TlsConfig,
    /// Underlying network stream
    stream: net.Stream,
    /// Io runtime
    io: std.Io,
    /// Is this the server side?
    is_server: bool,
    /// Current handshake state
    handshake_state: HandshakeState = .initial,
    /// Handshake transcript hash
    transcript: hash.Sha256,
    /// Random values
    client_random: [32]u8,
    server_random: [32]u8,
    /// Selected cipher suite
    cipher_suite: ?tls_config.CipherSuite = null,
    /// Selected ALPN protocol
    selected_alpn: ?[]const u8 = null,
    /// Client's server name indication
    client_sni: ?[]const u8 = null,
    /// Key exchange state
    server_key_share: ?asym.Curve25519KeyPair = null,
    client_public_key: ?[32]u8 = null,
    shared_secret: ?[32]u8 = null,
    /// Traffic secrets
    client_handshake_secret: ?[32]u8 = null,
    server_handshake_secret: ?[32]u8 = null,
    client_traffic_secret: ?[32]u8 = null,
    server_traffic_secret: ?[32]u8 = null,
    /// Traffic keys
    client_handshake_keys: ?TrafficKeys = null,
    server_handshake_keys: ?TrafficKeys = null,
    client_traffic_keys: ?TrafficKeys = null,
    server_traffic_keys: ?TrafficKeys = null,
    /// Session resumption
    session_ticket: ?[]u8 = null,
    /// Allocator
    allocator: std.mem.Allocator,

    /// Handshake states
    pub const HandshakeState = enum {
        initial,
        received_client_hello,
        sent_server_hello,
        sent_encrypted_extensions,
        sent_certificate_request,
        sent_certificate,
        sent_certificate_verify,
        sent_finished,
        received_finished,
        connected,
        closed,
        tls_error,
    };

    /// Traffic keys for encryption/decryption
    pub const TrafficKeys = struct {
        key: []u8,
        iv: []u8,
        sequence: u64 = 0,

        pub fn deinit(self: TrafficKeys, allocator: std.mem.Allocator) void {
            util.secureZero(self.key);
            util.secureZero(self.iv);
            allocator.free(self.key);
            allocator.free(self.iv);
        }
    };

    /// Perform TLS handshake (server side)
    pub fn handshake(self: *TlsConnection) !void {
        if (!self.is_server) {
            return error.NotServerConnection;
        }

        // Receive ClientHello
        try self.receiveClientHello();
        self.handshake_state = .received_client_hello;

        // Generate server random
        rand.fill(&self.server_random);

        // Send ServerHello
        try self.sendServerHello();
        self.handshake_state = .sent_server_hello;

        // Derive handshake secrets
        try self.deriveHandshakeSecrets();

        // Send EncryptedExtensions
        try self.sendEncryptedExtensions();
        self.handshake_state = .sent_encrypted_extensions;

        // Send Certificate (if not PSK)
        try self.sendCertificate();
        self.handshake_state = .sent_certificate;

        // Send CertificateVerify
        try self.sendCertificateVerify();
        self.handshake_state = .sent_certificate_verify;

        // Send Finished
        try self.sendFinished();
        self.handshake_state = .sent_finished;

        // Receive client Finished
        try self.receiveFinished();
        self.handshake_state = .received_finished;

        // Derive application traffic secrets
        try self.deriveApplicationSecrets();

        self.handshake_state = .connected;

        // Optionally send NewSessionTicket
        if (self.config.enable_session_tickets) {
            try self.sendNewSessionTicket();
        }
    }

    /// Write data to the connection
    pub fn write(self: *TlsConnection, data: []const u8) !usize {
        if (self.handshake_state != .connected) {
            return error.NotConnected;
        }

        // Fragment data if necessary
        var offset: usize = 0;
        while (offset < data.len) {
            const chunk_size = @min(data.len - offset, self.config.max_fragment_size);
            try self.writeRecord(.application_data, data[offset .. offset + chunk_size]);
            offset += chunk_size;
        }

        return data.len;
    }

    /// Read data from the connection
    pub fn read(self: *TlsConnection, buffer: []u8) !usize {
        if (self.handshake_state != .connected) {
            return error.NotConnected;
        }

        // Read and decrypt a record
        const record = try self.readRecord();
        defer self.allocator.free(record.data);

        switch (record.record_type) {
            .application_data => {
                const copy_len = @min(buffer.len, record.data.len);
                @memcpy(buffer[0..copy_len], record.data[0..copy_len]);
                return copy_len;
            },
            .alert => {
                // Handle alert
                if (record.data.len >= 2) {
                    const level = @as(tls_client.AlertLevel, @enumFromInt(record.data[0]));
                    const desc = @as(tls_client.AlertDescription, @enumFromInt(record.data[1]));

                    if (desc == .close_notify) {
                        self.handshake_state = .closed;
                        return 0; // EOF
                    }

                    if (level == .fatal) {
                        return error.FatalAlert;
                    }
                }
                // Continue reading for non-fatal alerts
                return self.read(buffer);
            },
            else => return error.UnexpectedRecord,
        }
    }

    /// Close the connection
    pub fn close(self: *TlsConnection) !void {
        if (self.handshake_state == .connected) {
            // Send close_notify alert
            const alert = [_]u8{ @intFromEnum(tls_client.AlertLevel.warning), @intFromEnum(tls_client.AlertDescription.close_notify) };
            try self.writeRecord(.alert, &alert);
        }

        self.handshake_state = .closed;
        self.stream.close();
    }

    /// Get the negotiated ALPN protocol
    pub fn getALPN(self: TlsConnection) ?[]const u8 {
        return self.selected_alpn;
    }

    /// Get the client's SNI hostname
    pub fn getServerName(self: TlsConnection) ?[]const u8 {
        return self.client_sni;
    }

    /// Deinitialize and clean up
    pub fn deinit(self: *TlsConnection) void {
        // Clean up key exchange material
        if (self.server_key_share) |*keypair| {
            util.secureZero(&keypair.private_key);
        }
        if (self.client_public_key) |*key| util.secureZero(key);
        if (self.shared_secret) |*secret| util.secureZero(secret);

        // Clean up secrets
        if (self.client_handshake_secret) |*secret| util.secureZero(secret);
        if (self.server_handshake_secret) |*secret| util.secureZero(secret);
        if (self.client_traffic_secret) |*secret| util.secureZero(secret);
        if (self.server_traffic_secret) |*secret| util.secureZero(secret);

        // Clean up keys
        if (self.client_handshake_keys) |keys| keys.deinit(self.allocator);
        if (self.server_handshake_keys) |keys| keys.deinit(self.allocator);
        if (self.client_traffic_keys) |keys| keys.deinit(self.allocator);
        if (self.server_traffic_keys) |keys| keys.deinit(self.allocator);

        // Clean up strings
        if (self.selected_alpn) |alpn| self.allocator.free(alpn);
        if (self.client_sni) |sni| self.allocator.free(sni);
        if (self.session_ticket) |ticket| self.allocator.free(ticket);
    }

    // Private helper methods

    fn receiveClientHello(self: *TlsConnection) !void {
        const msg = try self.readHandshakeMessage();
        defer self.allocator.free(msg.data);

        if (msg.msg_type != .client_hello) {
            return error.ExpectedClientHello;
        }

        // Parse ClientHello using manual buffer position tracking
        var pos: usize = 0;

        // Legacy version (2 bytes)
        if (pos + 2 > msg.data.len) return error.TruncatedMessage;
        _ = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
        pos += 2;

        // Client random (32 bytes)
        if (pos + 32 > msg.data.len) return error.TruncatedMessage;
        @memcpy(&self.client_random, msg.data[pos..][0..32]);
        pos += 32;

        // Session ID
        if (pos + 1 > msg.data.len) return error.TruncatedMessage;
        const session_id_len = msg.data[pos];
        pos += 1;
        if (session_id_len > 0) {
            if (pos + session_id_len > msg.data.len) return error.TruncatedMessage;
            pos += session_id_len;
        }

        // Cipher suites
        if (pos + 2 > msg.data.len) return error.TruncatedMessage;
        const cipher_suites_len = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
        pos += 2;
        const num_suites = cipher_suites_len / 2;

        // Select a cipher suite
        var selected = false;
        var i: usize = 0;
        while (i < num_suites) : (i += 1) {
            if (pos + 2 > msg.data.len) return error.TruncatedMessage;
            const suite_value = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
            pos += 2;
            const suite: tls_config.CipherSuite = switch (suite_value) {
                0x1301 => .TLS_AES_128_GCM_SHA256,
                0x1302 => .TLS_AES_256_GCM_SHA384,
                0x1303 => .TLS_CHACHA20_POLY1305_SHA256,
                else => continue,
            };

            // Check if this suite is in our configured list
            for (self.config.cipher_suites) |configured_suite| {
                if (suite == configured_suite) {
                    self.cipher_suite = suite;
                    selected = true;
                    break;
                }
            }

            if (selected) break;
        }

        if (!selected) {
            return error.NoCipherSuiteMatch;
        }

        // Skip remaining cipher suites
        if (i < num_suites - 1) {
            const skip_len = (num_suites - i - 1) * 2;
            if (pos + skip_len > msg.data.len) return error.TruncatedMessage;
            pos += skip_len;
        }

        // Compression methods
        if (pos + 1 > msg.data.len) return error.TruncatedMessage;
        const compression_len = msg.data[pos];
        pos += 1;
        if (compression_len > 0) {
            if (pos + compression_len > msg.data.len) return error.TruncatedMessage;
            pos += compression_len;
        }

        // Parse extensions
        if (pos + 2 > msg.data.len) return error.TruncatedMessage;
        const extensions_len = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
        pos += 2;
        const extensions_start = pos;

        while (pos < extensions_start + extensions_len) {
            if (pos + 4 > msg.data.len) return error.TruncatedMessage;
            const ext_type = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
            pos += 2;
            const ext_len = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
            pos += 2;

            if (pos + ext_len > msg.data.len) return error.TruncatedMessage;
            const ext_data = msg.data[pos .. pos + ext_len];

            const ext_type_enum: ?tls_client.ExtensionType = switch (ext_type) {
                0 => .server_name,
                10 => .supported_groups,
                13 => .signature_algorithms,
                16 => .application_layer_protocol_negotiation,
                41 => .pre_shared_key,
                42 => .early_data,
                43 => .supported_versions,
                44 => .cookie,
                45 => .psk_key_exchange_modes,
                47 => .certificate_authorities,
                51 => .key_share,
                else => null,
            };
            if (ext_type_enum) |ext| {
                switch (ext) {
                    .server_name => {
                        // Parse SNI
                        if (ext_data.len >= 5) {
                            const list_len = std.mem.readInt(u16, ext_data[0..2], .big);
                            if (list_len > 0 and ext_data[2] == 0) { // hostname type
                                const name_len = std.mem.readInt(u16, ext_data[3..5], .big);
                                if (5 + name_len <= ext_data.len) {
                                    self.client_sni = try self.allocator.dupe(u8, ext_data[5 .. 5 + name_len]);
                                }
                            }
                        }
                    },
                    .application_layer_protocol_negotiation => {
                        // Parse ALPN
                        if (self.config.alpn_protocols) |server_protocols| {
                            if (ext_data.len >= 2) {
                                const list_len = std.mem.readInt(u16, ext_data[0..2], .big);
                                var offset: usize = 2;

                                while (offset < 2 + list_len and offset < ext_data.len) {
                                    const proto_len = ext_data[offset];
                                    offset += 1;

                                    if (offset + proto_len <= ext_data.len) {
                                        const client_proto = ext_data[offset .. offset + proto_len];

                                        // Check against server's protocols
                                        for (server_protocols) |server_proto| {
                                            if (std.mem.eql(u8, client_proto, server_proto)) {
                                                self.selected_alpn = try self.allocator.dupe(u8, server_proto);
                                                break;
                                            }
                                        }

                                        offset += proto_len;
                                    }

                                    if (self.selected_alpn != null) break;
                                }
                            }
                        }
                    },
                    .key_share => {
                        // Parse client's key share
                        if (ext_data.len >= 2) {
                            const shares_len = std.mem.readInt(u16, ext_data[0..2], .big);
                            var offset: usize = 2;

                            while (offset < 2 + shares_len and offset + 4 <= ext_data.len) {
                                const group = std.mem.readInt(u16, ext_data[offset..][0..2], .big);
                                const key_len = std.mem.readInt(u16, ext_data[offset + 2 ..][0..2], .big);

                                if (group == 0x001d and key_len == 32 and offset + 4 + key_len <= ext_data.len) {
                                    // X25519 key share
                                    self.client_public_key = [_]u8{0} ** 32;
                                    @memcpy(&self.client_public_key.?, ext_data[offset + 4 .. offset + 4 + key_len]);
                                    break; // Use first X25519 key share
                                }

                                offset += 4 + key_len;
                            }
                        }
                    },
                    // Unhandled extensions - ignore them
                    .supported_groups, .signature_algorithms, .pre_shared_key, .early_data, .supported_versions, .cookie, .psk_key_exchange_modes, .certificate_authorities => {},
                }
            }

            pos += ext_len;
        }

        // Update transcript
        self.transcript.update(msg.data);
    }

    // Private helper methods for writing to ArrayList buffers
    fn writeU8(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, val: u8) !void {
        try buffer.append(allocator, val);
    }

    fn writeU16(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, val: u16) !void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, val, .big);
        try buffer.appendSlice(allocator, &bytes);
    }

    fn writeU24(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, val: u24) !void {
        var bytes: [3]u8 = undefined;
        std.mem.writeInt(u24, &bytes, val, .big);
        try buffer.appendSlice(allocator, &bytes);
    }

    fn writeU32(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, val: u32) !void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, val, .big);
        try buffer.appendSlice(allocator, &bytes);
    }

    fn writeBytes(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
        try buffer.appendSlice(allocator, bytes);
    }

    fn sendServerHello(self: *TlsConnection) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Generate server key share for X25519
        self.server_key_share = asym.x25519.generate();

        // TLS version (legacy)
        try writeU16(&buffer, self.allocator, 0x0303);

        // Server random
        try writeBytes(&buffer, self.allocator, &self.server_random);

        // Session ID (echo client's or generate new)
        try writeU8(&buffer, self.allocator, 32);
        const session_id = rand.randomArray(32);
        try writeBytes(&buffer, self.allocator, &session_id);

        // Selected cipher suite
        try writeU16(&buffer, self.allocator, @intFromEnum(self.cipher_suite.?));

        // Compression method (null)
        try writeU8(&buffer, self.allocator, 0);

        // Extensions
        var extensions: std.ArrayList(u8) = .empty;
        defer extensions.deinit(self.allocator);

        // Supported versions (TLS 1.3)
        try writeU16(&extensions, self.allocator, @intFromEnum(tls_client.ExtensionType.supported_versions));
        try writeU16(&extensions, self.allocator, 2);
        try writeU16(&extensions, self.allocator, 0x0304);

        // Key share
        try self.writeServerKeyShare(&extensions);

        // Write extensions
        try writeU16(&buffer, self.allocator, @intCast(extensions.items.len));
        try writeBytes(&buffer, self.allocator, extensions.items);

        // Update transcript
        self.transcript.update(buffer.items);

        // Send handshake message
        try self.writeHandshakeMessage(.server_hello, buffer.items);
    }

    fn sendEncryptedExtensions(self: *TlsConnection) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Extensions length (populated below)
        const len_pos = buffer.items.len;
        try writeU16(&buffer, self.allocator, 0);

        // ALPN extension if negotiated
        if (self.selected_alpn) |alpn| {
            try writeU16(&buffer, self.allocator, @intFromEnum(tls_client.ExtensionType.application_layer_protocol_negotiation));
            try writeU16(&buffer, self.allocator, @intCast(alpn.len + 3));
            try writeU16(&buffer, self.allocator, @intCast(alpn.len + 1));
            try writeU8(&buffer, self.allocator, @intCast(alpn.len));
            try writeBytes(&buffer, self.allocator, alpn);
        }

        // Update extensions length
        const ext_len = buffer.items.len - len_pos - 2;
        std.mem.writeInt(u16, buffer.items[len_pos..][0..2], @intCast(ext_len), .big);

        // Update transcript and send
        self.transcript.update(buffer.items);
        try self.writeHandshakeMessage(.encrypted_extensions, buffer.items);
    }

    fn sendCertificate(self: *TlsConnection) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Certificate request context (empty for server certificates)
        try writeU8(&buffer, self.allocator, 0);

        // Certificate list length (populated below)
        const list_len_pos = buffer.items.len;
        try writeU24(&buffer, self.allocator, 0);

        var total_len: usize = 0;

        // Write certificates
        if (self.config.certificates) |certs| {
            for (certs) |cert| {
                // Certificate data length
                try writeU24(&buffer, self.allocator, @intCast(cert.der.len));
                try writeBytes(&buffer, self.allocator, cert.der);
                total_len += 3 + cert.der.len;

                // Certificate extensions (empty for now)
                try writeU16(&buffer, self.allocator, 0);
                total_len += 2;
            }
        }

        // Update certificate list length
        std.mem.writeInt(u24, buffer.items[list_len_pos..][0..3], @intCast(total_len), .big);

        // Update transcript and send
        self.transcript.update(buffer.items);
        try self.writeHandshakeMessage(.certificate, buffer.items);
    }

    /// Send CertificateVerify message to prove server identity (RFC 8446 Section 4.4.3)
    ///
    /// Signs the handshake transcript with the server's private key to prove
    /// possession of the certificate's corresponding private key.
    fn sendCertificateVerify(self: *TlsConnection) !void {
        // Get the private key from config
        const private_key = self.config.private_key orelse return error.MissingPrivateKey;

        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Build the content to be signed (RFC 8446 Section 4.4.3):
        // - 64 bytes of 0x20 (space)
        // - Context string: "TLS 1.3, server CertificateVerify"
        // - Single 0x00 byte
        // - Hash of handshake transcript (up to but not including CertificateVerify)
        const context_string = "TLS 1.3, server CertificateVerify";
        const transcript_hash = self.transcript.finalResult();

        var content: [64 + context_string.len + 1 + 32]u8 = undefined;
        @memset(content[0..64], 0x20); // 64 spaces
        @memcpy(content[64 .. 64 + context_string.len], context_string);
        content[64 + context_string.len] = 0x00;
        @memcpy(content[64 + context_string.len + 1 ..], &transcript_hash);

        // Sign based on key type
        switch (private_key.key_type) {
            .ed25519 => {
                // Signature algorithm (Ed25519 = 0x0807)
                try writeU16(&buffer, self.allocator, 0x0807);

                // Ed25519 private key handling:
                // - If 64 bytes: full secret key (seed + public, as used by Zig's Ed25519)
                // - If 32 bytes: just the seed, need to derive full key
                var secret_key: [64]u8 = undefined;

                if (private_key.der.len == 64) {
                    // Full 64-byte secret key
                    @memcpy(&secret_key, private_key.der[0..64]);
                } else if (private_key.der.len >= 32) {
                    // 32-byte seed - generate full keypair
                    var seed: [32]u8 = undefined;
                    @memcpy(&seed, private_key.der[0..32]);
                    const keypair = asym.ed25519.generateFromSeed(seed);
                    secret_key = keypair.private_key;
                } else {
                    return error.InvalidPrivateKeySize;
                }

                // Create signature using ed25519.sign which takes 64-byte private key
                const signature = try asym.ed25519.sign(&content, secret_key);

                // Signature length (64 bytes for Ed25519)
                try writeU16(&buffer, self.allocator, 64);

                // Signature data
                try writeBytes(&buffer, self.allocator, &signature);
            },
            .ecdsa_p256 => {
                // ECDSA P-256 with SHA-256 (0x0403)
                try writeU16(&buffer, self.allocator, 0x0403);

                // TODO: Implement ECDSA P-256 signing
                std.log.warn("ECDSA P-256 signing not yet fully implemented", .{});

                // For now, use the secp256r1 implementation if available
                if (private_key.der.len >= 32) {
                    const private_bytes: [32]u8 = private_key.der[0..32].*;
                    const ecdsa_keypair = asym.secp256r1.fromPrivateKey(private_bytes);
                    const signature = asym.secp256r1.sign(&content, ecdsa_keypair);

                    // ECDSA signatures are DER-encoded, typically 70-72 bytes
                    try writeU16(&buffer, self.allocator, @intCast(signature.len));
                    try writeBytes(&buffer, self.allocator, &signature);
                } else {
                    return error.InvalidPrivateKeySize;
                }
            },
            .rsa => {
                // RSA-PSS with SHA-256 (0x0804)
                try writeU16(&buffer, self.allocator, 0x0804);

                // TODO: Implement RSA-PSS signing
                std.log.err("RSA-PSS signing not implemented", .{});
                return error.UnsupportedKeyType;
            },
            else => {
                std.log.err("Unsupported private key type for CertificateVerify", .{});
                return error.UnsupportedKeyType;
            },
        }

        // Update transcript and send
        self.transcript.update(buffer.items);
        try self.writeHandshakeMessage(.certificate_verify, buffer.items);
    }

    fn sendFinished(self: *TlsConnection) !void {
        const verify_data = try self.computeFinishedVerifyData(false); // Server finished
        defer self.allocator.free(verify_data);

        // Update transcript with Finished message
        self.transcript.update(verify_data);

        // Send Finished message
        try self.writeHandshakeMessage(.finished, verify_data);
    }

    fn receiveFinished(self: *TlsConnection) !void {
        // Skip any ChangeCipherSpec records (sent for middlebox compatibility in TLS 1.3)
        var msg: HandshakeMessage = undefined;
        while (true) {
            const record = try self.readRecord();
            if (record.record_type == .change_cipher_spec) {
                self.allocator.free(record.data);
                continue;
            }

            // Not ChangeCipherSpec, must be handshake
            if (record.record_type != .handshake) {
                self.allocator.free(record.data);
                return error.ExpectedHandshake;
            }

            const msg_type: tls_client.HandshakeType = switch (record.data[0]) {
                1 => .client_hello,
                2 => .server_hello,
                4 => .new_session_ticket,
                5 => .end_of_early_data,
                8 => .encrypted_extensions,
                11 => .certificate,
                13 => .certificate_request,
                15 => .certificate_verify,
                20 => .finished,
                else => {
                    self.allocator.free(record.data);
                    return error.UnknownHandshakeType;
                },
            };

            const msg_len = std.mem.readInt(u24, record.data[1..4], .big);
            const msg_data = try self.allocator.dupe(u8, record.data[4 .. 4 + msg_len]);
            self.allocator.free(record.data);

            msg = HandshakeMessage{
                .msg_type = msg_type,
                .data = msg_data,
            };
            break;
        }

        defer self.allocator.free(msg.data);

        if (msg.msg_type != .finished) {
            return error.ExpectedFinished;
        }

        // Compute expected verify data
        const expected_verify_data = try self.computeFinishedVerifyData(true); // Client finished
        defer self.allocator.free(expected_verify_data);

        // Verify the Finished message
        if (!util.constantTimeEqual(msg.data, expected_verify_data)) {
            return error.InvalidFinished;
        }

        // Update transcript
        self.transcript.update(msg.data);
    }

    fn sendNewSessionTicket(self: *TlsConnection) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Ticket lifetime (7 days in seconds)
        try writeU32(&buffer, self.allocator, 604800);

        // Ticket age add
        const age_add = rand.randomU32();
        try writeU32(&buffer, self.allocator, age_add);

        // Ticket nonce
        const nonce = rand.randomArray(8);
        try writeU8(&buffer, self.allocator, @intCast(nonce.len));
        try writeBytes(&buffer, self.allocator, &nonce);

        // Ticket
        const ticket = try self.generateSessionTicket();
        defer self.allocator.free(ticket);
        try writeU16(&buffer, self.allocator, @intCast(ticket.len));
        try writeBytes(&buffer, self.allocator, ticket);

        // Extensions
        try writeU16(&buffer, self.allocator, 0);

        try self.writeHandshakeMessage(.new_session_ticket, buffer.items);
    }

    /// Generate an encrypted session ticket (RFC 8446 Section 4.6.1)
    ///
    /// Ticket format (encrypted):
    /// - version (2 bytes): ticket format version
    /// - cipher_suite (2 bytes): negotiated cipher suite
    /// - resumption_secret (32-48 bytes): for PSK derivation
    /// - timestamp (8 bytes): creation time
    ///
    /// The entire ticket is encrypted with AES-256-GCM using a server-only key.
    fn generateSessionTicket(self: *TlsConnection) ![]u8 {
        const cipher_suite = self.cipher_suite orelse return error.NoCipherSuite;
        _ = cipher_suite.hashAlgorithm(); // Validate cipher suite has valid hash

        // Build plaintext ticket content
        var plaintext_buf: [128]u8 = undefined;
        var pos: usize = 0;

        // Version
        std.mem.writeInt(u16, plaintext_buf[pos..][0..2], 0x0001, .big);
        pos += 2;

        // Cipher suite
        std.mem.writeInt(u16, plaintext_buf[pos..][0..2], @intFromEnum(cipher_suite), .big);
        pos += 2;

        // Resumption secret (use server traffic secret as base for now)
        // In full implementation, this would be derived per RFC 8446 Section 7.5
        const resumption_secret = self.server_traffic_secret orelse return error.NoTrafficSecret;
        @memcpy(plaintext_buf[pos .. pos + 32], &resumption_secret);
        pos += 32;

        // Timestamp (seconds since epoch)
        var ts: std.posix.timespec = undefined;
        const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
        const timestamp: u64 = if (std.posix.errno(rc) == .SUCCESS) @intCast(ts.sec) else 0;
        std.mem.writeInt(u64, plaintext_buf[pos..][0..8], timestamp, .big);
        pos += 8;

        const plaintext = plaintext_buf[0..pos];

        // Generate ticket encryption key (server-only, should be stored/rotated in production)
        // For now, derive from a combination of server random and a fixed label
        var ticket_key: [32]u8 = undefined;
        var key_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        key_hasher.update(&self.server_random);
        key_hasher.update("zcrypto_ticket_key_v1");
        key_hasher.final(&ticket_key);

        // Generate random nonce
        var nonce: [12]u8 = undefined;
        rand.fill(&nonce);

        // Encrypt with AES-256-GCM
        const ciphertext_len = plaintext.len + 16; // +16 for auth tag
        const ticket = try self.allocator.alloc(u8, 12 + ciphertext_len); // nonce + ciphertext + tag

        // Store nonce at beginning of ticket
        @memcpy(ticket[0..12], &nonce);

        // Encrypt
        var tag: [16]u8 = undefined;
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
            ticket[12 .. 12 + plaintext.len],
            &tag,
            plaintext,
            &[_]u8{}, // No AAD
            nonce,
            ticket_key,
        );
        @memcpy(ticket[12 + plaintext.len ..], &tag);

        // Clear sensitive data
        util.secureZero(&ticket_key);

        return ticket;
    }

    /// Decrypt and validate a session ticket for resumption
    fn decryptSessionTicket(self: *TlsConnection, ticket: []const u8) !?SessionTicketData {
        if (ticket.len < 12 + 16 + 4) { // nonce + tag + min content
            return null;
        }

        // Extract nonce
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, ticket[0..12]);

        // Derive ticket key
        var ticket_key: [32]u8 = undefined;
        var key_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        key_hasher.update(&self.server_random);
        key_hasher.update("zcrypto_ticket_key_v1");
        key_hasher.final(&ticket_key);
        defer util.secureZero(&ticket_key);

        // Decrypt
        const ciphertext = ticket[12 .. ticket.len - 16];
        var tag: [16]u8 = undefined;
        @memcpy(&tag, ticket[ticket.len - 16 ..]);

        var plaintext = try self.allocator.alloc(u8, ciphertext.len);
        errdefer self.allocator.free(plaintext);

        std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
            plaintext,
            ciphertext,
            tag,
            &[_]u8{},
            nonce,
            ticket_key,
        ) catch {
            self.allocator.free(plaintext);
            return null; // Ticket tampering or wrong key
        };
        defer self.allocator.free(plaintext);

        // Parse ticket content
        if (plaintext.len < 44) return null; // version(2) + suite(2) + secret(32) + timestamp(8)

        const version = std.mem.readInt(u16, plaintext[0..2], .big);
        if (version != 0x0001) return null;

        const suite_int = std.mem.readInt(u16, plaintext[2..4], .big);
        const cipher_suite = std.meta.intToEnum(tls_config.CipherSuite, suite_int) catch return null;

        var resumption_secret: [32]u8 = undefined;
        @memcpy(&resumption_secret, plaintext[4..36]);

        const timestamp = std.mem.readInt(u64, plaintext[36..44], .big);

        // Check ticket age (max 7 days)
        var ts: std.posix.timespec = undefined;
        const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
        if (std.posix.errno(rc) == .SUCCESS) {
            const now: u64 = @intCast(ts.sec);
            if (now > timestamp + 604800) {
                return null; // Ticket expired
            }
        }

        return SessionTicketData{
            .cipher_suite = cipher_suite,
            .resumption_secret = resumption_secret,
            .timestamp = timestamp,
        };
    }

    const SessionTicketData = struct {
        cipher_suite: tls_config.CipherSuite,
        resumption_secret: [32]u8,
        timestamp: u64,
    };

    fn deriveHandshakeSecrets(self: *TlsConnection) !void {
        // Perform ECDHE key exchange
        if (self.server_key_share == null or self.client_public_key == null) {
            return error.MissingKeyExchange;
        }

        // Compute shared secret
        self.shared_secret = try asym.x25519.dh(self.server_key_share.?.private_key, self.client_public_key.?);

        // Initialize key schedule with the cipher suite's hash algorithm
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        var key_schedule = try tls.KeySchedule.init(self.allocator, hash_alg);
        defer key_schedule.deinit();

        // Derive early secret (no PSK)
        try key_schedule.deriveEarlySecret(null);

        // Derive handshake secret using ECDHE shared secret
        try key_schedule.deriveHandshakeSecret(&self.shared_secret.?);

        // Derive client and server handshake secrets
        const transcript_data = try self.getTranscriptHash();
        defer self.allocator.free(transcript_data);

        const client_hs_secret = try key_schedule.deriveSecret(key_schedule.handshake_secret, "c hs traffic", transcript_data);
        defer self.allocator.free(client_hs_secret);

        const server_hs_secret = try key_schedule.deriveSecret(key_schedule.handshake_secret, "s hs traffic", transcript_data);
        defer self.allocator.free(server_hs_secret);

        // Copy secrets (truncate to 32 bytes for now)
        self.client_handshake_secret = [_]u8{0} ** 32;
        self.server_handshake_secret = [_]u8{0} ** 32;
        @memcpy(&self.client_handshake_secret.?, client_hs_secret[0..32]);
        @memcpy(&self.server_handshake_secret.?, server_hs_secret[0..32]);

        self.client_handshake_keys = try self.deriveTrafficKeys(self.client_handshake_secret.?, true);
        self.server_handshake_keys = try self.deriveTrafficKeys(self.server_handshake_secret.?, false);
    }

    fn deriveApplicationSecrets(self: *TlsConnection) !void {
        // Initialize key schedule
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        var key_schedule = try tls.KeySchedule.init(self.allocator, hash_alg);
        defer key_schedule.deinit();

        // Reconstruct the key schedule
        try key_schedule.deriveEarlySecret(null);
        try key_schedule.deriveHandshakeSecret(&self.shared_secret.?);
        try key_schedule.deriveMasterSecret();

        // Get current transcript hash
        const transcript_data = try self.getTranscriptHash();
        defer self.allocator.free(transcript_data);

        // Derive application traffic secrets
        const client_app_secret = try key_schedule.deriveSecret(key_schedule.master_secret, "c ap traffic", transcript_data);
        defer self.allocator.free(client_app_secret);

        const server_app_secret = try key_schedule.deriveSecret(key_schedule.master_secret, "s ap traffic", transcript_data);
        defer self.allocator.free(server_app_secret);

        // Copy secrets (truncate to 32 bytes for now)
        self.client_traffic_secret = [_]u8{0} ** 32;
        self.server_traffic_secret = [_]u8{0} ** 32;
        @memcpy(&self.client_traffic_secret.?, client_app_secret[0..32]);
        @memcpy(&self.server_traffic_secret.?, server_app_secret[0..32]);

        self.client_traffic_keys = try self.deriveTrafficKeys(self.client_traffic_secret.?, true);
        self.server_traffic_keys = try self.deriveTrafficKeys(self.server_traffic_secret.?, false);
    }

    fn deriveTrafficKeys(self: *TlsConnection, secret: [32]u8, is_client: bool) !TrafficKeys {
        _ = is_client;
        const key_size = self.cipher_suite.?.keySize();

        const key = try kdf.hkdfExpandLabel(self.allocator, &secret, "key", "", key_size);
        const iv = try kdf.hkdfExpandLabel(self.allocator, &secret, "iv", "", 12);

        return TrafficKeys{
            .key = key,
            .iv = iv,
        };
    }

    fn getTranscriptHash(self: *TlsConnection) ![]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        const hash_len = hash_alg.digestSize();

        var transcript_copy = self.transcript;
        const result = try self.allocator.alloc(u8, hash_len);

        switch (hash_alg) {
            .sha256 => {
                const final_hash = transcript_copy.final();
                @memcpy(result[0..32], &final_hash);
            },
            .sha384 => {
                // Use SHA384 transcript hash
                var sha384_hasher = std.crypto.hash.sha2.Sha384.init(.{});
                const sha256_result = transcript_copy.finalResult();
                sha384_hasher.update(&sha256_result);
                var sha384_result: [48]u8 = undefined;
                sha384_hasher.final(&sha384_result);
                @memcpy(result[0..48], &sha384_result);
            },
            .sha512 => {
                // Use SHA512 transcript hash
                var sha512_hasher = hash.Sha512.init();
                const sha256_result = transcript_copy.finalResult();
                sha512_hasher.update(&sha256_result);
                const sha512_result = sha512_hasher.final();
                @memcpy(result[0..64], &sha512_result);
            },
        }

        return result;
    }

    fn computeFinishedVerifyData(self: *TlsConnection, is_client: bool) ![]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        const hash_len = hash_alg.digestSize();

        // Get current transcript hash
        const transcript_hash = try self.getTranscriptHash();
        defer self.allocator.free(transcript_hash);

        // Use appropriate handshake secret
        const secret = if (is_client)
            self.client_handshake_secret.?
        else
            self.server_handshake_secret.?;

        // Compute finished key using HKDF-Expand-Label
        const finished_key = try kdf.hkdfExpandLabel(self.allocator, &secret, "finished", "", hash_len);
        defer self.allocator.free(finished_key);

        // Compute HMAC of transcript hash
        const verify_data = try self.allocator.alloc(u8, hash_len);

        switch (hash_alg) {
            .sha256 => {
                const key_array: [32]u8 = finished_key[0..32].*;
                var hmac_result: [32]u8 = undefined;
                std.crypto.auth.hmac.sha2.HmacSha256.create(&hmac_result, transcript_hash, &key_array);
                @memcpy(verify_data, &hmac_result);
            },
            .sha384 => {
                // Use HMAC-SHA384 for TLS_AES_256_GCM_SHA384
                const key_array: [48]u8 = finished_key[0..48].*;
                var hmac_result: [48]u8 = undefined;
                std.crypto.auth.hmac.sha2.HmacSha384.create(&hmac_result, transcript_hash, &key_array);
                @memcpy(verify_data, &hmac_result);
            },
            .sha512 => {
                // Use HMAC-SHA512
                const key_array: [64]u8 = finished_key[0..64].*;
                var hmac_result: [64]u8 = undefined;
                std.crypto.auth.hmac.sha2.HmacSha512.create(&hmac_result, transcript_hash, &key_array);
                @memcpy(verify_data, &hmac_result);
            },
        }

        return verify_data;
    }

    fn writeServerKeyShare(self: *TlsConnection, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @intFromEnum(tls_client.ExtensionType.key_share));
        try writeU16(buffer, self.allocator, 36);
        try writeU16(buffer, self.allocator, 0x001d); // x25519
        try writeU16(buffer, self.allocator, 32);

        // Use real public key from generated key share
        if (self.server_key_share) |keypair| {
            try writeBytes(buffer, self.allocator, &keypair.public_key);
        } else {
            return error.NoServerKeyShare;
        }
    }

    // Record layer helpers with TLS 1.3 encryption support
    const Record = struct {
        record_type: tls_client.RecordType,
        data: []u8,
    };

    const HandshakeMessage = struct {
        msg_type: tls_client.HandshakeType,
        data: []u8,
    };

    /// Write a TLS record, encrypting if traffic keys are available
    fn writeRecord(self: *TlsConnection, record_type: tls_client.RecordType, data: []const u8) !void {
        // Check if we should encrypt (have server traffic keys)
        if (self.server_traffic_keys) |*keys| {
            try self.writeEncryptedRecord(record_type, data, keys);
        } else if (self.server_handshake_keys) |*keys| {
            try self.writeEncryptedRecord(record_type, data, keys);
        } else {
            try self.writePlaintextRecord(record_type, data);
        }
    }

    /// Write a plaintext TLS record
    fn writePlaintextRecord(self: *TlsConnection, record_type: tls_client.RecordType, data: []const u8) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        try writeU8(&buffer, self.allocator, @intFromEnum(record_type));
        try writeU16(&buffer, self.allocator, 0x0303);
        try writeU16(&buffer, self.allocator, @intCast(data.len));
        try writeBytes(&buffer, self.allocator, data);

        var write_buf: [8192]u8 = undefined;
        var writer = self.stream.writer(self.io, &write_buf);
        var source_reader = std.Io.Reader.fixed(buffer.items);
        _ = try source_reader.stream(&writer.interface, .unlimited);
        try writer.interface.flush();
    }

    /// Write an encrypted TLS 1.3 record (RFC 8446 Section 5.2)
    fn writeEncryptedRecord(self: *TlsConnection, record_type: tls_client.RecordType, data: []const u8, keys: *TrafficKeys) !void {
        const cipher_suite = self.cipher_suite orelse return error.NoCipherSuite;

        // Build inner plaintext: data + content type byte
        const inner_plaintext = try self.allocator.alloc(u8, data.len + 1);
        defer self.allocator.free(inner_plaintext);
        @memcpy(inner_plaintext[0..data.len], data);
        inner_plaintext[data.len] = @intFromEnum(record_type);

        // Construct nonce: XOR IV with sequence number
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, keys.iv[0..12]);
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, keys.sequence, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // AAD is the record header
        const ciphertext_len = inner_plaintext.len + 16;
        var aad: [5]u8 = undefined;
        aad[0] = @intFromEnum(tls_client.RecordType.application_data);
        aad[1] = 0x03;
        aad[2] = 0x03;
        std.mem.writeInt(u16, aad[3..5], @intCast(ciphertext_len), .big);

        // Encrypt
        const ciphertext = try self.allocator.alloc(u8, ciphertext_len);
        defer self.allocator.free(ciphertext);

        switch (cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const key: [16]u8 = keys.key[0..16].*;
                var tag: [16]u8 = undefined;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                    ciphertext[0..inner_plaintext.len],
                    &tag,
                    inner_plaintext,
                    &aad,
                    nonce,
                    key,
                );
                @memcpy(ciphertext[inner_plaintext.len..], &tag);
            },
            .TLS_AES_256_GCM_SHA384 => {
                const key: [32]u8 = keys.key[0..32].*;
                var tag: [16]u8 = undefined;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                    ciphertext[0..inner_plaintext.len],
                    &tag,
                    inner_plaintext,
                    &aad,
                    nonce,
                    key,
                );
                @memcpy(ciphertext[inner_plaintext.len..], &tag);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const key: [32]u8 = keys.key[0..32].*;
                var tag: [16]u8 = undefined;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                    ciphertext[0..inner_plaintext.len],
                    &tag,
                    inner_plaintext,
                    &aad,
                    nonce,
                    key,
                );
                @memcpy(ciphertext[inner_plaintext.len..], &tag);
            },
        }

        keys.sequence += 1;

        // Write record
        var write_buf: [8192]u8 = undefined;
        var writer = self.stream.writer(self.io, &write_buf);
        try writer.interface.writeAll(&aad);
        try writer.interface.writeAll(ciphertext);
        try writer.interface.flush();
    }

    /// Read a TLS record, decrypting if traffic keys are available
    fn readRecord(self: *TlsConnection) !Record {
        var header: [5]u8 = undefined;
        var read_buf: [8192]u8 = undefined;
        var reader = self.stream.reader(self.io, &read_buf);
        var header_writer = std.Io.Writer.fixed(&header);
        try reader.interface.streamExact(&header_writer, header.len);

        const outer_type: tls_client.RecordType = switch (header[0]) {
            20 => .change_cipher_spec,
            21 => .alert,
            22 => .handshake,
            23 => .application_data,
            else => return error.UnknownRecordType,
        };
        const length = std.mem.readInt(u16, header[3..5], .big);

        const record_data = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(record_data);
        var data_writer = std.Io.Writer.fixed(record_data);
        try reader.interface.streamExact(&data_writer, length);

        // Check if we should decrypt
        if (self.client_traffic_keys) |*keys| {
            return self.decryptRecord(&header, record_data, keys);
        } else if (self.client_handshake_keys) |*keys| {
            if (outer_type == .application_data and length > 16) {
                return self.decryptRecord(&header, record_data, keys);
            }
        }

        return Record{
            .record_type = outer_type,
            .data = record_data,
        };
    }

    /// Decrypt a TLS 1.3 record - auth tag verified BEFORE plaintext exposure
    fn decryptRecord(self: *TlsConnection, header: *const [5]u8, ciphertext: []u8, keys: *TrafficKeys) !Record {
        const cipher_suite = self.cipher_suite orelse return error.NoCipherSuite;

        if (ciphertext.len < 17) {
            return error.RecordTooShort;
        }

        const tag_start = ciphertext.len - 16;
        var tag: [16]u8 = undefined;
        @memcpy(&tag, ciphertext[tag_start..]);
        const encrypted_content = ciphertext[0..tag_start];

        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, keys.iv[0..12]);
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, keys.sequence, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= seq_bytes[i];
        }

        const aad = header;
        const plaintext = try self.allocator.alloc(u8, encrypted_content.len);
        errdefer self.allocator.free(plaintext);

        const decrypt_success = switch (cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => blk: {
                const key: [16]u8 = keys.key[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                    plaintext,
                    encrypted_content,
                    tag,
                    aad,
                    nonce,
                    key,
                ) catch break :blk false;
                break :blk true;
            },
            .TLS_AES_256_GCM_SHA384 => blk: {
                const key: [32]u8 = keys.key[0..32].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                    plaintext,
                    encrypted_content,
                    tag,
                    aad,
                    nonce,
                    key,
                ) catch break :blk false;
                break :blk true;
            },
            .TLS_CHACHA20_POLY1305_SHA256 => blk: {
                const key: [32]u8 = keys.key[0..32].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                    plaintext,
                    encrypted_content,
                    tag,
                    aad,
                    nonce,
                    key,
                ) catch break :blk false;
                break :blk true;
            },
        };

        if (!decrypt_success) {
            self.allocator.free(plaintext);
            self.allocator.free(ciphertext);
            return error.DecryptionFailed;
        }

        keys.sequence += 1;
        self.allocator.free(ciphertext);

        // Extract inner content type
        var content_end = plaintext.len;
        while (content_end > 0 and plaintext[content_end - 1] == 0) {
            content_end -= 1;
        }

        if (content_end == 0) {
            self.allocator.free(plaintext);
            return error.InvalidRecord;
        }

        const inner_type: tls_client.RecordType = switch (plaintext[content_end - 1]) {
            20 => .change_cipher_spec,
            21 => .alert,
            22 => .handshake,
            23 => .application_data,
            else => {
                self.allocator.free(plaintext);
                return error.UnknownRecordType;
            },
        };

        const content = try self.allocator.alloc(u8, content_end - 1);
        @memcpy(content, plaintext[0 .. content_end - 1]);
        self.allocator.free(plaintext);

        return Record{
            .record_type = inner_type,
            .data = content,
        };
    }

    fn writeHandshakeMessage(self: *TlsConnection, msg_type: tls_client.HandshakeType, data: []const u8) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        try writeU8(&buffer, self.allocator, @intFromEnum(msg_type));
        try writeU24(&buffer, self.allocator, @intCast(data.len));
        try writeBytes(&buffer, self.allocator, data);

        try self.writeRecord(.handshake, buffer.items);
    }

    fn readHandshakeMessage(self: *TlsConnection) !HandshakeMessage {
        const record = try self.readRecord();
        defer self.allocator.free(record.data);

        if (record.record_type != .handshake) {
            return error.ExpectedHandshake;
        }

        const msg_type: tls_client.HandshakeType = switch (record.data[0]) {
            1 => .client_hello,
            2 => .server_hello,
            4 => .new_session_ticket,
            5 => .end_of_early_data,
            8 => .encrypted_extensions,
            11 => .certificate,
            13 => .certificate_request,
            15 => .certificate_verify,
            20 => .finished,
            24 => .key_update,
            else => return error.UnknownHandshakeType,
        };
        const length = std.mem.readInt(u24, record.data[1..4], .big);

        const data = try self.allocator.alloc(u8, length);
        @memcpy(data, record.data[4 .. 4 + length]);

        return HandshakeMessage{
            .msg_type = msg_type,
            .data = data,
        };
    }
};

test "TLS server initialization" {
    const allocator = std.testing.allocator;

    // Create a dummy certificate - don't call deinit since config takes ownership
    const cert = tls_config.Certificate{
        .der = try allocator.dupe(u8, "dummy cert"),
    };

    const key = tls_config.PrivateKey{
        .key_type = .ed25519,
        .der = try allocator.dupe(u8, "dummy key"),
    };

    const config = tls_config.TlsConfig.init(allocator)
        .withCertificate(cert, key);
    defer config.deinit();

    // Test basic config setup without trying to listen (which validates certificates)
    try std.testing.expect(config.certificates != null);
    try std.testing.expect(config.private_key != null);
    try std.testing.expect(std.mem.eql(u8, config.certificates.?[0].der, "dummy cert"));
}

test "TLS connection helpers" {
    // Test cipher suite selection
    const suite = tls_config.CipherSuite.TLS_AES_128_GCM_SHA256;
    try std.testing.expectEqual(@as(usize, 16), suite.keySize());
    try std.testing.expectEqual(tls_config.HashAlgorithm.sha256, suite.hashAlgorithm());
}
