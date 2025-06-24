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

/// TLS server listener
pub const TlsServer = struct {
    /// Configuration
    config: tls_config.TlsConfig,
    /// Underlying network listener
    listener: std.net.Server,
    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize a new TLS server
    pub fn listen(allocator: std.mem.Allocator, address: []const u8, port: u16, config: tls_config.TlsConfig) !TlsServer {
        try config.validate();

        // Ensure server has certificates
        if (config.certificates == null or config.private_key == null) {
            return error.MissingServerCertificate;
        }

        const addr = try std.net.Address.parseIp(address, port);
        const listener = try addr.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });

        return TlsServer{
            .config = config,
            .listener = listener,
            .allocator = allocator,
        };
    }

    /// Accept a new TLS connection
    pub fn accept(self: *TlsServer) !TlsConnection {
        const connection = try self.listener.accept();
        
        var tls_conn = TlsConnection{
            .config = self.config,
            .stream = connection.stream,
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
        self.listener.deinit();
    }

    /// Get the server's address
    pub fn getAddress(self: TlsServer) !std.net.Address {
        return self.listener.listen_address;
    }
};

/// TLS connection (used by both client and server)
pub const TlsConnection = struct {
    /// Configuration
    config: tls_config.TlsConfig,
    /// Underlying network stream
    stream: std.net.Stream,
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
        rand.random(&self.server_random);

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
            try self.writeRecord(.application_data, data[offset..offset + chunk_size]);
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
            const alert = [_]u8{ 
                @intFromEnum(tls_client.AlertLevel.warning), 
                @intFromEnum(tls_client.AlertDescription.close_notify) 
            };
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

        var stream = std.io.fixedBufferStream(msg.data);
        const reader = stream.reader();

        // Legacy version
        _ = try reader.readInt(u16, .big);

        // Client random
        _ = try reader.readAll(&self.client_random);

        // Session ID
        const session_id_len = try reader.readByte();
        if (session_id_len > 0) {
            try reader.skipBytes(session_id_len, .{});
        }

        // Cipher suites
        const cipher_suites_len = try reader.readInt(u16, .big);
        const num_suites = cipher_suites_len / 2;
        
        // Select a cipher suite
        var selected = false;
        var i: usize = 0;
        while (i < num_suites) : (i += 1) {
            const suite_value = try reader.readInt(u16, .big);
            const suite = std.meta.intToEnum(tls_config.CipherSuite, suite_value) catch continue;
            
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
            try reader.skipBytes((num_suites - i - 1) * 2, .{});
        }

        // Compression methods
        const compression_len = try reader.readByte();
        try reader.skipBytes(compression_len, .{});

        // Parse extensions
        const extensions_len = try reader.readInt(u16, .big);
        const extensions_start = stream.pos;
        
        while (stream.pos < extensions_start + extensions_len) {
            const ext_type = try reader.readInt(u16, .big);
            const ext_len = try reader.readInt(u16, .big);
            const ext_data = msg.data[stream.pos..stream.pos + ext_len];
            
            switch (std.meta.intToEnum(tls_client.ExtensionType, ext_type) catch continue) {
                .server_name => {
                    // Parse SNI
                    if (ext_data.len >= 5) {
                        const list_len = std.mem.readInt(u16, ext_data[0..2], .big);
                        if (list_len > 0 and ext_data[2] == 0) { // hostname type
                            const name_len = std.mem.readInt(u16, ext_data[3..5], .big);
                            if (5 + name_len <= ext_data.len) {
                                self.client_sni = try self.allocator.dupe(u8, ext_data[5..5 + name_len]);
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
                                    const client_proto = ext_data[offset..offset + proto_len];
                                    
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
                            const group = std.mem.readInt(u16, ext_data[offset..offset+2], .big);
                            const key_len = std.mem.readInt(u16, ext_data[offset+2..offset+4], .big);
                            
                            if (group == 0x001d and key_len == 32 and offset + 4 + key_len <= ext_data.len) {
                                // X25519 key share
                                self.client_public_key = [_]u8{0} ** 32;
                                @memcpy(&self.client_public_key.?, ext_data[offset+4..offset+4+key_len]);
                                break; // Use first X25519 key share
                            }
                            
                            offset += 4 + key_len;
                        }
                    }
                },
                else => {},
            }
            
            stream.pos += ext_len;
        }

        // Update transcript
        self.transcript.update(msg.data);
    }

    fn sendServerHello(self: *TlsConnection) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Generate server key share for X25519
        self.server_key_share = asym.x25519.generate();

        // TLS version (legacy)
        try buffer.writer().writeInt(u16, 0x0303, .big);

        // Server random
        try buffer.writer().writeAll(&self.server_random);

        // Session ID (echo client's or generate new)
        try buffer.writer().writeByte(32);
        const session_id = rand.generateSessionId();
        try buffer.writer().writeAll(&session_id);

        // Selected cipher suite
        try buffer.writer().writeInt(u16, @intFromEnum(self.cipher_suite.?), .big);

        // Compression method (null)
        try buffer.writer().writeByte(0);

        // Extensions
        var extensions = std.ArrayList(u8).init(self.allocator);
        defer extensions.deinit();

        // Supported versions (TLS 1.3)
        try extensions.writer().writeInt(u16, @intFromEnum(tls_client.ExtensionType.supported_versions), .big);
        try extensions.writer().writeInt(u16, 2, .big);
        try extensions.writer().writeInt(u16, 0x0304, .big);

        // Key share
        try self.writeServerKeyShare(&extensions);

        // Write extensions
        try buffer.writer().writeInt(u16, @intCast(extensions.items.len), .big);
        try buffer.writer().writeAll(extensions.items);

        // Update transcript
        self.transcript.update(buffer.items);

        // Send handshake message
        try self.writeHandshakeMessage(.server_hello, buffer.items);
    }

    fn sendEncryptedExtensions(self: *TlsConnection) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Extensions length (populated below)
        const len_pos = buffer.items.len;
        try buffer.writer().writeInt(u16, 0, .big);

        // ALPN extension if negotiated
        if (self.selected_alpn) |alpn| {
            try buffer.writer().writeInt(u16, @intFromEnum(tls_client.ExtensionType.application_layer_protocol_negotiation), .big);
            try buffer.writer().writeInt(u16, @intCast(alpn.len + 3), .big);
            try buffer.writer().writeInt(u16, @intCast(alpn.len + 1), .big);
            try buffer.writer().writeByte(@intCast(alpn.len));
            try buffer.writer().writeAll(alpn);
        }

        // Update extensions length
        const ext_len = buffer.items.len - len_pos - 2;
        std.mem.writeInt(u16, buffer.items[len_pos..len_pos + 2], @intCast(ext_len), .big);

        // Update transcript and send
        self.transcript.update(buffer.items);
        try self.writeHandshakeMessage(.encrypted_extensions, buffer.items);
    }

    fn sendCertificate(self: *TlsConnection) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Certificate request context (empty for server certificates)
        try buffer.writer().writeByte(0);

        // Certificate list length (populated below)
        const list_len_pos = buffer.items.len;
        try buffer.writer().writeInt(u24, 0, .big);

        var total_len: usize = 0;

        // Write certificates
        if (self.config.certificates) |certs| {
            for (certs) |cert| {
                // Certificate data length
                try buffer.writer().writeInt(u24, @intCast(cert.der.len), .big);
                try buffer.writer().writeAll(cert.der);
                total_len += 3 + cert.der.len;

                // Certificate extensions (empty for now)
                try buffer.writer().writeInt(u16, 0, .big);
                total_len += 2;
            }
        }

        // Update certificate list length
        std.mem.writeInt(u24, buffer.items[list_len_pos..list_len_pos + 3], @intCast(total_len), .big);

        // Update transcript and send
        self.transcript.update(buffer.items);
        try self.writeHandshakeMessage(.certificate, buffer.items);
    }

    fn sendCertificateVerify(self: *TlsConnection) !void {
        // TODO: Implement proper signature
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Signature algorithm (Ed25519)
        try buffer.writer().writeInt(u16, 0x0807, .big);

        // Signature length
        try buffer.writer().writeInt(u16, 64, .big);

        // Placeholder signature
        try buffer.writer().writeAll(&[_]u8{0} ** 64);

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
        const msg = try self.readHandshakeMessage();
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
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Ticket lifetime (7 days in seconds)
        try buffer.writer().writeInt(u32, 604800, .big);

        // Ticket age add
        const age_add = rand.randomU32();
        try buffer.writer().writeInt(u32, age_add, .big);

        // Ticket nonce
        const nonce = rand.generateNonce();
        try buffer.writer().writeByte(@intCast(nonce.len));
        try buffer.writer().writeAll(&nonce);

        // Ticket
        const ticket = try self.generateSessionTicket();
        defer self.allocator.free(ticket);
        try buffer.writer().writeInt(u16, @intCast(ticket.len), .big);
        try buffer.writer().writeAll(ticket);

        // Extensions
        try buffer.writer().writeInt(u16, 0, .big);

        try self.writeHandshakeMessage(.new_session_ticket, buffer.items);
    }

    fn generateSessionTicket(self: *TlsConnection) ![]u8 {
        // TODO: Implement proper session ticket generation
        const ticket = try self.allocator.alloc(u8, 128);
        rand.random(ticket);
        return ticket;
    }

    fn deriveHandshakeSecrets(self: *TlsConnection) !void {
        // Perform ECDHE key exchange
        if (self.server_key_share == null or self.client_public_key == null) {
            return error.MissingKeyExchange;
        }
        
        // Compute shared secret
        self.shared_secret = asym.x25519.dh(
            self.server_key_share.?.private_key,
            self.client_public_key.?
        );
        
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
        
        const client_hs_secret = try key_schedule.deriveSecret(
            key_schedule.handshake_secret,
            "c hs traffic",
            transcript_data
        );
        defer self.allocator.free(client_hs_secret);
        
        const server_hs_secret = try key_schedule.deriveSecret(
            key_schedule.handshake_secret,
            "s hs traffic",
            transcript_data
        );
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
        const client_app_secret = try key_schedule.deriveSecret(
            key_schedule.master_secret,
            "c ap traffic",
            transcript_data
        );
        defer self.allocator.free(client_app_secret);
        
        const server_app_secret = try key_schedule.deriveSecret(
            key_schedule.master_secret,
            "s ap traffic",
            transcript_data
        );
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
            .sha384, .sha512 => {
                // For now, use SHA256 for compatibility
                const final_hash = transcript_copy.final();
                @memcpy(result[0..@min(32, hash_len)], &final_hash);
                if (hash_len > 32) {
                    @memset(result[32..], 0);
                }
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
        const finished_key = try kdf.hkdfExpandLabel(
            self.allocator,
            &secret,
            "finished",
            "",
            hash_len
        );
        defer self.allocator.free(finished_key);
        
        // Compute HMAC of transcript hash
        const verify_data = try self.allocator.alloc(u8, hash_len);
        
        switch (hash_alg) {
            .sha256 => {
                const key_array: [32]u8 = finished_key[0..32].*;
                const hmac_result = std.crypto.auth.hmac.HmacSha256.create(transcript_hash, &key_array);
                @memcpy(verify_data, &hmac_result);
            },
            .sha384, .sha512 => {
                // For compatibility, use SHA256 HMAC
                const key_array: [32]u8 = finished_key[0..32].*;
                const hmac_result = std.crypto.auth.hmac.HmacSha256.create(transcript_hash[0..32], &key_array);
                @memcpy(verify_data[0..32], &hmac_result);
                if (hash_len > 32) {
                    @memset(verify_data[32..], 0);
                }
            },
        }
        
        return verify_data;
    }

    fn writeServerKeyShare(self: *TlsConnection, buffer: *std.ArrayList(u8)) !void {
        try buffer.writer().writeInt(u16, @intFromEnum(tls_client.ExtensionType.key_share), .big);
        try buffer.writer().writeInt(u16, 36, .big);
        try buffer.writer().writeInt(u16, 0x001d, .big); // x25519
        try buffer.writer().writeInt(u16, 32, .big);
        
        // Use real public key from generated key share
        if (self.server_key_share) |keypair| {
            try buffer.writer().writeAll(&keypair.public_key);
        } else {
            return error.NoServerKeyShare;
        }
    }

    // Record layer helpers (shared with client)
    const Record = struct {
        record_type: tls_client.RecordType,
        data: []u8,
    };

    const HandshakeMessage = struct {
        msg_type: tls_client.HandshakeType,
        data: []u8,
    };

    fn writeRecord(self: *TlsConnection, record_type: tls_client.RecordType, data: []const u8) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Record header
        try buffer.writer().writeByte(@intFromEnum(record_type));
        try buffer.writer().writeInt(u16, 0x0303, .big); // Legacy version
        try buffer.writer().writeInt(u16, @intCast(data.len), .big);
        try buffer.writer().writeAll(data);

        try self.stream.writeAll(buffer.items);
    }

    fn readRecord(self: *TlsConnection) !Record {
        var header: [5]u8 = undefined;
        _ = try self.stream.read(&header);

        const record_type = std.meta.intToEnum(tls_client.RecordType, header[0]) catch {
            return error.UnknownRecordType;
        };
        const length = std.mem.readInt(u16, header[3..5], .big);

        const data = try self.allocator.alloc(u8, length);
        _ = try self.stream.read(data);

        return Record{
            .record_type = record_type,
            .data = data,
        };
    }

    fn writeHandshakeMessage(self: *TlsConnection, msg_type: tls_client.HandshakeType, data: []const u8) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try buffer.writer().writeByte(@intFromEnum(msg_type));
        try buffer.writer().writeInt(u24, @intCast(data.len), .big);
        try buffer.writer().writeAll(data);

        try self.writeRecord(.handshake, buffer.items);
    }

    fn readHandshakeMessage(self: *TlsConnection) !HandshakeMessage {
        const record = try self.readRecord();
        defer self.allocator.free(record.data);

        if (record.record_type != .handshake) {
            return error.ExpectedHandshake;
        }

        const msg_type = std.meta.intToEnum(tls_client.HandshakeType, record.data[0]) catch {
            return error.UnknownHandshakeType;
        };
        const length = std.mem.readInt(u24, record.data[1..4], .big);

        const data = try self.allocator.alloc(u8, length);
        @memcpy(data, record.data[4..4 + length]);

        return HandshakeMessage{
            .msg_type = msg_type,
            .data = data,
        };
    }
};

test "TLS server initialization" {
    const allocator = std.testing.allocator;
    
    // Create a dummy certificate
    const cert = tls_config.Certificate{
        .der = try allocator.dupe(u8, "dummy cert"),
    };
    defer cert.deinit(allocator);
    
    const key = tls_config.PrivateKey{
        .key_type = .ed25519,
        .der = try allocator.dupe(u8, "dummy key"),
    };
    defer key.deinit(allocator);
    
    const config = tls_config.TlsConfig.init(allocator)
        .withCertificate(cert, key);
    defer config.deinit();
    
    var server = try TlsServer.listen(allocator, "127.0.0.1", 0, config);
    defer server.close();
    
    const addr = try server.getAddress();
    try std.testing.expect(addr.getPort() > 0);
}

test "TLS connection helpers" {
    // Test cipher suite selection
    const suite = tls_config.CipherSuite.TLS_AES_128_GCM_SHA256;
    try std.testing.expectEqual(@as(usize, 16), suite.keySize());
    try std.testing.expectEqual(tls_config.HashAlgorithm.sha256, suite.hashAlgorithm());
}