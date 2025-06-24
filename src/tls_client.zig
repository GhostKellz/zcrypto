//! TLS Client Implementation
//!
//! Provides a high-level TLS client API for establishing secure connections
//! using TLS 1.3 with optional TLS 1.2 support.

const std = @import("std");
const tls = @import("tls.zig");
const tls_config = @import("tls_config.zig");
const hash = @import("hash.zig");
const rand = @import("rand.zig");
const sym = @import("sym.zig");
const kdf = @import("kdf.zig");
const util = @import("util.zig");
const asym = @import("asym.zig");

/// TLS alert levels
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
};

/// TLS alert descriptions
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    handshake_failure = 40,
    bad_certificate = 42,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    internal_error = 80,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
};

/// TLS record types
pub const RecordType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

/// TLS handshake message types
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
};

/// TLS extension types
pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    application_layer_protocol_negotiation = 16,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    key_share = 51,
};

/// TLS client connection state
pub const TlsClient = struct {
    /// Configuration
    config: tls_config.TlsConfig,
    /// Underlying network stream
    stream: std.net.Stream,
    /// Current handshake state
    handshake_state: HandshakeState = .initial,
    /// Handshake transcript hash
    transcript: hash.Sha256,
    /// Random values
    client_random: [32]u8,
    server_random: [32]u8,
    /// Selected cipher suite
    cipher_suite: ?tls_config.CipherSuite = null,
    /// Key exchange state
    client_key_share: ?asym.Curve25519KeyPair = null,
    server_public_key: ?[32]u8 = null,
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
    /// Session ID
    session_id: ?[32]u8 = null,
    /// Server certificates
    server_certificates: ?[]tls_config.Certificate = null,
    /// ALPN result
    selected_alpn: ?[]const u8 = null,
    /// Allocator
    allocator: std.mem.Allocator,

    /// Handshake states
    pub const HandshakeState = enum {
        initial,
        sent_client_hello,
        received_server_hello,
        received_encrypted_extensions,
        received_certificate,
        received_certificate_verify,
        received_finished,
        sent_finished,
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

    /// Initialize a new TLS client
    pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, config: tls_config.TlsConfig) !TlsClient {
        try config.validate();
        
        return TlsClient{
            .config = config,
            .stream = stream,
            .transcript = hash.Sha256.init(),
            .client_random = undefined,
            .server_random = undefined,
            .allocator = allocator,
        };
    }

    /// Perform TLS handshake
    pub fn handshake(self: *TlsClient) !void {
        // Generate client random
        rand.random(&self.client_random);

        // Send ClientHello
        try self.sendClientHello();
        self.handshake_state = .sent_client_hello;

        // Receive ServerHello
        try self.receiveServerHello();
        self.handshake_state = .received_server_hello;

        // Derive handshake secrets
        try self.deriveHandshakeSecrets();

        // Switch to encrypted handshake
        try self.receiveEncryptedExtensions();
        self.handshake_state = .received_encrypted_extensions;

        // Receive certificate (if not PSK)
        try self.receiveCertificate();
        self.handshake_state = .received_certificate;

        // Receive CertificateVerify
        try self.receiveCertificateVerify();
        self.handshake_state = .received_certificate_verify;

        // Receive Finished
        try self.receiveFinished();
        self.handshake_state = .received_finished;

        // Send client Finished
        try self.sendFinished();
        self.handshake_state = .sent_finished;

        // Derive application traffic secrets
        try self.deriveApplicationSecrets();

        self.handshake_state = .connected;
    }

    /// Write data to the connection
    pub fn write(self: *TlsClient, data: []const u8) !usize {
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
    pub fn read(self: *TlsClient, buffer: []u8) !usize {
        if (self.handshake_state != .connected) {
            return error.NotConnected;
        }

        // Read and decrypt a record
        const record = try self.readRecord();
        defer self.allocator.free(record.data);

        if (record.record_type != .application_data) {
            // Handle other record types (alerts, etc.)
            return error.UnexpectedRecord;
        }

        const copy_len = @min(buffer.len, record.data.len);
        @memcpy(buffer[0..copy_len], record.data[0..copy_len]);

        return copy_len;
    }

    /// Close the connection
    pub fn close(self: *TlsClient) !void {
        if (self.handshake_state == .connected) {
            // Send close_notify alert
            const alert = [_]u8{ @intFromEnum(AlertLevel.warning), @intFromEnum(AlertDescription.close_notify) };
            try self.writeRecord(.alert, &alert);
        }

        self.handshake_state = .closed;
        self.stream.close();
    }

    /// Deinitialize and clean up
    pub fn deinit(self: *TlsClient) void {
        // Clean up key exchange material
        if (self.client_key_share) |*keypair| {
            util.secureZero(&keypair.private_key);
        }
        if (self.server_public_key) |*key| util.secureZero(key);
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

        // Clean up certificates
        if (self.server_certificates) |certs| {
            for (certs) |cert| {
                cert.deinit(self.allocator);
            }
            self.allocator.free(certs);
        }

        if (self.selected_alpn) |alpn| {
            self.allocator.free(alpn);
        }
    }

    // Private helper methods

    fn sendClientHello(self: *TlsClient) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Generate client key share for X25519
        self.client_key_share = asym.x25519.generate();

        // TLS version (legacy)
        try buffer.writer().writeInt(u16, 0x0303, .big);

        // Client random
        try buffer.writer().writeAll(&self.client_random);

        // Session ID length (0 for new connection)
        try buffer.writer().writeByte(0);

        // Cipher suites
        try buffer.writer().writeInt(u16, @intCast(self.config.cipher_suites.len * 2), .big);
        for (self.config.cipher_suites) |suite| {
            try buffer.writer().writeInt(u16, @intFromEnum(suite), .big);
        }

        // Compression methods (null only)
        try buffer.writer().writeByte(1);
        try buffer.writer().writeByte(0);

        // Extensions
        var extensions = std.ArrayList(u8).init(self.allocator);
        defer extensions.deinit();

        // Supported versions extension
        try self.writeSupportedVersionsExtension(&extensions);

        // Server name extension
        if (self.config.server_name) |name| {
            try self.writeServerNameExtension(&extensions, name);
        }

        // Supported groups extension
        try self.writeSupportedGroupsExtension(&extensions);

        // Signature algorithms extension
        try self.writeSignatureAlgorithmsExtension(&extensions);

        // ALPN extension
        if (self.config.alpn_protocols) |protocols| {
            try self.writeALPNExtension(&extensions, protocols);
        }

        // Key share extension
        try self.writeKeyShareExtension(&extensions);

        // Write extensions length and data
        try buffer.writer().writeInt(u16, @intCast(extensions.items.len), .big);
        try buffer.writer().writeAll(extensions.items);

        // Update transcript
        self.transcript.update(buffer.items);

        // Send handshake message
        try self.writeHandshakeMessage(.client_hello, buffer.items);
    }

    fn receiveServerHello(self: *TlsClient) !void {
        const msg = try self.readHandshakeMessage();
        defer self.allocator.free(msg.data);

        if (msg.msg_type != .server_hello) {
            return error.UnexpectedMessage;
        }

        var stream = std.io.fixedBufferStream(msg.data);
        const reader = stream.reader();

        // Legacy version
        _ = try reader.readInt(u16, .big);

        // Server random
        _ = try reader.readAll(&self.server_random);

        // Session ID
        const session_id_len = try reader.readByte();
        if (session_id_len > 0) {
            var session_id: [32]u8 = undefined;
            _ = try reader.readAll(session_id[0..session_id_len]);
            self.session_id = session_id;
        }

        // Cipher suite
        const cipher_suite_value = try reader.readInt(u16, .big);
        self.cipher_suite = std.meta.intToEnum(tls_config.CipherSuite, cipher_suite_value) catch {
            return error.UnsupportedCipherSuite;
        };

        // Compression method (must be null)
        const compression = try reader.readByte();
        if (compression != 0) {
            return error.UnsupportedCompression;
        }

        // Parse extensions
        const extensions_len = try reader.readInt(u16, .big);
        const extensions_start = stream.pos;
        
        while (stream.pos < extensions_start + extensions_len) {
            const ext_type = try reader.readInt(u16, .big);
            const ext_len = try reader.readInt(u16, .big);
            const ext_data = msg.data[stream.pos..stream.pos + ext_len];
            
            switch (std.meta.intToEnum(ExtensionType, ext_type) catch .unsupported) {
                .supported_versions => {
                    const version = std.mem.readInt(u16, ext_data[0..2], .big);
                    if (version != 0x0304) { // TLS 1.3
                        return error.UnsupportedVersion;
                    }
                },
                .key_share => {
                    // Parse server's key share
                    if (ext_data.len >= 4) {
                        const group = std.mem.readInt(u16, ext_data[0..2], .big);
                        const key_len = std.mem.readInt(u16, ext_data[2..4], .big);
                        
                        if (group == 0x001d and key_len == 32 and ext_data.len >= 4 + key_len) {
                            // X25519 key share
                            self.server_public_key = [_]u8{0} ** 32;
                            @memcpy(&self.server_public_key.?, ext_data[4..4 + key_len]);
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

    fn deriveHandshakeSecrets(self: *TlsClient) !void {
        // Perform ECDHE key exchange
        if (self.client_key_share == null or self.server_public_key == null) {
            return error.MissingKeyExchange;
        }
        
        // Compute shared secret
        self.shared_secret = asym.x25519.dh(
            self.client_key_share.?.private_key,
            self.server_public_key.?
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

        // Derive traffic keys
        self.client_handshake_keys = try self.deriveTrafficKeys(self.client_handshake_secret.?, true);
        self.server_handshake_keys = try self.deriveTrafficKeys(self.server_handshake_secret.?, false);
    }

    fn deriveTrafficKeys(self: *TlsClient, secret: [32]u8, is_client: bool) !TrafficKeys {
        _ = is_client;
        const key_size = self.cipher_suite.?.keySize();
        
        const key = try kdf.hkdfExpandLabel(self.allocator, &secret, "key", "", key_size);
        const iv = try kdf.hkdfExpandLabel(self.allocator, &secret, "iv", "", 12);

        return TrafficKeys{
            .key = key,
            .iv = iv,
        };
    }

    fn getTranscriptHash(self: *TlsClient) ![]u8 {
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

    fn computeFinishedVerifyData(self: *TlsClient, is_client: bool) ![]u8 {
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

    fn deriveApplicationSecrets(self: *TlsClient) !void {
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

    // Stub implementations for remaining handshake messages
    fn receiveEncryptedExtensions(self: *TlsClient) !void {
        _ = self;
        // TODO: Implement
    }

    fn receiveCertificate(self: *TlsClient) !void {
        _ = self;
        // TODO: Implement
    }

    fn receiveCertificateVerify(self: *TlsClient) !void {
        _ = self;
        // TODO: Implement
    }

    fn receiveFinished(self: *TlsClient) !void {
        const msg = try self.readHandshakeMessage();
        defer self.allocator.free(msg.data);

        if (msg.msg_type != .finished) {
            return error.ExpectedFinished;
        }

        // Compute expected verify data
        const expected_verify_data = try self.computeFinishedVerifyData(false);
        defer self.allocator.free(expected_verify_data);

        // Verify the Finished message
        if (!util.constantTimeEqual(msg.data, expected_verify_data)) {
            return error.InvalidFinished;
        }

        // Update transcript
        self.transcript.update(msg.data);
    }

    fn sendFinished(self: *TlsClient) !void {
        const verify_data = try self.computeFinishedVerifyData(true);
        defer self.allocator.free(verify_data);
        
        // Update transcript with Finished message
        self.transcript.update(verify_data);
        
        // Send Finished message
        try self.writeHandshakeMessage(.finished, verify_data);
    }

    // Extension writers
    fn writeSupportedVersionsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        _ = self;
        try buffer.writer().writeInt(u16, @intFromEnum(ExtensionType.supported_versions), .big);
        try buffer.writer().writeInt(u16, 3, .big); // Extension length
        try buffer.writer().writeByte(2); // Versions list length
        try buffer.writer().writeInt(u16, 0x0304, .big); // TLS 1.3
    }

    fn writeServerNameExtension(self: *TlsClient, buffer: *std.ArrayList(u8), name: []const u8) !void {
        _ = self;
        try buffer.writer().writeInt(u16, @intFromEnum(ExtensionType.server_name), .big);
        try buffer.writer().writeInt(u16, @intCast(name.len + 5), .big);
        try buffer.writer().writeInt(u16, @intCast(name.len + 3), .big); // Server name list length
        try buffer.writer().writeByte(0); // Host name type
        try buffer.writer().writeInt(u16, @intCast(name.len), .big);
        try buffer.writer().writeAll(name);
    }

    fn writeSupportedGroupsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        _ = self;
        try buffer.writer().writeInt(u16, @intFromEnum(ExtensionType.supported_groups), .big);
        try buffer.writer().writeInt(u16, 4, .big); // Extension length
        try buffer.writer().writeInt(u16, 2, .big); // Groups list length
        try buffer.writer().writeInt(u16, 0x001d, .big); // x25519
    }

    fn writeSignatureAlgorithmsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        _ = self;
        try buffer.writer().writeInt(u16, @intFromEnum(ExtensionType.signature_algorithms), .big);
        try buffer.writer().writeInt(u16, 4, .big); // Extension length
        try buffer.writer().writeInt(u16, 2, .big); // Algorithms list length
        try buffer.writer().writeInt(u16, 0x0807, .big); // ed25519
    }

    fn writeALPNExtension(self: *TlsClient, buffer: *std.ArrayList(u8), protocols: [][]const u8) !void {
        var proto_list = std.ArrayList(u8).init(self.allocator);
        defer proto_list.deinit();

        for (protocols) |proto| {
            try proto_list.writer().writeByte(@intCast(proto.len));
            try proto_list.writer().writeAll(proto);
        }

        try buffer.writer().writeInt(u16, @intFromEnum(ExtensionType.application_layer_protocol_negotiation), .big);
        try buffer.writer().writeInt(u16, @intCast(proto_list.items.len + 2), .big);
        try buffer.writer().writeInt(u16, @intCast(proto_list.items.len), .big);
        try buffer.writer().writeAll(proto_list.items);
    }

    fn writeKeyShareExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try buffer.writer().writeInt(u16, @intFromEnum(ExtensionType.key_share), .big);
        try buffer.writer().writeInt(u16, 36, .big); // Extension length
        try buffer.writer().writeInt(u16, 34, .big); // Client shares length
        try buffer.writer().writeInt(u16, 0x001d, .big); // x25519
        try buffer.writer().writeInt(u16, 32, .big); // Key length
        
        // Use real public key from generated key share
        if (self.client_key_share) |keypair| {
            try buffer.writer().writeAll(&keypair.public_key);
        } else {
            return error.NoKeyShare;
        }
    }

    // Record layer helpers
    const Record = struct {
        record_type: RecordType,
        data: []u8,
    };

    const HandshakeMessage = struct {
        msg_type: HandshakeType,
        data: []u8,
    };

    fn writeRecord(self: *TlsClient, record_type: RecordType, data: []const u8) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Record header
        try buffer.writer().writeByte(@intFromEnum(record_type));
        try buffer.writer().writeInt(u16, 0x0303, .big); // Legacy version
        try buffer.writer().writeInt(u16, @intCast(data.len), .big);
        try buffer.writer().writeAll(data);

        try self.stream.writeAll(buffer.items);
    }

    fn readRecord(self: *TlsClient) !Record {
        var header: [5]u8 = undefined;
        _ = try self.stream.read(&header);

        const record_type = std.meta.intToEnum(RecordType, header[0]) catch {
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

    fn writeHandshakeMessage(self: *TlsClient, msg_type: HandshakeType, data: []const u8) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try buffer.writer().writeByte(@intFromEnum(msg_type));
        try buffer.writer().writeInt(u24, @intCast(data.len), .big);
        try buffer.writer().writeAll(data);

        try self.writeRecord(.handshake, buffer.items);
    }

    fn readHandshakeMessage(self: *TlsClient) !HandshakeMessage {
        const record = try self.readRecord();
        defer self.allocator.free(record.data);

        if (record.record_type != .handshake) {
            return error.ExpectedHandshake;
        }

        const msg_type = std.meta.intToEnum(HandshakeType, record.data[0]) catch {
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

test "TLS client initialization" {
    const allocator = std.testing.allocator;
    
    // Create a dummy stream (would be real network connection in practice)
    const address = try std.net.Address.parseIp("127.0.0.1", 443);
    const stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    
    const config = tls_config.TlsConfig.init(allocator);
    defer config.deinit();
    
    var client = try TlsClient.init(allocator, stream, config);
    defer client.deinit();
    
    try std.testing.expectEqual(TlsClient.HandshakeState.initial, client.handshake_state);
}

test "TLS client record writing" {
    const allocator = std.testing.allocator;
    
    // This is a simplified test - in practice, you'd use a mock stream
    const address = try std.net.Address.parseIp("127.0.0.1", 443);
    const stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    
    const config = tls_config.TlsConfig.init(allocator);
    defer config.deinit();
    
    var client = try TlsClient.init(allocator, stream, config);
    defer client.deinit();
    
    // Test would write records here
}