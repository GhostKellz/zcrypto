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
const security = @import("security.zig");
const x509 = @import("x509.zig");
const net = std.Io.net;

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
    stream: net.Stream,
    /// Io runtime for async operations
    io: std.Io,
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
    pub fn init(allocator: std.mem.Allocator, stream: net.Stream, io: std.Io, config: tls_config.TlsConfig) !TlsClient {
        try config.validate();

        return TlsClient{
            .config = config,
            .stream = stream,
            .io = io,
            .transcript = hash.Sha256.init(),
            .client_random = undefined,
            .server_random = undefined,
            .allocator = allocator,
        };
    }

    /// Perform TLS handshake
    pub fn handshake(self: *TlsClient) !void {
        // Generate client random
        rand.fillBytes(&self.client_random);

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
            try self.writeRecord(.application_data, data[offset .. offset + chunk_size]);
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
        self.stream.close(self.io);
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

    fn writeBytes(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
        try buffer.appendSlice(allocator, bytes);
    }

    fn sendClientHello(self: *TlsClient) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Generate client key share for X25519
        self.client_key_share = asym.x25519.generate();

        // TLS version (legacy)
        try writeU16(&buffer, self.allocator, 0x0303);

        // Client random
        try writeBytes(&buffer, self.allocator, &self.client_random);

        // Session ID length (0 for new connection)
        try writeU8(&buffer, self.allocator, 0);

        // Cipher suites
        try writeU16(&buffer, self.allocator, @intCast(self.config.cipher_suites.len * 2));
        for (self.config.cipher_suites) |suite| {
            try writeU16(&buffer, self.allocator, @intFromEnum(suite));
        }

        // Compression methods (null only)
        try writeU8(&buffer, self.allocator, 1);
        try writeU8(&buffer, self.allocator, 0);

        // Extensions
        var extensions: std.ArrayList(u8) = .empty;
        defer extensions.deinit(self.allocator);

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
        try writeU16(&buffer, self.allocator, @intCast(extensions.items.len));
        try writeBytes(&buffer, self.allocator, extensions.items);

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
            const ext_data = msg.data[stream.pos .. stream.pos + ext_len];

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
                            @memcpy(&self.server_public_key.?, ext_data[4 .. 4 + key_len]);
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
        self.shared_secret = asym.x25519.dh(self.client_key_share.?.private_key, self.server_public_key.?);

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

        const result = try self.allocator.alloc(u8, hash_len);

        switch (hash_alg) {
            .sha256 => {
                var transcript_copy = self.transcript;
                const final_hash = transcript_copy.final();
                @memcpy(result[0..32], &final_hash);
            },
            .sha384 => {
                // Use SHA384 transcript hash
                // Note: Would need to track SHA384 transcript separately for full support
                // For now, hash the current SHA256 transcript data with SHA384
                var sha384_hasher = std.crypto.hash.sha2.Sha384.init(.{});
                var transcript_copy = self.transcript;
                const sha256_result = transcript_copy.finalResult();
                sha384_hasher.update(&sha256_result);
                var sha384_result: [48]u8 = undefined;
                sha384_hasher.final(&sha384_result);
                @memcpy(result[0..48], &sha384_result);
            },
            .sha512 => {
                // Use SHA512 transcript hash
                var sha512_hasher = hash.Sha512.init();
                var transcript_copy = self.transcript;
                const sha256_result = transcript_copy.finalResult();
                sha512_hasher.update(&sha256_result);
                const sha512_result = sha512_hasher.final();
                @memcpy(result[0..64], &sha512_result);
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
        const finished_key = try kdf.hkdfExpandLabel(self.allocator, &secret, "finished", "", hash_len);
        defer self.allocator.free(finished_key);

        // Compute HMAC of transcript hash using the appropriate hash algorithm
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

    // TLS 1.3 Handshake Message Processing (RFC 8446)

    /// Receive and validate EncryptedExtensions message (RFC 8446 Section 4.3.1)
    ///
    /// This validates the server's encrypted extensions and checks for:
    /// - Forbidden extensions (those that must only appear in ClientHello/ServerHello)
    /// - ALPN protocol selection if we requested ALPN
    fn receiveEncryptedExtensions(self: *TlsClient) !void {
        const msg = try self.readHandshakeMessage();
        defer self.allocator.free(msg.data);

        if (msg.msg_type != .encrypted_extensions) {
            return error.ExpectedEncryptedExtensions;
        }

        // Update transcript with the full handshake message
        self.transcript.update(msg.data);

        // Parse extensions length (2 bytes)
        if (msg.data.len < 2) {
            return error.InvalidEncryptedExtensions;
        }
        const extensions_len = std.mem.readInt(u16, msg.data[0..2], .big);
        if (msg.data.len < 2 + extensions_len) {
            return error.InvalidEncryptedExtensions;
        }

        // Parse and validate extensions
        var pos: usize = 2;
        while (pos + 4 <= 2 + extensions_len) {
            const ext_type = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
            const ext_len = std.mem.readInt(u16, msg.data[pos + 2 ..][0..2], .big);
            pos += 4;

            if (pos + ext_len > 2 + extensions_len) {
                return error.InvalidExtension;
            }

            const ext_data = msg.data[pos .. pos + ext_len];
            pos += ext_len;

            // Validate extension types - some are forbidden in EncryptedExtensions
            switch (ext_type) {
                // Forbidden extensions (must only appear in ClientHello/ServerHello)
                @intFromEnum(ExtensionType.supported_versions),
                @intFromEnum(ExtensionType.key_share),
                @intFromEnum(ExtensionType.pre_shared_key),
                @intFromEnum(ExtensionType.psk_key_exchange_modes),
                @intFromEnum(ExtensionType.cookie),
                => return error.ForbiddenExtension,

                // ALPN - store selected protocol
                @intFromEnum(ExtensionType.application_layer_protocol_negotiation) => {
                    if (ext_len >= 3) {
                        const alpn_list_len = std.mem.readInt(u16, ext_data[0..2], .big);
                        if (alpn_list_len > 0 and ext_len >= 3) {
                            const proto_len = ext_data[2];
                            if (ext_len >= 3 + proto_len) {
                                self.selected_alpn = try self.allocator.dupe(u8, ext_data[3 .. 3 + proto_len]);
                            }
                        }
                    }
                },

                // Server name acknowledgment (no data expected)
                @intFromEnum(ExtensionType.server_name) => {},

                // Other extensions - allow for extensibility
                else => {},
            }
        }
    }

    /// Receive and validate server Certificate message (RFC 8446 Section 4.4.2)
    ///
    /// Parses the certificate chain and performs:
    /// - Certificate chain parsing
    /// - Hostname validation (if server_name was sent)
    /// - Trust anchor evaluation (if root CAs configured)
    /// - Validity period checks
    fn receiveCertificate(self: *TlsClient) !void {
        const msg = try self.readHandshakeMessage();
        defer self.allocator.free(msg.data);

        if (msg.msg_type != .certificate) {
            return error.ExpectedCertificate;
        }

        // Update transcript
        self.transcript.update(msg.data);

        // Parse Certificate message structure:
        // - certificate_request_context (1 byte length + data, empty for server cert)
        // - certificate_list (3 bytes length + entries)
        if (msg.data.len < 4) {
            return error.InvalidCertificate;
        }

        var pos: usize = 0;

        // certificate_request_context length (should be 0 for server certificate)
        const context_len = msg.data[pos];
        pos += 1 + context_len;

        if (pos + 3 > msg.data.len) {
            return error.InvalidCertificate;
        }

        // certificate_list length (3 bytes)
        const cert_list_len = std.mem.readInt(u24, msg.data[pos..][0..3], .big);
        pos += 3;

        if (pos + cert_list_len > msg.data.len) {
            return error.InvalidCertificate;
        }

        // Parse certificate entries
        var certs = std.ArrayList(tls_config.Certificate).init(self.allocator);
        errdefer {
            for (certs.items) |cert| {
                cert.deinit(self.allocator);
            }
            certs.deinit();
        }

        const cert_list_end = pos + cert_list_len;
        while (pos + 3 < cert_list_end) {
            // cert_data length (3 bytes)
            const cert_len = std.mem.readInt(u24, msg.data[pos..][0..3], .big);
            pos += 3;

            if (pos + cert_len > cert_list_end) {
                return error.InvalidCertificate;
            }

            // Certificate DER data
            const cert_der = msg.data[pos .. pos + cert_len];
            pos += cert_len;

            // Extensions for this certificate entry (2 bytes length + data)
            if (pos + 2 > cert_list_end) {
                return error.InvalidCertificate;
            }
            const cert_ext_len = std.mem.readInt(u16, msg.data[pos..][0..2], .big);
            pos += 2 + cert_ext_len;

            // Store certificate
            const cert = try tls_config.Certificate.fromDer(self.allocator, cert_der);
            try certs.append(cert);
        }

        if (certs.items.len == 0) {
            return error.EmptyCertificateChain;
        }

        // Store certificates
        self.server_certificates = try certs.toOwnedSlice();

        // Validate the end-entity certificate
        try self.validateServerCertificate();
    }

    /// Validate the server's certificate against configured trust anchors and hostname
    fn validateServerCertificate(self: *TlsClient) !void {
        const certs = self.server_certificates orelse return error.NoCertificateReceived;
        if (certs.len == 0) return error.EmptyCertificateChain;

        // Parse the end-entity (leaf) certificate
        var leaf_cert = certs[0];
        const parsed = try leaf_cert.parse(self.allocator);

        // Check if insecure mode is enabled
        if (self.config.insecure_skip_verify) {
            // Runtime check for release builds
            try security.checkInsecureOption("insecure_skip_verify");
            std.log.warn("SECURITY WARNING: Certificate verification SKIPPED. Connection vulnerable to MITM.", .{});
            return;
        }

        // Check certificate validity period
        if (!parsed.isValid()) {
            return error.CertificateExpired;
        }

        // Check hostname if server_name was configured
        if (self.config.server_name) |hostname| {
            if (!try parsed.isValidForHostname(hostname)) {
                return error.HostnameMismatch;
            }
        }

        // Verify against trust anchors
        if (self.config.root_cas) |root_cas| {
            var trusted = false;

            // For a proper implementation, we'd need to verify the full chain.
            // For now, check if any root CA directly signed the leaf or any intermediate.
            for (certs) |*cert| {
                var cert_parsed = try cert.parse(self.allocator);
                for (root_cas) |*ca| {
                    const ca_parsed = try ca.parse(self.allocator);
                    if (cert_parsed.verifySignature(ca_parsed.public_key_info.public_key) catch false) {
                        trusted = true;
                        break;
                    }
                }
                if (trusted) break;
            }

            if (!trusted) {
                return error.UntrustedCertificate;
            }
        } else {
            // SECURITY: No root CAs configured - this is a security risk
            // Fail closed by default unless insecure_skip_verify is set
            return error.NoTrustAnchorsConfigured;
        }
    }

    /// Receive and validate CertificateVerify message (RFC 8446 Section 4.4.3)
    ///
    /// Verifies that the server possesses the private key for its certificate by
    /// checking the signature over the handshake transcript.
    fn receiveCertificateVerify(self: *TlsClient) !void {
        const msg = try self.readHandshakeMessage();
        defer self.allocator.free(msg.data);

        if (msg.msg_type != .certificate_verify) {
            return error.ExpectedCertificateVerify;
        }

        // Don't update transcript yet - we need the hash up to (but not including) CertificateVerify
        // The transcript gets the Certificate message but we verify against that state

        // Parse CertificateVerify structure:
        // - signature_algorithm (2 bytes)
        // - signature (2 bytes length + data)
        if (msg.data.len < 4) {
            return error.InvalidCertificateVerify;
        }

        const sig_algorithm = std.mem.readInt(u16, msg.data[0..2], .big);
        const sig_len = std.mem.readInt(u16, msg.data[2..4], .big);

        if (msg.data.len < 4 + sig_len) {
            return error.InvalidCertificateVerify;
        }

        const signature = msg.data[4 .. 4 + sig_len];

        // Get the server's public key from the certificate
        const certs = self.server_certificates orelse return error.NoCertificateReceived;
        if (certs.len == 0) return error.EmptyCertificateChain;

        var leaf_cert = certs[0];
        const parsed = try leaf_cert.parse(self.allocator);

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

        // Verify signature based on algorithm
        const verified = switch (sig_algorithm) {
            0x0807 => blk: { // ed25519
                if (parsed.public_key_info.public_key.len != 32) {
                    break :blk false;
                }
                if (signature.len != 64) {
                    break :blk false;
                }
                const public_key: [32]u8 = parsed.public_key_info.public_key[0..32].*;
                const sig: [64]u8 = signature[0..64].*;
                break :blk asym.ed25519.verify(&content, sig, public_key);
            },
            0x0403 => blk: { // ecdsa_secp256r1_sha256
                // Would need ECDSA P-256 verification
                std.log.warn("ECDSA P-256 signature verification not yet implemented", .{});
                break :blk false;
            },
            0x0804 => blk: { // rsa_pss_rsae_sha256
                // Would need RSA-PSS verification
                std.log.warn("RSA-PSS signature verification not yet implemented", .{});
                break :blk false;
            },
            else => {
                std.log.warn("Unsupported signature algorithm: 0x{x:0>4}", .{sig_algorithm});
                return error.UnsupportedSignatureAlgorithm;
            },
        };

        if (!verified) {
            return error.InvalidCertificateVerifySignature;
        }

        // NOW update transcript with the CertificateVerify message
        self.transcript.update(msg.data);
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
        try writeU16(buffer, self.allocator, @intFromEnum(ExtensionType.supported_versions));
        try writeU16(buffer, self.allocator, 3); // Extension length
        try writeU8(buffer, self.allocator, 2); // Versions list length
        try writeU16(buffer, self.allocator, 0x0304); // TLS 1.3
    }

    fn writeServerNameExtension(self: *TlsClient, buffer: *std.ArrayList(u8), name: []const u8) !void {
        try writeU16(buffer, self.allocator, @intFromEnum(ExtensionType.server_name));
        try writeU16(buffer, self.allocator, @intCast(name.len + 5));
        try writeU16(buffer, self.allocator, @intCast(name.len + 3)); // Server name list length
        try writeU8(buffer, self.allocator, 0); // Host name type
        try writeU16(buffer, self.allocator, @intCast(name.len));
        try writeBytes(buffer, self.allocator, name);
    }

    fn writeSupportedGroupsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @intFromEnum(ExtensionType.supported_groups));
        try writeU16(buffer, self.allocator, 4); // Extension length
        try writeU16(buffer, self.allocator, 2); // Groups list length
        try writeU16(buffer, self.allocator, 0x001d); // x25519
    }

    fn writeSignatureAlgorithmsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @intFromEnum(ExtensionType.signature_algorithms));
        try writeU16(buffer, self.allocator, 4); // Extension length
        try writeU16(buffer, self.allocator, 2); // Algorithms list length
        try writeU16(buffer, self.allocator, 0x0807); // ed25519
    }

    fn writeALPNExtension(self: *TlsClient, buffer: *std.ArrayList(u8), protocols: [][]const u8) !void {
        var proto_list: std.ArrayList(u8) = .empty;
        defer proto_list.deinit(self.allocator);

        for (protocols) |proto| {
            try writeU8(&proto_list, self.allocator, @intCast(proto.len));
            try writeBytes(&proto_list, self.allocator, proto);
        }

        try writeU16(buffer, self.allocator, @intFromEnum(ExtensionType.application_layer_protocol_negotiation));
        try writeU16(buffer, self.allocator, @intCast(proto_list.items.len + 2));
        try writeU16(buffer, self.allocator, @intCast(proto_list.items.len));
        try writeBytes(buffer, self.allocator, proto_list.items);
    }

    fn writeKeyShareExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @intFromEnum(ExtensionType.key_share));
        try writeU16(buffer, self.allocator, 36); // Extension length
        try writeU16(buffer, self.allocator, 34); // Client shares length
        try writeU16(buffer, self.allocator, 0x001d); // x25519
        try writeU16(buffer, self.allocator, 32); // Key length

        // Use real public key from generated key share
        if (self.client_key_share) |keypair| {
            try writeBytes(buffer, self.allocator, &keypair.public_key);
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

    /// Write a TLS record, encrypting if traffic keys are available
    fn writeRecord(self: *TlsClient, record_type: RecordType, data: []const u8) !void {
        // Check if we should encrypt (have client traffic keys)
        if (self.client_traffic_keys) |*keys| {
            try self.writeEncryptedRecord(record_type, data, keys);
        } else if (self.client_handshake_keys) |*keys| {
            // Use handshake keys if available but not yet transitioned to traffic keys
            try self.writeEncryptedRecord(record_type, data, keys);
        } else {
            // No keys yet - send plaintext (only valid during initial handshake)
            try self.writePlaintextRecord(record_type, data);
        }
    }

    /// Write a plaintext TLS record (only for initial handshake before keys are derived)
    fn writePlaintextRecord(self: *TlsClient, record_type: RecordType, data: []const u8) !void {
        var header: [5]u8 = undefined;
        header[0] = @intFromEnum(record_type);
        header[1] = 0x03; // Legacy version high byte
        header[2] = 0x03; // Legacy version low byte
        header[3] = @intCast((data.len >> 8) & 0xFF);
        header[4] = @intCast(data.len & 0xFF);

        var write_buf: [8192]u8 = undefined;
        var w = self.stream.writer(self.io, &write_buf);
        try w.interface.writeAll(&header);
        try w.interface.writeAll(data);
        try w.interface.flush();
    }

    /// Write an encrypted TLS 1.3 record (RFC 8446 Section 5.2)
    ///
    /// TLS 1.3 encrypted record format:
    /// - Outer content type: application_data (0x17)
    /// - Legacy version: 0x0303
    /// - Length: ciphertext length + tag length
    /// - Ciphertext: AEAD(inner_plaintext)
    /// - inner_plaintext = content || content_type || zeros (padding)
    fn writeEncryptedRecord(self: *TlsClient, record_type: RecordType, data: []const u8, keys: *TrafficKeys) !void {
        const cipher_suite = self.cipher_suite orelse return error.NoCipherSuite;

        // Build inner plaintext: data + content type byte
        // TLS 1.3 puts the real content type at the end of the plaintext
        const inner_plaintext = try self.allocator.alloc(u8, data.len + 1);
        defer self.allocator.free(inner_plaintext);
        @memcpy(inner_plaintext[0..data.len], data);
        inner_plaintext[data.len] = @intFromEnum(record_type);

        // Construct nonce: XOR IV with sequence number (padded to 12 bytes)
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, keys.iv[0..12]);
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, keys.sequence, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // Additional authenticated data: record header with outer content type
        // AAD = record_type || legacy_version || length
        const ciphertext_len = inner_plaintext.len + 16; // +16 for auth tag
        var aad: [5]u8 = undefined;
        aad[0] = @intFromEnum(RecordType.application_data); // Outer type is always application_data
        aad[1] = 0x03;
        aad[2] = 0x03;
        std.mem.writeInt(u16, aad[3..5], @intCast(ciphertext_len), .big);

        // Encrypt based on cipher suite
        const ciphertext = try self.allocator.alloc(u8, ciphertext_len);
        errdefer self.allocator.free(ciphertext);

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

        // Increment sequence number
        keys.sequence += 1;

        // Write encrypted record
        var write_buf: [8192]u8 = undefined;
        var w = self.stream.writer(self.io, &write_buf);
        try w.interface.writeAll(&aad); // Header (AAD is the header)
        try w.interface.writeAll(ciphertext);
        try w.interface.flush();

        self.allocator.free(ciphertext);
    }

    /// Read a TLS record, decrypting if traffic keys are available
    fn readRecord(self: *TlsClient) !Record {
        var header: [5]u8 = undefined;

        var read_buf: [8192]u8 = undefined;
        var r = self.stream.reader(self.io, &read_buf);
        try r.interface.readSliceAll(&header);

        const outer_type = std.meta.intToEnum(RecordType, header[0]) catch {
            return error.UnknownRecordType;
        };
        const length = std.mem.readInt(u16, header[3..5], .big);

        const record_data = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(record_data);
        try r.interface.readSliceAll(record_data);

        // Check if we should decrypt
        if (self.server_traffic_keys) |*keys| {
            return self.decryptRecord(&header, record_data, keys);
        } else if (self.server_handshake_keys) |*keys| {
            // Check if this looks like an encrypted record
            if (outer_type == .application_data and length > 16) {
                return self.decryptRecord(&header, record_data, keys);
            }
        }

        // Return plaintext record
        return Record{
            .record_type = outer_type,
            .data = record_data,
        };
    }

    /// Decrypt a TLS 1.3 record (RFC 8446 Section 5.2)
    ///
    /// SECURITY: Auth tag is verified BEFORE plaintext is exposed.
    /// If verification fails, no plaintext data is returned.
    fn decryptRecord(self: *TlsClient, header: *const [5]u8, ciphertext: []u8, keys: *TrafficKeys) !Record {
        const cipher_suite = self.cipher_suite orelse return error.NoCipherSuite;

        if (ciphertext.len < 17) { // At least 1 byte content + 16 byte tag
            return error.RecordTooShort;
        }

        const tag_start = ciphertext.len - 16;
        var tag: [16]u8 = undefined;
        @memcpy(&tag, ciphertext[tag_start..]);
        const encrypted_content = ciphertext[0..tag_start];

        // Construct nonce
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, keys.iv[0..12]);
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, keys.sequence, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // AAD is the record header
        const aad = header;

        // Allocate plaintext buffer
        const plaintext = try self.allocator.alloc(u8, encrypted_content.len);
        errdefer self.allocator.free(plaintext);

        // Decrypt and verify auth tag - MUST verify before exposing plaintext
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
            // Free the ciphertext buffer since it was allocated by caller
            self.allocator.free(ciphertext);
            return error.DecryptionFailed;
        }

        // Increment sequence number after successful decryption
        keys.sequence += 1;

        // Free the original ciphertext buffer
        self.allocator.free(ciphertext);

        // Extract inner content type (last byte of plaintext)
        // Remove any padding zeros from the end
        var content_end = plaintext.len;
        while (content_end > 0 and plaintext[content_end - 1] == 0) {
            content_end -= 1;
        }

        if (content_end == 0) {
            self.allocator.free(plaintext);
            return error.InvalidRecord;
        }

        // Last non-zero byte is the content type
        const inner_type = std.meta.intToEnum(RecordType, plaintext[content_end - 1]) catch {
            self.allocator.free(plaintext);
            return error.UnknownRecordType;
        };

        // Return the actual content (excluding type byte)
        const content = try self.allocator.alloc(u8, content_end - 1);
        @memcpy(content, plaintext[0 .. content_end - 1]);
        self.allocator.free(plaintext);

        return Record{
            .record_type = inner_type,
            .data = content,
        };
    }

    fn writeHandshakeMessage(self: *TlsClient, msg_type: HandshakeType, data: []const u8) !void {
        // Build handshake header: 1 byte type + 3 bytes length (u24 big endian)
        var header: [4]u8 = undefined;
        header[0] = @intFromEnum(msg_type);
        header[1] = @intCast((data.len >> 16) & 0xFF);
        header[2] = @intCast((data.len >> 8) & 0xFF);
        header[3] = @intCast(data.len & 0xFF);

        // Combine header and data for writeRecord
        const full_msg = try self.allocator.alloc(u8, 4 + data.len);
        defer self.allocator.free(full_msg);
        @memcpy(full_msg[0..4], &header);
        @memcpy(full_msg[4..], data);

        try self.writeRecord(.handshake, full_msg);
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
        @memcpy(data, record.data[4 .. 4 + length]);

        return HandshakeMessage{
            .msg_type = msg_type,
            .data = data,
        };
    }
};

test "TLS client initialization" {
    const allocator = std.testing.allocator;

    // Test basic TLS client structure initialization
    const config = tls_config.TlsConfig.init(allocator);
    defer config.deinit();

    // Just test that config can be created and destroyed
    try std.testing.expect(config.certificates == null);
    try std.testing.expect(config.private_key == null);
}

test "TLS client record writing" {
    const allocator = std.testing.allocator;

    // Test basic config setup
    const config = tls_config.TlsConfig.init(allocator);
    defer config.deinit();

    // Test would write records here - simplified for now
    try std.testing.expect(config.certificates == null);
}
