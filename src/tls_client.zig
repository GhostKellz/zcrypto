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

/// Everything needed to resume a later connection: what the server handed out,
/// and what the client derived from it.
///
/// This outlives both the connection that received it and the one that presents
/// it, which is why it owns its ticket bytes and is handed to the caller rather
/// than kept inside a `TlsClient`.
///
/// The PSK is derived here, at receipt, rather than stored as the resumption
/// master secret plus a nonce: the master secret can mint every future ticket,
/// while this PSK is good for one. Keeping the narrower secret means a session
/// that leaks costs one resumption, not all of them.
pub const ResumptionSession = struct {
    /// The opaque ticket, echoed back verbatim as a PSK identity. Owned.
    ticket: []u8,
    /// `HKDF-Expand-Label(resumption_master_secret, "resumption", nonce, 32)`,
    /// RFC 8446 Section 4.6.1.
    psk: [32]u8,
    /// The suite this session ran under. RFC 8446 Section 4.2.11 only allows
    /// resumption under a suite with the same hash, since the PSK is bound to
    /// that hash's key schedule.
    cipher_suite: tls_config.CipherSuite,
    /// RFC 8446 Section 4.2.11.1: the client sends `age + ticket_age_add`, so
    /// the add has to survive with the ticket or the field is meaningless.
    ticket_age_add: u32,
    /// Lifetime in seconds as advertised by the server. Kept for callers that
    /// want to discard a session before offering it; nothing here enforces it,
    /// because the server re-checks freshness against the stamp sealed inside
    /// the ticket and is the only side that can be trusted to.
    lifetime_s: u32,

    pub fn deinit(self: *ResumptionSession, allocator: std.mem.Allocator) void {
        util.secureZero(&self.psk);
        allocator.free(self.ticket);
        self.* = undefined;
    }
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
    /// Resumption master secret, the input to every ticket PSK this session
    /// can later present (RFC 8446 Section 4.6.1).
    resumption_master_secret: ?[32]u8 = null,
    /// Transcript digest at ClientHello..server Finished.
    ///
    /// Captured during the handshake because RFC 8446 Section 7.1 bounds the
    /// application traffic secrets there, while the resumption master secret
    /// runs one message further. A single late snapshot cannot serve both, and
    /// using one for both is undetectable between two endpoints that make the
    /// same mistake.
    server_finished_transcript: ?[32]u8 = null,
    /// Traffic keys
    client_handshake_keys: ?TrafficKeys = null,
    server_handshake_keys: ?TrafficKeys = null,
    client_traffic_keys: ?TrafficKeys = null,
    server_traffic_keys: ?TrafficKeys = null,
    /// A ticket to offer for resumption, or null for a full handshake.
    ///
    /// Borrowed for the length of the handshake and never freed here: a session
    /// outlives the connection that produced it and the one that presents it,
    /// so the caller decides when it dies. Set this before `handshake`.
    offered_session: ?*const ResumptionSession = null,
    /// A ticket the server issued on this connection, if one has arrived.
    ///
    /// Populated by `read`, because RFC 8446 Section 4.6.1 puts NewSessionTicket
    /// after the handshake, in the application-data flow. Ownership passes to
    /// the caller via `takeSession`; anything still here at `deinit` is freed.
    received_session: ?ResumptionSession = null,
    /// The PSK this handshake resumed under, set only once the server has
    /// echoed `pre_shared_key`. Null means a full handshake.
    psk: ?[32]u8 = null,
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

        // Certificate and CertificateVerify, unless this handshake resumed.
        // RFC 8446 Section 4.4.2: a server that authenticated via PSK sends
        // neither, because possession of the ticket's PSK is the
        // authentication. `receiveServerHello` will not leave `psk` set unless
        // this client offered the ticket and the server echoed its selection,
        // so a server cannot reach this branch by claiming a PSK on its own.
        if (self.psk == null) {
            try self.receiveCertificate();
            self.handshake_state = .received_certificate;

            try self.receiveCertificateVerify();
            self.handshake_state = .received_certificate_verify;
        }

        // Receive Finished
        try self.receiveFinished();
        self.handshake_state = .received_finished;

        // RFC 8446 Section 7.1 derives the application traffic secrets over
        // ClientHello..server Finished. That range closes here, one message
        // before this endpoint sends its own Finished, so the digest has to be
        // taken now rather than reconstructed later from a transcript that has
        // moved on. The resumption master secret runs to
        // ClientHello..client Finished and is taken from the live transcript.
        self.server_finished_transcript = try self.snapshotTranscript();

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

        // Post-handshake handshake records are consumed here and the read
        // continues, rather than being surfaced to the caller. RFC 8446
        // Section 4.6.1 puts NewSessionTicket in the application-data flow at a
        // time of the server's choosing, so a caller doing nothing but reading
        // its own data would otherwise see a spurious failure whenever a ticket
        // happened to arrive.
        while (true) {
            const record = try self.readRecord();
            defer self.allocator.free(record.data);

            if (record.record_type == .handshake) {
                try self.handlePostHandshake(record.data);
                continue;
            }

            if (record.record_type != .application_data) {
                // Alerts and anything else still reach the caller.
                return error.UnexpectedRecord;
            }

            const copy_len = @min(buffer.len, record.data.len);
            @memcpy(buffer[0..copy_len], record.data[0..copy_len]);

            return copy_len;
        }
    }

    /// Dispatch a handshake message arriving after the handshake completed.
    ///
    /// Only NewSessionTicket is acted on. Anything else is ignored rather than
    /// rejected, because an unrecognised post-handshake message is not grounds
    /// to tear down a working connection -- but note that ignoring is not
    /// neutral for KeyUpdate, which this record layer does not implement: a
    /// peer that sends one will find subsequent records undecryptable. That
    /// failure is the record layer's to report, not this function's to fake.
    fn handlePostHandshake(self: *TlsClient, data: []const u8) !void {
        if (data.len < 4) return error.InvalidHandshake;
        const msg_len = std.mem.readInt(u24, data[1..4], .big);
        if (4 + @as(usize, msg_len) > data.len) return error.InvalidHandshake;
        if (data[0] != @backingInt(HandshakeType.new_session_ticket)) return;

        self.receiveNewSessionTicket(data[4 .. 4 + msg_len]) catch |err| switch (err) {
            // A ticket this client cannot parse or key costs a future
            // resumption and nothing else. Failing the connection over it would
            // let a malformed optional message take down live traffic.
            error.InvalidHandshake, error.TruncatedMessage => return,
            else => return err,
        };
    }

    /// RFC 8446 Section 4.6.1:
    ///     ticket_lifetime(4) || ticket_age_add(4) || nonce_len(1) || nonce
    ///         || ticket_len(2) || ticket || extensions_len(2)
    ///
    /// The PSK is derived here, at receipt, from the nonce carried in this
    /// message -- not from a nonce chosen locally. The server seals the PSK it
    /// derived from the nonce it put on the wire, so these must be the same
    /// bytes; if they are not, nothing fails until some later connection's
    /// binder is rejected for no stated reason.
    ///
    /// Public for the same reason as `buildClientHello`: it is one half of a
    /// cross-endpoint agreement, and the test that checks the halves agree has
    /// to sit next to the other one.
    pub fn receiveNewSessionTicket(self: *TlsClient, body: []const u8) !void {
        const res_master = self.resumption_master_secret orelse return error.InvalidHandshake;
        const suite = self.cipher_suite orelse return error.InvalidHandshake;

        var cur = Cursor{ .data = body };
        const lifetime_s = try cur.int32();
        const age_add = try cur.int32();
        const nonce = try cur.take(try cur.byte());
        const ticket = try cur.take(try cur.int16());
        if (ticket.len == 0) return error.InvalidHandshake;

        const psk = try kdf.hkdfExpandLabel(self.allocator, &res_master, "resumption", nonce, 32);
        defer {
            util.secureZero(psk);
            self.allocator.free(psk);
        }

        const owned = try self.allocator.dupe(u8, ticket);
        errdefer self.allocator.free(owned);

        // At most one session is held. A server may issue several; keeping the
        // newest and dropping the rest bounds how many live PSKs this client
        // holds, and `takeSession` gives a caller that wants them all a place
        // to collect each one.
        if (self.received_session) |*old| old.deinit(self.allocator);

        var session = ResumptionSession{
            .ticket = owned,
            .psk = undefined,
            .cipher_suite = suite,
            .ticket_age_add = age_add,
            .lifetime_s = lifetime_s,
        };
        @memcpy(&session.psk, psk);
        self.received_session = session;
    }

    /// Take ownership of the session ticket this connection received, if any.
    ///
    /// Moves rather than copies: a session is a credential, and leaving a second
    /// live copy behind in the connection would mean the caller cannot tell how
    /// long the PSK stays in memory. After this the connection has none, so a
    /// second call returns null.
    pub fn takeSession(self: *TlsClient) ?ResumptionSession {
        const session = self.received_session;
        self.received_session = null;
        return session;
    }

    /// Close the connection
    pub fn close(self: *TlsClient) !void {
        if (self.handshake_state == .connected) {
            // Send close_notify alert
            const alert = [_]u8{ @backingInt(AlertLevel.warning), @backingInt(AlertDescription.close_notify) };
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
        if (self.resumption_master_secret) |*secret| util.secureZero(secret);
        if (self.psk) |*secret| util.secureZero(secret);
        // `offered_session` is borrowed and deliberately untouched. Only a
        // session the caller never claimed is freed here.
        if (self.received_session) |*session| session.deinit(self.allocator);

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

    /// Bounds-checked forward reader over a handshake message body.
    const Cursor = struct {
        data: []const u8,
        pos: usize = 0,

        /// Consume `len` bytes, or fail if fewer remain.
        fn take(self: *Cursor, len: usize) ![]const u8 {
            // Subtraction, not `pos + len > data.len`, so a huge wire-supplied
            // length cannot wrap the comparison.
            if (len > self.data.len - self.pos) return error.TruncatedMessage;
            defer self.pos += len;
            return self.data[self.pos..][0..len];
        }

        fn byte(self: *Cursor) !u8 {
            return (try self.take(1))[0];
        }

        fn int16(self: *Cursor) !u16 {
            return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
        }

        fn int32(self: *Cursor) !u32 {
            return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
        }
    };

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

    fn sendClientHello(self: *TlsClient) !void {
        const body = try self.buildClientHello();
        defer self.allocator.free(body);

        self.transcriptUpdate(.client_hello, body);
        try self.writeHandshakeMessage(.client_hello, body);
    }

    /// The ClientHello body of RFC 8446 Section 4.1.2, binder included.
    ///
    /// Split from `sendClientHello` so the message can be read back without a
    /// socket, the same reason the server splits `buildNewSessionTicketBody`.
    /// The binder is the one field whose correctness cannot be judged from
    /// either endpoint alone -- it is a MAC over these very bytes, and a client
    /// and server that truncate the same way agree with each other whether or
    /// not they agree with the RFC -- so being able to hand the finished message
    /// to the server's parser, and to a hand-written check, is what makes it
    /// testable at all.
    ///
    /// Deliberately does not touch the transcript: the caller decides when this
    /// message enters it, and a test that builds a ClientHello to inspect must
    /// not perturb the connection it came from.
    ///
    /// Public because the resumption tests live beside the server, and Zig
    /// privacy is per file. Testing a copy of this logic from over there would
    /// test the copy.
    pub fn buildClientHello(self: *TlsClient) ![]u8 {
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

        // Cipher suites. Only SHA-256 suites are offered: the handshake
        // transcript is SHA-256 only (see getTranscriptHash), so offering a
        // SHA-384 suite invites the server to pick one we cannot complete.
        var offered: usize = 0;
        for (self.config.cipher_suites) |suite| {
            if (suite.hashAlgorithm() == .sha256) offered += 1;
        }
        if (offered == 0) return error.NoCipherSuite;

        try writeU16(&buffer, self.allocator, @intCast(offered * 2));
        for (self.config.cipher_suites) |suite| {
            if (suite.hashAlgorithm() != .sha256) continue;
            try writeU16(&buffer, self.allocator, @backingInt(suite));
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

        // Resumption offer. `pre_shared_key` goes last and nothing may be
        // appended after it: RFC 8446 Section 4.2.11 requires it, and the
        // requirement is structural rather than cosmetic -- the binder is a MAC
        // over the ClientHello up to the binders list, so that region is only a
        // well-defined prefix if this extension terminates the message.
        const offering = self.pskOffer();
        if (offering) |session| {
            try self.writePskKeyExchangeModesExtension(&extensions);
            try self.writePreSharedKeyExtension(&extensions, session);
        }

        // Write extensions length and data
        try writeU16(&buffer, self.allocator, @intCast(extensions.items.len));
        try writeBytes(&buffer, self.allocator, extensions.items);

        // The binder can only be computed once the message is otherwise
        // complete, because it covers the message itself. The placeholder
        // written above is the same length as the real value, so patching it in
        // here changes no offset and no declared length.
        if (offering) |session| {
            try self.fillPskBinder(buffer.items, session);
        }

        return buffer.toOwnedSlice(self.allocator);
    }

    fn receiveServerHello(self: *TlsClient) !void {
        const msg = try self.readHandshakeMessage();
        defer self.allocator.free(msg.data);

        if (msg.msg_type != .server_hello) {
            return error.UnexpectedMessage;
        }

        try self.parseServerHello(msg.data);
    }

    /// Read a ServerHello body, RFC 8446 Section 4.1.3.
    ///
    /// Parsed with an explicit cursor: every field here comes off the wire from
    /// an unauthenticated peer, so each read is length-checked. The previous
    /// reader-based version indexed the backing slice directly and would panic
    /// on a hostile ServerHello -- an over-long session ID, or a truncated
    /// supported_versions body.
    ///
    /// Public, and split from the socket, so the resumption tests can hand this
    /// parser a ServerHello the real server built. Zig privacy is per file and
    /// those tests live beside the server.
    pub fn parseServerHello(self: *TlsClient, body: []const u8) !void {
        var cur = Cursor{ .data = body };

        // Legacy version
        _ = try cur.int16();

        // Server random
        @memcpy(&self.server_random, try cur.take(32));

        // Session ID. We always send an empty legacy_session_id (see
        // sendClientHello), and RFC 8446 4.1.3 requires the server to echo it
        // verbatim, so anything else is a protocol violation.
        const session_id_len = try cur.byte();
        if (session_id_len != 0) return error.InvalidHandshake;

        // Cipher suite
        const cipher_suite_value = try cur.int16();
        self.cipher_suite = std.enums.fromInt(tls_config.CipherSuite, cipher_suite_value) orelse {
            return error.UnsupportedCipherSuite;
        };

        // Compression method (must be null)
        if (try cur.byte() != 0) {
            return error.UnsupportedCompression;
        }

        // Parse extensions
        const extensions_len = try cur.int16();
        var ext_cur = Cursor{ .data = try cur.take(extensions_len) };

        var psk_accepted = false;
        while (ext_cur.pos < ext_cur.data.len) {
            const ext_type = try ext_cur.int16();
            const ext_len = try ext_cur.int16();
            const ext_data = try ext_cur.take(ext_len);

            // Extensions we do not model are skipped, not rejected: the cursor
            // has already stepped past the body.
            const known = std.enums.fromInt(ExtensionType, ext_type) orelse continue;
            switch (known) {
                .supported_versions => {
                    if (ext_data.len < 2) return error.InvalidExtension;
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
                            self.server_public_key = std.mem.zeroes([32]u8);
                            @memcpy(&self.server_public_key.?, ext_data[4 .. 4 + key_len]);
                        }
                    }
                },
                .pre_shared_key => {
                    // RFC 8446 Section 4.2.11: the server echoes only the index
                    // of the identity it chose. One identity was offered, so the
                    // only valid answer is 0; anything else means the server is
                    // keyed on something this client did not send, and
                    // continuing would fail at Finished with no explanation.
                    if (ext_data.len != 2) return error.InvalidExtension;
                    if (std.mem.readInt(u16, ext_data[0..2], .big) != 0) return error.InvalidExtension;
                    // A server may not select a PSK that was never offered.
                    // Without this, a server could induce the client into the
                    // resumption path -- which skips Certificate and
                    // CertificateVerify -- while `psk` is null, so the client
                    // would complete an unauthenticated handshake.
                    if (self.psk == null) return error.InvalidExtension;
                    psk_accepted = true;
                },
                else => {},
            }
        }

        // The offer was declined, so this is a full handshake. Clearing the
        // provisional PSK here is what keeps the key schedule honest: it is read
        // back in `earlySecretIkm`, and leaving it set would mix a PSK the
        // server is not using into every secret derived from here on.
        if (!psk_accepted) {
            if (self.psk) |*secret| util.secureZero(secret);
            self.psk = null;
        }

        // Update transcript
        self.transcriptUpdate(.server_hello, body);
    }

    /// Derive both handshake traffic secrets at the ClientHello..ServerHello
    /// boundary.
    ///
    /// Public only as a seam: the resumption tests live beside the server, and
    /// comparing what the two sides derive is the one check that covers the PSK,
    /// the ECDHE share and the whole transcript in a single assertion. Callers
    /// driving a handshake should use `handshake`, which sequences this.
    pub fn deriveHandshakeSecrets(self: *TlsClient) !void {
        // Perform ECDHE key exchange
        if (self.client_key_share == null or self.server_public_key == null) {
            return error.MissingKeyExchange;
        }

        // Compute shared secret. `dh` returns IdentityElement when the peer's
        // share is a low-order point; propagate it rather than continuing with a
        // shared secret the peer could have forced to a known value.
        self.shared_secret = try asym.x25519.dh(self.client_key_share.?.private_key, self.server_public_key.?);

        // Initialize key schedule with the cipher suite's hash algorithm
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        var key_schedule = try tls.KeySchedule.init(self.allocator, hash_alg);
        defer key_schedule.deinit();

        try key_schedule.deriveEarlySecret(self.earlySecretIkm());

        // Derive handshake secret using ECDHE shared secret
        try key_schedule.deriveHandshakeSecret(&self.shared_secret.?);

        // RFC 8446 Section 7.1 bounds both handshake traffic secrets at
        // ClientHello..ServerHello. This runs immediately after ServerHello is
        // processed, which is that boundary.
        const transcript_data = try self.snapshotTranscript();

        const client_hs_secret = try key_schedule.deriveSecretFromTranscriptHash(key_schedule.handshake_secret, "c hs traffic", &transcript_data);
        defer self.allocator.free(client_hs_secret);

        const server_hs_secret = try key_schedule.deriveSecretFromTranscriptHash(key_schedule.handshake_secret, "s hs traffic", &transcript_data);
        defer self.allocator.free(server_hs_secret);

        // Copy secrets (truncate to 32 bytes for now)
        self.client_handshake_secret = std.mem.zeroes([32]u8);
        self.server_handshake_secret = std.mem.zeroes([32]u8);
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

    /// Transcript hash over the handshake messages seen so far.
    ///
    /// `self.transcript` is a SHA-256 hasher and is the only transcript this
    /// connection keeps, so only SHA-256 suites can be completed. The other arms
    /// fail closed rather than approximate: RFC 8446 defines the SHA-384
    /// transcript as SHA-384 *of the handshake messages*, which cannot be
    /// recovered from a finished SHA-256 digest. `sendClientHello` already
    /// declines to offer these suites; this is the backstop for a server that
    /// selects one anyway.
    fn getTranscriptHash(self: *TlsClient) ![]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        if (hash_alg != .sha256) return error.UnsupportedCipherSuite;

        var transcript_copy = self.transcript;
        const result = try self.allocator.alloc(u8, hash_alg.digestSize());
        errdefer self.allocator.free(result);

        const final_hash = transcript_copy.final();
        @memcpy(result[0..32], &final_hash);
        return result;
    }

    /// The transcript digest at this point in the handshake.
    ///
    /// Copies the hasher rather than finalising it: the transcript continues
    /// through every message that follows, and `final` consumes the state. The
    /// return is by value so a captured boundary cannot later be read through a
    /// hasher that has moved past it.
    fn snapshotTranscript(self: *TlsClient) ![32]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        if (hash_alg != .sha256) return error.UnsupportedCipherSuite;
        var transcript_copy = self.transcript;
        return transcript_copy.final();
    }

    fn computeFinishedVerifyData(self: *TlsClient, is_client: bool) ![]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();

        const transcript_hash = try self.getTranscriptHash();
        defer self.allocator.free(transcript_hash);

        const secret = if (is_client)
            self.client_handshake_secret.?
        else
            self.server_handshake_secret.?;

        return tls.verifyData(self.allocator, hash_alg, &secret, transcript_hash);
    }

    /// The IKM for `deriveEarlySecret`: the resumption PSK when the server
    /// accepted one, otherwise null, which RFC 8446 Section 7.1 defines as a
    /// string of `Hash.length` zeroes.
    ///
    /// Both `deriveHandshakeSecrets` and `deriveApplicationSecrets` rebuild the
    /// key schedule from scratch, so both must start it the same way; the two
    /// disagreeing would surface as a Finished mismatch several steps later,
    /// pointing at neither of them.
    fn earlySecretIkm(self: *const TlsClient) ?[]const u8 {
        return if (self.psk) |*p| p[0..] else null;
    }

    fn deriveApplicationSecrets(self: *TlsClient) !void {
        // Initialize key schedule
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        var key_schedule = try tls.KeySchedule.init(self.allocator, hash_alg);
        defer key_schedule.deinit();

        // Reconstruct the key schedule
        try key_schedule.deriveEarlySecret(self.earlySecretIkm());
        try key_schedule.deriveHandshakeSecret(&self.shared_secret.?);
        try key_schedule.deriveMasterSecret();

        // RFC 8446 Section 7.1 bounds the application traffic secrets at
        // ClientHello..server Finished. That range closed before this endpoint
        // sent its own Finished, so the digest comes from the snapshot taken
        // then and not from the live transcript, which has since moved on.
        const app_transcript = self.server_finished_transcript orelse
            return error.MissingFinishedTranscript;

        const client_app_secret = try key_schedule.deriveSecretFromTranscriptHash(key_schedule.master_secret, "c ap traffic", &app_transcript);
        defer self.allocator.free(client_app_secret);

        const server_app_secret = try key_schedule.deriveSecretFromTranscriptHash(key_schedule.master_secret, "s ap traffic", &app_transcript);
        defer self.allocator.free(server_app_secret);

        // Copy secrets (truncate to 32 bytes for now)
        self.client_traffic_secret = std.mem.zeroes([32]u8);
        self.server_traffic_secret = std.mem.zeroes([32]u8);
        @memcpy(&self.client_traffic_secret.?, client_app_secret[0..32]);
        @memcpy(&self.server_traffic_secret.?, server_app_secret[0..32]);

        self.client_traffic_keys = try self.deriveTrafficKeys(self.client_traffic_secret.?, true);
        self.server_traffic_keys = try self.deriveTrafficKeys(self.server_traffic_secret.?, false);

        // Resumption master secret, RFC 8446 Section 7.1:
        //   Derive-Secret(Master Secret, "res master", ClientHello..client Finished)
        // One message further than the application secrets above, which is why
        // this takes the live transcript rather than reusing `app_transcript`.
        const res_transcript = try self.snapshotTranscript();
        const res_master = try key_schedule.deriveSecretFromTranscriptHash(key_schedule.master_secret, "res master", &res_transcript);
        defer {
            util.secureZero(res_master);
            self.allocator.free(res_master);
        }
        self.resumption_master_secret = std.mem.zeroes([32]u8);
        @memcpy(&self.resumption_master_secret.?, res_master[0..32]);
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
        self.transcriptUpdate(.encrypted_extensions, msg.data);

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
                @backingInt(ExtensionType.supported_versions),
                @backingInt(ExtensionType.key_share),
                @backingInt(ExtensionType.pre_shared_key),
                @backingInt(ExtensionType.psk_key_exchange_modes),
                @backingInt(ExtensionType.cookie),
                => return error.ForbiddenExtension,

                // ALPN - store selected protocol
                @backingInt(ExtensionType.application_layer_protocol_negotiation) => {
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
                @backingInt(ExtensionType.server_name) => {},

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
        self.transcriptUpdate(.certificate, msg.data);

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
        var certs: std.ArrayList(tls_config.Certificate) = .empty;
        errdefer {
            for (certs.items) |cert| {
                cert.deinit(self.allocator);
            }
            certs.deinit(self.allocator);
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
            try certs.append(self.allocator, cert);
        }

        if (certs.items.len == 0) {
            return error.EmptyCertificateChain;
        }

        // Store certificates
        self.server_certificates = try certs.toOwnedSlice(self.allocator);

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

    /// Verify a TLS 1.3 CertificateVerify signature (RFC 8446 §4.4.3) for the
    /// given SignatureScheme over `content`, using the certificate's raw
    /// `public_key` bytes. Mirrors the server-side signer in `tls_server.zig`.
    ///
    /// Supported, FIPS-aligned, stdlib-backed schemes:
    ///   - 0x0807 ed25519                → raw 64-byte signature, 32-byte key
    ///   - 0x0403 ecdsa_secp256r1_sha256 → DER signature, SEC1 public key
    ///   - 0x0503 ecdsa_secp384r1_sha384 → DER signature, SEC1 public key
    ///
    /// Returns false on any malformed input (fail-closed). This is a pure
    /// function (no connection state) so it is directly unit-testable.
    fn verifyCertVerifySignature(
        sig_algorithm: u16,
        signature: []const u8,
        public_key: []const u8,
        content: []const u8,
    ) bool {
        return switch (sig_algorithm) {
            0x0807 => blk: { // ed25519
                if (public_key.len != 32 or signature.len != 64) break :blk false;
                const pk: [32]u8 = public_key[0..32].*;
                const sig: [64]u8 = signature[0..64].*;
                break :blk asym.ed25519.verify(content, sig, pk);
            },
            // ecdsa_secp256r1_sha256: DER signature over SEC1 public key.
            0x0403 => asym.secp256r1.verifyMessageDer(content, signature, public_key),
            // ecdsa_secp384r1_sha384: DER signature over SEC1 public key.
            0x0503 => asym.secp384r1.verifyMessageDer(content, signature, public_key),
            else => false,
        };
    }

    const ParsedCertificateVerify = struct {
        sig_algorithm: u16,
        signature: []const u8,
    };

    fn parseCertificateVerify(data: []const u8) !ParsedCertificateVerify {
        if (data.len < 4) return error.InvalidCertificateVerify;

        const sig_algorithm = std.mem.readInt(u16, data[0..2], .big);
        const sig_len = std.mem.readInt(u16, data[2..4], .big);

        if (data.len != 4 + sig_len) return error.InvalidCertificateVerify;

        return .{
            .sig_algorithm = sig_algorithm,
            .signature = data[4..],
        };
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

        const parsed_verify = try parseCertificateVerify(msg.data);

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
        // Hash a copy: `final` consumes the hasher, and the handshake is not over
        // -- Finished still has to be computed over a transcript that continues
        // through this CertificateVerify.
        var transcript_copy = self.transcript;
        const transcript_hash = transcript_copy.final();

        var content: [64 + context_string.len + 1 + 32]u8 = undefined;
        @memset(content[0..64], 0x20); // 64 spaces
        @memcpy(content[64 .. 64 + context_string.len], context_string);
        content[64 + context_string.len] = 0x00;
        @memcpy(content[64 + context_string.len + 1 ..], &transcript_hash);

        // Verify signature based on algorithm. RSA-PSS (0x0804) and any unknown
        // scheme fall through to the else branch and are rejected as
        // unsupported — zcrypto does not ship an unvetted RSA verifier.
        const verified = switch (parsed_verify.sig_algorithm) {
            0x0807, 0x0403, 0x0503 => verifyCertVerifySignature(
                parsed_verify.sig_algorithm,
                parsed_verify.signature,
                parsed.public_key_info.public_key,
                &content,
            ),
            else => {
                std.log.warn("Unsupported signature algorithm: 0x{x:0>4}", .{parsed_verify.sig_algorithm});
                return error.UnsupportedSignatureAlgorithm;
            },
        };

        if (!verified) {
            return error.InvalidCertificateVerifySignature;
        }

        // NOW update transcript with the CertificateVerify message
        self.transcriptUpdate(.certificate_verify, msg.data);
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
        self.transcriptUpdate(.finished, msg.data);
    }

    fn sendFinished(self: *TlsClient) !void {
        const verify_data = try self.computeFinishedVerifyData(true);
        defer self.allocator.free(verify_data);

        // Update transcript with Finished message
        self.transcriptUpdate(.finished, verify_data);

        // Send Finished message
        try self.writeHandshakeMessage(.finished, verify_data);
    }

    // Extension writers
    fn writeSupportedVersionsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.supported_versions));
        try writeU16(buffer, self.allocator, 3); // Extension length
        try writeU8(buffer, self.allocator, 2); // Versions list length
        try writeU16(buffer, self.allocator, 0x0304); // TLS 1.3
    }

    fn writeServerNameExtension(self: *TlsClient, buffer: *std.ArrayList(u8), name: []const u8) !void {
        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.server_name));
        try writeU16(buffer, self.allocator, @intCast(name.len + 5));
        try writeU16(buffer, self.allocator, @intCast(name.len + 3)); // Server name list length
        try writeU8(buffer, self.allocator, 0); // Host name type
        try writeU16(buffer, self.allocator, @intCast(name.len));
        try writeBytes(buffer, self.allocator, name);
    }

    fn writeSupportedGroupsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.supported_groups));
        try writeU16(buffer, self.allocator, 4); // Extension length
        try writeU16(buffer, self.allocator, 2); // Groups list length
        try writeU16(buffer, self.allocator, 0x001d); // x25519
    }

    fn writeSignatureAlgorithmsExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.signature_algorithms));
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

        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.application_layer_protocol_negotiation));
        try writeU16(buffer, self.allocator, @intCast(proto_list.items.len + 2));
        try writeU16(buffer, self.allocator, @intCast(proto_list.items.len));
        try writeBytes(buffer, self.allocator, proto_list.items);
    }

    fn writeKeyShareExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        // RFC 8446 Section 4.2.8: a ClientHello key_share carries a
        // KeyShareClientHello, which is a length-prefixed *list* of entries.
        // One x25519 entry is group(2) + key_exchange length(2) + 32 = 36, so
        // the list prefix is 36 and the extension body is 2 + 36 = 38.
        //
        // Both numbers used to be two short, counted as though the entry began
        // at its key_exchange length. Nothing caught it because a ClientHello
        // this client built had never been handed to a parser: the server's
        // key_share arm bounds-checks and silently skips a short entry, so the
        // handshake failed later at key exchange with a missing peer key rather
        // than here, and the two-byte shortfall desynchronised every extension
        // that followed.
        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.key_share));
        try writeU16(buffer, self.allocator, 38); // Extension length
        try writeU16(buffer, self.allocator, 36); // Client shares length
        try writeU16(buffer, self.allocator, 0x001d); // x25519
        try writeU16(buffer, self.allocator, 32); // Key length

        // Use real public key from generated key share
        if (self.client_key_share) |keypair| {
            try writeBytes(buffer, self.allocator, &keypair.public_key);
        } else {
            return error.NoKeyShare;
        }
    }

    /// The number of bytes a single-identity `binders` list occupies, counting
    /// the one-byte per-binder length but not the two-byte list prefix. This is
    /// the value the list prefix carries, and the same number
    /// `tls.clientHelloBinderPrefix` truncates from.
    const single_binder_list_len: usize = 1 + 32;

    /// The session this ClientHello should offer, or null for a full handshake.
    ///
    /// A session whose suite hashes with anything but SHA-256 is silently not
    /// offered rather than rejected: RFC 8446 Section 4.2.11 only permits
    /// resumption under a matching hash, this client offers SHA-256 suites
    /// exclusively (see `sendClientHello`), and a mismatched session therefore
    /// could never be accepted. Declining to offer it costs a resumption;
    /// offering it would invite a server to key off a PSK from a different key
    /// schedule.
    fn pskOffer(self: *const TlsClient) ?*const ResumptionSession {
        const session = self.offered_session orelse return null;
        if (session.cipher_suite.hashAlgorithm() != .sha256) return null;
        return session;
    }

    /// RFC 8446 Section 4.2.9. Only `psk_dhe_ke` (1) is offered: bare `psk_ke`
    /// resumes without a fresh key exchange, so the resumed connection would
    /// inherit the original's secrecy rather than having its own.
    fn writePskKeyExchangeModesExtension(self: *TlsClient, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.psk_key_exchange_modes));
        try writeU16(buffer, self.allocator, 2);
        try writeU8(buffer, self.allocator, 1); // one mode
        try writeU8(buffer, self.allocator, 1); // psk_dhe_ke
    }

    /// RFC 8446 Section 4.2.11, with the binder left zeroed for `fillPskBinder`.
    ///
    /// One identity is offered. Several would be legal, but each needs its own
    /// binder over the same transcript, and every additional identity is another
    /// ticket handed to whoever is listening in exchange for a chance at one
    /// fewer round trip.
    fn writePreSharedKeyExtension(self: *TlsClient, buffer: *std.ArrayList(u8), session: *const ResumptionSession) !void {
        const identities_len = 2 + session.ticket.len + 4;
        const ext_len = 2 + identities_len + 2 + single_binder_list_len;

        try writeU16(buffer, self.allocator, @backingInt(ExtensionType.pre_shared_key));
        try writeU16(buffer, self.allocator, @intCast(ext_len));

        try writeU16(buffer, self.allocator, @intCast(identities_len));
        try writeU16(buffer, self.allocator, @intCast(session.ticket.len));
        try writeBytes(buffer, self.allocator, session.ticket);
        // Obfuscated ticket age, RFC 8446 Section 4.2.11.1: elapsed
        // milliseconds plus the server's `ticket_age_add`. The elapsed term is
        // zero because this client has no clock wired in. That is honest for
        // this pairing -- the server judges freshness from the timestamp sealed
        // inside the ticket, which a client cannot influence -- but a server
        // using this field for 0-RTT anti-replay would need a real age here,
        // and this client offers no early data for exactly that reason.
        try writeU32(buffer, self.allocator, session.ticket_age_add);

        try writeU16(buffer, self.allocator, @intCast(single_binder_list_len));
        try writeU8(buffer, self.allocator, 32);
        const placeholder = std.mem.zeroes([32]u8);
        try writeBytes(buffer, self.allocator, &placeholder);
    }

    /// Compute the binder over the assembled ClientHello and write it into the
    /// placeholder at the end.
    ///
    /// `body` is the complete ClientHello body, binders included; the binder is
    /// its final 32 bytes. `tls.clientHelloBinderTranscript` does the truncation
    /// and restores the handshake header carrying the *untruncated* length,
    /// which is the part that cannot be checked against this repository's own
    /// server -- both sides would make the same mistake and agree. It is pinned
    /// against RFC 8448 Section 4 in `known_answer_vectors.zig` instead.
    fn fillPskBinder(self: *TlsClient, body: []u8, session: *const ResumptionSession) !void {
        const transcript = try tls.clientHelloBinderTranscript(body, single_binder_list_len);

        var ks = try tls.KeySchedule.init(self.allocator, .sha256);
        defer ks.deinit();
        try ks.deriveEarlySecret(&session.psk);

        const binder_key = try ks.resumptionBinderKey();
        defer {
            util.secureZero(binder_key);
            self.allocator.free(binder_key);
        }

        const binder = try tls.verifyData(self.allocator, .sha256, binder_key, &transcript);
        defer {
            util.secureZero(binder);
            self.allocator.free(binder);
        }

        if (binder.len != 32) return error.InvalidHandshake;
        @memcpy(body[body.len - 32 ..], binder);

        // Held so the key schedule can start from the same PSK. The server only
        // confirms its choice in ServerHello, so this is provisional: if no
        // `pre_shared_key` comes back, `receiveServerHello` clears it and the
        // handshake proceeds as a full one.
        self.psk = session.psk;
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
        header[0] = @backingInt(record_type);
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
        inner_plaintext[data.len] = @backingInt(record_type);

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
        aad[0] = @backingInt(RecordType.application_data); // Outer type is always application_data
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

        const outer_type = std.enums.fromInt(RecordType, header[0]) orelse {
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
        const inner_type = std.enums.fromInt(RecordType, plaintext[content_end - 1]) orelse {
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

    /// Feed one complete handshake message into the transcript. See
    /// `tls.transcriptUpdate` for why the four-byte header is part of the hash.
    fn transcriptUpdate(self: *TlsClient, msg_type: HandshakeType, body: []const u8) void {
        tls.transcriptUpdate(&self.transcript, @backingInt(msg_type), body);
    }

    fn writeHandshakeMessage(self: *TlsClient, msg_type: HandshakeType, data: []const u8) !void {
        // Build handshake header: 1 byte type + 3 bytes length (u24 big endian)
        var header: [4]u8 = undefined;
        header[0] = @backingInt(msg_type);
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

        const msg_type = std.enums.fromInt(HandshakeType, record.data[0]) orelse {
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

test "CertificateVerify verifier: Ed25519 accepts valid, rejects tampered" {
    const kp = asym.ed25519.generate();
    const content = "TLS 1.3, server CertificateVerify content (ed25519)";
    const sig = try asym.ed25519.sign(content, kp.private_key);

    try std.testing.expect(TlsClient.verifyCertVerifySignature(0x0807, &sig, &kp.public_key, content));
    // Tampered content fails closed.
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0807, &sig, &kp.public_key, "different"));
    // Wrong-length signature fails closed (no crash).
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0807, sig[0..32], &kp.public_key, content));
}

test "CertificateVerify verifier: ECDSA P-256 accepts valid DER, rejects tampered" {
    const kp = asym.secp256r1.generate();
    const content = "TLS 1.3, server CertificateVerify content (p256)";
    var der_buf: [asym.secp256r1.DER_SIGNATURE_MAX]u8 = undefined;
    const sig = try asym.secp256r1.signMessageDer(content, kp.private_key, &der_buf);

    try std.testing.expect(TlsClient.verifyCertVerifySignature(0x0403, sig, &kp.public_key, content));
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0403, sig, &kp.public_key, "different"));

    const bad_der = [_]u8{ 0x30, 0x00, 0x01, 0x02 };
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0403, &bad_der, &kp.public_key, content));
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0403, sig, kp.public_key[0..16], content));
}

test "CertificateVerify verifier: ECDSA P-384 accepts valid DER, rejects tampered" {
    const kp = asym.secp384r1.generate();
    const content = "TLS 1.3, server CertificateVerify content (p384)";
    var der_buf: [asym.secp384r1.DER_SIGNATURE_MAX]u8 = undefined;
    const sig = try asym.secp384r1.signMessageDer(content, kp.private_key, &der_buf);

    try std.testing.expect(TlsClient.verifyCertVerifySignature(0x0503, sig, &kp.public_key, content));
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0503, sig, &kp.public_key, "different"));

    const bad_der = [_]u8{ 0x30, 0x00, 0x01, 0x02 };
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0503, &bad_der, &kp.public_key, content));
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0503, sig, kp.public_key[0..16], content));
}

test "CertificateVerify verifier: unknown/RSA scheme rejected" {
    const content = "x";
    const sig = std.mem.zeroes([64]u8);
    const pk = std.mem.zeroes([32]u8);
    // RSA-PSS (0x0804) and unknown schemes are not supported → false.
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0x0804, &sig, &pk, content));
    try std.testing.expect(!TlsClient.verifyCertVerifySignature(0xFFFF, &sig, &pk, content));
}

test "CertificateVerify parser requires exact signature length" {
    const valid = [_]u8{ 0x08, 0x07, 0x00, 0x02, 0xaa, 0xbb };
    const parsed = try TlsClient.parseCertificateVerify(&valid);
    try std.testing.expectEqual(@as(u16, 0x0807), parsed.sig_algorithm);
    try std.testing.expectEqualSlices(u8, valid[4..], parsed.signature);

    const too_short_header = [_]u8{ 0x08, 0x07, 0x00 };
    try std.testing.expectError(error.InvalidCertificateVerify, TlsClient.parseCertificateVerify(&too_short_header));

    const truncated = [_]u8{ 0x08, 0x07, 0x00, 0x03, 0xaa, 0xbb };
    try std.testing.expectError(error.InvalidCertificateVerify, TlsClient.parseCertificateVerify(&truncated));

    const trailing = [_]u8{ 0x08, 0x07, 0x00, 0x01, 0xaa, 0xbb };
    try std.testing.expectError(error.InvalidCertificateVerify, TlsClient.parseCertificateVerify(&trailing));
}

/// A client with no socket behind it, positioned just after the client's
/// Finished went out. Enough state for the application-phase derivation and
/// nothing else; `deinit` never touches the stream or the io runtime, so
/// leaving them undefined is safe for the duration of this test.
fn transcriptTestClient(allocator: std.mem.Allocator) TlsClient {
    return TlsClient{
        .config = tls_config.TlsConfig.init(allocator),
        .stream = undefined,
        .io = undefined,
        .transcript = hash.Sha256.init(),
        .client_random = std.mem.zeroes([32]u8),
        .server_random = std.mem.zeroes([32]u8),
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .shared_secret = @splat(0x99),
        .allocator = allocator,
    };
}

test "every client secret is derived at its own transcript boundary" {
    const allocator = std.testing.allocator;
    var client = transcriptTestClient(allocator);
    defer client.deinit();

    // Three distinct transcript states, one per RFC 8446 Section 7.1 boundary:
    // ClientHello..ServerHello for the handshake traffic secrets,
    // ClientHello..server Finished for the application traffic secrets, and
    // ClientHello..client Finished for the resumption master secret. The
    // strings fed here stand in for the messages between them; all that matters
    // is that the three digests differ, so a derivation reaching for the wrong
    // one cannot accidentally agree.
    const peer = asym.generateCurve25519();
    client.client_key_share = asym.generateCurve25519();
    client.server_public_key = peer.public_key;

    client.transcript.update("ServerHello");
    const at_server_hello = try client.snapshotTranscript();
    try client.deriveHandshakeSecrets();

    client.transcript.update("server Finished");
    const at_server_finished = try client.snapshotTranscript();
    client.server_finished_transcript = at_server_finished;

    client.transcript.update("client Finished");
    const at_client_finished = try client.snapshotTranscript();
    try client.deriveApplicationSecrets();

    try std.testing.expect(!std.mem.eql(u8, &at_server_hello, &at_server_finished));
    try std.testing.expect(!std.mem.eql(u8, &at_server_finished, &at_client_finished));

    // Recompute each secret from the boundary it belongs to and assert the
    // client produced exactly that. Equality is what gives this teeth: it fails
    // if the transcript is hashed a second time on the way in, and it fails if
    // the wrong boundary is used. A client and a server running this same code
    // agree with each other in either case, so nothing but an explicit
    // assertion against an independently recomputed value catches it.
    var ks = try tls.KeySchedule.init(allocator, .sha256);
    defer ks.deinit();
    try ks.deriveEarlySecret(null);
    try ks.deriveHandshakeSecret(&client.shared_secret.?);
    try ks.deriveMasterSecret();

    const Expect = struct {
        secret: []const u8,
        label: []const u8,
        right: *const [32]u8,
        wrong: *const [32]u8,
        got: *const [32]u8,
    };
    const cases = [_]Expect{
        .{ .secret = ks.handshake_secret, .label = "c hs traffic", .right = &at_server_hello, .wrong = &at_server_finished, .got = &client.client_handshake_secret.? },
        .{ .secret = ks.handshake_secret, .label = "s hs traffic", .right = &at_server_hello, .wrong = &at_server_finished, .got = &client.server_handshake_secret.? },
        .{ .secret = ks.master_secret, .label = "c ap traffic", .right = &at_server_finished, .wrong = &at_client_finished, .got = &client.client_traffic_secret.? },
        .{ .secret = ks.master_secret, .label = "s ap traffic", .right = &at_server_finished, .wrong = &at_client_finished, .got = &client.server_traffic_secret.? },
        .{ .secret = ks.master_secret, .label = "res master", .right = &at_client_finished, .wrong = &at_server_finished, .got = &client.resumption_master_secret.? },
    };

    for (cases) |case| {
        const right = try ks.deriveSecretFromTranscriptHash(case.secret, case.label, case.right);
        defer allocator.free(right);
        try std.testing.expectEqualSlices(u8, right, case.got);

        const swapped = try ks.deriveSecretFromTranscriptHash(case.secret, case.label, case.wrong);
        defer allocator.free(swapped);
        try std.testing.expect(!std.mem.eql(u8, swapped, case.got));

        // The transcript is already a digest. Hashing it again yields a secret
        // no conforming peer will ever derive.
        const double_hashed = try ks.deriveSecret(case.secret, case.label, case.right);
        defer allocator.free(double_hashed);
        try std.testing.expect(!std.mem.eql(u8, double_hashed, case.got));
    }
}

test "the client refuses application secrets without the server Finished boundary" {
    const allocator = std.testing.allocator;
    var client = transcriptTestClient(allocator);
    defer client.deinit();

    // The application secrets are bound to ClientHello..server Finished, a
    // boundary the live transcript has already passed by the time this runs.
    // Without the snapshot there is no honest way to reach it, so the
    // derivation refuses rather than substituting the transcript it can see.
    try std.testing.expectError(error.MissingFinishedTranscript, client.deriveApplicationSecrets());
}
