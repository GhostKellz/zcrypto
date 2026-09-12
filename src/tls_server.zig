//! TLS Server Implementation
//!
//! Provides a high-level TLS server API for accepting secure connections
//! using TLS 1.3 with optional TLS 1.2 support.

const std = @import("std");
const builtin = @import("builtin");
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
const errors = @import("errors.zig");
const net = std.Io.net;

/// How long a session ticket stays valid, in seconds.
///
/// One name for two uses that must agree: the `ticket_lifetime` advertised in
/// NewSessionTicket and the age bound enforced when a ticket comes back. They
/// were separate literals, so lowering the advertised value would have left the
/// server still honouring week-old tickets. 7 days is the RFC 8446 section 4.6.1
/// ceiling.
const ticket_lifetime_s: u32 = 7 * 24 * 60 * 60;

/// Whether a ticket stamped `issued_s` is still within its lifetime at `now_s`.
///
/// Split out of `decryptSessionTicket` so the bound can be asserted at chosen
/// times: the caller reads an ambient clock, so in-place this branch is only
/// exercisable by waiting a week. That is how the check came to be skipped
/// entirely whenever the clock read failed, with every test still passing.
///
/// Saturating rather than wrapping. The stamp is AEAD-authenticated under a
/// server-only key so it is not attacker-chosen, but a near-max value must not
/// wrap the sum into the past and report an expired ticket as fresh.
///
/// A ticket stamped in the future is treated as fresh. Issue and validation are
/// the same server, so the gap is clock adjustment rather than forgery, and it
/// closes on its own as the clock advances.
fn ticketFresh(now_s: u64, issued_s: u64) bool {
    return now_s <= issued_s +| ticket_lifetime_s;
}

/// The realtime clock as the session-ticket paths see it.
///
/// A function pointer rather than a direct `util.getCurrentUnixTime` call so the
/// unreadable and negative branches can be asserted. Those branches decide
/// whether a ticket is minted and whether one is honoured, and in place they are
/// only reachable on a host whose clock is genuinely broken. That is how the
/// expiry check came to be skipped in exactly the case where it could not be
/// evaluated, with the whole suite still green.
pub const Clock = *const fn () ?i64;

fn systemClock() ?i64 {
    return util.getCurrentUnixTime();
}

/// Server-owned key material protecting session tickets.
///
/// A session ticket is a resumption credential the server hands to a peer and
/// later reads back; nothing but this server may open one. The protection key
/// therefore has to be owned secret state -- drawn from entropy, held by the
/// listener, shared by every connection it accepts.
///
/// It used to be `SHA256(server_random || "zcrypto_ticket_key_v1")`. Both inputs
/// are public: `server_random` is sent in the clear in ServerHello, and the label
/// is in this source file. Anyone who saw the handshake could derive the
/// "server-only" key, so encrypting the ticket under it protected nothing.
///
/// Two slots, rotated on the ticket lifetime. A ticket minted at `t` under a key
/// created at `c` satisfies `c <= t < c + lifetime`, and is presented at
/// `v <= t + lifetime < c + 2 * lifetime`. Holding the current key plus one
/// predecessor therefore covers every ticket still inside its advertised
/// lifetime, while retiring key material at a bounded age of two lifetimes: no
/// unbounded ring of keys, and nothing kept for ever.
pub const SessionTicketKeys = struct {
    /// Length of the identifier naming which key a ticket was minted under.
    ///
    /// It travels in the clear at the front of the ticket -- the server has to
    /// read it before it can pick a key to authenticate with -- and is covered by
    /// the AEAD's associated data, because it selects a key and so must not be
    /// swappable unnoticed. Random rather than a counter, so it carries no
    /// rotation history.
    pub const id_len = 16;

    pub const Key = struct {
        id: [id_len]u8,
        secret: [32]u8,
        created_s: u64,

        fn generate(now_s: u64) !Key {
            var key: Key = .{ .id = undefined, .secret = undefined, .created_s = now_s };
            errdefer util.secureZero(&key.secret);
            try rand.fillChecked(&key.id);
            try rand.fillChecked(&key.secret);
            return key;
        }
    };

    /// Guards `current` and `previous`.
    ///
    /// Every connection a listener accepts borrows the same instance, and a
    /// server that accepts on more than one thread will have them minting and
    /// reopening tickets at the same moment. `issuing` can rotate, which
    /// replaces both slots and zeroes a secret, so unsynchronised access is not
    /// merely stale -- it can read a key while it is being overwritten.
    ///
    /// Locked uncancelably. A cancellation landing between promoting `current`
    /// and installing the fresh key would leave the listener holding two copies
    /// of one key and no predecessor, silently voiding every ticket still inside
    /// its advertised lifetime.
    mutex: std.Io.Mutex = .init,
    current: Key,
    previous: ?Key,

    pub fn init(now_s: u64) !SessionTicketKeys {
        return .{ .current = try Key.generate(now_s), .previous = null };
    }

    /// Wipe both slots. The caller must have stopped handing this instance to
    /// new connections and joined the ones still holding it; a listener does
    /// that by calling this from `close`. The lock orders this against a ticket
    /// operation already in flight, but it cannot rescue a borrow that outlives
    /// the owner -- that is a use-after-free no amount of locking addresses.
    pub fn deinit(self: *SessionTicketKeys, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        util.secureZero(&self.current.secret);
        if (self.previous) |*p| util.secureZero(&p.secret);
        self.previous = null;
    }

    /// The key to mint under at `now_s`, rotating first if the current one has
    /// served its period.
    ///
    /// Returns a copy rather than a pointer into the struct. A pointer would
    /// stay valid only until the next rotation on any other thread, and the
    /// caller holds it across a ticket seal. The copy carries a secret, so the
    /// caller owns wiping it.
    pub fn issuing(self: *SessionTicketKeys, io: std.Io, now_s: u64) !Key {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (now_s >= self.current.created_s +| ticket_lifetime_s) try self.rotateLocked(now_s);
        return self.current;
    }

    /// Promote the current key and draw a fresh one.
    pub fn rotate(self: *SessionTicketKeys, io: std.Io, now_s: u64) !void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.rotateLocked(now_s);
    }

    /// The outgoing predecessor is wiped here rather than left to `deinit`: it is
    /// past the age at which any ticket it protects can still be honoured, so
    /// keeping it readable only widens what a memory disclosure yields.
    ///
    /// Separate from `rotate` because `issuing` already holds the lock and the
    /// mutex is not recursive -- calling the public entry point from inside the
    /// critical section would deadlock the accepting thread.
    fn rotateLocked(self: *SessionTicketKeys, now_s: u64) !void {
        const fresh = try Key.generate(now_s);
        if (self.previous) |*p| util.secureZero(&p.secret);
        self.previous = self.current;
        self.current = fresh;
    }

    /// The key `id` names, if it is still within its retirement bound at `now_s`.
    ///
    /// The comparison is not constant time and does not need to be: the id is
    /// public, carried in the clear at the front of every ticket.
    ///
    /// Returns a copy, for the same reason `issuing` does: the caller holds it
    /// across a ticket open, and a concurrent rotation would otherwise pull the
    /// key out from under it. The copy carries a secret, so the caller owns
    /// wiping it.
    pub fn lookup(self: *SessionTicketKeys, io: std.Io, id: [id_len]u8, now_s: u64) ?Key {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (std.mem.eql(u8, &self.current.id, &id) and !retired(self.current, now_s)) {
            return self.current;
        }
        if (self.previous) |p| {
            if (std.mem.eql(u8, &p.id, &id) and !retired(p, now_s)) return p;
        }
        return null;
    }

    fn retired(key: Key, now_s: u64) bool {
        return now_s > key.created_s +| (2 * @as(u64, ticket_lifetime_s));
    }
};

/// Ticket format version, first two bytes of every ticket.
///
/// Bumped from 1: the layout, the key derivation and the sealed content all
/// changed, and a v1 ticket must not be reinterpreted under the new rules.
const ticket_version: u16 = 0x0002;

/// version || ticket key id || AEAD nonce, all in the clear and all authenticated.
const ticket_header_len = 2 + SessionTicketKeys.id_len + 12;

/// cipher suite || per-ticket PSK || issue time, all sealed.
const ticket_plaintext_len = 2 + 32 + 8;

/// The listener's ticket keys, or null when session tickets are disabled.
///
/// Split out of `listen` so the decision can be exercised without binding a
/// socket. Two things are being decided here and both are load-bearing: that
/// keys exist at all when tickets are enabled -- a null would silently disable
/// resumption rather than fail -- and that a listener refuses to start when the
/// clock cannot be read, since every ticket it would mint carries an issue time
/// that freshness is later checked against.
/// Heap-allocated rather than stored inline in the listener, and this is the
/// point of it: `listen` returns a `TlsServer` by value, so the struct a caller
/// ends up holding is a copy of the one built here. Every connection borrows
/// these keys for as long as it lives. Inline, that borrow would point into
/// whichever copy of the listener happened to produce it, and would dangle the
/// moment the caller moved the server -- returned it up a frame, pushed it into
/// a list that grew. Behind a pointer the keys have an address of their own,
/// and moving the listener moves only the pointer.
fn initTicketKeys(allocator: std.mem.Allocator, config: tls_config.TlsConfig, clock: Clock) !?*SessionTicketKeys {
    if (!config.enable_session_tickets) return null;
    const now_s = clock() orelse return error.ClockUnavailable;
    if (now_s < 0) return error.ClockUnavailable;

    const keys = try allocator.create(SessionTicketKeys);
    errdefer allocator.destroy(keys);
    keys.* = try SessionTicketKeys.init(@intCast(now_s));
    return keys;
}

/// TLS server listener
pub const TlsServer = struct {
    /// Configuration
    config: tls_config.TlsConfig,
    /// Underlying network listener
    listener: net.Server,
    /// Io runtime
    io_runtime: std.Io.Threaded,
    /// Session-ticket protection keys, shared by every connection this listener
    /// accepts. Null when session tickets are disabled.
    ///
    /// Owned by the listener and freed in `close`. Connections borrow it, so
    /// `close` must not run until every connection this listener accepted has
    /// finished: a borrow outliving the owner is a use-after-free, not a stale
    /// read. Being behind a pointer makes the listener itself movable, which is
    /// what `listen` returning by value requires.
    ticket_keys: ?*SessionTicketKeys,
    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize a new TLS server
    pub fn listen(allocator: std.mem.Allocator, address: []const u8, port: u16, config: tls_config.TlsConfig) !TlsServer {
        try config.validate();

        // Ensure server has certificates
        if (config.certificates == null or config.private_key == null) {
            return error.MissingServerCertificate;
        }

        const ticket_keys = try initTicketKeys(allocator, config, systemClock);
        var io_runtime = std.Io.Threaded.init(allocator, .{ .environ = .empty });
        const io = io_runtime.io();

        errdefer if (ticket_keys) |keys| {
            keys.deinit(io);
            allocator.destroy(keys);
        };

        const addr = try net.IpAddress.parse(address, port);
        const listener = try addr.listen(io, .{
            .reuse_address = true,
        });

        return TlsServer{
            .config = config,
            .listener = listener,
            .io_runtime = io_runtime,
            .ticket_keys = ticket_keys,
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
            .ticket_keys = self.connectionTicketKeys(),
            .allocator = self.allocator,
        };

        // Perform handshake
        try tls_conn.handshake();

        return tls_conn;
    }

    /// The ticket keys every accepted connection borrows.
    ///
    /// The same instance for all of them, not a copy each: the whole point of
    /// server-owned ticket keys is that a ticket minted on one connection opens
    /// on another, and rotation performed by one connection is seen by the rest.
    /// Copying per connection would compile and pass every single-connection
    /// test while quietly making resumption work only against the connection
    /// that issued the ticket.
    fn connectionTicketKeys(self: *TlsServer) ?*SessionTicketKeys {
        return self.ticket_keys;
    }

    /// Close the server.
    ///
    /// This frees the ticket keys every connection this listener accepted is
    /// borrowing, so it must not run while any of them is still alive.
    pub fn close(self: *TlsServer) void {
        const io = self.io_runtime.io();
        self.listener.deinit(io);
        self.io_runtime.deinit();
        if (self.ticket_keys) |keys| {
            keys.deinit(io);
            self.allocator.destroy(keys);
        }
        self.ticket_keys = null;
    }

    /// The address the listener is actually bound to.
    ///
    /// Resolved rather than requested: binding port 0 reports the ephemeral port
    /// the OS chose, which is the case callers need this for.
    pub fn getAddress(self: TlsServer) net.IpAddress {
        return self.listener.socket.address;
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
    /// Resumption master secret (RFC 8446 Section 7.1). The input every ticket's
    /// PSK is derived from, and the only secret a ticket is allowed to descend
    /// from -- an application traffic secret protects live records and must never
    /// leave in a credential.
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
    /// The PSK this handshake resumed under, once a ticket has been reopened
    /// *and* its binder verified. Null means a full handshake, which is what
    /// every rejection path leaves behind: a ticket that does not decrypt, a
    /// binder that does not match, or a client that did not offer `psk_dhe_ke`
    /// all fall back rather than failing the connection.
    ///
    /// Set only by `selectPreSharedKey`, and only after the binder check, so
    /// that "this field is populated" and "the client proved possession" cannot
    /// come apart.
    psk: ?[32]u8 = null,
    /// Index into the client's `identities` list of the ticket that was accepted,
    /// echoed back in ServerHello. Non-null exactly when `psk` is.
    selected_psk_identity: ?u16 = null,
    /// The client's `legacy_session_id`, kept so ServerHello can echo it.
    ///
    /// RFC 8446 Section 4.1.3 requires the echo to be verbatim, and a client is
    /// entitled to abort when it is not. This server used to send 32 fresh
    /// random bytes instead, which no test caught because no client had ever
    /// read a ServerHello this server produced.
    legacy_session_id: [32]u8 = undefined,
    legacy_session_id_len: u8 = 0,
    /// Session resumption
    session_ticket: ?[]u8 = null,
    /// Session-ticket protection keys, owned by the listener that accepted this
    /// connection. Borrowed, never freed here.
    ticket_keys: ?*SessionTicketKeys = null,
    /// Clock the session-ticket paths read.
    clock: Clock = systemClock,
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

        // Certificate and CertificateVerify, unless this handshake resumed.
        // RFC 8446 Section 4.4.2: the server sends no certificate when it has
        // authenticated via PSK, because possession of the ticket's PSK is the
        // authentication. Sending one anyway would put messages in the
        // transcript the client does not expect, so the two sides would disagree
        // at Finished.
        if (self.psk == null) {
            try self.sendCertificate();
            self.handshake_state = .sent_certificate;

            try self.sendCertificateVerify();
            self.handshake_state = .sent_certificate_verify;
        }

        // Send Finished
        try self.sendFinished();
        self.handshake_state = .sent_finished;

        // RFC 8446 Section 7.1 derives the application traffic secrets over
        // ClientHello..server Finished. That range closes here, one message
        // before the client's Finished arrives, so the digest has to be taken
        // now rather than reconstructed later from a transcript that has moved
        // on. The resumption master secret runs to ClientHello..client Finished
        // and is taken further down, from the live transcript.
        self.server_finished_transcript = try self.snapshotTranscript();

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
                    const level = @as(tls_client.AlertLevel, @fromBackingInt(@intCast(record.data[0])));
                    const desc = @as(tls_client.AlertDescription, @fromBackingInt(@intCast(record.data[1])));

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
            const alert = [_]u8{ @backingInt(tls_client.AlertLevel.warning), @backingInt(tls_client.AlertDescription.close_notify) };
            try self.writeRecord(.alert, &alert);
        }

        self.handshake_state = .closed;
        self.stream.close(self.io);
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
        if (self.resumption_master_secret) |*secret| util.secureZero(secret);
        if (self.psk) |*secret| util.secureZero(secret);

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

        try self.parseClientHello(msg.data);
    }

    /// Negotiate from a ClientHello body, and enter it into the transcript.
    ///
    /// Split from `receiveClientHello` so a message can be fed in without a
    /// socket. That matters most for the PSK offer: the binder is a MAC over
    /// these bytes, and the only way to show that this server's truncation
    /// agrees with the client's is to run a real client's real ClientHello
    /// through this real parser.
    fn parseClientHello(self: *TlsConnection, body: []const u8) !void {
        // Parse ClientHello using manual buffer position tracking
        var pos: usize = 0;

        // Legacy version (2 bytes)
        if (pos + 2 > body.len) return error.TruncatedMessage;
        _ = std.mem.readInt(u16, body[pos..][0..2], .big);
        pos += 2;

        // Client random (32 bytes)
        if (pos + 32 > body.len) return error.TruncatedMessage;
        @memcpy(&self.client_random, body[pos..][0..32]);
        pos += 32;

        // Session ID
        if (pos + 1 > body.len) return error.TruncatedMessage;
        const session_id_len = body[pos];
        pos += 1;
        // RFC 8446 Section 4.1.2 bounds this vector at 32; a longer one cannot
        // be echoed and is not a session id this server will invent room for.
        if (session_id_len > 32) return error.InvalidHandshake;
        if (session_id_len > 0) {
            if (pos + session_id_len > body.len) return error.TruncatedMessage;
            @memcpy(self.legacy_session_id[0..session_id_len], body[pos .. pos + session_id_len]);
            pos += session_id_len;
        }
        self.legacy_session_id_len = session_id_len;

        // Cipher suites
        if (pos + 2 > body.len) return error.TruncatedMessage;
        const cipher_suites_len = std.mem.readInt(u16, body[pos..][0..2], .big);
        pos += 2;
        const num_suites = cipher_suites_len / 2;

        // Select a cipher suite
        var selected = false;
        var i: usize = 0;
        while (i < num_suites) : (i += 1) {
            if (pos + 2 > body.len) return error.TruncatedMessage;
            const suite_value = std.mem.readInt(u16, body[pos..][0..2], .big);
            pos += 2;
            const suite: tls_config.CipherSuite = switch (suite_value) {
                0x1301 => .TLS_AES_128_GCM_SHA256,
                0x1302 => .TLS_AES_256_GCM_SHA384,
                0x1303 => .TLS_CHACHA20_POLY1305_SHA256,
                else => continue,
            };

            // The handshake transcript is SHA-256 only (see `getTranscriptHash`),
            // so a SHA-384 suite cannot be served even if it is configured.
            // Skipping it here means an unservable suite shows up as
            // NoCipherSuiteMatch during negotiation rather than as a Finished
            // verify-data mismatch after the key schedule has already run.
            if (suite.hashAlgorithm() != .sha256) continue;

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
            if (pos + skip_len > body.len) return error.TruncatedMessage;
            pos += skip_len;
        }

        // Compression methods
        if (pos + 1 > body.len) return error.TruncatedMessage;
        const compression_len = body[pos];
        pos += 1;
        if (compression_len > 0) {
            if (pos + compression_len > body.len) return error.TruncatedMessage;
            pos += compression_len;
        }

        // Parse extensions
        if (pos + 2 > body.len) return error.TruncatedMessage;
        const extensions_len = std.mem.readInt(u16, body[pos..][0..2], .big);
        pos += 2;
        const extensions_start = pos;
        const extensions_end = extensions_start + extensions_len;

        // PSK offer, collected here and acted on after the loop: the binder
        // covers the ClientHello up to the binders list, so it cannot be checked
        // until the message has been walked far enough to know where that is.
        var psk_ext: ?[]const u8 = null;
        var psk_ext_last = false;
        var psk_dhe_ke = false;

        while (pos < extensions_end) {
            if (pos + 4 > body.len) return error.TruncatedMessage;
            const ext_type = std.mem.readInt(u16, body[pos..][0..2], .big);
            pos += 2;
            const ext_len = std.mem.readInt(u16, body[pos..][0..2], .big);
            pos += 2;

            if (pos + ext_len > body.len) return error.TruncatedMessage;
            const ext_data = body[pos .. pos + ext_len];

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
                                    self.client_public_key = std.mem.zeroes([32]u8);
                                    @memcpy(&self.client_public_key.?, ext_data[offset + 4 .. offset + 4 + key_len]);
                                    break; // Use first X25519 key share
                                }

                                offset += 4 + key_len;
                            }
                        }
                    },
                    .psk_key_exchange_modes => {
                        // RFC 8446 Section 4.2.9. Only `psk_dhe_ke` (1) is
                        // acceptable: this server always performs ECDHE, and
                        // resuming under bare `psk_ke` (0) would drop forward
                        // secrecy for the resumed connection.
                        if (ext_data.len >= 1) {
                            const modes_len = ext_data[0];
                            if (1 + @as(usize, modes_len) <= ext_data.len) {
                                for (ext_data[1 .. 1 + modes_len]) |mode| {
                                    if (mode == 1) psk_dhe_ke = true;
                                }
                            }
                        }
                    },
                    .pre_shared_key => {
                        psk_ext = ext_data;
                        // RFC 8446 Section 4.2.11 requires this to be the last
                        // extension, which is what makes the binder region a
                        // prefix of the message. If it is not last, the bytes
                        // the client signed and the bytes the server would hash
                        // are different regions, so the offer is unusable.
                        psk_ext_last = pos + ext_len == extensions_end;
                    },
                    // Unhandled extensions - ignore them
                    .supported_groups, .signature_algorithms, .early_data, .supported_versions, .cookie, .certificate_authorities => {},
                }
            }

            pos += ext_len;
        }

        if (psk_ext) |ext| {
            if (psk_dhe_ke and psk_ext_last) try self.selectPreSharedKey(body, ext);
        }

        // Update transcript
        self.transcriptUpdate(.client_hello, body);
    }

    /// Accept a PSK offer, or leave the handshake as a full one.
    ///
    /// RFC 8446 Section 4.2.11. Walks the client's `identities`, reopens each as
    /// a session ticket, and accepts the first whose binder verifies. Sets
    /// `self.psk` and `self.selected_psk_identity` only on success.
    ///
    /// Every rejection is a plain return, not an error: an offer this server
    /// cannot honour must degrade to a full handshake, never abort the
    /// connection and never proceed on an unverified PSK. A stale, tampered or
    /// foreign ticket costs the client one extra round trip; the alternative
    /// costs authentication. Only allocation failure propagates.
    ///
    /// `client_hello_body` is the whole message body including the binders,
    /// because the binder transcript is derived from it by truncation --
    /// see `tls.clientHelloBinderTranscript`.
    fn selectPreSharedKey(self: *TlsConnection, client_hello_body: []const u8, ext_data: []const u8) !void {
        if (ext_data.len < 2) return;
        const identities_len = std.mem.readInt(u16, ext_data[0..2], .big);
        const identities_end = 2 + @as(usize, identities_len);
        if (identities_end + 2 > ext_data.len) return;

        // The binders list, and with it the truncation point. Read before the
        // identities so that a malformed tail rejects the offer outright rather
        // than after tickets have been decrypted.
        const binders_len = std.mem.readInt(u16, ext_data[identities_end..][0..2], .big);
        const binders = ext_data[identities_end + 2 ..];
        if (binders.len != binders_len) return;

        const transcript = tls.clientHelloBinderTranscript(client_hello_body, binders_len) catch return;

        // Identities and binders are parallel lists, walked in step. RFC 8446
        // Section 4.2.11.2 requires them to be the same length; a mismatch is
        // caught by either walk running out first.
        var id_pos: usize = 2;
        var binder_pos: usize = 0;
        var index: u16 = 0;

        while (id_pos + 2 <= identities_end) : (index += 1) {
            const identity_len = std.mem.readInt(u16, ext_data[id_pos..][0..2], .big);
            id_pos += 2;
            // Identity, then the four-byte obfuscated ticket age that follows it.
            if (id_pos + identity_len + 4 > identities_end) return;
            const identity = ext_data[id_pos .. id_pos + identity_len];
            id_pos += identity_len + 4;

            if (binder_pos + 1 > binders.len) return;
            const binder_len = binders[binder_pos];
            binder_pos += 1;
            if (binder_pos + binder_len > binders.len) return;
            const offered_binder = binders[binder_pos .. binder_pos + binder_len];
            binder_pos += binder_len;

            var ticket = (try self.decryptSessionTicket(identity)) orelse continue;
            defer util.secureZero(&ticket.psk);

            // RFC 8446 Section 4.2.11: a ticket may only be resumed under a
            // suite with the same hash, since the PSK is bound to that hash's
            // key schedule.
            const negotiated = self.cipher_suite orelse return;
            if (ticket.cipher_suite.hashAlgorithm() != negotiated.hashAlgorithm()) continue;

            var ks = try tls.KeySchedule.init(self.allocator, .sha256);
            defer ks.deinit();
            try ks.deriveEarlySecret(&ticket.psk);

            const binder_key = try ks.resumptionBinderKey();
            defer {
                util.secureZero(binder_key);
                self.allocator.free(binder_key);
            }

            const expected = try tls.verifyData(self.allocator, .sha256, binder_key, &transcript);
            defer {
                util.secureZero(expected);
                self.allocator.free(expected);
            }

            // Constant time, and length-checked first: `constantTimeEqual` on
            // differing lengths would otherwise leak through its own early exit,
            // and a client controls this length.
            if (offered_binder.len != expected.len) continue;
            if (!util.constantTimeEqual(offered_binder, expected)) continue;

            self.psk = ticket.psk;
            self.selected_psk_identity = index;
            return;
        }
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
        const body = try self.buildServerHello();
        defer self.allocator.free(body);

        self.transcriptUpdate(.server_hello, body);
        try self.writeHandshakeMessage(.server_hello, body);
    }

    /// The ServerHello body of RFC 8446 Section 4.1.3.
    ///
    /// Split from `sendServerHello` for the reason `buildClientHello` is split
    /// on the other side: a client has to be able to read what this server
    /// writes without a socket between them, which is the only way the two
    /// halves of a resumed handshake are ever checked against each other.
    ///
    /// Deliberately does not touch the transcript; the caller decides when the
    /// message is really sent.
    fn buildServerHello(self: *TlsConnection) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Generate server key share for X25519
        self.server_key_share = asym.x25519.generate();

        // TLS version (legacy)
        try writeU16(&buffer, self.allocator, 0x0303);

        // Server random
        try writeBytes(&buffer, self.allocator, &self.server_random);

        // legacy_session_id_echo, RFC 8446 Section 4.1.3: the client's value
        // verbatim, whatever it was, including empty.
        try writeU8(&buffer, self.allocator, self.legacy_session_id_len);
        try writeBytes(&buffer, self.allocator, self.legacy_session_id[0..self.legacy_session_id_len]);

        // Selected cipher suite
        try writeU16(&buffer, self.allocator, @backingInt(self.cipher_suite.?));

        // Compression method (null)
        try writeU8(&buffer, self.allocator, 0);

        // Extensions
        var extensions: std.ArrayList(u8) = .empty;
        defer extensions.deinit(self.allocator);

        // Supported versions (TLS 1.3)
        try writeU16(&extensions, self.allocator, @backingInt(tls_client.ExtensionType.supported_versions));
        try writeU16(&extensions, self.allocator, 2);
        try writeU16(&extensions, self.allocator, 0x0304);

        // Key share
        try self.writeServerKeyShare(&extensions);

        // Accepted PSK, RFC 8446 Section 4.2.11: the server echoes only the
        // index of the identity it chose. Sent only when `selectPreSharedKey`
        // verified a binder, so the client cannot be told a PSK was accepted
        // that this side is not actually keyed on.
        if (self.selected_psk_identity) |identity| {
            try writeU16(&extensions, self.allocator, @backingInt(tls_client.ExtensionType.pre_shared_key));
            try writeU16(&extensions, self.allocator, 2);
            try writeU16(&extensions, self.allocator, identity);
        }

        // Write extensions
        try writeU16(&buffer, self.allocator, @intCast(extensions.items.len));
        try writeBytes(&buffer, self.allocator, extensions.items);

        return buffer.toOwnedSlice(self.allocator);
    }

    fn sendEncryptedExtensions(self: *TlsConnection) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        // Extensions length (populated below)
        const len_pos = buffer.items.len;
        try writeU16(&buffer, self.allocator, 0);

        // ALPN extension if negotiated
        if (self.selected_alpn) |alpn| {
            try writeU16(&buffer, self.allocator, @backingInt(tls_client.ExtensionType.application_layer_protocol_negotiation));
            try writeU16(&buffer, self.allocator, @intCast(alpn.len + 3));
            try writeU16(&buffer, self.allocator, @intCast(alpn.len + 1));
            try writeU8(&buffer, self.allocator, @intCast(alpn.len));
            try writeBytes(&buffer, self.allocator, alpn);
        }

        // Update extensions length
        const ext_len = buffer.items.len - len_pos - 2;
        std.mem.writeInt(u16, buffer.items[len_pos..][0..2], @intCast(ext_len), .big);

        // Update transcript and send
        self.transcriptUpdate(.encrypted_extensions, buffer.items);
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
        self.transcriptUpdate(.certificate, buffer.items);
        try self.writeHandshakeMessage(.certificate, buffer.items);
    }

    /// Build the TLS 1.3 CertificateVerify signature block (RFC 8446 §4.4.3).
    ///
    /// Signs `content` with the server's private key and returns allocator-owned
    /// wire bytes laid out as:
    ///   SignatureScheme (u16 BE) || signature_len (u16 BE) || signature
    ///
    /// Supported, FIPS-aligned, stdlib-backed schemes:
    ///   - Ed25519 (FIPS 186-5)      → ed25519 (0x0807), raw 64-byte signature
    ///   - ECDSA P-256 / SHA-256     → ecdsa_secp256r1_sha256 (0x0403), DER sig
    ///   - ECDSA P-384 / SHA-384     → ecdsa_secp384r1_sha384 (0x0503), DER sig
    ///
    /// RSA-PSS and X25519 are intentionally unsupported here: zcrypto does not
    /// ship a hand-rolled / unvetted RSA implementation, and X25519 is a key
    /// agreement key (not a signing key). Callers must use an EC or Ed25519
    /// server key. This is a pure function (no connection state) so it is
    /// directly unit-testable.
    fn buildCertVerifySignature(
        allocator: std.mem.Allocator,
        key_type: tls_config.PrivateKeyType,
        der_key: []const u8,
        content: []const u8,
    ) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(allocator);

        switch (key_type) {
            .ed25519 => {
                // ed25519 (0x0807)
                try writeU16(&buffer, allocator, 0x0807);

                // Ed25519 private key handling:
                // - 64 bytes: full secret key (seed + public, Zig's Ed25519 form)
                // - 32 bytes: seed only; derive the full keypair
                var secret_key: [64]u8 = undefined;
                if (der_key.len == 64) {
                    @memcpy(&secret_key, der_key[0..64]);
                } else if (der_key.len == 32) {
                    var seed: [32]u8 = undefined;
                    @memcpy(&seed, der_key[0..32]);
                    const keypair = asym.ed25519.generateFromSeed(seed);
                    secret_key = keypair.private_key;
                } else {
                    return error.InvalidPrivateKeySize;
                }

                const signature = try asym.ed25519.sign(content, secret_key);
                try writeU16(&buffer, allocator, 64);
                try writeBytes(&buffer, allocator, &signature);
            },
            .ecdsa_p256 => {
                if (der_key.len < asym.SECP256R1_PRIVATE_KEY_SIZE) return error.InvalidPrivateKeySize;
                // ecdsa_secp256r1_sha256 (0x0403)
                try writeU16(&buffer, allocator, 0x0403);

                const private_bytes: [asym.SECP256R1_PRIVATE_KEY_SIZE]u8 =
                    der_key[0..asym.SECP256R1_PRIVATE_KEY_SIZE].*;
                var der_buf: [asym.SECP256R1_DER_SIGNATURE_MAX]u8 = undefined;
                const sig = try asym.secp256r1.signMessageDer(content, private_bytes, &der_buf);
                try writeU16(&buffer, allocator, @intCast(sig.len));
                try writeBytes(&buffer, allocator, sig);
            },
            .ecdsa_p384 => {
                if (der_key.len < asym.SECP384R1_PRIVATE_KEY_SIZE) return error.InvalidPrivateKeySize;
                // ecdsa_secp384r1_sha384 (0x0503)
                try writeU16(&buffer, allocator, 0x0503);

                const private_bytes: [asym.SECP384R1_PRIVATE_KEY_SIZE]u8 =
                    der_key[0..asym.SECP384R1_PRIVATE_KEY_SIZE].*;
                var der_buf: [asym.SECP384R1_DER_SIGNATURE_MAX]u8 = undefined;
                const sig = try asym.secp384r1.signMessageDer(content, private_bytes, &der_buf);
                try writeU16(&buffer, allocator, @intCast(sig.len));
                try writeBytes(&buffer, allocator, sig);
            },
            .rsa, .x25519 => return error.UnsupportedKeyType,
        }

        return buffer.toOwnedSlice(allocator);
    }

    /// Send CertificateVerify message to prove server identity (RFC 8446 Section 4.4.3)
    ///
    /// Signs the handshake transcript with the server's private key to prove
    /// possession of the certificate's corresponding private key.
    fn sendCertificateVerify(self: *TlsConnection) !void {
        // Get the private key from config
        const private_key = self.config.private_key orelse return error.MissingPrivateKey;

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

        const sig_block = try buildCertVerifySignature(
            self.allocator,
            private_key.key_type,
            private_key.der,
            &content,
        );
        defer self.allocator.free(sig_block);

        // Update transcript and send
        self.transcriptUpdate(.certificate_verify, sig_block);
        try self.writeHandshakeMessage(.certificate_verify, sig_block);
    }

    fn sendFinished(self: *TlsConnection) !void {
        const verify_data = try self.computeFinishedVerifyData(false); // Server finished
        defer self.allocator.free(verify_data);

        // Update transcript with Finished message
        self.transcriptUpdate(.finished, verify_data);

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
        self.transcriptUpdate(.finished, msg.data);
    }

    fn sendNewSessionTicket(self: *TlsConnection) !void {
        const body = try self.buildNewSessionTicketBody();
        defer self.allocator.free(body);
        try self.writeHandshakeMessage(.new_session_ticket, body);
    }

    /// The NewSessionTicket body of RFC 8446 Section 4.6.1:
    ///     ticket_lifetime(4) || ticket_age_add(4) || nonce_len(1) || nonce
    ///         || ticket_len(2) || ticket || extensions_len(2)
    ///
    /// Split from `sendNewSessionTicket` so the message can be read back without
    /// a socket. These bytes are the only place the ticket nonce and the sealed
    /// PSK are required to agree: the client derives the PSK from the nonce it
    /// reads here, and the server seals the PSK it derived from the nonce it
    /// used. A disagreement is undetectable downstream -- resumption just fails
    /// to authenticate, on some later connection, for no stated reason -- so it
    /// has to be caught where the message is built.
    fn buildNewSessionTicketBody(self: *TlsConnection) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        try writeU32(&buffer, self.allocator, ticket_lifetime_s);

        // Ticket age add
        const age_add = rand.randomU32();
        try writeU32(&buffer, self.allocator, age_add);

        // Ticket nonce. RFC 8446 Section 4.6.1 derives this ticket's PSK from it,
        // so the same bytes have to reach `generateSessionTicket`; it used to draw
        // its own unrelated value and these went on the wire meaning nothing.
        var ticket_nonce: [8]u8 = undefined;
        try rand.fillChecked(&ticket_nonce);
        try writeU8(&buffer, self.allocator, @intCast(ticket_nonce.len));
        try writeBytes(&buffer, self.allocator, &ticket_nonce);

        // Ticket
        const ticket = try self.generateSessionTicket(&ticket_nonce);
        defer self.allocator.free(ticket);
        try writeU16(&buffer, self.allocator, @intCast(ticket.len));
        try writeBytes(&buffer, self.allocator, ticket);

        // Extensions
        try writeU16(&buffer, self.allocator, 0);

        return buffer.toOwnedSlice(self.allocator);
    }

    /// Mint an encrypted session ticket (RFC 8446 Section 4.6.1).
    ///
    /// Wire format:
    ///     version(2) || ticket_key_id(16) || aead_nonce(12) || ciphertext || tag(16)
    /// The header travels in the clear -- the server must read the key id before
    /// it can pick a key -- and is passed as AEAD associated data, so neither the
    /// key selector nor the version can be altered without failing the tag.
    ///
    /// Sealed content:
    ///     cipher_suite(2) || psk(32) || issued_s(8)
    ///
    /// `psk` is the per-ticket key of Section 4.6.1,
    /// `HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce,
    /// Hash.length)`. The ticket used to carry `server_traffic_secret` verbatim:
    /// a live application key, handed to the peer inside a credential, valid for
    /// the whole ticket lifetime.
    fn generateSessionTicket(self: *TlsConnection, ticket_nonce: []const u8) ![]u8 {
        const cipher_suite = self.cipher_suite orelse return error.NoCipherSuite;
        // The PSK is a fixed 32 bytes, so only the SHA-256 suites round-trip.
        // `getTranscriptHash` refuses the others for the same reason.
        if (cipher_suite.hashAlgorithm() != .sha256) return errors.TlsError.UnsupportedCipherSuite;

        const keys = self.ticket_keys orelse return error.NoTicketKeys;

        // Refuse to mint a ticket we cannot stamp. Stamping a sentinel and
        // issuing anyway would hand the peer a credential whose age nobody can
        // ever judge. A resumption that does not happen costs a full handshake;
        // one that never expires costs forward secrecy.
        const issued_s = try self.nowSeconds();
        var key = try keys.issuing(self.io, issued_s);
        defer util.secureZero(&key.secret);

        const res_master = self.resumption_master_secret orelse return error.NoResumptionSecret;
        const psk = try kdf.hkdfExpandLabel(self.allocator, &res_master, "resumption", ticket_nonce, 32);
        defer {
            util.secureZero(psk);
            self.allocator.free(psk);
        }

        var plaintext: [ticket_plaintext_len]u8 = undefined;
        defer util.secureZero(&plaintext);
        std.mem.writeInt(u16, plaintext[0..2], @backingInt(cipher_suite), .big);
        @memcpy(plaintext[2..34], psk);
        std.mem.writeInt(u64, plaintext[34..42], issued_s, .big);

        const ticket = try self.allocator.alloc(u8, ticket_header_len + ticket_plaintext_len + 16);
        errdefer self.allocator.free(ticket);

        std.mem.writeInt(u16, ticket[0..2], ticket_version, .big);
        @memcpy(ticket[2..18], &key.id);
        try rand.fillChecked(ticket[18..30]);

        var tag: [16]u8 = undefined;
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
            ticket[ticket_header_len..][0..ticket_plaintext_len],
            &tag,
            &plaintext,
            ticket[0..ticket_header_len],
            ticket[18..][0..12].*,
            key.secret,
        );
        @memcpy(ticket[ticket_header_len + ticket_plaintext_len ..], &tag);

        return ticket;
    }

    /// Reopen a session ticket minted by `generateSessionTicket`.
    ///
    /// Called by `selectPreSharedKey` for each identity a client offers. This
    /// establishes only that the ticket is one this server minted, is still
    /// fresh, and names a suite that can carry it -- possession of the PSK
    /// inside is proved separately, by the binder.
    ///
    /// Returns null for every rejection, deliberately: the caller must not be
    /// able to tell an unknown key id from a failed tag from an expired stamp.
    fn decryptSessionTicket(self: *TlsConnection, ticket: []const u8) !?SessionTicketData {
        if (ticket.len != ticket_header_len + ticket_plaintext_len + 16) return null;
        if (std.mem.readInt(u16, ticket[0..2], .big) != ticket_version) return null;

        const keys = self.ticket_keys orelse return null;

        // A failed clock read rejects the ticket. This check used to sit inside
        // `if (clock read succeeded)`, so on any host without a readable realtime
        // clock every ticket ever issued stayed valid for ever: the one condition
        // bounding a resumption credential's life was also the one skipped when
        // it could not be evaluated. Falling back to a full handshake is the
        // cheap direction to be wrong in.
        const now_s = self.nowSeconds() catch return null;

        var key_id: [SessionTicketKeys.id_len]u8 = undefined;
        @memcpy(&key_id, ticket[2..18]);
        var key = keys.lookup(self.io, key_id, now_s) orelse return null;
        defer util.secureZero(&key.secret);

        var tag: [16]u8 = undefined;
        @memcpy(&tag, ticket[ticket_header_len + ticket_plaintext_len ..]);

        var plaintext: [ticket_plaintext_len]u8 = undefined;
        defer util.secureZero(&plaintext);

        std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
            &plaintext,
            ticket[ticket_header_len..][0..ticket_plaintext_len],
            tag,
            ticket[0..ticket_header_len],
            ticket[18..][0..12].*,
            key.secret,
        ) catch return null; // Tampered, or minted under different key material.

        const suite_int = std.mem.readInt(u16, plaintext[0..2], .big);
        const cipher_suite = std.enums.fromInt(tls_config.CipherSuite, suite_int) orelse return null;
        if (cipher_suite.hashAlgorithm() != .sha256) return null;

        const issued_s = std.mem.readInt(u64, plaintext[34..42], .big);
        if (!ticketFresh(now_s, issued_s)) return null;

        var data = SessionTicketData{
            .cipher_suite = cipher_suite,
            .psk = undefined,
            .issued_s = issued_s,
        };
        @memcpy(&data.psk, plaintext[2..34]);
        return data;
    }

    const SessionTicketData = struct {
        cipher_suite: tls_config.CipherSuite,
        /// Per-ticket PSK, RFC 8446 Section 4.6.1.
        psk: [32]u8,
        issued_s: u64,
    };

    /// The IKM for `deriveEarlySecret`: the resumption PSK when this handshake
    /// accepted one, otherwise null, which RFC 8446 Section 7.1 defines as a
    /// string of `Hash.length` zeroes.
    ///
    /// Both `deriveHandshakeSecrets` and `deriveApplicationSecrets` rebuild the
    /// key schedule from scratch, so both must start it the same way; the two
    /// disagreeing would show up as a Finished mismatch several steps later.
    fn earlySecretIkm(self: *const TlsConnection) ?[]const u8 {
        return if (self.psk) |*p| p[0..] else null;
    }

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

        // Derive early secret (resumption PSK if one was accepted)
        try key_schedule.deriveEarlySecret(self.earlySecretIkm());

        // Derive handshake secret using ECDHE shared secret
        try key_schedule.deriveHandshakeSecret(&self.shared_secret.?);

        // RFC 8446 Section 7.1 bounds both handshake traffic secrets at
        // ClientHello..ServerHello. This runs immediately after ServerHello is
        // sent, which is that boundary.
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

        self.client_handshake_keys = try self.deriveTrafficKeys(self.client_handshake_secret.?, true);
        self.server_handshake_keys = try self.deriveTrafficKeys(self.server_handshake_secret.?, false);
    }

    fn deriveApplicationSecrets(self: *TlsConnection) !void {
        // Initialize key schedule
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        var key_schedule = try tls.KeySchedule.init(self.allocator, hash_alg);
        defer key_schedule.deinit();

        // Reconstruct the key schedule
        try key_schedule.deriveEarlySecret(self.earlySecretIkm());
        try key_schedule.deriveHandshakeSecret(&self.shared_secret.?);
        try key_schedule.deriveMasterSecret();

        // RFC 8446 Section 7.1 bounds the application traffic secrets at
        // ClientHello..server Finished. That range closed before the client's
        // Finished arrived, so the digest comes from the snapshot taken then and
        // not from the live transcript, which has since moved on.
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

    /// Current time in whole seconds.
    ///
    /// A negative reading is treated as unreadable rather than clamped: a
    /// pre-1970 realtime clock means the host does not know what time it is, and
    /// a ticket stamped from it can never be aged.
    fn nowSeconds(self: *const TlsConnection) !u64 {
        const t = self.clock() orelse return error.ClockUnavailable;
        if (t < 0) return error.ClockUnavailable;
        return @intCast(t);
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

    /// Transcript hash over the handshake messages seen so far.
    ///
    /// `self.transcript` is a SHA-256 hasher, and it is the only transcript this
    /// connection keeps, so only SHA-256 suites can be served. The other arms
    /// fail closed rather than approximate: RFC 8446 defines the SHA-384
    /// transcript as SHA-384 *of the handshake messages*, and there is no way to
    /// recover that from a finished SHA-256 digest. Hashing the SHA-256 digest
    /// with SHA-384 -- which is what this used to do -- produces 48 bytes no peer
    /// will ever compute, so the handshake fails at Finished with a verify-data
    /// mismatch instead of at negotiation. `selectCipherSuite` already refuses
    /// these suites; this is the backstop.
    fn getTranscriptHash(self: *TlsConnection) ![]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        if (hash_alg != .sha256) return errors.TlsError.UnsupportedCipherSuite;

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
    fn snapshotTranscript(self: *TlsConnection) ![32]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();
        if (hash_alg != .sha256) return errors.TlsError.UnsupportedCipherSuite;
        var transcript_copy = self.transcript;
        return transcript_copy.final();
    }

    fn computeFinishedVerifyData(self: *TlsConnection, is_client: bool) ![]u8 {
        const hash_alg = self.cipher_suite.?.hashAlgorithm();

        const transcript_hash = try self.getTranscriptHash();
        defer self.allocator.free(transcript_hash);

        const secret = if (is_client)
            self.client_handshake_secret.?
        else
            self.server_handshake_secret.?;

        return tls.verifyData(self.allocator, hash_alg, &secret, transcript_hash);
    }

    fn writeServerKeyShare(self: *TlsConnection, buffer: *std.ArrayList(u8)) !void {
        try writeU16(buffer, self.allocator, @backingInt(tls_client.ExtensionType.key_share));
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

        try writeU8(&buffer, self.allocator, @backingInt(record_type));
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
        inner_plaintext[data.len] = @backingInt(record_type);

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
        aad[0] = @backingInt(tls_client.RecordType.application_data);
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

        try writeU8(&buffer, self.allocator, @backingInt(msg_type));
        try writeU24(&buffer, self.allocator, @intCast(data.len));
        try writeBytes(&buffer, self.allocator, data);

        try self.writeRecord(.handshake, buffer.items);
    }

    /// Feed one complete handshake message into the transcript. See
    /// `tls.transcriptUpdate` for why the four-byte header is part of the hash.
    fn transcriptUpdate(self: *TlsConnection, msg_type: tls_client.HandshakeType, body: []const u8) void {
        tls.transcriptUpdate(&self.transcript, @backingInt(msg_type), body);
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

test "CertificateVerify signer: Ed25519 wire block round trips" {
    const allocator = std.testing.allocator;
    const kp = asym.ed25519.generate();
    const content = "TLS 1.3, server CertificateVerify content (ed25519)";

    const block = try TlsConnection.buildCertVerifySignature(allocator, .ed25519, &kp.private_key, content);
    defer allocator.free(block);

    // Wire layout: scheme(2) || len(2) || signature
    try std.testing.expect(block.len >= 4);
    try std.testing.expectEqual(@as(u16, 0x0807), std.mem.readInt(u16, block[0..2], .big));
    const sig_len = std.mem.readInt(u16, block[2..4], .big);
    try std.testing.expectEqual(@as(u16, 64), sig_len);
    const sig: [64]u8 = block[4..68].*;
    try std.testing.expect(asym.ed25519.verify(content, sig, kp.public_key));

    // Tamper: a different content must not verify under this signature.
    try std.testing.expect(!asym.ed25519.verify("different content", sig, kp.public_key));
}

test "CertificateVerify signer: ECDSA P-256 DER wire block round trips" {
    const allocator = std.testing.allocator;
    const kp = asym.secp256r1.generate();
    const content = "TLS 1.3, server CertificateVerify content (p256)";

    const block = try TlsConnection.buildCertVerifySignature(allocator, .ecdsa_p256, &kp.private_key, content);
    defer allocator.free(block);

    try std.testing.expectEqual(@as(u16, 0x0403), std.mem.readInt(u16, block[0..2], .big));
    const sig_len = std.mem.readInt(u16, block[2..4], .big);
    const sig = block[4 .. 4 + sig_len];
    try std.testing.expect(asym.secp256r1.verifyMessageDer(content, sig, &kp.public_key));
    try std.testing.expect(!asym.secp256r1.verifyMessageDer("different content", sig, &kp.public_key));
}

test "CertificateVerify signer: ECDSA P-384 DER wire block round trips" {
    const allocator = std.testing.allocator;
    const kp = asym.secp384r1.generate();
    const content = "TLS 1.3, server CertificateVerify content (p384)";

    const block = try TlsConnection.buildCertVerifySignature(allocator, .ecdsa_p384, &kp.private_key, content);
    defer allocator.free(block);

    try std.testing.expectEqual(@as(u16, 0x0503), std.mem.readInt(u16, block[0..2], .big));
    const sig_len = std.mem.readInt(u16, block[2..4], .big);
    const sig = block[4 .. 4 + sig_len];
    try std.testing.expect(asym.secp384r1.verifyMessageDer(content, sig, &kp.public_key));
    try std.testing.expect(!asym.secp384r1.verifyMessageDer("different content", sig, &kp.public_key));
}

test "CertificateVerify signer: RSA and X25519 keys are unsupported" {
    const allocator = std.testing.allocator;
    const dummy_key = std.mem.zeroes([64]u8); // placeholder; rejected before use
    try std.testing.expectError(error.UnsupportedKeyType, TlsConnection.buildCertVerifySignature(allocator, .rsa, &dummy_key, "x"));
    try std.testing.expectError(error.UnsupportedKeyType, TlsConnection.buildCertVerifySignature(allocator, .x25519, &dummy_key, "x"));
}

test "CertificateVerify signer: malformed private key sizes fail closed" {
    const allocator = std.testing.allocator;
    const content = "TLS 1.3, server CertificateVerify malformed key";

    const short_ed25519 = std.mem.zeroes([31]u8);
    try std.testing.expectError(
        error.InvalidPrivateKeySize,
        TlsConnection.buildCertVerifySignature(allocator, .ed25519, &short_ed25519, content),
    );

    const ambiguous_ed25519 = std.mem.zeroes([48]u8);
    try std.testing.expectError(
        error.InvalidPrivateKeySize,
        TlsConnection.buildCertVerifySignature(allocator, .ed25519, &ambiguous_ed25519, content),
    );

    const short_p256 = std.mem.zeroes([asym.SECP256R1_PRIVATE_KEY_SIZE - 1]u8);
    try std.testing.expectError(
        error.InvalidPrivateKeySize,
        TlsConnection.buildCertVerifySignature(allocator, .ecdsa_p256, &short_p256, content),
    );

    const short_p384 = std.mem.zeroes([asym.SECP384R1_PRIVATE_KEY_SIZE - 1]u8);
    try std.testing.expectError(
        error.InvalidPrivateKeySize,
        TlsConnection.buildCertVerifySignature(allocator, .ecdsa_p384, &short_p384, content),
    );
}

const ticket_test_now: u64 = 1_700_000_000;
const ticket_test_nonce = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

fn fixedClock() ?i64 {
    return @intCast(ticket_test_now);
}

fn unavailableClock() ?i64 {
    return null;
}

fn negativeClock() ?i64 {
    return -1;
}

fn expiredClock() ?i64 {
    return @intCast(ticket_test_now + ticket_lifetime_s + 1);
}

/// A real `std.Io` for tests, and nothing else.
///
/// The ticket-key mutex takes an `Io` because this toolchain parks a contended
/// lock on the runtime's futex. Passing `undefined` would work right up until
/// the first test that actually contends -- which is precisely the test worth
/// having -- so the tests run against a real runtime instead.
const TicketTestIo = struct {
    runtime: std.Io.Threaded,

    fn init(allocator: std.mem.Allocator) TicketTestIo {
        return .{ .runtime = std.Io.Threaded.init(allocator, .{ .environ = .empty }) };
    }

    fn io(self: *TicketTestIo) std.Io {
        return self.runtime.io();
    }

    fn deinit(self: *TicketTestIo) void {
        self.runtime.deinit();
    }
};

/// A connection carrying only the state the session-ticket paths read.
///
/// `stream` is `undefined` deliberately: minting and reopening a ticket is pure
/// computation over the allocator, the negotiated suite, the resumption master
/// secret and the listener's ticket keys. Handing it a real socket would make
/// the test need a listener to assert something that never reaches the wire.
/// `io` is real, because the ticket-key lock uses it.
///
/// The clock is fixed so that expiry, retirement and clock failure are each
/// reachable on demand rather than only on a host that has been running for a
/// week or has a broken RTC.
fn ticketTestConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    keys: *SessionTicketKeys,
    server_random: [32]u8,
) TlsConnection {
    return TlsConnection{
        .config = tls_config.TlsConfig.init(allocator),
        .stream = undefined,
        .io = io,
        .is_server = true,
        .transcript = hash.Sha256.init(),
        .client_random = std.mem.zeroes([32]u8),
        .server_random = server_random,
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .resumption_master_secret = @as([32]u8, @splat(0x5a)),
        .ticket_keys = keys,
        .clock = fixedClock,
        .allocator = allocator,
    };
}

test "a session ticket carries the RFC 8446 per-ticket PSK" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x11));

    const ticket = try conn.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    const data = (try conn.decryptSessionTicket(ticket)) orelse return error.TestExpectedTicket;
    try std.testing.expectEqual(conn.cipher_suite.?, data.cipher_suite);
    try std.testing.expectEqual(ticket_test_now, data.issued_s);

    // Section 4.6.1: PSK = HKDF-Expand-Label(resumption_master_secret,
    // "resumption", ticket_nonce, Hash.length). Recomputed from the spec rather
    // than compared against whatever the ticket happened to contain.
    const expected = try kdf.hkdfExpandLabel(
        allocator,
        &conn.resumption_master_secret.?,
        "resumption",
        &ticket_test_nonce,
        32,
    );
    defer allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, &data.psk);

    // And it is a derivation, not a copy: the ticket does not ship the secret it
    // descends from. The previous ticket shipped `server_traffic_secret`, a live
    // application key, verbatim.
    try std.testing.expect(!std.mem.eql(u8, &conn.resumption_master_secret.?, &data.psk));
}

test "the nonce on the wire is the nonce the ticket's PSK was derived from" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x13));

    // The tests above hand `generateSessionTicket` a nonce directly, so they
    // cannot see it disagree with the one NewSessionTicket puts on the wire.
    // That disagreement is the whole failure mode this derivation replaced, and
    // it is silent: a client would derive a PSK the server never sealed and
    // resumption would fail authentication with nothing pointing here.
    const body = try conn.buildNewSessionTicketBody();
    defer allocator.free(body);

    // Parse the message rather than trusting an offset, so a layout change is a
    // parse failure here rather than a wrong field compared successfully.
    var pos: usize = 0;
    try std.testing.expectEqual(ticket_lifetime_s, std.mem.readInt(u32, body[0..4], .big));
    pos += 4; // ticket_lifetime
    pos += 4; // ticket_age_add

    const nonce_len = body[pos];
    pos += 1;
    const wire_nonce = body[pos..][0..nonce_len];
    pos += nonce_len;

    const ticket_len = std.mem.readInt(u16, body[pos..][0..2], .big);
    pos += 2;
    const wire_ticket = body[pos..][0..ticket_len];
    pos += ticket_len;

    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, body[pos..][0..2], .big));
    try std.testing.expectEqual(body.len, pos + 2);

    // The nonce must be freshly drawn, not the fixed one the other tests pass.
    try std.testing.expect(!std.mem.eql(u8, wire_nonce, &ticket_test_nonce));

    const data = (try conn.decryptSessionTicket(wire_ticket)) orelse
        return error.TestExpectedTicket;
    const expected = try kdf.hkdfExpandLabel(
        allocator,
        &conn.resumption_master_secret.?,
        "resumption",
        wire_nonce,
        32,
    );
    defer allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, &data.psk);
}

test "each session ticket gets its own PSK" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x12));

    // Two tickets from one connection differ only in ticket_nonce. If the nonce
    // were ignored -- as it was, being generated separately and never fed to the
    // derivation -- every ticket on a connection would carry the same key.
    const first = try conn.generateSessionTicket(&[_]u8{ 9, 9, 9, 9, 9, 9, 9, 9 });
    defer allocator.free(first);
    const second = try conn.generateSessionTicket(&[_]u8{ 8, 8, 8, 8, 8, 8, 8, 8 });
    defer allocator.free(second);

    const a = (try conn.decryptSessionTicket(first)) orelse return error.TestExpectedTicket;
    const b = (try conn.decryptSessionTicket(second)) orelse return error.TestExpectedTicket;
    try std.testing.expect(!std.mem.eql(u8, &a.psk, &b.psk));
}

test "a ticket reopens on another connection of the same listener" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());

    // This is what resumption is for: the client returns later on a *new*
    // connection, with a new server_random, and the server must still recognise
    // its ticket. The old key was SHA256(server_random || label), which made that
    // impossible -- and a test asserted the failure as though it were the
    // requirement.
    var issuer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x33));
    var returning = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x44));

    const ticket = try issuer.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    const data = (try returning.decryptSessionTicket(ticket)) orelse return error.TestExpectedTicket;
    try std.testing.expectEqual(issuer.cipher_suite.?, data.cipher_suite);
}

test "a ticket does not reopen under another listener's keys" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var other_keys = try SessionTicketKeys.init(ticket_test_now);
    defer other_keys.deinit(tio.io());

    // The key *id* is public: it rides in the clear at the front of every ticket,
    // so anyone can mint one bearing another server's id. Give both listeners the
    // same id, leaving the secret as the only difference -- otherwise this test
    // passes on the id lookup alone and says nothing about whether the ticket is
    // actually protected.
    other_keys.current.id = keys.current.id;

    // Same resumption master secret, same suite, same clock, same handshake
    // random: only the owned secret differs. That is what has to separate one
    // server from another, now that the public handshake random no longer does.
    var issuer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x33));
    var stranger = ticketTestConnection(allocator, tio.io(), &other_keys, @splat(0x33));

    const ticket = try issuer.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    try std.testing.expect((try stranger.decryptSessionTicket(ticket)) == null);
}

test "a tampered session ticket is refused rather than partially trusted" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x22));

    const ticket = try conn.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    // Every byte is covered: the cleartext header -- version, key id, AEAD nonce
    // -- as well as the sealed body. The header is only safe to read before
    // authentication because it is bound in as associated data, so a flip there
    // must fail the tag rather than silently select a different key.
    for (0..ticket.len) |i| {
        const original = ticket[i];
        ticket[i] ^= 0x01;
        defer ticket[i] = original;
        try std.testing.expect((try conn.decryptSessionTicket(ticket)) == null);
    }
}

test "ticket keys survive one rotation and stop reopening after two" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x55));

    const ticket = try conn.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    // Rotation must not orphan tickets that are still inside their advertised
    // lifetime, which is why the predecessor is kept.
    try keys.rotate(tio.io(), ticket_test_now + ticket_lifetime_s);
    try std.testing.expect((try conn.decryptSessionTicket(ticket)) != null);

    // A second rotation pushes the minting key out of both slots. Retirement has
    // to be bounded; otherwise key material accumulates and a ticket stays
    // openable indefinitely.
    try keys.rotate(tio.io(), ticket_test_now + 2 * @as(u64, ticket_lifetime_s));
    try std.testing.expect((try conn.decryptSessionTicket(ticket)) == null);
}

test "an unreadable clock refuses to mint a ticket and refuses to honour one" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x66));

    const ticket = try conn.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    for ([_]Clock{ unavailableClock, negativeClock }) |broken| {
        conn.clock = broken;
        try std.testing.expectError(
            error.ClockUnavailable,
            conn.generateSessionTicket(&ticket_test_nonce),
        );
        try std.testing.expect((try conn.decryptSessionTicket(ticket)) == null);
    }

    // The rejections above were the clock's doing, not the ticket's: restore a
    // readable clock and the same bytes open. Without this the test would pass
    // just as well against a ticket that was invalid to begin with.
    conn.clock = fixedClock;
    try std.testing.expect((try conn.decryptSessionTicket(ticket)) != null);
}

test "a ticket past its lifetime is refused while its key is still live" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x77));

    const ticket = try conn.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    // One second past the advertised lifetime. The minting key retires only at
    // two lifetimes, so this is the age check failing on its own rather than the
    // ticket becoming undecryptable -- the two bounds are separately reachable.
    conn.clock = expiredClock;
    try std.testing.expect((try conn.decryptSessionTicket(ticket)) == null);
}

test "ticket freshness ends at the advertised lifetime and does not wrap" {
    const issued: u64 = 1_700_000_000;

    try std.testing.expect(ticketFresh(issued, issued));
    try std.testing.expect(ticketFresh(issued + ticket_lifetime_s, issued));
    try std.testing.expect(!ticketFresh(issued + ticket_lifetime_s + 1, issued));

    // The bound is the value put on the wire in NewSessionTicket, not a second
    // constant that happens to match today.
    try std.testing.expect(!ticketFresh(issued + ticket_lifetime_s * 2, issued));

    // Near u64 max the sum saturates instead of wrapping into the past, so an old
    // ticket cannot be made to look fresh by arithmetic.
    try std.testing.expect(ticketFresh(std.math.maxInt(u64), std.math.maxInt(u64) - 1));

    // A stamp ahead of the clock is accepted; see `ticketFresh`.
    try std.testing.expect(ticketFresh(issued, issued + 60));
}

fn ticketTestConfig(allocator: std.mem.Allocator, enabled: bool) tls_config.TlsConfig {
    var config = tls_config.TlsConfig.init(allocator);
    config.enable_session_tickets = enabled;
    return config;
}

/// A listener as `listen` leaves it, minus the socket it never reads here.
///
/// `listener` and `io_runtime` are `undefined` on purpose: which keys a
/// connection is handed is decided before anything is accepted, and binding a
/// port to assert it would only add a way for the test to fail for reasons of
/// its own.
fn ticketTestServer(allocator: std.mem.Allocator, keys: ?*SessionTicketKeys) TlsServer {
    return TlsServer{
        .config = ticketTestConfig(allocator, keys != null),
        .listener = undefined,
        .io_runtime = undefined,
        .ticket_keys = keys,
        .allocator = allocator,
    };
}

test "a listener will not start holding ticket keys it cannot date" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();

    // Tickets off is the one case where having no keys is the right answer.
    try std.testing.expect(
        (try initTicketKeys(allocator, ticketTestConfig(allocator, false), unavailableClock)) == null,
    );

    // Tickets on and no readable clock has to fail the listener. Returning null
    // would also compile and would leave a server running with resumption
    // silently off; failing to start says so.
    for ([_]Clock{ unavailableClock, negativeClock }) |broken| {
        try std.testing.expectError(
            error.ClockUnavailable,
            initTicketKeys(allocator, ticketTestConfig(allocator, true), broken),
        );
    }

    const keys = (try initTicketKeys(allocator, ticketTestConfig(allocator, true), fixedClock)) orelse
        return error.TestExpectedTicketKeys;
    defer {
        keys.deinit(tio.io());
        allocator.destroy(keys);
    }

    // Dated by the clock it was given, not by whatever the host reads: the
    // creation stamp is what rotation and retirement are measured from.
    try std.testing.expectEqual(ticket_test_now, keys.current.created_s);
    try std.testing.expect(keys.previous == null);
}

test "every connection a listener accepts borrows the one set of ticket keys" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();

    var server = ticketTestServer(
        allocator,
        try initTicketKeys(allocator, ticketTestConfig(allocator, true), fixedClock),
    );
    defer if (server.ticket_keys) |keys| {
        keys.deinit(tio.io());
        allocator.destroy(keys);
    };

    // Two connections as `accept` builds them, differing in handshake random --
    // which is what the ticket key used to be derived from, and would once have
    // made these two servers as far as a ticket was concerned.
    var first = ticketTestConnection(allocator, tio.io(), server.connectionTicketKeys().?, @splat(0xa1));
    var second = ticketTestConnection(allocator, tio.io(), server.connectionTicketKeys().?, @splat(0xa2));

    const ticket = try first.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);

    // The point of listener-owned keys: a peer resumes against whichever
    // connection it lands on, not only the one that issued its ticket.
    try std.testing.expect((try second.decryptSessionTicket(ticket)) != null);

    // A listener is returned by value and so may be moved after connections
    // have borrowed its keys -- handed up a frame, pushed into a growing list.
    // The keys live behind a pointer precisely so the borrow survives that.
    // Held inline, both connections here would still be pointing into the
    // husk `moved` left behind.
    var moved = server;
    server = undefined;
    try std.testing.expectEqual(first.ticket_keys.?, moved.connectionTicketKeys().?);
    try std.testing.expectEqual(second.ticket_keys.?, moved.connectionTicketKeys().?);
    try std.testing.expect((try second.decryptSessionTicket(ticket)) != null);
    server = moved;

    // Borrowed, not copied. Rotation driven through one connection retires the
    // minting key for all of them; against per-connection copies the assertion
    // above would still hold and this one would not.
    try first.ticket_keys.?.rotate(tio.io(), ticket_test_now + ticket_lifetime_s);
    try first.ticket_keys.?.rotate(tio.io(), ticket_test_now + 2 * @as(u64, ticket_lifetime_s));
    try std.testing.expect((try second.decryptSessionTicket(ticket)) == null);

    var disabled = ticketTestServer(allocator, null);
    try std.testing.expect(disabled.connectionTicketKeys() == null);
}

/// One thread's share of the concurrent ticket-key test.
///
/// A worker mints under the shared key set and immediately reopens what it
/// minted, while another thread rotates underneath it. Every field is written
/// only by the owning thread and read only after the join, so the counters need
/// no synchronisation of their own.
const TicketRaceWorker = struct {
    /// Rounds a worker runs before it is allowed to stop, so the rotator has
    /// live threads to interleave with rather than ones that already exited.
    const min_rounds = 256;

    /// Reached only if a worker never observes a rotation, which the loop
    /// otherwise waits for. Present so that regression stalls the test instead
    /// of hanging it.
    const max_rounds = 1 << 22;

    keys: *SessionTicketKeys,
    io: std.Io,
    done: *std.atomic.Value(usize),

    /// Distinct key ids this worker minted under. One means the rotator never
    /// interleaved with it, and the run proved nothing about concurrency.
    ids_seen: usize = 0,
    /// Lookups that returned the id asked for attached to different key
    /// material -- a read that straddled a rotation.
    torn: usize = 0,
    errors: usize = 0,
    rounds: usize = 0,

    fn run(self: *TicketRaceWorker) void {
        var last_id: [SessionTicketKeys.id_len]u8 = @splat(0);
        var have_last = false;

        while (self.rounds < max_rounds) : (self.rounds += 1) {
            if (self.rounds >= min_rounds and self.ids_seen >= 2) break;

            var minted = self.keys.issuing(self.io, ticket_test_now) catch {
                self.errors += 1;
                continue;
            };
            defer util.secureZero(&minted.secret);

            if (!have_last or !std.mem.eql(u8, &last_id, &minted.id)) {
                last_id = minted.id;
                have_last = true;
                self.ids_seen += 1;
            }

            // A miss is legitimate: two rotations can land between the mint and
            // the lookup, which is precisely when a ticket stops being
            // honoured. A hit that disagrees is not. The id selects the key, so
            // a matching id carrying different key material means the read saw
            // the slot mid-rotation -- which is what a borrowed `*const Key`,
            // or an unguarded struct, hands back here.
            if (self.keys.lookup(self.io, minted.id, ticket_test_now)) |found| {
                var reopened = found;
                defer util.secureZero(&reopened.secret);
                if (!std.mem.eql(u8, &reopened.secret, &minted.secret) or
                    reopened.created_s != minted.created_s)
                {
                    self.torn += 1;
                }
            }
        }

        _ = self.done.fetchAdd(1, .release);
    }
};

/// Rotates the shared key set until every worker has finished.
///
/// Deliberately not a fixed number of rotations: a fixed count can drain before
/// a worker is ever scheduled, which would leave "did a rotation interleave?"
/// up to the scheduler. Running until the workers report done makes the overlap
/// a property of the test rather than a coin flip.
const TicketRaceRotator = struct {
    keys: *SessionTicketKeys,
    io: std.Io,
    done: *std.atomic.Value(usize),
    workers: usize,
    rotations: usize = 0,
    errors: usize = 0,

    fn run(self: *TicketRaceRotator) void {
        while (self.done.load(.acquire) < self.workers) {
            if (self.keys.rotate(self.io, ticket_test_now)) |_| {
                self.rotations += 1;
            } else |_| {
                self.errors += 1;
            }
        }
    }
};

test "ticket keys hold up under concurrent issuance, lookup and rotation" {
    // `std.Thread.spawn` is a compile error, not a runtime failure, on a
    // single-threaded target, so this has to be skipped before the spawn is
    // ever analysed. The gate builds wasm32-wasi, which is single-threaded.
    if (builtin.single_threaded) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();

    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());

    const worker_count = 4;
    var done: std.atomic.Value(usize) = .init(0);

    var workers: [worker_count]TicketRaceWorker = undefined;
    for (&workers) |*w| w.* = .{ .keys = &keys, .io = tio.io(), .done = &done };

    var rotator: TicketRaceRotator = .{
        .keys = &keys,
        .io = tio.io(),
        .done = &done,
        .workers = worker_count,
    };

    // The rotator goes first: it exits on the workers' completion count, so
    // spawning it after a worker that has already run to its cap would be a
    // race to set up the race.
    const rotator_thread = try std.Thread.spawn(.{}, TicketRaceRotator.run, .{&rotator});

    var threads: [worker_count]std.Thread = undefined;
    var spawned: usize = 0;
    while (spawned < worker_count) : (spawned += 1) {
        threads[spawned] = std.Thread.spawn(.{}, TicketRaceWorker.run, .{&workers[spawned]}) catch break;
    }
    // A worker that never started will never report done, and the rotator would
    // spin for ever waiting for it. Account for the shortfall so the run ends
    // and fails on the assertion below rather than hanging.
    _ = done.fetchAdd(worker_count - spawned, .release);

    for (threads[0..spawned]) |t| t.join();
    rotator_thread.join();

    var torn: usize = 0;
    var failed: usize = rotator.errors;
    var interleaved: usize = 0;
    for (workers[0..spawned]) |w| {
        torn += w.torn;
        failed += w.errors;
        if (w.ids_seen >= 2) interleaved += 1;
    }

    try std.testing.expectEqual(@as(usize, worker_count), spawned);
    try std.testing.expectEqual(@as(usize, 0), failed);

    // The contract: an id names exactly one key, on every thread, always.
    try std.testing.expectEqual(@as(usize, 0), torn);

    // And the run actually raced. Without this the test would pass just as well
    // on threads that never overlapped, which is the gap the sequential
    // rotation test above leaves open.
    try std.testing.expectEqual(@as(usize, worker_count), interleaved);
    try std.testing.expect(rotator.rotations >= worker_count);

    // Still coherent after the pounding: the surviving key mints and reopens.
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0xc0));
    const ticket = try conn.generateSessionTicket(&ticket_test_nonce);
    defer allocator.free(ticket);
    try std.testing.expect((try conn.decryptSessionTicket(ticket)) != null);
}

test "a ticket cannot be minted before the resumption secret exists" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x88));
    defer conn.deinit();

    // `handshake` derives the application secrets and only then offers a ticket.
    // Reversing those two must not mint anything: with no resumption master
    // secret there is nothing a ticket PSK may legitimately descend from.
    conn.resumption_master_secret = null;
    try std.testing.expectError(error.NoResumptionSecret, conn.buildNewSessionTicketBody());

    conn.shared_secret = @splat(0x99);

    // The application secrets are bound to ClientHello..server Finished, a
    // boundary the live transcript has already passed by the time this runs.
    // Without the snapshot there is no honest way to reach it, so the
    // derivation refuses rather than substituting the transcript it can see.
    try std.testing.expectError(error.MissingFinishedTranscript, conn.deriveApplicationSecrets());

    conn.server_finished_transcript = @splat(0x77);
    try conn.deriveApplicationSecrets();
    const res_master = conn.resumption_master_secret orelse
        return error.TestExpectedResumptionSecret;

    // Derived under "res master", not merely non-null. The same key schedule
    // produces the traffic secrets a few lines above it, and a ticket carrying
    // one of those would hand a live record-protection secret to the peer.
    try std.testing.expect(!std.mem.eql(u8, &res_master, &conn.client_traffic_secret.?));
    try std.testing.expect(!std.mem.eql(u8, &res_master, &conn.server_traffic_secret.?));
    try std.testing.expect(!std.mem.eql(u8, &res_master, &conn.shared_secret.?));

    const body = try conn.buildNewSessionTicketBody();
    defer allocator.free(body);
}

test "every server secret is derived at its own transcript boundary" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());
    var conn = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x88));
    defer conn.deinit();

    // Three distinct transcript states, one per RFC 8446 Section 7.1 boundary:
    // ClientHello..ServerHello for the handshake traffic secrets,
    // ClientHello..server Finished for the application traffic secrets, and
    // ClientHello..client Finished for the resumption master secret. The
    // strings fed here stand in for the messages between them; all that matters
    // is that the three digests differ, so a derivation reaching for the wrong
    // one cannot accidentally agree.
    const peer = asym.generateCurve25519();
    conn.server_key_share = asym.generateCurve25519();
    conn.client_public_key = peer.public_key;

    conn.transcript.update("ServerHello");
    const at_server_hello = try conn.snapshotTranscript();
    try conn.deriveHandshakeSecrets();

    conn.transcript.update("server Finished");
    const at_server_finished = try conn.snapshotTranscript();
    conn.server_finished_transcript = at_server_finished;

    conn.transcript.update("client Finished");
    const at_client_finished = try conn.snapshotTranscript();
    try conn.deriveApplicationSecrets();

    try std.testing.expect(!std.mem.eql(u8, &at_server_hello, &at_server_finished));
    try std.testing.expect(!std.mem.eql(u8, &at_server_finished, &at_client_finished));

    // Recompute each secret from the boundary it belongs to and assert the
    // connection produced exactly that. Equality is what gives this teeth: it
    // fails if the transcript is hashed a second time on the way in, and it
    // fails if the wrong boundary is used. Two endpoints running this same code
    // agree with each other in either case, so nothing but an explicit
    // assertion against an independently recomputed value catches it.
    var ks = try tls.KeySchedule.init(allocator, .sha256);
    defer ks.deinit();
    try ks.deriveEarlySecret(null);
    try ks.deriveHandshakeSecret(&conn.shared_secret.?);
    try ks.deriveMasterSecret();

    const Expect = struct {
        secret: []const u8,
        label: []const u8,
        right: *const [32]u8,
        wrong: *const [32]u8,
        got: *const [32]u8,
    };
    const cases = [_]Expect{
        .{ .secret = ks.handshake_secret, .label = "c hs traffic", .right = &at_server_hello, .wrong = &at_server_finished, .got = &conn.client_handshake_secret.? },
        .{ .secret = ks.handshake_secret, .label = "s hs traffic", .right = &at_server_hello, .wrong = &at_server_finished, .got = &conn.server_handshake_secret.? },
        .{ .secret = ks.master_secret, .label = "c ap traffic", .right = &at_server_finished, .wrong = &at_client_finished, .got = &conn.client_traffic_secret.? },
        .{ .secret = ks.master_secret, .label = "s ap traffic", .right = &at_server_finished, .wrong = &at_client_finished, .got = &conn.server_traffic_secret.? },
        .{ .secret = ks.master_secret, .label = "res master", .right = &at_client_finished, .wrong = &at_server_finished, .got = &conn.resumption_master_secret.? },
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

// Resumption, driven through both endpoints' real code.
//
// These tests live here rather than in `tls_client.zig` because Zig privacy is
// per file and the server side owns the ticket harness. What they are for is
// the one property neither endpoint can establish alone: that the bytes a
// client MACs and the bytes a server MACs are the same bytes. A binder is a MAC
// over a truncated ClientHello, and two implementations that truncate
// identically agree with each other whether or not either agrees with RFC 8446.
// `known_answer_vectors.zig` anchors the truncation rule to the RFC 8448 trace;
// these anchor this repository's two endpoints to that same shared primitive by
// running one's output through the other's parser.

/// A client carrying only the state the ClientHello and ticket paths read.
///
/// `stream` is `undefined` for the same reason `ticketTestConnection` leaves it
/// so: building a ClientHello and reopening a ticket are computation, not I/O,
/// and requiring a socket here would mean a listener had to exist to assert
/// something that never reaches the wire.
fn resumptionTestClient(allocator: std.mem.Allocator, io: std.Io) tls_client.TlsClient {
    return tls_client.TlsClient{
        .config = tls_config.TlsConfig.init(allocator),
        .stream = undefined,
        .io = io,
        .transcript = hash.Sha256.init(),
        .client_random = @splat(0x33),
        .server_random = undefined,
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .allocator = allocator,
    };
}

/// Mint a ticket on `issuer` and carry it to a client the way the wire does:
/// through `buildNewSessionTicketBody` and back out through the client's own
/// `receiveNewSessionTicket`.
///
/// Deriving the client's PSK here instead would prove only that the test agrees
/// with the server. Round-tripping the actual message is what shows the client
/// derives its PSK from the nonce the server put on the wire, which is the
/// agreement that silently breaks and then surfaces, one connection later, as
/// an unexplained binder rejection.
fn issueSessionTo(
    client: *tls_client.TlsClient,
    issuer: *TlsConnection,
) !tls_client.ResumptionSession {
    const body = try issuer.buildNewSessionTicketBody();
    defer issuer.allocator.free(body);

    client.resumption_master_secret = issuer.resumption_master_secret;
    try client.receiveNewSessionTicket(body);
    return client.takeSession() orelse error.TestExpectedSession;
}

test "a client's PSK offer is accepted by the server that minted its ticket" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());

    var issuer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x11));
    var client = resumptionTestClient(allocator, tio.io());

    var session = try issueSessionTo(&client, &issuer);
    defer session.deinit(allocator);

    // The PSK the client derived is the PSK the server sealed. Checked before
    // the binder, because a binder mismatch and a PSK mismatch look identical
    // from the far side and only one of them is a framing bug.
    const sealed = (try issuer.decryptSessionTicket(session.ticket)) orelse
        return error.TestExpectedTicket;
    try std.testing.expectEqualSlices(u8, &sealed.psk, &session.psk);

    client.offered_session = &session;
    const hello = try client.buildClientHello();
    defer allocator.free(hello);

    try std.testing.expectEqualSlices(u8, &client.psk.?, &session.psk);

    // A second, independent connection on the same listener -- the case that
    // matters, since a client resumes against whichever one it lands on.
    var resumer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x22));
    defer resumer.deinit();

    try resumer.parseClientHello(hello);

    try std.testing.expect(resumer.psk != null);
    try std.testing.expectEqual(@as(?u16, 0), resumer.selected_psk_identity);
    try std.testing.expectEqualSlices(u8, &session.psk, &resumer.psk.?);
}

/// The negatives, each an offer that must degrade to a full handshake rather
/// than be honoured or abort the connection.
///
/// Every case starts from a ClientHello this repository's client actually
/// produced and that the positive test above proves is accepted, so a failure
/// here is the mutation being tolerated and not a malformed fixture.
const RejectedOffer = enum {
    /// A single bit flipped in the binder.
    tampered_binder,
    /// A binder MACed over the whole ClientHello instead of the truncated one.
    /// The plausible mistake, and the one two matching endpoints cannot see.
    untruncated_binder,
    /// A binder MACed over the truncated bytes but with the handshake header
    /// declaring the truncated length rather than the message's own -- the
    /// other half of the same trap.
    wrong_declared_length,
    /// A well formed, correctly bound offer that simply never announced
    /// `psk_dhe_ke`, so honouring it would resume without forward secrecy.
    no_psk_dhe_ke,
};

test "a PSK offer the server cannot verify falls back to a full handshake" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();

    for (std.enums.values(RejectedOffer)) |mutation| {
        var keys = try SessionTicketKeys.init(ticket_test_now);
        defer keys.deinit(tio.io());

        var issuer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x11));
        var client = resumptionTestClient(allocator, tio.io());

        var session = try issueSessionTo(&client, &issuer);
        defer session.deinit(allocator);

        client.offered_session = &session;
        const hello = try client.buildClientHello();
        defer allocator.free(hello);

        // Most mutations edit in place; one has to rebuild the message.
        var offer: []u8 = hello;
        var rebuilt: ?[]u8 = null;
        defer if (rebuilt) |buf| allocator.free(buf);

        switch (mutation) {
            .tampered_binder => hello[hello.len - 1] ^= 0x01,
            .untruncated_binder => try mangleBinder(allocator, hello, &session, .untruncated),
            .wrong_declared_length => try mangleBinder(allocator, hello, &session, .truncated_length),
            .no_psk_dhe_ke => {
                rebuilt = try withoutPskModes(allocator, hello, &session);
                offer = rebuilt.?;
            },
        }

        var resumer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x22));
        defer resumer.deinit();

        try resumer.parseClientHello(offer);

        // Fell back, rather than erroring: an offer this server cannot honour
        // costs the client a round trip, and must not cost it the connection.
        try std.testing.expect(resumer.psk == null);
        try std.testing.expect(resumer.selected_psk_identity == null);
        // Still a usable handshake -- the rest of the ClientHello was read.
        try std.testing.expect(resumer.cipher_suite != null);
        try std.testing.expect(resumer.client_public_key != null);
    }
}

test "a resumed handshake keys both sides identically and carries no certificate" {
    const allocator = std.testing.allocator;
    var tio = TicketTestIo.init(allocator);
    defer tio.deinit();
    var keys = try SessionTicketKeys.init(ticket_test_now);
    defer keys.deinit(tio.io());

    var issuer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x11));
    var client = resumptionTestClient(allocator, tio.io());
    defer client.deinit();

    var session = try issueSessionTo(&client, &issuer);
    defer session.deinit(allocator);

    client.offered_session = &session;
    const hello = try client.buildClientHello();
    defer allocator.free(hello);

    // What `sendClientHello` does around the socket write. Framed through the
    // shared `tls.transcriptUpdate` rather than by hand, because the four-byte
    // header this adds is precisely the detail that was wrong before, and a
    // test that reimplemented it would agree with whichever version it copied.
    tls.transcriptUpdate(&client.transcript, @backingInt(tls_client.HandshakeType.client_hello), hello);

    var resumer = ticketTestConnection(allocator, tio.io(), &keys, @splat(0x22));
    defer resumer.deinit();
    try resumer.parseClientHello(hello);
    try std.testing.expect(resumer.psk != null);

    const server_hello = try resumer.buildServerHello();
    defer allocator.free(server_hello);
    resumer.transcriptUpdate(.server_hello, server_hello);
    try resumer.deriveHandshakeSecrets();

    // The client reads the server's own bytes. This is where a ServerHello the
    // client refuses -- a session id that is not the echo it sent, a PSK index
    // it never offered -- surfaces as an error rather than as silence.
    try client.parseServerHello(server_hello);
    try client.deriveHandshakeSecrets();

    // Both sides are keyed on the ticket's PSK, and the client stayed on the
    // resumption path rather than being quietly downgraded to a full handshake.
    try std.testing.expect(client.psk != null);
    try std.testing.expectEqualSlices(u8, &resumer.psk.?, &client.psk.?);
    try std.testing.expectEqual(@as(?u16, 0), resumer.selected_psk_identity);

    // The point of the whole exercise: independently derived, and equal. These
    // are what Finished is computed from on both sides, so agreement here is
    // agreement about the PSK, the ECDHE share and every byte of the transcript
    // at once -- and no certificate was sent or expected to get here.
    try std.testing.expectEqualSlices(
        u8,
        &resumer.client_handshake_secret.?,
        &client.client_handshake_secret.?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &resumer.server_handshake_secret.?,
        &client.server_handshake_secret.?,
    );
    try std.testing.expect(client.server_certificates == null);
}

/// Rewrite the binder at the end of `hello` with one computed the wrong way.
///
/// Both variants are what a plausible implementation produces when it gets the
/// transcript boundary subtly wrong, and neither is detectable between two
/// endpoints that make the same mistake -- which is why the server has to
/// reject them here.
fn mangleBinder(
    allocator: std.mem.Allocator,
    hello: []u8,
    session: *const tls_client.ResumptionSession,
    variant: enum { untruncated, truncated_length },
) !void {
    const binders_len: usize = 1 + 32;

    var transcript = hash.Sha256.init();
    var header: [4]u8 = .{ 1, 0, 0, 0 };
    switch (variant) {
        .untruncated => {
            // No truncation, MAC over the entire ClientHello with the binder
            // slot left as the client found it: zeroed. Hashing the message
            // with the real binder already in place would be a mistake no
            // implementation can make, since the MAC would have to cover
            // itself; zeroing is the version two endpoints can both make and
            // still agree with each other.
            const zeroed = try allocator.dupe(u8, hello);
            defer allocator.free(zeroed);
            @memset(zeroed[zeroed.len - 32 ..], 0);
            std.mem.writeInt(u24, header[1..4], @intCast(zeroed.len), .big);
            transcript.update(&header);
            transcript.update(zeroed);
        },
        .truncated_length => {
            // Correctly truncated, but the header declares how much is being
            // hashed rather than how long the message is.
            const truncated = hello[0 .. hello.len - (2 + binders_len)];
            std.mem.writeInt(u24, header[1..4], @intCast(truncated.len), .big);
            transcript.update(&header);
            transcript.update(truncated);
        },
    }
    const digest = transcript.final();

    var ks = try tls.KeySchedule.init(allocator, .sha256);
    defer ks.deinit();
    try ks.deriveEarlySecret(&session.psk);

    const binder_key = try ks.resumptionBinderKey();
    defer allocator.free(binder_key);

    const binder = try tls.verifyData(allocator, .sha256, binder_key, &digest);
    defer allocator.free(binder);

    @memcpy(hello[hello.len - 32 ..], binder);
}

/// Rebuild `hello` without its `psk_key_exchange_modes` extension, correctly
/// bound so that the offer's only defect is the missing announcement.
///
/// The obvious shortcut -- overwriting the extension's type code in place --
/// does not work, and quietly produced a test with no teeth. Those two bytes lie
/// inside the region the binder covers, so the edit invalidates the binder and
/// the server rejects the offer for the wrong reason. Removing the
/// `psk_dhe_ke` requirement from the server left every test passing until this
/// was rebuilt. The offer has to be genuinely well formed and genuinely bound,
/// differing from an acceptable one only in that the client never said it would
/// perform ECDHE -- which is what makes honouring it a loss of forward secrecy.
fn withoutPskModes(
    allocator: std.mem.Allocator,
    hello: []const u8,
    session: *const tls_client.ResumptionSession,
) ![]u8 {
    const wire = [_]u8{ 0, 45, 0, 2, 1, 1 };
    const at = std.mem.indexOf(u8, hello, &wire) orelse
        return error.TestExpectedPskModesExtension;
    const ext_len_at = try extensionsLengthOffset(hello);

    const out = try allocator.alloc(u8, hello.len - wire.len);
    errdefer allocator.free(out);
    @memcpy(out[0..at], hello[0..at]);
    @memcpy(out[at..], hello[at + wire.len ..]);

    // The extensions vector's own length prefix shrinks with it, or every
    // length in the message disagrees and the server never reaches the binder.
    const shrunk = std.mem.readInt(u16, out[ext_len_at..][0..2], .big) - @as(u16, wire.len);
    std.mem.writeInt(u16, out[ext_len_at..][0..2], shrunk, .big);

    // Bound through the same helper the RFC 8448 vector anchors, so this is a
    // binder the server is obliged to accept if it looks at nothing else.
    const digest = try tls.clientHelloBinderTranscript(out, 1 + 32);
    var ks = try tls.KeySchedule.init(allocator, .sha256);
    defer ks.deinit();
    try ks.deriveEarlySecret(&session.psk);

    const binder_key = try ks.resumptionBinderKey();
    defer allocator.free(binder_key);

    const binder = try tls.verifyData(allocator, .sha256, binder_key, &digest);
    defer allocator.free(binder);

    @memcpy(out[out.len - 32 ..], binder);
    return out;
}

/// Offset of the two-byte extensions-vector length in a ClientHello body.
fn extensionsLengthOffset(body: []const u8) !usize {
    var pos: usize = 2 + 32; // legacy_version, random
    if (pos >= body.len) return error.TestMalformedHello;
    pos += 1 + @as(usize, body[pos]); // legacy_session_id
    if (pos + 2 > body.len) return error.TestMalformedHello;
    pos += 2 + @as(usize, std.mem.readInt(u16, body[pos..][0..2], .big)); // cipher_suites
    if (pos >= body.len) return error.TestMalformedHello;
    pos += 1 + @as(usize, body[pos]); // legacy_compression_methods
    if (pos + 2 > body.len) return error.TestMalformedHello;
    return pos;
}
