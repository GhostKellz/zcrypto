//! TLS 1.3 and QUIC cryptographic operations
//!
//! Key derivation, encryption, and decryption routines for TLS 1.3 and QUIC.
//! Implements RFC 8446 (TLS 1.3) and RFC 9001 (QUIC-TLS).

const std = @import("std");
const sym = @import("sym.zig");
const kdf = @import("kdf.zig");
const hash = @import("hash.zig");
const util = @import("util.zig");
const asym = @import("asym.zig");

const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

fn hkdfExtract(hash_alg: config.HashAlgorithm, salt: []const u8, ikm: []const u8, out: []u8) !void {
    switch (hash_alg) {
        .sha256 => {
            const extracted = std.crypto.kdf.hkdf.HkdfSha256.extract(salt, ikm);
            @memcpy(out, &extracted);
        },
        .sha384 => {
            const extracted = HkdfSha384.extract(salt, ikm);
            @memcpy(out, &extracted);
        },
        .sha512 => {
            const extracted = std.crypto.kdf.hkdf.HkdfSha512.extract(salt, ikm);
            @memcpy(out, &extracted);
        },
    }
}

// Re-export high-level modules for convenience
pub const config = @import("tls_config.zig");
pub const client = @import("tls_client.zig");
pub const server = @import("tls_server.zig");
pub const record = @import("tls_record.zig");
pub const errors = @import("errors.zig");

/// QUIC connection ID type
pub const ConnectionId = []const u8;

/// Initial secrets for QUIC connection
pub const Secrets = struct {
    client_initial_secret: [32]u8,
    server_initial_secret: [32]u8,

    /// Derive traffic keys from initial secrets
    pub fn deriveKeys(self: Secrets, allocator: std.mem.Allocator, is_client: bool) !TrafficKeys {
        const secret = if (is_client) self.client_initial_secret else self.server_initial_secret;

        const key = try kdf.hkdfExpandLabel(allocator, &secret, "quic key", "", 16);
        const iv = try kdf.hkdfExpandLabel(allocator, &secret, "quic iv", "", 12);
        const hp = try kdf.hkdfExpandLabel(allocator, &secret, "quic hp", "", 16);

        return TrafficKeys{
            .key = key[0..16].*,
            .iv = iv[0..12].*,
            .hp = hp[0..16].*,
            .allocator = allocator,
            .owned_key = key,
            .owned_iv = iv,
            .owned_hp = hp,
        };
    }
};

/// Traffic keys for encryption/decryption
pub const TrafficKeys = struct {
    key: [16]u8, // AES-128 key
    iv: [12]u8, // GCM IV
    hp: [16]u8, // Header protection key
    allocator: std.mem.Allocator,
    owned_key: []u8,
    owned_iv: []u8,
    owned_hp: []u8,

    pub fn deinit(self: TrafficKeys) void {
        self.allocator.free(self.owned_key);
        self.allocator.free(self.owned_iv);
        self.allocator.free(self.owned_hp);
    }
};

/// QUIC initial salt (RFC 9001)
const QUIC_INITIAL_SALT = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

/// Derive initial secrets from QUIC connection ID
pub fn deriveInitialSecrets(cid: ConnectionId, is_client: bool) Secrets {
    // Extract phase: HKDF-Extract with QUIC initial salt
    const initial_secret = std.crypto.kdf.hkdf.HkdfSha256.extract(&QUIC_INITIAL_SALT, cid);

    // Expand phase: derive client and server initial secrets
    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;

    // Use TLS 1.3 labels
    const client_label = "client in";
    const server_label = "server in";

    // Construct HKDF labels manually for exact TLS 1.3 compliance
    var client_hkdf_label: [32]u8 = undefined;
    var server_hkdf_label: [32]u8 = undefined;

    // Length (32 = 0x0020)
    client_hkdf_label[0] = 0x00;
    client_hkdf_label[1] = 0x20;

    // Label length and content for client
    client_hkdf_label[2] = @intCast(6 + client_label.len); // "tls13 " + label
    @memcpy(client_hkdf_label[3..9], "tls13 ");
    @memcpy(client_hkdf_label[9..18], client_label);
    client_hkdf_label[18] = 0; // Context length (empty)

    // Same for server
    server_hkdf_label[0] = 0x00;
    server_hkdf_label[1] = 0x20;
    server_hkdf_label[2] = @intCast(6 + server_label.len);
    @memcpy(server_hkdf_label[3..9], "tls13 ");
    @memcpy(server_hkdf_label[9..18], server_label);
    server_hkdf_label[18] = 0;

    // HKDF-Expand
    std.crypto.kdf.hkdf.HkdfSha256.expand(&client_secret, client_hkdf_label[0..19], initial_secret);
    std.crypto.kdf.hkdf.HkdfSha256.expand(&server_secret, server_hkdf_label[0..19], initial_secret);

    _ = is_client; // Parameter for API compatibility

    return Secrets{
        .client_initial_secret = client_secret,
        .server_initial_secret = server_secret,
    };
}

/// TLS 1.3 HKDF-Expand-Label (matches your API docs)
pub fn hkdfExpandLabel(
    allocator: std.mem.Allocator,
    secret: []const u8,
    label: []const u8,
    length: usize,
) ![]u8 {
    return kdf.hkdfExpandLabel(allocator, secret, label, "", length);
}

/// AES-128-GCM encryption (matches your API docs)
pub fn encryptAesGcm(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    plaintext: []const u8,
    aad: []const u8,
) !sym.Ciphertext {
    if (key.len != 16) return error.InvalidKeySize;
    if (nonce.len != 12) return error.InvalidNonceSize;

    const key_array: [16]u8 = key[0..16].*;
    const nonce_array: [12]u8 = nonce[0..12].*;

    return sym.encryptAes128Gcm(allocator, key_array, nonce_array, plaintext, aad);
}

/// AES-128-GCM decryption (matches your API docs)
pub fn decryptAesGcm(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    aad: []const u8,
) ![]u8 {
    if (key.len != 16) return error.InvalidKeySize;
    if (nonce.len != 12) return error.InvalidNonceSize;
    if (tag.len != 16) return error.InvalidTagSize;

    const key_array: [16]u8 = key[0..16].*;
    const nonce_array: [12]u8 = nonce[0..12].*;
    const tag_array: [16]u8 = tag[0..16].*;

    const plaintext = try sym.decryptAes128Gcm(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
    return plaintext;
}

/// Compute packet number from truncated packet number (RFC 9000 Section A.3)
pub fn computePacketNumber(largest_pn: u64, truncated_pn: u32, pn_nbits: u8) u64 {
    const expected_pn = largest_pn + 1;
    const pn_win = @as(u64, 1) << @intCast(pn_nbits);
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;

    // Reconstruct packet number by taking high bits from expected_pn
    // and low bits from truncated_pn
    const candidate_pn = (expected_pn & ~pn_mask) | @as(u64, truncated_pn);

    // Choose the candidate closest to expected_pn
    if (candidate_pn + pn_hwin <= expected_pn) {
        return candidate_pn + pn_win;
    } else if (candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    } else {
        return candidate_pn;
    }
}

/// Key schedule state for TLS 1.3
pub const KeySchedule = struct {
    /// Hash algorithm being used
    hash_alg: config.HashAlgorithm,
    /// Early secret
    early_secret: []u8,
    /// Handshake secret
    handshake_secret: []u8,
    /// Master secret
    master_secret: []u8,
    /// Allocator
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, hash_alg: config.HashAlgorithm) !KeySchedule {
        const hash_len = hash_alg.digestSize();

        return KeySchedule{
            .hash_alg = hash_alg,
            .early_secret = try allocator.alloc(u8, hash_len),
            .handshake_secret = try allocator.alloc(u8, hash_len),
            .master_secret = try allocator.alloc(u8, hash_len),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: KeySchedule) void {
        util.secureZero(self.early_secret);
        util.secureZero(self.handshake_secret);
        util.secureZero(self.master_secret);
        self.allocator.free(self.early_secret);
        self.allocator.free(self.handshake_secret);
        self.allocator.free(self.master_secret);
    }

    /// Derive early secret from PSK (or zeros)
    pub fn deriveEarlySecret(self: *KeySchedule, psk: ?[]const u8) !void {
        const zero_hash = try self.allocator.alloc(u8, self.hash_alg.digestSize());
        defer self.allocator.free(zero_hash);
        @memset(zero_hash, 0);

        const ikm = psk orelse zero_hash;

        switch (self.hash_alg) {
            .sha256 => {
                try hkdfExtract(self.hash_alg, &[_]u8{0}, ikm, self.early_secret);
            },
            .sha384, .sha512 => {
                try hkdfExtract(self.hash_alg, &[_]u8{0}, ikm, self.early_secret);
            },
        }
    }

    /// Derive handshake secret from ECDHE shared secret
    pub fn deriveHandshakeSecret(self: *KeySchedule, ecdhe_secret: []const u8) !void {
        const derived_secret = try self.deriveSecret(self.early_secret, "derived", "");
        defer self.allocator.free(derived_secret);

        switch (self.hash_alg) {
            .sha256 => {
                try hkdfExtract(self.hash_alg, derived_secret, ecdhe_secret, self.handshake_secret);
            },
            .sha384, .sha512 => {
                try hkdfExtract(self.hash_alg, derived_secret, ecdhe_secret, self.handshake_secret);
            },
        }
    }

    /// Derive master secret
    pub fn deriveMasterSecret(self: *KeySchedule) !void {
        const derived_secret = try self.deriveSecret(self.handshake_secret, "derived", "");
        defer self.allocator.free(derived_secret);

        const zero_hash = try self.allocator.alloc(u8, self.hash_alg.digestSize());
        defer self.allocator.free(zero_hash);
        @memset(zero_hash, 0);

        switch (self.hash_alg) {
            .sha256 => {
                try hkdfExtract(self.hash_alg, derived_secret, zero_hash, self.master_secret);
            },
            .sha384, .sha512 => {
                try hkdfExtract(self.hash_alg, derived_secret, zero_hash, self.master_secret);
            },
        }
    }

    /// TLS 1.3 Derive-Secret over raw handshake messages, hashed here.
    ///
    ///     Derive-Secret(Secret, Label, Messages) =
    ///         HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    ///
    /// `messages` is the message list, not its digest. RFC 8446 Section 7.1
    /// writes the third argument as `""` for the two "derived" steps, and this
    /// overload is what makes that literal correct: `Transcript-Hash("")` is
    /// `Hash("")`, which is what those steps consume.
    ///
    /// A handshake does not have a message list to hand -- it hashes the
    /// transcript incrementally and holds the running digest. Those callers want
    /// `deriveSecretFromTranscriptHash`. Passing an already-computed digest here
    /// hashes it a second time and yields a secret no peer will ever derive; it
    /// is self-consistent between two endpoints running this same code, so a
    /// round-trip test cannot see it, which is how it survived until the
    /// RFC 8448 vectors were added.
    pub fn deriveSecret(self: *KeySchedule, secret: []const u8, label: []const u8, messages: []const u8) ![]u8 {
        const hash_len = self.hash_alg.digestSize();
        const transcript_hash = try self.allocator.alloc(u8, hash_len);
        defer self.allocator.free(transcript_hash);

        // Hash the messages
        switch (self.hash_alg) {
            .sha256 => {
                var h = hash.Sha256.init();
                h.update(messages);
                const result = h.final();
                @memcpy(transcript_hash, &result);
            },
            .sha384 => {
                var h = std.crypto.hash.sha2.Sha384.init(.{});
                h.update(messages);
                var result: [48]u8 = undefined;
                h.final(&result);
                @memcpy(transcript_hash, &result);
            },
            .sha512 => {
                var h = hash.Sha512.init();
                h.update(messages);
                const result = h.final();
                @memcpy(transcript_hash, &result);
            },
        }

        return self.deriveSecretFromTranscriptHash(secret, label, transcript_hash);
    }

    /// TLS 1.3 Derive-Secret where `Transcript-Hash(Messages)` is already known.
    ///
    /// This is the form every handshake actually needs. The transcript is hashed
    /// incrementally as messages go by, so what a connection holds at a
    /// derivation point is the digest, never the message list.
    ///
    /// The length check is the whole point of the separation being a distinct
    /// function rather than a convention: a caller that reaches for this one with
    /// a raw message list gets `InvalidTranscriptHash` instead of a plausible
    /// secret. Without it the two overloads would differ only in a comment, and
    /// the confusion they exist to prevent would be free to recur.
    pub fn deriveSecretFromTranscriptHash(
        self: *KeySchedule,
        secret: []const u8,
        label: []const u8,
        transcript_hash: []const u8,
    ) ![]u8 {
        const hash_len = self.hash_alg.digestSize();
        if (transcript_hash.len != hash_len) return error.InvalidTranscriptHash;
        return kdf.hkdfExpandLabel(self.allocator, secret, label, transcript_hash, hash_len);
    }

    /// The PSK binder key, RFC 8446 Section 7.1:
    ///
    ///     Derive-Secret(Early Secret, "res binder", "")
    ///
    /// The `""` is the RFC's literal and is correct here for the same reason it
    /// is in the two "derived" steps: the binder key itself is bound to no
    /// transcript. What the binder is bound to arrives separately, as the digest
    /// handed to `verifyData`.
    ///
    /// Only meaningful once `deriveEarlySecret` has been given the resumption
    /// PSK. Called after `deriveEarlySecret(null)` it returns a key derived from
    /// zeros, which is a perfectly well-formed value that no peer will ever
    /// agree with; the ordering is the caller's to get right.
    pub fn resumptionBinderKey(self: *KeySchedule) ![]u8 {
        return self.deriveSecret(self.early_secret, "res binder", "");
    }
};

/// Feed one complete handshake message into a transcript hash.
///
/// RFC 8446 Section 4.4.1 hashes the concatenation of the handshake messages,
/// and a handshake message is its four-byte `HandshakeType || uint24 length`
/// header followed by the body. The header is part of the hash input, not
/// framing to be stripped before hashing. RFC 8448's traces show this directly:
/// the binder transcript in Section 4 is a digest of a ClientHello prefix that
/// begins `01 00 01 fc`, and `known_answer_vectors.zig` checks it.
///
/// This exists because the send path holds a body it is about to write a header
/// for, and the receive path holds a body whose header has already been
/// stripped. Both must hash the same bytes a conforming peer does, so both
/// reconstruct the header here rather than each open-coding it.
///
/// `msg_type` is the raw byte rather than the `HandshakeType` enum so that this
/// stays free of a dependency on the client module's wire enums.
///
/// Deliberately not folded into the send and receive helpers: callers must keep
/// control of *when* a message enters the transcript, because Finished is
/// verified against the transcript that excludes it and CertificateVerify signs
/// the transcript that excludes itself.
pub fn transcriptUpdate(transcript: *hash.Sha256, msg_type: u8, body: []const u8) void {
    var header: [4]u8 = undefined;
    header[0] = msg_type;
    std.mem.writeInt(u24, header[1..4], @intCast(body.len), .big);
    transcript.update(&header);
    transcript.update(body);
}

/// The prefix of a ClientHello that a PSK binder is computed over.
///
/// RFC 8446 Section 4.2.11.2: a binder is a MAC over the ClientHello up to and
/// including the `identities` list of the `pre_shared_key` extension, stopping
/// immediately before the `binders` list -- that list's own two-byte length
/// prefix included. The extension is required to be the last one in the message
/// exactly so that this region is a prefix, which is what lets the offering
/// client and the verifying server compute the same bytes.
///
/// `binders_len` is the value of the two-byte prefix, so the removed tail is
/// `2 + binders_len`. Since that tail is a suffix, this works equally on the
/// whole handshake message and on its body alone; `clientHelloBinderTranscript`
/// takes the body, because that is the form an endpoint has in hand.
///
/// A server calls this with a length it read out of an attacker-controlled
/// message, hence the bound check rather than an unchecked subtraction: a
/// `binders_len` larger than the message would otherwise underflow into a
/// slice covering most of the address space.
pub fn clientHelloBinderPrefix(client_hello: []const u8, binders_len: usize) ![]const u8 {
    const tail = 2 + binders_len;
    if (tail > client_hello.len) return error.MalformedClientHello;
    return client_hello[0 .. client_hello.len - tail];
}

/// `Transcript-Hash(Truncate(ClientHello))` -- the digest a PSK binder is a MAC
/// over, which is what both endpoints actually need.
///
/// `body` is the ClientHello body without its handshake header and *without* any
/// truncation applied: the whole message as it goes on the wire, binders and all.
///
/// The subtlety this exists to contain: the transcript covers the handshake
/// header (see `transcriptUpdate`), and the header still declares the length of
/// the *untruncated* ClientHello. Truncation removes bytes from the hash input
/// without renumbering the header, so the digest is over a byte string that is
/// not a well-formed handshake message. Writing this out at each call site
/// invites hashing the truncated length instead, which fails only against a real
/// peer -- both endpoints here would make the identical mistake and agree.
///
/// `known_answer_vectors.zig` pins this against RFC 8448 Section 4.
pub fn clientHelloBinderTranscript(body: []const u8, binders_len: usize) !hash.Sha256Hash {
    const truncated = try clientHelloBinderPrefix(body, binders_len);

    var header: [4]u8 = undefined;
    header[0] = 1; // client_hello
    std.mem.writeInt(u24, header[1..4], @intCast(body.len), .big);

    var transcript = hash.Sha256.init();
    transcript.update(&header);
    transcript.update(truncated);
    return transcript.final();
}

/// The Finished MAC, RFC 8446 Section 4.4.4:
///
///     finished_key = HKDF-Expand-Label(base_secret, "finished", "", Hash.length)
///     verify_data  = HMAC(finished_key, transcript_hash)
///
/// Also the PSK binder. RFC 8446 Section 4.2.11.2 defines a binder as exactly
/// this computation, taking the binder key as `base_secret` and the digest of
/// the truncated ClientHello as `transcript_hash` -- which is why there is one
/// function here rather than a third copy alongside the client's and the
/// server's. The binder path is then produced by code the existing handshake
/// tests already drive, and a correction to any of the three is a correction to
/// all of them.
///
/// Caller owns the returned buffer; it is `hash_alg.digestSize()` bytes.
pub fn verifyData(
    allocator: std.mem.Allocator,
    hash_alg: config.HashAlgorithm,
    base_secret: []const u8,
    transcript_hash: []const u8,
) ![]u8 {
    const hash_len = hash_alg.digestSize();
    if (transcript_hash.len != hash_len) return error.InvalidTranscriptHash;

    const finished_key = try kdf.hkdfExpandLabel(allocator, base_secret, "finished", "", hash_len);
    defer {
        util.secureZero(finished_key);
        allocator.free(finished_key);
    }

    const out = try allocator.alloc(u8, hash_len);
    errdefer allocator.free(out);

    switch (hash_alg) {
        .sha256 => std.crypto.auth.hmac.sha2.HmacSha256.create(out[0..32], transcript_hash, finished_key),
        .sha384 => std.crypto.auth.hmac.sha2.HmacSha384.create(out[0..48], transcript_hash, finished_key),
        .sha512 => std.crypto.auth.hmac.sha2.HmacSha512.create(out[0..64], transcript_hash, finished_key),
    }
    return out;
}

/// Transcript hash for TLS 1.3
pub const TranscriptHash = struct {
    hash_alg: config.HashAlgorithm,
    context: union(enum) {
        sha256: hash.Sha256,
        sha384: std.crypto.hash.sha2.Sha384,
        sha512: hash.Sha512,
    },

    pub fn init(hash_alg: config.HashAlgorithm) TranscriptHash {
        return switch (hash_alg) {
            .sha256 => .{
                .hash_alg = hash_alg,
                .context = .{ .sha256 = hash.Sha256.init() },
            },
            .sha384 => .{
                .hash_alg = hash_alg,
                .context = .{ .sha384 = std.crypto.hash.sha2.Sha384.init(.{}) },
            },
            .sha512 => .{
                .hash_alg = hash_alg,
                .context = .{ .sha512 = hash.Sha512.init() },
            },
        };
    }

    pub fn update(self: *TranscriptHash, data: []const u8) void {
        switch (self.context) {
            .sha256 => |*h| h.update(data),
            .sha384 => |*h| h.update(data),
            .sha512 => |*h| h.update(data),
        }
    }

    pub fn final(self: *TranscriptHash, out: []u8) void {
        switch (self.context) {
            .sha256 => |*h| {
                const result = h.final();
                @memcpy(out, &result);
            },
            .sha384 => |*h| {
                const len = @min(out.len, 48);
                var result: [48]u8 = undefined;
                h.final(&result);
                @memcpy(out[0..len], result[0..len]);
            },
            .sha512 => |*h| {
                const result = h.final();
                @memcpy(out, &result);
            },
        }
    }

    pub fn clone(self: TranscriptHash) TranscriptHash {
        return switch (self.context) {
            .sha256 => |h| .{
                .hash_alg = self.hash_alg,
                .context = .{ .sha256 = h },
            },
            .sha384 => |h| .{
                .hash_alg = self.hash_alg,
                .context = .{ .sha384 = h },
            },
            .sha512 => |h| .{
                .hash_alg = self.hash_alg,
                .context = .{ .sha512 = h },
            },
        };
    }
};

/// AEAD cipher for TLS 1.3
pub const AeadCipher = struct {
    cipher_suite: config.CipherSuite,
    key: []u8,
    iv: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, cipher_suite: config.CipherSuite, key: []const u8, iv: []const u8) !AeadCipher {
        const key_size = cipher_suite.keySize();
        if (key.len != key_size) return error.InvalidKeySize;
        if (iv.len != 12) return error.InvalidIvSize;

        return AeadCipher{
            .cipher_suite = cipher_suite,
            .key = try allocator.dupe(u8, key),
            .iv = try allocator.dupe(u8, iv),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: AeadCipher) void {
        util.secureZero(self.key);
        util.secureZero(self.iv);
        self.allocator.free(self.key);
        self.allocator.free(self.iv);
    }

    pub fn encrypt(self: AeadCipher, allocator: std.mem.Allocator, nonce: []const u8, plaintext: []const u8, aad: []const u8) !sym.Ciphertext {
        if (nonce.len != 12) return error.InvalidNonceSize;

        switch (self.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const key_array: [16]u8 = self.key[0..16].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                return sym.encryptAes128Gcm(allocator, key_array, nonce_array, plaintext, aad);
            },
            .TLS_AES_256_GCM_SHA384 => {
                const key_array: [32]u8 = self.key[0..32].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                return sym.encryptAes256Gcm(allocator, key_array, nonce_array, plaintext, aad);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const key_array: [32]u8 = self.key[0..32].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                // `ChaCha20Result` and `Ciphertext` have the same shape but are
                // distinct types. Move the buffer across rather than calling
                // `deinit`: ownership transfers to the returned `Ciphertext`.
                const result = try sym.encryptChaCha20Poly1305(allocator, key_array, nonce_array, plaintext, aad);
                return sym.Ciphertext{
                    .data = result.data,
                    .tag = result.tag,
                    .allocator = result.allocator,
                };
            },
        }
    }

    pub fn decrypt(self: AeadCipher, allocator: std.mem.Allocator, nonce: []const u8, ciphertext: []const u8, tag: []const u8, aad: []const u8) !?[]u8 {
        if (nonce.len != 12) return error.InvalidNonceSize;
        if (tag.len != 16) return error.InvalidTagSize;

        switch (self.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const key_array: [16]u8 = self.key[0..16].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                const tag_array: [16]u8 = tag[0..16].*;
                const plaintext = try sym.decryptAes128Gcm(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
                return plaintext;
            },
            .TLS_AES_256_GCM_SHA384 => {
                const key_array: [32]u8 = self.key[0..32].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                const tag_array: [16]u8 = tag[0..16].*;
                const plaintext = try sym.decryptAes256Gcm(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
                return plaintext;
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const key_array: [32]u8 = self.key[0..32].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                const tag_array: [16]u8 = tag[0..16].*;
                const plaintext = try sym.decryptChaCha20Poly1305(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
                return plaintext;
            },
        }
    }
};

// The transcript covers the handshake header, not just the body.
//
// The expected digests below were produced outside this codebase, by hashing
// `HandshakeType || uint24 length || body` directly, precisely because a
// transcript this implementation computes for itself proves nothing: for a
// long time both endpoints here hashed bodies alone, agreed with each other,
// and passed every handshake test in the repository while disagreeing with
// every conforming peer. `known_answer_vectors.zig` anchors the same rule to
// RFC 8448, where the binder transcript is a digest over a ClientHello prefix
// that starts with its own `01 00 01 fc` header.
test "the transcript hashes the handshake header along with the body" {
    // A plausible Finished body: 32 bytes, distinct from each other so that a
    // length or ordering slip shows up rather than cancelling out.
    const counting: [32]u8 = blk: {
        var b: [32]u8 = undefined;
        for (&b, 0..) |*x, i| x.* = @intCast(i);
        break :blk b;
    };

    const cases = .{
        .{
            .msg_type = @as(u8, 1), // client_hello
            .body = @as([]const u8, "hello world"),
            .framed = "dd0043d37eb13f2d9830f6b7abf1dae2b6f132e24311c20e77d537c6ea561661",
            .body_only = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        },
        .{
            .msg_type = @as(u8, 20), // finished
            .body = @as([]const u8, &counting),
            .framed = "2d8a5e23181b4135734b78755bf84e16e36ee15444ad0b6dea571108842231f7",
            .body_only = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
        },
    };

    inline for (cases) |case| {
        var expected_framed: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_framed, case.framed);
        var expected_body_only: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_body_only, case.body_only);

        var transcript = hash.Sha256.init();
        transcriptUpdate(&transcript, case.msg_type, case.body);
        const digest = transcript.final();

        try std.testing.expectEqualSlices(u8, &expected_framed, &digest);

        // The regression this replaces, stated so it cannot creep back: hashing
        // the body alone is a different transcript, not a harmless framing
        // choice.
        try std.testing.expect(!std.mem.eql(u8, &expected_body_only, &digest));
    }
}

// Message boundaries are part of the transcript, not just the byte stream.
//
// Two messages whose bodies concatenate to the same bytes must still produce
// different transcripts, because each contributes its own length header. A
// transcript that hashed bodies alone would collapse these two, which is the
// property that lets a peer re-cut a handshake into different messages without
// disturbing the Finished MACs.
test "the transcript distinguishes different message framings of the same bytes" {
    var one = hash.Sha256.init();
    transcriptUpdate(&one, 1, "abcdef");

    var two = hash.Sha256.init();
    transcriptUpdate(&two, 1, "abc");
    transcriptUpdate(&two, 1, "def");

    try std.testing.expect(!std.mem.eql(u8, &one.final(), &two.final()));
}

test "derive initial secrets" {
    const cid = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    const secrets = deriveInitialSecrets(&cid, true);

    // Should produce 32-byte secrets
    try std.testing.expectEqual(@as(usize, 32), secrets.client_initial_secret.len);
    try std.testing.expectEqual(@as(usize, 32), secrets.server_initial_secret.len);

    // Client and server secrets should be different
    try std.testing.expect(!util.constantTimeEqualArray([32]u8, secrets.client_initial_secret, secrets.server_initial_secret));
}

test "traffic key derivation" {
    const allocator = std.testing.allocator;

    const cid = [_]u8{ 0x42, 0x69, 0x13, 0x37 };
    const secrets = deriveInitialSecrets(&cid, true);

    const client_keys = try secrets.deriveKeys(allocator, true);
    defer client_keys.deinit();

    const server_keys = try secrets.deriveKeys(allocator, false);
    defer server_keys.deinit();

    // Keys should be different
    try std.testing.expect(!util.constantTimeEqualArray([16]u8, client_keys.key, server_keys.key));
    try std.testing.expect(!util.constantTimeEqualArray([12]u8, client_keys.iv, server_keys.iv));
}

test "quic traffic key derivation uses quic labels" {
    const allocator = std.testing.allocator;

    const secrets = Secrets{
        .client_initial_secret = blk: {
            var bytes = std.mem.zeroes([32]u8);
            @memset(bytes[0..], 0x42);
            break :blk bytes;
        },
        .server_initial_secret = blk: {
            var bytes = std.mem.zeroes([32]u8);
            @memset(bytes[0..], 0x24);
            break :blk bytes;
        },
    };

    const traffic = try secrets.deriveKeys(allocator, true);
    defer traffic.deinit();

    const generic_key = try kdf.hkdfExpandLabel(allocator, &secrets.client_initial_secret, "key", "", 16);
    defer allocator.free(generic_key);

    try std.testing.expect(!std.mem.eql(u8, generic_key, &traffic.key));
}

test "aes-gcm encryption integration" {
    const allocator = std.testing.allocator;

    const key = blk: {
        var bytes = std.mem.zeroes([16]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const nonce = blk: {
        var bytes = std.mem.zeroes([12]u8);
        @memset(bytes[0..], 0x69);
        break :blk bytes;
    };
    const plaintext = "Hello, QUIC!";
    const aad = "packet header";

    // Encrypt
    const ciphertext = try encryptAesGcm(allocator, &key, &nonce, plaintext, aad);
    defer ciphertext.deinit();

    // Decrypt
    const decrypted = try decryptAesGcm(allocator, &key, &nonce, ciphertext.data, &ciphertext.tag, aad);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "hkdf expand label integration" {
    const allocator = std.testing.allocator;

    const secret = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x23);
        break :blk bytes;
    };
    const label = "test label";

    const derived = try hkdfExpandLabel(allocator, &secret, label, 32);
    defer allocator.free(derived);

    try std.testing.expectEqual(@as(usize, 32), derived.len);
}

test "packet number computation" {
    // Test cases based on RFC 9000 Appendix A.3
    // Case: largest_pn=0xa82f30ea, truncated=0xac (8 bits)
    // Should reconstruct to 0xa82f30ac
    const result1 = computePacketNumber(0xa82f30ea, 0xac, 8);
    try std.testing.expectEqual(@as(u64, 0xa82f30ac), result1);

    // Additional test cases
    const result2 = computePacketNumber(0xa82f30ea, 0x9b, 8);
    try std.testing.expectEqual(@as(u64, 0xa82f309b), result2);

    // Test edge case with wraparound
    const result3 = computePacketNumber(0xff, 0x00, 8);
    try std.testing.expectEqual(@as(u64, 0x100), result3);
}

const TlsKeyDerivationData = struct {
    secrets: Secrets,
    is_client: bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *TlsKeyDerivationData) void {
        self.allocator.destroy(self);
    }
};

const HandshakeSecretsData = struct {
    handshake_secret: [32]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *HandshakeSecretsData) void {
        self.allocator.destroy(self);
    }
};

const ApplicationSecretsData = struct {
    master_secret: [32]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ApplicationSecretsData) void {
        self.allocator.destroy(self);
    }
};

/// Elapsed nanoseconds since `start`, or null if the duration is unknown.
///
/// Null covers all three ways the measurement can be unavailable -- the start
/// read failed, the end read failed, or the clock went backwards -- because a
/// caller can act on none of them differently: each means there is no duration
/// to report. The workers below call this rather than subtracting timestamps,
/// which is what let a failed clock read turn into a plausible-looking number.
fn elapsedNsSince(start: ?util.Instant) ?u64 {
    const begin = start orelse return null;
    const end = util.getMonotonic() orelse return null;
    return end.since(begin) catch null;
}

test "an unreadable start clock yields no duration rather than a number" {
    // The failure this guards is not a wrong duration, it is a duration that
    // looks right. The previous code read the wall clock with a 0 fallback, so a
    // failed start read published `end - 0` -- the whole Unix epoch, about 56
    // years -- through the same field a real measurement uses, and no caller
    // could tell the two apart. Passing null is how a caller sees that failure.
    try std.testing.expectEqual(@as(?u64, null), elapsedNsSince(null));
}

test "a readable clock still produces a duration" {
    // Pairs with the test above so that neither passes alone: a helper hardwired
    // to return null would satisfy the null case while measuring nothing.
    const start = util.getMonotonic() orelse return error.SkipZigTest;
    const elapsed = elapsedNsSince(start) orelse return error.TestUnexpectedResult;
    // Only an upper bound is asserted. Two adjacent reads may legitimately land
    // on the same tick, so `> 0` would be a timing race; a full minute between
    // them would not be.
    try std.testing.expect(elapsed < std.time.ns_per_min);
}

fn tlsKeyDerivationWorker(task_data: *TlsKeyDerivationData) @import("async_crypto.zig").AsyncCryptoResult {
    const start_time = util.getMonotonic();
    defer task_data.deinit();

    const traffic_keys = task_data.secrets.deriveKeys(task_data.allocator, task_data.is_client) catch |err| {
        const elapsed = elapsedNsSince(start_time);
        const error_msg = std.fmt.allocPrint(task_data.allocator, "TLS key derivation failed: {}", .{err}) catch "TLS key derivation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };

    // Serialize traffic keys to bytes for result
    const key_data = task_data.allocator.alloc(u8, 16 + 12 + 16) catch {
        traffic_keys.deinit();
        const elapsed = elapsedNsSince(start_time);
        const error_msg = task_data.allocator.dupe(u8, "Memory allocation failed") catch "Memory allocation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };

    @memcpy(key_data[0..16], &traffic_keys.key);
    @memcpy(key_data[16..28], &traffic_keys.iv);
    @memcpy(key_data[28..44], &traffic_keys.hp);
    traffic_keys.deinit();

    const elapsed = elapsedNsSince(start_time);
    return @import("async_crypto.zig").AsyncCryptoResult.success_result(key_data, elapsed);
}

fn handshakeSecretsWorker(task_data: *HandshakeSecretsData) @import("async_crypto.zig").AsyncCryptoResult {
    const start_time = util.getMonotonic();
    defer task_data.deinit();

    // Derive client and server handshake secrets
    const client_secret = kdf.hkdfExpandLabel(task_data.allocator, &task_data.handshake_secret, "c hs traffic", "", 32) catch |err| {
        const elapsed = elapsedNsSince(start_time);
        const error_msg = std.fmt.allocPrint(task_data.allocator, "Client handshake secret derivation failed: {}", .{err}) catch "Client handshake secret derivation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };
    defer task_data.allocator.free(client_secret);

    const server_secret = kdf.hkdfExpandLabel(task_data.allocator, &task_data.handshake_secret, "s hs traffic", "", 32) catch |err| {
        const elapsed = elapsedNsSince(start_time);
        const error_msg = std.fmt.allocPrint(task_data.allocator, "Server handshake secret derivation failed: {}", .{err}) catch "Server handshake secret derivation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };
    defer task_data.allocator.free(server_secret);

    // Combine secrets for result
    const combined_secrets = task_data.allocator.alloc(u8, 64) catch {
        const elapsed = elapsedNsSince(start_time);
        const error_msg = task_data.allocator.dupe(u8, "Memory allocation failed") catch "Memory allocation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };

    @memcpy(combined_secrets[0..32], client_secret);
    @memcpy(combined_secrets[32..64], server_secret);

    const elapsed = elapsedNsSince(start_time);
    return @import("async_crypto.zig").AsyncCryptoResult.success_result(combined_secrets, elapsed);
}

fn applicationSecretsWorker(task_data: *ApplicationSecretsData) @import("async_crypto.zig").AsyncCryptoResult {
    const start_time = util.getMonotonic();
    defer task_data.deinit();

    // Derive client and server application secrets
    const client_secret = kdf.hkdfExpandLabel(task_data.allocator, &task_data.master_secret, "c ap traffic", "", 32) catch |err| {
        const elapsed = elapsedNsSince(start_time);
        const error_msg = std.fmt.allocPrint(task_data.allocator, "Client application secret derivation failed: {}", .{err}) catch "Client application secret derivation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };
    defer task_data.allocator.free(client_secret);

    const server_secret = kdf.hkdfExpandLabel(task_data.allocator, &task_data.master_secret, "s ap traffic", "", 32) catch |err| {
        const elapsed = elapsedNsSince(start_time);
        const error_msg = std.fmt.allocPrint(task_data.allocator, "Server application secret derivation failed: {}", .{err}) catch "Server application secret derivation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };
    defer task_data.allocator.free(server_secret);

    // Combine secrets for result
    const combined_secrets = task_data.allocator.alloc(u8, 64) catch {
        const elapsed = elapsedNsSince(start_time);
        const error_msg = task_data.allocator.dupe(u8, "Memory allocation failed") catch "Memory allocation failed";
        return @import("async_crypto.zig").AsyncCryptoResult.error_result(error_msg, elapsed);
    };

    @memcpy(combined_secrets[0..32], client_secret);
    @memcpy(combined_secrets[32..64], server_secret);

    const elapsed = elapsedNsSince(start_time);
    return @import("async_crypto.zig").AsyncCryptoResult.success_result(combined_secrets, elapsed);
}
