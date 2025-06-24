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

        const key = try kdf.hkdfExpandLabel(allocator, &secret, "key", "", 16);
        const iv = try kdf.hkdfExpandLabel(allocator, &secret, "iv", "", 12);
        const hp = try kdf.hkdfExpandLabel(allocator, &secret, "hp", "", 16);

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
) !?[]u8 {
    if (key.len != 16) return error.InvalidKeySize;
    if (nonce.len != 12) return error.InvalidNonceSize;
    if (tag.len != 16) return error.InvalidTagSize;

    const key_array: [16]u8 = key[0..16].*;
    const nonce_array: [12]u8 = nonce[0..12].*;
    const tag_array: [16]u8 = tag[0..16].*;

    return sym.decryptAes128Gcm(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
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
                const extracted = std.crypto.kdf.hkdf.HkdfSha256.extract(&[_]u8{0}, ikm);
                @memcpy(self.early_secret, &extracted);
            },
            .sha384, .sha512 => {
                // For now, fall back to SHA256 for SHA384/SHA512
                // TODO: Implement proper SHA384/SHA512 HKDF when available
                const extracted = std.crypto.kdf.hkdf.HkdfSha256.extract(&[_]u8{0}, ikm);
                @memcpy(self.early_secret[0..32], &extracted);
            },
        }
    }

    /// Derive handshake secret from ECDHE shared secret
    pub fn deriveHandshakeSecret(self: *KeySchedule, ecdhe_secret: []const u8) !void {
        const derived_secret = try self.deriveSecret(self.early_secret, "derived", "");
        defer self.allocator.free(derived_secret);

        switch (self.hash_alg) {
            .sha256 => {
                const extracted = std.crypto.kdf.hkdf.HkdfSha256.extract(derived_secret, ecdhe_secret);
                @memcpy(self.handshake_secret, &extracted);
            },
            .sha384, .sha512 => {
                const extracted = std.crypto.kdf.hkdf.HkdfSha256.extract(derived_secret, ecdhe_secret);
                @memcpy(self.handshake_secret[0..32], &extracted);
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
                const extracted = std.crypto.kdf.hkdf.HkdfSha256.extract(derived_secret, zero_hash);
                @memcpy(self.master_secret, &extracted);
            },
            .sha384, .sha512 => {
                const extracted = std.crypto.kdf.hkdf.HkdfSha256.extract(derived_secret, zero_hash);
                @memcpy(self.master_secret[0..32], &extracted);
            },
        }
    }

    /// Derive a secret using TLS 1.3 Derive-Secret
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

        return kdf.hkdfExpandLabel(self.allocator, secret, label, transcript_hash, hash_len);
    }
};

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
                return sym.encryptChaCha20Poly1305(allocator, key_array, nonce_array, plaintext, aad);
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
                return sym.decryptAes128Gcm(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
            },
            .TLS_AES_256_GCM_SHA384 => {
                const key_array: [32]u8 = self.key[0..32].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                const tag_array: [16]u8 = tag[0..16].*;
                return sym.decryptAes256Gcm(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const key_array: [32]u8 = self.key[0..32].*;
                const nonce_array: [12]u8 = nonce[0..12].*;
                const tag_array: [16]u8 = tag[0..16].*;
                return sym.decryptChaCha20Poly1305(allocator, key_array, nonce_array, ciphertext, tag_array, aad);
            },
        }
    }
};

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

test "aes-gcm encryption integration" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x69} ** 12;
    const plaintext = "Hello, QUIC!";
    const aad = "packet header";

    // Encrypt
    const ciphertext = try encryptAesGcm(allocator, &key, &nonce, plaintext, aad);
    defer ciphertext.deinit();

    // Decrypt
    const decrypted = try decryptAesGcm(allocator, &key, &nonce, ciphertext.data, &ciphertext.tag, aad);
    defer if (decrypted) |d| allocator.free(d);

    try std.testing.expect(decrypted != null);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted.?);
}

test "hkdf expand label integration" {
    const allocator = std.testing.allocator;

    const secret = "test secret for hkdf";
    const label = "test label";

    const derived = try hkdfExpandLabel(allocator, secret, label, 32);
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
