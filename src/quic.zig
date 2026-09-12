//! QUIC Cryptography Module for zcrypto
//!
//! Provides cryptographic operations specifically designed for QUIC protocol:
//! - QUIC-specific key derivation (RFC 9001)
//! - Packet number protection and header protection
//! - AEAD encryption/decryption for QUIC packets
//! - Post-quantum QUIC extensions
//! This module integrates seamlessly with zquic for optimal performance.

const std = @import("std");
const root = @import("root.zig");
const kdf = @import("kdf.zig");
const sym = @import("sym.zig");
const pq = @import("pq.zig");
const security = @import("security.zig");

fn addChecked(a: usize, b: usize) QuicError!usize {
    return std.math.add(usize, a, b) catch QuicError.HeaderProtectionFailed;
}

/// Decode a QUIC variable-length integer (RFC 9000 Section 16). The top two
/// bits of the first byte select a 1, 2, 4, or 8 byte encoding.
fn decodeVarint(buf: []const u8) QuicError!struct { value: u64, len: usize } {
    if (buf.len == 0) return QuicError.HeaderProtectionFailed;
    const len = @as(usize, 1) << @as(u2, @intCast(buf[0] >> 6));
    if (buf.len < len) return QuicError.HeaderProtectionFailed;

    var value: u64 = buf[0] & 0x3f;
    for (buf[1..len]) |b| {
        value = (value << 8) | b;
    }
    return .{ .value = value, .len = len };
}

fn packetKeysAreInitialized(keys: *const PacketKeys) bool {
    return !std.mem.allEqual(u8, &keys.aead_key, 0) and
        !std.mem.allEqual(u8, &keys.header_protection_key, 0) and
        !std.mem.allEqual(u8, &keys.iv, 0);
}

/// QUIC cryptography errors
pub const QuicError = error{
    InvalidConnectionId,
    InvalidPacketNumber,
    InvalidKeys,
    PacketDecryptionFailed,
    HeaderProtectionFailed,
    KeyDerivationFailed,
    InvalidCipherSuite,
    EncryptionFailed,
    DecryptionFailed,
    InvalidPacket,
    PQHandshakeFailed,
    HybridModeRequired,
    UnsupportedPQAlgorithm,
};

/// QUIC v1 salt for initial key derivation (RFC 9001)
pub const QUIC_V1_SALT = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

/// Random number generation using OS entropy
const rand = @import("rand.zig");

/// HKDF-Expand-Label for TLS 1.3 / QUIC (RFC 8446 Section 7.1)
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// struct HkdfLabel {
///    uint16 length;
///    opaque label<7..255> = "tls13 " + Label;
///    opaque context<0..255> = Context;
/// };
fn hkdfExpandLabel(secret: *const [32]u8, label: []const u8, context: []const u8, output: []u8) !void {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

    // Build HkdfLabel structure
    var hkdf_label: [512]u8 = undefined;
    var offset: usize = 0;

    // length (2 bytes, big-endian)
    std.mem.writeInt(u16, hkdf_label[offset..][0..2], @intCast(output.len), .big);
    offset += 2;

    // label with "tls13 " prefix
    const full_label_len = 6 + label.len; // "tls13 " + label
    hkdf_label[offset] = @intCast(full_label_len);
    offset += 1;
    @memcpy(hkdf_label[offset .. offset + 6], "tls13 ");
    offset += 6;
    @memcpy(hkdf_label[offset .. offset + label.len], label);
    offset += label.len;

    // context
    hkdf_label[offset] = @intCast(context.len);
    offset += 1;
    if (context.len > 0) {
        @memcpy(hkdf_label[offset .. offset + context.len], context);
        offset += context.len;
    }

    // HKDF-Expand
    HkdfSha256.expand(output, hkdf_label[0..offset], secret.*);
}

/// QUIC encryption levels
pub const EncryptionLevel = enum {
    initial,
    early_data, // 0-RTT
    handshake,
    application, // 1-RTT
};

/// QUIC packet protection keys for a single direction
pub const PacketKeys = struct {
    aead_key: [32]u8, // Max key size (AES-256 or ChaCha20)
    iv: [12]u8, // IV for AEAD
    header_protection_key: [32]u8, // HP key

    /// Initialize with zeros
    pub fn zero() PacketKeys {
        return PacketKeys{
            .aead_key = std.mem.zeroes([32]u8),
            .iv = std.mem.zeroes([12]u8),
            .header_protection_key = std.mem.zeroes([32]u8),
        };
    }
};

/// QUIC connection crypto state
pub const QuicCrypto = struct {
    // Keys for different encryption levels
    initial_keys_client: PacketKeys,
    initial_keys_server: PacketKeys,
    handshake_keys_client: PacketKeys,
    handshake_keys_server: PacketKeys,
    application_keys_client: PacketKeys,
    application_keys_server: PacketKeys,
    early_data_keys: PacketKeys,

    // Current cipher suite
    cipher_suite: CipherSuite,

    /// Initialize QUIC crypto context
    pub fn init(cipher_suite: CipherSuite) QuicCrypto {
        return QuicCrypto{
            .initial_keys_client = PacketKeys.zero(),
            .initial_keys_server = PacketKeys.zero(),
            .handshake_keys_client = PacketKeys.zero(),
            .handshake_keys_server = PacketKeys.zero(),
            .application_keys_client = PacketKeys.zero(),
            .application_keys_server = PacketKeys.zero(),
            .early_data_keys = PacketKeys.zero(),
            .cipher_suite = cipher_suite,
        };
    }

    /// Derive initial keys from connection ID (RFC 9001 Section 5.2)
    ///
    /// Implements proper HKDF-based key derivation per RFC 9001.
    pub fn deriveInitialKeys(self: *QuicCrypto, connection_id: []const u8) QuicError!void {
        const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

        // Step 1: Extract initial_secret = HKDF-Extract(salt=QUIC_V1_SALT, IKM=connection_id)
        const initial_secret = HkdfSha256.extract(&QUIC_V1_SALT, connection_id);

        // Step 2: Derive client_initial_secret and server_initial_secret
        // client_in = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        var client_secret: [32]u8 = undefined;
        hkdfExpandLabel(&initial_secret, "client in", "", &client_secret) catch {
            return QuicError.KeyDerivationFailed;
        };

        // server_in = HKDF-Expand-Label(initial_secret, "server in", "", 32)
        var server_secret: [32]u8 = undefined;
        hkdfExpandLabel(&initial_secret, "server in", "", &server_secret) catch {
            return QuicError.KeyDerivationFailed;
        };

        // Step 3: Derive packet protection keys from secrets
        self.derivePacketKeys(&client_secret, &self.initial_keys_client) catch {
            return QuicError.KeyDerivationFailed;
        };

        self.derivePacketKeys(&server_secret, &self.initial_keys_server) catch {
            return QuicError.KeyDerivationFailed;
        };
    }

    /// Derive packet protection keys from traffic secret (RFC 9001 Section 5.1)
    ///
    /// key = HKDF-Expand-Label(secret, "quic key", "", key_length)
    /// iv = HKDF-Expand-Label(secret, "quic iv", "", 12)
    /// hp = HKDF-Expand-Label(secret, "quic hp", "", hp_key_length)
    fn derivePacketKeys(self: *QuicCrypto, secret: *const [32]u8, keys: *PacketKeys) QuicError!void {
        const key_len = self.cipher_suite.keyLength();
        const hp_key_len = self.cipher_suite.headerProtectionKeyLength();

        // Derive AEAD key
        var key_buf: [32]u8 = undefined;
        hkdfExpandLabel(secret, "quic key", "", key_buf[0..key_len]) catch {
            return QuicError.KeyDerivationFailed;
        };
        @memcpy(keys.aead_key[0..key_len], key_buf[0..key_len]);
        // Zero pad remaining bytes if key_len < 32
        if (key_len < 32) {
            @memset(keys.aead_key[key_len..], 0);
        }

        // Derive IV
        hkdfExpandLabel(secret, "quic iv", "", &keys.iv) catch {
            return QuicError.KeyDerivationFailed;
        };

        // Derive header protection key
        var hp_buf: [32]u8 = undefined;
        hkdfExpandLabel(secret, "quic hp", "", hp_buf[0..hp_key_len]) catch {
            return QuicError.KeyDerivationFailed;
        };
        @memcpy(keys.header_protection_key[0..hp_key_len], hp_buf[0..hp_key_len]);
        if (hp_key_len < 32) {
            @memset(keys.header_protection_key[hp_key_len..], 0);
        }
    }

    /// Encrypt QUIC packet payload using AEAD (RFC 9001 Section 5.3)
    ///
    /// Returns the length of encrypted data (ciphertext + 16-byte auth tag).
    /// Output buffer must be at least payload.len + 16 bytes.
    pub fn encryptPacket(self: *const QuicCrypto, level: EncryptionLevel, is_server: bool, packet_number: u64, header: []const u8, payload: []const u8, output: []u8) QuicError!usize {
        const keys = try self.requireKeys(level, is_server);

        // Output must fit ciphertext + 16-byte auth tag
        if (output.len < payload.len + 16) {
            return QuicError.InvalidPacket;
        }

        // Construct nonce: IV XOR packet_number (big-endian, right-aligned)
        var nonce: [12]u8 = keys.iv;
        var pn_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pn_bytes, packet_number, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= pn_bytes[i];
        }

        // AEAD encryption with header as AAD
        var tag: [16]u8 = undefined;
        switch (self.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                Aes128Gcm.encrypt(output[0..payload.len], &tag, payload, header, nonce, keys.aead_key[0..16].*);
            },
            .TLS_AES_256_GCM_SHA384, .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => {
                const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                Aes256Gcm.encrypt(output[0..payload.len], &tag, payload, header, nonce, keys.aead_key);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
                ChaCha20Poly1305.encrypt(output[0..payload.len], &tag, payload, header, nonce, keys.aead_key);
            },
        }

        // Append auth tag
        @memcpy(output[payload.len .. payload.len + 16], &tag);
        return payload.len + 16;
    }

    /// Decrypt QUIC packet payload using AEAD (RFC 9001 Section 5.3)
    ///
    /// Verifies authentication tag BEFORE exposing plaintext.
    /// Returns length of decrypted payload on success.
    pub fn decryptPacket(self: *const QuicCrypto, level: EncryptionLevel, is_server: bool, packet_number: u64, header: []const u8, ciphertext: []const u8, output: []u8) QuicError!usize {
        const keys = try self.requireKeys(level, is_server);

        // Ciphertext must include 16-byte auth tag
        if (ciphertext.len < 16) {
            return QuicError.InvalidPacket;
        }

        const payload_len = ciphertext.len - 16;
        if (output.len < payload_len) {
            return QuicError.InvalidPacket;
        }

        // Construct nonce: IV XOR packet_number (big-endian, right-aligned)
        var nonce: [12]u8 = keys.iv;
        var pn_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pn_bytes, packet_number, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= pn_bytes[i];
        }

        // Extract auth tag from end of ciphertext
        const tag: [16]u8 = ciphertext[payload_len..][0..16].*;
        const encrypted_payload = ciphertext[0..payload_len];

        // AEAD decryption with authentication - verifies tag BEFORE returning plaintext
        switch (self.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                Aes128Gcm.decrypt(output[0..payload_len], encrypted_payload, tag, header, nonce, keys.aead_key[0..16].*) catch {
                    return QuicError.DecryptionFailed;
                };
            },
            .TLS_AES_256_GCM_SHA384, .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => {
                const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                Aes256Gcm.decrypt(output[0..payload_len], encrypted_payload, tag, header, nonce, keys.aead_key) catch {
                    return QuicError.DecryptionFailed;
                };
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
                ChaCha20Poly1305.decrypt(output[0..payload_len], encrypted_payload, tag, header, nonce, keys.aead_key) catch {
                    return QuicError.DecryptionFailed;
                };
            },
        }

        return payload_len;
    }

    /// Protect packet header (RFC 9001 Section 5.4)
    ///
    /// Applies header protection mask to first byte and packet number bytes.
    /// Sample is 16 bytes taken from the ciphertext starting at pn_offset + 4.
    pub fn protectHeader(self: *const QuicCrypto, level: EncryptionLevel, is_server: bool, header: []u8, sample: []const u8) QuicError!void {
        if (sample.len < 16 or header.len == 0) {
            return QuicError.HeaderProtectionFailed;
        }

        const keys = try self.requireKeys(level, is_server);
        const pn_len = self.getPacketNumberLength(header);
        const pn_offset = try self.getPacketNumberOffset(header);
        if (try addChecked(pn_offset, pn_len) > header.len) return QuicError.HeaderProtectionFailed;

        const mask = self.createHeaderProtectionMask(keys, sample);

        // Apply mask to header
        const is_long_header = (header[0] & 0x80) != 0;
        if (is_long_header) {
            // Long header: mask lower 4 bits of first byte
            header[0] ^= (mask[0] & 0x0f);
        } else {
            // Short header: mask lower 5 bits of first byte
            header[0] ^= (mask[0] & 0x1f);
        }

        // Apply mask to packet number bytes
        for (0..pn_len) |i| {
            header[pn_offset + i] ^= mask[1 + i];
        }
    }

    /// Unprotect packet header (reverse of protectHeader)
    pub fn unprotectHeader(self: *const QuicCrypto, level: EncryptionLevel, is_server: bool, header: []u8, sample: []const u8) QuicError!void {
        if (sample.len < 16 or header.len == 0) {
            return QuicError.HeaderProtectionFailed;
        }

        const keys = try self.requireKeys(level, is_server);

        // Header protection never covers the bits this offset is parsed from
        // (the form bit and, for long headers, the packet type), so it can be
        // resolved before unmasking. Doing so keeps a malformed header from
        // being left half-modified when the parse fails.
        const pn_offset = try self.getPacketNumberOffset(header);

        const mask = self.createHeaderProtectionMask(keys, sample);

        const is_long_header = (header[0] & 0x80) != 0;
        if (is_long_header) {
            header[0] ^= (mask[0] & 0x0f);
        } else {
            header[0] ^= (mask[0] & 0x1f);
        }

        const pn_len = self.getPacketNumberLength(header);
        if (try addChecked(pn_offset, pn_len) > header.len) {
            // Restore the first byte so the caller's buffer is unchanged.
            header[0] ^= if (is_long_header) (mask[0] & 0x0f) else (mask[0] & 0x1f);
            return QuicError.HeaderProtectionFailed;
        }

        for (0..pn_len) |i| {
            header[pn_offset + i] ^= mask[1 + i];
        }
    }

    fn createHeaderProtectionMask(self: *const QuicCrypto, keys: *const PacketKeys, sample: []const u8) [5]u8 {
        var mask: [5]u8 = undefined;
        switch (self.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const Aes128 = std.crypto.core.aes.Aes128;
                const ctx = Aes128.initEnc(keys.header_protection_key[0..16].*);
                var block: [16]u8 = sample[0..16].*;
                ctx.encrypt(&block, &block);
                @memcpy(&mask, block[0..5]);
            },
            .TLS_AES_256_GCM_SHA384, .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => {
                const Aes128 = std.crypto.core.aes.Aes128;
                const ctx = Aes128.initEnc(keys.header_protection_key[0..16].*);
                var block: [16]u8 = sample[0..16].*;
                ctx.encrypt(&block, &block);
                @memcpy(&mask, block[0..5]);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const chacha_nonce: [12]u8 = sample[4..16].*;

                const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
                var keystream: [5]u8 = std.mem.zeroes([5]u8);
                ChaCha20.xor(&keystream, &keystream, counter, keys.header_protection_key, chacha_nonce);
                @memcpy(&mask, &keystream);
            },
        }
        return mask;
    }

    /// Get keys for encryption level and direction
    fn getKeys(self: *const QuicCrypto, level: EncryptionLevel, is_server: bool) *const PacketKeys {
        return switch (level) {
            .initial => if (is_server) &self.initial_keys_server else &self.initial_keys_client,
            .early_data => &self.early_data_keys,
            .handshake => if (is_server) &self.handshake_keys_server else &self.handshake_keys_client,
            .application => if (is_server) &self.application_keys_server else &self.application_keys_client,
        };
    }

    fn requireKeys(self: *const QuicCrypto, level: EncryptionLevel, is_server: bool) QuicError!*const PacketKeys {
        const keys = self.getKeys(level, is_server);
        if (!packetKeysAreInitialized(keys)) return QuicError.InvalidKeys;
        return keys;
    }

    /// Offset of the packet number field within a QUIC header.
    ///
    /// Long headers carry length-prefixed connection IDs and, for Initial
    /// packets, a token, so this offset has to be parsed off the wire
    /// (RFC 8999 Section 5.1, RFC 9000 Section 17.2). It was previously
    /// hardcoded to 7, which is wrong for every long header with a non-empty
    /// connection ID: RFC 9001 A.3 puts the packet number at offset 18. The
    /// round-trip tests did not catch it because protect and unprotect shared
    /// the same wrong offset.
    ///
    /// Short headers are a known limitation: the Destination Connection ID
    /// length is not encoded on the wire, so a zero-length DCID is assumed.
    /// Callers using non-empty short-header DCIDs must not use this path.
    fn getPacketNumberOffset(self: *const QuicCrypto, header: []const u8) QuicError!usize {
        _ = self;
        if (header.len == 0) return QuicError.HeaderProtectionFailed;
        if ((header[0] & 0x80) == 0) return 1;

        // Version Negotiation packets (version 0) and Retry packets carry no
        // packet number, so there is nothing to protect.
        if (header.len < 5) return QuicError.HeaderProtectionFailed;
        if (std.mem.readInt(u32, header[1..5], .big) == 0) return QuicError.HeaderProtectionFailed;

        // First byte, 4-byte version, then length-prefixed DCID and SCID.
        var offset: usize = 5;
        for (0..2) |_| {
            if (offset >= header.len) return QuicError.HeaderProtectionFailed;
            const cid_len = header[offset];
            if (cid_len > 20) return QuicError.HeaderProtectionFailed;
            offset = try addChecked(offset, 1 + @as(usize, cid_len));
        }

        switch ((header[0] & 0x30) >> 4) {
            0x00 => {
                // Initial: Token Length (varint), Token, Length (varint).
                if (offset >= header.len) return QuicError.HeaderProtectionFailed;
                const token_len = try decodeVarint(header[offset..]);
                offset = try addChecked(offset, token_len.len);
                offset = try addChecked(offset, std.math.cast(usize, token_len.value) orelse
                    return QuicError.HeaderProtectionFailed);
            },
            0x01, 0x02 => {}, // 0-RTT and Handshake: Length (varint) only.
            else => return QuicError.HeaderProtectionFailed, // Retry: no packet number.
        }

        if (offset >= header.len) return QuicError.HeaderProtectionFailed;
        const length_field = try decodeVarint(header[offset..]);
        return try addChecked(offset, length_field.len);
    }

    /// Get packet number length from header (simplified)
    fn getPacketNumberLength(self: *const QuicCrypto, header: []const u8) usize {
        _ = self;
        if (header.len > 0) {
            return @as(usize, (header[0] & 0x03)) + 1;
        }
        return 1;
    }
};

/// QUIC cipher suites (extended with post-quantum)
pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ML_KEM_768_X25519_AES256_GCM_SHA384, // Post-quantum hybrid

    /// Get AEAD key length for cipher suite
    pub fn keyLength(self: CipherSuite) usize {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => 16,
            .TLS_AES_256_GCM_SHA384 => 32,
            .TLS_CHACHA20_POLY1305_SHA256 => 32,
            .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => 32,
        };
    }

    /// Get header protection key length
    pub fn headerProtectionKeyLength(self: CipherSuite) usize {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => 16,
            .TLS_AES_256_GCM_SHA384 => 16,
            .TLS_CHACHA20_POLY1305_SHA256 => 32,
            .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => 16,
        };
    }

    /// Get hash algorithm for cipher suite
    pub fn hashAlgorithm(self: CipherSuite) []const u8 {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => "SHA256",
            .TLS_AES_256_GCM_SHA384 => "SHA384",
            .TLS_CHACHA20_POLY1305_SHA256 => "SHA256",
            .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => "SHA384",
        };
    }
};

/// Post-quantum QUIC extensions
pub const PostQuantumQuic = struct {
    /// Generate hybrid key share for QUIC ClientHello
    pub fn generateHybridKeyShare(
        classical_share: *[32]u8, // X25519 public key
        pq_share: *[pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8, // ML-KEM-768 public key
        entropy: []const u8,
    ) pq.PQError!void {
        // Generate X25519 key pair
        var x25519_seed: [32]u8 = undefined;
        @memcpy(&x25519_seed, entropy[0..32]);

        const basepoint = [_]u8{9} ++ std.mem.zeroes([31]u8);
        const x25519_public = std.crypto.dh.X25519.scalarmult(x25519_seed, basepoint) catch {
            return pq.PQError.KeyGenFailed;
        };
        @memcpy(classical_share, &x25519_public);

        // Generate ML-KEM-768 key pair
        var pq_seed: [32]u8 = undefined;
        if (entropy.len >= 64) {
            @memcpy(&pq_seed, entropy[32..64]);
        } else {
            rand.fill(&pq_seed);
        }

        const pq_keypair = pq.ml_kem.ML_KEM_768.KeyPair.generate(pq_seed) catch {
            return pq.PQError.KeyGenFailed;
        };
        @memcpy(pq_share, &pq_keypair.public_key);
    }

    /// Process hybrid key share in QUIC ServerHello
    pub fn processHybridKeyShare(client_classical: []const u8, client_pq: []const u8, server_classical: *[32]u8, server_pq: *[pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE]u8, shared_secret: *[64]u8) pq.PQError!void {
        // Generate server X25519 key pair
        var x25519_seed: [32]u8 = undefined;
        rand.fill(&x25519_seed);

        var server_x25519_seed: [32]u8 = undefined;
        rand.fill(&server_x25519_seed);
        const basepoint = [_]u8{9} ++ std.mem.zeroes([31]u8);
        const server_x25519_public = std.crypto.dh.X25519.scalarmult(server_x25519_seed, basepoint) catch {
            return pq.PQError.KeyGenFailed;
        };
        @memcpy(server_classical, &server_x25519_public);

        // Perform X25519 DH
        const client_x25519: [32]u8 = client_classical[0..32].*;
        const classical_shared = std.crypto.dh.X25519.scalarmult(server_x25519_seed, client_x25519) catch {
            return pq.PQError.EncapsFailed;
        };

        // Perform ML-KEM-768 encapsulation
        const client_pq_key: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = client_pq[0..pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE].*;

        var pq_randomness: [32]u8 = undefined;
        rand.fill(&pq_randomness);

        const pq_result = pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(client_pq_key, pq_randomness) catch {
            return pq.PQError.EncapsFailed;
        };

        @memcpy(server_pq, &pq_result.ciphertext);

        // Combine classical and post-quantum shared secrets
        var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
        hasher.update(&classical_shared);
        hasher.update(&pq_result.shared_secret);
        hasher.final(shared_secret);
    }

    /// QUIC transport parameters for post-quantum negotiation
    pub const PqTransportParams = struct {
        max_pq_key_update_interval: u64,
        pq_algorithm_preference: []const u8,
        hybrid_mode_required: bool,

        pub fn encode(self: *const PqTransportParams, output: []u8) usize {
            if (output.len < 17) return 0; // Minimum required size

            var offset: usize = 0;

            // Encode max_pq_key_update_interval (8 bytes)
            const interval_bytes = std.mem.toBytes(self.max_pq_key_update_interval);
            @memcpy(output[offset .. offset + 8], &interval_bytes);
            offset += 8;

            // Encode algorithm preference length and data
            const pref_len = @min(self.pq_algorithm_preference.len, 255);
            output[offset] = @intCast(pref_len);
            offset += 1;

            if (offset + pref_len <= output.len) {
                @memcpy(output[offset .. offset + pref_len], self.pq_algorithm_preference[0..pref_len]);
                offset += pref_len;
            }

            // Encode hybrid_mode_required (1 byte)
            if (offset < output.len) {
                output[offset] = if (self.hybrid_mode_required) 1 else 0;
                offset += 1;
            }

            return offset;
        }

        pub fn decode(data: []const u8) ?PqTransportParams {
            if (data.len < 10) return null; // Minimum required size

            var offset: usize = 0;

            // Decode max_pq_key_update_interval
            const interval = std.mem.bytesToValue(u64, data[offset .. offset + 8]);
            offset += 8;

            // Decode algorithm preference
            const pref_len = data[offset];
            offset += 1;

            if (offset + pref_len >= data.len) return null;
            const preference = data[offset .. offset + pref_len];
            offset += pref_len;

            // Decode hybrid_mode_required
            if (offset >= data.len) return null;
            const hybrid_required = data[offset] != 0;

            return PqTransportParams{
                .max_pq_key_update_interval = interval,
                .pq_algorithm_preference = preference,
                .hybrid_mode_required = hybrid_required,
            };
        }
    };

    /// Post-quantum key update for QUIC
    pub fn performPQKeyUpdate(
        current_secret: []const u8,
        pq_entropy: []const u8,
        new_secret: []u8,
    ) pq.PQError!void {
        if (new_secret.len < 32) return pq.PQError.InvalidSharedSecret;

        // Enhanced key update with post-quantum entropy
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(current_secret);
        hasher.update("pq_quic_key_update");
        hasher.update(pq_entropy);
        hasher.final(new_secret[0..32]);
    }

    /// Quantum-safe 0-RTT protection using AES-256-GCM
    ///
    /// Derives a hybrid key from classical and post-quantum PSKs, then
    /// encrypts with authenticated encryption.
    /// Output must be at least plaintext.len + 28 bytes (12 nonce + 16 tag).
    pub fn protectZeroRTTPQ(
        classical_psk: []const u8,
        pq_psk: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
    ) pq.PQError!void {
        // Need space for: 12-byte nonce + plaintext + 16-byte tag
        if (ciphertext.len < plaintext.len + 28) {
            return pq.PQError.InvalidSharedSecret;
        }

        // Derive enhanced 0-RTT key (64 bytes: 32 for key, 32 for additional entropy)
        var enhanced_key: [64]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
        hasher.update(classical_psk);
        hasher.update(pq_psk);
        hasher.update("pq_zero_rtt");
        hasher.final(&enhanced_key);

        // Use first 32 bytes as AES-256 key
        const aead_key: [32]u8 = enhanced_key[0..32].*;

        // Generate random nonce and write to output
        var nonce: [12]u8 = undefined;
        rand.fill(&nonce);
        @memcpy(ciphertext[0..12], &nonce);

        // Encrypt with AES-256-GCM
        const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
        var tag: [16]u8 = undefined;
        Aes256Gcm.encrypt(
            ciphertext[12 .. 12 + plaintext.len],
            &tag,
            plaintext,
            &[_]u8{}, // No AAD for 0-RTT
            nonce,
            aead_key,
        );

        // Append tag
        @memcpy(ciphertext[12 + plaintext.len ..][0..16], &tag);
    }

    /// Decrypt quantum-safe 0-RTT protected data
    ///
    /// Input format: 12-byte nonce + ciphertext + 16-byte tag.
    /// Returns decrypted plaintext length on success.
    pub fn unprotectZeroRTTPQ(
        classical_psk: []const u8,
        pq_psk: []const u8,
        ciphertext: []const u8,
        plaintext: []u8,
    ) pq.PQError!usize {
        // Must have at least nonce + tag
        if (ciphertext.len < 28) {
            return pq.PQError.InvalidSharedSecret;
        }

        const payload_len = ciphertext.len - 28;
        if (plaintext.len < payload_len) {
            return pq.PQError.InvalidSharedSecret;
        }

        // Derive enhanced 0-RTT key
        var enhanced_key: [64]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
        hasher.update(classical_psk);
        hasher.update(pq_psk);
        hasher.update("pq_zero_rtt");
        hasher.final(&enhanced_key);

        const aead_key: [32]u8 = enhanced_key[0..32].*;
        const nonce: [12]u8 = ciphertext[0..12].*;
        const encrypted = ciphertext[12 .. 12 + payload_len];
        const tag: [16]u8 = ciphertext[12 + payload_len ..][0..16].*;

        // Decrypt with authentication
        const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
        Aes256Gcm.decrypt(
            plaintext[0..payload_len],
            encrypted,
            tag,
            &[_]u8{},
            nonce,
            aead_key,
        ) catch {
            return pq.PQError.DecapsFailed;
        };

        return payload_len;
    }
};

/// Zero-copy packet processing for high performance
///
/// Uses proper AEAD encryption (AES-GCM or ChaCha20-Poly1305) with authentication.
/// The packet buffer must have space for the 16-byte auth tag appended after encryption.
pub const ZeroCopy = struct {
    /// In-place packet encryption with AEAD
    ///
    /// Encrypts payload in-place and appends 16-byte auth tag.
    /// Packet buffer must have header_len + payload_len + 16 bytes available.
    /// Returns total encrypted length (payload + tag).
    pub fn encryptInPlace(crypto: *const QuicCrypto, level: EncryptionLevel, is_server: bool, packet_number: u64, packet: []u8, header_len: usize) QuicError!usize {
        const keys = try crypto.requireKeys(level, is_server);

        if (packet.len <= header_len + 16) {
            return QuicError.InvalidPacket;
        }

        const payload_len = packet.len - header_len - 16; // Reserve space for tag

        // Construct nonce: IV XOR packet_number (big-endian, right-aligned)
        var nonce: [12]u8 = keys.iv;
        var pn_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pn_bytes, packet_number, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= pn_bytes[i];
        }

        // Header is AAD, payload is encrypted in-place
        const header = packet[0..header_len];
        const payload = packet[header_len .. header_len + payload_len];

        var tag: [16]u8 = undefined;
        switch (crypto.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                Aes128Gcm.encrypt(payload, &tag, payload, header, nonce, keys.aead_key[0..16].*);
            },
            .TLS_AES_256_GCM_SHA384, .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => {
                const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                Aes256Gcm.encrypt(payload, &tag, payload, header, nonce, keys.aead_key);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
                ChaCha20Poly1305.encrypt(payload, &tag, payload, header, nonce, keys.aead_key);
            },
        }

        // Append auth tag
        @memcpy(packet[header_len + payload_len ..][0..16], &tag);
        return payload_len + 16;
    }

    /// In-place packet decryption with AEAD authentication
    ///
    /// Verifies auth tag BEFORE exposing plaintext.
    /// Returns decrypted payload length (excluding tag) on success.
    pub fn decryptInPlace(crypto: *const QuicCrypto, level: EncryptionLevel, is_server: bool, packet_number: u64, packet: []u8, header_len: usize) QuicError!usize {
        const keys = try crypto.requireKeys(level, is_server);

        // Must have at least header + 16-byte tag
        if (packet.len <= header_len + 16) {
            return QuicError.InvalidPacket;
        }

        const ciphertext_len = packet.len - header_len;
        const payload_len = ciphertext_len - 16;

        // Construct nonce: IV XOR packet_number (big-endian, right-aligned)
        var nonce: [12]u8 = keys.iv;
        var pn_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pn_bytes, packet_number, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= pn_bytes[i];
        }

        // Extract tag and prepare slices
        const header = packet[0..header_len];
        const ciphertext = packet[header_len .. header_len + payload_len];
        const tag: [16]u8 = packet[header_len + payload_len ..][0..16].*;

        // AEAD decryption - verifies tag before decrypting
        switch (crypto.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                Aes128Gcm.decrypt(ciphertext, ciphertext, tag, header, nonce, keys.aead_key[0..16].*) catch {
                    return QuicError.DecryptionFailed;
                };
            },
            .TLS_AES_256_GCM_SHA384, .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384 => {
                const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                Aes256Gcm.decrypt(ciphertext, ciphertext, tag, header, nonce, keys.aead_key) catch {
                    return QuicError.DecryptionFailed;
                };
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
                ChaCha20Poly1305.decrypt(ciphertext, ciphertext, tag, header, nonce, keys.aead_key) catch {
                    return QuicError.DecryptionFailed;
                };
            },
        }

        return payload_len;
    }

    /// Batch process multiple packets for maximum throughput
    ///
    /// For encryption: each packet must have space for 16-byte tag.
    /// For decryption: each packet must include the 16-byte tag.
    pub fn batchProcessPackets(
        crypto: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packets: [][]u8,
        header_lens: []const usize,
        packet_numbers: []const u64,
        encrypt: bool,
    ) QuicError!void {
        if (packets.len != header_lens.len or packets.len != packet_numbers.len) {
            return QuicError.InvalidPacket;
        }

        for (packets, header_lens, packet_numbers) |packet, header_len, pn| {
            if (encrypt) {
                _ = try encryptInPlace(crypto, level, is_server, pn, packet, header_len);
            } else {
                _ = try decryptInPlace(crypto, level, is_server, pn, packet, header_len);
            }
        }
    }
};

test "QUIC initial key derivation" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    const connection_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    try crypto.deriveInitialKeys(&connection_id);

    // Keys should not be all zeros after derivation
    var all_zero = true;
    for (crypto.initial_keys_client.aead_key) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "QUIC packet encryption/decryption" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    const connection_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    try crypto.deriveInitialKeys(&connection_id);

    const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
    const payload = "Hello, QUIC!";
    var encrypted: [64]u8 = undefined;

    // Encrypt packet
    const encrypted_len = try crypto.encryptPacket(.initial, false, 1, &header, payload, &encrypted);

    // Encrypted length should be payload + 16-byte auth tag
    try std.testing.expectEqual(payload.len + 16, encrypted_len);

    // Ciphertext should be different from plaintext
    try std.testing.expect(!std.mem.eql(u8, payload, encrypted[0..payload.len]));

    // Decrypt packet
    var decrypted: [64]u8 = undefined;
    const decrypted_len = try crypto.decryptPacket(.initial, false, 1, &header, encrypted[0..encrypted_len], &decrypted);

    // Decrypted should match original payload
    try std.testing.expectEqual(payload.len, decrypted_len);
    try std.testing.expectEqualSlices(u8, payload, decrypted[0..decrypted_len]);

    // Test tampering detection - modify ciphertext
    var tampered = encrypted;
    tampered[5] ^= 0xFF;
    const tamper_result = crypto.decryptPacket(.initial, false, 1, &header, tampered[0..encrypted_len], &decrypted);
    try std.testing.expectError(QuicError.DecryptionFailed, tamper_result);
}

test "QUIC rejects uninitialized handshake keys" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);

    const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
    const payload = "Hello, QUIC!";
    var encrypted: [64]u8 = undefined;

    try std.testing.expectError(
        QuicError.InvalidKeys,
        crypto.encryptPacket(.handshake, false, 1, &header, payload, &encrypted),
    );
}

test "QUIC header protection round trip preserves packet number length" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    const connection_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    try crypto.deriveInitialKeys(&connection_id);

    var header = [_]u8{ 0x43, 0x11, 0x22, 0x33, 0x44 };
    const original = header;
    const sample = [_]u8{
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    };

    try crypto.protectHeader(.initial, false, &header, &sample);
    try std.testing.expect(!std.mem.eql(u8, &original, &header));

    try crypto.unprotectHeader(.initial, false, &header, &sample);
    try std.testing.expectEqualSlices(u8, &original, &header);
}

test "QUIC header protection rejects truncated packet number bytes" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    const connection_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    try crypto.deriveInitialKeys(&connection_id);

    var header = [_]u8{ 0x43, 0x11, 0x22 };
    const sample = [_]u8{
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    };

    try std.testing.expectError(
        QuicError.HeaderProtectionFailed,
        crypto.protectHeader(.initial, false, &header, &sample),
    );
}

test "QUIC cipher suite properties" {
    const cs = CipherSuite.TLS_AES_256_GCM_SHA384;
    try std.testing.expect(cs.keyLength() == 32);
    try std.testing.expect(cs.headerProtectionKeyLength() == 16);
    try std.testing.expectEqualStrings(cs.hashAlgorithm(), "SHA384");
}

test "Post-quantum QUIC key exchange" {
    var classical_share: [32]u8 = undefined;
    var pq_share: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8 = undefined;
    const entropy = blk: {
        var bytes = std.mem.zeroes([64]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };

    // Generate hybrid key share
    try PostQuantumQuic.generateHybridKeyShare(&classical_share, &pq_share, &entropy);

    // Keys should not be all zeros
    var all_zero = true;
    for (classical_share) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);

    // Test server processing
    var server_classical: [32]u8 = undefined;
    var server_pq: [pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE]u8 = undefined;
    var shared_secret: [64]u8 = undefined;

    try PostQuantumQuic.processHybridKeyShare(
        &classical_share,
        &pq_share,
        &server_classical,
        &server_pq,
        &shared_secret,
    );

    // Shared secret should not be all zeros
    all_zero = true;
    for (shared_secret) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "QUIC transport parameter encoding/decoding" {
    const params = PostQuantumQuic.PqTransportParams{
        .max_pq_key_update_interval = 3600000, // 1 hour in ms
        .pq_algorithm_preference = "kyber768",
        .hybrid_mode_required = true,
    };

    var encoded: [64]u8 = undefined;
    const encoded_len = params.encode(&encoded);
    try std.testing.expect(encoded_len > 0);

    const decoded = PostQuantumQuic.PqTransportParams.decode(encoded[0..encoded_len]);
    try std.testing.expect(decoded != null);
    try std.testing.expect(decoded.?.max_pq_key_update_interval == 3600000);
    try std.testing.expect(decoded.?.hybrid_mode_required == true);
}

test "Zero-copy packet processing" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    const connection_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    try crypto.deriveInitialKeys(&connection_id);

    // Test packet with header, payload, and space for 16-byte auth tag
    const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
    const payload = "Hello QUIC!";
    const header_len = 5;
    const payload_len = 11;
    const packet_number: u64 = 1;

    // Buffer: header + payload + 16-byte tag
    var packet: [header_len + payload_len + 16]u8 = undefined;
    @memcpy(packet[0..header_len], &header);
    @memcpy(packet[header_len .. header_len + payload_len], payload);

    // Store original payload for comparison
    var original_payload: [payload_len]u8 = undefined;
    @memcpy(&original_payload, packet[header_len .. header_len + payload_len]);

    // Encrypt in place (encrypts payload and appends tag)
    const encrypted_len = try ZeroCopy.encryptInPlace(&crypto, .initial, false, packet_number, &packet, header_len);
    try std.testing.expectEqual(payload_len + 16, encrypted_len);

    // Payload should be different after encryption
    try std.testing.expect(!std.mem.eql(u8, &original_payload, packet[header_len .. header_len + payload_len]));

    // Decrypt in place (verifies tag and decrypts)
    const decrypted_len = try ZeroCopy.decryptInPlace(&crypto, .initial, false, packet_number, &packet, header_len);
    try std.testing.expectEqual(payload_len, decrypted_len);

    // Should match original payload after decryption
    try std.testing.expectEqualSlices(u8, &original_payload, packet[header_len .. header_len + payload_len]);

    // Test tampering detection
    @memcpy(packet[0..header_len], &header);
    @memcpy(packet[header_len .. header_len + payload_len], payload);
    _ = try ZeroCopy.encryptInPlace(&crypto, .initial, false, packet_number, &packet, header_len);

    // Tamper with ciphertext
    packet[header_len + 3] ^= 0xFF;
    const tamper_result = ZeroCopy.decryptInPlace(&crypto, .initial, false, packet_number, &packet, header_len);
    try std.testing.expectError(QuicError.DecryptionFailed, tamper_result);
}

test "QUIC zero-copy rejects uninitialized application keys" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);

    var packet: [32]u8 = undefined;
    @memset(&packet, 0);
    packet[0] = 0x40;

    try std.testing.expectError(
        QuicError.InvalidKeys,
        ZeroCopy.encryptInPlace(&crypto, .application, false, 1, &packet, 1),
    );
}

// ---------------------------------------------------------------------------
// RFC 9001 Appendix A published test vectors.
//
// Provenance: RFC 9001 "Using TLS to Secure QUIC", Appendix A "Sample Packet
// Protection", retrieved from https://www.rfc-editor.org/rfc/rfc9001.txt
// (sha256 3bbaecdf5afd278052a2c48348ce118c4ff8d0cf6b9915549858171b3f98a591).
// These are an independent oracle: the expected bytes come from the
// specification, not from this implementation, so a round-trip that is
// self-consistent but wrong cannot satisfy them.
// ---------------------------------------------------------------------------

fn decodeHex(comptime N: usize, hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// RFC 9001 A.1: the 8-byte client-chosen Destination Connection ID.
const RFC9001_DCID = decodeHex(8, "8394c8f03e515708");

test "RFC 9001 A.1: initial salt matches the specification" {
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(20, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        &QUIC_V1_SALT,
    );
}

test "RFC 9001 A.1: initial secret derivation matches published vector" {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const initial_secret = HkdfSha256.extract(&QUIC_V1_SALT, &RFC9001_DCID);

    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(32, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"),
        &initial_secret,
    );

    var client_secret: [32]u8 = undefined;
    try hkdfExpandLabel(&initial_secret, "client in", "", &client_secret);
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
        &client_secret,
    );

    var server_secret: [32]u8 = undefined;
    try hkdfExpandLabel(&initial_secret, "server in", "", &server_secret);
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
        &server_secret,
    );
}

test "RFC 9001 A.1: deriveInitialKeys produces the published key, iv, and hp" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    // Client packet protection keys.
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(16, "1f369613dd76d5467730efcbe3b1a22d"),
        crypto.initial_keys_client.aead_key[0..16],
    );
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(12, "fa044b2f42a3fd3b46fb255c"),
        &crypto.initial_keys_client.iv,
    );
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(16, "9f50449e04a0e810283a1e9933adedd2"),
        crypto.initial_keys_client.header_protection_key[0..16],
    );

    // Server packet protection keys.
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(16, "cf3a5331653c364c88f0f379b6067e37"),
        crypto.initial_keys_server.aead_key[0..16],
    );
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(12, "0ac1493ca1905853b0bba03e"),
        &crypto.initial_keys_server.iv,
    );
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(16, "c206b8d9b9f0f37644430b490eeaa314"),
        crypto.initial_keys_server.header_protection_key[0..16],
    );
}

/// RFC 9001 A.3: the server Initial packet, unprotected payload (99 bytes).
const RFC9001_A3_PAYLOAD = decodeHex(99, "02000000000600405a020000560303ee" ++
    "fce7f7b37ba1d1632e96677825ddf739" ++
    "88cfc79825df566dc5430b9a045a1200" ++
    "130100002e00330024001d00209d3c94" ++
    "0d89690b84d08a60993c144eca684d10" ++
    "81287c834d5311bcf32bb9da1a002b00" ++
    "020304");

/// RFC 9001 A.3: the unprotected server header. Packet number 1, encoded in
/// 2 bytes, sitting at offset 18 (after version, an empty DCID, an 8-byte
/// SCID, an empty token, and the 2-byte Length varint).
const RFC9001_A3_HEADER = decodeHex(20, "c1000000010008f067a5502a4262b50040750001");

/// RFC 9001 A.3: the fully protected packet (135 bytes = 20 header + 99 + 16 tag).
const RFC9001_A3_PROTECTED = decodeHex(135, "cf000000010008f067a5502a4262b500" ++
    "4075c0d95a482cd0991cd25b0aac406a" ++
    "5816b6394100f37a1c69797554780bb3" ++
    "8cc5a99f5ede4cf73c3ec2493a1839b3" ++
    "dbcba3f6ea46c5b7684df3548e7ddeb9" ++
    "c3bf9c73cc3f3bded74b562bfb19fb84" ++
    "022f8ef4cdd93795d77d06edbb7aaf2f" ++
    "58891850abbdca3d20398c276456cbc4" ++
    "2158407dd074ee");

test "RFC 9001 A.3: server Initial AEAD matches the published ciphertext" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    var output: [RFC9001_A3_PAYLOAD.len + 16]u8 = undefined;
    const written = try crypto.encryptPacket(
        .initial,
        true,
        1,
        &RFC9001_A3_HEADER,
        &RFC9001_A3_PAYLOAD,
        &output,
    );

    // The ciphertext follows the 20-byte header in the published packet, and
    // the unprotected header is the AAD. Matching here pins the nonce
    // construction and the AAD choice, not just "some AEAD ran".
    try std.testing.expectEqual(RFC9001_A3_PROTECTED.len - RFC9001_A3_HEADER.len, written);
    try std.testing.expectEqualSlices(
        u8,
        RFC9001_A3_PROTECTED[RFC9001_A3_HEADER.len..],
        output[0..written],
    );

    // And the same keys must recover the published plaintext.
    var recovered: [RFC9001_A3_PAYLOAD.len]u8 = undefined;
    const plaintext_len = try crypto.decryptPacket(
        .initial,
        true,
        1,
        &RFC9001_A3_HEADER,
        RFC9001_A3_PROTECTED[RFC9001_A3_HEADER.len..],
        &recovered,
    );
    try std.testing.expectEqualSlices(u8, &RFC9001_A3_PAYLOAD, recovered[0..plaintext_len]);
}

test "RFC 9001 A.3: header protection mask matches the published sample" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    // "the header protection sample is taken starting from the third protected
    // byte", i.e. pn_offset + 4 == 22 into the packet.
    const sample = RFC9001_A3_PROTECTED[22..38];
    try std.testing.expectEqualSlices(u8, &decodeHex(16, "2cd0991cd25b0aac406a5816b6394100"), sample);

    const mask = crypto.createHeaderProtectionMask(&crypto.initial_keys_server, sample);
    try std.testing.expectEqualSlices(u8, &decodeHex(5, "2ec0d8356a"), &mask);
}

test "RFC 9001 A.3: protectHeader reproduces the published protected header" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    const sample = RFC9001_A3_PROTECTED[22..38];

    var header = RFC9001_A3_HEADER;
    try crypto.protectHeader(.initial, true, &header, sample);
    try std.testing.expectEqualSlices(u8, RFC9001_A3_PROTECTED[0..20], &header);

    // Removing protection must return the original header exactly.
    try crypto.unprotectHeader(.initial, true, &header, sample);
    try std.testing.expectEqualSlices(u8, &RFC9001_A3_HEADER, &header);
}

test "RFC 9001 A.3: AEAD rejects tampered tag, header, and packet number" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    const ciphertext = RFC9001_A3_PROTECTED[RFC9001_A3_HEADER.len..];
    var recovered: [RFC9001_A3_PAYLOAD.len]u8 = undefined;

    // Flipping any tag bit must fail authentication.
    var bad_tag: [ciphertext.len]u8 = ciphertext.*;
    bad_tag[bad_tag.len - 1] ^= 0x01;
    try std.testing.expectError(QuicError.DecryptionFailed, crypto.decryptPacket(.initial, true, 1, &RFC9001_A3_HEADER, &bad_tag, &recovered));

    // Flipping a ciphertext bit must fail authentication.
    var bad_body: [ciphertext.len]u8 = ciphertext.*;
    bad_body[0] ^= 0x01;
    try std.testing.expectError(QuicError.DecryptionFailed, crypto.decryptPacket(.initial, true, 1, &RFC9001_A3_HEADER, &bad_body, &recovered));

    // The header is the AAD, so altering it must fail authentication.
    var bad_header = RFC9001_A3_HEADER;
    bad_header[9] ^= 0x01;
    try std.testing.expectError(QuicError.DecryptionFailed, crypto.decryptPacket(.initial, true, 1, &bad_header, ciphertext, &recovered));

    // The packet number feeds the nonce, so the wrong one must fail.
    try std.testing.expectError(QuicError.DecryptionFailed, crypto.decryptPacket(.initial, true, 2, &RFC9001_A3_HEADER, ciphertext, &recovered));

    // Client keys must not open a server packet.
    try std.testing.expectError(QuicError.DecryptionFailed, crypto.decryptPacket(.initial, false, 1, &RFC9001_A3_HEADER, ciphertext, &recovered));
}

test "QUIC AEAD rejects truncated ciphertext and undersized output" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    var out: [64]u8 = undefined;

    // Anything shorter than the 16-byte tag cannot be a packet.
    for (0..16) |n| {
        try std.testing.expectError(QuicError.InvalidPacket, crypto.decryptPacket(.initial, true, 1, &RFC9001_A3_HEADER, RFC9001_A3_PROTECTED[20 .. 20 + n], &out));
    }

    // Output buffer must have room for the recovered plaintext.
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(QuicError.InvalidPacket, crypto.decryptPacket(.initial, true, 1, &RFC9001_A3_HEADER, RFC9001_A3_PROTECTED[20..], &tiny));

    // And for the ciphertext plus tag on the way out.
    try std.testing.expectError(QuicError.InvalidPacket, crypto.encryptPacket(.initial, true, 1, &RFC9001_A3_HEADER, &RFC9001_A3_PAYLOAD, &out));
}

test "QUIC header protection parses packet number offset from the wire" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    // The RFC 9001 A.3 header: empty DCID, 8-byte SCID, empty token.
    try std.testing.expectEqual(@as(usize, 18), try crypto.getPacketNumberOffset(&RFC9001_A3_HEADER));

    // A Handshake packet (type 0x02) has no token, so the Length varint
    // follows the connection IDs directly.
    const handshake = decodeHex(11, "e100000001000040750001");
    try std.testing.expectEqual(@as(usize, 9), try crypto.getPacketNumberOffset(&handshake));

    // Short headers assume a zero-length connection ID.
    const short = decodeHex(4, "41000001");
    try std.testing.expectEqual(@as(usize, 1), try crypto.getPacketNumberOffset(&short));
}

test "QUIC header protection rejects malformed long headers" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    const cases = [_][]const u8{
        // Version Negotiation (version 0) carries no packet number.
        &decodeHex(11, "c000000000000040750001"),
        // Retry (type 0x03) carries no packet number.
        &decodeHex(11, "f100000001000040750001"),
        // Connection ID length exceeds the 20-byte maximum.
        &decodeHex(8, "c1000000012a0001"),
        // A valid DCID length that runs past the end of the header.
        &decodeHex(6, "c10000000114"),
        // Truncated before the version.
        &decodeHex(3, "c10000"),
        // Truncated before the Length varint.
        &decodeHex(16, "c1000000010008f067a5502a4262b500"),
    };

    const sample: [16]u8 = @splat(0xab);
    for (cases) |case| {
        try std.testing.expectError(QuicError.HeaderProtectionFailed, crypto.getPacketNumberOffset(case));

        // The same rejection must surface through the public entry points,
        // and must leave the caller's buffer untouched.
        var buf = std.mem.zeroes([32]u8);
        @memcpy(buf[0..case.len], case);
        const before = buf;
        try std.testing.expectError(QuicError.HeaderProtectionFailed, crypto.unprotectHeader(.initial, true, buf[0..case.len], &sample));
        try std.testing.expectEqualSlices(u8, &before, &buf);
    }
}

test "QUIC header protection requires a full 16-byte sample" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    var header = RFC9001_A3_HEADER;
    const full_sample = RFC9001_A3_PROTECTED[22..38];

    for (0..16) |n| {
        try std.testing.expectError(QuicError.HeaderProtectionFailed, crypto.protectHeader(.initial, true, &header, full_sample[0..n]));
    }
    // Rejected samples must not have altered the header.
    try std.testing.expectEqualSlices(u8, &RFC9001_A3_HEADER, &header);
}

test "QUIC header protection round trips every packet number length" {
    var crypto = QuicCrypto.init(.TLS_AES_128_GCM_SHA256);
    try crypto.deriveInitialKeys(&RFC9001_DCID);

    const sample = RFC9001_A3_PROTECTED[22..38];

    for (1..5) |pn_len| {
        // Header is the A.3 shape with the packet number length varied; the
        // Length varint stays 2 bytes so the offset is unchanged at 18.
        var header: [18 + 4]u8 = undefined;
        @memcpy(header[0..18], RFC9001_A3_HEADER[0..18]);
        @memset(header[18..], 0x00);
        header[0] = (RFC9001_A3_HEADER[0] & 0xfc) | @as(u8, @intCast(pn_len - 1));

        const original = header;
        const in_use = header[0 .. 18 + pn_len];

        try crypto.protectHeader(.initial, true, in_use, sample);
        try std.testing.expect(!std.mem.eql(u8, original[0 .. 18 + pn_len], in_use));

        try crypto.unprotectHeader(.initial, true, in_use, sample);
        try std.testing.expectEqualSlices(u8, original[0 .. 18 + pn_len], in_use);
    }
}
