//! QUIC-specific cryptographic operations
//! Implements RFC 9001 - Using TLS to Secure QUIC
//! Optimized for high-performance packet processing

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const QuicCrypto = struct {
    pub const Error = error{
        InvalidKey,
        InvalidNonce,
        DecryptionFailed,
        InsufficientBuffer,
        UnsupportedCipher,
    };

    pub const CipherSuite = enum {
        aes_128_gcm,
        aes_256_gcm,
        chacha20_poly1305,

        pub fn keySize(self: CipherSuite) usize {
            return switch (self) {
                .aes_128_gcm => 16,
                .aes_256_gcm => 32,
                .chacha20_poly1305 => 32,
            };
        }

        pub fn nonceSize(self: CipherSuite) usize {
            return switch (self) {
                .aes_128_gcm, .aes_256_gcm => 12,
                .chacha20_poly1305 => 12,
            };
        }

        pub fn tagSize(_: CipherSuite) usize {
            return 16; // All QUIC AEAD ciphers use 16-byte tags
        }
    };

    /// HKDF implementation for QUIC key derivation (RFC 5869)
    pub const HKDF = struct {
        pub fn extract(salt: []const u8, ikm: []const u8, prk: []u8) void {
            std.debug.assert(prk.len == 32); // SHA-256 output size
            crypto.auth.hmac.sha2.HmacSha256.create(prk[0..32], ikm, salt);
        }

        pub fn expand(prk: []const u8, info: []const u8, okm: []u8) void {
            const n = (okm.len + 31) / 32; // Ceiling division for SHA-256
            var t: [32]u8 = undefined;
            var offset: usize = 0;

            for (0..n) |i| {
                var hmac = crypto.auth.hmac.sha2.HmacSha256.init(prk);
                if (i > 0) {
                    hmac.update(&t);
                }
                hmac.update(info);
                hmac.update(&[_]u8{@intCast(i + 1)});
                hmac.final(&t);

                const copy_len = @min(32, okm.len - offset);
                @memcpy(okm[offset .. offset + copy_len], t[0..copy_len]);
                offset += copy_len;
            }
        }

        /// QUIC-specific HKDF-Expand-Label (RFC 8446 Section 7.1)
        pub fn expandLabel(secret: []const u8, label: []const u8, context: []const u8, out: []u8) void {
            var info_buffer: [256]u8 = undefined;
            var info_len: usize = 0;

            // length (2 bytes)
            info_buffer[info_len] = @intCast(out.len >> 8);
            info_buffer[info_len + 1] = @intCast(out.len & 0xFF);
            info_len += 2;

            // label with "tls13 " prefix
            const quic_label = "tls13 ";
            info_buffer[info_len] = @intCast(quic_label.len + label.len);
            info_len += 1;
            @memcpy(info_buffer[info_len .. info_len + quic_label.len], quic_label);
            info_len += quic_label.len;
            @memcpy(info_buffer[info_len .. info_len + label.len], label);
            info_len += label.len;

            // context
            info_buffer[info_len] = @intCast(context.len);
            info_len += 1;
            if (context.len > 0) {
                @memcpy(info_buffer[info_len .. info_len + context.len], context);
                info_len += context.len;
            }

            expand(secret, info_buffer[0..info_len], out);
        }
    };

    /// Header protection for QUIC packets (RFC 9001 Section 5.4)
    pub const HeaderProtection = struct {
        cipher: CipherSuite,
        key: []const u8,

        pub fn init(cipher: CipherSuite, key: []const u8) HeaderProtection {
            std.debug.assert(key.len == cipher.keySize());
            return HeaderProtection{
                .cipher = cipher,
                .key = key,
            };
        }

        /// Generate protection mask from sample
        pub fn createMask(self: HeaderProtection, sample: []const u8, mask: []u8) Error!void {
            std.debug.assert(sample.len >= 16);
            std.debug.assert(mask.len >= 5);

            switch (self.cipher) {
                .aes_128_gcm, .aes_256_gcm => {
                    // AES-ECB encryption of sample
                    var aes_mask: [16]u8 = undefined;
                    if (self.cipher == .aes_128_gcm) {
                        const aes = crypto.core.aes.Aes128.initEnc(self.key[0..16].*);
                        aes.encrypt(&aes_mask, sample[0..16]);
                    } else {
                        const aes = crypto.core.aes.Aes256.initEnc(self.key[0..32].*);
                        aes.encrypt(&aes_mask, sample[0..16]);
                    }
                    @memcpy(mask[0..5], aes_mask[0..5]);
                },
                .chacha20_poly1305 => {
                    // ChaCha20 with counter=0
                    var chacha_mask: [64]u8 = undefined;
                    const key_array: [32]u8 = self.key[0..32].*;
                    const nonce_array: [12]u8 = sample[4..16].*;
                    crypto.stream.chacha.ChaCha20IETF.xor(&chacha_mask, &chacha_mask, 0, key_array, nonce_array);
                    @memcpy(mask[0..5], chacha_mask[0..5]);
                },
            }
        }

        /// Apply header protection to packet
        pub fn apply(self: HeaderProtection, packet: []u8, sample_offset: usize) Error!void {
            if (sample_offset + 16 > packet.len) return Error.InsufficientBuffer;

            var mask: [5]u8 = undefined;
            try self.createMask(packet[sample_offset .. sample_offset + 16], &mask);

            // Apply mask to first byte and packet number
            const mask_bits: u8 = if (packet[0] & 0x80 != 0) 0x0F else 0x1F;
            packet[0] ^= mask[0] & mask_bits;

            // Determine packet number length and apply mask
            const pn_length = (packet[0] & 0x03) + 1;
            for (0..pn_length) |i| {
                if (1 + i < packet.len) {
                    packet[1 + i] ^= mask[1 + i];
                }
            }
        }

        /// Remove header protection from packet
        pub fn remove(self: HeaderProtection, packet: []u8, sample_offset: usize) Error!void {
            // Same operation as apply (XOR is its own inverse)
            try self.apply(packet, sample_offset);
        }
    };

    /// Zero-copy AEAD operations for QUIC packet protection
    pub const AEAD = struct {
        cipher: CipherSuite,
        key: []const u8,

        pub fn init(cipher: CipherSuite, key: []const u8) AEAD {
            std.debug.assert(key.len == cipher.keySize());
            return AEAD{
                .cipher = cipher,
                .key = key,
            };
        }

        /// Encrypt in-place with authentication
        pub fn sealInPlace(self: AEAD, nonce: []const u8, plaintext: []u8, aad: []const u8, tag: []u8) Error!usize {
            std.debug.assert(nonce.len == self.cipher.nonceSize());
            std.debug.assert(tag.len >= self.cipher.tagSize());

            switch (self.cipher) {
                .aes_128_gcm => {
                    const key_array: [16]u8 = self.key[0..16].*;
                    const nonce_array: [12]u8 = nonce[0..12].*;
                    crypto.aead.aes_gcm.Aes128Gcm.encrypt(plaintext, tag[0..16], plaintext, aad, nonce_array, key_array);
                },
                .aes_256_gcm => {
                    const key_array: [32]u8 = self.key[0..32].*;
                    const nonce_array: [12]u8 = nonce[0..12].*;
                    crypto.aead.aes_gcm.Aes256Gcm.encrypt(plaintext, tag[0..16], plaintext, aad, nonce_array, key_array);
                },
                .chacha20_poly1305 => {
                    const key_array: [32]u8 = self.key[0..32].*;
                    const nonce_array: [12]u8 = nonce[0..12].*;
                    crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(plaintext, tag[0..16], plaintext, aad, nonce_array, key_array);
                },
            }

            return plaintext.len;
        }

        /// Decrypt in-place with authentication
        pub fn openInPlace(self: AEAD, nonce: []const u8, ciphertext: []u8, aad: []const u8, tag: []const u8) Error!usize {
            std.debug.assert(nonce.len == self.cipher.nonceSize());
            std.debug.assert(tag.len >= self.cipher.tagSize());

            switch (self.cipher) {
                .aes_128_gcm => {
                    const key_array: [16]u8 = self.key[0..16].*;
                    const nonce_array: [12]u8 = nonce[0..12].*;
                    const tag_array: [16]u8 = tag[0..16].*;
                    crypto.aead.aes_gcm.Aes128Gcm.decrypt(ciphertext, ciphertext, tag_array, aad, nonce_array, key_array) catch {
                        return Error.DecryptionFailed;
                    };
                },
                .aes_256_gcm => {
                    const key_array: [32]u8 = self.key[0..32].*;
                    const nonce_array: [12]u8 = nonce[0..12].*;
                    const tag_array: [16]u8 = tag[0..16].*;
                    crypto.aead.aes_gcm.Aes256Gcm.decrypt(ciphertext, ciphertext, tag_array, aad, nonce_array, key_array) catch {
                        return Error.DecryptionFailed;
                    };
                },
                .chacha20_poly1305 => {
                    const key_array: [32]u8 = self.key[0..32].*;
                    const nonce_array: [12]u8 = nonce[0..12].*;
                    const tag_array: [16]u8 = tag[0..16].*;
                    crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(ciphertext, ciphertext, tag_array, aad, nonce_array, key_array) catch {
                        return Error.DecryptionFailed;
                    };
                },
            }

            return ciphertext.len;
        }
    };

    /// Batch processing for high-throughput scenarios
    pub const BatchProcessor = struct {
        aead: AEAD,
        buffer_pool: [][]u8,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, aead: AEAD, max_packets: usize, max_packet_size: usize) !BatchProcessor {
            const buffer_pool = try allocator.alloc([]u8, max_packets);
            for (buffer_pool) |*buffer| {
                buffer.* = try allocator.alloc(u8, max_packet_size);
            }

            return BatchProcessor{
                .aead = aead,
                .buffer_pool = buffer_pool,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *BatchProcessor) void {
            for (self.buffer_pool) |buffer| {
                self.allocator.free(buffer);
            }
            self.allocator.free(self.buffer_pool);
        }

        /// Process multiple packets in batch for improved performance
        pub fn encryptBatch(self: *BatchProcessor, packets: [][]u8, nonces: [][]const u8, aads: [][]const u8) ![]usize {
            std.debug.assert(packets.len == nonces.len);
            std.debug.assert(packets.len == aads.len);
            std.debug.assert(packets.len <= self.buffer_pool.len);

            const results = try self.allocator.alloc(usize, packets.len);

            for (packets, nonces, aads, results, 0..) |packet, nonce, aad, *result, i| {
                var tag: [16]u8 = undefined;
                result.* = try self.aead.sealInPlace(nonce, packet, aad, &tag);
                // In real implementation, you'd append tag to packet
                _ = i; // Suppress unused variable warning
            }

            return results;
        }
    };
};

// QUIC-specific key derivation labels (RFC 9001)
pub const QuicLabels = struct {
    pub const initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    pub const client_initial = "client in";
    pub const server_initial = "server in";
    pub const key = "quic key";
    pub const iv = "quic iv";
    pub const hp = "quic hp";
    pub const ku = "quic ku";
};

// High-level QUIC crypto context
pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    cipher_suite: QuicCrypto.CipherSuite,
    client_secret: [32]u8,
    server_secret: [32]u8,
    header_protection: QuicCrypto.HeaderProtection,
    aead: QuicCrypto.AEAD,

    pub fn initFromConnectionId(allocator: std.mem.Allocator, connection_id: []const u8, cipher_suite: QuicCrypto.CipherSuite) !QuicConnection {
        // Derive initial secrets
        var initial_salt: [20]u8 = undefined;
        _ = std.fmt.hexToBytes(&initial_salt, QuicLabels.initial_salt) catch unreachable;

        var initial_secret: [32]u8 = undefined;
        QuicCrypto.HKDF.extract(&initial_salt, connection_id, &initial_secret);

        var client_secret: [32]u8 = undefined;
        var server_secret: [32]u8 = undefined;

        QuicCrypto.HKDF.expandLabel(&initial_secret, QuicLabels.client_initial, "", &client_secret);
        QuicCrypto.HKDF.expandLabel(&initial_secret, QuicLabels.server_initial, "", &server_secret);

        // Derive keys
        var client_key: [32]u8 = undefined;
        var hp_key: [32]u8 = undefined;

        QuicCrypto.HKDF.expandLabel(&client_secret, QuicLabels.key, "", client_key[0..cipher_suite.keySize()]);
        QuicCrypto.HKDF.expandLabel(&client_secret, QuicLabels.hp, "", hp_key[0..cipher_suite.keySize()]);

        return QuicConnection{
            .allocator = allocator,
            .cipher_suite = cipher_suite,
            .client_secret = client_secret,
            .server_secret = server_secret,
            .header_protection = QuicCrypto.HeaderProtection.init(cipher_suite, &hp_key),
            .aead = QuicCrypto.AEAD.init(cipher_suite, &client_key),
        };
    }

    pub fn encryptPacket(self: *QuicConnection, packet: []u8, packet_number: u64) !usize {
        // Construct nonce from packet number
        var nonce: [12]u8 = std.mem.zeroes([12]u8);
        std.mem.writeIntBig(u64, nonce[4..12], packet_number);

        // Encrypt payload
        var tag: [16]u8 = undefined;
        const payload_len = try self.aead.sealInPlace(&nonce, packet[1..], "", &tag);

        // Append tag
        @memcpy(packet[1 + payload_len .. 1 + payload_len + 16], &tag);

        // Apply header protection
        try self.header_protection.apply(packet, 1 + payload_len - 16);

        return 1 + payload_len + 16;
    }

    pub fn decryptPacket(self: *QuicConnection, packet: []u8, packet_number: u64) !usize {
        // Remove header protection first
        try self.header_protection.remove(packet, packet.len - 16 - 4);

        // Construct nonce
        var nonce: [12]u8 = std.mem.zeroes([12]u8);
        std.mem.writeIntBig(u64, nonce[4..12], packet_number);

        // Decrypt payload
        const tag = packet[packet.len - 16 ..];
        const payload_len = try self.aead.openInPlace(&nonce, packet[1 .. packet.len - 16], "", tag);

        return 1 + payload_len;
    }
};

// Tests
test "HKDF extract and expand" {
    const salt = "salt";
    const ikm = "input key material";

    var prk: [32]u8 = undefined;
    QuicCrypto.HKDF.extract(salt, ikm, &prk);

    var okm: [42]u8 = undefined;
    QuicCrypto.HKDF.expand(&prk, "info", &okm);

    // Basic sanity check - output should not be all zeros
    var all_zeros = true;
    for (okm) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);
}

test "AEAD seal and open" {
    const key: [32]u8 = [_]u8{1} ** 32;
    const nonce: [12]u8 = [_]u8{2} ** 12;
    var plaintext = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"
    const aad = "additional authenticated data";

    const aead = QuicCrypto.AEAD.init(.chacha20_poly1305, &key);

    var tag: [16]u8 = undefined;
    _ = try aead.sealInPlace(&nonce, &plaintext, aad, &tag);

    _ = try aead.openInPlace(&nonce, &plaintext, aad, &tag);

    // Should decrypt back to original
    try testing.expectEqualSlices(u8, &[_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }, &plaintext);
}

test "Header protection" {
    const key: [32]u8 = [_]u8{3} ** 32;
    const hp = QuicCrypto.HeaderProtection.init(.chacha20_poly1305, &key);

    var packet = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 } ++ [_]u8{0} ** 20;
    const original_first_byte = packet[0];

    try hp.apply(&packet, 5);
    try testing.expect(packet[0] != original_first_byte);

    try hp.remove(&packet, 5);
    try testing.expectEqual(original_first_byte, packet[0]);
}
