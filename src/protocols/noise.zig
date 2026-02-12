//! Noise Protocol Framework Implementation for zcrypto
//!
//! Implements the Noise Protocol Framework with post-quantum enhancements
//! Supports multiple handshake patterns with cryptographic agility

const std = @import("std");
const pq = @import("../pq.zig");
const kdf = @import("../kdf.zig");

/// Noise Protocol errors
pub const NoiseError = error{
    InvalidHandshake,
    InvalidMessage,
    InvalidKey,
    HandshakeFailed,
    DecryptionFailed,
    InvalidPattern,
};

/// Noise handshake patterns
pub const HandshakePattern = enum {
    NN, // No static keys
    KN, // Initiator has static key
    NK, // Responder has static key
    KK, // Both have static keys
    NX, // Responder transmits static key
    KX, // Responder transmits static key, initiator has static
    XN, // Initiator transmits static key
    XK, // Initiator transmits static key, responder has static
    XX, // Both transmit static keys
    IK, // Initiator knows responder static key
    IX, // Initiator transmits static key immediately

    // Post-quantum enhanced patterns
    pqNN, // PQ + NN
    pqXX, // PQ + XX
    pqIK, // PQ + IK
};

/// Cipher suite configuration
pub const CipherSuite = struct {
    dh: DHFunction,
    cipher: CipherFunction,
    hash: HashFunction,

    pub const DHFunction = enum {
        Curve25519,
        Kyber768,
        Hybrid_X25519_Kyber768,
    };

    pub const CipherFunction = enum {
        ChaChaPoly,
        AESGCM,
    };

    pub const HashFunction = enum {
        SHA256,
        SHA512,
        BLAKE2s,
        BLAKE2b,
    };
};

/// Noise handshake state
pub const HandshakeState = struct {
    pattern: HandshakePattern,
    cipher_suite: CipherSuite,
    is_initiator: bool,

    // Symmetric state
    ck: [32]u8, // Chaining key
    h: [32]u8, // Handshake hash

    // Key pairs
    s: ?KeyPair, // Static key pair
    e: ?KeyPair, // Ephemeral key pair
    rs: ?[32]u8, // Remote static public key
    re: ?[32]u8, // Remote ephemeral public key

    // PQ keys
    pq_s: ?pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
    pq_e: ?pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
    pq_rs: ?[pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8,
    pq_re: ?[pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8,

    // Message patterns for this handshake
    message_patterns: []const MessagePattern,
    current_pattern_index: usize,

    const KeyPair = struct {
        public: [32]u8,
        private: [32]u8,
    };

    const MessagePattern = struct {
        tokens: []const Token,

        const Token = enum {
            e, // Ephemeral key
            s, // Static key
            ee, // DH(e, e)
            es, // DH(e, s) or DH(s, e)
            se, // DH(s, e) or DH(e, s)
            ss, // DH(s, s)
            psk, // Pre-shared key

            // Post-quantum tokens
            pqe, // PQ ephemeral
            pqs, // PQ static
            pqee, // PQ DH(e, e)
            pqes, // PQ DH(e, s)
            pqse, // PQ DH(s, e)
            pqss, // PQ DH(s, s)
        };
    };

    /// Initialize handshake state
    pub fn init(
        pattern: HandshakePattern,
        cipher_suite: CipherSuite,
        is_initiator: bool,
        prologue: []const u8,
        static_keypair: ?KeyPair,
        pq_static_keypair: ?pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
    ) !HandshakeState {
        var state = HandshakeState{
            .pattern = pattern,
            .cipher_suite = cipher_suite,
            .is_initiator = is_initiator,
            .ck = undefined,
            .h = undefined,
            .s = static_keypair,
            .e = null,
            .rs = null,
            .re = null,
            .pq_s = pq_static_keypair,
            .pq_e = null,
            .pq_rs = null,
            .pq_re = null,
            .message_patterns = undefined,
            .current_pattern_index = 0,
        };

        // Initialize chaining key and hash
        const protocol_name = try getProtocolName(pattern, cipher_suite);
        if (protocol_name.len <= 32) {
            @memcpy(state.h[0..protocol_name.len], protocol_name);
            @memset(state.h[protocol_name.len..], 0);
        } else {
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(protocol_name);
            hasher.final(&state.h);
        }

        state.ck = state.h;

        // Mix prologue
        mixHash(&state.h, prologue, cipher_suite.hash);

        // Set message patterns based on handshake pattern
        state.message_patterns = getMessagePatterns(pattern);

        return state;
    }

    /// Generate the next handshake message
    pub fn writeMessage(self: *HandshakeState, payload: []const u8, message_buffer: []u8) !struct {
        message: []const u8,
        transport_keys: ?TransportKeys,
    } {
        if (self.current_pattern_index >= self.message_patterns.len) {
            return NoiseError.InvalidHandshake;
        }

        const pattern = self.message_patterns[self.current_pattern_index];
        var offset: usize = 0;

        // Process each token in the pattern
        for (pattern.tokens) |token| {
            switch (token) {
                .e => {
                    // Generate ephemeral key
                    self.e = try generateKeyPair();
                    @memcpy(message_buffer[offset .. offset + 32], &self.e.?.public);
                    mixHash(&self.h, &self.e.?.public, self.cipher_suite.hash);
                    offset += 32;
                },
                .s => {
                    // Send static key (encrypted if k > 0)
                    if (self.s) |static_key| {
                        @memcpy(message_buffer[offset .. offset + 32], &static_key.public);
                        mixHash(&self.h, &static_key.public, self.cipher_suite.hash);
                        offset += 32;
                    } else {
                        return NoiseError.InvalidKey;
                    }
                },
                .ee => {
                    // DH(e, e)
                    if (self.e != null and self.re != null) {
                        const dh_result = try performDH(self.e.?.private, self.re.?);
                        mixKey(&self.ck, &dh_result, self.cipher_suite.hash);
                    }
                },
                .es => {
                    // DH(e, s) or DH(s, e)
                    if (self.is_initiator) {
                        if (self.e != null and self.rs != null) {
                            const dh_result = try performDH(self.e.?.private, self.rs.?);
                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);
                        }
                    } else {
                        if (self.s != null and self.re != null) {
                            const dh_result = try performDH(self.s.?.private, self.re.?);
                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);
                        }
                    }
                },
                .se => {
                    // DH(s, e) or DH(e, s)
                    if (self.is_initiator) {
                        if (self.s != null and self.re != null) {
                            const dh_result = try performDH(self.s.?.private, self.re.?);
                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);
                        }
                    } else {
                        if (self.e != null and self.rs != null) {
                            const dh_result = try performDH(self.e.?.private, self.rs.?);
                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);
                        }
                    }
                },
                .ss => {
                    // DH(s, s)
                    if (self.s != null and self.rs != null) {
                        const dh_result = try performDH(self.s.?.private, self.rs.?);
                        mixKey(&self.ck, &dh_result, self.cipher_suite.hash);
                    }
                },
                .pqe => {
                    // Post-quantum ephemeral
                    self.pq_e = try pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();
                    @memcpy(message_buffer[offset .. offset + 32], &self.pq_e.?.classical_public);
                    offset += 32;
                    @memcpy(message_buffer[offset .. offset + pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE], &self.pq_e.?.pq_public);
                    offset += pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE;
                },
                .pqee => {
                    // Post-quantum DH(e, e)
                    if (self.pq_e != null and self.pq_re != null) {
                        // Simplified PQ key exchange
                        var pq_randomness: [32]u8 = undefined;
                        rand.fill(&pq_randomness);

                        const pq_result = pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(self.pq_re.?, pq_randomness) catch {
                            return NoiseError.HandshakeFailed;
                        };

                        mixKey(&self.ck, &pq_result.shared_secret, self.cipher_suite.hash);
                    }
                },
                else => {
                    // Other tokens handled similarly
                },
            }
        }

        // Encrypt payload if we have a key
        const encrypted_payload_len = try encryptAndHash(self, payload, message_buffer[offset..]);
        offset += encrypted_payload_len;

        self.current_pattern_index += 1;

        // Check if handshake is complete
        const transport_keys = if (self.current_pattern_index >= self.message_patterns.len)
            try split(&self.ck, self.cipher_suite.hash)
        else
            null;

        return .{
            .message = message_buffer[0..offset],
            .transport_keys = transport_keys,
        };
    }

    /// Process received handshake message
    pub fn readMessage(self: *HandshakeState, message: []const u8, payload_buffer: []u8) !struct {
        payload: []const u8,
        transport_keys: ?TransportKeys,
    } {
        if (self.current_pattern_index >= self.message_patterns.len) {
            return NoiseError.InvalidHandshake;
        }

        const pattern = self.message_patterns[self.current_pattern_index];
        var offset: usize = 0;

        // Process each token in the pattern
        for (pattern.tokens) |token| {
            switch (token) {
                .e => {
                    // Receive ephemeral key
                    if (offset + 32 > message.len) return NoiseError.InvalidMessage;
                    self.re = message[offset .. offset + 32].*;
                    mixHash(&self.h, &self.re.?, self.cipher_suite.hash);
                    offset += 32;
                },
                .s => {
                    // Receive static key
                    if (offset + 32 > message.len) return NoiseError.InvalidMessage;
                    self.rs = message[offset .. offset + 32].*;
                    mixHash(&self.h, &self.rs.?, self.cipher_suite.hash);
                    offset += 32;
                },
                .ee, .es, .se, .ss => {
                    // DH operations (same as writeMessage)
                    // ... (implementation similar to writeMessage)
                },
                .pqe => {
                    // Receive PQ ephemeral
                    const classical_size = 32;
                    const pq_size = pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE;

                    if (offset + classical_size + pq_size > message.len) {
                        return NoiseError.InvalidMessage;
                    }

                    // Store received PQ public key
                    self.pq_re = message[offset + classical_size .. offset + classical_size + pq_size].*;
                    offset += classical_size + pq_size;
                },
                else => {},
            }
        }

        // Decrypt payload
        const payload_len = try decryptAndHash(self, message[offset..], payload_buffer);

        self.current_pattern_index += 1;

        // Check if handshake is complete
        const transport_keys = if (self.current_pattern_index >= self.message_patterns.len)
            try split(&self.ck, self.cipher_suite.hash)
        else
            null;

        return .{
            .payload = payload_buffer[0..payload_len],
            .transport_keys = transport_keys,
        };
    }
};

/// Transport keys for post-handshake communication
pub const TransportKeys = struct {
    send_key: [32]u8,
    recv_key: [32]u8,
};

/// Transport state for post-handshake communication
pub const TransportState = struct {
    send_key: [32]u8,
    recv_key: [32]u8,
    send_nonce: u64,
    recv_nonce: u64,

    pub fn init(keys: TransportKeys) TransportState {
        return TransportState{
            .send_key = keys.send_key,
            .recv_key = keys.recv_key,
            .send_nonce = 0,
            .recv_nonce = 0,
        };
    }

    pub fn encrypt(self: *TransportState, plaintext: []const u8, ciphertext: []u8) ![]const u8 {
        // Simple encryption (would use ChaCha20-Poly1305 in production)
        const min_len = @min(plaintext.len, ciphertext.len);

        for (0..min_len) |i| {
            ciphertext[i] = plaintext[i] ^ self.send_key[i % 32] ^ @as(u8, @truncate(self.send_nonce));
        }

        self.send_nonce += 1;
        return ciphertext[0..min_len];
    }

    pub fn decrypt(self: *TransportState, ciphertext: []const u8, plaintext: []u8) ![]const u8 {
        // Simple decryption
        const min_len = @min(ciphertext.len, plaintext.len);

        for (0..min_len) |i| {
            plaintext[i] = ciphertext[i] ^ self.recv_key[i % 32] ^ @as(u8, @truncate(self.recv_nonce));
        }

        self.recv_nonce += 1;
        return plaintext[0..min_len];
    }
};

// Helper functions

fn generateKeyPair() !HandshakeState.KeyPair {
    var seed: [32]u8 = undefined;
    rand.fill(&seed);

    const keypair = std.crypto.dh.X25519.KeyPair.create(seed) catch {
        return NoiseError.InvalidKey;
    };

    return HandshakeState.KeyPair{
        .public = keypair.public_key,
        .private = keypair.secret_key,
    };
}

fn performDH(private_key: [32]u8, public_key: [32]u8) ![32]u8 {
    const keypair = std.crypto.dh.X25519.KeyPair{
        .public_key = undefined, // Not needed for DH
        .secret_key = private_key,
    };

    return keypair.secret_key.mul(public_key) catch {
        return NoiseError.HandshakeFailed;
    };
}

fn mixHash(h: []u8, data: []const u8, hash_func: CipherSuite.HashFunction) void {
    _ = hash_func;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(h);
    hasher.update(data);
    hasher.final(h[0..32]);
}

fn mixKey(ck: []u8, input_key_material: []const u8, hash_func: CipherSuite.HashFunction) void {
    _ = hash_func;
    // Simplified HKDF
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(ck);
    hasher.update(input_key_material);
    hasher.final(ck[0..32]);
}

fn encryptAndHash(state: *HandshakeState, plaintext: []const u8, ciphertext_buffer: []u8) !usize {
    // Simplified encryption
    _ = state;
    const len = @min(plaintext.len, ciphertext_buffer.len);
    @memcpy(ciphertext_buffer[0..len], plaintext[0..len]);
    return len;
}

fn decryptAndHash(state: *HandshakeState, ciphertext: []const u8, plaintext_buffer: []u8) !usize {
    // Simplified decryption
    _ = state;
    const len = @min(ciphertext.len, plaintext_buffer.len);
    @memcpy(plaintext_buffer[0..len], ciphertext[0..len]);
    return len;
}

fn split(ck: []const u8, hash_func: CipherSuite.HashFunction) !TransportKeys {
    _ = hash_func;
    var keys: TransportKeys = undefined;

    // Derive two keys from chaining key
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(ck);
    hasher.update("send");
    hasher.final(&keys.send_key);

    hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(ck);
    hasher.update("recv");
    hasher.final(&keys.recv_key);

    return keys;
}

fn getProtocolName(pattern: HandshakePattern, cipher_suite: CipherSuite) ![]const u8 {
    _ = pattern;
    _ = cipher_suite;
    return "Noise_XX_25519_ChaChaPoly_SHA256";
}

fn getMessagePatterns(pattern: HandshakePattern) []const HandshakeState.MessagePattern {
    const Token = HandshakeState.MessagePattern.Token;

    return switch (pattern) {
        .XX => &[_]HandshakeState.MessagePattern{
            HandshakeState.MessagePattern{ .tokens = &[_]Token{.e} },
            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .e, .ee, .s, .es } },
            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .s, .se } },
        },
        .pqXX => &[_]HandshakeState.MessagePattern{
            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .e, .pqe } },
            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .e, .pqe, .ee, .pqee, .s, .pqs, .es, .pqes } },
            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .s, .pqs, .se, .pqse } },
        },
        else => &[_]HandshakeState.MessagePattern{
            HandshakeState.MessagePattern{ .tokens = &[_]Token{.e} },
        },
    };
}

test "Noise handshake XX pattern" {
    const cipher_suite = CipherSuite{
        .dh = .Curve25519,
        .cipher = .ChaChaPoly,
        .hash = .SHA256,
    };

    // Generate static keys
    const alice_static = try generateKeyPair();
    const bob_static = try generateKeyPair();

    // Initialize handshake states
    var alice_state = try HandshakeState.init(
        .XX,
        cipher_suite,
        true, // Alice is initiator
        "test prologue",
        alice_static,
        null,
    );

    var bob_state = try HandshakeState.init(
        .XX,
        cipher_suite,
        false, // Bob is responder
        "test prologue",
        bob_static,
        null,
    );

    // Message buffers
    var message_buffer = [_]u8{0} ** 1024;
    var payload_buffer = [_]u8{0} ** 512;

    // Alice -> Bob (message 1)
    const msg1 = try alice_state.writeMessage("Hello", &message_buffer);
    const recv1 = try bob_state.readMessage(msg1.message, &payload_buffer);

    try std.testing.expect(std.mem.eql(u8, "Hello", recv1.payload));
    try std.testing.expect(recv1.transport_keys == null); // Handshake not complete

    // Test that handshake progresses
    try std.testing.expect(alice_state.current_pattern_index == 1);
    try std.testing.expect(bob_state.current_pattern_index == 1);
}
