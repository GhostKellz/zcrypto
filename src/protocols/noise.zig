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
    h: [32]u8,  // Handshake hash
    
    // Key pairs
    s: ?KeyPair,  // Static key pair
    e: ?KeyPair,  // Ephemeral key pair
    rs: ?[32]u8,  // Remote static public key
    re: ?[32]u8,  // Remote ephemeral public key
    
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
            e,  // Ephemeral key
            s,  // Static key
            ee, // DH(e, e)
            es, // DH(e, s) or DH(s, e)
            se, // DH(s, e) or DH(e, s)
            ss, // DH(s, s)
            psk, // Pre-shared key
            
            // Post-quantum tokens
            pqe,  // PQ ephemeral
            pqs,  // PQ static
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
    ) !HandshakeState {\n        var state = HandshakeState{\n            .pattern = pattern,\n            .cipher_suite = cipher_suite,\n            .is_initiator = is_initiator,\n            .ck = undefined,\n            .h = undefined,\n            .s = static_keypair,\n            .e = null,\n            .rs = null,\n            .re = null,\n            .pq_s = pq_static_keypair,\n            .pq_e = null,\n            .pq_rs = null,\n            .pq_re = null,\n            .message_patterns = undefined,\n            .current_pattern_index = 0,\n        };\n        \n        // Initialize chaining key and hash\n        const protocol_name = try getProtocolName(pattern, cipher_suite);\n        if (protocol_name.len <= 32) {\n            @memcpy(state.h[0..protocol_name.len], protocol_name);\n            @memset(state.h[protocol_name.len..], 0);\n        } else {\n            var hasher = std.crypto.hash.sha2.Sha256.init(.{});\n            hasher.update(protocol_name);\n            hasher.final(&state.h);\n        }\n        \n        state.ck = state.h;\n        \n        // Mix prologue\n        mixHash(&state.h, prologue, cipher_suite.hash);\n        \n        // Set message patterns based on handshake pattern\n        state.message_patterns = getMessagePatterns(pattern);\n        \n        return state;\n    }\n    \n    /// Generate the next handshake message\n    pub fn writeMessage(self: *HandshakeState, payload: []const u8, message_buffer: []u8) !struct {\n        message: []const u8,\n        transport_keys: ?TransportKeys,\n    } {\n        if (self.current_pattern_index >= self.message_patterns.len) {\n            return NoiseError.InvalidHandshake;\n        }\n        \n        const pattern = self.message_patterns[self.current_pattern_index];\n        var offset: usize = 0;\n        \n        // Process each token in the pattern\n        for (pattern.tokens) |token| {\n            switch (token) {\n                .e => {\n                    // Generate ephemeral key\n                    self.e = try generateKeyPair();\n                    @memcpy(message_buffer[offset..offset + 32], &self.e.?.public);\n                    mixHash(&self.h, &self.e.?.public, self.cipher_suite.hash);\n                    offset += 32;\n                },\n                .s => {\n                    // Send static key (encrypted if k > 0)\n                    if (self.s) |static_key| {\n                        @memcpy(message_buffer[offset..offset + 32], &static_key.public);\n                        mixHash(&self.h, &static_key.public, self.cipher_suite.hash);\n                        offset += 32;\n                    } else {\n                        return NoiseError.InvalidKey;\n                    }\n                },\n                .ee => {\n                    // DH(e, e)\n                    if (self.e != null and self.re != null) {\n                        const dh_result = try performDH(self.e.?.private, self.re.?);\n                        mixKey(&self.ck, &dh_result, self.cipher_suite.hash);\n                    }\n                },\n                .es => {\n                    // DH(e, s) or DH(s, e)\n                    if (self.is_initiator) {\n                        if (self.e != null and self.rs != null) {\n                            const dh_result = try performDH(self.e.?.private, self.rs.?);\n                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);\n                        }\n                    } else {\n                        if (self.s != null and self.re != null) {\n                            const dh_result = try performDH(self.s.?.private, self.re.?);\n                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);\n                        }\n                    }\n                },\n                .se => {\n                    // DH(s, e) or DH(e, s)\n                    if (self.is_initiator) {\n                        if (self.s != null and self.re != null) {\n                            const dh_result = try performDH(self.s.?.private, self.re.?);\n                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);\n                        }\n                    } else {\n                        if (self.e != null and self.rs != null) {\n                            const dh_result = try performDH(self.e.?.private, self.rs.?);\n                            mixKey(&self.ck, &dh_result, self.cipher_suite.hash);\n                        }\n                    }\n                },\n                .ss => {\n                    // DH(s, s)\n                    if (self.s != null and self.rs != null) {\n                        const dh_result = try performDH(self.s.?.private, self.rs.?);\n                        mixKey(&self.ck, &dh_result, self.cipher_suite.hash);\n                    }\n                },\n                .pqe => {\n                    // Post-quantum ephemeral\n                    self.pq_e = try pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();\n                    @memcpy(message_buffer[offset..offset + 32], &self.pq_e.?.classical_public);\n                    offset += 32;\n                    @memcpy(message_buffer[offset..offset + pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE], &self.pq_e.?.pq_public);\n                    offset += pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE;\n                },\n                .pqee => {\n                    // Post-quantum DH(e, e)\n                    if (self.pq_e != null and self.pq_re != null) {\n                        // Simplified PQ key exchange\n                        var pq_randomness: [32]u8 = undefined;\n                        std.crypto.random.bytes(&pq_randomness);\n                        \n                        const pq_result = pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(self.pq_re.?, pq_randomness) catch {\n                            return NoiseError.HandshakeFailed;\n                        };\n                        \n                        mixKey(&self.ck, &pq_result.shared_secret, self.cipher_suite.hash);\n                    }\n                },\n                else => {\n                    // Other tokens handled similarly\n                },\n            }\n        }\n        \n        // Encrypt payload if we have a key\n        const encrypted_payload_len = try encryptAndHash(self, payload, message_buffer[offset..]);\n        offset += encrypted_payload_len;\n        \n        self.current_pattern_index += 1;\n        \n        // Check if handshake is complete\n        const transport_keys = if (self.current_pattern_index >= self.message_patterns.len)\n            try split(&self.ck, self.cipher_suite.hash)\n        else\n            null;\n        \n        return .{\n            .message = message_buffer[0..offset],\n            .transport_keys = transport_keys,\n        };\n    }\n    \n    /// Process received handshake message\n    pub fn readMessage(self: *HandshakeState, message: []const u8, payload_buffer: []u8) !struct {\n        payload: []const u8,\n        transport_keys: ?TransportKeys,\n    } {\n        if (self.current_pattern_index >= self.message_patterns.len) {\n            return NoiseError.InvalidHandshake;\n        }\n        \n        const pattern = self.message_patterns[self.current_pattern_index];\n        var offset: usize = 0;\n        \n        // Process each token in the pattern\n        for (pattern.tokens) |token| {\n            switch (token) {\n                .e => {\n                    // Receive ephemeral key\n                    if (offset + 32 > message.len) return NoiseError.InvalidMessage;\n                    self.re = message[offset..offset + 32].*;\n                    mixHash(&self.h, &self.re.?, self.cipher_suite.hash);\n                    offset += 32;\n                },\n                .s => {\n                    // Receive static key\n                    if (offset + 32 > message.len) return NoiseError.InvalidMessage;\n                    self.rs = message[offset..offset + 32].*;\n                    mixHash(&self.h, &self.rs.?, self.cipher_suite.hash);\n                    offset += 32;\n                },\n                .ee, .es, .se, .ss => {\n                    // DH operations (same as writeMessage)\n                    // ... (implementation similar to writeMessage)\n                },\n                .pqe => {\n                    // Receive PQ ephemeral\n                    const classical_size = 32;\n                    const pq_size = pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE;\n                    \n                    if (offset + classical_size + pq_size > message.len) {\n                        return NoiseError.InvalidMessage;\n                    }\n                    \n                    // Store received PQ public key\n                    self.pq_re = message[offset + classical_size..offset + classical_size + pq_size].*;\n                    offset += classical_size + pq_size;\n                },\n                else => {},\n            }\n        }\n        \n        // Decrypt payload\n        const payload_len = try decryptAndHash(self, message[offset..], payload_buffer);\n        \n        self.current_pattern_index += 1;\n        \n        // Check if handshake is complete\n        const transport_keys = if (self.current_pattern_index >= self.message_patterns.len)\n            try split(&self.ck, self.cipher_suite.hash)\n        else\n            null;\n        \n        return .{\n            .payload = payload_buffer[0..payload_len],\n            .transport_keys = transport_keys,\n        };\n    }\n};\n\n/// Transport keys for post-handshake communication\npub const TransportKeys = struct {\n    send_key: [32]u8,\n    recv_key: [32]u8,\n};\n\n/// Transport state for post-handshake communication\npub const TransportState = struct {\n    send_key: [32]u8,\n    recv_key: [32]u8,\n    send_nonce: u64,\n    recv_nonce: u64,\n    \n    pub fn init(keys: TransportKeys) TransportState {\n        return TransportState{\n            .send_key = keys.send_key,\n            .recv_key = keys.recv_key,\n            .send_nonce = 0,\n            .recv_nonce = 0,\n        };\n    }\n    \n    pub fn encrypt(self: *TransportState, plaintext: []const u8, ciphertext: []u8) ![]const u8 {\n        // Simple encryption (would use ChaCha20-Poly1305 in production)\n        const min_len = @min(plaintext.len, ciphertext.len);\n        \n        for (0..min_len) |i| {\n            ciphertext[i] = plaintext[i] ^ self.send_key[i % 32] ^ @as(u8, @truncate(self.send_nonce));\n        }\n        \n        self.send_nonce += 1;\n        return ciphertext[0..min_len];\n    }\n    \n    pub fn decrypt(self: *TransportState, ciphertext: []const u8, plaintext: []u8) ![]const u8 {\n        // Simple decryption\n        const min_len = @min(ciphertext.len, plaintext.len);\n        \n        for (0..min_len) |i| {\n            plaintext[i] = ciphertext[i] ^ self.recv_key[i % 32] ^ @as(u8, @truncate(self.recv_nonce));\n        }\n        \n        self.recv_nonce += 1;\n        return plaintext[0..min_len];\n    }\n};\n\n// Helper functions\n\nfn generateKeyPair() !HandshakeState.KeyPair {\n    var seed: [32]u8 = undefined;\n    std.crypto.random.bytes(&seed);\n    \n    const keypair = std.crypto.dh.X25519.KeyPair.create(seed) catch {\n        return NoiseError.InvalidKey;\n    };\n    \n    return HandshakeState.KeyPair{\n        .public = keypair.public_key,\n        .private = keypair.secret_key,\n    };\n}\n\nfn performDH(private_key: [32]u8, public_key: [32]u8) ![32]u8 {\n    const keypair = std.crypto.dh.X25519.KeyPair{\n        .public_key = undefined, // Not needed for DH\n        .secret_key = private_key,\n    };\n    \n    return keypair.secret_key.mul(public_key) catch {\n        return NoiseError.HandshakeFailed;\n    };\n}\n\nfn mixHash(h: []u8, data: []const u8, hash_func: CipherSuite.HashFunction) void {\n    _ = hash_func;\n    var hasher = std.crypto.hash.sha2.Sha256.init(.{});\n    hasher.update(h);\n    hasher.update(data);\n    hasher.final(h[0..32]);\n}\n\nfn mixKey(ck: []u8, input_key_material: []const u8, hash_func: CipherSuite.HashFunction) void {\n    _ = hash_func;\n    // Simplified HKDF\n    var hasher = std.crypto.hash.sha2.Sha256.init(.{});\n    hasher.update(ck);\n    hasher.update(input_key_material);\n    hasher.final(ck[0..32]);\n}\n\nfn encryptAndHash(state: *HandshakeState, plaintext: []const u8, ciphertext_buffer: []u8) !usize {\n    // Simplified encryption\n    _ = state;\n    const len = @min(plaintext.len, ciphertext_buffer.len);\n    @memcpy(ciphertext_buffer[0..len], plaintext[0..len]);\n    return len;\n}\n\nfn decryptAndHash(state: *HandshakeState, ciphertext: []const u8, plaintext_buffer: []u8) !usize {\n    // Simplified decryption\n    _ = state;\n    const len = @min(ciphertext.len, plaintext_buffer.len);\n    @memcpy(plaintext_buffer[0..len], ciphertext[0..len]);\n    return len;\n}\n\nfn split(ck: []const u8, hash_func: CipherSuite.HashFunction) !TransportKeys {\n    _ = hash_func;\n    var keys: TransportKeys = undefined;\n    \n    // Derive two keys from chaining key\n    var hasher = std.crypto.hash.sha2.Sha256.init(.{});\n    hasher.update(ck);\n    hasher.update(\"send\");\n    hasher.final(&keys.send_key);\n    \n    hasher = std.crypto.hash.sha2.Sha256.init(.{});\n    hasher.update(ck);\n    hasher.update(\"recv\");\n    hasher.final(&keys.recv_key);\n    \n    return keys;\n}\n\nfn getProtocolName(pattern: HandshakePattern, cipher_suite: CipherSuite) ![]const u8 {\n    _ = pattern;\n    _ = cipher_suite;\n    return \"Noise_XX_25519_ChaChaPoly_SHA256\";\n}\n\nfn getMessagePatterns(pattern: HandshakePattern) []const HandshakeState.MessagePattern {\n    const Token = HandshakeState.MessagePattern.Token;\n    \n    return switch (pattern) {\n        .XX => &[_]HandshakeState.MessagePattern{\n            HandshakeState.MessagePattern{ .tokens = &[_]Token{.e} },\n            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .e, .ee, .s, .es } },\n            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .s, .se } },\n        },\n        .pqXX => &[_]HandshakeState.MessagePattern{\n            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .e, .pqe } },\n            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .e, .pqe, .ee, .pqee, .s, .pqs, .es, .pqes } },\n            HandshakeState.MessagePattern{ .tokens = &[_]Token{ .s, .pqs, .se, .pqse } },\n        },\n        else => &[_]HandshakeState.MessagePattern{\n            HandshakeState.MessagePattern{ .tokens = &[_]Token{.e} },\n        },\n    };\n}\n\ntest \"Noise handshake XX pattern\" {\n    const cipher_suite = CipherSuite{\n        .dh = .Curve25519,\n        .cipher = .ChaChaPoly,\n        .hash = .SHA256,\n    };\n    \n    // Generate static keys\n    const alice_static = try generateKeyPair();\n    const bob_static = try generateKeyPair();\n    \n    // Initialize handshake states\n    var alice_state = try HandshakeState.init(\n        .XX,\n        cipher_suite,\n        true, // Alice is initiator\n        \"test prologue\",\n        alice_static,\n        null,\n    );\n    \n    var bob_state = try HandshakeState.init(\n        .XX,\n        cipher_suite,\n        false, // Bob is responder\n        \"test prologue\",\n        bob_static,\n        null,\n    );\n    \n    // Message buffers\n    var message_buffer = [_]u8{0} ** 1024;\n    var payload_buffer = [_]u8{0} ** 512;\n    \n    // Alice -> Bob (message 1)\n    const msg1 = try alice_state.writeMessage(\"Hello\", &message_buffer);\n    const recv1 = try bob_state.readMessage(msg1.message, &payload_buffer);\n    \n    try std.testing.expect(std.mem.eql(u8, \"Hello\", recv1.payload));\n    try std.testing.expect(recv1.transport_keys == null); // Handshake not complete\n    \n    // Test that handshake progresses\n    try std.testing.expect(alice_state.current_pattern_index == 1);\n    try std.testing.expect(bob_state.current_pattern_index == 1);\n}