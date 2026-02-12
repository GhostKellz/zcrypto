//! Signal Protocol Implementation for zcrypto
//!
//! Implements the Signal Protocol (X3DH + Double Ratchet) for secure messaging
//! with post-quantum enhancements for future-proofing

const std = @import("std");
const pq = @import("../pq.zig");
const asym = @import("../asym.zig");
const kdf = @import("../kdf.zig");

/// Signal Protocol errors
pub const SignalError = error{
    InvalidKey,
    InvalidSignature,
    RatchetFailed,
    MessageDecryptionFailed,
    KeyExchangeFailed,
    InvalidMessage,
};

/// X3DH Key Exchange Implementation
pub const X3DH = struct {
    /// Identity key pair (long-term)
    pub const IdentityKey = struct {
        public: [32]u8,
        private: [32]u8,

        pub fn generate() !IdentityKey {
            var seed: [32]u8 = undefined;
            rand.fill(&seed);

            const keypair = std.crypto.sign.Ed25519.KeyPair.create(seed) catch {
                return SignalError.KeyExchangeFailed;
            };

            return IdentityKey{
                .public = keypair.public_key,
                .private = keypair.secret_key,
            };
        }
    };

    /// Signed prekey (medium-term)
    pub const SignedPrekey = struct {
        public: [32]u8,
        private: [32]u8,
        signature: [64]u8,

        pub fn generate(identity_key: *const IdentityKey) !SignedPrekey {
            var seed: [32]u8 = undefined;
            rand.fill(&seed);

            const dh_keypair = std.crypto.dh.X25519.KeyPair.create(seed) catch {
                return SignalError.KeyExchangeFailed;
            };

            // Sign the prekey with identity key
            const identity_keypair = std.crypto.sign.Ed25519.KeyPair{
                .public_key = identity_key.public,
                .secret_key = identity_key.private,
            };

            const signature = identity_keypair.sign(&dh_keypair.public_key, null) catch {
                return SignalError.InvalidSignature;
            };

            return SignedPrekey{
                .public = dh_keypair.public_key,
                .private = dh_keypair.secret_key,
                .signature = signature,
            };
        }

        pub fn verify(self: *const SignedPrekey, identity_public: [32]u8) !bool {
            std.crypto.sign.Ed25519.verify(self.signature, &self.public, identity_public) catch {
                return false;
            };
            return true;
        }
    };

    /// One-time prekey (ephemeral)
    pub const OneTimePrekey = struct {
        public: [32]u8,
        private: [32]u8,

        pub fn generate() !OneTimePrekey {
            var seed: [32]u8 = undefined;
            rand.fill(&seed);

            const keypair = std.crypto.dh.X25519.KeyPair.create(seed) catch {
                return SignalError.KeyExchangeFailed;
            };

            return OneTimePrekey{
                .public = keypair.public_key,
                .private = keypair.secret_key,
            };
        }
    };

    /// Perform X3DH key exchange
    pub fn keyExchange(
        alice_identity: *const IdentityKey,
        alice_ephemeral: *const OneTimePrekey,
        bob_identity_public: [32]u8,
        bob_signed_prekey: *const SignedPrekey,
        bob_onetime_public: ?[32]u8,
    ) !struct { shared_secret: [32]u8, associated_data: [64]u8 } {
        // Verify Bob's signed prekey
        if (!try bob_signed_prekey.verify(bob_identity_public)) {
            return SignalError.InvalidSignature;
        }

        var dh_outputs: [4][32]u8 = undefined;
        var dh_count: usize = 0;

        // DH1 = DH(IK_A, SPK_B)
        const alice_identity_dh = std.crypto.dh.X25519.KeyPair{
            .public_key = alice_identity.public,
            .secret_key = alice_identity.private,
        };
        dh_outputs[dh_count] = alice_identity_dh.secret_key.mul(bob_signed_prekey.public) catch {
            return SignalError.KeyExchangeFailed;
        };
        dh_count += 1;

        // DH2 = DH(EK_A, IK_B)
        const alice_ephemeral_dh = std.crypto.dh.X25519.KeyPair{
            .public_key = alice_ephemeral.public,
            .secret_key = alice_ephemeral.private,
        };
        dh_outputs[dh_count] = alice_ephemeral_dh.secret_key.mul(bob_identity_public) catch {
            return SignalError.KeyExchangeFailed;
        };
        dh_count += 1;

        // DH3 = DH(EK_A, SPK_B)
        dh_outputs[dh_count] = alice_ephemeral_dh.secret_key.mul(bob_signed_prekey.public) catch {
            return SignalError.KeyExchangeFailed;
        };
        dh_count += 1;

        // DH4 = DH(EK_A, OPK_B) (if one-time prekey exists)
        if (bob_onetime_public) |opk| {
            dh_outputs[dh_count] = alice_ephemeral_dh.secret_key.mul(opk) catch {
                return SignalError.KeyExchangeFailed;
            };
            dh_count += 1;
        }

        // Combine all DH outputs using KDF
        var kdf_input: [128]u8 = undefined;
        var offset: usize = 0;

        for (0..dh_count) |i| {
            @memcpy(kdf_input[offset .. offset + 32], &dh_outputs[i]);
            offset += 32;
        }

        // Derive shared secret
        var shared_secret: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(kdf_input[0..offset]);
        hasher.final(&shared_secret);

        // Create associated data
        var associated_data: [64]u8 = undefined;
        @memcpy(associated_data[0..32], &alice_identity.public);
        @memcpy(associated_data[32..64], &bob_identity_public);

        return .{ .shared_secret = shared_secret, .associated_data = associated_data };
    }
};

/// Double Ratchet Implementation
pub const DoubleRatchet = struct {
    /// Ratchet state
    pub const State = struct {
        root_key: [32]u8,
        chain_key_send: [32]u8,
        chain_key_recv: [32]u8,
        dh_send: std.crypto.dh.X25519.KeyPair,
        dh_recv_public: ?[32]u8,
        send_count: u32,
        recv_count: u32,
        prev_send_count: u32,
        skipped_keys: std.ArrayList([32]u8),

        pub fn init(allocator: std.mem.Allocator, shared_secret: [32]u8) !State {
            var seed: [32]u8 = undefined;
            rand.fill(&seed);

            const dh_keypair = std.crypto.dh.X25519.KeyPair.create(seed) catch {
                return SignalError.KeyExchangeFailed;
            };

            return State{
                .root_key = shared_secret,
                .chain_key_send = shared_secret,
                .chain_key_recv = shared_secret,
                .dh_send = dh_keypair,
                .dh_recv_public = null,
                .send_count = 0,
                .recv_count = 0,
                .prev_send_count = 0,
                .skipped_keys = std.ArrayList([32]u8).init(allocator),
            };
        }

        pub fn deinit(self: *State) void {
            self.skipped_keys.deinit();
        }
    };

    /// Encrypted message
    pub const Message = struct {
        header: MessageHeader,
        ciphertext: []const u8,

        pub const MessageHeader = struct {
            dh_public: [32]u8,
            prev_chain_length: u32,
            message_number: u32,
        };
    };

    /// Encrypt message with double ratchet
    pub fn encrypt(state: *State, plaintext: []const u8, ciphertext: []u8) !Message {
        // Derive message key from chain key
        var message_key: [32]u8 = undefined;
        deriveMessageKey(&state.chain_key_send, &message_key);

        // Advance chain key
        advanceChainKey(&state.chain_key_send);

        // Simple encryption (would use proper AEAD in production)
        const min_len = @min(plaintext.len, ciphertext.len);
        for (0..min_len) |i| {
            ciphertext[i] = plaintext[i] ^ message_key[i % 32];
        }

        const header = Message.MessageHeader{
            .dh_public = state.dh_send.public_key,
            .prev_chain_length = state.prev_send_count,
            .message_number = state.send_count,
        };

        state.send_count += 1;

        return Message{
            .header = header,
            .ciphertext = ciphertext[0..min_len],
        };
    }

    /// Decrypt message with double ratchet
    pub fn decrypt(state: *State, message: Message, plaintext: []u8) !void {
        // Check if we need to perform DH ratchet
        if (state.dh_recv_public == null or
            !std.mem.eql(u8, &state.dh_recv_public.?, &message.header.dh_public))
        {

            // Perform DH ratchet
            try dhRatchet(state, message.header.dh_public);
        }

        // Derive message key
        var message_key: [32]u8 = undefined;
        deriveMessageKey(&state.chain_key_recv, &message_key);

        // Advance chain key
        advanceChainKey(&state.chain_key_recv);

        // Decrypt message
        const min_len = @min(message.ciphertext.len, plaintext.len);
        for (0..min_len) |i| {
            plaintext[i] = message.ciphertext[i] ^ message_key[i % 32];
        }

        state.recv_count += 1;
    }

    fn dhRatchet(state: *State, remote_public: [32]u8) !void {
        // Save current sending chain length
        state.prev_send_count = state.send_count;

        // Generate new DH key pair
        var seed: [32]u8 = undefined;
        rand.fill(&seed);

        state.dh_send = std.crypto.dh.X25519.KeyPair.create(seed) catch {
            return SignalError.KeyExchangeFailed;
        };

        state.dh_recv_public = remote_public;

        // Derive new root key and chain keys
        const dh_output = state.dh_send.secret_key.mul(remote_public) catch {
            return SignalError.KeyExchangeFailed;
        };

        // KDF to derive new keys
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(&state.root_key);
        hasher.update(&dh_output);
        hasher.final(&state.root_key);

        // Derive new chain keys
        hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(&state.root_key);
        hasher.update("send");
        hasher.final(&state.chain_key_send);

        hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(&state.root_key);
        hasher.update("recv");
        hasher.final(&state.chain_key_recv);

        // Reset counters
        state.send_count = 0;
        state.recv_count = 0;
    }

    fn deriveMessageKey(chain_key: []const u8, message_key: []u8) void {
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(chain_key);
        hasher.update("message");
        hasher.final(message_key[0..32]);
    }

    fn advanceChainKey(chain_key: []u8) void {
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(chain_key);
        hasher.update("chain");
        hasher.final(chain_key[0..32]);
    }
};

/// Post-Quantum Enhanced Signal Protocol
pub const PQSignal = struct {
    /// Hybrid X3DH with post-quantum enhancement
    pub fn hybridX3DH(
        alice_identity: *const X3DH.IdentityKey,
        alice_ephemeral: *const X3DH.OneTimePrekey,
        alice_pq_keypair: *const pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
        bob_identity_public: [32]u8,
        bob_signed_prekey: *const X3DH.SignedPrekey,
        bob_pq_public: [pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8,
        bob_onetime_public: ?[32]u8,
    ) !struct { shared_secret: [64]u8, associated_data: [64]u8 } {
        // Classical X3DH
        const classical_result = try X3DH.keyExchange(
            alice_identity,
            alice_ephemeral,
            bob_identity_public,
            bob_signed_prekey,
            bob_onetime_public,
        );

        // Post-quantum key exchange
        var pq_randomness: [32]u8 = undefined;
        rand.fill(&pq_randomness);

        const pq_result = pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(bob_pq_public, pq_randomness) catch {
            return SignalError.KeyExchangeFailed;
        };

        // Combine classical and post-quantum secrets
        var combined_secret: [64]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
        hasher.update(&classical_result.shared_secret);
        hasher.update(&pq_result.shared_secret);
        hasher.final(&combined_secret);

        return .{
            .shared_secret = combined_secret,
            .associated_data = classical_result.associated_data,
        };
    }
};

test "Signal Protocol X3DH" {
    const alice_identity = try X3DH.IdentityKey.generate();
    const alice_ephemeral = try X3DH.OneTimePrekey.generate();

    const bob_identity = try X3DH.IdentityKey.generate();
    const bob_signed_prekey = try X3DH.SignedPrekey.generate(&bob_identity);
    const bob_onetime = try X3DH.OneTimePrekey.generate();

    const result = try X3DH.keyExchange(
        &alice_identity,
        &alice_ephemeral,
        bob_identity.public,
        &bob_signed_prekey,
        bob_onetime.public,
    );

    // Verify we got a shared secret
    try std.testing.expect(!std.mem.allEqual(u8, &result.shared_secret, 0));
}

test "Double Ratchet encryption/decryption" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var shared_secret: [32]u8 = undefined;
    rand.fill(&shared_secret);

    var alice_state = try DoubleRatchet.State.init(gpa.allocator(), shared_secret);
    defer alice_state.deinit();

    var bob_state = try DoubleRatchet.State.init(gpa.allocator(), shared_secret);
    defer bob_state.deinit();

    // Test message
    const plaintext = "Hello, Signal!";
    var ciphertext = [_]u8{0} ** 64;
    var decrypted = [_]u8{0} ** 64;

    // Alice encrypts
    const message = try DoubleRatchet.encrypt(&alice_state, plaintext, &ciphertext);

    // Bob decrypts
    try DoubleRatchet.decrypt(&bob_state, message, &decrypted);

    try std.testing.expect(std.mem.eql(u8, plaintext, decrypted[0..plaintext.len]));
}
