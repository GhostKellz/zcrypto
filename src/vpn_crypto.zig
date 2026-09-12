//! Building blocks for a VPN data channel.
//!
//! # This is not a VPN protocol
//!
//! There is no WireGuard, IPsec, or IKEv2 here: no handshake, no peer
//! authentication, and no rekey negotiation. What it provides is an AEAD
//! record layer keyed by an X25519 exchange, which a real protocol could
//! build on.
//!
//! # Peers are NOT authenticated
//!
//! `establishTunnel` performs a raw X25519 exchange. Binding the two public
//! keys into the key schedule makes both peers agree on *a* transcript; it does
//! not tell either peer *who* is on the other end. An active attacker who can
//! substitute public keys machine-in-the-middles this tunnel completely.
//! Authenticating the peer's static public key is the caller's job.
//!
//! # What is provided
//!
//! - Directional key derivation from an X25519 shared secret (see `TunnelRole`)
//! - AEAD packet sealing via ChaCha20-Poly1305, XChaCha20-Poly1305, or AES-256-GCM
//! - An authenticated wire header carrying the key epoch and sequence number,
//!   plus a sliding anti-replay window, so the tunnel survives loss and
//!   reordering (see `packet_overhead` and `max_plaintext_length`)
//! - Explicit, wire-signalled key updates (see `initiateKeyUpdate`)
//! - Static-key XOR masking for traffic obfuscation (no cryptographic value)
//!
//! # Caller obligations
//!
//! - **Fresh session material.** Every `establishTunnel` call needs a session
//!   nonce pair that has never been used with the same static key pair. See
//!   `TunnelSetup`. Getting this wrong repeats the key *and* nonce sequence,
//!   which breaks the AEAD outright.
//! - **Ownership and zeroization.** `VpnTunnel` is a plain value with no
//!   allocations; it owns copies of its keys. Call `deinit` when finished to
//!   wipe them, and do not copy an established tunnel around, because each copy
//!   keeps its own send counter and two copies will reuse nonces.
//! - **Concurrency.** `VpnTunnel` is not thread-safe. `encryptPacket` and
//!   `decryptPacket` both mutate tunnel state; serialize access externally.

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const util = @import("util.zig");
const rand = @import("rand.zig");

/// VPN-specific errors
pub const VpnCryptoError = error{
    /// The X25519 exchange or key schedule failed; the tunnel is left unusable.
    TunnelEstablishmentFailed,
    /// A packet or key operation was attempted on a tunnel that is not
    /// established (never established, deinitialized, or failed to establish).
    TunnelNotEstablished,
    /// `TunnelSetup` supplied session material that cannot be fresh.
    SessionMaterialReused,
    InvalidTunnelId,
    /// AEAD tag did not verify: the packet was forged, corrupted, truncated, or
    /// sealed under a different key.
    AuthenticationFailed,
    /// Plaintext or packet exceeds `max_plaintext_length` / `max_packet_length`.
    PacketTooLarge,
    BufferTooSmall,
    /// Sequence number already used, or too far behind the replay window.
    ReplayDetected,
    /// Send counter exhausted; call `initiateKeyUpdate` or re-establish rather
    /// than wrap and reuse a nonce.
    SequenceExhausted,
    /// The packet's key epoch is neither the current one nor its immediate
    /// successor. See `decryptPacket` for the bounded epoch policy.
    UnknownKeyEpoch,
    /// Key epoch exhausted; the tunnel must be re-established.
    KeyEpochExhausted,
};

/// Wire layout: `epoch (4, LE) || sequence (8, LE) || ciphertext || tag (16)`.
///
/// The epoch and sequence number travel in the clear, as the sequence number
/// does in WireGuard, because the receiver needs both to pick the key and
/// reconstruct the nonce before it can decrypt. The whole header is
/// authenticated as associated data, so editing either invalidates the tag.
pub const epoch_length = 4;
pub const sequence_length = 8;
pub const header_length = epoch_length + sequence_length;
pub const tag_length = 16;
pub const packet_overhead = header_length + tag_length;

/// One size contract shared by `encryptPacket` and `decryptPacket`.
///
/// `max_packet_length` bounds the total wire bytes, which is what the receive
/// path has to buffer; `max_plaintext_length` is the same bound expressed for
/// the send path. Deriving one from the other is what stops the two paths from
/// drifting apart and letting `encryptPacket` emit packets its own
/// `decryptPacket` would reject as oversized.
pub const max_packet_length = 4096;
pub const max_plaintext_length = max_packet_length - packet_overhead;

/// Length of each peer's per-session nonce. See `TunnelSetup`.
pub const session_nonce_length = 32;

/// Number of packets behind the highest accepted sequence that can still be
/// accepted out of order.
pub const replay_window_size = 64;

/// Send-counter value at which `keyUpdateDue` starts asking for a key update.
///
/// Well below the u64 sequence limit, so a caller that honours `keyUpdateDue`
/// never has to handle `SequenceExhausted` in practice.
pub const key_update_packet_threshold: u64 = 1 << 48;

/// Build an AEAD nonce from a monotonic packet counter, left-padded with zeros.
///
/// The epoch is deliberately absent: each epoch has its own key, so counter
/// uniqueness within an epoch is sufficient for (key, nonce) uniqueness.
fn nonceFrom(comptime len: usize, counter: u64) [len]u8 {
    var nonce = std.mem.zeroes([len]u8);
    std.mem.writeInt(u64, nonce[len - 8 ..][0..8], counter, .little);
    return nonce;
}

/// Derive the key for `epoch` from the key for `epoch - 1`.
///
/// The epoch is mixed in so that two different ratchet steps cannot produce the
/// same key, and so a key is only ever valid at the epoch it was derived for.
fn ratchetKey(key: [32]u8, epoch: u32) [32]u8 {
    const label = "zcrypto-vpn-key-update-v1";
    var info: [label.len + epoch_length]u8 = undefined;
    @memcpy(info[0..label.len], label);
    std.mem.writeInt(u32, info[label.len..][0..epoch_length], epoch, .little);

    var next: [32]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&next, &info, key);
    return next;
}

/// Sliding-window replay filter (RFC 6479 style).
///
/// Only ever updated with sequence numbers whose AEAD tag has already
/// verified; feeding it unauthenticated input would let an attacker advance
/// the window and suppress genuine packets.
///
/// The window is scoped to a single key epoch. That is what makes resetting it
/// on establishment and on a key update safe: an old packet replayed into a new
/// epoch is rejected by the epoch check or fails authentication under the new
/// key, so it never reaches the window in the first place.
const ReplayWindow = struct {
    highest: u64 = 0,
    /// Bit i marks "highest - i has been seen". Bit 0 is `highest` itself.
    bitmap: u64 = 1,
    seeded: bool = false,

    fn check(self: *const ReplayWindow, seq: u64) bool {
        if (!self.seeded) return true;
        if (seq > self.highest) return true;
        const diff = self.highest - seq;
        if (diff >= replay_window_size) return false; // too old to judge
        return (self.bitmap >> @intCast(diff)) & 1 == 0;
    }

    fn commit(self: *ReplayWindow, seq: u64) void {
        if (!self.seeded) {
            self.seeded = true;
            self.highest = seq;
            self.bitmap = 1;
            return;
        }
        if (seq > self.highest) {
            const shift = seq - self.highest;
            self.bitmap = if (shift >= replay_window_size) 1 else (self.bitmap << @intCast(shift)) | 1;
            self.highest = seq;
        } else {
            const diff = self.highest - seq;
            if (diff < replay_window_size) {
                self.bitmap |= @as(u64, 1) << @intCast(diff);
            }
        }
    }
};

/// VPN tunnel configuration
pub const TunnelConfig = struct {
    tunnel_id: u64,
    encryption_algorithm: EncryptionAlgorithm,
    /// Advisory only: consulted by `keyUpdateDue`, never acted on automatically.
    key_update_interval_ms: u64 = 300000, // 5 minutes
    enable_header_protection: bool = true,
    enable_traffic_obfuscation: bool = true,
};

/// Supported encryption algorithms
pub const EncryptionAlgorithm = enum {
    ChaCha20Poly1305,
    AesGcm256,
    XChaCha20Poly1305, // For mobile clients

    /// AEAD nonce length in bytes for this algorithm.
    pub fn nonceLength(self: EncryptionAlgorithm) usize {
        return switch (self) {
            .ChaCha20Poly1305, .AesGcm256 => 12,
            .XChaCha20Poly1305 => 24,
        };
    }
};

/// Which side of the tunnel this endpoint represents.
///
/// Both peers derive the same two directional keys from the shared secret;
/// the role decides which one is used for sending and which for receiving.
/// The two peers MUST be configured with opposite roles or the tunnel will
/// not decrypt.
pub const TunnelRole = enum { initiator, responder };

/// Lifecycle state. Packet and key operations are refused unless `established`.
pub const TunnelState = enum {
    /// Constructed but never keyed.
    new,
    /// Keyed and usable.
    established,
    /// Deliberately unusable: establishment failed part-way, or `deinit` ran.
    /// Key material has been wiped. Re-establishing is the only way out.
    unusable,
};

/// Everything `establishTunnel` needs, including the per-session material that
/// makes the derived keys unique.
///
/// `local_session_nonce` and `peer_session_nonce` must be freshly generated for
/// every session and exchanged with the peer, the same way a real handshake
/// exchanges nonces. They are public; they do not need to be secret, only
/// fresh. Use `generateSessionNonce`.
///
/// Without them the key schedule is a pure function of the two static keys, so
/// a second tunnel between the same peers — including a brand new `VpnTunnel`
/// object — reproduces the same keys with the counter back at zero. That is
/// AEAD nonce reuse, which leaks plaintext and forfeits integrity.
pub const TunnelSetup = struct {
    role: TunnelRole,
    local_private: [32]u8,
    peer_public: [32]u8,
    local_session_nonce: [session_nonce_length]u8,
    peer_session_nonce: [session_nonce_length]u8,
};

/// Generate one side's session nonce from OS entropy.
///
/// Propagates entropy failures rather than falling back to a weaker source.
pub fn generateSessionNonce() rand.RngError![session_nonce_length]u8 {
    var nonce: [session_nonce_length]u8 = undefined;
    try rand.fillChecked(&nonce);
    return nonce;
}

/// VPN tunnel state
pub const VpnTunnel = struct {
    config: TunnelConfig,
    state: TunnelState,
    send_key: [32]u8,
    recv_key: [32]u8,
    send_epoch: u32,
    recv_epoch: u32,
    send_counter: u64,
    recv_counter: u64,
    last_key_update: i64,
    /// Split so the two masking layers never cancel out. Both are derived from
    /// the shared secret, so peers agree; neither adds cryptographic strength.
    header_mask_key: [16]u8,
    traffic_mask_key: [16]u8,
    replay: ReplayWindow,

    pub fn init(config: TunnelConfig) VpnTunnel {
        return VpnTunnel{
            .config = config,
            .state = .new,
            .send_key = std.mem.zeroes([32]u8),
            .recv_key = std.mem.zeroes([32]u8),
            .send_epoch = 0,
            .recv_epoch = 0,
            .send_counter = 0,
            .recv_counter = 0,
            .last_key_update = util.getCurrentUnixTime() orelse 0,
            .header_mask_key = std.mem.zeroes([16]u8),
            .traffic_mask_key = std.mem.zeroes([16]u8),
            .replay = .{},
        };
    }

    /// Wipe key material and mark the tunnel unusable.
    pub fn deinit(self: *VpnTunnel) void {
        self.wipe();
        self.state = .unusable;
    }

    fn wipe(self: *VpnTunnel) void {
        crypto.secureZero(u8, &self.send_key);
        crypto.secureZero(u8, &self.recv_key);
        crypto.secureZero(u8, &self.header_mask_key);
        crypto.secureZero(u8, &self.traffic_mask_key);
        self.send_epoch = 0;
        self.recv_epoch = 0;
        self.send_counter = 0;
        self.recv_counter = 0;
        self.replay = .{};
    }

    /// Establish a new VPN tunnel using an X25519 key exchange.
    ///
    /// `setup.role` must be opposite on the two peers, and both must supply the
    /// same session nonce pair with local/peer swapped. Both sides derive the
    /// same keying material; the role selects which half is used for sending,
    /// so the initiator's send key is the responder's receive key and vice
    /// versa.
    ///
    /// On success the tunnel is fully reset: epoch 0, counters at zero, and an
    /// empty replay window. Clearing the replay window is only safe because the
    /// session nonces guarantee this session's keys differ from the last one's,
    /// so nothing from the previous session can authenticate here.
    ///
    /// On failure the tunnel is left `.unusable` with key material wiped, so a
    /// caller that ignores the error cannot go on to send under partial keys.
    pub fn establishTunnel(self: *VpnTunnel, setup: TunnelSetup) !void {
        errdefer self.deinit();

        // Catches the common misuse of passing the same buffer twice, and of
        // passing two all-zero "I'll fill these in later" nonces. It is a
        // misuse check, not a freshness proof: only the caller can guarantee
        // these have never been used with this static key pair before.
        if (std.mem.eql(u8, &setup.local_session_nonce, &setup.peer_session_nonce)) {
            return VpnCryptoError.SessionMaterialReused;
        }

        // X25519 rejects low-order points, so a degenerate peer key surfaces
        // here rather than silently producing an all-zero shared secret.
        var shared_secret = crypto.dh.X25519.scalarmult(setup.local_private, setup.peer_public) catch {
            return VpnCryptoError.TunnelEstablishmentFailed;
        };
        defer crypto.secureZero(u8, &shared_secret);

        const local_public = crypto.dh.X25519.recoverPublicKey(setup.local_private) catch {
            return VpnCryptoError.TunnelEstablishmentFailed;
        };

        // Order both the public keys and the session nonces by role rather than
        // by who is local, so the two peers feed an identical transcript into
        // the KDF.
        const initiator_public, const responder_public = switch (setup.role) {
            .initiator => .{ local_public, setup.peer_public },
            .responder => .{ setup.peer_public, local_public },
        };
        const initiator_nonce, const responder_nonce = switch (setup.role) {
            .initiator => .{ setup.local_session_nonce, setup.peer_session_nonce },
            .responder => .{ setup.peer_session_nonce, setup.local_session_nonce },
        };

        // Fresh per-session material goes in the extract salt, static identity
        // in the expand info. Both are bound; splitting them this way mirrors
        // the usual HKDF idiom of salting with the handshake nonces.
        const salt_label = "zcrypto-vpn-tunnel-v2";
        var salt: [salt_label.len + 2 * session_nonce_length]u8 = undefined;
        @memcpy(salt[0..salt_label.len], salt_label);
        @memcpy(salt[salt_label.len..][0..session_nonce_length], &initiator_nonce);
        @memcpy(salt[salt_label.len + session_nonce_length ..][0..session_nonce_length], &responder_nonce);

        const info_label = "vpn-tunnel-keys";
        var info: [info_label.len + 64]u8 = undefined;
        @memcpy(info[0..info_label.len], info_label);
        @memcpy(info[info_label.len..][0..32], &initiator_public);
        @memcpy(info[info_label.len + 32 ..][0..32], &responder_public);

        const prk = crypto.kdf.hkdf.HkdfSha256.extract(&salt, &shared_secret);

        // 32B initiator->responder key, 32B responder->initiator key, then two
        // 16B masking keys. The masking keys must come from the shared secret:
        // if each peer generated them randomly the two sides would unmask with
        // different keys and every packet would fail authentication.
        var okm: [96]u8 = undefined;
        defer crypto.secureZero(u8, &okm);
        crypto.kdf.hkdf.HkdfSha256.expand(&okm, &info, prk);

        const i2r = okm[0..32];
        const r2i = okm[32..64];
        switch (setup.role) {
            .initiator => {
                @memcpy(&self.send_key, i2r);
                @memcpy(&self.recv_key, r2i);
            },
            .responder => {
                @memcpy(&self.send_key, r2i);
                @memcpy(&self.recv_key, i2r);
            },
        }
        @memcpy(&self.header_mask_key, okm[64..80]);
        @memcpy(&self.traffic_mask_key, okm[80..96]);

        self.send_epoch = 0;
        self.recv_epoch = 0;
        self.send_counter = 0;
        self.recv_counter = 0;
        self.replay = .{};
        self.last_key_update = util.getCurrentUnixTime() orelse 0;
        self.state = .established;
    }

    /// Advisory: has this tunnel been sending under one key long enough that the
    /// caller should schedule an `initiateKeyUpdate`?
    ///
    /// Nothing in this module acts on this by itself. Deciding when to update is
    /// a policy question, and a key update costs the receiver its in-flight
    /// packets (see `decryptPacket`).
    pub fn keyUpdateDue(self: *const VpnTunnel) bool {
        if (self.state != .established) return false;
        if (self.send_counter >= key_update_packet_threshold) return true;
        const now = util.getCurrentUnixTime() orelse return false;
        const interval_s: i64 = @intCast(self.config.key_update_interval_ms / 1000);
        return now -| self.last_key_update >= interval_s;
    }

    /// Ratchet the send direction to the next key epoch.
    ///
    /// The new epoch travels in every subsequent packet header, so the peer
    /// adopts it on the first packet that authenticates under the ratcheted key.
    /// No separate signalling channel and no clock agreement is required; this
    /// is one-directional and needs no reply.
    ///
    /// The receive direction is untouched. Each direction has its own key and
    /// its own epoch, and each peer updates its own send direction when it
    /// wants to.
    pub fn initiateKeyUpdate(self: *VpnTunnel) !void {
        if (self.state != .established) return VpnCryptoError.TunnelNotEstablished;
        if (self.send_epoch == std.math.maxInt(u32)) return VpnCryptoError.KeyEpochExhausted;

        const next_epoch = self.send_epoch + 1;
        const next_key = ratchetKey(self.send_key, next_epoch);
        crypto.secureZero(u8, &self.send_key);
        self.send_key = next_key;
        self.send_epoch = next_epoch;

        // Safe to restart the counter: the key is new, so (key, nonce) pairs
        // cannot collide with the previous epoch's.
        self.send_counter = 0;
        self.last_key_update = util.getCurrentUnixTime() orelse self.last_key_update;
    }

    /// Seal a packet as `epoch || sequence || ciphertext || tag`.
    ///
    /// Returns the number of bytes written, which is `plaintext.len +
    /// packet_overhead`.
    pub fn encryptPacket(self: *VpnTunnel, plaintext: []const u8, output: []u8) !usize {
        if (self.state != .established) return VpnCryptoError.TunnelNotEstablished;
        if (plaintext.len > max_plaintext_length) return VpnCryptoError.PacketTooLarge;

        // Cannot overflow: bounded by max_plaintext_length just above.
        const total = plaintext.len + packet_overhead;
        if (output.len < total) return VpnCryptoError.BufferTooSmall;

        // Reusing a nonce under the same key would be catastrophic, so refuse
        // to wrap rather than silently repeating one.
        if (self.send_counter == std.math.maxInt(u64)) return VpnCryptoError.SequenceExhausted;
        const seq = self.send_counter;

        const header = output[0..header_length];
        std.mem.writeInt(u32, header[0..epoch_length], self.send_epoch, .little);
        std.mem.writeInt(u64, header[epoch_length..][0..sequence_length], seq, .little);

        const body = output[header_length..][0..plaintext.len];
        const tag = output[header_length + plaintext.len ..][0..tag_length];

        // The header goes in as associated data. Editing it is already fatal
        // without this — the epoch selects the key and the sequence selects the
        // nonce, so a rewritten header decrypts under different inputs and the
        // tag fails. The AAD makes that binding explicit instead of emergent,
        // so it survives a future header field that is not a key/nonce input.
        switch (self.config.encryption_algorithm) {
            .ChaCha20Poly1305 => {
                const Aead = crypto.aead.chacha_poly.ChaCha20Poly1305;
                Aead.encrypt(body, tag, plaintext, header, nonceFrom(Aead.nonce_length, seq), self.send_key);
            },
            .XChaCha20Poly1305 => {
                const Aead = crypto.aead.chacha_poly.XChaCha20Poly1305;
                Aead.encrypt(body, tag, plaintext, header, nonceFrom(Aead.nonce_length, seq), self.send_key);
            },
            .AesGcm256 => {
                const Aead = crypto.aead.aes_gcm.Aes256Gcm;
                Aead.encrypt(body, tag, plaintext, header, nonceFrom(Aead.nonce_length, seq), self.send_key);
            },
        }

        // Masking covers only the sealed portion; the header must stay readable
        // for the peer to pick the key and derive the nonce.
        const sealed = output[header_length..total];
        if (self.config.enable_header_protection) self.protectHeader(sealed);
        if (self.config.enable_traffic_obfuscation) self.maskTraffic(sealed, seq);

        self.send_counter += 1;
        return total;
    }

    /// Open a packet sealed by the peer's `encryptPacket`.
    ///
    /// Returns the plaintext length written to `output`.
    ///
    /// Epoch policy, deliberately bounded: a packet is accepted at the current
    /// receive epoch, or at exactly one epoch ahead. One epoch ahead is how a
    /// peer's `initiateKeyUpdate` is adopted, and it is only committed once the
    /// packet authenticates. Anything older than the current epoch is dropped —
    /// so a key update discards whatever the peer still had in flight. Anything
    /// more than one epoch ahead is refused rather than silently ratcheting
    /// forward on an attacker's say-so.
    ///
    /// On any error the first `plaintext_len` bytes of `output` are zeroed, so
    /// a caller that ignores the return value cannot read unauthenticated
    /// plaintext out of the buffer.
    pub fn decryptPacket(self: *VpnTunnel, packet: []const u8, output: []u8) !usize {
        if (self.state != .established) return VpnCryptoError.TunnelNotEstablished;
        if (packet.len < packet_overhead) return VpnCryptoError.AuthenticationFailed;
        if (packet.len > max_packet_length) return VpnCryptoError.PacketTooLarge;

        const sealed_len = packet.len - header_length;
        const plaintext_len = sealed_len - tag_length;
        if (output.len < plaintext_len) return VpnCryptoError.BufferTooSmall;

        const header = packet[0..header_length];
        const epoch = std.mem.readInt(u32, header[0..epoch_length], .little);
        const seq = std.mem.readInt(u64, header[epoch_length..][0..sequence_length], .little);

        var key: [32]u8 = undefined;
        defer crypto.secureZero(u8, &key);

        const adopting_next = blk: {
            if (epoch == self.recv_epoch) {
                key = self.recv_key;
                break :blk false;
            }
            if (self.recv_epoch != std.math.maxInt(u32) and epoch == self.recv_epoch + 1) {
                key = ratchetKey(self.recv_key, epoch);
                break :blk true;
            }
            return VpnCryptoError.UnknownKeyEpoch;
        };

        // Reject replays before spending a decryption, but do not record the
        // sequence yet: an unauthenticated packet must not move the window. A
        // packet from the next epoch is checked against that epoch's fresh
        // window, which is empty, so there is nothing to check.
        if (!adopting_next and !self.replay.check(seq)) return VpnCryptoError.ReplayDetected;

        var working_buffer: [max_packet_length - header_length]u8 = undefined;
        @memcpy(working_buffer[0..sealed_len], packet[header_length..]);
        const work_slice = working_buffer[0..sealed_len];

        // Undo masking in the reverse of the order it was applied.
        if (self.config.enable_traffic_obfuscation) self.maskTraffic(work_slice, seq);
        if (self.config.enable_header_protection) self.protectHeader(work_slice);

        const tag = work_slice[plaintext_len..][0..tag_length].*;
        const body = work_slice[0..plaintext_len];
        const out = output[0..plaintext_len];
        errdefer crypto.secureZero(u8, out);

        switch (self.config.encryption_algorithm) {
            .ChaCha20Poly1305 => {
                const Aead = crypto.aead.chacha_poly.ChaCha20Poly1305;
                Aead.decrypt(out, body, tag, header, nonceFrom(Aead.nonce_length, seq), key) catch return VpnCryptoError.AuthenticationFailed;
            },
            .XChaCha20Poly1305 => {
                const Aead = crypto.aead.chacha_poly.XChaCha20Poly1305;
                Aead.decrypt(out, body, tag, header, nonceFrom(Aead.nonce_length, seq), key) catch return VpnCryptoError.AuthenticationFailed;
            },
            .AesGcm256 => {
                const Aead = crypto.aead.aes_gcm.Aes256Gcm;
                Aead.decrypt(out, body, tag, header, nonceFrom(Aead.nonce_length, seq), key) catch return VpnCryptoError.AuthenticationFailed;
            },
        }

        // Authenticated: only now is it safe to move receive state forward.
        if (adopting_next) {
            crypto.secureZero(u8, &self.recv_key);
            self.recv_key = key;
            self.recv_epoch = epoch;
            self.replay = .{};
            self.recv_counter = 0;
        }
        self.replay.commit(seq);
        self.recv_counter = @max(self.recv_counter, seq +| 1);
        return plaintext_len;
    }

    /// Obfuscate the leading packet bytes.
    ///
    /// This is a static-key XOR mask, not encryption. Confidentiality and
    /// integrity come solely from the AEAD applied before this step; the mask
    /// only makes the traffic less trivially fingerprintable and is
    /// recoverable by anyone who can guess plaintext header bytes. It is its
    /// own inverse.
    ///
    /// Callers guarantee `packet.len >= tag_length`, which every sealed packet
    /// satisfies by construction.
    fn protectHeader(self: *const VpnTunnel, packet: []u8) void {
        std.debug.assert(packet.len >= tag_length);
        for (packet[0..@min(self.header_mask_key.len, packet.len)], 0..) |*byte, i| {
            byte.* ^= self.header_mask_key[i];
        }
    }

    /// Mask the packet body to blunt traffic fingerprinting.
    ///
    /// As with `protectHeader`, this is a XOR mask over ciphertext and adds no
    /// cryptographic strength. It is its own inverse, and is keyed by the
    /// packet's sequence number rather than a local counter so that it stays
    /// correct under reordering. It uses a key distinct from `protectHeader`'s
    /// so the two layers cannot cancel each other out.
    fn maskTraffic(self: *const VpnTunnel, packet: []u8, seq: u64) void {
        for (packet, 0..) |*byte, i| {
            // The offset is computed in u64 rather than usize on purpose. `i` is
            // usize, so on a 32-bit target this mixed `i +% seq` did not even
            // compile, and had it been widened to usize instead it would wrap at
            // 32 bits there and at 64 bits elsewhere. That would give a 32-bit
            // peer a different mask than a 64-bit peer for the same sequence
            // number, so the two could not talk to each other.
            const offset = @as(u64, i) +% seq;
            byte.* ^= self.traffic_mask_key[@intCast(offset % self.traffic_mask_key.len)];
        }
    }
};

/// Multi-hop VPN encryption for mesh routing
pub const MeshVpn = struct {
    tunnels: std.ArrayList(VpnTunnel),
    allocator: Allocator,

    pub fn init(allocator: Allocator) MeshVpn {
        return MeshVpn{
            .tunnels = .empty,
            .allocator = allocator,
        };
    }

    /// Wipes every tunnel's key material before releasing the backing storage.
    pub fn deinit(self: *MeshVpn) void {
        for (self.tunnels.items) |*tunnel| tunnel.deinit();
        self.tunnels.deinit(self.allocator);
    }

    /// Add a tunnel to the mesh
    pub fn addTunnel(self: *MeshVpn, config: TunnelConfig) !void {
        const tunnel = VpnTunnel.init(config);
        try self.tunnels.append(self.allocator, tunnel);
    }

    fn findTunnel(self: *MeshVpn, tunnel_id: u64) ?*VpnTunnel {
        for (self.tunnels.items) |*t| {
            if (t.config.tunnel_id == tunnel_id) return t;
        }
        return null;
    }

    /// Wrap `plaintext` in one AEAD layer per hop, innermost hop last.
    ///
    /// The receiver peels the layers by calling `decryptPacket` on each hop's
    /// tunnel in `hop_ids` order; there is deliberately no `decryptMultiHop`,
    /// because in real onion routing each layer is stripped by a different
    /// node, not all at once by the sender.
    ///
    /// `output` must have room for `plaintext.len + hop_ids.len * packet_overhead`,
    /// and that total must fit `max_plaintext_length` at every intermediate
    /// layer, so the effective payload budget shrinks by `packet_overhead` per
    /// hop.
    pub fn encryptMultiHop(self: *MeshVpn, plaintext: []const u8, hop_ids: []const u64, output: []u8) !usize {
        if (hop_ids.len == 0) return VpnCryptoError.InvalidTunnelId;

        // Checked so a caller-supplied hop count cannot wrap the size contract.
        const layers = std.math.mul(usize, hop_ids.len, packet_overhead) catch
            return VpnCryptoError.PacketTooLarge;
        const required = std.math.add(usize, plaintext.len, layers) catch
            return VpnCryptoError.PacketTooLarge;
        if (required > max_packet_length) return VpnCryptoError.PacketTooLarge;
        if (output.len < required) return VpnCryptoError.BufferTooSmall;

        // encryptPacket cannot read and write the same buffer, so layers
        // alternate between `output` and scratch. Pick the starting buffer by
        // parity so the outermost layer lands in `output`.
        const scratch = try self.allocator.alloc(u8, required);
        defer {
            crypto.secureZero(u8, scratch);
            self.allocator.free(scratch);
        }

        var to_output = hop_ids.len % 2 == 1;
        var current: []const u8 = plaintext;

        // Encrypt in reverse order (onion routing).
        var i = hop_ids.len;
        while (i > 0) {
            i -= 1;
            const tunnel = self.findTunnel(hop_ids[i]) orelse return VpnCryptoError.InvalidTunnelId;

            const dest = if (to_output) output else scratch;
            const written = try tunnel.encryptPacket(current, dest);
            current = dest[0..written];
            to_output = !to_output;
        }

        std.debug.assert(current.ptr == output.ptr);
        return current.len;
    }
};

/// Bandwidth-efficient crypto for mobile VPN clients
pub const MobileCrypto = struct {
    pub fn optimizeForMobile(config: *TunnelConfig) void {
        // Use XChaCha20-Poly1305 for better ARM performance
        config.encryption_algorithm = .XChaCha20Poly1305;

        // Reduce key update frequency to save battery
        config.key_update_interval_ms = 600000; // 10 minutes

        // Enable traffic obfuscation for cellular networks
        config.enable_traffic_obfuscation = true;
    }

    /// Bytes added to every packet by `VpnTunnel.encryptPacket`.
    ///
    /// The same for every algorithm: nonces are derived from the transmitted
    /// sequence number rather than sent separately, so only the wire header and
    /// the AEAD tag are on the wire.
    pub fn estimateBandwidthOverhead(comptime algorithm: EncryptionAlgorithm, packet_size: usize) usize {
        _ = algorithm;
        _ = packet_size;
        return packet_overhead;
    }
};

// Tests
const testing = std.testing;

const test_initiator_nonce: [session_nonce_length]u8 = @splat(0xa1);
const test_responder_nonce: [session_nonce_length]u8 = @splat(0xb2);

const TestTunnelPair = struct { initiator: VpnTunnel, responder: VpnTunnel };

/// Build a connected initiator/responder pair over a real X25519 exchange.
fn testTunnelPair(algorithm: EncryptionAlgorithm) !TestTunnelPair {
    const seed_a: [32]u8 = @splat(0x11);
    const seed_b: [32]u8 = @splat(0x22);
    return testTunnelPairSeeded(algorithm, seed_a, seed_b, test_initiator_nonce, test_responder_nonce);
}

fn testTunnelPairSeeded(
    algorithm: EncryptionAlgorithm,
    seed_a: [32]u8,
    seed_b: [32]u8,
    initiator_nonce: [session_nonce_length]u8,
    responder_nonce: [session_nonce_length]u8,
) !TestTunnelPair {
    const a = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_a);
    const b = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_b);

    const config = TunnelConfig{ .tunnel_id = 1, .encryption_algorithm = algorithm };
    var initiator = VpnTunnel.init(config);
    var responder = VpnTunnel.init(config);

    try initiator.establishTunnel(.{
        .role = .initiator,
        .local_private = a.secret_key,
        .peer_public = b.public_key,
        .local_session_nonce = initiator_nonce,
        .peer_session_nonce = responder_nonce,
    });
    try responder.establishTunnel(.{
        .role = .responder,
        .local_private = b.secret_key,
        .peer_public = a.public_key,
        .local_session_nonce = responder_nonce,
        .peer_session_nonce = initiator_nonce,
    });

    return .{ .initiator = initiator, .responder = responder };
}

test "established tunnel derives opposite directional keys" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    // The initiator must send with the key the responder receives with.
    try testing.expectEqualSlices(u8, &pair.initiator.send_key, &pair.responder.recv_key);
    try testing.expectEqualSlices(u8, &pair.initiator.recv_key, &pair.responder.send_key);

    // The two directions must not share a key, or a reflected packet would
    // decrypt back at the sender.
    try testing.expect(!std.mem.eql(u8, &pair.initiator.send_key, &pair.initiator.recv_key));

    // Both peers must agree on the masking keys, and the two mask layers must
    // not share one, or they would cancel out on the bytes they overlap.
    try testing.expectEqualSlices(u8, &pair.initiator.header_mask_key, &pair.responder.header_mask_key);
    try testing.expectEqualSlices(u8, &pair.initiator.traffic_mask_key, &pair.responder.traffic_mask_key);
    try testing.expect(!std.mem.eql(u8, &pair.initiator.header_mask_key, &pair.initiator.traffic_mask_key));
    try testing.expect(!std.mem.allEqual(u8, &pair.initiator.header_mask_key, 0));
}

test "packets round-trip between peers in both directions" {
    for ([_]EncryptionAlgorithm{ .ChaCha20Poly1305, .AesGcm256, .XChaCha20Poly1305 }) |algorithm| {
        var pair = try testTunnelPair(algorithm);

        // Header protection and obfuscation are on by default, so this also
        // proves the masking layers agree across peers.
        const to_responder = "packet from initiator";
        var wire: [128]u8 = undefined;
        var plain: [128]u8 = undefined;

        var len = try pair.initiator.encryptPacket(to_responder, &wire);
        var got = try pair.responder.decryptPacket(wire[0..len], &plain);
        try testing.expectEqualSlices(u8, to_responder, plain[0..got]);

        const to_initiator = "and one back";
        len = try pair.responder.encryptPacket(to_initiator, &wire);
        got = try pair.initiator.decryptPacket(wire[0..len], &plain);
        try testing.expectEqualSlices(u8, to_initiator, plain[0..got]);
    }
}

test "multiple sequential packets stay in sync" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    for (0..8) |i| {
        var msg: [16]u8 = undefined;
        @memset(&msg, @intCast(i));
        const len = try pair.initiator.encryptPacket(&msg, &wire);
        const got = try pair.responder.decryptPacket(wire[0..len], &plain);
        try testing.expectEqualSlices(u8, &msg, plain[0..got]);
    }
    try testing.expectEqual(@as(u64, 8), pair.initiator.send_counter);
    try testing.expectEqual(@as(u64, 8), pair.responder.recv_counter);
}

test "xchacha20 uses an extended nonce rather than falling back" {
    // A 24-byte nonce is what distinguishes XChaCha20-Poly1305; if the
    // implementation silently fell back to ChaCha20-Poly1305 this would be 12.
    try testing.expectEqual(@as(usize, 24), EncryptionAlgorithm.XChaCha20Poly1305.nonceLength());
    try testing.expectEqual(@as(usize, 24), crypto.aead.chacha_poly.XChaCha20Poly1305.nonce_length);

    var pair = try testTunnelPair(.XChaCha20Poly1305);
    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const msg = "extended nonce payload";
    const len = try pair.initiator.encryptPacket(msg, &wire);
    const got = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectEqualSlices(u8, msg, plain[0..got]);
}

test "tampered packet is rejected" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const msg = "authentic payload";
    const len = try pair.initiator.encryptPacket(msg, &wire);

    wire[len - 1] ^= 0x01; // flip a tag bit
    try testing.expectError(VpnCryptoError.AuthenticationFailed, pair.responder.decryptPacket(wire[0..len], &plain));
}

test "mismatched roles cannot talk" {
    const seed_a: [32]u8 = @splat(0x33);
    const seed_b: [32]u8 = @splat(0x44);
    const a = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_a);
    const b = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_b);

    const config = TunnelConfig{ .tunnel_id = 7, .encryption_algorithm = .ChaCha20Poly1305 };
    var left = VpnTunnel.init(config);
    var right = VpnTunnel.init(config);

    // Both configured as initiator: send/recv keys line up the wrong way.
    try left.establishTunnel(.{
        .role = .initiator,
        .local_private = a.secret_key,
        .peer_public = b.public_key,
        .local_session_nonce = test_initiator_nonce,
        .peer_session_nonce = test_responder_nonce,
    });
    try right.establishTunnel(.{
        .role = .initiator,
        .local_private = b.secret_key,
        .peer_public = a.public_key,
        .local_session_nonce = test_responder_nonce,
        .peer_session_nonce = test_initiator_nonce,
    });

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const len = try left.encryptPacket("should not decrypt", &wire);
    try testing.expectError(VpnCryptoError.AuthenticationFailed, right.decryptPacket(wire[0..len], &plain));
}

test "low-order peer key is rejected and leaves the tunnel unusable" {
    var tunnel = VpnTunnel.init(.{ .tunnel_id = 1, .encryption_algorithm = .ChaCha20Poly1305 });
    const local_private: [32]u8 = @splat(0x01);
    try testing.expectError(VpnCryptoError.TunnelEstablishmentFailed, tunnel.establishTunnel(.{
        .role = .initiator,
        .local_private = local_private,
        .peer_public = std.mem.zeroes([32]u8),
        .local_session_nonce = test_initiator_nonce,
        .peer_session_nonce = test_responder_nonce,
    }));

    // Failed establishment must fail closed, not leave a zero-keyed tunnel that
    // still seals packets.
    try testing.expectEqual(TunnelState.unusable, tunnel.state);
    var wire: [128]u8 = undefined;
    try testing.expectError(VpnCryptoError.TunnelNotEstablished, tunnel.encryptPacket("nope", &wire));
}

// ---------------------------------------------------------------------------
// Lifecycle regressions
//
// Each of these fails if its specific guard is removed; the assertion, not a
// passing round trip, is the point.
// ---------------------------------------------------------------------------

test "a tunnel that was never established refuses to seal or open" {
    // Regression: `init` zeroes the keys, so without a state guard this sealed
    // real traffic under an all-zero key that any observer can reproduce.
    var tunnel = VpnTunnel.init(.{ .tunnel_id = 1, .encryption_algorithm = .ChaCha20Poly1305 });
    try testing.expectEqual(TunnelState.new, tunnel.state);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const minimal_packet: [packet_overhead]u8 = @splat(0);
    try testing.expectError(VpnCryptoError.TunnelNotEstablished, tunnel.encryptPacket("secret", &wire));
    try testing.expectError(VpnCryptoError.TunnelNotEstablished, tunnel.decryptPacket(&minimal_packet, &plain));
    try testing.expectError(VpnCryptoError.TunnelNotEstablished, tunnel.initiateKeyUpdate());
    try testing.expect(!tunnel.keyUpdateDue());
}

test "deinit wipes keys and closes the tunnel" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);
    pair.initiator.deinit();

    try testing.expectEqual(TunnelState.unusable, pair.initiator.state);
    try testing.expect(std.mem.allEqual(u8, &pair.initiator.send_key, 0));
    try testing.expect(std.mem.allEqual(u8, &pair.initiator.recv_key, 0));
    try testing.expect(std.mem.allEqual(u8, &pair.initiator.traffic_mask_key, 0));

    var wire: [128]u8 = undefined;
    try testing.expectError(VpnCryptoError.TunnelNotEstablished, pair.initiator.encryptPacket("after close", &wire));
}

test "a fresh object with the same static keys does not reproduce the key stream" {
    // Regression for cross-session nonce reuse. Before session nonces existed,
    // the key schedule was a pure function of the two static keys, so this
    // second tunnel produced a byte-identical packet for sequence 0.
    const seed_a: [32]u8 = @splat(0x11);
    const seed_b: [32]u8 = @splat(0x22);

    var first = try testTunnelPairSeeded(.ChaCha20Poly1305, seed_a, seed_b, @splat(0x01), @splat(0x02));
    var second = try testTunnelPairSeeded(.ChaCha20Poly1305, seed_a, seed_b, @splat(0x03), @splat(0x04));

    try testing.expect(!std.mem.eql(u8, &first.initiator.send_key, &second.initiator.send_key));

    const msg = "same plaintext, same counter";
    var wire_a: [128]u8 = undefined;
    var wire_b: [128]u8 = undefined;
    const len_a = try first.initiator.encryptPacket(msg, &wire_a);
    const len_b = try second.initiator.encryptPacket(msg, &wire_b);
    try testing.expectEqual(len_a, len_b);

    // Identical plaintext at identical sequence numbers must not produce
    // identical ciphertext across sessions.
    try testing.expect(!std.mem.eql(u8, wire_a[0..len_a], wire_b[0..len_b]));

    // And the sessions must not be interoperable.
    var plain: [128]u8 = undefined;
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        second.responder.decryptPacket(wire_a[0..len_a], &plain),
    );
}

test "re-establishing invalidates the previous session's traffic" {
    // Regression: re-establishment used to reset the counters and clear the
    // replay window while keeping the same keys, which made an old session's
    // captured packets replayable.
    const seed_a: [32]u8 = @splat(0x55);
    const seed_b: [32]u8 = @splat(0x66);
    const a = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_a);
    const b = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_b);

    var pair = try testTunnelPairSeeded(.ChaCha20Poly1305, seed_a, seed_b, @splat(0x0a), @splat(0x0b));

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const len = try pair.initiator.encryptPacket("old session traffic", &wire);

    // Second session between the same peers, fresh nonces.
    try pair.responder.establishTunnel(.{
        .role = .responder,
        .local_private = b.secret_key,
        .peer_public = a.public_key,
        .local_session_nonce = @splat(0x0d),
        .peer_session_nonce = @splat(0x0c),
    });
    try testing.expect(!pair.responder.replay.seeded);

    // The replay window is empty again, so only the key change can reject this.
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        pair.responder.decryptPacket(wire[0..len], &plain),
    );
}

test "establishment rejects a repeated session nonce" {
    var tunnel = VpnTunnel.init(.{ .tunnel_id = 1, .encryption_algorithm = .ChaCha20Poly1305 });
    const kp = try crypto.dh.X25519.KeyPair.generateDeterministic(@splat(0x77));
    const peer = try crypto.dh.X25519.KeyPair.generateDeterministic(@splat(0x78));

    // Both zeroed is the "I forgot to fill these in" case.
    try testing.expectError(VpnCryptoError.SessionMaterialReused, tunnel.establishTunnel(.{
        .role = .initiator,
        .local_private = kp.secret_key,
        .peer_public = peer.public_key,
        .local_session_nonce = @splat(0x00),
        .peer_session_nonce = @splat(0x00),
    }));
    try testing.expectEqual(TunnelState.unusable, tunnel.state);
}

test "replay is still rejected after an authentication failure" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const len = try pair.initiator.encryptPacket("deliver once", &wire);

    // A forgery at the same sequence number must not consume that sequence...
    var forged: [128]u8 = undefined;
    @memcpy(forged[0..len], wire[0..len]);
    forged[len - 1] ^= 0xff;
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        pair.responder.decryptPacket(forged[0..len], &plain),
    );

    // ...so the genuine packet still opens...
    const got = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectEqualSlices(u8, "deliver once", plain[0..got]);

    // ...and only then is it burned.
    try testing.expectError(
        VpnCryptoError.ReplayDetected,
        pair.responder.decryptPacket(wire[0..len], &plain),
    );
}

test "failed decryption zeroes the caller's output buffer" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    @memset(&plain, 0xcd);

    const msg = "authentic payload";
    const len = try pair.initiator.encryptPacket(msg, &wire);
    wire[len - 1] ^= 0x01;

    try testing.expectError(VpnCryptoError.AuthenticationFailed, pair.responder.decryptPacket(wire[0..len], &plain));
    try testing.expect(std.mem.allEqual(u8, plain[0..msg.len], 0));
}

// ---------------------------------------------------------------------------
// Size contract
// ---------------------------------------------------------------------------

test "seal and open agree on the maximum packet size" {
    // Regression: encryptPacket used to accept any plaintext the caller had
    // room for, while decryptPacket rejected anything over its fixed 4096-byte
    // working buffer. The two limits are now derived from each other.
    try testing.expectEqual(max_packet_length, max_plaintext_length + packet_overhead);

    for ([_]EncryptionAlgorithm{ .ChaCha20Poly1305, .AesGcm256, .XChaCha20Poly1305 }) |algorithm| {
        // Both optional masking layers, on and off independently: they change
        // the bytes the receive path has to unwind, so the size contract has to
        // hold for every combination.
        for ([_][2]bool{ .{ false, false }, .{ true, false }, .{ false, true }, .{ true, true } }) |masking| {
            const seed_a: [32]u8 = @splat(0x11);
            const seed_b: [32]u8 = @splat(0x22);
            var pair = try testTunnelPairSeeded(algorithm, seed_a, seed_b, @splat(0x31), @splat(0x32));
            for ([_]*VpnTunnel{ &pair.initiator, &pair.responder }) |tunnel| {
                tunnel.config.enable_header_protection = masking[0];
                tunnel.config.enable_traffic_obfuscation = masking[1];
            }

            var plaintext: [max_plaintext_length]u8 = undefined;
            @memset(&plaintext, 0x5a);
            var wire: [max_packet_length]u8 = undefined;
            var plain: [max_plaintext_length]u8 = undefined;

            // Exact maximum round-trips.
            const len = try pair.initiator.encryptPacket(&plaintext, &wire);
            try testing.expectEqual(max_packet_length, len);
            const got = try pair.responder.decryptPacket(wire[0..len], &plain);
            try testing.expectEqualSlices(u8, &plaintext, plain[0..got]);

            // One byte over is refused by the send path.
            var oversized: [max_plaintext_length + 1]u8 = undefined;
            @memset(&oversized, 0x5a);
            var big_wire: [max_packet_length + 64]u8 = undefined;
            try testing.expectError(
                VpnCryptoError.PacketTooLarge,
                pair.initiator.encryptPacket(&oversized, &big_wire),
            );

            // ...and by the receive path, so neither side can be talked into
            // handling a packet the other would reject.
            try testing.expectError(
                VpnCryptoError.PacketTooLarge,
                pair.responder.decryptPacket(big_wire[0 .. max_packet_length + 1], &plain),
            );

            // Empty payloads are legal and carry only the overhead.
            const empty_len = try pair.initiator.encryptPacket("", &wire);
            try testing.expectEqual(packet_overhead, empty_len);
            const empty_got = try pair.responder.decryptPacket(wire[0..empty_len], &plain);
            try testing.expectEqual(@as(usize, 0), empty_got);
        }
    }
}

test "the two masking layers do not cancel each other" {
    // Regression: both layers used to share one 16-byte key, and the traffic
    // mask indexed it by (i + seq) % 16. At seq 0 the two XORs lined up exactly
    // over the first 16 bytes and undid each other, leaving the raw AEAD output
    // on the wire while the config claimed two layers of obfuscation. A round
    // trip cannot catch this, because cancellation is symmetric.
    const seed_a: [32]u8 = @splat(0x11);
    const seed_b: [32]u8 = @splat(0x22);
    const nonce_i: [session_nonce_length]u8 = @splat(0x41);
    const nonce_r: [session_nonce_length]u8 = @splat(0x42);

    // Two identically seeded pairs produce identical AEAD output at seq 0, so
    // any difference on the wire is attributable to masking alone.
    var bare = try testTunnelPairSeeded(.ChaCha20Poly1305, seed_a, seed_b, nonce_i, nonce_r);
    bare.initiator.config.enable_header_protection = false;
    bare.initiator.config.enable_traffic_obfuscation = false;
    var masked = try testTunnelPairSeeded(.ChaCha20Poly1305, seed_a, seed_b, nonce_i, nonce_r);

    var bare_wire: [128]u8 = undefined;
    var masked_wire: [128]u8 = undefined;
    const message = "the first sixteen bytes must not survive masking";
    const bare_len = try bare.initiator.encryptPacket(message, &bare_wire);
    const masked_len = try masked.initiator.encryptPacket(message, &masked_wire);
    try testing.expectEqual(bare_len, masked_len);

    // Headers are deliberately left in the clear for the receiver.
    try testing.expectEqualSlices(
        u8,
        bare_wire[0..header_length],
        masked_wire[0..header_length],
    );

    // The masked region the old bug exposed: sealed bytes 0..16 at sequence 0.
    const region = header_length + 16;
    try testing.expect(!std.mem.eql(u8, bare_wire[header_length..region], masked_wire[header_length..region]));
}

test "insufficient buffers and truncated input are rejected" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    const msg = "size contract probe";
    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;

    // One byte short of the sealed size.
    try testing.expectError(
        VpnCryptoError.BufferTooSmall,
        pair.initiator.encryptPacket(msg, wire[0 .. msg.len + packet_overhead - 1]),
    );

    const len = try pair.initiator.encryptPacket(msg, &wire);

    // One byte short of the plaintext size on the receive side.
    try testing.expectError(
        VpnCryptoError.BufferTooSmall,
        pair.responder.decryptPacket(wire[0..len], plain[0 .. msg.len - 1]),
    );

    // Truncated wire input: shorter than the header plus tag is not a packet.
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        pair.responder.decryptPacket(wire[0 .. packet_overhead - 1], &plain),
    );
    // Truncated but still well-formed lengths must fail authentication.
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        pair.responder.decryptPacket(wire[0 .. len - 1], &plain),
    );
}

// ---------------------------------------------------------------------------
// Key updates
// ---------------------------------------------------------------------------

test "key update is adopted by the peer from the wire" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);
    const before = pair.initiator.send_key;

    try pair.initiator.initiateKeyUpdate();
    try testing.expectEqual(@as(u32, 1), pair.initiator.send_epoch);
    try testing.expectEqual(@as(u64, 0), pair.initiator.send_counter);
    try testing.expect(!std.mem.eql(u8, &before, &pair.initiator.send_key));

    // The responder has not been told anything out of band; it learns the new
    // epoch from the packet header alone.
    try testing.expectEqual(@as(u32, 0), pair.responder.recv_epoch);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const msg = "first packet of the new epoch";
    const len = try pair.initiator.encryptPacket(msg, &wire);
    const got = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectEqualSlices(u8, msg, plain[0..got]);

    try testing.expectEqual(@as(u32, 1), pair.responder.recv_epoch);
    try testing.expectEqualSlices(u8, &pair.initiator.send_key, &pair.responder.recv_key);

    // The other direction is untouched: updates are one-directional.
    try testing.expectEqual(@as(u32, 0), pair.responder.send_epoch);
    const back_len = try pair.responder.encryptPacket("still epoch 0", &wire);
    const back_got = try pair.initiator.decryptPacket(wire[0..back_len], &plain);
    try testing.expectEqualSlices(u8, "still epoch 0", plain[0..back_got]);
}

test "a forged key update does not advance the receiver" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const len = try pair.initiator.encryptPacket("epoch 0 packet", &wire);

    // Rewrite the cleartext epoch to claim an update the sender never made.
    std.mem.writeInt(u32, wire[0..epoch_length], 1, .little);
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        pair.responder.decryptPacket(wire[0..len], &plain),
    );

    // The receiver must not have ratcheted on an unauthenticated header.
    try testing.expectEqual(@as(u32, 0), pair.responder.recv_epoch);

    // ...and the genuine packet still opens.
    std.mem.writeInt(u32, wire[0..epoch_length], 0, .little);
    const got = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectEqualSlices(u8, "epoch 0 packet", plain[0..got]);
}

test "duplicate key updates and skipped epochs are refused" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;

    // Two updates in a row on the sender skips an epoch from the peer's view.
    try pair.initiator.initiateKeyUpdate();
    try pair.initiator.initiateKeyUpdate();
    try testing.expectEqual(@as(u32, 2), pair.initiator.send_epoch);

    const len = try pair.initiator.encryptPacket("epoch 2", &wire);
    try testing.expectError(
        VpnCryptoError.UnknownKeyEpoch,
        pair.responder.decryptPacket(wire[0..len], &plain),
    );
    try testing.expectEqual(@as(u32, 0), pair.responder.recv_epoch);
}

test "packets from a superseded epoch are dropped" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var in_flight: [128]u8 = undefined;
    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;

    // A packet the peer sent just before the sender updated its key.
    const stale_len = try pair.initiator.encryptPacket("still in flight", &in_flight);

    try pair.initiator.initiateKeyUpdate();
    const len = try pair.initiator.encryptPacket("new epoch", &wire);
    _ = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectEqual(@as(u32, 1), pair.responder.recv_epoch);

    // Documented, bounded policy: the update costs the in-flight packet.
    try testing.expectError(
        VpnCryptoError.UnknownKeyEpoch,
        pair.responder.decryptPacket(in_flight[0..stale_len], &plain),
    );
}

test "a key update restarts the replay window without reopening old sequences" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;

    const seq0_len = try pair.initiator.encryptPacket("epoch 0 seq 0", &wire);
    var seq0: [128]u8 = undefined;
    @memcpy(seq0[0..seq0_len], wire[0..seq0_len]);
    _ = try pair.responder.decryptPacket(wire[0..seq0_len], &plain);

    // Sent but never delivered, so it is not in any replay window.
    var seq1: [128]u8 = undefined;
    const seq1_len = try pair.initiator.encryptPacket("epoch 0 seq 1", &seq1);

    try pair.initiator.initiateKeyUpdate();
    const len = try pair.initiator.encryptPacket("epoch 1 seq 0", &wire);
    const got = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectEqualSlices(u8, "epoch 1 seq 0", plain[0..got]);

    // The window restarted, yet the old epoch-0 packets stay dead. Their epoch
    // is behind the receiver...
    try testing.expectError(
        VpnCryptoError.UnknownKeyEpoch,
        pair.responder.decryptPacket(seq0[0..seq0_len], &plain),
    );

    // ...and rewriting the epoch does not resurrect them. Sequence 0 was already
    // consumed in the new epoch, so the window catches it first.
    std.mem.writeInt(u32, seq0[0..epoch_length], 1, .little);
    try testing.expectError(
        VpnCryptoError.ReplayDetected,
        pair.responder.decryptPacket(seq0[0..seq0_len], &plain),
    );

    // Sequence 1 is untouched in the new epoch, so the window lets it through
    // and the AEAD has to reject it: the epoch is authenticated, not just read.
    std.mem.writeInt(u32, seq1[0..epoch_length], 1, .little);
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        pair.responder.decryptPacket(seq1[0..seq1_len], &plain),
    );
}

test "send counter exhaustion is refused rather than wrapped" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);
    pair.initiator.send_counter = std.math.maxInt(u64);

    var wire: [128]u8 = undefined;
    try testing.expectError(
        VpnCryptoError.SequenceExhausted,
        pair.initiator.encryptPacket("would reuse a nonce", &wire),
    );

    // A key update is the documented way out, and it restores capacity.
    try pair.initiator.initiateKeyUpdate();
    _ = try pair.initiator.encryptPacket("fresh epoch", &wire);
}

test "epoch exhaustion is refused rather than wrapped" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);
    pair.initiator.send_epoch = std.math.maxInt(u32);
    try testing.expectError(VpnCryptoError.KeyEpochExhausted, pair.initiator.initiateKeyUpdate());
}

test "key updates are advisory, never automatic" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);
    try testing.expect(!pair.initiator.keyUpdateDue());

    pair.initiator.last_key_update = 0;
    try testing.expect(pair.initiator.keyUpdateDue());

    // Sending does not silently rotate behind the caller's back.
    var wire: [128]u8 = undefined;
    _ = try pair.initiator.encryptPacket("overdue but unchanged", &wire);
    try testing.expectEqual(@as(u32, 0), pair.initiator.send_epoch);
}

// ---------------------------------------------------------------------------
// Loss, reordering, and replay
// ---------------------------------------------------------------------------

test "a dropped packet does not desynchronize the tunnel" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var dropped: [128]u8 = undefined;
    _ = try pair.initiator.encryptPacket("this one is lost", &dropped);

    // The receiver never sees the packet above; the next one must still open.
    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const msg = "this one arrives";
    const len = try pair.initiator.encryptPacket(msg, &wire);
    const got = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectEqualSlices(u8, msg, plain[0..got]);
}

test "out-of-order packets are accepted within the replay window" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var first: [128]u8 = undefined;
    var second: [128]u8 = undefined;
    const first_len = try pair.initiator.encryptPacket("sent first", &first);
    const second_len = try pair.initiator.encryptPacket("sent second", &second);

    // Deliver them reversed, as a lossy network would.
    var plain: [128]u8 = undefined;
    var got = try pair.responder.decryptPacket(second[0..second_len], &plain);
    try testing.expectEqualSlices(u8, "sent second", plain[0..got]);

    got = try pair.responder.decryptPacket(first[0..first_len], &plain);
    try testing.expectEqualSlices(u8, "sent first", plain[0..got]);
}

test "a replayed packet is rejected" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const len = try pair.initiator.encryptPacket("deliver once", &wire);

    _ = try pair.responder.decryptPacket(wire[0..len], &plain);
    try testing.expectError(
        VpnCryptoError.ReplayDetected,
        pair.responder.decryptPacket(wire[0..len], &plain),
    );
}

test "a packet older than the replay window is rejected" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var stale: [128]u8 = undefined;
    const stale_len = try pair.initiator.encryptPacket("far too old", &stale);

    // Advance the receiver past the window with later packets.
    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    for (0..replay_window_size + 1) |_| {
        const len = try pair.initiator.encryptPacket("filler", &wire);
        _ = try pair.responder.decryptPacket(wire[0..len], &plain);
    }

    try testing.expectError(
        VpnCryptoError.ReplayDetected,
        pair.responder.decryptPacket(stale[0..stale_len], &plain),
    );
}

test "tampering with the sequence number is detected" {
    var pair = try testTunnelPair(.ChaCha20Poly1305);

    var wire: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const len = try pair.initiator.encryptPacket("bind the header", &wire);

    // The sequence number rides in the clear, so an attacker can edit it. It is
    // bound twice over: it derives the nonce and it is passed as associated
    // data, so either binding alone catches this.
    wire[epoch_length] ^= 0x40;
    try testing.expectError(
        VpnCryptoError.AuthenticationFailed,
        pair.responder.decryptPacket(wire[0..len], &plain),
    );
}

// ---------------------------------------------------------------------------
// Mesh and mobile helpers
// ---------------------------------------------------------------------------

test "multi-hop layers peel back to the original plaintext" {
    const seeds = [_]u8{ 0x31, 0x32, 0x33 };
    var mesh = MeshVpn.init(testing.allocator);
    defer mesh.deinit();

    // One tunnel per hop on the sender, plus the matching peer tunnel that the
    // hop itself would hold.
    var peers: [seeds.len]VpnTunnel = undefined;
    defer for (&peers) |*peer| peer.deinit();

    for (seeds, 0..) |seed, i| {
        const local = try crypto.dh.X25519.KeyPair.generateDeterministic(@splat(seed));
        const remote = try crypto.dh.X25519.KeyPair.generateDeterministic(@splat(seed +% 0x80));
        const config = TunnelConfig{ .tunnel_id = i + 1, .encryption_algorithm = .ChaCha20Poly1305 };
        const local_nonce: [session_nonce_length]u8 = @splat(seed);
        const remote_nonce: [session_nonce_length]u8 = @splat(seed +% 0x40);

        try mesh.addTunnel(config);
        try mesh.tunnels.items[i].establishTunnel(.{
            .role = .initiator,
            .local_private = local.secret_key,
            .peer_public = remote.public_key,
            .local_session_nonce = local_nonce,
            .peer_session_nonce = remote_nonce,
        });

        peers[i] = VpnTunnel.init(config);
        try peers[i].establishTunnel(.{
            .role = .responder,
            .local_private = remote.secret_key,
            .peer_public = local.public_key,
            .local_session_nonce = remote_nonce,
            .peer_session_nonce = local_nonce,
        });
    }

    const hop_ids = [_]u64{ 1, 2, 3 };
    const message = "onion payload";
    var wire: [256]u8 = undefined;
    const wire_len = try mesh.encryptMultiHop(message, &hop_ids, &wire);
    try testing.expectEqual(message.len + hop_ids.len * packet_overhead, wire_len);

    // Each hop strips its own layer, in hop order.
    var buffers: [2][256]u8 = undefined;
    var current: []const u8 = wire[0..wire_len];
    for (&peers, 0..) |*peer, i| {
        const dest = &buffers[i % 2];
        const len = try peer.decryptPacket(current, dest);
        current = dest[0..len];
    }

    try testing.expectEqualSlices(u8, message, current);
}

test "multi-hop refuses to exceed the packet size contract" {
    var mesh = MeshVpn.init(testing.allocator);
    defer mesh.deinit();

    var output: [max_packet_length]u8 = undefined;
    const hop_ids = [_]u64{1};

    // Layering must not be able to build a packet the receive path would reject.
    var plaintext: [max_plaintext_length + 1]u8 = undefined;
    @memset(&plaintext, 0x5a);
    try testing.expectError(
        VpnCryptoError.PacketTooLarge,
        mesh.encryptMultiHop(&plaintext, &hop_ids, &output),
    );

    // Per-hop overhead accumulates, so a large hop count is refused on the same
    // size contract rather than silently building an oversized packet.
    const absurd_hops: [8]u64 = @splat(1);
    try testing.expectError(
        VpnCryptoError.PacketTooLarge,
        mesh.encryptMultiHop(&plaintext, &absurd_hops, &output),
    );
}

test "mobile crypto optimization" {
    var config = TunnelConfig{ .tunnel_id = 1, .encryption_algorithm = .ChaCha20Poly1305 };

    MobileCrypto.optimizeForMobile(&config);

    try testing.expect(config.encryption_algorithm == .XChaCha20Poly1305);
    try testing.expect(config.key_update_interval_ms == 600000);
    try testing.expect(config.enable_traffic_obfuscation);
}

test "bandwidth overhead estimate matches the real wire cost" {
    // Assert against what encryptPacket actually emits, not a hardcoded number,
    // so the estimate cannot silently drift away from the wire format again.
    inline for (.{ .ChaCha20Poly1305, .XChaCha20Poly1305, .AesGcm256 }) |algorithm| {
        var peers = try testTunnelPair(algorithm);

        const plaintext = "overhead probe";
        var packet: [128]u8 = undefined;
        const packet_len = try peers.initiator.encryptPacket(plaintext, &packet);

        const estimate = MobileCrypto.estimateBandwidthOverhead(algorithm, plaintext.len);
        try testing.expectEqual(packet_len - plaintext.len, estimate);
    }
}

test "session nonces come from OS entropy and differ" {
    const first = try generateSessionNonce();
    const second = try generateSessionNonce();
    try testing.expect(!std.mem.eql(u8, &first, &second));
    try testing.expect(!std.mem.allEqual(u8, &first, 0));
}
