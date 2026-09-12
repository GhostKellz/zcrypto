//! Forces one real public API body per enabled feature to compile, link, and run.
//!
//! The feature matrix used to be checked by building the library under each flag
//! combination, but a build only proves the sources parse. Zig will not codegen a
//! function nobody reaches, so a namespace can be re-exported, imported, and
//! `_ = module`-referenced while its bodies are never analysed past declaration.
//! Every check below therefore calls through to a real implementation and asserts
//! something about the result.
//!
//! Each block is gated on the comptime `build_config` boolean, so a disabled
//! feature's branch is never analysed and this file compiles under every
//! configuration in the gate.

const std = @import("std");
const builtin = @import("builtin");
const zcrypto = @import("zcrypto");

const testing = std.testing;

test "core surface is present in every configuration" {
    const allocator = testing.allocator;

    const digest = zcrypto.hash.sha256("feature surface");
    try testing.expect(!std.mem.allEqual(u8, &digest, 0));

    var key: [32]u8 = undefined;
    zcrypto.rand.fill(&key);
    defer zcrypto.util.secureZero(&key);

    const sealed = try zcrypto.sym.encryptChaCha20(allocator, "feature surface", &key);
    defer allocator.free(sealed);
    const opened = try zcrypto.sym.decryptChaCha20(allocator, sealed, &key);
    defer allocator.free(opened);
    try testing.expectEqualStrings("feature surface", opened);

    var alice = try zcrypto.kex.X25519.generateKeypair();
    defer alice.zeroize();
    var bob = try zcrypto.kex.X25519.generateKeypair();
    defer bob.zeroize();
    const shared_a = try zcrypto.kex.X25519.computeSharedSecret(alice.private_key, bob.public_key);
    const shared_b = try zcrypto.kex.X25519.computeSharedSecret(bob.private_key, alice.public_key);
    try testing.expectEqualSlices(u8, &shared_a, &shared_b);
}

test "tls surface derives initial secrets when enabled" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;

    const cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client = zcrypto.tls.deriveInitialSecrets(&cid, true);
    const server = zcrypto.tls.deriveInitialSecrets(&cid, false);

    // Both directions must derive from the same connection ID without
    // collapsing to the same secret.
    try testing.expect(!std.mem.eql(
        u8,
        &client.client_initial_secret,
        &server.server_initial_secret,
    ));
}

test "hardware surface reports a detection result when enabled" {
    if (comptime !zcrypto.build_config.hardware_accel_enabled) return error.SkipZigTest;

    const features = zcrypto.hardware.HardwareAcceleration.detect();

    // The specific bits depend on the host, so assert only what is portable:
    // detection ran and produced a coherent answer for this architecture.
    switch (builtin.target.cpu.arch) {
        .x86_64, .x86 => try testing.expect(!features.arm_crypto),
        .aarch64 => try testing.expect(!features.aes_ni and !features.avx2),
        else => {},
    }
}

test "vpn surface completes an authenticated round trip when enabled" {
    if (comptime !zcrypto.build_config.vpn_enabled) return error.SkipZigTest;

    const vpn = zcrypto.vpn_crypto.vpn_crypto;

    var initiator_secret: [32]u8 = undefined;
    var responder_secret: [32]u8 = undefined;
    zcrypto.rand.fill(&initiator_secret);
    zcrypto.rand.fill(&responder_secret);
    const initiator_public = try std.crypto.dh.X25519.recoverPublicKey(initiator_secret);
    const responder_public = try std.crypto.dh.X25519.recoverPublicKey(responder_secret);

    var initiator_nonce: [vpn.session_nonce_length]u8 = undefined;
    var responder_nonce: [vpn.session_nonce_length]u8 = undefined;
    zcrypto.rand.fill(&initiator_nonce);
    zcrypto.rand.fill(&responder_nonce);

    var initiator = vpn.VpnTunnel.init(.{ .tunnel_id = 1, .encryption_algorithm = .ChaCha20Poly1305 });
    defer initiator.deinit();
    var responder = vpn.VpnTunnel.init(.{ .tunnel_id = 1, .encryption_algorithm = .ChaCha20Poly1305 });
    defer responder.deinit();

    try initiator.establishTunnel(.{
        .role = .initiator,
        .local_private = initiator_secret,
        .peer_public = responder_public,
        .local_session_nonce = initiator_nonce,
        .peer_session_nonce = responder_nonce,
    });
    try responder.establishTunnel(.{
        .role = .responder,
        .local_private = responder_secret,
        .peer_public = initiator_public,
        .local_session_nonce = responder_nonce,
        .peer_session_nonce = initiator_nonce,
    });

    const plaintext = "vpn feature surface";
    var wire: [vpn.max_packet_length]u8 = undefined;
    const wire_len = try initiator.encryptPacket(plaintext, &wire);

    var recovered: [vpn.max_plaintext_length]u8 = undefined;
    const recovered_len = try responder.decryptPacket(wire[0..wire_len], &recovered);
    try testing.expectEqualStrings(plaintext, recovered[0..recovered_len]);

    // The same packet a second time must not be accepted.
    try testing.expectError(
        vpn.VpnCryptoError.ReplayDetected,
        responder.decryptPacket(wire[0..wire_len], &recovered),
    );
}

test "wasm surface hashes through emulated linear memory when enabled" {
    if (comptime !zcrypto.build_config.wasm_enabled) return error.SkipZigTest;

    // The flattened path, which is what the documentation points at. The nested
    // `zcrypto.wasm_crypto.wasm_crypto.*` spelling is kept working for callers
    // written against it, and is asserted to be the same declaration below
    // rather than left to be assumed.
    const wasm = zcrypto.wasm_crypto;
    try testing.expect(wasm.WasmCrypto == zcrypto.wasm_crypto.wasm_crypto.WasmCrypto);

    var linear: [256]u8 = undefined;
    @memset(&linear, 0);
    const memory = wasm.WasmMemory.init(&linear, linear.len);

    var ctx = wasm.WasmCrypto.init(testing.allocator, 1_000_000, linear.len);
    const input = "wasm feature surface";
    try memory.write(0, input);
    try ctx.sha256(memory, 0, @intCast(input.len), 64);

    const produced = try memory.read(64, 32);
    try testing.expectEqualSlices(u8, &zcrypto.hash.sha256(input), produced);
}

test "post-quantum surface round trips KEM and signatures when enabled" {
    if (comptime !zcrypto.build_config.post_quantum_enabled) return error.SkipZigTest;

    const kem = zcrypto.post_quantum.ML_KEM_768;
    const kem_keys = try kem.generateKeypair();
    const encapsulated = try kem.encapsulate(kem_keys.public_key);
    const decapsulated = try kem.decapsulate(kem_keys.private_key, encapsulated.ciphertext);
    try testing.expectEqualSlices(u8, &encapsulated.shared_secret, &decapsulated);

    const dsa = zcrypto.post_quantum.ML_DSA_65;
    const sig_keys = try dsa.generateKeypair();
    const message = "post-quantum feature surface";
    const signature = try dsa.sign(sig_keys.private_key, message);
    try testing.expect(try dsa.verify(sig_keys.public_key, message, signature));

    var tampered = signature;
    tampered[0] ^= 0x01;
    try testing.expect(!(dsa.verify(sig_keys.public_key, message, tampered) catch false));
}

test "async surface is codegenned when enabled" {
    if (comptime !zcrypto.build_config.async_enabled) return error.SkipZigTest;

    // Unlike the other features this one cannot be *called* here: every entry
    // point needs a live zsync `Io`, and standing a runtime up inside a surface
    // check would be testing zsync rather than zcrypto. Taking the addresses
    // still forces the bodies through semantic analysis and codegen, which is
    // what this file is for; the behavioural async tests live with the module.
    _ = &zcrypto.async_crypto.AsyncCrypto.init;
    _ = &zcrypto.async_crypto.AsyncCrypto.encryptAsync;
    _ = &zcrypto.async_crypto.AsyncCrypto.decryptAsync;
    _ = &zcrypto.async_crypto.AsyncCrypto.hashAsync;
}

test "experimental surfaces are reachable only behind their opt-in" {
    // These are experimental families. The point here is the gate wiring, not
    // the cryptography: a family must be reachable when its flag is on and its
    // namespace must be absent otherwise.
    if (comptime zcrypto.build_config.blockchain_enabled) {
        var tree = zcrypto.blockchain_crypto.blockchain_crypto.MerkleTree.init(testing.allocator);
        defer tree.deinit();
        try tree.addLeaf("left");
        try tree.addLeaf("right");
        try tree.buildTree();
        try testing.expect(tree.getRoot() != null);
    }

    if (comptime zcrypto.build_config.zkp_enabled) {
        var generators = try zcrypto.zkp.zkp.Bulletproofs.Generators.init(testing.allocator, 8);
        defer generators.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 8), generators.g.len);
    }

    if (comptime zcrypto.build_config.enterprise_enabled) {
        const ctx = zcrypto.formal.formal.VerificationContext.init(
            .constant_time,
            "featureSurface",
            "none",
        );
        try testing.expect(!ctx.verified);
    }

    // Every experimental family above requires the experimental opt-in. If any
    // of them is on without it the build should never have got this far.
    if (comptime zcrypto.build_config.blockchain_enabled or
        zcrypto.build_config.zkp_enabled or
        zcrypto.build_config.enterprise_enabled or
        zcrypto.build_config.post_quantum_enabled)
    {
        try testing.expect(zcrypto.build_config.experimental_crypto_enabled);
    }
}
