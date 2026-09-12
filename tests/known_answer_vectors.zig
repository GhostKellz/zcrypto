//! Known-answer tests against **published** vectors, run through `zcrypto`'s
//! own public API.
//!
//! Why this file exists separately from `tests/hardware_parity.zig`: that file
//! can only compare a wrapper against the primitive it wraps, and says so. Both
//! sides of that comparison are the same `std.crypto` code in the same build,
//! so it cannot detect a build in which that code is wrong -- only one in which
//! this crate's wrapper is. The expected bytes below come from outside this
//! repository and outside Zig, so they can.
//!
//! Sources, and how each was checked before being written down:
//!
//! - AES-GCM: McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)",
//!   submission to the NIST Modes of Operation process, Appendix B. Test cases
//!   1, 2, 4 (AES-128) and 13, 16 (AES-256).
//! - ChaCha20-Poly1305: RFC 8439, section 2.8.2.
//! - SHA-256: FIPS 180-4 worked examples ("abc" and the two-block message).
//! - HKDF-SHA256: RFC 5869, test case 1.
//! - TLS 1.3 key schedule: RFC 8448, section 3, "Simple 1-RTT Handshake".
//!
//! Every value was transcribed from the published document and then recomputed
//! with an implementation independent of Zig's standard library (OpenSSL, via
//! py-cryptography and hashlib) before landing here. That second step is not
//! ceremony: the GCM vectors were extracted from a PDF whose table layout
//! interleaves adjacent test cases, which is exactly the kind of source a
//! transcription error hides in.
//!
//! The AES-128 cases 1 and 2 and the AES-256 case 13 were already asserted in
//! `src/sym.zig`; they are all-zero key/IV/plaintext cases that never exercise
//! GHASH with associated data or a plaintext that is not a whole number of
//! blocks. Cases 4 and 16 add both, which is where a defective carry-less
//! multiply or a mishandled partial tail block shows up.
//!
//! What makes this file worth running more than once: `std.crypto` selects its
//! AES, ChaCha20 and SHA-256 implementations at comptime from the build target,
//! so a generic-CPU build and a host-feature build execute *different* code for
//! these same calls. Running this suite under each is the evidence that both
//! implementations agree with the published answers. `expect_aes_hardware`
//! makes that pair honest: without it, two stages could quietly compile the
//! same way and prove half of what they claim.

const std = @import("std");
const builtin = @import("builtin");
const zcrypto = @import("zcrypto");
const kat_options = @import("kat_options");

const testing = std.testing;

fn hex(comptime N: usize, comptime s: []const u8) [N]u8 {
    // One backwards branch per byte decoded, and the RFC 8448 ClientHello is
    // 512 of them.
    @setEvalBranchQuota(8 * N + 1000);
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "build target selects the AES backend the caller asked for" {
    // Structural check, not a printed banner: the gate runs this suite once per
    // CPU target and states which backend that target must produce. A stage
    // that silently compiled for the wrong target fails here instead of
    // reporting a pass for a build it did not exercise.
    //
    // Deliberately not `std.debug.print`: writing to stderr from a test body
    // makes the build runner report the run command as failed even when every
    // test passes (see `tests/hardware_parity.zig`). One instance of that
    // false alarm in the tree is one too many already.
    if (kat_options.expect_aes_hardware) |want| {
        try testing.expectEqual(want, std.crypto.core.aes.has_hardware_support);
    }
}

test "AES-128-GCM matches GCM spec test cases 1, 2 and 4" {
    const allocator = testing.allocator;

    // Test case 1: empty plaintext, empty AAD. Tag is GHASH of nothing.
    const zero_key = hex(16, "00000000000000000000000000000000");
    const zero_iv = hex(12, "000000000000000000000000");

    const tc1 = try zcrypto.sym.encryptAes128Gcm(allocator, zero_key, zero_iv, "", "");
    defer tc1.deinit();
    try testing.expectEqual(@as(usize, 0), tc1.data.len);
    try testing.expectEqualSlices(u8, &hex(16, "58e2fccefa7e3061367f1d57a4e7455a"), &tc1.tag);

    // Test case 2: exactly one block of plaintext, still no AAD.
    const tc2_pt = hex(16, "00000000000000000000000000000000");
    const tc2 = try zcrypto.sym.encryptAes128Gcm(allocator, zero_key, zero_iv, &tc2_pt, "");
    defer tc2.deinit();
    try testing.expectEqualSlices(u8, &hex(16, "0388dace60b6a392f328c2b971b2fe78"), tc2.data);
    try testing.expectEqualSlices(u8, &hex(16, "ab6e47d42cec13bdf53a67b21257bddf"), &tc2.tag);

    // Test case 4: 20 bytes of AAD and 60 bytes of plaintext. 60 is not a
    // multiple of 16, so this is the case that exercises the partial trailing
    // block and the AAD length encoding in the GHASH length block.
    const tc4_key = hex(16, "feffe9928665731c6d6a8f9467308308");
    const tc4_iv = hex(12, "cafebabefacedbaddecaf888");
    const tc4_pt = hex(60, "d9313225f88406e5a55909c5aff5269a" ++
        "86a7a9531534f7da2e4c303d8a318a72" ++
        "1c3c0c95956809532fcf0e2449a6b525" ++
        "b16aedf5aa0de657ba637b39");
    const tc4_aad = hex(20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");

    const tc4 = try zcrypto.sym.encryptAes128Gcm(allocator, tc4_key, tc4_iv, &tc4_pt, &tc4_aad);
    defer tc4.deinit();
    try testing.expectEqualSlices(u8, &hex(60, "42831ec2217774244b7221b784d0d49c" ++
        "e3aa212f2c02a4e035c17e2329aca12e" ++
        "21d514b25466931c7d8f6a5aac84aa05" ++
        "1ba30b396a0aac973d58e091"), tc4.data);
    try testing.expectEqualSlices(u8, &hex(16, "5bc94fbc3221a5db94fae95ae7121a47"), &tc4.tag);
}

test "AES-256-GCM matches GCM spec test cases 13 and 16" {
    const allocator = testing.allocator;

    const zero_key = hex(32, "00000000000000000000000000000000" ++
        "00000000000000000000000000000000");
    const zero_iv = hex(12, "000000000000000000000000");

    const tc13 = try zcrypto.sym.encryptAes256Gcm(allocator, zero_key, zero_iv, "", "");
    defer tc13.deinit();
    try testing.expectEqual(@as(usize, 0), tc13.data.len);
    try testing.expectEqualSlices(u8, &hex(16, "530f8afbc74536b9a963b4f1c4cb738b"), &tc13.tag);

    const tc16 = try zcrypto.sym.encryptAes256Gcm(
        allocator,
        tc16_key,
        tc16_iv,
        &tc16_plaintext,
        &tc16_aad,
    );
    defer tc16.deinit();
    try testing.expectEqualSlices(u8, &tc16_ciphertext, tc16.data);
    try testing.expectEqualSlices(u8, &tc16_tag, &tc16.tag);
}

// Test case 16 is reused by the decrypt and wrapper tests below, so it is
// declared once rather than transcribed three times -- a vector copied by hand
// per call site is a vector that eventually disagrees with itself.
const tc16_key = hex(32, "feffe9928665731c6d6a8f9467308308" ++
    "feffe9928665731c6d6a8f9467308308");
const tc16_iv = hex(12, "cafebabefacedbaddecaf888");
const tc16_plaintext = hex(60, "d9313225f88406e5a55909c5aff5269a" ++
    "86a7a9531534f7da2e4c303d8a318a72" ++
    "1c3c0c95956809532fcf0e2449a6b525" ++
    "b16aedf5aa0de657ba637b39");
const tc16_aad = hex(20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
const tc16_ciphertext = hex(60, "522dc1f099567d07f47f37a32a84427d" ++
    "643a8cdcbfe5c0c97598a2bd2555d1aa" ++
    "8cb08e48590dbb3da7b08b1056828838" ++
    "c5f61e6393ba7a0abcc9f662");
const tc16_tag = hex(16, "76fc6ece0f4e1768cddf8853bb2d551b");

test "published AES-256-GCM ciphertext decrypts, and a flipped bit does not" {
    // The encrypt tests prove this build can reproduce the published bytes.
    // This proves it can *consume* them, which is the direction that matters
    // for interoperating with the implementations that produced them. A library
    // that encrypts correctly but rejects valid foreign ciphertext is still
    // broken, and no encrypt-side vector would show it.
    const allocator = testing.allocator;

    const recovered = try zcrypto.sym.decryptAes256Gcm(
        allocator,
        tc16_key,
        tc16_iv,
        &tc16_ciphertext,
        tc16_tag,
        &tc16_aad,
    );
    defer allocator.free(recovered);
    try testing.expectEqualSlices(u8, &tc16_plaintext, recovered);

    var tampered = tc16_ciphertext;
    tampered[0] ^= 0x01;
    try testing.expectError(
        zcrypto.sym.SymError.DecryptionFailed,
        zcrypto.sym.decryptAes256Gcm(allocator, tc16_key, tc16_iv, &tampered, tc16_tag, &tc16_aad),
    );
}

test "ChaCha20-Poly1305 matches RFC 8439 section 2.8.2" {
    const allocator = testing.allocator;

    const key = hex(32, "808182838485868788898a8b8c8d8e8f" ++
        "909192939495969798999a9b9c9d9e9f");
    const nonce = hex(12, "070000004041424344454647");
    const aad = hex(12, "50515253c0c1c2c3c4c5c6c7");
    const plaintext = "Ladies and Gentlemen of the class of '99: " ++
        "If I could offer you only one tip for the future, sunscreen would be it.";

    const result = try zcrypto.sym.encryptChaCha20Poly1305(allocator, key, nonce, plaintext, &aad);
    defer result.deinit();

    try testing.expectEqualSlices(u8, &hex(114, "d31a8d34648e60db7b86afbc53ef7ec2" ++
        "a4aded51296e08fea9e2b5a736ee62d6" ++
        "3dbea45e8ca9671282fafb69da92728b" ++
        "1a71de0a9e060b2905d6a5b67ecd3b36" ++
        "92ddbd7f2d778b8c9803aee328091b58" ++
        "fab324e4fad675945585808b4831d7bc" ++
        "3ff4def08e4b7a9de576d26586cec64b" ++
        "6116"), result.data);
    try testing.expectEqualSlices(u8, &hex(16, "1ae10b594f09e26a7e902ecbd0600691"), &result.tag);
}

test "SHA-256 matches the FIPS 180-4 worked examples" {
    // One-block and two-block messages. The two-block case is included because
    // a compression function that is correct for a single block can still be
    // wrong in how it chains state between them.
    try testing.expectEqualSlices(
        u8,
        &hex(32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        &zcrypto.hash.sha256("abc"),
    );
    try testing.expectEqualSlices(
        u8,
        &hex(32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        &zcrypto.hash.sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    );
}

test "HKDF-SHA256 matches RFC 5869 test case 1" {
    const allocator = testing.allocator;

    const ikm = hex(22, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hex(13, "000102030405060708090a0b0c");
    const info = hex(10, "f0f1f2f3f4f5f6f7f8f9");

    const okm = try zcrypto.kdf.hkdfSha256(allocator, &ikm, &salt, &info, 42);
    defer allocator.free(okm);

    try testing.expectEqualSlices(u8, &hex(42, "3cb25f25faacd57a90434f64d0362f2a" ++
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" ++
        "34007208d5b887185865"), okm);
}

test "hardware wrappers match the published vectors, not just the primitive" {
    // `tests/hardware_parity.zig` states plainly that it compares the wrapper
    // against the same primitive the wrapper calls, and that there is no second
    // backend to compare against. This closes the other half: the wrapper's
    // output is checked against bytes that came from outside this toolchain, so
    // key and nonce copying, buffer slicing and argument order are pinned to a
    // published answer rather than to a neighbouring call.
    if (!zcrypto.build_config.hardware_accel_enabled) return error.SkipZigTest;

    var ct: [tc16_ciphertext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try zcrypto.HardwareCrypto.aesGcmEncryptHw(
        &tc16_key,
        &tc16_iv,
        &tc16_plaintext,
        &tc16_aad,
        &ct,
        &tag,
    );
    try testing.expectEqualSlices(u8, &tc16_ciphertext, &ct);
    try testing.expectEqualSlices(u8, &tc16_tag, &tag);
}

// RFC 8448, "Example Handshake Traces for TLS 1.3", Section 3, "Simple 1-RTT
// Handshake". Every value below is transcribed from that trace.
//
// This is the only vector source in the tree that can judge the key schedule.
// Both endpoints in this repository run the same derivation code, so a
// client/server round trip agrees with itself no matter what it computes;
// RFC 8448 was produced by an unrelated implementation and states the expected
// bytes at every step, including the four distinct transcript hashes the
// schedule consumes. That last part is what makes the boundary testable: a
// derivation performed at the wrong point in the handshake reads a real
// transcript hash, just not the one RFC 8446 Section 7.1 names for it, and no
// amount of self-consistency checking notices.
const rfc8448 = struct {
    // Transcript hashes, in handshake order. The labels are the RFC 8446
    // Section 7.1 message ranges, not positions in the trace.
    const empty_hash = hex(32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const hash_ch_sh = hex(32, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    const hash_ch_server_fin = hex(32, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const hash_ch_client_fin = hex(32, "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d");

    const ecdhe = hex(32, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");

    const early_secret = hex(32, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    const handshake_secret = hex(32, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    const master_secret = hex(32, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");

    const c_hs_traffic = hex(32, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    const s_hs_traffic = hex(32, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    const c_ap_traffic = hex(32, "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    const s_ap_traffic = hex(32, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
    const exp_master = hex(32, "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50");
    const res_master = hex(32, "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c");

    // The per-ticket PSK: HKDF-Expand-Label(res_master, "resumption", nonce, 32)
    // with the trace's two-octet nonce. RFC 8446 Section 4.6.1.
    const ticket_nonce = hex(2, "0000");
    const resumption_psk = hex(32, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
};

/// One Derive-Secret call: which secret, which label, which transcript
/// boundary, and the answer the trace gives. Named fields rather than a tuple
/// because "which of these two 32-byte values is the transcript" is exactly the
/// confusion these tests exist to catch.
const DeriveCase = struct {
    secret: []const u8,
    label: []const u8,
    transcript: *const [32]u8,
    expect: *const [32]u8,
};

fn rfc8448Schedule(allocator: std.mem.Allocator) !zcrypto.tls.KeySchedule {
    var ks = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
    errdefer ks.deinit();
    try ks.deriveEarlySecret(null);
    try ks.deriveHandshakeSecret(&rfc8448.ecdhe);
    try ks.deriveMasterSecret();
    return ks;
}

test "the extract steps match the RFC 8448 trace" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;
    var ks = try rfc8448Schedule(allocator);
    defer ks.deinit();

    // Early Secret = HKDF-Extract(0, 0). Both arguments are all-zero here, so
    // this is the one step a wrong salt convention could still pass by
    // coincidence -- it is checked because the two after it chain off it.
    try testing.expectEqualSlices(u8, &rfc8448.early_secret, ks.early_secret);

    // These two consume Derive-Secret(secret, "derived", "") -- the literal
    // empty message list, hashed. They are the callers `deriveSecret` exists
    // for, and they would break if hashing were removed from it wholesale.
    try testing.expectEqualSlices(u8, &rfc8448.handshake_secret, ks.handshake_secret);
    try testing.expectEqualSlices(u8, &rfc8448.master_secret, ks.master_secret);
}

test "every Derive-Secret output matches the RFC 8448 trace at its own transcript boundary" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;
    var ks = try rfc8448Schedule(allocator);
    defer ks.deinit();

    const cases = [_]DeriveCase{
        .{ .secret = ks.handshake_secret, .label = "c hs traffic", .transcript = &rfc8448.hash_ch_sh, .expect = &rfc8448.c_hs_traffic },
        .{ .secret = ks.handshake_secret, .label = "s hs traffic", .transcript = &rfc8448.hash_ch_sh, .expect = &rfc8448.s_hs_traffic },
        .{ .secret = ks.master_secret, .label = "c ap traffic", .transcript = &rfc8448.hash_ch_server_fin, .expect = &rfc8448.c_ap_traffic },
        .{ .secret = ks.master_secret, .label = "s ap traffic", .transcript = &rfc8448.hash_ch_server_fin, .expect = &rfc8448.s_ap_traffic },
        .{ .secret = ks.master_secret, .label = "exp master", .transcript = &rfc8448.hash_ch_server_fin, .expect = &rfc8448.exp_master },
        .{ .secret = ks.master_secret, .label = "res master", .transcript = &rfc8448.hash_ch_client_fin, .expect = &rfc8448.res_master },
    };

    for (cases) |case| {
        const got = try ks.deriveSecretFromTranscriptHash(case.secret, case.label, case.transcript);
        defer allocator.free(got);
        try testing.expectEqualSlices(u8, case.expect, got);
    }
}

test "Derive-Secret rejects a transcript hash that is not one" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;
    var ks = try rfc8448Schedule(allocator);
    defer ks.deinit();

    // The failure this guards is passing raw handshake messages where a digest
    // belongs. Anything that is not exactly Hash.length is refused rather than
    // expanded into a secret that looks fine and interoperates with nothing.
    for ([_][]const u8{ "", "ClientHello...ServerHello", rfc8448.hash_ch_sh[0..31] }) |not_a_hash| {
        try testing.expectError(
            error.InvalidTranscriptHash,
            ks.deriveSecretFromTranscriptHash(ks.master_secret, "c ap traffic", not_a_hash),
        );
    }
}

test "hashing a transcript hash a second time does not produce the RFC 8448 secret" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;
    var ks = try rfc8448Schedule(allocator);
    defer ks.deinit();

    // `deriveSecret` hashes what it is given. Handing it a value that is already
    // Transcript-Hash(Messages) computes Hash(Transcript-Hash(Messages)), which
    // is a well-formed 32-byte input and expands to a well-formed secret --
    // simply not the one in the trace, nor the one any peer derives.
    //
    // This is pinned rather than merely fixed because the two calls differ by
    // one identifier at the call site and the wrong one stays green against
    // every test that compares this implementation to itself.
    const double_hashed = try ks.deriveSecret(ks.master_secret, "c ap traffic", &rfc8448.hash_ch_server_fin);
    defer allocator.free(double_hashed);
    try testing.expect(!std.mem.eql(u8, &rfc8448.c_ap_traffic, double_hashed));

    // And the correct call is right there, on the same inputs.
    const once = try ks.deriveSecretFromTranscriptHash(ks.master_secret, "c ap traffic", &rfc8448.hash_ch_server_fin);
    defer allocator.free(once);
    try testing.expectEqualSlices(u8, &rfc8448.c_ap_traffic, once);
}

test "a Derive-Secret taken at the wrong transcript boundary does not match" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;
    var ks = try rfc8448Schedule(allocator);
    defer ks.deinit();

    // RFC 8446 Section 7.1 fixes a different message range for each of these:
    // ClientHello..ServerHello, ClientHello..server Finished, and
    // ClientHello..client Finished. Deriving all of them from whichever
    // transcript happens to be current is the mistake this pins, and it is
    // invisible to a same-implementation round trip because both ends make it.
    const wrong = [_]DeriveCase{
        .{ .secret = ks.handshake_secret, .label = "c hs traffic", .transcript = &rfc8448.hash_ch_server_fin, .expect = &rfc8448.c_hs_traffic },
        .{ .secret = ks.master_secret, .label = "c ap traffic", .transcript = &rfc8448.hash_ch_client_fin, .expect = &rfc8448.c_ap_traffic },
        .{ .secret = ks.master_secret, .label = "s ap traffic", .transcript = &rfc8448.hash_ch_client_fin, .expect = &rfc8448.s_ap_traffic },
        .{ .secret = ks.master_secret, .label = "res master", .transcript = &rfc8448.hash_ch_server_fin, .expect = &rfc8448.res_master },
    };

    for (wrong) |case| {
        const got = try ks.deriveSecretFromTranscriptHash(case.secret, case.label, case.transcript);
        defer allocator.free(got);
        try testing.expect(!std.mem.eql(u8, case.expect, got));
    }
}

test "the per-ticket resumption PSK matches the RFC 8448 trace" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;

    // RFC 8446 Section 4.6.1:
    //   PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
    //                           ticket_nonce, Hash.length)
    // This is the derivation `generateSessionTicket` performs. Until now it was
    // asserted only against itself.
    const psk = try zcrypto.kdf.hkdfExpandLabel(
        allocator,
        &rfc8448.res_master,
        "resumption",
        &rfc8448.ticket_nonce,
        32,
    );
    defer allocator.free(psk);

    try testing.expectEqualSlices(u8, &rfc8448.resumption_psk, psk);
}

// RFC 8448, Section 4, "Resumed 0-RTT Handshake". Only the PSK binder chain is
// taken from here; the 0-RTT data path is out of scope. The binder is not, and
// this is the only published trace that states its intermediate values rather
// than just the final MAC.
//
// The chain starts at `rfc8448.resumption_psk` above, which Section 3 produced
// and this repository's `generateSessionTicket` derivation is already pinned
// against. That the two sections join is the point: these vectors judge the
// binder over the ticket PSK this library actually mints, not over a PSK
// invented for the test.
const rfc8448_resumed = struct {
    /// The ClientHello handshake message, four-byte header included, exactly as
    /// the trace puts it on the wire -- binders and all.
    ///
    /// Kept whole rather than stored pre-truncated so that the truncation rule
    /// is something the test computes and then checks. A pre-truncated constant
    /// would assert the MAC and take the interesting half on faith.
    const client_hello = hex(512, "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");

    /// The value of the two-byte `binders` length prefix: one 32-byte binder
    /// plus its own one-byte length.
    const binders_len = 33;

    /// Early Secret = HKDF-Extract(0, resumption_psk). Differs from
    /// `rfc8448.early_secret` above only in that the IKM is the PSK rather than
    /// zeros, which is the whole of what resumption changes here.
    const early_secret = hex(32, "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");

    /// Transcript-Hash of the truncated ClientHello.
    const binder_hash = hex(32, "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");

    /// Derive-Secret(Early Secret, "res binder", ""). The trace calls this the
    /// PRK, since it is what the "finished" expansion is keyed on.
    const binder_key = hex(32, "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256");

    /// HKDF-Expand-Label(binder_key, "finished", "", 32).
    const finished_key = hex(32, "5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa");

    /// The binder itself, which is also the last 32 bytes of `client_hello`.
    const binder = hex(32, "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");
};

fn rfc8448ResumedSchedule(allocator: std.mem.Allocator) !zcrypto.tls.KeySchedule {
    var ks = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
    errdefer ks.deinit();
    try ks.deriveEarlySecret(&rfc8448.resumption_psk);
    return ks;
}

test "the PSK binder chain matches the RFC 8448 trace" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;
    var ks = try rfc8448ResumedSchedule(allocator);
    defer ks.deinit();

    try testing.expectEqualSlices(u8, &rfc8448_resumed.early_secret, ks.early_secret);

    const binder_key = try ks.resumptionBinderKey();
    defer allocator.free(binder_key);
    try testing.expectEqualSlices(u8, &rfc8448_resumed.binder_key, binder_key);

    // The truncation rule, computed rather than assumed: drop the binders list
    // and its length prefix, and the digest of what remains is the trace's.
    const prefix = try zcrypto.tls.clientHelloBinderPrefix(
        &rfc8448_resumed.client_hello,
        rfc8448_resumed.binders_len,
    );
    try testing.expectEqual(@as(usize, 477), prefix.len);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(prefix, &digest, .{});
    try testing.expectEqualSlices(u8, &rfc8448_resumed.binder_hash, &digest);

    const binder = try zcrypto.tls.verifyData(allocator, .sha256, binder_key, &digest);
    defer allocator.free(binder);
    try testing.expectEqualSlices(u8, &rfc8448_resumed.binder, binder);

    // And it is the value the trace actually put on the wire: the tail of the
    // very message it was computed over. A binder that matched the RFC's
    // intermediate printout but not the bytes in the ClientHello would mean the
    // truncation length above was wrong in a way the digest check absorbed.
    const on_the_wire = rfc8448_resumed.client_hello[rfc8448_resumed.client_hello.len - 32 ..];
    try testing.expectEqualSlices(u8, on_the_wire, binder);
}

test "the binder transcript helper reproduces the RFC 8448 digest from a ClientHello body" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    // What the endpoints call. It is handed the body, because that is what a
    // server has after `readHandshakeMessage` strips the header and what a
    // client has before `writeHandshakeMessage` adds one -- and it has to put
    // the header back, still carrying the *untruncated* length, to arrive at the
    // digest below. Checking it against the trace here means the handshake path
    // is anchored to RFC 8448 rather than to this implementation's own opinion.
    const body = rfc8448_resumed.client_hello[4..];
    const digest = try zcrypto.tls.clientHelloBinderTranscript(body, rfc8448_resumed.binders_len);
    try testing.expectEqualSlices(u8, &rfc8448_resumed.binder_hash, &digest);
}

test "the binder transcript declares the untruncated ClientHello length" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    // The header states how long the message is, not how much of it is being
    // hashed. Re-deriving the length from the truncated bytes is the plausible
    // slip, and it is invisible between two endpoints that both make it, so it
    // is worth pinning separately from the digest check above.
    const body = rfc8448_resumed.client_hello[4..];
    const truncated = try zcrypto.tls.clientHelloBinderPrefix(body, rfc8448_resumed.binders_len);

    var wrong = std.crypto.hash.sha2.Sha256.init(.{});
    var header: [4]u8 = .{ 1, 0, 0, 0 };
    std.mem.writeInt(u24, header[1..4], @intCast(truncated.len), .big);
    wrong.update(&header);
    wrong.update(truncated);

    var wrong_digest: [32]u8 = undefined;
    wrong.final(&wrong_digest);
    try testing.expect(!std.mem.eql(u8, &rfc8448_resumed.binder_hash, &wrong_digest));
}

test "a PSK binder over the untruncated ClientHello does not match" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;
    var ks = try rfc8448ResumedSchedule(allocator);
    defer ks.deinit();

    const binder_key = try ks.resumptionBinderKey();
    defer allocator.free(binder_key);

    // Computing the binder over the whole message is the natural mistake: the
    // transcript is otherwise always the complete message, and the binder is
    // the one place RFC 8446 stops short. It is also self-consistent -- a
    // client and server that both made it would interoperate with each other
    // and with nothing else -- so only a published vector catches it.
    var whole: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&rfc8448_resumed.client_hello, &whole, .{});

    const wrong = try zcrypto.tls.verifyData(allocator, .sha256, binder_key, &whole);
    defer allocator.free(wrong);
    try testing.expect(!std.mem.eql(u8, &rfc8448_resumed.binder, wrong));
}

test "a PSK binder keyed on a zero-PSK early secret does not match" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;

    // `deriveEarlySecret(null)` is what a full handshake calls, and it succeeds
    // whether or not a PSK was meant to be in play. A resumption path that
    // forgot to pass the ticket PSK would therefore still produce a binder --
    // a well-formed one, over the right transcript, that no peer can verify.
    var ks = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
    defer ks.deinit();
    try ks.deriveEarlySecret(null);
    try testing.expectEqualSlices(u8, &rfc8448.early_secret, ks.early_secret);

    const binder_key = try ks.resumptionBinderKey();
    defer allocator.free(binder_key);
    try testing.expect(!std.mem.eql(u8, &rfc8448_resumed.binder_key, binder_key));

    const wrong = try zcrypto.tls.verifyData(allocator, .sha256, binder_key, &rfc8448_resumed.binder_hash);
    defer allocator.free(wrong);
    try testing.expect(!std.mem.eql(u8, &rfc8448_resumed.binder, wrong));
}

test "the binder prefix refuses a binders length the ClientHello cannot hold" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    // The length comes off the wire, so it is an attacker's to choose. Unchecked,
    // `len - (2 + binders_len)` wraps and yields a slice running off the end of
    // the message.
    for ([_]usize{
        rfc8448_resumed.client_hello.len,
        rfc8448_resumed.client_hello.len - 1,
        std.math.maxInt(usize) - 2,
    }) |too_long| {
        try testing.expectError(
            error.MalformedClientHello,
            zcrypto.tls.clientHelloBinderPrefix(&rfc8448_resumed.client_hello, too_long),
        );
    }

    // The largest length that does fit leaves an empty prefix, not an error:
    // the boundary is at `len - 2`, and it is checked from both sides so that
    // the guard cannot be off by one without this failing.
    const exact = try zcrypto.tls.clientHelloBinderPrefix(
        &rfc8448_resumed.client_hello,
        rfc8448_resumed.client_hello.len - 2,
    );
    try testing.expectEqual(@as(usize, 0), exact.len);
}

test "verifyData rejects a transcript hash that is not one" {
    if (comptime !zcrypto.build_config.tls_enabled) return error.SkipZigTest;
    const allocator = testing.allocator;

    // Same guard as `deriveSecretFromTranscriptHash`, for the same reason: the
    // binder is a MAC over a digest, and a caller that hands it raw message
    // bytes must not get a plausible-looking MAC back.
    for ([_][]const u8{ "", "ClientHello", rfc8448_resumed.binder_hash[0..31] }) |not_a_hash| {
        try testing.expectError(
            error.InvalidTranscriptHash,
            zcrypto.tls.verifyData(allocator, .sha256, &rfc8448_resumed.binder_key, not_a_hash),
        );
    }
}
