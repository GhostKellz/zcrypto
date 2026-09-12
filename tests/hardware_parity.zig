//! Consistency test: the `HardwareCrypto` wrappers against the `std.crypto`
//! primitives they wrap.
//!
//! What this file proves, stated exactly: that calling a wrapper produces the
//! same bytes as calling the underlying primitive directly, that the wrapper's
//! output verifies under the primitive's decrypt, and that the wrapper's length
//! contract is enforced by returned errors in every optimization mode.
//!
//! What it does not prove, and never did: equivalence of an accelerated backend
//! against a software one. There is no second backend to compare against.
//! `HardwareCrypto` and the reference calls below resolve to the same
//! `std.crypto` primitive in the same target module, so an equality check
//! between them is a statement about this crate's wrapper code -- buffer
//! slicing, key and nonce copying, argument order, length handling -- and about
//! nothing else. That is worth testing, and the injected-defect check confirms
//! these assertions do fail when the wrapper is wrong, but it is a narrower
//! claim than the "accelerated vs portable" framing this file used to carry.
//!
//! The header previously described a branch on `HardwareAcceleration.detect()`
//! choosing between backends. That branch existed but was decorative: both arms
//! called the same code. It has been removed; see the comment in
//! `src/hardware.zig` for why, including the two cases where its conditions
//! disagreed with the stdlib's actual dispatch.
//!
//! The detected feature set is the one thing here that varies by build, so it
//! is worth having in a run's log -- but it is not printed from this file, and
//! must not be. A test root runs under the build runner's `--listen=-` test
//! protocol, which captures the child's stderr; any output at all makes the
//! runner print the step's argv under `failed command:` and mark it `w` in the
//! summary, on a run where every test passed. That cost time twice before it
//! was traced, and it is a cry-wolf hazard in exactly the logs this evidence is
//! meant to be read from. `.stdio = .inherit` would suppress it by abandoning
//! the protocol, which also discards the pass/fail counts -- a worse trade.
//!
//! The record lives in `examples/advanced_features.zig` instead: a plain `run`
//! step passes stderr through untouched, and the release gate captures it in
//! the `smoke-runs` stage. It is build metadata either way, not a runtime
//! capability check -- `detect()` reads `builtin.cpu.features`, fixed at
//! compile time, so a result gathered on one machine does not describe another.

const std = @import("std");
const builtin = @import("builtin");
const zcrypto = @import("zcrypto");

const testing = std.testing;

const HardwareCrypto = zcrypto.HardwareCrypto;
const Detect = zcrypto.hardware.hardware.HardwareAcceleration;

test "detected feature set agrees with the target it was built for" {
    const features = Detect.detect();

    switch (builtin.target.cpu.arch) {
        .x86_64, .x86 => try testing.expect(!features.arm_crypto),
        .aarch64 => try testing.expect(!features.aes_ni and !features.avx2),
        else => {},
    }
}

test "AES-128-GCM wrapper matches the primitive it wraps" {
    const key: [16]u8 = @splat(0x2b);
    const nonce: [12]u8 = @splat(0x07);
    const plaintext = "parity vector for AES-128-GCM";
    const aad = "associated data";

    var hw_ct: [plaintext.len]u8 = undefined;
    var hw_tag: [16]u8 = undefined;
    try HardwareCrypto.aesGcmEncryptHw(&key, &nonce, plaintext, aad, &hw_ct, &hw_tag);

    var ref_ct: [plaintext.len]u8 = undefined;
    var ref_tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&ref_ct, &ref_tag, plaintext, aad, nonce, key);

    try testing.expectEqualSlices(u8, &ref_ct, &hw_ct);
    try testing.expectEqualSlices(u8, &ref_tag, &hw_tag);

    // Byte equality alone would still pass if the wrapper and the reference
    // both produced a tag no verifier accepts. Round-tripping through decrypt
    // pins the output as usable, not merely reproducible.
    var recovered: [plaintext.len]u8 = undefined;
    try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(&recovered, &hw_ct, hw_tag, aad, nonce, key);
    try testing.expectEqualSlices(u8, plaintext, &recovered);
}

test "AES-256-GCM wrapper matches the primitive it wraps" {
    const key: [32]u8 = @splat(0x5c);
    const nonce: [12]u8 = @splat(0x11);
    const plaintext = "parity vector for AES-256-GCM";
    const aad = "";

    var hw_ct: [plaintext.len]u8 = undefined;
    var hw_tag: [16]u8 = undefined;
    try HardwareCrypto.aesGcmEncryptHw(&key, &nonce, plaintext, aad, &hw_ct, &hw_tag);

    var ref_ct: [plaintext.len]u8 = undefined;
    var ref_tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(&ref_ct, &ref_tag, plaintext, aad, nonce, key);

    try testing.expectEqualSlices(u8, &ref_ct, &hw_ct);
    try testing.expectEqualSlices(u8, &ref_tag, &hw_tag);
}

test "ChaCha20-Poly1305 wrapper matches the primitive it wraps" {
    const key: [32]u8 = @splat(0x91);
    const nonce: [12]u8 = @splat(0x3d);
    const plaintext = "parity vector for ChaCha20-Poly1305";
    const aad = "aad bytes";

    var hw_ct: [plaintext.len]u8 = undefined;
    var hw_tag: [16]u8 = undefined;
    try HardwareCrypto.chacha20Poly1305EncryptHw(&key, &nonce, plaintext, aad, &hw_ct, &hw_tag);

    var ref_ct: [plaintext.len]u8 = undefined;
    var ref_tag: [16]u8 = undefined;
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(&ref_ct, &ref_tag, plaintext, aad, nonce, key);

    try testing.expectEqualSlices(u8, &ref_ct, &hw_ct);
    try testing.expectEqualSlices(u8, &ref_tag, &hw_tag);
}

test "SHA-256 wrapper matches the primitive it wraps" {
    const data = "parity vector for SHA-256";

    var hw_hash: [32]u8 = undefined;
    try HardwareCrypto.sha256HashHw(data, &hw_hash);

    var ref_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &ref_hash, .{});

    try testing.expectEqualSlices(u8, &ref_hash, &hw_hash);
}

test "authentication fails on tampered ciphertext, tag, and aad" {
    // `HardwareCrypto` is encrypt-only, so tampering has to be detected by
    // `std.crypto`'s verifier. That is the point: a wrapper that mangled the
    // tag or the AAD binding would pass every equality check above while
    // silently breaking authentication for the caller.
    const key: [32]u8 = @splat(0x44);
    const nonce: [12]u8 = @splat(0x99);
    const plaintext = "authenticate me";
    const aad = "bound context";

    var ct: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try HardwareCrypto.chacha20Poly1305EncryptHw(&key, &nonce, plaintext, aad, &ct, &tag);

    var out: [plaintext.len]u8 = undefined;
    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    var bad_ct = ct;
    bad_ct[0] ^= 0x01;
    try testing.expectError(
        error.AuthenticationFailed,
        Aead.decrypt(&out, &bad_ct, tag, aad, nonce, key),
    );

    var bad_tag = tag;
    bad_tag[15] ^= 0x80;
    try testing.expectError(
        error.AuthenticationFailed,
        Aead.decrypt(&out, &ct, bad_tag, aad, nonce, key),
    );

    try testing.expectError(
        error.AuthenticationFailed,
        Aead.decrypt(&out, &ct, tag, "different context", nonce, key),
    );

    // ...and the untampered triple still verifies, so the checks above are
    // rejecting the tampering rather than failing for an unrelated reason.
    try Aead.decrypt(&out, &ct, tag, aad, nonce, key);
    try testing.expectEqualSlices(u8, plaintext, &out);
}

test "wrapper entry points reject out-of-range lengths" {
    // Enforced with `std.debug.assert` before, which is removed in ReleaseFast,
    // so these calls read and wrote past the end of the caller's buffers there.
    const key: [32]u8 = @splat(0x01);
    const nonce: [12]u8 = @splat(0x02);
    const plaintext = "0123456789";
    var ct: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    try testing.expectError(
        error.InvalidKey,
        HardwareCrypto.aesGcmEncryptHw(key[0..24], &nonce, plaintext, "", &ct, &tag),
    );
    try testing.expectError(
        error.InvalidNonce,
        HardwareCrypto.aesGcmEncryptHw(&key, nonce[0..8], plaintext, "", &ct, &tag),
    );
    try testing.expectError(
        error.BufferTooSmall,
        HardwareCrypto.aesGcmEncryptHw(&key, &nonce, plaintext, "", ct[0..4], &tag),
    );
    try testing.expectError(
        error.BufferTooSmall,
        HardwareCrypto.aesGcmEncryptHw(&key, &nonce, plaintext, "", &ct, tag[0..8]),
    );

    try testing.expectError(
        error.InvalidKey,
        HardwareCrypto.chacha20Poly1305EncryptHw(key[0..16], &nonce, plaintext, "", &ct, &tag),
    );
    try testing.expectError(
        error.InvalidNonce,
        HardwareCrypto.chacha20Poly1305EncryptHw(&key, nonce[0..4], plaintext, "", &ct, &tag),
    );

    var short_hash: [31]u8 = undefined;
    try testing.expectError(
        error.BufferTooSmall,
        HardwareCrypto.sha256HashHw(plaintext, &short_hash),
    );
}

test "AEAD nonce length is exact, and a rejected call writes nothing" {
    // The length checks above only ever passed a *short* nonce, which the old
    // `nonce.len >= 12` boundary already rejected. The defect was on the other
    // side: a 13-byte nonce was accepted and then silently truncated to its
    // first 12 bytes by the inner `nonce[0..12]`. The caller was told its
    // distinct nonce had been used while two nonces sharing a 12-byte prefix
    // encrypted identically -- nonce reuse under GCM and Poly1305, which forfeits
    // authentication entirely. So 13 is the case that matters here, and 11 is
    // included to pin both sides of the contract rather than just the new one.
    //
    // Nothing in this test depends on `std.debug.assert`, deliberately: the
    // original enforcement was an assert, which is compiled out in ReleaseFast.
    // A test that relied on one would report a pass in exactly the build where
    // the truncation still happened, so every assertion here is an explicit
    // error check on a returned value.
    const key: [32]u8 = @splat(0x11);
    const plaintext = "nonce length is part of the contract";
    const aad = "aad";

    const untouched: u8 = 0xc7;
    var ct: [plaintext.len]u8 = @splat(untouched);
    var tag: [16]u8 = @splat(untouched);

    const short: [11]u8 = @splat(0x22);
    const exact: [12]u8 = @splat(0x22);
    const long: [13]u8 = @splat(0x22);

    // Both AEADs, both wrong lengths. A rejected call must leave the output
    // buffers exactly as it found them: a partially written ciphertext or a
    // stale tag next to an error return is material the caller may still use.
    try testing.expectError(
        error.InvalidNonce,
        HardwareCrypto.aesGcmEncryptHw(&key, &short, plaintext, aad, &ct, &tag),
    );
    try testing.expectError(
        error.InvalidNonce,
        HardwareCrypto.aesGcmEncryptHw(&key, &long, plaintext, aad, &ct, &tag),
    );
    try testing.expectError(
        error.InvalidNonce,
        HardwareCrypto.chacha20Poly1305EncryptHw(&key, &short, plaintext, aad, &ct, &tag),
    );
    try testing.expectError(
        error.InvalidNonce,
        HardwareCrypto.chacha20Poly1305EncryptHw(&key, &long, plaintext, aad, &ct, &tag),
    );

    for (ct) |byte| try testing.expectEqual(untouched, byte);
    for (tag) |byte| try testing.expectEqual(untouched, byte);

    // The exact length is the one that works, so the contract is "exactly 12"
    // rather than "12 is also rejected now".
    try HardwareCrypto.aesGcmEncryptHw(&key, &exact, plaintext, aad, &ct, &tag);
    try testing.expect(!std.mem.eql(u8, plaintext, &ct));

    var chacha_ct: [plaintext.len]u8 = undefined;
    var chacha_tag: [16]u8 = undefined;
    try HardwareCrypto.chacha20Poly1305EncryptHw(&key, &exact, plaintext, aad, &chacha_ct, &chacha_tag);
    try testing.expect(!std.mem.eql(u8, plaintext, &chacha_ct));

    // The truncation itself, stated as a property. `long` shares all 12 bytes of
    // `exact` as its prefix, so under the old behaviour this call succeeded and
    // produced byte-identical output. It must now fail instead.
    try testing.expectEqualSlices(u8, &exact, long[0..12]);
    try testing.expectError(
        error.InvalidNonce,
        HardwareCrypto.aesGcmEncryptHw(&key, &long, plaintext, aad, &ct, &tag),
    );
}

test "stubbed backends report unimplemented rather than returning plaintext" {
    // `/dev/crypto` and the OpenSSL engine are declared but not implemented. An
    // unimplemented cipher that returned success would hand the caller an
    // unencrypted buffer, so the failure has to be explicit.
    const hw = zcrypto.hardware.hardware;

    var dev = try hw.DevCrypto.init();
    defer dev.deinit();

    const key: [16]u8 = @splat(0x33);
    const plaintext = "must not pass through";
    var out: [plaintext.len]u8 = @splat(0);

    const dev_result = dev.aesEncrypt(&key, plaintext, &out);
    try testing.expect(std.meta.isError(dev_result));
    try testing.expect(!std.mem.eql(u8, plaintext, &out));
}
