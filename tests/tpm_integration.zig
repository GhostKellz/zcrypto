//! TPM 2.0 integration tests against a real TPM 2.0 command interface.
//!
//! These are not unit tests with a mocked device. Every test here sends real
//! commands to whatever TPM `ZCRYPTO_TPM_TCTI` points at: an isolated swtpm
//! instance in CI/dev, or `device:/dev/tpmrm0` on a host where the caller can
//! open the TPM. When the variable is unset the suite skips, so an ordinary
//! `zig build test` on a machine with no TPM does not fail.
//!
//! Verification discipline, stated because the code this replaces got it
//! wrong: no test here uses the TPM to check the TPM. Signatures are verified
//! with `std.crypto`'s P-256 implementation, quote contents are re-derived
//! from independently read PCR values, and the RNG is checked on response
//! structure rather than by comparing two draws for inequality (which passes
//! for any counter and proves nothing about entropy).

const std = @import("std");
const tpm2 = @import("tpm2");
const testing = std.testing;

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Open the TPM named by `ZCRYPTO_TPM_TCTI`. With the variable unset the test
/// skips rather than passing, so "no TPM was present" and "the TPM behaved
/// correctly" are distinguishable in the log.
fn openTpm(allocator: std.mem.Allocator) !tpm2.Tpm {
    // `std.testing.environ` is populated by the test runner. `getPosix`
    // returns the value already NUL-terminated, which is what the TCTI
    // loader wants, so no copy is made.
    const conf = std.testing.environ.getPosix("ZCRYPTO_TPM_TCTI") orelse
        return error.SkipZigTest;

    var tpm = try tpm2.Tpm.open(allocator, .{
        .tcti = conf,
        // Simulators need an explicit startup; a firmware-started TPM answers
        // TPM2_RC_INITIALIZE, which `open` accepts.
        .send_startup = true,
    });
    errdefer tpm.close();

    // Start every test from a device that will accept authorization.
    //
    // Several tests below deliberately present wrong auth values, and a TPM
    // answers a handful of those by refusing *every* authorized command until a
    // lockout interval elapses -- so one test's refusal assertions otherwise
    // reappear as a dozen unrelated failures in whatever runs next, and the
    // suite reports a broken TPM instead of a working guard. This is a fixture
    // reset. Nothing in the library does it on a caller's behalf, because the
    // lockout is the protection.
    try tpm.resetDictionaryAttackLock();
    return tpm;
}

test "TPM reports itself as 2.0 rather than being assumed" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    // The old provider hardcoded version 2.0. This asserts the device said so.
    try testing.expectEqualSlices(u8, "2.0", tpm.info.family[0..3]);

    // Manufacturer is four printable ASCII bytes on every conforming TPM.
    for (tpm.info.manufacturer) |b| {
        try testing.expect(b == 0 or (b >= 0x20 and b < 0x7f));
    }
}

test "GetRandom fills exactly the requested length across sizes" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    // Sizes deliberately span below, at, and well above a single TPM digest
    // response, so the partial-response loop is actually exercised rather
    // than only the one-shot path.
    const sizes = [_]usize{ 1, 16, 32, 48, 64, 200, 1024 };

    for (sizes) |n| {
        const buf = try allocator.alloc(u8, n + 2);
        defer allocator.free(buf);

        // Sentinels catch a backend that writes past the requested length.
        buf[0] = 0x5a;
        buf[n + 1] = 0x5a;
        const target = buf[1 .. n + 1];
        @memset(target, 0);

        try tpm.getRandom(target);

        try testing.expectEqual(@as(u8, 0x5a), buf[0]);
        try testing.expectEqual(@as(u8, 0x5a), buf[n + 1]);

        // Not an entropy test: an all-zero return of 1024 bytes indicates the
        // buffer was never written, which is a structural bug, not bad luck.
        if (n >= 32) {
            var all_zero = true;
            for (target) |b| {
                if (b != 0) {
                    all_zero = false;
                    break;
                }
            }
            try testing.expect(!all_zero);
        }
    }
}

test "GetRandom of zero length is a no-op that touches nothing" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var guard: [4]u8 = @splat(0xa5);
    try tpm.getRandom(guard[0..0]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xa5, 0xa5, 0xa5, 0xa5 }, &guard);
}

test "PCR read returns a well-formed SHA-256 bank value" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    // PCR 16 is the debug PCR: defined in every profile, and reading it
    // changes nothing.
    const pcr = try tpm.readPcrSha256(16);
    try testing.expectEqual(@as(usize, 32), pcr.len);

    // Reading twice without extending must be stable. This is a real
    // invariant of PCRs, unlike "two RNG draws differ".
    const again = try tpm.readPcrSha256(16);
    try testing.expectEqualSlices(u8, &pcr, &again);
}

test "TPM P-256 signature verifies under an independent software verifier" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var key = try tpm.createPrimarySigningKey(false);
    defer tpm.flush(&key) catch {};

    // The public key is parsed by std.crypto, so a bogus point fails here
    // rather than being taken on trust.
    const public = try key.publicKey();

    const message = "zcrypto TPM 2.0 signing integration";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});

    const raw = try tpm.signDigest(key, digest);
    const sig = Ecdsa.Signature.fromBytes(raw);

    // std.crypto verifies the TPM's signature. Nothing in this assertion
    // comes from the TPM except the signature itself.
    try sig.verifyPrehashed(digest, public);
}

test "TPM signature is rejected for an altered message" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var key = try tpm.createPrimarySigningKey(false);
    defer tpm.flush(&key) catch {};
    const public = try key.publicKey();

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("original message", &digest, .{});
    const sig = Ecdsa.Signature.fromBytes(try tpm.signDigest(key, digest));

    var other: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("tampered message", &other, .{});

    try testing.expectError(
        error.SignatureVerificationFailed,
        sig.verifyPrehashed(other, public),
    );
}

test "TPM signature is rejected under a different TPM key" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var key_a = try tpm.createPrimarySigningKey(false);
    defer tpm.flush(&key_a) catch {};

    // A software key of the same curve. What this proves is narrow and worth
    // naming: that a signature binds to *a* specific public key. It does not
    // prove two TPM primaries differ -- the key it is checked against never
    // came from the TPM -- which is why the test below does that separately
    // against a second on-device primary.
    // Deterministic so the test cannot depend on entropy or an Io instance.
    const other_kp = try Ecdsa.KeyPair.generateDeterministic(@splat(0x11));

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("bound to key A", &digest, .{});
    const sig = Ecdsa.Signature.fromBytes(try tpm.signDigest(key_a, digest));

    try testing.expectError(
        error.SignatureVerificationFailed,
        sig.verifyPrehashed(digest, other_kp.public_key),
    );
}

test "two primary signing keys are two keys, not one key derived twice" {
    // The contract `createPrimarySigningKey` claims -- that each call is a
    // generator, not a lookup -- can only be tested against a second *TPM*
    // key. A primary is derived from the hierarchy seed and the template, so
    // this holds solely because the template's `unique` field is seeded per
    // call; a fixed template makes both calls return the same key with the
    // same private half, and every assertion below fails.
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var key_a = try tpm.createPrimarySigningKey(false);
    defer tpm.flush(&key_a) catch {};
    var key_b = try tpm.createPrimarySigningKey(false);
    defer tpm.flush(&key_b) catch {};

    const public_a = try key_a.publicKey();
    const public_b = try key_b.publicKey();
    try testing.expect(!std.mem.eql(
        u8,
        &public_a.toCompressedSec1(),
        &public_b.toCompressedSec1(),
    ));

    // Distinct public points could still be reported by a device that signs
    // with one private key regardless, so the private halves are separated
    // too: A's signature must fail under B's public key, and B's under A's.
    // Checked both ways because a one-way check passes if either key is
    // simply broken.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("bound to exactly one of these", &digest, .{});

    const sig_a = Ecdsa.Signature.fromBytes(try tpm.signDigest(key_a, digest));
    const sig_b = Ecdsa.Signature.fromBytes(try tpm.signDigest(key_b, digest));

    try sig_a.verifyPrehashed(digest, public_a);
    try sig_b.verifyPrehashed(digest, public_b);
    try testing.expectError(
        error.SignatureVerificationFailed,
        sig_a.verifyPrehashed(digest, public_b),
    );
    try testing.expectError(
        error.SignatureVerificationFailed,
        sig_b.verifyPrehashed(digest, public_a),
    );
}

test "a tampered signature does not verify" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var key = try tpm.createPrimarySigningKey(false);
    defer tpm.flush(&key) catch {};
    const public = try key.publicKey();

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("signature tamper case", &digest, .{});

    var raw = try tpm.signDigest(key, digest);
    raw[0] ^= 0x01;

    const sig = Ecdsa.Signature.fromBytes(raw);
    // A corrupted scalar can be rejected either as a bad signature or as a
    // non-canonical encoding; both are correct refusals.
    if (sig.verifyPrehashed(digest, public)) |_| {
        return error.TamperedSignatureAccepted;
    } else |_| {}
}

test "a restricted key refuses to sign caller-supplied data" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    // This is a TPM-enforced rule, and asserting it proves the restricted
    // attribute actually reached the device rather than being set in a struct
    // and ignored.
    var ak = try tpm.createPrimarySigningKey(true);
    defer tpm.flush(&ak) catch {};

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("external data", &digest, .{});

    // The specific error matters as much as the refusal. The TPM answers
    // TPM2_RC_TICKET with the parameter number packed into the high bits
    // (0x3E0). A response-code decoder that masks the low 12 bits misses it
    // and degrades to a generic failure, so asserting `RestrictedKey` here is
    // what keeps `mapTpmError` honest.
    try testing.expectError(
        tpm2.TpmError.RestrictedKey,
        tpm.signDigest(ak, digest),
    );
}

test "a key handle from a closed context is refused" {
    const allocator = testing.allocator;

    var first = try openTpm(allocator);
    var key = try first.createPrimarySigningKey(false);
    const stale = key;
    try first.flush(&key);
    first.close();

    var second = try openTpm(allocator);
    defer second.close();

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("stale handle", &digest, .{});

    // Without the epoch check this would address whatever object now occupies
    // that ESYS_TR slot in the new context.
    try testing.expectError(
        tpm2.TpmError.AuthorizationFailed,
        second.signDigest(stale, digest),
    );
}

test "flushing a key handle from another context is refused rather than performed" {
    // `flush` used to accept any handle, discard the response code and blank
    // its input regardless. Given a handle from a closed context that meant
    // releasing whatever object now occupies that ESYS_TR slot in the new
    // context, silently -- the exact case `signDigest` already refused above,
    // on the one operation whose effect cannot be noticed afterwards.
    const allocator = testing.allocator;

    var first = try openTpm(allocator);
    var key = try first.createPrimarySigningKey(false);
    const original = key;
    var stale = key;
    try first.flush(&key);
    first.close();

    var second = try openTpm(allocator);
    defer second.close();

    try testing.expectError(tpm2.TpmError.AuthorizationFailed, second.flush(&stale));

    // Refusing also left the caller's handle alone. A flush that blanks its
    // input before deciding what to do leaves nothing to retry with and nothing
    // to report about.
    try testing.expectEqual(original.handle, stale.handle);
    try testing.expectEqual(original.session_epoch, stale.session_epoch);
}

/// Minimal TPMS_ATTEST reader. Only the fields the quote assertions need are
/// decoded, and every read is bounds-checked, because this parses a structure
/// that arrived from a device.
const AttestView = struct {
    extra_data: []const u8,
    pcr_digest: []const u8,

    fn parse(buf: []const u8) !AttestView {
        var pos: usize = 0;

        const magic = try readU32(buf, &pos);
        if (magic != 0xff544347) return error.BadAttestMagic;

        const attest_type = try readU16(buf, &pos);
        if (attest_type != 0x8018) return error.NotAQuote; // TPM2_ST_ATTEST_QUOTE

        _ = try readSized16(buf, &pos); // qualifiedSigner
        const extra = try readSized16(buf, &pos); // extraData == caller nonce

        pos += 17; // TPMS_CLOCK_INFO: clock u64, resetCount u32, restartCount u32, safe u8
        pos += 8; // firmwareVersion
        if (pos > buf.len) return error.TruncatedAttest;

        // TPML_PCR_SELECTION
        const sel_count = try readU32(buf, &pos);
        var i: u32 = 0;
        while (i < sel_count) : (i += 1) {
            pos += 2; // hash alg
            if (pos >= buf.len) return error.TruncatedAttest;
            const size_of_select = buf[pos];
            pos += 1 + size_of_select;
            if (pos > buf.len) return error.TruncatedAttest;
        }

        const digest = try readSized16(buf, &pos);

        return AttestView{ .extra_data = extra, .pcr_digest = digest };
    }

    fn readU16(buf: []const u8, pos: *usize) !u16 {
        if (pos.* + 2 > buf.len) return error.TruncatedAttest;
        const v = std.mem.readInt(u16, buf[pos.*..][0..2], .big);
        pos.* += 2;
        return v;
    }

    fn readU32(buf: []const u8, pos: *usize) !u32 {
        if (pos.* + 4 > buf.len) return error.TruncatedAttest;
        const v = std.mem.readInt(u32, buf[pos.*..][0..4], .big);
        pos.* += 4;
        return v;
    }

    fn readSized16(buf: []const u8, pos: *usize) ![]const u8 {
        const n = try readU16(buf, pos);
        if (pos.* + n > buf.len) return error.TruncatedAttest;
        const slice = buf[pos.*..][0..n];
        pos.* += n;
        return slice;
    }
};

test "quote signature verifies and binds the caller nonce and PCR digest" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var ak = try tpm.createPrimarySigningKey(true);
    defer tpm.flush(&ak) catch {};
    const public = try ak.publicKey();

    const selected = [_]u5{ 0, 1, 16 };
    const nonce = "zcrypto-quote-nonce-0001";

    var q = try tpm.quote(ak, &selected, nonce);
    defer q.deinit();

    // 1. The signature is over SHA-256 of the attest blob, verified by
    //    std.crypto rather than by asking the TPM.
    var attest_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(q.attested, &attest_digest, .{});
    const sig = Ecdsa.Signature.fromBytes(q.signature);
    try sig.verifyPrehashed(attest_digest, public);

    const view = try AttestView.parse(q.attested);

    // 2. Freshness: the nonce the caller supplied is inside the signed blob.
    //    A quote that verifies but does not carry the nonce proves nothing
    //    about liveness.
    try testing.expectEqualSlices(u8, nonce, view.extra_data);

    // 3. The PCR digest is re-derived from PCR values read independently.
    //    TPM2 defines it as the hash of the selected PCR values concatenated
    //    in ascending index order.
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (selected) |idx| {
        const pcr = try tpm.readPcrSha256(idx);
        hasher.update(&pcr);
    }
    var expected: [32]u8 = undefined;
    hasher.final(&expected);

    try testing.expectEqualSlices(u8, &expected, view.pcr_digest);
}

test "quote with a different nonce produces a different signed blob" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var ak = try tpm.createPrimarySigningKey(true);
    defer tpm.flush(&ak) catch {};
    const public = try ak.publicKey();

    const selected = [_]u5{16};

    var q1 = try tpm.quote(ak, &selected, "nonce-one");
    defer q1.deinit();
    var q2 = try tpm.quote(ak, &selected, "nonce-two");
    defer q2.deinit();

    const v1 = try AttestView.parse(q1.attested);
    const v2 = try AttestView.parse(q2.attested);
    try testing.expectEqualSlices(u8, "nonce-one", v1.extra_data);
    try testing.expectEqualSlices(u8, "nonce-two", v2.extra_data);

    // A replayed quote must not verify against the other transcript: this is
    // the property a relying party depends on.
    var d2: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(q2.attested, &d2, .{});
    const sig1 = Ecdsa.Signature.fromBytes(q1.signature);
    try testing.expectError(
        error.SignatureVerificationFailed,
        sig1.verifyPrehashed(d2, public),
    );
}

test "quote over a tampered attest blob does not verify" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var ak = try tpm.createPrimarySigningKey(true);
    defer tpm.flush(&ak) catch {};
    const public = try ak.publicKey();

    var q = try tpm.quote(ak, &[_]u5{16}, "tamper-case");
    defer q.deinit();

    // Flip a bit in the signed material; the signature must stop verifying.
    q.attested[q.attested.len - 1] ^= 0x01;

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(q.attested, &digest, .{});
    const sig = Ecdsa.Signature.fromBytes(q.signature);

    try testing.expectError(
        error.SignatureVerificationFailed,
        sig.verifyPrehashed(digest, public),
    );
}

test "seal then unseal returns the original secret" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    const secret = "zcrypto-seal-roundtrip-32-byte!!";
    var blob = try tpm.seal(parent, secret);
    defer blob.deinit();

    // The blob must not simply contain the plaintext. Sealing that leaked the
    // secret into its own output would still pass a round-trip test.
    try testing.expect(std.mem.indexOf(u8, blob.private, secret) == null);
    try testing.expect(std.mem.indexOf(u8, blob.public, secret) == null);

    var out: [64]u8 = undefined;
    const len = try tpm.unseal(parent, blob, &out);
    try testing.expectEqualSlices(u8, secret, out[0..len]);
}

test "the storage parent is stable, so a blob outlives the context that sealed it" {
    // The mirror image of the signing-key contract, and the reason the two
    // templates differ: `createPrimaryStorageKey` sends no `unique` seed, so
    // the same template on the same TPM re-derives the same parent. That is
    // what lets a blob sealed by one process be unsealed by the next without
    // any persistent handle being made. Seeding it the way the signing
    // template is seeded would make every sealed blob unrecoverable as soon
    // as its context closed.
    //
    // Separate `Tpm` connections, not just separate handles, so nothing about
    // the first context can be carrying the result.
    const allocator = testing.allocator;

    var sealing = try openTpm(allocator);
    var parent_a = try sealing.createPrimaryStorageKey();
    const secret = "survives-the-context-that-made-it";
    var blob = try sealing.seal(parent_a, secret);
    defer blob.deinit();
    sealing.flushStorageKey(&parent_a) catch {};
    sealing.close();

    var opening = try openTpm(allocator);
    defer opening.close();
    var parent_b = try opening.createPrimaryStorageKey();
    defer opening.flushStorageKey(&parent_b) catch {};

    var out: [64]u8 = undefined;
    const len = try opening.unseal(parent_b, blob, &out);
    try testing.expectEqualSlices(u8, secret, out[0..len]);
}

test "unsealing needs access to this TPM and no caller secret" {
    // Recorded as a test rather than a comment because it is the security
    // boundary this API actually has, and a comment cannot go stale loudly.
    //
    // Plain `seal` uses empty object auth and no PCR policy. The blob is
    // therefore bound to the device, not to the caller: anything that can reach
    // this TPM's owner hierarchy can re-derive the parent and unseal, with no
    // password, no policy session, and nothing carried over from the context
    // that sealed. The test above shows that as a durability feature; this one
    // states the same fact as its cost, so neither reading is left implicit.
    //
    // This is the *default*, and it stays the default: `sealWithPolicy` now
    // offers an auth value and a PCR policy, and the tests below prove both
    // refuse. A caller who asks for neither still gets device-bound wrapping,
    // which is not caller authorization and not trusted-boot sealing. This test
    // is what fails if that default ever quietly acquires a guard -- which
    // would break every existing blob rather than protect it.
    const allocator = testing.allocator;

    var sealing = try openTpm(allocator);
    defer sealing.close();
    var parent = try sealing.createPrimaryStorageKey();
    defer sealing.flushStorageKey(&parent) catch {};
    var blob = try sealing.seal(parent, "no-secret-guards-this");
    defer blob.deinit();

    // A second connection is given the blob and nothing else -- no handle, no
    // auth value, no session. If a caller secret were required, this could not
    // succeed, and the day one is added this test is what fails.
    var unrelated = try openTpm(allocator);
    defer unrelated.close();
    var rederived = try unrelated.createPrimaryStorageKey();
    defer unrelated.flushStorageKey(&rederived) catch {};

    var out: [64]u8 = undefined;
    const len = try unrelated.unseal(rederived, blob, &out);
    try testing.expectEqualSlices(u8, "no-secret-guards-this", out[0..len]);
}

// =============================================================================
// Auth values and PCR policies
//
// The two guards `sealWithPolicy` adds on top of device binding. Each is tested
// in both directions: that the right credential unseals, and -- the half that
// actually matters -- that the wrong one refuses. A policy that never refuses
// is indistinguishable from no policy at all, and the failure mode of getting
// the object attributes wrong is exactly that: a blob that unseals for anyone,
// silently, with no error to notice.
// =============================================================================

/// The PCR these tests move.
///
/// 23 is the resettable application PCR: no firmware measurement lands in it,
/// so extending it cannot invalidate anything outside this file, and the
/// simulator these tests run against starts it at zero. The firmware-owned
/// PCRs 0-7 would be a more realistic trusted-boot binding and are exactly the
/// ones a test must not touch.
const scratch_pcr: u5 = 23;

test "an auth value is required to unseal, not merely recorded" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    const secret = "guarded-by-a-caller-secret";
    const auth = "correct horse battery staple";

    var blob = try tpm.sealWithPolicy(parent, secret, .{ .auth = auth });
    defer blob.deinit();

    // The auth value must not be recoverable from the blob, which is written to
    // ordinary storage. A `TPM2B_SENSITIVE_CREATE` that leaked `userAuth` into
    // its own public output would still pass the round trip below.
    try testing.expect(std.mem.indexOf(u8, blob.public, auth) == null);
    try testing.expect(std.mem.indexOf(u8, blob.private, auth) == null);

    var out: [64]u8 = undefined;
    const len = try tpm.unsealWithPolicy(parent, blob, .{ .auth = auth }, &out);
    try testing.expectEqualSlices(u8, secret, out[0..len]);

    // A wrong value differing in one byte and matching in length, so the
    // refusal is about the bytes and not about the size.
    const wrong = "correct horse battery stapld";
    comptime std.debug.assert(wrong.len == auth.len);
    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unsealWithPolicy(parent, blob, .{ .auth = wrong }, &out),
    );

    // And no value at all. This is the path a caller reaches by using the
    // plain `unseal`, so it is the one that decides whether the auth value is
    // a guard or a decoration.
    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unseal(parent, blob, &out),
    );
}

test "a PCR-sealed blob unseals only while the PCR still holds its value" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    const pcrs: tpm2.PcrPolicy = .{ .indices = &.{scratch_pcr} };
    const secret = "bound-to-a-boot-state";

    var blob = try tpm.sealWithPolicy(parent, secret, .{ .pcrs = pcrs });
    defer blob.deinit();

    // Still the same boot state, so this must succeed -- otherwise the refusal
    // below would prove nothing, since a policy that never satisfies is also a
    // policy that always refuses.
    var out: [64]u8 = undefined;
    const len = try tpm.unsealWithPolicy(parent, blob, .{ .pcrs = pcrs }, &out);
    try testing.expectEqualSlices(u8, secret, out[0..len]);

    // Plain `unseal` supplies no PCR assertion, so the policy session it opens
    // cannot satisfy the object's policy.
    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unseal(parent, blob, &out),
    );

    // The refusal above is necessary but not sufficient, and this is the
    // difference. `unsealWithPolicy` picks a policy session whenever the blob
    // carries a policy digest, so it would refuse the same way even if the
    // object had been created with `TPMA_OBJECT_USERWITHAUTH` set -- and such
    // a blob unseals for anyone holding the (here empty) auth value under any
    // other TPM software. Confirmed by mutation: setting that bit leaves every
    // refusal above intact and only this assertion fails.
    const guards = try blob.guards();
    try testing.expect(guards.policy_bound);
    try testing.expect(!guards.auth_value_suffices);

    const before = try tpm.readPcrSha256(scratch_pcr);
    const measurement: [32]u8 = @splat(0x5C);
    try tpm.extendPcrSha256(scratch_pcr, measurement);
    const after = try tpm.readPcrSha256(scratch_pcr);
    // The extend has to have done something, or the refusal below would be
    // measuring nothing.
    try testing.expect(!std.mem.eql(u8, &before, &after));

    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unsealWithPolicy(parent, blob, .{ .pcrs = pcrs }, &out),
    );

    // The refusals above may have tripped the lockout, which would make the
    // seal below fail for a reason that has nothing to do with PCRs.
    try tpm.resetDictionaryAttackLock();

    // A blob sealed after the change unseals, so the failure above is the
    // policy refusing a changed state and not the PCR path being broken
    // outright.
    var rebound = try tpm.sealWithPolicy(parent, secret, .{ .pcrs = pcrs });
    defer rebound.deinit();
    const relen = try tpm.unsealWithPolicy(parent, rebound, .{ .pcrs = pcrs }, &out);
    try testing.expectEqualSlices(u8, secret, out[0..relen]);
}

test "with both guards set, either one alone is not enough" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    const pcrs: tpm2.PcrPolicy = .{ .indices = &.{scratch_pcr} };
    const auth = "both-guards";
    const secret = "needs-the-secret-and-the-state";
    const full: tpm2.SealOptions = .{ .auth = auth, .pcrs = pcrs };

    var blob = try tpm.sealWithPolicy(parent, secret, full);
    defer blob.deinit();

    var out: [64]u8 = undefined;
    const len = try tpm.unsealWithPolicy(parent, blob, full, &out);
    try testing.expectEqualSlices(u8, secret, out[0..len]);

    // Right state, wrong secret.
    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unsealWithPolicy(parent, blob, .{ .auth = "wrong-guards", .pcrs = pcrs }, &out),
    );

    // Right secret, no PCR assertion. The policy digest differs, so this fails
    // even though the caller holds the auth value.
    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unsealWithPolicy(parent, blob, .{ .auth = auth }, &out),
    );

    // Right secret, right assertion, changed state.
    const measurement: [32]u8 = @splat(0xA7);
    try tpm.extendPcrSha256(scratch_pcr, measurement);
    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unsealWithPolicy(parent, blob, full, &out),
    );
}

test "a refused unseal wipes the response buffer it never returned" {
    // The existing buffer-hygiene test covers `BufferTooSmall`, which happens
    // after the TPM has handed the plaintext back. An authorization refusal
    // happens before that, so the claim being made here is the narrower one:
    // a refusal leaves no plaintext behind because none was ever produced.
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    var blob = try tpm.sealWithPolicy(parent, "never-comes-back", .{ .auth = "right" });
    defer blob.deinit();

    tpm2.resetUnsealObservationForTesting();
    var out: [64]u8 = undefined;
    try testing.expectError(
        error.AuthorizationFailed,
        tpm.unsealWithPolicy(parent, blob, .{ .auth = "wrong" }, &out),
    );
    // Null, not `false`: the observation seam is only reached after a
    // successful `Esys_Unseal`, and the point is that this refusal never got
    // there.
    try testing.expect(tpm2.unsealBufferWasZeroedForTesting() == null);
}

test "an auth value longer than the object's digest is refused here, not by the TPM" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    const too_long: [tpm2.max_auth_len + 1]u8 = @splat(0x11);
    try testing.expectError(
        error.BufferTooSmall,
        tpm.sealWithPolicy(parent, "x", .{ .auth = &too_long }),
    );
}

test "provider: a policy-sealed blob round-trips and refuses the wrong auth" {
    var provider = try openProvider();
    defer provider.deinit();

    var blob = try provider.sealWithPolicy("provider-guarded-secret", .{ .auth = "provider-auth" });
    defer blob.deinit();

    var out: [64]u8 = undefined;
    const len = try provider.unsealWithPolicy(blob, .{ .auth = "provider-auth" }, &out);
    try testing.expectEqualSlices(u8, "provider-guarded-secret", out[0..len]);

    // `AuthenticationFailed`, the provider's spelling of the backend's
    // `AuthorizationFailed`. Not `OperationFailed`: a caller that only ever
    // sees `HSMError` still has to be able to tell "wrong credential" from
    // "the device is broken".
    try testing.expectError(
        hsm.HSMError.AuthenticationFailed,
        provider.unsealWithPolicy(blob, .{ .auth = "provider-authX" }, &out),
    );
    try testing.expectError(
        hsm.HSMError.AuthenticationFailed,
        provider.unseal(blob, &out),
    );
}

test "a sealed blob is rejected when its private half is altered" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    var blob = try tpm.seal(parent, "unseal-must-be-authenticated");
    defer blob.deinit();

    // Flip a bit in the ciphertext. The TPM's own integrity check must catch
    // this at load time; unseal must never return altered plaintext.
    blob.private[blob.private.len - 1] ^= 0x01;

    var out: [64]u8 = undefined;
    try testing.expectError(
        tpm2.TpmError.MalformedResponse,
        tpm.unseal(parent, blob, &out),
    );
}

test "unseal into a buffer that is too small fails instead of truncating" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    var blob = try tpm.seal(parent, "0123456789abcdef");
    defer blob.deinit();

    var too_small: [8]u8 = undefined;
    try testing.expectError(
        tpm2.TpmError.BufferTooSmall,
        tpm.unseal(parent, blob, &too_small),
    );
}

test "unseal wipes the recovered secret even when it refuses to return it" {
    // The failing return is the interesting one. `Esys_Free` hands the response
    // buffer back to the allocator without clearing it, and the wipe used to sit
    // after the capacity check, so this exact path released the plaintext
    // intact. It cannot be observed from out here -- the allocation is gone by
    // the time this test resumes -- so the backend reports what the buffer held
    // at the moment it was released.
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    var blob = try tpm.seal(parent, "0123456789abcdef");
    defer blob.deinit();

    tpm2.resetUnsealObservationForTesting();
    // A sentinel rather than `undefined`, so "unchanged" is a property this can
    // actually assert. Reading `undefined` back would prove nothing either way.
    var too_small: [8]u8 = @splat(0xa5);
    try testing.expectError(
        tpm2.TpmError.BufferTooSmall,
        tpm.unseal(parent, blob, &too_small),
    );

    // Not `orelse false`: null means the unseal never reached the release, so
    // the test would be reporting on something that did not happen.
    try testing.expectEqual(@as(?bool, true), tpm2.unsealBufferWasZeroedForTesting());

    // The refusal still wrote nothing to the caller's buffer -- a truncating
    // copy would have left the first eight plaintext bytes here.
    try testing.expect(std.mem.allEqual(u8, &too_small, 0xa5));

    // And the successful path is unaffected by the wipe being deferred.
    var out: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 16), try tpm.unseal(parent, blob, &out));
    try testing.expectEqualStrings("0123456789abcdef", &out);
}

test "sealing more than the TPM permits reports a size error" {
    const allocator = testing.allocator;
    var tpm = try openTpm(allocator);
    defer tpm.close();

    var parent = try tpm.createPrimaryStorageKey();
    defer tpm.flushStorageKey(&parent) catch {};

    // Within this module's own buffer bound, so the refusal comes from the
    // TPM's sealed-object size rule rather than from a local length check.
    const oversized: [200]u8 = @splat(0x5a);
    try testing.expectError(
        tpm2.TpmError.BufferTooSmall,
        tpm.seal(parent, &oversized),
    );
}

test "a storage key handle from a closed context is refused" {
    const allocator = testing.allocator;
    var first = try openTpm(allocator);
    var parent = try first.createPrimaryStorageKey();
    const stale = parent;
    try first.flushStorageKey(&parent);
    first.close();

    var second = try openTpm(allocator);
    defer second.close();

    try testing.expectError(
        tpm2.TpmError.AuthorizationFailed,
        second.seal(stale, "must not be sealed under a foreign handle"),
    );
}

test "an absent device path is reported as absent, not as a generic failure" {
    const allocator = testing.allocator;
    // Independent of ZCRYPTO_TPM_TCTI: this asserts the error taxonomy.
    try testing.expectError(
        tpm2.TpmError.DeviceAbsent,
        tpm2.Tpm.open(allocator, .{ .tcti = "device:/nonexistent/zcrypto-tpm-probe" }),
    );
}

// =============================================================================
// Provider layer
// =============================================================================
//
// The tests above drive the backend directly. These drive `hsm.TPMProvider`
// against the same live device, because the contract that matters to a caller
// — owned key references, stale-reference rejection, truthful capabilities —
// lives in the provider, and none of it is exercised by a host with no TPM.

const hsm = @import("hsm");

/// A provider aimed at `ZCRYPTO_TPM_TCTI`, or a skip. `simulated` is passed
/// through so the reported backing matches what the endpoint actually is.
fn openProvider() !hsm.TPMProvider {
    const conf = std.testing.environ.getPosix("ZCRYPTO_TPM_TCTI") orelse
        return error.SkipZigTest;

    // Same fixture reset as `openTpm`, for the same reason; the provider
    // exposes no way to do it, because clearing a dictionary-attack lockout is
    // an operator action rather than something a key-using caller should reach.
    {
        var device = try openTpm(std.testing.allocator);
        device.close();
    }

    var provider = hsm.TPMProvider.init(.{
        .tcti = conf,
        .send_startup = true,
        // Every endpoint this suite is pointed at in dev is a simulator. A
        // hardware run would set this false; it only affects reported backing.
        .simulated = true,
    });
    if (!provider.status.isReady()) {
        // Not a skip. `ZCRYPTO_TPM_TCTI` being set means an operator named a
        // TPM and asked for it to be tested; "I could not open it" is a result
        // about that TPM, not the absence of one. Skipping here would let a
        // release gate report success having talked to no device at all, which
        // is the reporting failure this whole provider rewrite exists to end.
        // The status is printed because it *is* the diagnosis: `permission_denied`
        // and `device_absent` send an operator to entirely different places.
        std.debug.print(
            "TPMProvider.init(\"{s}\") is not ready: {s}\n",
            .{ conf, @tagName(std.meta.activeTag(provider.status)) },
        );
        provider.deinit();
        return error.ProviderNotReady;
    }
    return provider;
}

test "provider: an open device advertises exactly the operations it implements" {
    var provider = try openProvider();
    defer provider.deinit();

    // Advertised because they are implemented below in this file.
    for ([_]hsm.Operation{
        .random,      .generate_signing_key, .export_public_key,
        .sign,        .seal,                 .unseal,
        .destroy_key, .attestation_quote,
    }) |op| {
        try testing.expect(provider.status.supports(op));
    }

    // The device answered the identity commands, so this is read, not assumed.
    try testing.expect(provider.deviceInfo() != null);
    try testing.expectEqualSlices(u8, "2.0", provider.deviceInfo().?.family[0..3]);
}

test "provider: a simulator is reported as a software token even when fully working" {
    var provider = try openProvider();
    defer provider.deinit();

    // This is the assertion that stops a simulator run being presented as
    // evidence of hardware protection: everything below works, and the
    // provider still refuses to call it hardware.
    try testing.expectEqual(hsm.Backing.software_token, provider.backing);

    const key = try provider.generateSigningKey(false);
    defer provider.destroyKey(key) catch {};
    try testing.expectEqual(hsm.Backing.software_token, key.properties.backing);
    // A TPM primary key's private half never leaves the device, and this
    // provider creates no persistent handles.
    try testing.expect(!key.properties.extractable);
    try testing.expect(!key.properties.persistent);
}

test "provider: random comes from the device and fills the buffer" {
    var provider = try openProvider();
    defer provider.deinit();

    var buf: [48]u8 = @splat(0xAA);
    try provider.getRandom(&buf);

    // Checked on structure, not by comparing two draws: the TPM was asked for
    // 48 bytes and the sentinel must be gone from all of them.
    var still_sentinel: usize = 0;
    for (buf) |b| {
        if (b == 0xAA) still_sentinel += 1;
    }
    // 48 untouched bytes would mean nothing was written. A handful of genuine
    // 0xAA bytes is expected, so the bound is loose on purpose.
    try testing.expect(still_sentinel < 8);
}

test "provider: a signature from a provider-held key verifies under std.crypto" {
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey(false);
    defer provider.destroyKey(key) catch {};

    const message = "provider layer signing over a real device";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});

    const sig_bytes = try provider.signDigest(key, digest);
    const public_sec1 = try provider.exportPublicKey(key);

    // Verified by an implementation that is not the TPM. If the provider
    // returned a fabricated signature, or the public key of some other object,
    // this fails.
    const public = try Ecdsa.PublicKey.fromSec1(&public_sec1);
    const sig = Ecdsa.Signature.fromBytes(sig_bytes);
    try sig.verify(message, public);
}

test "provider: a destroyed key reference stops working" {
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey(false);
    try provider.destroyKey(key);

    // The reference is a value the caller still holds; it must be refused
    // rather than resolving to whatever now occupies the slot.
    const digest: [32]u8 = @splat(0);
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.signDigest(key, digest));
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.exportPublicKey(key));
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.destroyKey(key));
}

test "provider: a stale reference does not authorize the key that reused its slot" {
    // The test above destroys a key and finds the slot empty, which any
    // `used` flag catches. This is the case that flag cannot catch: the slot is
    // occupied again, by a *different* key, and the stale reference is
    // byte-identical to the new one unless issuance is tracked. Without that,
    // a caller holding an old handle can sign with, export, and above all
    // destroy a key it never created.
    var provider = try openProvider();
    defer provider.deinit();

    const first = try provider.generateSigningKey(false);
    const first_public = try provider.exportPublicKey(first);
    try provider.destroyKey(first);

    const second = try provider.generateSigningKey(false);
    defer provider.destroyKey(second) catch {};

    // The slot really was reused, so the rejection below cannot be passing for
    // the trivial reason that the two keys landed in different slots.
    try testing.expectEqual(first.native, second.native);

    // And they really are different keys, so authorizing one with the other's
    // reference would be a genuine authorization failure, not a rename.
    const second_public = try provider.exportPublicKey(second);
    try testing.expect(!std.mem.eql(u8, &first_public, &second_public));

    const digest: [32]u8 = @splat(0xC3);
    try testing.expectError(hsm.HSMError.StaleKeyReference, provider.signDigest(first, digest));
    try testing.expectError(hsm.HSMError.StaleKeyReference, provider.exportPublicKey(first));
    try testing.expectError(hsm.HSMError.StaleKeyReference, provider.destroyKey(first));

    // The live key is unaffected by the refusals aimed at its slot.
    _ = try provider.signDigest(second, digest);
}

test "provider: a key reference is refused by a second live provider" {
    var a = try openProvider();
    defer a.deinit();
    var b = try openProvider();
    defer b.deinit();

    const key = try a.generateSigningKey(false);
    defer a.destroyKey(key) catch {};

    // Both providers are open on the same device and `b`'s slot 0 is free, so
    // this is rejected on ownership rather than by accident.
    const digest: [32]u8 = @splat(0);
    try testing.expectError(hsm.HSMError.StaleKeyReference, b.signDigest(key, digest));

    // And `a` still works: rejecting the foreign reference did not disturb it.
    _ = try a.signDigest(key, digest);
}

test "provider: running out of key slots is reported as exhaustion, not as a device failure" {
    var provider = try openProvider();
    defer provider.deinit();

    // Two limits can bind here: this provider's table, and the TPM's own
    // transient object memory. The simulator's is far lower — it refuses the
    // fourth key — so the loop stops wherever the first ceiling is, and the
    // assertion is that either one is reported as exhaustion. Asserting a
    // fixed count instead would only be testing one particular device.
    var made: [hsm.TPMProvider.max_keys]hsm.KeyRef = undefined;
    var count: usize = 0;
    defer for (made[0..count]) |k| {
        provider.destroyKey(k) catch {};
    };

    const stopped_on = while (count < made.len) {
        made[count] = provider.generateSigningKey(false) catch |err| break err;
        count += 1;
    } else blk: {
        // The table filled before the device complained; one more must be
        // refused by the table itself.
        break :blk provider.generateSigningKey(false) catch |err| err;
    };

    try testing.expect(count > 0);
    // Not `OperationFailed`: an opaque failure gives the caller nothing to act
    // on, whereas exhaustion says "free a key and retry".
    try testing.expectEqual(hsm.HSMError.KeyTableFull, stopped_on);

    // Freeing one makes room again, so this is a live count and not a latch
    // that permanently disables the provider.
    try provider.destroyKey(made[count - 1]);
    made[count - 1] = try provider.generateSigningKey(false);
}

test "provider: seal and unseal round-trip through the provider" {
    var provider = try openProvider();
    defer provider.deinit();

    const secret = "provider-level sealed application key";
    var blob = try provider.seal(secret);
    defer blob.deinit();

    // The sealed blob is not secret, but it must not be the plaintext.
    try testing.expect(std.mem.indexOf(u8, blob.private, secret) == null);
    try testing.expect(std.mem.indexOf(u8, blob.public, secret) == null);

    var out: [64]u8 = undefined;
    const len = try provider.unseal(blob, &out);
    try testing.expectEqualSlices(u8, secret, out[0..len]);
}

test "provider: an unseal buffer that is too small yields no plaintext" {
    var provider = try openProvider();
    defer provider.deinit();

    const secret = "sixteen bytes ok";
    var blob = try provider.seal(secret);
    defer blob.deinit();

    var out: [4]u8 = @splat(0);
    try testing.expectError(hsm.HSMError.BufferTooSmall, provider.unseal(blob, &out));
    // Nothing was written, so no prefix of the secret leaked into the buffer.
    for (out) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "provider: a quote from a restricted key carries the caller's nonce" {
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey(true);
    defer provider.destroyKey(key) catch {};

    const nonce = "provider-nonce-0123456789";
    var quote = try provider.attestationQuote(key, &[_]u5{ 0, 1 }, nonce);
    defer quote.deinit();

    // The nonce must appear inside the structure the TPM signed. A quote
    // whose nonce is not there proves nothing about freshness.
    try testing.expect(std.mem.indexOf(u8, quote.attested, nonce) != null);

    // And the signature is over that structure, checked outside the TPM.
    const public_sec1 = try provider.exportPublicKey(key);
    const public = try Ecdsa.PublicKey.fromSec1(&public_sec1);
    const sig = Ecdsa.Signature.fromBytes(quote.signature);
    try sig.verify(quote.attested, public);
}

test "provider: a restricted key refuses to sign caller data" {
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey(true);
    defer provider.destroyKey(key) catch {};

    // The TPM enforces this, not the provider. It surfaces as an unsupported
    // mechanism rather than a generic failure.
    const digest: [32]u8 = @splat(0x11);
    try testing.expectError(hsm.HSMError.UnsupportedMechanism, provider.signDigest(key, digest));
}

test "provider: concurrent use is reported instead of corrupting the session" {
    var provider = try openProvider();
    defer provider.deinit();

    // Standing in for a second thread inside a provider call. Spawning one
    // would make the test depend on winning a race; setting the guard tests
    // the same branch deterministically.
    provider.busy.store(true, .release);
    var buf: [8]u8 = @splat(0);
    try testing.expectError(hsm.HSMError.ConcurrentUse, provider.getRandom(&buf));

    provider.busy.store(false, .release);
    // The guard is not a latch: the provider works again once released.
    try provider.getRandom(&buf);
}

test "provider: a closed provider refuses further work" {
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey(false);
    provider.deinit();

    // deinit is idempotent for the defer above, and every entry point now
    // answers from status rather than touching a freed context.
    try testing.expect(!provider.status.isReady());
    var buf: [8]u8 = @splat(0);
    try testing.expectError(hsm.HSMError.DeviceAbsent, provider.getRandom(&buf));
    const digest: [32]u8 = @splat(0);
    try testing.expectError(hsm.HSMError.DeviceAbsent, provider.signDigest(key, digest));
}
