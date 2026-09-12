//! PKCS#11 integration tests against a real Cryptoki provider module.
//!
//! Nothing here is mocked. Every test loads the shared object named by
//! `ZCRYPTO_PKCS11_MODULE` with dlopen, calls `C_GetFunctionList` on it and
//! drives the resulting table. With the variable unset the suite skips, so an
//! ordinary `zig build test` on a host with no provider does not fail.
//!
//! The suite is in two tiers because the two available providers can do
//! different things:
//!
//!   * Tier one runs against any conforming module, including a read-only one.
//!     It covers module loading, the two-call size-query convention, slot and
//!     token enumeration, mechanism interrogation, session lifetime, object
//!     search, and the negative cases — a path that is not a library, a library
//!     that is not a Cryptoki module, an out-of-range slot, an undersized
//!     buffer, and a write-protected token refusing to create an object.
//!
//!   * Tier two needs a token that permits key creation, which means a PIN in
//!     `ZCRYPTO_PKCS11_PIN` and a token whose `CKF_WRITE_PROTECTED` bit is
//!     clear. It covers ECDSA P-256 generation, public-key export, signing,
//!     verification, reopening a key by label in a fresh session, destruction,
//!     and AES-GCM including tamper rejection. When those conditions are not
//!     met each tier-two test skips, so "the token cannot create keys" and
//!     "key creation worked" are distinguishable in the log rather than both
//!     showing green.
//!
//! Verification discipline: the token is never used to check itself. A
//! signature the token produces is verified with `std.crypto`'s P-256
//! implementation against the public point the token exported, and the token's
//! AES-GCM output is decrypted by `std.crypto` under a key the test supplies
//! where the token allows it. `C_Verify` is exercised as a separate assertion
//! about the token, not as the proof that signing worked.

const std = @import("std");
const pkcs11 = @import("pkcs11");
const hsm = @import("hsm");
const testing = std.testing;

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Label used for every object this suite creates, so a token left dirty by an
/// interrupted run can be identified and cleaned up.
const test_label = "zcrypto-pkcs11-integration";

fn modulePath() ![]const u8 {
    const path = std.testing.environ.getPosix("ZCRYPTO_PKCS11_MODULE") orelse
        return error.SkipZigTest;
    if (path.len == 0) return error.SkipZigTest;
    return path;
}

/// Slot index to use, from `ZCRYPTO_PKCS11_SLOT`. Defaults to the first slot
/// holding a token. A module can present several tokens with different
/// capabilities — p11-kit-trust presents two — so which one is under test has
/// to be selectable without editing the suite.
fn slotIndex() usize {
    const raw = std.testing.environ.getPosix("ZCRYPTO_PKCS11_SLOT") orelse return 0;
    return std.fmt.parseInt(usize, raw, 10) catch 0;
}

/// Provider-specific initialization string from `ZCRYPTO_PKCS11_CONFIG`, passed
/// through as `CK_C_INITIALIZE_ARGS.pReserved`. NSS softoken needs one to be
/// pointed at a database it may write to; without it every slot it offers is
/// write-protected and tier two cannot run.
fn moduleConfig() ?[]const u8 {
    const raw = std.testing.environ.getPosix("ZCRYPTO_PKCS11_CONFIG") orelse return null;
    return if (raw.len == 0) null else raw;
}

fn openModule() !pkcs11.Module {
    return pkcs11.Module.open(.{
        .module_path = try modulePath(),
        .slot_index = slotIndex(),
        .module_config = moduleConfig(),
    });
}

/// Remove every object of `class` carrying this suite's label. Used where the
/// handles that created the objects are no longer valid, and as a best-effort
/// cleanup: a failure here must not mask the assertion that actually failed.
fn destroyByLabel(session: *pkcs11.Session, class: pkcs11.ObjectClass) void {
    var found: [16]pkcs11.ObjectHandle = undefined;
    const hits = session.findByLabel(class, test_label, &found) catch return;
    for (hits) |h| session.destroyObject(h) catch {};
}

/// Open a read/write session on a token that can create objects, or skip.
///
/// Three separate reasons to skip, each checked explicitly: no PIN was
/// supplied, the token is write-protected, or it refuses a read/write session.
/// Collapsing them would make a genuinely broken token look like a missing
/// configuration.
fn openWritableSession(mod: *pkcs11.Module) !pkcs11.Session {
    const pin = std.testing.environ.getPosix("ZCRYPTO_PKCS11_PIN") orelse
        return error.SkipZigTest;

    var slots: [16]pkcs11.SlotId = undefined;
    const list = try mod.slotsWithToken(&slots);
    const idx = slotIndex();
    if (idx >= list.len) return error.SkipZigTest;

    const info = try mod.tokenInfo(list[idx]);
    if (info.write_protected) return error.SkipZigTest;

    var session = try mod.openSessionOnSlot(list[idx], true);
    errdefer session.close();
    if (info.login_required or pin.len > 0) try session.login(pin);
    return session;
}

// =============================================================================
// Tier one — any conforming module
// =============================================================================

test "the module loads and reports its own Cryptoki version" {
    var mod = try openModule();
    defer mod.close();

    // Read from C_GetInfo rather than assumed. Every shipped module implements
    // 2.x or 3.x; a zero major would mean the struct was never filled.
    try testing.expect(mod.info.cryptoki_version.major >= 2);

    // Cryptoki pads these with spaces and does not terminate them. A non-empty
    // trimmed manufacturer proves the padding was actually stripped rather
    // than the field being read as a C string.
    try testing.expect(mod.info.manufacturerSlice().len > 0);
    try testing.expect(mod.info.manufacturerSlice()[mod.info.manufacturerSlice().len - 1] != ' ');
}

test "a path that is not a library is reported as an absent library" {
    _ = try modulePath(); // Skip in the same conditions as the rest of the suite.
    try testing.expectError(
        pkcs11.Pkcs11Error.LibraryAbsent,
        pkcs11.Module.open(.{ .module_path = "/nonexistent/zcrypto-not-a-module.so" }),
    );
}

test "a real shared object that is not a Cryptoki module is rejected as such" {
    _ = try modulePath();

    // libc is present on every host that can run this suite and exports no
    // C_GetFunctionList. This distinguishes "could not load" from "loaded but
    // is not a provider", which is the difference between a wrong path and a
    // wrong library.
    const candidates = [_][]const u8{
        "/usr/lib/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib64/libc.so.6",
    };

    for (candidates) |path| {
        const err = pkcs11.Module.open(.{ .module_path = path });
        if (err) |_| {
            return error.TestUnexpectedResult;
        } else |e| switch (e) {
            // The candidate is not on this host; try the next spelling.
            pkcs11.Pkcs11Error.LibraryAbsent => continue,
            pkcs11.Pkcs11Error.NotACryptokiModule => return,
            else => return e,
        }
    }
    return error.SkipZigTest;
}

test "slot enumeration uses the two-call size query and respects the buffer" {
    var mod = try openModule();
    defer mod.close();

    var slots: [16]pkcs11.SlotId = undefined;
    const list = try mod.slotsWithToken(&slots);
    try testing.expect(list.len > 0);

    // An undersized buffer must be refused, not silently truncated: a caller
    // that got a short list would conclude a token is absent.
    var tiny: [0]pkcs11.SlotId = undefined;
    try testing.expectError(pkcs11.Pkcs11Error.BufferTooSmall, mod.slotsWithToken(&tiny));
}

test "token information is read from the token, not inferred" {
    var mod = try openModule();
    defer mod.close();

    var slots: [16]pkcs11.SlotId = undefined;
    const list = try mod.slotsWithToken(&slots);
    const idx = slotIndex();
    try testing.expect(idx < list.len);

    const info = try mod.tokenInfo(list[idx]);
    try testing.expectEqual(list[idx], info.slot_id);
    try testing.expect(info.labelSlice().len > 0);
    // Trailing padding must be gone from every text field, not just the label.
    if (info.modelSlice().len > 0) {
        try testing.expect(info.modelSlice()[info.modelSlice().len - 1] != ' ');
    }
}

test "an out-of-range slot index is refused rather than wrapped" {
    var mod = try openModule();
    defer mod.close();

    try testing.expectError(
        pkcs11.Pkcs11Error.SlotNotFound,
        mod.openSession(.{ .module_path = "", .slot_index = 9999 }),
    );
}

test "mechanism support is asked of the token" {
    var mod = try openModule();
    defer mod.close();

    var slots: [16]pkcs11.SlotId = undefined;
    const list = try mod.slotsWithToken(&slots);
    const idx = slotIndex();
    try testing.expect(idx < list.len);

    var buf: [512]pkcs11.MechanismType = undefined;
    const list_of_mechs = try mod.mechanisms(list[idx], &buf);

    // A token may legitimately implement none — p11-kit-trust is a certificate
    // store. What must hold is that the answer to "do you support X" agrees
    // with the list the token just gave, for every X in it and for a value
    // that cannot be in it.
    for (list_of_mechs) |m| {
        try testing.expect(try mod.supportsMechanism(list[idx], m));
    }
    // 0xffff_ffff is in the vendor-defined range and is not a real mechanism.
    try testing.expect(!try mod.supportsMechanism(list[idx], 0xffff_ffff));
}

test "a read-only session opens, finds objects and closes" {
    var mod = try openModule();
    defer mod.close();

    var session = try mod.openSession(.{ .module_path = "", .slot_index = slotIndex() });
    defer session.close();

    // Counting exercises C_FindObjectsInit/C_FindObjects/C_FindObjectsFinal
    // including the batching loop. Zero is a valid answer; a token that never
    // called Final would fail the next search instead.
    const certs = try session.countObjects(pkcs11.object_class.certificate);
    const second = try session.countObjects(pkcs11.object_class.certificate);
    try testing.expectEqual(certs, second);
}

test "a write-protected token refuses to create a persistent key" {
    var mod = try openModule();
    defer mod.close();

    var slots: [16]pkcs11.SlotId = undefined;
    const list = try mod.slotsWithToken(&slots);
    const idx = slotIndex();
    try testing.expect(idx < list.len);

    const info = try mod.tokenInfo(list[idx]);
    // Only meaningful against a read-only token. On a writable one the
    // creation path is covered by the tier-two tests instead.
    if (!info.write_protected) return error.SkipZigTest;

    // A write-protected token may refuse at either of two points, and both are
    // conforming. p11-kit-trust refuses the read/write session outright; NSS
    // softoken grants the session and refuses only when an object would be
    // written to the token. Asserting the first behaviour alone made this test
    // fail against NSS, which was the test being wrong rather than the module.
    // What both must do — and what this asserts — is refuse somewhere before a
    // persistent key exists.
    var session = mod.openSessionOnSlot(list[idx], true) catch |err| {
        try testing.expectEqual(pkcs11.Pkcs11Error.ReadOnlyToken, err);
        return;
    };
    defer session.close();

    // A token that also demands a login would answer AuthorizationFailed first,
    // which says nothing about write protection. Skipping keeps this from
    // passing for the wrong reason.
    if (info.login_required) return error.SkipZigTest;

    const keys = session.generateEcdsaP256(test_label, true) catch |err| {
        try testing.expectEqual(pkcs11.Pkcs11Error.ReadOnlyToken, err);
        return;
    };

    // Reached only if the token contradicted its own flag. Remove the objects
    // before failing so the token is not left dirty for the next run.
    session.destroyObject(keys.private) catch {};
    session.destroyObject(keys.public) catch {};
    return error.WriteProtectedTokenCreatedAKey;
}

// =============================================================================
// Tier two — a token that permits key creation
// =============================================================================

test "an ECDSA P-256 key generated on the token signs verifiably" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    const kp = try session.generateEcdsaP256(test_label, false);
    defer session.destroyObject(kp.private) catch {};
    defer session.destroyObject(kp.public) catch {};

    // The point came from CKA_EC_POINT on the object the token created. If it
    // is not a valid P-256 point this fails here rather than at verification.
    const public = try kp.publicKey();

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("zcrypto pkcs11 integration", &digest, .{});

    const raw = try session.signDigest(kp.private, digest);

    // Verified by std.crypto, not by asking the token. A token that returned
    // 64 bytes of anything would pass a C_Verify round-trip against itself.
    const sig = Ecdsa.Signature.fromBytes(raw);
    try sig.verifyPrehashed(digest, public);

    // The token's own verifier is a separate assertion about the token.
    try session.verifyDigest(kp.public, digest, raw);

    // And the DER spelling of the same signature must still verify, which is
    // what a TLS or X.509 caller will actually hold.
    var der: [pkcs11.max_der_signature_len]u8 = undefined;
    const n = try pkcs11.derFromRaw(raw, &der);
    var back: [64]u8 = undefined;
    try pkcs11.rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}

test "the token reports a signature buffer size that a signature fits in" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    const kp = try session.generateEcdsaP256(test_label, false);
    defer session.destroyObject(kp.private) catch {};
    defer session.destroyObject(kp.public) catch {};

    // The size-query convention applied to C_Sign. The spec permits the answer
    // to be an upper bound rather than the exact length, and NSS softoken uses
    // that latitude: it reports 144 for a P-256 key whose signatures are 64
    // bytes. So the property is that the answer is a safe buffer size, not that
    // it equals 64 — asserting equality tested this module's assumption rather
    // than the token's contract.
    const reported = try session.signatureLength(kp.private);
    try testing.expect(reported >= 64);

    // And it is genuinely usable as a buffer size: the real signature fits.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("sized by the token", &digest, .{});
    const raw = try session.signDigest(kp.private, digest);
    try testing.expect(raw.len <= reported);
}

test "a signature over a different digest does not verify" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    const kp = try session.generateEcdsaP256(test_label, false);
    defer session.destroyObject(kp.private) catch {};
    defer session.destroyObject(kp.public) catch {};

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("the signed message", &digest, .{});
    const raw = try session.signDigest(kp.private, digest);

    var other: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("a different message", &other, .{});

    // A suite that only ever checks the positive case cannot tell a working
    // verifier from one that returns success unconditionally.
    try testing.expectError(
        pkcs11.Pkcs11Error.SignatureInvalid,
        session.verifyDigest(kp.public, other, raw),
    );
}

test "a token key is reopened by label in a later session" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    // Closed explicitly below rather than by `defer`: the session must be gone
    // before the second one opens, and a `defer` as well would close the same
    // handle twice. `errdefer` still covers the paths that fail before then.
    errdefer session.close();

    // A token object this time: handles are session-scoped, labels are not,
    // which is the property under test.
    const kp = try session.generateEcdsaP256(test_label, true);
    const exported = kp.public_sec1;
    session.close();

    var reopened = try openWritableSession(&mod);
    defer reopened.close();

    // The handles from the first session cannot be used to clean up here, for
    // the same reason the test exists. Removal goes by label instead.
    defer destroyByLabel(&reopened, pkcs11.object_class.private_key);
    defer destroyByLabel(&reopened, pkcs11.object_class.public_key);

    var found: [8]pkcs11.ObjectHandle = undefined;
    const hits = try reopened.findByLabel(pkcs11.object_class.public_key, test_label, &found);
    try testing.expect(hits.len >= 1);

    // Identity is checked on the key material, not on the handle value, which
    // is meaningless across sessions.
    var matched = false;
    for (hits) |h| {
        const point = reopened.readPublicPoint(h) catch continue;
        if (std.mem.eql(u8, &point, &exported)) matched = true;
    }
    try testing.expect(matched);
}

test "a destroyed key is gone rather than merely unreferenced" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    const before = try session.countObjects(pkcs11.object_class.public_key);

    const kp = try session.generateEcdsaP256(test_label, true);
    try testing.expectEqual(before + 1, try session.countObjects(pkcs11.object_class.public_key));

    try session.destroyObject(kp.private);
    try session.destroyObject(kp.public);
    try testing.expectEqual(before, try session.countObjects(pkcs11.object_class.public_key));
}

test "the private key is not extractable from the token" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    const kp = try session.generateEcdsaP256(test_label, false);
    defer session.destroyObject(kp.private) catch {};
    defer session.destroyObject(kp.public) catch {};

    // CKA_SENSITIVE and CKA_EXTRACTABLE are set at generation. This asserts
    // the token honoured them: an HSM whose keys can be read back is not
    // providing what it is used for.
    try testing.expect(try session.readBoolAttribute(kp.private, 0x0103)); // CKA_SENSITIVE
    try testing.expect(!try session.readBoolAttribute(kp.private, 0x0162)); // CKA_EXTRACTABLE
}

test "token AES-GCM round-trips and rejects a tampered tag" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    const key = session.generateAesKey(32, test_label, false) catch |err| switch (err) {
        // A token with no AES-GCM says so; that is a capability fact, not a
        // failure of this code.
        pkcs11.Pkcs11Error.UnsupportedMechanism => return error.SkipZigTest,
        else => return err,
    };
    defer session.destroyObject(key) catch {};

    var iv: [12]u8 = undefined;
    try session.getRandom(&iv);

    const aad = "zcrypto-aad";
    const plaintext = "attack at dawn, or possibly not";

    var ct_buf: [128]u8 = undefined;
    const ct = session.aesGcmEncrypt(key, &iv, aad, plaintext, &ct_buf) catch |err| switch (err) {
        pkcs11.Pkcs11Error.UnsupportedMechanism => return error.SkipZigTest,
        else => return err,
    };

    // GCM appends a 16-byte tag; anything shorter means the tag was dropped.
    try testing.expectEqual(plaintext.len + 16, ct.len);

    var pt_buf: [128]u8 = undefined;
    const pt = try session.aesGcmDecrypt(key, &iv, aad, ct, &pt_buf);
    try testing.expectEqualStrings(plaintext, pt);

    // Flipping a tag bit must fail. Without this the round-trip proves only
    // that the two calls are inverses, which is also true of a no-op.
    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..ct.len], ct);
    tampered[ct.len - 1] ^= 0x01;
    try testing.expectError(
        pkcs11.Pkcs11Error.SignatureInvalid,
        session.aesGcmDecrypt(key, &iv, aad, tampered[0..ct.len], &pt_buf),
    );

    // Changing the AAD must fail for the same reason, and covers the separate
    // pAAD path rather than the ciphertext one.
    try testing.expectError(
        pkcs11.Pkcs11Error.SignatureInvalid,
        session.aesGcmDecrypt(key, &iv, "different-aad", ct, &pt_buf),
    );
}

test "a wrong PIN is refused" {
    var mod = try openModule();
    defer mod.close();

    var slots: [16]pkcs11.SlotId = undefined;
    const list = try mod.slotsWithToken(&slots);
    const idx = slotIndex();
    if (idx >= list.len) return error.SkipZigTest;

    const info = try mod.tokenInfo(list[idx]);
    if (!info.login_required) return error.SkipZigTest;

    var session = try mod.openSessionOnSlot(list[idx], false);
    defer session.close();

    // Deliberately not retried: repeated failures lock a real token, so this
    // runs once and only against a token the operator pointed the suite at.
    try testing.expectError(
        pkcs11.Pkcs11Error.AuthorizationFailed,
        session.login("this-is-not-the-pin"),
    );
}

test "an operation on a key that does not exist is refused" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    // A handle the token never issued. Object handles are token-assigned, so
    // there is no value guaranteed invalid; this one is chosen to be far
    // outside any plausible allocation, and the test asserts only that the
    // token refuses rather than which refusal it picks.
    const bogus: pkcs11.ObjectHandle = std.math.maxInt(pkcs11.ObjectHandle) - 1;

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("signed with a key that is not there", &digest, .{});

    if (session.signDigest(bogus, digest)) |_| {
        return error.TokenSignedWithAMissingKey;
    } else |_| {}
}

test "objects in a closed session are gone from the token's view of it" {
    var mod = try openModule();
    defer mod.close();

    // Using a `Session` after `close` is a programming error, not a runtime
    // one: `close` sets the struct to `undefined`, so a later call reads
    // poisoned memory and traps in a safe build. That is deliberate, and it is
    // not what this test asserts — there is no way to assert on undefined
    // behaviour. What is observable, and what matters, is the token's side of
    // session lifetime: a session object does not outlive its session.
    var first = try openWritableSession(&mod);
    const kp = try first.generateEcdsaP256(test_label, false);
    const exported = kp.public_sec1;
    first.close();

    var second = try openWritableSession(&mod);
    defer second.close();

    var found: [8]pkcs11.ObjectHandle = undefined;
    const hits = try second.findByLabel(pkcs11.object_class.public_key, test_label, &found);
    for (hits) |h| {
        const point = second.readPublicPoint(h) catch continue;
        if (std.mem.eql(u8, &point, &exported)) return error.SessionObjectOutlivedItsSession;
    }
}

test "a mechanism the key cannot be used with is refused as unsupported" {
    var mod = try openModule();
    defer mod.close();

    var session = try openWritableSession(&mod);
    defer session.close();

    // An AES key is a real, valid object; ECDSA over it is a real, valid
    // mechanism. Only the pairing is impossible, which is what makes this a
    // clean probe of the mechanism-rejection path: nothing else about the call
    // is wrong, so any other error would be the backend misreporting.
    const key = session.generateAesKey(32, test_label, false) catch |err| switch (err) {
        pkcs11.Pkcs11Error.UnsupportedMechanism => return error.SkipZigTest,
        else => return err,
    };
    defer session.destroyObject(key) catch {};

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ECDSA over an AES key", &digest, .{});

    try testing.expectError(
        pkcs11.Pkcs11Error.UnsupportedMechanism,
        session.signDigest(key, digest),
    );
}

// =============================================================================
// Tier three — `hsm.PKCS11Provider` over the same live token
//
// The tests above drive the backend directly. These drive the provider layer,
// which is what callers actually use: it is where key references, the epoch and
// kind checks, the concurrency guard and the capability reporting live, and
// none of that is exercised by testing the backend underneath it.
// =============================================================================

/// A TCTI that cannot resolve to a device, so an `HSMInterface` built for a
/// PKCS#11 assertion is not also opening whatever TPM this host happens to have.
const no_tpm = "device:/nonexistent/zcrypto-pkcs11-suite";

fn providerConfig() !hsm.PKCS11Provider.Config {
    return .{
        .module_path = try modulePath(),
        .slot_index = slotIndex(),
        .module_config = moduleConfig(),
        .pin = std.testing.environ.getPosix("ZCRYPTO_PKCS11_PIN"),
        .key_label = test_label,
    };
}

/// A provider on a token that can create objects, or a skip.
///
/// The token is probed through the backend and that module is closed before the
/// provider opens its own: two live `C_Initialize` calls on one module in one
/// process is the case Cryptoki answers with `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
fn openProvider() !hsm.PKCS11Provider {
    const config = try providerConfig();
    if (config.pin == null) return error.SkipZigTest;

    {
        var mod = try openModule();
        defer mod.close();

        var slots: [16]pkcs11.SlotId = undefined;
        const list = try mod.slotsWithToken(&slots);
        const idx = slotIndex();
        if (idx >= list.len) return error.SkipZigTest;
        if ((try mod.tokenInfo(list[idx])).write_protected) return error.SkipZigTest;
    }

    var provider = hsm.PKCS11Provider.init(config);
    if (!provider.status.isReady()) {
        // Not a skip, and the block above is why: `openModule` already loaded
        // this module, found the slot and confirmed the token is writable. The
        // environment is therefore known good, so a provider that still will
        // not open is a defect in the provider layer, and skipping would file
        // that defect as "nothing to test here".
        std.debug.print(
            "PKCS11Provider.init(\"{s}\") is not ready: {s}\n",
            .{ config.module_path, @tagName(std.meta.activeTag(provider.status)) },
        );
        provider.deinit();
        return error.ProviderNotReady;
    }
    return provider;
}

test "a provider with no module named says so, rather than looking absent" {
    // `not_configured` and `library_absent` send an operator to different
    // places: one to supply a path, the other to install a file. This is the
    // case the old implementation could not express, because it decided
    // availability by calling `access()` on a path.
    var provider = hsm.PKCS11Provider.init(.{ .module_path = "" });
    defer provider.deinit();

    try testing.expect(!provider.status.isReady());
    try testing.expect(std.meta.activeTag(provider.status) == .not_configured);

    var buf: [16]u8 = @splat(0xAA);
    try testing.expectError(hsm.HSMError.ProviderNotConfigured, provider.getRandom(&buf));
}

test "a named path that is not a Cryptoki module is not a usable provider" {
    if (!pkcs11.is_real_backend) return error.SkipZigTest;

    // The file exists — it is this test binary's own libc — so a check that
    // asks only whether the path exists would call this provider available.
    var provider = hsm.PKCS11Provider.init(.{ .module_path = "/usr/lib/libc.so.6" });
    defer provider.deinit();

    try testing.expect(!provider.status.isReady());
    var buf: [16]u8 = @splat(0xAA);
    try testing.expectError(hsm.HSMError.LibraryAbsent, provider.getRandom(&buf));
}

test "a software token is never reported as hardware-backed" {
    // The requirement this exists for: a software token proves the PKCS#11
    // integration and proves nothing about physical key protection, so the
    // capability output has to keep the two apart. `hardware_token` is left at
    // its default, which is the honest answer for every token this suite can
    // reach.
    {
        var provider = try openProvider();
        defer provider.deinit();

        try testing.expectEqual(hsm.Backing.software_token, provider.backing);

        const key = try provider.generateSigningKey();
        defer provider.destroyKey(key) catch {};
        try testing.expectEqual(hsm.Backing.software_token, key.properties.backing);

        // The token will happily generate bytes when asked by name.
        var buf: [16]u8 = @splat(0xAA);
        try provider.getRandom(&buf);
    }

    // And through the unified interface, which is where a caller reads it. The
    // provider above is closed first: one live `C_Initialize` per module per
    // process, so the interface has to be the only holder while it runs.
    var iface = hsm.HSMInterface.init(.{
        .tpm = .{ .tcti = no_tpm },
        .pkcs11 = try providerConfig(),
    });
    defer iface.deinit();

    const caps = iface.capabilities();
    try testing.expect(caps.has_pkcs11);
    try testing.expect(caps.has_token_signing);
    try testing.expect(!caps.has_hardware_backed_keys);
    try testing.expect(!caps.has_hardware_rng);

    // The refusal is the same point made from the other side: the same bytes
    // the provider just handed over are declined here, because this entry point
    // promises hardware entropy and a software token is not that.
    var buf: [16]u8 = @splat(0xAA);
    try testing.expectError(hsm.HSMError.DeviceAbsent, iface.getHardwareRandom(&buf));
}

test "the provider's signature verifies under an independent implementation" {
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey();
    defer provider.destroyKey(key) catch {};

    // Non-extractable is read back from the created object, not assumed.
    try testing.expect(!key.properties.extractable);
    try testing.expect(!key.properties.persistent);

    const point = try provider.exportPublicKey(key);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("provider-layer signing", &digest, .{});

    const sig = try provider.signDigest(key, digest);

    // `std.crypto`, not the token, decides whether the signature is good.
    // Prehashed: `signDigest` signed this digest, so a plain `verify` would
    // hash it a second time and reject a correct signature.
    const pub_key = try Ecdsa.PublicKey.fromSec1(&point);
    try Ecdsa.Signature.fromBytes(sig).verifyPrehashed(digest, pub_key);

    // `C_Verify` is asserted separately, as a statement about the token rather
    // than as the proof that signing worked.
    try provider.verifyDigest(key, digest, sig);

    var wrong = digest;
    wrong[0] ^= 0x01;
    try testing.expectError(
        hsm.HSMError.VerificationFailed,
        provider.verifyDigest(key, wrong, sig),
    );
}

test "the provider round-trips AES-GCM and rejects a tampered tag" {
    var provider = try openProvider();
    defer provider.deinit();

    if (!provider.status.supports(.authenticated_encryption)) return error.SkipZigTest;

    const key = try provider.generateAeadKey();
    defer provider.destroyKey(key) catch {};
    try testing.expectEqual(hsm.KeyKind.aes_256, key.kind);

    var iv: [12]u8 = undefined;
    try provider.getRandom(&iv);

    const aad = "provider-aad";
    const plaintext = "held by the token, not by the caller";

    var ct_buf: [128]u8 = undefined;
    const ct = try provider.authenticatedEncrypt(key, &iv, aad, plaintext, &ct_buf);
    try testing.expectEqual(plaintext.len + 16, ct.len);

    var pt_buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        plaintext,
        try provider.authenticatedDecrypt(key, &iv, aad, ct, &pt_buf),
    );

    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..ct.len], ct);
    tampered[ct.len - 1] ^= 0x01;
    try testing.expectError(
        hsm.HSMError.VerificationFailed,
        provider.authenticatedDecrypt(key, &iv, aad, tampered[0..ct.len], &pt_buf),
    );
}

test "a key reference is refused for the wrong kind of operation" {
    var provider = try openProvider();
    defer provider.deinit();

    if (!provider.status.supports(.authenticated_encryption)) return error.SkipZigTest;

    const signing = try provider.generateSigningKey();
    defer provider.destroyKey(signing) catch {};
    const aead = try provider.generateAeadKey();
    defer provider.destroyKey(aead) catch {};

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("wrong kind", &digest, .{});

    // Without the kind check these would reach the token holding the other
    // object's handle, and the answer would depend on what the token made of it.
    try testing.expectError(
        hsm.HSMError.UnsupportedMechanism,
        provider.signDigest(aead, digest),
    );
    var out: [64]u8 = undefined;
    const iv: [12]u8 = @splat(0);
    try testing.expectError(
        hsm.HSMError.UnsupportedMechanism,
        provider.authenticatedEncrypt(signing, &iv, "", "x", &out),
    );
}

test "a second provider on a module this process already holds is refused" {
    // Cryptoki allows one live `C_Initialize` per module per process. The
    // second provider must say so in a way that names the caller's own program
    // as the cause, because `initialization_failed` would send an operator to
    // inspect a module that is working correctly.
    var first = try openProvider();
    defer first.deinit();

    var second = hsm.PKCS11Provider.init(try providerConfig());
    defer second.deinit();

    try testing.expect(!second.status.isReady());
    try testing.expect(std.meta.activeTag(second.status) == .already_initialized);

    var buf: [16]u8 = @splat(0xAA);
    try testing.expectError(hsm.HSMError.ProviderAlreadyOpen, second.getRandom(&buf));

    // The first provider is untouched by the second's failure: the refusal is
    // the point, and a refused open that finalized the module on its way out
    // would take the working provider down with it.
    try first.getRandom(&buf);
}

test "a key reference from a previous provider instance is refused" {
    var key: hsm.KeyRef = undefined;
    {
        var a = try openProvider();
        defer a.deinit();
        key = try a.generateSigningKey();
        try a.destroyKey(key);
    }

    // `b` reuses slot 0 of its own table, so the numeric handle in `key` is a
    // live index there. Only the epoch distinguishes the instances, which is
    // the whole reason it is stamped into the reference.
    var b = try openProvider();
    defer b.deinit();
    const fresh = try b.generateSigningKey();
    defer b.destroyKey(fresh) catch {};
    try testing.expectEqual(key.native, fresh.native);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("cross-provider", &digest, .{});
    try testing.expectError(hsm.HSMError.StaleKeyReference, b.signDigest(key, digest));
    try testing.expectError(hsm.HSMError.StaleKeyReference, b.exportPublicKey(key));
    try testing.expectError(hsm.HSMError.StaleKeyReference, b.destroyKey(key));
}

test "a destroyed reference is not resolved again" {
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey();
    try provider.destroyKey(key);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("already gone", &digest, .{});
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.signDigest(key, digest));
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.exportPublicKey(key));
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.destroyKey(key));
}

test "a stale reference does not authorize the key that reused its slot" {
    // The test above destroys a key and finds the slot empty, which the `used`
    // flag alone catches. This is the case that flag cannot catch: the slot is
    // occupied again, by a different key, and before keys were given issuance
    // numbers the stale reference was byte-identical to the live one. The TPM
    // counterpart of this test got a valid signature out of the replacement.
    var provider = try openProvider();
    defer provider.deinit();

    const first = try provider.generateSigningKey();
    const first_public = try provider.exportPublicKey(first);
    try provider.destroyKey(first);

    const second = try provider.generateSigningKey();
    defer provider.destroyKey(second) catch {};

    // The slot really was reused, so the refusals below cannot be passing for
    // the trivial reason that the two keys landed at different indices.
    try testing.expectEqual(first.native, second.native);

    // And they really are different keys, so a refusal is a refusal rather than
    // an operation that would have succeeded identically either way.
    const second_public = try provider.exportPublicKey(second);
    try testing.expect(!std.mem.eql(u8, &first_public, &second_public));

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("aimed at a slot, not a key", &digest, .{});
    try testing.expectError(hsm.HSMError.StaleKeyReference, provider.signDigest(first, digest));
    try testing.expectError(hsm.HSMError.StaleKeyReference, provider.exportPublicKey(first));
    try testing.expectError(hsm.HSMError.StaleKeyReference, provider.destroyKey(first));

    // The live key is unharmed by the refusals aimed at its slot.
    _ = try provider.signDigest(second, digest);
}

test "a stale reference does not destroy a key of another kind in its slot" {
    // `destroyKey` accepts every key kind, so it does not go through `resolve`
    // and re-checks the reference itself. That duplication is where an identity
    // check is most easily left out, and destruction is the one operation whose
    // damage cannot be undone by noticing later.
    var provider = try openProvider();
    defer provider.deinit();

    if (!provider.status.supports(.authenticated_encryption)) return error.SkipZigTest;

    const signing = try provider.generateSigningKey();
    try provider.destroyKey(signing);

    const aead = try provider.generateAeadKey();
    defer provider.destroyKey(aead) catch {};
    try testing.expectEqual(signing.native, aead.native);

    try testing.expectError(hsm.HSMError.StaleKeyReference, provider.destroyKey(signing));

    // Still usable, which is the property the refusal was protecting.
    var iv: [12]u8 = undefined;
    try provider.getRandom(&iv);
    var ct_buf: [64]u8 = undefined;
    _ = try provider.authenticatedEncrypt(aead, &iv, "", "survived", &ct_buf);
}

test "a deletion that fails leaves the key intact and retryable" {
    // The provider used to release the slot whichever way the token answered,
    // so this call reported failure while having already forgotten the only
    // handles that could finish the job. What is asserted here is the opposite:
    // failure changed nothing, and the caller still holds a working key.
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey();
    const public_before = try provider.exportPublicKey(key);

    pkcs11.failDestroyForTesting(1);
    defer pkcs11.clearDestroyFailureForTesting();
    try testing.expectError(hsm.HSMError.OperationFailed, provider.destroyKey(key));

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("still mine", &digest, .{});
    _ = try provider.signDigest(key, digest);
    try testing.expectEqualSlices(u8, &public_before, &(try provider.exportPublicKey(key)));

    // And the retry completes, rather than the key being stuck undeletable.
    try provider.destroyKey(key);
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.signDigest(key, digest));
}

test "a deletion that fails halfway resumes rather than restarting" {
    // Destroying a key pair is two token operations. With the second failing,
    // the private object is already gone: the key cannot work, but the public
    // object is still on the token and something must remain able to remove it.
    // Retrying must not re-attempt the private half either -- that object no
    // longer exists, so a retry that started over would fail forever and strand
    // the public object with nothing pointing at it.
    var provider = try openProvider();
    defer provider.deinit();

    const key = try provider.generateSigningKey();

    pkcs11.failDestroyForTesting(2);
    defer pkcs11.clearDestroyFailureForTesting();
    try testing.expectError(hsm.HSMError.OperationFailed, provider.destroyKey(key));

    // The private half really did go, so the key is not usable even though the
    // reference is still held open for the retry.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("half gone", &digest, .{});
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.signDigest(key, digest));

    // The retry removes what is left and releases the slot.
    try provider.destroyKey(key);
    try testing.expectError(hsm.HSMError.KeyNotFound, provider.destroyKey(key));
}

test "the provider's key table has a bound, and reports reaching it" {
    var provider = try openProvider();
    defer provider.deinit();

    var made: [hsm.PKCS11Provider.max_keys]hsm.KeyRef = undefined;
    var count: usize = 0;
    defer for (made[0..count]) |k| provider.destroyKey(k) catch {};

    const stopped_on = while (count < made.len) {
        made[count] = provider.generateSigningKey() catch |err| break err;
        count += 1;
    } else provider.generateSigningKey() catch |err| err;

    // Either the token ran out of room first or this table did. Both are
    // reported, and a caller's remedy — free a key — is the same for each.
    try testing.expectEqual(hsm.HSMError.KeyTableFull, stopped_on);
}

test "concurrent use of one provider is reported rather than corrupting it" {
    var provider = try openProvider();
    defer provider.deinit();

    // Claiming the guard directly is what a second thread mid-operation looks
    // like from here, without the flakiness of actually racing one.
    provider.busy.store(true, .release);
    defer provider.busy.store(false, .release);

    var buf: [16]u8 = undefined;
    try testing.expectError(hsm.HSMError.ConcurrentUse, provider.getRandom(&buf));
}
