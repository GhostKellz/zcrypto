//! Real Apple Secure Enclave backend, built on Security.framework's `SecKey`
//! API.
//!
//! This module talks to an actual Secure Enclave Processor. It is compiled only
//! when the build is configured with `-Dsecure-enclave=true` on a macOS target,
//! which links `Security` and `CoreFoundation`. The dependency is opt-in
//! precisely so an ordinary zcrypto build stays free of Apple framework
//! requirements; when the flag is off, `hsm.zig` uses `secure_enclave_absent.zig`
//! instead and every entry point reports the backend as not built.
//!
//! What the enclave will and will not do, stated once here because the
//! constraints are unusually tight and shape the whole API:
//!   - NIST P-256 only. There is no other curve, no RSA, no Ed25519, and no
//!     symmetric key storage. Anything else is `UnsupportedMechanism`.
//!   - The private scalar never leaves the enclave. It has no representation in
//!     this module: `EnclaveKey` holds a `SecKeyRef`, which is a reference to a
//!     key the enclave holds, and nothing here can export it. That is why
//!     `SecKeyCopyExternalRepresentation` is only ever called on the *public*
//!     key.
//!   - A key is created for signing or for key agreement, never both. The
//!     enclave enforces this, so the choice is recorded on the handle and
//!     checked before the call rather than discovered as an opaque failure.
//!
//! The single invariant this module exists to hold:
//!
//!   **A key is reported as enclave-backed only if the enclave says it is.**
//!
//! `kSecAttrTokenIDSecureEnclave` is a *request*. Security.framework is within
//! its rights to hand back an ordinary software key, and on some
//! configurations it does. A backend that returned that key would be claiming
//! hardware protection it does not have — the worst possible failure for this
//! module, because everything downstream still works and nothing looks wrong.
//! So `createKey` reads `kSecAttrTokenID` back off the created key and refuses
//! with `NotEnclaveBacked` unless it is the enclave's token. There is no
//! fallback path and no option to disable the check; see
//! `attributesReportEnclaveResidency`, which is tested directly.

const std = @import("std");
const c = @import("security");
const ecdsa_sig = @import("ecdsa_sig");

/// See `secure_enclave_absent.is_real_backend`. Both backends declare it so a
/// caller can tell which one it was compiled against without a build-option
/// import.
pub const is_real_backend = true;

/// Errors distinguish *why* the enclave is unusable. The distinctions that
/// matter most are the first three: hardware that does not exist, a key that
/// turned out not to be enclave-backed, and a binary that is not entitled to
/// ask. All three would collapse into "unavailable" under a coarser set, and
/// all three call for different action.
pub const SecureEnclaveError = error{
    /// This Mac has no Secure Enclave. Every pre-T2 Intel Mac is in this state
    /// and is behaving correctly; the answer is different hardware, not repair.
    EnclaveAbsent,
    /// A key was created but did not read back as enclave-resident. The key has
    /// already been destroyed by the time this is returned. Never suppress
    /// this: the software key it refers to would have worked perfectly while
    /// providing none of the protection the caller asked for.
    NotEnclaveBacked,
    /// The process lacks the code signature or keychain entitlement needed to
    /// use the enclave. Distinct from `EnclaveAbsent` because the hardware is
    /// present and fine; an unsigned command-line binary hits this routinely.
    NotEntitled,
    /// The access-control policy could not be constructed, e.g. a
    /// biometry-bound policy on a device with no enrolled biometry.
    AccessControlRejected,
    /// The user failed to authenticate.
    AuthorizationFailed,
    /// The user dismissed the authentication prompt.
    UserCanceled,
    /// The key needs user authentication and this process cannot present a
    /// prompt. A daemon or a `ssh` session sees this, not a fault.
    InteractionRequired,
    /// The enclave does not implement what was asked: a curve other than
    /// P-256, or an operation the key was not created for.
    UnsupportedMechanism,
    /// No key in the keychain carries the requested tag.
    KeyNotFound,
    /// A persistent key with that tag already exists.
    DuplicateKey,
    /// Key generation failed for a reason the error mapping did not recognise.
    KeyCreationFailed,
    SignatureFailed,
    KeyAgreementFailed,
    /// Security.framework returned something structurally wrong: a public
    /// point that is not 65 uncompressed SEC1 bytes, a signature that is not
    /// valid DER, a shared secret of the wrong length.
    MalformedResponse,
    /// The key came from a different `Enclave` instance than the one it was
    /// used against. Handles do not survive `close`.
    StaleKeyReference,
    CommandFailed,
    /// Never returned by this module. Declared so that this error set and
    /// `secure_enclave_absent.SecureEnclaveError` are identical, which lets
    /// `hsm.zig` handle one error union across both backends.
    BackendNotBuilt,
    OutOfMemory,
};

/// What the enclave key is allowed to do. The enclave enforces this: a key
/// created for agreement cannot be talked into signing later, so the choice is
/// made once, at creation, and recorded on the handle.
pub const KeyUsage = enum { signing, key_agreement };

/// How the private key is protected at use time.
pub const Protection = enum {
    /// Usable whenever the device is unlocked, with no per-use prompt.
    device_unlocked,
    /// Each use requires the user to authenticate (Touch ID, Watch, or
    /// passcode). Non-interactive callers get `InteractionRequired`.
    user_presence,
};

pub const Config = struct {
    /// Application tag for the throwaway key `open` creates to prove the
    /// enclave answers. Never persisted.
    probe_tag: []const u8 = "dev.zcrypto.enclave.probe",
};

pub const KeySpec = struct {
    /// Application tag bytes, used to find a persistent key again. Opaque to
    /// the enclave; the keychain compares it byte for byte.
    tag: []const u8,
    usage: KeyUsage,
    /// Store the key in the keychain so a later process can find it by tag.
    /// A non-persistent key is gone once its handle is released.
    persistent: bool = false,
    protection: Protection = .device_unlocked,
};

/// An enclave-resident key. `private` is a reference to a key inside the
/// enclave, not the key: there is no field here that could hold the private
/// scalar, because no API in Security.framework will produce it.
pub const EnclaveKey = struct {
    private: c.SecKeyRef,
    /// Bound to the `Enclave` that created it, so a handle cannot be replayed
    /// against a later instance after the first was closed.
    session_epoch: u64,
    /// Uncompressed SEC1 public point (0x04 || X || Y) for NIST P-256, the
    /// only curve the enclave implements.
    public_sec1: [65]u8,
    usage: KeyUsage,

    pub fn publicKey(self: EnclaveKey) !std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&self.public_sec1);
    }
};

// =============================================================================
// CoreFoundation plumbing
//
// Every Security.framework call traffics in CF objects, which are manually
// reference counted under the "Create/Copy means you own it" rule. These
// helpers exist so the ownership shows up as a `defer` next to the acquisition
// instead of as a hand-audited release at each exit.
// =============================================================================

/// Erases a concrete CF pointer type to `CFTypeRef`. Every dictionary key,
/// dictionary value and `CFEqual` operand needs this, and spelling out
/// `@ptrCast` at each of the several dozen call sites buries the logic.
inline fn cf(value: anytype) c.CFTypeRef {
    return @ptrCast(value);
}

/// Drops a reference acquired from a Create/Copy call.
///
/// Accepts both the optional CF pointer types as translate-c spells them and
/// the non-optional pointers that fall out of an `orelse` unwrap, so the
/// `defer` can sit next to the acquisition either way. Null-tolerant because
/// the failure paths release whatever they managed to build.
inline fn release(object: anytype) void {
    if (comptime @typeInfo(@TypeOf(object)) == .optional) {
        if (object) |p| c.CFRelease(@ptrCast(p));
    } else {
        c.CFRelease(@ptrCast(object));
    }
}

/// Consumes a `CFErrorRef` out-parameter, releasing it and translating its code
/// into this module's error set.
///
/// Taking a pointer rather than the value is deliberate: the error is always
/// released here, so there is no path on which a caller can forget. `fallback`
/// is what a caller means by "this call failed and the error told me nothing
/// more specific".
fn takeError(err: *c.CFErrorRef, fallback: SecureEnclaveError) SecureEnclaveError {
    const e = err.* orelse return fallback;
    const code = c.CFErrorGetCode(e);
    c.CFRelease(@ptrCast(e));
    err.* = null;
    return mapOsStatus(code, fallback);
}

/// Translates an `OSStatus`-valued code into this module's error set.
///
/// Split out from `takeError` so the `SecItem*` functions, which return an
/// `OSStatus` directly rather than a `CFErrorRef`, produce the same answers for
/// the same conditions.
fn mapOsStatus(code: i64, fallback: SecureEnclaveError) SecureEnclaveError {
    return switch (code) {
        c.errSecUnimplemented, c.errSecNotAvailable => error.EnclaveAbsent,
        c.errSecMissingEntitlement => error.NotEntitled,
        c.errSecUserCanceled => error.UserCanceled,
        c.errSecAuthFailed => error.AuthorizationFailed,
        c.errSecInteractionNotAllowed => error.InteractionRequired,
        c.errSecItemNotFound => error.KeyNotFound,
        c.errSecDuplicateItem => error.DuplicateKey,
        c.errSecParam => error.UnsupportedMechanism,
        c.errSecDecode => error.MalformedResponse,
        // LocalAuthentication reports through the same `CFErrorRef` channel
        // with its own domain and a much smaller code space. `-2` is
        // `LAError.userCancel`, which reaches here whenever a per-use
        // authentication prompt is dismissed, and would otherwise surface as
        // an unexplained `SignatureFailed`.
        -2 => error.UserCanceled,
        else => fallback,
    };
}

fn dataFromSlice(bytes: []const u8) SecureEnclaveError!c.CFDataRef {
    return c.CFDataCreate(c.kCFAllocatorDefault, bytes.ptr, @intCast(bytes.len)) orelse
        error.OutOfMemory;
}

/// Copies a `CFData` payload into `out`, requiring an exact length match.
///
/// The length check is the point. A short public point or shared secret would
/// otherwise be copied into a fixed array over stale stack bytes and used as if
/// it were a full-length value.
fn copyExact(data: c.CFDataRef, out: []u8) SecureEnclaveError!void {
    const len = c.CFDataGetLength(data);
    if (len != @as(c.CFIndex, @intCast(out.len))) return error.MalformedResponse;
    const ptr = c.CFDataGetBytePtr(data) orelse return error.MalformedResponse;
    @memcpy(out, ptr[0..out.len]);
}

/// Builds an immutable CF dictionary from parallel key and value arrays.
///
/// `kCFTypeDictionary*CallBacks` makes the dictionary retain its contents, so
/// the caller still owns and must release everything it passed in.
fn makeDictionary(keys: []const c.CFTypeRef, values: []const c.CFTypeRef) SecureEnclaveError!c.CFDictionaryRef {
    std.debug.assert(keys.len == values.len);
    // `CFDictionaryCreate` declares its key and value arrays as `const void **`
    // — the *elements* are const, the array pointer is not — and translate-c
    // renders that as a mutable `[*c]`. The const here is this module's own,
    // and the function only reads through these pointers, so `@constCast` is
    // discarding a qualifier the C declaration never had.
    return c.CFDictionaryCreate(
        c.kCFAllocatorDefault,
        @ptrCast(@constCast(keys.ptr)),
        @ptrCast(@constCast(values.ptr)),
        @intCast(keys.len),
        &c.kCFTypeDictionaryKeyCallBacks,
        &c.kCFTypeDictionaryValueCallBacks,
    ) orelse error.OutOfMemory;
}

fn makeNumber(value: c_int) SecureEnclaveError!c.CFNumberRef {
    var v = value;
    return c.CFNumberCreate(c.kCFAllocatorDefault, @intCast(c.kCFNumberIntType), &v) orelse
        error.OutOfMemory;
}

// =============================================================================
// The residency check
// =============================================================================

/// Whether the enclave attests that the key described by `attrs` lives inside
/// it.
///
/// This is the whole safety property of the module, reduced to a pure function
/// of a dictionary so it can be tested without any enclave present — which is
/// what makes it testable at all, since the machines that would exercise the
/// true branch are exactly the machines where an incorrect answer is invisible.
///
/// A missing `kSecAttrTokenID` is false, not an error: that is precisely what a
/// software key looks like, and it is the case a fallback bug produces.
///
/// `CFEqual` and not pointer comparison. The returned attribute is a CFString
/// whose contents equal the constant's; whether it is the same object is an
/// implementation detail of Security.framework that this must not depend on.
fn attributesReportEnclaveResidency(attrs: c.CFDictionaryRef) bool {
    const token = c.CFDictionaryGetValue(attrs, cf(c.kSecAttrTokenID)) orelse return false;
    return c.CFEqual(token, cf(c.kSecAttrTokenIDSecureEnclave)) != 0;
}

// =============================================================================
// Enclave
// =============================================================================

/// Distinguishes one `Enclave` instance from the next so a key handle from a
/// closed instance is rejected instead of being used against a fresh one.
var epoch_counter: std.atomic.Value(u64) = .init(1);

pub const Enclave = struct {
    epoch: u64,

    /// Opens the enclave, proving it answers rather than assuming it does.
    ///
    /// The proof is a real key generation, discarded immediately. Checking
    /// `hw.optional.arm64` or the machine model would only describe what Apple
    /// shipped; generating a key is the same operation every later call
    /// depends on, performed under the same entitlements, so a host that gets
    /// past `open` has demonstrated the capability rather than advertised it.
    pub fn open(config: Config) SecureEnclaveError!Enclave {
        var enclave = Enclave{ .epoch = epoch_counter.fetchAdd(1, .monotonic) };

        var probe = try enclave.createKey(.{
            .tag = config.probe_tag,
            .usage = .signing,
            .persistent = false,
            .protection = .device_unlocked,
        });
        enclave.destroyKey(&probe);

        return enclave;
    }

    pub fn close(self: *Enclave) void {
        self.* = undefined;
    }

    /// Generates a P-256 key inside the enclave.
    ///
    /// Returns `NotEnclaveBacked`, having destroyed the key, if what came back
    /// is not enclave-resident. See the module comment.
    pub fn createKey(self: *Enclave, spec: KeySpec) SecureEnclaveError!EnclaveKey {
        const flags: c.SecAccessControlCreateFlags = switch (spec.protection) {
            .device_unlocked => c.kSecAccessControlPrivateKeyUsage,
            .user_presence => c.kSecAccessControlPrivateKeyUsage | c.kSecAccessControlUserPresence,
        };

        var err: c.CFErrorRef = null;
        // `WhenUnlockedThisDeviceOnly` rather than a backup-eligible class: an
        // enclave key cannot leave the device in any case, so a protection
        // class that implies it could would describe the wrong thing.
        const access = c.SecAccessControlCreateWithFlags(
            c.kCFAllocatorDefault,
            cf(c.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            flags,
            &err,
        ) orelse return takeError(&err, error.AccessControlRejected);
        defer release(access);

        const tag_data = try dataFromSlice(spec.tag);
        defer release(tag_data);

        const permanent = if (spec.persistent) c.kCFBooleanTrue else c.kCFBooleanFalse;
        const usage_key = switch (spec.usage) {
            .signing => c.kSecAttrCanSign,
            .key_agreement => c.kSecAttrCanDerive,
        };

        const private_attrs = try makeDictionary(
            &.{
                cf(c.kSecAttrIsPermanent),
                cf(c.kSecAttrApplicationTag),
                cf(c.kSecAttrAccessControl),
                cf(usage_key),
            },
            &.{
                cf(permanent),
                cf(tag_data),
                cf(access),
                cf(c.kCFBooleanTrue),
            },
        );
        defer release(private_attrs);

        const bits = try makeNumber(256);
        defer release(bits);

        const params = try makeDictionary(
            &.{
                cf(c.kSecAttrKeyType),
                cf(c.kSecAttrKeySizeInBits),
                cf(c.kSecAttrTokenID),
                cf(c.kSecPrivateKeyAttrs),
            },
            &.{
                cf(c.kSecAttrKeyTypeECSECPrimeRandom),
                cf(bits),
                cf(c.kSecAttrTokenIDSecureEnclave),
                cf(private_attrs),
            },
        );
        defer release(params);

        const private = c.SecKeyCreateRandomKey(params, &err) orelse
            return takeError(&err, error.KeyCreationFailed);
        errdefer release(private);

        try requireEnclaveResidency(private, spec);

        return .{
            .private = private,
            .session_epoch = self.epoch,
            .public_sec1 = try publicPoint(private),
            .usage = spec.usage,
        };
    }

    /// Looks up a previously created persistent key by its application tag.
    pub fn findKey(self: *Enclave, tag: []const u8, usage: KeyUsage) SecureEnclaveError!EnclaveKey {
        const tag_data = try dataFromSlice(tag);
        defer release(tag_data);

        const query = try makeDictionary(
            &.{
                cf(c.kSecClass),
                cf(c.kSecAttrApplicationTag),
                cf(c.kSecAttrKeyType),
                cf(c.kSecAttrKeyClass),
                cf(c.kSecReturnRef),
            },
            &.{
                cf(c.kSecClassKey),
                cf(tag_data),
                cf(c.kSecAttrKeyTypeECSECPrimeRandom),
                cf(c.kSecAttrKeyClassPrivate),
                cf(c.kCFBooleanTrue),
            },
        );
        defer release(query);

        var found: c.CFTypeRef = null;
        const status = c.SecItemCopyMatching(query, @ptrCast(&found));
        if (status != c.errSecSuccess) return mapOsStatus(status, error.KeyNotFound);
        const private: c.SecKeyRef = @ptrCast(@constCast(found orelse return error.KeyNotFound));
        errdefer release(private);

        // A key read back out of the keychain gets the same residency check as
        // a freshly created one. The keychain will happily store a software
        // key under the tag a caller expects to be an enclave key — by an
        // earlier buggy build, or by another program entirely.
        try requireEnclaveResidency(private, .{ .tag = tag, .usage = usage });

        return .{
            .private = private,
            .session_epoch = self.epoch,
            .public_sec1 = try publicPoint(private),
            .usage = usage,
        };
    }

    /// Signs a SHA-256 digest, returning the raw `r || s` pair.
    ///
    /// `DigestX962SHA256` and not a `Message` algorithm: the caller has already
    /// hashed, and the message variants would hash again.
    pub fn signDigest(self: *Enclave, key: EnclaveKey, digest: [32]u8) SecureEnclaveError![64]u8 {
        try self.checkKey(key, .signing);

        const digest_data = try dataFromSlice(&digest);
        defer release(digest_data);

        var err: c.CFErrorRef = null;
        const signature = c.SecKeyCreateSignature(
            key.private,
            c.kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
            digest_data,
            &err,
        ) orelse return takeError(&err, error.SignatureFailed);
        defer release(signature);

        const len: usize = @intCast(c.CFDataGetLength(signature));
        const ptr = c.CFDataGetBytePtr(signature) orelse return error.MalformedResponse;

        var raw: [64]u8 = undefined;
        ecdsa_sig.rawFromDer(ptr[0..len], &raw) catch return error.MalformedResponse;
        return raw;
    }

    /// Performs ECDH against a peer's public point, returning the raw X
    /// coordinate of the shared point.
    ///
    /// Raw, not a derived key: this is `ECDHKeyExchangeStandard`, so the result
    /// is the coordinate itself and callers must run it through a KDF. The
    /// enclave's `*CofactorX963SHA256` variants are deliberately not offered —
    /// a KDF hidden inside a hardware call is a KDF nobody can test against a
    /// vector.
    pub fn sharedSecret(self: *Enclave, key: EnclaveKey, peer_public_sec1: [65]u8) SecureEnclaveError![32]u8 {
        try self.checkKey(key, .key_agreement);
        if (peer_public_sec1[0] != 0x04) return error.MalformedResponse;

        // Parsing the peer point with the standard library first means a
        // malformed or off-curve point is rejected by code with known-answer
        // tests behind it, rather than handed to the enclave to judge.
        _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&peer_public_sec1) catch
            return error.MalformedResponse;

        const peer_data = try dataFromSlice(&peer_public_sec1);
        defer release(peer_data);

        const bits = try makeNumber(256);
        defer release(bits);

        const peer_attrs = try makeDictionary(
            &.{ cf(c.kSecAttrKeyType), cf(c.kSecAttrKeyClass), cf(c.kSecAttrKeySizeInBits) },
            &.{ cf(c.kSecAttrKeyTypeECSECPrimeRandom), cf(c.kSecAttrKeyClassPublic), cf(bits) },
        );
        defer release(peer_attrs);

        var err: c.CFErrorRef = null;
        const peer = c.SecKeyCreateWithData(peer_data, peer_attrs, &err) orelse
            return takeError(&err, error.MalformedResponse);
        defer release(peer);

        // `SecKeyCopyKeyExchangeResult` rejects a null parameter dictionary
        // even when the algorithm takes no parameters.
        const no_params = try makeDictionary(&.{}, &.{});
        defer release(no_params);

        const shared = c.SecKeyCopyKeyExchangeResult(
            key.private,
            c.kSecKeyAlgorithmECDHKeyExchangeStandard,
            peer,
            no_params,
            &err,
        ) orelse return takeError(&err, error.KeyAgreementFailed);
        defer release(shared);

        var out: [32]u8 = undefined;
        errdefer std.crypto.secureZero(u8, &out);
        try copyExact(shared, &out);
        return out;
    }

    /// Removes a persistent key from the keychain. The enclave destroys the
    /// private half; it is not recoverable afterwards.
    pub fn deleteKey(self: *Enclave, tag: []const u8) SecureEnclaveError!void {
        _ = self;
        const tag_data = try dataFromSlice(tag);
        defer release(tag_data);

        const query = try makeDictionary(
            &.{ cf(c.kSecClass), cf(c.kSecAttrApplicationTag), cf(c.kSecAttrKeyType) },
            &.{ cf(c.kSecClassKey), cf(tag_data), cf(c.kSecAttrKeyTypeECSECPrimeRandom) },
        );
        defer release(query);

        const status = c.SecItemDelete(query);
        if (status != c.errSecSuccess) return mapOsStatus(status, error.CommandFailed);
    }

    /// Releases the local reference to a key. A persistent key stays in the
    /// keychain; use `deleteKey` to remove it.
    pub fn destroyKey(self: *Enclave, key: *EnclaveKey) void {
        _ = self;
        release(key.private);
        key.* = undefined;
    }

    fn checkKey(self: *Enclave, key: EnclaveKey, want: KeyUsage) SecureEnclaveError!void {
        if (key.session_epoch != self.epoch) return error.StaleKeyReference;
        if (key.usage != want) return error.UnsupportedMechanism;
    }
};

/// Rejects a key that is not enclave-resident, erasing any persisted copy.
///
/// Does **not** release `private`. Both callers hold an `errdefer release` over
/// it from the moment they acquire it, so releasing here as well would be a
/// second `CFRelease` on the same object — on the one path where that is least
/// likely to be noticed, since it needs a host that actually hands back a
/// software key. Ownership stays with the caller for the whole of its
/// lifetime, which is the only arrangement that does not require reading this
/// function to know who frees what.
///
/// A persistent key is deleted from the keychain before the refusal, so a
/// later `findKey` cannot pick up what this call rejected. That deletion reads
/// `private`, which is why it happens here rather than after the caller's
/// `errdefer` has run.
fn requireEnclaveResidency(private: c.SecKeyRef, spec: KeySpec) SecureEnclaveError!void {
    const attrs = c.SecKeyCopyAttributes(private) orelse return error.NotEnclaveBacked;
    defer release(attrs);

    if (attributesReportEnclaveResidency(attrs)) return;

    if (spec.persistent) {
        const query = try makeDictionary(
            &.{ cf(c.kSecClass), cf(c.kSecValueRef) },
            &.{ cf(c.kSecClassKey), cf(private) },
        );
        defer release(query);
        _ = c.SecItemDelete(query);
    }
    return error.NotEnclaveBacked;
}

/// Exports the public half as an uncompressed SEC1 point.
///
/// Only ever called on the public key. `SecKeyCopyExternalRepresentation` on an
/// enclave private key fails by design, and if it ever stopped failing, this
/// module still would not be the thing that called it.
fn publicPoint(private: c.SecKeyRef) SecureEnclaveError![65]u8 {
    const public = c.SecKeyCopyPublicKey(private) orelse return error.CommandFailed;
    defer release(public);

    var err: c.CFErrorRef = null;
    const data = c.SecKeyCopyExternalRepresentation(public, &err) orelse
        return takeError(&err, error.CommandFailed);
    defer release(data);

    var out: [65]u8 = undefined;
    try copyExact(data, &out);
    if (out[0] != 0x04) return error.MalformedResponse;
    // Parsed rather than trusted, so a point the standard library cannot use
    // is reported here instead of by whichever caller first tries to verify
    // against it.
    _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&out) catch
        return error.MalformedResponse;
    return out;
}

// =============================================================================
// Signature encoding
//
// Shared verbatim with the absent backend via `ecdsa_sig.zig`.
// =============================================================================

pub const derFromRaw = ecdsa_sig.derFromRaw;
pub const rawFromDer = ecdsa_sig.rawFromDer;
pub const max_der_signature_len = ecdsa_sig.max_der_len;

// =============================================================================
// Tests
//
// These run on any Mac, including one with no Secure Enclave. That is
// deliberate: the residency check is exactly the code whose failure mode is
// invisible on capable hardware, so it is exercised as a pure function against
// dictionaries built by hand rather than only as a side effect of key
// generation. The hardware-dependent paths live in `tests/` and skip when the
// enclave is absent.
// =============================================================================

const testing = std.testing;

fn testString(literal: [:0]const u8) c.CFStringRef {
    return c.CFStringCreateWithCString(
        c.kCFAllocatorDefault,
        literal.ptr,
        @intCast(c.kCFStringEncodingUTF8),
    );
}

test "residency check rejects a key with no token id" {
    // This is what a software key looks like: the attribute is simply absent.
    // It is the shape a silent fallback produces, so it must be false and not
    // an error the caller might treat as inconclusive.
    const attrs = try makeDictionary(
        &.{cf(c.kSecAttrKeyType)},
        &.{cf(c.kSecAttrKeyTypeECSECPrimeRandom)},
    );
    defer release(attrs);
    try testing.expect(!attributesReportEnclaveResidency(attrs));
}

test "residency check rejects a key carrying some other token id" {
    const other = testString("com.example.not.the.secure.enclave");
    defer release(other);

    const attrs = try makeDictionary(
        &.{cf(c.kSecAttrTokenID)},
        &.{cf(other)},
    );
    defer release(attrs);
    try testing.expect(!attributesReportEnclaveResidency(attrs));
}

test "residency check accepts the enclave token id" {
    const attrs = try makeDictionary(
        &.{cf(c.kSecAttrTokenID)},
        &.{cf(c.kSecAttrTokenIDSecureEnclave)},
    );
    defer release(attrs);
    try testing.expect(attributesReportEnclaveResidency(attrs));
}

test "residency check compares token id by value, not by object identity" {
    // A CFString built here is a different object from Apple's constant. If
    // the check ever regressed to pointer comparison this would fail, and the
    // regression would otherwise only show up as every real enclave key being
    // rejected on some future OS version that hands back a copy.
    const copy = testString("com.apple.setoken");
    defer release(copy);

    const attrs = try makeDictionary(&.{cf(c.kSecAttrTokenID)}, &.{cf(copy)});
    defer release(attrs);

    // Guard the assumption the test is built on: if Apple ever changes the
    // constant's value, say so here rather than silently testing nothing.
    const matches = c.CFEqual(cf(copy), cf(c.kSecAttrTokenIDSecureEnclave)) != 0;
    if (!matches) return error.SkipZigTest;

    try testing.expect(attributesReportEnclaveResidency(attrs));
}

test "OSStatus mapping separates absent hardware from an unentitled binary" {
    // These two are the pair most likely to be conflated, and the operator
    // action differs completely: replace the Mac versus sign the binary.
    try testing.expectEqual(
        SecureEnclaveError.EnclaveAbsent,
        mapOsStatus(c.errSecUnimplemented, error.CommandFailed),
    );
    try testing.expectEqual(
        SecureEnclaveError.NotEntitled,
        mapOsStatus(c.errSecMissingEntitlement, error.CommandFailed),
    );
    try testing.expectEqual(
        SecureEnclaveError.UserCanceled,
        mapOsStatus(-2, error.CommandFailed),
    );
    // An unrecognised code must reach the caller as the call's own failure,
    // not as a guess.
    try testing.expectEqual(
        SecureEnclaveError.SignatureFailed,
        mapOsStatus(-999999, error.SignatureFailed),
    );
}

test "exact-length copy rejects a short payload" {
    const short = try dataFromSlice(&[_]u8{ 1, 2, 3 });
    defer release(short);

    var out: [32]u8 = undefined;
    try testing.expectError(SecureEnclaveError.MalformedResponse, copyExact(short, &out));
}

test "signature conversion round-trips" {
    var raw: [64]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @intCast(i + 1);

    var der: [max_der_signature_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}

test "opening the enclave either produces an enclave-resident key or refuses" {
    // The one test here that talks to the hardware, and the only one that can
    // fail on a Mac with no Secure Enclave. It deliberately does not skip when
    // the enclave is absent: "absent" is the case the module is most likely to
    // get wrong, because the wrong behaviour — quietly returning a software
    // key — still looks like success.
    //
    // Both outcomes are asserted, so the test has teeth on either kind of Mac:
    //
    //   - Success means `createKey` ran the residency check and passed it, so
    //     the key really is in the enclave. Asserted below by re-checking a
    //     freshly created key's attributes directly, rather than trusting that
    //     `open` did.
    //   - Failure must name one of the conditions that actually mean "no
    //     usable enclave here". Anything else — and in particular a success
    //     with a software key — fails the test.
    var enclave = Enclave.open(.{}) catch |err| {
        // Reported rather than swallowed. Both branches of this test pass, so
        // without this line a run on a Mac with an enclave and a run on a Mac
        // without one are indistinguishable in the output — and the second is
        // a much weaker result than the first.
        std.debug.print(
            "\n[secure enclave] no usable enclave on this host: {s}\n",
            .{@errorName(err)},
        );
        switch (err) {
            // No SEP on this machine, which is every pre-T2 Intel Mac.
            error.EnclaveAbsent,
            // A Mac that has one, running a binary not signed with the
            // keychain-access-group entitlement the enclave requires.
            error.NotEntitled,
            error.AccessControlRejected,
            // The enclave was asked and handed back a software key, which
            // `createKey` destroyed rather than return. This is the refusal
            // the module exists to make.
            error.NotEnclaveBacked,
            => return,
            else => return err,
        }
    };
    defer enclave.close();

    // Reached only on hardware that really has an enclave. Prove residency
    // independently of `createKey`'s own check, so a regression that stubbed
    // that check out would show up here rather than pass silently.
    var key = try enclave.createKey(.{
        .tag = "dev.zcrypto.enclave.test",
        .usage = .signing,
        .persistent = false,
        .protection = .device_unlocked,
    });
    defer enclave.destroyKey(&key);

    const attrs = c.SecKeyCopyAttributes(key.private) orelse return error.MalformedResponse;
    defer release(attrs);
    try testing.expect(attributesReportEnclaveResidency(attrs));

    // And that the key is usable, so "enclave-backed" is not merely a label on
    // something that cannot sign.
    const digest: [32]u8 = @splat(0xA5);
    const sig = try enclave.signDigest(key, digest);
    // `verifyPrehashed`, not `verify`: the enclave signed this digest as-is,
    // so hashing it a second time would check a different message.
    try std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.fromBytes(sig)
        .verifyPrehashed(digest, try key.publicKey());
}
