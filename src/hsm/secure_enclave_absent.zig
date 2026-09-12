//! Stand-in for the Apple Secure Enclave backend in builds configured without
//! `-Dsecure-enclave=true`.
//!
//! `build.zig` binds either this file or `secure_enclave.zig` to the module
//! name `secure_enclave_backend`, so `hsm.zig` contains one unconditional
//! import and one set of call sites. The alternative — a conditional `@import`
//! guarded on a build option — turns "this build has no enclave support" into a
//! compile error at every call site, which pushes the same
//! `if (build_options.enable_secure_enclave)` test into every caller and makes
//! the absent case impossible to write a test against.
//!
//! Every entry point here answers `SecureEnclaveError.BackendNotBuilt`. That is
//! a deliberately different answer from `EnclaveAbsent`: this build has no
//! Security.framework bindings compiled in at all, whereas `EnclaveAbsent` is
//! the real backend reporting that this Mac has no enclave to talk to. The
//! distinction matters more here than for the other two backends, because the
//! second case is the common one — every pre-T2 Intel Mac is in it — and an
//! operator who conflates them goes looking for a hardware fault on a machine
//! that is behaving exactly as designed.
//!
//! The types below mirror `secure_enclave.zig` so both satisfy the same call
//! sites. They are inert: no value of `Enclave` is ever constructed, because
//! `open` is the only constructor and it always fails.

const std = @import("std");
const ecdsa_sig = @import("ecdsa_sig");

/// Lets a caller assert which backend it was compiled against, so a test can
/// expect one exact outcome instead of accepting either. Both backends declare
/// it, so reading it is never a compile error.
pub const is_real_backend = false;

/// Mirrors `secure_enclave.SecureEnclaveError`. The two sets are kept identical
/// so `hsm.zig` maps one error union rather than two.
pub const SecureEnclaveError = error{
    EnclaveAbsent,
    NotEnclaveBacked,
    NotEntitled,
    AccessControlRejected,
    AuthorizationFailed,
    UserCanceled,
    InteractionRequired,
    UnsupportedMechanism,
    KeyNotFound,
    DuplicateKey,
    KeyCreationFailed,
    SignatureFailed,
    KeyAgreementFailed,
    MalformedResponse,
    StaleKeyReference,
    CommandFailed,
    /// This build was compiled without Secure Enclave support. Only this
    /// module ever returns it; the real backend never does.
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

/// An enclave-resident key. `private` is the native `SecKeyRef`, spelled as an
/// opaque pointer here because this build has no Security.framework types. The
/// private scalar has no representation in either backend: it exists only
/// inside the enclave, and nothing in this API can export it.
pub const EnclaveKey = struct {
    private: ?*anyopaque,
    session_epoch: u64,
    /// Uncompressed SEC1 public point (0x04 || X || Y) for NIST P-256, the
    /// only curve the enclave implements.
    public_sec1: [65]u8,
    usage: KeyUsage,

    pub fn publicKey(self: EnclaveKey) !std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&self.public_sec1);
    }
};

/// Mirrors `secure_enclave.Enclave`. Inert: no value is ever constructed,
/// because `open` is the only constructor and it always fails.
pub const Enclave = struct {
    epoch: u64,

    pub fn open(config: Config) SecureEnclaveError!Enclave {
        _ = config;
        return SecureEnclaveError.BackendNotBuilt;
    }

    // The remaining methods are unreachable in practice: an `Enclave` can only
    // be obtained from `open`, which never returns one. They exist so that
    // `hsm.zig` compiles identically against either backend, which is what
    // makes the flag-off build a real compile of the calling code rather than
    // an untested branch.

    pub fn close(self: *Enclave) void {
        self.* = undefined;
    }

    pub fn createKey(self: *Enclave, spec: KeySpec) SecureEnclaveError!EnclaveKey {
        _ = self;
        _ = spec;
        return SecureEnclaveError.BackendNotBuilt;
    }

    pub fn findKey(self: *Enclave, tag: []const u8, usage: KeyUsage) SecureEnclaveError!EnclaveKey {
        _ = self;
        _ = tag;
        _ = usage;
        return SecureEnclaveError.BackendNotBuilt;
    }

    pub fn signDigest(self: *Enclave, key: EnclaveKey, digest: [32]u8) SecureEnclaveError![64]u8 {
        _ = self;
        _ = key;
        _ = digest;
        return SecureEnclaveError.BackendNotBuilt;
    }

    pub fn sharedSecret(self: *Enclave, key: EnclaveKey, peer_public_sec1: [65]u8) SecureEnclaveError![32]u8 {
        _ = self;
        _ = key;
        _ = peer_public_sec1;
        return SecureEnclaveError.BackendNotBuilt;
    }

    pub fn deleteKey(self: *Enclave, tag: []const u8) SecureEnclaveError!void {
        _ = self;
        _ = tag;
        return SecureEnclaveError.BackendNotBuilt;
    }

    pub fn destroyKey(self: *Enclave, key: *EnclaveKey) void {
        _ = self;
        key.* = undefined;
    }
};

// =============================================================================
// Signature encoding
//
// Shared verbatim with the real backend via `ecdsa_sig.zig`, for the same
// reason `pkcs11_absent.zig` re-exports it: Security.framework hands back a DER
// signature and callers of this library want the raw pair, and converting
// between those two spellings touches no Apple type.
// =============================================================================

pub const derFromRaw = ecdsa_sig.derFromRaw;
pub const rawFromDer = ecdsa_sig.rawFromDer;
pub const max_der_signature_len = ecdsa_sig.max_der_len;

const testing = std.testing;

test "the absent Secure Enclave backend reports a missing build, not missing hardware" {
    // `EnclaveAbsent` is what a real backend says on a Mac with no SEP, and it
    // is the answer an operator would act on by moving to different hardware.
    // The answer here is that no build of this backend exists to ask with, and
    // the fix is `-Dsecure-enclave=true`.
    try testing.expectError(
        SecureEnclaveError.BackendNotBuilt,
        Enclave.open(.{}),
    );
    try testing.expect(!is_real_backend);
}

test "signature conversion still works in a build without the backend" {
    var raw: [64]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @intCast(i + 1);

    var der: [max_der_signature_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}
