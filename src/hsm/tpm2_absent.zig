//! Stand-in for the TPM 2.0 backend in builds configured without `-Dtpm=true`.
//!
//! `build.zig` binds either this file or `tpm2.zig` to the module name
//! `tpm_backend`, so `hsm.zig` contains one unconditional import and one set of
//! call sites. The alternative — a conditional `@import` guarded on a build
//! option — turns "this build has no TPM support" into a compile error at every
//! call site, which pushes the same `if (build_options.enable_tpm)` test into
//! every caller and makes the absent case impossible to write a test against.
//!
//! Every entry point here answers `TpmError.BackendNotBuilt`. That is a
//! deliberately different answer from `DeviceAbsent`: this build cannot talk to
//! a TPM at all, whereas `DeviceAbsent` is a real backend reporting that this
//! host has no device. Collapsing the two would tell an operator to go looking
//! for missing hardware when the fix is a build flag.
//!
//! The types below mirror `tpm2.zig` so both satisfy the same call sites. They
//! are inert: no value of `Tpm` is ever constructed, because `open` is the only
//! constructor and it always fails.

const std = @import("std");

/// Lets a caller assert which backend it was compiled against, so a test can
/// expect one exact outcome instead of accepting either. Both backends declare
/// it, so reading it is never a compile error.
pub const is_real_backend = false;

/// Mirrors `tpm2.TpmError`. The two sets are kept identical so `hsm.zig` maps
/// one error union rather than two.
pub const TpmError = error{
    DeviceAbsent,
    PermissionDenied,
    TransportUnavailable,
    ContextInitFailed,
    NotTpm2,
    UnsupportedMechanism,
    RestrictedKey,
    CommandFailed,
    MalformedResponse,
    EntropyStalled,
    BufferTooSmall,
    AuthorizationFailed,
    DictionaryLockout,
    ResourcesExhausted,
    /// This build was compiled without the TPM2-TSS dependency. Only this
    /// module ever returns it; the real backend never does.
    BackendNotBuilt,
    OutOfMemory,
};

pub const Config = struct {
    tcti: [:0]const u8 = "device:/dev/tpmrm0",
    send_startup: bool = false,
    entropy_retry_budget: u8 = 8,
};

pub const DeviceInfo = struct {
    family: [4]u8,
    manufacturer: [4]u8,
};

pub const SigningKey = struct {
    handle: u32,
    session_epoch: u64,
    public_sec1: [65]u8,
    restricted: bool,

    pub fn publicKey(self: SigningKey) !std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&self.public_sec1);
    }
};

pub const StorageKey = struct {
    handle: u32,
    session_epoch: u64,
};

pub const Quote = struct {
    attested: []u8,
    signature: [64]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Quote) void {
        self.allocator.free(self.attested);
        self.* = undefined;
    }
};

pub const SealedBlob = struct {
    public: []u8,
    private: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SealedBlob) void {
        self.allocator.free(self.public);
        self.allocator.free(self.private);
        self.* = undefined;
    }

    pub fn guards(self: SealedBlob) TpmError!BlobGuards {
        _ = self;
        return TpmError.BackendNotBuilt;
    }
};

/// Mirrors `tpm2.BlobGuards`.
pub const BlobGuards = struct {
    policy_bound: bool,
    auth_value_suffices: bool,
};

/// Mirrors `tpm2.max_auth_len`.
pub const max_auth_len = 32;

/// Mirrors `tpm2.PcrPolicy`.
pub const PcrPolicy = struct {
    indices: []const u5,
};

/// Mirrors `tpm2.SealOptions`. Declared here so a caller can name the type and
/// build a value in a build without the backend, and find out at the call that
/// there is no TPM rather than at compile time that there is no type.
pub const SealOptions = struct {
    auth: ?[]const u8 = null,
    pcrs: ?PcrPolicy = null,
};

pub const Tpm = struct {
    allocator: std.mem.Allocator,
    info: DeviceInfo,
    epoch: u64,

    pub fn open(allocator: std.mem.Allocator, config: Config) TpmError!Tpm {
        _ = allocator;
        _ = config;
        return TpmError.BackendNotBuilt;
    }

    // The remaining methods are unreachable in practice: a `Tpm` can only be
    // obtained from `open`, which never returns one. They exist so that
    // `hsm.zig` compiles identically against either backend, which is what
    // makes the flag-off build a real compile of the calling code rather than
    // an untested branch.

    pub fn close(self: *Tpm) void {
        self.* = undefined;
    }

    pub fn getRandom(self: *Tpm, out: []u8) TpmError!void {
        _ = self;
        _ = out;
        return TpmError.BackendNotBuilt;
    }

    pub fn resetDictionaryAttackLock(self: *Tpm) TpmError!void {
        _ = self;
        return TpmError.BackendNotBuilt;
    }

    pub fn readPcrSha256(self: *Tpm, index: u5) TpmError![32]u8 {
        _ = self;
        _ = index;
        return TpmError.BackendNotBuilt;
    }

    pub fn extendPcrSha256(self: *Tpm, index: u5, digest: [32]u8) TpmError!void {
        _ = self;
        _ = index;
        _ = digest;
        return TpmError.BackendNotBuilt;
    }

    pub fn createPrimarySigningKey(self: *Tpm, restricted: bool) TpmError!SigningKey {
        _ = self;
        _ = restricted;
        return TpmError.BackendNotBuilt;
    }

    pub fn signDigest(self: *Tpm, key: SigningKey, digest: [32]u8) TpmError![64]u8 {
        _ = self;
        _ = key;
        _ = digest;
        return TpmError.BackendNotBuilt;
    }

    pub fn quote(self: *Tpm, key: SigningKey, pcr_indices: []const u5, nonce: []const u8) TpmError!Quote {
        _ = self;
        _ = key;
        _ = pcr_indices;
        _ = nonce;
        return TpmError.BackendNotBuilt;
    }

    pub fn createPrimaryStorageKey(self: *Tpm) TpmError!StorageKey {
        _ = self;
        return TpmError.BackendNotBuilt;
    }

    pub fn seal(self: *Tpm, parent: StorageKey, secret: []const u8) TpmError!SealedBlob {
        _ = self;
        _ = parent;
        _ = secret;
        return TpmError.BackendNotBuilt;
    }

    pub fn sealWithPolicy(
        self: *Tpm,
        parent: StorageKey,
        secret: []const u8,
        opts: SealOptions,
    ) TpmError!SealedBlob {
        _ = self;
        _ = parent;
        _ = secret;
        _ = opts;
        return TpmError.BackendNotBuilt;
    }

    pub fn unseal(self: *Tpm, parent: StorageKey, blob: SealedBlob, out: []u8) TpmError!usize {
        _ = self;
        _ = parent;
        _ = blob;
        _ = out;
        return TpmError.BackendNotBuilt;
    }

    pub fn unsealWithPolicy(
        self: *Tpm,
        parent: StorageKey,
        blob: SealedBlob,
        opts: SealOptions,
        out: []u8,
    ) TpmError!usize {
        _ = self;
        _ = parent;
        _ = blob;
        _ = opts;
        _ = out;
        return TpmError.BackendNotBuilt;
    }

    pub fn flush(self: *Tpm, key: *SigningKey) TpmError!void {
        _ = self;
        key.* = undefined;
    }

    pub fn flushStorageKey(self: *Tpm, key: *StorageKey) TpmError!void {
        _ = self;
        key.* = undefined;
    }
};

test "the absent backend reports a build configuration problem, not missing hardware" {
    // `DeviceAbsent` would send an operator looking for hardware; the actual
    // fix is `-Dtpm=true`.
    try std.testing.expectError(
        TpmError.BackendNotBuilt,
        Tpm.open(std.testing.allocator, .{}),
    );
}
