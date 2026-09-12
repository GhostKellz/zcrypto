//! Hardware-backed key storage and cryptographic operations.
//!
//! Three providers are implemented behind one contract: `TPMProvider`
//! (TPM 2.0), `PKCS11Provider` (Cryptoki tokens) and `SecureEnclaveProvider`
//! (Apple Secure Enclave).
//!
//! ## Contract
//!
//! - A provider advertises only operations it performs. `status.supports(op)` is
//!   built from what the opened device answered, never from the platform, the
//!   CPU or the configuration.
//! - `backing` states what actually holds the key. A simulator or software token
//!   reports `.software` however well it works, so `has_hardware_backed_keys`
//!   and `has_hardware_rng` cannot be satisfied by a simulator.
//! - A `KeyRef` is issued only for an object the provider created, and is bound
//!   to the provider kind and session epoch that created it. A reference from
//!   another provider, another instance, or a closed one is refused.
//! - There is no software fallback anywhere. A provider that cannot do the work
//!   returns an error naming why; absence never produces a plausible value.
//!
//! ## Migration from the previous API
//!
//! The previous version returned plausible-looking values for operations it
//! never performed. Those entry points were removed rather than renamed, so a
//! caller depending on one gets a compile error, not a silent behaviour change.
//!
//! - `SecureEnclaveProvider.secureOperation(operation: []const u8, ...)` → the
//!   `Operation` enum and per-operation methods. An unrecognised operation name
//!   used to return the input unchanged and report success.
//! - `HSMKeyHandle.id: u32` → `KeyRef`. The old id came from an RNG and named no
//!   real key, and was too narrow for a `CK_OBJECT_HANDLE` or `SecKeyRef`.
//! - `TPMProvider.deriveKey` → `seal`/`unseal`. The old body ran HKDF host-side
//!   over a hardcoded 0x42 key, ignored `parent_key` and `salt`, and called the
//!   result hardware-derived.
//! - `HSMInterface.getHardwareRandom` no longer answers from the OS CSPRNG under
//!   a hardware name. Use a provider RNG, or `rand.fill` for OS entropy.
//! - `HSMInterface.getTPMRandom` → `TPMProvider.getRandom`. The old body was a
//!   timestamp-seeded PRNG, which is why it sat behind
//!   `-Dexperimental-crypto=true`; the replacement calls `TPM2_GetRandom`.
//! - `HSMInterface.generateKeyExperimental` → `TPMProvider.generateSigningKey`
//!   and `PKCS11Provider.generateKeyPair`. It was gated for the same reason and
//!   dispatched to the placeholder bodies named above.
//!
//! No entry point here is gated on `-Dexperimental-crypto` any more. That flag
//! was standing in for "the implementation is fake", which is not a state this
//! module is in.

const std = @import("std");
const util = @import("util.zig");
const testing = std.testing;
const tpm_backend = @import("tpm_backend");
const pkcs11_backend = @import("pkcs11_backend");
const secure_enclave_backend = @import("secure_enclave_backend");

pub const HSMError = error{
    /// No device of this kind on this host.
    DeviceAbsent,
    /// The device is present but this process may not open it. Distinct from
    /// absence: the operator's fix is permissions, not hardware.
    PermissionDenied,
    /// A provider library could not be loaded, or is not a module of the
    /// expected kind. File existence is not loading.
    LibraryAbsent,
    /// The provider rejected the supplied credential (PIN, auth value, policy).
    AuthenticationFailed,
    /// The device has stopped accepting credentials at all after too many wrong
    /// ones, and is refusing authorized commands until a lockout interval
    /// elapses or an operator clears it.
    ///
    /// Separate from `AuthenticationFailed` because the caller's remedy is the
    /// opposite: there, supplying the right credential succeeds; here, it fails
    /// identically, and retrying is what keeps the device locked. A caller that
    /// read this as a wrong password would prompt a user who has nothing wrong
    /// to fix.
    DeviceLockedOut,
    /// The provider works but does not implement this algorithm or operation.
    UnsupportedMechanism,
    /// This build or this platform has no implementation of the provider.
    ProviderNotBuilt,
    /// The provider is implemented in this build but the caller named no
    /// instance of it. Distinct from `LibraryAbsent`: nothing was looked for,
    /// so the fix is to supply a configuration rather than to install a file.
    ProviderNotConfigured,
    /// Something else in this process already holds this module open. Cryptoki
    /// permits one live `C_Initialize` per module per process, so a second
    /// provider on the same module is refused rather than quietly sharing the
    /// first one's initialization — where the first `close` would finalize the
    /// module out from under the second holder. One provider can serve many
    /// keys; a caller needing more should share the one it has.
    ProviderAlreadyOpen,
    /// The provider refuses to create or modify the object because the token is
    /// write-protected. Distinct from `OperationFailed`: the remedy is a
    /// writable token, or asking for a key that does not outlive the session.
    ReadOnlyProvider,
    /// The provider completed the verification and the signature did not match.
    /// This is an answer, not a malfunction, and is kept apart from
    /// `OperationFailed` so a caller cannot read a broken token as a forgery.
    VerificationFailed,
    /// The provider produced a key but would not hold it in hardware, so the
    /// key was destroyed and refused rather than returned.
    ///
    /// Distinct from every other failure here because nothing is broken: the
    /// operation succeeded and the result was thrown away on purpose. A caller
    /// that treated this as a transient fault and retried would get the same
    /// answer forever; a caller that treated it as `OperationFailed` would
    /// likely fall back to software, which is the exact outcome refusing the
    /// key exists to prevent.
    HardwareBackingRefused,
    /// The provider was reachable but the operation failed.
    OperationFailed,
    /// A key reference from a different provider, or from a closed session.
    StaleKeyReference,
    KeyNotFound,
    /// The provider's key table is full.
    KeyTableFull,
    /// This provider has issued every key identity it can name, so it cannot
    /// create another key without reusing an identity a caller may still hold.
    /// Separate from `KeyTableFull` because freeing a slot does not help: the
    /// provider is finished, and the caller's remedy is a new provider.
    KeyIssuanceExhausted,
    /// Caller buffer too small for the result; nothing was written.
    BufferTooSmall,
    /// Two threads used one provider at once. The provider serializes nothing
    /// on the caller's behalf, so this is a reported contract violation rather
    /// than a corrupted session.
    ConcurrentUse,
    OutOfMemory,
};

/// Operations a provider may support.
///
/// This is the replacement for the previous `secureOperation(operation:
/// []const u8, ...)`. Capabilities are reported as a set of these values, so a
/// caller can ask what a provider does before asking it to do anything, and an
/// unimplemented operation is a compile-time-known name rather than a string
/// that silently falls through to a no-op.
pub const Operation = enum {
    /// Random bytes from the provider's own generator.
    random,
    /// Create a signing key whose private half stays inside the provider.
    generate_signing_key,
    /// Export the public half of a provider-held key.
    export_public_key,
    /// Sign a digest with a provider-held key.
    sign,
    /// Verify a signature inside the provider. Separate from `sign` because a
    /// provider may do one and not the other: a TPM has no verify command this
    /// module needs, while a PKCS#11 token has `C_Verify`. Verification against
    /// an exported public key is a software operation and is not this.
    verify,
    /// Derive a shared secret with a provider-held private key (ECDH).
    key_agreement,
    /// Encrypt and decrypt with a provider-held symmetric key under a mode that
    /// authenticates. Unauthenticated encryption is deliberately not an
    /// operation any provider here can advertise.
    authenticated_encryption,
    /// Encrypt a secret to the provider so only that provider can recover it.
    seal,
    unseal,
    /// Destroy a provider-held object.
    destroy_key,
    /// A signed statement about provider state bound to a caller nonce.
    attestation_quote,
};

pub const OperationSet = std.EnumSet(Operation);

/// Which provider family issued a key reference. Checked on every use so a
/// reference cannot be handed to a different provider that happens to have an
/// object at the same numeric handle.
pub const ProviderKind = enum { tpm2, pkcs11, secure_enclave };

/// Where a key's private material actually lives.
///
/// `software_token` exists because SoftHSM and a TPM simulator implement the
/// same API as hardware while providing none of the protection. Reporting them
/// as `hardware` would make a test token indistinguishable from a real one in
/// the capability output.
pub const Backing = enum { hardware, software_token };

/// Facts about the object the provider actually created. These are read back
/// from the created object, not defaulted: the previous `KeyAttributes` struct
/// defaulted `hardware_protected = true` for keys that did not exist.
pub const KeyProperties = struct {
    backing: Backing,
    /// Whether the private half can be read out of the provider.
    extractable: bool,
    /// Whether the object survives the session that created it. Every key this
    /// module currently creates is transient; nothing here writes a persistent
    /// handle, because doing so would mutate device state a caller did not ask
    /// to have mutated.
    persistent: bool,
};

pub const KeyKind = enum { ecdsa_p256, aes_256 };

/// A reference to a key owned by the provider that created it.
///
/// Lifetime: valid until the owning provider is deinitialized or `destroyKey`
/// is called for it, whichever comes first. It is not valid across processes
/// and it is not valid across two providers of the same kind.
///
/// `native` is 64 bits because native handles are 32-bit (`ESYS_TR`), pointer
/// width (`SecKeyRef`) or `CK_ULONG`; the previous `u32` truncated two of the
/// three. It is an index into the owning provider's table rather than a raw
/// native value, so a forged reference addresses a table slot that is checked,
/// not a device handle that is not.
pub const KeyRef = struct {
    provider: ProviderKind,
    /// Identifies the exact provider instance that issued this reference.
    /// Monotonic across the process, so a reference from a closed provider is
    /// rejected rather than resolved against whatever now occupies the slot.
    session_epoch: u64,
    native: u64,
    /// Identifies the individual key, as opposed to the slot holding it.
    ///
    /// `native` alone is a table index, and an index is reused the moment the
    /// key in it is destroyed. Without this field a reference to a destroyed key
    /// is byte-identical to the reference for whatever key next lands in that
    /// slot, so it authorizes signing, export and destruction of a key its
    /// holder never created. Measured, not theorised: before this field existed
    /// the regression test in `tests/tpm_integration.zig` got a valid signature
    /// out of a destroyed key's reference.
    ///
    /// Issued from a per-provider counter that never repeats a value and never
    /// wraps; see `Issuer`.
    issuance: u64,
    kind: KeyKind,
    properties: KeyProperties,
};

/// Names keys within one provider so that a slot index is never mistaken for a
/// key identity.
///
/// The counter is deliberately not an atomic `fetchAdd` like `epoch_counter`:
/// `fetchAdd` wraps silently, and a wrapped issuance number reintroduces exactly
/// the collision this type exists to prevent. Exhaustion is refused instead.
/// Both providers serialize their own operations already, so a plain integer is
/// sufficient here.
const Issuer = struct {
    /// Starts at 1 so that a default-initialized slot, whose `issuance` is 0,
    /// cannot match any reference this ever hands out.
    next: u64 = 1,

    fn issue(self: *Issuer) HSMError!u64 {
        // At one key per nanosecond this is unreachable for longer than the
        // hardware will exist. It is checked anyway because the alternative to
        // an unreachable branch is a silent wrap, and the cost of being wrong
        // about "unreachable" is a reference that authorizes another key.
        if (self.next == std.math.maxInt(u64)) return HSMError.KeyIssuanceExhausted;
        const value = self.next;
        self.next += 1;
        return value;
    }
};

/// Why a provider is or is not usable, and what it can do if it is.
///
/// The previous code reduced all of this to a single `is_available` bool, which
/// made "no TPM on this host" and "there is a TPM but this process cannot open
/// it" the same answer.
pub const ProviderStatus = union(enum) {
    ready: OperationSet,
    device_absent,
    permission_denied,
    library_absent,
    authentication_failed,
    /// No implementation of this provider on this platform or in this build.
    not_built,
    /// This build implements the provider, but the caller named no instance to
    /// open. A PKCS#11 module has no discoverable default: guessing one would
    /// silently pick a different token on every host.
    not_configured,
    /// Something in this process already initialized this module and has not
    /// finalized it. Kept apart from `initialization_failed` because the module
    /// is fine and the remedy is in the caller's own program: use the provider
    /// that already holds it, or close that one first.
    already_initialized,
    /// Initialization ran out of memory. Kept apart from every other state
    /// because nothing is wrong with the device, the library or the caller's
    /// configuration, and reporting it as absence would have an operator hunt
    /// for hardware that is present and working.
    out_of_memory,
    /// The provider works, but the key it produced was not hardware-backed and
    /// was refused. See `HSMError.HardwareBackingRefused`.
    hardware_backing_refused,
    /// The provider was reachable but initialization failed.
    initialization_failed,

    pub fn isReady(self: ProviderStatus) bool {
        return self == .ready;
    }

    pub fn supports(self: ProviderStatus, op: Operation) bool {
        return switch (self) {
            .ready => |ops| ops.contains(op),
            else => false,
        };
    }

    /// The error a caller gets when asking an unusable provider to work.
    pub fn toError(self: ProviderStatus) HSMError {
        return switch (self) {
            .ready => HSMError.UnsupportedMechanism,
            .device_absent => HSMError.DeviceAbsent,
            .permission_denied => HSMError.PermissionDenied,
            .library_absent => HSMError.LibraryAbsent,
            .authentication_failed => HSMError.AuthenticationFailed,
            .not_built => HSMError.ProviderNotBuilt,
            .not_configured => HSMError.ProviderNotConfigured,
            .already_initialized => HSMError.ProviderAlreadyOpen,
            .out_of_memory => HSMError.OutOfMemory,
            .hardware_backing_refused => HSMError.HardwareBackingRefused,
            .initialization_failed => HSMError.OperationFailed,
        };
    }
};

/// Distinguishes provider instances process-wide.
var epoch_counter: util.Counter64 = util.Counter64.init(1);

fn nextEpoch() u64 {
    return epoch_counter.fetchAdd(1);
}

// =============================================================================
// TPM 2.0
// =============================================================================

/// TPM 2.0 provider, backed by the TPM2-TSS ESAPI stack.
///
/// The backend is bound by `build.zig` to the module name `tpm_backend`: the
/// real implementation under `-Dtpm=true`, otherwise a shim reporting
/// `BackendNotBuilt`. Both are compiled against these call sites.
///
/// Concurrency: a `TPMProvider` owns one ESAPI context, and an `ESYS_CONTEXT`
/// is not safe for concurrent use. Callers must serialize access to one
/// provider. That requirement is enforced rather than merely documented: every
/// entry point claims an atomic guard and returns `ConcurrentUse` if another
/// thread already holds it, so a caller who violates the contract gets a
/// deterministic error instead of a corrupted TPM session. The guard is not a
/// mutex — it does not wait — because blocking would need an `Io` on every
/// signature, and a caller who needs shared access should own the lock.
///
/// Two providers may exist at once; their key references are not interchangeable.
pub const TPMProvider = struct {
    /// The backend types that appear in this provider's public signatures.
    ///
    /// Re-exported because `tpm_backend` is private to this file, and without
    /// these a consumer of the zcrypto package could call `sealWithPolicy` with
    /// an anonymous literal but could not name its argument or store its result
    /// in a struct field. The in-tree tests do not catch that: `build.zig`
    /// hands them the backend as a module, which no consumer gets.
    ///
    /// Aliases, not wrappers, so the types stay identical to the ones the
    /// backend actually takes and returns.
    pub const SealOptions = tpm_backend.SealOptions;
    pub const PcrPolicy = tpm_backend.PcrPolicy;
    pub const SealedBlob = tpm_backend.SealedBlob;
    pub const DeviceInfo = tpm_backend.DeviceInfo;
    pub const Quote = tpm_backend.Quote;

    /// Upper bound on live TPM objects this provider will track.
    ///
    /// This is a bound on the table, not a statement about the device. Real
    /// TPMs hold far fewer transient objects — the reference simulator refuses
    /// the fourth — so in practice the device's own limit is usually reached
    /// first. Both routes end at `KeyTableFull`, so a caller does not have to
    /// know which limit it hit to know what to do about it.
    pub const max_keys = 8;

    const Slot = struct {
        used: bool = false,
        /// Which key occupies the slot, not merely whether one does. Zero on a
        /// fresh or freed slot, so no reference can resolve against it.
        issuance: u64 = 0,
        key: tpm_backend.SigningKey = undefined,
    };

    status: ProviderStatus,
    epoch: u64,
    tpm: ?tpm_backend.Tpm,
    /// Read from the device, not assumed. The previous provider hardcoded
    /// `.version = .tpm_2_0` with the comment "assume TPM 2.0 for modern
    /// systems"; the backend now reads TPM2_PT_FAMILY_INDICATOR and refuses to
    /// open anything that does not answer "2.0".
    info: ?tpm_backend.DeviceInfo,
    backing: Backing,
    slots: [max_keys]Slot,
    issuer: Issuer,
    busy: std.atomic.Value(bool),

    pub const Config = struct {
        /// TCTI configuration string. Explicit rather than probed, so a caller
        /// aimed at a simulator and a caller aimed at `/dev/tpmrm0` differ only
        /// in this value.
        tcti: [:0]const u8 = "device:/dev/tpmrm0",
        /// A simulator generally needs TPM2_Startup; firmware-started hardware
        /// answers TPM2_RC_INITIALIZE, which the backend accepts.
        send_startup: bool = false,
        /// Whether the endpoint is a simulator. This is a caller statement, not
        /// something the TPM can be asked: a simulator answers the identity
        /// commands exactly as hardware does. It only affects the reported
        /// `Backing`, so a simulator run can never be presented as evidence of
        /// hardware protection.
        simulated: bool = false,
    };

    /// Open the TPM. Absence, permission and build configuration are separate
    /// answers, and none of them is an error from this function: a caller
    /// inspects `status`.
    pub fn init(config: Config) TPMProvider {
        var self = TPMProvider{
            .status = .not_built,
            .epoch = nextEpoch(),
            .tpm = null,
            .info = null,
            .backing = if (config.simulated) .software_token else .hardware,
            .slots = @splat(.{}),
            .issuer = .{},
            .busy = .init(false),
        };

        const opened = tpm_backend.Tpm.open(std.heap.page_allocator, .{
            .tcti = config.tcti,
            .send_startup = config.send_startup,
        }) catch |err| {
            self.status = switch (err) {
                error.DeviceAbsent, error.NotTpm2 => .device_absent,
                error.PermissionDenied => .permission_denied,
                error.BackendNotBuilt => .not_built,
                error.TransportUnavailable, error.ContextInitFailed => .initialization_failed,
                error.AuthorizationFailed => .authentication_failed,
                error.OutOfMemory => .out_of_memory,
                else => .initialization_failed,
            };
            return self;
        };

        self.tpm = opened;
        self.info = opened.info;

        // Advertised operations are the ones this backend implements against a
        // TPM 2.0, not a wish list. There is no `key_agreement` here because
        // this backend does not implement ECDH, and no generic decrypt because
        // a TPM has no such command.
        self.status = .{ .ready = OperationSet.initMany(&.{
            .random,
            .generate_signing_key,
            .export_public_key,
            .sign,
            .seal,
            .unseal,
            .destroy_key,
            .attestation_quote,
        }) };

        return self;
    }

    /// Requires exclusive ownership; it does not claim the concurrency guard,
    /// because a destructor that could fail on contention would leave the
    /// caller holding an open device with no way to close it.
    pub fn deinit(self: *TPMProvider) void {
        if (self.tpm) |*t| {
            // Every transient object this provider created is released before
            // the context goes away. Leaking one is not a memory leak: it
            // occupies a device slot until the TPM is reset.
            for (&self.slots) |*slot| {
                if (slot.used) {
                    // Best effort, and said so rather than assumed: `deinit`
                    // returns void, so it has no way to report a flush that
                    // failed. A failure here leaves a transient object holding a
                    // device slot until the TPM is reset. The slot is cleared
                    // anyway because the provider is going away and no reference
                    // to it can be used again; what is not done is to call that
                    // success. Callers who need to know a key was released use
                    // `destroyKey`, which reports.
                    t.flush(&slot.key) catch {};
                    // Reset whole, so a freed slot names no key. Clearing only
                    // `used` would leave the previous occupant's issuance number
                    // behind for the next key to be compared against.
                    slot.* = .{};
                }
            }
            t.close();
        }
        self.tpm = null;
        // Any reference issued by this provider is now stale, and the epoch it
        // was stamped with is never reissued.
        self.status = .device_absent;
    }

    /// The TPM's own family and manufacturer strings, or null if not open.
    pub fn deviceInfo(self: *const TPMProvider) ?tpm_backend.DeviceInfo {
        return self.info;
    }

    /// Claim exclusive use of this provider, or report that someone else has
    /// it. Acquire ordering pairs with the release in `exit` so the key table
    /// written under a previous claim is visible under this one.
    fn enter(self: *TPMProvider) HSMError!void {
        if (self.busy.cmpxchgStrong(false, true, .acquire, .monotonic) != null) {
            return HSMError.ConcurrentUse;
        }
    }

    fn exit(self: *TPMProvider) void {
        self.busy.store(false, .release);
    }

    fn device(self: *TPMProvider) HSMError!*tpm_backend.Tpm {
        if (self.tpm) |*t| return t;
        return self.status.toError();
    }

    fn resolve(self: *TPMProvider, ref: KeyRef) HSMError!*Slot {
        if (ref.provider != .tpm2) return HSMError.StaleKeyReference;
        if (ref.session_epoch != self.epoch) return HSMError.StaleKeyReference;
        if (ref.native >= max_keys) return HSMError.KeyNotFound;
        const slot = &self.slots[@intCast(ref.native)];
        if (!slot.used) return HSMError.KeyNotFound;
        // The slot is occupied, but not necessarily by the key this reference
        // names. Checking the occupant's identity is what stops a destroyed
        // key's reference from operating on its replacement.
        if (slot.issuance != ref.issuance) return HSMError.StaleKeyReference;
        return slot;
    }

    /// Random bytes generated by the TPM. Never falls back to the OS CSPRNG:
    /// a caller who asked for TPM entropy and silently received host entropy
    /// has no way to tell.
    pub fn getRandom(self: *TPMProvider, out: []u8) HSMError!void {
        try self.enter();
        defer self.exit();
        const t = try self.device();
        return t.getRandom(out) catch |err| return mapBackendError(err);
    }

    /// Create a P-256 signing key inside the TPM.
    ///
    /// `restricted` selects an attestation key: it can sign TPM-generated
    /// structures such as a quote, and the TPM refuses to sign caller-supplied
    /// data with it. That is a TPM rule, not a policy invented here.
    pub fn generateSigningKey(self: *TPMProvider, restricted: bool) HSMError!KeyRef {
        try self.enter();
        defer self.exit();
        const t = try self.device();

        const index = for (&self.slots, 0..) |*slot, i| {
            if (!slot.used) break i;
        } else return HSMError.KeyTableFull;

        // Claimed before the TPM is asked to do work, so a provider that can no
        // longer name a key refuses instead of creating one it cannot safely
        // hand back. A number consumed by a failed creation is simply skipped;
        // the counter's only promise is that it never repeats.
        const issuance = try self.issuer.issue();

        const key = t.createPrimarySigningKey(restricted) catch |err| return mapBackendError(err);
        self.slots[index] = .{ .used = true, .issuance = issuance, .key = key };

        return KeyRef{
            .provider = .tpm2,
            .session_epoch = self.epoch,
            .native = @intCast(index),
            .issuance = issuance,
            .kind = .ecdsa_p256,
            .properties = .{
                // The private half of a TPM primary key is generated inside the
                // TPM and only the public point is returned, so these are
                // properties of the created object rather than defaults.
                .backing = self.backing,
                .extractable = false,
                .persistent = false,
            },
        };
    }

    /// The uncompressed SEC1 public point of a provider-held key.
    pub fn exportPublicKey(self: *TPMProvider, ref: KeyRef) HSMError![65]u8 {
        try self.enter();
        defer self.exit();
        _ = try self.device();
        const slot = try self.resolve(ref);
        return slot.key.public_sec1;
    }

    /// Sign a SHA-256 digest, returning a raw r || s signature.
    pub fn signDigest(self: *TPMProvider, ref: KeyRef, digest: [32]u8) HSMError![64]u8 {
        try self.enter();
        defer self.exit();
        const t = try self.device();
        const slot = try self.resolve(ref);
        return t.signDigest(slot.key, digest) catch |err| return mapBackendError(err);
    }

    /// A TPM-signed statement about the selected SHA-256 PCRs, bound to
    /// `nonce`. `ref` must name a restricted key; the TPM enforces this.
    ///
    /// The nonce is placed inside the signed structure. A verifier that does
    /// not check it there has verified nothing about freshness, and a valid
    /// signature alone is not evidence of a trusted boot state.
    pub fn attestationQuote(
        self: *TPMProvider,
        ref: KeyRef,
        pcr_indices: []const u5,
        nonce: []const u8,
    ) HSMError!tpm_backend.Quote {
        try self.enter();
        defer self.exit();
        const t = try self.device();
        const slot = try self.resolve(ref);
        return t.quote(slot.key, pcr_indices, nonce) catch |err| return mapBackendError(err);
    }

    /// Encrypt `secret` to this TPM. The returned blob is not secret and is
    /// useless on any other TPM. This is the supported replacement for the
    /// removed `deriveKey`.
    ///
    /// "To this TPM" is the exact extent of it: the blob is bound to the
    /// device and not to the caller. Any process that can open this TPM can
    /// unseal, because no auth value or PCR policy guards the object -- see
    /// the boundary notes on `tpm2.Tpm.seal`. Do not read this as caller
    /// authorization or as trusted-boot sealing; `sealWithPolicy` is what
    /// offers those.
    pub fn seal(self: *TPMProvider, secret: []const u8) HSMError!tpm_backend.SealedBlob {
        return self.sealWithPolicy(secret, .{});
    }

    /// Encrypt `secret` to this TPM under the guard described by `opts`.
    ///
    /// Device binding is the floor and is always present. `opts.auth` adds
    /// caller authorization: the same bytes must be handed to
    /// `unsealWithPolicy` or the TPM refuses. `opts.pcrs` adds trusted-boot
    /// sealing: the named PCRs must still hold their current values. See
    /// `tpm2.Tpm.sealWithPolicy` for the full statement.
    pub fn sealWithPolicy(
        self: *TPMProvider,
        secret: []const u8,
        opts: tpm_backend.SealOptions,
    ) HSMError!tpm_backend.SealedBlob {
        try self.enter();
        defer self.exit();
        const t = try self.device();

        var parent = t.createPrimaryStorageKey() catch |err| return mapBackendError(err);
        defer t.flushStorageKey(&parent) catch {};

        return t.sealWithPolicy(parent, secret, opts) catch |err| return mapBackendError(err);
    }

    /// Recover a secret sealed by `seal` on this TPM, returning its length.
    ///
    /// A blob whose ciphertext was altered, or that was sealed to a different
    /// TPM, is rejected by the TPM's own integrity check and never yields
    /// plaintext.
    ///
    /// For a blob sealed by `seal`, those are the only two rejections:
    /// presenting an intact one to the TPM it was sealed to always succeeds,
    /// whatever process presents it and whatever the machine has booted since.
    /// A blob sealed by `sealWithPolicy` under a non-default guard is refused
    /// here with `AuthorizationFailed` and must go through `unsealWithPolicy`.
    pub fn unseal(self: *TPMProvider, blob: tpm_backend.SealedBlob, out: []u8) HSMError!usize {
        return self.unsealWithPolicy(blob, .{}, out);
    }

    /// Recover a secret sealed by `sealWithPolicy`, returning its length.
    ///
    /// `opts` must describe the same guard the blob was sealed under. A wrong
    /// or absent auth value, and a PCR that has moved since the seal, are both
    /// `AuthorizationFailed`, and neither yields any part of the plaintext.
    pub fn unsealWithPolicy(
        self: *TPMProvider,
        blob: tpm_backend.SealedBlob,
        opts: tpm_backend.SealOptions,
        out: []u8,
    ) HSMError!usize {
        try self.enter();
        defer self.exit();
        const t = try self.device();

        var parent = t.createPrimaryStorageKey() catch |err| return mapBackendError(err);
        defer t.flushStorageKey(&parent) catch {};

        return t.unsealWithPolicy(parent, blob, opts, out) catch |err| return mapBackendError(err);
    }

    /// Release a provider-held key. The reference is invalid afterwards.
    pub fn destroyKey(self: *TPMProvider, ref: KeyRef) HSMError!void {
        try self.enter();
        defer self.exit();
        const t = try self.device();
        const slot = try self.resolve(ref);
        // The slot is released only once the TPM says the object is gone. It
        // used to be released unconditionally, which turned a failed flush into
        // a reported success and left the caller with no reference to retry
        // with while the object still occupied a device slot. Keeping the slot
        // and the reference alive on failure is what makes a retry possible.
        t.flush(&slot.key) catch |err| return mapBackendError(err);
        slot.* = .{};
    }
};

// =============================================================================
// PKCS#11
// =============================================================================

/// PKCS#11 provider, backed by a Cryptoki module the caller names.
///
/// The backend is bound by `build.zig` to the module name `pkcs11_backend`: the
/// real implementation under `-Dpkcs11=true`, otherwise a shim reporting
/// `BackendNotBuilt`. Both are compiled against these call sites.
///
/// This replaces a `PKCS11Provider.init` that checked a file path with
/// `access()` and reported the token available if the file existed, without
/// ever loading the library or calling `C_Initialize`. Availability here means
/// the module loaded, handed back a function table, initialized, and offered a
/// token in the requested slot.
///
/// Concurrency: a provider owns one session, and a Cryptoki session is serial
/// by definition — `CKF_SERIAL_SESSION` is mandatory. Access is guarded exactly
/// as `TPMProvider` guards its ESAPI context, and for the same reason.
///
/// Backing: a Cryptoki module cannot be asked whether it is hardware in any way
/// worth trusting, so this defaults to `software_token` and the caller must
/// assert otherwise. That default is what keeps a SoftHSM or NSS-softoken run
/// from being reported as hardware protection.
pub const PKCS11Provider = struct {
    /// Upper bound on live objects this provider will track. Larger than the
    /// TPM's because a token holds objects in ordinary storage rather than in a
    /// handful of device slots.
    pub const max_keys = 16;

    const Slot = struct {
        used: bool = false,
        /// Which key occupies the slot, not merely whether one does. See
        /// `KeyRef.issuance`; a token reuses an index exactly as the TPM does.
        issuance: u64 = 0,
        kind: KeyKind = .ecdsa_p256,
        /// For a key pair, the public object; unused for a secret key.
        public: pkcs11_backend.ObjectHandle = 0,
        /// The private or secret object — the one that does the work.
        private: pkcs11_backend.ObjectHandle = 0,
        public_sec1: [65]u8 = @splat(0),
        persistent: bool = false,
    };

    status: ProviderStatus,
    epoch: u64,
    module: ?pkcs11_backend.Module,
    session: ?pkcs11_backend.Session,
    backing: Backing,
    /// Whether created keys are token objects. Kept from the config because it
    /// decides both what `KeyProperties.persistent` says and whether `deinit`
    /// leaves anything behind.
    persistent_keys: bool,
    key_label: []const u8,
    slots: [max_keys]Slot,
    issuer: Issuer,
    busy: std.atomic.Value(bool),

    pub const Config = struct {
        /// Filesystem path of the Cryptoki module. Required, and not defaulted
        /// for the same reason the backend does not default it: a default picks
        /// a different token on every host.
        module_path: []const u8,
        /// Index into the module's live slot list, not a `CK_SLOT_ID`.
        slot_index: usize = 0,
        /// Provider-specific initialization string. NSS softoken needs one to
        /// offer a writable token; most modules need none.
        module_config: ?[]const u8 = null,
        /// User PIN. Borrowed for the duration of `init` only: it is passed
        /// straight to `C_Login` and never stored on the provider, so a
        /// provider value in a core file does not contain it.
        pin: ?[]const u8 = null,
        /// Whether created keys survive the session. Off by default because a
        /// persistent object mutates token state the caller did not ask to have
        /// mutated, and because `deinit` cannot clean up what it is told to keep.
        persistent_keys: bool = false,
        /// Label applied to created objects, and the identity a later session
        /// finds them by. Handles do not survive a session; labels do.
        key_label: []const u8 = "zcrypto",
        /// The caller's assertion that this module fronts real hardware. It
        /// cannot be verified — `CKF_HW_SLOT` is whatever the module says — so
        /// it only ever downgrades to the honest answer when left alone. It
        /// affects reported `Backing` and nothing else.
        hardware_token: bool = false,
    };

    /// Open the module and a session on the requested slot. As with the TPM,
    /// none of the ways this can fail is an error from this function: the
    /// caller inspects `status`.
    pub fn init(config: Config) PKCS11Provider {
        var self = PKCS11Provider{
            .status = .not_configured,
            .epoch = nextEpoch(),
            .module = null,
            .session = null,
            .backing = if (config.hardware_token) .hardware else .software_token,
            .persistent_keys = config.persistent_keys,
            .key_label = config.key_label,
            .slots = @splat(.{}),
            .issuer = .{},
            .busy = .init(false),
        };

        if (config.module_path.len == 0) return self;

        const backend_config = pkcs11_backend.Config{
            .module_path = config.module_path,
            .slot_index = config.slot_index,
            // Always read/write. A read-only session cannot create even a
            // session object, so it could not perform a single operation this
            // provider advertises; a token that refuses says so here rather
            // than at the first key generation.
            .read_write = true,
            .module_config = config.module_config,
        };

        var opened = pkcs11_backend.Module.open(backend_config) catch |err| {
            self.status = statusFor(err);
            return self;
        };

        var session = opened.openSession(backend_config) catch |err| {
            opened.close();
            self.status = statusFor(err);
            return self;
        };

        if (config.pin) |pin| {
            session.login(pin) catch |err| {
                session.close();
                opened.close();
                self.status = statusFor(err);
                return self;
            };
        }

        self.module = opened;
        self.session = session;

        // Advertised operations are the ones the token itself reports it can
        // perform, asked of the token rather than assumed from the fact that a
        // module loaded. A certificate store such as p11-kit-trust loads
        // perfectly and can do none of this.
        var ops = OperationSet.empty;
        ops.insert(.random);
        if (self.mechanismReady(config.slot_index, pkcs11_backend.mechanism.ec_key_pair_gen)) {
            ops.insert(.generate_signing_key);
            ops.insert(.export_public_key);
            ops.insert(.destroy_key);
        }
        if (self.mechanismReady(config.slot_index, pkcs11_backend.mechanism.ecdsa)) {
            ops.insert(.sign);
            ops.insert(.verify);
        }
        if (self.mechanismReady(config.slot_index, pkcs11_backend.mechanism.aes_key_gen) and
            self.mechanismReady(config.slot_index, pkcs11_backend.mechanism.aes_gcm))
        {
            ops.insert(.authenticated_encryption);
            ops.insert(.destroy_key);
        }
        // No `key_agreement`: this backend implements no ECDH. No `seal` or
        // `unseal`: Cryptoki has no operation that binds a blob to the token
        // the way TPM2_Seal does, and presenting AES-GCM under a token key as
        // sealing would overstate what recovery requires.
        self.status = .{ .ready = ops };

        return self;
    }

    /// Whether the token in `slot_index` reports `mech`. A module that cannot
    /// answer the question is treated as not supporting it: an unreadable
    /// capability list is not evidence of a capability.
    fn mechanismReady(self: *PKCS11Provider, slot_index: usize, mech: pkcs11_backend.MechanismType) bool {
        var mod = &(self.module orelse return false);
        var buf: [64]pkcs11_backend.SlotId = undefined;
        const slots = mod.slotsWithToken(&buf) catch return false;
        if (slot_index >= slots.len) return false;
        return mod.supportsMechanism(slots[slot_index], mech) catch false;
    }

    /// Requires exclusive ownership, for the same reason as `TPMProvider.deinit`.
    ///
    /// Session objects are destroyed by closing the session, so nothing here
    /// enumerates them. Token objects are deliberately left on the token: the
    /// caller asked for keys that outlive the session, and silently deleting
    /// them at teardown would make `persistent_keys` mean nothing.
    pub fn deinit(self: *PKCS11Provider) void {
        if (self.session) |*s| s.close();
        self.session = null;
        if (self.module) |*m| m.close();
        self.module = null;
        // Reset whole, so a freed slot names no key. See the TPM provider's
        // `deinit` for why clearing only `used` is not enough.
        for (&self.slots) |*slot| slot.* = .{};
        // Any reference issued by this provider is now stale, and the epoch it
        // was stamped with is never reissued.
        self.status = .not_configured;
    }

    fn enter(self: *PKCS11Provider) HSMError!void {
        if (self.busy.cmpxchgStrong(false, true, .acquire, .monotonic) != null) {
            return HSMError.ConcurrentUse;
        }
    }

    fn exit(self: *PKCS11Provider) void {
        self.busy.store(false, .release);
    }

    fn open(self: *PKCS11Provider) HSMError!*pkcs11_backend.Session {
        if (self.session) |*s| return s;
        return self.status.toError();
    }

    /// Resolve a reference against this provider's table, refusing one issued
    /// by another provider, by a previous instance, or for a key of the wrong
    /// kind. The kind check matters here in a way it does not for the TPM: this
    /// table holds both key pairs and secret keys, and a secret-key handle
    /// passed to `signDigest` would otherwise reach the token.
    fn resolve(self: *PKCS11Provider, ref: KeyRef, want: KeyKind) HSMError!*Slot {
        if (ref.provider != .pkcs11) return HSMError.StaleKeyReference;
        if (ref.session_epoch != self.epoch) return HSMError.StaleKeyReference;
        if (ref.native >= max_keys) return HSMError.KeyNotFound;
        const slot = &self.slots[@intCast(ref.native)];
        if (!slot.used) return HSMError.KeyNotFound;
        // Occupied is not the same as occupied by this key.
        if (slot.issuance != ref.issuance) return HSMError.StaleKeyReference;
        // A slot left mid-deletion by a `destroyKey` that failed on the public
        // half: the private object is already gone, so the key cannot do work
        // even though the slot is still held open for the retry.
        if (slot.private == 0) return HSMError.KeyNotFound;
        if (slot.kind != want) return HSMError.UnsupportedMechanism;
        return slot;
    }

    fn freeIndex(self: *PKCS11Provider) HSMError!usize {
        return for (&self.slots, 0..) |*slot, i| {
            if (!slot.used) break i;
        } else HSMError.KeyTableFull;
    }

    fn require(self: *PKCS11Provider, op: Operation) HSMError!void {
        // An unready provider answers with why it is unready. `supports` is
        // false for every operation in that case, so checking it first would
        // report a token that is absent, unbuilt or unauthenticated as one
        // that does not implement the mechanism — the one answer that is both
        // wrong and actionable, since it suggests picking a different
        // algorithm rather than fixing the token.
        if (!self.status.isReady()) return self.status.toError();
        if (!self.status.supports(op)) return HSMError.UnsupportedMechanism;
    }

    /// Random bytes from the token's own generator, via `C_GenerateRandom`.
    /// Never falls back to the OS CSPRNG.
    ///
    /// Note that a software token's generator is the host's, reached the long
    /// way round. `HSMInterface.getHardwareRandom` will not use a provider
    /// whose `backing` is `software_token` for exactly that reason; a caller
    /// who wants this anyway can ask for it here, where the provider is named.
    pub fn getRandom(self: *PKCS11Provider, out: []u8) HSMError!void {
        try self.enter();
        defer self.exit();
        const s = try self.open();
        return s.getRandom(out) catch |err| return mapBackendError(err);
    }

    /// Generate a P-256 key pair on the token. The private half is created
    /// sensitive and non-extractable, which is read back and reported rather
    /// than assumed.
    pub fn generateSigningKey(self: *PKCS11Provider) HSMError!KeyRef {
        try self.enter();
        defer self.exit();
        try self.require(.generate_signing_key);
        const s = try self.open();

        const index = try self.freeIndex();
        // Claimed before the token is asked to do work; see the TPM provider.
        const issuance = try self.issuer.issue();
        const pair = s.generateEcdsaP256(self.key_label, self.persistent_keys) catch |err| {
            return mapBackendError(err);
        };

        // Asked of the object, not defaulted. If a module ever honoured the
        // template loosely enough to leave the private half extractable, the
        // reference must say so instead of claiming protection it lacks.
        const extractable = s.readBoolAttribute(pair.private, pkcs11_backend.attribute.extractable) catch false;

        self.slots[index] = .{
            .used = true,
            .issuance = issuance,
            .kind = .ecdsa_p256,
            .public = pair.public,
            .private = pair.private,
            .public_sec1 = pair.public_sec1,
            .persistent = self.persistent_keys,
        };

        return KeyRef{
            .provider = .pkcs11,
            .session_epoch = self.epoch,
            .native = @intCast(index),
            .issuance = issuance,
            .kind = .ecdsa_p256,
            .properties = .{
                .backing = self.backing,
                .extractable = extractable,
                .persistent = self.persistent_keys,
            },
        };
    }

    /// The uncompressed SEC1 public point of a token-held key pair.
    pub fn exportPublicKey(self: *PKCS11Provider, ref: KeyRef) HSMError![65]u8 {
        try self.enter();
        defer self.exit();
        _ = try self.open();
        const slot = try self.resolve(ref, .ecdsa_p256);
        return slot.public_sec1;
    }

    /// Sign a SHA-256 digest, returning a raw r || s signature. Cryptoki's
    /// `CKM_ECDSA` produces that form; the DER spelling is available from the
    /// backend's `derFromRaw` for callers who need it.
    pub fn signDigest(self: *PKCS11Provider, ref: KeyRef, digest: [32]u8) HSMError![64]u8 {
        try self.enter();
        defer self.exit();
        try self.require(.sign);
        const s = try self.open();
        const slot = try self.resolve(ref, .ecdsa_p256);
        return s.signDigest(slot.private, digest) catch |err| return mapBackendError(err);
    }

    /// Verify a signature on the token, with the token's own public object.
    ///
    /// A caller holding the exported point can verify in software and should
    /// usually do so. This exists because it checks a different thing: that the
    /// object the token signed with is the object it is verifying with, without
    /// the export step in between.
    pub fn verifyDigest(
        self: *PKCS11Provider,
        ref: KeyRef,
        digest: [32]u8,
        signature: [64]u8,
    ) HSMError!void {
        try self.enter();
        defer self.exit();
        try self.require(.verify);
        const s = try self.open();
        const slot = try self.resolve(ref, .ecdsa_p256);
        return s.verifyDigest(slot.public, digest, signature) catch |err| return mapBackendError(err);
    }

    /// Generate an AES-256 key on the token for authenticated encryption.
    pub fn generateAeadKey(self: *PKCS11Provider) HSMError!KeyRef {
        try self.enter();
        defer self.exit();
        try self.require(.authenticated_encryption);
        const s = try self.open();

        const index = try self.freeIndex();
        const issuance = try self.issuer.issue();
        const key = s.generateAesKey(32, self.key_label, self.persistent_keys) catch |err| {
            return mapBackendError(err);
        };

        const extractable = s.readBoolAttribute(key, pkcs11_backend.attribute.extractable) catch false;

        self.slots[index] = .{
            .used = true,
            .issuance = issuance,
            .kind = .aes_256,
            .public = 0,
            .private = key,
            .persistent = self.persistent_keys,
        };

        return KeyRef{
            .provider = .pkcs11,
            .session_epoch = self.epoch,
            .native = @intCast(index),
            .issuance = issuance,
            .kind = .aes_256,
            .properties = .{
                .backing = self.backing,
                .extractable = extractable,
                .persistent = self.persistent_keys,
            },
        };
    }

    /// AES-GCM encrypt under a token-held key. `iv` must be unique per message
    /// under that key; the token does not track that and neither does this. The
    /// 16-byte tag is appended to the ciphertext, so `out` needs
    /// `plaintext.len + 16` bytes.
    ///
    /// There is deliberately no unauthenticated counterpart. The API this
    /// replaced took an operation name and would encrypt without authenticating
    /// if given one it did not recognise.
    pub fn authenticatedEncrypt(
        self: *PKCS11Provider,
        ref: KeyRef,
        iv: []const u8,
        aad: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) HSMError![]u8 {
        try self.enter();
        defer self.exit();
        try self.require(.authenticated_encryption);
        const s = try self.open();
        const slot = try self.resolve(ref, .aes_256);
        return s.aesGcmEncrypt(slot.private, iv, aad, plaintext, out) catch |err| {
            return mapBackendError(err);
        };
    }

    /// AES-GCM decrypt under a token-held key. A tag or AAD that does not match
    /// yields `VerificationFailed` and no plaintext.
    pub fn authenticatedDecrypt(
        self: *PKCS11Provider,
        ref: KeyRef,
        iv: []const u8,
        aad: []const u8,
        ciphertext: []const u8,
        out: []u8,
    ) HSMError![]u8 {
        try self.enter();
        defer self.exit();
        try self.require(.authenticated_encryption);
        const s = try self.open();
        const slot = try self.resolve(ref, .aes_256);
        return s.aesGcmDecrypt(slot.private, iv, aad, ciphertext, out) catch |err| {
            return mapBackendError(err);
        };
    }

    /// Destroy a token-held object. The reference is invalid afterwards, and a
    /// persistent object is really removed from the token, not just forgotten
    /// by this provider.
    pub fn destroyKey(self: *PKCS11Provider, ref: KeyRef) HSMError!void {
        try self.enter();
        defer self.exit();
        const s = try self.open();

        if (ref.provider != .pkcs11) return HSMError.StaleKeyReference;
        if (ref.session_epoch != self.epoch) return HSMError.StaleKeyReference;
        if (ref.native >= max_keys) return HSMError.KeyNotFound;
        const slot = &self.slots[@intCast(ref.native)];
        if (!slot.used) return HSMError.KeyNotFound;
        // This path duplicates `resolve` rather than calling it, because it
        // accepts any key kind. The issuance check must be duplicated with it:
        // omitting it here would leave destruction as the one operation a stale
        // reference could still perform on its replacement.
        if (slot.issuance != ref.issuance) return HSMError.StaleKeyReference;

        // Deletion of a key pair is two token operations, so it can half
        // succeed. The slot used to be released whichever way the token
        // answered, which meant a failure reported to the caller had already
        // thrown away the only handles that could complete the job: a
        // persistent public object stayed on the token with nothing pointing at
        // it. Each half is instead cleared as the token confirms it, so the
        // reference stays valid, a retry resumes where this left off rather
        // than re-deleting an object that is already gone, and the slot is
        // released only when there is nothing left to release.
        if (slot.private != 0) {
            s.destroyObject(slot.private) catch |err| return mapBackendError(err);
            slot.private = 0;
        }
        if (slot.kind == .ecdsa_p256 and slot.public != 0) {
            s.destroyObject(slot.public) catch |err| return mapBackendError(err);
            slot.public = 0;
        }
        slot.* = .{};
    }
};

// =============================================================================
// Apple Secure Enclave
// =============================================================================

/// Secure Enclave provider, backed by Security.framework's `SecKey` API.
///
/// The backend is bound by `build.zig` to the module name
/// `secure_enclave_backend`: the real implementation under
/// `-Dsecure-enclave=true` on a macOS target, otherwise a shim reporting
/// `BackendNotBuilt`. Both are compiled against these call sites.
///
/// This is the one provider whose `backing` is not a caller's assertion. A TPM
/// simulator and a software token answer their APIs exactly as hardware does,
/// so `TPMProvider.Config.simulated` and `PKCS11Provider.Config.hardware_token`
/// can only ever be believed. The enclave instead attests each key's residency
/// through `kSecAttrTokenID`, which the backend reads back and refuses the key
/// over; see `secure_enclave.requireEnclaveResidency`. So `backing` here is
/// `.hardware` unconditionally, and it means it.
///
/// What the enclave does not do is as load-bearing as what it does. It exposes
/// no RNG, no sealing, no attestation, and no symmetric keys, so none of those
/// operations is advertised and every one of them fails with
/// `UnsupportedMechanism` rather than being served from somewhere else.
///
/// Concurrency: as with the other two providers, callers must serialize access
/// to one instance, and a violation is reported as `ConcurrentUse` rather than
/// tolerated.
pub const SecureEnclaveProvider = struct {
    /// Upper bound on live keys this provider will track. Matched to the TPM's
    /// rather than the token's: an enclave key is a device-resident object, and
    /// a caller holding many at once is doing something the enclave is not for.
    pub const max_keys = 8;

    const Slot = struct {
        used: bool = false,
        /// Which key occupies the slot, not merely whether one does. See
        /// `KeyRef.issuance`.
        issuance: u64 = 0,
        key: secure_enclave_backend.EnclaveKey = undefined,
    };

    status: ProviderStatus,
    epoch: u64,
    enclave: ?secure_enclave_backend.Enclave,
    backing: Backing,
    /// Whether created keys are written to the keychain. Kept from the config
    /// because it decides both what `KeyProperties.persistent` says and whether
    /// `deinit` leaves anything behind.
    persistent_keys: bool,
    key_tag: []const u8,
    protection: secure_enclave_backend.Protection,
    slots: [max_keys]Slot,
    issuer: Issuer,
    busy: std.atomic.Value(bool),

    pub const Config = struct {
        /// Application tag applied to created keys, and the identity a later
        /// session finds them by with `findKey`. Key references do not survive
        /// a provider; tags do.
        key_tag: []const u8 = "dev.zcrypto.enclave.key",
        /// Off by default for the same reason as the PKCS#11 provider's: a
        /// keychain-resident key mutates state the caller did not ask to have
        /// mutated, and `deinit` cannot clean up what it is told to keep.
        persistent_keys: bool = false,
        /// Require the user to authenticate on every use of a created key.
        ///
        /// A caller that sets this must be able to present a prompt. A daemon
        /// or an SSH session cannot, and gets `AuthenticationFailed` on first
        /// use rather than at creation, because the enclave only discovers it
        /// when the key is actually needed.
        require_user_presence: bool = false,
    };

    /// A provider for a caller that named no enclave. Reports `not_configured`,
    /// and every call through it fails with `ProviderNotConfigured`.
    ///
    /// This exists so `HSMInterface.init` does not open the enclave on every
    /// construction. Opening it generates a key — that is how the backend
    /// proves the enclave answers rather than assuming it — and a library that
    /// silently made a hardware key because someone constructed an interface
    /// would be doing work nobody asked for.
    pub fn unconfigured() SecureEnclaveProvider {
        return .{
            .status = .not_configured,
            .epoch = nextEpoch(),
            .enclave = null,
            .backing = .hardware,
            .persistent_keys = false,
            .key_tag = "",
            .protection = .device_unlocked,
            .slots = @splat(.{}),
            .issuer = .{},
            .busy = .init(false),
        };
    }

    /// Open the enclave. As with the other providers, none of the ways this can
    /// fail is an error from this function: the caller inspects `status`.
    pub fn init(config: Config) SecureEnclaveProvider {
        var self = unconfigured();
        self.persistent_keys = config.persistent_keys;
        self.key_tag = config.key_tag;
        self.protection = if (config.require_user_presence) .user_presence else .device_unlocked;

        const opened = secure_enclave_backend.Enclave.open(.{}) catch |err| {
            self.status = statusFor(err);
            return self;
        };

        self.enclave = opened;
        self.status = .{ .ready = OperationSet.initMany(&.{
            .generate_signing_key,
            .export_public_key,
            .sign,
            .key_agreement,
            .destroy_key,
        }) };

        return self;
    }

    /// Requires exclusive ownership, for the same reason as the other two
    /// providers' destructors.
    ///
    /// Every key reference this provider holds is released, because each one is
    /// a retained `SecKeyRef` and dropping the provider without releasing them
    /// leaks native objects. A persistent key stays in the keychain: the caller
    /// asked for keys that outlive the session, and deleting them here would
    /// make `persistent_keys` mean nothing.
    pub fn deinit(self: *SecureEnclaveProvider) void {
        if (self.enclave) |*e| {
            for (&self.slots) |*slot| {
                if (slot.used) e.destroyKey(&slot.key);
            }
            e.close();
        }
        self.enclave = null;
        // Reset whole, so a freed slot names no key.
        for (&self.slots) |*slot| slot.* = .{};
        self.status = .not_configured;
    }

    fn enter(self: *SecureEnclaveProvider) HSMError!void {
        if (self.busy.cmpxchgStrong(false, true, .acquire, .monotonic) != null) {
            return HSMError.ConcurrentUse;
        }
    }

    fn exit(self: *SecureEnclaveProvider) void {
        self.busy.store(false, .release);
    }

    fn open(self: *SecureEnclaveProvider) HSMError!*secure_enclave_backend.Enclave {
        if (self.enclave) |*e| return e;
        return self.status.toError();
    }

    /// Resolve a reference against this provider's table, refusing one issued
    /// by another provider, by a previous instance, or for a destroyed key.
    fn resolve(self: *SecureEnclaveProvider, ref: KeyRef) HSMError!*Slot {
        if (ref.provider != .secure_enclave) return HSMError.StaleKeyReference;
        if (ref.session_epoch != self.epoch) return HSMError.StaleKeyReference;
        if (ref.native >= max_keys) return HSMError.KeyNotFound;
        const slot = &self.slots[@intCast(ref.native)];
        if (!slot.used) return HSMError.KeyNotFound;
        // Occupied is not the same as occupied by this key.
        if (slot.issuance != ref.issuance) return HSMError.StaleKeyReference;
        return slot;
    }

    fn freeIndex(self: *SecureEnclaveProvider) HSMError!usize {
        return for (&self.slots, 0..) |*slot, i| {
            if (!slot.used) break i;
        } else HSMError.KeyTableFull;
    }

    fn require(self: *SecureEnclaveProvider, op: Operation) HSMError!void {
        // Status before mechanism, for the reason given on `PKCS11Provider`'s
        // copy. It matters more here: `EnclaveAbsent` and "this build has no
        // Security.framework" are the two ordinary states of this provider,
        // and neither has anything to do with the mechanism asked for.
        if (!self.status.isReady()) return self.status.toError();
        if (!self.status.supports(op)) return HSMError.UnsupportedMechanism;
    }

    fn createKey(self: *SecureEnclaveProvider, usage: secure_enclave_backend.KeyUsage) HSMError!KeyRef {
        const e = try self.open();

        const index = try self.freeIndex();
        // Claimed before the enclave is asked to do work, so a failed creation
        // cannot leave a later key reusing an identity a caller already holds.
        const issuance = try self.issuer.issue();
        const key = e.createKey(.{
            .tag = self.key_tag,
            .usage = usage,
            .persistent = self.persistent_keys,
            .protection = self.protection,
        }) catch |err| return mapBackendError(err);

        self.slots[index] = .{ .used = true, .issuance = issuance, .key = key };

        return KeyRef{
            .provider = .secure_enclave,
            .session_epoch = self.epoch,
            .native = @intCast(index),
            .issuance = issuance,
            .kind = .ecdsa_p256,
            .properties = .{
                // Attested by the enclave, not defaulted: `createKey` already
                // refused anything that did not read back as enclave-resident,
                // so reaching this line is the evidence.
                .backing = .hardware,
                // There is no API that extracts an enclave private key, so this
                // is a property of the hardware rather than of a template the
                // device might have honoured loosely.
                .extractable = false,
                .persistent = self.persistent_keys,
            },
        };
    }

    /// Generate a P-256 signing key inside the enclave.
    pub fn generateSigningKey(self: *SecureEnclaveProvider) HSMError!KeyRef {
        try self.enter();
        defer self.exit();
        try self.require(.generate_signing_key);
        return self.createKey(.signing);
    }

    /// Generate a P-256 key inside the enclave for ECDH.
    ///
    /// Separate from `generateSigningKey` because the enclave binds the use at
    /// creation: a key made for signing cannot later agree, and vice versa.
    /// Offering one constructor and discovering the restriction at first use
    /// would turn a fixed property into an intermittent-looking failure.
    pub fn generateAgreementKey(self: *SecureEnclaveProvider) HSMError!KeyRef {
        try self.enter();
        defer self.exit();
        try self.require(.key_agreement);
        return self.createKey(.key_agreement);
    }

    /// The uncompressed SEC1 public point of an enclave-held key.
    pub fn exportPublicKey(self: *SecureEnclaveProvider, ref: KeyRef) HSMError![65]u8 {
        try self.enter();
        defer self.exit();
        _ = try self.open();
        const slot = try self.resolve(ref);
        return slot.key.public_sec1;
    }

    /// Sign a SHA-256 digest, returning a raw r || s signature.
    ///
    /// The enclave produces DER; the backend converts, so this matches what
    /// `TPMProvider.signDigest` and `PKCS11Provider.signDigest` return.
    pub fn signDigest(self: *SecureEnclaveProvider, ref: KeyRef, digest: [32]u8) HSMError![64]u8 {
        try self.enter();
        defer self.exit();
        try self.require(.sign);
        const e = try self.open();
        const slot = try self.resolve(ref);
        return e.signDigest(slot.key, digest) catch |err| return mapBackendError(err);
    }

    /// ECDH against a peer's uncompressed SEC1 point, returning the raw X
    /// coordinate of the shared point.
    ///
    /// Raw, not a derived key. The caller must run this through a KDF. The
    /// enclave offers variants that apply X9.63 internally and they are
    /// deliberately not used: a KDF inside a hardware call cannot be checked
    /// against a test vector.
    pub fn deriveSharedSecret(
        self: *SecureEnclaveProvider,
        ref: KeyRef,
        peer_public_sec1: [65]u8,
    ) HSMError![32]u8 {
        try self.enter();
        defer self.exit();
        try self.require(.key_agreement);
        const e = try self.open();
        const slot = try self.resolve(ref);
        return e.sharedSecret(slot.key, peer_public_sec1) catch |err| return mapBackendError(err);
    }

    /// Release an enclave key and free its slot.
    ///
    /// A persistent key is removed from the keychain as well, because the
    /// caller asked for this key to be gone and leaving it findable by tag
    /// would make `destroyKey` a rename of "close".
    pub fn destroyKey(self: *SecureEnclaveProvider, ref: KeyRef) HSMError!void {
        try self.enter();
        defer self.exit();
        try self.require(.destroy_key);
        const e = try self.open();
        const slot = try self.resolve(ref);

        e.destroyKey(&slot.key);
        // The slot is released whether or not the keychain removal succeeds:
        // the local reference is already gone, so the reference the caller
        // holds must stop resolving either way.
        const persistent = self.persistent_keys;
        slot.* = .{};
        if (persistent) {
            e.deleteKey(self.key_tag) catch |err| return mapBackendError(err);
        }
    }
};

/// Which status a backend error means for a provider that is being opened.
/// Separate from `mapBackendError`, which answers a different question: that
/// one says what a caller's operation failed with, this one says what state the
/// provider is left in.
fn statusFor(err: anyerror) ProviderStatus {
    return switch (err) {
        error.LibraryAbsent, error.NotACryptokiModule => .library_absent,
        error.BackendNotBuilt => .not_built,
        error.AlreadyInitialized => .already_initialized,
        error.OutOfMemory => .out_of_memory,
        error.TokenAbsent, error.SlotNotFound => .device_absent,
        error.AuthorizationFailed => .authentication_failed,

        // Secure Enclave. `EnclaveAbsent` is the ordinary state of every
        // pre-T2 Mac, and `NotEntitled` is the ordinary state of an unsigned
        // binary on a Mac that does have one; keeping them apart is the
        // difference between "get different hardware" and "sign this build".
        error.EnclaveAbsent => .device_absent,
        error.NotEntitled => .permission_denied,
        error.NotEnclaveBacked => .hardware_backing_refused,
        error.UserCanceled, error.InteractionRequired => .authentication_failed,
        else => .initialization_failed,
    };
}

/// Translate a backend error into this module's taxonomy. The distinctions the
/// backend draws are preserved: collapsing them here would undo the point of
/// drawing them.
fn mapBackendError(err: anyerror) HSMError {
    return switch (err) {
        error.DeviceAbsent => HSMError.DeviceAbsent,
        error.PermissionDenied => HSMError.PermissionDenied,
        error.BackendNotBuilt => HSMError.ProviderNotBuilt,
        error.AuthorizationFailed => HSMError.AuthenticationFailed,
        error.DictionaryLockout => HSMError.DeviceLockedOut,
        error.UnsupportedMechanism, error.RestrictedKey => HSMError.UnsupportedMechanism,

        // PKCS#11. A module that will not load and one that loads but is not a
        // Cryptoki provider are the same answer to the caller — the path names
        // nothing usable — and the backend already draws the finer distinction
        // for anyone calling it directly.
        error.LibraryAbsent, error.NotACryptokiModule => HSMError.LibraryAbsent,
        error.AlreadyInitialized => HSMError.ProviderAlreadyOpen,
        error.TokenAbsent, error.SlotNotFound => HSMError.DeviceAbsent,
        error.ReadOnlyToken => HSMError.ReadOnlyProvider,
        error.ObjectNotFound, error.AttributeUnavailable => HSMError.KeyNotFound,
        // A session the token has invalidated makes every reference issued
        // against it stale, which is what the caller has to act on.
        error.SessionInvalid => HSMError.StaleKeyReference,
        error.SignatureInvalid => HSMError.VerificationFailed,
        // Whether the provider's own table or the device's object slots ran
        // out first, the caller's situation and remedy are the same: free a
        // key before asking for another.
        error.ResourcesExhausted => HSMError.KeyTableFull,
        error.BufferTooSmall => HSMError.BufferTooSmall,
        error.OutOfMemory => HSMError.OutOfMemory,

        // Secure Enclave.
        error.EnclaveAbsent => HSMError.DeviceAbsent,
        error.NotEntitled => HSMError.PermissionDenied,
        error.NotEnclaveBacked => HSMError.HardwareBackingRefused,
        // The user dismissed the prompt, or there was no way to show one. Both
        // are the caller failing to authorize the key, which is what
        // `AuthenticationFailed` says.
        error.UserCanceled, error.InteractionRequired => HSMError.AuthenticationFailed,
        // A policy the device cannot satisfy, e.g. biometry-bound with no
        // biometry enrolled. Nothing is broken and no credential was wrong.
        error.AccessControlRejected => HSMError.UnsupportedMechanism,
        error.KeyNotFound => HSMError.KeyNotFound,
        error.StaleKeyReference => HSMError.StaleKeyReference,
        else => HSMError.OperationFailed,
    };
}

// =============================================================================
// Unified interface
// =============================================================================

/// Capability bits, reported from provider status rather than from detection
/// guesses. A bit is set only when the corresponding provider is ready and
/// advertises the operation.
pub const HSMCapabilities = struct {
    has_tpm: bool = false,
    has_pkcs11: bool = false,
    has_secure_enclave: bool = false,
    /// Set only when a ready provider generates entropy in hardware. A TPM
    /// simulator and a software token both answer `C_GenerateRandom` and
    /// `TPM2_GetRandom` perfectly well, so availability of the operation is not
    /// the question this bit answers.
    has_hardware_rng: bool = false,
    /// Set only when a ready provider holds private keys in hardware. This is
    /// the bit that §5A requires a software token not to set: a SoftHSM or
    /// NSS-softoken run proves the integration and proves nothing about
    /// physical protection.
    has_hardware_backed_keys: bool = false,
    has_attestation: bool = false,
    has_sealing: bool = false,
    /// Signing and verification inside a provider, whatever the backing.
    has_token_signing: bool = false,
    /// AEAD under a provider-held symmetric key.
    has_authenticated_encryption: bool = false,
    /// ECDH with a provider-held private key. Only the Secure Enclave offers
    /// it; the TPM backend implements no ECDH and the PKCS#11 backend does not
    /// expose `C_DeriveKey`.
    has_key_agreement: bool = false,
};

pub const HSMInterface = struct {
    tpm: TPMProvider,
    pkcs11: PKCS11Provider,
    secure_enclave: SecureEnclaveProvider,

    pub const Config = struct {
        tpm: TPMProvider.Config = .{},
        /// Null means no PKCS#11 module was named, which is not the same as one
        /// being missing. The provider reports `not_configured` and every call
        /// through it fails with `ProviderNotConfigured`.
        pkcs11: ?PKCS11Provider.Config = null,
        /// Null means the caller did not ask for the enclave. It is opt-in and
        /// not defaulted for a reason the other two do not share: opening the
        /// enclave generates a key, so constructing this interface would
        /// otherwise perform a hardware operation as a side effect.
        secure_enclave: ?SecureEnclaveProvider.Config = null,
    };

    pub fn init(config: Config) HSMInterface {
        return .{
            .tpm = TPMProvider.init(config.tpm),
            .pkcs11 = PKCS11Provider.init(config.pkcs11 orelse .{ .module_path = "" }),
            .secure_enclave = if (config.secure_enclave) |sec|
                SecureEnclaveProvider.init(sec)
            else
                SecureEnclaveProvider.unconfigured(),
        };
    }

    pub fn deinit(self: *HSMInterface) void {
        self.tpm.deinit();
        self.pkcs11.deinit();
        self.secure_enclave.deinit();
    }

    pub fn capabilities(self: *const HSMInterface) HSMCapabilities {
        const tpm_hw = self.tpm.backing == .hardware;
        const p11_hw = self.pkcs11.backing == .hardware;
        // Not a caller's claim, unlike the two above: the enclave attests each
        // key's residency and the backend refuses any key that fails the check,
        // so a ready provider here is hardware by construction.
        const sec_hw = self.secure_enclave.backing == .hardware;
        return .{
            .has_tpm = self.tpm.status.isReady(),
            .has_pkcs11 = self.pkcs11.status.isReady(),
            .has_secure_enclave = self.secure_enclave.status.isReady(),
            // The enclave exposes no RNG, so it contributes nothing here. That
            // is absence of an operation, not of hardware.
            .has_hardware_rng = (tpm_hw and self.tpm.status.supports(.random)) or
                (p11_hw and self.pkcs11.status.supports(.random)),
            .has_hardware_backed_keys = (tpm_hw and self.tpm.status.supports(.generate_signing_key)) or
                (p11_hw and self.pkcs11.status.supports(.generate_signing_key)) or
                (sec_hw and self.secure_enclave.status.supports(.generate_signing_key)),
            .has_attestation = self.tpm.status.supports(.attestation_quote),
            .has_sealing = self.tpm.status.supports(.seal),
            .has_token_signing = self.tpm.status.supports(.sign) or
                self.pkcs11.status.supports(.sign) or
                self.secure_enclave.status.supports(.sign),
            .has_authenticated_encryption = self.pkcs11.status.supports(.authenticated_encryption),
            .has_key_agreement = self.secure_enclave.status.supports(.key_agreement),
        };
    }

    /// Random bytes from a hardware provider.
    ///
    /// Fails when no provider can supply them. It does not fall back to the OS
    /// CSPRNG: the previous version did exactly that, so every caller believed
    /// it had hardware entropy on every host. Callers who want OS entropy
    /// should call `rand.fill`, which is what this used to do underneath.
    ///
    /// A provider whose `backing` is `software_token` is not used here even
    /// when it is ready and offers `random`. Its generator is the host's,
    /// reached through a library, so answering from it would recreate the
    /// original defect one layer down. Such a provider can still be asked
    /// directly, where the caller has named it and knows what it is.
    pub fn getHardwareRandom(self: *HSMInterface, buffer: []u8) HSMError!void {
        if (self.tpm.backing == .hardware and self.tpm.status.supports(.random)) {
            return self.tpm.getRandom(buffer);
        }
        if (self.pkcs11.backing == .hardware and self.pkcs11.status.supports(.random)) {
            return self.pkcs11.getRandom(buffer);
        }
        // A provider that is ready and got this far is one that works and is
        // not hardware-backed. What is absent is a hardware source, so that is
        // what is reported: passing on the TPM's `not_built` here would send an
        // operator to rebuild for a device the host may not even have.
        if (self.tpm.status.isReady() or self.pkcs11.status.isReady()) {
            return HSMError.DeviceAbsent;
        }
        // Otherwise nothing is ready, and the reason is reported against the
        // TPM, the provider that exists on every build; a caller wanting the
        // PKCS#11 reason reads `pkcs11.status`.
        return self.tpm.status.toError();
    }
};

// =============================================================================
// TESTS
// =============================================================================
//
// These run on any host. Behaviour that needs a real device lives in
// tests/tpm_integration.zig, which is driven by ZCRYPTO_TPM_TCTI.

test "an unavailable TPM provider reports why, and refuses to work" {
    var provider = TPMProvider.init(.{ .tcti = "device:/nonexistent/zcrypto-hsm-probe" });
    defer provider.deinit();

    // Not merely "unavailable": the specific reason is preserved, and which
    // reason is correct depends on the build. A build with the TPM backend
    // compiled in really did look for the device and not find it; a build
    // without it never looked, and saying `device_absent` there would send an
    // operator hunting for hardware when the fix is `-Dtpm=true`.
    const expected: ProviderStatus = if (tpm_backend.is_real_backend) .device_absent else .not_built;
    try testing.expect(!provider.status.isReady());
    try testing.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(provider.status));

    // And it refuses rather than inventing a result.
    var buf: [16]u8 = @splat(0xAA);
    try testing.expectError(expected.toError(), provider.getRandom(&buf));
    // The refusal did not touch the caller's buffer.
    try testing.expectEqual(@as(u8, 0xAA), buf[0]);
}

test "capabilities are false when no provider is ready" {
    var hsm = HSMInterface.init(.{ .tpm = .{ .tcti = "device:/nonexistent/zcrypto-hsm-probe" } });
    defer hsm.deinit();

    const caps = hsm.capabilities();
    try testing.expect(!caps.has_tpm);
    try testing.expect(!caps.has_hardware_rng);
    try testing.expect(!caps.has_attestation);
    try testing.expect(!caps.has_sealing);
}

test "getHardwareRandom fails rather than answering from the OS CSPRNG" {
    var hsm = HSMInterface.init(.{ .tpm = .{ .tcti = "device:/nonexistent/zcrypto-hsm-probe" } });
    defer hsm.deinit();

    // The previous implementation called rand.fill here and reported success,
    // so this assertion is the whole point of the change.
    var buffer: [32]u8 = @splat(0);
    try testing.expectError(hsm.tpm.status.toError(), hsm.getHardwareRandom(&buffer));

    var untouched = true;
    for (buffer) |b| {
        if (b != 0) untouched = false;
    }
    try testing.expect(untouched);
}

test "a key reference from another provider instance is refused" {
    var a = TPMProvider.init(.{ .tcti = "device:/nonexistent/zcrypto-hsm-probe" });
    defer a.deinit();
    var b = TPMProvider.init(.{ .tcti = "device:/nonexistent/zcrypto-hsm-probe" });
    defer b.deinit();

    // Two providers never share an epoch, so a reference minted by one cannot
    // resolve against the other's table even at the same numeric handle.
    try testing.expect(a.epoch != b.epoch);

    const forged = KeyRef{
        .provider = .tpm2,
        .session_epoch = a.epoch,
        .native = 0,
        .issuance = 1,
        .kind = .ecdsa_p256,
        .properties = .{ .backing = .hardware, .extractable = false, .persistent = false },
    };
    // `resolve` rejects the epoch before any table lookup happens.
    try testing.expectError(HSMError.StaleKeyReference, b.resolve(forged));
}

test "a key reference from a different provider kind is refused" {
    var provider = TPMProvider.init(.{ .tcti = "device:/nonexistent/zcrypto-hsm-probe" });
    defer provider.deinit();

    const foreign = KeyRef{
        .provider = .pkcs11,
        .session_epoch = provider.epoch,
        .native = 0,
        .issuance = 1,
        .kind = .ecdsa_p256,
        .properties = .{ .backing = .hardware, .extractable = false, .persistent = false },
    };
    try testing.expectError(HSMError.StaleKeyReference, provider.resolve(foreign));
}

test "a native handle outside the key table is refused rather than indexed" {
    // This check is the only thing standing between a forged reference and an
    // out-of-bounds index into `slots`, so it is asserted rather than trusted.
    // Neither provider needs a device: `resolve` decides on the reference alone.
    var tpm = TPMProvider.init(.{ .tcti = "device:/nonexistent/zcrypto-hsm-probe" });
    defer tpm.deinit();
    try testing.expectError(HSMError.KeyNotFound, tpm.resolve(.{
        .provider = .tpm2,
        .session_epoch = tpm.epoch,
        .native = std.math.maxInt(u64),
        .issuance = 1,
        .kind = .ecdsa_p256,
        .properties = .{ .backing = .hardware, .extractable = false, .persistent = false },
    }));

    var token = PKCS11Provider.init(.{ .module_path = "" });
    defer token.deinit();
    try testing.expectError(HSMError.KeyNotFound, token.resolve(.{
        .provider = .pkcs11,
        .session_epoch = token.epoch,
        .native = PKCS11Provider.max_keys,
        .issuance = 1,
        .kind = .ecdsa_p256,
        .properties = .{ .backing = .hardware, .extractable = false, .persistent = false },
    }, .ecdsa_p256));
}

test "a key reference from a different provider kind is refused by the token too" {
    // The same guard as the TPM's, on the provider whose table holds two kinds
    // of object: a `tpm2` reference must not resolve here even at a live index.
    var token = PKCS11Provider.init(.{ .module_path = "" });
    defer token.deinit();
    try testing.expectError(HSMError.StaleKeyReference, token.resolve(.{
        .provider = .tpm2,
        .session_epoch = token.epoch,
        .native = 0,
        .issuance = 1,
        .kind = .ecdsa_p256,
        .properties = .{ .backing = .hardware, .extractable = false, .persistent = false },
    }, .ecdsa_p256));
}

test "a simulated endpoint is never reported as hardware-backed" {
    // The distinction is a caller statement because a simulator answers the
    // identity commands exactly as hardware does; what matters is that the
    // capability output cannot claim hardware protection for a simulator run.
    var sim = TPMProvider.init(.{ .tcti = "device:/nonexistent/x", .simulated = true });
    defer sim.deinit();
    try testing.expectEqual(Backing.software_token, sim.backing);

    var hw = TPMProvider.init(.{ .tcti = "device:/nonexistent/x", .simulated = false });
    defer hw.deinit();
    try testing.expectEqual(Backing.hardware, hw.backing);
}

test "provider status maps each cause to its own error" {
    // A single `is_available` bool cannot express these, which is why the
    // previous version reported missing permissions as missing hardware.
    try testing.expectEqual(HSMError.DeviceAbsent, (ProviderStatus{ .device_absent = {} }).toError());
    try testing.expectEqual(HSMError.PermissionDenied, (ProviderStatus{ .permission_denied = {} }).toError());
    try testing.expectEqual(HSMError.LibraryAbsent, (ProviderStatus{ .library_absent = {} }).toError());
    try testing.expectEqual(HSMError.AuthenticationFailed, (ProviderStatus{ .authentication_failed = {} }).toError());
    try testing.expectEqual(HSMError.ProviderNotBuilt, (ProviderStatus{ .not_built = {} }).toError());
    try testing.expectEqual(HSMError.OperationFailed, (ProviderStatus{ .initialization_failed = {} }).toError());
    try testing.expectEqual(
        HSMError.HardwareBackingRefused,
        (ProviderStatus{ .hardware_backing_refused = {} }).toError(),
    );
}

test "an unready provider advertises no operations" {
    const status = ProviderStatus{ .device_absent = {} };
    inline for (comptime std.enums.values(Operation)) |op| {
        try testing.expect(!status.supports(op));
    }
}

test "an unavailable token says why, rather than blaming the mechanism" {
    // `supports` is false for every operation on an unready provider, so the
    // operation gate had to be ordered after the readiness gate. Without that,
    // "there is no module at this path" reached the caller as
    // `UnsupportedMechanism`, which reads as "ask for a different algorithm"
    // — an answer that is wrong and actionable at the same time.
    var provider = PKCS11Provider.init(.{ .module_path = "/nonexistent/zcrypto-pkcs11-probe.so" });
    defer provider.deinit();

    try testing.expect(!provider.status.isReady());
    const expected = provider.status.toError();
    try testing.expect(expected != HSMError.UnsupportedMechanism);
    try testing.expectError(expected, provider.generateSigningKey());
}

test "a Secure Enclave provider reports which kind of absence it hit" {
    var provider = SecureEnclaveProvider.init(.{});
    defer provider.deinit();

    if (secure_enclave_backend.is_real_backend) {
        // On a Mac with an enclave this is ready; on one without, the backend
        // said so and the provider must repeat that rather than flatten it to
        // a generic failure. Either way it must never be `not_built`: this
        // build really did ask the hardware.
        try testing.expect(std.meta.activeTag(provider.status) != .not_built);
        if (!provider.status.isReady()) {
            try testing.expectEqual(
                std.meta.activeTag(ProviderStatus{ .device_absent = {} }),
                std.meta.activeTag(provider.status),
            );
        }
    } else {
        // No Security.framework in this build, so nothing was asked. Saying
        // `device_absent` here would send someone looking for a different Mac
        // when the fix is `-Dsecure-enclave=true`.
        try testing.expectEqual(
            std.meta.activeTag(ProviderStatus{ .not_built = {} }),
            std.meta.activeTag(provider.status),
        );
        try testing.expectError(HSMError.ProviderNotBuilt, provider.generateSigningKey());
    }
}

test "the Secure Enclave provider never advertises what the enclave cannot do" {
    var provider = SecureEnclaveProvider.init(.{});
    defer provider.deinit();

    // Only meaningful once the provider is ready; on a host without an
    // enclave the empty set is already covered by the test above.
    if (!provider.status.isReady()) return;

    // The enclave has no RNG, no sealing and no attestation. Advertising any
    // of them would invite `HSMInterface` to route the call here and answer it
    // from somewhere that is not hardware — which is how the previous
    // "hardware" provider ended up serving `getHardwareRandom` from the OS
    // CSPRNG.
    try testing.expect(!provider.status.supports(.random));
    try testing.expect(!provider.status.supports(.seal));
    try testing.expect(!provider.status.supports(.unseal));
    try testing.expect(!provider.status.supports(.attestation_quote));

    try testing.expect(provider.status.supports(.sign));
    try testing.expect(provider.status.supports(.key_agreement));
}

test "the Secure Enclave provider's backing is hardware because the enclave attests it" {
    // Unlike the TPM and PKCS#11 providers there is no config field that could
    // say otherwise, and that is the point: residency is read back off the key
    // rather than asserted by the caller, so there is nothing here to lie
    // with. A future config knob that softened this would fail this test.
    var provider = SecureEnclaveProvider.init(.{});
    defer provider.deinit();
    try testing.expectEqual(Backing.hardware, provider.backing);
}
