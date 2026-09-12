//! Real TPM 2.0 backend built on the TPM2-TSS ESAPI stack.
//!
//! This module talks to an actual TPM. It is compiled only when the build is
//! configured with `-Dtpm=true`, which links `tss2-esys`, `tss2-tctildr` and
//! `tss2-rc` from the host. The dependency is opt-in precisely so that an
//! ordinary zcrypto build stays free of native library requirements; when the
//! flag is off, `hsm.zig` uses `tpm2_absent.zig` instead and every entry point
//! reports the backend as not built.
//!
//! What leaves the TPM, stated once here because the old API lied about it:
//!   - `getRandom` returns bytes produced by the TPM RNG.
//!   - `SigningKey` private material never leaves the TPM. Only the public
//!     point is exported, and `signDigest` sends a digest in and gets a
//!     signature out.
//!   - `quote` returns a TPM-signed statement about PCR contents bound to a
//!     caller nonce. The nonce is inside the signed blob, not alongside it.
//!   - `seal` sends a secret in and returns a blob encrypted to this TPM under
//!     a storage parent; `unseal` returns the plaintext. The sealed blob is
//!     not secret and is useless on any other TPM. This replaces the old
//!     `deriveKey`, which was host-side HKDF over a hardcoded 0x42 key wearing
//!     a TPM label. TPM 2.0 exposes no generic HKDF, so there is no `deriveKey`
//!     here: a caller who wants derived keys runs a named KDF host-side and
//!     says so, or seals the root secret with this API.

const std = @import("std");
const builtin = @import("builtin");
const c = @import("tss2");

/// See `tpm2_absent.is_real_backend`. Both backends declare it so a caller can
/// tell which one it was compiled against without a build-option import.
pub const is_real_backend = true;

/// Errors distinguish *why* the backend is unusable. The previous code
/// collapsed every one of these into "not available", which made a permission
/// problem indistinguishable from absent hardware and an unsupported algorithm
/// indistinguishable from a broken device.
/// Observation seam for `unseal`'s handling of the response buffer, present in
/// test builds only.
///
/// Whether the plaintext was wiped before ESAPI reclaimed its buffer cannot be
/// checked from outside `unseal`: by the time the caller regains control the
/// allocation is already gone. This records the one fact worth knowing at the
/// moment of release.
///
/// It records a boolean and not the bytes. A seam that copied the recovered
/// plaintext into a global to let a test inspect it would create exactly the
/// leak it exists to detect.
const unseal_seam = if (builtin.is_test) struct {
    var released_zeroed: ?bool = null;
} else struct {};

/// Forget any previous observation, so a test reads its own result rather than
/// an earlier test's. Test builds only.
pub fn resetUnsealObservationForTesting() void {
    comptime std.debug.assert(builtin.is_test);
    unseal_seam.released_zeroed = null;
}

/// Whether `unseal`'s response buffer was all zeros when it was released, or
/// null if no unseal has reached that point since the last reset. Test builds
/// only.
pub fn unsealBufferWasZeroedForTesting() ?bool {
    comptime std.debug.assert(builtin.is_test);
    return unseal_seam.released_zeroed;
}

pub const TpmError = error{
    /// No TPM device at the configured path.
    DeviceAbsent,
    /// The device exists but this process may not open it.
    PermissionDenied,
    /// TCTI could not be loaded or connected (bad conf string, dead simulator).
    TransportUnavailable,
    /// ESAPI context creation failed.
    ContextInitFailed,
    /// The device answered, but is not a TPM 2.0.
    NotTpm2,
    /// The TPM rejected the command as unsupported.
    UnsupportedMechanism,
    /// The key is restricted and the TPM refuses to use it this way, e.g.
    /// signing caller-supplied data with an attestation key.
    RestrictedKey,
    /// The TPM returned an error for a well-formed command.
    CommandFailed,
    /// The TPM returned a structurally invalid response.
    MalformedResponse,
    /// The RNG made no forward progress within the retry budget.
    EntropyStalled,
    /// Caller buffer too small for the result.
    BufferTooSmall,
    /// Authorization failed (bad auth value / policy).
    AuthorizationFailed,
    /// The TPM's dictionary-attack defence has tripped: it is refusing
    /// authorized commands until the lockout interval passes or
    /// `resetDictionaryAttackLock` clears it. Distinct from
    /// `AuthorizationFailed`, which is one wrong credential; this is the device
    /// declining to be asked again.
    DictionaryLockout,
    /// The TPM has no free transient object or session slot. A device state
    /// the caller can act on by flushing something, not a malfunction.
    ResourcesExhausted,
    /// Never returned by this module. Declared so that this error set and
    /// `tpm2_absent.TpmError` are identical, which lets `hsm.zig` handle one
    /// error union across both backends.
    BackendNotBuilt,
    OutOfMemory,
};

/// How to reach the TPM. Explicit rather than inferred: a caller running
/// against a simulator and a caller running against `/dev/tpmrm0` differ only
/// in this value, and neither is guessed from the environment.
pub const Config = struct {
    /// TCTI configuration string, e.g. `"device:/dev/tpmrm0"` or
    /// `"swtpm:host=127.0.0.1,port=2321"`.
    tcti: [:0]const u8 = "device:/dev/tpmrm0",
    /// Send TPM2_Startup on open. A simulator generally needs this; a TPM the
    /// firmware already started answers TPM2_RC_INITIALIZE, which is accepted.
    send_startup: bool = false,
    /// Bound on GetRandom round trips before declaring the RNG stalled.
    entropy_retry_budget: u8 = 8,
};

/// Identity read out of the device rather than assumed.
pub const DeviceInfo = struct {
    /// TPM2_PT_FAMILY_INDICATOR as four ASCII bytes, e.g. "2.0\x00".
    family: [4]u8,
    /// TPM2_PT_MANUFACTURER as four ASCII bytes.
    manufacturer: [4]u8,
};

/// A TPM-resident key. The handle is the ESAPI object reference, not a
/// fabricated integer id, and it is bound to the context that created it:
/// `session_epoch` is checked on every use so a handle from a closed context
/// cannot be replayed against a new one.
pub const SigningKey = struct {
    handle: c.ESYS_TR,
    session_epoch: u64,
    /// Uncompressed SEC1 public point (0x04 || X || Y) for NIST P-256.
    public_sec1: [65]u8,
    /// True when the key was created `restricted`, i.e. usable for Quote but
    /// not for signing arbitrary external data.
    restricted: bool,

    pub fn publicKey(self: SigningKey) !std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&self.public_sec1);
    }
};

/// A quote: the TPM's signed statement about PCR contents plus caller nonce.
pub const Quote = struct {
    /// TPMS_ATTEST structure, marshalled. This is what was signed.
    attested: []u8,
    /// ECDSA signature over SHA-256(attested), as r || s.
    signature: [64]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Quote) void {
        self.allocator.free(self.attested);
        self.* = undefined;
    }
};

/// A TPM storage key: the parent a sealed object is encrypted to. Restricted
/// decrypt, so it can wrap children and cannot be used to sign or to decrypt
/// caller-chosen ciphertext.
pub const StorageKey = struct {
    handle: c.ESYS_TR,
    session_epoch: u64,
};

/// A sealed blob. Both halves are required to unseal and neither is secret:
/// this is ciphertext under a key that never leaves the TPM, so it is safe to
/// write to ordinary storage and useless on any other TPM.
///
/// Both halves are held in the TPM's canonical wire encoding, produced by
/// `Tss2_MU_*_Marshal`, not as a memory image of a C struct. A struct image
/// would embed this compiler's padding and endianness and would stop loading
/// after a library or architecture change, which for sealed application keys
/// means unrecoverable data.
pub const SealedBlob = struct {
    public: []u8,
    private: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SealedBlob) void {
        self.allocator.free(self.public);
        self.allocator.free(self.private);
        self.* = undefined;
    }

    /// What the stored public half says about how this object may be
    /// authorized.
    ///
    /// Read from the blob rather than from the `SealOptions` that produced it,
    /// because the blob is what gets written to disk and handed to whatever
    /// unseals it later -- this library or `tpm2-tools` or anything else. The
    /// options are a statement of intent; this is the artifact.
    pub fn guards(self: SealedBlob) TpmError!BlobGuards {
        var public = std.mem.zeroes(c.TPM2B_PUBLIC);
        var offset: usize = 0;
        if (c.Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            self.public.ptr,
            self.public.len,
            &offset,
            &public,
        ) != c.TPM2_RC_SUCCESS) return TpmError.MalformedResponse;

        return .{
            .policy_bound = public.publicArea.authPolicy.size > 0,
            .auth_value_suffices = (public.publicArea.objectAttributes & c.TPMA_OBJECT_USERWITHAUTH) != 0,
        };
    }
};

/// How a `SealedBlob` may be authorized, as recorded in the blob itself.
pub const BlobGuards = struct {
    /// A policy digest is recorded, so satisfying that policy is a way to
    /// authorize the object.
    policy_bound: bool,
    /// `TPMA_OBJECT_USERWITHAUTH` is set, so the object's auth value alone
    /// satisfies the USER role.
    ///
    /// On a policy-bound object this is the difference between a policy that is
    /// enforced and one that is merely recorded: with the bit set, a caller
    /// presenting the (possibly empty) auth value unseals the object and the
    /// policy is never evaluated. Nothing in this module would notice, because
    /// `unsealWithPolicy` opens a policy session whenever a policy digest is
    /// present -- the weakness is only reachable by other TPM software, which
    /// is exactly why it has to be asserted on the blob and not on this
    /// module's behaviour.
    auth_value_suffices: bool,
};

/// The largest auth value this module accepts, in bytes.
///
/// A TPM refuses an auth value longer than the digest produced by the object's
/// `nameAlg`, and every object here is created with SHA-256. Bounding it in Zig
/// turns a caller mistake into a named error instead of `TPM2_RC_SIZE` from the
/// device, which is indistinguishable from a secret that was too large to seal.
pub const max_auth_len = 32;

/// Which SHA-256 PCRs a sealed object's policy is bound to.
///
/// SHA-256 only, matching `readPcrSha256` and `quote`. A TPM may implement
/// several banks, and a policy over the SHA-1 bank of a device that also has
/// SHA-256 is a weaker statement than a caller asking for "PCR 7" expects; the
/// bank is therefore not a parameter rather than being a parameter with a
/// dangerous value.
pub const PcrPolicy = struct {
    /// PCR indices, in the order the caller wants them selected. The selection
    /// sent to the TPM is a bitmap, so order and duplicates do not affect the
    /// resulting policy digest.
    indices: []const u5,
};

/// What guards a sealed object, chosen at seal time and re-presented at unseal.
///
/// The default — both fields null — is the device-bound wrapping that `seal`
/// has always provided, and is what `seal`/`unseal` pass. Each field added
/// narrows who can unseal:
///
///   - `auth`: the caller must present this value. Without it the TPM refuses
///     with `AuthorizationFailed`. This is the caller authorization that plain
///     `seal` explicitly does not offer.
///   - `pcrs`: the named PCRs must hold, at unseal time, the values they held
///     at seal time. This is trusted-boot sealing: a machine that booted
///     differently cannot unseal, on the same TPM, with the right auth value.
///
/// Both may be set, in which case both must hold.
pub const SealOptions = struct {
    auth: ?[]const u8 = null,
    pcrs: ?PcrPolicy = null,

    /// True when the object needs a policy session rather than a plain auth
    /// value. An auth value on its own rides `TPMA_OBJECT_USERWITHAUTH`, which
    /// needs no policy; a PCR binding has no expression other than a policy.
    fn needsPolicy(self: SealOptions) bool {
        return self.pcrs != null;
    }
};

/// Monotonic across all contexts in the process, so a handle minted by one
/// context is never silently accepted by another.
///
/// `std.atomic.Value(u64)` directly rather than `util.Counter64`, which exists
/// precisely to make this portable to a target without 64-bit atomics. This
/// file is its own Zig module (`tpm_backend`), and `@import("../util.zig")`
/// would put `src/util.zig` in both that module and `zcrypto`, which Zig
/// rejects. The counter is also not worth restructuring the build graph for:
/// this backend links libtss2 and talks to a TPM, so wasm32 is not a target it
/// can ever have.
var epoch_counter = std.atomic.Value(u64).init(1);

pub const Tpm = struct {
    allocator: std.mem.Allocator,
    tcti: ?*c.TSS2_TCTI_CONTEXT,
    esys: ?*c.ESYS_CONTEXT,
    info: DeviceInfo,
    epoch: u64,
    entropy_retry_budget: u8,

    /// Open a TPM. Failure modes are distinguished, not merged.
    pub fn open(allocator: std.mem.Allocator, config: Config) TpmError!Tpm {
        // Probing the device node first is what makes "absent" and "present
        // but I cannot open it" different answers. TCTI reports both as a
        // generic IO error, which is how the old code ended up claiming a
        // host had no TPM when it merely lacked group membership.
        try probeDevicePath(config.tcti);

        var tcti: ?*c.TSS2_TCTI_CONTEXT = null;
        if (c.Tss2_TctiLdr_Initialize(config.tcti.ptr, &tcti) != c.TPM2_RC_SUCCESS) {
            return TpmError.TransportUnavailable;
        }
        errdefer c.Tss2_TctiLdr_Finalize(&tcti);

        var esys: ?*c.ESYS_CONTEXT = null;
        if (c.Esys_Initialize(&esys, tcti, null) != c.TPM2_RC_SUCCESS) {
            return TpmError.ContextInitFailed;
        }
        errdefer c.Esys_Finalize(&esys);

        if (config.send_startup) {
            const rc = c.Esys_Startup(esys, c.TPM2_SU_CLEAR);
            // A TPM the firmware already started reports INITIALIZE. That is
            // the expected answer on real hardware, not a failure.
            if (rc != c.TPM2_RC_SUCCESS and rc != c.TPM2_RC_INITIALIZE) {
                return mapTpmError(rc);
            }
        }

        var self = Tpm{
            .allocator = allocator,
            .tcti = tcti,
            .esys = esys,
            .info = undefined,
            .epoch = epoch_counter.fetchAdd(1, .monotonic),
            .entropy_retry_budget = config.entropy_retry_budget,
        };

        // Ask the device what it is. The old provider hardcoded
        // `.version = .tpm_2_0` with the comment "assume TPM 2.0 for modern
        // systems"; this reads TPM2_PT_FAMILY_INDICATOR and refuses anything
        // that does not answer "2.0".
        self.info = try self.readIdentity();
        if (!std.mem.eql(u8, self.info.family[0..3], "2.0")) return TpmError.NotTpm2;

        return self;
    }

    pub fn close(self: *Tpm) void {
        c.Esys_Finalize(&self.esys);
        c.Tss2_TctiLdr_Finalize(&self.tcti);
        self.* = undefined;
    }

    fn readIdentity(self: *Tpm) TpmError!DeviceInfo {
        return DeviceInfo{
            .family = try self.readFixedProperty(c.TPM2_PT_FAMILY_INDICATOR),
            .manufacturer = try self.readFixedProperty(c.TPM2_PT_MANUFACTURER),
        };
    }

    fn readFixedProperty(self: *Tpm, property: u32) TpmError![4]u8 {
        var more: c.TPMI_YES_NO = 0;
        var data: [*c]c.TPMS_CAPABILITY_DATA = null;
        const rc = c.Esys_GetCapability(
            self.esys,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.TPM2_CAP_TPM_PROPERTIES,
            property,
            1,
            &more,
            &data,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        defer c.Esys_Free(data);

        const props = data.*.data.tpmProperties;
        // The TPM may legitimately return the *next* property if the one asked
        // for is unimplemented, so the identity of the answer is checked, not
        // just its presence.
        if (props.count < 1) return TpmError.MalformedResponse;
        if (props.tpmProperty[0].property != property) return TpmError.MalformedResponse;

        const v = props.tpmProperty[0].value;
        return [4]u8{
            @truncate(v >> 24),
            @truncate(v >> 16),
            @truncate(v >> 8),
            @truncate(v),
        };
    }

    /// Fill `out` with TPM-generated entropy.
    ///
    /// TPM2_GetRandom is permitted to return fewer bytes than requested, so
    /// this loops. Three things are enforced that a naive single-shot call
    /// would miss: the response can never be longer than requested (a longer
    /// one would overflow the caller's buffer), a response of zero bytes is
    /// counted against a retry budget rather than spun on forever, and the
    /// request size is clamped to UINT16 because that is the wire type.
    pub fn getRandom(self: *Tpm, out: []u8) TpmError!void {
        var filled: usize = 0;
        var stalls: u8 = 0;

        while (filled < out.len) {
            const remaining = out.len - filled;
            const want: u16 = @intCast(@min(remaining, std.math.maxInt(u16)));

            var digest: [*c]c.TPM2B_DIGEST = null;
            const rc = c.Esys_GetRandom(
                self.esys,
                c.ESYS_TR_NONE,
                c.ESYS_TR_NONE,
                c.ESYS_TR_NONE,
                want,
                &digest,
            );
            if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
            defer c.Esys_Free(digest);

            const got = digest.*.size;
            // A TPM returning more than asked for is a broken or hostile
            // device; copying it would be a buffer overflow.
            if (got > want) return TpmError.MalformedResponse;

            if (got == 0) {
                stalls += 1;
                if (stalls >= self.entropy_retry_budget) return TpmError.EntropyStalled;
                continue;
            }
            stalls = 0;

            @memcpy(out[filled..][0..got], digest.*.buffer[0..got]);
            filled += got;
        }
    }

    /// Read one SHA-256 PCR.
    pub fn readPcrSha256(self: *Tpm, index: u5) TpmError![32]u8 {
        var selection = pcrSelectionSha256(&.{index});

        var update_counter: u32 = 0;
        var out_selection: [*c]c.TPML_PCR_SELECTION = null;
        var values: [*c]c.TPML_DIGEST = null;

        const rc = c.Esys_PCR_Read(
            self.esys,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &selection,
            &update_counter,
            &out_selection,
            &values,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        defer c.Esys_Free(out_selection);
        defer c.Esys_Free(values);

        if (values.*.count < 1) return TpmError.MalformedResponse;
        if (values.*.digests[0].size != 32) return TpmError.MalformedResponse;

        var pcr: [32]u8 = undefined;
        @memcpy(&pcr, values.*.digests[0].buffer[0..32]);
        return pcr;
    }

    /// Extend `digest` into SHA-256 PCR `index`, setting it to
    /// SHA-256(old ‖ digest).
    ///
    /// A PCR cannot be assigned, only extended, which is what makes its value a
    /// summary of everything measured into it in order. This is therefore a
    /// one-way change to shared device state: every policy already sealed to
    /// `index` stops unsealing, and nothing here can put the old value back.
    /// The TPM's own locality and platform rules decide which PCRs a caller may
    /// extend at all -- the firmware-owned ones generally refuse, surfacing as
    /// `AuthorizationFailed` or `CommandFailed`.
    ///
    /// Present because `sealWithPolicy` without it is a facility a caller can
    /// neither exercise nor test: sealing to PCRs is only meaningful if
    /// something measures into them, and a refusal that cannot be provoked is
    /// an unverified claim.
    pub fn extendPcrSha256(self: *Tpm, index: u5, digest: [32]u8) TpmError!void {
        var values = std.mem.zeroes(c.TPML_DIGEST_VALUES);
        values.count = 1;
        values.digests[0].hashAlg = c.TPM2_ALG_SHA256;
        @memcpy(values.digests[0].digest.sha256[0..32], &digest);

        // `index` is both the PCR being extended and its own authorization:
        // ESAPI maps a PCR handle onto itself, and the PCR's auth policy is
        // what the TPM consults.
        const rc = c.Esys_PCR_Extend(
            self.esys,
            @as(c.ESYS_TR, index),
            c.ESYS_TR_PASSWORD,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &values,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
    }

    /// Clear the TPM's dictionary-attack lockout, restoring the failed-attempt
    /// counter to zero.
    ///
    /// Needs lockout-hierarchy authorization, which is empty on a fresh TPM and
    /// is normally set to an owner secret during provisioning; where it has
    /// been set this refuses with `AuthorizationFailed`. That is the intended
    /// shape of the thing -- a lockout an unauthorized caller could clear would
    /// not be a defence.
    ///
    /// Present because `DictionaryLockout` is otherwise a state a caller can
    /// reach and cannot leave: a handful of wrong auth values is enough to trip
    /// it, and the alternative recovery is waiting out an interval the TPM's
    /// provisioning chose.
    pub fn resetDictionaryAttackLock(self: *Tpm) TpmError!void {
        const rc = c.Esys_DictionaryAttackLockReset(
            self.esys,
            c.ESYS_TR_RH_LOCKOUT,
            c.ESYS_TR_PASSWORD,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
    }

    /// Create a primary NIST P-256 signing key in the owner hierarchy.
    ///
    /// `restricted = true` produces an attestation key: it can sign
    /// TPM-generated structures such as a quote, and the TPM will refuse to
    /// sign caller-supplied data with it. `restricted = false` produces a key
    /// usable with `signDigest`. The distinction is a TPM rule, not a policy
    /// invented here, which is why both variants exist.
    ///
    /// Each call returns a *different* key. That is not automatic: a primary is
    /// derived by the TPM from the hierarchy seed and the template, so the
    /// fixed template this function used to send made every call re-derive one
    /// key. Two "generated" keys then had the same public point and the same
    /// private key, and a caller holding several was holding one. The template's
    /// `unique` field is extra derivation input, so seeding it per call is what
    /// makes this a generator rather than a lookup.
    ///
    /// The consequence of seeding from entropy is that these keys are not
    /// re-derivable: nothing records the seed, so once the handle is flushed the
    /// key is gone. That matches how they are used -- transient objects held by
    /// handle for the life of one context -- and no entry point here offers to
    /// recover a key, so nothing is being taken away.
    pub fn createPrimarySigningKey(self: *Tpm, restricted: bool) TpmError!SigningKey {
        // From the TPM's RNG rather than the host's: the seed is derivation
        // input for an on-device key, and `getRandom` is already the audited
        // path for asking this device for bytes.
        var unique_seed: [32]u8 = undefined;
        try self.getRandom(&unique_seed);

        var in_sensitive = std.mem.zeroes(c.TPM2B_SENSITIVE_CREATE);

        var in_public = std.mem.zeroes(c.TPM2B_PUBLIC);
        const pa = &in_public.publicArea;
        pa.type = c.TPM2_ALG_ECC;
        pa.nameAlg = c.TPM2_ALG_SHA256;
        pa.unique.ecc.x.size = unique_seed.len;
        @memcpy(pa.unique.ecc.x.buffer[0..unique_seed.len], &unique_seed);
        pa.objectAttributes =
            c.TPMA_OBJECT_FIXEDTPM |
            c.TPMA_OBJECT_FIXEDPARENT |
            c.TPMA_OBJECT_SENSITIVEDATAORIGIN |
            c.TPMA_OBJECT_USERWITHAUTH |
            c.TPMA_OBJECT_SIGN_ENCRYPT |
            (if (restricted) c.TPMA_OBJECT_RESTRICTED else 0);
        pa.parameters.eccDetail.symmetric.algorithm = c.TPM2_ALG_NULL;
        pa.parameters.eccDetail.scheme.scheme = c.TPM2_ALG_ECDSA;
        pa.parameters.eccDetail.scheme.details.ecdsa.hashAlg = c.TPM2_ALG_SHA256;
        pa.parameters.eccDetail.curveID = c.TPM2_ECC_NIST_P256;
        pa.parameters.eccDetail.kdf.scheme = c.TPM2_ALG_NULL;

        const outside_info = std.mem.zeroes(c.TPM2B_DATA);
        const creation_pcr = std.mem.zeroes(c.TPML_PCR_SELECTION);

        var handle: c.ESYS_TR = c.ESYS_TR_NONE;
        var out_public: [*c]c.TPM2B_PUBLIC = null;
        var creation_data: [*c]c.TPM2B_CREATION_DATA = null;
        var creation_hash: [*c]c.TPM2B_DIGEST = null;
        var creation_ticket: [*c]c.TPMT_TK_CREATION = null;

        const rc = c.Esys_CreatePrimary(
            self.esys,
            c.ESYS_TR_RH_OWNER,
            c.ESYS_TR_PASSWORD,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &in_sensitive,
            &in_public,
            &outside_info,
            &creation_pcr,
            &handle,
            &out_public,
            &creation_data,
            &creation_hash,
            &creation_ticket,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        defer c.Esys_Free(out_public);
        defer c.Esys_Free(creation_data);
        defer c.Esys_Free(creation_hash);
        defer c.Esys_Free(creation_ticket);

        // If anything below fails the transient object must not be left
        // occupying a TPM slot; TPMs have very few.
        errdefer _ = c.Esys_FlushContext(self.esys, handle);

        const point = out_public.*.publicArea.unique.ecc;
        if (point.x.size != 32 or point.y.size != 32) return TpmError.MalformedResponse;

        var sec1: [65]u8 = undefined;
        sec1[0] = 0x04;
        @memcpy(sec1[1..33], point.x.buffer[0..32]);
        @memcpy(sec1[33..65], point.y.buffer[0..32]);

        // Reject a point the TPM claims but that is not actually on the
        // curve. Parsing it here means every returned SigningKey has a
        // usable public key rather than one that fails much later.
        _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&sec1) catch {
            return TpmError.MalformedResponse;
        };

        return SigningKey{
            .handle = handle,
            .session_epoch = self.epoch,
            .public_sec1 = sec1,
            .restricted = restricted,
        };
    }

    /// Sign a SHA-256 digest with a TPM-resident key, returning r || s.
    pub fn signDigest(self: *Tpm, key: SigningKey, digest: [32]u8) TpmError![64]u8 {
        try self.checkHandle(key.session_epoch);

        var tpm_digest = std.mem.zeroes(c.TPM2B_DIGEST);
        tpm_digest.size = 32;
        @memcpy(tpm_digest.buffer[0..32], &digest);

        var scheme = std.mem.zeroes(c.TPMT_SIG_SCHEME);
        scheme.scheme = c.TPM2_ALG_ECDSA;
        scheme.details.ecdsa.hashAlg = c.TPM2_ALG_SHA256;

        // A null hashcheck ticket says "this digest did not come from the
        // TPM". A restricted key refuses exactly this, which is why
        // signDigest is documented as unrestricted-key-only.
        var validation = std.mem.zeroes(c.TPMT_TK_HASHCHECK);
        validation.tag = c.TPM2_ST_HASHCHECK;
        validation.hierarchy = c.TPM2_RH_NULL;

        var signature: [*c]c.TPMT_SIGNATURE = null;
        const rc = c.Esys_Sign(
            self.esys,
            key.handle,
            c.ESYS_TR_PASSWORD,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &tpm_digest,
            &scheme,
            &validation,
            &signature,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        defer c.Esys_Free(signature);

        return extractEcdsa(signature);
    }

    /// Produce a quote over the selected SHA-256 PCRs, bound to `nonce`.
    ///
    /// `key` must be restricted (an attestation key); the TPM enforces this.
    /// The caller nonce lands in the `extraData` field of the signed
    /// TPMS_ATTEST, which is what makes the quote fresh. A verifier that does
    /// not check it is verifying nothing about liveness.
    pub fn quote(
        self: *Tpm,
        key: SigningKey,
        pcr_indices: []const u5,
        nonce: []const u8,
    ) TpmError!Quote {
        try self.checkHandle(key.session_epoch);
        if (nonce.len > @sizeOf(@TypeOf(std.mem.zeroes(c.TPM2B_DATA).buffer))) {
            return TpmError.BufferTooSmall;
        }

        var qualifying = std.mem.zeroes(c.TPM2B_DATA);
        qualifying.size = @intCast(nonce.len);
        @memcpy(qualifying.buffer[0..nonce.len], nonce);

        var scheme = std.mem.zeroes(c.TPMT_SIG_SCHEME);
        scheme.scheme = c.TPM2_ALG_ECDSA;
        scheme.details.ecdsa.hashAlg = c.TPM2_ALG_SHA256;

        var selection = pcrSelectionSha256(pcr_indices);

        var quoted: [*c]c.TPM2B_ATTEST = null;
        var signature: [*c]c.TPMT_SIGNATURE = null;

        const rc = c.Esys_Quote(
            self.esys,
            key.handle,
            c.ESYS_TR_PASSWORD,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &qualifying,
            &scheme,
            &selection,
            &quoted,
            &signature,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        defer c.Esys_Free(quoted);
        defer c.Esys_Free(signature);

        const sig = try extractEcdsa(signature);

        const attested = self.allocator.alloc(u8, quoted.*.size) catch return TpmError.OutOfMemory;
        errdefer self.allocator.free(attested);
        @memcpy(attested, quoted.*.attestationData[0..quoted.*.size]);

        return Quote{
            .attested = attested,
            .signature = sig,
            .allocator = self.allocator,
        };
    }

    /// Create a primary restricted-decrypt storage key in the owner hierarchy.
    ///
    /// This is the parent that sealed blobs are encrypted to. It is derived
    /// deterministically from the owner primary seed, so the same template on
    /// the same TPM reproduces the same parent and a blob sealed in one
    /// process unseals in the next — without any persistent handle being
    /// created, which is what keeps this API from mutating TPM state the
    /// caller did not ask it to mutate.
    pub fn createPrimaryStorageKey(self: *Tpm) TpmError!StorageKey {
        var in_sensitive = std.mem.zeroes(c.TPM2B_SENSITIVE_CREATE);

        var in_public = std.mem.zeroes(c.TPM2B_PUBLIC);
        const pa = &in_public.publicArea;
        pa.type = c.TPM2_ALG_ECC;
        pa.nameAlg = c.TPM2_ALG_SHA256;
        pa.objectAttributes =
            c.TPMA_OBJECT_FIXEDTPM |
            c.TPMA_OBJECT_FIXEDPARENT |
            c.TPMA_OBJECT_SENSITIVEDATAORIGIN |
            c.TPMA_OBJECT_USERWITHAUTH |
            c.TPMA_OBJECT_RESTRICTED |
            c.TPMA_OBJECT_DECRYPT;
        // A storage parent wraps its children with this symmetric algorithm.
        // TPM2_ALG_NULL here — correct for a signing key — makes the TPM
        // reject the object as an invalid parent.
        pa.parameters.eccDetail.symmetric.algorithm = c.TPM2_ALG_AES;
        pa.parameters.eccDetail.symmetric.keyBits.aes = 128;
        pa.parameters.eccDetail.symmetric.mode.aes = c.TPM2_ALG_CFB;
        pa.parameters.eccDetail.scheme.scheme = c.TPM2_ALG_NULL;
        pa.parameters.eccDetail.curveID = c.TPM2_ECC_NIST_P256;
        pa.parameters.eccDetail.kdf.scheme = c.TPM2_ALG_NULL;

        const outside_info = std.mem.zeroes(c.TPM2B_DATA);
        const creation_pcr = std.mem.zeroes(c.TPML_PCR_SELECTION);

        var handle: c.ESYS_TR = c.ESYS_TR_NONE;
        var out_public: [*c]c.TPM2B_PUBLIC = null;
        var creation_data: [*c]c.TPM2B_CREATION_DATA = null;
        var creation_hash: [*c]c.TPM2B_DIGEST = null;
        var creation_ticket: [*c]c.TPMT_TK_CREATION = null;

        const rc = c.Esys_CreatePrimary(
            self.esys,
            c.ESYS_TR_RH_OWNER,
            c.ESYS_TR_PASSWORD,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &in_sensitive,
            &in_public,
            &outside_info,
            &creation_pcr,
            &handle,
            &out_public,
            &creation_data,
            &creation_hash,
            &creation_ticket,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        c.Esys_Free(out_public);
        c.Esys_Free(creation_data);
        c.Esys_Free(creation_hash);
        c.Esys_Free(creation_ticket);

        return StorageKey{ .handle = handle, .session_epoch = self.epoch };
    }

    // =========================================================================
    // Sessions and policy
    //
    // Three things happen here that plain `ESYS_TR_PASSWORD` cannot do:
    // encrypt command and response parameters on the bus, carry a PCR
    // assertion, and carry an auth value without sending it in the clear.
    // =========================================================================

    /// Start a session salted to `parent` with AES-128-CFB parameter
    /// encryption.
    ///
    /// Salting is the part that matters and the part that is easy to leave
    /// out: an unsalted, unbound session derives its key from nonces that a bus
    /// observer sees, so it encrypts parameters against nobody. Passing
    /// `parent.handle` as `tpmKey` makes the TPM's own restricted decrypt key
    /// the salt recipient, which is why this takes a `StorageKey` rather than
    /// offering a convenient no-parent form.
    ///
    /// The caller owns the returned handle and must `Esys_FlushContext` it. A
    /// TPM holds very few session slots, so leaking one here would surface much
    /// later as `ResourcesExhausted` on an unrelated call.
    fn startSaltedSession(
        self: *Tpm,
        parent: StorageKey,
        session_type: c.TPM2_SE,
    ) TpmError!c.ESYS_TR {
        var symmetric = std.mem.zeroes(c.TPMT_SYM_DEF);
        symmetric.algorithm = c.TPM2_ALG_AES;
        symmetric.keyBits.aes = 128;
        symmetric.mode.aes = c.TPM2_ALG_CFB;

        var session: c.ESYS_TR = c.ESYS_TR_NONE;
        const rc = c.Esys_StartAuthSession(
            self.esys,
            parent.handle,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            null,
            session_type,
            &symmetric,
            c.TPM2_ALG_SHA256,
            &session,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        errdefer _ = c.Esys_FlushContext(self.esys, session);

        // DECRYPT covers the first command parameter, ENCRYPT the first
        // response parameter -- for the two commands that carry a secret,
        // `TPM2_Create`'s `inSensitive` and `TPM2_Unseal`'s `outData`. Both are
        // set on every session rather than tailored per call, because the cost
        // is nil and the failure mode of getting it wrong is a plaintext on the
        // bus that no test can see.
        const attrs: c.TPMA_SESSION =
            c.TPMA_SESSION_DECRYPT |
            c.TPMA_SESSION_ENCRYPT |
            c.TPMA_SESSION_CONTINUESESSION;
        const set_rc = c.Esys_TRSess_SetAttributes(self.esys, session, attrs, 0xff);
        if (set_rc != c.TPM2_RC_SUCCESS) return mapTpmError(set_rc);

        return session;
    }

    /// A trial session, used only to compute a policy digest.
    ///
    /// Unsalted and unencrypted on purpose: a trial session authorizes nothing
    /// and carries no secret, and salting it would need a parent handle at a
    /// point where the caller may not have one.
    fn startTrialSession(self: *Tpm) TpmError!c.ESYS_TR {
        var symmetric = std.mem.zeroes(c.TPMT_SYM_DEF);
        symmetric.algorithm = c.TPM2_ALG_NULL;

        var session: c.ESYS_TR = c.ESYS_TR_NONE;
        const rc = c.Esys_StartAuthSession(
            self.esys,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            null,
            c.TPM2_SE_TRIAL,
            &symmetric,
            c.TPM2_ALG_SHA256,
            &session,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        return session;
    }

    /// Replay `opts` onto `session`, extending its policy digest.
    ///
    /// One function for both the trial session that computes the digest at seal
    /// time and the real session that must reproduce it at unseal time. The
    /// TPM compares the two digests byte for byte, so any difference in the
    /// assertions or their order is an unrecoverable blob rather than a
    /// diagnosable error -- which is the whole reason this is not written out
    /// twice.
    fn applyPolicy(self: *Tpm, session: c.ESYS_TR, opts: SealOptions) TpmError!void {
        if (opts.pcrs) |pcrs| {
            var selection = pcrSelectionSha256(pcrs.indices);
            // Null `pcrDigest`: the TPM uses the PCRs' current values rather
            // than a digest the caller asserts. On a trial session that records
            // the sealing machine's state; on a real session it records the
            // unsealing machine's. Passing a digest instead would let a caller
            // compute a policy for a boot state the machine is not in, which is
            // the opposite of what sealing to PCRs is for.
            const rc = c.Esys_PolicyPCR(
                self.esys,
                session,
                c.ESYS_TR_NONE,
                c.ESYS_TR_NONE,
                c.ESYS_TR_NONE,
                null,
                &selection,
            );
            if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        }

        if (opts.auth != null) {
            // Records that the auth value is required; the value itself is
            // never part of the policy digest, which is why the same digest
            // works for any auth value and why the check happens at use time.
            const rc = c.Esys_PolicyAuthValue(
                self.esys,
                session,
                c.ESYS_TR_NONE,
                c.ESYS_TR_NONE,
                c.ESYS_TR_NONE,
            );
            if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        }
    }

    /// The policy digest `opts` will require, computed by the TPM on a trial
    /// session rather than by reimplementing the extend chain here.
    fn computePolicyDigest(self: *Tpm, opts: SealOptions) TpmError!c.TPM2B_DIGEST {
        const session = try self.startTrialSession();
        defer _ = c.Esys_FlushContext(self.esys, session);

        try self.applyPolicy(session, opts);

        var digest: [*c]c.TPM2B_DIGEST = null;
        const rc = c.Esys_PolicyGetDigest(
            self.esys,
            session,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &digest,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        defer c.Esys_Free(digest);

        if (digest.*.size > digest.*.buffer.len) return TpmError.MalformedResponse;
        return digest.*;
    }

    /// Seal `secret` to this TPM under `parent`, device-bound and nothing more.
    ///
    /// Equivalent to `sealWithPolicy` with default options; see that function
    /// for what the blob is and what guards it. Kept as its own entry point
    /// because "bound to this device" is a complete answer for a caller who
    /// wants a key that survives a reboot and does not want to manage an auth
    /// value, and because it is the shape every existing caller uses.
    ///
    /// It is not caller authorization -- there is no caller secret to present
    /// or withhold -- and it is not trusted-boot sealing, since no PCR values
    /// enter the policy and a changed boot state unseals identically. Callers
    /// needing either pass `SealOptions` to `sealWithPolicy`.
    pub fn seal(self: *Tpm, parent: StorageKey, secret: []const u8) TpmError!SealedBlob {
        return self.sealWithPolicy(parent, secret, .{});
    }

    /// Seal `secret` to this TPM under `parent`, guarded by `opts`.
    ///
    /// The returned blob is ciphertext plus a public area; neither half is
    /// secret and neither is usable on another TPM. The plaintext is sent to
    /// the TPM once and is not retained by this module.
    ///
    /// What guards the blob, stated as a boundary rather than left to be
    /// inferred from what it refuses. Every blob is bound to the *device*: the
    /// object is wrapped to `parent`, which is re-derived from the owner primary
    /// seed, so no other TPM can unseal it and no state from the sealing context
    /// is needed. That is what makes a blob survive a reboot. On top of that
    /// floor, `opts` adds:
    ///
    ///   - nothing, by default. Anything that can reach this TPM's owner
    ///     hierarchy can unseal.
    ///   - `auth`: the same bytes must be presented to `unsealWithPolicy`.
    ///     Withholding them is a refusal, which makes this caller
    ///     authorization.
    ///   - `pcrs`: the named PCRs must hold at unseal time the values they
    ///     hold now. A machine that booted differently cannot unseal even with
    ///     the right auth value, which makes this trusted-boot sealing.
    ///
    /// Transport: the command runs under a session salted to `parent` with
    /// AES-128-CFB parameter encryption, so `secret` is encrypted between this
    /// process and the TPM rather than crossing a discrete TPM's bus in the
    /// clear. The salt is encrypted to `parent`, a TPM-resident restricted
    /// decrypt key, so a bus observer cannot derive the session key.
    ///
    /// An `auth` value participates in the TPM's dictionary-attack defence, and
    /// the object is deliberately not created with `TPMA_OBJECT_NODA`: a low
    /// entropy auth value is exactly what that defence exists for, and an
    /// unsealing that could be attempted without limit would make a short
    /// passphrase no protection at all. The cost is that a handful of wrong
    /// guesses puts the whole TPM into `DictionaryLockout` until it clears or
    /// `resetDictionaryAttackLock` is called, which is a real operational
    /// consequence of choosing this guard.
    ///
    /// The TPM bounds how much data a sealed object may hold and answers
    /// `TPM2_RC_SIZE` when the limit is exceeded; that surfaces here as
    /// `BufferTooSmall` rather than being pre-judged against a guessed limit.
    pub fn sealWithPolicy(
        self: *Tpm,
        parent: StorageKey,
        secret: []const u8,
        opts: SealOptions,
    ) TpmError!SealedBlob {
        try self.checkHandle(parent.session_epoch);

        var in_sensitive = std.mem.zeroes(c.TPM2B_SENSITIVE_CREATE);
        if (secret.len > in_sensitive.sensitive.data.buffer.len) {
            return TpmError.BufferTooSmall;
        }
        if (opts.auth) |auth| {
            if (auth.len > max_auth_len) return TpmError.BufferTooSmall;
            in_sensitive.sensitive.userAuth.size = @intCast(auth.len);
            @memcpy(in_sensitive.sensitive.userAuth.buffer[0..auth.len], auth);
        }
        in_sensitive.sensitive.data.size = @intCast(secret.len);
        @memcpy(in_sensitive.sensitive.data.buffer[0..secret.len], secret);
        // Armed before the first fallible call below, so no early return leaves
        // the caller's secret and auth value in this frame.
        defer std.crypto.secureZero(u8, std.mem.asBytes(&in_sensitive));

        var in_public = std.mem.zeroes(c.TPM2B_PUBLIC);
        const pa = &in_public.publicArea;
        pa.type = c.TPM2_ALG_KEYEDHASH;
        pa.nameAlg = c.TPM2_ALG_SHA256;
        // No SENSITIVEDATAORIGIN: the data comes from the caller, not from the
        // TPM's RNG. Asserting otherwise makes the TPM refuse the create.
        // No SIGN_ENCRYPT/DECRYPT either — this is an inert data object, and
        // TPM2_ALG_NULL as the scheme is what makes it unsealable rather than
        // an HMAC key.
        pa.objectAttributes =
            c.TPMA_OBJECT_FIXEDTPM |
            c.TPMA_OBJECT_FIXEDPARENT;
        if (opts.needsPolicy()) {
            // USERWITHAUTH stays *clear* here, and that is what makes the
            // policy binding rather than advisory. With it set, presenting the
            // auth value satisfies the USER role and the policy is never
            // evaluated, so a PCR-sealed blob would unseal in any boot state.
            //
            // `unsealWithPolicy` would not expose that: it opens a policy
            // session whenever the blob carries a policy digest, so this
            // module's own round trip behaves identically either way. The
            // weakened blob is only unsealable by *other* TPM software, which
            // is why the test for this reads the attribute back off the blob
            // (`SealedBlob.guards`) instead of asserting a refusal here.
            pa.authPolicy = try self.computePolicyDigest(opts);
        } else {
            pa.objectAttributes |= c.TPMA_OBJECT_USERWITHAUTH;
        }
        pa.parameters.keyedHashDetail.scheme.scheme = c.TPM2_ALG_NULL;

        const outside_info = std.mem.zeroes(c.TPM2B_DATA);
        const creation_pcr = std.mem.zeroes(c.TPML_PCR_SELECTION);

        var out_private: [*c]c.TPM2B_PRIVATE = null;
        var out_public: [*c]c.TPM2B_PUBLIC = null;
        var creation_data: [*c]c.TPM2B_CREATION_DATA = null;
        var creation_hash: [*c]c.TPM2B_DIGEST = null;
        var creation_ticket: [*c]c.TPMT_TK_CREATION = null;

        const session = try self.startSaltedSession(parent, c.TPM2_SE_HMAC);
        defer _ = c.Esys_FlushContext(self.esys, session);

        const rc = c.Esys_Create(
            self.esys,
            parent.handle,
            session,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &in_sensitive,
            &in_public,
            &outside_info,
            &creation_pcr,
            &out_private,
            &out_public,
            &creation_data,
            &creation_hash,
            &creation_ticket,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        defer c.Esys_Free(out_private);
        defer c.Esys_Free(out_public);
        defer c.Esys_Free(creation_data);
        defer c.Esys_Free(creation_hash);
        defer c.Esys_Free(creation_ticket);

        const public = try self.marshalPublic(out_public);
        errdefer self.allocator.free(public);
        const private = try self.marshalPrivate(out_private);

        return SealedBlob{
            .public = public,
            .private = private,
            .allocator = self.allocator,
        };
    }

    /// Unseal a blob produced by `seal` under the same `parent`, writing the
    /// plaintext to `out` and returning its length.
    ///
    /// Equivalent to `unsealWithPolicy` with default options, and correct only
    /// for a blob sealed the same way. A blob carrying an auth value or a PCR
    /// policy is refused here with `AuthorizationFailed` rather than being
    /// unsealed, because the guard is recorded in the object and enforced by
    /// the TPM, not by this function remembering how the blob was made.
    pub fn unseal(self: *Tpm, parent: StorageKey, blob: SealedBlob, out: []u8) TpmError!usize {
        return self.unsealWithPolicy(parent, blob, .{}, out);
    }

    /// Unseal a blob under the same `parent` and the same `opts` it was sealed
    /// with, writing the plaintext to `out` and returning its length.
    ///
    /// Loading is a TPM-side integrity check: a blob whose private half was
    /// altered, or one sealed to a different parent or a different TPM, fails
    /// at `Esys_Load` and never reaches `Esys_Unseal`.
    ///
    /// Whether a policy session is needed is read out of the blob's own public
    /// area, not taken from `opts`. The object records its `authPolicy`, so a
    /// caller who passes the wrong shape of options gets a refusal from the TPM
    /// rather than this function guessing; `opts` supplies only what the object
    /// cannot carry, namely the PCR selection to assert and the auth value to
    /// present.
    ///
    /// The two refusals worth naming, both `AuthorizationFailed`: a wrong or
    /// missing auth value, and a PCR that has changed since the seal. Neither
    /// yields any part of the plaintext.
    ///
    /// Transport: as in `sealWithPolicy`, the unseal runs under a session
    /// salted to `parent` with parameter encryption, so the recovered plaintext
    /// is encrypted on the way back.
    pub fn unsealWithPolicy(
        self: *Tpm,
        parent: StorageKey,
        blob: SealedBlob,
        opts: SealOptions,
        out: []u8,
    ) TpmError!usize {
        try self.checkHandle(parent.session_epoch);
        if (opts.auth) |auth| {
            if (auth.len > max_auth_len) return TpmError.BufferTooSmall;
        }

        var in_public = std.mem.zeroes(c.TPM2B_PUBLIC);
        var offset: usize = 0;
        if (c.Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            blob.public.ptr,
            blob.public.len,
            &offset,
            &in_public,
        ) != c.TPM2_RC_SUCCESS) return TpmError.MalformedResponse;

        var in_private = std.mem.zeroes(c.TPM2B_PRIVATE);
        offset = 0;
        if (c.Tss2_MU_TPM2B_PRIVATE_Unmarshal(
            blob.private.ptr,
            blob.private.len,
            &offset,
            &in_private,
        ) != c.TPM2_RC_SUCCESS) return TpmError.MalformedResponse;

        var item: c.ESYS_TR = c.ESYS_TR_NONE;
        const load_rc = c.Esys_Load(
            self.esys,
            parent.handle,
            c.ESYS_TR_PASSWORD,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &in_private,
            &in_public,
            &item,
        );
        if (load_rc != c.TPM2_RC_SUCCESS) return mapTpmError(load_rc);
        // The loaded object occupies one of the TPM's few slots for the
        // duration of the unseal only.
        defer _ = c.Esys_FlushContext(self.esys, item);

        if (opts.auth) |auth| {
            // ESAPI holds the auth value against the ESYS_TR and folds it into
            // the session HMAC; it is not a parameter of `Esys_Unseal` and is
            // never sent as a value.
            var tpm_auth = std.mem.zeroes(c.TPM2B_AUTH);
            tpm_auth.size = @intCast(auth.len);
            @memcpy(tpm_auth.buffer[0..auth.len], auth);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&tpm_auth));
            const auth_rc = c.Esys_TR_SetAuth(self.esys, item, &tpm_auth);
            if (auth_rc != c.TPM2_RC_SUCCESS) return mapTpmError(auth_rc);
        }

        // The object, not `opts`, decides which kind of session authorizes it.
        const session_type: c.TPM2_SE = if (in_public.publicArea.authPolicy.size > 0)
            c.TPM2_SE_POLICY
        else
            c.TPM2_SE_HMAC;

        const session = try self.startSaltedSession(parent, session_type);
        defer _ = c.Esys_FlushContext(self.esys, session);

        if (session_type == c.TPM2_SE_POLICY) {
            // Replays the same assertions the trial session made at seal time.
            // This does not itself detect a changed PCR: with a null
            // `pcrDigest` the TPM extends the session with whatever the PCRs
            // hold *now*, so a moved PCR produces a different session digest
            // and succeeds here. The comparison against the object's
            // `authPolicy` happens inside `Esys_Unseal`, which is what refuses.
            try self.applyPolicy(session, opts);
        }

        var data: [*c]c.TPM2B_SENSITIVE_DATA = null;
        const rc = c.Esys_Unseal(
            self.esys,
            item,
            session,
            c.ESYS_TR_NONE,
            c.ESYS_TR_NONE,
            &data,
        );
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);

        // Defers run last-registered-first, so these three give, in order:
        // wipe, observe, free.
        defer c.Esys_Free(data);
        defer if (builtin.is_test) {
            unseal_seam.released_zeroed = std.mem.allEqual(u8, &data.*.buffer, 0);
        };
        // The whole buffer, armed before any length the device reported is used
        // for anything. The wipe used to sit after the capacity comparison
        // below, so the `BufferTooSmall` return handed the plaintext to
        // `Esys_Free` intact -- and ESAPI returns that allocation to the
        // allocator without clearing it. Deferred rather than repeated on each
        // path, because the next path added would be the one that forgot.
        defer std.crypto.secureZero(u8, &data.*.buffer);

        // Bound the device's own length claim before indexing with it.
        const len = data.*.size;
        if (len > data.*.buffer.len) return TpmError.MalformedResponse;
        if (len > out.len) return TpmError.BufferTooSmall;
        @memcpy(out[0..len], data.*.buffer[0..len]);
        return len;
    }

    fn marshalPublic(self: *Tpm, src: [*c]c.TPM2B_PUBLIC) TpmError![]u8 {
        // The marshalled form is never longer than the in-memory struct, and
        // the marshaller is given the bound so a wrong assumption is an error
        // rather than an overflow.
        var scratch: [@sizeOf(c.TPM2B_PUBLIC)]u8 = undefined;
        var offset: usize = 0;
        if (c.Tss2_MU_TPM2B_PUBLIC_Marshal(src, &scratch, scratch.len, &offset) != c.TPM2_RC_SUCCESS) {
            return TpmError.MalformedResponse;
        }
        return self.allocator.dupe(u8, scratch[0..offset]) catch TpmError.OutOfMemory;
    }

    fn marshalPrivate(self: *Tpm, src: [*c]c.TPM2B_PRIVATE) TpmError![]u8 {
        var scratch: [@sizeOf(c.TPM2B_PRIVATE)]u8 = undefined;
        var offset: usize = 0;
        if (c.Tss2_MU_TPM2B_PRIVATE_Marshal(src, &scratch, scratch.len, &offset) != c.TPM2_RC_SUCCESS) {
            return TpmError.MalformedResponse;
        }
        return self.allocator.dupe(u8, scratch[0..offset]) catch TpmError.OutOfMemory;
    }

    /// Release a transient TPM object. TPMs have a very small number of
    /// object slots, so leaking one is not a mere memory leak: it makes
    /// subsequent key creation fail with an out-of-slots error.
    ///
    /// Reports failure instead of swallowing it, and leaves `key` intact when it
    /// fails. Both halves of that matter: this used to discard the response code
    /// and overwrite `key` with `undefined` regardless, so a caller was told the
    /// object was destroyed, had nothing left to retry with, and the object went
    /// on occupying a device slot until the next TPM reset.
    pub fn flush(self: *Tpm, key: *SigningKey) TpmError!void {
        // A handle means nothing outside the context that created it. Flushing
        // an unchecked one would release whatever object now occupies that slot
        // -- the same reasoning `signDigest` already applied, missing here.
        try self.checkHandle(key.session_epoch);
        const rc = c.Esys_FlushContext(self.esys, key.handle);
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        key.* = undefined;
    }

    pub fn flushStorageKey(self: *Tpm, key: *StorageKey) TpmError!void {
        try self.checkHandle(key.session_epoch);
        const rc = c.Esys_FlushContext(self.esys, key.handle);
        if (rc != c.TPM2_RC_SUCCESS) return mapTpmError(rc);
        key.* = undefined;
    }

    fn checkHandle(self: *Tpm, session_epoch: u64) TpmError!void {
        // A key handle is only meaningful to the context that made it.
        // Accepting a foreign one would address whatever object happens to
        // occupy that slot now.
        if (session_epoch != self.epoch) return TpmError.AuthorizationFailed;
    }
};

/// For a `device:` TCTI, resolve absence and permission separately by looking
/// at the node itself. Non-device TCTIs (simulators over TCP) have no path to
/// probe and are left to the TCTI loader.
///
/// The probe opens read-write because that is how the TCTI will open it: a
/// read-only check would pass on a node the transport cannot actually use.
/// `device:` is a POSIX-only TCTI (Windows uses `tbs`), so the syscall path is
/// pruned at comptime elsewhere rather than guarded at runtime.
fn probeDevicePath(tcti: [:0]const u8) TpmError!void {
    const prefix = "device:";
    if (!std.mem.startsWith(u8, tcti, prefix)) return;
    if (builtin.os.tag == .windows) return;
    const path = tcti[prefix.len..];
    if (path.len == 0) return;

    const fd = std.posix.openat(
        std.posix.AT.FDCWD,
        path,
        .{ .ACCMODE = .RDWR, .CLOEXEC = true },
        0,
    ) catch |err| switch (err) {
        // These three are the distinction the old provider threw away: it
        // reported "no TPM" for a host that had one but denied access.
        error.FileNotFound => return TpmError.DeviceAbsent,
        error.AccessDenied, error.PermissionDenied => return TpmError.PermissionDenied,
        error.NoDevice => return TpmError.DeviceAbsent,
        else => return TpmError.TransportUnavailable,
    };
    // The probe descriptor is closed immediately; the TCTI opens its own.
    std.Io.Threaded.closeFd(fd);
}

/// Decode a TSS2 return code into this module's error taxonomy.
///
/// TPM 2.0 Part 2 defines two response-code formats and they cannot be masked
/// the same way. Format 1 (bit 7 set) packs *which* handle, parameter or
/// session was at fault into bit 6 and bits 8-11, so the error number is only
/// bits 0-5 plus the format bit. Masking the whole low 12 bits leaves those
/// positional bits in place, and every comparison then fails silently: the
/// simulator's restricted-key refusal arrives as 0x3E0, never as the bare
/// 0x0A0 that `TPM2_RC_TICKET` holds, and a real `TPM2_RC_BAD_AUTH` arrives
/// as 0x9A2 rather than 0x0A2. Getting this wrong does not produce a visible
/// failure — it produces a taxonomy that always answers `CommandFailed`.
/// A one-bank SHA-256 PCR selection over `indices`.
///
/// Shared by `readPcrSha256`, `quote` and the sealing policy so that "PCR 7"
/// means the same bitmap in all three. The selection the policy asserts and the
/// selection a caller reads back have to agree exactly or the policy digest
/// differs, and two hand-rolled copies of this loop is how they stop agreeing.
///
/// `sizeofSelect = 3` covers PCR 0-23, which is every index a `u5` can name.
fn pcrSelectionSha256(indices: []const u5) c.TPML_PCR_SELECTION {
    var selection = std.mem.zeroes(c.TPML_PCR_SELECTION);
    selection.count = 1;
    selection.pcrSelections[0].hash = c.TPM2_ALG_SHA256;
    selection.pcrSelections[0].sizeofSelect = 3;
    for (indices) |idx| {
        selection.pcrSelections[0].pcrSelect[idx / 8] |= @as(u8, 1) << @intCast(idx % 8);
    }
    return selection;
}

fn mapTpmError(rc: c.TSS2_RC) TpmError {
    // A non-zero layer means the code came from ESAPI/SAPI/TCTI, not from the
    // TPM. Decoding it as a TPM verdict would attribute a transport problem
    // to the device.
    if (rc & c.TSS2_RC_LAYER_MASK != 0) return TpmError.TransportUnavailable;

    if (rc & c.TPM2_RC_FMT1 != 0) {
        return switch (rc & (c.TPM2_RC_FMT1 | 0x03f)) {
            c.TPM2_RC_BAD_AUTH, c.TPM2_RC_AUTH_FAIL => TpmError.AuthorizationFailed,
            // The scheme, curve or key type asked for is not one this TPM
            // implements.
            c.TPM2_RC_SCHEME,
            c.TPM2_RC_CURVE,
            c.TPM2_RC_ASYMMETRIC,
            c.TPM2_RC_KEY,
            => TpmError.UnsupportedMechanism,
            // A restricted key rejects the null hashcheck ticket that says
            // "this digest did not come from the TPM". That is the key being
            // the wrong kind for the operation, not a malfunction.
            c.TPM2_RC_TICKET, c.TPM2_RC_ATTRIBUTES => TpmError.RestrictedKey,
            // The TPM bounds sealed-object size itself; report that as the
            // size problem it is rather than a generic command failure.
            c.TPM2_RC_SIZE => TpmError.BufferTooSmall,
            // A sealed blob that failed its integrity check is not a
            // malfunction: it is a blob that was altered, or was sealed to a
            // different parent or a different TPM.
            c.TPM2_RC_INTEGRITY => TpmError.MalformedResponse,
            // A policy session whose digest does not match the object's
            // `authPolicy`. For a PCR-sealed blob this is the ordinary,
            // expected refusal on a machine whose boot state changed, and it
            // belongs with the other authorization failures rather than looking
            // like a malfunctioning device. `POLICY_CC` is the same verdict
            // reached by a policy that permits a different command.
            c.TPM2_RC_POLICY_FAIL, c.TPM2_RC_POLICY_CC => TpmError.AuthorizationFailed,
            else => TpmError.CommandFailed,
        };
    }

    // Format 0 carries no positional bits; the error number is bits 0-6 with
    // the version bit.
    return switch (rc) {
        // A TPM holds only a handful of transient objects and sessions — three
        // is a common limit. Running into that ceiling is a resource state the
        // caller can act on by flushing something, so it is reported as
        // exhaustion. Left as `CommandFailed` it is indistinguishable from a
        // malfunctioning device, which is what it looked like before a live
        // simulator hit it at the fourth concurrent key.
        c.TPM2_RC_OBJECT_MEMORY,
        c.TPM2_RC_SESSION_MEMORY,
        c.TPM2_RC_MEMORY,
        => TpmError.ResourcesExhausted,
        // The PCRs moved between the `PolicyPCR` assertion and the use of the
        // session. A narrower case than `POLICY_FAIL`, and the same refusal
        // from the caller's side. (`POLICY_FAIL` itself is a format-1 code and
        // is handled above -- the two look like they belong together and do
        // not live together, which is worth saying once here rather than
        // rediscovering.)
        c.TPM2_RC_PCR_CHANGED => TpmError.AuthorizationFailed,
        // The TPM's dictionary-attack defence has tripped and it is refusing
        // authorized commands until the lockout clears or is reset. A device
        // state an operator acts on, not a malfunction and not a wrong
        // credential -- reporting it as either sends them looking in the wrong
        // place, and it is reached by exactly the sequence a caller using auth
        // values is most likely to produce.
        c.TPM2_RC_LOCKOUT => TpmError.DictionaryLockout,
        // The remaining format-0 codes map to nothing narrower here, so they
        // stay `CommandFailed` rather than being given an invented meaning.
        else => TpmError.CommandFailed,
    };
}

fn extractEcdsa(signature: [*c]c.TPMT_SIGNATURE) TpmError![64]u8 {
    if (signature.*.sigAlg != c.TPM2_ALG_ECDSA) return TpmError.MalformedResponse;
    const ecdsa = signature.*.signature.ecdsa;
    if (ecdsa.signatureR.size != 32 or ecdsa.signatureS.size != 32) {
        return TpmError.MalformedResponse;
    }
    var out: [64]u8 = undefined;
    @memcpy(out[0..32], ecdsa.signatureR.buffer[0..32]);
    @memcpy(out[32..64], ecdsa.signatureS.buffer[0..32]);
    return out;
}
