//! Stand-in for the PKCS#11 backend in builds configured without
//! `-Dpkcs11=true`.
//!
//! `build.zig` binds either this file or `pkcs11.zig` to the module name
//! `pkcs11_backend`, so `hsm.zig` contains one unconditional import and one set
//! of call sites. The alternative — a conditional `@import` guarded on a build
//! option — turns "this build has no PKCS#11 support" into a compile error at
//! every call site, which pushes the same `if (build_options.enable_pkcs11)`
//! test into every caller and makes the absent case impossible to write a test
//! against.
//!
//! Every entry point here answers `Pkcs11Error.BackendNotBuilt`. That is a
//! deliberately different answer from `LibraryAbsent`: this build has no
//! Cryptoki types compiled in at all, whereas `LibraryAbsent` is the real
//! backend reporting that the module the caller named would not load.
//! Collapsing the two would send an operator looking for a missing `.so` when
//! the fix is a build flag.
//!
//! The signature encoders are the exception. They are re-exported from
//! `ecdsa_sig.zig`, which both backends import, so they work here rather than
//! failing: converting between the raw and DER spellings of an ECDSA signature
//! touches no Cryptoki type and is a real job whether or not this build can
//! reach a token.

const std = @import("std");
const ecdsa_sig = @import("ecdsa_sig");

/// Lets a caller assert which backend it was compiled against, so a test can
/// expect one exact outcome instead of accepting either. Both backends declare
/// it, so reading it is never a compile error.
pub const is_real_backend = false;

/// Mirrors `pkcs11.Pkcs11Error`. The two sets are kept identical so `hsm.zig`
/// maps one error union rather than two.
pub const Pkcs11Error = error{
    LibraryAbsent,
    NotACryptokiModule,
    InitializationFailed,
    AlreadyInitialized,
    TokenAbsent,
    SlotNotFound,
    AuthorizationFailed,
    UnsupportedMechanism,
    ReadOnlyToken,
    ObjectNotFound,
    SessionInvalid,
    AttributeUnavailable,
    BufferTooSmall,
    MalformedResponse,
    SignatureInvalid,
    ResourcesExhausted,
    CommandFailed,
    /// This build was compiled without PKCS#11 support. Only this module ever
    /// returns it; the real backend never does.
    BackendNotBuilt,
    OutOfMemory,
};

/// Cryptoki's handle and identifier types are `CK_ULONG`, which is
/// `unsigned long`. They are spelled `c_ulong` here for the same reason the
/// real backend gets them from translate-c: the width is 8 bytes on 64-bit
/// Unix and 4 on Windows, and a fixed-width stand-in would make the two
/// backends disagree about the size of a handle.
pub const ObjectHandle = c_ulong;
pub const SlotId = c_ulong;
pub const MechanismType = c_ulong;
pub const ObjectClass = c_ulong;

/// The `CKO_*` values, spelled out because this build has no header to read
/// them from. They are fixed by the standard, not by a vendor, so transcribing
/// them cannot drift; the real backend takes the same values from the
/// translated header, and a test asserts the two agree.
pub const object_class = struct {
    pub const data: ObjectClass = 0;
    pub const certificate: ObjectClass = 1;
    pub const public_key: ObjectClass = 2;
    pub const private_key: ObjectClass = 3;
    pub const secret_key: ObjectClass = 4;
};

/// The `CKM_*` values, transcribed for the same reason as the classes above and
/// checked against the translated header by a test in the real backend.
pub const mechanism = struct {
    pub const ec_key_pair_gen: MechanismType = 0x1040;
    pub const ecdsa: MechanismType = 0x1041;
    pub const aes_key_gen: MechanismType = 0x1080;
    pub const aes_gcm: MechanismType = 0x1087;
};

/// The `CKA_*` values, transcribed and cross-checked the same way.
pub const attribute = struct {
    pub const sensitive: c_ulong = 0x103;
    pub const extractable: c_ulong = 0x162;
};

pub const Config = struct {
    module_path: []const u8,
    slot_index: usize = 0,
    read_write: bool = false,
    module_config: ?[]const u8 = null,
};

pub const Version = struct { major: u8, minor: u8 };

pub const ModuleInfo = struct {
    cryptoki_version: Version,
    library_version: Version,
    manufacturer: [32]u8,
    manufacturer_len: usize,
    description: [32]u8,
    description_len: usize,

    pub fn manufacturerSlice(self: *const ModuleInfo) []const u8 {
        return self.manufacturer[0..self.manufacturer_len];
    }

    pub fn descriptionSlice(self: *const ModuleInfo) []const u8 {
        return self.description[0..self.description_len];
    }
};

pub const TokenInfo = struct {
    slot_id: SlotId,
    label: [32]u8,
    label_len: usize,
    model: [16]u8,
    model_len: usize,
    serial: [16]u8,
    serial_len: usize,
    write_protected: bool,
    login_required: bool,
    initialized: bool,

    pub fn labelSlice(self: *const TokenInfo) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn modelSlice(self: *const TokenInfo) []const u8 {
        return self.model[0..self.model_len];
    }

    pub fn serialSlice(self: *const TokenInfo) []const u8 {
        return self.serial[0..self.serial_len];
    }
};

pub const KeyPair = struct {
    public: ObjectHandle,
    private: ObjectHandle,
    public_sec1: [65]u8,

    pub fn publicKey(self: KeyPair) !std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&self.public_sec1);
    }
};

/// Mirrors `pkcs11.Module`. Inert: no value is ever constructed, because `open`
/// is the only constructor and it always fails.
pub const Module = struct {
    info: ModuleInfo,

    pub fn open(config: Config) Pkcs11Error!Module {
        _ = config;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn close(self: *Module) void {
        self.* = undefined;
    }

    pub fn slotsWithToken(self: *Module, out: []SlotId) Pkcs11Error![]SlotId {
        _ = self;
        _ = out;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn tokenInfo(self: *Module, slot_id: SlotId) Pkcs11Error!TokenInfo {
        _ = self;
        _ = slot_id;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn mechanisms(self: *Module, slot_id: SlotId, out: []MechanismType) Pkcs11Error![]MechanismType {
        _ = self;
        _ = slot_id;
        _ = out;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn supportsMechanism(self: *Module, slot_id: SlotId, want: MechanismType) Pkcs11Error!bool {
        _ = self;
        _ = slot_id;
        _ = want;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn openSession(self: *Module, config: Config) Pkcs11Error!Session {
        _ = self;
        _ = config;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn openSessionOnSlot(self: *Module, slot_id: SlotId, read_write: bool) Pkcs11Error!Session {
        _ = self;
        _ = slot_id;
        _ = read_write;
        return Pkcs11Error.BackendNotBuilt;
    }
};

/// Mirrors `pkcs11.Session`. Inert for the same reason as `Module`.
pub const Session = struct {
    handle: c_ulong,
    slot_id: SlotId,
    logged_in: bool,

    pub fn login(self: *Session, pin: []const u8) Pkcs11Error!void {
        _ = self;
        _ = pin;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn logout(self: *Session) void {
        _ = self;
    }

    pub fn close(self: *Session) void {
        self.* = undefined;
    }

    pub fn getRandom(self: *Session, out: []u8) Pkcs11Error!void {
        _ = self;
        _ = out;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn generateEcdsaP256(self: *Session, label: []const u8, token_object: bool) Pkcs11Error!KeyPair {
        _ = self;
        _ = label;
        _ = token_object;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn readPublicPoint(self: *Session, obj: ObjectHandle) Pkcs11Error![65]u8 {
        _ = self;
        _ = obj;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn readAttribute(self: *Session, obj: ObjectHandle, attr: c_ulong, out: []u8) Pkcs11Error![]u8 {
        _ = self;
        _ = obj;
        _ = attr;
        _ = out;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn readBoolAttribute(self: *Session, obj: ObjectHandle, attr: c_ulong) Pkcs11Error!bool {
        _ = self;
        _ = obj;
        _ = attr;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn signDigest(self: *Session, private: ObjectHandle, digest: [32]u8) Pkcs11Error![64]u8 {
        _ = self;
        _ = private;
        _ = digest;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn signatureLength(self: *Session, private: ObjectHandle) Pkcs11Error!usize {
        _ = self;
        _ = private;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn verifyDigest(self: *Session, public: ObjectHandle, digest: [32]u8, signature: [64]u8) Pkcs11Error!void {
        _ = self;
        _ = public;
        _ = digest;
        _ = signature;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn generateAesKey(self: *Session, bytes: u8, label: []const u8, token_object: bool) Pkcs11Error!ObjectHandle {
        _ = self;
        _ = bytes;
        _ = label;
        _ = token_object;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn aesGcmEncrypt(
        self: *Session,
        key: ObjectHandle,
        iv: []const u8,
        aad: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) Pkcs11Error![]u8 {
        _ = self;
        _ = key;
        _ = iv;
        _ = aad;
        _ = plaintext;
        _ = out;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn aesGcmDecrypt(
        self: *Session,
        key: ObjectHandle,
        iv: []const u8,
        aad: []const u8,
        ciphertext: []const u8,
        out: []u8,
    ) Pkcs11Error![]u8 {
        _ = self;
        _ = key;
        _ = iv;
        _ = aad;
        _ = ciphertext;
        _ = out;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn destroyObject(self: *Session, obj: ObjectHandle) Pkcs11Error!void {
        _ = self;
        _ = obj;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn findByLabel(
        self: *Session,
        class: ObjectClass,
        label: []const u8,
        out: []ObjectHandle,
    ) Pkcs11Error![]ObjectHandle {
        _ = self;
        _ = class;
        _ = label;
        _ = out;
        return Pkcs11Error.BackendNotBuilt;
    }

    pub fn countObjects(self: *Session, class: ObjectClass) Pkcs11Error!usize {
        _ = self;
        _ = class;
        return Pkcs11Error.BackendNotBuilt;
    }
};

// =============================================================================
// Signature encoding
//
// Shared verbatim with the real backend via `ecdsa_sig.zig`. Re-exported rather
// than stubbed so this build can still convert a signature it obtained
// elsewhere, and so the two backends cannot drift apart.
// =============================================================================

pub const derFromRaw = ecdsa_sig.derFromRaw;
pub const rawFromDer = ecdsa_sig.rawFromDer;
pub const max_der_signature_len = ecdsa_sig.max_der_len;

const testing = std.testing;

test "the absent PKCS#11 backend reports a missing build, not a missing library" {
    // `LibraryAbsent` would send an operator looking for a module file. The
    // answer here is that no build of this backend exists to look with.
    try testing.expectError(
        Pkcs11Error.BackendNotBuilt,
        Module.open(.{ .module_path = "/nonexistent/zcrypto-probe.so" }),
    );
    try testing.expect(!is_real_backend);
}

test "signature conversion still works in a build without the backend" {
    // The exhaustive encoder tests live in `ecdsa_sig.zig`. This one exists to
    // catch the specific regression of someone stubbing these out alongside
    // everything else in this file: a caller with a raw signature in hand can
    // convert it whether or not this build can reach a token.
    var raw: [64]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @intCast(i + 1);

    var der: [max_der_signature_len]u8 = undefined;
    const n = try derFromRaw(raw, &der);

    var back: [64]u8 = undefined;
    try rawFromDer(der[0..n], &back);
    try testing.expectEqualSlices(u8, &raw, &back);
}
