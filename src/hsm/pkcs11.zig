//! PKCS#11 (Cryptoki) backend.
//!
//! A PKCS#11 provider is a shared object supplied by the token vendor. This
//! module loads one the caller names, takes its function table, and drives it.
//! Nothing here is linked at build time: there is no such thing as "the"
//! PKCS#11 library to link against, and a build that linked one would only work
//! with that one token.
//!
//! ## What "loaded" means here
//!
//! `Module.open` is not satisfied by a file existing at the path. It requires,
//! in order: the object loads; it exports `C_GetFunctionList`; that call
//! succeeds; the returned table is non-null and its mandatory entry points are
//! non-null; and `C_Initialize` succeeds. A path that passes `dlopen` but is not
//! a Cryptoki module fails with `NotACryptokiModule`, which is a different
//! answer from `LibraryAbsent`, because the operator's fix is different.
//!
//! ## Ownership and cleanup
//!
//! `Module` owns the library handle and the Cryptoki initialization; `Session`
//! owns a session handle. Both are closed by their own `close`, and closing a
//! `Module` does not close sessions opened from it — the caller owns those.
//! `C_Finalize` is called exactly once per successful `C_Initialize`, on
//! `Module.close`. Cryptoki is explicit that a process must not have two
//! concurrent initializations of the same module, so a caller that opens the
//! same path twice will see the second `C_Initialize` answer
//! `CKR_CRYPTOKI_ALREADY_INITIALIZED`; that is reported as
//! `AlreadyInitialized` rather than being swallowed, because silently sharing
//! another owner's initialization would mean the first `close` finalizes the
//! module out from under the second holder.
//!
//! ## Signature encoding
//!
//! PKCS#11 specifies that `CKM_ECDSA` produces the raw concatenation r || s,
//! each padded to the byte length of the curve order — 64 bytes for P-256. It
//! is *not* the DER `SEQUENCE { INTEGER r, INTEGER s }` that OpenSSL and X.509
//! use. `signDigest` returns the raw form because that is what the token
//! returned; `derFromRaw` converts when a caller needs the X.509 spelling. The
//! conversion is explicit in both directions rather than guessed from the
//! length, because a 64-byte DER signature is also possible.
//!
//! ## What this backend does not claim
//!
//! Reaching a token through PKCS#11 says nothing about how that token protects
//! keys. SoftHSM implements this entire API in a file under `$HOME`. The caller
//! states which it is opening and `hsm.zig` reports the backing accordingly; no
//! code here infers hardware protection from a successful call.

const std = @import("std");
const builtin = @import("builtin");
const c = @import("pkcs11");
const ecdsa_sig = @import("ecdsa_sig");

/// Lets a caller assert which backend it was compiled against, so a test can
/// expect one exact outcome instead of accepting either. Both backends declare
/// it, so reading it is never a compile error.
pub const is_real_backend = true;

/// Mirrors `pkcs11_absent.Pkcs11Error`. The two sets are kept identical so
/// `hsm.zig` maps one error union rather than two.
/// Fault injection for `Session.destroyObject`, present in test builds only.
///
/// Destroying a key pair is two token operations, so it can half succeed, and
/// the two interesting outcomes are "the first call failed" and "the second
/// failed after the first had already removed an object". Neither can be
/// provoked from a working token, and both are exactly where a provider is
/// liable to lose track of a live object. The seam exists so those paths are
/// tested rather than reasoned about.
const destroy_seam = if (builtin.is_test) struct {
    var pending: ?usize = null;
    var calls: usize = 0;
} else struct {};

/// Make the `nth` `destroyObject` call from now fail once, counting from 1.
/// Test builds only.
pub fn failDestroyForTesting(nth: usize) void {
    comptime std.debug.assert(builtin.is_test);
    std.debug.assert(nth >= 1);
    destroy_seam.pending = nth;
    destroy_seam.calls = 0;
}

/// Cancel an armed failure that was never reached, so it cannot fire inside an
/// unrelated later test. Test builds only.
pub fn clearDestroyFailureForTesting() void {
    comptime std.debug.assert(builtin.is_test);
    destroy_seam.pending = null;
    destroy_seam.calls = 0;
}

pub const Pkcs11Error = error{
    /// The module path could not be loaded at all.
    LibraryAbsent,
    /// The object loaded but is not a Cryptoki provider: no `C_GetFunctionList`,
    /// or a table missing entry points the spec makes mandatory.
    NotACryptokiModule,
    /// `C_Initialize` failed for a reason other than already being initialized.
    InitializationFailed,
    /// This process already initialized this module and has not finalized it.
    AlreadyInitialized,
    /// No slot, or no slot with a token in it.
    TokenAbsent,
    /// The named slot index is outside what the module reported.
    SlotNotFound,
    /// Wrong PIN, PIN locked, or an operation that needs a login without one.
    AuthorizationFailed,
    /// The token does not implement this mechanism.
    UnsupportedMechanism,
    /// The token or the session is read-only, so the object cannot be created
    /// or destroyed. Distinct from an authorization failure: logging in does
    /// not fix it.
    ReadOnlyToken,
    ObjectNotFound,
    /// The session handle is no longer valid — closed, or invalidated by the
    /// token. Distinct from `CommandFailed` because the caller can act on it:
    /// open a new session and retry.
    SessionInvalid,
    /// The token holds the value but will not disclose it — a sensitive or
    /// unextractable attribute. This is the token behaving correctly.
    AttributeUnavailable,
    BufferTooSmall,
    /// The token's answer did not have the shape the spec requires.
    MalformedResponse,
    /// The token verified a signature and rejected it.
    SignatureInvalid,
    /// Token or host memory exhausted, or too many sessions.
    ResourcesExhausted,
    /// The token was reachable and the call failed.
    CommandFailed,
    /// This build was compiled without PKCS#11 support. Only the absent shim
    /// ever returns it; this backend never does.
    BackendNotBuilt,
    OutOfMemory,
};

/// Translate a Cryptoki return value into this module's taxonomy.
///
/// The distinctions Cryptoki draws that an operator can act on are preserved.
/// Codes that mean the same thing to a caller are deliberately merged — the
/// four PIN failures all mean "the credential was not accepted" — and anything
/// unrecognized becomes `CommandFailed` rather than being mapped to whichever
/// error looks closest.
fn mapRv(rv: c.CK_RV) Pkcs11Error {
    return switch (rv) {
        c.CKR_HOST_MEMORY, c.CKR_DEVICE_MEMORY => Pkcs11Error.OutOfMemory,
        c.CKR_SESSION_COUNT => Pkcs11Error.ResourcesExhausted,

        c.CKR_SLOT_ID_INVALID => Pkcs11Error.SlotNotFound,
        c.CKR_TOKEN_NOT_PRESENT, c.CKR_TOKEN_NOT_RECOGNIZED, c.CKR_DEVICE_REMOVED => Pkcs11Error.TokenAbsent,

        c.CKR_PIN_INCORRECT,
        c.CKR_PIN_INVALID,
        c.CKR_PIN_LEN_RANGE,
        c.CKR_PIN_EXPIRED,
        c.CKR_PIN_LOCKED,
        c.CKR_USER_NOT_LOGGED_IN,
        c.CKR_USER_PIN_NOT_INITIALIZED,
        => Pkcs11Error.AuthorizationFailed,

        c.CKR_MECHANISM_INVALID,
        c.CKR_MECHANISM_PARAM_INVALID,
        c.CKR_FUNCTION_NOT_SUPPORTED,
        c.CKR_CURVE_NOT_SUPPORTED,
        c.CKR_KEY_TYPE_INCONSISTENT,
        c.CKR_KEY_SIZE_RANGE,
        => Pkcs11Error.UnsupportedMechanism,

        c.CKR_TOKEN_WRITE_PROTECTED,
        c.CKR_SESSION_READ_ONLY,
        c.CKR_ACTION_PROHIBITED,
        => Pkcs11Error.ReadOnlyToken,

        c.CKR_OBJECT_HANDLE_INVALID,
        c.CKR_KEY_HANDLE_INVALID,
        => Pkcs11Error.ObjectNotFound,

        // The session this call named is gone: closed, or invalidated by the
        // token underneath the caller. Kept separate from `CommandFailed`
        // because the remedy is specific and mechanical — open a new session
        // and retry — whereas a generic failure gives the caller nothing to
        // act on.
        c.CKR_SESSION_HANDLE_INVALID,
        c.CKR_SESSION_CLOSED,
        => Pkcs11Error.SessionInvalid,

        c.CKR_ATTRIBUTE_SENSITIVE,
        c.CKR_INFORMATION_SENSITIVE,
        c.CKR_KEY_UNEXTRACTABLE,
        c.CKR_ATTRIBUTE_TYPE_INVALID,
        => Pkcs11Error.AttributeUnavailable,

        c.CKR_BUFFER_TOO_SMALL => Pkcs11Error.BufferTooSmall,

        c.CKR_SIGNATURE_INVALID,
        c.CKR_SIGNATURE_LEN_RANGE,
        c.CKR_ENCRYPTED_DATA_INVALID,
        c.CKR_ENCRYPTED_DATA_LEN_RANGE,
        c.CKR_AEAD_DECRYPT_FAILED,
        => Pkcs11Error.SignatureInvalid,

        c.CKR_CRYPTOKI_ALREADY_INITIALIZED => Pkcs11Error.AlreadyInitialized,
        c.CKR_CRYPTOKI_NOT_INITIALIZED => Pkcs11Error.InitializationFailed,

        else => Pkcs11Error.CommandFailed,
    };
}

fn check(rv: c.CK_RV) Pkcs11Error!void {
    if (rv != c.CKR_OK) return mapRv(rv);
}

/// The DER encoding of the ANSI X9.62 OID for the P-256 curve
/// (`1.2.840.10045.3.1.7`), which is what `CKA_EC_PARAMS` takes for that curve.
/// Written as the encoded bytes rather than assembled at runtime because it is
/// a constant of the standard, not a value with a lifetime.
const p256_ec_params = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

/// Cryptoki spells its booleans two ways: `CK_TRUE`/`CK_FALSE` are `int` in the
/// header, while every boolean attribute value is a one-byte `CK_BBOOL`.
/// Narrowing once here keeps the cast out of every attribute template.
const ck_true: c.CK_BBOOL = @intCast(c.CK_TRUE);
const ck_false: c.CK_BBOOL = @intCast(c.CK_FALSE);

/// The Cryptoki scalar types a caller has to be able to name, re-exported so
/// no caller imports the translated header itself. The absent shim declares
/// the same four names with the same widths, which is what lets one call site
/// compile against either backend.
pub const ObjectHandle = c.CK_OBJECT_HANDLE;
pub const SlotId = c.CK_SLOT_ID;
pub const MechanismType = c.CK_MECHANISM_TYPE;
pub const ObjectClass = c.CK_OBJECT_CLASS;

/// The object classes this backend can search for. Re-exported for the same
/// reason as the types above: `findByLabel` and `countObjects` take a class,
/// so a caller that cannot name one cannot call them.
pub const object_class = struct {
    pub const data: ObjectClass = c.CKO_DATA;
    pub const certificate: ObjectClass = c.CKO_CERTIFICATE;
    pub const public_key: ObjectClass = c.CKO_PUBLIC_KEY;
    pub const private_key: ObjectClass = c.CKO_PRIVATE_KEY;
    pub const secret_key: ObjectClass = c.CKO_SECRET_KEY;
};

/// The mechanisms this backend uses. Exported so a caller can ask
/// `supportsMechanism` about them before attempting an operation, rather than
/// discovering the answer as a failure part-way through one.
pub const mechanism = struct {
    pub const ec_key_pair_gen: MechanismType = c.CKM_EC_KEY_PAIR_GEN;
    pub const ecdsa: MechanismType = c.CKM_ECDSA;
    pub const aes_key_gen: MechanismType = c.CKM_AES_KEY_GEN;
    pub const aes_gcm: MechanismType = c.CKM_AES_GCM;
};

/// Attribute types a caller may want to read back with `readBoolAttribute`.
/// Exported so that checking whether a created key really is non-extractable
/// does not require the caller to transcribe a constant.
pub const attribute = struct {
    pub const sensitive: c.CK_ATTRIBUTE_TYPE = c.CKA_SENSITIVE;
    pub const extractable: c.CK_ATTRIBUTE_TYPE = c.CKA_EXTRACTABLE;
};

pub const Config = struct {
    /// Filesystem path of the provider module. There is no default: a default
    /// would silently pick a token the caller did not choose, and on a host
    /// with several installed it would pick a different one per machine.
    module_path: []const u8,
    /// Index into the module's own slot list, not a `CK_SLOT_ID`. Slot ids are
    /// module-assigned and need not be small or contiguous, so an index is the
    /// only thing a caller can state without first enumerating.
    slot_index: usize = 0,
    /// Whether to ask for a read/write session. Object creation and destruction
    /// need one; a read-only token will refuse.
    read_write: bool = false,
    /// Module-specific initialization string, passed through as
    /// `CK_C_INITIALIZE_ARGS.pReserved`.
    ///
    /// The spec reserves this field, but the convention that a provider may
    /// read a configuration string from it is near-universal, and for some
    /// providers it is the only way to reach a writable token. NSS softoken is
    /// the case that forced this: with `pReserved` null it offers only
    /// write-protected slots, and it names its database with
    /// `configdir='sql:/path' certPrefix='' keyPrefix='' secmod='' flags=`.
    /// Left null the field is not set at all, so providers that genuinely
    /// reserve it see the same call they saw before.
    module_config: ?[]const u8 = null,
};

/// What the module says about itself, with the spec's blank-padded fixed-width
/// fields trimmed.
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

pub const Version = struct { major: u8, minor: u8 };

/// What the token in a slot says about itself.
///
/// `write_protected` and `login_required` are read from `CKF_*` bits rather
/// than assumed, because they decide whether key generation can be attempted at
/// all and whether a PIN is needed first.
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

/// Cryptoki pads its fixed-width text fields with spaces and does not
/// NUL-terminate them, so the trailing blanks have to be removed explicitly.
fn trimPadded(comptime n: usize, src: [n]u8, dst: *[n]u8) usize {
    dst.* = src;
    const trimmed = std.mem.trimEnd(u8, &src, " \x00");
    return trimmed.len;
}

/// A key pair the token created and holds.
///
/// `private` is a handle, never material: `CKA_SENSITIVE` and
/// `CKA_EXTRACTABLE` are set so that asking the token for the private value is
/// refused by the token itself rather than by a check in this file.
pub const KeyPair = struct {
    public: ObjectHandle,
    private: ObjectHandle,
    /// Uncompressed SEC1 point, `0x04 || X || Y`, read back from the object the
    /// token created rather than computed here.
    public_sec1: [65]u8,

    pub fn publicKey(self: KeyPair) !std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&self.public_sec1);
    }
};

/// A loaded, initialized provider.
pub const Module = struct {
    lib: std.DynLib,
    fns: *c.CK_FUNCTION_LIST,
    info: ModuleInfo,

    /// Load and initialize the module at `config.module_path`.
    ///
    /// `path` is copied into a NUL-terminated stack buffer because `dlopen`
    /// takes a C string and a Zig slice is not one.
    pub fn open(config: Config) Pkcs11Error!Module {
        var lib = std.DynLib.open(config.module_path) catch {
            // `DlDynLib` reports every `dlopen` failure as `FileNotFound`,
            // including a file that exists but cannot be mapped. Both are
            // "this build could not load the module the caller named", which
            // is exactly what `LibraryAbsent` says.
            return Pkcs11Error.LibraryAbsent;
        };
        errdefer lib.close();

        // A Cryptoki provider is required to export this one symbol; everything
        // else is reached through the table it hands back. Its absence is the
        // sharpest available test that the object is not a PKCS#11 module.
        const get_list = lib.lookup(
            *const fn ([*c][*c]c.CK_FUNCTION_LIST) callconv(.c) c.CK_RV,
            "C_GetFunctionList",
        ) orelse return Pkcs11Error.NotACryptokiModule;

        var raw: [*c]c.CK_FUNCTION_LIST = null;
        if (get_list(&raw) != c.CKR_OK) return Pkcs11Error.NotACryptokiModule;
        if (raw == null) return Pkcs11Error.NotACryptokiModule;
        const fns: *c.CK_FUNCTION_LIST = raw;

        // The table is C: every entry is a nullable pointer. Checking the ones
        // this module calls up front means a later call site can dereference
        // without each one deciding what to do about a null.
        if (fns.C_Initialize == null or
            fns.C_Finalize == null or
            fns.C_GetInfo == null or
            fns.C_GetSlotList == null or
            fns.C_GetTokenInfo == null or
            fns.C_GetMechanismList == null or
            fns.C_OpenSession == null or
            fns.C_CloseSession == null)
        {
            return Pkcs11Error.NotACryptokiModule;
        }

        // The provider reads this string during `C_Initialize` and does not
        // retain the pointer, so a buffer living to the end of `open` is
        // enough. It is NUL-terminated because the field is a C string.
        var config_buf: [512]u8 = undefined;
        var reserved: ?*anyopaque = null;
        if (config.module_config) |text| {
            if (text.len >= config_buf.len) return Pkcs11Error.BufferTooSmall;
            @memcpy(config_buf[0..text.len], text);
            config_buf[text.len] = 0;
            reserved = @ptrCast(&config_buf);
        }

        // `CKF_OS_LOCKING_OK` tells the module it may use the platform's own
        // locking primitives. Without it a module that needs locking would ask
        // this process for mutex callbacks it does not supply.
        var args = c.CK_C_INITIALIZE_ARGS{ .flags = c.CKF_OS_LOCKING_OK, .pReserved = reserved };
        switch (fns.C_Initialize.?(@ptrCast(&args))) {
            c.CKR_OK => {},
            c.CKR_CRYPTOKI_ALREADY_INITIALIZED => return Pkcs11Error.AlreadyInitialized,
            // A module that cannot use OS locking says so. The spec's own
            // remedy is to initialize with no arguments, which promises the
            // module it will only ever be called from one thread — a promise
            // this backend keeps, because `hsm.zig` serializes every entry
            // point behind its concurrency guard. When a configuration string
            // was supplied, dropping to a null argument would silently discard
            // it and open a different token than the caller named, so the
            // retry keeps the arguments and clears only the locking flag.
            c.CKR_CANT_LOCK, c.CKR_NEED_TO_CREATE_THREADS => {
                const retry: c.CK_VOID_PTR = if (config.module_config == null) null else blk: {
                    args.flags = 0;
                    break :blk @ptrCast(&args);
                };
                if (fns.C_Initialize.?(retry) != c.CKR_OK) {
                    return Pkcs11Error.InitializationFailed;
                }
            },
            else => return Pkcs11Error.InitializationFailed,
        }

        return finishOpen(lib, fns);
    }

    /// Shared tail of `open`: read the module's self-description once
    /// `C_Initialize` has succeeded, by whichever of the two routes.
    fn finishOpen(lib: std.DynLib, fns: *c.CK_FUNCTION_LIST) Pkcs11Error!Module {
        var self = Module{ .lib = lib, .fns = fns, .info = undefined };
        errdefer {
            _ = fns.C_Finalize.?(null);
            self.lib.close();
        }

        var raw_info: c.CK_INFO = .{};
        try check(fns.C_GetInfo.?(&raw_info));

        self.info = .{
            .cryptoki_version = .{
                .major = raw_info.cryptokiVersion.major,
                .minor = raw_info.cryptokiVersion.minor,
            },
            .library_version = .{
                .major = raw_info.libraryVersion.major,
                .minor = raw_info.libraryVersion.minor,
            },
            .manufacturer = undefined,
            .manufacturer_len = 0,
            .description = undefined,
            .description_len = 0,
        };
        self.info.manufacturer_len = trimPadded(32, raw_info.manufacturerID, &self.info.manufacturer);
        self.info.description_len = trimPadded(32, raw_info.libraryDescription, &self.info.description);

        return self;
    }

    /// Finalize Cryptoki and unload the library. Sessions opened from this
    /// module must be closed first; `C_Finalize` closes them on the module's
    /// side, but a `Session` value still holding a handle would then be
    /// referring to nothing.
    pub fn close(self: *Module) void {
        _ = self.fns.C_Finalize.?(null);
        self.lib.close();
        self.* = undefined;
    }

    /// Slot ids for slots that currently contain a token.
    ///
    /// Two calls are required by the spec's size-query convention: the first
    /// with a null buffer to learn the count, the second to fill it. The count
    /// is re-checked after the second call because a token can be removed
    /// between them.
    pub fn slotsWithToken(self: *Module, out: []SlotId) Pkcs11Error![]SlotId {
        var count: c.CK_ULONG = 0;
        try check(self.fns.C_GetSlotList.?(ck_true, null, &count));
        if (count == 0) return out[0..0];
        if (count > out.len) return Pkcs11Error.BufferTooSmall;

        var got: c.CK_ULONG = count;
        try check(self.fns.C_GetSlotList.?(ck_true, out.ptr, &got));
        if (got > count) return Pkcs11Error.MalformedResponse;
        return out[0..@intCast(got)];
    }

    pub fn tokenInfo(self: *Module, slot_id: SlotId) Pkcs11Error!TokenInfo {
        var raw: c.CK_TOKEN_INFO = .{};
        try check(self.fns.C_GetTokenInfo.?(slot_id, &raw));

        var out = TokenInfo{
            .slot_id = slot_id,
            .label = undefined,
            .label_len = 0,
            .model = undefined,
            .model_len = 0,
            .serial = undefined,
            .serial_len = 0,
            .write_protected = (raw.flags & c.CKF_WRITE_PROTECTED) != 0,
            .login_required = (raw.flags & c.CKF_LOGIN_REQUIRED) != 0,
            .initialized = (raw.flags & c.CKF_TOKEN_INITIALIZED) != 0,
        };
        out.label_len = trimPadded(32, raw.label, &out.label);
        out.model_len = trimPadded(16, raw.model, &out.model);
        out.serial_len = trimPadded(16, raw.serialNumber, &out.serial);
        return out;
    }

    /// Mechanisms the token in `slot_id` implements.
    pub fn mechanisms(self: *Module, slot_id: SlotId, out: []MechanismType) Pkcs11Error![]MechanismType {
        var count: c.CK_ULONG = 0;
        try check(self.fns.C_GetMechanismList.?(slot_id, null, &count));
        if (count == 0) return out[0..0];
        if (count > out.len) return Pkcs11Error.BufferTooSmall;

        var got: c.CK_ULONG = count;
        try check(self.fns.C_GetMechanismList.?(slot_id, out.ptr, &got));
        if (got > count) return Pkcs11Error.MalformedResponse;
        return out[0..@intCast(got)];
    }

    /// Whether the token implements a mechanism. Asked of the token rather
    /// than inferred from its model string.
    pub fn supportsMechanism(self: *Module, slot_id: SlotId, want: MechanismType) Pkcs11Error!bool {
        var buf: [512]c.CK_MECHANISM_TYPE = undefined;
        const list = self.mechanisms(slot_id, &buf) catch |err| switch (err) {
            // A token advertising more than 512 mechanisms is not a reason to
            // answer "no": fall back to asking about the one mechanism.
            Pkcs11Error.BufferTooSmall => {
                var info: c.CK_MECHANISM_INFO = .{};
                if (self.fns.C_GetMechanismInfo) |f| {
                    return f(slot_id, want, &info) == c.CKR_OK;
                }
                return err;
            },
            else => return err,
        };
        return std.mem.indexOfScalar(c.CK_MECHANISM_TYPE, list, want) != null;
    }

    /// Open a session on `slot_index`, resolving the index against the module's
    /// live slot list.
    pub fn openSession(self: *Module, config: Config) Pkcs11Error!Session {
        var slot_buf: [64]c.CK_SLOT_ID = undefined;
        const slots = try self.slotsWithToken(&slot_buf);
        if (slots.len == 0) return Pkcs11Error.TokenAbsent;
        if (config.slot_index >= slots.len) return Pkcs11Error.SlotNotFound;
        return self.openSessionOnSlot(slots[config.slot_index], config.read_write);
    }

    pub fn openSessionOnSlot(self: *Module, slot_id: SlotId, read_write: bool) Pkcs11Error!Session {
        // `CKF_SERIAL_SESSION` is mandatory in every version of the spec that
        // has shipped; the flag exists only for a parallel mode that was never
        // defined.
        var flags: c.CK_FLAGS = c.CKF_SERIAL_SESSION;
        if (read_write) flags |= c.CKF_RW_SESSION;

        var handle: c.CK_SESSION_HANDLE = 0;
        try check(self.fns.C_OpenSession.?(slot_id, flags, null, null, &handle));

        return Session{
            .fns = self.fns,
            .handle = handle,
            .slot_id = slot_id,
            .logged_in = false,
        };
    }
};

/// An open session against one token.
pub const Session = struct {
    fns: *c.CK_FUNCTION_LIST,
    handle: c.CK_SESSION_HANDLE,
    slot_id: SlotId,
    logged_in: bool,

    /// Log in as the normal user.
    ///
    /// `pin` is taken as a slice from the caller and is neither copied nor
    /// logged here. Cryptoki's parameter is non-const `CK_BYTE_PTR`, so the
    /// cast is required by the C signature; no module writes through it.
    pub fn login(self: *Session, pin: []const u8) Pkcs11Error!void {
        const f = self.fns.C_Login orelse return Pkcs11Error.NotACryptokiModule;
        try check(f(self.handle, c.CKU_USER, @constCast(pin.ptr), pin.len));
        self.logged_in = true;
    }

    pub fn logout(self: *Session) void {
        if (!self.logged_in) return;
        if (self.fns.C_Logout) |f| _ = f(self.handle);
        self.logged_in = false;
    }

    /// Close the session and poison the struct.
    ///
    /// Setting `self.*` to `undefined` makes any later use — including a second
    /// `close` — trap in a safe build instead of passing a stale handle to the
    /// token, which is a far quieter failure. Callers must therefore close
    /// exactly once; pair an explicit `close` with `errdefer`, not `defer`.
    pub fn close(self: *Session) void {
        self.logout();
        _ = self.fns.C_CloseSession.?(self.handle);
        self.* = undefined;
    }

    /// Random bytes from the token's own generator. Never falls back to the OS
    /// CSPRNG: a caller who asked for token entropy and silently received host
    /// entropy has no way to tell.
    pub fn getRandom(self: *Session, out: []u8) Pkcs11Error!void {
        if (out.len == 0) return;
        const f = self.fns.C_GenerateRandom orelse return Pkcs11Error.UnsupportedMechanism;
        try check(f(self.handle, out.ptr, out.len));
    }

    /// Generate a P-256 key pair on the token.
    ///
    /// The private half is created with `CKA_SENSITIVE` and without
    /// `CKA_EXTRACTABLE`, so the token refuses to disclose it. `label` names
    /// the objects so a later session can find them by identity rather than by
    /// a handle, which does not survive the session.
    pub fn generateEcdsaP256(self: *Session, label: []const u8, token_object: bool) Pkcs11Error!KeyPair {
        const f = self.fns.C_GenerateKeyPair orelse return Pkcs11Error.UnsupportedMechanism;

        var mech = c.CK_MECHANISM{
            .mechanism = c.CKM_EC_KEY_PAIR_GEN,
            .pParameter = null,
            .ulParameterLen = 0,
        };

        var yes: c.CK_BBOOL = ck_true;
        var no: c.CK_BBOOL = ck_false;
        var on_token: c.CK_BBOOL = if (token_object) ck_true else ck_false;
        var params = p256_ec_params;

        var pub_tmpl = [_]c.CK_ATTRIBUTE{
            .{ .type = c.CKA_TOKEN, .pValue = &on_token, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_VERIFY, .pValue = &yes, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_EC_PARAMS, .pValue = &params, .ulValueLen = params.len },
            .{ .type = c.CKA_LABEL, .pValue = @constCast(label.ptr), .ulValueLen = label.len },
        };
        var priv_tmpl = [_]c.CK_ATTRIBUTE{
            .{ .type = c.CKA_TOKEN, .pValue = &on_token, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_PRIVATE, .pValue = &yes, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_SIGN, .pValue = &yes, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_SENSITIVE, .pValue = &yes, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_EXTRACTABLE, .pValue = &no, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_LABEL, .pValue = @constCast(label.ptr), .ulValueLen = label.len },
        };

        var pub_h: c.CK_OBJECT_HANDLE = 0;
        var priv_h: c.CK_OBJECT_HANDLE = 0;
        try check(f(
            self.handle,
            &mech,
            &pub_tmpl,
            pub_tmpl.len,
            &priv_tmpl,
            priv_tmpl.len,
            &pub_h,
            &priv_h,
        ));

        const point = self.readPublicPoint(pub_h) catch |err| {
            // A key pair whose public point cannot be read is unusable, and
            // leaving it on the token would litter it with objects the caller
            // has no handle for.
            self.destroyObject(priv_h) catch {};
            self.destroyObject(pub_h) catch {};
            return err;
        };

        return .{ .public = pub_h, .private = priv_h, .public_sec1 = point };
    }

    /// Read `CKA_EC_POINT` and return the uncompressed SEC1 point.
    ///
    /// The spec says this attribute is the DER encoding of the X9.62 ECPoint as
    /// an OCTET STRING, i.e. `04 41 <65 bytes>` for P-256. Several shipped
    /// tokens return the bare 65 bytes instead. Both are accepted, and which
    /// one arrived is decided by parsing rather than by length alone: the bare
    /// form starts `0x04` (the uncompressed-point marker) and the wrapped form
    /// starts `0x04` (the OCTET STRING tag) too, so the second byte has to be
    /// checked against the remaining length.
    pub fn readPublicPoint(self: *Session, obj: ObjectHandle) Pkcs11Error![65]u8 {
        var buf: [128]u8 = undefined;
        const raw = try self.readAttribute(obj, c.CKA_EC_POINT, &buf);

        if (raw.len == 65 and raw[0] == 0x04) {
            var out: [65]u8 = undefined;
            @memcpy(&out, raw);
            return out;
        }

        // DER OCTET STRING: tag 0x04, then a definite-form length. 65 fits in
        // the short form, but the long form (0x81 0x41) is also legal DER and
        // some tokens emit it.
        if (raw.len >= 2 and raw[0] == 0x04) {
            var body: []const u8 = undefined;
            if (raw[1] == 0x41 and raw.len >= 2 + 65) {
                body = raw[2..][0..65];
            } else if (raw[1] == 0x81 and raw.len >= 3 + 65 and raw[2] == 0x41) {
                body = raw[3..][0..65];
            } else {
                return Pkcs11Error.MalformedResponse;
            }
            if (body[0] != 0x04) return Pkcs11Error.MalformedResponse;
            var out: [65]u8 = undefined;
            @memcpy(&out, body);
            return out;
        }

        return Pkcs11Error.MalformedResponse;
    }

    /// Read one attribute, using the spec's two-call size-query convention.
    ///
    /// A token that will not disclose the value sets `ulValueLen` to the
    /// unsigned equivalent of -1 and returns a sensitivity error; that is
    /// reported as `AttributeUnavailable` rather than as an empty value.
    pub fn readAttribute(self: *Session, obj: ObjectHandle, attr: c.CK_ATTRIBUTE_TYPE, out: []u8) Pkcs11Error![]u8 {
        const f = self.fns.C_GetAttributeValue orelse return Pkcs11Error.NotACryptokiModule;

        var query = [_]c.CK_ATTRIBUTE{.{ .type = attr, .pValue = null, .ulValueLen = 0 }};
        try check(f(self.handle, obj, &query, 1));

        const unavailable = ~@as(c.CK_ULONG, 0);
        if (query[0].ulValueLen == unavailable) return Pkcs11Error.AttributeUnavailable;
        if (query[0].ulValueLen > out.len) return Pkcs11Error.BufferTooSmall;

        const want: usize = @intCast(query[0].ulValueLen);
        var fetch = [_]c.CK_ATTRIBUTE{.{ .type = attr, .pValue = out.ptr, .ulValueLen = query[0].ulValueLen }};
        try check(f(self.handle, obj, &fetch, 1));
        if (fetch[0].ulValueLen != want) return Pkcs11Error.MalformedResponse;
        return out[0..want];
    }

    /// Read a `CK_BBOOL` attribute. Cryptoki's rule is that any non-zero byte
    /// is true, not that true is 1.
    pub fn readBoolAttribute(self: *Session, obj: ObjectHandle, attr: c.CK_ATTRIBUTE_TYPE) Pkcs11Error!bool {
        var buf: [1]u8 = undefined;
        const got = try self.readAttribute(obj, attr, &buf);
        if (got.len != 1) return Pkcs11Error.MalformedResponse;
        return got[0] != 0;
    }

    /// Sign a SHA-256 digest with `CKM_ECDSA`, returning raw r || s.
    ///
    /// `CKM_ECDSA` signs a pre-hashed value: the token does not hash the input.
    /// Passing a 32-byte digest is therefore correct for SHA-256 and P-256, and
    /// passing a message here would sign the wrong thing without any error.
    pub fn signDigest(self: *Session, private: ObjectHandle, digest: [32]u8) Pkcs11Error![64]u8 {
        const init_f = self.fns.C_SignInit orelse return Pkcs11Error.UnsupportedMechanism;
        const sign_f = self.fns.C_Sign orelse return Pkcs11Error.UnsupportedMechanism;

        var mech = c.CK_MECHANISM{ .mechanism = c.CKM_ECDSA, .pParameter = null, .ulParameterLen = 0 };
        try check(init_f(self.handle, &mech, private));

        var sig: [64]u8 = undefined;
        var len: c.CK_ULONG = sig.len;
        var input = digest;
        try check(sign_f(self.handle, &input, input.len, &sig, &len));

        // P-256 r || s is exactly 64 bytes. A token that answered with a DER
        // signature, or with unpadded halves, would produce a shorter value;
        // accepting it and calling it raw would hand the caller something that
        // silently fails to verify.
        if (len != sig.len) return Pkcs11Error.MalformedResponse;
        return sig;
    }

    /// Ask the token how large a signature buffer must be. This is the spec's
    /// size-query convention applied to `C_Sign`, and it is how a caller sizes
    /// a buffer for a curve this module does not hardcode.
    ///
    /// The result is an upper bound, not necessarily the exact length: the spec
    /// allows a token to answer with a conservative maximum, and NSS softoken
    /// does exactly that, reporting 144 for a P-256 key whose signatures are 64
    /// bytes. Callers must use it to size a buffer and then read the length
    /// `C_Sign` actually writes, not treat it as the signature length.
    ///
    /// A size query does *not* end the signing operation it queried, and
    /// Cryptoki 2.40 has no way to cancel one — `C_SessionCancel` arrived in
    /// 3.0 and the tokens this is aimed at do not implement it. An
    /// implementation that returned here would leave the session with an
    /// operation active, and every later operation on it would fail with
    /// `CKR_OPERATION_ACTIVE`; because that failure lands on the *next* call,
    /// it would look like a bug anywhere but here. So the operation is carried
    /// to completion and the result discarded. The digest signed is a fixed
    /// zero block, never anything the caller supplied.
    pub fn signatureLength(self: *Session, private: ObjectHandle) Pkcs11Error!usize {
        const init_f = self.fns.C_SignInit orelse return Pkcs11Error.UnsupportedMechanism;
        const sign_f = self.fns.C_Sign orelse return Pkcs11Error.UnsupportedMechanism;

        var mech = c.CK_MECHANISM{ .mechanism = c.CKM_ECDSA, .pParameter = null, .ulParameterLen = 0 };
        try check(init_f(self.handle, &mech, private));

        var digest: [32]u8 = @splat(0);
        var len: c.CK_ULONG = 0;
        try check(sign_f(self.handle, &digest, digest.len, null, &len));

        var scratch: [512]u8 = undefined;
        if (len > scratch.len) return Pkcs11Error.BufferTooSmall;
        var produced: c.CK_ULONG = scratch.len;
        try check(sign_f(self.handle, &digest, digest.len, &scratch, &produced));

        return @intCast(len);
    }

    /// Verify a raw r || s signature on the token, with the token's own public
    /// key object.
    ///
    /// This exists to exercise the token's verify path. It is not how a relying
    /// party should check a signature: a verifier that asks the same token that
    /// produced the signature has learned nothing. Callers verify against the
    /// exported public point with `std.crypto`.
    pub fn verifyDigest(
        self: *Session,
        public: ObjectHandle,
        digest: [32]u8,
        signature: [64]u8,
    ) Pkcs11Error!void {
        const init_f = self.fns.C_VerifyInit orelse return Pkcs11Error.UnsupportedMechanism;
        const verify_f = self.fns.C_Verify orelse return Pkcs11Error.UnsupportedMechanism;

        var mech = c.CK_MECHANISM{ .mechanism = c.CKM_ECDSA, .pParameter = null, .ulParameterLen = 0 };
        try check(init_f(self.handle, &mech, public));

        var input = digest;
        var sig = signature;
        try check(verify_f(self.handle, &input, input.len, &sig, sig.len));
    }

    /// Generate an AES key on the token for `CKM_AES_GCM`.
    pub fn generateAesKey(self: *Session, bytes: u8, label: []const u8, token_object: bool) Pkcs11Error!ObjectHandle {
        const f = self.fns.C_GenerateKey orelse return Pkcs11Error.UnsupportedMechanism;
        if (bytes != 16 and bytes != 24 and bytes != 32) return Pkcs11Error.UnsupportedMechanism;

        var mech = c.CK_MECHANISM{ .mechanism = c.CKM_AES_KEY_GEN, .pParameter = null, .ulParameterLen = 0 };

        var yes: c.CK_BBOOL = ck_true;
        var no: c.CK_BBOOL = ck_false;
        var on_token: c.CK_BBOOL = if (token_object) ck_true else ck_false;
        var len: c.CK_ULONG = bytes;

        var tmpl = [_]c.CK_ATTRIBUTE{
            .{ .type = c.CKA_TOKEN, .pValue = &on_token, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_VALUE_LEN, .pValue = &len, .ulValueLen = @sizeOf(c.CK_ULONG) },
            .{ .type = c.CKA_ENCRYPT, .pValue = &yes, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_DECRYPT, .pValue = &yes, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_SENSITIVE, .pValue = &yes, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_EXTRACTABLE, .pValue = &no, .ulValueLen = @sizeOf(c.CK_BBOOL) },
            .{ .type = c.CKA_LABEL, .pValue = @constCast(label.ptr), .ulValueLen = label.len },
        };

        var key: c.CK_OBJECT_HANDLE = 0;
        try check(f(self.handle, &mech, &tmpl, tmpl.len, &key));
        return key;
    }

    /// AES-GCM encrypt on the token.
    ///
    /// `out` receives ciphertext || tag, which is how `C_Encrypt` returns a GCM
    /// result — the tag is appended, not returned separately. The caller
    /// supplies the IV; this module does not invent one, because a GCM IV
    /// reused under one key destroys the mode's security and only the caller
    /// knows its own IV discipline.
    pub fn aesGcmEncrypt(
        self: *Session,
        key: ObjectHandle,
        iv: []const u8,
        aad: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) Pkcs11Error![]u8 {
        const init_f = self.fns.C_EncryptInit orelse return Pkcs11Error.UnsupportedMechanism;
        const enc_f = self.fns.C_Encrypt orelse return Pkcs11Error.UnsupportedMechanism;

        var params = gcmParams(iv, aad);
        var mech = c.CK_MECHANISM{
            .mechanism = c.CKM_AES_GCM,
            .pParameter = &params,
            .ulParameterLen = @sizeOf(c.CK_GCM_PARAMS),
        };
        try check(init_f(self.handle, &mech, key));

        var len: c.CK_ULONG = out.len;
        try check(enc_f(
            self.handle,
            @constCast(plaintext.ptr),
            plaintext.len,
            out.ptr,
            &len,
        ));
        if (len > out.len) return Pkcs11Error.MalformedResponse;
        return out[0..@intCast(len)];
    }

    /// AES-GCM decrypt on the token. `ciphertext` is ciphertext || tag.
    ///
    /// A tampered ciphertext, tag or AAD is rejected by the token's own tag
    /// check and yields `SignatureInvalid`. On that failure, and on any failure
    /// once the decrypt path has been entered, `out` is wiped rather than left
    /// as the caller had it: the guarantee is that no plaintext survives the
    /// call, not that the buffer is untouched. A conforming module may write
    /// recovered plaintext into `out` before failing the tag check, so the wipe
    /// is what makes the guarantee true for any module, not only well-behaved
    /// ones.
    ///
    /// The two mechanism-availability errors are the exception, and are called
    /// out because the wipe is deliberately not claimed for them: they return
    /// before the `errdefer` is installed and so leave `out` alone. Nothing is
    /// lost by that, because those paths return before the token is ever asked
    /// to decrypt, so no plaintext from this call can exist to leak.
    pub fn aesGcmDecrypt(
        self: *Session,
        key: ObjectHandle,
        iv: []const u8,
        aad: []const u8,
        ciphertext: []const u8,
        out: []u8,
    ) Pkcs11Error![]u8 {
        const init_f = self.fns.C_DecryptInit orelse return Pkcs11Error.UnsupportedMechanism;
        const dec_f = self.fns.C_Decrypt orelse return Pkcs11Error.UnsupportedMechanism;

        // `authenticatedDecrypt` promises the caller "no plaintext" when the tag
        // does not match. Cryptoki does not promise that: nothing in the spec
        // forbids C_Decrypt from writing the recovered plaintext into the output
        // buffer and only then failing the tag check, and a module doing so is
        // conforming. Whatever one token happens to do is not a guarantee for
        // every module a caller may load, so the guarantee is made here.
        //
        // A wipe rather than a staging buffer: staging needs an allocator, and
        // neither `Session` nor `Module` has one, so providing it would thread an
        // allocator -- and a new failure mode -- through the whole open path to
        // defend a buffer the caller has already given up. Zeroing covers every
        // error return uniformly, including one added later, and its cleanup is
        // bounded by `out` and needs no free.
        //
        // Installed before the first token call, so `C_DecryptInit` failures are
        // covered too. The contract itself is stated on the doc comment above,
        // where callers read it; it is not restated here to avoid two copies
        // that can drift apart.
        errdefer std.crypto.secureZero(u8, out);

        var params = gcmParams(iv, aad);
        var mech = c.CK_MECHANISM{
            .mechanism = c.CKM_AES_GCM,
            .pParameter = &params,
            .ulParameterLen = @sizeOf(c.CK_GCM_PARAMS),
        };
        try check(init_f(self.handle, &mech, key));

        var len: c.CK_ULONG = out.len;
        try check(dec_f(
            self.handle,
            @constCast(ciphertext.ptr),
            ciphertext.len,
            out.ptr,
            &len,
        ));
        if (len > out.len) return Pkcs11Error.MalformedResponse;
        return out[0..@intCast(len)];
    }

    /// Destroy a token object by handle.
    pub fn destroyObject(self: *Session, obj: ObjectHandle) Pkcs11Error!void {
        if (builtin.is_test) {
            if (destroy_seam.pending) |nth| {
                destroy_seam.calls += 1;
                if (destroy_seam.calls == nth) {
                    destroy_seam.pending = null;
                    return Pkcs11Error.CommandFailed;
                }
            }
        }
        const f = self.fns.C_DestroyObject orelse return Pkcs11Error.UnsupportedMechanism;
        try check(f(self.handle, obj));
    }

    /// Find objects by label and class, so a key persisted on the token can be
    /// reopened by identity in a later session. Object handles are session
    /// scoped; labels are not.
    pub fn findByLabel(
        self: *Session,
        class: ObjectClass,
        label: []const u8,
        out: []ObjectHandle,
    ) Pkcs11Error![]ObjectHandle {
        const init_f = self.fns.C_FindObjectsInit orelse return Pkcs11Error.UnsupportedMechanism;
        const find_f = self.fns.C_FindObjects orelse return Pkcs11Error.UnsupportedMechanism;
        const final_f = self.fns.C_FindObjectsFinal orelse return Pkcs11Error.UnsupportedMechanism;

        var want_class = class;
        var tmpl = [_]c.CK_ATTRIBUTE{
            .{ .type = c.CKA_CLASS, .pValue = &want_class, .ulValueLen = @sizeOf(c.CK_OBJECT_CLASS) },
            .{ .type = c.CKA_LABEL, .pValue = @constCast(label.ptr), .ulValueLen = label.len },
        };

        try check(init_f(self.handle, &tmpl, tmpl.len));
        defer _ = final_f(self.handle);

        var count: c.CK_ULONG = 0;
        try check(find_f(self.handle, out.ptr, out.len, &count));
        if (count > out.len) return Pkcs11Error.MalformedResponse;
        return out[0..@intCast(count)];
    }

    /// Count the objects of a class visible in this session, in batches, so a
    /// caller can enumerate a token without allocating for its whole contents.
    pub fn countObjects(self: *Session, class: ObjectClass) Pkcs11Error!usize {
        const init_f = self.fns.C_FindObjectsInit orelse return Pkcs11Error.UnsupportedMechanism;
        const find_f = self.fns.C_FindObjects orelse return Pkcs11Error.UnsupportedMechanism;
        const final_f = self.fns.C_FindObjectsFinal orelse return Pkcs11Error.UnsupportedMechanism;

        var want_class = class;
        var tmpl = [_]c.CK_ATTRIBUTE{
            .{ .type = c.CKA_CLASS, .pValue = &want_class, .ulValueLen = @sizeOf(c.CK_OBJECT_CLASS) },
        };

        try check(init_f(self.handle, &tmpl, tmpl.len));
        defer _ = final_f(self.handle);

        var total: usize = 0;
        var batch: [32]c.CK_OBJECT_HANDLE = undefined;
        while (true) {
            var count: c.CK_ULONG = 0;
            try check(find_f(self.handle, &batch, batch.len, &count));
            if (count == 0) break;
            if (count > batch.len) return Pkcs11Error.MalformedResponse;
            total += @intCast(count);
        }
        return total;
    }
};

/// Build the GCM mechanism parameter block.
///
/// `ulIvBits` is set as well as `ulIvLen` because the two coexist in the
/// structure and modules disagree about which they read: the field was present
/// in the v2.40 header, dropped from the v3.0 structure, then restored. Setting
/// both consistently is the only spelling every shipped module accepts.
fn gcmParams(iv: []const u8, aad: []const u8) c.CK_GCM_PARAMS {
    return .{
        .pIv = @constCast(iv.ptr),
        .ulIvLen = iv.len,
        .ulIvBits = iv.len * 8,
        .pAAD = if (aad.len == 0) null else @constCast(aad.ptr),
        .ulAADLen = aad.len,
        // GCM tag length in bits. 128 is the full tag; a truncated tag weakens
        // forgery resistance and is not offered here.
        .ulTagBits = 128,
    };
}

// =============================================================================
// Signature encoding
//
// The raw/DER conversion lives in `ecdsa_sig.zig` because it touches no
// Cryptoki type. Re-exported here so a PKCS#11 caller finds it where it needs
// it, and shared with the absent shim so the two backends cannot drift.
// =============================================================================

pub const derFromRaw = ecdsa_sig.derFromRaw;
pub const rawFromDer = ecdsa_sig.rawFromDer;
pub const max_der_signature_len = ecdsa_sig.max_der_len;

// =============================================================================
// Tests
//
// Everything that requires a token is in tests/pkcs11_integration.zig, because
// a test that cannot reach one can only prove that absence is reported. The
// signature encoders carry their own tests in `ecdsa_sig.zig`.
// =============================================================================

const testing = std.testing;

test "padded Cryptoki text fields are trimmed" {
    // Cryptoki pads with spaces and does not NUL-terminate, so this is what a
    // 32-byte CK_TOKEN_INFO.label actually looks like on the wire.
    var src: [32]u8 = @splat(' ');
    @memcpy(src[0..14], "SoftHSM slot 0");

    var dst: [32]u8 = undefined;
    const len = trimPadded(32, src, &dst);
    try testing.expectEqualStrings("SoftHSM slot 0", dst[0..len]);

    // A field that is all padding trims to empty rather than to one space.
    const blank: [32]u8 = @splat(' ');
    try testing.expectEqual(@as(usize, 0), trimPadded(32, blank, &dst));
}

test "the P-256 EC parameters are the X9.62 prime256v1 OID" {
    // 1.2.840.10045.3.1.7, DER-encoded. Checked here because a wrong OID would
    // make the token generate a key on a different curve, or refuse, and the
    // failure would surface far from this constant.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 },
        &p256_ec_params,
    );
}

test "Cryptoki handle types are pointer-width on this target" {
    // `CK_ULONG` is `unsigned long`. If translate-c ever resolved it to a
    // fixed-width type, every struct in the ABI would silently shift.
    try testing.expectEqual(@sizeOf(c_ulong), @sizeOf(c.CK_ULONG));
    try testing.expectEqual(@sizeOf(c_ulong), @sizeOf(c.CK_OBJECT_HANDLE));
    try testing.expectEqual(@sizeOf(c_ulong), @sizeOf(c.CK_SESSION_HANDLE));
    try testing.expectEqual(@as(usize, 1), @sizeOf(c.CK_BBOOL));
}

test "the object classes match the values the absent shim transcribes" {
    // `pkcs11_absent.zig` cannot read the header, so it spells these out. If
    // the header ever disagreed with the standard's numbering, a call site
    // would mean one thing in one build and another in the other.
    try testing.expectEqual(@as(ObjectClass, 0), object_class.data);
    try testing.expectEqual(@as(ObjectClass, 1), object_class.certificate);
    try testing.expectEqual(@as(ObjectClass, 2), object_class.public_key);
    try testing.expectEqual(@as(ObjectClass, 3), object_class.private_key);
    try testing.expectEqual(@as(ObjectClass, 4), object_class.secret_key);
}

test "the mechanism values match the ones the absent shim transcribes" {
    // Same hazard as the object classes, with a sharper edge: a wrong value
    // here is not a compile error anywhere, it is a token being asked for a
    // mechanism nobody meant.
    try testing.expectEqual(@as(MechanismType, 0x1040), mechanism.ec_key_pair_gen);
    try testing.expectEqual(@as(MechanismType, 0x1041), mechanism.ecdsa);
    try testing.expectEqual(@as(MechanismType, 0x1080), mechanism.aes_key_gen);
    try testing.expectEqual(@as(MechanismType, 0x1087), mechanism.aes_gcm);
    try testing.expectEqual(@as(c.CK_ATTRIBUTE_TYPE, 0x103), attribute.sensitive);
    try testing.expectEqual(@as(c.CK_ATTRIBUTE_TYPE, 0x162), attribute.extractable);
}

test "the real backend identifies itself as real" {
    try testing.expect(is_real_backend);
}

/// A Cryptoki module that writes the recovered plaintext into the caller's
/// buffer and only then fails the tag check. Nothing in the spec forbids that,
/// so it is the module `aesGcmDecrypt`'s guarantee has to hold against. It is
/// not a stand-in for a token: it implements exactly the one behaviour the
/// guarantee exists to contain, because a real token that happens to behave
/// well would test nothing.
const hostile_module = struct {
    const leaked = "recovered-plaintext";

    fn decryptInit(
        _: c.CK_SESSION_HANDLE,
        _: [*c]c.CK_MECHANISM,
        _: c.CK_OBJECT_HANDLE,
    ) callconv(.c) c.CK_RV {
        return c.CKR_OK;
    }

    fn decrypt(
        _: c.CK_SESSION_HANDLE,
        _: [*c]u8,
        _: c.CK_ULONG,
        data: [*c]u8,
        data_len: [*c]c.CK_ULONG,
    ) callconv(.c) c.CK_RV {
        @memcpy(data[0..leaked.len], leaked);
        data_len.* = leaked.len;
        return c.CKR_ENCRYPTED_DATA_INVALID;
    }
};

test "a module that writes plaintext before failing the tag check leaks none of it" {
    var fns = std.mem.zeroes(c.CK_FUNCTION_LIST);
    fns.C_DecryptInit = hostile_module.decryptInit;
    fns.C_Decrypt = hostile_module.decrypt;

    var session = Session{
        .fns = &fns,
        .handle = 1,
        .slot_id = 0,
        .logged_in = true,
    };

    // Deliberately larger than the plaintext, so a wipe of only the reported
    // length would still pass while leaving the tail as the module left it.
    var out: [64]u8 = @splat(0xa5);
    const iv: [12]u8 = @splat(0);
    const ciphertext: [32]u8 = @splat(0);
    try testing.expectError(
        Pkcs11Error.SignatureInvalid,
        session.aesGcmDecrypt(1, &iv, "", &ciphertext, &out),
    );

    // Not "out is unchanged": the contract is no plaintext, and the buffer is
    // zeroed to deliver it. Asserting the sentinel survived would be asserting
    // the opposite of what this promises.
    try testing.expect(std.mem.allEqual(u8, &out, 0));
    try testing.expect(std.mem.indexOf(u8, &out, hostile_module.leaked) == null);
}
