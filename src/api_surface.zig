//! Forces the compiler to analyse every public declaration zcrypto exports.
//!
//! Zig type-checks a function where it is *referenced*, not where it is
//! defined. A `pub fn` that no test happens to call is therefore never
//! compiled, and ships broken with the whole suite green. That is not a
//! hypothetical: when this file was first written it surfaced 18 such entry
//! points, among them `WasmCrypto.hkdf`, which called `HkdfSha256.extract` with
//! the wrong arity *and* the salt and IKM transposed, and
//! `security.isReleaseBuild`, the guard behind `insecure_skip_verify`, which
//! still compared against the pre-rename `.Debug` tag.
//!
//! This is the API-surface counterpart to the wasm32 problem in §4: a green
//! build only ever describes the code that was reached. The difference is who
//! pays. An unanalysed internal helper is our problem; an unanalysed `pub fn`
//! is a compile error we hand to a consumer.
//!
//! `std.testing.refAllDecls` is not sufficient. It is shallow -- it references
//! the top-level decls of one namespace and does not descend into nested types,
//! so it reaches `zcrypto.tls` but not `TlsConfig.clone`. None of the 18 were
//! in its reach. The recursive variant that used to live beside it is gone from
//! `0.17.0-dev.2085+5e36170b5`, hence the local implementation.
const std = @import("std");

/// Namespaces zcrypto re-exports but does not own.
///
/// `async_crypto.Io` is `zsync.Io` is `std.Io`. Descending into it compiles
/// std's Darwin, Windows and kqueue I/O backends on a Linux host: 66 errors,
/// every one inside the Zig standard library and none in zcrypto. Whether std
/// builds for a target we are not building for is not a property of this
/// library's API surface. Our obligation is that the alias resolves and that
/// zcrypto's own functions using it compile, and both still hold.
///
/// Matched by type identity rather than by name. `@typeName` renders std's
/// `Io.Dispatch` and our `hash.Sha256` in the same `<file>.<Type>` form, so a
/// prefix test cannot tell a foreign namespace from one of ours. Identity can.
///
/// Anything absent from this list is still descended into. That is the safe
/// direction: a newly re-exported third-party namespace shows up as build noise
/// and gets a deliberate decision, rather than silently going unchecked.
const foreign_namespaces = [_]type{
    std.Io,
};

fn isForeign(comptime T: type) bool {
    inline for (foreign_namespaces) |f| {
        if (T == f) return true;
    }
    return false;
}

/// Reference every declaration of `T`, descending into nested namespaces.
///
/// `depth` bounds the recursion rather than tracking visited types: a type that
/// declares itself (`pub const Self = @This()`) is an ordinary Zig idiom and
/// would otherwise not terminate. It is a budget, not a property -- raising it
/// can only find more, never less, so it is set well past the deepest namespace
/// zcrypto actually nests.
fn refRecursive(comptime T: type, comptime depth: usize) void {
    if (depth == 0) return;
    inline for (comptime std.meta.declarations(T)) |name| {
        const decl = @field(T, name);
        if (@TypeOf(decl) == type) {
            switch (@typeInfo(decl)) {
                .@"struct", .@"enum", .@"union", .@"opaque" => {
                    if (comptime !isForeign(decl)) refRecursive(decl, depth - 1);
                },
                else => {},
            }
        }
        // Take the address so function bodies are analysed, not just their types.
        _ = &@field(T, name);
    }
}

test "every exported declaration compiles" {
    refRecursive(@import("root.zig"), 8);
}
