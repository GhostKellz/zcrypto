//! Proves that a downstream package's requested target and optimization mode
//! actually reach the zcrypto dependency.
//!
//! Asserting on this program's own `@import("builtin").mode` would prove
//! nothing: it reports how *this* file was compiled, and a zcrypto pinned to
//! Debug underneath a ReleaseSafe consumer looks exactly the same from here.
//! `zcrypto.build_info` is resolved inside the zcrypto module, so comparing the
//! two is what makes the check real. `-Dpin-dependency-debug=true` is the
//! control that forces the mismatch and must fail.

const std = @import("std");
const builtin = @import("builtin");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var failures: usize = 0;

    if (zcrypto.build_info.mode != builtin.mode) {
        std.debug.print(
            "optimize mode not inherited: consumer={s} zcrypto={s}\n",
            .{ @tagName(builtin.mode), @tagName(zcrypto.build_info.mode) },
        );
        failures += 1;
    }

    if (zcrypto.build_info.cpu_arch != builtin.target.cpu.arch) {
        std.debug.print(
            "cpu arch not inherited: consumer={s} zcrypto={s}\n",
            .{ @tagName(builtin.target.cpu.arch), @tagName(zcrypto.build_info.cpu_arch) },
        );
        failures += 1;
    }

    if (zcrypto.build_info.os_tag != builtin.target.os.tag) {
        std.debug.print(
            "os tag not inherited: consumer={s} zcrypto={s}\n",
            .{ @tagName(builtin.target.os.tag), @tagName(zcrypto.build_info.os_tag) },
        );
        failures += 1;
    }

    if (zcrypto.build_info.abi != builtin.target.abi) {
        std.debug.print(
            "abi not inherited: consumer={s} zcrypto={s}\n",
            .{ @tagName(builtin.target.abi), @tagName(zcrypto.build_info.abi) },
        );
        failures += 1;
    }

    // Importing a module only proves it parses. Call through real API bodies so
    // the dependency is genuinely codegenned in the inherited mode.
    try exerciseStableApi();
    try nameMigrationSurface();

    if (failures != 0) return error.DependencyBuildSettingsNotInherited;

    std.debug.print(
        "zcrypto {s} consumed as {s}/{s}-{s}-{s}: build settings inherited\n",
        .{
            zcrypto.version,
            @tagName(zcrypto.build_info.mode),
            @tagName(zcrypto.build_info.cpu_arch),
            @tagName(zcrypto.build_info.os_tag),
            @tagName(zcrypto.build_info.abi),
        },
    );
}

fn exerciseStableApi() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const message = "zcrypto external consumer guard";

    const digest = zcrypto.hash.sha256(message);
    if (std.mem.allEqual(u8, &digest, 0)) return error.HashProducedZeroDigest;

    var key: [32]u8 = undefined;
    zcrypto.rand.fill(&key);
    defer zcrypto.util.secureZero(&key);

    const ciphertext = try zcrypto.sym.encryptAesGcm(allocator, message, &key);
    defer allocator.free(ciphertext);
    const recovered = try zcrypto.sym.decryptAesGcm(allocator, ciphertext, &key);
    defer allocator.free(recovered);
    if (!std.mem.eql(u8, message, recovered)) return error.AeadRoundTripMismatch;

    var alice = try zcrypto.kex.X25519.generateKeypair();
    defer alice.zeroize();
    var bob = try zcrypto.kex.X25519.generateKeypair();
    defer bob.zeroize();
    const shared_a = try zcrypto.kex.X25519.computeSharedSecret(alice.private_key, bob.public_key);
    const shared_b = try zcrypto.kex.X25519.computeSharedSecret(bob.private_key, alice.public_key);
    if (!std.mem.eql(u8, &shared_a, &shared_b)) return error.KeyExchangeMismatch;

    const okm = try zcrypto.kdf.hkdfSha256(allocator, &shared_a, "consumer-salt", "consumer-info", 32);
    defer allocator.free(okm);
    if (okm.len != 32) return error.KdfLengthMismatch;
}

/// Names, from outside the package, every type `docs/migration/v1.0.7.md` tells
/// a caller to move to.
///
/// Reachability from inside the repository is not the same question. The
/// in-tree TPM tests receive the backend as a module that `build.zig` wires up,
/// so they can write `tpm2.SealOptions` whether or not `zcrypto.hsm` re-exports
/// it; a consumer has only what the package exports. `SealOptions`,
/// `PcrPolicy` and `SealedBlob` appear in `TPMProvider`'s public signatures and
/// were unnameable from here until v1.0.7 added the aliases -- a caller could
/// pass an anonymous literal but could not declare a variable or a struct field
/// of the type.
///
/// Declaring the types is the whole check; a migration note that points at a
/// name nobody outside can write is not a migration path.
fn nameMigrationSurface() !void {
    const seal_opts: zcrypto.hsm.TPMProvider.SealOptions = .{};
    const pcrs: zcrypto.hsm.TPMProvider.PcrPolicy = .{ .indices = &.{} };
    _ = seal_opts;
    _ = pcrs;

    const BlobType = zcrypto.hsm.TPMProvider.SealedBlob;
    const InfoType = zcrypto.hsm.TPMProvider.DeviceInfo;
    const QuoteType = zcrypto.hsm.TPMProvider.Quote;
    if (@sizeOf(BlobType) == 0 or @sizeOf(InfoType) == 0 or @sizeOf(QuoteType) == 0) {
        return error.HsmBackendTypeIsEmpty;
    }

    // The replacement for the removed `util.getTimestampNanos` family. A caller
    // following the migration note runs exactly this shape.
    const start = try zcrypto.util.getMonotonicOrError();
    const end = try zcrypto.util.getMonotonicOrError();
    _ = try end.since(start);
}
