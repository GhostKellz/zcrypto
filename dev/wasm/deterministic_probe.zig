//! Shows that zcrypto's deterministic primitives need nothing from the host.
//!
//! `rand` fails closed on a target with no entropy source, and on freestanding
//! wasm it refuses to compile at all. Neither of those is a statement about
//! hashing or key derivation, which are pure functions of their inputs and
//! should run in a sandbox that offers no CSPRNG whatsoever.
//!
//! The gate runs this module under `--entropy=failing`, where the host's
//! `random_get` is present and returns EIO to every call. Exiting 0 there means
//! the deterministic path never consulted it.
//!
//! `--entropy=missing` would have been the stronger check -- a module that does
//! not import `random_get` cannot be affected by it at all -- but that check is
//! not available on this target. Zig's wasm32-wasi preamble imports the whole
//! `wasi_snapshot_preview1` set unconditionally: a program whose entire body is
//! `std.debug.print("hi")` imports `random_get`, and imports exactly the same 28
//! syscalls this one does. So every Zig WASI module fails to instantiate on a
//! host that omits it, whatever the module computes, and the gate asserts that
//! link failure separately rather than pretending the absence is meaningful
//! here.
//!
//! Still a separate program from dev/wasm/entropy_probe.zig. Folding the two
//! together would put a genuine `rand` call in the same binary and leave the
//! result resting on which branch ran.
//!
//! The values are checked against fixed vectors rather than merely computed:
//! a run that produced the wrong digest without entropy would still prove
//! independence from the host, and would still be a broken library.

const std = @import("std");
const zcrypto = @import("zcrypto");

fn hex(comptime n: usize, comptime s: *const [n * 2]u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectBytes(what: []const u8, actual: []const u8, expected: []const u8) void {
    if (std.mem.eql(u8, actual, expected)) return;
    std.debug.print("deterministic_probe: {s} mismatch\n  want {x}\n  got  {x}\n", .{ what, expected, actual });
    std.process.exit(1);
}

pub fn main() !void {
    // FIPS 180-4 SHA-256 of "abc".
    expectBytes(
        "sha256(\"abc\")",
        &zcrypto.hash.sha256("abc"),
        &hex(32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    );

    // RFC 5869 test case 1. Allocation is served from this program's own stack
    // so the run depends on no allocator that might reach for the host.
    var scratch: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);

    const ikm = hex(22, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hex(13, "000102030405060708090a0b0c");
    const info = hex(10, "f0f1f2f3f4f5f6f7f8f9");
    const okm = try zcrypto.kdf.hkdfSha256(fba.allocator(), &ikm, &salt, &info, 42);
    defer fba.allocator().free(okm);

    expectBytes(
        "hkdf-sha256 rfc 5869 tc1",
        okm,
        &hex(42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
    );

    std.debug.print("deterministic_probe: sha256 and hkdf agree with their vectors, no host entropy used\n", .{});
}
