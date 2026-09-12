//! Exercises zcrypto's entropy path on wasm32-wasi.
//!
//! dev/wasm/control.zig calls `random_get` itself, which proves the *runner* can
//! present a working, broken, or absent host CSPRNG. It says nothing about what
//! this library does when handed one, because it does not contain any of this
//! library. This program closes that gap: it reaches the host only through
//! `zcrypto.rand`, so what the gate observes is zcrypto's behaviour under each
//! host condition rather than WASI's.
//!
//! Deliberately separate from dev/wasm/deterministic_probe.zig. A module that
//! imports `random_get` cannot be instantiated by a host that does not provide
//! it, so the two claims -- "entropy fails closed" and "hashing needs no host
//! entropy at all" -- can only be made by two modules.

const std = @import("std");
const zcrypto = @import("zcrypto");

const Mode = enum {
    /// `rand.fillChecked`, the API a caller uses when it intends to handle a
    /// dead entropy source. Under `--entropy=failing` this must surface the
    /// error; the failure this guards against is returning success with a
    /// buffer that was never written.
    checked,
    /// `rand.fill`, which panics rather than returning. Under
    /// `--entropy=failing` that panic must actually happen: this is the API
    /// most callers reach for, so "fails closed" has to hold for it too and
    /// not only for the checked variant.
    unchecked,
};

fn readMode() ?Mode {
    var argc: usize = 0;
    var argv_buf_size: usize = 0;
    if (std.os.wasi.args_sizes_get(&argc, &argv_buf_size) != .SUCCESS) return null;

    var argv: [8][*:0]u8 = undefined;
    var argv_buf: [256]u8 = undefined;
    if (argc < 2 or argc > argv.len or argv_buf_size > argv_buf.len) return null;
    if (std.os.wasi.args_get(&argv, &argv_buf) != .SUCCESS) return null;

    return std.meta.stringToEnum(Mode, std.mem.span(argv[1]));
}

/// Reject a buffer the library reported as filled but left untouched.
///
/// An entropy path that fails open does not announce itself: it returns success
/// and leaves whatever was in the buffer. Checking for all-zero catches the
/// common shape of that -- a zero-initialised or memset buffer -- and costs a
/// pass every 2^-2048 runs on a working CSPRNG, which is not a rate worth
/// engineering around.
fn allZero(buf: []const u8) bool {
    for (buf) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

pub fn main() !void {
    const mode = readMode() orelse {
        std.debug.print("entropy_probe: expected one mode argument, one of: ", .{});
        inline for (@typeInfo(Mode).@"enum".field_names) |name| {
            std.debug.print("{s} ", .{name});
        }
        std.debug.print("\n", .{});
        std.process.exit(2);
    };

    var buf: [256]u8 = @splat(0);

    switch (mode) {
        .checked => zcrypto.rand.fillChecked(&buf) catch |err| {
            std.debug.print("entropy_probe: fillChecked failed: {t}\n", .{err});
            std.process.exit(1);
        },
        .unchecked => zcrypto.rand.fill(&buf),
    }

    if (allZero(&buf)) {
        std.debug.print("entropy_probe: reported success but the buffer is all zero\n", .{});
        std.process.exit(1);
    }
    std.debug.print("entropy_probe: {t} filled {d} bytes, first {d}\n", .{ mode, buf.len, buf[0] });
}
