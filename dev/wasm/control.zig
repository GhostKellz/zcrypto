//! Negative controls for dev/wasm/run.mjs.
//!
//! Every outcome the runner claims to detect is produced here on demand, so the
//! runner's detection is checked against a module that really does the thing
//! rather than against an assertion that it would. Without these, a runner that
//! reported `ok` unconditionally -- which is exactly what the harnesses this
//! replaces did -- would pass every check in the gate.
//!
//! Built for wasm32-wasi by dev/wasm/check.sh and driven by its first argument.
//! It is deliberately not part of the library and imports none of it: a control
//! that depended on zcrypto could fail for a zcrypto reason and be mistaken for
//! the runner working.

const std = @import("std");

const Mode = enum {
    /// Exit 0. Distinguishes "the runner reports every run as failing" from a
    /// runner that discriminates.
    ok,
    /// Exit non-zero, the way a Zig test binary with a failing test does.
    exit_nonzero,
    /// Trap. `@trap` lowers to the wasm `unreachable` instruction, which is
    /// what a failed bounds check or a panic on this target reaches.
    trap,
    /// Ask the host for entropy. Combined with `--entropy=missing` or
    /// `--entropy=failing` this is what turns those runner modes into a real
    /// observation instead of an untested branch.
    entropy,
};

/// Read the mode from argv[1] through the WASI syscalls directly.
///
/// Deliberately not `std.process`, whose argument iterator needs an allocator on
/// WASI and has moved across recent Zig versions. This file exists to be a fixed
/// point the runner is measured against, so it depends on as little as it can.
fn readMode() ?Mode {
    var argc: usize = 0;
    var argv_buf_size: usize = 0;
    if (std.os.wasi.args_sizes_get(&argc, &argv_buf_size) != .SUCCESS) return null;

    var argv: [8][*:0]u8 = undefined;
    var argv_buf: [256]u8 = undefined;
    // argv[0] is the program name, so a mode needs at least two entries. The
    // capacity checks are not defensive padding: `args_get` writes whatever the
    // host sent, and the host here is a test script that could be edited.
    if (argc < 2 or argc > argv.len or argv_buf_size > argv_buf.len) return null;
    if (std.os.wasi.args_get(&argv, &argv_buf) != .SUCCESS) return null;

    return std.meta.stringToEnum(Mode, std.mem.span(argv[1]));
}

pub fn main() !void {
    const mode = readMode() orelse {
        std.debug.print("control: expected one mode argument, one of: ", .{});
        inline for (@typeInfo(Mode).@"enum".field_names) |name| {
            std.debug.print("{s} ", .{name});
        }
        std.debug.print("\n", .{});
        std.process.exit(2);
    };

    switch (mode) {
        .ok => std.debug.print("control: ok\n", .{}),
        .exit_nonzero => {
            std.debug.print("control: exiting 1 deliberately\n", .{});
            std.process.exit(1);
        },
        .trap => {
            std.debug.print("control: trapping deliberately\n", .{});
            @trap();
        },
        .entropy => {
            var seed: [32]u8 = undefined;
            // `random_get` fills the whole buffer or fails, so this either
            // returns bytes from the host CSPRNG or a hard error. There is no
            // fallback to hide a broken host behind.
            const rc = std.os.wasi.random_get(&seed, seed.len);
            if (rc != .SUCCESS) {
                std.debug.print("control: random_get failed: {t}\n", .{rc});
                std.process.exit(1);
            }
            // Printed so a run whose entropy source was silently stubbed out
            // with zeroes is visible rather than merely "successful".
            std.debug.print("control: entropy first byte {d}\n", .{seed[0]});
        },
    }
}
