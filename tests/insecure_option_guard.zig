//! The refusing branch of `security.checkInsecureOption`, exercised directly.
//!
//! This is a standalone program rather than a `test` block, for two reasons that
//! a test artifact cannot satisfy at the same time.
//!
//! The branch only exists in a release build, so this artifact pins its own
//! optimize mode (see build.zig) rather than following `-Doptimize`. In a Debug
//! `zig build test` the guard permits everything and there is nothing to refuse.
//!
//! And the branch logs, deliberately: refusing an insecure option silently would
//! leave an operator with a build that fails and no statement of why. Zig's test
//! runner owns `std_options` and fails any test that logs an error, so inside a
//! test the diagnostic can only be suppressed or tripped over. As a root module
//! this file installs its own `logFn`, which turns the diagnostic into something
//! to be asserted: the message has to name the option and tell the operator how
//! to proceed.
//!
//! Testing `insecureOptionsPermitted` alone -- which is all the general suite
//! could do -- says nothing about whether `checkInsecureOption` acts on it. A
//! missing `return error` there would leave that test green.

const std = @import("std");
const builtin = @import("builtin");
const zcrypto = @import("zcrypto");
const security = zcrypto.security;

pub const std_options: std.Options = .{ .logFn = captureLog };

var log_buf: [512]u8 = undefined;
var log_len: usize = 0;
var log_count: usize = 0;
var log_level: ?std.log.Level = null;

fn captureLog(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    log_count += 1;
    log_level = message_level;
    const written = std.fmt.bufPrint(log_buf[log_len..], format, args) catch return;
    log_len += written.len;
}

fn captured() []const u8 {
    return log_buf[0..log_len];
}

fn resetLog() void {
    log_len = 0;
    log_count = 0;
    log_level = null;
}

pub fn main() !void {
    try sinkIsASink();
    try refusesLoudly();

    std.debug.print(
        "insecure-option guard: refusal asserted in {s}\n",
        .{@tagName(builtin.mode)},
    );
}

/// If `captureLog` were never installed -- a renamed `std_options`, a changed
/// field, a future Zig that resolves it elsewhere -- the check below would see
/// zero messages and fail on the count, which reads like the guard not logging.
/// Assert the other direction first, so that a broken sink is reported as a
/// broken sink and the content assertions are known to be reading real text
/// rather than an empty buffer that happens to satisfy nothing.
fn sinkIsASink() !void {
    resetLog();
    std.log.warn("sink probe {d}", .{7});
    if (log_count != 1) {
        std.debug.print("log sink not installed: captured {d} messages, wanted 1\n", .{log_count});
        return error.LogSinkNotInstalled;
    }
    if (!std.mem.eql(u8, captured(), "sink probe 7")) {
        std.debug.print("log sink garbled the message: {s}\n", .{captured()});
        return error.LogSinkNotInstalled;
    }
    resetLog();
}

fn refusesLoudly() !void {
    // The whole point of this artifact is that it is not Debug. If the pinned
    // mode is ever lost, the assertions below would silently move to the
    // permissive branch and stop testing the guard.
    if (builtin.mode == .debug) {
        std.debug.print("guard built in Debug; the refusing branch does not exist there\n", .{});
        return error.GuardBuiltInDebug;
    }
    if (security.allow_insecure_options or security.insecureOptionsPermitted()) {
        std.debug.print("guard built with insecure options permitted\n", .{});
        return error.InsecureOptionsPermitted;
    }

    resetLog();
    security.checkInsecureOption("gate_probe_option") catch |err| {
        if (err != error.InsecureOptionInReleaseBuild) {
            std.debug.print("refused with the wrong error: {s}\n", .{@errorName(err)});
            return error.WrongRefusalError;
        }
        return try refusalWasAudible();
    };

    std.debug.print("checkInsecureOption accepted an insecure option in a release build\n", .{});
    return error.InsecureOptionAccepted;
}

/// Refusing is half of it. A guard that fails without saying which option it
/// objected to, or how to override it deliberately, sends the operator to the
/// source to find out -- or, worse, to disabling the guard wholesale.
fn refusalWasAudible() !void {
    if (log_count != 1 or log_level != .err) {
        std.debug.print(
            "refusal logged {d} messages at {?s}, wanted 1 at err\n",
            .{ log_count, if (log_level) |l| @tagName(l) else null },
        );
        return error.RefusalNotDiagnosed;
    }

    const text = captured();
    for ([_][]const u8{
        "gate_probe_option",
        "not allowed in release builds",
        "-Dallow-insecure=true",
    }) |needle| {
        if (std.mem.indexOf(u8, text, needle) == null) {
            std.debug.print("refusal diagnostic omits {s}: {s}\n", .{ needle, text });
            return error.RefusalNotDiagnosed;
        }
    }
}
