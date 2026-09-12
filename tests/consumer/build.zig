const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Negative control. The guard in src/main.zig is only worth running if it
    // can fail, so this reproduces the regression it exists to catch.
    //
    // Passing `.optimize` to `b.dependency` does NOT do it: zcrypto's exported
    // module deliberately leaves `optimize` unset so it inherits from whatever
    // roots it, which makes that argument inert for the module (it still
    // selects the mode for the dependency's own executables and tests). The
    // way a consumer really ends up with a Debug crypto library is the library
    // pinning `optimize` on its exported module. Setting the field here
    // reproduces exactly that, and keeps the broken configuration inside this
    // fixture instead of adding a loaded footgun to zcrypto's build.zig.
    const pin_dependency_debug = b.option(
        bool,
        "pin-dependency-debug",
        "Pin the zcrypto dependency module to Debug regardless of the consumer's mode (negative control)",
    ) orelse false;

    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });

    const zcrypto_mod = zcrypto_dep.module("zcrypto");
    if (pin_dependency_debug) zcrypto_mod.optimize = .debug;

    const exe = b.addExecutable(.{
        .name = "zcrypto-consumer-guard",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the dependency inheritance guard");
    run_step.dependOn(&run_cmd.step);
}
