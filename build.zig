const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // zsync dependency for async crypto operations
    const zsync_dep = b.lazyDependency("zsync", .{
        .target = target,
        .optimize = optimize,
    });

    // zcrypto module for library consumers
    const zcrypto_imports: []const std.Build.Module.Import = if (zsync_dep) |zsync| blk: {
        break :blk &.{
            .{ .name = "zsync", .module = zsync.module("zsync") },
        };
    } else &.{};

    const zcrypto_mod = b.addModule("zcrypto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = zcrypto_imports,
    });

    // Main executable (demo)
    const exe = b.addExecutable(.{
        .name = "zcrypto-demo",
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

    // zsync crypto example executable
    if (zsync_dep) |zsync| {
        const zsync_example = b.addExecutable(.{
            .name = "zsync-crypto-example",
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/zsync_crypto_example.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "zcrypto", .module = zcrypto_mod },
                    .{ .name = "zsync", .module = zsync.module("zsync") },
                },
            }),
        });
        b.installArtifact(zsync_example);

        // zsync example run step
        const run_zsync_step = b.step("run-zsync", "Run the zsync crypto example");
        const run_zsync_cmd = b.addRunArtifact(zsync_example);
        run_zsync_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_zsync_cmd.addArgs(args);
        run_zsync_step.dependOn(&run_zsync_cmd.step);
    }

    // Advanced features example executable
    const advanced_example = b.addExecutable(.{
        .name = "advanced-features-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/advanced_features.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    b.installArtifact(advanced_example);

    // Benchmark executable
    const bench = b.addExecutable(.{
        .name = "zcrypto-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    b.installArtifact(bench);

    // Run steps
    const run_step = b.step("run", "Run the demo");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // Advanced features example run step
    const run_advanced_step = b.step("run-advanced", "Run the advanced features example");
    const run_advanced_cmd = b.addRunArtifact(advanced_example);
    run_advanced_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_advanced_cmd.addArgs(args);
    run_advanced_step.dependOn(&run_advanced_cmd.step);

    // Benchmark step
    const bench_step = b.step("bench", "Run performance benchmarks");
    const bench_cmd = b.addRunArtifact(bench);
    bench_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| bench_cmd.addArgs(args);
    bench_step.dependOn(&bench_cmd.step);

    // Test steps
    const mod_tests = b.addTest(.{
        .root_module = zcrypto_mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
