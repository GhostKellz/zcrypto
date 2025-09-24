const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ============================================================================
    // FEATURE FLAGS - Enable/disable optional components for modular builds
    // ============================================================================

    const enable_tls = b.option(bool, "tls", "Enable TLS 1.3 and QUIC support") orelse true;
    const enable_post_quantum = b.option(bool, "post-quantum", "Enable post-quantum cryptography (ML-KEM, ML-DSA)") orelse true;
    const enable_hardware_accel = b.option(bool, "hardware-accel", "Enable hardware acceleration (SIMD, AES-NI)") orelse true;
    const enable_blockchain = b.option(bool, "blockchain", "Enable blockchain crypto (BLS, Schnorr)") orelse true;
    const enable_vpn = b.option(bool, "vpn", "Enable VPN-specific crypto features") orelse true;
    const enable_wasm = b.option(bool, "wasm", "Enable WebAssembly support") orelse true;
    const enable_enterprise = b.option(bool, "enterprise", "Enable enterprise features (HSM, formal verification)") orelse true;
    const enable_zkp = b.option(bool, "zkp", "Enable zero-knowledge proofs") orelse true;
    const enable_async = b.option(bool, "async", "Enable async crypto operations (requires zsync)") orelse true;

    // ============================================================================
    // DEPENDENCIES - Conditionally include based on features
    // ============================================================================

    var zsync_dep: ?*std.Build.Dependency = null;
    if (enable_async) {
        zsync_dep = b.lazyDependency("zsync", .{
            .target = target,
            .optimize = optimize,
        });
    }

    // ============================================================================
    // MODULE DEFINITIONS - Build modules conditionally
    // ============================================================================

    // Core crypto module (always included)
    const core_imports = &[_]std.Build.Module.Import{};
    const core_mod = b.addModule("zcrypto_core", .{
        .root_source_file = b.path("src/core.zig"),
        .target = target,
        .imports = core_imports,
    });

    // Feature-specific modules
    var feature_imports_buffer: [16]std.Build.Module.Import = undefined;
    var feature_imports_count: usize = 0;

    // TLS module
    if (enable_tls) {
        const tls_mod = b.addModule("zcrypto_tls", .{
            .root_source_file = b.path("src/feature_tls.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "tls", .module = tls_mod };
        feature_imports_count += 1;
    }

    // Post-quantum module
    if (enable_post_quantum) {
        const pq_mod = b.addModule("zcrypto_pq", .{
            .root_source_file = b.path("src/feature_pq.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "post_quantum", .module = pq_mod };
        feature_imports_count += 1;
    }

    // Hardware acceleration module
    if (enable_hardware_accel) {
        const hw_mod = b.addModule("zcrypto_hw", .{
            .root_source_file = b.path("src/feature_hw.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "hardware", .module = hw_mod };
        feature_imports_count += 1;
    }

    // Blockchain module
    if (enable_blockchain) {
        const bc_mod = b.addModule("zcrypto_blockchain", .{
            .root_source_file = b.path("src/feature_blockchain.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "blockchain", .module = bc_mod };
        feature_imports_count += 1;
    }

    // VPN module
    if (enable_vpn) {
        const vpn_mod = b.addModule("zcrypto_vpn", .{
            .root_source_file = b.path("src/feature_vpn.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "vpn", .module = vpn_mod };
        feature_imports_count += 1;
    }

    // WebAssembly module
    if (enable_wasm) {
        const wasm_mod = b.addModule("zcrypto_wasm", .{
            .root_source_file = b.path("src/feature_wasm.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "wasm", .module = wasm_mod };
        feature_imports_count += 1;
    }

    // Enterprise module
    if (enable_enterprise) {
        const ent_mod = b.addModule("zcrypto_enterprise", .{
            .root_source_file = b.path("src/feature_enterprise.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "enterprise", .module = ent_mod };
        feature_imports_count += 1;
    }

    // ZKP module
    if (enable_zkp) {
        const zkp_mod = b.addModule("zcrypto_zkp", .{
            .root_source_file = b.path("src/feature_zkp.zig"),
            .target = target,
            .imports = &.{.{ .name = "zcrypto_core", .module = core_mod }},
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "zkp", .module = zkp_mod };
        feature_imports_count += 1;
    }

    // Async module (requires zsync)
    if (enable_async and zsync_dep != null) {
        const async_mod = b.addModule("zcrypto_async", .{
            .root_source_file = b.path("src/feature_async.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "zcrypto_core", .module = core_mod },
                .{ .name = "zsync", .module = zsync_dep.?.module("zsync") },
            },
        });
        feature_imports_buffer[feature_imports_count] = .{ .name = "async", .module = async_mod };
        feature_imports_count += 1;
    }

    // ============================================================================
    // MAIN ZCRYPTO MODULE - Combines all enabled features
    // ============================================================================

    // Add build options for conditional compilation
    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_tls", enable_tls);
    build_options.addOption(bool, "enable_post_quantum", enable_post_quantum);
    build_options.addOption(bool, "enable_hardware_accel", enable_hardware_accel);
    build_options.addOption(bool, "enable_blockchain", enable_blockchain);
    build_options.addOption(bool, "enable_vpn", enable_vpn);
    build_options.addOption(bool, "enable_wasm", enable_wasm);
    build_options.addOption(bool, "enable_enterprise", enable_enterprise);
    build_options.addOption(bool, "enable_zkp", enable_zkp);
    build_options.addOption(bool, "enable_async", enable_async);

    // Create zcrypto imports array, including build_options
    var zcrypto_imports_buffer: [18]std.Build.Module.Import = undefined;
    var zcrypto_imports_count: usize = 1; // Start with build_options

    // Add build_options first
    zcrypto_imports_buffer[0] = .{ .name = "build_options", .module = build_options.createModule() };

    // Copy feature imports
    for (feature_imports_buffer[0..feature_imports_count], 0..) |import, i| {
        zcrypto_imports_buffer[i + 1] = import;
    }
    zcrypto_imports_count += feature_imports_count;

    // Add zsync if async is enabled
    if (enable_async and zsync_dep != null) {
        zcrypto_imports_buffer[zcrypto_imports_count] = .{ .name = "zsync", .module = zsync_dep.?.module("zsync") };
        zcrypto_imports_count += 1;
    }

    const zcrypto_mod = b.addModule("zcrypto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = zcrypto_imports_buffer[0..zcrypto_imports_count],
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
