const std = @import("std");
const build_zon = @import("build.zig.zon");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ============================================================================
    // FEATURE FLAGS - Enable/disable optional components for modular builds
    // ============================================================================

    const enable_tls = b.option(bool, "tls", "Enable TLS 1.3 and QUIC support") orelse true;
    const enable_post_quantum = b.option(bool, "post-quantum", "Enable experimental post-quantum cryptography (requires -Dexperimental-crypto=true)") orelse false;
    const enable_hardware_accel = b.option(bool, "hardware-accel", "Enable hardware acceleration (SIMD, AES-NI)") orelse true;
    const enable_blockchain = b.option(bool, "blockchain", "Enable experimental blockchain crypto helpers (requires -Dexperimental-crypto=true)") orelse false;
    const enable_vpn = b.option(bool, "vpn", "Enable VPN data-channel primitives (AEAD tunnel record layer; not a VPN protocol, peer authentication is the caller's job)") orelse true;
    const enable_wasm = b.option(bool, "wasm", "Enable WebAssembly support") orelse true;
    const enable_enterprise = b.option(bool, "enterprise", "Enable experimental enterprise features (requires -Dexperimental-crypto=true)") orelse false;
    const enable_zkp = b.option(bool, "zkp", "Enable experimental zero-knowledge proofs (requires -Dexperimental-crypto=true)") orelse false;
    const enable_async = b.option(bool, "async", "Enable async crypto operations (requires zsync)") orelse false;
    // Off by default because it is the only flag that pulls in native C
    // libraries. A build with -Dtpm=false has no libtss2 dependency at all;
    // with it on, the host must provide tss2-esys/tss2-tctildr/tss2-rc and
    // their headers.
    const enable_tpm = b.option(bool, "tpm", "Build the real TPM 2.0 backend (requires the host TPM2-TSS libraries and headers)") orelse false;
    // Off for the same reason as -Dtpm, with one difference: no PKCS#11
    // library is linked even when this is on. The provider module is opened
    // with dlopen from a path the caller supplies at runtime, so the flag buys
    // the Cryptoki *headers* (p11-kit-1) and nothing else.
    const enable_pkcs11 = b.option(bool, "pkcs11", "Build the real PKCS#11 backend (requires the Cryptoki headers; the provider module itself is loaded at runtime)") orelse false;
    // Off for the same reason as the two above, plus one it does not share:
    // the real backend only exists on macOS. Requesting it for any other
    // target is a configuration error rather than a silently absent backend,
    // because the flag's whole purpose is to say "use real hardware" and no
    // other platform has the hardware to use.
    const enable_secure_enclave = b.option(bool, "secure-enclave", "Build the real Apple Secure Enclave backend (macOS targets only; links Security and CoreFoundation)") orelse false;
    if (enable_secure_enclave and target.result.os.tag != .macos) {
        return error.SecureEnclaveRequiresMacos;
    }

    // ============================================================================
    // SECURITY FLAGS - Control access to experimental/insecure code paths
    // ============================================================================

    const allow_experimental_crypto = b.option(bool, "experimental-crypto", "Allow use of incomplete/placeholder crypto implementations (DANGEROUS: not for production)") orelse false;
    const allow_insecure_options = b.option(bool, "allow-insecure", "Allow insecure options like skip_verify in release builds (DANGEROUS: not for production)") orelse false;

    // Not a feature. Adds one deliberately-broken public declaration so the gate
    // can prove src/api_surface.zig still catches an exported function nothing
    // calls. See the api-surface-control stage in dev/release_check.sh.
    const api_surface_control = b.option(bool, "api-surface-control", "Inject a broken public declaration; the build is REQUIRED to fail (gate self-check only)") orelse false;

    if ((enable_post_quantum or enable_blockchain or enable_enterprise or enable_zkp) and !allow_experimental_crypto) {
        return error.ExperimentalCryptoRequiresOptIn;
    }

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

    // The raw/DER ECDSA signature conversion is shared by the PKCS#11 and
    // Secure Enclave backends — both talk to an API that speaks DER while this
    // library's callers want the raw pair. It is a module rather than a file
    // import because a source file may belong to exactly one module, and a
    // build that binds two of those backends at once would otherwise reach the
    // same file from two module roots and fail to compile.
    const ecdsa_sig_mod = b.createModule(.{
        .root_source_file = b.path("src/hsm/ecdsa_sig.zig"),
        .target = target,
    });

    // The TPM backend is always bound to the module name `tpm_backend`, so
    // `hsm.zig` has one unconditional import and one set of call sites. With
    // `-Dtpm=true` the name resolves to the real ESAPI backend; otherwise to a
    // shim with the same API whose entry points report `BackendNotBuilt`. A
    // conditional `@import` would instead make the flag-off build fail to
    // compile at each call site, leaving that path never type-checked.
    //
    // It is created here, ahead of the feature modules, because `hsm.zig` is
    // reached through the enterprise module as well as through the main module,
    // and both need the name bound.
    //
    // `optimize` is deliberately left unset on the backend module for the same
    // reason it is unset on `zcrypto_mod` below: a dependency module with no
    // optimize mode inherits from whatever compilation roots it.
    const tpm_backend_mod = if (enable_tpm) blk: {
        // Zig 0.17 removed @cImport, so the ESAPI bindings come from a build
        // step. `/usr/include` is stated explicitly because translate-c does
        // not pick up the distribution's system include path on its own —
        // without it the header resolves to "file not found".
        const tss2 = b.addTranslateC(.{
            .root_source_file = b.path("src/hsm/tss2_headers.h"),
            .target = target,
            .optimize = optimize,
        });
        tss2.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
        tss2.linkSystemLibrary("tss2-esys", .{});
        tss2.linkSystemLibrary("tss2-tctildr", .{});
        tss2.linkSystemLibrary("tss2-rc", .{});
        tss2.linkSystemLibrary("tss2-mu", .{});

        break :blk b.createModule(.{
            .root_source_file = b.path("src/hsm/tpm2.zig"),
            .target = target,
            .link_libc = true,
            .imports = &.{
                .{ .name = "tss2", .module = tss2.createModule() },
            },
        });
    } else b.createModule(.{
        .root_source_file = b.path("src/hsm/tpm2_absent.zig"),
        .target = target,
    });

    // The PKCS#11 backend follows the same bind-one-name pattern as the TPM
    // one, and for the same reason: the flag-off path stays compiled and
    // testable instead of turning into a compile error at every call site.
    //
    // Unlike the TPM backend it links nothing. A Cryptoki provider is a
    // caller-supplied `.so` opened with dlopen at runtime, so the only thing
    // the flag adds is the translated header. `link_libc` is still required —
    // `std.DynLib` is dlopen/dlsym when libc is linked, and the ELF loader it
    // falls back to otherwise cannot load a module with its own dependencies.
    const pkcs11_backend_mod = if (enable_pkcs11) blk: {
        const cryptoki = b.addTranslateC(.{
            .root_source_file = b.path("src/hsm/pkcs11_headers.h"),
            .target = target,
            .optimize = optimize,
        });
        // p11-kit installs its headers under a versioned prefix, so the
        // `<p11-kit/pkcs11.h>` spelling only resolves with this on the path.
        // `/usr/include` is stated for the same reason as in the TPM branch.
        cryptoki.addSystemIncludePath(.{ .cwd_relative = "/usr/include/p11-kit-1" });
        cryptoki.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });

        break :blk b.createModule(.{
            .root_source_file = b.path("src/hsm/pkcs11.zig"),
            .target = target,
            .link_libc = true,
            .imports = &.{
                .{ .name = "pkcs11", .module = cryptoki.createModule() },
                .{ .name = "ecdsa_sig", .module = ecdsa_sig_mod },
            },
        });
    } else b.createModule(.{
        .root_source_file = b.path("src/hsm/pkcs11_absent.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "ecdsa_sig", .module = ecdsa_sig_mod },
        },
    });

    // The Secure Enclave backend follows the same bind-one-name pattern again.
    //
    // Two things differ from the other two. The header deliberately omits the
    // `<Security/Security.h>` umbrella — see the comment in
    // `security_headers.h`; it reaches `<xpc/xpc.h>`, which translate-c cannot
    // process. And no include path is stated: `translate-c` locates the macOS
    // SDK itself when the target is macOS, whereas `-isysroot` is not among
    // the flags it accepts.
    const secure_enclave_backend_mod = if (enable_secure_enclave) blk: {
        const security = b.addTranslateC(.{
            .root_source_file = b.path("src/hsm/security_headers.h"),
            .target = target,
            .optimize = optimize,
        });
        // The frameworks are linked on the module rather than on the translate
        // step: `translate-c` only ever reads headers, and `TranslateC` has no
        // `linkFramework`. Whatever roots this module needs the actual
        // `SecKey*`/`CF*` symbols, and that is a link-time concern.
        const mod = b.createModule(.{
            .root_source_file = b.path("src/hsm/secure_enclave.zig"),
            .target = target,
            .link_libc = true,
            .imports = &.{
                .{ .name = "security", .module = security.createModule() },
                .{ .name = "ecdsa_sig", .module = ecdsa_sig_mod },
            },
        });
        mod.linkFramework("CoreFoundation", .{});
        mod.linkFramework("Security", .{});
        break :blk mod;
    } else b.createModule(.{
        .root_source_file = b.path("src/hsm/secure_enclave_absent.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "ecdsa_sig", .module = ecdsa_sig_mod },
        },
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
            // `hsm.zig` sits under this module and imports the backends, so
            // the names have to be bound here too, not only on `zcrypto_mod`.
            .imports = &.{
                .{ .name = "zcrypto_core", .module = core_mod },
                .{ .name = "tpm_backend", .module = tpm_backend_mod },
                .{ .name = "pkcs11_backend", .module = pkcs11_backend_mod },
                .{ .name = "secure_enclave_backend", .module = secure_enclave_backend_mod },
            },
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
    build_options.addOption([]const u8, "version", build_zon.version);
    build_options.addOption(bool, "enable_tls", enable_tls);
    build_options.addOption(bool, "enable_post_quantum", enable_post_quantum);
    build_options.addOption(bool, "enable_hardware_accel", enable_hardware_accel);
    build_options.addOption(bool, "enable_blockchain", enable_blockchain);
    build_options.addOption(bool, "enable_vpn", enable_vpn);
    build_options.addOption(bool, "enable_wasm", enable_wasm);
    build_options.addOption(bool, "enable_enterprise", enable_enterprise);
    build_options.addOption(bool, "enable_zkp", enable_zkp);
    build_options.addOption(bool, "enable_async", enable_async);
    build_options.addOption(bool, "enable_tpm", enable_tpm);
    build_options.addOption(bool, "enable_pkcs11", enable_pkcs11);
    build_options.addOption(bool, "enable_secure_enclave", enable_secure_enclave);

    // Security options
    build_options.addOption(bool, "allow_experimental_crypto", allow_experimental_crypto);
    build_options.addOption(bool, "allow_insecure_options", allow_insecure_options);
    build_options.addOption(bool, "api_surface_control", api_surface_control);

    // Create zcrypto imports array, including build_options
    var zcrypto_imports_buffer: [20]std.Build.Module.Import = undefined;
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

    zcrypto_imports_buffer[zcrypto_imports_count] = .{ .name = "tpm_backend", .module = tpm_backend_mod };
    zcrypto_imports_count += 1;

    zcrypto_imports_buffer[zcrypto_imports_count] = .{ .name = "pkcs11_backend", .module = pkcs11_backend_mod };
    zcrypto_imports_count += 1;

    zcrypto_imports_buffer[zcrypto_imports_count] = .{ .name = "secure_enclave_backend", .module = secure_enclave_backend_mod };
    zcrypto_imports_count += 1;

    const zcrypto_imports = zcrypto_imports_buffer[0..zcrypto_imports_count];

    // The exported module deliberately leaves `optimize` unset. A dependency
    // module with no optimize mode inherits the one of whatever compilation
    // roots it, which is how a downstream `b.dependency("zcrypto", .{ .optimize
    // = ... })` gets a library built in its own mode. Pinning it here would
    // silently give every consumer a Debug zcrypto. The same reasoning applies
    // to `core_mod` and the feature modules above.
    const zcrypto_mod = b.addModule("zcrypto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = zcrypto_imports,
    });

    // Probes for the WASM gate, built only when the target is one.
    //
    // These are not examples and not tests. `zig build test -Dtarget=wasm32-wasi`
    // runs the library's own tests under a host that behaves, which cannot say
    // anything about a host whose CSPRNG is absent or broken -- a test binary
    // that fails to instantiate is indistinguishable from a build that is
    // simply broken. Each probe is therefore a single-purpose program whose
    // exit status has one meaning, so dev/wasm/check.sh can state the expected
    // outcome per host condition and have the mismatch be the failure.
    //
    // Gated on the target because they exist to be run by dev/wasm/run.mjs
    // under Node's WASI. Built for the host they would be ordinary executables
    // installed into zig-out/bin that nothing runs.
    if (target.result.cpu.arch.isWasm()) {
        for ([_][]const u8{ "entropy_probe", "deterministic_probe" }) |name| {
            const probe = b.addExecutable(.{
                .name = b.fmt("wasm-{s}", .{name}),
                .root_module = b.createModule(.{
                    .root_source_file = b.path(b.fmt("dev/wasm/{s}.zig", .{name})),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zcrypto", .module = zcrypto_mod },
                    },
                }),
            });
            b.installArtifact(probe);
        }
    }

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

    const core_example = b.addExecutable(.{
        .name = "core-stable-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/core_stable.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    b.installArtifact(core_example);

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
        run_zsync_cmd.addPassthruArgs();
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
    run_cmd.addPassthruArgs();
    run_step.dependOn(&run_cmd.step);

    const run_core_step = b.step("run-core", "Run the stable core example");
    const run_core_cmd = b.addRunArtifact(core_example);
    run_core_cmd.step.dependOn(b.getInstallStep());
    run_core_cmd.addPassthruArgs();
    run_core_step.dependOn(&run_core_cmd.step);

    // Advanced features example run step
    const run_advanced_step = b.step("run-advanced", "Run the advanced features example");
    const run_advanced_cmd = b.addRunArtifact(advanced_example);
    run_advanced_cmd.step.dependOn(b.getInstallStep());
    run_advanced_cmd.addPassthruArgs();
    run_advanced_step.dependOn(&run_advanced_cmd.step);

    // Benchmark step
    const bench_step = b.step("bench", "Run performance benchmarks");
    const bench_cmd = b.addRunArtifact(bench);
    bench_cmd.step.dependOn(b.getInstallStep());
    bench_cmd.addPassthruArgs();
    bench_step.dependOn(&bench_cmd.step);

    // Test steps
    //
    // Test roots need their own module with an explicit optimize mode. Using
    // the exported `zcrypto_mod` directly makes it the *root* of the test
    // compilation, and a root module with no optimize mode falls back to Debug
    // — so `zig build test -Doptimize=ReleaseSafe` silently ran the library
    // tests in Debug. Building a separate root over the same sources keeps the
    // exported module free to inherit downstream while the tests honour the
    // mode that was actually requested.
    const zcrypto_test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = zcrypto_imports,
    });

    const mod_tests = b.addTest(.{
        .name = "zcrypto-lib-test",
        .root_module = zcrypto_test_mod,
    });
    const run_mod_tests = addTestRun(b, mod_tests);

    const exe_tests = b.addTest(.{
        .name = "zcrypto-demo-test",
        .root_module = exe.root_module,
    });
    const run_exe_tests = addTestRun(b, exe_tests);

    var ffi_imports_buffer: [5]std.Build.Module.Import = undefined;
    var ffi_imports_count: usize = 4;
    ffi_imports_buffer[0] = .{ .name = "build_options", .module = build_options.createModule() };
    // src/ffi.zig reaches hsm.zig through root.zig, so this module needs the
    // backend names bound even though no FFI export calls a provider directly.
    ffi_imports_buffer[1] = .{ .name = "tpm_backend", .module = tpm_backend_mod };
    ffi_imports_buffer[2] = .{ .name = "pkcs11_backend", .module = pkcs11_backend_mod };
    ffi_imports_buffer[3] = .{ .name = "secure_enclave_backend", .module = secure_enclave_backend_mod };
    if (enable_async and zsync_dep != null) {
        ffi_imports_buffer[ffi_imports_count] = .{ .name = "zsync", .module = zsync_dep.?.module("zsync") };
        ffi_imports_count += 1;
    }

    const ffi_mod = b.createModule(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
        .imports = ffi_imports_buffer[0..ffi_imports_count],
        // Most distributions build executables as PIE by default, so a
        // non-PIC archive is not linkable by an ordinary consumer: gcc on
        // Ubuntu rejects it with "relocation R_X86_64_32S ... can not be used
        // when making a PIE object". The archive is meant to be linked by
        // third parties, so it has to be position independent.
        .pic = true,
    });

    // The public header carries a second, hand-maintained copy of the error
    // constants. Nothing forced the two copies to agree: the C consumer only
    // compares a returned code against a header constant, so it can only catch a
    // drifted value for a code it can actually provoke, and the internal-failure
    // codes are not reachable from a caller passing well-formed input. Importing
    // the header as data lets a test read it directly and check every constant,
    // including the unreachable ones.
    ffi_mod.addAnonymousImport("zcrypto_header", .{
        .root_source_file = b.path("include/zcrypto.h"),
    });

    const ffi_tests = b.addTest(.{
        .name = "zcrypto-ffi-test",
        .root_module = ffi_mod,
    });
    const run_ffi_tests = addTestRun(b, ffi_tests);

    // The C ABI surface only exists if something links it. Until this artifact
    // was added, the `export fn` declarations in src/ffi.zig were compiled by
    // the test build and then discarded: no static or shared object carried
    // them, so no C caller could reach them and no header could be checked
    // against them. A C ABI nothing links is an unverified claim.
    const ffi_lib = b.addLibrary(.{
        .name = "zcrypto",
        .linkage = .static,
        .root_module = ffi_mod,
    });
    ffi_lib.installHeader(b.path("include/zcrypto.h"), "zcrypto.h");
    b.installArtifact(ffi_lib);

    // The C consumer is compiled and executed, not syntax-checked. It links the
    // real artifact through the public header, so a signature that drifts from
    // the header fails the build rather than silently changing the ABI.
    const ffi_consumer_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    // -Werror with -Wconversion is deliberate. The ABI is uint32_t lengths and
    // a C caller on a 64-bit host reaches it from size_t; an implicit narrowing
    // is exactly the mistake this harness exists to catch, so it must not be
    // possible to write one here by accident.
    ffi_consumer_mod.addCSourceFile(.{
        .file = b.path("tests/ffi/consumer.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wconversion" },
    });
    ffi_consumer_mod.addIncludePath(b.path("include"));
    ffi_consumer_mod.linkLibrary(ffi_lib);

    const ffi_consumer = b.addExecutable(.{
        .name = "zcrypto-ffi-consumer",
        .root_module = ffi_consumer_mod,
    });
    // Deliberately not installed. This is the ABI test harness, and installing
    // it put a test binary into the release prefix alongside the library a
    // packager would ship. Nothing referenced the installed copy: the
    // `ffi-consumer` step runs the build artifact directly, and the release
    // gate consumes only `lib/libzcrypto.a` and `include/zcrypto.h`.

    const run_ffi_consumer = b.addRunArtifact(ffi_consumer);
    const ffi_consumer_step = b.step("ffi-consumer", "Build and run the C consumer against the FFI library");
    ffi_consumer_step.dependOn(&run_ffi_consumer.step);

    const stable_api_guard_tests = b.addTest(.{
        .name = "zcrypto-stable-api-guard-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/stable_api_guard.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    const run_stable_api_guard_tests = addTestRun(b, stable_api_guard_tests);

    const feature_surface_tests = b.addTest(.{
        .name = "zcrypto-feature-surface-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/feature_surface.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    const run_feature_surface_tests = addTestRun(b, feature_surface_tests);

    // The insecure-option guard's refusing branch, which only exists in a
    // release build.
    //
    // An executable rather than a test artifact, because the branch logs by
    // design and Zig's test runner owns `std_options` -- a test cannot install
    // a sink for the diagnostic, and the runner fails any test that logs an
    // error. As its own root module this program installs the sink and asserts
    // the message.
    //
    // The optimize mode is pinned rather than inherited: under a plain `zig
    // build test` the guard permits everything, so following `-Doptimize` would
    // leave the branch asserted in some invocations and silently skipped in the
    // rest -- and "skipped" is indistinguishable from "passed" in a summary.
    // ReleaseSafe rather than ReleaseFast so the program's own assertions keep
    // their safety checks. `zcrypto_mod` leaves `optimize` unset, so importing
    // it here compiles `src/security.zig` in this root's mode, which is what
    // puts `isReleaseBuild()` on the refusing side.
    const insecure_option_guard = b.addExecutable(.{
        .name = "zcrypto-insecure-option-guard",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/insecure_option_guard.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
            },
        }),
    });
    const run_insecure_option_guard = b.addRunArtifact(insecure_option_guard);

    // Whether the built artifact can run on this machine at all. Under a cross
    // `-Dtarget` -- the wasm gate, say -- it cannot, and the build runner's own
    // skip only applies to run steps whose stdio it has taken over, which would
    // mean giving up the guard's diagnostics on the runs that matter.
    //
    // Compiling it unconditionally and running it only where it can run is the
    // honest split. What it asserts is a build-configuration policy --
    // `builtin.mode != .debug` and the `allow_insecure_options` option -- which
    // does not vary by target, and every native stage of the gate executes it;
    // a cross build failing here would only mean "no emulator on this host".
    // Pinning the artifact to the host instead is not available: `zcrypto_mod`
    // carries `-Dtarget`, so a host root importing it is a mixed-target
    // compilation that does not link.
    const guard_runs_on_host = target.result.os.tag == b.graph.host.result.os.tag and
        target.result.cpu.arch == b.graph.host.result.cpu.arch;

    // Known-answer tests against published vectors. `std.crypto` picks its AES,
    // ChaCha20 and SHA-256 implementations at comptime from the build target,
    // so this suite is meant to be run more than once, under different `-Dcpu`
    // values, to check each selected implementation against the same published
    // answers.
    //
    // `expect-aes-hardware` is what stops that pair of runs from being
    // decorative. Without it, a stage that meant to build for a generic CPU but
    // did not would still pass, and the run would claim to have covered a
    // backend it never compiled. Omitted, nothing is asserted about the
    // backend, so a plain `zig build test` is unaffected.
    const expect_aes_hardware = b.option(
        bool,
        "expect-aes-hardware",
        "Fail the known-answer run unless std.crypto's AES backend matches (true: must be hardware-backed, false: must be software). Omitted: not checked.",
    );
    const kat_options = b.addOptions();
    kat_options.addOption(?bool, "expect_aes_hardware", expect_aes_hardware);

    const kat_tests = b.addTest(.{
        .name = "zcrypto-known-answer-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/known_answer_vectors.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_mod },
                .{ .name = "kat_options", .module = kat_options.createModule() },
            },
        }),
    });
    const run_kat_tests = addTestRun(b, kat_tests);
    const kat_step = b.step("kat", "Check published known-answer vectors against this build target");
    kat_step.dependOn(&run_kat_tests.step);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_kat_tests.step);
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_ffi_tests.step);
    test_step.dependOn(&run_stable_api_guard_tests.step);
    test_step.dependOn(&run_feature_surface_tests.step);
    test_step.dependOn(if (guard_runs_on_host)
        &run_insecure_option_guard.step
    else
        &insecure_option_guard.step);

    // The accelerated backends only exist in the build when the flag is on, so
    // the parity suite is added rather than comptime-skipped: a skipped test
    // that never compiles is indistinguishable from one that does not exist.
    if (enable_hardware_accel) {
        const hardware_parity_tests = b.addTest(.{
            .name = "zcrypto-hardware-parity-test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/hardware_parity.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "zcrypto", .module = zcrypto_mod },
                },
            }),
        });
        const run_hardware_parity_tests = addTestRun(b, hardware_parity_tests);
        test_step.dependOn(&run_hardware_parity_tests.step);

        const hardware_parity_step = b.step("hardware-parity", "Check the HardwareCrypto wrappers against the std.crypto primitives they wrap");
        hardware_parity_step.dependOn(&run_hardware_parity_tests.step);
    }

    // The TPM backend is only compiled when its native dependency is opted
    // into. It is wired as a real compilation rather than a comptime-skipped
    // stub: a backend nothing builds is an unverified claim, which is what the
    // previous "hardware" provider amounted to.
    if (enable_tpm) {
        const tpm_tests = b.addTest(.{
            .name = "zcrypto-tpm-integration-test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/tpm_integration.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    // The same module `hsm.zig` uses, so the suite exercises
                    // the shipped backend rather than a second copy compiled
                    // with its own settings.
                    .{ .name = "tpm2", .module = tpm_backend_mod },
                    // The provider layer is covered against the same live
                    // device. Without this the only tests of `TPMProvider`
                    // would be the ones where no device is present, which
                    // proves the refusal path and nothing about the
                    // operations it claims to support.
                    .{ .name = "hsm", .module = b.createModule(.{
                        .root_source_file = b.path("src/hsm.zig"),
                        .target = target,
                        .optimize = optimize,
                        .imports = &.{
                            .{ .name = "tpm_backend", .module = tpm_backend_mod },
                            .{ .name = "pkcs11_backend", .module = pkcs11_backend_mod },
                            .{ .name = "secure_enclave_backend", .module = secure_enclave_backend_mod },
                        },
                    }) },
                },
            }),
        });
        const run_tpm_tests = addTestRun(b, tpm_tests);
        // The suite talks to whatever ZCRYPTO_TPM_TCTI names and skips when it
        // is unset, so the result must never be served from a previous run's
        // cache: the environment, not the sources, decides what it does.
        run_tpm_tests.has_side_effects = true;

        test_step.dependOn(&run_tpm_tests.step);

        const tpm_step = b.step("tpm-integration", "Run TPM 2.0 integration tests against ZCRYPTO_TPM_TCTI");
        tpm_step.dependOn(&run_tpm_tests.step);
    } else {
        // Zig only runs the tests in a compilation's root module, so the shim's
        // own test never executes while it is merely an imported dependency.
        // Rooting a test at it here is what makes that test a result rather
        // than an unrun claim.
        const absent_tests = b.addTest(.{
            .name = "zcrypto-tpm-absent-test",
            .root_module = testRootOver(b, tpm_backend_mod, optimize),
        });
        test_step.dependOn(&addTestRun(b, absent_tests).step);
    }

    // The raw/DER ECDSA signature conversion is a dependency of four backends
    // and the root of none of them, and a compilation only runs the tests in
    // its own module. Rooting the encoder here is what makes its vectors a
    // result rather than an unrun claim, in every configuration. It touches no
    // Cryptoki or Security.framework type, so it needs neither flag.
    const ecdsa_sig_tests = b.addTest(.{
        .name = "zcrypto-ecdsa-sig-test",
        .root_module = testRootOver(b, ecdsa_sig_mod, optimize),
    });
    test_step.dependOn(&addTestRun(b, ecdsa_sig_tests).step);

    if (enable_pkcs11) {
        const pkcs11_tests = b.addTest(.{
            .name = "zcrypto-pkcs11-integration-test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/pkcs11_integration.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    // The same module `hsm.zig` uses, so the suite exercises
                    // the shipped backend rather than a second copy.
                    .{ .name = "pkcs11", .module = pkcs11_backend_mod },
                    // And the provider layer over it, against the same live
                    // token. Without this the only tests of `PKCS11Provider`
                    // would be the ones where no module is configured, which
                    // proves the refusal path and nothing about the operations
                    // it claims to support.
                    .{ .name = "hsm", .module = b.createModule(.{
                        .root_source_file = b.path("src/hsm.zig"),
                        .target = target,
                        .optimize = optimize,
                        .imports = &.{
                            .{ .name = "tpm_backend", .module = tpm_backend_mod },
                            .{ .name = "pkcs11_backend", .module = pkcs11_backend_mod },
                            .{ .name = "secure_enclave_backend", .module = secure_enclave_backend_mod },
                        },
                    }) },
                },
            }),
        });
        const run_pkcs11_tests = addTestRun(b, pkcs11_tests);
        // What this suite does is decided by ZCRYPTO_PKCS11_MODULE and the
        // token behind it, not by the sources, so a cached result from a
        // previous run would be a lie about a different environment.
        run_pkcs11_tests.has_side_effects = true;

        test_step.dependOn(&run_pkcs11_tests.step);

        const pkcs11_step = b.step("pkcs11-integration", "Run PKCS#11 integration tests against ZCRYPTO_PKCS11_MODULE");
        pkcs11_step.dependOn(&run_pkcs11_tests.step);

        // The backend's own tests — the ones asserting Cryptoki's ABI widths
        // on this target — only run if something roots the module. The
        // integration suite imports it by name, which does not.
        const pkcs11_unit_tests = b.addTest(.{
            .name = "zcrypto-pkcs11-unit-test",
            .root_module = testRootOver(b, pkcs11_backend_mod, optimize),
        });
        test_step.dependOn(&addTestRun(b, pkcs11_unit_tests).step);
    } else {
        const absent_tests = b.addTest(.{
            .name = "zcrypto-pkcs11-absent-test",
            .root_module = testRootOver(b, pkcs11_backend_mod, optimize),
        });
        test_step.dependOn(&addTestRun(b, absent_tests).step);
    }

    // Whichever Secure Enclave backend is bound, root it so its own tests run.
    // For the real one those are the residency-check tests, and they are the
    // reason this is not conditional: they are the only part of the backend
    // that can be proven on a Mac without an enclave, which is the only kind
    // of Mac this project has.
    const secure_enclave_test_root = testRootOver(b, secure_enclave_backend_mod, optimize);
    if (enable_secure_enclave) {
        // `testRootOver` mirrors the module's source and imports, which is
        // everything the other two backends need. This one also links two
        // frameworks, and linkage is not part of a module's import table — so
        // it has to be restated here or the test root fails to resolve
        // `SecKey*`/`CF*` at link time.
        secure_enclave_test_root.linkFramework("CoreFoundation", .{});
        secure_enclave_test_root.linkFramework("Security", .{});
    }
    const secure_enclave_tests = b.addTest(.{
        .name = if (enable_secure_enclave)
            "zcrypto-secure-enclave-test"
        else
            "zcrypto-secure-enclave-absent-test",
        .root_module = secure_enclave_test_root,
    });
    const run_secure_enclave_tests = addTestRun(b, secure_enclave_tests);
    // One of these tests asks the host whether it has an enclave, so the
    // machine and not the sources decides what it proves. A cached result
    // would report the last host's answer on this one — including reporting a
    // pass earned by refusal as though the key path had been exercised.
    run_secure_enclave_tests.has_side_effects = enable_secure_enclave;
    test_step.dependOn(&run_secure_enclave_tests.step);
}

/// Run a test binary, routing through a WASM runtime when the host cannot
/// execute it directly.
///
/// `addRunArtifact` spawns the artifact as a host process. For a wasm32 target
/// that fails with "unable to spawn foreign binary", so `zig build test
/// -Dtarget=wasm32-wasi` compiled every test root and ran none of them. The
/// build still went red, which is why this was not mistaken for coverage --
/// but there was no way to *get* coverage, and so the library's behaviour on
/// wasm32 had never been observed at all.
///
/// Node's WASI is used rather than `-fwasmtime` because the entropy contract
/// checks in dev/wasm/check.sh need to substitute and remove the `random_get`
/// host import, which means driving instantiation directly. Using the same
/// runner for both keeps the gate from proving its properties against a
/// different runtime than the one the tests run in.
fn addTestRun(b: *std.Build, tests: *std.Build.Step.Compile) *std.Build.Step.Run {
    if (!tests.rootModuleTarget().cpu.arch.isWasm()) return b.addRunArtifact(tests);

    const run = b.addSystemCommand(&.{ "node", "dev/wasm/run.mjs", "--expect=ok" });
    run.addPrefixedFileArg("--module=", tests.getEmittedBin());
    return run;
}

/// Build a test root over the same sources as `mod`, pinned to `optimize`.
///
/// The backend modules deliberately leave `optimize` unset so they inherit from
/// whatever roots them (see the comment above `tpm_backend_mod`). That is right
/// for a dependency and wrong for a test: `addTest` makes the module it is
/// given the *root* of that compilation, and a root with no optimize mode falls
/// back to Debug — so `zig build test -Doptimize=ReleaseSafe` compiled these
/// backends in Debug whatever was asked for. It is the same trap already
/// documented for `zcrypto_test_mod`, and the same answer: a separate root, so
/// the shared module stays free to inherit.
///
/// Mirrored from the module's own fields rather than by restating its source
/// path and imports, because a restatement is a copy that can drift from what
/// it claims to mirror — and the drift would be silent, since both would still
/// compile.
fn testRootOver(
    b: *std.Build,
    mod: *std.Build.Module,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const root = b.createModule(.{
        .root_source_file = mod.root_source_file,
        .target = mod.resolved_target,
        .optimize = optimize,
        .link_libc = mod.link_libc,
    });
    // Imports are shared by reference, which is what keeps them dependencies:
    // they carry no optimize mode of their own and so inherit this root's.
    var it = mod.import_table.iterator();
    while (it.next()) |entry| root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    return root;
}
