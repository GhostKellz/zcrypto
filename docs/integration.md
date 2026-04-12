# Integration Guide

This guide covers the supported ways to integrate `zcrypto v1.0.0` into another Zig project.

For non-Zig language bindings, use the current FFI surface only after verifying the bindings you need actually exist in the release you are consuming.

## Zig Projects

### Fetch the release

```bash
zig fetch --save https://github.com/ghostkellz/zcrypto/archive/refs/tags/v1.0.0.tar.gz
```

### Add the dependency

```zig
const zcrypto = b.lazyDependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
    .tls = true,
    .@"hardware-accel" = true,
    .@"async" = false,
    .@"post-quantum" = false,
    .blockchain = false,
    .enterprise = false,
    .zkp = false,
});

exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
```

## Stable Integration Surface

Prefer these modules for stable `v1.0.0` integrations:

- `zcrypto.hash`
- `zcrypto.sym`
- `zcrypto.asym`
- `zcrypto.kdf`
- `zcrypto.rand`
- `zcrypto.util`
- `zcrypto.kex`
- `zcrypto.quic_crypto`
- `zcrypto.quic`

## Feature-Gated Integrations

- `zcrypto.tls` requires `-Dtls=true`
- `zcrypto.hardware` requires `-Dhardware-accel=true`
- `zcrypto.async_crypto` requires `-Dasync=true`

## Experimental Feature Policy

The following feature families are available, but are not part of the stable core contract for `v1.0.0`:

- `post-quantum`
- `blockchain`
- `enterprise`
- `zkp`

To enable them, set both the feature flag and:

```bash
-Dexperimental-crypto=true
```

Example experimental build:

```bash
zig build -Dpost-quantum=true -Dexperimental-crypto=true
```

## Local Verification

Use the repository scripts before cutting or consuming a release:

```bash
bash dev/release_check.sh
bash dev/experimental_pq_check.sh
```

## Notes

- Prefer release tags over `main` tarballs for reproducibility.
- If you depend on experimental modules, expect more churn than the stable core API.
