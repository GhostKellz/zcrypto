# zcrypto v1.0.0 API Reference

This document describes the current `zcrypto` API surface at a high level.

For the stable `v1.0.0` surface, prefer `core.md`.

## Stable Core

These modules are the intended stable surface for `v1.0.0`:

- `zcrypto.hash`
- `zcrypto.auth`
- `zcrypto.sym`
- `zcrypto.asym`
- `zcrypto.kdf`
- `zcrypto.rand`
- `zcrypto.util`
- `zcrypto.batch`
- `zcrypto.kex`
- `zcrypto.blake3`
- `zcrypto.merkle`
- `zcrypto.timing`
- `zcrypto.arena`
- `zcrypto.quic_crypto`
- `zcrypto.quic`
- `zcrypto.key_rotation`

## Feature-Gated Modules

- `zcrypto.tls`
- `zcrypto.hardware`
- `zcrypto.async_crypto`
- `zcrypto.vpn_crypto`
- `zcrypto.wasm_crypto`

These modules are available only when their corresponding build flags are enabled.

## Experimental Modules

The following feature families are available for research and iteration, but they are not the stable core contract for `v1.0.0`.

- `zcrypto.post_quantum`
- `zcrypto.pq`
- `zcrypto.blockchain_crypto`
- `zcrypto.formal`
- `zcrypto.zkp`

These require explicit build-time opt-in with `-Dexperimental-crypto=true` in addition to their feature flags.

## Build-Aware API

The root module exposes build-time feature state through `zcrypto.build_config`.

Useful fields include:

- `zcrypto.build_config.tls_enabled`
- `zcrypto.build_config.post_quantum_enabled`
- `zcrypto.build_config.hardware_accel_enabled`
- `zcrypto.build_config.async_enabled`
- `zcrypto.build_config.experimental_crypto_enabled`

## Verification

Local release verification scripts live in `dev/`:

```bash
bash dev/release_check.sh
bash dev/experimental_pq_check.sh
```

## Notes

- Prefer the examples in `src/main.zig`, `examples/advanced_features.zig`, and `examples/zsync_crypto_example.zig` over older ad hoc snippets.
- If a module is experimental, treat its API as subject to change until a later release explicitly promotes it.
