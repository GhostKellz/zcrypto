# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2026-04-12

### Changed

- Aligned the package and exported version metadata on `v1.0.1`.
- Tightened the downstream compatibility posture for `/data/projects/zquic` by keeping only real, supportable API polish in `zcrypto` and leaving stale convenience assumptions downstream.
- Replaced the previous custom ML-KEM implementation path with stdlib-backed wrappers so the exposed ML-KEM API is backed by Zig stdlib behavior instead of project-local lattice code.
- Corrected TLS/QUIC HKDF usage so `hkdfExpandLabel` expands the provided secret instead of re-extracting it, and aligned TLS key-schedule extraction with the selected hash family.
- Tightened the secondary `quic_crypto` helper stack so key derivation, nonce handling, header protection, and stored key material are internally consistent instead of depending on stack-local slices or zero-IV behavior.
- Narrowed the experimental post-quantum convenience layer toward the canonical `pq` implementation rather than keeping conflicting local ML-DSA constants and behavior.

### Added

- Added direct `post_quantum` convenience re-exports for `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`, `ML_DSA_44`, `ML_DSA_65`, and `ML_DSA_87`.
- Added a top-level `QuicCrypto` alias to the existing QUIC crypto module surface.
- Added stdlib-backed symmetric helpers for QUIC/TLS header protection use cases:
  - `sym.aes_128_ecb_encrypt`
  - `sym.aes_256_ecb_encrypt`
  - `sym.chacha20_generate_keystream`

### Fixed

- Fixed the `zcrypto.post_quantum.ML_KEM_768` convenience path expected by downstream code so it now resolves to a real implementation.
- Fixed ML-KEM encapsulate/decapsulate agreement through the public post-quantum surface and associated FFI coverage.
- Fixed missing downstream hash compatibility gaps earlier in the cycle by exporting `hash.Sha384`, `hash.Sha384Hash`, `hash.Algorithm`, and `hash.Blake3`.
- Fixed QUIC packet handling so unsupported derived encryption levels no longer silently proceed with uninitialized keys in `quic.zig` and the FFI entrypoints.
- Fixed FFI feature reporting so capability queries now reflect the actual build flags instead of always claiming PQ/ZKP/hardware support.
- Fixed an untested FFI build gap by wiring `src/ffi.zig` into the normal package `test` step and updating the current Zig `0.16.0-dev` locking/build wiring needed for it to compile.
- Fixed TLS/QUIC key derivation labels so QUIC traffic keys derive from `quic key`, `quic iv`, and `quic hp` instead of generic TLS labels.
- Fixed `post_quantum.ML_DSA_65` size mismatches by aligning its private-key and signature sizes with the canonical `pq.zig` values (`4016` / `3309`).
- Fixed `quic_crypto.zig` key ownership bugs where AEAD/header-protection state previously held references to stack-local key buffers.

### Verified

- `zig test src/sym.zig`
- `zig test src/kdf.zig`
- `zig test src/tls.zig`
- `zig test src/quic.zig`
- `zig test src/quic_crypto.zig`
- `zig test src/post_quantum.zig -Dpost-quantum=true -Dexperimental-crypto=true`
- `zig build test --summary all`
- `bash dev/release_check.sh`
- `bash dev/experimental_pq_check.sh`
- `zig build test --summary all` in `/data/projects/zquic`

### Notes

- Remaining `zquic` drift around `Blake3.init(.{})` call shape and the oversized `HardwareCrypto` facade should stay downstream instead of being absorbed into `zcrypto` as fake compatibility.
- `v1.0.1` continues the stable-core posture while improving stdlib-backed correctness on the exported surfaces that are actually supportable.

## [1.0.0] - 2026-04-12

### Added

- Added `zcrypto.build_config` so downstreams can inspect enabled feature state at compile time.
- Added local verification scripts under `dev/`:
  - `dev/release_check.sh`
  - `dev/experimental_pq_check.sh`
  - `dev/smoke_run.sh`
- Added `/data/projects/zquic/tasks/zcrypto_spec.md` to define the `zcrypto v1.0.0` integration contract for `zquic`.
- Added a root `SECURITY.md` with reporting and release-support guidance.

### Changed

- Promoted the package version and public release posture from `v0.9.9` to `v1.0.0`.
- Stabilized the documented core API surface and narrowed the `v1.0.0` contract to modules that are actually verified in this repository.
- Marked post-quantum, blockchain, enterprise, and ZKP feature families as experimental for `v1.0.0`.
- Required `-Dexperimental-crypto=true` to enable those experimental feature families.
- Updated `README.md`, `docs/`, examples, and integration docs to reflect the actual `v1.0.0` build flags, API names, and release policy.
- Updated fetch/install guidance to prefer immutable release tags over `main` tarballs.
- Updated the `zsync` dependency to `v0.7.9`.
- Updated badges in `README.md` to the current project style.

### Fixed

- Fixed Zig `0.16.0-dev` compatibility issues across library and test code, including allocator updates and `ArrayList` initialization changes.
- Fixed feature-gated entrypoints so disabled features no longer break shipped demos, examples, or bench targets.
- Fixed stale docs and examples that referenced removed commands, old module names, or nonexistent example files.
- Fixed `advanced_features` runtime crashes caused by incorrect QUIC packet buffer handling.
- Fixed QUIC packet encryption buffer handling in `src/quic_crypto.zig` and added regression coverage for the reserved-tag-space contract.
- Fixed repository hygiene issues around package paths, generated artifacts, and stale duplicate examples.

### Verified

- `zig build -Doptimize=ReleaseSafe`
- `zig build test`
- `zig build -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dasync=false`
- `bash dev/release_check.sh`
- `bash dev/experimental_pq_check.sh`
- `bash dev/smoke_run.sh`

### Notes

- `v1.0.0` is intentionally a stable-core release.
- Experimental modules remain available for research and iteration, but are not part of the frozen core contract for this release.
