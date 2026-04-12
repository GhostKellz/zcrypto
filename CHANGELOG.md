# Changelog

All notable changes to this project will be documented in this file.

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
