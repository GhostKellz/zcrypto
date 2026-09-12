# Changelog

All notable changes to this project will be documented in this file.

## [1.0.7] - 2026-09-11

Consumer-facing upgrade notes are in
[`docs/migration/v1.0.7.md`](docs/migration/v1.0.7.md). Short version: the C ABI
is unchanged, and the only break on the stable Zig core is two removed
wall-clock helpers.

The theme of this release is removing code that reported success without doing
the work. Several modules that returned plausible values now return errors
instead. Each is listed below with what it actually did, because "improved" is
not an accurate description of deleting a signature verifier that answered
`true`.

### Added

- **Real hardware-backed key providers.** `zcrypto.hsm` is now a root export and
  carries three implemented backends, each opt-in and each with a separate shim
  that reports `BackendNotBuilt` when the flag is off:
  - `-Dtpm=true` — TPM 2.0 over TPM2-TSS/ESAPI (`src/hsm/tpm2.zig`): random,
    PCR read, key create/load/export/sign/flush, quote against a real
    attestation key, and seal/unseal.
  - `-Dpkcs11=true` — Cryptoki tokens (`src/hsm/pkcs11.zig`): caller-configured
    module load, function table, slot and mechanism enumeration, session
    login, EC key-pair generation, ECDSA signing, token AES-GCM, object
    destroy. No default module path, because a default silently selects a
    different token per host.
  - `-Dsecure-enclave=true` — Apple Secure Enclave via Security.framework
    (`src/hsm/secure_enclave.zig`): P-256 only, signing or ECDH per key, public
    key export only. The private scalar has no representation in the module.
    macOS targets only; the flag is refused at configure time elsewhere.
- **TPM sealing with caller auth and PCR policy.** `TPMProvider.sealWithPolicy`
  and `unsealWithPolicy` take an optional auth value and an optional
  `PcrPolicy`. Both run a session salted to the storage parent with AES-128-CFB
  and `DECRYPT|ENCRYPT`, so `TPM2_Create`'s `inSensitive` and `TPM2_Unseal`'s
  `outData` are parameter-encrypted on the bus. `unsealWithPolicy` selects the
  session kind from the blob's own `authPolicy` rather than from the caller's
  options, so a caller who misremembers how a blob was made gets a TPM refusal
  instead of a wrong answer. Plain `seal`/`unseal` are unchanged wrappers.
  `HSMError.DeviceLockedOut` is new, for the dictionary-attack lockout that
  repeated bad auth values produce.
- **Public API surface is now compiled.** `src/api_surface.zig` references every
  public declaration recursively and is built by the release gate. Zig
  type-checks a function where it is referenced, not where it is defined, so a
  `pub fn` no test calls was never compiled and shipped broken with the suite
  green. This found 18 such entry points, including `WasmCrypto.hkdf` (wrong
  arity, salt and IKM transposed) and `security.isReleaseBuild` — the guard
  behind `insecure_skip_verify` — which still compared against the pre-rename
  `.Debug` tag. `std.testing.refAllDecls` reaches none of the 18: it is shallow
  and does not descend into nested types.
- `util.Instant`, `util.getMonotonic` and `util.getMonotonicOrError`: a
  monotonic clock, distinct in type from `Timestamp` so the two cannot be mixed
  silently. `Instant.since` returns `error.ClockWentBackwards` rather than
  saturating.
- `zcrypto.build_info` (resolved inside the zcrypto module, so a consumer can
  prove its optimize mode and target actually reached the dependency) and
  `zcrypto.api_surface_control`.
- `include/zcrypto.h` is now part of `.paths`, so the C header ships with the
  package. `tests/ffi/consumer.c` is a C harness run in Debug, ReleaseSafe and
  ReleaseFast, and the `ffi-header-agreement` gate stage keeps the header and
  `src/ffi.zig` in agreement by construction rather than by inspection.
- Published known-answer vectors (`tests/known_answer_vectors.zig`) run against
  both a generic CPU target and the host feature set, so a generic-CPU
  deployment is covered by its own vectors rather than by the host's.
- Local test harnesses that provision their own endpoint:
  `dev/tpm_swtpm.sh` (swtpm simulator), `dev/pkcs11_softoken.sh` (NSS
  softoken), `dev/wasm/check.sh` (real wasm32-wasi execution),
  `dev/orphan_check.sh`, and `dev/platform_check.sh` / `.ps1` /
  `platform_matrix.sh`.
- `docs/platform-support.md` — what the library has been built and run on
  natively, per host, including the stages that did *not* run and why.
- `tests/consumer/` — an external package that consumes zcrypto through
  `build.zig.zon` and asserts the requested target and optimize mode actually
  reach the dependency, with `-Dpin-dependency-debug=true` as the control that
  must fail.

### Changed

- Updated the `zsync` dependency from `v0.8.4` to `v0.8.6`.
- Raised `minimum_zig_version` to `0.17.0-dev.2085+5e36170b5`, matching the
  toolchain used for this release pass on all four hosts.
- `util.secureZero` and `timing.secureZero` take `[]volatile u8`. Source
  compatible; the qualifier moves the "this store must not be optimised out"
  guarantee into the type.
- `zcrypto.hsm` moved from `zcrypto.formal.hsm` behind `-Denterprise=true` to a
  root export. The gate existed to keep placeholder crypto out of a default
  build, and a consequence of it was that **none of the provider layer's own
  tests ran in a default `zig build test`** — which is why fabricated key
  handles survived as long as they did. Default test count moved 605 → 648 when
  the export was added.
- `HSMCapabilities` is a plain `struct`, not a `packed struct`, and its fields
  changed. `has_hardware_rng` and `has_hardware_backed_keys` require
  `backing == .hardware` *and* the operation, so a TPM simulator or a software
  token cannot set them however well they answer.
- Unreferenced sources moved from `src/` to `attic/`: the `protocols/` tree
  (noise, signal, mls, dht, gossip), `zkp/` (bulletproofs, groth16), `asm/`,
  `pq/ml_dsa.zig` and `tls_test.zig`. `attic` is absent from `.paths`, so these
  no longer ship; while they sat under `src/` they were published to every
  consumer beside the real implementations. The Zig module rooted at
  `src/root.zig` cannot import outside its own directory, so re-importing one is
  a compile error rather than a review finding.
- Hardware AEAD nonce validation narrowed from `>= 12` to exactly 12 at the
  wrapper boundary.

### Removed

- `util.getTimestampNanos` and `util.getTimestampNanosOrZero`. **The only
  removal from a stable module, and the only change here that breaks a build.**
  They read the wall clock, which cannot measure a duration because it can step
  between two reads, and the `OrZero` variant substituted `0` for a failed read
  — so a zeroed end gave a negative difference that `@intCast` to `u64` turns
  into illegal behaviour, and a zeroed start published roughly 56 years as an
  elapsed time, which a benchmark then divided by. Use `getMonotonicOrError`.
- `asym.Async`, `kdf.Async`, `sym.Async`, `tls.Async`. No migration is needed:
  each referred to `async_crypto.AsyncAsymmetric`, `AsyncKdf`, `AsyncSymmetric`
  or `Task`, none of which was ever declared anywhere in the tree. They were
  uncallable. `zcrypto.async_crypto` itself is unchanged.
- `HSMKeyHandle`, `TPMProvider.deriveKey`, `SecureEnclaveProvider.secureOperation`,
  `HSMInterface.getHardwareRandom`, `getTPMRandom` and `generateKeyExperimental`.
  Removed rather than renamed, so a caller depending on one gets a compile error
  instead of a silent behaviour change. See `src/hsm.zig`'s module doc for the
  replacement of each.

### Fixed

- **`src/bls.zig`, `src/schnorr.zig` and `src/zkp.zig` no longer fabricate
  results.** Every signing, verification, aggregation and proof entry point now
  returns `UnsupportedAlgorithm`; return types widened accordingly
  (`verifyBLS` is `BLSError!bool`, not `bool`). What was there before was SHA-2
  shaped like a signature scheme: `verifyBLS` returned `true` for any input
  whose compression bits were set, `verifySchnorr` discarded the public key
  entirely, and `Bulletproofs.verifyRange` discarded the commitment, the bounds
  and the generators before `return true`. All three carved out inputs
  containing the literal substring `"Wrong"` so their own negative tests would
  pass. Verification returns an error rather than `false` deliberately: `false`
  would imply the signature was checked. Wire sizes and key shapes are retained,
  so code that only parses and carries this material still compiles.
- **TLS session-ticket protection key was public-derived.** `src/tls_server.zig`
  derived the ticket AES-GCM key as `SHA256(server_random || fixed label)`, and
  the same `server_random` is serialized into ServerHello — so anyone with the
  handshake random and a ticket could derive its protection key, and the ticket
  carries a traffic secret. Replaced with server-level ticket-key material from
  checked entropy, shared across connections, with key identity and bounded
  rotation/retirement. Entropy failure now rejects issuance.
- **TLS resumption is wired end to end**, with the per-ticket PSK derived from
  the resumption master secret and ticket nonce per RFC 8446 §4.6.1. The
  previous round-trip test asserted application traffic secret == resumption
  secret, which encoded the wrong design. Transcript boundaries for
  handshake and application traffic secrets were corrected and pinned against
  independently sourced key-schedule vectors.
- **TPM stale key references survived slot reuse**, deletion lost track of live
  objects on error paths, `generateSigningKey` did not generate, and unseal
  failed to wipe on a short-output error. A `KeyRef` is now bound to the
  provider kind and session epoch that issued it.
- **C NULL handling.** Every FFI pointer parameter is `[*]allowzero const u8`.
  Without it the compiler is entitled to assume the pointer is non-NULL — it
  emits LLVM's `nonnull` — and delete the written NULL check as unreachable,
  which it was doing. Passing NULL now reliably returns
  `ZCRYPTO_ERROR_NULL_POINTER` instead of being undefined. ABI-invisible to C.
- **`zcrypto.tls.bbr`'s `cpu_utilization` was never assigned**, so it read 0 forever,
  which made `getPacingAdjustment()` return 1.2 unconditionally whenever
  hardware acceleration was on — a pacing advisor that could tell BBR to speed
  up and never to slow down. Unknown now declines to adjust. The same file's
  `recordEncryption` panicked on `end < start` and `predictCryptoCapacity`
  overflowed a `u32` on an ordinary 10GbE jumbo-frame load; the timing API now
  takes an elapsed duration, so the underflow is unrepresentable.
- `PKCS11Provider.signatureLength` ran the `C_Sign` size query without
  completing the operation. Cryptoki 2.40 has no cancel, so the session was left
  with an operation active and the *next* unrelated call failed.
- Provider-absence reporting no longer misdirects: a ready software token on a
  host with no TPM backend built reports `DeviceAbsent`, not `ProviderNotBuilt`;
  and two providers on one Cryptoki module report `ProviderAlreadyOpen`, naming
  the caller's own program rather than sending an operator to inspect a module
  that is working correctly.
- Provider integration suites no longer collapse every not-ready status into
  `error.SkipZigTest`. Once an operator has named a device, "I could not open
  it" is a result about that device, and skipping let a gate report success
  having reached no hardware at all.

### Security posture, unchanged but restated

- `zcrypto.vpn_crypto` **does not authenticate peers.** It is an AEAD record
  layer: no handshake, no peer authentication, no rekey negotiation.
  `establishTunnel` performs a raw X25519 exchange, which agrees a key with
  whoever is on the other end and says nothing about who that is.
  Authenticating the peer's static public key is the caller's job.
- ML-KEM and ML-DSA wrappers remain experimental and require
  `-Dexperimental-crypto=true`, as do the blockchain, enterprise/formal and ZKP
  surfaces.

### Hardware not exercised

Recorded rather than omitted, because a check that never ran and a check that
passed are otherwise indistinguishable once the result reaches a summary table.

- **Discrete TPM hardware.** The TPM backend is proven against the `swtpm`
  simulator only. A simulator answers `TPM2_GetRandom` exactly as hardware does,
  which is why the code asserts a simulator reports `backing == .software` even
  when every operation succeeds — that assertion is what stops a simulator run
  being presented as evidence of hardware protection.
- **PKCS#11 hardware tokens.** Proven against the NSS software token only, under
  the same rule: a software token is asserted never to be reported as
  hardware-backed.
- **Apple Secure Enclave silicon.** The backend compiles, links against
  Security.framework and runs natively on the lab Mac, which is an `iMac19,1`
  with no T2 and therefore no enclave. What that host proves is the refusal
  path: a `kSecAttrTokenIDSecureEnclave` request fails explicitly with
  `EnclaveAbsent` and no software key is substituted. What it cannot prove is
  that a real enclave signs correctly. Physical SEP execution is **pending**.
- **aarch64, including Apple silicon.** Every host in the platform matrix is
  x86_64.

### Verified

- `bash dev/tpm_swtpm.sh`
  (44/44 tests, 4/4 steps; swtpm 0.10.1 simulator)
- `bash dev/pkcs11_softoken.sh`
  (34/35 plus 1 deliberate environment skip; NSS 3.128-1 softoken)
- `zig build test -Dsecure-enclave=true` on `Darwin 25.6.0 x86_64`
  (28/28 steps, 773/779 tests passed, 6 skipped, in both Debug and ReleaseSafe;
  `[secure enclave] no usable enclave on this host: EnclaveAbsent`. Without the
  flag, 27/27 steps and 767/773 — the difference is the eight-test
  `zcrypto-secure-enclave-test` root that only exists when Security.framework is
  linked.)
- `zig build -Dsecure-enclave=true` on Linux
  (refused at configure time with `SecureEnclaveRequiresMacos`, as required)
- `bash dev/release_check.sh` on zig `0.17.0-dev.2085+5e36170b5`
  (52 stages, 0 failures: 45 positive stages and 7 negative controls, each of
  which asserts a specific diagnostic rather than a nonzero exit. Default
  configuration 27/27 steps and 767/773 tests in both Debug and ReleaseSafe; the
  feature matrix, both hardware-backend configurations and their combination all
  pass in both modes; every compiled artifact is asserted to have used the
  optimize mode that was requested.)
- `bash dev/platform_check.sh` on four native hosts — Arch Linux, Ubuntu,
  macOS, Windows 11 — all on zig `0.17.0-dev.2085+5e36170b5`
  (9/9 stages each; 671/677 tests passed, 6 skipped, in each of Debug,
  ReleaseSafe and ReleaseFast. Details and the skip breakdown are in
  `docs/platform-support.md`.)
- Packaged-candidate consumption from the release tarball rather than from a
  checkout: fetched into an empty cache over loopback HTTP and built for the
  core, TLS, async and post-quantum configurations, plus ReleaseSafe. The
  fingerprint read back out of the fetched package is `0xc9ed93d230004ae`,
  unchanged. Making the archive unreachable turns the same build into
  `ConnectionRefused` rather than a silent fallback to the adjacent working
  tree. (The archive digest and Zig package hash are deliberately not quoted
  here: this file is inside the archive, so any value printed in it would be
  invalidated by printing it.)
- Downstream check against zquic, baseline (zcrypto v1.0.6) versus candidate
  (this release), same compiler and configuration: `build`, `test`
  (272/272), `integration-tests` (96/96), `fuzz-tests` (6/6) and the
  post-quantum gate (315/315) are identical on both sides, with the two sides
  confirmed to have resolved different zcrypto versions. **zquic requires no
  source change to move to 1.0.7.**

## [1.0.6] - 2026-06-23

### Changed

- Bumped package metadata to `1.0.6`.
- Updated the `zsync` dependency from `v0.8.3` to `v0.8.4`.
- Kept the async integration on the std.Io-backed zsync contract:
  `zsync.Io`, `zsync.Future`, `zsync.Runtime.init(allocator, .{})`, and
  `rt.io()`.
- Refreshed release-facing documentation for the v1.0.6 stable core contract,
  experimental feature posture, and zsync v0.8.4 async dependency baseline.
- Reworked the docs tree around a single `docs/README.md` landing page,
  lowercase descriptive pages in subfolders, and Mermaid diagrams for the docs
  map, feature gates, build graph, integration flow, QUIC flow, async boundary,
  and downstream zquic contract.
- Normalized stable AEAD decrypt helpers to return `SymError![]u8` and
  `SymError.DecryptionFailed` instead of nullable plaintext on authentication
  failure.
- Exported `zcrypto.core` from the root module and made `zcrypto.CryptoError`
  alias the core stable error vocabulary.
- Added a runnable stable core example covering hash, Blake3, AEAD, Ed25519,
  X25519, HKDF, QUIC AEAD, random fill, and secure zeroization.
- Added a stable API guard test target to force-reference v1.0.x root exports
  and high-value stable calls.
- Changed the default async feature to `false`; zsync-backed helpers are now
  pulled only when consumers pass `-Dasync=true`.
- Expanded FFI feature reporting so the exported capability bitmask tracks
  async, blockchain, VPN, WASM, enterprise, and other enabled feature flags.
- Reclassified root exports by stability class and gated `ghostchain` behind
  the experimental blockchain feature instead of exporting it by default.
- Added stable key wrappers for AES-256-GCM, ChaCha20-Poly1305, and HMAC key
  material with explicit import/export and zeroization/deinit behavior.

### Verified

- `zig build test -j1 --summary all`
  (471/471 tests pass; default async and blockchain disabled)
- `zig build test -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dvpn=false -Dwasm=false -Dasync=false -j1 --summary all`
  (343/343 tests pass)
- `zig build test -Dtls=true -Dpost-quantum=false -Dhardware-accel=false -Dvpn=false -Dwasm=false -Dasync=false -j1 --summary all`
  (421/421 tests pass)
- `zig build test -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dvpn=false -Dwasm=false -Dasync=true -j1 --summary all`
  (359/359 tests pass)
- `zig build test -Dtls=false -Dpost-quantum=true -Dexperimental-crypto=true -Dhardware-accel=false -Dvpn=false -Dwasm=false -Dasync=false -j1 --summary all`
  (345/345 tests pass)
- `zig build test -Dpost-quantum=true -Dexperimental-crypto=true -Dblockchain=true -Dvpn=true -Dwasm=true -Denterprise=true -Dzkp=true -Dasync=true -j1 --summary all`
  (575/575 tests pass)
- `zig build run-core -j1 --summary all`
  (12/12 steps pass; stable core example runs)
- `zig build run-zsync -Dasync=true -j1 --summary all`
  (15/15 steps pass; zsync integration example runs)
- `zig build -Doptimize=ReleaseSafe -j1 --summary all`
  (10/10 steps pass; max compile RSS 591M)
- `zig build -Doptimize=ReleaseFast -j1 --summary all`
  (10/10 steps pass; max compile RSS 576M)
- `zig fmt --check src/ examples/*.zig build.zig build.zig.zon tests/`
  (pass)
- `cc -fsyntax-only examples/ffi_smoke.c`
  (pass)
- `git diff --check`
  (pass)
- `env ZIG_GLOBAL_CACHE_DIR=.zig-cache-global-v106-final ZIG_LOCAL_CACHE_DIR=.zig-cache-v106-final-release-check bash dev/release_check.sh`
  (pass)
- `env ZIG_GLOBAL_CACHE_DIR=.zig-cache-global-v106-final ZIG_LOCAL_CACHE_DIR=.zig-cache-v106-final-smoke bash dev/smoke_run.sh`
  (pass)
- `env ZIG_GLOBAL_CACHE_DIR=.zig-cache-global-v106-final ZIG_LOCAL_CACHE_DIR=.zig-cache-v106-final-pq-script bash dev/experimental_pq_check.sh`
  (pass)
- `zig build bench -j1 --summary all`
  (pass; max compile RSS 578M)
- `zig build bench -Dpost-quantum=true -Dexperimental-crypto=true -j1 --summary all`
  (pass; max compile RSS 678M)

### Benchmark Notes

- Representative PQ-enabled baseline from this pass:
  SHA-256 1MB 2284 ops/sec, Blake3 1MB 9264 ops/sec, Ed25519 sign 37156
  ops/sec, X25519 DH 42164 ops/sec, AES-128-GCM 1KB 334436 ops/sec,
  ChaCha20-Poly1305 1KB 238951 ops/sec, QUIC packet encrypt 12050356 ops/sec,
  ML-KEM-768 keygen 35071 ops/sec, ML-KEM-768 encaps 35580 ops/sec,
  ML-KEM-768 decaps 29530 ops/sec, ML-DSA-65 sign 4112 ops/sec, and
  ML-DSA-65 verify 11196 ops/sec.

## [1.0.5] - 2026-06-21

### Added

- Added validated raw key import/export helpers for Ed25519, X25519, P-256, and
  P-384 on the stable `asym` surface, plus matching Ed25519/X25519 helpers on
  `kex`.
- Added length-checked ML-KEM-768 and ML-DSA-65 FFI entrypoints:
  `zcrypto_ml_kem_768_keygen_checked`, `zcrypto_ml_kem_768_encaps_checked`,
  `zcrypto_ml_kem_768_decaps_checked`, `zcrypto_ml_dsa_65_keygen_checked`,
  `zcrypto_ml_dsa_65_sign_checked`, and `zcrypto_ml_dsa_65_verify_checked`.
- Added known-answer coverage for SHA-256, SHA-384, SHA-512, Blake2b-512,
  RFC 4231 HMAC, RFC 5869 HKDF-SHA256, PBKDF2-HMAC-SHA256, NIST AES-GCM,
  RFC 8032 Ed25519, and RFC 7748 X25519.
- Extended benchmarks to cover Blake3 small/1MB hashing, X25519 DH, QUIC packet
  encrypt/decrypt, ML-KEM-768 keygen/encaps/decaps, and ML-DSA-65 sign/verify.

### Changed

- Raised `minimum_zig_version` to `0.17.0-dev.931+84f84267c`, matching the
  `/opt/zig-dev/zig` toolchain used for this release pass.
- Updated package paths to include `CHANGELOG.md`, `CONTRIBUTING.md`,
  `SECURITY.md`, and `test_vectors/` in addition to source, docs, examples, dev
  scripts, README, and license.
- Tightened async documentation around the std.Io-backed `zsync v0.8.3` runtime
  contract and caller-owned buffers.
- Clarified experimental module posture: PQ, blockchain, enterprise/formal, and
  ZKP surfaces require explicit opt-in and remain outside the stable-core
  contract.
- Updated dev scripts to default to `/opt/zig-dev/zig` and writable cache
  directories while still allowing `ZIG=/path/to/zig` overrides.

### Fixed

- Fixed QUIC header protection handling so protect/unprotect read packet-number
  length from the correct header state and reject truncated packet-number bytes.
- Fixed ChaCha20 header-protection mask argument ordering.
- Fixed TLS CertificateVerify parsing to require exact signature lengths and
  reject ambiguous Ed25519 private-key sizes.
- Fixed post-quantum convenience hybrid signatures to use real Ed25519 plus
  ML-DSA verification rather than placeholder classical signatures.
- Fixed async batch encryption cleanup so partial failure frees already allocated
  ciphertexts and the results array.
- Tightened FFI pointer handling for feature, version, cipher-suite, and secure
  memory helpers.
- Removed stale API documentation for nonexistent deterministic random bytes and
  corrected PBKDF2 allocator ownership docs.

### Verified

- `zig fmt --check src/ examples/ build.zig` (pass)
- `zig build -Doptimize=ReleaseSafe --summary all` (pass)
- `zig build -Doptimize=ReleaseFast --summary all` (pass)
- `zig build test -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dasync=false --summary all`
  (373/373 tests pass)
- `zig build test -Dtls=true -Dpost-quantum=false -Dhardware-accel=false -Dasync=false --summary all`
  (457/457 tests pass)
- `zig build test -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dasync=true --summary all`
  (389/389 tests pass)
- `zig build test -Dtls=false -Dpost-quantum=true -Dexperimental-crypto=true -Dhardware-accel=false -Dasync=false --summary all`
  (383/383 tests pass)
- `zig build test --summary all` (475/475 tests pass)
- `zig build test -Dpost-quantum=true -Dexperimental-crypto=true -Dblockchain=true -Dvpn=true -Dwasm=true -Denterprise=true -Dzkp=true -Dasync=true --summary all`
  (551/551 tests pass)
- `bash dev/release_check.sh` (pass)
- `bash dev/smoke_run.sh` (pass)
- `bash dev/experimental_pq_check.sh` (pass)
- `zig build bench` (pass)
- `zig build bench -Dpost-quantum=true -Dexperimental-crypto=true` (pass)

### Notes

- Representative PQ-enabled benchmark baseline from this pass:
  SHA-256 1MB 2180 ops/sec, Blake3 1MB 5239 ops/sec, Ed25519 sign 35082
  ops/sec, X25519 DH 40541 ops/sec, AES-128-GCM 1KB 272117 ops/sec,
  ChaCha20-Poly1305 1KB 208730 ops/sec, QUIC packet encrypt 10673498 ops/sec,
  ML-KEM-768 keygen 33296 ops/sec, ML-KEM-768 encaps 32278 ops/sec,
  ML-KEM-768 decaps 29582 ops/sec, ML-DSA-65 sign 3907 ops/sec, and
  ML-DSA-65 verify 11284 ops/sec.
- The stable v1.0.5 contract remains the core primitives, QUIC helpers,
  allocator ownership rules, and feature-gated integrations verified above.
  Experimental modules are usable for research but not promoted to frozen API
  status.

## [1.0.4] - 2026-06-03

### Added

- Added ECDSA signer/verifier primitives to `asym.zig`: a `secp384r1` namespace
  (backed by `std.crypto.sign.ecdsa.EcdsaP384Sha384`) mirroring the existing
  `secp256r1`, plus `signMessageDer` / `verifyMessageDer` arbitrary-length message
  helpers (DER-encoded) on both P-256 and P-384. Covered by sign→DER→verify
  round-trip, tamper, and malformed-DER unit tests.
- Implemented real TLS 1.3 CertificateVerify signing and verification. Extracted
  `buildCertVerifySignature` (`tls_server.zig`) and `verifyCertVerifySignature`
  (`tls_client.zig`) as pure, unit-tested functions supporting `ed25519` (0x0807),
  `ecdsa_secp256r1_sha256` (0x0403), and `ecdsa_secp384r1_sha384` (0x0503).
- Added real post-quantum round-trip tests in `pq.zig`: ML-KEM-768 (FIPS 203)
  encapsulate/decapsulate agreement, ML-DSA-65 (FIPS 204) sign/verify with
  tamper detection, and both hybrid constructions (X25519+ML-KEM-768 key exchange,
  Ed25519+ML-DSA-65 signatures), replacing the previous empty TODO tests.
- Added `CONTRIBUTING.md` (root) and `docs/security/fips.md` documenting the FIPS
  posture: approved/stdlib-backed vs experimental vs unsupported algorithms.

### Changed

- Bumped the `zsync` dependency from `v0.8.2` to `v0.8.3`, which rebases the
  async runtime onto `std.Io`.
- Migrated `async_crypto.zig` and the zsync example/docs off the removed
  `zsync.BlockingIo` backend to `zsync.Runtime.init(allocator, .{})` +
  `rt.io()`. The `AsyncCrypto` API surface (`Io`, `Future`, `init`) is
  unchanged; only the runtime construction differs.
- Updated `build.zig` run steps to use `addPassthruArgs()` for the current
  Zig `0.17.0-dev` build API.
- Raised `minimum_zig_version` to `0.17.0-dev.639+284ab0ad8`.
- TLS CertificateVerify now returns `error.UnsupportedKeyType` for RSA and X25519
  key types instead of logging a misleading "not yet implemented" placeholder.
  The supported set is Ed25519 + ECDSA P-256/P-384.
- Documentation now references `minimum_zig_version` in `build.zig.zon` instead of
  hardcoding a Zig dev version, and points to the root `CONTRIBUTING.md`. README
  roadmap and feature stability notes clarify zcrypto's role (primitives + QUIC
  crypto), the experimental TLS stack, and the SLH-DSA/RSA stance.

### Removed

- **Removed the hand-rolled SLH-DSA-128s placeholder** from `pq.zig` (and the
  `,SLH-DSA-128s` entry from the FFI capability string). There is no `std.crypto`
  backend for FIPS 205 and zcrypto does not ship homemade SPHINCS+. Post-quantum
  signatures use ML-DSA-65 (FIPS 204). Downstream `zquic` is migrated accordingly
  (see `zquic/tasks/zcrypto_and_zig.md`).

### Fixed

- Removed hardcoded version strings from source header comments
  (`bbr_crypto.zig`, `pq.zig`, `quic.zig`, `zero_copy.zig`). Version is sourced
  only from `build.zig.zon` via `build_options.version`.
- Modernized the last managed-`ArrayList` call site (`tls_client.zig`
  certificate-chain parsing) to the Zig 0.17 unmanaged API (`.empty`,
  `append(allocator, x)`, `toOwnedSlice(allocator)`).
- Fixed a latent (never-compiled) bug in the Ed25519+ML-DSA-65 hybrid `sign`
  path where the Ed25519 `Signature` struct was memcpy'd directly instead of its
  `toBytes()` encoding. Now exercised by the new hybrid round-trip test.

### Verified

- `zig build` (pass)
- `zig build test` (pass)
- `zig build test -Dpost-quantum=true -Dexperimental-crypto=true --summary all`
  (440/440 tests pass)
- `zig build run-zsync` (pass)
- `zig fmt --check src examples` (clean)

### Notes

- Downstream consumers like `/data/projects/zquic` are unaffected: the changed
  surface (`async_crypto`/`zsync`/`BlockingIo`) is not part of the core crypto
  API zquic consumes. See `zquic/tasks/zcrypto_update.md` for the pin bump.

## [1.0.3] - 2026-05-04

### Changed

- Bumped the package version metadata to `v1.0.3`.
- Kept the existing `zsync v0.8.2` dependency update in place for the current release line.

### Fixed

- Restored `zcrypto` build compatibility on the current Zig `0.17.0-dev` toolchain after the newer parser started rejecting repeat-expression forms used across the project.
- Replaced fragile array repeat initializers in the active build and test surface with parser-stable zero-initialization or explicit filled-buffer setup.
- Fixed the same parser-sensitive patterns in examples, FFI tests, QUIC/TLS helpers, and post-quantum wrappers so downstream consumers like `/data/projects/zquic` no longer fail immediately on dependency parse errors.

### Verified

- `"/opt/zig-dev/zig" build`
- `"/opt/zig-dev/zig" build test --summary all`
- `"/opt/zig-dev/zig" build -Dpost-quantum=true -Dexperimental-crypto=true`

### Notes

- `v1.0.3` is the Zig-dev compatibility follow-up to `v1.0.2`.
- A final cleanup pass is still warranted for remaining non-default files that use the old repeat-expression style, even though the primary build and test surface is now passing.

## [1.0.2] - 2026-04-18

### Changed

- Bumped the package and exported version metadata to `v1.0.2`.
- Updated the project Zig baseline and release validation around `0.17.0-dev.9+046002d1a`.
- Reworked the exported post-quantum release surface so ML-DSA paths now follow current Zig stdlib behavior instead of older project-local placeholders.
- Tightened the async integration wording so `zcrypto` now documents the supported `zsync` core surface it actually targets instead of implying unsupported runtime offload behavior.

### Fixed

- Fixed ML-DSA encoded sizes and FFI-facing key/signature expectations to match current Zig stdlib `MLDSA44`, `MLDSA65`, and `MLDSA87` values.
- Fixed remaining Zig master API drift across Ed25519, X25519, and unmanaged `std.ArrayList` callsites on the audited release paths.
- Fixed old compatibility wording in source comments that still described Zig `0.16.0-dev` as the active target.
- Fixed the Ed25519 context-signing surface to fail explicitly as unsupported on the current Zig stdlib baseline instead of leaving the contract ambiguous.

### Verified

- `"/opt/zig-dev/zig" build test`
- `"/opt/zig-dev/zig" build test -Dexperimental-crypto=true -Dpost-quantum=true -Dblockchain=true -Denterprise=true -Dzkp=true`
- `"/opt/zig-dev/zig" build`
- `"/opt/zig-dev/zig" build -Doptimize=ReleaseSafe`
- `"/opt/zig-dev/zig" build -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dasync=false -Dvpn=false -Dwasm=false`
- `"/opt/zig-dev/zig" build -Dexperimental-crypto=true -Dpost-quantum=true -Dblockchain=true -Denterprise=true -Dzkp=true`
- `"/opt/zig-dev/zig" build run`
- `"/opt/zig-dev/zig" build run-advanced`
- `"/opt/zig-dev/zig" build bench`
- `"/opt/zig-dev/zig" build run-zsync`

### Notes

- `v1.0.2` is the release intended to carry the Zig `0.17.0-dev.9+046002d1a` compatibility pass.
- The remaining follow-up after this bump is release-note and documentation polish rather than an identified Zig `0.17` code-compatibility blocker.

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
