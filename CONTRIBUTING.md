# Contributing to zcrypto

Welcome! This guide covers development setup, coding standards, and contribution
workflows for zcrypto.

## Development Setup

### Prerequisites

- A Zig toolchain that satisfies `minimum_zig_version` in
  [`build.zig.zon`](build.zig.zon). zcrypto tracks Zig `0.17.0-dev` (nightly);
  the exact supported baseline is whatever that field declares — it is the
  single source of truth, so this document does not duplicate the version.
- Git
- Linux, macOS, or Windows (all supported)

### Clone and Build

```bash
git clone https://github.com/ghostkellz/zcrypto.git
cd zcrypto
zig build test   # verify your toolchain
```

### Verification Commands

These are the build/test invocations the project actually exposes (see
`build.zig`):

```bash
zig build                 # build library + examples
zig build test            # run the full test suite
zig build run             # run the demo
zig build run-advanced    # run the advanced features example
zig build run-zsync       # run the zsync async example
zig build bench           # run benchmarks

# Release + experimental coverage
zig build -Doptimize=ReleaseSafe
zig build test -Dpost-quantum=true -Dexperimental-crypto=true
```

## Build Flags

Feature flags are declared in `build.zig`. Experimental families require
`-Dexperimental-crypto=true` and are otherwise gated off.

| Flag | Default | Description |
|------|---------|-------------|
| `-Dtls` | `true` | TLS 1.3 and QUIC support |
| `-Dpost-quantum` | `false` | Post-quantum crypto (requires `-Dexperimental-crypto`) |
| `-Dhardware-accel` | `true` | SIMD / AES-NI acceleration |
| `-Dblockchain` | `false` | Experimental blockchain helpers (requires `-Dexperimental-crypto`) |
| `-Dvpn` | `true` | VPN-specific crypto features |
| `-Dwasm` | `true` | WebAssembly support |
| `-Denterprise` | `false` | Experimental enterprise helpers (requires `-Dexperimental-crypto`) |
| `-Dzkp` | `false` | Experimental zero-knowledge proofs (requires `-Dexperimental-crypto`) |
| `-Dasync` | `true` | Async crypto via zsync |
| `-Dexperimental-crypto` | `false` | Allow incomplete/placeholder crypto (DANGEROUS: not for production) |
| `-Dallow-insecure` | `false` | Allow insecure options in release builds (DANGEROUS: not for production) |

## Coding Standards

### Zig Style

Follow the [Zig Style Guide](https://ziglang.org/documentation/master/#Style-Guide):

- `snake_case` for functions and variables, `PascalCase` for types
- 4-space indentation
- Run `zig fmt src examples` before committing; CI treats `zig fmt --check` as
  authoritative

### Documentation

- Public functions get `///` doc comments describing parameters and return values
- Comments explain *why*, not *what*
- Do not hardcode version strings in source, comments, or examples — the version
  comes from `build.zig.zon` via `build_options.version`

### No Hand-Rolled Crypto

Cryptographic primitives must be backed by Zig stdlib (`std.crypto`) or a
reviewed, audited dependency. Do not introduce homemade implementations of
ciphers, signatures, KEMs, or hashes. Algorithms without a safe backing should
be marked unsupported rather than stubbed.

### Error Handling

- Use specific error types from `errors.zig`
- Document the error conditions a public function can return

### Testing

- Unit tests for all public functions, colocated in the module under test
- Round-trip + tamper/negative tests for signature and KEM code
- Add RFC/NIST test vectors where they exist

## Feature Development

### Adding a New Feature

1. **Design** — open an issue describing the API and security implications.
2. **Implement** — add the feature flag to `build.zig`, create the
   `src/feature_*.zig` module, wire conditional imports in `src/root.zig`, and
   add tests.
3. **Document** — update `docs/features/` and the API reference.

### Feature Flag Guidelines

- Descriptive names (`post-quantum`, `hardware-accel`)
- Optional/experimental families default to `false`
- Experimental crypto stays behind `-Dexperimental-crypto`

## Security Considerations

- All crypto code requires review against established standards (FIPS, RFCs).
  See [`docs/security/fips.md`](docs/security/fips.md) for the FIPS posture.
- Validate inputs at boundaries; keep core primitives allocation-free where
  practical.
- Prefer constant-time operations for secret-dependent code paths and clear
  sensitive material from memory.
- Report security issues privately per [`SECURITY.md`](SECURITY.md).

## Pull Request Process

1. Fork and branch from `main`.
2. Write tests, implement, update docs, run the full suite + `zig fmt --check`.
3. Open a PR and address review feedback.
4. Squash on request; keep the changelog entry accurate.

## Release Process

zcrypto follows [Semantic Versioning](https://semver.org/). The version lives in
`build.zig.zon` and is surfaced at runtime via `build_options.version`.

### Release Checklist

- [ ] `zig build` and `zig build test` pass (default)
- [ ] `zig build test -Dpost-quantum=true -Dexperimental-crypto=true` passes
- [ ] `zig fmt --check src examples` clean
- [ ] Documentation updated
- [ ] `CHANGELOG.md` entry added
- [ ] Version bumped in `build.zig.zon`

Thank you for contributing to zcrypto.
