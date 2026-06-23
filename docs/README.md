# zcrypto Documentation

zcrypto is a modular cryptography library for Zig. The v1.0.x documentation is
organized around a stable core API, explicit feature gates, and clear separation
between production-ready primitives and experimental research surfaces.

## Documentation Map

```mermaid
flowchart TD
    start["Start here<br/>docs/README.md"]

    start --> gs["Getting Started"]
    start --> api["API Reference"]
    start --> features["Feature Guides"]
    start --> examples["Examples"]
    start --> internals["Internals"]
    start --> security["Security"]

    gs --> quick["quick-start.md"]
    gs --> config["build-config.md"]

    api --> core["core.md<br/>stable API"]
    api --> reference["reference.md<br/>full surface"]

    features --> foverview["overview.md"]
    features --> tls["tls.md"]

    examples --> eoverview["overview.md"]
    examples --> basic["basic.md"]

    internals --> arch["architecture.md"]
    security --> fips["fips.md"]
```

## Runtime Shape

```mermaid
flowchart LR
    app["Zig application"] --> zcrypto["zcrypto module"]
    zcrypto --> stable["Stable core<br/>hash, auth, sym, asym, kdf, rand, kex"]
    zcrypto --> quic["QUIC helpers<br/>packet protection, key derivation"]
    zcrypto --> gated["Feature-gated modules"]

    gated --> tls["tls"]
    gated --> async["async_crypto<br/>zsync v0.8.4"]
    gated --> hw["hardware"]
    gated --> pq["post_quantum<br/>experimental"]
    gated --> research["blockchain / zkp / enterprise<br/>experimental"]

    stable --> stdcrypto["Zig std.crypto"]
    quic --> stdcrypto
    pq --> stdcrypto
```

## Stability Model

```mermaid
flowchart TD
    surface{"Which API surface?"}
    surface --> stable["Stable v1.0.x core"]
    surface --> gated["Feature-gated stable helpers"]
    surface --> experimental["Experimental crypto"]
    surface --> compat["Compatibility aliases"]

    stable --> prod["Use for production integrations"]
    gated --> flags["Enable only needed build flags"]
    experimental --> optin["Requires -Dexperimental-crypto=true"]
    compat --> migrate["Prefer documented stable modules for new code"]

    optin --> churn["Expect API churn and research posture"]
```

## Common Paths

```mermaid
flowchart TD
    task{"What are you doing?"}
    task -->|"Trying zcrypto"| quick["getting-started/quick-start.md"]
    task -->|"Choosing feature flags"| build["getting-started/build-config.md"]
    task -->|"Using stable primitives"| core["api/core.md"]
    task -->|"Checking all exports"| ref["api/reference.md"]
    task -->|"Integrating with another Zig package"| integ["integration.md"]
    task -->|"Using QUIC/TLS helpers"| tls["features/tls.md"]
    task -->|"Reviewing security posture"| fips["security/fips.md"]
    task -->|"Understanding internals"| arch["internals/architecture.md"]
```

## Getting Started

- [Quick Start](getting-started/quick-start.md) - Install and use the stable core APIs.
- [Build Configuration](getting-started/build-config.md) - Feature flags, dependency shape, and example package configurations.

## API Reference

- [Core API](api/core.md) - Stable hash, authentication, symmetric, asymmetric, KDF, random, KEX, and ownership rules.
- [Full Reference](api/reference.md) - Stable, feature-gated, experimental, FFI, and build-aware exports.

## Feature Guides

- [Feature Overview](features/overview.md) - Feature flags, dependencies, stability notes, and use-case configurations.
- [TLS/QUIC](features/tls.md) - TLS-related helpers and QUIC crypto building blocks.

## Examples

- [Examples Overview](examples/overview.md) - Repository examples and what each one demonstrates.
- [Basic Usage](examples/basic.md) - Hashing, AEAD, signatures, KDF, and random examples.

## Internals

- [Architecture](internals/architecture.md) - Module graph, build graph, request/key flows, and downstream boundaries.

## Security

- [FIPS Posture](security/fips.md) - Approved, experimental, and unsupported algorithms.
- [Security Policy](../SECURITY.md) - Reporting vulnerabilities and supported release line.

## Quick Links

| Area | Path |
|------|------|
| Package metadata | [`../build.zig.zon`](../build.zig.zon) |
| Build script | [`../build.zig`](../build.zig) |
| Stable root module | [`../src/root.zig`](../src/root.zig) |
| Release notes | [`../CHANGELOG.md`](../CHANGELOG.md) |
| Contributing | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |

## Production Checklist

- Keep production code on the stable core plus documented QUIC helpers unless a feature gate is intentional.
- Enable only the features your consumer needs.
- Require `-Dexperimental-crypto=true` for PQ, blockchain, enterprise/formal, and ZKP surfaces.
- Treat ML-KEM and ML-DSA wrappers as useful but still experimental in v1.0.x.
- Query FFI/runtime capabilities instead of assuming optional feature symbols exist.
- Preserve allocator ownership: returned slices from allocator-taking APIs are caller-owned unless a `deinit` method is documented.
