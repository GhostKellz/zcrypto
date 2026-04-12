# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x: |

## Reporting a Vulnerability

If you discover a security vulnerability in `zcrypto`, please report it responsibly:

1. Do not open a public GitHub issue for security vulnerabilities.
2. Email security concerns to: `ckelley@ghostkellz.sh`
3. Include:
   - a clear description of the issue
   - affected module or feature flag
   - steps to reproduce
   - impact assessment
   - proposed mitigation or fix if available

You can expect:

- acknowledgment within 48 hours
- a status update within 7 days
- coordinated disclosure when a fix is available

## Release Scope and Stability

`zcrypto v1.0.0` has a stable core API and a separate set of explicitly experimental feature families.

Stable core modules are the intended long-lived support surface for `v1.0.x`.

Experimental feature families currently include:

- `post-quantum`
- `blockchain`
- `enterprise`
- `zkp`

These require `-Dexperimental-crypto=true` and should not be treated as a frozen production contract.

## Security Practices

### Build and Verification

Run the local verification scripts before release work:

```bash
bash dev/release_check.sh
bash dev/experimental_pq_check.sh
bash dev/smoke_run.sh
```

These currently verify:

- formatting
- default build
- full test build
- reduced-feature build
- experimental PQ build
- shipped runtime entrypoints

### Dependency Management

- Dependencies are pinned in `build.zig.zon`
- Release/tag archives are preferred over `main` tarballs for reproducibility
- Dependency upgrades should be revalidated with the local release scripts

### Code Safety

- Avoid placeholder or incomplete cryptographic implementations in stable release paths
- Keep experimental crypto behind explicit build-time opt-in
- Do not log secrets, key material, nonces, or shared secrets
- Prefer explicit error handling over silent fallback behavior in security-sensitive code

### Secret Handling

Recommendations for contributors and downstream integrators:

- never commit private keys, seed material, `.env` files, or credential dumps
- use restricted file permissions for test fixtures containing sensitive material
- zero sensitive buffers where practical

## Known Security Considerations

### Experimental Crypto

Some optional modules are present for research, compatibility work, or iterative development. These are intentionally not enabled by default in `v1.0.0`.

If you enable them:

- treat the API as higher-churn
- perform your own threat modeling and validation
- do not assume the same support guarantees as the stable core

### FFI Consumers

FFI consumers should verify ABI expectations against the exact released tag they depend on.

Do not assume experimental modules expose stable FFI contracts unless that support is explicitly documented in the release you are consuming.

## Security Checklist for Contributors

Before submitting a security-sensitive change:

- [ ] no hardcoded secrets or credentials
- [ ] no stale docs claiming unsupported security guarantees
- [ ] experimental features remain behind explicit opt-in
- [ ] local verification scripts pass
- [ ] tests cover the affected security-sensitive path

## Security Updates

Security fixes for supported versions should be released as patch updates in the `1.0.x` line when possible.

Announcements should go through:

- release notes
- GitHub Security Advisories
- repository documentation updates when relevant

## Contact

- Security issues: `ckelley@ghostkellz.sh`
- General project issues: GitHub Issues
