# Contributing to zcrypto

Welcome! We appreciate your interest in contributing to zcrypto. This guide covers development setup, coding standards, and contribution workflows.

## Development Setup

### Prerequisites

- Zig 0.16.0 or later
- Git
- Linux/macOS/Windows (all supported)

### Clone and Setup

```bash
git clone https://github.com/ghostkellz/zcrypto.git
cd zcrypto
zig build test  # Run tests to verify setup
```

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes
zig build test  # Run tests frequently

# Format code
zig fmt src/*.zig

# Run benchmarks
zig build bench

# Commit changes
git add .
git commit -m "feat: add your feature"
```

## Coding Standards

### Zig Style Guide

Follow the [Zig Style Guide](https://ziglang.org/documentation/master/#Style-Guide):

- Use `snake_case` for functions and variables
- Use `PascalCase` for types and structs
- 4-space indentation
- Maximum line length: 100 characters
- Use `zig fmt` for formatting

### Documentation

- All public functions must have doc comments
- Use `///` for function documentation
- Include parameter descriptions and return values
- Add examples for complex APIs

```zig
/// Computes SHA-256 hash of input data.
/// Returns 32-byte hash digest.
/// Example:
///   const hash = sha256("hello");
pub fn sha256(data: []const u8) [32]u8 {
    // implementation
}
```

### Error Handling

- Use specific error types from `errors.zig`
- Prefer `!T` return types over error unions in results
- Document all possible error conditions

### Testing

- Unit tests for all public functions
- Integration tests for complex features
- Fuzz testing for cryptographic functions
- Performance benchmarks

```zig
test "sha256 basic" {
    const input = "hello world";
    const expected = [_]u8{ /* expected hash */ };
    const result = sha256(input);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}
```

## Feature Development

### Adding New Features

1. **Design Phase**
   - Create GitHub issue describing the feature
   - Discuss API design and implementation approach
   - Consider security implications

2. **Implementation**
   - Add feature flag to `build.zig`
   - Create `src/feature_*.zig` module
   - Update `src/root.zig` conditional imports
   - Add comprehensive tests

3. **Documentation**
   - Update `docs/features/` with feature guide
   - Add examples in `examples/`
   - Update API reference

### Feature Flag Guidelines

- Use descriptive names: `post_quantum`, `hardware_accel`
- Default to `false` for optional features
- Document size impact in build config
- Test all combinations

## Security Considerations

### Cryptographic Review

- All crypto code requires security review
- Follow established cryptographic standards
- Include test vectors from RFCs/specifications
- Document security properties and limitations

### Memory Safety

- Use Zig's compile-time safety features
- Avoid buffer overflows and use-after-free
- Validate all inputs
- Use `std.mem.secret` for sensitive data

### Side Channels

- Constant-time operations for secret data
- Avoid timing attacks
- Clear sensitive data from memory
- Document side-channel resistance

## Testing

### Running Tests

```bash
# All tests
zig build test

# Specific test
zig build test -Dtest-filter="sha256"

# Feature-specific tests
zig build test -Dtls=true

# Fuzz testing
zig build fuzz
```

### Test Coverage

- Unit tests for all functions
- Integration tests for features
- Cross-platform testing
- Memory leak detection

### Benchmarks

```bash
# Run benchmarks
zig build bench

# Compare performance
zig build bench -- --baseline
```

## Pull Request Process

1. **Fork and Branch**
   - Fork the repository
   - Create feature branch from `main`

2. **Development**
   - Write tests first (TDD)
   - Implement feature
   - Update documentation
   - Run full test suite

3. **Code Review**
   - Create pull request
   - Address review comments
   - Maintain commit history

4. **Merge**
   - Squash commits if requested
   - Delete feature branch
   - Update any dependent branches

## Release Process

### Versioning

Follow [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- Breaking changes increment MAJOR
- New features increment MINOR
- Bug fixes increment PATCH

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] Benchmarks run
- [ ] Security review completed
- [ ] API compatibility checked
- [ ] Changelog updated
- [ ] Version bumped in relevant files

## Community

- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Report bugs and request features
- **Security**: Report security issues privately
- **Code of Conduct**: Be respectful and inclusive

## Recognition

Contributors are recognized in:
- GitHub contributor statistics
- CHANGELOG.md for significant contributions
- Special mentions for security research

Thank you for contributing to zcrypto! 🚀