# Examples

Practical examples for the currently documented `zcrypto` surfaces.

## Available Example Docs

### [Basic Cryptography](basic.md)
- Hash functions
- Symmetric encryption
- Digital signatures
- Key exchange
- Key derivation
- Random generation

## Running Examples

```bash
# Build the installed targets
zig build

# Run the default demo
zig build run

# Run the advanced example with hardware acceleration
zig build run-advanced -Dhardware-accel=true

# Run the advanced example with experimental PQ enabled
zig build run-advanced -Dhardware-accel=true -Dpost-quantum=true -Dexperimental-crypto=true
```

## Example Structure

The docs in this directory should only describe examples and commands that currently exist in this repository.

## Contributing Examples

Add new examples to the `examples/` directory and update this documentation.
