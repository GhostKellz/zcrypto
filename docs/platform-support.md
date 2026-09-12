# Platform support

What this library has actually been built and run on, how that was established,
and what is not covered.

Every row below comes from a run **on the machine it describes**. A
cross-compiled binary is not a native pass: it shows the code compiles for a
target, which says nothing about the platform branches — entropy, clocks,
hardware detection — that are the reason platform support is in question at all.
The harness refuses to emit a record if the build is not native, and refuses any
individual stage that passes `-Dtarget=`.

## Matrix

Toolchain: **Zig 0.17.0-dev.2085+5e36170b5**, identical on all four hosts.
Tree: commit `155c96a`, worktree dirty (this gate is run against work in
progress, and the record says so rather than implying a tag).

| Host | `uname` | Zig native target | Stages | Tests (each of 3 optimize modes) |
|---|---|---|---|---|
| Arch Linux | `Linux 7.2.4-1-cachyos-lto x86_64` | `x86_64-linux.7.2.4...7.2.4-gnu.2.44` | 9/9 pass | 671/677 passed, 6 skipped |
| Ubuntu | `Linux 7.0.0-28-generic x86_64` | `x86_64-linux.7.0...7.0-gnu.2.43` | 9/9 pass | 671/677 passed, 6 skipped |
| macOS | `Darwin 25.6.0 x86_64` | `x86_64-macos.26.6.2...26.6.2-none` | 9/9 pass | 671/677 passed, 6 skipped |
| Windows 11 | `Windows 10.0.26200 build 26200 AMD64` | `x86_64-windows.win11_br...win11_br-gnu` | 9/9 pass | 671/677 passed, 6 skipped |

The two Linux rows are not redundant. They resolve different glibc versions
(2.44 against 2.43) and different kernel headers, which is exactly the axis along
which a "works on Linux" claim usually turns out to be "works on my Linux".

## Stages run on every host

| Stage | Command |
|---|---|
| `build` | `zig build` |
| `test-debug` | `zig build test -Doptimize=Debug --summary all` |
| `test-releasesafe` | `zig build test -Doptimize=ReleaseSafe --summary all` |
| `test-releasefast` | `zig build test -Doptimize=ReleaseFast --summary all` |
| `hardware-parity-debug` | `zig build hardware-parity -Doptimize=Debug` |
| `hardware-parity-releasefast` | `zig build hardware-parity -Doptimize=ReleaseFast` |
| `kat` | `zig build kat` |
| `ffi-consumer` | `zig build ffi-consumer` |
| `run-core` | `zig build run-core` |

All nine exited 0 on all four hosts.

Three optimize modes are run rather than one because the safety checks that
catch a platform bug are compiled out of `ReleaseFast`, and the codegen that
exposes one is absent from `Debug`. `hardware-parity` runs in both extremes for
the same reason: it exists to check that the accelerated path and the portable
path agree, and that comparison is only meaningful where the accelerated path is
actually selected.

## Tests that did not run

Six tests skip, and the same six skip on every host:

| Test binary | Skipped | Why |
|---|---|---|
| `zcrypto-ffi-test` | 4 | Post-quantum FFI surface; `-Dpost-quantum` defaults to false |
| `zcrypto-feature-surface-test` | 2 | Post-quantum and async surfaces; both default to false |

These are gated on build flags, not on the host. No platform in the matrix has a
coverage gap relative to another — the skips are a property of the default build
configuration, and enabling those features runs them everywhere.

## Host services not present

These back stages of `dev/release_check.sh` that need a service the machine does
not have. They are recorded as pending rather than omitted, because a check that
never ran and a check that passed are otherwise indistinguishable once the
result reaches a summary table.

| Host | Pending |
|---|---|
| Arch Linux | `softhsm` |
| Ubuntu | `swtpm`, `softhsm` |
| macOS | `swtpm`, `softhsm` |
| Windows | `swtpm`, `softhsm`, `system-cc` (no MSVC `cl.exe`) |

`system-cc` gates only `ffi-consumer-system-cc`, which compiles the C consumer
with the host's own toolchain. The `ffi-consumer` stage in the matrix above ran
everywhere regardless, because the build compiles `tests/ffi/consumer.c` with
the clang Zig bundles — so the C API is exercised on Windows too, just not
against MSVC.

## Not covered

- **Freestanding / bare metal.** Not supported, by design and enforced at
  compile time. A freestanding target has no entropy source, so `src/rand.zig`
  fails the build rather than substituting a PRNG that would hand the caller
  predictable keys indistinguishable from CSPRNG output:

  ```
  src/rand.zig:169:13: error: zcrypto: no entropy source exists on a freestanding
  target. Build for wasm32-wasi, which provides random_get, or supply a host
  import and route osRandomChecked through it.
  ```

  The error surfaces as soon as anything reaches `rand`; a build that merely
  imports the library without touching randomness still compiles, which is not
  the same as being supported.
- **WebAssembly.** `wasm32-wasi` is out of scope for this matrix, which
  certifies native hosts only. It has its own gate.
- **Non-x86_64.** Every host here is x86_64. aarch64 — including Apple silicon,
  where the macOS row would otherwise imply coverage — is untested.
- **MSVC ABI on Windows.** The Windows target resolved to `-gnu`.
- **musl, and other libc implementations.** Both Linux rows are glibc.

## Reproducing

One host, run on that host:

```sh
ZIG=/path/to/zig bash dev/platform_check.sh
```

The whole matrix, driven from a dev machine:

```sh
bash dev/platform_matrix.sh
```

The driver needs a host list at `dev/platform_hosts.conf`; the format is
documented in the header of the script. That file is untracked, because lab
addresses are deployment detail rather than source.

The driver ships the **working tree**, not `HEAD`, so what gets certified is
what the developer is looking at. Each remote record carries a stamp naming the
commit and whether the tree was dirty, since a remote host has no repository of
its own and would otherwise produce an unattributable pass.

Windows uses `dev/platform_check.ps1`, which emits the identical record format.
It is a separate script rather than a shim over the shell one because the only
`bash` on a stock Windows host is the WSL launcher — running the shell script
there would certify a Linux guest and label the result Windows.
