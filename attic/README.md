# attic

Quarantined source files. **Nothing here is compiled, tested, shipped, or
supported.** Do not import anything in this directory.

## Why the files are here rather than deleted

The instruction on record was to prefer quarantine and an explicit unsupported
contract over deletion, and to add a guard so future imports cannot silently
expose insecure operations.

Both halves are satisfied by the location itself. The Zig module rooted at
`src/root.zig` cannot reach outside its own directory, so an import from `src/`
into this directory is a compile error, not a review finding:

```
src/util.zig:656:17: error: import of file outside module path
    _ = @import("../attic/protocols/noise.zig");
                ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

`attic` is also absent from `.paths` in `build.zig.zon`, so these files are no
longer part of the published package. While they sat under `src/` they were
shipped to every consumer, sitting beside the real implementations with nothing
to distinguish them.

`dev/orphan_check.sh` closes the other direction: it walks `@import` from every
`root_source_file` in `build.zig` and fails if any file under `src/` is
unreachable. Adding a file back to `src/` without wiring it into the build fails
the release gate.

## Why a guard rather than a reviewed list

Two files in this directory — `asm/x86_64.zig` and `protocols/signal.zig` —
were missing from the hand-maintained inventory of unreferenced sources, and
were found only by compiling the set and diffing import reachability. A list
maintained by reading is the thing that failed; the check is mechanical for that
reason.

## What is here

Layout mirrors the original location under `src/`.

### Does not compile

Measured against the module they were removed from, as members of it. These are
the diagnostics from a single compilation; a file may hold further errors behind
the first.

| File | Diagnostics |
| --- | --- |
| `protocols.zig` | `:38:30` expected type `[32]u8`, found `[64]u8`; `:345:24` `mem` has no member named `writeIntLittle` |
| `protocols/gossip.zig` | `:270:26` missing struct field: `items` |
| `protocols/mls.zig` | `:114:28` expected type `[32]u8`, found `Ed25519.PublicKey` |
| `protocols/noise.zig` | `:306:61` index syntax required to access runtime-known slice |
| `zkp/bulletproofs.zig` | `:61:31` type `u64` cannot represent integer value `115792089237316195423570985008687907852837564279074904382605163141518161494335`; `:86:30` `mem` has no member named `readIntBig`; `:165:16` … `writeIntBig` |
| `zkp/groth16.zig` | `:86:30` and `:256:28` `mem` has no member named `readIntBig` |
| `asm/x86_64.zig` | `:103:9` pointless discard of function parameter |
| `tls_test.zig` | `:51:19` expected `[][]const u8`, found `*const [2][]const u8`; `:94:34` `feature_tls` has no member named `TranscriptHash`; `:128:34` and `:405:34` … `AeadCipher`; `:293:43` and `:353:44` expected `[]const u8`, found `*const error{IdentityElement}![32]u8`; `:304:29` `std` has no member named `net` |

`mem.readIntBig`, `writeIntBig` and `writeIntLittle` were removed from the
standard library some releases ago, which dates how long these went unbuilt.

### Compiles, but unreferenced

`protocols/dht.zig`, `protocols/signal.zig`, `asm/aarch64.zig`,
`asm/generic.zig`, `pq/ml_dsa.zig`.

Compiling is not evidence of correctness here: nothing calls them, so no test
covers them and `src/api_surface.zig` never analysed them either.

## Consumer impact of the move

None, and this is checkable rather than asserted. No file in this directory was
named by `build.zig`, imported by any file that was, or reachable through
`@import("zcrypto")`. The only reference of any kind anywhere in the repository
was a path mention in `docs/features/tls.md`, since corrected.

## One trap worth naming

`pq/ml_dsa.zig` is not the implementation behind `zcrypto.pq.ml_dsa`. That name
is a struct defined inline at `src/pq.zig:36`. Only `ml_kem` is an import
(`src/pq.zig:33`). Anyone reading the old directory listing would reasonably
have concluded the opposite, which is the kind of mistake a filename alone can
cause and a reason not to leave these where they were.

## If you want one of these back

Fix it, move it under `src/`, and wire it into the build so the gates cover it.
Restoring the file without the wiring fails `dev/orphan_check.sh`. For the
protocol and zero-knowledge files specifically, note the standing instruction
that placeholder Noise/MLS/Signal/proof implementations must not be wired into
exports — a compiling file is not a working protocol.
