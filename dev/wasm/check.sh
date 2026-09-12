#!/usr/bin/env bash
#
# The WASM gate: build zcrypto for wasm32-wasi and run it.
#
# Scope, stated once so nothing below has to be read as a broader claim. This
# checks wasm32-wasi under Node's WASI preview1. It says nothing about a
# browser, which provides no WASI at all, and nothing about wasm32-freestanding
# beyond the one compile-time assertion at the end.
#
# Three things are established, in order:
#
#   1. dev/wasm/run.mjs reports what actually happened. Checked against
#      dev/wasm/control.zig, which produces each outcome on demand, and against
#      the off-diagonal: every wrong expectation must fail. Without this the
#      rest of the file is a list of assertions checked by a program that has
#      never been shown to be able to disagree.
#   2. The library's own test suite passes on wasm32. Not a subset transcribed
#      into a bespoke wasm program -- the real roots, so the vectors cannot
#      drift apart from the native ones.
#   3. The entropy contract holds under a host CSPRNG that works and one that
#      is broken, exercised through zcrypto's own API rather than through a
#      direct `random_get` call.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
zig_bin="${ZIG:-/opt/zig-dev/zig}"

cd "$repo_root"

: "${ZIG_GLOBAL_CACHE_DIR:=$repo_root/.scratch/zig-global-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=$repo_root/.scratch/wasm-check-cache}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

work_dir="$(mktemp -d -p "$repo_root/.scratch" wasm-check.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

if ! command -v node >/dev/null 2>&1; then
    echo "wasm check: node is required to execute wasm32-wasi modules" >&2
    exit 1
fi

target="wasm32-wasi"
runner="dev/wasm/run.mjs"

# Run one module and require a specific outcome. `run.mjs` exits non-zero on a
# mismatch, so `set -e` carries the failure -- there is no status to forget to
# check here.
expect() {
    local label="$1"
    shift
    printf '  %-58s' "$label"
    if node "$runner" "$@" >"$work_dir/out.log" 2>&1; then
        printf 'ok\n'
    else
        printf 'FAILED\n'
        cat "$work_dir/out.log" >&2
        return 1
    fi
}

# Require the runner to *reject* an expectation. The argument is what a caller
# would have written; the point is that writing the wrong thing must not pass.
reject() {
    local label="$1"
    shift
    printf '  %-58s' "$label"
    if node "$runner" "$@" >"$work_dir/out.log" 2>&1; then
        printf 'FAILED (runner accepted a wrong expectation)\n'
        cat "$work_dir/out.log" >&2
        return 1
    fi
    printf 'ok\n'
}

echo "== runner controls (target: $target, runtime: node WASI preview1)"

control="$work_dir/control.wasm"
"$zig_bin" build-exe dev/wasm/control.zig -target "$target" -femit-bin="$control" \
    --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR"

# The diagonal: each outcome, correctly predicted.
expect "control ok => ok"                 --module="$control" --arg=ok           --expect=ok
expect "control exit 1 => nonzero"        --module="$control" --arg=exit_nonzero --expect=nonzero
expect "control trap => trap"             --module="$control" --arg=trap         --expect=trap

# The off-diagonal. A runner that reported success unconditionally -- which is
# what the harnesses this replaces did, printing WASI_EXIT=<n> and exiting 0 --
# passes every line above and fails every line here.
reject "control exit 1 is not ok"         --module="$control" --arg=exit_nonzero --expect=ok
reject "control trap is not ok"           --module="$control" --arg=trap         --expect=ok
reject "control trap is not nonzero"      --module="$control" --arg=trap         --expect=nonzero
reject "control ok is not a trap"         --module="$control" --arg=ok           --expect=trap

# Entropy modes, against a control that calls `random_get` directly and holds no
# zcrypto code. This separates "the runner can present a broken host" from "the
# library reacts correctly to one", which the probes below then test.
expect "control entropy, working host => ok"     --module="$control" --arg=entropy --expect=ok         --entropy=ok
expect "control entropy, EIO host => nonzero"    --module="$control" --arg=entropy --expect=nonzero    --entropy=failing
expect "control entropy, absent import => link"  --module="$control" --arg=entropy --expect=link-error --entropy=missing

echo "== library test suite on $target"

# `zig build test` cannot spawn a wasm binary; build.zig routes test artifacts
# for a wasm target through the runner above. Every root is analysed here, which
# is what makes this different from `zig build -Dtarget=wasm32-wasi`: that only
# compiles what the examples reach, and exited 0 for a long time while the
# library itself did not compile for this target at all.
"$zig_bin" build test -Dtarget="$target" --summary none

echo "== entropy contract through zcrypto's API"

"$zig_bin" build -Dtarget="$target" --summary none
entropy_probe="zig-out/bin/wasm-entropy_probe.wasm"
deterministic_probe="zig-out/bin/wasm-deterministic_probe.wasm"

# Working host: both APIs must return bytes. The probe also rejects an all-zero
# buffer, so "succeeded" cannot mean "was never written".
expect "rand.fillChecked, working host => ok"    --module="$entropy_probe" --arg=checked   --expect=ok --entropy=ok
expect "rand.fill, working host => ok"           --module="$entropy_probe" --arg=unchecked --expect=ok --entropy=ok

# Broken host: fail closed. `fillChecked` returns the error; `fill` panics,
# which lowers to a wasm trap. Neither may hand back a buffer.
expect "rand.fillChecked, EIO host => error"     --module="$entropy_probe" --arg=checked   --expect=nonzero --entropy=failing
expect "rand.fill, EIO host => panic"            --module="$entropy_probe" --arg=unchecked --expect=trap    --entropy=failing

# Deterministic primitives do not consult the host CSPRNG: same vectors, same
# result, on a host whose `random_get` returns EIO to every call.
expect "sha256+hkdf vectors, EIO host => ok"     --module="$deterministic_probe" --expect=ok --entropy=failing

# Recorded rather than assumed: Zig's wasm32-wasi preamble imports the whole
# preview1 syscall set regardless of what the program uses, so *every* module
# built for this target needs the host to provide `random_get` in order to
# instantiate, including one that only hashes. Anyone shipping zcrypto to a
# restricted WASI host needs to know that, and if a future Zig stops doing it
# this line turns red and the finding gets revisited instead of quietly aging.
expect "even a pure-hash module needs the import" --module="$deterministic_probe" --expect=link-error --entropy=missing

echo "== freestanding entropy refuses to compile"

# wasm32-freestanding has no host interface at all, so there is no entropy to
# be had. src/rand.zig answers with @compileError rather than a PRNG, and this
# checks that the answer is still a compile error: a fallback added there would
# hand out predictable key material that looks exactly like CSPRNG output.
freestanding_log="$work_dir/freestanding.log"
if "$zig_bin" build-obj -target wasm32-freestanding \
    -femit-bin="$work_dir/freestanding.o" \
    --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
    --dep zcrypto_rand -Mroot=dev/wasm/freestanding_entropy.zig -Mzcrypto_rand=src/rand.zig \
    >"$freestanding_log" 2>&1; then
    echo "  freestanding build succeeded; entropy fallback may have been added" >&2
    exit 1
fi
if ! grep -q "no entropy source exists on a freestanding target" "$freestanding_log"; then
    echo "  freestanding build failed, but not for the expected reason:" >&2
    cat "$freestanding_log" >&2
    exit 1
fi
printf '  %-58sok\n' "rand refuses freestanding with its own message"

echo
echo "wasm check passed ($target, node WASI preview1)"
