#!/usr/bin/env bash
#
# The release gate: the full set of checks a release candidate must pass.
#
# This script is run by hand. The CI workflow in .github/workflows/ runs its own
# smaller set of checks and does NOT invoke this file, so the two can and do
# drift -- a check added here is enforced on the release run only. Do not read a
# green CI badge as evidence that this gate passed.
#
# Environment:
#   ZIG                     Compiler to use (default: /opt/zig-dev/zig).
#   ZCRYPTO_GATE_KEEP=1     Keep this run's scratch directory and logs.
#   ZIG_GLOBAL_CACHE_DIR    Shared package cache (default: .scratch/zig-global-cache).

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

zig_bin="${ZIG:-/opt/zig-dev/zig}"

# ---------------------------------------------------------------------------
# Scratch layout
# ---------------------------------------------------------------------------
# Everything this run writes goes under one uniquely named directory. `mktemp`
# supplies the uniqueness, so two gate runs — concurrent or successive, retained
# or not — can never land on the same path and clobber each other's evidence.
# Nothing goes under /tmp: it is RAM-backed on the primary dev host, and a full
# gate run's caches are large enough to matter.
mkdir -p "$repo_root/.scratch"
run_dir="$(mktemp -d "$repo_root/.scratch/gate-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
log_dir="$run_dir/logs"
mkdir -p "$log_dir"

# The package cache is deliberately shared and outside the per-run directory.
# It holds fetched dependencies, not this invocation's output, and making it
# per-run would force a network fetch on every gate run — the opposite of what
# a release gate wants. It is still project-local rather than /tmp.
: "${ZIG_GLOBAL_CACHE_DIR:=$repo_root/.scratch/zig-global-cache}"
export ZIG_GLOBAL_CACHE_DIR
export ZIG_LOCAL_CACHE_DIR="$run_dir/zig-local-cache"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR"

keep_scratch="${ZCRYPTO_GATE_KEEP:-0}"

cleanup() {
    local status=$?
    if [[ "$keep_scratch" != "0" ]]; then
        echo "gate scratch retained: $run_dir"
    elif [[ $status -ne 0 ]]; then
        # A failing run's logs are the whole point, so keep them even when
        # retention was not requested.
        echo "gate failed; scratch retained for inspection: $run_dir"
    else
        # Remove only this invocation's directory. Never the shared package
        # cache, and never a sibling run's retained evidence.
        rm -rf "$run_dir"
    fi
    return $status
}
trap cleanup EXIT

stage_index=0
run_stage() {
    local name="$1"
    shift
    stage_index=$((stage_index + 1))
    local log
    log="$(printf '%s/%02d-%s.log' "$log_dir" "$stage_index" "$name")"
    printf '\n>>> %s\n' "$name"
    if ! "$@" >"$log" 2>&1; then
        printf 'FAILED: %s\n' "$name"
        echo "--- last 40 lines of $log ---"
        tail -40 "$log"
        return 1
    fi

    # A stage that exited 0 must not have left a failure diagnostic behind.
    #
    # The build runner captures a test binary's stderr through the `--listen=-`
    # protocol, and prints the step's argv under `failed command:` for *any*
    # output at all -- including a deliberate `std.debug.print` on a run where
    # every test passed. That produces a green stage whose log reads as a
    # failure, which cost time twice before it was traced. Exit status alone
    # cannot distinguish the two, so the log is checked as well.
    #
    # This is the right place for the check rather than one stage's business:
    # any test root can reintroduce it, and `expect_failure` is a separate
    # function, so genuinely-failing commands are unaffected.
    if grep -q 'failed command:' "$log"; then
        printf 'FAILED: %s exited 0 but its log reports a failed command\n' "$name"
        echo "A passing run must not print a failure diagnostic. The usual cause"
        echo "is a test body writing to stderr; move the output to a run step."
        echo "--- matching lines in $log ---"
        grep -n -B2 'failed command:' "$log"
        return 1
    fi
    return 0
}

# Runs a command that is REQUIRED to fail, for the REQUIRED reason.
#
#   expect_failure <name> <diagnostic-regex> <command...>
#
# A negative control is only evidence if it fails the way it is supposed to.
# This used to accept any nonzero exit, which means a typo in a flag, a renamed
# build step, a missing file or an unrelated compile error in a file the control
# has nothing to do with all read as "the guard works". Every one of those is a
# control that has silently stopped controlling anything -- the same failure mode
# the controls themselves exist to catch, one level up.
#
# So each control names the diagnostic it is asserting, and the log has to
# contain it.
expect_failure() {
    local name="$1"
    local expect="$2"
    shift 2
    stage_index=$((stage_index + 1))
    local log
    log="$(printf '%s/%02d-%s.log' "$log_dir" "$stage_index" "$name")"
    printf '\n>>> %s (must fail: %s)\n' "$name" "$expect"
    if "$@" >"$log" 2>&1; then
        printf 'FAILED: %s succeeded but was required to fail\n' "$name"
        echo "--- last 40 lines of $log ---"
        tail -40 "$log"
        return 1
    fi
    if ! grep -Eq -- "$expect" "$log"; then
        printf 'FAILED: %s failed, but not for the reason it asserts\n' "$name"
        printf 'expected a line matching: %s\n' "$expect"
        echo "The control fired on something else, so it is no longer evidence"
        echo "for the guard it names. Fix the cause, or update the pattern if the"
        echo "diagnostic legitimately changed."
        echo "--- last 40 lines of $log ---"
        tail -40 "$log"
        return 1
    fi
    return 0
}

# Run a build step and assert that every artifact it actually compiled was
# compiled in the requested mode, for the host.
#
# This exists because the requested mode was not a checked property. A test root
# with no optimize mode of its own falls back to Debug, so
# `zig build test -Doptimize=ReleaseSafe` reported success while two backend test
# roots compiled in Debug -- the ReleaseSafe stage was not testing ReleaseSafe
# behaviour for those artifacts, and nothing in the gate said so. Reading the mode
# back out of the build's own summary turns the request into an assertion.
#
# `$4`/`$5` are the mode and target: summary lines read
# `compile <kind> <name> <mode> <target> <status> ...`. Cached steps still carry
# both, so this is meaningful on a warm cache.
#
# One artifact is deliberately exempt. tests/insecure_option_guard.zig drives
# `security.checkInsecureOption`'s refusing branch, which only exists in a
# release build, so build.zig pins it to ReleaseSafe rather than letting it
# follow `-Doptimize`. Under a Debug stage that is a legitimate mismatch.
#
# It is named rather than the rule being relaxed, and its pinned mode is
# asserted rather than merely tolerated: what this check exists to catch is an
# artifact pinned by accident, and a guard that quietly went back to inheriting
# the mode would stop exercising the branch in every Debug run while still
# printing success. Its presence in a `test` build is required for the same
# reason -- dropping it from the step would leave the branch untested with the
# whole gate green.
pinned_artifact='zcrypto-insecure-option-guard'
pinned_artifact_mode='safe'

checked_mode_build() {
    local want="$1"
    local step="$2"
    shift
    local out
    if ! out="$("$zig_bin" build "$@" --summary all 2>&1)"; then
        printf '%s\n' "$out"
        return 1
    fi
    printf '%s\n' "$out"

    local compiled
    compiled="$(printf '%s\n' "$out" |
        grep -oE 'compile (test|exe|lib) [^ ]+ [a-z]+ [^ ]+' || true)"

    # A build that compiled nothing would otherwise satisfy "every artifact
    # matched" and pass without checking anything.
    if [[ -z "$compiled" ]]; then
        echo "mode check: the build summary listed no compiled artifacts" >&2
        return 1
    fi

    if [[ "$step" == test ]] && ! printf '%s\n' "$compiled" | grep -q " $pinned_artifact "; then
        echo "mode check: $pinned_artifact was not built by this test step" >&2
        return 1
    fi

    local bad
    bad="$(printf '%s\n' "$compiled" |
        awk -v want="$want" -v pinned="$pinned_artifact" -v pinned_want="$pinned_artifact_mode" '
            $3 == pinned { if ($4 != pinned_want || $5 != "native") print; next }
            $4 != want || $5 != "native" { print }
        ')"
    if [[ -n "$bad" ]]; then
        echo "mode check: artifacts not compiled as $want/native" >&2
        echo "($pinned_artifact is exempt and must be $pinned_artifact_mode/native):" >&2
        printf '%s\n' "$bad" >&2
        return 1
    fi

    printf 'mode check: %s artifact(s), all %s native\n' \
        "$(printf '%s\n' "$compiled" | wc -l)" "$want"
}

# ---------------------------------------------------------------------------
# 1. Compiler identity
# ---------------------------------------------------------------------------
# Recorded, never asserted. The self-hosted runners track zig-dev on a nightly
# cron, so the installed compiler moves without anyone touching this tree. A
# version assertion there fails on upstream publishing an unrelated nightly --
# an infrastructure event, not a defect here -- and a gate that goes red for
# reasons nobody caused is a gate people learn to ignore.
#
# Compiler incompatibility does not need its own check: it shows up as a real
# build, format or test failure in the stages below, which is both stricter and
# more honest than comparing version strings. `minimum_zig_version` in the
# manifest is a lower bound for consumers and is not this script's business.
actual_zig="$("$zig_bin" version)"

{
    echo "zig binary:    $zig_bin"
    echo "zig version:   $actual_zig"
    echo "run directory: $run_dir"
} | tee "$log_dir/00-compiler-identity.log"

# ---------------------------------------------------------------------------
# 2. Source hygiene
# ---------------------------------------------------------------------------
# Globbed rather than listed: the explicit list had already fallen behind by one
# script, so every new harness was silently exempt from syntax checking.
run_stage shellcheck-syntax bash -n dev/*.sh
run_stage whitespace git diff --check

# Format coverage spans everything a reviewer reads: sources, examples, the
# Zig embedded in docs, the build script, the manifest, and the test roots.
#
# `dev/` is in the list because the gate's own Zig now lives there — the WASM
# controls and probes. The line above checks dev/*.sh for syntax and stopped at
# the shell scripts, so those files would have been exempt from both.
run_stage format "$zig_bin" fmt --check src/ examples/ docs/ dev/ build.zig build.zig.zon tests/

# Every other stage below is blind to a source file nothing imports: it is never
# compiled, so no test can fail on it and the API surface check cannot see it,
# but it still ships because build.zig.zon lists "src" in .paths. Thirteen had
# accumulated, eight of which no longer compiled.
run_stage orphan-sources "$repo_root/dev/orphan_check.sh"

# ---------------------------------------------------------------------------
# 3. Tests in both modes
# ---------------------------------------------------------------------------
# A ReleaseSafe *library build* proves nothing about ReleaseSafe *behaviour*.
# Safety checks, integer overflow traps, and optimizer-visible UB only show up
# when the tests themselves run in that mode.
run_stage test-debug checked_mode_build debug test
run_stage test-releasesafe checked_mode_build safe test -Doptimize=ReleaseSafe

# Proves the stages above actually compile the public API surface.
#
# Zig type-checks a function where it is referenced, not where it is defined, so
# an exported function no test happens to call is never compiled and ships
# broken with the suite green. That was not hypothetical: src/api_surface.zig
# found eighteen such entry points on the run that introduced it, among them
# WasmCrypto.hkdf (wrong arity, and salt and IKM transposed) and
# security.isReleaseBuild, the guard behind insecure_skip_verify.
#
# api_surface.zig closes that, but it can only be trusted while it still
# descends -- a broken refRecursive would keep the suite green and the surface
# unchecked, which is indistinguishable from correct without this stage.
# -Dapi-surface-control adds one exported function that cannot compile and
# nothing calls; if the build succeeds, the check has stopped working.
#
# The required diagnostic is the reference trace, not the error text: what is
# being asserted is that the compiler reached the broken function *through*
# api_surface.zig's recursion. A plain "expected 2 argument(s)" would also match
# an unrelated arity error somewhere else in the tree.
expect_failure api-surface-control \
    'refRecursive.*src/api_surface\.zig' \
    "$zig_bin" build test -Dapi-surface-control=true

# ---------------------------------------------------------------------------
# 3b. Published known-answer vectors, once per CPU target
# ---------------------------------------------------------------------------
# `std.crypto` selects its AES, ChaCha20 and SHA-256 implementations at comptime
# from the build target. The stages above only ever build for one target, so
# they exercise one of those selections and say nothing about the other. These
# two run the same published vectors -- GCM spec Appendix B, RFC 8439, FIPS
# 180-4, RFC 5869 -- against both, so a generic-CPU deployment is covered by
# evidence rather than by the assumption that it behaves like the build host.
#
# `-Dexpect-aes-hardware` is what stops this pair from being decorative. A stage
# that failed to apply its `-Dcpu` would otherwise still pass, and the run would
# report coverage of a backend it never compiled -- the same class of defect as
# a "hardware accelerated" flag that was true for a software build.
run_stage kat-cpu-generic "$zig_bin" build kat -Dcpu=x86_64 -Dexpect-aes-hardware=false
run_stage kat-cpu-native "$zig_bin" build kat -Dcpu=native -Dexpect-aes-hardware=true

# Proves the assertion above is live rather than vacuously true: the generic
# target must *fail* when told to expect the hardware backend. Without this, a
# broken `expect_aes_hardware` check would make both stages pass unconditionally
# and the pair would again be proving nothing.
expect_failure kat-cpu-generic-control \
    "build target selects the AES backend the caller asked for' failed" \
    "$zig_bin" build kat -Dcpu=x86_64 -Dexpect-aes-hardware=true

# ---------------------------------------------------------------------------
# 4. Feature matrix
# ---------------------------------------------------------------------------
# `zig build test` rather than `zig build`, because tests/feature_surface.zig
# calls real API bodies for whichever features are on. Building alone would let
# an unreachable-but-broken feature namespace pass.
#
# Every configuration runs in both modes, for the reason section 3 already gives
# for the default configuration: safety checks, overflow traps and
# optimizer-visible UB only appear when the tests themselves run in that mode.
# Applying that argument to the default build and not to the feature axis left
# TLS, PQ and the all-features surface with no ReleaseSafe behavioural coverage
# at all. It costs a second cold compile per configuration, which is the price of
# the stages meaning what their names say.
feature_config() {
    local name="$1"
    shift
    run_stage "config-$name-debug" checked_mode_build debug test "$@" || return 1
    run_stage "config-$name-releasesafe" checked_mode_build safe test \
        -Doptimize=ReleaseSafe "$@" || return 1
}

feature_config default
feature_config minimal-core \
    -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dblockchain=false \
    -Dvpn=false -Dwasm=false -Denterprise=false -Dzkp=false -Dasync=false
feature_config tls \
    -Dtls=true -Dhardware-accel=true -Dvpn=false -Dwasm=false -Dasync=false
feature_config async -Dasync=true
feature_config post-quantum -Dpost-quantum=true -Dexperimental-crypto=true
feature_config all-features \
    -Dtls=true -Dpost-quantum=true -Dhardware-accel=true -Dblockchain=true \
    -Dvpn=true -Dwasm=true -Denterprise=true -Dzkp=true -Dasync=true \
    -Dexperimental-crypto=true

# The hardware backends are their own axis: `-Dtpm`/`-Dpkcs11` are independent
# of every feature flag above, so none of those stages compiles a line of
# src/hsm/tpm2.zig or src/hsm/pkcs11.zig. Without these three stages the real
# backend sources -- the entire subject of this update -- reach a release
# candidate having never been given to the compiler by this gate.
#
# These run the absent-provider and error-path tests, which need no device.
# Execution against a live simulator and a live token is in section 8, because
# that needs daemons this stage cannot assume.
#
# Both modes here too, and these are the stages that motivated the mode check:
# the backend test roots are exactly the artifacts that were compiling in Debug
# under a ReleaseSafe request.
feature_config tpm-backend -Dtpm=true
feature_config pkcs11-backend -Dpkcs11=true
feature_config both-backends -Dtpm=true -Dpkcs11=true

# ---------------------------------------------------------------------------
# 5. Forbidden feature combinations
# ---------------------------------------------------------------------------
# Every experimental family must refuse to build without the explicit opt-in.
# These are the checks that keep placeholder crypto out of a default build, so
# they are asserted to fail rather than assumed to.
#
# Each must fail on the opt-in guard specifically. Without the pattern these
# passed on any configure error at all, so renaming one of the build options
# would have turned all four into no-ops that still reported success.
experimental_optin_error='ExperimentalCryptoRequiresOptIn'
expect_failure reject-post-quantum-without-optin "$experimental_optin_error" \
    "$zig_bin" build -Dpost-quantum=true
expect_failure reject-blockchain-without-optin "$experimental_optin_error" \
    "$zig_bin" build -Dblockchain=true
expect_failure reject-enterprise-without-optin "$experimental_optin_error" \
    "$zig_bin" build -Denterprise=true
expect_failure reject-zkp-without-optin "$experimental_optin_error" \
    "$zig_bin" build -Dzkp=true

# ---------------------------------------------------------------------------
# 6. External consumer inheritance
# ---------------------------------------------------------------------------
# Proves a downstream package's requested target and optimization mode actually
# reach the zcrypto module, with a control that must fail.
consumer_dir="$repo_root/tests/consumer"
consumer_check() {
    (cd "$consumer_dir" && ZIG_LOCAL_CACHE_DIR="$run_dir/consumer-cache" "$@")
}
run_stage consumer-debug consumer_check "$zig_bin" build run
run_stage consumer-releasesafe consumer_check "$zig_bin" build run -Doptimize=ReleaseSafe
expect_failure consumer-pinned-debug-control \
    'DependencyBuildSettingsNotInherited' \
    consumer_check "$zig_bin" build run -Doptimize=ReleaseSafe -Dpin-dependency-debug=true

# ---------------------------------------------------------------------------
# 7. C ABI consumer
# ---------------------------------------------------------------------------
# Compiles and RUNS tests/ffi/consumer.c against the installed static library
# through include/zcrypto.h. A syntax-only check of the header would not have
# caught either defect this stage exists for.
#
# Debug and ReleaseSafe are both mandatory, and not for symmetry. The FFI null
# guards compare a pointer against zero; when the parameter is a non-optional
# Zig pointer the compiler may assume it is non-null and delete the comparison,
# so NULL is rejected in Debug and dereferenced in every optimized build. A
# Debug-only run reports a clean pass on exactly that bug. ReleaseSafe is where
# it surfaces.
# ReleaseFast is here for positive assurance in the mode downstream projects
# actually ship, not because it detects a class ReleaseSafe misses. That
# distinction was measured rather than assumed: reintroducing the historical
# unbounded `header_len + 16` arithmetic fails all three modes, and ReleaseSafe
# is in fact the better *diagnostic* -- it reports `panic: integer overflow`,
# while ReleaseFast only manages a SEGV. So the justification is not "catches
# more bugs".
#
# What this stage establishes is that the library is correct with the safety
# checks compiled out -- 569 checks pass, rather than merely failing loudly.
# Without it, nothing in the gate showed the library produced right answers in
# ReleaseFast at all, which is the build most consumers link against.
run_stage ffi-consumer-debug checked_mode_build debug ffi-consumer
run_stage ffi-consumer-releasesafe checked_mode_build safe ffi-consumer -Doptimize=ReleaseSafe
run_stage ffi-consumer-releasefast checked_mode_build fast ffi-consumer -Doptimize=ReleaseFast

# The C ABI is compiled unconditionally, so the harness must hold in the
# configurations a downstream consumer might actually build against — including
# the minimal one, where most feature namespaces are off.
#
# Both modes, for the same reason as above rather than for symmetry: ReleaseSafe
# is where a deleted null guard surfaces, and Debug is where a safety-checked
# failure reports its cause instead of trapping in optimized code. Neither mode
# subsumes the other, and these configurations were previously ReleaseSafe-only.
ffi_consumer_config() {
    local name="$1"
    shift
    run_stage "ffi-consumer-$name-debug" checked_mode_build debug ffi-consumer "$@" || return 1
    run_stage "ffi-consumer-$name-releasesafe" checked_mode_build safe ffi-consumer \
        -Doptimize=ReleaseSafe "$@" || return 1
    run_stage "ffi-consumer-$name-releasefast" checked_mode_build fast ffi-consumer \
        -Doptimize=ReleaseFast "$@" || return 1
}

ffi_consumer_config minimal \
    -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dblockchain=false \
    -Dvpn=false -Dwasm=false -Denterprise=false -Dzkp=false -Dasync=false
ffi_consumer_config post-quantum -Dpost-quantum=true -Dexperimental-crypto=true

# Every exported symbol must be declared in the public header, and every
# declaration must resolve to a real symbol. Linking the harness only proves the
# prototypes it happens to call; it cannot notice an export that was never
# declared, which is how a C ABI grows an undocumented entry point.
#
# SCOPE: this is a Linux/GNU-binutils *packaging* check, not a native-platform
# ABI gate, and it is deliberately not written to pretend otherwise. It depends
# on GNU `nm --defined-only`, on GNU nm's output columns, on the `lib*.a` archive
# naming, and on symbols carrying no leading underscore. Every one of those
# differs somewhere that matters: BSD and macOS `nm` take different flags and
# macOS prefixes C symbols with `_`; Windows produces `zcrypto.lib`. Writing
# those branches here would mean writing them blind, since none of those
# toolchains is available to run them against, and an unverified portability
# branch is worse than an honest restriction.
#
# What covers the other platforms is the C ABI consumer above: it compiles and
# links tests/ffi/consumer.c against the installed header and library and *runs*
# it, using only the C toolchain, so it is the portable half of this evidence.
# What it cannot do is notice an export the header never declared, which is why
# this symbol-level check exists in addition to it.
#
# The preconditions are asserted rather than assumed, because the failure mode
# otherwise is a confusing `nm: unrecognized option` or `grep: invalid option`
# in the middle of a release run. It fails rather than skips: a release should
# not be cut from a host where this check silently did not happen.
ffi_header_agreement() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "ffi-header-agreement is a Linux/GNU-binutils packaging check;" >&2
        echo "host is $(uname -s). The portable C ABI evidence is the" >&2
        echo "ffi-consumer stages above, which run everywhere." >&2
        return 1
    fi
    if ! nm --version 2>/dev/null | grep -qi 'GNU\|binutils'; then
        echo "ffi-header-agreement needs GNU nm (binutils); found:" >&2
        nm --version 2>&1 | head -1 >&2
        return 1
    fi

    local install_dir="$run_dir/ffi-install"
    "$zig_bin" build --prefix "$install_dir"

    local archive="$install_dir/lib/libzcrypto.a"
    # The name is a literal because the scope above fixes the platform, but its
    # existence is still checked: a renamed or relocated artifact would
    # otherwise reach `nm` as a missing-file error rather than as this.
    if [[ ! -f "$archive" ]]; then
        echo "expected static archive not found: $archive" >&2
        return 1
    fi

    nm --defined-only "$archive" \
        | awk '$2 == "T" { print $3 }' \
        | grep '^zcrypto_' | sort -u >"$run_dir/ffi-exports.txt"
    # POSIX sed rather than `grep -oP`: PCRE and `\K` are a GNU grep extension,
    # and this extraction needs neither. Verified to produce byte-identical
    # output to the PCRE form it replaces.
    sed -n 's/^[[:space:]]*zcrypto_result_t \([A-Za-z0-9_][A-Za-z0-9_]*\).*/\1/p' \
        include/zcrypto.h | sort -u >"$run_dir/ffi-header.txt"

    # Neither side may be empty. `diff` of two empty files exits 0, so a parse
    # that silently stopped matching would report agreement rather than a
    # problem. `pipefail` already aborts the fully-empty case above; this is the
    # assertion for it rather than a side effect relied upon from a distance.
    if [[ ! -s "$run_dir/ffi-exports.txt" || ! -s "$run_dir/ffi-header.txt" ]]; then
        echo "symbol extraction produced an empty list; the check would" >&2
        echo "otherwise compare nothing against nothing and pass." >&2
        return 1
    fi

    # Left side is the header, right side the library, so a diff reads as
    # "what the header promises" versus "what the library provides".
    diff -u "$run_dir/ffi-header.txt" "$run_dir/ffi-exports.txt"
}
run_stage ffi-header-agreement ffi_header_agreement

# ---------------------------------------------------------------------------
# 7b. The C ABI as seen by a compiler that is not Zig's
# ---------------------------------------------------------------------------
# The ffi-consumer stages above compile consumer.c with the clang Zig bundles.
# That proves the header is self-consistent, but not that it is valid C to
# anyone else, and it cannot detect a struct layout or calling convention that
# is merely self-consistent: both sides of the comparison come from the same
# toolchain. This stage builds the same harness with the *system* compiler and
# links it against the *installed* archive, so the header, the layout, the
# calling convention and the archive's linkability are checked by an
# independent implementation.
#
# This had been done once by hand and never recorded, which is the failure mode
# that made it worth a stage: the evidence expired silently and nothing noticed.
#
# It fails rather than skips, for the same reason as the stage above -- a
# release should not be cut from a host where the check quietly did not run.
ffi_consumer_system_cc() {
    local cc_bin="${CC:-cc}"
    if ! command -v "$cc_bin" >/dev/null 2>&1; then
        echo "no system C compiler ($cc_bin) found. This stage exists to check" >&2
        echo "the ABI with a toolchain other than Zig's; skipping it would" >&2
        echo "leave that unverified while the run still reported success." >&2
        return 1
    fi

    # Captured whole, then split, rather than piped into `grep -q` or `head`:
    # those exit as soon as they have what they need, which SIGPIPEs the
    # compiler, and under `pipefail` that surfaces as exit 141. Here that would
    # read as "not Zig" and let a `cc` that is really `zig cc` pass as
    # independent -- the precise thing this stage exists to rule out.
    local cc_all cc_version
    cc_all="$("$cc_bin" --version 2>&1 || true)"
    cc_version="${cc_all%%$'\n'*}"
    case "$cc_version" in
        *zig* | *Zig* | *ZIG*)
            echo "$cc_bin reports as Zig ($cc_version); this stage needs a" >&2
            echo "compiler independent of the one that built the library." >&2
            return 1
            ;;
    esac
    echo "independent C compiler: $cc_version"

    local install_dir="$run_dir/ffi-syscc-install"
    "$zig_bin" build --prefix "$install_dir"

    local archive="$install_dir/lib/libzcrypto.a"
    local header_dir="$install_dir/include"
    if [[ ! -f "$archive" || ! -f "$header_dir/zcrypto.h" ]]; then
        echo "installed archive or header missing under $install_dir" >&2
        return 1
    fi

    # Same warning set as the Zig-built harness, so the independent compiler is
    # held to the same standard rather than a laxer one that would let a
    # narrowing conversion through here and nowhere else.
    local bin="$run_dir/ffi-consumer-syscc"
    "$cc_bin" -std=c11 -Wall -Wextra -Werror -Wconversion \
        -I"$header_dir" tests/ffi/consumer.c "$archive" -o "$bin"

    local out="$run_dir/ffi-consumer-syscc.log"
    "$bin" >"$out" 2>&1

    # Exit status alone is not evidence. A harness that ran no checks at all
    # also exits 0, so the reported totals are asserted: some checks ran, and
    # none failed. This is the difference between a result and smoke output.
    local summary
    summary="$(sed -n 's/^\([0-9][0-9]*\) checks, \([0-9][0-9]*\) failures$/\1 \2/p' "$out")"
    if [[ -z "$summary" ]]; then
        echo "consumer produced no recognisable summary line:" >&2
        tail -5 "$out" >&2
        return 1
    fi
    local checks="${summary%% *}" failures="${summary##* }"
    if [[ "$checks" -eq 0 ]]; then
        echo "consumer reported 0 checks; it linked and ran but tested nothing." >&2
        return 1
    fi
    if [[ "$failures" -ne 0 ]]; then
        echo "consumer reported $failures failures:" >&2
        cat "$out" >&2
        return 1
    fi
    echo "$checks checks, $failures failures (built by $cc_bin)"
}
run_stage ffi-consumer-system-cc ffi_consumer_system_cc

# ---------------------------------------------------------------------------
# 7c. What a packager actually gets
# ---------------------------------------------------------------------------
# The C ABI is deliberately static-only: one `.a` and one header, no `.so`. That
# is a supported position rather than an omission, but it is only meaningful if
# something checks that the install prefix really contains that and nothing
# else. It previously did not, and the prefix had quietly acquired
# `bin/zcrypto-ffi-consumer` -- the ABI test harness -- which no release should
# ship and which nothing referenced.
#
# The expected set is written out in full rather than pattern-matched. A
# manifest that a new artifact silently satisfies is not a manifest; making an
# addition or a removal fail here forces it to be a decision. The list is for
# the default configuration, which is what this stage builds.
shipped_artifacts() {
    local install_dir="$run_dir/ship-install"
    rm -rf "$install_dir"
    "$zig_bin" build --prefix "$install_dir"

    (cd "$install_dir" && find . -type f | sed 's|^\./||' | sort) >"$run_dir/ship-actual.txt"

    cat >"$run_dir/ship-expected.txt" <<'EOF'
bin/advanced-features-example
bin/core-stable-example
bin/zcrypto-bench
bin/zcrypto-demo
include/zcrypto.h
lib/libzcrypto.a
EOF

    if ! diff -u "$run_dir/ship-expected.txt" "$run_dir/ship-actual.txt"; then
        echo "installed artifact set changed; update the manifest deliberately" >&2
        return 1
    fi

    # Static-only is the claim, so the absence of a shared object is asserted
    # rather than inferred from the manifest matching.
    local shared
    shared="$(find "$install_dir" \( -name '*.so' -o -name '*.so.*' -o -name '*.dll' \
        -o -name '*.dylib' \) -print)"
    if [[ -n "$shared" ]]; then
        echo "shared libraries present in a static-only distribution:" >&2
        printf '%s\n' "$shared" >&2
        return 1
    fi

    # And that the archive is genuinely an archive: `file` distinguishes a real
    # `ar` archive from a linker script or a renamed shared object, either of
    # which would satisfy the name check above while breaking static linking.
    local kind
    kind="$(file -b "$install_dir/lib/libzcrypto.a")"
    case "$kind" in
        *"ar archive"*) ;;
        *)
            echo "lib/libzcrypto.a is not an ar archive: $kind" >&2
            return 1
            ;;
    esac

    printf 'static-only distribution verified: %s file(s), no shared objects\n' \
        "$(wc -l <"$run_dir/ship-actual.txt")"
}
run_stage shipped-artifacts shipped_artifacts

# ---------------------------------------------------------------------------
# 8. Runnable examples and the experimental PQ build
# ---------------------------------------------------------------------------
# These inherit the exported cache variables above, so they write into this
# run's scratch directory rather than their own defaults.
run_stage smoke-runs "$repo_root/dev/smoke_run.sh"
run_stage experimental-pq "$repo_root/dev/experimental_pq_check.sh"

# ---------------------------------------------------------------------------
# 9. Provider execution against a live simulator and a live token
# ---------------------------------------------------------------------------
# The stages in section 4 prove the backends compile and that their absent and
# error paths behave. They do not prove a single TPM or Cryptoki command was
# ever sent. These do, and they are the only stages in this file that talk to
# something outside the build.
#
# Each provisions its own throwaway endpoint and tears it down; neither touches
# the host's real TPM or any existing token database. Real hardware is a
# deliberately separate, operator-run step -- see the header of dev/tpm_swtpm.sh
# -- because creating objects on a host's actual TPM is not a thing a release
# script gets to decide to do.
#
# They are required, not best-effort: the scripts fail if their prerequisite is
# missing rather than reporting success having tested nothing.
run_stage tpm-simulator "$repo_root/dev/tpm_swtpm.sh"
run_stage pkcs11-softoken "$repo_root/dev/pkcs11_softoken.sh"

# ---------------------------------------------------------------------------
# 10. WebAssembly
# ---------------------------------------------------------------------------
# Every stage above runs on the host. wasm32 differs from it in ways that are
# invisible from here and that this library is directly exposed to: `usize` is
# 32 bits, there are no 64-bit atomics, and `single_threaded` is true. Each of
# those has already produced a real defect in this tree.
#
# Cross-compiling is not a substitute. `zig build -Dtarget=wasm32-wasi` exited 0
# for a long time while the library did not compile for wasm32 at all -- Zig
# only analyses what is reached, and the examples reach very little. The check
# builds and *runs* the test suite, which is what analyses all of it.
#
# Required rather than best-effort, and it fails if node is absent instead of
# skipping: a WASM claim that is only checked when a tool happens to be present
# is a claim that goes unchecked on the machine that matters.
run_stage wasm "$repo_root/dev/wasm/check.sh"

printf '\nrelease checks passed (zig %s)\n' "$actual_zig"
