#!/usr/bin/env bash
#
# Native platform evidence for one host (Linux, macOS).
#
# Run this ON the machine being certified, not on the dev host with a
# `-Dtarget=` flag. A cross-compiled binary proves the code compiles for a
# platform; it proves nothing about running there, which is where the platform
# branches in this library actually differ. The script refuses to produce a
# record if the build is not native -- see `assert_native` below.
#
# Windows uses `dev/platform_check.ps1`, which emits the same record format.
# It is a separate file rather than this one under a shim because the only
# `bash` on the Windows lab host is the WSL launcher: running this there would
# certify Linux and label the result Windows.
#
# Output is a machine-readable evidence record on stdout. Per-stage logs are
# written under a run directory and are retained on failure.
#
# Environment:
#   ZIG                        Compiler to use (default: first `zig` on PATH).
#   ZCRYPTO_PLATFORM_KEEP=1    Keep this run's scratch directory and logs.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root" || exit 127

zig_bin="${ZIG:-zig}"
if ! command -v "$zig_bin" >/dev/null 2>&1; then
    echo "platform_check: no compiler: $zig_bin" >&2
    exit 127
fi

mkdir -p "$repo_root/.scratch"
run_dir="$(mktemp -d "$repo_root/.scratch/platform-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
log_dir="$run_dir/logs"
mkdir -p "$log_dir"

export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$repo_root/.scratch/zig-global-cache}"
export ZIG_LOCAL_CACHE_DIR="$run_dir/zig-local-cache"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR"

fail_count=0
pass_count=0
runners_pending=0

cleanup() {
    local status=$?
    if [[ "${ZCRYPTO_PLATFORM_KEEP:-0}" != "0" || $fail_count -ne 0 ]]; then
        echo "LOGS|$run_dir"
    else
        rm -rf "$run_dir"
    fi
    return $status
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
# Everything here is read out of the machine and the toolchain rather than
# passed in, so a record cannot be mislabelled by the caller that requested it.

zig_version="$("$zig_bin" version 2>/dev/null)"

# `zig env` reports the *detected native* target, including the OS and libc
# versions it probed for. That is the identity that matters for this record:
# two hosts running the same `uname` can still resolve different glibc versions
# and select different code.
zig_target="$("$zig_bin" env 2>/dev/null | sed -n 's/^[[:space:]]*\.target = "\(.*\)",$/\1/p')"

emit_identity() {
    echo "ZCRYPTO_PLATFORM_EVIDENCE|v1"
    echo "host.uname|$(uname -srm)"
    echo "host.name|$(uname -n)"
    echo "host.utc|$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "zig.exe|$(command -v "$zig_bin")"
    echo "zig.version|$zig_version"
    echo "zig.native_target|$zig_target"
    # The tree under test, not the tree the driver believes it sent. A dirty
    # worktree is normal here and is recorded rather than rejected: this gate
    # runs against work in progress far more often than against a tag.
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
        echo "repo.commit|$(git rev-parse HEAD 2>/dev/null)"
        if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
            echo "repo.worktree|dirty"
        else
            echo "repo.worktree|clean"
        fi
    else
        # The driver ships a source snapshot, not a repository, so this is the
        # normal case on a remote host. The driver stamps the origin instead.
        echo "repo.commit|unavailable-no-git-dir"
        echo "repo.worktree|unknown"
    fi
    if [[ -f "$repo_root/.zcrypto-origin" ]]; then
        echo "repo.origin|$(cat "$repo_root/.zcrypto-origin")"
    fi
}

# ---------------------------------------------------------------------------
# Native check
# ---------------------------------------------------------------------------
# The item this script exists to satisfy says a cross-compiled binary is not a
# native pass, so that has to be enforced rather than trusted. Two independent
# checks, because either alone is weak: the OS/arch comparison catches a record
# produced on the wrong machine, and the `-Dtarget` scan catches a stage list
# edited to cross-compile on the right one.
assert_native() {
    local uname_s uname_m want_os want_arch
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"

    case "$uname_s" in
        Linux) want_os="linux" ;;
        Darwin) want_os="macos" ;;
        *) want_os="$(echo "$uname_s" | tr '[:upper:]' '[:lower:]')" ;;
    esac
    case "$uname_m" in
        x86_64 | amd64) want_arch="x86_64" ;;
        arm64 | aarch64) want_arch="aarch64" ;;
        *) want_arch="$uname_m" ;;
    esac

    if [[ "$zig_target" != "$want_arch-$want_os"* ]]; then
        echo "native.check|FAIL: zig reports '$zig_target', host is '$want_arch-$want_os'"
        return 1
    fi
    echo "native.check|ok ($want_arch-$want_os)"
    return 0
}

# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------
# Each stage records the exact argv, the exit status, and -- for test stages --
# the compiler's own count of tests run. The count is load-bearing: a build
# whose test step matched nothing still exits 0, and without the count a record
# saying `exit=0` could not be told apart from one that verified nothing.

stage_index=0

run_stage() {
    local name="$1"
    shift
    stage_index=$((stage_index + 1))

    # Refuse to certify a stage that cross-compiles. This is checked per stage
    # rather than once, so adding a `-Dtarget` later cannot slip past.
    local arg
    for arg in "$@"; do
        case "$arg" in
            -Dtarget=*)
                printf 'STAGE|%s|%s|refused|cross-compile: %s\n' "$name" "$*" "$arg"
                fail_count=$((fail_count + 1))
                return 1
                ;;
        esac
    done

    local log
    log="$(printf '%s/%02d-%s.log' "$log_dir" "$stage_index" "$name")"

    "$@" >"$log" 2>&1
    local status=$?

    # Keep the skip parenthetical the build runner appends. A skipped test and a
    # passing one are both "not a failure" to the exit status, and the whole
    # point of this record is that the two are told apart.
    local counts
    counts="$(sed -n 's/.*; \([0-9]*\/[0-9]* tests passed.*\)$/\1/p' "$log" | tail -1)"
    [[ -z "$counts" ]] && counts="$(sed -n 's/.*All \([0-9]*\) tests passed.*/\1 tests passed/p' "$log" | tail -1)"
    [[ -z "$counts" ]] && counts="-"

    if [[ $status -eq 0 ]]; then
        pass_count=$((pass_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi

    printf 'STAGE|%s|%s|exit=%d|%s\n' "$name" "$*" "$status" "$counts"

    # Name the skips. A total of "6 skipped" tells a reader that something was
    # not verified but not what, which is the difference between a known gap and
    # an unknown one. The build runner prints the owning test binary per step.
    #
    # These lines only appear on a step that actually ran, so the record would
    # lose them to a warm cache -- which is why ZIG_LOCAL_CACHE_DIR is per-run
    # above. Every stage here executes from cold.
    while IFS= read -r line; do
        printf 'SKIP|%s|%s\n' "$name" "$line"
    done < <(sed -n 's/.*run test \([A-Za-z0-9._-]*\) [0-9]* pass, \([0-9]*\) skip.*/\1 \2 skipped/p' "$log")

    if [[ $status -ne 0 ]]; then
        # A failure that reports only its exit status is not evidence anyone can
        # act on from another machine, so the tail travels with the record.
        while IFS= read -r line; do
            printf 'LOG|%s|%s\n' "$name" "$line"
        done < <(tail -25 "$log")
    fi
    return $status
}

# A runner that is absent must appear in the record as an explicit skip with a
# reason. Omitting it silently is what turns "we did not test this" into "this
# passed everywhere" by the time the matrix is read.
probe_runner() {
    local name="$1" cmd="$2" why="$3"
    if command -v "$cmd" >/dev/null 2>&1; then
        printf 'RUNNER|%s|available|%s\n' "$name" "$(command -v "$cmd")"
    else
        printf 'RUNNER|%s|pending|%s\n' "$name" "$why"
        runners_pending=$((runners_pending + 1))
    fi
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

emit_identity

if ! assert_native; then
    echo "RESULT|refused pass=0 fail=1 runners_pending=0"
    fail_count=1
    exit 2
fi

# Optional external runners. Each one backs a real stage of `release_check.sh`
# that cannot run without a host service, so the record says which were present
# rather than leaving the reader to assume this host could have run everything.
# Nothing is probed speculatively: a runner listed here that gates no existing
# stage would read as "this host skipped a check" when no such check exists.
probe_runner "swtpm" "swtpm" \
    "no software TPM; release_check.sh stage 'tpm-simulator' (dev/tpm_swtpm.sh) cannot run here"
probe_runner "softhsm" "softhsm2-util" \
    "no SoftHSM token; release_check.sh stage 'pkcs11-softoken' (dev/pkcs11_softoken.sh) cannot run here"
probe_runner "system-cc" "cc" \
    "no system C compiler; release_check.sh stage 'ffi-consumer-system-cc' cannot run here"

run_stage "build" "$zig_bin" build
run_stage "test-debug" "$zig_bin" build test -Doptimize=Debug --summary all
run_stage "test-releasesafe" "$zig_bin" build test -Doptimize=ReleaseSafe --summary all
run_stage "test-releasefast" "$zig_bin" build test -Doptimize=ReleaseFast --summary all
run_stage "hardware-parity-debug" "$zig_bin" build hardware-parity -Doptimize=Debug
run_stage "hardware-parity-releasefast" "$zig_bin" build hardware-parity -Doptimize=ReleaseFast
run_stage "kat" "$zig_bin" build kat
run_stage "ffi-consumer" "$zig_bin" build ffi-consumer
run_stage "run-core" "$zig_bin" build run-core

# `runners_pending` counts absent host services, not skipped tests. Those are
# the `SKIP|` lines above and are a different thing entirely: a pending runner
# means a stage could not be attempted on this host, a skipped test means a
# stage ran and declined a case. Calling both "skip" in one record invites the
# reader to add them up.
printf 'RESULT|pass=%d fail=%d runners_pending=%d\n' "$pass_count" "$fail_count" "$runners_pending"

[[ $fail_count -eq 0 ]]
