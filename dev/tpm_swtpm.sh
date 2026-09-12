#!/usr/bin/env bash
#
# Start an isolated swtpm 2.0 simulator and run the TPM integration suite
# against it.
#
# The suite needs a TPM it is allowed to create keys on, seal to, and quote
# from. The host's real TPM is not that: it holds keys this project does not
# own, and the suite's cleanup discipline is not a licence to create objects on
# a daily driver's device. So this provisions a throwaway simulator whose entire
# state lives in a directory belonging to this invocation alone.
#
# Four things about it are not obvious and are the reason this script exists:
#
#   * Each invocation gets its own state directory, created fresh under a
#     parent and removed on exit. The parent is never deleted. An earlier
#     version recursively deleted a caller-overridable path at startup, so two
#     concurrent runs erased each other's live simulator state -- and pointing
#     the override at a directory that mattered would have destroyed it.
#
#   * The transport is a UNIX socket inside that directory, not a TCP port.
#     Probing for a free port and then binding it is a race: two runs starting
#     together can both see the same port free, and the loser either fails or,
#     worse, attaches to the winner's simulator and reports on a device it does
#     not own. A path this invocation just created cannot collide.
#
#   * Readiness checks that the simulator is still alive *before* it concludes
#     anything from the absence of a listener, so a simulator that died at
#     startup is reported as that rather than as a timeout.
#
#   * Only the swtpm this script started is killed, by PID recorded at start.
#     Never by name: on a host running libvirt there is a second swtpm serving a
#     VM's vTPM, and killing that destroys a running guest's TPM.
#
# Set ZCRYPTO_KEEP_STATE=1 to retain the state directory for inspection; the
# path is printed. Set ZCRYPTO_SWTPM_STATE_ROOT to place these directories
# somewhere other than .scratch. That variable names the *parent*: the previous
# ZCRYPTO_SWTPM_STATE named the state directory itself and was deleted, so the
# rename makes a stale setting inert instead of silently changing meaning.
#
# To point the same suite at real hardware instead:
#
#     ZCRYPTO_TPM_TCTI=device:/dev/tpmrm0 zig build tpm-integration -Dtpm=true
#
# That requires the invoking user to be able to open /dev/tpmrm0. When they
# cannot, the suite fails with `permission_denied` naming the device, which is
# the intended outcome -- it does not skip, because a gate that reports success
# after reaching no device is worse than one that fails.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
zig_bin="${ZIG:-/opt/zig-dev/zig}"
state_root="${ZCRYPTO_SWTPM_STATE_ROOT:-$repo_root/.scratch/tpm-swtpm}"

cd "$repo_root"

if ! command -v swtpm >/dev/null 2>&1; then
    echo "swtpm not found; install the 'swtpm' package." >&2
    exit 1
fi

# The swtpm TCTI is a separate shared object from libtss2-esys and is the piece
# that is actually missing when a host has the TPM libraries but no simulator
# transport, so it is checked by name rather than assumed present.
if ! ls /usr/lib/libtss2-tcti-swtpm.so* >/dev/null 2>&1; then
    echo "libtss2-tcti-swtpm not found; install the TPM2-TSS libraries." >&2
    exit 1
fi

# Only the parent is created. It is never removed, because it is a location the
# caller chose and may hold other runs' retained evidence.
mkdir -p "$state_root"

# mktemp creates the directory 0700 at creation rather than widening a default
# and narrowing it afterwards, and it makes the name unique against concurrent
# invocations without this script implementing its own collision handling.
state_dir="$(mktemp -d -p "$state_root" "run-XXXXXXXX")"

swtpm_pid=""

# By recorded PID only. See the header: pkill swtpm would take out libvirt's.
# Removes only the directory this invocation created.
cleanup() {
    if [ -n "$swtpm_pid" ]; then
        kill "$swtpm_pid" 2>/dev/null || true
        wait "$swtpm_pid" 2>/dev/null || true
    fi
    if [ "${ZCRYPTO_KEEP_STATE:-0}" = "1" ]; then
        echo "swtpm state retained at $state_dir" >&2
    else
        rm -rf "$state_dir"
    fi
}
# Signals exit rather than cleaning up directly, so cleanup runs once from the
# EXIT trap on every path instead of twice on an interrupt.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

server_sock="$state_dir/tpm"

# The TCTI derives its control socket as "<path>.ctrl", and AF_UNIX truncates
# rather than reporting, so the bound is checked here instead of surfacing as a
# connection failure to a path nobody asked for. 107 is sun_path minus its NUL.
if [ "$(( ${#server_sock} + 5 ))" -gt 107 ]; then
    echo "State path too long for a UNIX socket: $server_sock" >&2
    echo "Set ZCRYPTO_SWTPM_STATE_ROOT to a shorter directory." >&2
    exit 1
fi

# `not-need-init,startup-clear` leaves the simulator already started, so the
# suite's TPM2_Startup gets TPM2_RC_INITIALIZE, which the backend accepts. That
# is the same path a firmware-started hardware TPM takes, so the simulator is
# not exercising a branch the real device never would.
#
# mode=0600 on both sockets: the containing directory is already 0700, and a
# TPM transport should not be the one thing in it that is not.
swtpm socket \
    --tpmstate "dir=$state_dir" \
    --ctrl "type=unixio,path=$server_sock.ctrl,mode=0600" \
    --server "type=unixio,path=$server_sock,mode=0600" \
    --tpm2 \
    --flags not-need-init,startup-clear &
swtpm_pid=$!

# A bound socket is not necessarily a listening one, so readiness is taken from
# the kernel's socket table rather than from the path existing.
listening() {
    ss -lxn 2>/dev/null | awk -v p="$1" '$5 == p { found = 1 } END { exit !found }'
}

for _ in $(seq 1 50); do
    # The liveness check comes first: if the simulator has already exited, the
    # missing listener is that exit and not a slow start, and saying so is more
    # use than a timeout fifty iterations later.
    if ! kill -0 "$swtpm_pid" 2>/dev/null; then
        echo "swtpm exited before accepting connections." >&2
        exit 1
    fi
    if listening "$server_sock" && listening "$server_sock.ctrl"; then
        break
    fi
    sleep 0.1
done

if ! listening "$server_sock"; then
    echo "swtpm did not listen on $server_sock." >&2
    exit 1
fi

: "${ZIG_GLOBAL_CACHE_DIR:=$repo_root/.scratch/zig-global-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=$repo_root/.scratch/tpm-cache}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

export ZCRYPTO_TPM_TCTI="swtpm:path=$server_sock"

# Quieten tpm2-tss's own logging by default. Roughly a third of this suite is
# negative-path tests that deliberately provoke a TPM error, and esys logs each
# one as `WARNING:`/`ERROR:` on stderr. Those lines carry nothing the tests do
# not already assert -- each such test names the exact mapped error via
# `expectError` -- but the build runner captures a test binary's stderr and, on
# seeing any, prints the step's argv under `failed command:`. The result was a
# 38/38 green run whose log read as a failure.
#
# Overridable rather than hard-coded: `TSS2_LOG=all+warning dev/tpm_swtpm.sh`
# puts the library's view back when a real swtpm problem is being diagnosed.
: "${TSS2_LOG:=all+none}"
export TSS2_LOG

"$zig_bin" build tpm-integration -Dtpm=true --summary all
