#!/usr/bin/env bash
#
# Collect native platform evidence from every host in the matrix.
#
# This is the repeatable half of the platform gate: `dev/platform_check.sh` and
# `dev/platform_check.ps1` produce one host's record, and this drives them
# across the lab and checks the records are actually comparable. Running it is
# the whole procedure -- there is no sequence of scp/ssh lines to remember, so a
# re-run a month from now is the same run.
#
# What gets tested is the *working tree*, not HEAD. This gate is used against
# work in progress far more often than against a tag, and shipping HEAD would
# quietly certify code the developer is not looking at. The snapshot is built
# from `git ls-files -co --exclude-standard`, which is tracked files plus
# untracked-but-not-ignored ones -- the same set a reader sees in the checkout.
#
# Host list. Lab addresses are deployment detail, not source, so they live in an
# untracked config rather than here:
#
#   dev/platform_hosts.conf   (or $ZCRYPTO_PLATFORM_HOSTS)
#
# One host per line, `#` comments and blanks ignored, whitespace separated:
#
#   <name> <kind> <ssh-target> <zig-path> <remote-dir>
#
#   name        Label for the record and the matrix row.
#   kind        local | posix | windows
#   ssh-target  user@host, or `-` for kind=local.
#   zig-path    Compiler on that host, or `-` to use its PATH.
#   remote-dir  Where to unpack, or `-` for kind=local.
#
# Example:
#   arch    local   -               /opt/zig-dev/zig                         -
#   ubuntu  posix   user@10.0.0.72  /opt/zig-dev/zig                         /home/user/zc-probe
#   macos   posix   user@10.0.0.75  /opt/zig-dev/zig                         /Users/user/zc-probe
#   win     windows user@10.0.0.70  C:\zig-versions\zig-0.17.0-dev\zig.exe   C:\zc-probe
#
# Environment:
#   ZCRYPTO_MATRIX_OUT=<dir>   Where records land (default: a new run dir).
#   ZCRYPTO_MATRIX_KEEP=1      Leave the remote checkouts in place afterwards.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root" || exit 127

conf="${ZCRYPTO_PLATFORM_HOSTS:-$repo_root/dev/platform_hosts.conf}"
if [[ ! -f "$conf" ]]; then
    echo "platform_matrix: no host list at $conf" >&2
    echo "platform_matrix: see the header of $0 for the format" >&2
    exit 127
fi

mkdir -p "$repo_root/.scratch"
out_dir="${ZCRYPTO_MATRIX_OUT:-$repo_root/.scratch/matrix-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$out_dir"

snapshot="$out_dir/zcrypto-snapshot.tar.gz"

# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

# Stamp the origin *before* listing files, so the stamp is inside the snapshot.
# A remote host has no repository, so without this its record can only say
# `repo.commit|unavailable-no-git-dir` and the reader has no way to tell which
# tree produced it.
origin_stamp="$repo_root/.zcrypto-origin"
worktree_state="clean"
[[ -n "$(git status --porcelain 2>/dev/null)" ]] && worktree_state="dirty"
printf 'commit=%s worktree=%s from=%s\n' \
    "$(git rev-parse HEAD 2>/dev/null)" "$worktree_state" "$(uname -n)" \
    >"$origin_stamp"

# `-co` is tracked plus untracked-not-ignored. The stamp is named explicitly as
# well, because whether `-co` yields it depends on `.gitignore` -- it is listed
# there so it can never be committed, which also means it is never listed here.
#
# `sort -zu` is what makes that safe. Naming a file twice makes GNU tar record
# the second copy as a hardlink to the first, and bsdtar on Windows refuses to
# extract a hardlink pointing at itself, so the whole snapshot fails to unpack.
# De-duplicating means neither ignoring nor un-ignoring the stamp can break this.
if ! { git ls-files -co --exclude-standard -z; printf '%s\0' ".zcrypto-origin"; } \
    | sort -zu | tar --null -czf "$snapshot" -T -; then
    echo "platform_matrix: could not build snapshot" >&2
    rm -f "$origin_stamp"
    exit 1
fi
rm -f "$origin_stamp"

# ---------------------------------------------------------------------------
# Record validation
# ---------------------------------------------------------------------------
# A record that is missing a line is worse than one that fails: the matrix still
# renders, the row still says the host passed, and the absent line is invisible
# because nothing was looking for it. This caught exactly that -- the Windows
# script's native check emitted nothing and refused nothing, because a
# PowerShell function returns everything it writes, so emitting the line *and*
# returning a boolean returned a truthy two-element array. Two green runs went
# by before a negative control caught it. Hence: every record must carry every
# key, and a host that cannot be reached is a named failure, never a silent gap.
required_keys=(
    "ZCRYPTO_PLATFORM_EVIDENCE"
    "host.uname"
    "host.name"
    "host.utc"
    "zig.exe"
    "zig.version"
    "zig.native_target"
    "repo.commit"
    "repo.worktree"
    "native.check"
    "RESULT"
)

validate_record() {
    local name="$1" file="$2" missing=()

    local key
    for key in "${required_keys[@]}"; do
        grep -q "^$key|" "$file" || missing+=("$key")
    done
    # A record with no stages is a record of nothing having run.
    grep -q "^STAGE|" "$file" || missing+=("STAGE")

    if [[ ${#missing[@]} -ne 0 ]]; then
        printf 'INVALID|%s|missing: %s\n' "$name" "${missing[*]}"
        return 1
    fi
    if ! grep -q "^native.check|ok" "$file"; then
        printf 'INVALID|%s|not a native run: %s\n' \
            "$name" "$(grep '^native.check|' "$file")"
        return 1
    fi

    # A record has to say which tree it built. A remote host has no repository,
    # so its own `repo.commit` is `unavailable-no-git-dir` and the stamp the
    # driver ships is the only attribution it has -- and that stamp went missing
    # once already, silently, when the file it reads was added to `.gitignore`.
    # An unattributable pass is indistinguishable from a pass on stale sources.
    if ! grep -q "^repo.commit|[0-9a-f]" "$file" && ! grep -q "^repo.origin|" "$file"; then
        printf 'INVALID|%s|unattributable: no repo.commit and no repo.origin\n' "$name"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Per-host runs
# ---------------------------------------------------------------------------

# `-n` is not optional. Without it `ssh` reads the driver's stdin, and the first
# remote stage swallows the rest of the host list: the run reports the hosts it
# managed to reach, exits 0, and the ones it ate are absent rather than failed.
# The host list is also read into an array before any of this runs, so the loop
# below has no stdin to lose in the first place.
scp_opts=(-o BatchMode=yes -o ConnectTimeout=15)
ssh_opts=(-n "${scp_opts[@]}")

# The remote commands below interpolate `$rdir` and `$zig` on purpose: both come
# from the local config and name paths on the remote host, so client-side
# expansion is the intent rather than an oversight (shellcheck SC2029).

run_local() {
    local zig="$1"
    if [[ "$zig" == "-" ]]; then
        bash "$repo_root/dev/platform_check.sh"
    else
        ZIG="$zig" bash "$repo_root/dev/platform_check.sh"
    fi
}

run_posix() {
    local target="$1" zig="$2" rdir="$3"

    ssh "${ssh_opts[@]}" "$target" "rm -rf '$rdir' && mkdir -p '$rdir'" >/dev/null || return 1
    scp -q "${scp_opts[@]}" "$snapshot" "$target:$rdir/snapshot.tar.gz" >/dev/null || return 1

    local zig_env=""
    [[ "$zig" != "-" ]] && zig_env="ZIG='$zig' "
    ssh "${ssh_opts[@]}" "$target" \
        "cd '$rdir' && tar -xzf snapshot.tar.gz && rm -f snapshot.tar.gz && ${zig_env}bash dev/platform_check.sh"
}

run_windows() {
    local target="$1" zig="$2" rdir="$3"

    # `cmd` is the login shell on the Windows host. The `bash` there is the WSL
    # launcher, so a POSIX path through this function would run the check inside
    # a Linux guest and label the result Windows -- which is why the Windows
    # script is a separate file rather than a shim.
    ssh "${ssh_opts[@]}" "$target" "rmdir /s /q $rdir 2>nul & mkdir $rdir" >/dev/null 2>&1
    scp -q "${scp_opts[@]}" "$snapshot" "$target:${rdir//\\//}/snapshot.tar.gz" >/dev/null || return 1

    local zig_env=""
    [[ "$zig" != "-" ]] && zig_env="set ZIG=$zig&& "
    # `tar` is bsdtar shipped with Windows; it is present from Windows 10 1803.
    #
    # Records come back CRLF-terminated, and PowerShell's UTF-16 console output
    # can carry stray NULs. Both have to go here rather than at the reader: a
    # trailing CR is invisible in a terminal but makes the version string on this
    # row unequal to the identical one from every other host, which is enough to
    # make the compiler-skew check below cry wolf on a matrix that agrees.
    ssh "${ssh_opts[@]}" "$target" \
        "cd $rdir && tar -xzf snapshot.tar.gz && del snapshot.tar.gz && ${zig_env}powershell -NoProfile -ExecutionPolicy Bypass -File $rdir\\dev\\platform_check.ps1" \
        | tr -d '\000\r'
}

cleanup_remote() {
    local kind="$1" target="$2" rdir="$3"
    [[ "${ZCRYPTO_MATRIX_KEEP:-0}" != "0" ]] && return 0
    case "$kind" in
        posix) ssh "${ssh_opts[@]}" "$target" "rm -rf '$rdir'" >/dev/null 2>&1 ;;
        windows) ssh "${ssh_opts[@]}" "$target" "rmdir /s /q $rdir" >/dev/null 2>&1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Drive
# ---------------------------------------------------------------------------

host_count=0
ok_count=0
bad_count=0

echo "ZCRYPTO_PLATFORM_MATRIX|v1"
echo "matrix.out|$out_dir"

mapfile -t host_lines <"$conf"

for host_line in "${host_lines[@]}"; do
    read -r name kind target zig rdir _rest <<<"$host_line"
    [[ -z "${name:-}" || "$name" == \#* ]] && continue
    host_count=$((host_count + 1))

    record="$out_dir/$name.record"

    case "$kind" in
        local) run_local "$zig" >"$record" 2>&1 ;;
        posix) run_posix "$target" "$zig" "$rdir" >"$record" 2>&1 ;;
        windows) run_windows "$target" "$zig" "$rdir" >"$record" 2>&1 ;;
        *)
            printf 'INVALID|%s|unknown kind: %s\n' "$name" "$kind"
            bad_count=$((bad_count + 1))
            continue
            ;;
    esac
    status=$?

    cleanup_remote "$kind" "$target" "$rdir"

    if ! validate_record "$name" "$record"; then
        bad_count=$((bad_count + 1))
        # An unreachable host produces a short file of ssh noise rather than a
        # record. Carry it, so "we could not reach it" is distinguishable from
        # "it failed" without opening the run directory.
        while IFS= read -r line; do
            printf 'INVALID|%s|%s\n' "$name" "$line"
        done < <(head -5 "$record")
        continue
    fi

    result="$(grep '^RESULT|' "$record" | tail -1)"
    target_line="$(sed -n 's/^zig.native_target|//p' "$record")"
    version_line="$(sed -n 's/^zig.version|//p' "$record")"

    printf 'HOST|%s|%s|%s|%s|exit=%d\n' \
        "$name" "$target_line" "$version_line" "${result#RESULT|}" "$status"

    if [[ $status -eq 0 ]]; then
        ok_count=$((ok_count + 1))
    else
        bad_count=$((bad_count + 1))
    fi
done

# Every host must agree on the compiler. The item behind this gate says not to
# install an older compiler to make identities line up, so the check reports the
# disagreement rather than papering over it.
mapfile -t versions < <(sed -n 's/^zig.version|//p' "$out_dir"/*.record 2>/dev/null | sort -u)
if [[ ${#versions[@]} -gt 1 ]]; then
    printf 'COMPILER-SKEW|%s\n' "${versions[*]}"
fi

printf 'MATRIX|hosts=%d ok=%d bad=%d\n' "$host_count" "$ok_count" "$bad_count"

# A config with no usable lines otherwise reports `ok=0 bad=0` and exits 0,
# which reads as a clean matrix rather than an empty one.
[[ $host_count -gt 0 && $bad_count -eq 0 ]]
