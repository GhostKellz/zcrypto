#!/usr/bin/env bash
#
# Fail if any .zig file under src/ is unreachable from the build graph.
#
# An unreferenced source file is invisible to every other gate in this
# repository. It is not compiled, so `zig build test` cannot fail on it; it is
# not analysed, so src/api_surface.zig cannot see it; `zig fmt --check` passes
# on files that do not type-check. It still ships, because build.zig.zon lists
# "src" in .paths, so a consumer unpacking the package finds it sitting beside
# the real implementations with nothing marking it as dead. That is the shape of
# the problem this guards: thirteen such files had accumulated, eight of which
# no longer compiled at all, several of them placeholder protocol and
# zero-knowledge implementations that would be actively dangerous to `@import`
# on the strength of their filenames.
#
# The reason this is mechanical rather than a reviewed list: the hand-kept
# inventory of those files was wrong twice, missing asm/x86_64.zig and
# protocols/signal.zig both times. Reading imports is exactly the work a
# computer does without getting bored.
#
# Reachability is computed the way Zig resolves imports -- a breadth-first walk
# of `@import("....zig")` from every root_source_file in build.zig, each path
# resolved against the directory of the file that imports it. Imports by module
# name (`@import("std")`, `@import("build_options")`, `@import("tpm_backend")`)
# are skipped: they are not paths, and the files behind the project's own
# module names are already seeds because build.zig names them.
#
# Following the shipped-artifacts stage, this diffs a computed set against
# reality rather than grepping for known-bad names. A guard that only rejects
# the files someone already thought of is not a guard.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Seeds: every Zig file build.zig names directly. Includes examples/ and tests/
# roots, not just src/ -- a src file reachable only from a test root is
# genuinely reachable, and seeding from src/ alone would report it as an orphan
# and invite someone to quarantine a file the suite depends on.
mapfile -t queue < <(
    grep -o 'b\.path("[^"]*\.zig")' build.zig |
        sed 's/^b\.path("//; s/")$//' |
        sort -u
)

if [[ ${#queue[@]} -eq 0 ]]; then
    echo "orphan-check: found no root_source_file entries in build.zig." >&2
    echo "The extraction pattern no longer matches; this check is not running." >&2
    exit 1
fi

declare -A seen=()
reachable=()

while [[ ${#queue[@]} -gt 0 ]]; do
    file="${queue[0]}"
    queue=("${queue[@]:1}")

    [[ -n "${seen[$file]:-}" ]] && continue
    seen[$file]=1

    # A named root that does not exist means build.zig references a deleted
    # file; the build would fail, but say so here rather than silently treating
    # it as a leaf.
    if [[ ! -f "$file" ]]; then
        echo "orphan-check: $file is named by build.zig but does not exist." >&2
        exit 1
    fi

    reachable+=("$file")
    dir="$(dirname "$file")"

    while IFS= read -r target; do
        # -m: resolve lexically. The target need not exist -- a broken import is
        # the build's failure to report, not this script's, and erroring here
        # would replace a clear compiler diagnostic with a worse one.
        resolved="$(realpath -m --relative-to="$repo_root" "$dir/$target")"
        queue+=("$resolved")
    done < <(grep -o '@import("[^"]*\.zig")' "$file" | sed 's/^@import("//; s/")$//' | sort -u)
done

expected="$(printf '%s\n' "${reachable[@]}" | grep '^src/' | sort -u)"
actual="$(find src -name '*.zig' -type f | sort)"

if ! diff -u <(echo "$expected") <(echo "$actual") --label reachable-from-build --label present-in-src; then
    cat >&2 <<'EOF'

orphan-check FAILED.

Lines marked '+' are files under src/ that nothing in the build graph imports.
They are not compiled, not tested, and not covered by the API surface check,
yet they ship to consumers. Either wire the file into the build so it is
checked, or move it to attic/ (see attic/README.md), which is outside the
module root and therefore cannot be imported by accident.

Lines marked '-' mean the walk reached a src/ file that is not on disk, which
means an @import in the build graph is broken.
EOF
    exit 1
fi

echo "orphan-check: $(echo "$actual" | wc -l) files under src/, all reachable from build.zig."
