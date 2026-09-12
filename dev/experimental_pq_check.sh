#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
zig_bin="${ZIG:-/opt/zig-dev/zig}"

cd "$repo_root"

# Caches stay project-local. /tmp is RAM-backed on the primary dev host, and
# these defaults only apply when the release gate has not already exported its
# own per-invocation directories.
: "${ZIG_GLOBAL_CACHE_DIR:=$repo_root/.scratch/zig-global-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=$repo_root/.scratch/experimental-pq-cache}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

"$zig_bin" build -Dpost-quantum=true -Dexperimental-crypto=true

echo "experimental PQ build passed"
