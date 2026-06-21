#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
zig_bin="${ZIG:-/opt/zig-dev/zig}"

cd "$repo_root"

: "${ZIG_GLOBAL_CACHE_DIR:=/tmp/zig-global-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=/tmp/zcrypto-zig-cache-experimental-pq}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR

"$zig_bin" build -Dpost-quantum=true -Dexperimental-crypto=true

echo "experimental PQ build passed"
