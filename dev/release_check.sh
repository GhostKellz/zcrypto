#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
zig_bin="${ZIG:-/opt/zig-dev/zig}"

cd "$repo_root"

: "${ZIG_GLOBAL_CACHE_DIR:=/tmp/zig-global-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=/tmp/zcrypto-zig-cache-release-check}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR

"$zig_bin" fmt --check src/ examples/ docs/
"$zig_bin" build -Doptimize=ReleaseSafe
"$zig_bin" build test
"$zig_bin" build -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dasync=false

echo "release checks passed"
