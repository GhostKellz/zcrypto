#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
zig_bin="${ZIG:-/opt/zig-dev/zig}"

cd "$repo_root"

: "${ZIG_GLOBAL_CACHE_DIR:=/tmp/zig-global-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=/tmp/zcrypto-zig-cache-smoke-run}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR

"$zig_bin" build run
"$zig_bin" build run-advanced -Dhardware-accel=true
"$zig_bin" build run-zsync

echo "smoke runs passed"
