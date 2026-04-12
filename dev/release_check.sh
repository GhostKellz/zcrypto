#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

cd "$repo_root"

zig fmt --check src/ examples/ docs/
zig build -Doptimize=ReleaseSafe
zig build test
zig build -Dtls=false -Dpost-quantum=false -Dhardware-accel=false -Dasync=false

echo "release checks passed"
