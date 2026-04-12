#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

cd "$repo_root"

zig build run
zig build run-advanced -Dhardware-accel=true
zig build run-zsync

echo "smoke runs passed"
