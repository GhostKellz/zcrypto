#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

cd "$repo_root"

zig build -Dpost-quantum=true -Dexperimental-crypto=true

echo "experimental PQ build passed"
