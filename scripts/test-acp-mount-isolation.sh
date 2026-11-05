#!/usr/bin/env bash
# Opt-in only. This script neither compiles nor invokes Gradle.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repo"
export PYTHONDONTWRITEBYTECODE=1
exec python3 src/test/python/acp_mount_isolation_protocol_test.py "$@"
