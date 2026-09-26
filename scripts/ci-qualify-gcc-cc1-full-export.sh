#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo 'usage: scripts/ci-qualify-gcc-cc1-full-export.sh' >&2
  exit 64
fi

for name in DECOMP_GCC_CLI_INSTALLATION DECOMP_GCC_CLI_PROFILE DECOMP_GCC_CLI_ARCHIVE \
  DECOMP_GCC_CLI_CC1_BINARY DECOMP_GCC_CLI_CC1_FRESH_SCRATCH DECOMP_GCC_CLI_EVIDENCE_ROOT; do
  if [[ -z "${!name:-}" ]]; then
    echo "required cc1 full-export qualification input is missing: $name" >&2
    exit 64
  fi
done

project_root="$(cd "$(dirname "$0")/.." && pwd -P)"
export DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT=true
export RUN_REAL_GHIDRA=true
exec "$project_root/gradlew" --no-daemon -p "$project_root" test --rerun-tasks \
  --tests decompengine.oracle.gcc.GccProductionFullExportQualificationTest
