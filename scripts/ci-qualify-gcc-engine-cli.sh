#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo 'usage: scripts/ci-qualify-gcc-engine-cli.sh' >&2
  exit 64
fi

for name in DECOMP_GCC_CLI_PROFILE DECOMP_GCC_CLI_ARCHIVE DECOMP_GCC_CLI_CC1_BINARY DECOMP_GCC_CLI_LTO1_BINARY \
  DECOMP_GCC_CLI_CC1_FRESH_SCRATCH DECOMP_GCC_CLI_CC1_RESUME_SCRATCH \
  DECOMP_GCC_CLI_LTO1_FRESH_SCRATCH DECOMP_GCC_CLI_LTO1_RESUME_SCRATCH DECOMP_GCC_CLI_EVIDENCE_ROOT; do
  if [[ -z "${!name:-}" ]]; then
    echo "required real-engine CLI qualification input is missing: $name" >&2
    exit 64
  fi
done

project_root="$(cd "$(dirname "$0")/.." && pwd -P)"
export DECOMP_REQUIRE_GCC_ENGINE_CLI=true
exec "$project_root/gradlew" --no-daemon -p "$project_root" test \
  --tests decompengine.oracle.gcc.GccBundledCliQualificationTest
