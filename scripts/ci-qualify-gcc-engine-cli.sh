#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo 'usage: scripts/ci-qualify-gcc-engine-cli.sh' >&2
  exit 64
fi

selected_engine="${DECOMP_GCC_CLI_ENGINE-all}"
case "$selected_engine" in
  all) engines=(CC1 LTO1) ;;
  cc1) engines=(CC1) ;;
  lto1) engines=(LTO1) ;;
  *) echo "invalid real-engine CLI qualification engine: $selected_engine" >&2; exit 64 ;;
esac

required=(DECOMP_GCC_CLI_INSTALLATION DECOMP_GCC_CLI_PROFILE DECOMP_GCC_CLI_ARCHIVE DECOMP_GCC_CLI_EVIDENCE_ROOT)
for engine in "${engines[@]}"; do
  required+=("DECOMP_GCC_CLI_${engine}_BINARY" "DECOMP_GCC_CLI_${engine}_FRESH_SCRATCH" "DECOMP_GCC_CLI_${engine}_RESUME_SCRATCH")
done
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "required real-engine CLI qualification input is missing: $name" >&2
    exit 64
  fi
done

project_root="$(cd "$(dirname "$0")/.." && pwd -P)"
export DECOMP_REQUIRE_GCC_ENGINE_CLI=true
exec "$project_root/gradlew" --no-daemon -p "$project_root" test \
  --tests decompengine.oracle.gcc.GccBundledCliQualificationTest
