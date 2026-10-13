#!/usr/bin/env bash
set -euo pipefail

if (($# > 1)); then
  echo 'usage: scripts/ci-qualify-gcc-cc1-full-export.sh [qualification|cc1-runtime-diagnostics]' >&2
  exit 64
fi
mode="${1:-qualification}"
case "$mode" in
  qualification|cc1-runtime-diagnostics) ;;
  *) echo 'unknown full-export capture mode' >&2; exit 64 ;;
esac

export DECOMP_GCC_CLI_FULL_EXPORT_ENGINE="${DECOMP_GCC_CLI_FULL_EXPORT_ENGINE:-cc1}"
case "$DECOMP_GCC_CLI_FULL_EXPORT_ENGINE" in
  cc1|driver) ;;
  *) echo 'full-export qualification requires cc1 or driver' >&2; exit 64 ;;
esac
if [[ "$mode" == cc1-runtime-diagnostics && "$DECOMP_GCC_CLI_FULL_EXPORT_ENGINE" != cc1 ]]; then
  echo 'runtime diagnostics require cc1' >&2
  exit 64
fi
export DECOMP_GCC_CLI_EXPORT_BINARY="${DECOMP_GCC_CLI_EXPORT_BINARY:-${DECOMP_GCC_CLI_CC1_BINARY:-}}"
export DECOMP_GCC_CLI_EXPORT_SCRATCH="${DECOMP_GCC_CLI_EXPORT_SCRATCH:-${DECOMP_GCC_CLI_CC1_FRESH_SCRATCH:-}}"

for name in DECOMP_GCC_CLI_INSTALLATION DECOMP_GCC_CLI_PROFILE DECOMP_GCC_CLI_ARCHIVE \
  DECOMP_GCC_CLI_EXPORT_BINARY DECOMP_GCC_CLI_EXPORT_SCRATCH DECOMP_GCC_CLI_EVIDENCE_ROOT; do
  if [[ -z "${!name:-}" ]]; then
    echo "required full-export qualification input is missing: $name" >&2
    exit 64
  fi
done

project_root="$(cd "$(dirname "$0")/.." && pwd -P)"
if [[ "$mode" == cc1-runtime-diagnostics ]]; then
  unset DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT
  export DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS=true
  selected_test='decompengine.oracle.gcc.GccProductionFullExportQualificationTest.live cc1 runtime diagnostics retain bounded logs and available operation evidence'
else
  unset DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS
  export DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT=true
  selected_test='decompengine.oracle.gcc.GccProductionFullExportQualificationTest.live selected GCC full export retains its profile-bound model and receipt evidence'
fi
export RUN_REAL_GHIDRA=true
exec "$project_root/gradlew" --no-daemon -p "$project_root" test --rerun \
  --tests "$selected_test"
