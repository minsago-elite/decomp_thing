#!/usr/bin/env bash
set -euo pipefail

if (($# > 1)); then
  echo 'usage: scripts/ci-qualify-gcc-cc1-full-export.sh [qualification|cc1-runtime-diagnostics|cc1-native-calls|driver-native-calls|driver-interface-observations]' >&2
  exit 64
fi
mode="${1:-qualification}"
case "$mode" in
  qualification|cc1-runtime-diagnostics|cc1-native-calls|driver-native-calls|driver-interface-observations) ;;
  *) echo 'unknown full-export capture mode' >&2; exit 64 ;;
esac

export DECOMP_GCC_CLI_FULL_EXPORT_ENGINE="${DECOMP_GCC_CLI_FULL_EXPORT_ENGINE:-cc1}"
case "$DECOMP_GCC_CLI_FULL_EXPORT_ENGINE" in
  cc1|driver) ;;
  *) echo 'full-export qualification requires cc1 or driver' >&2; exit 64 ;;
esac
case "$mode:$DECOMP_GCC_CLI_FULL_EXPORT_ENGINE" in
  qualification:*|cc1-runtime-diagnostics:cc1|cc1-native-calls:cc1|driver-native-calls:driver|driver-interface-observations:driver) ;;
  driver-native-calls:*|driver-interface-observations:*) echo "$mode requires driver" >&2; exit 64 ;;
  *) echo "$mode requires cc1" >&2; exit 64 ;;
esac
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
unset DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS DECOMP_REQUIRE_GCC_NATIVE_CALLS DECOMP_REQUIRE_GCC_INTERFACE_OBSERVATIONS
if [[ "$mode" == driver-interface-observations ]]; then
  export DECOMP_REQUIRE_GCC_INTERFACE_OBSERVATIONS=true
  selected_test='decompengine.oracle.gcc.GccInferredInterfaceQualificationTest.live pinned driver retains complete owned raw interface observations'
  report="$project_root/build/test-results/test/TEST-decompengine.oracle.gcc.GccInferredInterfaceQualificationTest.xml"
  if [[ -e "$report" || -L "$report" ]]; then
    echo 'interface qualification refuses a preexisting execution report' >&2
    exit 64
  fi
elif [[ "$mode" == cc1-runtime-diagnostics ]]; then
  export DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS=true
  selected_test='decompengine.oracle.gcc.GccProductionFullExportQualificationTest.live cc1 runtime diagnostics retain bounded logs and available operation evidence'
elif [[ "$mode" == cc1-native-calls || "$mode" == driver-native-calls ]]; then
  export DECOMP_REQUIRE_GCC_NATIVE_CALLS=true
  selected_test='decompengine.oracle.gcc.GccProductionFullExportQualificationTest.live selected GCC native call observations retain profile-bound capture evidence'
else
  export DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT=true
  selected_test='decompengine.oracle.gcc.GccProductionFullExportQualificationTest.live selected GCC full export retains its profile-bound model and receipt evidence'
fi
export RUN_REAL_GHIDRA=true
# The native helper builds are deliberately never up to date and embed a fresh random staging path in their
# build records, so a second build changes the application JAR and the BOOT classpath reference. DECOMP_GCC_CLI_INSTALLATION
# was installed from the earlier installDist build; reuse that build's outputs (the verify tasks still run) so the
# regenerated expected reference stays byte-identical to the installed one.
if [[ "$mode" == driver-interface-observations ]]; then
  set +e
  "$project_root/gradlew" --no-daemon -p "$project_root" test --rerun \
    -x buildAnalysisIoHelper -x buildAcpGateHelper -x buildLlvmBehaviorHelper \
    --tests "$selected_test"
  status=$?
  set -e
  python3 "$project_root/scripts/verify-gcc-interface-qualification.py" \
    --report "$report" --output "$DECOMP_GCC_CLI_EVIDENCE_ROOT/execution-inventory.json" --gradle-exit "$status"
  exit "$status"
fi
exec "$project_root/gradlew" --no-daemon -p "$project_root" test --rerun \
  -x buildAnalysisIoHelper -x buildAcpGateHelper -x buildLlvmBehaviorHelper \
  --tests "$selected_test"
