#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test

# verifyReconstructionNeutrality is a standalone draft diagnostic gate (#84):
# known lexical findings remain and docs/reconstruction-neutrality.md records it
# as not ready for integration, so it runs non-blockingly here until its
# findings are resolved.
echo "==> Reconstruction neutrality diagnostic (non-blocking)"
set +e
./gradlew --no-daemon verifyReconstructionNeutrality
neutrality_status=$?
set -e
if [[ "$neutrality_status" -eq 1 ]]; then
  echo "verifyReconstructionNeutrality reported known findings; the draft gate is not blocking CI."
elif [[ "$neutrality_status" -ne 0 ]]; then
  echo "verifyReconstructionNeutrality failed to run (exit $neutrality_status)." >&2
  exit "$neutrality_status"
fi
