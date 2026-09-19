#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test

# The neutrality gate is a draft diagnostic: known lexical findings remain and
# docs/reconstruction-neutrality.md records it as not ready for integration, so
# it runs non-blockingly here until its findings are resolved.
echo "==> Reconstruction neutrality diagnostic (non-blocking)"
./gradlew --no-daemon verifyReconstructionNeutrality || \
  echo "verifyReconstructionNeutrality reported known findings; the draft gate is not blocking CI."
