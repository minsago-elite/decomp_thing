#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test

# Draft reconstruction-neutrality gate: still fails on the documented #84
# migration baseline (docs/reconstruction-neutrality.md), so CI reports it
# without blocking until that baseline is clean.
echo "==> Reconstruction neutrality gate (non-blocking draft)"
./gradlew --no-daemon verifyReconstructionNeutrality ||
    echo "WARNING: neutrality gate reported baseline findings; see docs/reconstruction-neutrality.md"
