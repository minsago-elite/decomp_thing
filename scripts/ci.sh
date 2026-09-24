#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Reconstruction neutrality gate"
./gradlew --no-daemon verifyReconstructionNeutrality

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test
