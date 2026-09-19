#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
# verifyReconstructionNeutrality stays standalone until the #84 migration
# finishes; ./gradlew --no-daemon verifyReconstructionNeutrality runs it directly.
./gradlew --no-daemon test
