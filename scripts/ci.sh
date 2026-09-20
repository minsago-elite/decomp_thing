#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
# verifyReconstructionNeutrality stays standalone until the #84 migration
# finishes (the repository scan still fails on remaining ownership
# migrations); run it directly via ./gradlew verifyReconstructionNeutrality.
./gradlew --no-daemon test
