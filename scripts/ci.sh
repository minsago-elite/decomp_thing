#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
# verifyReconstructionNeutrality is a standalone draft gate for now (#84): the
# repository scan still fails on remaining ownership migrations, so it is not
# wired into check or CI until those findings are resolved.
./gradlew --no-daemon test
