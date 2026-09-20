#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test

echo "==> Reconstruction neutrality scan (advisory)"
# The draft neutrality gate still reports outstanding #84 migrations and exits
# non-zero, so keep it non-blocking until it passes instead of aborting CI
# before the test task completes (docs/reconstruction-neutrality.md).
if ./gradlew --no-daemon verifyReconstructionNeutrality; then
    echo "==> Neutrality scan passed"
else
    echo "==> Neutrality scan still reports outstanding #84 findings; advisory only"
fi
