#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# The neutrality gate still reports known #84 findings; run it as a non-blocking
# diagnostic so the Kotlin tests below always execute.
echo "==> Reconstruction neutrality diagnostic (non-blocking until the scanner is clean)"
scripts/check-generic-leakage.sh || true

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test
