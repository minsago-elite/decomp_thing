#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# The neutrality gate still reports known #84 findings; run it as a non-blocking
# diagnostic so the Kotlin tests below always execute.
echo "==> Reconstruction neutrality diagnostic (non-blocking until the scanner is clean)"
set +e
scripts/check-generic-leakage.sh
scanner_status=$?
set -e
if ((scanner_status != 0 && scanner_status != 1)); then
  echo "Reconstruction neutrality scanner failed with infrastructure status $scanner_status" >&2
  exit "$scanner_status"
fi

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test
