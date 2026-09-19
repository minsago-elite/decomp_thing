#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test
# Draft reconstruction-neutrality gate: still fails on the documented #84
# migration baseline (docs/reconstruction-neutrality.md), so CI reports it
# without blocking until that baseline is clean. Invoke the scanner directly so
# its documented infrastructure status is not collapsed by Gradle's Exec task.
echo "==> Reconstruction neutrality gate (non-blocking draft)"
set +e
python3 -B scripts/check-generic-leakage.py
neutrality_status=$?
set -e
case "$neutrality_status" in
  0) ;;
  1) echo "WARNING: neutrality gate reported baseline findings; see docs/reconstruction-neutrality.md" ;;
  *) echo "ERROR: neutrality gate infrastructure failed (status $neutrality_status)" >&2; exit "$neutrality_status" ;;
esac
