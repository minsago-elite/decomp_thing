#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test

echo "==> Python checks"
python -m pytest

echo "==> Roadmap consistency"
python -m decomp_engine.roadmap check
