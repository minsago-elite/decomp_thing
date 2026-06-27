#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> JVM/Kotlin checks"
./gradlew --no-daemon test

echo "==> Roadmap consistency"
./gradlew --no-daemon roadmapCheck
