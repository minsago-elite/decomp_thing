#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Reconstruction neutrality gate"
./gradlew --no-daemon verifyReconstructionNeutrality

echo "==> JVM/Kotlin checks"
case "${DECOMP_CI_TEST_SHARD:-full}" in
  full) ./gradlew --no-daemon test ;;
  core|live) ./gradlew --no-daemon test "-PciTestShard=$DECOMP_CI_TEST_SHARD" ;;
  *) echo "unsupported DECOMP_CI_TEST_SHARD" >&2; exit 2 ;;
esac
