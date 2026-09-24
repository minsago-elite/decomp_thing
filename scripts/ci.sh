#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Reconstruction neutrality gate and JVM/Kotlin checks"
case "${DECOMP_CI_TEST_SHARD:-full}" in
  full) ./gradlew --no-daemon verifyReconstructionNeutrality test ;;
  core|live) ./gradlew --no-daemon verifyReconstructionNeutrality test "-PciTestShard=$DECOMP_CI_TEST_SHARD" ;;
  *) echo "unsupported DECOMP_CI_TEST_SHARD" >&2; exit 2 ;;
esac
