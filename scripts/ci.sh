#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Reconstruction neutrality gate and JVM/Kotlin checks"
case "${DECOMP_CI_TEST_SHARD:-full}" in
  full)
    ./gradlew --no-daemon verifyReconstructionNeutrality test \
      v3BoundaryFinalStagingIsolated v3BoundaryPublicationIsolated v3BoundaryCensusIsolated \
      -PisolateV3BoundaryTests=true
    ;;
  core)
    ./gradlew --no-daemon verifyReconstructionNeutrality test \
      v3BoundaryFinalStagingIsolated v3BoundaryPublicationIsolated v3BoundaryCensusIsolated \
      -PciTestShard=core -PisolateV3BoundaryTests=true
    ;;
  live) ./gradlew --no-daemon verifyReconstructionNeutrality test "-PciTestShard=$DECOMP_CI_TEST_SHARD" ;;
  *) echo "unsupported DECOMP_CI_TEST_SHARD" >&2; exit 2 ;;
esac
