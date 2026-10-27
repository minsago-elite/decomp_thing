#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
repair_gradle_home="${GRADLE_USER_HOME:-$PWD/build/gradle-user-home}"
repair_node_home="${DECOMP_TEST_FRONTEND_NODE_HOME:-}"
repair_preparation_args=(:testClasses :installDist :stageOracleNativeLibraries --no-daemon)
repair_verify_installed_io=false
repair_test_shard=""
case "$#" in
  0) ;;
  1)
    if [[ "$1" != "--ci-verify-installed-analysis-io" ]]; then
      echo "unsupported repair snapshot option" >&2
      exit 2
    fi
    if [[ -z "${GRADLE_USER_HOME:-}" || -n "$repair_node_home" ]]; then
      echo "combined CI preparation requires explicit GRADLE_USER_HOME and no frontend Node override" >&2
      exit 2
    fi
    repair_verify_installed_io=true
    repair_preparation_args=(:verifyAnalysisIoHelperInstalled "${repair_preparation_args[@]}")
    ;;
  *)
    echo "unsupported repair snapshot arguments" >&2
    exit 2
    ;;
esac
if [[ "$repair_verify_installed_io" == true ]]; then
  case "${DECOMP_CI_TEST_SHARD:-}" in
    ""|core) ;; # Preserve the existing combined invocation for legacy callers.
    core-main) repair_test_shard=core-main ;;
    *) echo "unsupported repair snapshot CI partition" >&2; exit 2 ;;
  esac
fi
if [[ -n "$repair_node_home" ]]; then
  repair_preparation_args+=("-PfrontendNodeHome=$repair_node_home")
fi
# Compile and authenticate the real application/helper dependency closure with host credentials.
# Namespace root maps only this user's UID and cannot lease the host-root-owned compiler inode.
if [[ "$repair_verify_installed_io" == true ]]; then
  GRADLE_USER_HOME="$repair_gradle_home" ./gradlew "${repair_preparation_args[@]}" \
    | tee build/analysis-native-installed-verification.txt
else
  GRADLE_USER_HOME="$repair_gradle_home" ./gradlew "${repair_preparation_args[@]}"
fi

repair_fixture_directory="$PWD/build"
mkdir -p "$repair_fixture_directory"
repair_fixture_parent="$(mktemp -d "$repair_fixture_directory/decomp-repair-snapshot.XXXXXX")"
repair_source_mount="$repair_fixture_parent/source"
repair_output_mount="$repair_fixture_parent/output"
mkdir -m 0700 "$repair_source_mount" "$repair_output_mount"
trap 'rmdir "$repair_source_mount" "$repair_output_mount" "$repair_fixture_parent"' EXIT

unshare -Ur -m bash -c '
  set -euo pipefail
  repair_source_mount="$1"
  repair_output_mount="$2"
  repair_gradle_home="$3"
  repair_node_home="$4"
  repair_test_shard="$5"
  cleanup_mounts() {
    repair_status=$?
    umount "$repair_output_mount" || repair_status=1
    umount "$repair_source_mount" || repair_status=1
    exit "$repair_status"
  }
  trap cleanup_mounts EXIT
  mount -t tmpfs -o rw,nodev,nosuid,noexec,size=1M,nr_inodes=128,uid=0,gid=0,mode=0700 \
    decomp-repair-source "$repair_source_mount"
  mount -t tmpfs -o rw,nodev,nosuid,noexec,size=1M,nr_inodes=128,uid=0,gid=0,mode=0700 \
    decomp-repair-output "$repair_output_mount"
  # Reuse the dependency closure prepared above; only the quota-backed test runs in this namespace.
  # Checksum/resource/distribution checks remain enabled; only the prepared compiler producers are excluded.
  repair_gradle_args=(cleanTest test --tests decompengine.project.GeneratedCValidationSnapshotFixtureTest
    -x :buildLlvmBehaviorHelper -x :buildAnalysisIoHelper --no-daemon)
  if [[ -n "$repair_node_home" ]]; then
    repair_gradle_args+=("-PfrontendNodeHome=$repair_node_home")
  fi
  if [[ -n "$repair_test_shard" ]]; then
    repair_gradle_args+=("-PciTestShard=$repair_test_shard")
  fi
  DECOMP_TEST_REPAIR_SOURCE_TMPFS="$repair_source_mount" \
    DECOMP_TEST_REPAIR_OUTPUT_TMPFS="$repair_output_mount" \
    GRADLE_USER_HOME="$repair_gradle_home" \
    ./gradlew "${repair_gradle_args[@]}"
' bash "$repair_source_mount" "$repair_output_mount" "$repair_gradle_home" "$repair_node_home" "$repair_test_shard"
