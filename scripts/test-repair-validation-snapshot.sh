#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
repair_gradle_home="${GRADLE_USER_HOME:-${HOME}/.gradle}"
repair_node_home="${DECOMP_TEST_FRONTEND_NODE_HOME:-}"
repair_fixture_parent="$(mktemp -d /tmp/decomp-repair-snapshot.XXXXXX)"
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
  repair_gradle_args=(cleanTest test --tests decompengine.project.GeneratedCValidationSnapshotFixtureTest --no-daemon)
  if [[ -n "$repair_node_home" ]]; then
    repair_gradle_args+=("-PfrontendNodeHome=$repair_node_home")
  fi
  DECOMP_TEST_REPAIR_SOURCE_TMPFS="$repair_source_mount" \
    DECOMP_TEST_REPAIR_OUTPUT_TMPFS="$repair_output_mount" \
    GRADLE_USER_HOME="$repair_gradle_home" \
    ./gradlew "${repair_gradle_args[@]}"
' bash "$repair_source_mount" "$repair_output_mount" "$repair_gradle_home" "$repair_node_home"
