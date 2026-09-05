#!/usr/bin/env bash
set -euo pipefail

if (($# > 1)) || [[ $# == 1 && "${1:-}" != --bundled-ghidra && "${1:-}" != --bundled-ghidra-resume && "${1:-}" != --bundled-ghidra-resume-control ]]; then
  echo "usage: scripts/ci-release-oracle-ext4-scratch.sh [--bundled-ghidra|--bundled-ghidra-resume|--bundled-ghidra-resume-control]" >&2
  exit 64
fi

: "${RUNNER_TEMP:?RUNNER_TEMP must name the GitHub Actions temporary directory}"
mount_path="${DECOMP_TEST_ORACLE_EXT4_SCRATCH:-}"
image="${DECOMP_TEST_ORACLE_EXT4_IMAGE:-}"
expected_parent=/var/lib/decomp-oracle-ci
expected_image="$RUNNER_TEMP/decomp-oracle-ext4-scratch.img"
if [[ "${1:-}" == --bundled-ghidra ]]; then
  mount_path="${DECOMP_TEST_BUNDLED_GHIDRA_EXT4_SCRATCH:-}"
  image="${DECOMP_TEST_BUNDLED_GHIDRA_EXT4_IMAGE:-}"
  expected_parent=/var/lib/decomp-bundled-ghidra-ci
  expected_image="$RUNNER_TEMP/decomp-bundled-ghidra-ext4-scratch.img"
fi

if [[ "${1:-}" == --bundled-ghidra-resume ]]; then
  mount_path="${DECOMP_TEST_BUNDLED_GHIDRA_RESUME_EXT4_SCRATCH:-}"
  image="${DECOMP_TEST_BUNDLED_GHIDRA_RESUME_EXT4_IMAGE:-}"
  expected_parent=/var/lib/decomp-bundled-ghidra-resume-ci
  expected_image="$RUNNER_TEMP/decomp-bundled-ghidra-resume-ext4-scratch.img"
elif [[ "${1:-}" == --bundled-ghidra-resume-control ]]; then
  mount_path="${DECOMP_TEST_BUNDLED_GHIDRA_RESUME_CONTROL_EXT4_SCRATCH:-}"
  image="${DECOMP_TEST_BUNDLED_GHIDRA_RESUME_CONTROL_EXT4_IMAGE:-}"
  expected_parent=/var/lib/decomp-bundled-ghidra-resume-control-ci
  expected_image="$RUNNER_TEMP/decomp-bundled-ghidra-resume-control-ext4-scratch.img"
fi

if [[ -n "$mount_path" ]]; then
  if [[ "$mount_path" != "$expected_parent/scratch" || -L "$expected_parent" || -L "$mount_path" ]]; then
    echo "oracle scratch cleanup refuses an unexpected or linked mount target" >&2
    exit 1
  fi
  sudo -n umount "$mount_path"
  if mountpoint --quiet "$mount_path"; then
    echo "bounded ext4 oracle scratch remained mounted" >&2
    exit 1
  fi
  sudo -n rmdir "$mount_path"
  sudo -n rmdir "$expected_parent"
fi
if [[ -n "$image" ]]; then
  if [[ "$image" != "$expected_image" || -L "$image" ]]; then
    echo "oracle scratch cleanup refuses an unexpected or linked image" >&2
    exit 1
  fi
  for attempt in {1..20}; do
    if [[ -z "$(sudo -n losetup --associated "$image")" ]]; then
      break
    fi
    if ((attempt == 20)); then
      echo "bounded ext4 oracle scratch retained a loop device" >&2
      exit 1
    fi
    sleep 0.1
  done
  rm -f "$image"
fi
