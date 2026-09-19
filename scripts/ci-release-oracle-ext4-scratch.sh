#!/usr/bin/env bash
set -euo pipefail

if (($# > 1)); then
  echo "usage: $0 [--bundled-ghidra|--bundled-ghidra-resume|--bundled-ghidra-resume-control|--gcc-engine-{cc1,lto1}-{fresh,resume}]" >&2
  exit 64
fi
source "$(cd "$(dirname "$0")" && pwd -P)/oracle-ext4-scratch-profile.sh"
oracle_ext4_scratch_profile "${1:-}"

: "${RUNNER_TEMP:?RUNNER_TEMP must name the GitHub Actions temporary directory}"
mount_variable="${environment_prefix}_SCRATCH"
image_variable="${environment_prefix}_IMAGE"
mount_path="${!mount_variable:-}"
image="${!image_variable:-}"
expected_parent="$mount_parent"
expected_image="$RUNNER_TEMP/$image_basename"

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
