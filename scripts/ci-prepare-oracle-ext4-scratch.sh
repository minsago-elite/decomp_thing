#!/usr/bin/env bash
set -euo pipefail

if (($# > 1)) || [[ $# == 1 && "${1:-}" != --bundled-ghidra && "${1:-}" != --bundled-ghidra-resume && "${1:-}" != --bundled-ghidra-resume-control ]]; then
  echo "usage: scripts/ci-prepare-oracle-ext4-scratch.sh [--bundled-ghidra|--bundled-ghidra-resume|--bundled-ghidra-resume-control]" >&2
  exit 64
fi

: "${GITHUB_ENV:?GITHUB_ENV must name the GitHub Actions environment file}"
: "${RUNNER_TEMP:?RUNNER_TEMP must name the GitHub Actions temporary directory}"
if [[ ! -f "$GITHUB_ENV" || ! -w "$GITHUB_ENV" ]]; then
  echo "GITHUB_ENV must be an existing writable regular file" >&2
  exit 1
fi

for command in chown chmod id losetup mkfs.ext4 mkdir mount mountpoint rmdir stat sudo truncate; do
  command -v "$command" >/dev/null || {
    echo "required oracle scratch provisioning command is unavailable: $command" >&2
    exit 1
  }
done

user_id="$(id -u)"
group_id="$(id -g)"
image="$RUNNER_TEMP/decomp-oracle-ext4-scratch.img"
mount_parent="/var/lib/decomp-oracle-ci"
image_size=64M
inode_count=4096
environment_prefix=DECOMP_TEST_ORACLE_EXT4
if [[ "${1:-}" == --bundled-ghidra ]]; then
  image="$RUNNER_TEMP/decomp-bundled-ghidra-ext4-scratch.img"
  mount_parent="/var/lib/decomp-bundled-ghidra-ci"
  image_size=1G
  inode_count=16384
  environment_prefix=DECOMP_TEST_BUNDLED_GHIDRA_EXT4
fi
if [[ "${1:-}" == --bundled-ghidra-resume || "${1:-}" == --bundled-ghidra-resume-control ]]; then
  image_size=1G
  inode_count=16384
  if [[ "$1" == --bundled-ghidra-resume ]]; then
    image="$RUNNER_TEMP/decomp-bundled-ghidra-resume-ext4-scratch.img"
    mount_parent="/var/lib/decomp-bundled-ghidra-resume-ci"
    environment_prefix=DECOMP_TEST_BUNDLED_GHIDRA_RESUME_EXT4
  else
    image="$RUNNER_TEMP/decomp-bundled-ghidra-resume-control-ext4-scratch.img"
    mount_parent="/var/lib/decomp-bundled-ghidra-resume-control-ci"
    environment_prefix=DECOMP_TEST_BUNDLED_GHIDRA_RESUME_CONTROL_EXT4
  fi
fi
mount_path="$mount_parent/scratch"

if [[ -e "$image" || -L "$image" || -e "$mount_parent" || -L "$mount_parent" ]]; then
  echo "oracle scratch provisioning target already exists" >&2
  exit 1
fi

complete=false
cleanup_failed_provisioning() {
  if [[ "$complete" == true ]]; then
    return
  fi
  if mountpoint --quiet "$mount_path" 2>/dev/null; then
    sudo -n umount "$mount_path" || true
  fi
  sudo -n rmdir "$mount_path" 2>/dev/null || true
  sudo -n rmdir "$mount_parent" 2>/dev/null || true
  rm -f "$image"
}
trap cleanup_failed_provisioning EXIT

truncate --size="$image_size" "$image"
mkfs.ext4 -q -F -N "$inode_count" -m 0 "$image"
sudo -n mkdir "$mount_parent"
sudo -n chown 0:0 "$mount_parent"
sudo -n chmod 0755 "$mount_parent"
sudo -n mkdir "$mount_path"
sudo -n mount -o loop,rw,nodev,nosuid,noexec,noatime "$image" "$mount_path"
sudo -n chown "$user_id:$group_id" "$mount_path"
sudo -n chmod 0700 "$mount_path"
if [[ -d "$mount_path/lost+found" ]]; then
  sudo -n rmdir "$mount_path/lost+found"
fi

if [[ "$(stat --file-system --format='%T' "$mount_path")" != ext2/ext3 ]]; then
  # GNU stat uses the historical ext2/ext3 label for ext4's shared magic.
  echo "oracle scratch provisioning did not produce ext4" >&2
  exit 1
fi
if [[ "$(stat --format='%u:%a' "$mount_path")" != "$user_id:700" ]]; then
  echo "oracle scratch mount has the wrong owner or mode" >&2
  exit 1
fi

{
  printf '%s_SCRATCH=%s\n' "$environment_prefix" "$mount_path"
  printf '%s_IMAGE=%s\n' "$environment_prefix" "$image"
} >>"$GITHUB_ENV"
complete=true
trap - EXIT
