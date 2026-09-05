#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/ci-prepare-acp-quota.sh" >&2
  exit 64
fi
: "${GITHUB_ENV:?GITHUB_ENV must name the GitHub Actions environment file}"
if [[ ! -f "$GITHUB_ENV" || ! -w "$GITHUB_ENV" || -L "$GITHUB_ENV" ]]; then
  echo "GITHUB_ENV must be an existing writable regular file" >&2
  exit 1
fi
for command in findmnt id mkdir mount mountpoint rmdir stat sudo timeout umount; do
  command -v "$command" >/dev/null || {
    echo "required ACP quota provisioning command is unavailable: $command" >&2
    exit 1
  }
done

acp_quota_parent=/var/lib/decomp-acp-contract-ci
acp_quota_mount="$acp_quota_parent/quota"
acp_quota_uid="$(id -u)"
acp_quota_gid="$(id -g)"
if [[ -e "$acp_quota_parent" || -L "$acp_quota_parent" ]]; then
  echo "ACP quota provisioning target already exists; refusing to adopt it" >&2
  exit 1
fi

acp_quota_parent_created=false
acp_quota_child_created=false
acp_quota_mount_attempted=false
cleanup_failed_provisioning() {
  if [[ "$acp_quota_mount_attempted" == true ]] && mountpoint --quiet "$acp_quota_mount"; then
    if [[ "$(findmnt --mountpoint "$acp_quota_mount" --noheadings --output FSTYPE)" != tmpfs ]] ||
      [[ "$(findmnt --mountpoint "$acp_quota_mount" --noheadings --output SOURCE)" != decomp-acp-contract ]]; then
      echo "ACP quota fixture identity changed during provisioning" >&2
      return 1
    fi
    timeout --kill-after=5s 15s sudo -n umount "$acp_quota_mount" || return 1
  fi
  if [[ "$acp_quota_child_created" == true ]]; then
    sudo -n rmdir "$acp_quota_mount" || return 1
  fi
  if [[ "$acp_quota_parent_created" == true ]]; then
    sudo -n rmdir "$acp_quota_parent" || return 1
  fi
}
trap cleanup_failed_provisioning EXIT
sudo -n mkdir --mode=0755 "$acp_quota_parent"
acp_quota_parent_created=true
sudo -n mkdir --mode=0700 "$acp_quota_mount"
acp_quota_child_created=true
acp_quota_mount_attempted=true
timeout --kill-after=5s 15s sudo -n mount -t tmpfs \
  -o "rw,nodev,nosuid,noexec,size=64M,nr_inodes=4096,uid=$acp_quota_uid,gid=$acp_quota_gid,mode=0700" \
  decomp-acp-contract "$acp_quota_mount"
if ! mountpoint --quiet "$acp_quota_mount" ||
  [[ "$(stat --file-system --format='%T' "$acp_quota_mount")" != tmpfs ]] ||
  [[ "$(stat --format='%u:%a' "$acp_quota_mount")" != "$acp_quota_uid:700" ]]; then
  echo "ACP quota mount failed filesystem, ownership or permission verification" >&2
  exit 1
fi
# The production staging authority independently checks the exact mount identity,
# finite byte/inode capacity and empty mount before it creates its workflow root.
printf 'DECOMP_TEST_ACP_QUOTA_TMPFS=%s\n' "$acp_quota_mount" >>"$GITHUB_ENV"
trap - EXIT
