#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/ci-release-acp-quota.sh" >&2
  exit 64
fi
if [[ -z "${DECOMP_TEST_ACP_QUOTA_TMPFS:-}" ]]; then
  exit 0
fi
acp_quota_parent=/var/lib/decomp-acp-contract-ci
acp_quota_mount="$acp_quota_parent/quota"
if [[ "$DECOMP_TEST_ACP_QUOTA_TMPFS" != "$acp_quota_mount" ||
  -L "$acp_quota_parent" || -L "$acp_quota_mount" ]]; then
  echo "refusing cleanup of an unexpected ACP quota fixture path" >&2
  exit 1
fi
if [[ "$(stat --format='%u:%a' "$acp_quota_parent")" != 0:755 ]] ||
  [[ "$(findmnt --mountpoint "$acp_quota_mount" --noheadings --output FSTYPE)" != tmpfs ]] ||
  [[ "$(findmnt --mountpoint "$acp_quota_mount" --noheadings --output SOURCE)" != decomp-acp-contract ]]; then
  echo "ACP quota fixture identity changed; refusing to unmount unrelated state" >&2
  exit 1
fi
timeout --kill-after=5s 15s sudo -n umount "$acp_quota_mount"
if mountpoint --quiet "$acp_quota_mount"; then
  echo "ACP quota fixture remains mounted" >&2
  exit 1
fi
sudo -n rmdir "$acp_quota_mount"
sudo -n rmdir "$acp_quota_parent"
