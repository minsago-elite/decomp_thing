#!/usr/bin/env bash
# Pure profile checks: no mounts, privilege changes, or host writes.
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd -P)"
source "$project_root/scripts/oracle-ext4-scratch-profile.sh"
for selected in first replay; do
  oracle_ext4_scratch_profile "--gcc-metadata-reference-$selected"
  test "$image_size" = 512M
  test "$inode_count" = 16384
  test "$scratch_profile_name" = "gcc-metadata-reference-$selected"
  test "$environment_prefix" = "DECOMP_GCC_METADATA_${selected^^}"
  test "$mount_parent" = "/var/lib/decomp-gcc-metadata-reference-$selected-ci"
  test "$image_basename" = "decomp-gcc-metadata-reference-$selected-ext4-scratch.img"
done
oracle_ext4_scratch_profile ''
test "$image_size:$inode_count:$environment_prefix" = '64M:4096:DECOMP_TEST_ORACLE_EXT4'
oracle_ext4_scratch_profile --bundled-ghidra
test "$image_size:$inode_count" = '1G:16384'
oracle_ext4_scratch_profile --gcc-engine-cc1-fresh
test "$image_size:$inode_count" = '12G:262144'
if oracle_ext4_scratch_profile --gcc-metadata-reference-unknown 2>/dev/null; then
  echo 'scratch profile accepted an unregistered reference selection' >&2
  exit 1
fi
printf '%s\n' 'Oracle ext4 scratch profile checks passed.'
