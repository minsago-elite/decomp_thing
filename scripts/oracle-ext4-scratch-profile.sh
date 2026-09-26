#!/usr/bin/env bash
# Shared, fixed provisioner selections. This file performs no filesystem operations.
oracle_ext4_scratch_profile() {
  image_size=64M
  inode_count=4096
  scratch_profile_name=oracle
  environment_prefix=DECOMP_TEST_ORACLE_EXT4
  case "${1:-}" in
    "") ;;
    --bundled-ghidra)
      scratch_profile_name=bundled-ghidra
      environment_prefix=DECOMP_TEST_BUNDLED_GHIDRA_EXT4
      image_size=1G; inode_count=16384 ;;
    --bundled-ghidra-resume)
      scratch_profile_name=bundled-ghidra-resume
      environment_prefix=DECOMP_TEST_BUNDLED_GHIDRA_RESUME_EXT4
      image_size=1G; inode_count=16384 ;;
    --bundled-ghidra-resume-control)
      scratch_profile_name=bundled-ghidra-resume-control
      environment_prefix=DECOMP_TEST_BUNDLED_GHIDRA_RESUME_CONTROL_EXT4
      image_size=1G; inode_count=16384 ;;
    --gcc-engine-cc1-fresh|--gcc-engine-cc1-resume|--gcc-engine-lto1-fresh|--gcc-engine-lto1-resume)
      scratch_profile_name="${1#--}"
      local engine_mode="${1#--gcc-engine-}"
      environment_prefix="DECOMP_GCC_CLI_${engine_mode^^}"
      environment_prefix="${environment_prefix//-/_}"
      # Full exports can retain a record per function plus global, type, and failure records.
      # Leave inode headroom above cc1's 50,228-function inventory and the 8 GiB host minimum.
      image_size=12G; inode_count=262144 ;;
    *)
      echo "unknown oracle scratch profile: $1" >&2
      return 64 ;;
  esac
  mount_parent="/var/lib/decomp-${scratch_profile_name}-ci"
  image_basename="decomp-${scratch_profile_name}-ext4-scratch.img"
}
