#!/usr/bin/env bash
set -euo pipefail

# Pure selection and argument checks: no filesystem provisioning or privilege calls.
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
source "$script_dir/oracle-ext4-scratch-profile.sh"

assert_equal() {
  if [[ "$1" != "$2" ]]; then
    printf '%s: expected %s, got %s\n' "$3" "$1" "$2" >&2
    exit 1
  fi
}

assert_module_profile() {
  assert_equal 512M "$image_size" 'module image capacity'
  assert_equal 16384 "$inode_count" 'module inode count'
  assert_equal module-compile "$scratch_profile_name" 'module profile name'
  assert_equal DECOMP_TEST_MODULE_COMPILE_EXT4 "$environment_prefix" 'module environment prefix'
  assert_equal /var/lib/decomp-module-compile-ci/scratch "$mount_parent/scratch" 'module mount target'
  assert_equal decomp-module-compile-ext4-scratch.img "$image_basename" 'module image basename'
}

# The named selection owns every value; inherited values cannot resize or redirect it.
image_size=99G
inode_count=999999
scratch_profile_name=inherited
environment_prefix=INHERITED
mount_parent=/inherited
image_basename=inherited.img
oracle_ext4_scratch_profile --module-compile
assert_module_profile

# Switching from the large export profile must reset its capacity and namespace.
oracle_ext4_scratch_profile --gcc-engine-lto1-resume
assert_equal 12G "$image_size" 'export image capacity'
oracle_ext4_scratch_profile --module-compile
assert_module_profile

# A module selection must not leak into the existing default profile.
oracle_ext4_scratch_profile
assert_equal 64M "$image_size" 'default image capacity'
assert_equal 4096 "$inode_count" 'default inode count'
assert_equal oracle "$scratch_profile_name" 'default profile name'
assert_equal DECOMP_TEST_ORACLE_EXT4 "$environment_prefix" 'default environment prefix'
assert_equal /var/lib/decomp-oracle-ci/scratch "$mount_parent/scratch" 'default mount target'
assert_equal decomp-oracle-ext4-scratch.img "$image_basename" 'default image basename'

for invalid in --module-compile=1G --module-compile-resume --module-compile/../oracle; do
  if output="$(oracle_ext4_scratch_profile "$invalid" 2>&1)"; then
    printf 'unexpected accepted module profile: %s\n' "$invalid" >&2
    exit 1
  else
    assert_equal 64 "$?" 'unknown profile exit status'
    assert_equal "unknown oracle scratch profile: $invalid" "$output" 'unknown profile diagnostic'
  fi
done

# Both entry points reject extra arguments before consulting CI paths or privileged tools.
for entry_point in ci-prepare-oracle-ext4-scratch.sh ci-release-oracle-ext4-scratch.sh; do
  if output="$(env -i PATH="$PATH" bash "$script_dir/$entry_point" --module-compile unexpected 2>&1)"; then
    printf 'unexpected accepted extra argument: %s\n' "$entry_point" >&2
    exit 1
  else
    assert_equal 64 "$?" 'extra argument exit status'
    [[ "$output" == usage:* && "$output" == *--module-compile* ]] || {
      printf 'module profile missing from usage: %s\n' "$entry_point" >&2
      exit 1
    }
  fi
  if output="$(env -i PATH="$PATH" bash "$script_dir/$entry_point" --module-compile=1G 2>&1)"; then
    printf 'unexpected accepted capacity override: %s\n' "$entry_point" >&2
    exit 1
  else
    assert_equal 64 "$?" 'capacity override exit status'
  fi
done

# Use an empty subprocess environment so an existing CI lease cannot be touched.
# Wrong namespace selection would reject these sentinels before any privileged call.
output="$(env -i PATH="$PATH" RUNNER_TEMP="$script_dir" \
  DECOMP_TEST_ORACLE_EXT4_SCRATCH=/other-oracle-lease \
  DECOMP_TEST_ORACLE_EXT4_IMAGE=/other-oracle-image \
  DECOMP_TEST_BUNDLED_GHIDRA_EXT4_SCRATCH=/other-ghidra-lease \
  DECOMP_TEST_BUNDLED_GHIDRA_EXT4_IMAGE=/other-ghidra-image \
  DECOMP_GCC_CLI_CC1_FRESH_SCRATCH=/other-gcc-lease \
  DECOMP_GCC_CLI_CC1_FRESH_IMAGE=/other-gcc-image \
  bash "$script_dir/ci-release-oracle-ext4-scratch.sh" --module-compile 2>&1)"
assert_equal '' "$output" 'empty module release ignores other leases'

for target in SCRATCH IMAGE; do
  if [[ "$target" == SCRATCH ]]; then
    wrong_target=/var/lib/decomp-oracle-ci/scratch
    diagnostic='oracle scratch cleanup refuses an unexpected or linked mount target'
  else
    wrong_target="$script_dir/decomp-oracle-ext4-scratch.img"
    diagnostic='oracle scratch cleanup refuses an unexpected or linked image'
  fi
  if output="$(env -i PATH="$PATH" RUNNER_TEMP="$script_dir" \
    "DECOMP_TEST_MODULE_COMPILE_EXT4_$target=$wrong_target" \
    bash "$script_dir/ci-release-oracle-ext4-scratch.sh" --module-compile 2>&1)"; then
    printf 'unexpected accepted module cleanup target: %s\n' "$target" >&2
    exit 1
  else
    assert_equal 1 "$?" 'cross-profile cleanup target exit status'
    assert_equal "$diagnostic" "$output" 'cross-profile cleanup target diagnostic'
  fi
done

echo 'module compile ext4 scratch profile checks passed'
