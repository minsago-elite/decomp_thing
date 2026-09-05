#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/ci-prepare-bundled-ghidra-runtime.sh" >&2
  exit 64
fi

: "${GITHUB_ENV:?GITHUB_ENV must name the GitHub Actions environment file}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
if [[ ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,19}$ ||
  ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,19}$ ]]; then
  echo "bundled Ghidra provisioning requires bounded positive GitHub run identities" >&2
  exit 1
fi
if [[ ! -f "$GITHUB_ENV" || -L "$GITHUB_ENV" || ! -w "$GITHUB_ENV" ]]; then
  echo "GitHub Actions environment file must be a writable non-linked regular file" >&2
  exit 1
fi

project_root="$(cd "$(dirname "$0")/.." && pwd -P)"
target="/var/lib/decomp-ci-ghidra-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
"$project_root/gradlew" --no-daemon -p "$project_root" installDist
source_bundle="$project_root/build/install/llm_bin_patch/libexec/ghidra"

sudo -n /usr/bin/python3 - "$source_bundle" "$target" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" <<'PY'
import os
import stat
import sys

source, target, run_id, attempt = sys.argv[1:]
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
maximum_entries = 20_000
maximum_file_bytes = 128 * 1024 * 1024
maximum_total_bytes = 2 * 1024 * 1024 * 1024
counts = {"entries": 0, "bytes": 0}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def identity(attributes):
    return (attributes.st_dev, attributes.st_ino, attributes.st_mode, attributes.st_uid,
            attributes.st_gid, attributes.st_size, attributes.st_mtime_ns, attributes.st_ctime_ns)

def names(directory):
    result = []
    with os.scandir(directory) as children:
        for child in children:
            require(len(result) < maximum_entries, "bundled directory exceeds its entry bound")
            result.append(child.name)
    return sorted(result)

def require_trusted_directory(descriptor):
    attributes = os.fstat(descriptor)
    require(stat.S_ISDIR(attributes.st_mode) and attributes.st_uid == 0 and
            stat.S_IMODE(attributes.st_mode) & 0o022 == 0,
            "runtime ancestor is not a root-owned non-writable directory")
    return attributes

def write_all(descriptor, content):
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        require(written > 0, "runtime copy stopped writing")
        remaining = remaining[written:]

def copy_directory(source_descriptor, destination_descriptor, relative=""):
    before = os.fstat(source_descriptor)
    require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o755,
            "installed bundle directory has unexpected permissions")
    selected_names = names(source_descriptor)
    for name in selected_names:
        path = f"{relative}/{name}" if relative else name
        components = path.split("/")
        require(len(components) <= 32 and len(path.encode("utf-8")) <= 4096 and
                all(component.strip() and component not in (".", "..") and
                    len(component.encode("utf-8")) <= 255 for component in components) and
                all(ord(character) >= 32 and ord(character) != 127 and character not in ":\\"
                    for character in path), "installed bundle has an unsafe relative path")
        counts["entries"] += 1
        require(counts["entries"] <= maximum_entries, "installed bundle exceeds its entry bound")
        selected = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
        if stat.S_ISDIR(selected.st_mode):
            child_source = os.open(name, directory_flags, dir_fd=source_descriptor)
            try:
                require(identity(os.fstat(child_source)) == identity(selected), "source directory was replaced")
                os.mkdir(name, 0o700, dir_fd=destination_descriptor)
                child_destination = os.open(name, directory_flags, dir_fd=destination_descriptor)
                try:
                    copy_directory(child_source, child_destination, path)
                finally:
                    os.close(child_destination)
            finally:
                os.close(child_source)
        else:
            require(stat.S_ISREG(selected.st_mode) and stat.S_IMODE(selected.st_mode) in (0o644, 0o755),
                    "installed bundle contains a linked, special or incorrectly permissioned file")
            require(0 <= selected.st_size <= maximum_file_bytes, "installed bundle file exceeds its byte bound")
            counts["bytes"] += selected.st_size
            require(counts["bytes"] <= maximum_total_bytes, "installed bundle exceeds its aggregate byte bound")
            source_file = os.open(name, file_flags, dir_fd=source_descriptor)
            try:
                require(identity(os.fstat(source_file)) == identity(selected), "source file was replaced")
                destination_file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=destination_descriptor)
                try:
                    observed = 0
                    while True:
                        content = os.read(source_file, 65536)
                        if not content:
                            break
                        observed += len(content)
                        require(observed <= selected.st_size, "source file grew during runtime copy")
                        write_all(destination_file, content)
                    require(observed == selected.st_size and identity(os.fstat(source_file)) == identity(selected),
                            "source file changed during runtime copy")
                    os.fchmod(destination_file, stat.S_IMODE(selected.st_mode))
                    os.fsync(destination_file)
                    copied = os.fstat(destination_file)
                    require(copied.st_uid == 0 and copied.st_gid == 0 and copied.st_nlink == 1 and
                            copied.st_size == selected.st_size, "copied runtime file has an invalid identity")
                finally:
                    os.close(destination_file)
            finally:
                os.close(source_file)
        require(identity(os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)) == identity(selected),
                "installed bundle entry changed during runtime copy")
    require(names(source_descriptor) == selected_names and identity(os.fstat(source_descriptor)) == identity(before),
            "installed bundle directory changed during runtime copy")
    os.fchmod(destination_descriptor, 0o755)
    os.fsync(destination_descriptor)
    require_trusted_directory(destination_descriptor)

require(os.geteuid() == 0, "explicit CI provisioning requires root")
require(target == f"/var/lib/decomp-ci-ghidra-{run_id}-{attempt}", "runtime provisioning target differs")
require(os.path.isabs(source) and os.path.realpath(source) == source, "installed source bundle is not canonical")
filesystem_root = os.open("/", directory_flags)
try:
    require_trusted_directory(filesystem_root)
    var = os.open("var", directory_flags, dir_fd=filesystem_root)
    try:
        require_trusted_directory(var)
        runtime_parent = os.open("lib", directory_flags, dir_fd=var)
        try:
            require_trusted_directory(runtime_parent)
            target_name = os.path.basename(target)
            os.mkdir(target_name, 0o700, dir_fd=runtime_parent)
            target_descriptor = os.open(target_name, directory_flags, dir_fd=runtime_parent)
            try:
                target_identity = require_trusted_directory(target_descriptor)
                marker = ("decomp-ci-bundled-ghidra-runtime-v1\n"
                          f"run_id={run_id}\nrun_attempt={attempt}\npath={target}\n"
                          f"identity={target_identity.st_dev}:{target_identity.st_ino}\n").encode("ascii")
                marker_descriptor = os.open(".decomp-ci-bundled-ghidra-owner-v1", os.O_WRONLY | os.O_CREAT |
                                            os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=target_descriptor)
                try:
                    write_all(marker_descriptor, marker)
                    os.fchmod(marker_descriptor, 0o444)
                    os.fsync(marker_descriptor)
                finally:
                    os.close(marker_descriptor)
                os.fsync(target_descriptor)
                os.fsync(runtime_parent)
                require(os.fstatvfs(target_descriptor).f_flag & os.ST_NOEXEC == 0,
                        "provisioned bundled Ghidra runtime filesystem is noexec")
                os.mkdir("bundle", 0o700, dir_fd=target_descriptor)
                bundle_descriptor = os.open("bundle", directory_flags, dir_fd=target_descriptor)
                try:
                    source_descriptor = os.open(source, directory_flags)
                    try:
                        copy_directory(source_descriptor, bundle_descriptor)
                    finally:
                        os.close(source_descriptor)
                finally:
                    os.close(bundle_descriptor)
                os.fchmod(target_descriptor, 0o755)
                os.fsync(target_descriptor)
                require_trusted_directory(target_descriptor)
                require(os.fstatvfs(target_descriptor).f_flag & os.ST_NOEXEC == 0,
                        "provisioned runtime became noexec")
                print(f"Provisioned application-bundled Ghidra: {counts['entries']} entries, {counts['bytes']} bytes at {target}/bundle")
            finally:
                os.close(target_descriptor)
        finally:
            os.close(runtime_parent)
    finally:
        os.close(var)
finally:
    os.close(filesystem_root)
PY

printf 'DECOMP_TEST_BUNDLED_GHIDRA_ROOT=%s/bundle\n' "$target" >>"$GITHUB_ENV"
printf 'DECOMP_REQUIRE_BUNDLED_GHIDRA_RUNTIME=true\n' >>"$GITHUB_ENV"
