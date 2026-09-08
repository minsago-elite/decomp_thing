#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/ci-release-bundled-ghidra-runtime.sh" >&2
  exit 64
fi

: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
if [[ ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,19}$ ||
  ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,19}$ ]]; then
  echo "bundled Ghidra release requires bounded positive GitHub run identities" >&2
  exit 1
fi
target="/var/lib/decomp-ci-ghidra-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
if [[ -n "${DECOMP_TEST_BUNDLED_GHIDRA_ROOT:-}" &&
  "$DECOMP_TEST_BUNDLED_GHIDRA_ROOT" != "$target/bundle" ]]; then
  echo "bundled Ghidra release refuses an unexpected runtime target" >&2
  exit 1
fi

sudo -n /usr/bin/python3 - "$target" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" <<'PY'
import os
import stat
import sys

target, run_id, attempt = sys.argv[1:]
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
marker_name = ".decomp-ci-bundled-ghidra-owner-v1"
records = {}
children_by_path = {}
counts = {"entries": 0, "bytes": 0}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def identity(attributes):
    return (attributes.st_dev, attributes.st_ino, attributes.st_mode, attributes.st_uid, attributes.st_gid)

def names(directory):
    result = []
    with os.scandir(directory) as children:
        for child in children:
            require(len(result) < 20_002, "runtime cleanup directory exceeds its entry bound")
            result.append(child.name)
    return sorted(result)

def require_trusted_directory(descriptor):
    attributes = os.fstat(descriptor)
    require(stat.S_ISDIR(attributes.st_mode) and attributes.st_uid == 0 and
            stat.S_IMODE(attributes.st_mode) & 0o022 == 0,
            "runtime cleanup ancestor is not a root-owned non-writable directory")
    return attributes

def require_no_mounts():
    with open("/proc/self/mountinfo", "rb") as source:
        content = source.read(16 * 1024 * 1024 + 1)
    require(len(content) <= 16 * 1024 * 1024, "runtime cleanup mount table exceeds its byte bound")
    lines = content.decode("utf-8", errors="strict").splitlines()
    require(len(lines) <= 100_000, "runtime cleanup mount table exceeds its record bound")
    for line in lines:
        require(len(line) <= 65536 and " - " in line, "runtime cleanup mount record is invalid")
        fields = line.split(" - ", 1)[0].split(" ")
        require(len(fields) >= 6, "runtime cleanup mount record is incomplete")
        require(fields[4] != target and not fields[4].startswith(target + "/"),
                "runtime cleanup refuses a mounted runtime tree")

def inspect(directory, relative=""):
    require_trusted_directory(directory)
    selected_names = names(directory)
    children_by_path[relative] = selected_names
    if not relative:
        require(marker_name in selected_names and set(selected_names) <= {marker_name, "bundle"},
                "runtime cleanup target has unexpected top-level entries")
    for name in selected_names:
        path = f"{relative}/{name}" if relative else name
        require(len(path.split("/")) <= 33 and len(path.encode("utf-8")) <= 4103,
                "runtime cleanup path exceeds its bound")
        counts["entries"] += 1
        require(counts["entries"] <= 20_002, "runtime cleanup exceeds its entry bound")
        attributes = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(path != "bundle" or stat.S_ISDIR(attributes.st_mode),
                "runtime cleanup bundle root is not a directory")
        require(attributes.st_uid == 0 and attributes.st_gid == 0 and
                stat.S_IMODE(attributes.st_mode) & 0o022 == 0,
                "runtime cleanup entry has untrusted ownership or permissions")
        records[path] = identity(attributes)
        if stat.S_ISDIR(attributes.st_mode):
            require(path != marker_name and stat.S_IMODE(attributes.st_mode) in (0o700, 0o755),
                    "runtime cleanup directory has unexpected permissions")
            child = os.open(name, directory_flags, dir_fd=directory)
            try:
                require(identity(os.fstat(child)) == records[path], "runtime cleanup directory was replaced")
                inspect(child, path)
            finally:
                os.close(child)
        else:
            require(stat.S_ISREG(attributes.st_mode) and attributes.st_nlink == 1 and
                    stat.S_IMODE(attributes.st_mode) in ((0o444,) if path == marker_name else (0o600, 0o644, 0o755)),
                    "runtime cleanup rejects a linked, special or incorrectly permissioned file")
            require(0 <= attributes.st_size <= 128 * 1024 * 1024, "runtime cleanup file exceeds its byte bound")
            counts["bytes"] += attributes.st_size
            require(counts["bytes"] <= 2 * 1024 * 1024 * 1024 + 1024,
                    "runtime cleanup exceeds its aggregate byte bound")
    require(names(directory) == selected_names, "runtime cleanup directory changed during inspection")

def remove_contents(directory, relative=""):
    require(names(directory) == children_by_path[relative], "runtime cleanup membership changed before removal")
    for name in children_by_path[relative]:
        if not relative and name == marker_name:
            continue
        path = f"{relative}/{name}" if relative else name
        selected = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(identity(selected) == records[path], "runtime cleanup entry was replaced before removal")
        if stat.S_ISDIR(selected.st_mode):
            child = os.open(name, directory_flags, dir_fd=directory)
            try:
                require(identity(os.fstat(child)) == records[path], "runtime cleanup selected a replaced directory")
                remove_contents(child, path)
                require(identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == records[path],
                        "runtime cleanup directory name was replaced")
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory)
        else:
            os.unlink(name, dir_fd=directory)

require(os.geteuid() == 0, "explicit CI runtime release requires root")
require(target == f"/var/lib/decomp-ci-ghidra-{run_id}-{attempt}", "runtime cleanup target differs")
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
            try:
                descriptor = os.open(target_name, directory_flags, dir_fd=runtime_parent)
            except FileNotFoundError:
                print("No provisioned bundled Ghidra runtime remains")
                sys.exit(0)
            try:
                original = require_trusted_directory(descriptor)
                require(stat.S_IMODE(original.st_mode) in (0o700, 0o755), "runtime cleanup target mode differs")
                marker_descriptor = os.open(marker_name, os.O_RDONLY | os.O_NOFOLLOW |
                                            os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptor)
                try:
                    marker_attributes = os.fstat(marker_descriptor)
                    require(stat.S_ISREG(marker_attributes.st_mode) and marker_attributes.st_uid == 0 and
                            marker_attributes.st_gid == 0 and marker_attributes.st_nlink == 1 and
                            stat.S_IMODE(marker_attributes.st_mode) == 0o444 and marker_attributes.st_size <= 1024,
                            "runtime cleanup ownership marker has an invalid identity")
                    expected = ("decomp-ci-bundled-ghidra-runtime-v1\n"
                                f"run_id={run_id}\nrun_attempt={attempt}\npath={target}\n"
                                f"identity={original.st_dev}:{original.st_ino}\n").encode("ascii")
                    require(os.read(marker_descriptor, 1025) == expected, "runtime cleanup ownership marker differs")
                finally:
                    os.close(marker_descriptor)
                require_no_mounts()
                inspect(descriptor)
                require_no_mounts()
                remove_contents(descriptor)
                require(names(descriptor) == [marker_name] and
                        identity(os.stat(marker_name, dir_fd=descriptor, follow_symlinks=False)) == records[marker_name],
                        "runtime cleanup marker changed before final removal")
                require(identity(os.stat(target_name, dir_fd=runtime_parent, follow_symlinks=False)) == identity(original),
                        "runtime cleanup target name was replaced")
                os.unlink(marker_name, dir_fd=descriptor)
                os.fsync(descriptor)
                os.rmdir(target_name, dir_fd=runtime_parent)
                os.fsync(runtime_parent)
                print(f"Released provisioned application-bundled Ghidra: {target}")
            finally:
                os.close(descriptor)
        finally:
            os.close(runtime_parent)
    finally:
        os.close(var)
finally:
    os.close(filesystem_root)
PY
