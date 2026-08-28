#!/usr/bin/env python3
"""Emit deterministic build-record tool entries for named role/path pairs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", action="append", nargs=2, metavar=("ROLE", "PATH"), required=True)
    parser.add_argument(
        "--version-command",
        action="append",
        nargs=2,
        default=[],
        metavar=("ROLE", "JSON_ARGV"),
        help="override PATH --version for one role with a JSON argv array beginning with PATH",
    )
    arguments = parser.parse_args()
    version_commands = {}
    for role, raw_command in arguments.version_command:
        if role in version_commands:
            parser.error(f"duplicate version command for role: {role}")
        try:
            command = json.loads(raw_command)
        except json.JSONDecodeError as error:
            parser.error(f"invalid JSON version command for {role}: {error}")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
            parser.error(f"version command for {role} must be a non-empty JSON string array")
        version_commands[role] = command

    records = []
    tool_roles = {role for role, _ in arguments.tool}
    unknown_roles = sorted(set(version_commands) - tool_roles)
    if unknown_roles:
        parser.error(f"version command has no matching tool role: {', '.join(unknown_roles)}")
    for role, raw_path in sorted(arguments.tool):
        path = Path(raw_path)
        if path.is_symlink() or not path.is_file():
            parser.error(f"{role} path must be a non-symlink regular file: {path}")
        command = version_commands.get(role, [str(path), "--version"])
        if command[0] != str(path):
            parser.error(f"version command for {role} must begin with its tool path: {path}")
        completed = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        payload = path.read_bytes()
        records.append(
            {
                "executableBytes": len(payload),
                "executableSha256": hashlib.sha256(payload).hexdigest(),
                "path": str(path),
                "role": role,
                "versionCommand": command,
                "versionOutput": completed.stdout.decode("utf-8"),
            }
        )
    print(json.dumps(records, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
