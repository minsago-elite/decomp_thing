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
    arguments = parser.parse_args()
    records = []
    for role, raw_path in sorted(arguments.tool):
        path = Path(raw_path)
        if path.is_symlink() or not path.is_file():
            parser.error(f"{role} path must be a non-symlink regular file: {path}")
        command = [str(path), "--version"]
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
