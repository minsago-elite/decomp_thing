#!/usr/bin/env python3
"""Generate canonical cc1/lto1 records from the authenticated GCC base build."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.gcc.compiler_engines import load_compiler_engine_profile  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=REPOSITORY_ROOT / "oracle/gcc/16.2.0/compiler-engines.json")
    parser.add_argument("--output-root", type=Path)
    arguments = parser.parse_args()
    try:
        profile, records = load_compiler_engine_profile(arguments.profile)
        output_root = arguments.output_root or arguments.profile.parent
        output_root.mkdir(parents=True, exist_ok=True)
        for engine in profile["engines"]:
            output = output_root / engine["buildRecord"]
            temporary = output.with_name(f".{output.name}.tmp")
            temporary.write_bytes(canonical_json_bytes(records[engine["id"]]))
            temporary.replace(output)
            print(f"wrote {output}")
    except (OSError, VerificationError) as error:
        print(f"compiler-engine build-record generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
