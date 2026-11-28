#!/usr/bin/env python3
"""Compare retained cc1 analyzer censuses without selecting an analyzer profile."""
from pathlib import Path
import argparse
import os
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from oracle.function_recovery import ScoringError
from oracle.gcc.compare_analysis_variants import DEFAULT_MANIFEST, compare_variants, report_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--variant", action="append", required=True, metavar="NAME=PATH")
    parser.add_argument("--rich-artifact", type=Path)
    parser.add_argument("--stripped-artifact", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        variants = {}
        for value in args.variant:
            name, separator, path = value.partition("=")
            if not separator or not path or name in variants:
                raise ScoringError("each variant must have one unique NAME=PATH")
            variants[name] = Path(path)
        output = args.output.absolute()
        if not output.parent.resolve(strict=True).is_relative_to(ROOT):
            raise ScoringError("output parent must be inside this repository")
        report = compare_variants(manifest_path=args.manifest, baseline_path=args.baseline, variant_paths=variants,
                                  rich_artifact_path=args.rich_artifact, stripped_artifact_path=args.stripped_artifact)
        # Never overwrite earlier evidence or an input, including a symlink target.
        descriptor, staged_name = tempfile.mkstemp(prefix=".analysis-comparison-", dir=output.parent)
        staged = Path(staged_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(report_bytes(report))
                stream.flush()
                os.fsync(stream.fileno())
            os.link(staged, output, follow_symlinks=False)
        finally:
            staged.unlink(missing_ok=True)
        print(f"retained diagnostic entry deltas: {output}")
        print("Reviewed source-function accuracy unavailable; production analyzer selection unchanged.")
        return 0
    except (ScoringError, OSError, ValueError) as error:
        print(f"analyzer comparison failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
