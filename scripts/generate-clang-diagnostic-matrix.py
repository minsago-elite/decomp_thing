#!/usr/bin/env python3
"""Generate the checked Clang diagnostic matrix from its reviewed corpus."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(REPOSITORY_ROOT))
from oracle.behavior_corpus import load_corpus  # noqa: E402
from oracle.clang_diagnostic_matrix import generate_clang_diagnostic_matrix  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--corpus", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/behavior-corpus.json"); parser.add_argument("--output", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/diagnostic-matrix.json"); arguments = parser.parse_args()
    corpus, _ = load_corpus(arguments.corpus); matrix = generate_clang_diagnostic_matrix(corpus); arguments.output.write_bytes(canonical_json_bytes(matrix)); print(f"wrote {len(matrix['cases'])} diagnostic cases"); return 0
if __name__ == "__main__": raise SystemExit(main())
