from __future__ import annotations

import json
from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.behavior_corpus import load_corpus  # noqa: E402
from oracle.clang_diagnostic_matrix import (  # noqa: E402
    ClangDiagnosticMatrixError,
    generate_clang_diagnostic_matrix,
    validate_clang_diagnostic_matrix,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


class ClangDiagnosticMatrixTest(unittest.TestCase):
    def test_checked_matrix_is_complete_bound_and_byte_deterministic(self) -> None:
        corpus, _ = load_corpus(REPOSITORY_ROOT / "oracle/llvm/22.1.6/behavior-corpus.json")
        checked = json.loads(
            (REPOSITORY_ROOT / "oracle/llvm/22.1.6/diagnostic-matrix.json").read_text(encoding="utf-8")
        )
        validate_clang_diagnostic_matrix(checked, corpus)
        regenerated = generate_clang_diagnostic_matrix(corpus)
        self.assertEqual(canonical_json_bytes(checked), canonical_json_bytes(regenerated))
        self.assertTrue(all(not case["normalizations"]["stderr"] for case in checked["cases"]))

        mutated = json.loads(json.dumps(checked))
        mutated["cases"][0]["stderrSha256"] = "0" * 64
        with self.assertRaisesRegex(ClangDiagnosticMatrixError, "hash binding"):
            validate_clang_diagnostic_matrix(mutated, corpus)


if __name__ == "__main__":
    unittest.main()
