from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.full_tree_source_inventory import (  # noqa: E402
    FullTreeSourceInventoryError,
    validate_full_tree_source_inventory,
)


class FullTreeSourceInventoryTest(unittest.TestCase):
    def test_checked_inventory_partitions_source_dwarf_generated_and_tablegen_inputs(self) -> None:
        profile = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
        report_payload = (profile / "full-tree-source-inventory.json").read_bytes()
        report = json.loads(report_payload)
        self.assertEqual(canonical_json_bytes(report), report_payload)
        inventory = json.loads((profile / "full-tree-inventory.json").read_text(encoding="utf-8"))
        scope_sha256 = hashlib.sha256((profile / "full-tree-scope.json").read_bytes()).hexdigest()
        validate_full_tree_source_inventory(report, inventory=inventory, scope_sha256=scope_sha256)
        self.assertEqual(2149, report["counts"]["linkedSourceUnits"])
        self.assertGreater(report["counts"]["sourceOnlyUnits"], 0)
        self.assertGreater(report["counts"]["tablegenInputs"], 0)
        self.assertEqual(1, report["counts"]["generatedCompilationUnits"])

        mutated = json.loads(json.dumps(report))
        removed = next(item for item in mutated["sourceUnits"] if item["classification"] == "linked")
        mutated["sourceUnits"].remove(removed)
        mutated["counts"]["candidateTranslationUnits"] -= 1
        mutated["counts"]["linkedSourceUnits"] -= 1
        without_hash = {key: value for key, value in mutated.items() if key != "reportSha256"}
        mutated["reportSha256"] = hashlib.sha256(canonical_json_bytes(without_hash)).hexdigest()
        with self.assertRaisesRegex(FullTreeSourceInventoryError, "handwritten DWARF"):
            validate_full_tree_source_inventory(mutated, inventory=inventory, scope_sha256=scope_sha256)


if __name__ == "__main__":
    unittest.main()
