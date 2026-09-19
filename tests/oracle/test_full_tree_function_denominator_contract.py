from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPOSITORY_ROOT / "docs/evidence/full-tree-function-denominator-contract-2026-09-08.json"
FIXTURE_ROOT = REPOSITORY_ROOT / "src/test/resources/oracle/full-tree-function-truth-v2"


class FullTreeFunctionDenominatorContractTest(unittest.TestCase):
    def test_checked_fixture_matches_the_explicit_denominator_slice(self) -> None:
        contract_payload = CONTRACT_PATH.read_bytes()
        contract = json.loads(contract_payload)
        index_payload = (FIXTURE_ROOT / "expected-truth/index.json").read_bytes()
        index = json.loads(index_payload)
        shard_path = FIXTURE_ROOT / "expected-truth/shards/generated-tools-clang.json"
        shard_payload = shard_path.read_bytes()
        shard = json.loads(shard_payload)

        self.assertEqual("fixture-only-evidence", contract["status"])
        self.assertEqual("bf2501568f39ab52b23492dfc37839bb81895587", contract["provenance"]["sourceBaseCommit"])
        self.assertEqual(
            "9f097308c076fbbc8822169db6088ecfa94e2a95449eb2434a39a60a3db6973e",
            contract["provenance"]["scopeSha256"],
        )
        self.assertEqual(
            contract["provenance"]["truthIndexArtifactSha256"],
            hashlib.sha256(index_payload).hexdigest(),
        )
        self.assertEqual(contract["provenance"]["truthIndexSha256"], index["indexSha256"])
        self.assertEqual(
            contract["provenance"]["truthShardSha256"],
            hashlib.sha256(shard_payload).hexdigest(),
        )

        denominator = contract["denominatorContract"]
        functions = shard["functions"]
        non_emitted = shard["nonEmitted"]
        self.assertEqual(4, len(functions))
        self.assertEqual(3, sum(item["population"] == "scored" for item in functions))
        self.assertEqual(1, sum(item["population"] == "excluded" for item in functions))
        self.assertEqual(
            denominator["specializedEvidence"]["coalescedEmittedRvas"],
            sum(item["emissionKind"] == "coalesced-odr-or-comdat" for item in functions),
        )
        self.assertEqual(
            denominator["specializedEvidence"]["thunkEmittedRvas"],
            sum(item["entityKind"] == "thunk" for item in functions),
        )
        self.assertEqual(4, len(non_emitted))
        self.assertTrue(all(item["population"] == "unobservable" for item in non_emitted))
        reason_counts = {
            reason: sum(item["reasonCode"] == reason for item in non_emitted)
            for reason in denominator["nonEmitted"]["reasonCounts"]
        }
        self.assertEqual(denominator["nonEmitted"]["reasonCounts"], reason_counts)

        counts = index["counts"]
        self.assertEqual(3, counts["scoredRvas"])
        self.assertEqual(1, counts["dwarfOnlyRvas"])
        self.assertEqual(1, counts["coalescedEmittedRvas"])
        self.assertEqual(1, counts["inlineOnlyUnique"])
        self.assertEqual(2, counts["selectedElsewhereUnique"])
        self.assertEqual(1, counts["definitionNoRangeUnique"])
        self.assertEqual(6, counts["nonEmittedObservations"])
        self.assertEqual(4, counts["nonEmittedUnique"])

        unresolved = {item["id"] for item in contract["unresolved"]}
        self.assertEqual(
            {
                "template-pattern-and-instance-identity",
                "inline-instance-ownership",
                "typed-comdat-selection-and-discard-reason",
                "normalized-thunk-target",
            },
            unresolved,
        )
        self.assertTrue(all(item["state"] == "unresolved" for item in contract["unresolved"]))
        self.assertTrue(all(item["state"] == "unavailable" for item in contract["productionGates"]))


if __name__ == "__main__":
    unittest.main()
