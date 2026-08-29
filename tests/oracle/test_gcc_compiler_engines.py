from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.gcc.compiler_engines import load_compiler_engine_profile  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


PROFILE = REPOSITORY_ROOT / "oracle/gcc/16.2.0/compiler-engines.json"


class GccCompilerEngineProfileTest(unittest.TestCase):
    def test_checked_profile_binds_budgets_provenance_and_derived_records(self) -> None:
        profile, records = load_compiler_engine_profile(PROFILE)
        self.assertEqual(1800, profile["budgets"]["exportWallClockSeconds"])
        self.assertEqual(16 * 1024 * 1024 * 1024, profile["budgets"]["exportMaximumResidentBytes"])
        self.assertEqual(["cc1", "lto1"], list(records))
        for engine in profile["engines"]:
            record = records[engine["id"]]
            self.assertEqual(engine["buildOutput"], record["commands"]["stageFull"][3])
            self.assertEqual(engine["fullArtifact"], record["outputs"]["full"])
            checked = PROFILE.parent / engine["buildRecord"]
            self.assertEqual(canonical_json_bytes(record), checked.read_bytes())

    def test_cross_engine_substitution_unknown_fields_and_hash_drift_fail_closed(self) -> None:
        base = json.loads(PROFILE.read_text(encoding="utf-8"))
        mutations = []
        substitution = copy.deepcopy(base)
        substitution["engines"][0]["buildOutput"] = "/oracle/build/gcc/lto1"
        mutations.append((substitution, "inconsistent buildOutput"))
        unknown = copy.deepcopy(base)
        unknown["unchecked"] = True
        mutations.append((unknown, "fails JSON Schema"))
        drift = copy.deepcopy(base)
        drift["provenance"]["baseBuildRecordSha256"] = "0" * 64
        mutations.append((drift, "SHA-256"))

        for value, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ("source-lock.json", "build-record.json", "toolchain-reproduction.json"):
                    (root / name).write_bytes((PROFILE.parent / name).read_bytes())
                shutil.copytree(PROFILE.parent / "tag", root / "tag")
                shutil.copytree(PROFILE.parent / "keys", root / "keys")
                path = root / "compiler-engines.json"
                path.write_bytes(canonical_json_bytes(value))
                with self.assertRaisesRegex(VerificationError, message):
                    load_compiler_engine_profile(path)


if __name__ == "__main__":
    unittest.main()
