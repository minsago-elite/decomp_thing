#!/usr/bin/env python3
"""Exercise the actual CI entry point with an inert argument-recording Gradle fixture."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
BASE = ["--no-daemon", "verifyReconstructionNeutrality", "test"]
ISOLATED = [
    "v3BoundaryFinalStagingIsolated",
    "v3BoundaryPublicationIsolated",
    "v3BoundaryCensusIsolated",
]


class CiPartitionRoutingTest(unittest.TestCase):
    def setUp(self):
        build = REPOSITORY / "build"
        build.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="ci partition routing ", dir=build)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "scripts/ci.sh").write_bytes((REPOSITORY / "scripts/ci.sh").read_bytes())
        gradle = self.root / "gradlew"
        gradle.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            "with pathlib.Path('arguments.jsonl').open('a') as output:\n"
            "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        gradle.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, selector):
        environment = os.environ.copy()
        environment.pop("DECOMP_CI_TEST_SHARD", None)
        if selector is not None:
            environment["DECOMP_CI_TEST_SHARD"] = selector
        capture = self.root / "arguments.jsonl"
        if capture.exists():
            capture.unlink()
        result = subprocess.run(
            ["bash", str(self.root / "scripts/ci.sh")],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        invocations = [json.loads(line) for line in capture.read_text().splitlines()] if capture.exists() else []
        return result, invocations

    def assert_selection(self, selector, expected):
        result, invocations = self.invoke(selector)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([expected], invocations)

    def test_full_and_unset_entry_points_keep_all_isolated_checks(self):
        for selector in [None, "", "full"]:
            with self.subTest(selector=selector):
                self.assert_selection(selector, BASE + ISOLATED + ["-PisolateV3BoundaryTests=true"])

    def test_legacy_core_still_selects_the_complete_non_live_suite(self):
        self.assert_selection("core", BASE + ISOLATED + ["-PciTestShard=core", "-PisolateV3BoundaryTests=true"])

    def test_main_partition_selects_the_complement_without_isolated_oracle_tasks(self):
        self.assert_selection("core-main", BASE + ["-PciTestShard=core-main"])

    def test_oracle_partition_requires_all_three_isolated_boundary_tasks(self):
        self.assert_selection("core-oracle", BASE + ISOLATED + ["-PciTestShard=core-oracle", "-PisolateV3BoundaryTests=true"])

    def test_live_entry_point_keeps_its_original_selection(self):
        self.assert_selection("live", BASE + ["-PciTestShard=live"])

    def test_unsupported_selections_refuse_before_any_gradle_invocation(self):
        for selector in ["core-other", "../../core"]:
            with self.subTest(selector=selector):
                result, invocations = self.invoke(selector)
                self.assertEqual(2, result.returncode)
                self.assertIn("unsupported DECOMP_CI_TEST_SHARD", result.stderr)
                self.assertEqual([], invocations)


if __name__ == "__main__":
    unittest.main()
