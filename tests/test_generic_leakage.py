from __future__ import annotations

import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCANNER_PATH = REPOSITORY_ROOT / "scripts/check-generic-leakage.py"
SCANNER = runpy.run_path(str(SCANNER_PATH))
scan_repository = SCANNER["scan_repository"]
PolicyError = SCANNER["PolicyError"]
FIXTURE = json.loads(
    (REPOSITORY_ROOT / "oracle/gcc/neutrality-test-fixtures.json").read_text(encoding="utf-8")
)


class GenericLeakageTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="neutrality-scanner-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        subprocess.run(
            ["git", "init", "--quiet", str(self.root)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        (self.root / "src").mkdir()
        (self.root / "oracle/gcc").mkdir(parents=True)
        self.policy = {
            "schemaVersion": 1,
            "genericRoots": ["src"],
            "benchmarkRoots": ["oracle/gcc"],
            "adapterFiles": [],
            "allowances": [],
            "benchmarkCatalog": "oracle/gcc/identities.json",
        }
        self.write_json("oracle/gcc/identities.json", {
            "schemaVersion": 1,
            "identities": [FIXTURE["identity"]],
        })
        self.save_policy()

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_json(self, relative: str, document: object) -> None:
        self.write(relative, json.dumps(document, indent=2) + "\n")

    def save_policy(self) -> None:
        self.write_json("oracle/gcc/reconstruction-neutrality-policy.json", self.policy)

    def allowance(self, path: str, rule: str, fragment: str, count: int = 1) -> dict:
        return {
            "path": path,
            "rule": rule,
            "fragment": fragment,
            "count": count,
            "reason": "Authored exact compatibility expression for scanner verification.",
        }

    def test_exact_adapter_ownership_does_not_waive_benchmark_identity(self) -> None:
        source = 'val definition = "Makefile"\nval flags = listOf("-Werror")\n'
        self.write("src/Workflow.kt", source)
        self.write("src/RegisteredAdapter.kt", source +
                   'val identity = "' + FIXTURE["identity"]["sha256"] + '"\n')
        self.policy["adapterFiles"] = [{
            "path": "src/RegisteredAdapter.kt",
            "reason": "Explicit authored adapter implementation.",
        }]
        self.save_policy()

        findings = scan_repository(self.root).findings

        self.assertEqual(
            [(item.path, item.rule) for item in findings],
            [("src/RegisteredAdapter.kt", "benchmark-hash"),
             ("src/Workflow.kt", "generic-layout"),
             ("src/Workflow.kt", "generic-compiler-flag")],
        )

    def test_new_generated_c_filename_does_not_acquire_adapter_ownership(self) -> None:
        self.write("src/RegisteredAdapter.kt", 'val compiler = "cc"\n')
        self.write("src/GeneratedCUnlisted.kt", 'val compiler = "cc"\n')
        self.policy["adapterFiles"] = [{
            "path": "src/RegisteredAdapter.kt",
            "reason": "Only this exact file owns the authored adapter policy.",
        }]
        self.save_policy()

        findings = scan_repository(self.root).findings

        self.assertEqual([(item.path, item.rule) for item in findings],
                         [("src/GeneratedCUnlisted.kt", "generic-tool")])

    def test_generic_policy_rules_report_each_literal_family(self) -> None:
        self.write("src/Workflow.kt", '\n'.join([
            'path.endsWith(".c")',
            'path.removeSuffix(".h")',
            'val source = "src/units"',
            'val tool = "ninja"',
            'val flags = "-std=c11 -fsyntax-only -Iinclude"',
            'val builder = MakeProjectBuilder()',
        ]) + '\n')

        findings = scan_repository(self.root).findings

        self.assertEqual([(item.line, item.rule) for item in findings], [
            (1, "generic-suffix"), (2, "generic-suffix"),
            (3, "generic-layout"), (4, "generic-tool"),
            (5, "generic-compiler-flag"), (5, "generic-compiler-flag"),
            (5, "generic-compiler-flag"), (6, "generic-adapter-reference"),
        ])

    def test_nested_benchmark_ownership_has_a_path_component_boundary(self) -> None:
        document = {
            "version": FIXTURE["version"],
            "target": FIXTURE["target"],
            "sha256": FIXTURE["identity"]["sha256"],
        }
        self.write_json("oracle/gcc/revisions/v9/nested/profile.json", document)
        self.write_json("oracle/gccish/profile.json", document)
        self.write_json("src/profile.json", document)

        findings = scan_repository(self.root).findings

        self.assertEqual({item.path for item in findings},
                         {"oracle/gccish/profile.json", "src/profile.json"})
        for path in ("oracle/gccish/profile.json", "src/profile.json"):
            self.assertEqual({item.rule for item in findings if item.path == path},
                             {"benchmark-version", "benchmark-target", "benchmark-hash"})
        self.assertEqual(len(findings), 6)

    def test_markdown_is_excluded_and_multiline_allowance_preserves_line_numbers(self) -> None:
        self.write("src/README.md", json.dumps(FIXTURE) + '\n"Makefile"\n')
        fragment = 'val tool =\n    "make"'
        self.write("src/Workflow.kt", "// authored context\n" + fragment +
                   '\nval definition = "Makefile"\nval flags = "-Werror"\n')
        self.policy["allowances"] = [self.allowance("src/Workflow.kt", "generic-tool", fragment)]
        self.save_policy()

        findings = scan_repository(self.root).findings

        self.assertEqual([(item.path, item.line, item.rule, item.text) for item in findings], [
            ("src/Workflow.kt", 4, "generic-layout", '"Makefile"'),
            ("src/Workflow.kt", 5, "generic-compiler-flag", "-Werror"),
        ])

    def test_exact_allowance_leaves_neighboring_policy_visible(self) -> None:
        fragment = 'val known = "Makefile"'
        self.write("src/Workflow.kt", fragment + '; val neighboring = "include"\n')
        self.policy["allowances"] = [self.allowance("src/Workflow.kt", "generic-layout", fragment)]
        self.save_policy()

        findings = scan_repository(self.root).findings

        self.assertEqual([(item.line, item.rule, item.text) for item in findings],
                         [(1, "generic-layout", '"include"')])

    def test_stale_and_unused_allowances_are_rejected(self) -> None:
        self.write("src/Workflow.kt", 'val definition = "Makefile"\nval count = 1\n')
        cases = (
            (self.allowance("src/Workflow.kt", "generic-layout", '"Makefile"', 2), "stale"),
            (self.allowance("src/Workflow.kt", "generic-layout", '"missing"'), "stale"),
            (self.allowance("src/Workflow.kt", "generic-layout", "val count = 1"), "unused"),
        )
        for entry, message in cases:
            with self.subTest(message=message, fragment=entry["fragment"]):
                self.policy["allowances"] = [entry]
                self.save_policy()
                with self.assertRaisesRegex(PolicyError, message):
                    scan_repository(self.root)

    def test_duplicate_and_overlapping_allowances_are_rejected(self) -> None:
        self.write("src/Workflow.kt", 'val definition = "Makefile"\n')
        narrow = self.allowance("src/Workflow.kt", "generic-layout", '"Makefile"')
        broad = self.allowance("src/Workflow.kt", "generic-layout", 'val definition = "Makefile"')
        for entries, message in (([narrow, dict(narrow)], "duplicate"), ([narrow, broad], "overlapping")):
            with self.subTest(message=message):
                self.policy["allowances"] = entries
                self.save_policy()
                with self.assertRaisesRegex(PolicyError, message):
                    scan_repository(self.root)

    def test_duplicate_and_overlapping_roots_are_rejected(self) -> None:
        (self.root / "src/nested").mkdir()
        for roots, message in ((["src", "src"], "duplicate"), (["src", "src/nested"], "overlapping")):
            with self.subTest(message=message):
                self.policy["genericRoots"] = roots
                self.save_policy()
                with self.assertRaisesRegex(PolicyError, message):
                    scan_repository(self.root)

    def test_generic_and_benchmark_roots_cannot_overlap(self) -> None:
        self.policy["benchmarkRoots"] = ["src"]
        self.save_policy()
        with self.assertRaisesRegex(PolicyError, "must be disjoint"):
            scan_repository(self.root)

    def test_allowances_cannot_overlap_across_rule_ids(self) -> None:
        source = 'val tool = "make"\n'
        self.write("src/Workflow.kt", source)
        self.policy["allowances"] = [
            self.allowance("src/Workflow.kt", "generic-tool", '"make"'),
            self.allowance("src/Workflow.kt", "generic-layout", source),
        ]
        self.save_policy()
        with self.assertRaisesRegex(PolicyError, "overlapping literal allowances"):
            scan_repository(self.root)

    def test_scans_version_assignments_build_descendants_and_dockerfile_variants(self) -> None:
        self.write("src/Workflow.kt", "GCC_VERSION=16.2.0\nval output = \"build/reconstructed/program\"\n")
        self.write("src/Dockerfile.dev", 'val output = "build/reconstructed/program"\n')

        findings = scan_repository(self.root).findings

        self.assertEqual(
            [(item.path, item.rule, item.text) for item in findings],
            [
                ("src/Dockerfile.dev", "generic-layout", '"build/reconstructed/program"'),
                ("src/Workflow.kt", "benchmark-version", "GCC_VERSION=16.2.0"),
                ("src/Workflow.kt", "generic-layout", '"build/reconstructed/program"'),
            ],
        )

    def test_missing_declared_roots_are_rejected(self) -> None:
        for field in ("genericRoots", "benchmarkRoots"):
            with self.subTest(field=field):
                original = self.policy[field]
                self.policy[field] = ["missing-root"]
                self.save_policy()
                with self.assertRaisesRegex(PolicyError, "scan path is unavailable"):
                    scan_repository(self.root)
                self.policy[field] = original

    def test_non_normalized_roots_and_non_string_rules_are_rejected(self) -> None:
        for root in (".", "src/", "src/../src"):
            with self.subTest(root=root):
                self.policy["genericRoots"] = [root]
                self.save_policy()
                with self.assertRaisesRegex(PolicyError, "not normalized"):
                    scan_repository(self.root)
        self.policy["genericRoots"] = ["src"]
        self.write("src/Workflow.kt", 'val definition = "Makefile"\n')
        entry = self.allowance("src/Workflow.kt", "generic-layout", '"Makefile"')
        entry["rule"] = []
        self.policy["allowances"] = [entry]
        self.save_policy()
        with self.assertRaisesRegex(PolicyError, "unknown rule"):
            scan_repository(self.root)

    def test_duplicate_policy_json_fields_are_rejected(self) -> None:
        document = json.dumps(self.policy)
        self.write("oracle/gcc/reconstruction-neutrality-policy.json", '{"schemaVersion": 1,' + document[1:])

        with self.assertRaisesRegex(PolicyError, "duplicate policy JSON field"):
            scan_repository(self.root)

    def test_supported_untracked_sources_are_scanned_and_binary_and_ignored_untracked_files_are_omitted(self) -> None:
        self.write(".gitignore", "src/ignored.kt\n")
        self.write("src/Workflow.kt", 'val definition = "Makefile"\n')
        self.write("src/helper.py", 'compiler = "cc"\n')
        self.write("src/ignored.kt", 'val tool = "ninja"\n')
        (self.root / "src/authored.bin").write_bytes(bytes([255, 0, 128]))

        findings = scan_repository(self.root).findings

        self.assertEqual([(item.path, item.rule) for item in findings], [
            ("src/Workflow.kt", "generic-layout"),
            ("src/helper.py", "generic-tool"),
        ])

    def test_unstaged_deletions_are_omitted_but_tracked_ignored_sources_are_scanned(self) -> None:
        self.write("src/removed.kt", 'val definition = "Makefile"\n')
        self.write("src/retained.kt", 'val definition = "Makefile"\n')
        subprocess.run(["git", "-C", str(self.root), "add", "src"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (self.root / "src/removed.kt").unlink()
        self.write(".gitignore", "src/*.kt\n")

        findings = scan_repository(self.root).findings

        self.assertEqual([(item.path, item.rule) for item in findings],
                         [("src/retained.kt", "generic-layout")])

    def test_cli_distinguishes_clean_findings_and_policy_errors(self) -> None:
        command = [sys.executable, "-B", str(SCANNER_PATH), "--root", str(self.root),
                   "--policy", "oracle/gcc/reconstruction-neutrality-policy.json", "--json"]
        self.write("src/Workflow.kt", "val count = 1\n")
        clean = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        self.assertEqual(json.loads(clean.stdout)["findings"], [])

        self.write("src/Workflow.kt", 'val definition = "Makefile"\n')
        finding = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
        self.assertEqual(finding.returncode, 1, finding.stdout + finding.stderr)
        document = json.loads(finding.stdout)
        self.assertEqual([(item["path"], item["line"], item["rule"]) for item in document["findings"]],
                         [("src/Workflow.kt", 1, "generic-layout")])

        self.policy["schemaVersion"] = 2
        self.save_policy()
        invalid = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
        self.assertEqual(invalid.returncode, 2, invalid.stdout + invalid.stderr)
        self.assertIn("unsupported neutrality policy schema", json.loads(invalid.stdout)["error"])


if __name__ == "__main__":
    unittest.main()
