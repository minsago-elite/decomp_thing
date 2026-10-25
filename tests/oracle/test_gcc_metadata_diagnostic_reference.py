from __future__ import annotations

import base64
import json
import hashlib
import lzma
import re
from pathlib import Path
import runpy
import unittest
import tempfile
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CAPTURE = runpy.run_path(str(REPOSITORY_ROOT / "scripts/capture-gcc-preprocessing-reference.py"))
ORACLE = REPOSITORY_ROOT / "oracle/gcc/16.2.0"
RECORD = json.loads((ORACLE / "metadata-diagnostic-reference.json").read_text())
CORPUS = json.loads((ORACLE / "behavior-corpus.json").read_text())
substitute = CAPTURE["substitute"]

# A standalone `gcc` word outside install paths; `GCC` and `/lib/gcc/` do not match.
DRIVER_WORD = re.compile(r"(?<![\w/.-])gcc(?![\w/-])")
# Real GCC 16.2.0 prints these words verbatim whatever name the driver is invoked as.
LITERAL_GCC_LINES = {
    "gcc version 16.2.0 (GCC) ",
    "                           prefixes to other gcc components.",
}


def streams(case: dict):
    for name in ("stdout", "stderr"):
        yield name, base64.b64decode(case["observed"][name]["base64"])


class MetadataDiagnosticReferenceTest(unittest.TestCase):
    def test_metadata_cases_never_pass_nostdinc(self) -> None:
        for spec in CAPTURE["METADATA_CASES"]:
            self.assertNotIn("-nostdinc", spec["arguments"], spec["id"])
        for case in RECORD["cases"]:
            self.assertNotIn("-nostdinc", case["arguments"], case["id"])

    def test_metadata_toolchain_does_not_claim_nostdinc(self) -> None:
        self.assertNotRegex(RECORD["toolchain"]["includeSearch"], r"^-nostdinc")
        self.assertIn("no metadata case passes -nostdinc", RECORD["toolchain"]["includeSearch"])

    def test_metadata_runtime_inventory_does_not_claim_image_execution_owners(self) -> None:
        for field in ("driver", "frontend", "target", "resourceIncludeDirectory"):
            self.assertNotIn(field, RECORD["toolchain"])
        self.assertIn("metadata executable owners", RECORD["toolchain"]["scope"])

    def test_driver_only_cases_agree_with_the_authenticated_corpus(self) -> None:
        cases = {tuple(case["arguments"]): case for case in RECORD["cases"]}
        compared = []
        for expected in CORPUS["cases"]:
            case = cases.get(tuple(expected["arguments"]))
            if case is None:
                continue
            compared.append(expected["id"])
            self.assertEqual(case["driver"], "oracle", case["id"])
            self.assertEqual(case["observed"]["exitCode"], expected["expected"]["exitCode"], case["id"])
            for name, data in streams(case):
                # The corpus invokes the oracle as `oracle`; that is the permitted basename substitution.
                self.assertEqual(
                    substitute(data, {"driver-basename": "oracle"}),
                    base64.b64decode(expected["expected"][name]["base64"]),
                    f"{case['id']} {name}",
                )
        self.assertIn("metadata-dumpmachine", compared)
        self.assertIn("metadata-version", compared)
        self.assertIn("help-driver", compared)

    def test_oracle_driver_identity_matches_the_manifest(self) -> None:
        stripped = json.loads((ORACLE / "oracle-manifest.json").read_text())["artifacts"]["stripped"]
        self.assertEqual(RECORD["oracleDriver"]["sha256"], stripped["sha256"])
        self.assertEqual(RECORD["oracleDriver"]["bytes"], stripped["bytes"])

    def test_configuration_cases_run_the_oracle_driver(self) -> None:
        configuration = {"version", "target", "configuration", "search-directory", "help"}
        for case in RECORD["cases"]:
            if configuration & set(case["categories"]):
                self.assertEqual(case["driver"], "oracle", case["id"])

    def test_every_metadata_case_executes_the_authenticated_driver(self) -> None:
        self.assertTrue(all(case["driver"] == "oracle" for case in RECORD["cases"]))
        expected_frontend = {"missing-input-file", "option-invalid-frontend-value", "malformed-source"}
        self.assertEqual({case["id"] for case in RECORD["cases"] if case.get("frontend")}, expected_frontend)
        for spec in CAPTURE["METADATA_CASES"]:
            self.assertEqual(spec["driver"], "oracle")
            self.assertEqual(spec["frontend"], spec["id"] in expected_frontend)

    def test_frontend_and_link_support_are_bound_to_recorded_identity(self) -> None:
        frontend = RECORD["oracleFrontend"]
        manifest = json.loads((ORACLE / "cc1-oracle-manifest.json").read_text())
        driver = json.loads((ORACLE / "oracle-manifest.json").read_text())
        self.assertEqual(frontend["source"], driver["oracle"])
        self.assertEqual(frontend["sourceLock"], driver["inputs"]["sourceLock"])
        self.assertEqual(frontend["sha256"], manifest["artifacts"]["stripped"]["sha256"])
        self.assertEqual(frontend["bytes"], manifest["artifacts"]["stripped"]["bytes"])
        link_case = next(case for case in RECORD["cases"] if case["id"] == "malformed-link-input")
        self.assertEqual(link_case["environment"], {**CAPTURE["ENVIRONMENT"], **RECORD["linkSupport"]["environment"]})
        self.assertEqual({tool["role"] for tool in RECORD["linkSupport"]["tools"]}, {"collect2", "ld"})
        self.assertEqual(RECORD["linkSupport"]["imageConfig"], CAPTURE["IMAGE_CONFIG"])

    def test_frontend_archive_is_verified_before_extraction_is_published(self) -> None:
        prepare = CAPTURE["prepare_oracle_frontend"]
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            identity = prepare(scratch)
            artifact = scratch / "oracle-cc1"
            self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), identity["sha256"])
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o555)
        compressed = CAPTURE["ORACLE_FRONTEND_ARCHIVE"].read_bytes()
        invalid_archives = {
            "wrong-content": lzma.compress(b"not the authenticated frontend"),
            "trailing-bytes": compressed + b"unbound trailing data",
            "truncated": compressed[:-8],
            "oversize-output": lzma.compress(bytes(RECORD["oracleFrontend"]["bytes"] + 1)),
        }
        for name, data in invalid_archives.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                scratch = Path(directory)
                archive = scratch / "bad.xz"
                archive.write_bytes(data)
                with self.assertRaises(SystemExit):
                    prepare(scratch, archive)
                self.assertFalse((scratch / "oracle-cc1").exists())

    def test_frontend_rejects_an_unbound_source_revision(self) -> None:
        prepare = CAPTURE["prepare_oracle_frontend"]
        manifest = json.loads(CAPTURE["ORACLE_FRONTEND_MANIFEST"].read_text())
        manifest["oracle"]["sourceRevision"] = "0" * 40
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            changed = scratch / "manifest.json"
            changed.write_text(json.dumps(manifest))
            with patch.dict(prepare.__globals__, {"ORACLE_FRONTEND_MANIFEST": changed}):
                with self.assertRaisesRegex(SystemExit, "source identities differ"):
                    prepare(scratch)
            self.assertFalse((scratch / "oracle-cc1").exists())

    def test_record_substitutions_match_capture_script(self) -> None:
        self.assertEqual(RECORD["identitySubstitutions"], CAPTURE["IDENTITY_SUBSTITUTIONS"])
        self.assertEqual(len(RECORD["cases"]), len(CAPTURE["METADATA_CASES"]))

    def test_driver_name_substitutions_cover_every_driver_name_site(self) -> None:
        values = {"driver-basename": "candidate-cc", "driver-argv0": "/opt/candidate-cc"}
        for case in RECORD["cases"]:
            for name, data in streams(case):
                for line in substitute(data, values).decode().split("\n"):
                    if line in LITERAL_GCC_LINES:
                        continue
                    self.assertIsNone(DRIVER_WORD.search(line), f"{case['id']} {name}: {line!r}")

    def test_each_driver_name_pattern_matches_the_record(self) -> None:
        text = "\n".join(data.decode() for case in RECORD["cases"] for _, data in streams(case))
        for rule in RECORD["identitySubstitutions"]:
            for pattern in rule["patterns"]:
                self.assertRegex(text, re.compile(pattern, re.MULTILINE), rule["id"])

    def test_configured_prefix_substitution_covers_retained_verbose_output(self) -> None:
        case = next(case for case in RECORD["cases"] if case["id"] == "verbose-configuration")
        original = base64.b64decode(case["observed"]["stderr"]["base64"])
        expected = original.replace(b"--prefix=/oracle/install ", b"--prefix=/candidate/install ")
        self.assertNotEqual(original, expected)
        # argv[0] is an independent identity and does not need to share the install prefix.
        actual = substitute(original, {
            "driver-argv0": "/retained/path/gcc",
            "install-prefix": "/candidate/install",
        })
        self.assertEqual(
            actual,
            expected.replace(b"COLLECT_GCC=/oracle/install/bin/gcc", b"COLLECT_GCC=/retained/path/gcc"),
        )

    def test_configured_prefix_substitution_has_bounded_argument_and_line(self) -> None:
        allowed = (
            b"Configured with: /source/configure --prefix=/oracle/install --enable-languages=c\n"
            b"Configured with: /source/configure --prefix=/oracle/install\n"
        )
        self.assertEqual(
            substitute(allowed, {"install-prefix": "/candidate"}),
            allowed.replace(b"--prefix=/oracle/install", b"--prefix=/candidate"),
        )
        unchanged = (
            b"Configured with: /source/configure --prefix=/oracle/install-extra --enable-languages=c\n"
            b"Configured with: /source/configure --exec-prefix=/oracle/install --enable-languages=c\n"
            b"Configured with: /source/configure --prefix=/unrelated/oracle/install\n"
            b"gcc: error: unexpected --prefix=/oracle/install argument\n"
        )
        self.assertEqual(substitute(unchanged, {"install-prefix": "/candidate"}), unchanged)

    def test_substitute_replaces_only_the_captured_span(self) -> None:
        data = (
            b"gcc (GCC) 16.2.0\n"
            b"COLLECT_GCC=/oracle/install/bin/gcc\n"
            b"install: /oracle/install/lib/gcc/x86_64-pc-linux-gnu/16.2.0/\n"
            b"gcc version 16.2.0 (GCC) \n"
            b"gcc: fatal error: no input files\n"
        )
        values = {"driver-basename": "xcc", "driver-argv0": "/opt/bin/xcc", "install-prefix": "/opt"}
        self.assertEqual(
            substitute(data, values),
            b"xcc (GCC) 16.2.0\n"
            b"COLLECT_GCC=/opt/bin/xcc\n"
            b"install: /opt/lib/gcc/x86_64-pc-linux-gnu/16.2.0/\n"
            b"gcc version 16.2.0 (GCC) \n"
            b"xcc: fatal error: no input files\n",
        )


if __name__ == "__main__":
    unittest.main()
