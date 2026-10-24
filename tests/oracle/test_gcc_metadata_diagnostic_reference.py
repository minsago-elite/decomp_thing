from __future__ import annotations

import base64
import json
import re
from pathlib import Path
import runpy
import unittest


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

    def test_image_cases_carry_no_image_configuration(self) -> None:
        image = [case for case in RECORD["cases"] if case["driver"] == "image"]
        self.assertEqual(
            {case["id"] for case in image},
            {"missing-input-file", "option-invalid-frontend-value", "malformed-source", "malformed-link-input"},
        )
        for case in image:
            for name, data in streams(case):
                for identity in (RECORD["toolchain"]["target"], "/usr/local", "gcc:"):
                    self.assertNotIn(identity.encode(), data, f"{case['id']} {name}")

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
