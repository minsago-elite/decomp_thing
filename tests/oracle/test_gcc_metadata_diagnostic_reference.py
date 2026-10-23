from __future__ import annotations

import base64
import json
import re
from pathlib import Path
import runpy
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CAPTURE = runpy.run_path(str(REPOSITORY_ROOT / "scripts/capture-gcc-preprocessing-reference.py"))
RECORD = json.loads((REPOSITORY_ROOT / "oracle/gcc/16.2.0/metadata-diagnostic-reference.json").read_text())
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
            b"COLLECT_GCC=gcc\n"
            b"COLLECT_LTO_WRAPPER=/usr/local/libexec/gcc/x86_64-linux-gnu/16.2.0/lto-wrapper\n"
            b"gcc version 16.2.0 (GCC) \n"
            b"gcc: fatal error: no input files\n"
        )
        values = {"driver-basename": "xcc", "driver-argv0": "/opt/bin/xcc", "install-prefix": "/opt"}
        self.assertEqual(
            substitute(data, values),
            b"xcc (GCC) 16.2.0\n"
            b"COLLECT_GCC=/opt/bin/xcc\n"
            b"COLLECT_LTO_WRAPPER=/opt/libexec/gcc/x86_64-linux-gnu/16.2.0/lto-wrapper\n"
            b"gcc version 16.2.0 (GCC) \n"
            b"xcc: fatal error: no input files\n",
        )


if __name__ == "__main__":
    unittest.main()
