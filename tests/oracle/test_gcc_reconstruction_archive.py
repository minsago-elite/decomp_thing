from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts/verify-gcc-reconstruction-archive.py"
PROFILE = REPOSITORY_ROOT / "oracle/gcc/16.2.0/compiler-engines.json"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def source_revision(files: dict[str, bytes]) -> str:
    records = [
        {"path": path, "bytes": len(value), "sha256": sha256_bytes(value)}
        for path, value in sorted(files.items())
        if path == "Makefile" or path.startswith("src/") or path.startswith("include/")
    ]
    canonical = "".join(f"{item['path'].__len__()}:{item['path']}:{item['bytes']}:{item['sha256']}\n" for item in records)
    return sha256_bytes(canonical.encode())


class GccReconstructionArchiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="gcc-cc1-archive-test-")
        self.root = Path(self.temporary.name)
        checked = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.expected_input = json.loads(
            (PROFILE.parent / checked["engines"][0]["oracleManifest"]).read_text(encoding="utf-8")
        )["artifacts"]["stripped"]["sha256"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_archive(self, destination: Path, *, input_sha256: str | None = None) -> None:
        files = {
            "Makefile": (
                "CC ?= gcc\nCFLAGS ?= -std=c11 -g -Wall -Wextra -Werror -ffile-prefix-map=$(CURDIR)=/reconstructed\n"
                "all: build/reconstructed\n\n"
                "build/reconstructed: src/main.c\n\tmkdir -p build\n\t$(CC) $(CFLAGS) src/main.c -o $@\n"
            ).encode(),
            "BUILDING.md": b"Run the recorded Make command.\n",
            "ARCHIVE_README.md": b"Accepted archive evidence fixture.\n",
            "UNRESOLVED.md": b"No unresolved entities in this fixture.\n",
            "src/main.c": b"int main(void) { return 0; }\n",
            "reports/toolchain.json": b'{"compiler":"fixture-local"}\n',
            "reports/archival_audit.json": b'{"sourceRevisionSha256":"fixture"}\n',
            "reports/program_model.json": json.dumps({"inputSha256": input_sha256 or self.expected_input}).encode() + b"\n",
        }
        inputs = [
            {"path": path, "bytes": len(value), "sha256": sha256_bytes(value)}
            for path, value in sorted(files.items())
            if path == "Makefile" or path.startswith("src/") or path.startswith("include/")
        ]
        revision = source_revision(files)
        project = self.root / destination.stem
        project.mkdir()
        for relative, value in files.items():
            path = project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        subprocess.run(["make", "--jobs=1"], cwd=project, check=True)
        artifact = project / "build/reconstructed"
        contract = {
            "schemaVersion": 2,
            "command": ["make", "--jobs=1"],
            "parallelism": 1,
            "wallClockTimeoutMillis": 60_000,
            "maximumOutputBytes": 1_000_000,
            "warningsAsErrors": True,
            "reproduciblePathMapping": True,
            "apiCredentialsRequired": False,
            "analysisCachesRequired": False,
            "returnCode": 0,
            "sourceStableDuringBuild": True,
            "sourceRevisionSha256": revision,
            "sourceInputs": inputs,
            "artifact": {"path": "build/reconstructed", "bytes": artifact.stat().st_size, "sha256": sha256_bytes(artifact.read_bytes())},
        }
        (project / "reports/build_contract.json").write_text(json.dumps(contract) + "\n", encoding="utf-8")
        source_manifest = {
            "profileId": "generated-c-make-v1-gcc-compiler-engines-16.2.0",
            "profileSha256": "a" * 64,
            "inputSha256": input_sha256 or self.expected_input,
            "files": [{"path": path, "sha256": sha256_bytes(value)} for path, value in sorted(files.items())],
        }
        (project / "source_tree_manifest.json").write_text(json.dumps(source_manifest) + "\n", encoding="utf-8")
        payload = {}
        for path in sorted(project.rglob("*")):
            if path.is_file() and "build" not in path.relative_to(project).parts and path.name != "ARCHIVE_MANIFEST.sha256":
                payload[path.relative_to(project).as_posix()] = path.read_bytes()
        manifest = "".join(f"{sha256_bytes(value)}  {path}\n" for path, value in sorted(payload.items()))
        payload["ARCHIVE_MANIFEST.sha256"] = manifest.encode()
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
            for path, value in sorted(payload.items()):
                archive.writestr(path, value)

    def run_verifier(self, archive: Path, repeat: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3", str(SCRIPT), "--profile", str(PROFILE), "--engine", "cc1",
                "--archive", str(archive), "--repeat-archive", str(repeat),
                "--evidence", str(self.root / "evidence.json"),
            ],
            cwd=REPOSITORY_ROOT, text=True, capture_output=True, check=False,
        )

    def test_cc1_archives_are_repeatedly_extracted_built_and_recorded(self) -> None:
        first = self.root / "cc1-a.zip"
        repeat = self.root / "cc1-b.zip"
        self.make_archive(first)
        shutil.copyfile(first, repeat)
        result = self.run_verifier(first, repeat)
        self.assertEqual(0, result.returncode, result.stderr)
        evidence = json.loads((self.root / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual("cc1", evidence["engine"])
        self.assertTrue(evidence["archives"]["byteIdentical"])
        self.assertEqual(evidence["cleanBuilds"][0]["executable"], evidence["cleanBuilds"][1]["executable"])
        self.assertFalse(evidence["complete"])
        self.assertFalse(evidence["releaseEligible"])

    def test_cc1_input_substitution_is_rejected(self) -> None:
        first = self.root / "bad.zip"
        repeat = self.root / "bad-repeat.zip"
        self.make_archive(first, input_sha256="0" * 64)
        shutil.copyfile(first, repeat)
        result = self.run_verifier(first, repeat)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("authenticated cc1 stripped artifact", result.stderr)

    def test_non_identical_repeated_archives_are_rejected_before_build(self) -> None:
        first = self.root / "first.zip"
        repeat = self.root / "repeat.zip"
        self.make_archive(first)
        self.make_archive(repeat)
        repeat.write_bytes(repeat.read_bytes() + b"trailing-byte")
        result = self.run_verifier(first, repeat)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("byte-identical", result.stderr)


if __name__ == "__main__":
    unittest.main()
