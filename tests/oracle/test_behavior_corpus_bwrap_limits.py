"""Live regressions for distinct stream/artifact limits in the generic runner (#97)."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from oracle import behavior_corpus_bwrap as backend
from oracle.behavior_corpus import BehaviorCorpusError

ROOT = Path(__file__).resolve().parents[2]
DIAGNOSTIC = b"diagnostic-only case\n"
SOURCE = r"""
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "diagnostic")) {
        static const char diagnostic[] = "diagnostic-only case\n";
        return write(2, diagnostic, sizeof diagnostic - 1) == sizeof diagnostic - 1 ? 0 : 3;
    }
    if (!strcmp(argv[1], "stream-overflow")) {
        static const char data[] = "more-than-eight-bytes";
        return write(1, data, sizeof data - 1) == sizeof data - 1 ? 0 : 4;
    }
    if (!strcmp(argv[1], "artifact-overflow")) {
        int fd = open("artifact", O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) return 5;
        int result = write(fd, "ab", 2) == 2 ? 0 : 6;
        close(fd);
        return result;
    }
    return 7;
}
"""


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@unittest.skipUnless(os.environ.get("BEHAVIOR_CORPUS_BWRAP_LIVE") == "1", "set BEHAVIOR_CORPUS_BWRAP_LIVE=1")
class LiveSeparateFileLimitTests(unittest.TestCase):
    """Explicit live selection requires the real compiler, kernel and bubblewrap path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.bwrap = Path("/usr/bin/bwrap")
        compiler = next((path for name in ("cc", "gcc", "clang") if (path := shutil.which(name))), None)
        if compiler is None or not cls.bwrap.is_file():
            raise AssertionError("live file-limit controls require a C compiler and /usr/bin/bwrap")
        (ROOT / "build").mkdir(exist_ok=True)
        cls.directory = tempfile.TemporaryDirectory(prefix="bwrap-file-limits-", dir=ROOT / "build")
        cls.root = Path(cls.directory.name)
        source = cls.root / "fixture.c"
        source.write_text(SOURCE)
        cls.executable = cls.root / "fixture"
        subprocess.run([compiler, "-O1", "-o", os.fspath(cls.executable), os.fspath(source)],
                       env={**os.environ, "TMPDIR": os.fspath(cls.root)}, check=True, timeout=30)
        cls.payload = cls.executable.read_bytes()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def corpus(self, mode: str, *, artifact_bytes: int, stream_bytes: int) -> dict:
        machine = {"x86_64": 62, "aarch64": 183}[platform.machine()]
        artifacts = []
        if mode == "artifact-overflow":
            artifacts = [{"path": "artifact", "mode": "0o644", "normalizations": [],
                          "normalizedSha256": sha(b"ab")}]
        return backend.validate_corpus({
            "schemaVersion": 1,
            "scope": "fixture",
            "id": f"separate-file-limit-{mode}",
            "executable": {"bytes": len(self.payload), "sha256": sha(self.payload)},
            "sandbox": {
                "backend": backend.BACKEND,
                "profile": "separate-file-limit-control",
                "baseArgv": list(backend.BASE_ARGV),
                "executablePath": "/oracle/exe",
                "workspacePath": "/work",
                "programPath": "/oracle/program",
                "executeElfMachine": machine,
                "hostTools": [],
                "storagePolicy": backend.STORAGE_POLICY_ID,
                "syscallPolicy": backend.storage_filter_identity(machine),
            },
            "environment": {},
            "limits": {
                "wallSeconds": 10, "cpuSeconds": 10, "streamBytes": stream_bytes,
                "artifactBytes": artifact_bytes, "compileAddressSpaceBytes": 1024 ** 3,
                "executeAddressSpaceBytes": 64 * 1024 * 1024, "openFiles": 64, "closureLibraries": 64,
                "workspaceEntries": 2, "processes": 32, "writableBytes": 64 * 1024, "writableEntries": 8,
            },
            "artifactNormalizations": [],
            "cases": [{
                "id": mode,
                "categories": ["file-limit-control"],
                "repetitions": 1,
                "arguments": [mode],
                "inputs": [],
                "expected": {"exitCode": 0, "stdout": backend.blob(b""),
                             "stderr": backend.blob(DIAGNOSTIC if mode == "diagnostic" else b""),
                             "artifacts": artifacts},
                "execute": None,
            }],
        })

    def run_case(self, mode: str, *, artifact_bytes: int, stream_bytes: int) -> dict:
        return backend.run_corpus(self.corpus(mode, artifact_bytes=artifact_bytes, stream_bytes=stream_bytes),
                                  self.executable, bwrap=self.bwrap, temporary_root=self.root)

    def test_diagnostic_only_case_uses_its_declared_stream_limit(self) -> None:
        report = self.run_case("diagnostic", artifact_bytes=1, stream_bytes=4096)
        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["cases"][0]["runs"][0]["compile"]["stderr"], backend.blob(DIAGNOSTIC))

    def test_artifact_allowance_does_not_raise_individual_stream_limit(self) -> None:
        with self.assertRaisesRegex(BehaviorCorpusError, "stream exceeds the 8-byte limit"):
            self.run_case("stream-overflow", artifact_bytes=4096, stream_bytes=8)

    def test_stream_allowance_does_not_raise_individual_artifact_limit(self) -> None:
        with self.assertRaisesRegex(BehaviorCorpusError, "artifact artifact exceeds the 1-byte limit"):
            self.run_case("artifact-overflow", artifact_bytes=1, stream_bytes=4096)


if __name__ == "__main__":
    unittest.main()
