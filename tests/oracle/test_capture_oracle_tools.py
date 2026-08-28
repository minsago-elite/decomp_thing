from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CAPTURE = REPOSITORY_ROOT / "scripts/capture-oracle-tools.py"


class CaptureOracleToolsTest(unittest.TestCase):
    def _tool(self, directory: Path) -> Path:
        tool = directory / "multicall"
        tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n", encoding="utf-8")
        tool.chmod(0o500)
        return tool

    def test_custom_version_command_is_recorded_and_executed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            tool = self._tool(Path(raw_directory))
            command = [str(tool), "-flavor", "gnu", "--version"]
            completed = subprocess.run(
                [
                    "python3",
                    str(CAPTURE),
                    "--tool",
                    "linker",
                    str(tool),
                    "--version-command",
                    "linker",
                    json.dumps(command),
                ],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )

        record = json.loads(completed.stdout)[0]
        self.assertEqual(command, record["versionCommand"])
        self.assertEqual("-flavor gnu --version\n", record["versionOutput"])

    def test_custom_version_command_must_execute_the_recorded_tool(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            tool = self._tool(Path(raw_directory))
            completed = subprocess.run(
                [
                    "python3",
                    str(CAPTURE),
                    "--tool",
                    "linker",
                    str(tool),
                    "--version-command",
                    "linker",
                    json.dumps(["/bin/true", "--version"]),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("must begin with its tool path", completed.stderr)


if __name__ == "__main__":
    unittest.main()
