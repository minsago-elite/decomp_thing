"""Real pinned API controls for static pointer-slot evidence, with no target execution."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.oracle.test_byte_instruction_decoder import ISOLATED_LAUNCHER, ROOT, _release


class ByteStaticMemoryTransferDecoderTest(unittest.TestCase):
    def test_authored_bytes_and_exact_pcode_use_def_controls(self) -> None:
        release = _release()
        if release is None:
            self.skipTest("stage bundled Ghidra or set DECOMP_BYTE_DECODER_GHIDRA_RELEASE")
        if not shutil.which("javac") or not shutil.which("java"):
            self.skipTest("static transfer controls require JDK 21")
        build = ROOT / "build/static-memory-transfer-api-controls"
        build.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="authored-", dir=build) as name:
            root = Path(name)
            classes, home, temporary = (root / child for child in ("classes", "home", "tmp"))
            for directory in (classes, home, temporary):
                directory.mkdir()
            jars = sorted(path for path in (release / "Ghidra").rglob("*.jar") if path.parent.name == "lib")
            self.assertTrue(jars)
            properties = [f"-Duser.home={home}", f"-Djava.io.tmpdir={temporary}", f"-Djna.tmpdir={temporary}",
                          "-Djava.awt.headless=true", "-XX:-UsePerfData"]
            environment = {key: value for key, value in os.environ.items()
                           if key not in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}}
            environment.update({"TMPDIR": str(temporary), "XDG_CACHE_HOME": str(home / "cache"), "XDG_CONFIG_HOME": str(home / "config")})
            launcher = root / "IsolatedByteDecoderControls.java"
            launcher.write_text(ISOLATED_LAUNCHER.replace('"ByteInstructionDecoderControls"',
                '"decompengine.ghidra.ByteStaticMemoryTransferDecoderControls"'), encoding="utf-8")
            jar_list = root / "approved-bundled-jars.txt"
            jar_list.write_text("".join(str(path) + "\n" for path in jars), encoding="utf-8")
            bridge = ROOT / "ghidra-bridge/src/main/java/decompengine/ghidra"
            harness = ROOT / "src/test/resources/machinecalls/ByteStaticMemoryTransferDecoderControls.java"
            compiled = subprocess.run(["javac", "-J-Xmx256m", *("-J" + value for value in properties), "-proc:none",
                "-cp", os.pathsep.join(str(path) for path in jars), "-d", str(classes), str(bridge / "ByteInstructionDecoderV1.java"),
                str(bridge / "ByteStaticMemoryTransferDecoderV1.java"), str(harness), str(launcher)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=45, check=False)
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            result = subprocess.run(["java", "-Xmx384m", *properties, "-cp", str(classes), "IsolatedByteDecoderControls",
                str(release), str(root), str(classes), str(jar_list)], cwd=root, env=environment,
                capture_output=True, text=True, timeout=90, check=False)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertRegex(result.stdout, r"STATIC-MEMORY-TRANSFER-CONTROLS passed=\d+")


if __name__ == "__main__":
    unittest.main()
