"""Real bundled byte-decoder controls; never import or execute an input binary."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_NAME = "ghidra_12.1.3_PUBLIC"

# The boot JVM intentionally has no Ghidra classes on java.class.path. The actual
# worker's authenticated explicit-JAR loader has separate Kotlin integration tests;
# this small JDK-only launcher checks that byte initialization needs no class search.
ISOLATED_LAUNCHER = r"""
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
public final class IsolatedByteDecoderControls {
    public static void main(String[] args) throws Exception {
        String originalClassPath = System.getProperty("java.class.path");
        try {
            Class.forName("ghidra.framework.Application", false, ClassLoader.getSystemClassLoader());
            throw new AssertionError("Ghidra unexpectedly exists on the boot classpath");
        } catch (ClassNotFoundException expected) { }
        var urls = new ArrayList<URL>();
        urls.add(Path.of(args[2]).toUri().toURL());
        for (String path : Files.readAllLines(Path.of(args[3]))) urls.add(Path.of(path).toUri().toURL());
        try (var loader = new URLClassLoader(urls.toArray(URL[]::new), ClassLoader.getPlatformClassLoader())) {
            var thread = Thread.currentThread();
            var previous = thread.getContextClassLoader();
            thread.setContextClassLoader(loader);
            try {
                Class.forName("ByteInstructionDecoderControls", true, loader).getMethod("main", String[].class)
                    .invoke(null, (Object) new String[] {args[0], args[1]});
                if (!originalClassPath.equals(System.getProperty("java.class.path")))
                    throw new AssertionError("byte decoder changed the boot classpath");
            } finally { thread.setContextClassLoader(previous); }
        }
    }
}
"""


def _release() -> Path | None:
    explicit = os.environ.get("DECOMP_BYTE_DECODER_GHIDRA_RELEASE")
    candidates = [Path(explicit)] if explicit else [
        ROOT / "build/install/llm_bin_patch/libexec/ghidra" / RELEASE_NAME,
        ROOT / "ghidra-bridge/build/release" / RELEASE_NAME,
    ]
    return next((path.resolve() for path in candidates if path.is_dir()), None)


class ByteInstructionDecoderTest(unittest.TestCase):
    def test_authored_bytes_use_real_program_free_bundled_decoder(self) -> None:
        release = _release()
        if release is None:
            self.skipTest("stage bundled Ghidra or set DECOMP_BYTE_DECODER_GHIDRA_RELEASE")
        if not shutil.which("javac") or not shutil.which("java"):
            self.skipTest("bundled byte-decoder controls require JDK 21")
        build = ROOT / "build/byte-decoder-api-controls"
        build.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="authored-", dir=build) as name:
            root = Path(name)
            classes = root / "classes"
            home = root / "home"
            temporary = root / "tmp"
            for directory in (classes, home, temporary):
                directory.mkdir()
            jars = sorted(path for path in (release / "Ghidra").rglob("*.jar") if path.parent.name == "lib")
            self.assertTrue(jars, "bundled Java APIs missing")
            classpath = os.pathsep.join(str(path) for path in jars)
            properties = [f"-Duser.home={home}", f"-Djava.io.tmpdir={temporary}", f"-Djna.tmpdir={temporary}",
                          "-Djava.awt.headless=true", "-XX:-UsePerfData"]
            environment = {key: value for key, value in os.environ.items()
                           if key not in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}}
            environment.update({"TMPDIR": str(temporary), "XDG_CACHE_HOME": str(home / "cache"),
                                "XDG_CONFIG_HOME": str(home / "config")})
            bridge = ROOT / "ghidra-bridge/src/main/java/decompengine/ghidra/ByteInstructionDecoderV1.java"
            harness = ROOT / "src/test/resources/machinecalls/ByteInstructionDecoderControls.java"
            launcher = root / "IsolatedByteDecoderControls.java"
            launcher.write_text(ISOLATED_LAUNCHER, encoding="utf-8")
            jar_list = root / "approved-bundled-jars.txt"
            jar_list.write_text("".join(str(path) + "\n" for path in jars), encoding="utf-8")
            compile_result = subprocess.run(
                ["javac", *("-J" + option for option in properties), "-proc:none", "-cp", classpath,
                 "-d", str(classes), str(bridge), str(harness), str(launcher)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=45, check=False,
            )
            self.assertEqual(0, compile_result.returncode, compile_result.stderr)
            result = subprocess.run(
                ["java", "-Xmx512m", *properties, "-cp", str(classes),
                 "IsolatedByteDecoderControls", str(release), str(root), str(classes), str(jar_list)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=90, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertRegex(result.stdout, r"BYTE-DECODER-CONTROLS passed=\d+")


if __name__ == "__main__":
    unittest.main()
