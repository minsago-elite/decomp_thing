#!/usr/bin/env python3
"""Check that Gradle build tools keep temporary files under the repository (#2008)."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parent.parent
PROBE_MARKER = "DECOMP_TEMP_PROBE "

FAKE_JAVA = """#!/bin/sh
{ printf '%s\\n' "$@"; printf 'TMPDIR=%s\\n' "$TMPDIR"; } > "$DECOMP_FAKE_JAVA_RECORD"
"""

# Groovy, so the probe does not pay for Kotlin script compilation.
PROBE = """
import java.lang.management.ManagementFactory
gradle.projectsEvaluated { g ->
    def root = g.rootProject
    def report = [
        daemonArguments: ManagementFactory.runtimeMXBean.inputArguments,
        daemonTemporaryDirectory: System.getProperty("java.io.tmpdir"),
        daemonEnvironmentTmpdir: System.getenv("TMPDIR"),
        kotlinDaemonArguments: root.tasks.getByName("compileKotlin").kotlinDaemonJvmArguments.get(),
        acpGateHelperTmpdir: root.tasks.getByName("buildAcpGateHelper").environment["TMPDIR"]?.toString(),
        acpGateHelperTemporaryDirectory: root.tasks.getByName("buildAcpGateHelper").temporaryDir.absolutePath,
    ]
    println("DECOMP_TEMP_PROBE " + groovy.json.JsonOutput.toJson(report))
}
"""


def within(path, parent):
    return Path(path).resolve().is_relative_to(Path(parent).resolve())


class GradleWrapperTemporaryDirectoryTest(unittest.TestCase):
    """Runs the checked-in wrapper script against a fake java, so no JVM starts."""

    def setUp(self):
        (REPOSITORY / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="gradle-temp-wrapper-", dir=REPOSITORY / "build")
        self.root = Path(self.temporary.name)
        shutil.copy2(REPOSITORY / "gradlew", self.root / "gradlew")
        java_home = self.root / "java-home"
        (java_home / "bin").mkdir(parents=True)
        java = java_home / "bin/java"
        java.write_text(FAKE_JAVA)
        java.chmod(0o755)
        self.record = self.root / "java-arguments.txt"
        self.environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root),
            "JAVA_HOME": str(java_home),
            "DECOMP_FAKE_JAVA_RECORD": str(self.record),
            # A caller's own settings must not move build-tool temporary files out of the repository.
            "TMPDIR": "/elsewhere",
            "GRADLE_OPTS": "-Djava.io.tmpdir=/elsewhere",
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_wrapper_client_disables_perf_data_and_uses_repository_temporary_directory(self):
        subprocess.run(["sh", str(self.root / "gradlew"), "help"], cwd=self.root, env=self.environment,
                       check=True, timeout=60)
        lines = self.record.read_text().splitlines()
        expected = self.root / ".gradle/tmp"
        self.assertTrue(expected.is_dir(), "gradlew must create the temporary directory before java starts")
        self.assertIn(f"TMPDIR={expected}", lines)
        arguments = lines[:lines.index("-jar")]
        self.assertIn("-XX:-UsePerfData", arguments)
        temporary = [argument for argument in arguments if argument.startswith("-Djava.io.tmpdir=")]
        self.assertEqual(f"-Djava.io.tmpdir={expected}", temporary[-1], "the last java.io.tmpdir wins")


class SystemTemporaryDirectoryCheckTest(unittest.TestCase):
    """Runs the before/after check against a stand-in system temporary directory under build/."""

    def setUp(self):
        (REPOSITORY / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="system-temp-check-", dir=REPOSITORY / "build")
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(REPOSITORY / "scripts/check-system-temp-isolation.sh", self.root / "scripts")
        self.system_temp = self.root / "system-tmp"
        user = subprocess.run(["id", "-un"], check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        self.perf_data = self.system_temp / f"hsperfdata_{user}"
        self.perf_data.mkdir(parents=True)
        (self.system_temp / "existing").touch()
        (self.perf_data / "100").touch()

    def tearDown(self):
        self.temporary.cleanup()

    def check(self, command):
        return subprocess.run(["bash", str(self.root / "scripts/check-system-temp-isolation.sh"), "sh", "-c", command],
                              env={**os.environ, "DECOMP_SYSTEM_TEMP_DIR": str(self.system_temp)},
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)

    def test_reports_no_new_entries_when_the_command_leaves_none(self):
        result = self.check(f"rm {self.perf_data}/100")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("No new entries", result.stdout)
        self.assertEqual("", (self.root / "build/system-temp-isolation/new-entries.txt").read_text())

    def test_fails_and_lists_new_top_level_and_perf_data_entries(self):
        result = self.check(f"mkdir {self.system_temp}/cc-leak && touch {self.perf_data}/4242")
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertEqual(["cc-leak", f"{self.perf_data.name}/4242"],
                         (self.root / "build/system-temp-isolation/new-entries.txt").read_text().splitlines())

    def test_preserves_the_command_failure_status(self):
        self.assertEqual(7, self.check("exit 7").returncode)


class GradleDaemonTemporaryDirectoryTest(unittest.TestCase):
    """Configures the real build in a single-use daemon and reports its effective settings."""

    def setUp(self):
        (REPOSITORY / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="gradle-temp-daemon-", dir=REPOSITORY / "build")
        self.probe = Path(self.temporary.name) / "probe.gradle"
        self.probe.write_text(PROBE)

    def tearDown(self):
        self.temporary.cleanup()

    def test_gradle_and_kotlin_daemons_and_native_compiler_use_repository_temporary_directories(self):
        result = subprocess.run(
            ["./gradlew", "--no-daemon", "--offline", "--quiet", "--init-script", str(self.probe), "help"],
            cwd=REPOSITORY, check=True, timeout=900, stdout=subprocess.PIPE, text=True)
        reports = [line[len(PROBE_MARKER):] for line in result.stdout.splitlines() if line.startswith(PROBE_MARKER)]
        self.assertEqual(1, len(reports), result.stdout)
        report = json.loads(reports[0])
        repository_temporary = REPOSITORY / ".gradle/tmp"

        self.assertIn("-XX:-UsePerfData", report["daemonArguments"])
        self.assertEqual(repository_temporary.resolve(), Path(report["daemonTemporaryDirectory"]).resolve())
        self.assertEqual(repository_temporary.resolve(), Path(report["daemonEnvironmentTmpdir"]).resolve())

        kotlin = report["kotlinDaemonArguments"]
        self.assertIn("-XX:-UsePerfData", kotlin)
        self.assertIn("-Xmx2048m", kotlin, "the gradle.properties Kotlin daemon heap must be preserved")
        kotlin_temporary = [argument for argument in kotlin if argument.startswith("-Djava.io.tmpdir=")]
        self.assertEqual(1, len(kotlin_temporary), kotlin)
        self.assertTrue(within(kotlin_temporary[0].split("=", 1)[1], REPOSITORY), kotlin_temporary)

        self.assertEqual(report["acpGateHelperTemporaryDirectory"], report["acpGateHelperTmpdir"])
        self.assertTrue(within(report["acpGateHelperTmpdir"], REPOSITORY / "build"), report)


if __name__ == "__main__":
    unittest.main()
