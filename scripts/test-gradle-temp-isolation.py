#!/usr/bin/env python3
"""Check that Gradle build tools keep temporary files under the repository (#2008)."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parent.parent
CHECK = REPOSITORY / "scripts/check-system-temp-isolation.py"
HOOK_LINE = '. "$APP_HOME/gradle/repository-temp.sh"'
PROBE_MARKER = "DECOMP_TEMP_PROBE "

FAKE_JAVA = """#!/bin/sh
{ printf '%s\\n' "$@"; printf 'TMPDIR=%s\\n' "$TMPDIR"; } > "$DECOMP_FAKE_JAVA_RECORD"
"""

# Groovy, so the probes do not pay for Kotlin script compilation.
KOTLIN_COMPILE_PROBE = """
import java.lang.management.ManagementFactory
gradle.projectsEvaluated { g ->
    g.rootProject.tasks.named("compileKotlin") { task ->
        task.doLast {
            def report = [
                strategy: task.compilerExecutionStrategy.get().toString(),
                daemonArguments: ManagementFactory.runtimeMXBean.inputArguments,
                temporaryDirectory: System.getProperty("java.io.tmpdir"),
                environmentTmpdir: System.getenv("TMPDIR"),
                kotlinDaemons: ProcessHandle.current().descendants()
                    .map { it.info().commandLine().orElse("") }
                    .filter { it.contains("KotlinCompileDaemon") }.toList(),
            ]
            println("DECOMP_TEMP_PROBE " + groovy.json.JsonOutput.toJson(report))
        }
    }
}
"""

# Moves only the root build directory, so a real `clean` cannot touch the checkout's build/.
BUILD_DIRECTORY_PROBE = """
beforeProject { project ->
    if (project.path == ":") {
        project.layout.buildDirectory.set(new File(System.getenv("DECOMP_TEST_BUILD_DIRECTORY")))
    }
}
"""

RECORDING_COMPILER = """#!/bin/sh
{ printf 'TMPDIR=%s\\n' "$TMPDIR"; if [ -d "$TMPDIR" ]; then echo exists; else echo missing; fi; } \\
    > "$DECOMP_TEST_COMPILER_RECORD"
exec /usr/bin/cc "$@"
"""

# Redirects the wrapper task's outputs, so regeneration cannot rewrite the checked-in wrapper.
WRAPPER_PROBE = """
gradle.projectsEvaluated { g ->
    g.rootProject.tasks.named("wrapper") { task ->
        def root = new File(System.getenv("DECOMP_TEST_WRAPPER_ROOT"))
        task.scriptFile = new File(root, "gradlew")
        task.jarFile = new File(root, "gradle/wrapper/gradle-wrapper.jar")
    }
}
"""


def within(path, parent):
    return Path(path).resolve().is_relative_to(Path(parent).resolve())


def scratch(test, prefix):
    (REPOSITORY / "build").mkdir(exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix=prefix, dir=REPOSITORY / "build")
    test.addCleanup(temporary.cleanup)
    return Path(temporary.name)


def checked(label, command, environment=None, cwd=REPOSITORY, timeout=900):
    """Runs command through the system temporary directory check and returns (result, report)."""
    result = subprocess.run([str(CHECK), "--label", label, "--", *command], cwd=cwd, timeout=timeout,
                            env={**os.environ, **(environment or {})}, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    reports = sorted((REPOSITORY / "build/system-temp-isolation").glob(f"{label}-*"))
    return result, reports[-1] if reports else None


class GradleWrapperHookTest(unittest.TestCase):
    """Runs the checked-in wrapper script and hook against a fake java, so no JVM starts."""

    def test_wrapper_sources_the_hook_once_after_the_default_jvm_options(self):
        lines = (REPOSITORY / "gradlew").read_text().splitlines()
        self.assertEqual(1, lines.count(HOOK_LINE))
        self.assertTrue(lines[lines.index(HOOK_LINE) - 1].startswith("DEFAULT_JVM_OPTS="))

    def test_wrapper_client_disables_perf_data_and_uses_repository_temporary_directory(self):
        root = scratch(self, "gradle-temp-wrapper-")
        shutil.copy2(REPOSITORY / "gradlew", root / "gradlew")
        (root / "gradle").mkdir()
        shutil.copy2(REPOSITORY / "gradle/repository-temp.sh", root / "gradle")
        java = root / "java-home/bin/java"
        java.parent.mkdir(parents=True)
        java.write_text(FAKE_JAVA)
        java.chmod(0o755)
        record = root / "java-arguments.txt"
        subprocess.run(["sh", str(root / "gradlew"), "help"], cwd=root, check=True, timeout=60, env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root),
            "JAVA_HOME": str(java.parent.parent), "DECOMP_FAKE_JAVA_RECORD": str(record),
            # A caller's own settings must not move build-tool temporary files out of the repository.
            "TMPDIR": "/elsewhere", "GRADLE_OPTS": "-Djava.io.tmpdir=/elsewhere -XX:+UsePerfData",
        })
        lines = record.read_text().splitlines()
        expected = root / ".gradle/tmp"
        self.assertTrue(expected.is_dir(), "gradlew must create the temporary directory before java starts")
        self.assertIn(f"TMPDIR={expected}", lines)
        arguments = lines[:lines.index("-jar")]
        perf_data = [argument for argument in arguments if argument.endswith("UsePerfData")]
        self.assertEqual("-XX:-UsePerfData", perf_data[-1], "the last UsePerfData option wins")
        temporary = [argument for argument in arguments if argument.startswith("-Djava.io.tmpdir=")]
        self.assertEqual(f"-Djava.io.tmpdir={expected}", temporary[-1], "the last java.io.tmpdir wins")


class WrapperRegenerationTest(unittest.TestCase):
    def test_regenerated_wrapper_matches_the_checked_in_wrapper_with_the_hook(self):
        root = scratch(self, "gradle-temp-regenerate-")
        probe = root / "probe.gradle"
        probe.write_text(WRAPPER_PROBE)
        subprocess.run(["./gradlew", "--no-daemon", "--quiet", "--init-script", str(probe), "wrapper"],
                       cwd=REPOSITORY, check=True, timeout=900, env={**os.environ, "DECOMP_TEST_WRAPPER_ROOT": str(root)})
        self.assertEqual((REPOSITORY / "gradlew").read_text(), (root / "gradlew").read_text(),
                         "the wrapper task must reproduce the checked-in gradlew, hook line included")


class SystemTemporaryDirectoryCheckTest(unittest.TestCase):
    """Runs the check on small commands; their /tmp is the check's private observed directory."""

    def setUp(self):
        self.marker = f"decomp-check-{os.getpid()}-{self.id().rsplit('.', 1)[-1]}"

    def tearDown(self):
        self.assertFalse(any(name.startswith(self.marker) for name in os.listdir("/tmp")),
                         "the check must redirect the command's /tmp away from the host /tmp")

    def summary(self, report):
        return json.loads((report / "summary.json").read_text())

    def test_passes_a_command_that_writes_only_to_its_own_temporary_directory(self):
        private = scratch(self, "system-temp-private-")
        result, report = checked("selftest-clean", ["sh", "-c", 'mktemp "$TMPDIR/x.XXXXXX" >/dev/null'],
                                 {"TMPDIR": str(private)})
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual("clean", self.summary(report)["result"])
        self.assertEqual("/tmp", self.summary(report)["systemTemporaryDirectory"])
        for name in ("events.txt", "remaining.txt", "host-before.txt", "host-after.txt", "host-new.txt"):
            self.assertTrue((report / name).is_file(), name)

    def test_fails_on_an_entry_kept_under_a_subdirectory(self):
        result, report = checked("selftest-nested", ["sh", "-c",
                                 f"mkdir -p /tmp/{self.marker}/existing && touch /tmp/{self.marker}/existing/kept"])
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn(f"{self.marker}/existing/kept", (report / "remaining.txt").read_text().splitlines())

    def test_fails_on_a_top_level_entry_deleted_before_the_command_exits(self):
        result, report = checked("selftest-transient", ["sh", "-c",
                                 f"touch /tmp/{self.marker} && rm /tmp/{self.marker}"])
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertEqual("", (report / "remaining.txt").read_text())
        self.assertIn(f"create {self.marker}", (report / "events.txt").read_text().splitlines())

    def test_fails_on_a_hotspot_perf_data_file(self):
        result, report = checked("selftest-hsperfdata", ["java", "-XX:+UsePerfData", "-version"])
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertTrue(any(line.startswith("create hsperfdata_")
                            for line in (report / "events.txt").read_text().splitlines()), result.stdout)

    def test_jdk_version_probes_with_perf_data_disabled_leave_no_events(self):
        # The same probes scripts/ci-prepare-oracle-runtime.sh runs inside the check in CI.
        result, report = checked("selftest-jdk-probes", ["sh", "-c",
                                 "java -XX:-UsePerfData -version && javac -J-XX:-UsePerfData -version"])
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual("", (report / "events.txt").read_text())
        self.assertEqual("clean", self.summary(report)["result"])

    def test_preserves_the_command_failure_status_and_writes_one_report_per_invocation(self):
        first = checked("selftest-status", ["sh", "-c", "exit 7"])
        second = checked("selftest-status", ["true"])
        self.assertEqual(7, first[0].returncode)
        self.assertEqual(0, second[0].returncode)
        self.assertNotEqual(first[1], second[1])
        self.assertEqual(7, self.summary(first[1])["commandExitStatus"])


class CheckedWorkflowScriptTest(unittest.TestCase):
    """Scripts that CI runs inside the check must not start a JDK tool that writes hsperfdata."""

    # A command line that starts a JDK tool, directly or through exec/sudo, by name or path.
    JDK_TOOL = re.compile(r'^\s*(?:exec\s+|sudo\s+(?:-\S+\s+)*)?"?(?:\S*/)?'
                          r'(?:java|javac|jar|jshell|keytool|jlink|jpackage)"?(?:\s|$)')

    def test_direct_jdk_tool_calls_in_checked_ci_scripts_disable_perf_data(self):
        workflow = (REPOSITORY / ".github/workflows/ci.yml").read_text()
        scripts = set(re.findall(r"check-system-temp-isolation\.py[^\n]*? -- (?:bash )?(scripts/[\w.-]+)", workflow))
        self.assertTrue({"scripts/ci-prepare-oracle-runtime.sh", "scripts/ci-prepare-bundled-ghidra-runtime.sh",
                         "scripts/ci.sh"} <= scripts, scripts)
        for script in sorted(scripts):
            for number, line in enumerate((REPOSITORY / script).read_text().splitlines(), 1):
                if line.lstrip().startswith("#") or not self.JDK_TOOL.search(line):
                    continue
                self.assertRegex(line, r"(?:^|\s)(?:-J)?-XX:-UsePerfData\b",
                                 f"{script}:{number} starts a JDK tool without -XX:-UsePerfData")


class GradleBuildTemporaryDirectoryTest(unittest.TestCase):
    """Real builds inside the check: a Kotlin compile, and `clean` before the native helper."""

    def test_real_kotlin_compile_runs_in_process_with_repository_temporary_directories(self):
        root = scratch(self, "gradle-temp-kotlin-")
        probe = root / "probe.gradle"
        probe.write_text(KOTLIN_COMPILE_PROBE)
        result, report = checked("kotlin-compile", ["./gradlew", "--no-daemon", "--init-script", str(probe),
                                                     "compileKotlin", "--rerun"])
        self.assertEqual(0, result.returncode, result.stdout[-6000:])
        reports = [line[len(PROBE_MARKER):] for line in result.stdout.splitlines() if line.startswith(PROBE_MARKER)]
        self.assertEqual(1, len(reports), result.stdout[-6000:])
        compile_report = json.loads(reports[0])
        repository_temporary = (REPOSITORY / ".gradle/tmp").resolve()
        self.assertEqual("IN_PROCESS", compile_report["strategy"])
        self.assertEqual([], compile_report["kotlinDaemons"])
        self.assertIn("-XX:-UsePerfData", compile_report["daemonArguments"])
        self.assertEqual(repository_temporary, Path(compile_report["temporaryDirectory"]).resolve())
        self.assertEqual(repository_temporary, Path(compile_report["environmentTmpdir"]).resolve())
        self.assertEqual("clean", json.loads((report / "summary.json").read_text())["result"])

    def test_clean_then_native_helper_build_gives_the_compiler_an_existing_repository_tmpdir(self):
        root = scratch(self, "gradle-temp-clean-")
        probe = root / "probe.gradle"
        probe.write_text(BUILD_DIRECTORY_PROBE)
        compiler = root / "recording-cc"
        compiler.write_text(RECORDING_COMPILER)
        compiler.chmod(0o755)
        record = root / "compiler-record.txt"
        build_directory = root / "build"
        result, report = checked("clean-native-helper", [
            "./gradlew", "--no-daemon", "--init-script", str(probe), ":clean", ":buildAcpGateHelper",
            f"-PacpGateHelperCompiler={compiler}"],
            {"DECOMP_TEST_BUILD_DIRECTORY": str(build_directory), "DECOMP_TEST_COMPILER_RECORD": str(record)})
        self.assertEqual(0, result.returncode, result.stdout[-6000:])
        lines = record.read_text().splitlines()
        self.assertEqual(f"TMPDIR={build_directory / 'tmp/buildAcpGateHelper'}", lines[0])
        self.assertEqual("exists", lines[1], "clean must not leave the compiler a deleted TMPDIR")
        self.assertTrue((build_directory / "native/acp/decomp-acp-gate-helper").is_file())
        self.assertEqual("clean", json.loads((report / "summary.json").read_text())["result"])


if __name__ == "__main__":
    unittest.main()
