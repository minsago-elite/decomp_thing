#!/usr/bin/env python3
"""Prove stale reports refuse before Gradle Test output preparation and fresh Test still runs."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "scripts/module-compilation-qualification.init.gradle"
QUALIFIER = ROOT / "scripts/qualify-contained-module-compilation.sh"
REPORT_RELATIVE = Path("build/test-results/moduleCompilationLiveQualification")


class ModuleCompilationQualificationFreshnessTest(unittest.TestCase):
    def test_production_test_task_uses_a_preparation_prerequisite(self) -> None:
        source = INIT.read_text(encoding="utf-8")
        preflight = source.partition("tasks.register('moduleCompilationLiveQualificationFreshness')")[2].partition(
            "tasks.register('moduleCompilationLiveQualification', Test)"
        )[0]
        test_task = source.partition("tasks.register('moduleCompilationLiveQualification', Test)")[2].partition(
            "\n        }"
        )[0]
        self.assertIn("Files.exists(reports, LinkOption.NOFOLLOW_LINKS)", preflight)
        self.assertIn("dependsOn tasks.named('moduleCompilationLiveQualificationFreshness')", test_task)
        self.assertNotIn("refusing existing hosted compiler test reports", test_task)
        self.assertIn('moduleCompilationLiveQualification', QUALIFIER.read_text(encoding="utf-8"))

    def test_hosted_preflight_preserves_stale_report_bytes_and_rejects_report_symlink(self) -> None:
        with self.fixture() as checkout:
            (checkout / "scripts").mkdir()
            script = checkout / "scripts/qualify-contained-module-compilation.sh"
            shutil.copyfile(QUALIFIER, script)
            reports = checkout / REPORT_RELATIVE
            reports.mkdir(parents=True)
            stale = reports / "TEST-old.xml"
            stale_bytes = b"old result bytes\n"
            stale.write_bytes(stale_bytes)

            result = self.run_preflight(checkout)
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("refusing to reuse compiler qualification inventory or reports", result.stderr)
            self.assertEqual(stale_bytes, stale.read_bytes(), "stale result must remain available for inspection")

            shutil.rmtree(reports)
            target = checkout / "build/elsewhere/missing-report-target"
            target.parent.mkdir(parents=True)
            reports.symlink_to(target)
            result = self.run_preflight(checkout)
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("refusing to reuse compiler qualification inventory or reports", result.stderr)
            self.assertTrue(reports.is_symlink(), "preflight must preserve the substituted report path")
            self.assertFalse(target.exists())

    def test_gradle_freshness_prerequisite_runs_before_real_test_outputs(self) -> None:
        with self.fixture() as checkout:
            build = checkout / "gradle-fixture"
            (build / "src/test/java/fixture").mkdir(parents=True)
            (build / "settings.gradle").write_text("rootProject.name = 'freshness-ordering'\n", encoding="utf-8")
            (build / "build.gradle").write_text(textwrap.dedent("""\
                plugins { id 'java' }
                repositories { mavenCentral() }
                dependencies { testImplementation 'junit:junit:4.13.2' }

                tasks.register('moduleCompilationLiveQualificationFreshness') {
                    doLast {
                        def reports = file('build/test-results/moduleCompilationLiveQualification').toPath()
                        assert !java.nio.file.Files.exists(reports, java.nio.file.LinkOption.NOFOLLOW_LINKS):
                            'refusing existing hosted compiler test reports'
                    }
                }
                tasks.register('moduleCompilationLiveQualification', Test) {
                    dependsOn tasks.named('testClasses')
                    dependsOn tasks.named('moduleCompilationLiveQualificationFreshness')
                    outputs.upToDateWhen { false }
                    testClassesDirs = sourceSets.test.output.classesDirs
                    classpath = sourceSets.test.runtimeClasspath
                    systemProperty 'freshness.marker', file('build/fresh-test-ran').absolutePath
                }
            """), encoding="utf-8")
            (build / "src/test/java/fixture/FreshnessOrderingTest.java").write_text(textwrap.dedent("""\
                package fixture;
                import java.nio.file.Files;
                import java.nio.file.Path;
                import org.junit.Test;
                import static org.junit.Assert.assertTrue;

                public class FreshnessOrderingTest {
                    @Test public void runsAfterFreshnessCheck() throws Exception {
                        Path marker = Path.of(System.getProperty("freshness.marker"));
                        Files.createDirectories(marker.getParent());
                        Files.writeString(marker, "test-ran\\n");
                        assertTrue(Files.isRegularFile(marker));
                    }
                }
            """), encoding="utf-8")

            reports = build / REPORT_RELATIVE
            reports.mkdir(parents=True)
            stale = reports / "TEST-stale.xml"
            stale_bytes = b"preserve stale XML\n"
            stale.write_bytes(stale_bytes)
            refused = self.run_gradle(build)
            self.assertNotEqual(0, refused.returncode, refused.stdout + refused.stderr)
            self.assertIn("refusing existing hosted compiler test reports", refused.stdout + refused.stderr)
            self.assertEqual(stale_bytes, stale.read_bytes())
            self.assertFalse((build / "build/fresh-test-ran").exists())

            shutil.rmtree(reports)
            executed = self.run_gradle(build)
            self.assertEqual(0, executed.returncode, executed.stdout + executed.stderr)
            self.assertEqual("test-ran\n", (build / "build/fresh-test-ran").read_text(encoding="utf-8"))
            self.assertTrue(list(reports.glob("TEST-*.xml")), "fresh Test task must publish its actual test report")

    @contextmanager
    def fixture(self):
        parent = ROOT / "build/test-work/module-compilation-qualification-freshness"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="case-", dir=parent) as directory:
            yield Path(directory)

    def run_preflight(self, checkout: Path) -> subprocess.CompletedProcess[str]:
        env = self.environment(checkout)
        return subprocess.run(
            ["/bin/bash", "scripts/qualify-contained-module-compilation.sh"], cwd=checkout,
            env=env, capture_output=True, text=True, timeout=15, check=False,
        )

    def run_gradle(self, project: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(ROOT / "gradlew"), "--no-daemon", "--console=plain", "--max-workers=1", "-p", str(project),
             "moduleCompilationLiveQualification"], cwd=ROOT, env=self.environment(project),
            capture_output=True, text=True, timeout=240, check=False,
        )

    @staticmethod
    def environment(project: Path) -> dict[str, str]:
        env = dict(os.environ)
        temp = project / "build/test-tmp"
        cache = project / "build/npm-cache"
        temp.mkdir(parents=True, exist_ok=True)
        cache.mkdir(parents=True, exist_ok=True)
        env.update({
            "TMPDIR": str(temp),
            "NPM_CONFIG_CACHE": str(cache),
            "GRADLE_USER_HOME": str(ROOT / "build/gradle-user-home"),
            "JAVA_TOOL_OPTIONS": f"-Djava.io.tmpdir={temp}",
            "GITHUB_RUN_ID": "90000000001",
            "GITHUB_RUN_ATTEMPT": "1",
            "DECOMP_TEST_MODULE_COMPILE_EXT4_SCRATCH": str(project / "build/mock-module-scratch"),
            "DECOMP_TEST_ORACLE_EXT4_SCRATCH": str(project / "build/mock-terminal-scratch"),
        })
        return env


if __name__ == "__main__":
    unittest.main(verbosity=2)
