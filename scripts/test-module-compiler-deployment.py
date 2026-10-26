#!/usr/bin/env python3
"""Small Gradle and filesystem controls for frozen module deployment re-entry."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys_path = ROOT / "scripts/module_compiler_deployment.py"
SPEC = importlib.util.spec_from_file_location("module_compiler_deployment", sys_path)
DEPLOYMENT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(DEPLOYMENT)
INIT = ROOT / "scripts/module-compilation-qualification.init.gradle"


def make_jar(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("fixture.bin", payload)


class DeploymentFixture(unittest.TestCase):
    def setUp(self) -> None:
        fixture_root = ROOT / "build/test-work/module-compiler-deployment"
        fixture_root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="case-", dir=fixture_root)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.sources = [self.root / "inputs/app.jar", self.root / "inputs/dependency.jar"]
        make_jar(self.sources[0], b"application bytes")
        make_jar(self.sources[1], b"runtime dependency bytes")
        self.output_root = self.root / "build/module-compilation-qualification"
        self.output_root.mkdir(parents=True)
        self.manifest = self.output_root / "worker-classpath.json"
        self.stage = self.output_root / "deployment"

    def prepare(self) -> bytes:
        return DEPLOYMENT.materialize(self.manifest, self.stage, self.sources)

    def snapshot(self) -> tuple[bytes, dict[str, bytes]]:
        return self.manifest.read_bytes(), {path.name: path.read_bytes() for path in self.stage.iterdir()}

    def assert_refusal_preserves(self, original: tuple[bytes, dict[str, bytes]]) -> None:
        with self.assertRaises((DEPLOYMENT.DeploymentError, OSError)):
            self.prepare()
        self.assertEqual(original, self.snapshot())

    def test_unchanged_inputs_reuse_exact_manifest_and_stage_bytes(self) -> None:
        first = self.prepare()
        before = self.snapshot()
        self.assertEqual(first, before[0])
        self.assertEqual(first, self.prepare())
        self.assertEqual(before, self.snapshot())
        self.assertEqual({"000-app.jar", "001-dependency.jar"}, set(before[1]))
        self.assertEqual({"schemaVersion", "entries"}, set(json.loads(first)))
        self.assertEqual(0o444, self.manifest.stat().st_mode & 0o777)
        self.assertEqual(0o700, self.stage.stat().st_mode & 0o777)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o444 for path in self.stage.iterdir()))

    def test_empty_gradle_stage_is_tightened_and_published_stage_mode_is_pinned(self) -> None:
        self.stage.mkdir(mode=0o755)
        self.assertEqual(0o755, self.stage.stat().st_mode & 0o777)
        self.prepare()
        frozen = self.snapshot()
        self.assertEqual(0o700, self.stage.stat().st_mode & 0o777)

        os.chmod(self.stage, 0o750)
        altered_mode_state = self.snapshot()
        with self.assertRaises(DEPLOYMENT.DeploymentError):
            self.prepare()
        self.assertEqual(altered_mode_state, self.snapshot())
        self.assertEqual(0o750, self.stage.stat().st_mode & 0o777)
        self.assertEqual(frozen[0], self.manifest.read_bytes())

    def test_missing_extra_substituted_and_symlinked_members_refuse_without_repair(self) -> None:
        self.prepare()
        original = self.snapshot()

        (self.stage / "001-dependency.jar").unlink()
        self.assert_refusal_preserves((original[0], {"000-app.jar": original[1]["000-app.jar"]}))
        (self.stage / "001-dependency.jar").write_bytes(original[1]["001-dependency.jar"])
        os.chmod(self.stage / "001-dependency.jar", 0o444)

        extra = self.stage / "unexpected.jar"
        extra.write_bytes(b"extra")
        with self.assertRaises(DEPLOYMENT.DeploymentError):
            self.prepare()
        self.assertEqual(original[0], self.manifest.read_bytes())
        extra.unlink()

        member = self.stage / "001-dependency.jar"
        os.chmod(member, 0o644)
        writable = self.snapshot()
        with self.assertRaises(DEPLOYMENT.DeploymentError):
            self.prepare()
        self.assertEqual(writable, self.snapshot())
        os.chmod(member, 0o444)

        target = self.stage / "000-app.jar"
        os.chmod(target, 0o644)
        target.write_bytes(target.read_bytes()[:-1] + bytes([target.read_bytes()[-1] ^ 1]))
        os.chmod(target, 0o444)
        substituted = self.snapshot()
        with self.assertRaises(DEPLOYMENT.DeploymentError):
            self.prepare()
        self.assertEqual(substituted, self.snapshot())

        target.unlink()
        target.symlink_to(self.sources[0])
        linked = self.snapshot()
        with self.assertRaises((DEPLOYMENT.DeploymentError, OSError)):
            self.prepare()
        self.assertEqual(linked[0], self.manifest.read_bytes())
        self.assertTrue(target.is_symlink())

    def test_changed_source_hash_refuses_and_preserves_prepared_manifest(self) -> None:
        self.prepare()
        original = self.snapshot()
        source = self.sources[0]
        before = source.read_bytes()
        source.write_bytes(before[:-1] + bytes([before[-1] ^ 1]))
        changed_source = source.read_bytes()
        self.assertEqual(len(before), len(changed_source))
        self.assertNotEqual(hashlib.sha256(before).digest(), hashlib.sha256(changed_source).digest())
        self.assert_refusal_preserves(original)

    def test_changed_manifest_hash_and_missing_manifest_refuse_without_overwrite(self) -> None:
        self.prepare()
        original = self.snapshot()
        raw = self.manifest.read_bytes()
        os.chmod(self.manifest, 0o644)
        self.manifest.write_bytes(raw.replace(b"\"sha256\":\"", b"\"sha256\":\"0", 1))
        os.chmod(self.manifest, 0o444)
        tampered = self.snapshot()
        with self.assertRaises(DEPLOYMENT.DeploymentError):
            self.prepare()
        self.assertEqual(tampered, self.snapshot())

        os.chmod(self.manifest, 0o644)
        self.manifest.write_bytes(original[0])
        os.chmod(self.manifest, 0o444)
        self.manifest.unlink()
        stage_before = {path.name: path.read_bytes() for path in self.stage.iterdir()}
        with self.assertRaises(DEPLOYMENT.DeploymentError):
            self.prepare()
        self.assertEqual(stage_before, {path.name: path.read_bytes() for path in self.stage.iterdir()})
        self.assertFalse(self.manifest.exists())

    def test_symlinked_output_ancestor_is_refused_without_writing_through_it(self) -> None:
        redirected = self.root / "redirected-output"
        redirected.mkdir()
        saved_output = self.root / "original-output"
        self.output_root.rename(saved_output)
        self.output_root.symlink_to(redirected, target_is_directory=True)
        with self.assertRaises((DEPLOYMENT.DeploymentError, OSError)):
            self.prepare()
        self.assertEqual([], list(redirected.iterdir()))


class GradleTaskReentryTest(DeploymentFixture):
    def test_real_gradle_task_revalidates_unchanged_then_rejects_changed_inputs(self) -> None:
        project = self.root / "gradle-fixture"
        project.mkdir()
        for source in self.sources:
            make_jar(project / "inputs" / source.name, source.read_bytes())
        helper = (ROOT / "scripts/module_compiler_deployment.py").as_posix()
        build = textwrap.dedent(f"""\
            plugins {{ id 'base' }}
            def output = layout.buildDirectory.file('module-compilation-qualification/worker-classpath.json')
            def staged = layout.buildDirectory.dir('module-compilation-qualification/deployment')
            def sources = [file('inputs/app.jar'), file('inputs/dependency.jar')]
            tasks.register('moduleCompilerDeploymentManifest') {{
                inputs.files(sources)
                outputs.file(output)
                outputs.dir(staged)
                outputs.upToDateWhen {{ false }}
                doLast {{
                    assert staged.get().asFile.parentFile.mkdirs() || staged.get().asFile.parentFile.isDirectory()
                    def command = ['python3', '{helper}', '--manifest', output.get().asFile.absolutePath,
                        '--stage', staged.get().asFile.absolutePath]
                    sources.each {{ source -> command.addAll(['--source', source.absolutePath]) }}
                    def process = new ProcessBuilder(command).redirectErrorStream(true).start()
                    def helperOutput = process.inputStream.getText('UTF-8')
                    def exitCode = process.waitFor()
                    if (!helperOutput.isEmpty()) println(helperOutput)
                    assert exitCode == 0: 'module compiler deployment helper refused'
                }}
            }}
        """)
        (project / "settings.gradle").write_text("rootProject.name = 'module-deployment-reentry'\n", encoding="utf-8")
        (project / "build.gradle").write_text(build, encoding="utf-8")

        def run_gradle() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [str(ROOT / "gradlew"), "--no-daemon", "--console=plain", "-p", str(project),
                 "moduleCompilerDeploymentManifest"], cwd=ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120, check=False,
            )

        first = run_gradle()
        self.assertEqual(0, first.returncode, first.stdout[-4000:])
        manifest = project / "build/module-compilation-qualification/worker-classpath.json"
        stage = project / "build/module-compilation-qualification/deployment"
        frozen_manifest = manifest.read_bytes()
        frozen_entries = {path.name: path.read_bytes() for path in stage.iterdir()}
        self.assertEqual(0o700, stage.stat().st_mode & 0o777)

        second = run_gradle()
        self.assertEqual(0, second.returncode, second.stdout[-4000:])
        self.assertEqual(frozen_manifest, manifest.read_bytes())
        self.assertEqual(frozen_entries, {path.name: path.read_bytes() for path in stage.iterdir()})

        source = project / "inputs/app.jar"
        source.write_bytes(source.read_bytes().replace(b"application bytes", b"application BYTES"))
        changed = run_gradle()
        self.assertNotEqual(0, changed.returncode, changed.stdout[-4000:])
        self.assertIn("differs from current prepared source identities", changed.stdout)
        self.assertEqual(frozen_manifest, manifest.read_bytes())
        self.assertEqual(frozen_entries, {path.name: path.read_bytes() for path in stage.iterdir()})

    def test_production_task_declares_and_revalidates_the_materialized_directory(self) -> None:
        source = INIT.read_text(encoding="utf-8")
        task = source.partition("tasks.register('moduleCompilerDeploymentManifest')")[2].partition("tasks.register('moduleCompilerWriteConfig')")[0]
        self.assertIn("outputs.file(output)", task)
        self.assertIn("outputs.dir(staged)", task)
        self.assertIn("outputs.upToDateWhen { false }", task)
        self.assertIn("scripts/module_compiler_deployment.py", task)
        self.assertIn("moduleCompilerDeploymentManifest'),", source)
        self.assertIn("moduleCompilerHostedCompiledEvidence", source)
        reproducibility = (ROOT / "scripts/check-reproducible-jar.py").read_text(encoding="utf-8")
        self.assertEqual(2, reproducibility.count('["moduleCompilerDeploymentManifest"]'))
        self.assertLess(reproducibility.index('["moduleCompilerDeploymentManifest"]'),
                        reproducibility.index('["processResources", "--rerun", "jar", "--rerun"]'))
        self.assertGreater(reproducibility.rindex('["moduleCompilerDeploymentManifest"]'),
                           reproducibility.index('["processResources", "--rerun", "jar", "--rerun"]'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
