#!/usr/bin/env python3
"""Pure controls for excluded regular leaves under recursive upload patterns."""
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('artifact_leaf_controls', ROOT / 'scripts/atomic_install_artifacts.py')
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)
BASE = ROOT / 'build/orchestration/atomic-artifact-leaf-controls'


class ExcludedLeafControls(unittest.TestCase):
    def setUp(self):
        BASE.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=BASE)
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        workflow = self.root / '.github/workflows/ci.yml'
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes((ROOT / '.github/workflows/ci.yml').read_bytes())
        self.fixture = self.root / 'build/orchestration/atomic-install-remediation/driver-controls-case/java-fixture'
        self.fixture.mkdir(parents=True)
        self.selected = self.fixture / 'result.json'
        self.selected.write_bytes(b'{"fixture":"retained"}\n')
        self.excluded = self.fixture / 'fixture.jar'
        self.manifest = self.root / 'build' / artifacts.MANIFEST
        patterns = artifacts.rules(self.root)
        self.assertTrue(artifacts.selected(patterns, self.selected.relative_to(self.root).as_posix()))
        self.assertFalse(artifacts.selected(patterns, self.excluded.relative_to(self.root).as_posix()))

    def seal(self):
        receipt = artifacts.seal(self.root)
        return receipt, json.loads(self.manifest.read_text())['members']

    def test_exact_workflow_excluded_regular_jar_does_not_become_an_ancestor(self):
        self.excluded.write_bytes(b'inert excluded archive')
        before = self.excluded.stat()
        _, members = self.seal()
        name = self.selected.relative_to(self.root / 'build').as_posix()
        self.assertEqual(set(members), {name})
        self.assertEqual(members[name], {'bytes': self.selected.stat().st_size,
                                       'sha256': hashlib.sha256(self.selected.read_bytes()).hexdigest()})
        after = self.excluded.stat()
        self.assertEqual((before.st_dev, before.st_ino, before.st_size),
                         (after.st_dev, after.st_ino, after.st_size))

    def test_empty_excluded_regular_leaf_is_also_ignored(self):
        self.excluded.touch()
        _, members = self.seal()
        self.assertEqual(len(members), 1)

    def test_excluded_symlink_still_refuses_and_invalidates_previous_manifest(self):
        self.seal()
        self.excluded.symlink_to('absent')
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            self.seal()
        self.assertFalse(self.manifest.exists())

    def test_excluded_fifo_is_not_treated_as_a_regular_leaf(self):
        self.seal()
        os.mkfifo(self.excluded)
        with self.assertRaisesRegex(RuntimeError, 'not directory'):
            self.seal()
        self.assertFalse(self.manifest.exists())

    def test_selected_symlink_is_not_skipped(self):
        self.seal()
        self.selected.unlink()
        self.selected.symlink_to('absent')
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            self.seal()
        self.assertFalse(self.manifest.exists())

    def test_downloaded_membership_still_rejects_excluded_archive(self):
        self.excluded.write_bytes(b'inert excluded archive')
        receipt, members = self.seal()
        archive = self.root / 'download.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            for name in [*members, artifacts.MANIFEST]:
                output.write(self.root / 'build' / name, name)
        self.assertEqual(artifacts.verify(archive, receipt['sha256'])['status'], 'passed')
        with zipfile.ZipFile(archive, 'a') as output:
            output.write(self.excluded, self.excluded.relative_to(self.root / 'build').as_posix())
        with self.assertRaises(RuntimeError):
            artifacts.verify(archive, receipt['sha256'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
