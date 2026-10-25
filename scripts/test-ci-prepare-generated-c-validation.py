#!/usr/bin/env python3
"""Unprivileged worker-manifest controls; no provisioning, compiler, mount or candidate executes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('generated_c_provisioner', ROOT / 'scripts/ci-prepare-generated-c-validation.py')
PROVISIONER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISIONER)


class ModuleWorkerClasspathControls(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / 'build/task-tmp/worker-manifest-tests'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary)
        self.root = Path(self.temporary.name).resolve()
        self.jar = self.root / 'worker.jar'
        with zipfile.ZipFile(self.jar, 'w') as jar:
            jar.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
        self.manifest = self.root / 'worker-classpath.json'

    def tearDown(self):
        self.temporary.cleanup()

    def entry(self, path=None):
        path = path or self.jar
        payload = path.read_bytes()
        return {'path': str(path), 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}

    def admit(self, value=None):
        self.manifest.write_text(json.dumps(value or {'schemaVersion': 1, 'entries': [self.entry()]}))
        return PROVISIONER.read_module_worker_classpath(self.manifest, self.root, os.getuid())

    def test_copies_only_pinned_jars_read_only_and_emits_installed_pins(self):
        admitted = self.admit()
        result = PROVISIONER.copy_module_worker_classpath(admitted, self.root / 'installed', os.getuid())
        installed = self.root / 'installed/classpath-0.jar'
        self.assertEqual(self.jar.read_bytes(), installed.read_bytes())
        self.assertEqual(0o444, stat.S_IMODE(installed.stat().st_mode))
        self.assertEqual({'schemaVersion': 1, 'entries': [self.entry(installed)]}, result)

    def test_exact_fields_types_and_content_pins_are_required(self):
        entry = self.entry()
        for field, value in [('path', 'relative.jar'), ('bytes', True), ('bytes', entry['bytes'] + 1),
                             ('bytes', 0), ('sha256', 'A' * 64), ('sha256', '0' * 64)]:
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, OSError)):
                self.admit({'schemaVersion': 1, 'entries': [{**entry, field: value}]})
        for value in ({'schemaVersion': True, 'entries': [entry]}, {'schemaVersion': 2, 'entries': [entry]},
                      {'schemaVersion': 1, 'entries': [entry], 'command': 'arbitrary'},
                      {'schemaVersion': 1, 'entries': [{**entry, 'optional': True}]},
                      {'schemaVersion': 1, 'entries': [{key: value for key, value in entry.items() if key != 'sha256'}]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.admit(value)

    def test_symlinks_hardlinks_duplicates_and_paths_outside_build_are_rejected(self):
        symlink = self.root / 'alias.jar'
        symlink.symlink_to(self.jar)
        with self.assertRaises(ValueError):
            self.admit({'schemaVersion': 1, 'entries': [self.entry(symlink)]})
        symlink.unlink()
        hardlink = self.root / 'hard.jar'
        os.link(self.jar, hardlink)
        with self.assertRaises(ValueError):
            self.admit()
        hardlink.unlink()
        with self.assertRaises(ValueError):
            self.admit({'schemaVersion': 1, 'entries': [self.entry(), self.entry()]})
        with self.assertRaises(ValueError):
            PROVISIONER.worker_path(str(ROOT / 'scripts/ci-prepare-generated-c-validation.py'), self.root)
        directory_link = self.root / 'directory-link'
        directory_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.admit({'schemaVersion': 1, 'entries': [{**self.entry(), 'path': str(directory_link / self.jar.name)}]})

    def test_non_jars_special_files_wrong_owner_and_duplicate_keys_are_rejected(self):
        self.jar.write_bytes(b'not a jar')
        with self.assertRaises(ValueError):
            self.admit()
        with self.assertRaises(ValueError):
            PROVISIONER.open_worker_file(self.jar, 1024, os.getuid() + 1)
        self.manifest.write_text('{"schemaVersion":1,"schemaVersion":1,"entries":[]}')
        with self.assertRaises(ValueError):
            PROVISIONER.read_module_worker_classpath(self.manifest, self.root)
        directory = self.root / 'directory.jar'
        directory.mkdir()
        with self.assertRaises(ValueError):
            PROVISIONER.open_worker_file(directory, 1024)
        fifo = self.root / 'fifo.jar'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            PROVISIONER.open_worker_file(fifo, 1024)

    def test_count_manifest_size_and_aggregate_bounds_are_enforced_before_copy(self):
        for entries in ([], [self.entry()] * (PROVISIONER.MAX_WORKER_ENTRIES + 1)):
            with self.assertRaises(ValueError):
                self.admit({'schemaVersion': 1, 'entries': entries})
        self.manifest.write_bytes(b' ' * (PROVISIONER.MAX_WORKER_MANIFEST_BYTES + 1))
        with self.assertRaises(ValueError):
            PROVISIONER.read_module_worker_classpath(self.manifest, self.root)
        before = PROVISIONER.MAX_WORKER_BYTES
        try:
            PROVISIONER.MAX_WORKER_BYTES = self.jar.stat().st_size
            second = self.root / 'second.jar'
            second.write_bytes(self.jar.read_bytes())
            with self.assertRaises(ValueError):
                self.admit({'schemaVersion': 1, 'entries': [self.entry(), self.entry(second)]})
        finally:
            PROVISIONER.MAX_WORKER_BYTES = before

    def test_copy_rechecks_pin_after_admission_and_keeps_failed_output_private(self):
        admitted = self.admit()
        self.jar.write_bytes(self.jar.read_bytes().replace(b'Manifest-Version', b'Manifest-VersioN'))
        with self.assertRaises(ValueError):
            PROVISIONER.copy_module_worker_classpath(admitted, self.root / 'installed', os.getuid())
        self.assertEqual(0o600, stat.S_IMODE((self.root / 'installed/classpath-0.jar').stat().st_mode))


if __name__ == '__main__':
    unittest.main()
