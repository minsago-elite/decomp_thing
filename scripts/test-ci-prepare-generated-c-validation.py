#!/usr/bin/env python3
"""Unprivileged provisioner controls; no compiler, mount or candidate executes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
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


class CompilerProvisioningControls(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / 'build/task-tmp/generated-c-provisioner-tests'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary)
        self.root = Path(self.temporary.name).resolve()
        self.runtime = self.root / 'runtime'
        self.mounts = self.root / 'mounts'
        self.gcc = self.executable('bin/gcc')
        self.runtime_patch = patch.object(PROVISIONER, 'RUNTIME', self.runtime)
        self.mounts_patch = patch.object(PROVISIONER, 'MOUNTS', self.mounts)
        self.runtime_patch.start()
        self.mounts_patch.start()
        # Root ownership is deliberately mocked: every copied byte is a fixture
        # under checkout/build, and no executable fixture is ever launched.
        self.trusted_patch = patch.object(PROVISIONER, 'trusted', side_effect=lambda path: path.resolve(strict=True))
        self.trusted_mock = self.trusted_patch.start()

    def tearDown(self):
        self.trusted_patch.stop()
        self.mounts_patch.stop()
        self.runtime_patch.stop()
        self.temporary.cleanup()

    def executable(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'fixture bytes, never executed: ' + path.name.encode())
        path.chmod(0o555)
        return path

    def args(self):
        return SimpleNamespace(uid=1000, gid=1000, module_worker_classpath=None,
                               run_id='fixture-run', gate_helper='unused', gate_sha256='0' * 64)

    def test_discovers_and_copies_exact_subprograms_from_both_gcc_layouts(self):
        for layout in ('lib', 'libexec'):
            with self.subTest(layout=layout):
                sources = {role: self.executable(f'usr/{layout}/gcc/fixture/13/{role}')
                           for role in ('cc1', 'collect2')}
                selected_runtime = self.root / f'runtime-{layout}'
                def query(arguments):
                    self.assertEqual(str(self.gcc), arguments[0])
                    self.assertEqual(2, len(arguments))
                    role = arguments[1].removeprefix('-print-prog-name=')
                    self.assertIn(role, sources)
                    return str(sources[role])
                with patch.object(PROVISIONER, 'command', side_effect=query) as command, \
                        patch.object(PROVISIONER, 'RUNTIME', selected_runtime):
                    copier = PROVISIONER.Copier()
                    actual, aliases = PROVISIONER.copy_compiler_subprograms(self.gcc, copier)
                self.assertEqual(sources, actual)
                self.assertEqual([{'source': str(selected_runtime / 'tools' / role),
                                   'destination': f'/decomp-generated-c-tools/{role}'}
                                  for role in ('cc1', 'collect2')], aliases)
                self.assertEqual(2, command.call_count)
                self.assertEqual(2, copier.entries)
                self.assertEqual(sum(path.stat().st_size for path in sources.values()), copier.bytes)
                self.assertEqual({'cc1', 'collect2'}, {path.name for path in (selected_runtime / 'tools').iterdir()})
                for role, source in sources.items():
                    installed = selected_runtime / 'tools' / role
                    self.assertEqual(source.read_bytes(), installed.read_bytes())
                    self.assertEqual(0o555, stat.S_IMODE(installed.stat().st_mode))
                    self.assertFalse(installed.is_symlink())

    def test_absolute_gcc_search_spelling_retains_only_canonical_target(self):
        selected = self.executable('usr/libexec/gcc/fixture/13/cc1')
        search = self.root / 'usr/lib/gcc/fixture/13'
        search.mkdir(parents=True)
        spelling = str(search / '../../../../libexec/gcc/fixture/13/cc1')
        with patch.object(PROVISIONER, 'command', return_value=spelling):
            self.assertEqual(selected, PROVISIONER.compiler_subprogram(self.gcc, 'cc1'))

    def test_unreviewed_roles_fail_before_command_execution(self):
        with patch.object(PROVISIONER, 'command') as command:
            for role in ('as', 'cc1plus', '../cc1', '', 'CC1'):
                with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'unsupported'):
                    PROVISIONER.compiler_subprogram(self.gcc, role)
            command.assert_not_called()

    def test_query_rejects_relative_missing_wrong_role_control_and_oversized_paths(self):
        existing = self.executable('compiler/cc1')
        values = ('', 'cc1', 'compiler/cc1', str(existing.with_name('collect2')),
                  str(self.root / 'absent/cc1'), str(existing) + '\nextra', str(existing) + '\0',
                  '/' + 'x' * 4096 + '/cc1', '/' + '\u00e9' * 2048 + '/cc1')
        for value in values:
            with self.subTest(value=value[:80]), patch.object(PROVISIONER, 'command', return_value=value), \
                    self.assertRaises((ValueError, OSError)):
                PROVISIONER.compiler_subprogram(self.gcc, 'cc1')

    def test_query_rejects_nonregular_nonexecutable_and_changed_canonical_role(self):
        selected = self.executable('compiler/cc1')
        with patch.object(PROVISIONER, 'command', return_value=str(selected)):
            selected.chmod(0o444)
            with self.assertRaisesRegex(ValueError, 'regular executable'):
                PROVISIONER.compiler_subprogram(self.gcc, 'cc1')
            selected.unlink()
            selected.mkdir()
            with self.assertRaisesRegex(ValueError, 'regular executable'):
                PROVISIONER.compiler_subprogram(self.gcc, 'cc1')
            selected.rmdir()
            alternate = self.executable('compiler/foreign')
            selected.symlink_to(alternate)
            with self.assertRaisesRegex(ValueError, 'for its role'):
                PROVISIONER.compiler_subprogram(self.gcc, 'cc1')

    def test_untrusted_gcc_or_subprogram_fails_closed(self):
        selected = self.executable('compiler/cc1')
        with patch.object(PROVISIONER, 'command', return_value=str(selected)) as command:
            self.trusted_mock.side_effect = ValueError('untrusted GCC')
            with self.assertRaisesRegex(ValueError, 'untrusted GCC'):
                PROVISIONER.compiler_subprogram(self.gcc, 'cc1')
            command.assert_not_called()
            def trust_gcc_only(path):
                if path != self.gcc:
                    raise ValueError('untrusted subprogram')
                return self.gcc
            self.trusted_mock.side_effect = trust_gcc_only
            with self.assertRaisesRegex(ValueError, 'untrusted subprogram'):
                PROVISIONER.compiler_subprogram(self.gcc, 'cc1')
            self.assertEqual(1, command.call_count)

    def test_nonexecutable_selected_gcc_is_not_queried(self):
        self.gcc.chmod(0o444)
        with patch.object(PROVISIONER, 'command') as command, \
                self.assertRaisesRegex(ValueError, 'selected GCC'):
            PROVISIONER.compiler_subprogram(self.gcc, 'cc1')
        command.assert_not_called()

    def test_subprogram_copy_charges_existing_entry_and_byte_limits(self):
        sources = {role: self.executable(f'compiler/{role}') for role in ('cc1', 'collect2')}
        with patch.object(PROVISIONER, 'command', side_effect=lambda args: str(sources[args[1].split('=')[1]])):
            for field, maximum in (('MAX_ENTRIES', 1), ('MAX_BYTES', sources['cc1'].stat().st_size)):
                with self.subTest(field=field), patch.object(PROVISIONER, field, maximum), \
                        patch.object(PROVISIONER, 'RUNTIME', self.root / field), \
                        self.assertRaisesRegex(ValueError, 'exceeded'):
                    PROVISIONER.copy_compiler_subprograms(self.gcc, PROVISIONER.Copier())

    def test_all_parents_are_validated_before_any_fresh_root_mutation(self):
        unsafe_parent = self.root / 'unsafe-parent'
        unsafe_parent.mkdir()
        def trust(path):
            if path == unsafe_parent:
                raise ValueError('unsafe parent')
            return path.resolve(strict=True)
        self.trusted_mock.side_effect = trust
        with patch.object(PROVISIONER, 'MOUNTS', unsafe_parent / 'mounts'), \
                patch.object(PROVISIONER, 'cleanup') as cleanup, \
                patch.object(PROVISIONER, 'command') as command, \
                self.assertRaisesRegex(ValueError, 'unsafe parent'):
            PROVISIONER.prepare(self.args())
        self.assertFalse(self.runtime.exists())
        self.assertEqual([], list(unsafe_parent.iterdir()))
        cleanup.assert_not_called()
        command.assert_not_called()

    def test_noncanonical_missing_and_nondirectory_parents_are_refused(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        ordinary_file = self.root / 'file'
        ordinary_file.write_text('not a directory')
        for parent in (alias, ordinary_file, self.root / 'absent'):
            with self.subTest(parent=parent), patch.object(PROVISIONER, 'RUNTIME', parent / 'runtime'), \
                    self.assertRaises((ValueError, OSError)):
                PROVISIONER.require_fresh_qualification_roots()
        self.assertFalse(self.mounts.exists())

    def test_existing_directory_file_and_dangling_link_targets_are_never_adopted(self):
        for kind in ('directory', 'file', 'symlink'):
            target = self.root / kind
            if kind == 'directory':
                target.mkdir()
            elif kind == 'file':
                target.write_text('foreign')
            else:
                target.symlink_to(self.root / 'absent')
            with self.subTest(kind=kind), patch.object(PROVISIONER, 'RUNTIME', target), \
                    patch.object(PROVISIONER, 'cleanup') as cleanup, \
                    self.assertRaisesRegex(ValueError, 'refusing to adopt'):
                PROVISIONER.prepare(self.args())
            cleanup.assert_not_called()
        self.assertFalse(self.mounts.exists())

    def test_primary_failure_survives_explicit_cleanup_refusal(self):
        primary = FileNotFoundError('missing exact compiler subprogram')
        with patch.object(PROVISIONER.Copier, 'copy', side_effect=primary), \
                patch.object(PROVISIONER, 'cleanup', side_effect=ValueError('foreign root marker')) as cleanup:
            with self.assertRaises(FileNotFoundError) as raised:
                PROVISIONER.prepare(self.args())
        self.assertIs(primary, raised.exception)
        cleanup.assert_called_once_with('fixture-run')
        self.assertEqual(['Qualification cleanup also failed; cleanup is not proved: ValueError: foreign root marker'],
                         primary.__notes__)

    def test_successful_cleanup_does_not_replace_or_annotate_primary_failure(self):
        primary = ValueError('primary fixture failure')
        with patch.object(PROVISIONER.Copier, 'copy', side_effect=primary), \
                patch.object(PROVISIONER, 'cleanup') as cleanup:
            with self.assertRaises(ValueError) as raised:
                PROVISIONER.prepare(self.args())
        self.assertIs(primary, raised.exception)
        self.assertFalse(hasattr(primary, '__notes__'))
        cleanup.assert_called_once_with('fixture-run')

    def test_cleanup_still_refuses_foreign_ownership_before_removal_or_unmount(self):
        self.runtime.mkdir()
        marker = self.runtime / 'qualification-owner.json'
        marker.write_text(json.dumps({'runId': 'foreign-run', 'purpose': 'generated-c-public-factory-ci'}))
        with patch.object(PROVISIONER.shutil, 'rmtree') as remove, \
                patch.object(PROVISIONER.subprocess, 'run') as run, \
                self.assertRaisesRegex(ValueError, 'different run'):
            PROVISIONER.cleanup('fixture-run')
        remove.assert_not_called()
        run.assert_not_called()
        self.assertTrue(marker.is_file())


if __name__ == '__main__':
    unittest.main()
