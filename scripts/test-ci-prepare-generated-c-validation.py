#!/usr/bin/env python3
"""Unprivileged provisioner controls; no compiler, mount or candidate executes."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout
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

    def test_contained_module_runtime_closure_includes_accepted_standard_headers(self):
        for header in ('<stdlib.h>', '<string.h>'):
            with self.subTest(header=header):
                self.assertIn(header, PROVISIONER.HEADER_CLOSURE_SOURCE)

    def test_compiler_include_search_evidence_is_bounded_and_pins_stddef(self):
        include = self.root / 'gcc/include'
        include.mkdir(parents=True)
        mounted_include = self.runtime / 'gcc/include'
        mounted_include.mkdir(parents=True)
        (self.runtime / 'headers').mkdir(parents=True)
        header = mounted_include / 'stddef.h'
        header.write_bytes(b'authenticated standard header\n')
        stdarg = mounted_include / 'stdarg.h'
        stdarg.write_bytes(b'authenticated GCC builtin header\n')
        unapproved = self.root / 'unapproved/include'
        stderr = (b'#include <...> search starts here:\n' + str(mounted_include).encode() + b'\n' +
                  str(include).encode() + b'\n' +
                  str(unapproved).encode() + b'\nEnd of search list.\n')
        result = SimpleNamespace(returncode=0, stdout='', stderr=stderr.decode())
        staged = self.executable('runtime/tools/cc')
        prefix = staged.parent
        with patch.object(PROVISIONER.subprocess, 'run', return_value=result) as run:
            evidence = PROVISIONER.staged_compiler_include_search(staged, prefix,
                ((self.root / 'gcc', self.runtime / 'gcc'), (Path('/usr/include'), self.runtime / 'headers')),
                mounted_include)
        self.assertEqual(0, evidence['exitCode'])
        self.assertEqual([str(mounted_include), str(include), str(unapproved)], evidence['searchPaths'])
        self.assertEqual([{'searchPath': str(mounted_include), 'mountedPath': str(header), 'bytes': len(header.read_bytes()),
                           'sha256': hashlib.sha256(header.read_bytes()).hexdigest()},
                          {'searchPath': str(include), 'mountedPath': str(header), 'bytes': len(header.read_bytes()),
                           'sha256': hashlib.sha256(header.read_bytes()).hexdigest()}], evidence['stddefCandidates'])
        self.assertEqual([{'searchPath': str(mounted_include), 'mountedPath': str(stdarg), 'bytes': len(stdarg.read_bytes()),
                           'sha256': hashlib.sha256(stdarg.read_bytes()).hexdigest()},
                          {'searchPath': str(include), 'mountedPath': str(stdarg), 'bytes': len(stdarg.read_bytes()),
                           'sha256': hashlib.sha256(stdarg.read_bytes()).hexdigest()}], evidence['stdargCandidates'])
        PROVISIONER.require_compiler_builtin_header_candidate(evidence, mounted_include, 'stdarg.h')
        self.assertIn('-B' + str(prefix) + '/', run.call_args.args[0])
        self.assertIn('-I' + str(mounted_include), run.call_args.args[0])
        no_candidate = SimpleNamespace(returncode=1, stdout='', stderr=(
            '#include <...> search starts here:\n' + str(unapproved) + '\nEnd of search list.\n'))
        with patch.object(PROVISIONER.subprocess, 'run', return_value=no_candidate):
            absent = PROVISIONER.staged_compiler_include_search(staged, prefix,
                ((self.root / 'gcc', self.runtime / 'gcc'), (Path('/usr/include'), self.runtime / 'headers')),
                mounted_include)
        self.assertEqual([], absent['stddefCandidates'])
        with self.assertRaisesRegex(ValueError, 'authenticated readable GCC builtin stdarg.h'):
            PROVISIONER.require_compiler_builtin_header_candidate(absent, mounted_include, 'stdarg.h')
        with self.assertRaisesRegex(ValueError, 'complete include-search list'):
            PROVISIONER.parse_gcc_include_search_paths(b'no compiler diagnostics')
        with self.assertRaisesRegex(ValueError, 'canonical and absolute'):
            PROVISIONER.parse_gcc_include_search_paths(
                b'#include <...> search starts here:\nrelative/include\nEnd of search list.\n')
        with self.assertRaisesRegex(ValueError, 'byte bound'):
            PROVISIONER.parse_gcc_include_search_paths(b'x' * (1024 * 1024 + 1))

    def test_failed_stddef_admission_retains_bounded_search_evidence_without_raw_diagnostics(self):
        evidence = {'exitCode': 1, 'searchPaths': ['/usr/include'], 'stddefCandidates': [],
                    'diagnosticsBytes': 42, 'diagnosticsSha256': 'a' * 64}
        output = io.StringIO()
        with redirect_stdout(output):
            with self.assertRaisesRegex(ValueError, 'authenticated readable stddef'):
                PROVISIONER.require_compiler_stddef_candidate(evidence)
        retained = json.loads(output.getvalue())
        self.assertEqual({'schemaVersion': 1, 'compilerIncludeSearch': evidence}, retained)
        self.assertNotIn('fatal error', output.getvalue().lower())

    def test_stddef_admission_emits_no_failure_record_when_candidate_is_authenticated(self):
        output = io.StringIO()
        with redirect_stdout(output):
            PROVISIONER.require_compiler_stddef_candidate(
                {'exitCode': 0, 'searchPaths': ['/usr/include'], 'stddefCandidates': [{'sha256': 'b' * 64}],
                 'diagnosticsBytes': 0, 'diagnosticsSha256': 'c' * 64})
        self.assertEqual('', output.getvalue())

    def test_compiler_builtin_stddef_is_materialized_under_the_authenticated_include_alias(self):
        gcc_runtime = self.root / 'gcc'
        builtin = gcc_runtime / 'include/stddef.h'
        builtin.parent.mkdir(parents=True)
        builtin.write_bytes(b'pinned GCC builtin stddef bytes\n')
        headers = self.runtime / 'headers'
        headers.mkdir(parents=True)
        copier = PROVISIONER.Copier()

        PROVISIONER.preserve_compiler_builtin_headers([str(builtin)], gcc_runtime, headers, copier)

        installed = headers / 'stddef.h'
        self.assertEqual(builtin.read_bytes(), installed.read_bytes())
        self.assertEqual(0o444, stat.S_IMODE(installed.stat().st_mode))
        self.assertEqual(1, copier.entries)
        PROVISIONER.preserve_compiler_builtin_headers([str(builtin)], gcc_runtime, headers, copier)
        self.assertEqual(1, copier.entries)

    def test_compiler_builtin_stddef_requires_one_pinned_header_under_gcc_runtime(self):
        gcc_runtime = self.root / 'gcc'
        gcc_runtime.mkdir()
        elsewhere = self.root / 'other/include/stddef.h'
        elsewhere.parent.mkdir(parents=True)
        elsewhere.write_bytes(b'not in GCC runtime')
        headers = self.runtime / 'headers'
        headers.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'one pinned GCC builtin stddef'):
            PROVISIONER.preserve_compiler_builtin_headers([str(elsewhere)], gcc_runtime, headers, PROVISIONER.Copier())

    def test_compiler_builtin_include_tree_is_copied_to_the_authenticated_b_prefix(self):
        gcc_runtime = self.root / 'gcc'
        source = gcc_runtime / 'include'
        source.mkdir(parents=True)
        (source / 'stdarg.h').write_bytes(b'pinned builtin stdarg bytes\n')
        (source / 'stddef.h').write_bytes(b'pinned builtin stddef bytes\n')
        tools = self.runtime / 'tools'
        tools.mkdir(parents=True)
        copier = PROVISIONER.Copier()

        destination = PROVISIONER.copy_compiler_builtin_include_directory(source, gcc_runtime, tools, copier)

        self.assertEqual(b'pinned builtin stdarg bytes\n', (destination / 'stdarg.h').read_bytes())
        self.assertEqual(0o444, stat.S_IMODE((destination / 'stdarg.h').stat().st_mode))
        self.assertEqual(3, copier.entries)
        with self.assertRaisesRegex(ValueError, 'destination already exists'):
            PROVISIONER.copy_compiler_builtin_include_directory(source, gcc_runtime, tools, copier)

    def test_compiler_builtin_include_tree_refuses_unpinned_roots_and_missing_stdarg(self):
        gcc_runtime = self.root / 'gcc'
        source = gcc_runtime / 'include'
        source.mkdir(parents=True)
        tools = self.runtime / 'tools'
        tools.mkdir(parents=True)
        outside = self.root / 'outside/include'
        outside.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'pinned include subtree'):
            PROVISIONER.copy_compiler_builtin_include_directory(
                outside, gcc_runtime, tools, PROVISIONER.Copier())
        with self.assertRaisesRegex(ValueError, 'lacks a regular stdarg.h'):
            PROVISIONER.copy_compiler_builtin_include_directory(source, gcc_runtime, tools, PROVISIONER.Copier())

    def args(self):
        return SimpleNamespace(uid=1000, gid=1000, module_worker_classpath=None,
                               module_compiler_exec_helper=None, module_compiler_exec_helper_sha256=None,
                               run_id='fixture-run', gate_helper='unused', gate_sha256='0' * 64)

    def test_pinned_module_trampoline_is_copied_only_after_identity_and_digest_recheck(self):
        build_root = ROOT / 'build'
        source = build_root / 'task-tmp' / f'module-helper-{self.root.name}'
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b'fixed native helper bytes')
        source.chmod(0o555)
        self.addCleanup(source.unlink, missing_ok=True)
        target_dir = self.runtime / 'tools'
        target_dir.mkdir(parents=True)
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        installed = target_dir / 'decomp-module-compiler-exec'
        result = PROVISIONER.copy_pinned_module_exec_helper(str(source), expected, build_root, installed, os.getuid())
        self.assertEqual(source.read_bytes(), installed.read_bytes())
        self.assertEqual(0o555, stat.S_IMODE(installed.stat().st_mode))
        self.assertEqual(expected, result['sha256'])
        rejected = target_dir / 'substituted-helper'
        with self.assertRaises(ValueError):
            PROVISIONER.copy_pinned_module_exec_helper(str(source), '0' * 64, build_root, rejected, os.getuid())
        self.assertFalse(rejected.exists())

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
