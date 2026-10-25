#!/usr/bin/python3
"""Pure/unprivileged controls; these do not qualify any mounted kernel case."""
import contextlib
import errno
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

mut = load('reset_mutations', 'oracle-ext4-reset-fixture-mutations.py')
core = load('reset_mutation_test_core', 'oracle-ext4-reset.py')
BUILD = HERE.parent / 'build/issue933-evidence/mutation-controls'
BUILD.mkdir(parents=True, exist_ok=True)


class FileMutationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=BUILD)
        self.root = Path(self.temp.name)
        self.private = self.root / 'private'
        self.private.mkdir()
        self.original = self.private / 'image'
        self.original.write_bytes(b'original backing bytes')
        self.patcher = patch.object(mut, 'PRIVATE', self.private)
        self.patcher.start()
        self.subject = object.__new__(mut.Mutations)
        self.subject.core = core
        self.subject.state = {'image': core.file_identity(self.original)}
        # These ordinary test files are deliberately unprivileged. The live
        # constructor and replacement checks still require root ownership.
        actual = core.file_identity
        def fake_identity(path):
            result = actual(path)
            result['uid'] = 0
            return result
        self.fake = types.SimpleNamespace(file_identity=fake_identity, fd_identity=lambda fd: dict(core.fd_identity(fd), uid=0),
                                          mount_table=lambda: [])
        self.subject.core = self.fake
        self.subject.state['image'] = fake_identity(self.original)

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def test_no_clobber_rename_preserves_both_files(self):
        target = self.private / 'occupied'
        target.write_bytes(b'alien')
        with self.assertRaises(OSError) as caught:
            mut.rename_noreplace(self.original, target)
        self.assertEqual(errno.EEXIST, caught.exception.errno)
        self.assertEqual(b'original backing bytes', self.original.read_bytes())
        self.assertEqual(b'alien', target.read_bytes())

    def test_backing_replacement_restores_same_inode(self):
        old = self.original.stat().st_ino
        with self.subject.backing_path_replacement() as facts:
            self.assertEqual(mut.CANARY, self.original.read_bytes())
            self.assertNotEqual(old, self.original.stat().st_ino)
            self.assertEqual(old, (self.private / 'fixture-old-image').stat().st_ino)
        self.assertEqual(old, self.original.stat().st_ino)
        self.assertTrue(facts['cleanup'])
        self.assertEqual(facts['canaryBeforeSha256'], facts['canaryAfterSha256'])

    def test_unknown_replacement_is_preserved_with_original(self):
        context = self.subject.backing_path_replacement()
        context.__enter__()
        self.original.rename(self.private / 'owned-replacement-retained')
        self.original.write_bytes(b'alien replacement')
        with self.assertRaises(mut.MutationError):
            context.__exit__(None, None, None)
        self.assertEqual(b'alien replacement', self.original.read_bytes())
        self.assertEqual(b'original backing bytes', (self.private / 'fixture-old-image').read_bytes())

    def test_changed_canary_content_preserves_original_and_replacement(self):
        context = self.subject.backing_path_replacement()
        context.__enter__()
        self.original.chmod(0o600)
        self.original.write_bytes(b'changed')
        with self.assertRaises(mut.MutationError):
            context.__exit__(None, None, None)
        self.assertEqual(b'changed', self.original.read_bytes())
        self.assertTrue((self.private / 'fixture-old-image').exists())

    def test_same_size_changed_canary_is_refused_by_bytes(self):
        context = self.subject.backing_path_replacement()
        context.__enter__()
        self.original.chmod(0o600)
        self.original.write_bytes(b'X' * len(mut.CANARY))
        self.original.chmod(0o400)
        with self.assertRaisesRegex(mut.MutationError, 'canary changed'):
            context.__exit__(None, None, None)
        self.assertEqual(b'X' * len(mut.CANARY), self.original.read_bytes())
        self.assertTrue((self.private / 'fixture-old-image').exists())

    def test_replacement_mount_drift_refuses_before_any_unmount(self):
        scratch = self.root / 'scratch'
        scratch.mkdir()
        self.subject.scratch = scratch
        self.subject.record = {'underlying': {'id': 'underlying'}}
        original = {'path': str(scratch), 'id': 42}
        replacement = {'path': str(scratch), 'id': 43}
        calls = []
        self.subject._original_mount = lambda path: original
        self.subject._mkdir = lambda path: {'id': 'empty'}
        self.subject._expect = lambda *args: None
        self.subject._row = lambda path, expected=None: replacement
        self.subject._run = lambda role, *args, **kwargs: calls.append((role, args))
        context = self.subject.mount_replacement()
        context.__enter__()
        def refuse(*args):
            raise mut.MutationError('owned mount changed')
        self.subject._row = refuse
        with self.assertRaisesRegex(mut.MutationError, 'mount changed'):
            context.__exit__(None, None, None)
        self.assertEqual(['mount', 'mount'], [role for role, _ in calls])
        self.assertEqual(mut.CANARY, (scratch / 'fixture-canary').read_bytes())

    def test_companion_is_retained_bound_without_detach_or_unlink(self):
        self.subject.state.update(loop={'path': '/dev/loop12', 'rdev': os.makedev(7, 12)}, owner={})
        self.fake.loop_identity = lambda *args: self.subject.state['loop']
        self.subject._run = lambda *args, **kwargs: b'/dev/loop11\n'
        real_open = os.open
        def fake_open(path, flags, *args, **kwargs):
            return real_open(self.original if path == '/dev/loop11' else path, flags, *args, **kwargs)
        def observed(*args):
            image = self.subject._id(self.private / 'fixture-companion-image')
            return {'node': {'rdev': os.makedev(7, 11)}, 'backingDevice': image['device'],
                    'backingInode': image['inode'], 'sizeLimit': 4096, 'flags': 0}
        with patch.object(mut.os, 'open', fake_open), patch.object(mut, 'companion_identity', observed), \
                patch.object(mut.fcntl, 'ioctl', side_effect=AssertionError('no detach ioctl')):
            with self.subject.unrelated_loop() as facts:
                self.assertEqual(4096, (self.private / 'fixture-companion-image').stat().st_size)
        self.assertTrue(facts['cleanup'])
        self.assertTrue(facts['companionReserved'])
        self.assertEqual(4096, (self.private / 'fixture-companion-image').stat().st_size)

    def test_preexisting_saved_path_refuses_before_mutation(self):
        saved = self.private / 'fixture-old-image'
        saved.symlink_to('missing')
        with self.assertRaises(mut.MutationError):
            with self.subject.backing_path_replacement():
                self.fail('must refuse')
        self.assertTrue(saved.is_symlink())
        self.assertEqual(b'original backing bytes', self.original.read_bytes())

    def test_canary_fifo_replacement_refuses_without_blocking_or_deleting(self):
        directory = os.open(self.private, os.O_RDONLY | os.O_DIRECTORY)
        fd, identity = self.subject._canary(directory)
        try:
            (self.private / 'fixture-canary').rename(self.private / 'retained-canary')
            os.mkfifo(self.private / 'fixture-canary')
            with self.assertRaises(mut.MutationError):
                self.subject._check_canary(directory, fd, identity)
            self.assertTrue((self.private / 'fixture-canary').exists())
        finally:
            os.close(fd); os.close(directory)

    def test_rmdir_unknown_population_does_not_delete_it(self):
        path = self.private / 'directory'
        path.mkdir()
        ident = self.subject._id(path)
        (path / 'alien').write_bytes(b'kept')
        with self.assertRaises(OSError):
            self.subject._rmdir(path, ident)
        self.assertEqual(b'kept', (path / 'alien').read_bytes())


class PhysicalContractTests(unittest.TestCase):
    def test_nonroot_constructor_refuses_before_any_probe(self):
        with patch.object(mut.os, 'geteuid', return_value=65534), self.assertRaises(mut.MutationError):
            mut.Mutations(None, None, None)

    def test_companion_observer_rejects_wrong_binding_parameters(self):
        obj = {'kind': 'block', 'rdev': os.makedev(7, 11), 'uid': 0}
        fake = types.SimpleNamespace(fd_identity=lambda fd: obj)
        def ioctl_for(values, size=4096):
            def ioctl(fd, command, buffer, mutate=True):
                if command == 0x4C05:
                    struct.pack_into('=QQQQQIIII', buffer, 0, *values)
                else:
                    struct.pack_into('=Q', buffer, 0, size)
            return ioctl
        valid = [1, 2, 0, 0, 4096, 11, 0, 0, 0]
        with patch.object(mut.fcntl, 'ioctl', ioctl_for(valid)):
            observed = mut.companion_identity(fake, 10, '/dev/loop11')
        self.assertEqual(4096, observed['sizeLimit'])
        for index, value in ((3, 512), (4, 67108864), (5, 12), (6, 1), (7, 1), (8, 4)):
            changed = valid.copy(); changed[index] = value
            with self.subTest(index=index), patch.object(mut.fcntl, 'ioctl', ioctl_for(changed)), self.assertRaises(mut.MutationError):
                mut.companion_identity(fake, 10, '/dev/loop11')
        with patch.object(mut.fcntl, 'ioctl', ioctl_for(valid, 8192)), self.assertRaises(mut.MutationError):
            mut.companion_identity(fake, 10, '/dev/loop11')

    def test_stacked_and_descendant_mounts_are_rejected(self):
        subject = object.__new__(mut.Mutations)
        root = {'path': '/fixed', 'id': 42}
        for rows in ([root, root], [root, {'path': '/fixed/child', 'id': 43}], []):
            subject.core = types.SimpleNamespace(mount_table=lambda: rows)
            with self.subTest(rows=rows), self.assertRaises(mut.MutationError):
                subject._row('/fixed')

    def test_exact_mount_change_refuses(self):
        subject = object.__new__(mut.Mutations)
        subject.core = types.SimpleNamespace(mount_table=lambda: [{'path': '/fixed', 'id': 43}])
        with self.assertRaises(mut.MutationError):
            subject._row('/fixed', {'path': '/fixed', 'id': 42})

    def test_runner_only_supports_closed_fixed_tools(self):
        subject = object.__new__(mut.Mutations)
        calls = []
        subject.runner = lambda argv, **kwargs: calls.append((argv, kwargs)) or b''
        subject._run('umount', '--no-canonicalize', '/fixed')
        self.assertEqual('/usr/bin/umount', calls[0][0][0])
        with self.assertRaises(mut.MutationError):
            subject._run('foreign', 'command')
        self.assertEqual(1, len(calls))

    def test_final_cleanup_requires_current_state_and_inactive_custodian_under_lock(self):
        subject = object.__new__(mut.Mutations)
        subject.state = {'phase': 'PUBLISHED', 'sequence': 7}
        events = []
        @contextlib.contextmanager
        def opened():
            events.append('lock')
            yield types.SimpleNamespace(load=lambda: subject.state, lock=11)
            events.append('unlock')
        subject.core = types.SimpleNamespace(opened_store=opened,
            inactive_snapshot=lambda store, state: events.append('inactive'))
        subject._fence_and_unmount = lambda fd: events.append(('fence', fd)) or {'cleanup': True}
        self.assertEqual({'cleanup': True}, subject.fence_and_unmount())
        self.assertEqual(['lock', 'inactive', ('fence', 11), 'unlock'], events)

    def test_candidate_wrapper_refuses_wrong_phase_without_mutation(self):
        subject = object.__new__(mut.Mutations)
        subject.state = {'phase': 'PUBLISHED'}
        subject.mount_replacement = lambda: self.fail('must not start mutation')
        with self.assertRaises(mut.MutationError):
            subject.candidate_intent_replacement()

    def test_final_fence_refuses_changed_loop_before_chmod_or_command(self):
        subject = object.__new__(mut.Mutations)
        subject.state = {'loop': {'path': '/dev/loop11'}, 'owner': {}}
        subject.core = types.SimpleNamespace(loop_identity=lambda *args: {'path': '/dev/loop12'})
        with patch.object(mut.os, 'fchmod') as chmod, self.assertRaises(mut.MutationError):
            subject._fence_and_unmount(99)
        chmod.assert_not_called()


if __name__ == '__main__':
    unittest.main()
