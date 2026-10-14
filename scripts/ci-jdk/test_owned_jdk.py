"""Owned fake-JDK controls. No downloads, namespace changes, model or authentication calls."""
from pathlib import Path
import hashlib
import importlib.util
import os
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('owned_jdk', ROOT / 'scripts/ci-owned-jdk.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)

class OwnedJdkTest(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'build/owned-jdk-controls'; base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.repo = Path(self.temp.name)
        self.source = self.repo / 'selected'; (self.source / 'bin').mkdir(parents=True)
        (self.source / 'lib').mkdir()
        self.java = self.source / 'bin/java'; self.java.write_bytes(b'fixed owned fake launcher'); self.java.chmod(0o777)
        (self.source / 'release').write_text('JAVA_VERSION="21.0.12"\nIMPLEMENTOR="owned inert fixture"\n')
        (self.source / 'lib/modules').write_bytes(b'inert modules')
        (self.source / 'lib/ambient-link').symlink_to('/does-not-exist/ambient')
    def tearDown(self): self.temp.cleanup()
    def test_0777_source_unchanged_and_independent_clone_0755(self):
        before = fixture.identity(self.java.stat()); digest = hashlib.sha256(self.java.read_bytes()).hexdigest()
        result = fixture.provision(self.repo, self.source)
        copied = Path(result['home']) / 'bin/java'
        self.assertEqual(before, fixture.identity(self.java.stat()))
        self.assertEqual(0o777, stat.S_IMODE(self.java.stat().st_mode))
        self.assertEqual(0o755, stat.S_IMODE(copied.stat().st_mode))
        self.assertNotEqual((copied.stat().st_dev, copied.stat().st_ino), before[:2])
        self.assertEqual(digest, hashlib.sha256(copied.read_bytes()).hexdigest())
        self.assertEqual('/does-not-exist/ambient', os.readlink(Path(result['home']) / 'lib/ambient-link'))
        self.assertEqual(os.geteuid(), copied.stat().st_uid); self.assertEqual(1, copied.stat().st_nlink)
        fixture.verify_source(result)
        second = fixture.provision(self.repo, self.source)
        self.assertNotEqual(result['home'], second['home'])
    def test_chmod_never_targets_any_source_inode(self):
        sources = {(p.lstat().st_dev, p.lstat().st_ino) for p in [self.source, *self.source.rglob('*')]}
        original = os.fchmod
        def checked(fd, mode):
            value = os.fstat(fd)
            self.assertNotIn((value.st_dev, value.st_ino), sources)
            return original(fd, mode)
        with mock.patch.object(fixture.os, 'fchmod', checked): fixture.provision(self.repo, self.source)
    def test_partial_open_failure_recovers_descriptors(self):
        before = len(os.listdir('/proc/self/fd')); original = os.open
        def failed(path, flags, *args, **kwargs):
            if flags & os.O_CREAT: raise OSError('inert copied-file allocation failure')
            return original(path, flags, *args, **kwargs)
        with mock.patch.object(fixture.os, 'open', failed), self.assertRaises(OSError): fixture.provision(self.repo, self.source)
        self.assertEqual(before, len(os.listdir('/proc/self/fd')))
    def test_symlink_launcher_refused_without_changing_target(self):
        self.java.unlink(); target = self.source / 'lib/target'; target.write_bytes(b'unchanged'); target.chmod(0o777)
        self.java.symlink_to('../lib/target')
        with self.assertRaises(ValueError): fixture.provision(self.repo, self.source)
        self.assertEqual(0o777, stat.S_IMODE(target.stat().st_mode)); self.assertEqual(b'unchanged', target.read_bytes())
    def test_special_source_file_refused(self):
        os.mkfifo(self.source / 'pipe')
        with self.assertRaises(ValueError): fixture.provision(self.repo, self.source)
    def test_symlink_build_refused(self):
        other = self.repo / 'other'; other.mkdir(); (self.repo / 'build').symlink_to(other)
        with self.assertRaises(ValueError): fixture.provision(self.repo, self.source)
        self.assertEqual([], list(other.iterdir()))
    def test_changed_source_refused(self):
        result = fixture.provision(self.repo, self.source); self.java.chmod(0o755)
        with self.assertRaises(ValueError): fixture.verify_source(result)
    def test_changed_owned_launcher_refused(self):
        result = fixture.provision(self.repo, self.source); (Path(result['home']) / 'bin/java').write_bytes(b'substitute')
        with self.assertRaises(ValueError): fixture.verify_source(result)
    def test_full_caller_credentials_are_authority(self):
        result = fixture.credentials('Pid:\t123\nUid:\t10 11 12 13\nGid:\t20 21 22 23\n', 123)
        self.assertEqual({'Uid':'10,11,12,13','Gid':'20,21,22,23'}, result)
        actual = fixture.caller_credentials(); self.assertEqual(list(os.getresuid()), list(map(int, actual['Uid'].split(',')))[:3])
    def test_unknown_duplicate_wrong_pid_credentials_refused(self):
        for text in ['Pid: 124\nUid: 1 1 1 1\nGid: 1 1 1 1\n',
                     'Pid: 123\nUid: 1 1 1\nGid: 1 1 1 1\n',
                     'Pid: 123\nUid: 1 1 1 1\nUid: 2 2 2 2\nGid: 1 1 1 1\n', 'x' * 65537]:
            with self.subTest(text=text[:20]), self.assertRaises(ValueError): fixture.credentials(text,123)
    def test_socket_budget_is_encoded_bytes_and_accepts_hosted_root_only(self):
        hosted = Path('/home/runner/work/decomp_thing/decomp_thing')
        self.assertEqual(63, len(fixture.SOCKET_FIXTURE_SUFFIX.encode('ascii')))
        self.assertEqual(106, len(os.fsencode(hosted)) + 63)
        # Exercise actual canonical ownership independently of this checkout's length.
        with mock.patch.object(fixture, 'UNIX_SOCKET_PATH_BYTES', 4096):
            result = fixture.socket_scratch(ROOT)
            self.assertEqual(str(ROOT), result['path'])
            self.assertEqual(os.geteuid(), result['uid'])
        for path in [Path('/' + 'x' * 44), Path('/' + 'é' * 22)]:
            with self.assertRaisesRegex(ValueError, 'byte budget'):
                fixture.socket_scratch(path)
        with mock.patch.object(fixture, 'secure_directory', return_value=os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)):
            self.assertEqual(str(hosted), fixture.socket_scratch(hosted)['path'])
        with self.assertRaisesRegex(ValueError, 'byte budget'):
            fixture.socket_scratch(hosted / 't')
    def test_socket_scratch_refuses_symlink_or_writable_directory(self):
        # Keep this independent of the checkout's actual path length.
        with mock.patch.object(fixture, 'UNIX_SOCKET_PATH_BYTES', 4096):
            target = self.repo / 'scratch'; target.mkdir(); alias = self.repo / 'alias'; alias.symlink_to(target)
            with self.assertRaises(ValueError): fixture.socket_scratch(alias)
            target.chmod(0o777)
            with self.assertRaises(ValueError): fixture.socket_scratch(target)

    def test_missing_actual_test_jvm_proof_refused(self):
        with self.assertRaises(ValueError): fixture.verify_jvms(fixture.provision(self.repo, self.source))
    def test_actual_worker_scratch_must_equal_exact_repository(self):
        result = fixture.provision(self.repo, self.source); container = Path(result['container'])
        expected = fixture.parse_properties(container / 'provision.properties')
        props = {k: v for k,v in expected.items() if k not in ('java','receipts')}
        props.update(command=result['home'] + '/bin/java', pid='123', task=':test', scratch=str(self.repo))
        file = container / 'receipts/test.properties'
        def write(): file.write_text(''.join(k+'='+v+'\n' for k,v in props.items()))
        write(); file.with_suffix('.closed').write_text('closed\n')
        (container / 'selections/test.properties').write_text('task=:test\nhome='+result['home']+'\njava='+result['home']+'/bin/java\n')
        self.assertEqual(1, fixture.verify_jvms(result))
        for substitute in [str(self.repo.parent), '/home/june']:
            props['scratch'] = substitute; write()
            with self.assertRaisesRegex(ValueError, 'identity mismatch'): fixture.verify_jvms(result)

    def test_byte_equal_command_at_source_cannot_substitute_clone(self):
        result = fixture.provision(self.repo, self.source); container = Path(result['container'])
        expected = fixture.parse_properties(container / 'provision.properties')
        props = {k: v for k,v in expected.items() if k not in ('java','receipts')}
        props.update(command=str(self.java), pid='123', task=':test')
        file = container / 'receipts/test.properties'; file.write_text(''.join(k+'='+v+'\n' for k,v in props.items()))
        file.with_suffix('.closed').write_text('closed\n')
        (container / 'selections/test.properties').write_text('task=:test\nhome='+result['home']+'\njava='+result['home']+'/bin/java\n')
        with self.assertRaises(ValueError): fixture.verify_jvms(result)

if __name__ == '__main__': unittest.main()
