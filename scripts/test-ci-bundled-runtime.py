#!/usr/bin/env python3
"""Exercise CI runtime copy/release with inert files in a disposable root user namespace.

Run as an ordinary Linux user with bubblewrap and unprivileged user namespaces.
No Ghidra application, privileged host directory, or analysis workflow is executed.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def python_body(name):
    script = Path('/repo/scripts', name).read_text()
    return script.split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]


class RuntimeInstallationTest(unittest.TestCase):
    run_id = '424242424242'
    attempt = '1'
    target = Path('/var/lib/decomp-ci-ghidra-424242424242-1')

    def setUp(self):
        self.assertFalse(self.target.exists())
        self.temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name, 'source')
        self.source.mkdir(mode=0o755)
        (self.source / 'a-marker.txt').write_text('owned inert fixture\n')
        (self.source / 'a-marker.txt').chmod(0o644)
        (self.source / 'nested').mkdir(mode=0o755)
        (self.source / 'nested' / 'mode-marker').write_text('not executed\n')
        (self.source / 'nested' / 'mode-marker').chmod(0o755)

    def invoke(self, prepare, target=None):
        args = [str(target or self.target), self.run_id, self.attempt]
        if prepare:
            args.insert(0, str(self.source))
        name = 'ci-prepare-bundled-ghidra-runtime.sh' if prepare else 'ci-release-bundled-ghidra-runtime.sh'
        return subprocess.run([sys.executable, '-', *args], input=python_body(name), text=True,
                              capture_output=True, timeout=15)

    def success(self, result):
        self.assertEqual(0, result.returncode, result.stderr)

    def test_copy_and_release_with_writable_opt(self):
        os.chmod('/opt', 0o777)
        self.success(self.invoke(True))
        self.assertEqual('owned inert fixture\n', (self.target / 'bundle/a-marker.txt').read_text())
        copied = (self.target / 'bundle/nested/mode-marker').stat()
        self.assertEqual((0, 0, 0o755, 1), (copied.st_uid, copied.st_gid, copied.st_mode & 0o777, copied.st_nlink))
        self.assertNotEqual(0, self.invoke(True).returncode)  # An existing target is never adopted.
        self.success(self.invoke(False))
        self.assertFalse(self.target.exists())
        self.success(self.invoke(False))
        self.assertEqual(0o777, Path('/opt').stat().st_mode & 0o777)

    def test_every_ancestor_still_requires_trusted_permissions(self):
        for path in ('/', '/var', '/var/lib'):
            original = Path(path).stat().st_mode & 0o777
            try:
                os.chmod(path, 0o777)
                for prepare in (True, False):
                    result = self.invoke(prepare)
                    self.assertNotEqual(0, result.returncode, path)
                    self.assertIn('ancestor is not a root-owned non-writable directory', result.stderr)
                self.assertFalse(self.target.exists())
            finally:
                os.chmod(path, original)

    def test_linked_parent_is_rejected_without_touching_owned_alternate(self):
        alternate = Path(self.temporary.name, 'alternate')
        alternate.mkdir()
        Path('/var/lib').rmdir()
        Path('/var/lib').symlink_to(alternate)
        try:
            self.assertNotEqual(0, self.invoke(True).returncode)
            self.assertNotEqual(0, self.invoke(False).returncode)
            self.assertEqual([], list(alternate.iterdir()))
        finally:
            Path('/var/lib').unlink()
            Path('/var/lib').mkdir(mode=0o755)

    def test_marker_mismatch_preserves_copy_until_expected_marker_is_restored(self):
        self.success(self.invoke(True))
        marker = self.target / '.decomp-ci-bundled-ghidra-owner-v1'
        original = marker.read_bytes()
        marker.chmod(0o600)
        marker.write_bytes(original.replace(b'run_attempt=1', b'run_attempt=2'))
        marker.chmod(0o444)
        result = self.invoke(False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('ownership marker differs', result.stderr)
        self.assertTrue((self.target / 'bundle/a-marker.txt').is_file())
        marker.chmod(0o600)
        marker.write_bytes(original)
        marker.chmod(0o444)
        self.success(self.invoke(False))

    def test_interrupted_copy_cleanup_and_exact_target_binding(self):
        invalid = self.source / 'b-invalid-mode'
        invalid.write_text('inert incomplete-copy fixture\n')
        invalid.chmod(0o600)
        self.assertNotEqual(0, self.invoke(True).returncode)
        self.assertTrue((self.target / 'bundle/a-marker.txt').exists())
        self.assertNotEqual(0, self.invoke(False, Path('/var/lib/unrelated')).returncode)
        self.assertTrue(self.target.exists())
        self.success(self.invoke(False))
        self.assertFalse(self.target.exists())


def main():
    if sys.argv[1:] == ['--inside']:
        # Reject accidental use on a host root filesystem. The driver supplies a new user namespace.
        mapping = Path('/proc/self/uid_map').read_text().split()
        if os.geteuid() != 0 or mapping != ['0', os.environ['RUNTIME_TEST_OUTER_UID'], '1']:
            raise SystemExit('requires the disposable driver user namespace')
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    elif sys.argv[1:]:
        raise SystemExit('usage: python3 scripts/test-ci-bundled-runtime.py')
    else:
        if os.geteuid() == 0:
            raise SystemExit('run the test driver as an ordinary user')
        root = Path(__file__).resolve().parent.parent
        command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--uid', '0', '--gid', '0']
        for path in ('/usr', '/lib', '/lib64'):
            if Path(path).exists():
                command += ['--ro-bind', path, path]
        command += ['--symlink', 'usr/bin', '/bin', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                    '--dir', '/var', '--dir', '/var/lib', '--dir', '/opt', '--ro-bind', str(root), '/repo',
                    '--setenv', 'RUNTIME_TEST_OUTER_UID', str(os.getuid()), '--',
                    '/usr/bin/python3', '/repo/scripts/test-ci-bundled-runtime.py', '--inside']
        raise SystemExit(subprocess.run(command, timeout=120).returncode)


if __name__ == '__main__':
    main()
