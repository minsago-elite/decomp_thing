#!/usr/bin/python3
"""Unprivileged bootstrap refusal controls; these are not mounted qualification."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('oracle-ext4-reset-install.py')
spec = importlib.util.spec_from_file_location('reset_install', SOURCE)
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)
BUILD = SOURCE.parent.parent / 'build/issue933-evidence/install-controls'
BUILD.mkdir(parents=True, exist_ok=True)


def package(name='e2fsprogs', version='1.47.0-2.4~exp1ubuntu4.1', source='e2fsprogs'):
    return {'binaryPackage': name, 'version': version, 'sourcePackage': source,
            'sourceVersion': version, 'architecture': 'amd64', 'status': 'install ok installed'}


def apt_stanza(value):
    return ('Package: ' + value['binaryPackage'] + '\nVersion: ' + value['version'] +
            '\nArchitecture: amd64\nSHA256: ' + 'a' * 64 +
            '\nDescription: retained archive\n continuation\n\n').encode()


class PackageIdentityTests(unittest.TestCase):
    def test_exact_reviewed_formatter_source_is_retained(self):
        raw = b'e2fsprogs\t1.47.0-2.4~exp1ubuntu4.1\te2fsprogs\t1.47.0-2.4~exp1ubuntu4.1\tamd64\tinstall ok installed\n'
        self.assertEqual(package(), install.parse_package_query(raw, 'e2fsprogs'))

    def test_library_must_share_reviewed_formatter_source(self):
        raw = b'libext2fs2t64\t1.47.0-2.4~exp1ubuntu4.1\tchanged-source\t1.47.0-2.4~exp1ubuntu4.1\tamd64\tinstall ok installed\n'
        with self.assertRaises(install.InstallError):
            install.parse_package_query(raw, 'libext2fs2t64')

    def test_unreviewed_version_and_partial_install_are_rejected(self):
        base = b'e2fsprogs\t1.47.0-2.4~exp1ubuntu4.1\te2fsprogs\t1.47.0-2.4~exp1ubuntu4.1\tamd64\tinstall ok installed\n'
        for raw in (base.replace(b'ubuntu4.1', b'ubuntu4.2'), base.replace(b'install ok installed', b'install ok unpacked'),
                    base.replace(b'amd64', b'arm64'), base + base):
            with self.subTest(raw=raw), self.assertRaises(install.InstallError):
                install.parse_package_query(raw, 'e2fsprogs')

    def test_single_archive_metadata_binds_exact_version_and_sha(self):
        raw = apt_stanza(package())
        text, archive_sha = install.parse_apt_metadata(raw, package())
        self.assertEqual(raw, text.encode())
        self.assertEqual('a' * 64, archive_sha)

    def test_duplicate_or_candidate_substituted_archive_is_rejected(self):
        raw = apt_stanza(package())
        variants = (raw + raw, raw.replace(b'ubuntu4.1', b'ubuntu4.2'),
                    raw.replace(b'SHA256: ', b'Unknown: '), raw.replace(b'Architecture: amd64', b'Architecture: arm64'),
                    raw.replace(b'Description:', b'SHA256:'))
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(install.InstallError):
                install.parse_apt_metadata(variant, package())

    def test_metadata_bounds_and_malformed_continuation_are_rejected(self):
        for raw in (b' continuation\n' + apt_stanza(package()), b'x' * (install.MAX_CAPTURE + 1),
                    apt_stanza(package()) + b'\x00', b'\xff'):
            with self.subTest(raw=raw[:20]), self.assertRaises(install.InstallError):
                install.parse_apt_metadata(raw, package())


class ClosureTests(unittest.TestCase):
    def test_root_library_aliases_are_deduplicated(self):
        raw = (b'linux-vdso.so.1 (0x00007fff)\n'
               b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x7ff)\n'
               b'/lib64/ld-linux-x86-64.so.2 (0x7aa)\n'
               b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x7ff)\n')
        self.assertEqual({Path('/lib/x86_64-linux-gnu/libc.so.6'), Path('/lib64/ld-linux-x86-64.so.2')}, install.parse_ldd(raw))

    def test_unresolved_or_untrusted_library_is_rejected(self):
        for raw in (b'libbad.so => not found\n', b'libbad.so => /tmp/hostile.so (0x123)\n',
                    b'libbad.so => /lib/../tmp/hostile.so (0x123)\n', b'statically linked\n', b''):
            with self.subTest(raw=raw), self.assertRaises(install.InstallError):
                install.parse_ldd(raw)


class FilesystemRefusalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=BUILD)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_capture_preserves_exact_bytes_and_enforces_bound(self):
        target = self.root / 'source'
        target.write_bytes(b'abc\x00def')
        self.assertEqual(b'abc\x00def', install.read_regular(target, 7))
        with self.assertRaises(install.InstallError):
            install.read_regular(target, 6)

    def test_symlink_hardlink_and_fifo_are_not_regular_capture(self):
        target = self.root / 'source'
        target.write_bytes(b'untouched')
        symlink = self.root / 'symlink'
        symlink.symlink_to(target)
        with self.assertRaises(OSError):
            install.read_regular(symlink, 32)
        hardlink = self.root / 'hardlink'
        os.link(target, hardlink)
        with self.assertRaises(install.InstallError):
            install.read_regular(hardlink, 32)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(install.InstallError):
            install.read_regular(fifo, 32)
        self.assertEqual(b'untouched', target.read_bytes())

    def test_broken_existing_link_is_not_an_absent_install_target(self):
        link = self.root / 'reserved'
        link.symlink_to(self.root / 'missing')
        with self.assertRaises(install.InstallError):
            install.absent(link)
        self.assertTrue(link.is_symlink())

    def test_nonroot_bootstrap_refuses_before_any_mutator(self):
        with patch.object(install.os, 'geteuid', return_value=65534), \
                patch.object(install, 'mkdir_exact') as mutation, \
                self.assertRaises(install.InstallError):
            install.install()
        mutation.assert_not_called()

    def test_existing_namespace_refuses_before_source_loading(self):
        with patch.object(install.os, 'geteuid', return_value=0), \
                patch.object(install, 'ROOT', self.root), \
                patch.object(install, '_load_core') as load, \
                self.assertRaises(install.InstallError):
            install.install()
        load.assert_not_called()

    def test_closed_file_names_reject_path_injection_before_open(self):
        for name in ('../state', 'nested/state', '', '.', '..'):
            with self.subTest(name=name), patch.object(install.os, 'open') as opened, \
                    self.assertRaises(install.InstallError):
                install.create_file(123, name, b'bad')
            opened.assert_not_called()

    def test_installed_capture_denies_writable_control_file(self):
        target = self.root / 'mode'
        target.write_bytes(b'sealed')
        target.chmod(0o666)
        with self.assertRaises(install.InstallError):
            install.read_regular(target, 32, trusted=True)


if __name__ == '__main__':
    unittest.main()
