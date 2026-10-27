#!/usr/bin/python3
"""Unprivileged bootstrap refusal controls; these are not mounted qualification."""
import hashlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
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


class PackageVerificationTests(unittest.TestCase):
    def query(self, name):
        version = install.FORMATTER_VERSIONS[-1]
        source = 'e2fsprogs' if name in ('e2fsprogs', 'libext2fs2t64') else name
        return '\t'.join((name, version, source, version, 'amd64',
                          'install ok installed\n')).encode()

    def test_modified_package_refuses_before_metadata_with_exact_diagnostics(self):
        output = b'??5?????? c /etc/modified-config\n'
        for name in install.PACKAGES:
            with self.subTest(name=name), \
                    patch.object(install, 'PACKAGES', (name,)), \
                    patch.object(install, 'trusted_executable'), \
                    patch.object(install, '_run', side_effect=(self.query(name), output)) as run, \
                    self.assertRaises(install.InstallError) as refused:
                install.capture_package_provenance(None, {}, deadline=123)
            message = str(refused.exception)
            self.assertIn('reports modifications: ' + name, message)
            self.assertIn('verifyOutputSha256=' + hashlib.sha256(output).hexdigest(), message)
            self.assertIn('outputPrefix=' + repr(output), message)
            self.assertEqual(2, run.call_count)
            self.assertEqual(['/usr/bin/dpkg', '--verify', name], run.call_args.args[1])

    def test_modification_diagnostic_is_bounded_and_escapes_control_bytes(self):
        output = b'\x1b[31m\n\x00' + b'x' * (install.MAX_CAPTURE - 10) + b'END'
        with patch.object(install, 'trusted_executable'), \
                patch.object(install, '_run', side_effect=(self.query('e2fsprogs'), output)), \
                self.assertRaises(install.InstallError) as refused:
            install.capture_package_provenance(None, {}, deadline=123)
        message = str(refused.exception)
        self.assertIn(repr(output[:1024]), message)
        self.assertIn(hashlib.sha256(output).hexdigest(), message)
        self.assertNotIn('END', message)
        self.assertNotIn('\x1b', message)
        self.assertNotIn('\n', message)
        self.assertNotIn('\x00', message)
        self.assertLess(len(message), 5000)

    def test_clean_verification_still_retains_empty_output_digest(self):
        def run(core, argv, **kwargs):
            if argv[0] == '/usr/bin/dpkg-query':
                return self.query(argv[-1])
            if argv[0] == '/usr/bin/dpkg':
                return b''
            if argv[:2] == ['/usr/bin/apt-cache', 'show']:
                return apt_stanza(package(name=argv[-1].split('=')[0]))
            if argv[:2] == ['/usr/bin/apt-cache', 'policy']:
                return b'retained policy\n'
            return {('/systemctl', '--version'): b'systemd 255 (255)\n',
                    ('/python', '--version'): b'Python 3.12.3\n'}[tuple(argv)]

        with patch.object(install, 'trusted_executable'), \
                patch.object(install, '_run', side_effect=run), \
                patch.object(install.platform, 'machine', return_value='x86_64'):
            result = install.capture_package_provenance(
                None, {'systemctl': '/systemctl', 'python': '/python'}, deadline=123)
        self.assertEqual(set(install.PACKAGES), set(result['packages']))
        for value in result['packages'].values():
            self.assertEqual(hashlib.sha256(b'').hexdigest(), value['verifyOutputSha256'])


class HostPackagePreparationTests(unittest.TestCase):
    """Inert package/manager commands; never mutate the host or claim kernel proof."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=BUILD)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / 'system.conf'
        self.before = b'runner-specific manager configuration\n'
        self.distribution = b'authenticated distribution configuration\n'
        self.config.write_bytes(self.before)
        self.evidence = self.root / 'packages'
        self.calls = []
        self.initial_verify = install.KNOWN_SYSTEMD_DRIFT
        self.final_verify = b''
        self.verifications = 0
        self.query = b'systemd\t255.4-1ubuntu8.12\tsystemd\t255.4-1ubuntu8.12\tamd64\tinstall ok installed\n'
        self.package = install.parse_package_query(self.query, 'systemd')
        self.core = SimpleNamespace(run_process=self.run_command)
        for context in (
                patch.object(install.os, 'geteuid', return_value=0),
                patch.object(install.os, 'chown'), patch.object(install.os, 'fchown'),
                patch.object(install, 'require_root_ancestry'), patch.object(install, 'trusted_executable'),
                patch.object(install, '_load_core', return_value=self.core),
                patch.object(install, 'ROOT', self.root / 'slot'),
                patch.object(install, 'UNIT_FILE', self.root / 'unit'),
                patch.object(install, 'RETENTION_FILE', self.root / 'target'),
                patch.object(install, 'PACKAGE_ROOT', self.evidence),
                patch.object(install, 'SYSTEM_CONF', self.config)):
            context.start()
            self.addCleanup(context.stop)
        read = install.read_regular
        # Only the owner check is outside this unprivileged filesystem model.
        context = patch.object(install, 'read_regular', side_effect=lambda p, n, **kw: read(p, n))
        context.start()
        self.addCleanup(context.stop)

    def run_command(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertGreater(kwargs['timeout'], 0)
        self.assertLessEqual(kwargs['maximum_output'], install.MAX_CAPTURE)
        if argv[0] == '/usr/bin/dpkg-query':
            return self.query, b''
        if argv[0] == '/usr/bin/dpkg':
            self.verifications += 1
            return (self.initial_verify if self.verifications == 1 else self.final_verify), b''
        if argv[0] == '/usr/bin/apt-cache':
            return apt_stanza(self.package), b''
        if argv[0] == '/usr/bin/apt-get':
            self.assertFalse(self.config.exists())
            self.assertEqual(self.before, (self.evidence / 'system.conf.before').read_bytes())
            self.assertTrue((self.evidence / 'intent.json').is_file())
            self.config.write_bytes(self.distribution)
            return b'reinstalled exact package\n', b''
        if argv == ['/usr/bin/systemctl', 'daemon-reexec']:
            self.assertEqual(self.verifications, 2, 'manager reexec precedes clean verification')
            return b'', b''
        self.fail('unexpected command: ' + repr(argv))

    def test_known_drift_retains_original_and_reinstalls_same_authenticated_package(self):
        inode = self.config.stat().st_ino
        receipt = install.prepare_host_packages()
        self.assertTrue(receipt['restored'])
        self.assertEqual(hashlib.sha256(self.before).hexdigest(), receipt['beforeSha256'])
        self.assertEqual(hashlib.sha256(self.distribution).hexdigest(), receipt['afterSha256'])
        self.assertEqual(hashlib.sha256(b'').hexdigest(), receipt['verifyAfterSha256'])
        self.assertEqual(inode, (self.evidence / 'system.conf.before').stat().st_ino)
        self.assertEqual(0o700, stat.S_IMODE(self.evidence.stat().st_mode))
        self.assertEqual(0o400, stat.S_IMODE((self.evidence / 'intent.json').stat().st_mode))
        self.assertTrue((self.evidence / 'completed.json').is_file())
        self.assertEqual(b'reinstalled exact package\n', (self.evidence / 'apt-reinstall.stdout').read_bytes())
        apt = next(argv for argv in self.calls if argv[0] == '/usr/bin/apt-get')
        for option in ('APT::Get::AllowUnauthenticated=false', 'Acquire::AllowInsecureRepositories=false',
                       'Acquire::AllowDowngradeToInsecureRepositories=false', 'Dpkg::Options::=--force-confmiss',
                       '--reinstall', 'systemd=' + self.package['version']):
            self.assertIn(option, apt)
        self.assertNotIn('--allow-unauthenticated', apt)
        self.assertEqual(['/usr/bin/systemctl', 'daemon-reexec'], self.calls[-1])

    def test_clean_host_never_reinstalls_or_reexecutes_manager(self):
        self.initial_verify = b''
        inode = self.config.stat().st_ino
        receipt = install.prepare_host_packages()
        self.assertFalse(receipt['restored'])
        self.assertEqual(inode, self.config.stat().st_ino)
        self.assertEqual(self.before, self.config.read_bytes())
        self.assertEqual(receipt['beforeSha256'], receipt['afterSha256'])
        self.assertFalse(any(argv[0] in ('/usr/bin/apt-get', '/usr/bin/systemctl') for argv in self.calls))

    def test_unknown_or_multiple_modifications_refuse_before_any_mutation(self):
        for output in (install.KNOWN_SYSTEMD_DRIFT + b'??5?????? /usr/bin/systemctl\n',
                       b'??5?????? c /etc/systemd/other.conf\n', b'missing /etc/systemd/system.conf\n'):
            with self.subTest(output=output):
                self.initial_verify = output
                self.verifications = 0
                with self.assertRaisesRegex(install.InstallError, 'unrecognized'):
                    install.prepare_host_packages()
                self.assertFalse(self.evidence.exists())
                self.assertEqual(self.before, self.config.read_bytes())

    def test_existing_setup_or_fixture_refuses_before_package_commands(self):
        for path in (self.evidence, install.ROOT, install.UNIT_FILE, install.RETENTION_FILE):
            with self.subTest(path=path):
                path.write_bytes(b'alien or interrupted setup')
                with self.assertRaisesRegex(install.InstallError, 'preexisting'):
                    install.prepare_host_packages()
                self.assertEqual([], self.calls)
                self.assertEqual(b'alien or interrupted setup', path.read_bytes())
                path.unlink()

    def test_nonroot_refuses_without_mutation(self):
        with patch.object(install.os, 'geteuid', return_value=65534), \
                self.assertRaisesRegex(install.InstallError, 'requires root'):
            install.prepare_host_packages()
        self.assertFalse(self.evidence.exists())
        self.assertEqual([], self.calls)

    def test_unavailable_exact_archive_refuses_before_moving_configuration(self):
        run = self.core.run_process
        def command(argv, **kwargs):
            if argv[0] == '/usr/bin/apt-cache':
                return b'', b''
            return run(argv, **kwargs)
        self.core.run_process = command
        with self.assertRaises(install.InstallError):
            install.prepare_host_packages()
        self.assertFalse(self.evidence.exists())
        self.assertEqual(self.before, self.config.read_bytes())

    def test_configuration_substitution_before_rename_is_preserved_and_refused(self):
        mkdir = install.mkdir_exact
        def replace(path, mode):
            mkdir(path, mode)
            self.config.unlink()
            self.config.write_bytes(b'replacement canary')
        with patch.object(install, 'mkdir_exact', side_effect=replace), \
                self.assertRaisesRegex(install.InstallError, 'configuration changed'):
            install.prepare_host_packages()
        self.assertEqual(b'replacement canary', self.config.read_bytes())
        self.assertFalse((self.evidence / 'completed.json').exists())
        self.assertFalse(any(argv[0] == '/usr/bin/apt-get' for argv in self.calls))

    def test_failed_reinstall_keeps_original_without_claiming_completion(self):
        run = self.core.run_process
        def command(argv, **kwargs):
            if argv[0] == '/usr/bin/apt-get':
                raise RuntimeError('APT refused unavailable or unauthenticated archive')
            return run(argv, **kwargs)
        self.core.run_process = command
        with self.assertRaisesRegex(RuntimeError, 'APT refused'):
            install.prepare_host_packages()
        self.assertEqual(self.before, (self.evidence / 'system.conf.before').read_bytes())
        self.assertFalse(self.config.exists())
        self.assertFalse((self.evidence / 'completed.json').exists())
        self.assertFalse(any(argv[0] == '/usr/bin/systemctl' for argv in self.calls))

    def test_nonempty_post_verification_stays_failed_and_never_reexecutes(self):
        self.final_verify = install.KNOWN_SYSTEMD_DRIFT
        with self.assertRaisesRegex(install.InstallError, 'not clean'):
            install.prepare_host_packages()
        self.assertFalse((self.evidence / 'completed.json').exists())
        self.assertFalse(any(argv[0] == '/usr/bin/systemctl' for argv in self.calls))

    def test_failed_manager_reexec_never_records_completion(self):
        run = self.core.run_process
        def command(argv, **kwargs):
            if argv[0] == '/usr/bin/systemctl':
                raise RuntimeError('manager reexec refused')
            return run(argv, **kwargs)
        self.core.run_process = command
        with self.assertRaisesRegex(RuntimeError, 'manager reexec refused'):
            install.prepare_host_packages()
        self.assertEqual(self.before, (self.evidence / 'system.conf.before').read_bytes())
        self.assertFalse((self.evidence / 'completed.json').exists())

    def test_expired_preflight_deadline_refuses_before_commands_or_mutations(self):
        with patch.object(install.time, 'monotonic', side_effect=[0, 241]), \
                self.assertRaisesRegex(install.InstallError, 'deadline expired'):
            install.prepare_host_packages()
        self.assertFalse(self.evidence.exists())
        self.assertEqual([], self.calls)
        self.assertEqual(self.before, self.config.read_bytes())

    def test_workflow_prepares_packages_before_any_reset_slot(self):
        workflow = (SOURCE.parent.parent / '.github/workflows/ci.yml').read_text()
        prepare = 'scripts/oracle-ext4-reset-install.py prepare-host-packages'
        slot = 'scripts/ci-oracle-ext4-reset.py prepare'
        self.assertEqual(1, workflow.count(prepare))
        self.assertLess(workflow.index(prepare), workflow.index(slot))
        self.assertIn('python3 -B scripts/test-oracle-ext4-reset-install.py --verbose', workflow)
        self.assertIn('Require all 32 actual trusted ext4 reset controls', workflow)

    def test_linked_or_fifo_configuration_refuses_before_setup(self):
        self.config.unlink()
        target = self.root / 'target-config'
        target.write_bytes(self.before)
        self.config.symlink_to(target)
        with self.assertRaises(OSError):
            install.prepare_host_packages()
        self.assertFalse(self.evidence.exists())
        self.config.unlink()
        os.mkfifo(self.config)
        self.verifications = 0
        with self.assertRaises(install.InstallError):
            install.prepare_host_packages()
        self.assertFalse(self.evidence.exists())
        self.assertEqual(self.before, target.read_bytes())


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

    def test_existing_retention_target_refuses_before_source_loading(self):
        target = self.root / 'existing.target'
        target.write_bytes(b'alien target')
        with patch.object(install.os, 'geteuid', return_value=0), \
                patch.object(install, 'ROOT', self.root / 'absent-root'), \
                patch.object(install, 'UNIT_FILE', self.root / 'absent.service'), \
                patch.object(install, 'RETENTION_FILE', target), \
                patch.object(install, '_load_core') as load, \
                self.assertRaises(install.InstallError):
            install.install()
        load.assert_not_called()
        self.assertEqual(b'alien target', target.read_bytes())

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
