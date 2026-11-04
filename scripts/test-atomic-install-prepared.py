#!/usr/bin/env python3
"""Bounded Python-only ordering, failure diagnostics and inventory controls."""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('prepared_driver_controls', ROOT / 'scripts/test-atomic-install.py')
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
prep = driver.prepared
BASE = ROOT / 'build/orchestration/atomic-install-prepared-replay-remediation/tmp'
BASE.mkdir(parents=True, exist_ok=True)


class PreparedControls(unittest.TestCase):
    def exercise(self, fault=None):
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            work = pathlib.Path(directory)
            events = []
            state = {}
            child = mock.Mock()
            child.process.poll.return_value = None
            child.probe = {}
            record = {'commands': [], 'probes': [child.probe], 'phase': 'initial A and no-update'}
            original_write = prep.write_json
            original_snapshot = prep.protected
            def write(path, value, **kwargs):
                events.append(path.name)
                if fault == 'diagnostic-write' and path.name == 'protected-after.json':
                    raise OSError('diagnostic disk failure')
                return original_write(path, value, **kwargs)
            def install(generation, *, replay=False):
                self.assertEqual('A', generation)
                events.append('replay' if replay else 'prepare')
                if not replay:
                    lib = work / 'root-build/install/llm_bin_patch/lib'; lib.mkdir(parents=True)
                    for name in ('app.jar', *prep.REFERENCES.values()): (lib / name).write_bytes(b'prepared')
                    bin_dir = lib.parent / 'bin'; bin_dir.mkdir()
                    for name in ('llm_bin_patch', 'llm_bin_patch.bat'): (bin_dir / name).write_bytes(b'launcher')
                    source = work / 'root-build/input'; source.write_bytes(b'prepared')
                    state.update(source=source, jar=lib / 'app.jar')
                else:
                    self.assertIn('READY', events)
                    if fault in ('command', 'diagnostic-write'): raise RuntimeError('primary command failed')
                    if fault == 'guard':
                        state['source'].write_bytes(b'changed')
                        prep.check_prepared(state['manifest'], {})
                    if fault == 'installed-mutation': state['jar'].write_bytes(b'changed')
                    if fault == 'overflow': state['source'].write_bytes(b'x' * 33)
                    if fault == 'dead-jvm': child.process.poll.return_value = 7
            def seal():
                events.append('seal')
                value = {'roots': [str(state['source'])], 'inventory': prep.inventory([str(state['source'])]), 'plan': {}}
                original_write(work / 'prepared-A.json', value, immutable=True)
                state['manifest'] = value
                return value
            def launch(generation):
                events.append('READY')
                original_write(work / 'prepared-guard.json', {})
                return child, work / 'RELEASE', {'descriptorDigest': driver.digest(state['jar'])}, state['jar']
            def release(held, path, generation, expected):
                self.assertIs(held, child); self.assertEqual(expected, 'unchanged')
                for prefix in ('protected', 'prepared-input'):
                    for suffix in ('before', 'after', 'diff'):
                        self.assertTrue((work / f'{prefix}-{suffix}.json').is_file())
                events.append('RELEASE')
                if fault == 'cleanup': raise RuntimeError('cleanup failed')
                return {'descriptorDigest': driver.digest(state['jar']), 'installedPathDigestAfterRelease': driver.digest(state['jar'])}
            def snapshot(root, run):
                if fault == 'read' and 'replay' in events:
                    return {'status': 'failed', 'error': 'injected read error', 'entries': {}}
                return original_snapshot(root, run)
            with mock.patch.object(driver, 'WORK', work), mock.patch.object(driver, 'RECORD', record), \
                    mock.patch.object(driver, 'install', side_effect=install), mock.patch.object(driver, 'seal_preparation', side_effect=seal), \
                    mock.patch.object(driver, 'launch_blocked', side_effect=launch), mock.patch.object(driver, 'release_and_reap', side_effect=release), \
                    mock.patch.object(driver, 'validate_replay_receipt', side_effect=lambda m: events.append('publisher-checked')), \
                    mock.patch.object(prep, 'check_sources'), mock.patch.object(prep, 'write_json', side_effect=write), \
                    mock.patch.object(prep, 'protected', side_effect=snapshot), mock.patch.object(prep, 'MAX_FILE', 32):
                if fault:
                    with self.assertRaises((RuntimeError, OSError)) as failure:
                        driver.live_no_update()
                    if fault == 'diagnostic-write': self.assertIn('primary command failed', str(failure.exception))
                else:
                    self.assertEqual(driver.live_no_update()['status'], 'passed')
            for name in ('protected-before', 'protected-diff', 'prepared-input-before', 'prepared-input-after', 'prepared-input-diff'):
                if fault != 'diagnostic-write' or name != 'protected-diff':
                    self.assertTrue((work / (name + '.json')).exists(), name)
            if fault != 'diagnostic-write': self.assertTrue((work / 'protected-after.json').exists())
            if fault in ('command', 'guard', 'installed-mutation', 'overflow', 'read', 'dead-jvm', 'diagnostic-write'):
                self.assertNotIn('RELEASE', events)
            if fault is None:
                ordered = ('prepare', 'seal', 'protected-before.json', 'READY', 'replay', 'protected-after.json',
                           'protected-diff.json', 'prepared-input-after.json', 'prepared-input-diff.json', 'publisher-checked', 'RELEASE')
                self.assertEqual(sorted(events.index(e) for e in ordered), [events.index(e) for e in ordered])
            if fault in ('installed-mutation', 'guard', 'overflow', 'read'):
                prefix = 'prepared-input' if fault in ('guard', 'overflow') else 'protected'
                self.assertNotEqual(prep.EMPTY_DIFF, prep.read_json(work / (prefix + '-diff.json')))

    def test_ordered_live_replay(self): self.exercise()
    def test_command_failure_diagnostics(self): self.exercise('command')
    def test_guard_failure_diagnostics(self): self.exercise('guard')
    def test_installed_mutation_diagnostics(self): self.exercise('installed-mutation')
    def test_overflow_diagnostics(self): self.exercise('overflow')
    def test_read_failure_diagnostics(self): self.exercise('read')
    def test_cleanup_failure_diagnostics(self): self.exercise('cleanup')
    def test_dead_jvm_rejected(self): self.exercise('dead-jvm')
    def test_primary_survives_diagnostic_failure(self): self.exercise('diagnostic-write')

    def test_primary_and_cleanup_failures_wait_run_release(self):
        import subprocess
        for lane in ('wait', 'run', 'release'):
            for failed in (True, False):
                with self.subTest(lane=lane, primary=failed), tempfile.TemporaryDirectory(dir=BASE) as directory:
                    work = pathlib.Path(directory)
                    record = {'commands': [], 'phase': 'inert'}
                    primary = subprocess.TimeoutExpired(['inert'], 1)
                    child = object.__new__(driver.Child)
                    child.process = mock.Mock(); child.reader = mock.Mock()
                    child.reader.is_alive.return_value = False
                    child.error = None; child.kill_group = mock.Mock()
                    child.close = mock.Mock(side_effect=RuntimeError('secondary cleanup failed'))
                    child.log = work / 'inert.log'; child.log.write_bytes(b'inert')
                    child.probe = {}; child.text = lambda: 'inert'
                    if lane == 'wait':
                        child.process.wait.side_effect = primary if failed else None
                        child.process.wait.return_value = 0
                        action = lambda: child.wait(1)
                    else:
                        child.wait = mock.Mock(side_effect=primary if failed else None, return_value=0)
                        if lane == 'run': action = lambda: driver.run(['inert'])
                        else:
                            (work / 'READY.loaded').write_text(json.dumps({'lateResourceMarker': 'A', 'schemaVersion': '4',
                                'inputSha256': 'a'*64, 'modelLoader': 'same', 'transformLoader': 'same',
                                'modelOrigin': 'same', 'transformOrigin': 'same'}))
                            action = lambda: driver.release_and_reap(child, work / 'RELEASE', 'A')
                    with mock.patch.object(driver, 'WORK', work), mock.patch.object(driver, 'RECORD', record), \
                            mock.patch.object(driver, 'Child', return_value=child) if lane == 'run' else mock.patch.object(driver, 'AGENT', driver.AGENT), \
                            mock.patch.object(driver, 'save_record'):
                        with self.assertRaises(BaseException) as caught: action()
                    if failed: self.assertIs(caught.exception, primary)
                    else: self.assertIn('secondary cleanup failed', str(caught.exception))
                    self.assertEqual(record['status'], 'failed')
                    self.assertIn('secondary cleanup failed', record['cleanupFailures'][0])
                    detail = record['commands'][0] if lane == 'run' else child.probe
                    if lane != 'wait':
                        self.assertEqual(detail['status'], 'failed')
                        self.assertIn('TimeoutExpired' if failed else 'secondary cleanup failed', detail['failure'])
                        self.assertIn('secondary cleanup failed', detail['cleanupFailures'][0])
                        self.assertIn('cleanupFailures', json.dumps(record))

    def test_retention_independently_rejects_missing_descendant(self):
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            root = pathlib.Path(directory); source = root / 'classes'; source.mkdir()
            member = source / 'producer.class'; member.write_bytes(b'inert class')
            manifest = {'roots': [str(source)], 'inventory': prep.inventory([str(source)])}
            manifest['inventory']['entries'].pop(str(member))
            with self.assertRaisesRegex(RuntimeError, 'recursive closure differs'):
                prep.retain_inputs(manifest, root)
            self.assertFalse((root / 'prepared-products').exists())

    def test_inventory_bounds_and_symlinks(self):
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            root = pathlib.Path(directory)
            data = root / 'data'; data.write_bytes(b'12345678')
            self.assertEqual('passed', prep.inventory([str(data)])['status'])
            self.assertEqual('failed', prep.inventory([str(data)], max_bytes=7)['status'])
            self.assertEqual('failed', prep.inventory([str(root)], max_entries=1)['status'])
            (root / 'link').symlink_to(data)
            self.assertEqual('failed', prep.inventory([str(root)])['status'])
            (root / 'link').unlink(); os.mkfifo(root / 'fifo')
            self.assertEqual('failed', prep.inventory([str(root)])['status'])
            (root / 'fifo').unlink()
            link = root / 'dir-link'; link.symlink_to(root, target_is_directory=True)
            self.assertEqual('failed', prep.inventory([str(link / 'data')])['status'])
            with mock.patch.object(prep, 'MAX_FILE', 4):
                self.assertEqual('failed', prep.inventory([str(data)])['status'])

    def test_current_input_membership_and_identity(self):
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            root = pathlib.Path(directory); source = root / 'source'; source.mkdir()
            data = source / 'data'; data.write_bytes(b'original')
            manifest = {'roots': [str(source)], 'inventory': prep.inventory([str(source)]), 'plan': {}}
            with mock.patch.object(prep, 'check_sources'):
                prep.check_prepared(manifest, {})
                extra = source / 'extra'; extra.write_bytes(b'extra')
                with self.assertRaises(RuntimeError): prep.check_prepared(manifest, {})
                extra.unlink()
                data.chmod(0o600)
                with self.assertRaises(RuntimeError): prep.check_prepared(manifest, {})
                data.chmod(0o644)
                replacement = root / 'replacement'; replacement.write_bytes(b'original'); replacement.replace(data)
                with self.assertRaises(RuntimeError): prep.check_prepared(manifest, {})
                data.unlink()
                with self.assertRaises(RuntimeError): prep.check_prepared(manifest, {})

    def test_fresh_frontend_equality_retains_input_identity(self):
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            root = pathlib.Path(directory)
            for name in ('fresh', 'prepared'):
                folder = root / name; (folder / 'dist').mkdir(parents=True)
                for child in ('dist/app.js', 'bundle-report.json', 'bundle-composition.json'):
                    (folder / child).write_bytes(b'equal')
            before = prep.inventory([str(root / 'prepared')])
            prep.frontend_compare(root / 'fresh', root / 'prepared')
            self.assertEqual(before, prep.inventory([str(root / 'prepared')]))
            (root / 'fresh/dist/app.js').write_bytes(b'changed')
            with self.assertRaises(RuntimeError): prep.frontend_compare(root / 'fresh', root / 'prepared')

    def test_replay_command_only_exclusions_immutable_init(self):
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            work = pathlib.Path(directory)
            with mock.patch.object(driver, 'WORK', work), mock.patch.object(driver, 'RECORD', {'commands': [None, None]}), \
                    mock.patch.object(driver, 'gradle', return_value=(0, '')) as run:
                driver.install('A', replay=True)
                self.assertEqual(run.call_args.args, ('-I', work / 'command-02.init.gradle', 'installDist', *prep.EXCLUSIONS))
                text = driver.INIT.read_text()
                self.assertEqual(text.count('outputs.upToDateWhen { false }'), 2)  # existing fresh frontend + only installDist
                self.assertNotIn('--rerun-tasks', text)
                self.assertNotIn('enabled = false', text)
                self.assertIn("'guard'", text)
                self.assertIn('atomicInstallTestEvent', text)
                with self.assertRaises(FileExistsError): driver.write_init('B', command_id=2)


class ArtifactControls(unittest.TestCase):
    def test_static_membership_with_exact_proposed_exclusion(self):
        spec = importlib.util.spec_from_file_location('atomic_artifact_controls', ROOT / 'scripts/atomic_install_artifacts.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        paths = module.rules(ROOT)
        exclusion = '!build/orchestration/atomic-install-remediation/installed-*/prepared-products/**'
        result = module.membership_controls([*paths, exclusion])
        self.assertGreater(result['retained'], 50)
        if exclusion not in paths:
            with self.assertRaisesRegex(RuntimeError, 'includes products'):
                module.membership_controls(paths)

    def test_downloaded_membership_and_hashes(self):
        import zipfile
        spec = importlib.util.spec_from_file_location('atomic_artifact_roundtrip', ROOT / 'scripts/atomic_install_artifacts.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            root = pathlib.Path(directory)
            patterns = [*module.rules(ROOT), '!build/orchestration/atomic-install-remediation/installed-*/prepared-products/**']
            evidence = root / 'build/orchestration/atomic-install-ci'; evidence.mkdir(parents=True)
            (evidence / 'verification.json').write_text('{"status":"fixture"}')
            with mock.patch.object(module, 'rules', return_value=patterns):
                seal = module.seal(root)
            def make(extra=False, changed=False, missing=False, kind=None):
                archive = root / 'download.zip'
                with zipfile.ZipFile(archive, 'w') as output:
                    for path in (root / 'build').rglob('*'):
                        if path.is_file():
                            if missing and path.name == 'verification.json': continue
                            name = path.relative_to(root / 'build').as_posix()
                            if kind == 'nul-file' and path.name == 'verification.json': name += 'X'
                            if kind == 'file-directory-type' and path.name == 'verification.json':
                                info = zipfile.ZipInfo(name); info.external_attr = 0o040755 << 16
                                output.writestr(info, path.read_bytes())
                            else:
                                output.writestr(name, b'changed' if changed and path.name == 'verification.json' else path.read_bytes())
                    if extra: output.writestr('extra', b'extra')
                    if kind == 'nul-directory': output.writestr('orchestration/X', b'')
                    if kind == 'canonical-parents':
                        output.writestr('orchestration/', b'')
                        output.writestr('orchestration/atomic-install-ci/', b'')
                    elif kind == 'duplicate-parent':
                        output.writestr('orchestration/', b''); output.writestr('orchestration/', b'')
                    elif kind == 'compressed-parent': output.writestr('orchestration/', b'', compress_type=zipfile.ZIP_DEFLATED)
                    elif kind == 'duplicate-file': output.writestr(module.MANIFEST, b'{}')
                    elif kind in ('extra-directory', 'payload-directory', 'parent-payload', 'directory-file-type', 'noncanonical', 'traversal', 'backslash', 'symlink'):
                        name = {'extra-directory': 'unexpected/', 'payload-directory': 'unexpected/', 'parent-payload': 'orchestration/',
                                'directory-file-type': 'orchestration/', 'noncanonical': 'orchestration//', 'traversal': 'orchestration/../',
                                'backslash': 'orchestration\\/', 'symlink': 'orchestration/'}[kind]
                        info = zipfile.ZipInfo(name)
                        info.external_attr = (0o100644 if kind == 'directory-file-type' else 0o120777 if kind == 'symlink' else 0o040755) << 16
                        output.writestr(info, b'hidden bytes' if kind in ('payload-directory', 'parent-payload') else b'')
                if kind in ('nul-file', 'nul-directory'):
                    marker = b'verification.jsonX' if kind == 'nul-file' else b'orchestration/X'
                    raw = archive.read_bytes()
                    self.assertEqual(2, raw.count(marker))  # local and central names
                    archive.write_bytes(raw.replace(marker, marker[:-1] + b'\0'))
                return archive
            self.assertEqual(module.verify(make(), seal['sha256'])['status'], 'passed')
            for args in ({'extra': True}, {'changed': True}, {'missing': True}):
                with self.assertRaises(RuntimeError): module.verify(make(**args), seal['sha256'])
            with self.assertRaises(RuntimeError): module.verify(make(), '0' * 64)
            self.assertEqual(module.verify(make(kind='canonical-parents'), seal['sha256'])['status'], 'passed')
            for kind in ('extra-directory', 'payload-directory', 'parent-payload', 'duplicate-parent', 'duplicate-file',
                         'file-directory-type', 'directory-file-type', 'noncanonical', 'traversal', 'backslash', 'symlink', 'compressed-parent', 'nul-file', 'nul-directory'):
                with self.subTest(kind=kind), self.assertRaises(RuntimeError): module.verify(make(kind=kind), seal['sha256'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
