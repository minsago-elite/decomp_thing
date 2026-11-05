"""Pure fixtures only: no build, JVM, worker, compiler or installed application execution."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import shutil
import time
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('witness', Path(__file__).with_name('ghidra_invocation_provenance.py'))
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class BuildProvenanceControls(unittest.TestCase):
    def setUp(self):
        parent = Path('build/orchestration/ghidra-invocation-046-diagnostics/python-fixtures')
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=parent)
        w.ROOT = Path(self.temp.name).resolve()
        w.OUT = w.ROOT / 'build/orchestration'
        w.PIN = w.OUT / 'pin.json'
        w.SEALED = w.OUT / 'seal.json'
        self.source = w.ROOT / 'src/main/kotlin/Adapter.kt'
        self.source.parent.mkdir(parents=True)
        self.source.write_text('authored-source')
        self.exporters = {}
        for name in ('ExportProgramModelOwned.java', 'ExportProgramModel.java'):
            path = w.ROOT / 'src/main/resources/ghidra_scripts' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('authored-exporter-' + name)
            self.exporters['ghidra_scripts/' + name] = path.read_bytes()
        for name in set(w.HELPER_SOURCES.values()):
            path = w.ROOT / 'src/test/kotlin/decompengine/project' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('authored-helper-source-' + name)
        self.old_current = w.current
        w.current = lambda: dict(head='a' * 40, dirty=[' M src/main/kotlin/Adapter.kt'],
                                 sources={str(p.relative_to(w.ROOT)): w.digest(p) for p in sorted((w.ROOT / 'src').rglob('*')) if p.is_file()})
        w.publish(w.PIN, dict(schemaVersion=1, pinnedAtNanos=time.time_ns() - 1000000, **w.current()))
        self.helpers = w.ROOT / w.HELPER_DIRECTORIES[0]
        for name in w.HELPER_ROOTS:
            self.write_helper(name, [name + '$Nested'])
            self.write_helper(name + '$Nested')
        self.entries = dict(self.exporters)
        for name in ('analysis/GhidraJvmAnalyzer', 'analysis/PreparedGhidraCommand', 'analysis/GhidraInvocationReceipt',
                     'analysis/BundledGhidra', 'project/GhidraHeadlessProgramModelAnalyzer'):
            relative = 'decompengine/' + name + '.class'
            path = w.ROOT / 'build/classes/kotlin/main' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('controlled-not-class-bytes-' + name).encode())
            self.entries[relative] = path.read_bytes()
        self.app = w.ROOT / 'build/install/llm_bin_patch/lib/application.jar'
        self.write_zip(self.app, self.entries)
        relative = 'decompengine/ghidra/BundledGhidraWorker.class'
        path = w.ROOT / 'ghidra-bridge/build/classes/java/main' / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'controlled-bridge-not-class-bytes')
        self.bridge = w.ROOT / 'build/install/llm_bin_patch/libexec/ghidra/decomp-ghidra-bridge.jar'
        self.write_zip(self.bridge, {relative: path.read_bytes()})
        self.bridge.with_name('bundle.sha256').write_text('controlled-manifest')

    def tearDown(self):
        w.current = self.old_current
        self.temp.cleanup()

    def write_zip(self, path, entries):
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in entries.items():
                archive.writestr(name, data)

    def write_helper(self, name, references=()):
        import struct
        def u2(value): return struct.pack('>H', value)
        def utf(value):
            data = value.encode('ascii')
            return b'\x01' + u2(len(data)) + data
        pool = [utf(w.HELPER_PACKAGE + name), b'\x07' + u2(1), utf('SourceFile'),
                utf(w.HELPER_SOURCES[name.split('$')[0]])]
        for ref in references:
            pool.append(utf(w.HELPER_PACKAGE + ref))
            pool.append(b'\x07' + u2(len(pool)))
        content = (b'\xca\xfe\xba\xbe' + u2(0) + u2(65) + u2(len(pool) + 1) + b''.join(pool)
                   + u2(0) + u2(2) + u2(0) + u2(0) + u2(0) + u2(0)
                   + u2(1) + u2(3) + struct.pack('>I', 2) + u2(4))
        path = self.helpers / (w.HELPER_PACKAGE + name + '.class')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_helpers_bind_sources_directory_and_complete_nested_closure(self):
        w.seal(); w.verify()
        helpers = w.read(w.SEALED)['testHelpers']
        self.assertEqual(helpers['directory'], w.HELPER_DIRECTORIES[0])
        self.assertEqual(len(helpers['classes']), 6)
        self.assertEqual(len(helpers['sources']), 2)
        self.assertEqual(len(helpers['closureSha256']), 64)

    def test_added_unsealed_dependency_without_helpers_refuses_verification(self):
        w.seal()
        self.write_zip(self.app.with_name('000-unsealed.jar'), {'authored.txt': b'not executable'})
        with self.assertRaises(ValueError): w.verify()

    def test_removed_sealed_dependency_refuses_verification(self):
        extra = self.app.with_name('dependency.jar')
        self.write_zip(extra, {'authored.txt': b'not executable'})
        w.seal(); w.verify()
        extra.unlink()
        with self.assertRaises(ValueError): w.verify()

    def test_renamed_sealed_dependency_refuses_verification(self):
        extra = self.app.with_name('dependency.jar')
        self.write_zip(extra, {'authored.txt': b'not executable'})
        w.seal(); w.verify()
        extra.rename(extra.with_name('renamed.jar'))
        with self.assertRaises(ValueError): w.verify()

    def test_dependency_present_before_seal_is_bound(self):
        extra = self.app.with_name('dependency.jar')
        self.write_zip(extra, {'authored.txt': b'not executable'})
        w.seal(); w.verify()
        self.assertEqual(w.read(w.SEALED)['artifacts'][extra.relative_to(w.ROOT).as_posix()], w.digest(extra))

    def test_missing_nested_helper_refuses_seal(self):
        next(self.helpers.rglob('*$Nested.class')).unlink()
        with self.assertRaises(ValueError): w.seal()

    def test_stale_helper_refuses_seal(self):
        path = next(self.helpers.rglob('*.class'))
        os.utime(path, ns=(1, 1))
        with self.assertRaises(ValueError): w.seal()

    def test_extra_unreachable_helper_refuses_seal(self):
        self.write_helper('InvocationQualification$Extra')
        with self.assertRaises(ValueError): w.seal()

    def test_wrong_helper_source_binding_refuses_seal(self):
        path = next(self.helpers.rglob('InvocationQualification.class'))
        path.write_bytes(path.read_bytes().replace(b'GhidraInvocationQualificationSupport.kt', b'XhidraInvocationQualificationSupport.kt'))
        with self.assertRaises(ValueError): w.seal()

    def test_changed_missing_extra_helper_after_seal_refuses(self):
        w.seal()
        path = next(self.helpers.rglob('*$Nested.class')); original = path.read_bytes()
        path.unlink()
        with self.assertRaises(ValueError): w.verify()
        path.write_bytes(original + b'changed')
        with self.assertRaises(ValueError): w.verify()
        path.write_bytes(original)
        extra = self.write_helper('InvocationQualification$Extra')
        with self.assertRaises(ValueError): w.verify()
        extra.unlink(); w.verify()

    def test_wrong_defining_directory_after_seal_refuses(self):
        w.seal()
        other = w.ROOT / w.HELPER_DIRECTORIES[1]
        other.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(self.helpers, other)
        with self.assertRaises(ValueError): w.verify()

    def test_duplicate_helper_directory_refuses(self):
        other = w.ROOT / w.HELPER_DIRECTORIES[1]
        shutil.copytree(self.helpers, other)
        with self.assertRaises(ValueError): w.seal()

    def test_duplicate_installed_defining_location_refuses(self):
        path = next(self.helpers.rglob('*.class'))
        self.entries[path.relative_to(self.helpers).as_posix()] = path.read_bytes()
        self.write_zip(self.app, self.entries)
        with self.assertRaises(ValueError): w.seal()

    def test_duplicate_after_seal_and_symlink_helper_refuse(self):
        w.seal()
        self.write_zip(self.app.with_name('extra.jar'), {w.HELPER_PACKAGE + 'InvocationQualification.class': b'duplicate'})
        with self.assertRaises(ValueError): w.verify()
        self.app.with_name('extra.jar').unlink()
        path = next(self.helpers.rglob('*.class')); data = path.read_bytes()
        target = w.ROOT / 'saved.class'; target.write_bytes(data)
        path.unlink(); path.symlink_to(target)
        with self.assertRaises(ValueError): w.verify()

    def test_matching_fixture(self):
        w.seal()
        w.verify()
        self.assertEqual(w.SEALED.stat().st_mode & 0o777, 0o600)

    def split_scripts(self):
        scripts = []
        for name in ('RunBundledExports.class', 'ExportNativeCallsV1.class', 'ExportNativeCallsV1$Control.class'):
            compiled = w.ROOT / 'ghidra-bridge/build/classes/java/main' / name
            compiled.write_bytes(('controlled-script-' + name).encode())
            installed = self.bridge.parent / 'scripts' / name
            installed.parent.mkdir(exist_ok=True)
            installed.write_bytes(compiled.read_bytes())
            scripts.append(installed)
        return scripts

    def test_split_script_layout_is_sealed_and_verified(self):
        scripts = self.split_scripts()
        w.seal()
        w.verify()
        artifacts = w.read(w.SEALED)['artifacts']
        for script in scripts:
            self.assertEqual(w.digest(script), artifacts[script.relative_to(w.ROOT).as_posix()])

    def test_missing_split_script_rejects(self):
        self.split_scripts()[0].unlink()
        with self.assertRaises(ValueError): w.seal()

    def test_changed_split_script_rejects(self):
        self.split_scripts()[1].write_bytes(b'wrong-script')
        with self.assertRaises(ValueError): w.seal()

    def test_changed_split_script_after_seal_rejects(self):
        script = self.split_scripts()[2]
        w.seal()
        script.write_bytes(b'changed-after-seal')
        with self.assertRaises(ValueError): w.verify()

    def test_symlink_split_script_rejects(self):
        script = self.split_scripts()[0]
        script.unlink()
        script.symlink_to(w.ROOT / 'ghidra-bridge/build/classes/java/main' / script.name)
        with self.assertRaises(ValueError): w.seal()

    def test_packaged_class_with_script_like_name_still_requires_bridge_entry(self):
        relative = 'other/ExportNativeCallsV1.class'
        compiled = w.ROOT / 'ghidra-bridge/build/classes/java/main' / relative
        compiled.parent.mkdir(parents=True)
        compiled.write_bytes(b'ordinary-packaged-class')
        with self.assertRaises((KeyError, ValueError)): w.seal()
        with zipfile.ZipFile(self.bridge) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries[relative] = compiled.read_bytes()
        self.write_zip(self.bridge, entries)
        w.seal()
        w.verify()

    def test_stale_application(self):
        self.entries['decompengine/analysis/GhidraJvmAnalyzer.class'] = b'stale'
        self.write_zip(self.app, self.entries)
        with self.assertRaises(ValueError): w.seal()

    def test_stale_resource(self):
        self.entries['ghidra_scripts/ExportProgramModelOwned.java'] = b'stale'
        self.write_zip(self.app, self.entries)
        with self.assertRaises(ValueError): w.seal()

    def test_stale_bridge(self):
        self.write_zip(self.bridge, {'decompengine/ghidra/BundledGhidraWorker.class': b'stale'})
        with self.assertRaises(ValueError): w.seal()

    def test_source_changed_after_pin(self):
        self.source.write_text('changed')
        with self.assertRaises(ValueError): w.seal()

    def test_absent_manifest(self):
        self.bridge.with_name('bundle.sha256').unlink()
        with self.assertRaises(ValueError): w.seal()

    def test_absent_build_proof(self):
        with self.assertRaises(FileNotFoundError): w.verify()

    def test_changed_installed_artifact_after_seal(self):
        w.seal()
        self.app.write_bytes(b'changed-after-seal')
        with self.assertRaises(ValueError): w.verify()

    def test_old_compiler_output(self):
        compiled = next((w.ROOT / 'build/classes/kotlin/main').rglob('*.class'))
        os.utime(compiled, ns=(1, 1))
        with self.assertRaises(ValueError): w.seal()

    def upload_fixture(self):
        source = w.ROOT / 'qualified'
        source.mkdir()
        (source / 'retained-invocation.json').write_text('{"schemaVersion":2}')
        (source / 'observed-worker.json').write_text('{"runId":"run-authored"}')
        (source / 'compiler.json').write_text('{"exitCode":0}')
        evidence = {p.name: w.digest(p) for p in source.iterdir()}
        (source / 'provenance.json').write_text(json.dumps(dict(schemaVersion=1, runId='run-authored', evidence=evidence)))
        copied = w.ROOT / 'downloaded'
        shutil.copytree(source, copied)
        return source, copied

    def diagnostics_fixture(self):
        source = w.ROOT / 'failed'; run = source / 'run-authored'; run.mkdir(parents=True)
        (run / 'observer-failure.json').write_text('{"kind":"observer_failure"}')
        (run / 'observer-followup.json').write_text('{"kind":"observer_followup"}')
        (run / 'observer-cleanup.json').write_text('{"kind":"observer_cleanup"}')
        (run / 'build-provenance.json').write_text('{"sources":{}}')
        copied = w.ROOT / 'failed-download'; shutil.copytree(source, copied)
        return source, copied

    def test_failure_download_verified_without_invented_success(self):
        source, copied = self.diagnostics_fixture()
        w.verify_uploaded_diagnostics(source, copied)
        self.assertFalse((copied / 'provenance.json').exists())
        self.assertFalse((copied / 'run-authored/provenance.json').exists())

    def test_changed_followup_diagnostic_refuses_download_verification(self):
        source, copied = self.diagnostics_fixture()
        (copied / 'run-authored/observer-followup.json').write_text('{}')
        with self.assertRaises(ValueError): w.verify_uploaded_diagnostics(source, copied)

    def test_diagnostic_download_missing_changed_extra_symlink_overflow_refuse(self):
        source, copied = self.diagnostics_fixture()
        target = copied / 'run-authored/observer-failure.json'
        original = target.read_bytes()
        for change in ('missing', 'changed', 'symlink', 'overflow'):
            target.unlink()
            if change == 'changed': target.write_bytes(b'changed')
            elif change == 'symlink': target.symlink_to(source / 'run-authored/observer-failure.json')
            elif change == 'overflow': target.write_bytes(b'x' * 4097)
            with self.assertRaises(ValueError): w.verify_uploaded_diagnostics(source, copied)
            target.unlink(missing_ok=True); target.write_bytes(original)
        extra = copied / 'run-authored/child-failure.json'; extra.write_text('{}')
        with self.assertRaises(ValueError): w.verify_uploaded_diagnostics(source, copied)
        extra.unlink()
        witness = copied / 'run-authored/build-provenance.json'; witness.write_bytes(b'x' * (w.LIMIT + 1))
        with self.assertRaises(ValueError): w.verify_uploaded_diagnostics(source, copied)

    def test_uploaded_four_file_set_matches(self):
        source, copied = self.upload_fixture()
        w.verify_uploaded(source, copied)

    def test_uploaded_missing_changed_or_symlinked_file_rejects(self):
        source, copied = self.upload_fixture()
        for name in ('retained-invocation.json', 'observed-worker.json', 'compiler.json', 'provenance.json'):
            path = copied / name
            path.unlink()
            with self.assertRaises(ValueError): w.verify_uploaded(source, copied)
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError): w.verify_uploaded(source, copied)
            path.unlink()
            path.symlink_to(source / name)
            with self.assertRaises(ValueError): w.verify_uploaded(source, copied)
            path.unlink()
            shutil.copyfile(source / name, path)

    def test_uploaded_oversize_is_rejected_before_reading(self):
        source, copied = self.upload_fixture()
        for directory in (source, copied):
            with (directory / 'compiler.json').open('wb') as stream: stream.truncate(w.LIMIT + 1)
        with self.assertRaises(ValueError): w.verify_uploaded(source, copied)

    def test_identical_upload_with_bad_manifest_or_run_correlation_rejects(self):
        source, copied = self.upload_fixture()
        original = json.loads((source / 'provenance.json').read_text())
        wrong_digest = dict(original, evidence=dict(original['evidence'], **{'compiler.json': '0' * 64}))
        wrong_run = dict(original, runId='different-run')
        for broken in (wrong_digest, wrong_run, dict(original, evidence={})):
            for directory in (source, copied):
                (directory / 'provenance.json').write_text(json.dumps(broken))
            with self.assertRaises(ValueError): w.verify_uploaded(source, copied)


if __name__ == '__main__':
    unittest.main()
