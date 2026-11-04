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
        parent = Path('build/orchestration/ghidra-invocation-remediation/python-fixtures')
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
        self.old_current = w.current
        w.current = lambda: dict(head='a' * 40, dirty=[' M src/main/kotlin/Adapter.kt'],
                                 sources={str(p.relative_to(w.ROOT)): w.digest(p) for p in sorted((w.ROOT / 'src').rglob('*')) if p.is_file()})
        w.publish(w.PIN, dict(schemaVersion=1, pinnedAtNanos=time.time_ns() - 1000000, **w.current()))
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
