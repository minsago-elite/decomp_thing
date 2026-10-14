"""Inert receipt-checker controls; no JVM, native helper, model or authentication calls."""
from pathlib import Path
import base64
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('dns_gate', REPO / 'scripts/verify-acp-provider-dns.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class CheckerTest(unittest.TestCase):
    def setUp(self):
        base = REPO / 'build/provider-dns-checker-tests'
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.temp.name)
        self.run = 'inert-checker-run'
        def write(name, data, executable=False):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if executable:
                path.chmod(0o755)
            return path
        self.write = write
        source = write('src/test/provider-dns/native/provider_dns_loopback_fixture.c', b'fixed helper source')
        test = write('src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt', b'fixed test source')
        helper = write('build/provider-dns/native/provider-dns-loopback-fixture', b'\x7fELFfixed inert helper', True)
        worker = self.root / 'build/provider-dns/decomp-acp-provider-dns.jar'
        worker.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(worker, 'w') as archive:
            archive.writestr('decompengine/acp/ProviderDnsWorker.class', b'fixed inert bytecode')
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        java = write('runtime/jdk/bin/java', b'inert Java', True)
        release = write('runtime/jdk/release', b'inert release')
        modules = write('runtime/jdk/lib/modules', b'inert modules')
        tools = {name: write('runtime/' + name, ('inert ' + name).encode(), True)
                 for name in ['bwrap', 'env', 'compiler', 'linker']}
        self.runtime = {'javaHome': java.parent.parent, **tools}
        argv = [str(tools['compiler']), *gate.FLAGS, str(source), '-o', str(helper)]
        argv_bytes = '\0'.join(argv).encode()
        metadata = {'schema': '1', 'sourceSha256': digest(source), 'compilerPath': str(tools['compiler']),
                    'compilerSha256': digest(tools['compiler']), 'linkerPath': str(tools['linker']),
                    'linkerSha256': digest(tools['linker']), 'helperSha256': digest(helper),
                    'compileArgvSha256': hashlib.sha256(argv_bytes).hexdigest(),
                    'compileArgvBase64': base64.b64encode(argv_bytes).decode()}
        reference = write('build/provider-dns/native/loopback-reference.properties',
                          ''.join(k + '=' + v + '\n' for k, v in metadata.items()).encode())
        write('build/provider-dns/native/loopback-reference.sha256', (digest(reference) + '\n').encode())
        write('build/generated/provider-dns-resources/acp-provider-dns/worker.sha256', (digest(worker) + '\n').encode())
        self.stdlib = write('trusted-gradle-cache/kotlin-stdlib-2.4.0.jar', b'fixed trusted stdlib')
        self.runtime['stdlib'] = self.stdlib
        self.class_names = {
            'decompengine/acp/AcpProviderNativeDnsControl.class': b'current test bytecode',
            'decompengine/acp/NativeNamespace.class': b'current namespace bytecode',
            'decompengine/acp/AcpProviderDnsProcess.class': b'current main bytecode',
            'decompengine/acp/ProviderDnsWorkerOwner.class': b'current owner bytecode',
        }
        for name, data in self.class_names.items():
            source_set = 'test' if 'Native' in name else 'main'
            write('build/classes/kotlin/' + source_set + '/' + name, data)
        self.control_entries = {**self.class_names, 'acp-provider-dns/worker.sha256': (digest(worker) + '\n').encode()}
        for case in gate.CASES:
            directory = self.root / ('build/provider-dns-native-qualification/' + case + '-' + self.run + '-closure')
            directory.mkdir(parents=True)
            with zipfile.ZipFile(directory / 'control.jar', 'w') as archive:
                for name, data in self.control_entries.items(): archive.writestr(name, data)
            (directory / 'kotlin-stdlib.jar').write_bytes(self.stdlib.read_bytes())
        closure = gate.verify_control_closure(self.root, self.closure_dir(), self.stdlib)
        self.receipt = {key: True for key in gate.FACTS}
        self.receipt.update({'schemaVersion': 1, 'caseName': 'cancel', 'runId': self.run,
                             'innerBoundingMask': '1400', 'workerBoundingMask': '1400',
                             'queryCount': 1, 'queryType': 28, 'childPid': 123,
                             'testSourceSha256': digest(test), 'helperSourceSha256': digest(source),
                             'workerJarSha256': digest(worker), 'javaExecutableSha256': digest(java),
                             'jdkReleaseSha256': digest(release), 'jdkModulesSha256': digest(modules),
                             'bwrapSha256': digest(tools['bwrap']), 'envExecutableSha256': digest(tools['env']),
                             'loopbackHelperSha256': digest(helper), 'loopbackReferenceSha256': digest(reference),
                             'compilerSha256': digest(tools['compiler']), 'linkerSha256': digest(tools['linker']),
                             'compileArgvSha256': metadata['compileArgvSha256'],
                             'controlRuntimeClosureSha256': closure})
        for case in gate.CASES:
            receipt = dict(self.receipt, caseName=case)
            write('build/provider-dns-native-qualification/' + case + '.json', json.dumps(receipt).encode())
        self.xml = ('<testsuite name="' + gate.SUITE + '" tests="2" failures="0" errors="0" skipped="0">' +
                    ''.join('<testcase classname="' + gate.SUITE + '" name="' + name + '()"/>' for name in gate.CASES.values()) +
                    '</testsuite>')
        self.report = write('build/test-results/test/TEST-native.xml', self.xml.encode())

    def closure_dir(self, case='cancel'):
        return self.root / ('build/provider-dns-native-qualification/' + case + '-' + self.run + '-closure')

    def rewrite_control(self, entries):
        with zipfile.ZipFile(self.closure_dir() / 'control.jar', 'w') as archive:
            for name, data in entries: archive.writestr(name, data)
        self.rehash_closure()

    def rehash_closure(self, case='cancel'):
        directory = self.closure_dir(case)
        value = hashlib.sha256('\0'.join(name + ':' + hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                         for name in ['control.jar', 'kotlin-stdlib.jar']).encode()).hexdigest()
        path = self.root / ('build/provider-dns-native-qualification/' + case + '.json')
        if path.exists():
            receipt = json.loads(path.read_text()); receipt['controlRuntimeClosureSha256'] = value
            path.write_text(json.dumps(receipt))

    def test_rehashed_substituted_control_rejected(self):
        entries = dict(self.control_entries)
        entries['decompengine/acp/AcpProviderDnsProcess.class'] = b'substitute'
        self.rewrite_control(entries.items())
        with self.assertRaises(gate.Invalid): self.verify()

    def test_stale_compiled_control_rejected(self):
        self.write('build/classes/kotlin/main/decompengine/acp/AcpProviderDnsProcess.class', b'new compiled main')
        with self.assertRaises(gate.Invalid): self.verify()

    def test_rehashed_wrong_worker_commitment_rejected(self):
        entries = dict(self.control_entries); entries['acp-provider-dns/worker.sha256'] = b'f' * 64 + b'\n'
        self.rewrite_control(entries.items())
        with self.assertRaises(gate.Invalid): self.verify()

    def test_missing_extra_duplicate_control_entries_rejected(self):
        original = list(self.control_entries.items())
        for entries in [original[1:], original + [('extra.class', b'extra')], original + [original[0]]]:
            with self.subTest(entries=len(entries)):
                self.rewrite_control(entries)
                with self.assertRaises(gate.Invalid): self.verify()

    def test_oversized_control_entry_rejected(self):
        entries = dict(self.control_entries); entries['decompengine/acp/AcpProviderDnsProcess.class'] = b'x' * (1024 * 1024 + 1)
        self.rewrite_control(entries.items())
        with self.assertRaises(gate.Invalid): self.verify()

    def test_rehashed_substituted_stdlib_rejected(self):
        (self.closure_dir() / 'kotlin-stdlib.jar').write_bytes(b'substitute stdlib')
        self.rehash_closure()
        with self.assertRaises(gate.Invalid): self.verify()

    def test_deadline_closure_independently_checked(self):
        (self.closure_dir('deadline') / 'kotlin-stdlib.jar').write_bytes(b'substitute deadline stdlib')
        self.rehash_closure('deadline')
        with self.assertRaises(gate.Invalid): self.verify()

    def test_substituted_ordered_closure_digest_rejected(self):
        self.alter('controlRuntimeClosureSha256', 'a' * 64)
        with self.assertRaises(gate.Invalid): self.verify()

    def test_missing_and_extra_closure_artifact_rejected(self):
        path = self.closure_dir() / 'extra.jar'; path.write_bytes(b'extra')
        with self.assertRaises(gate.Invalid): self.verify()
        path.unlink(); (self.closure_dir() / 'control.jar').unlink()
        with self.assertRaises(gate.Invalid): self.verify()

    def test_symlink_control_rejected(self):
        path = self.closure_dir() / 'control.jar'; data = path.read_bytes(); path.unlink()
        target = self.write('substituted.jar', data); path.symlink_to(target)
        with self.assertRaises(gate.Invalid): self.verify()

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        return gate.verify(self.root, self.run, self.runtime)

    def alter(self, key, value):
        path = self.root / 'build/provider-dns-native-qualification/cancel.json'
        receipt = json.loads(path.read_text())
        if value is None:
            del receipt[key]
        else:
            receipt[key] = value
        path.write_text(json.dumps(receipt))

    def test_valid_inert_fixture(self):
        result = self.verify()
        self.assertEqual('PASS', result['status'])
        self.assertEqual(2, len(result['cases']))
        self.assertFalse(result['realProviderQualified'])

    def test_altered_mask_rejected(self):
        self.alter('workerBoundingMask', '0')
        with self.assertRaises(gate.Invalid): self.verify()

    def test_missing_fact_rejected(self):
        self.alter('childReaped', None)
        with self.assertRaises(gate.Invalid): self.verify()

    def test_stale_run_rejected(self):
        self.alter('runId', 'old-run')
        with self.assertRaises(gate.Invalid): self.verify()

    def test_source_mismatch_rejected(self):
        self.write('src/test/provider-dns/native/provider_dns_loopback_fixture.c', b'changed source')
        with self.assertRaises(gate.Invalid): self.verify()

    def test_receipt_hash_mismatch_rejected(self):
        self.alter('javaExecutableSha256', 'b' * 64)
        with self.assertRaises(gate.Invalid): self.verify()

    def test_duplicate_xml_suite_rejected(self):
        self.write('build/test-results/test/TEST-duplicate.xml', self.xml.encode())
        with self.assertRaises(gate.Invalid): self.verify()

    def test_extra_xml_case_rejected(self):
        self.report.write_text(self.xml.replace('</testsuite>', '<testcase classname="' + gate.SUITE + '" name="extra"/></testsuite>'))
        with self.assertRaises(gate.Invalid): self.verify()

    def test_duplicate_xml_case_rejected(self):
        names = list(gate.CASES.values())
        self.report.write_text(self.xml.replace(names[1], names[0]))
        with self.assertRaises(gate.Invalid): self.verify()

    def test_nested_extra_xml_case_rejected(self):
        self.report.write_text(self.xml.replace('</testsuite>', '<testsuite><testcase name="extra"/></testsuite></testsuite>'))
        with self.assertRaises(gate.Invalid): self.verify()

    def test_duplicate_json_key_rejected(self):
        path = self.root / 'build/provider-dns-native-qualification/cancel.json'
        path.write_text(path.read_text().replace('{', '{"runId":"duplicate",', 1))
        with self.assertRaises(gate.Invalid): self.verify()

    def test_partial_observation_not_a_receipt(self):
        path = self.root / 'build/provider-dns-native-qualification/cancel.json'
        path.unlink()
        self.write('build/provider-dns-native-qualification/inner.properties', b'childReaped=true\n')
        with self.assertRaises(FileNotFoundError): self.verify()

    def test_boolean_integer_substitution_rejected(self):
        self.alter('childReaped', 1)
        with self.assertRaises(gate.Invalid): self.verify()

    def test_private_tree_remaining_rejected(self):
        (self.root / ('build/provider-dns-native-qualification/cancel-' + self.run)).mkdir()
        with self.assertRaises(gate.Invalid): self.verify()

if __name__ == '__main__':
    unittest.main()
