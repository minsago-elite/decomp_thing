"""Authored checker-consistency vectors; no native observations or qualification.

No JVM, native helper, model or authentication calls.
"""
from pathlib import Path
import base64
import copy
import hashlib
import io
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('dns_gate', REPO / 'scripts/verify-acp-provider-dns.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class CheckerTest(unittest.TestCase):
    def setUp(self):
        # Authored parser vectors only, never retained native execution evidence.
        base = REPO / 'build/provider-dns-checker-tests'
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = 'inert-checker-run'
        def write(name, data, executable=False):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if executable: path.chmod(0o755)
            return path
        self.write = write
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.digest = digest
        self.authored_hash = lambda name: hashlib.sha256(('inert authored ' + name).encode()).hexdigest()
        source = write('src/test/provider-dns/native/provider_dns_loopback_fixture.c', b'fixed helper source')
        for name in gate.HOST_SOURCE_PATHS.values(): write(name, ('authored source fixture: ' + name).encode())
        test = self.root / gate.HOST_SOURCE_PATHS['testSourceSha256']
        helper = write('build/provider-dns/native/provider-dns-loopback-fixture', b'\x7fELFfixed inert helper', True)
        worker = write('build/provider-dns/decomp-acp-provider-dns.jar', self.jar_bytes({
            'decompengine/acp/ProviderDnsWorker.class': self.class_bytes('ProviderDnsWorker', 'ProviderDnsWorker.java')}))
        java = write('runtime/jdk/bin/java', b'inert Java', True)
        release = write('runtime/jdk/release', b'inert release')
        modules = write('runtime/jdk/lib/modules', b'inert modules')
        tools = {name: write('runtime/' + name, ('inert ' + name).encode(), True) for name in ['bwrap', 'env', 'compiler', 'linker']}
        self.runtime = {'javaHome': java.parent.parent, **tools}
        argv = [str(tools['compiler']), *gate.FLAGS, str(source), '-o', str(helper)]
        argv_bytes = '\0'.join(argv).encode()
        metadata = {'schema': '1', 'sourceSha256': digest(source), 'compilerPath': str(tools['compiler']),
            'compilerSha256': digest(tools['compiler']), 'linkerPath': str(tools['linker']), 'linkerSha256': digest(tools['linker']),
            'helperSha256': digest(helper), 'compileArgvSha256': hashlib.sha256(argv_bytes).hexdigest(),
            'compileArgvBase64': base64.b64encode(argv_bytes).decode()}
        reference = self.write_properties('build/provider-dns/native/loopback-reference.properties', metadata)
        write('build/provider-dns/native/loopback-reference.sha256', (digest(reference) + '\n').encode())
        write('build/generated/provider-dns-resources/acp-provider-dns/worker.sha256', (digest(worker) + '\n').encode())
        self.stdlib = write('trusted-gradle-cache/kotlin-stdlib-2.4.0.jar', b'fixed authored stdlib')
        jna = write('trusted-gradle-cache/jna-5.19.1.jar', b'fixed authored JNA')
        jni = write('build/native/oracle/libjnidispatch.so', b'fixed authored JNI, never loaded')
        boot_jni = write('build/provider-dns/host-runtime/libjnidispatch.so', jni.read_bytes())
        self.runtime.update(stdlib=self.stdlib, jna=jna)
        native_policy = {'schemaVersion': '1', 'platform': 'linux-x86-64', 'relativeDirectory': 'lib/decomp-oracle-native'}
        for prefix in ('jna', 'sqlite'):
            native_policy.update({prefix + '.' + key: value for key, value in {
                'artifact': 'jna-5.19.1.jar' if prefix == 'jna' else 'authored-sqlite.jar',
                'artifactSha256': digest(jna) if prefix == 'jna' else self.authored_hash('sqlite jar'),
                'resource': 'authored/' + prefix, 'name': 'lib' + prefix + '.so', 'bytes': str(jni.stat().st_size),
                'sha256': digest(jni) if prefix == 'jna' else self.authored_hash('sqlite JNI')}.items()})
        self.write_properties(gate.HOST_SOURCE_PATHS['hostNativePolicySourceSha256'], native_policy)
        self.host_entries = {}
        for source_set, by_source in gate.HOST_RUNTIME_ROOTS.items():
            for source_name, roots in by_source.items():
                for root in roots:
                    name = 'decompengine/acp/' + root + '.class'
                    data = self.class_bytes(root, source_name)
                    write('build/classes/kotlin/' + source_set + '/' + name, data)
                    self.host_entries[name] = data
        nested = 'decompengine/acp/NativeObserverBudget$1.class'
        data = self.class_bytes('NativeObserverBudget$1', 'AcpProviderNativeDnsContractTest.kt')
        write('build/classes/kotlin/test/' + nested, data)
        self.host_entries[nested] = data
        for name in ('AcpProviderDnsProcess', 'ProviderDnsWorkerOwner'):
            write('build/classes/kotlin/main/decompengine/acp/' + name + '.class', self.class_bytes(name, name + '.kt'))
        self.control_entries = gate.compiled_control_entries(self.root)
        self.class_names = {name: data for name, data in self.control_entries.items() if name.endswith('.class')}
        sources = {key: digest(self.root / name) for key, name in gate.HOST_SOURCE_PATHS.items()}
        host_jar = self.jar_bytes(self.host_entries)
        self.host_metadata = {**sources, 'schema': '2',
            'kotlinCoordinates': 'org.jetbrains.kotlin:kotlin-stdlib:2.4.0', 'jnaCoordinates': 'net.java.dev.jna:jna:5.19.1',
            'stdlibSha256': digest(self.stdlib), 'jnaJarSha256': digest(jna), 'jniDispatchSha256': digest(jni),
            'hostClassesSha256': hashlib.sha256(host_jar).hexdigest(),
            'bytecodeClosureSha256': self.ordered_hash([name + ':' + hashlib.sha256(data).hexdigest() for name, data in sorted(self.host_entries.items())]),
            'sourceGenerationSha256': self.ordered_hash([key + ':' + value for key, value in sorted(sources.items())])}
        boot_identity = boot_jni.lstat()  # Authored file identity, never a loaded mapping observation.
        observed = {'schema': '2', 'loadedClassOriginsVerified': 'true', 'fixedJnaSelectionVerified': 'true',
            'jniMappingCount': '1', 'jniDevice': str(boot_identity.st_dev), 'jniInode': str(boot_identity.st_ino),
            'jniMappingSha256': self.authored_hash('mapping correlation fixture')}
        self.host_tools = {Path('/usr/bin/' + name): write('runtime/' + name, ('authored ' + name).encode()) for name in ('systemd-run', 'systemctl')}
        original_digest = gate.digest
        def fixture_digest(path, maximum=4 * 1024**3):
            path = Path(path)
            if path in self.host_tools: return original_digest(self.host_tools[path], maximum)
            resolved = path.resolve(strict=True)
            if resolved != Path(gate.__file__).resolve() and not resolved.is_relative_to(self.root):
                raise AssertionError('inert checker attempted an outside-fixture artifact read')
            return original_digest(path, maximum)
        digest_patch = patch.object(gate, 'digest', side_effect=fixture_digest)
        digest_patch.start(); self.addCleanup(digest_patch.stop)
        environment_patch = patch.object(gate.os, 'environ', {})
        environment_patch.start(); self.addCleanup(environment_patch.stop)
        self.receipt = {key: True for key in gate.FACTS}
        self.receipt.update({key: self.authored_hash(key) for key in gate.HASH_FIELDS})
        self.receipt.update({'schemaVersion': 2, 'caseName': 'cancel', 'runId': self.run,
            'namespaceDeduction': 'CONDITIONAL', 'executorContract': 'required-contract-hosted-ubuntu24-v1',
            'innerBoundingMask': '1400', 'workerBoundingMask': '1400', 'queryCount': 1, 'queryType': 28, 'childPid': 3,
            'testSourceSha256': digest(test), 'helperSourceSha256': digest(source), 'ownedContractSourceSha256': sources['ownedContractSourceSha256'],
            'scopeBackendSourceSha256': sources['scopeBackendSourceSha256'], 'scopeFilesystemSourceSha256': sources['scopeFilesystemSourceSha256'],
            'workerJarSha256': digest(worker), 'javaExecutableSha256': digest(java), 'jdkReleaseSha256': digest(release), 'jdkModulesSha256': digest(modules),
            'bwrapSha256': digest(tools['bwrap']), 'envExecutableSha256': digest(tools['env']), 'loopbackHelperSha256': digest(helper),
            'loopbackReferenceSha256': digest(reference), 'compilerSha256': digest(tools['compiler']), 'linkerSha256': digest(tools['linker']),
            'compileArgvSha256': metadata['compileArgvSha256']})
        for evidence_case in list(gate.CASES) + list(gate.NEGATIVES):
            control = 'positive' if evidence_case in gate.CASES else evidence_case
            case = evidence_case if control == 'positive' else 'cancel'
            directory = self.closure_dir(evidence_case); directory.mkdir(parents=True)
            (directory / 'control.jar').write_bytes(self.jar_bytes(self.control_entries))
            (directory / 'kotlin-stdlib.jar').write_bytes(self.stdlib.read_bytes())
            host = directory / 'host-runtime'; host.mkdir()
            (host / 'host-control.jar').write_bytes(host_jar)
            (host / 'kotlin-stdlib.jar').write_bytes(self.stdlib.read_bytes())
            (host / 'jna.jar').write_bytes(jna.read_bytes())
            (host / 'libjnidispatch.so').write_bytes(jni.read_bytes())
            self.write_properties(str((host / 'host-runtime.properties').relative_to(self.root)), self.host_metadata)
            self.write_properties(str((host / 'host-runtime-observed.properties').relative_to(self.root)), observed)
            receipt = dict(self.receipt, caseName=case)
            if control != 'positive': receipt.update(negativeControl=control, qualificationRefused=True)
            context = {'schema': '2', 'role': 'CORRELATION_ONLY_UNQUALIFIED', 'testTaskHex': ':test'.encode().hex(),
                'maxParallelForks': '1', 'forkEvery': '0', 'junitParallelEnabled': 'false',
                **{'context' + str(i) + 'Hex': 'UNAVAILABLE' for i in range(len(gate.CONTEXT_ENVIRONMENT_KEYS))}}
            context_path = self.write_properties('build/provider-dns-native-qualification/' + evidence_case + '-host-context.properties', context)
            receipt.update({'hostContextSha256': digest(context_path), 'hostRuntimeManifestSha256': digest(host / 'host-runtime.properties'),
                'hostRuntimeClassesSha256': self.host_metadata['hostClassesSha256'], 'hostRuntimeGenerationSha256': self.host_metadata['sourceGenerationSha256'],
                'hostRuntimeJnaSha256': digest(jna), 'hostRuntimeJniSha256': digest(jni), 'hostRuntimeJniMappingSha256': observed['jniMappingSha256'],
                'hostRuntimeClosureSha256': self.ordered_hash([name + ':' + digest(host / name) for name in gate.HOST_ARTIFACTS + ('host-runtime-observed.properties',)])})
            self.owned_records(evidence_case, case, control, directory, receipt)
            receipt['controlRuntimeClosureSha256'] = gate.verify_control_closure(self.root, directory, self.stdlib, control)
            self.bind_domain(evidence_case, receipt)
            write('build/provider-dns-native-qualification/' + evidence_case + '.json', json.dumps(receipt).encode())
        self.xml = self.suite_xml(gate.SUITE, gate.CASES.values())
        self.report = write('build/test-results/test/TEST-native.xml', self.xml.encode())
        self.negative_report = write('build/test-results/test/TEST-owned-negative.xml', self.suite_xml(gate.NEGATIVE_SUITE, gate.NEGATIVES.values()).encode())
        # Every tamper control must begin at the full positive parser path.
        self.assert_unqualified(self.verify())

    @staticmethod
    def ordered_hash(rows):
        return hashlib.sha256('\0'.join(rows).encode()).hexdigest()

    @staticmethod
    def jar_bytes(entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, data in sorted(entries.items()):
                archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), data)
        return stream.getvalue()

    @staticmethod
    def class_bytes(name, source):
        # Minimal authored class-file structure for identity parsing; never JVM-loaded.
        utf = lambda value: b'\x01' + len(value.encode('ascii')).to_bytes(2, 'big') + value.encode('ascii')
        return (b'\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x07' + utf('decompengine/acp/' + name) + b'\x07\x00\x01' +
                utf('java/lang/Object') + b'\x07\x00\x03' + utf('SourceFile') + utf(source) +
                b'\x00\x21\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x05\x00\x00\x00\x02\x00\x06')

    def write_properties(self, name, fields):
        return self.write(name, ''.join(key + '=' + str(value) + '\n' for key, value in sorted(fields.items())).encode('ascii'))

    @staticmethod
    def suite_xml(name, cases):
        cases = list(cases)
        return ('<testsuite name="' + name + '" tests="' + str(len(cases)) + '" failures="0" errors="0" skipped="0">' +
                ''.join('<testcase classname="' + name + '" name="' + case + '()"/>' for case in cases) + '</testsuite>')

    def owned_records(self, evidence_case, case, control, directory, receipt):
        # These facts are synthetic schema vectors, not assertions about actual processes.
        domain = {key: '0' for key in 'schema caseName control unit cgroupIdentitySha256 directHostPid directStart pidsMax memoryMax\nmemorySwapMax memoryOomGroup runtimeMaxMicros timeoutStopMicros cpuQuota cpuPeriod nproc fixedRlimitsVerified\nstartedNanos executionEndNanos cleanupEndNanos firstGateObservedNanos scopeBoundObservedNanos secondGateObservedNanos\nprocDevice procInode procMountId mountClosureSha256 privateProcBound nonEscapeVerified bootstrapNamespaceReferenceCount\nbootstrapFdLedgerSha256 hostNamespaceReferenceCount nativeNamespaceReferenceCount pid1HostPid pid1HostStart pid1InnerStart pid1InnerPid\nhostPidNsDevice hostPidNsInode escapeCanariesPassed firstGateHeld secondGateHeld pidDevice pidInode userDevice userInode\nnetDevice netInode mntDevice mntInode payloadReleased payloadReleaseNanos rootReapedObservedNanos payloadTerminalObservedNanos\nnativeEchild nativeReferencesClosed scopeAbsentObservedNanos hostStateUnchanged streamsClosedObservedNanos rootReaped\nscopeAbsent streamsJoinedClosed referencesClosed referencesClosedObservedNanos observationTimely observedEndNanos cleanupVerified\nrunId testSourceSha256 helperSourceSha256 workerJarSha256 controlRuntimeClosureSha256 ownedContractSourceSha256\nhostRuntimeClosureSha256 hostRuntimeManifestSha256 hostRuntimeClassesSha256 hostRuntimeGenerationSha256 hostRuntimeJnaSha256 hostRuntimeJniSha256 hostRuntimeJniMappingSha256 hostContextSha256\nnormalReferencesClosed normalReferenceClosedCount normalHandlesClosedObservedNanos pairedCleanPredicate pairedCleanObservedNanos scopeKillAttempted scopeRemovedBeforeSignal scopeKillRemovedDuringSignal\nscopeBackendSourceSha256 scopeFilesystemSourceSha256 scopeSupervisorSha256 scopeInspectorSha256 hostUid hostObserverScans hostObserverWork hostObserverPids hostObserverBytes'.split()}
        domain.update({key: self.authored_hash(key) for key in domain if key.endswith('Sha256')})
        domain.update({'schema': '2', 'caseName': case, 'control': control, 'runId': self.run,
            'unit': 'dns-fixture-00000000-0000-0000-0000-000000000001.scope', 'directHostPid': '111', 'directStart': '1',
            'pid1HostPid': '222', 'pid1HostStart': '2', 'pid1InnerStart': '2', 'pid1InnerPid': '1', 'hostPidNsDevice': '10', 'hostPidNsInode': '999',
            'procDevice': '11', 'procInode': '201', 'procMountId': '301', 'nproc': '32', 'pidsMax': '32', 'memoryMax': '2147483648',
            'memorySwapMax': '0', 'memoryOomGroup': 'true', 'runtimeMaxMicros': '33000000', 'timeoutStopMicros': '3000000',
            'cpuQuota': '100000', 'cpuPeriod': '100000', 'bootstrapNamespaceReferenceCount': '0',
            'hostNamespaceReferenceCount': '6' if control == 'retained-reference' else '5', 'nativeNamespaceReferenceCount': '6',
            'normalReferenceClosedCount': '5', 'scopeKillAttempted': 'true', 'scopeRemovedBeforeSignal': 'false', 'scopeKillRemovedDuringSignal': 'false',
            'startedNanos': '100', 'executionEndNanos': '25000000100', 'cleanupEndNanos': '30000000100',
            'hostUid': '1000', 'hostObserverScans': '1', 'hostObserverWork': '1', 'hostObserverPids': '1', 'hostObserverBytes': '64'})
        for key in '''fixedRlimitsVerified privateProcBound nonEscapeVerified escapeCanariesPassed firstGateHeld secondGateHeld
payloadReleased nativeEchild nativeReferencesClosed hostStateUnchanged rootReaped scopeAbsent streamsJoinedClosed
referencesClosed observationTimely cleanupVerified normalReferencesClosed pairedCleanPredicate'''.split(): domain[key] = 'true'
        for i, key in enumerate('''firstGateObservedNanos scopeBoundObservedNanos secondGateObservedNanos payloadReleaseNanos
rootReapedObservedNanos payloadTerminalObservedNanos scopeAbsentObservedNanos streamsClosedObservedNanos
normalHandlesClosedObservedNanos pairedCleanObservedNanos referencesClosedObservedNanos observedEndNanos'''.split(), 1): domain[key] = str(i * 1000)
        for i, kind in enumerate(('pid', 'user', 'net', 'mnt'), 101):
            domain[kind + 'Device'] = '10'; domain[kind + 'Inode'] = str(i)
        domain['scopeSupervisorSha256'] = self.digest(self.host_tools[Path('/usr/bin/systemd-run')])
        domain['scopeInspectorSha256'] = self.digest(self.host_tools[Path('/usr/bin/systemctl')])
        gate_record = {key: '0' for key in 'schema caseName control innerPid innerStart activeCapabilitiesZero boundingMask noNewPrivileges seccomp\nescapeCanariesPassed privateProcOnlyPid1 nproc nofile fsize as cpu core pidDev pidIno userDev userIno netDev netIno mntDev mntIno\nprocDev procIno procMountId'.split()}
        gate_record.update({'schema': '2', 'caseName': case, 'control': control, 'innerPid': '1', 'innerStart': '2', 'boundingMask': '1400',
            'seccomp': '2', 'nproc': '32', 'nofile': '128', 'fsize': '67108864', 'as': '2147483648', 'cpu': '120', 'core': '0',
            'procDev': '11', 'procIno': '201', 'procMountId': '301'})
        for key in ('activeCapabilitiesZero', 'noNewPrivileges', 'escapeCanariesPassed', 'privateProcOnlyPid1'): gate_record[key] = 'true'
        for kind in ('pid', 'user', 'net', 'mnt'):
            gate_record[kind + 'Dev'] = domain[kind + 'Device']; gate_record[kind + 'Ino'] = domain[kind + 'Inode']
        child_negative = control in ('retained-child', 'inaccessible-owned')
        terminal = {'schema': '2', 'caseName': case, 'control': control, 'innerPid': '1', 'childInnerPid': '3', 'childRawStatus': '0',
            'queryCount': '1', 'queryType': '28', 'observerScans': '1', 'observerWork': '1', 'observerPids': '1', 'observerBytes': '64',
            'negativeObserved': str(child_negative).lower(), 'negativeInnerPid': '4' if child_negative else '0',
            'primaryFailure': 'POSSIBLE_OWNED_VISIBILITY' if control == 'inaccessible-owned' else 'RETAINED_OWNED_CHILD' if control == 'retained-child' else 'NONE'}
        for key in ('childReaped', 'finalEchild', 'ownedChildrenZero', 'privateProcOnlyPid1', 'fixedReferencesClosed', 'blackholeJoined'): terminal[key] = 'true'
        inner = {key: 'true' for key in 'caseName workerJarSha256 childPid realQueryObserved nativeBuiltinWorker childReaped ownerJoined streamsClosed\nnoAddressAdmitted noConnectAdmitted workerCapabilitiesZero innerBoundingMask workerBoundingMask innerNoNewPrivileges workerNoNewPrivileges'.split()}
        inner.update({'caseName': case, 'workerJarSha256': receipt['workerJarSha256'], 'childPid': '3', 'innerBoundingMask': '1400', 'workerBoundingMask': '1400'})
        if control == 'retained-reference':
            domain.update({'retainedReferenceRefused': 'true', 'retainedReferenceOnlyOpen': 'true', 'retainedReferenceObservedNanos': '9500',
                'retainedReferenceDevice': domain['netDevice'], 'retainedReferenceInode': domain['netInode'], 'retainedReferenceMountId': '401'})
        if control == 'inaccessible-owned':
            domain.update({'possibleOwnedVisibilityRefused': 'true', 'witnessInnerPid': '4', 'witnessPidNamespaceInode': domain['pidInode']})
            self.write_properties(str((directory / 'witness.properties').relative_to(self.root)), {'schema': '2', 'pid': '4', 'callerPid': '1',
                'kind': 'net', 'phase': 'OUTER_CLEANUP', 'namespaceRead': 'ACCESS_DENIED', 'identity': 'UNAVAILABLE'})
        for name, fields, key in [('gate.properties', gate_record, 'ownedGateSha256'), ('owner.properties', terminal, 'ownedTerminalSha256'),
                                   ('inner.properties', inner, 'ownedInnerSha256')]:
            path = self.write_properties(str((directory / name).relative_to(self.root)), fields)
            receipt[key] = self.digest(path)
        self.domains = getattr(self, 'domains', {})
        self.domains[evidence_case] = domain

    def bind_domain(self, evidence_case, receipt):
        domain = self.domains[evidence_case]
        for key in ('testSourceSha256', 'helperSourceSha256', 'workerJarSha256', 'controlRuntimeClosureSha256', 'ownedContractSourceSha256',
            'scopeBackendSourceSha256', 'scopeFilesystemSourceSha256', 'hostRuntimeClosureSha256', 'hostRuntimeManifestSha256',
            'hostRuntimeClassesSha256', 'hostRuntimeGenerationSha256', 'hostRuntimeJnaSha256', 'hostRuntimeJniSha256', 'hostRuntimeJniMappingSha256', 'hostContextSha256'):
            domain[key] = receipt[key]
        domain['cgroupIdentitySha256'] = receipt['ownedScopeIdentitySha256']
        path = self.write_properties('build/provider-dns-native-qualification/' + evidence_case + '-owned.properties', domain)
        receipt['ownedDomainSha256'] = self.digest(path)

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
            self.bind_domain(case, receipt)
            path.write_text(json.dumps(receipt))

    def test_observer_roots_and_actual_zip_nested_inventory_are_source_bound(self):
        self.assertEqual(('NativeObserverBudget', 'NativeObserverBudgetOwner',
                          'NativeVisibilityAccumulator', 'NativeObserverFailure'), gate.OBSERVER_CONTROL_ROOTS)
        expected = gate.compiled_control_entries(self.root)
        for root in gate.OBSERVER_CONTROL_ROOTS:
            self.assertIn('decompengine/acp/' + root + '.class', expected)
            self.assertTrue(gate.observer_control_class(root + '$generated.class'))
            self.assertFalse(gate.observer_control_class(root + 'Unrelated.class'))
        self.assertIn('decompengine/acp/NativeObserverBudget$1.class', expected)
        with zipfile.ZipFile(self.closure_dir() / 'control.jar') as archive:
            self.assertEqual(set(expected), set(archive.namelist()))
            for name, data in expected.items(): self.assertEqual(data, archive.read(name))
        self.assertEqual('OWNED_OBSERVATIONS_VERIFIED_UNQUALIFIED', self.verify()['status'])

    def test_observer_archive_omission_and_hash_tamper_rejected_even_after_rehash(self):
        names = ['decompengine/acp/' + root + '.class' for root in gate.OBSERVER_CONTROL_ROOTS]
        names.append('decompengine/acp/NativeObserverBudget$1.class')
        for name in names:
            with self.subTest(name=name, mutation='omission'):
                entries = dict(self.control_entries); del entries[name]
                self.rewrite_control(entries.items())
                with self.assertRaises(gate.Invalid): self.verify()
            with self.subTest(name=name, mutation='tamper'):
                entries = dict(self.control_entries); entries[name] = b'tampered observer bytecode'
                self.rewrite_control(entries.items())
                with self.assertRaises(gate.Invalid): self.verify()

    def test_observer_roots_cannot_disappear_from_both_compilation_and_archive(self):
        for root in gate.OBSERVER_CONTROL_ROOTS:
            name = 'decompengine/acp/' + root + '.class'
            path = self.root / ('build/classes/kotlin/test/' + name)
            with self.subTest(root=root):
                path.unlink()
                try:
                    entries = dict(self.control_entries); del entries[name]
                    self.rewrite_control(entries.items())
                    with self.assertRaisesRegex(gate.Invalid, 'missing observer runtime dependency'): self.verify()
                finally: path.write_bytes(self.class_names[name])

    def test_observer_lookalikes_and_uncompiled_nested_extras_remain_rejected(self):
        for name in ['NativeObserverBudgetUnrelated.class', 'Unrelated.class', 'NativeDnsObserverDiagnosticTest.class']:
            self.write('build/classes/kotlin/test/decompengine/acp/' + name, b'extra unrelated compiled class')
            self.assertNotIn('decompengine/acp/' + name, gate.compiled_control_entries(self.root))
            entries = dict(self.control_entries); entries['decompengine/acp/' + name] = b'extra unrelated compiled class'
            self.rewrite_control(entries.items())
            with self.assertRaises(gate.Invalid): self.verify()
        entries = dict(self.control_entries); entries['decompengine/acp/NativeObserverBudget$uncompiled.class'] = b'extra nested'
        self.rewrite_control(entries.items())
        with self.assertRaises(gate.Invalid): self.verify()

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

    def assert_unqualified(self, result):
        self.assertEqual('OWNED_OBSERVATIONS_VERIFIED_UNQUALIFIED', result['status'])
        self.assertEqual(5, len(result['cases']))
        self.assertEqual('CONDITIONAL', result['namespaceConclusion']['kind'])
        self.assertEqual('UNAVAILABLE_PENDING_INDEPENDENT_SERVICE_JOB_JOIN', result['namespaceConclusion']['qualification'])
        self.assertFalse(result['supportedFixtureHostQualified'])
        self.assertFalse(result['releaseQualified'])
        self.assertFalse(result['realProviderQualified'])

    def test_valid_inert_fixture(self):
        self.assert_unqualified(self.verify())

    def test_case_specific_inaccessible_witness_inventory_required(self):
        (self.closure_dir('inaccessible-owned') / 'witness.properties').unlink()
        with self.assertRaisesRegex(gate.Invalid, 'retained closure inventory refused'):
            self.verify()

    def test_negative_suite_is_required(self):
        self.negative_report.unlink()
        with self.assertRaisesRegex(gate.Invalid, 'missing native positive/negative suite'):
            self.verify()

    def test_host_runtime_class_tamper_reaches_source_bound_comparison(self):
        entries = dict(self.host_entries)
        entries['decompengine/acp/VerifiedSystemdScope.class'] = b'authored substituted host class'
        (self.closure_dir() / 'host-runtime/host-control.jar').write_bytes(self.jar_bytes(entries))
        with self.assertRaisesRegex(gate.Invalid, 'executed host class differs from current compilation'):
            self.verify()

    def test_host_policy_generation_cannot_be_reused_after_source_change(self):
        self.write(gate.HOST_SOURCE_PATHS['scopePolicySourceSha256'], b'authored changed scope policy')
        with self.assertRaisesRegex(gate.Invalid, 'host source generation mismatch'):
            self.verify()

    def test_rehashed_owned_domain_cannot_conflate_host_and_inner_pid_namespaces(self):
        domain = self.domains['cancel']
        domain['hostPidNsDevice'] = domain['pidDevice']
        domain['hostPidNsInode'] = domain['pidInode']
        path = self.root / 'build/provider-dns-native-qualification/cancel.json'
        receipt = json.loads(path.read_text())
        self.bind_domain('cancel', receipt)
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(gate.Invalid, 'host/inner PID coordinate conflation'):
            self.verify()

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
