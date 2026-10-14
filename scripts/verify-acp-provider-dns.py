#!/usr/bin/env python3
"""Verify fresh source-bound native DNS qualification. Never accept partial observations."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile
from itertools import islice

SUITE = 'decompengine.acp.AcpProviderNativeDnsContractTest'
CASES = {'cancel': 'native stalled lookup cancellation kills and reaps the resolver child',
         'deadline': 'native stalled lookup deadline kills and reaps the resolver child'}
FACTS = '''realQueryObserved nativeBuiltinWorker childReaped ownerJoined streamsClosed noAddressAdmitted
noConnectAdmitted noActiveDescendants blackholeJoined workerCapabilitiesZero privateTreeRemoved
namespaceDestroyed noSurvivingChildMembership hostNamespacesUnchanged hostLoopbackUnchanged
innerNoNewPrivileges workerNoNewPrivileges'''.split()
HASH_FIELDS = '''testSourceSha256 helperSourceSha256 workerJarSha256 javaExecutableSha256 jdkReleaseSha256
jdkModulesSha256 bwrapSha256 loopbackHelperSha256 envExecutableSha256 loopbackReferenceSha256
compilerSha256 linkerSha256 compileArgvSha256 controlRuntimeClosureSha256'''.split()
FLAGS = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-ident', '-Wl,--build-id=none']
# Keep in lockstep with snapshotNativeControl's exact observer roots plus generated nested classes.
OBSERVER_CONTROL_ROOTS = ('NativeObserverBudget', 'NativeObserverBudgetOwner',
                          'NativeVisibilityAccumulator', 'NativeObserverFailure')
MAX_JSON = 64 * 1024

class Invalid(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Invalid(reason)

def read(path: Path, maximum: int) -> bytes:
    require(not path.is_symlink(), 'symlink evidence refused')
    with path.open('rb') as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'evidence size/type refused')
        data = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    require(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'evidence changed during read')
    named = path.lstat()
    require((named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns) ==
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) and
            stat.S_ISREG(named.st_mode), 'evidence name changed')
    return data

def digest(path: Path, maximum=4 * 1024**3) -> str:
    path = path.resolve(strict=True)
    with path.open('rb') as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'bound artifact size/type refused')
        result = hashlib.sha256()
        total = 0
        while chunk := handle.read(65536):
            total += len(chunk)
            require(total <= maximum, 'bound artifact oversized')
            result.update(chunk)
        after = os.fstat(handle.fileno())
    require(total == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'bound artifact changed')
    return result.hexdigest()

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def load_json(path):
    data = read(path, MAX_JSON)
    value = json.loads(data.decode('ascii'), object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite JSON number')))
    require(type(value) is dict, 'receipt must be an object')
    return value

def properties(path):
    data = read(path, 16 * 1024).decode('ascii')
    require(data.endswith('\n'), 'noncanonical properties')
    result = {}
    for line in data.splitlines():
        require(re.fullmatch(r'[A-Za-z][A-Za-z0-9]*=[ -~]+', line) is not None, 'invalid properties line')
        key, value = line.split('=', 1)
        require(key not in result and '\\' not in value, 'duplicate/escaped properties refused')
        result[key] = value
    return result

def commitment(path):
    data = read(path, 65)
    require(re.fullmatch(rb'[0-9a-f]{64}\n', data) is not None, 'invalid SHA commitment')
    return data.decode('ascii').strip()

def observer_control_class(name: str) -> bool:
    return name.endswith('.class') and any(name == root + '.class' or name.startswith(root + '$')
                                          for root in OBSERVER_CONTROL_ROOTS)


def compiled_control_entries(root: Path) -> dict[str, bytes]:
    expected = {}
    for source_set, prefixes in [('test', ('AcpProviderNativeDns', 'NativeNamespace')),
                                 ('main', ('AcpProviderDns', 'ProviderDns'))]:
        directory = root / ('build/classes/kotlin/' + source_set + '/decompengine/acp')
        require(directory.resolve(strict=True) == directory, 'noncanonical compiled control directory')
        paths = sorted(islice(directory.glob('*.class'), 8193))
        require(len(paths) <= 8192, 'compiled class inventory oversized')
        selected = [path for path in paths if path.name.startswith(prefixes) or
                    source_set == 'test' and observer_control_class(path.name)]
        require(0 < len(selected) <= 128, 'missing/oversized compiled control set')
        for path in selected:
            name = 'decompengine/acp/' + path.name
            require(name not in expected, 'duplicate compiled control class')
            expected[name] = read(path, 1024 * 1024)
    require(all('decompengine/acp/' + name + '.class' in expected for name in OBSERVER_CONTROL_ROOTS),
            'compiled control missing observer runtime dependency')
    resource = 'acp-provider-dns/worker.sha256'
    expected[resource] = read(root / ('build/generated/provider-dns-resources/' + resource), 65)
    require(len(expected) <= 256 and sum(map(len, expected.values())) <= 16 * 1024**2,
            'compiled closure exceeds bound')
    return expected


def verify_control_closure(root: Path, directory: Path, trusted_stdlib: Path) -> str:
    require(directory.resolve(strict=True) == directory and not directory.is_symlink(), 'noncanonical retained closure')
    require(sorted(path.name for path in islice(directory.iterdir(), 3)) == ['control.jar', 'kotlin-stdlib.jar'],
            'retained closure inventory refused')
    expected = compiled_control_entries(root)
    control = read(directory / 'control.jar', 16 * 1024**2)
    import io
    with zipfile.ZipFile(io.BytesIO(control)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        require(len(names) == len(set(names)) and set(names) == set(expected), 'control jar missing/extra/duplicate entries')
        require(all(not info.is_dir() and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                    not info.flag_bits & 1 and 0 < info.file_size <= 1024 * 1024 for info in infos),
                'control jar entry type/size refused')
        require(sum(info.file_size for info in infos) <= 16 * 1024**2, 'control jar expanded size refused')
        for info in infos:
            require(archive.read(info) == expected[info.filename], 'control class/resource differs from current compilation')
    # trusted_stdlib is supplied by the trusted Gradle task's resolved artifact coordinates,
    # never a receipt, jar entry, adjacent digest or retained manifest.
    require(trusted_stdlib.resolve(strict=True) == trusted_stdlib and not trusted_stdlib.is_symlink(),
            'noncanonical resolved stdlib')
    stdlib = read(directory / 'kotlin-stdlib.jar', 8 * 1024**2)
    require(stdlib == read(trusted_stdlib, 8 * 1024**2), 'retained stdlib differs from Gradle resolved artifact')
    ordered = [('control.jar', control), ('kotlin-stdlib.jar', stdlib)]
    return hashlib.sha256('\0'.join(name + ':' + hashlib.sha256(data).hexdigest()
                                     for name, data in ordered).encode('utf-8')).hexdigest()


def verify(root: Path, run_id: str, runtime: dict[str, Path]) -> dict:
    require(re.fullmatch(r'[A-Za-z0-9-]{1,80}', run_id) is not None, 'invalid run identifier')
    root = root.resolve(strict=True)
    qualification = root / 'build/provider-dns-native-qualification'
    require(qualification.resolve(strict=True) == qualification, 'noncanonical qualification directory')
    summaries = []
    report_hashes = {}
    native_suites = []
    reports = sorted((root / 'build/test-results/test').glob('TEST-*.xml'))
    require(0 < len(reports) <= 512, 'missing/oversized XML inventory')
    for path in reports:
        data = read(path, 16 * 1024 * 1024)
        require(b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(), 'XML declarations refused')
        suite = ET.fromstring(data)
        matching = [node for node in suite.iter('testsuite') if node.attrib.get('name') == SUITE]
        if matching:
            require(suite.tag == 'testsuite' and matching == [suite], 'nested/duplicate native XML suite')
            native_suites.append(suite)
            report_hashes[path.name] = hashlib.sha256(data).hexdigest()
    require(len(native_suites) == 1, 'missing/duplicate native XML suite')
    suite = native_suites[0]
    for field, value in [('tests', '2'), ('failures', '0'), ('errors', '0'), ('skipped', '0')]:
        require(suite.attrib.get(field) == value, 'native XML count/failure/skip refused')
    names = []
    for case in suite.iter('testcase'):
        require(case.attrib.get('classname') == SUITE and not any(case.find(k) is not None for k in
                ('failure', 'error', 'skipped')), 'native testcase failure/type refused')
        name = case.attrib.get('name', '')
        names.append(name[:-2] if name.endswith('()') else name)
    require(len(names) == 2 and set(names) == set(CASES.values()), 'missing/duplicate/extra native testcase')
    native = root / 'build/provider-dns/native'
    worker = root / 'build/provider-dns/decomp-acp-provider-dns.jar'
    source = root / 'src/test/provider-dns/native/provider_dns_loopback_fixture.c'
    test_source = root / 'src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt'
    helper = native / 'provider-dns-loopback-fixture'
    reference = native / 'loopback-reference.properties'
    metadata = properties(reference)
    expected_keys = {'schema', 'sourceSha256', 'compilerPath', 'compilerSha256', 'linkerPath', 'linkerSha256',
                     'helperSha256', 'compileArgvSha256', 'compileArgvBase64'}
    require(set(metadata) == expected_keys and metadata['schema'] == '1', 'reference schema refused')
    reference_sha = digest(reference, 16384)
    require(commitment(native / 'loopback-reference.sha256') == reference_sha, 'reference commitment mismatch')
    require(commitment(root / 'build/generated/provider-dns-resources/acp-provider-dns/worker.sha256') == digest(worker, 65536),
            'worker commitment mismatch')
    worker_bytes = read(worker, 65536)
    with zipfile.ZipFile(worker) as archive:
        entries = archive.namelist()
        require(len(entries) == len(set(entries)) and len(entries) <= 16 and
                'decompengine/acp/ProviderDnsWorker.class' in entries and
                not any('services/' in name or 'fixtures/' in name for name in entries), 'resolver SPI/fixture worker refused')
        require(all(info.file_size <= 65536 for info in archive.infolist()), 'worker entry oversized')
    require(hashlib.sha256(worker_bytes).hexdigest() == digest(worker, 65536), 'worker changed')
    compiler, linker = runtime['compiler'].resolve(strict=True), runtime['linker'].resolve(strict=True)
    require(metadata['compilerPath'] == str(compiler) and metadata['linkerPath'] == str(linker), 'tool path mismatch')
    argv_bytes = base64.b64decode(metadata['compileArgvBase64'], validate=True)
    require(len(argv_bytes) <= 16384 and hashlib.sha256(argv_bytes).hexdigest() == metadata['compileArgvSha256'],
            'compile argv commitment mismatch')
    argv = argv_bytes.decode('utf-8').split('\0')
    require(argv == [str(compiler), *FLAGS, str(source.resolve(strict=True)), '-o', str(helper.resolve(strict=True))],
            'compile argv mismatch')
    require(read(helper, 1024 * 1024).startswith(b'\x7fELF'), 'helper is not ELF')
    require(os.access(helper, os.X_OK), 'helper not executable')
    java_home = runtime['javaHome'].resolve(strict=True)
    expected = {
        'testSourceSha256': digest(test_source, 1024 * 1024), 'helperSourceSha256': digest(source, 65536),
        'workerJarSha256': digest(worker, 65536), 'javaExecutableSha256': digest(java_home / 'bin/java'),
        'jdkReleaseSha256': digest(java_home / 'release'), 'jdkModulesSha256': digest(java_home / 'lib/modules'),
        'bwrapSha256': digest(runtime['bwrap']), 'envExecutableSha256': digest(runtime['env']),
        'loopbackHelperSha256': digest(helper, 1024 * 1024), 'loopbackReferenceSha256': reference_sha,
        'compilerSha256': digest(compiler), 'linkerSha256': digest(linker),
        'compileArgvSha256': metadata['compileArgvSha256'],
    }
    for key, value in [('sourceSha256', expected['helperSourceSha256']), ('helperSha256', expected['loopbackHelperSha256']),
                       ('compilerSha256', expected['compilerSha256']), ('linkerSha256', expected['linkerSha256'])]:
        require(metadata[key] == value, 'reference artifact/source mismatch')
    required = set(FACTS + HASH_FIELDS + ['schemaVersion', 'caseName', 'runId', 'innerBoundingMask',
                                        'workerBoundingMask', 'queryCount', 'queryType', 'childPid'])
    for case in CASES:
        receipt_path = qualification / (case + '.json')
        receipt = load_json(receipt_path)
        require(set(receipt) == required, 'receipt keys missing/extra')
        require(type(receipt['schemaVersion']) is int and receipt['schemaVersion'] == 1 and
                receipt['caseName'] == case and receipt['runId'] == run_id, 'receipt schema/case/freshness mismatch')
        require(all(receipt[k] is True for k in FACTS), 'receipt required fact missing/false')
        require(receipt['innerBoundingMask'] == receipt['workerBoundingMask'] == '1400', 'capability bounding mask mismatch')
        require(all(type(receipt[k]) is str and re.fullmatch(r'[0-9a-f]{64}', receipt[k]) for k in HASH_FIELDS),
                'receipt hash format refused')
        require(all(receipt[k] == value for k, value in expected.items()), 'receipt source/artifact hash mismatch')
        closure = verify_control_closure(root, qualification / (case + '-' + run_id + '-closure'), runtime['stdlib'])
        require(receipt['controlRuntimeClosureSha256'] == closure, 'receipt control closure mismatch')
        require(type(receipt['queryCount']) is int and 1 <= receipt['queryCount'] <= 64 and
                type(receipt['queryType']) is int and receipt['queryType'] in (1, 28) and
                type(receipt['childPid']) is int and receipt['childPid'] > 0, 'query/child facts refused')
        private_tree = qualification / (case + '-' + run_id)
        require(not private_tree.exists() and not private_tree.is_symlink(), 'private qualification tree remains')
        summaries.append({'receiptSha256': digest(receipt_path, MAX_JSON), 'receipt': receipt})
    return {'schemaVersion': 1, 'runId': run_id, 'status': 'PASS', 'nativeSuite': SUITE,
            'checkerSha256': digest(Path(__file__), 1024 * 1024),
            'xmlSha256': report_hashes, 'sourceAndArtifactSha256': expected,
            'reference': metadata, 'cases': summaries, 'realProviderQualified': False}

def main():
    require(len(sys.argv) == 3, 'invoke the trusted verifyProviderDnsNativeQualification Gradle task')
    run_id = sys.argv[1]
    require('JAVA_HOME' in os.environ, 'JAVA_HOME is required for runtime binding')
    root = Path(__file__).resolve().parents[1]
    runtime = {'javaHome': Path(os.environ['JAVA_HOME']), 'bwrap': Path('/usr/bin/bwrap'),
               'env': Path('/usr/bin/env'), 'compiler': Path('/usr/bin/cc'), 'linker': Path('/usr/bin/ld'),
               'stdlib': Path(sys.argv[2])}
    summary = verify(root, run_id, runtime)
    output = root / 'build/provider-dns-native-qualification/gate-summary.json'
    pending = output.with_suffix('.json.pending')
    require(not pending.exists() and not pending.is_symlink() and not output.is_symlink(), 'unsafe summary destination')
    data = (json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')
    with pending.open('xb') as handle:
        handle.write(data)
    pending.replace(output)
    print(json.dumps({'status': 'PASS', 'runId': run_id, 'summarySha256': hashlib.sha256(data).hexdigest()}, sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except (Invalid, OSError, ValueError, KeyError, RecursionError, ET.ParseError, zipfile.BadZipFile):
        print('native DNS qualification verification failed', file=sys.stderr)
        raise SystemExit(1)
