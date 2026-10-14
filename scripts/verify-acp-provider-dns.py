#!/usr/bin/env python3
"""Verify fresh source-bound native DNS qualification. Never accept partial observations."""
from __future__ import annotations
import base64
import struct
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
ownedProcessClosureObserved ownedReferenceClosureObserved noSurvivingChildMembership hostNamespacesUnchanged hostLoopbackUnchanged
innerNoNewPrivileges workerNoNewPrivileges'''.split()
HASH_FIELDS = '''testSourceSha256 helperSourceSha256 workerJarSha256 javaExecutableSha256 jdkReleaseSha256
jdkModulesSha256 bwrapSha256 loopbackHelperSha256 envExecutableSha256 loopbackReferenceSha256
compilerSha256 linkerSha256 compileArgvSha256 controlRuntimeClosureSha256'''.split()
NEGATIVE_SUITE = 'decompengine.acp.NativeDnsOwnedDomainBoundaryTest'
NEGATIVES = {'retained-child': 'retainedChildCannotCertifyCleanup',
             'retained-reference': 'retainedNamespaceReferenceCannotBorrowEmptyScope',
             'inaccessible-owned': 'inaccessibleOwnedMemberRemainsFatal'}
HASH_FIELDS += '''ownedContractSourceSha256 scopeBackendSourceSha256 scopeFilesystemSourceSha256 ownedDomainSha256 ownedScopeIdentitySha256
ownedGateSha256 ownedTerminalSha256 ownedInnerSha256 hostRuntimeClosureSha256 hostRuntimeManifestSha256 hostRuntimeClassesSha256
hostRuntimeGenerationSha256 hostRuntimeJnaSha256 hostRuntimeJniSha256 hostRuntimeJniMappingSha256 hostContextSha256'''.split()
OWNED_CONTROL_ROOTS = ('NativeDnsOwnedDomainOwner', 'NativeDnsOwnedResult', 'NativeDnsOwnedLib',
                       'NativeDnsOwnedFd', 'NativeDnsOwnedDomainContract')
FLAGS = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-ident', '-Wl,--build-id=none']
# Keep in lockstep with snapshotNativeControl's exact observer roots plus generated nested classes.
OBSERVER_CONTROL_ROOTS = ('NativeObserverBudget', 'NativeObserverBudgetOwner',
                          'NativeVisibilityAccumulator', 'NativeObserverFailure')
HOST_RUNTIME_ROOTS = {
    "test": {
        "AcpProviderNativeDnsContractTest.kt": [
            "AcpProviderNativeDnsContractTestKt",
            "AcpProviderNativeDnsControl",
            "NativeNamespace",
            "NativeNamespaceCredentials",
            "NativeNamespaceWaitFailure",
            "NativeObserverBudget",
            "NativeObserverBudgetOwner",
            "NativeVisibilityAccumulator",
            "NativeObserverFailure",
            "NativeDnsOwnedDomainOwner",
            "NativeDnsOwnedResult",
            "NativeDnsOwnedLib",
            "NativeDnsOwnedFd",
            "AcpProviderNativeDnsContractTest",
            "NativeDnsOwnedDomainBoundaryTest"
        ],
        "NativeDnsOwnedDomainContract.kt": [
            "NativeDnsOwnedDomainContract"
        ]
    },
    "main": {
        "LinuxBubblewrapBoundary.kt": [
            "LinuxBubblewrapBoundaryKt",
            "SystemdScopeController",
            "VerifiedScopeManager",
            "VerifiedSystemdScope",
            "PinnedSecurityExecutable",
            "PinnedSystemdBusEndpoint",
            "PinnedFileIdentity",
            "AcpSandboxScopeIdentity",
            "AcpCgroupControllerEvidence",
            "AcpSandboxRlimitEvidence",
            "AcpSecurityExecutableEvidence",
            "AcpCleanupProofFailure",
            "CommandResult",
            "TrustedControlProcessOwner",
            "TrustedControlProcesses"
        ],
        "LinuxFilesystemSyscalls.kt": [
            "LinuxFilesystemSyscalls",
            "LinuxFilesystemSyscallsKt",
            "LinuxFileKey",
            "LinuxFileIdentity",
            "LinuxFilesystemCapacity",
            "LinuxDescriptor",
            "LinuxProcessDescriptor",
            "LinuxDescriptorReserve",
            "NativeClose",
            "LinuxSyscallException",
            "LinuxResourceLimitException",
            "LinuxNamedRegularFileReplacedException",
            "RuntimeCopyStatistics"
        ],
        "AcpSandboxPolicy.kt": [
            "AcpSandboxPolicyKt",
            "AcpSandboxResourceLimits"
        ]
    }
}
HOST_SOURCE_PATHS = {
    "testSourceSha256": "src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt",
    "ownedContractSourceSha256": "src/test/kotlin/decompengine/acp/NativeDnsOwnedDomainContract.kt",
    "scopeBackendSourceSha256": "src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt",
    "scopeFilesystemSourceSha256": "src/main/kotlin/decompengine/acp/LinuxFilesystemSyscalls.kt",
    "scopePolicySourceSha256": "src/main/kotlin/decompengine/acp/AcpSandboxPolicy.kt",
    "hostNativePolicySourceSha256": "src/main/resources/oracle-native-libraries-v1.properties",
    "hostBuildSourceSha256": "build.gradle.kts"
}
HOST_ARTIFACTS = ('host-control.jar', 'kotlin-stdlib.jar', 'jna.jar', 'libjnidispatch.so', 'host-runtime.properties')

MAX_JSON = 64 * 1024

class Invalid(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Invalid(reason)

def read(path: Path, maximum: int) -> bytes:
    require(not path.is_symlink(), 'symlink evidence refused')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as handle:
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
                                          for root in OBSERVER_CONTROL_ROOTS + OWNED_CONTROL_ROOTS)


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
    require(all('decompengine/acp/' + name + '.class' in expected for name in OBSERVER_CONTROL_ROOTS + OWNED_CONTROL_ROOTS),
            'compiled control missing observer runtime dependency')
    resource = 'acp-provider-dns/worker.sha256'
    expected[resource] = read(root / ('build/generated/provider-dns-resources/' + resource), 65)
    require(len(expected) <= 256 and sum(map(len, expected.values())) <= 16 * 1024**2,
            'compiled closure exceeds bound')
    return expected


def verify_control_closure(root: Path, directory: Path, trusted_stdlib: Path, control: str) -> str:
    require(directory.resolve(strict=True) == directory and not directory.is_symlink(), 'noncanonical retained closure')
    inventory = {'control.jar', 'kotlin-stdlib.jar', 'gate.properties', 'owner.properties', 'inner.properties', 'host-runtime'}
    if control == 'inaccessible-owned':
        inventory.add('witness.properties')
    require(set(path.name for path in islice(directory.iterdir(), 8)) == inventory, 'retained closure inventory refused')
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


def trusted_native_policy(path):
    raw = read(path, 16384).decode('ascii')
    require(raw.endswith('\n') and '\\' not in raw, 'native policy encoding refused')
    rows = [line.split('=', 1) for line in raw.splitlines()]
    require(all(len(row) == 2 for row in rows), 'native policy row refused')
    result = pairs(rows)
    expected = {'schemaVersion', 'platform', 'relativeDirectory'} | {
        prefix + '.' + key for prefix in ('jna', 'sqlite') for key in ('artifact', 'artifactSha256', 'resource', 'name', 'bytes', 'sha256')}
    require(set(result) == expected and result['schemaVersion'] == '1' and result['platform'] == 'linux-x86-64' and
            result['relativeDirectory'] == 'lib/decomp-oracle-native' and result['jna.artifact'] == 'jna-5.19.1.jar',
            'existing native runtime policy shape refused')
    return result


def host_class_identity(data):
    require(24 <= len(data) <= 1024 * 1024, 'host class size refused')
    cursor = 0
    def take(n):
        nonlocal cursor
        require(type(n) is int and 0 <= n <= len(data) - cursor, 'truncated host class')
        result = data[cursor:cursor+n]; cursor += n
        return result
    def u1(): return take(1)[0]
    def u2(): return struct.unpack('>H', take(2))[0]
    def u4(): return struct.unpack('>I', take(4))[0]
    require(u4() == 0xcafebabe, 'host class magic refused')
    u2(); require(u2() >= 45, 'host class version refused')
    count = u2(); require(count > 1, 'host class pool empty')
    strings, classes = {}, {}
    index = 1
    while index < count:
        tag = u1()
        if tag == 1: strings[index] = take(u2())
        elif tag in (3, 4): take(4)
        elif tag in (5, 6):
            take(8); index += 1
            require(index < count, 'host class wide constant refused')
        elif tag == 7: classes[index] = u2()
        elif tag in (8, 16, 19, 20): take(2)
        elif tag in (9, 10, 11, 12, 17, 18): take(4)
        elif tag == 15: take(3)
        else: require(False, 'host class constant refused')
        index += 1
    def utf(i):
        require(i in strings, 'host class UTF index refused')
        return strings[i].decode('ascii')
    def attributes():
        result = []
        for _ in range(u2()):
            name = utf(u2()); value = take(u4()); result.append((name, value))
        return result
    u2(); this_class = u2(); u2()
    require(this_class in classes, 'host class identity absent')
    for _ in range(u2()): u2()
    for _ in range(2):
        for _ in range(u2()): take(6); attributes()
    source = [value for name, value in attributes() if name == 'SourceFile']
    require(len(source) == 1 and len(source[0]) == 2 and cursor == len(data), 'host class source binding absent')
    return utf(classes[this_class]), utf(struct.unpack('>H', source[0])[0])


def host_current_entries(root):
    entries = {}
    for source_set, by_source in HOST_RUNTIME_ROOTS.items():
        directory = root / ('build/classes/kotlin/' + source_set + '/decompengine/acp')
        require(directory.resolve(strict=True) == directory, 'host compiled directory noncanonical')
        paths = sorted(islice(directory.glob('*.class'), 8193))
        require(len(paths) <= 8192, 'host compiled directory oversized')
        for path in paths:
            matches = [source for source, roots in by_source.items() if any(
                path.name == name + '.class' or path.name.startswith(name + '$') for name in roots)]
            require(len(matches) <= 1, 'ambiguous host class source')
            if not matches: continue
            key = 'decompengine/acp/' + path.name
            value = read(path, 1024 * 1024)
            require(host_class_identity(value) == (key[:-6], matches[0]), 'compiled host class/source generation mismatch')
            require(key not in entries, 'duplicate host runtime class')
            entries[key] = value
            require(len(entries) <= 256 and sum(map(len, entries.values())) <= 16 * 1024**2, 'host runtime class bound exceeded')
        require(all('decompengine/acp/' + name + '.class' in entries for roots in by_source.values() for name in roots),
                'host runtime dependency missing')
    return entries


def ordered_hash(rows):
    return hashlib.sha256('\0'.join(rows).encode('utf-8')).hexdigest()


def verify_host_runtime(root, directory, receipt, runtime):
    host = directory / 'host-runtime'
    require(host.resolve(strict=True) == host and not host.is_symlink(), 'host runtime directory noncanonical')
    names = HOST_ARTIFACTS + ('host-runtime-observed.properties',)
    require(set(path.name for path in islice(host.iterdir(), 7)) == set(names), 'host runtime artifact inventory refused')
    metadata = properties(host / 'host-runtime.properties')
    require(set(metadata) == set(HOST_SOURCE_PATHS) | {'schema', 'kotlinCoordinates', 'jnaCoordinates', 'stdlibSha256',
            'jnaJarSha256', 'jniDispatchSha256', 'hostClassesSha256', 'bytecodeClosureSha256', 'sourceGenerationSha256'},
            'host runtime metadata shape refused')
    require(metadata['schema'] == '2' and metadata['kotlinCoordinates'] == 'org.jetbrains.kotlin:kotlin-stdlib:2.4.0' and
            metadata['jnaCoordinates'] == 'net.java.dev.jna:jna:5.19.1', 'host resolved coordinates refused')
    sources = {key: digest(root / path, 1024 * 1024) for key, path in HOST_SOURCE_PATHS.items()}
    require(all(metadata[key] == value for key, value in sources.items()) and metadata['sourceGenerationSha256'] ==
            ordered_hash([key + ':' + value for key, value in sorted(sources.items())]), 'host source generation mismatch')
    entries = host_current_entries(root)
    import io
    control = read(host / 'host-control.jar', 16 * 1024**2)
    with zipfile.ZipFile(io.BytesIO(control)) as archive:
        infos = archive.infolist()
        require(len(infos) <= 256 and len(infos) == len({x.filename for x in infos}) and
                {x.filename for x in infos} == set(entries), 'host runtime missing/extra/duplicate class')
        require(all(not x.is_dir() and x.compress_type in (0, 8) and not x.flag_bits & 1 and 0 < x.file_size <= 1024 * 1024 for x in infos),
                'host runtime class ZIP metadata refused')
        require(sum(x.file_size for x in infos) <= 16 * 1024**2, 'host class archive expansion refused')
        for info in infos:
            require(archive.read(info) == entries[info.filename], 'executed host class differs from current compilation')
    require(hashlib.sha256(control).hexdigest() == metadata['hostClassesSha256'] and metadata['bytecodeClosureSha256'] ==
            ordered_hash([key + ':' + hashlib.sha256(value).hexdigest() for key, value in sorted(entries.items())]),
            'host compiled bytecode closure mismatch')
    for name, resolved, field in [('kotlin-stdlib.jar', runtime['stdlib'], 'stdlibSha256'), ('jna.jar', runtime['jna'], 'jnaJarSha256'),
                                  ('libjnidispatch.so', root / 'build/native/oracle/libjnidispatch.so', 'jniDispatchSha256')]:
        require(resolved.resolve(strict=True) == resolved and not resolved.is_symlink(), 'host resolved runtime noncanonical')
        actual = read(host / name, 8 * 1024**2)
        require(actual == read(resolved, 8 * 1024**2) and hashlib.sha256(actual).hexdigest() == metadata[field], 'host resolved runtime byte mismatch')
    policy = trusted_native_policy(root / 'src/main/resources/oracle-native-libraries-v1.properties')
    require(metadata['jnaJarSha256'] == policy['jna.artifactSha256'] and metadata['jniDispatchSha256'] == policy['jna.sha256'],
            'host JNI runtime differs from authenticated existing policy')
    observed = properties(host / 'host-runtime-observed.properties')
    require(set(observed) == {'schema', 'loadedClassOriginsVerified', 'fixedJnaSelectionVerified', 'jniMappingCount', 'jniDevice', 'jniInode', 'jniMappingSha256'} and
            observed['schema'] == '2' and observed['loadedClassOriginsVerified'] == observed['fixedJnaSelectionVerified'] == 'true',
            'actual loaded host origin/JNI selection missing')
    number(observed, 'jniMappingCount', 1, 16)
    boot_dispatch = root / 'build/provider-dns/host-runtime/libjnidispatch.so'
    require(read(boot_dispatch, 1024 * 1024) == read(host / 'libjnidispatch.so', 1024 * 1024), 'actual boot JNI bytes changed')
    boot_identity = boot_dispatch.lstat()
    require(number(observed, 'jniDevice') == boot_identity.st_dev and number(observed, 'jniInode', 1) == boot_identity.st_ino,
            'observed loaded JNI file identity differs from actual fixed boot selection')
    require(re.fullmatch(r'[0-9a-f]{64}', observed['jniMappingSha256']), 'JNI mapping digest refused')
    require(receipt['hostRuntimeManifestSha256'] == digest(host / 'host-runtime.properties', 16384) and
            receipt['hostRuntimeClassesSha256'] == metadata['hostClassesSha256'] and
            receipt['hostRuntimeGenerationSha256'] == metadata['sourceGenerationSha256'] and
            receipt['hostRuntimeJnaSha256'] == metadata['jnaJarSha256'] and receipt['hostRuntimeJniSha256'] == metadata['jniDispatchSha256'] and
            receipt['hostRuntimeJniMappingSha256'] == observed['jniMappingSha256'] and receipt['hostRuntimeClosureSha256'] ==
            ordered_hash([name + ':' + digest(host / name, 16 * 1024**2) for name in names]), 'host runtime receipt commitment mismatch')
    payload = compiled_control_entries(root)
    require(len(entries) + len(payload) + len(names) <= 256 and sum(map(len, entries.values())) + sum(map(len, payload.values())) +
            (directory / 'kotlin-stdlib.jar').stat().st_size + sum((host / name).stat().st_size for name in names if name != 'host-control.jar') <= 16 * 1024**2,
            'shared payload/host closure bounds exceeded')


def number(fields, key, minimum=0, maximum=2**63 - 1):
    value = fields.get(key)
    require(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}', value) is not None,
            'owned-domain integer refused')
    parsed = int(value)
    require(minimum <= parsed <= maximum, 'owned-domain integer bound refused')
    return parsed



def verify_owned(qualification, directory, evidence_case, case, control, run_id, receipt, expected, runtime):
    domain_path = qualification / (evidence_case + '-owned.properties')
    domain = properties(domain_path)
    gate = properties(directory / 'gate.properties')
    terminal = properties(directory / 'owner.properties')
    inner = properties(directory / 'inner.properties')
    require(digest(domain_path, 16384) == receipt['ownedDomainSha256'], 'domain commitment mismatch')
    for name, field in [('gate.properties', 'ownedGateSha256'), ('owner.properties', 'ownedTerminalSha256'),
                        ('inner.properties', 'ownedInnerSha256')]:
        require(digest(directory / name, 16384) == receipt[field], 'native retained record commitment mismatch')
    domain_keys = set('''schema caseName control unit cgroupIdentitySha256 directHostPid directStart pidsMax memoryMax
memorySwapMax memoryOomGroup runtimeMaxMicros timeoutStopMicros cpuQuota cpuPeriod nproc fixedRlimitsVerified
startedNanos executionEndNanos cleanupEndNanos firstGateObservedNanos scopeBoundObservedNanos secondGateObservedNanos
procDevice procInode procMountId mountClosureSha256 privateProcBound nonEscapeVerified bootstrapNamespaceReferenceCount
bootstrapFdLedgerSha256 hostNamespaceReferenceCount nativeNamespaceReferenceCount pid1HostPid pid1HostStart pid1InnerStart pid1InnerPid
hostPidNsDevice hostPidNsInode escapeCanariesPassed firstGateHeld secondGateHeld pidDevice pidInode userDevice userInode
netDevice netInode mntDevice mntInode payloadReleased payloadReleaseNanos rootReapedObservedNanos payloadTerminalObservedNanos
nativeEchild nativeReferencesClosed scopeAbsentObservedNanos hostStateUnchanged streamsClosedObservedNanos rootReaped
scopeAbsent streamsJoinedClosed referencesClosed referencesClosedObservedNanos observationTimely observedEndNanos cleanupVerified
runId testSourceSha256 helperSourceSha256 workerJarSha256 controlRuntimeClosureSha256 ownedContractSourceSha256
hostRuntimeClosureSha256 hostRuntimeManifestSha256 hostRuntimeClassesSha256 hostRuntimeGenerationSha256 hostRuntimeJnaSha256 hostRuntimeJniSha256 hostRuntimeJniMappingSha256 hostContextSha256
normalReferencesClosed normalReferenceClosedCount normalHandlesClosedObservedNanos pairedCleanPredicate pairedCleanObservedNanos scopeKillAttempted scopeRemovedBeforeSignal scopeKillRemovedDuringSignal
scopeBackendSourceSha256 scopeFilesystemSourceSha256 scopeSupervisorSha256 scopeInspectorSha256 hostUid hostObserverScans hostObserverWork hostObserverPids hostObserverBytes'''.split())
    extras = {'retainedReferenceRefused', 'retainedReferenceObservedNanos', 'retainedReferenceOnlyOpen',
              'retainedReferenceDevice', 'retainedReferenceInode', 'retainedReferenceMountId'} if control == 'retained-reference' else (
        {'possibleOwnedVisibilityRefused', 'witnessInnerPid', 'witnessPidNamespaceInode'} if control == 'inaccessible-owned' else set())
    require(set(domain) == domain_keys | extras, 'domain keys missing/extra')
    for fields in (domain, gate, terminal):
        require(fields['schema'] == '2' and fields['caseName'] == case and fields['control'] == control,
                'owned-domain generation/case mismatch')
    require(domain['runId'] == run_id and re.fullmatch(r'dns-fixture-[a-f0-9-]{36}\.scope', domain['unit']),
            'owned-domain freshness refused')
    for field in ('testSourceSha256', 'helperSourceSha256', 'workerJarSha256', 'controlRuntimeClosureSha256',
                  'ownedContractSourceSha256', 'scopeBackendSourceSha256', 'scopeFilesystemSourceSha256', 'hostRuntimeClosureSha256', 'hostRuntimeManifestSha256', 'hostRuntimeClassesSha256',
                  'hostRuntimeGenerationSha256', 'hostRuntimeJnaSha256', 'hostRuntimeJniSha256', 'hostRuntimeJniMappingSha256', 'hostContextSha256'):
        require(domain[field] == receipt[field], 'domain source/runtime binding mismatch')
    require(domain['cgroupIdentitySha256'] == receipt['ownedScopeIdentitySha256'], 'scope identity commitment mismatch')
    for field in ('cgroupIdentitySha256', 'mountClosureSha256', 'bootstrapFdLedgerSha256', 'scopeSupervisorSha256', 'scopeInspectorSha256'):
        require(re.fullmatch(r'[0-9a-f]{64}', domain[field]), 'domain hash malformed')
    require(domain['scopeSupervisorSha256'] == digest(Path('/usr/bin/systemd-run')) and
            domain['scopeInspectorSha256'] == digest(Path('/usr/bin/systemctl')), 'observed scope executable changed')
    number(domain, 'hostUid', 0, 2**32 - 1)
    for key in '''fixedRlimitsVerified privateProcBound nonEscapeVerified escapeCanariesPassed firstGateHeld secondGateHeld
payloadReleased nativeEchild nativeReferencesClosed hostStateUnchanged rootReaped scopeAbsent streamsJoinedClosed
referencesClosed observationTimely cleanupVerified normalReferencesClosed pairedCleanPredicate'''.split():
        require(domain[key] == 'true', 'owned-domain cleanup/admission fact absent')
    if control == 'retained-reference':
        require(domain['retainedReferenceRefused'] == domain['retainedReferenceOnlyOpen'] == 'true', 'sole held reference did not prevent qualification')
        require(number(domain, 'retainedReferenceDevice') == number(domain, 'netDevice') and
                number(domain, 'retainedReferenceInode', 1) == number(domain, 'netInode', 1), 'held reference is not the declared exact net namespace')
        number(domain, 'retainedReferenceMountId', 1)
    if control == 'inaccessible-owned':
        require(domain['possibleOwnedVisibilityRefused'] == 'true', 'inaccessible owned member not fatal')
    for field, value in {'pidsMax': 32, 'memoryMax': 2147483648, 'memorySwapMax': 0,
                         'runtimeMaxMicros': 33000000, 'timeoutStopMicros': 3000000}.items():
        require(number(domain, field) == value, 'existing cgroup limit mismatch')
    require(domain['memoryOomGroup'] == 'true' and number(domain, 'cpuQuota', 1) == number(domain, 'cpuPeriod', 1),
            'cgroup OOM/CPU limit mismatch')
    for key, bound in {'hostObserverScans': 128, 'hostObserverWork': 32768, 'hostObserverPids': 16384, 'hostObserverBytes': 33554432}.items():
        number(domain, key, 0, bound)
    require(number(domain, 'normalReferenceClosedCount') == 5 and domain['scopeKillAttempted'] in ('true', 'false') and
            domain['scopeRemovedBeforeSignal'] in ('true', 'false') and
            domain['scopeKillRemovedDuringSignal'] in ('true', 'false') and
            (domain['scopeKillRemovedDuringSignal'] == 'false' or domain['scopeKillAttempted'] == 'true') and
            (domain['scopeKillAttempted'] == 'true' or domain['scopeRemovedBeforeSignal'] == 'true'), 'acquired-domain cleanup/reference evidence absent')
    nproc = number(domain, 'nproc', 32, 2**31 - 1)
    gate_keys = set('''schema caseName control innerPid innerStart activeCapabilitiesZero boundingMask noNewPrivileges seccomp
escapeCanariesPassed privateProcOnlyPid1 nproc nofile fsize as cpu core pidDev pidIno userDev userIno netDev netIno mntDev mntIno
procDev procIno procMountId'''.split())
    require(set(gate) == gate_keys, 'native gate shape refused')
    require(gate['innerPid'] == '1' and gate['boundingMask'] == '1400' and gate['seccomp'] == '2', 'native gate identity/filter refused')
    for key in ('activeCapabilitiesZero', 'noNewPrivileges', 'escapeCanariesPassed', 'privateProcOnlyPid1'):
        require(gate[key] == 'true', 'native escape/capability control absent')
    for key, value in {'nproc': nproc, 'nofile': 128, 'fsize': 67108864, 'as': 2147483648, 'cpu': 120, 'core': 0}.items():
        require(number(gate, key) == value, 'native rlimit mismatch')
    for kind in ('pid', 'user', 'net', 'mnt'):
        require(number(gate, kind + 'Dev') == number(domain, kind + 'Device') and
                number(gate, kind + 'Ino', 1) == number(domain, kind + 'Inode', 1), 'namespace identity mismatch')
    require((number(domain, 'hostPidNsDevice'), number(domain, 'hostPidNsInode', 1)) !=
            (number(domain, 'pidDevice'), number(domain, 'pidInode', 1)), 'host/inner PID coordinate conflation')
    require(number(domain, 'directHostPid', 1, 2**32 - 1) != number(domain, 'pid1HostPid', 1, 2**32 - 1) and
            number(domain, 'pid1InnerPid') == 1, 'host root/PID1 projection refused')
    number(domain, 'directStart')
    require(number(domain, 'pid1HostStart') == number(domain, 'pid1InnerStart') == number(gate, 'innerStart'),
            'host/private PID1 start identity mismatch')
    for suffix in ('Device', 'Inode', 'MountId'):
        require(number(domain, 'proc' + suffix, 0 if suffix == 'Device' else 1) ==
                number(gate, 'proc' + ('Dev' if suffix == 'Device' else 'Ino' if suffix == 'Inode' else suffix),
                       0 if suffix == 'Device' else 1), 'private proc mount binding mismatch')
    require(number(domain, 'hostNamespaceReferenceCount') == (6 if control == 'retained-reference' else 5) and
            number(domain, 'nativeNamespaceReferenceCount') == 6 and
            number(domain, 'bootstrapNamespaceReferenceCount', 0, 5) + number(domain, 'hostNamespaceReferenceCount') + 6 <= 16,
            'reference inventory exceeds unchanged capacity')
    start = number(domain, 'startedNanos'); execution_end = number(domain, 'executionEndNanos')
    cleanup_end = number(domain, 'cleanupEndNanos')
    require(start < execution_end < cleanup_end and cleanup_end - start <= 30000000000 and
            cleanup_end - execution_end == 5000000000, 'original deadline vector changed')
    prior = start
    for key in '''firstGateObservedNanos scopeBoundObservedNanos secondGateObservedNanos payloadReleaseNanos
rootReapedObservedNanos payloadTerminalObservedNanos'''.split():
        observed = number(domain, key)
        require(prior <= observed < execution_end, 'late/out-of-order admission/terminal observation')
        prior = observed
    for key in ('scopeAbsentObservedNanos', 'streamsClosedObservedNanos', 'normalHandlesClosedObservedNanos', 'pairedCleanObservedNanos', 'referencesClosedObservedNanos', 'observedEndNanos'):
        observed = number(domain, key)
        require(prior <= observed < cleanup_end, 'late/out-of-order cleanup observation')
        prior = observed
    if control == 'retained-reference':
        require(number(domain, 'normalHandlesClosedObservedNanos') <= number(domain, 'retainedReferenceObservedNanos') <=
                number(domain, 'pairedCleanObservedNanos'), 'reference denial not observed before reference release')
    require(set(terminal) == set('''schema caseName control innerPid childInnerPid childRawStatus childReaped finalEchild
ownedChildrenZero privateProcOnlyPid1 fixedReferencesClosed blackholeJoined queryCount queryType observerScans observerWork observerPids observerBytes
negativeObserved negativeInnerPid primaryFailure'''.split()), 'native terminal shape refused')
    require(terminal['innerPid'] == '1' and number(terminal, 'childInnerPid', 2) > 1 and terminal['childRawStatus'] == '0',
            'native child coordinate/termination refused')
    for key in ('childReaped', 'finalEchild', 'ownedChildrenZero', 'privateProcOnlyPid1', 'fixedReferencesClosed', 'blackholeJoined'):
        require(terminal[key] == 'true', 'native exhaustive cleanup absent')
    for key, bound in {'observerScans': 128, 'observerWork': 32768, 'observerPids': 16384, 'observerBytes': 33554432}.items():
        number(terminal, key, 0, bound)
    require(number(terminal, 'queryCount', 1, 64) == receipt['queryCount'] and
            number(terminal, 'queryType') == receipt['queryType'], 'actual query binding mismatch')
    is_child_negative = control in ('retained-child', 'inaccessible-owned')
    require(terminal['negativeObserved'] == str(is_child_negative).lower() and
            terminal['primaryFailure'] == ('POSSIBLE_OWNED_VISIBILITY' if control == 'inaccessible-owned' else
                                           'RETAINED_OWNED_CHILD' if control == 'retained-child' else 'NONE'),
            'negative primary refusal mismatch')
    negative_pid = number(terminal, 'negativeInnerPid')
    require((2 <= negative_pid != number(terminal, 'childInnerPid')) if is_child_negative else negative_pid == 0,
            'negative owned child coordinate absent')
    inner_keys = set('''caseName workerJarSha256 childPid realQueryObserved nativeBuiltinWorker childReaped ownerJoined streamsClosed
noAddressAdmitted noConnectAdmitted workerCapabilitiesZero innerBoundingMask workerBoundingMask innerNoNewPrivileges workerNoNewPrivileges'''.split())
    require(set(inner) == inner_keys and inner['caseName'] == case and inner['workerJarSha256'] == expected['workerJarSha256'] and
            number(inner, 'childPid', 2) == receipt['childPid'], 'inner worker coordinate/source refused')
    require(inner['innerBoundingMask'] == inner['workerBoundingMask'] == '1400', 'inner bounding capabilities mismatch')
    require(all(inner[key] == 'true' for key in inner_keys - {'caseName', 'workerJarSha256', 'childPid', 'innerBoundingMask', 'workerBoundingMask'}),
            'inner cleanup/capability fact absent')
    if control == 'inaccessible-owned':
        witness = properties(directory / 'witness.properties')
        known = set('schema pid callerPid kind phase callerUid callerGid targetUid targetGid startBefore startAfter namespaceRead'.split())
        unknown = set('schema pid callerPid kind phase namespaceRead identity'.split())
        require(set(witness) in (known, unknown) and witness['schema'] == '2' and witness['callerPid'] == '1' and
                witness['kind'] == 'net' and witness['phase'] == 'OUTER_CLEANUP' and witness['namespaceRead'] == 'ACCESS_DENIED',
                'actual inaccessible-owned witness absent')
        require(number(witness, 'pid', 2) == negative_pid == number(domain, 'witnessInnerPid', 2) and
                number(domain, 'witnessPidNamespaceInode') == number(domain, 'pidInode'), 'witness inner coordinate mismatch')
        if set(witness) == known:
            tuples = []
            for key in ('callerUid', 'callerGid', 'targetUid', 'targetGid'):
                require(re.fullmatch(r'[0-9]{1,10}(,[0-9]{1,10}){3}', witness[key]), 'witness credentials malformed')
                values = [int(x) for x in witness[key].split(',')]
                require(all(x <= 2**32 - 1 for x in values), 'witness credentials oversized')
                tuples.append(set(values))
            require(number(witness, 'startBefore') == number(witness, 'startAfter') and
                    (tuples[0] & tuples[2] or tuples[1] & tuples[3]), 'stable overlap witness invalid')
        else:
            require(witness['identity'] == 'UNAVAILABLE', 'unknown witness must remain unqualified')


CONTEXT_ENVIRONMENT_KEYS = ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_WORKFLOW_REF', 'GITHUB_SHA', 'GITHUB_EVENT_NAME',
                            'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_ENVIRONMENT', 'RUNNER_NAME', 'ImageOS', 'ImageVersion')

def verify_context(qualification, evidence_case, receipt):
    path = qualification / (evidence_case + '-host-context.properties')
    context = properties(path)
    require(set(context) == {'schema', 'role', 'testTaskHex', 'maxParallelForks', 'forkEvery', 'junitParallelEnabled'} |
            {'context' + str(i) + 'Hex' for i in range(len(CONTEXT_ENVIRONMENT_KEYS))}, 'host correlation context shape refused')
    require(context['schema'] == '2' and context['role'] == 'CORRELATION_ONLY_UNQUALIFIED' and
            context['testTaskHex'] == ':test'.encode('ascii').hex() and context['maxParallelForks'] == '1' and
            context['forkEvery'] == '0' and context['junitParallelEnabled'] == 'false', 'effective native scheduler/context missing')
    observed = {}
    for i, key in enumerate(CONTEXT_ENVIRONMENT_KEYS):
        value = context['context' + str(i) + 'Hex']
        if value == 'UNAVAILABLE': decoded = None
        else:
            require(re.fullmatch(r'[0-9a-f]{2,512}', value) is not None and len(value) % 2 == 0, 'host context encoding refused')
            decoded = bytes.fromhex(value).decode('ascii')
            require(all(32 <= ord(c) <= 126 for c in decoded), 'host context character refused')
        require(decoded == os.environ.get(key), 'host correlation context changed between test and replay')
        observed[key] = decoded
    require(receipt['hostContextSha256'] == digest(path, 16384), 'host context commitment mismatch')
    return {'role': 'CORRELATION_ONLY_UNQUALIFIED', 'environment': observed,
            'effectiveNativeScheduling': {'testTask': ':test', 'maxParallelForks': 1, 'forkEvery': 0, 'junitParallelEnabled': False},
            'sha256': receipt['hostContextSha256']}


def verify(root: Path, run_id: str, runtime: dict[str, Path]) -> dict:
    require(re.fullmatch(r'[A-Za-z0-9-]{1,80}', run_id) is not None, 'invalid run identifier')
    root = root.resolve(strict=True)
    qualification = root / 'build/provider-dns-native-qualification'
    require(qualification.resolve(strict=True) == qualification, 'noncanonical qualification directory')
    summaries = []
    observed_context = None
    report_hashes = {}
    native_suites = {}
    reports = sorted((root / 'build/test-results/test').glob('TEST-*.xml'))
    require(0 < len(reports) <= 512, 'missing/oversized XML inventory')
    for path in reports:
        data = read(path, 16 * 1024 * 1024)
        require(b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(), 'XML declarations refused')
        suite = ET.fromstring(data)
        matching = [node for node in suite.iter('testsuite') if node.attrib.get('name') in (SUITE, NEGATIVE_SUITE)]
        if matching:
            require(suite.tag == 'testsuite' and matching == [suite], 'nested/duplicate native XML suite')
            require(suite.attrib['name'] not in native_suites, 'duplicate native suite')
            native_suites[suite.attrib['name']] = suite
            report_hashes[path.name] = hashlib.sha256(data).hexdigest()
    require(set(native_suites) == {SUITE, NEGATIVE_SUITE}, 'missing native positive/negative suite')
    for suite_name, expected_names in [(SUITE, CASES.values()), (NEGATIVE_SUITE, NEGATIVES.values())]:
        suite = native_suites[suite_name]
        expected_names = set(expected_names)
        for field, value in [('tests', str(len(expected_names))), ('failures', '0'), ('errors', '0'), ('skipped', '0')]:
            require(suite.attrib.get(field) == value, 'native XML count/failure/skip refused')
        names = []
        for case in suite.iter('testcase'):
            require(case.attrib.get('classname') == suite_name and not any(case.find(k) is not None for k in
                    ('failure', 'error', 'skipped')), 'native testcase failure/type refused')
            name = case.attrib.get('name', '')
            names.append(name[:-2] if name.endswith('()') else name)
        require(len(names) == len(expected_names) and set(names) == expected_names, 'missing/duplicate/extra native testcase')
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
        'testSourceSha256': digest(test_source, 1024 * 1024),
        'ownedContractSourceSha256': digest(root / 'src/test/kotlin/decompengine/acp/NativeDnsOwnedDomainContract.kt', 65536),
        'scopeBackendSourceSha256': digest(root / 'src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt', 1024 * 1024),
        'scopeFilesystemSourceSha256': digest(root / 'src/main/kotlin/decompengine/acp/LinuxFilesystemSyscalls.kt', 1024 * 1024), 'helperSourceSha256': digest(source, 65536),
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
                                        'workerBoundingMask', 'queryCount', 'queryType', 'childPid', 'namespaceDeduction', 'executorContract'])
    for evidence_case in list(CASES) + list(NEGATIVES):
        control = 'positive' if evidence_case in CASES else evidence_case
        case = evidence_case if control == 'positive' else 'cancel'
        receipt_path = qualification / (evidence_case + '.json')
        receipt = load_json(receipt_path)
        require(set(receipt) == required | (set() if control == 'positive' else {'negativeControl', 'qualificationRefused'}), 'receipt keys missing/extra')
        if control != 'positive':
            require(receipt['negativeControl'] == control and receipt['qualificationRefused'] is True, 'negative control did not refuse')
        require(type(receipt['schemaVersion']) is int and receipt['schemaVersion'] == 2 and
                receipt['caseName'] == case and receipt['runId'] == run_id, 'receipt schema/case/freshness mismatch')
        require(all(receipt[k] is True for k in FACTS), 'receipt required owned observation missing/false')
        require(receipt['namespaceDeduction'] == 'CONDITIONAL' and receipt['executorContract'] == 'required-contract-hosted-ubuntu24-v1',
                'unconditional or unspecified namespace deduction refused')
        require(receipt['innerBoundingMask'] == receipt['workerBoundingMask'] == '1400', 'capability bounding mask mismatch')
        require(all(type(receipt[k]) is str and re.fullmatch(r'[0-9a-f]{64}', receipt[k]) for k in HASH_FIELDS),
                'receipt hash format refused')
        require(all(receipt[k] == value for k, value in expected.items()), 'receipt source/artifact hash mismatch')
        directory = qualification / (evidence_case + '-' + run_id + '-closure')
        closure = verify_control_closure(root, directory, runtime['stdlib'], control)
        require(receipt['controlRuntimeClosureSha256'] == closure, 'receipt control closure mismatch')
        require(type(receipt['queryCount']) is int and 1 <= receipt['queryCount'] <= 64 and
                type(receipt['queryType']) is int and receipt['queryType'] in (1, 28) and
                type(receipt['childPid']) is int and receipt['childPid'] > 0, 'query/child facts refused')
        context = verify_context(qualification, evidence_case, receipt)
        require(observed_context is None or observed_context == context, "mixed host context/scheduling across cases")
        observed_context = context
        verify_host_runtime(root, directory, receipt, runtime)
        verify_owned(qualification, directory, evidence_case, case, control, run_id, receipt, expected, runtime)
        private_tree = qualification / (evidence_case + '-' + run_id)
        require(not private_tree.exists() and not private_tree.is_symlink(), 'private qualification tree remains')
        summaries.append({'receiptSha256': digest(receipt_path, MAX_JSON), 'receipt': receipt})
    return {'schemaVersion': 2, 'runId': run_id, 'status': 'OWNED_OBSERVATIONS_VERIFIED_UNQUALIFIED', 'nativeSuites': [SUITE, NEGATIVE_SUITE],
            'scope': 'stage1-owned-observations-only; independent supported-host/service-job join unavailable',
            'namespaceConclusion': {'kind': 'CONDITIONAL', 'executorContract': 'required-contract-hosted-ubuntu24-v1',
                                    'qualification': 'UNAVAILABLE_PENDING_INDEPENDENT_SERVICE_JOB_JOIN'},
            'requiredIndependentJoin': ['service run/attempt/job/check/workflow/event/checkout',
                'actual hosted runner/image/resolved actions and reviewed job/runtime generation',
                'fresh same-job UUID/artifact/XML; real2positive3negative/paired canaries; timely owned facts',
                'independent supported-executor review under the explicit TCB/no-external-holder assumption'],
            'checkerSha256': digest(Path(__file__), 1024 * 1024),
            'xmlSha256': report_hashes, 'sourceAndArtifactSha256': expected, 'observedContext': observed_context,
            'reference': metadata, 'cases': summaries, 'realProviderQualified': False, 'supportedFixtureHostQualified': False,
            'trustedExecutorNoExternalHoldersRequired': True, 'releaseQualified': False}

def main():
    require(len(sys.argv) == 4, 'invoke the trusted verifyProviderDnsNativeQualification Gradle task')
    run_id = sys.argv[1]
    require('JAVA_HOME' in os.environ, 'JAVA_HOME is required for runtime binding')
    root = Path(__file__).resolve().parents[1]
    runtime = {'javaHome': Path(os.environ['JAVA_HOME']), 'bwrap': Path('/usr/bin/bwrap'),
               'env': Path('/usr/bin/env'), 'compiler': Path('/usr/bin/cc'), 'linker': Path('/usr/bin/ld'),
               'stdlib': Path(sys.argv[2]), 'jna': Path(sys.argv[3])}
    summary = verify(root, run_id, runtime)
    output = root / 'build/provider-dns-native-qualification/gate-summary.json'
    pending = output.with_suffix('.json.pending')
    require(not pending.exists() and not pending.is_symlink() and not output.is_symlink(), 'unsafe summary destination')
    data = (json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')
    with pending.open('xb') as handle:
        handle.write(data)
    pending.replace(output)
    print(json.dumps({'status': summary['status'], 'runId': run_id, 'summarySha256': hashlib.sha256(data).hexdigest()}, sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except (Invalid, OSError, ValueError, KeyError, RecursionError, ET.ParseError, zipfile.BadZipFile):
        print('native DNS qualification verification failed', file=sys.stderr)
        raise SystemExit(1)
