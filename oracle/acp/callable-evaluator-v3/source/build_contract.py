"""Closed v3 command/limit contract; import and profile loading never launch tools."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
import re

BASE = Path(__file__).resolve().parent
PROFILE_PATH = BASE / 'contracts/candidate-build-profile.json'
MAXIMUM_PROFILE_BYTES = 65536
MAXIMUM_VISIBLE_BYTES = 131072

# Reviewed immutable commands, environment, bounds and isolation. Dynamic toolchain pins are
# separately authenticated by the preparation; native argv/flags are unchanged from aab1938d.
_IMMUTABLE = json.loads(r'''{"schemaVersion":3,"target":"x86_64 SysV AMD64 ELF LP64; C11; GCC; no LTO, external libraries, injected headers or export scripts","environment":{"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","TMPDIR":"/tmp"},"commands":{"preprocess":["/usr/bin/gcc","-E","-P","-std=c11","/work/candidate.c","-o","/work/candidate.i"],"compile":["/usr/bin/gcc","-std=c11","-O2","-fPIC","-g","-Wall","-Wextra","-Werror","-fno-fast-math","-ffp-contract=off","-fvisibility=default","-c","/work/candidate.i","-o","/work/candidate.o"],"link":["/usr/bin/gcc","-shared","-Wl,-z,relro,-z,now,-z,noexecstack,--no-undefined","/work/candidate.o","-o","/work/libcandidate.so"]},"exports":"Provide external function definitions acp_mix acp_pair_scale acp_update acp_apply acp_fold and writable object acp_state. Ordinary external definitions have default public visibility.","bounds":{"memoryBytes":536870912,"swapBytes":0,"tasks":32,"compilerSeconds":30,"runtimeSeconds":5,"outputBytesPerStream":65536,"sourceBytes":262144,"virtualAddressSpaceBytes":2147483648,"cpuSeconds":30,"helperOutputBytesPerStream":1048576,"elfInspectionSeconds":10,"coreBytes":0,"openFiles":64,"fileSizeBytes":16777216,"probeSeconds":30,"callerBuildSeconds":30,"helperBuildSeconds":60,"toolchainInspectionSeconds":10,"stdinBytes":4096,"cleanupWaitSeconds":5,"cleanupVerificationSeconds":5,"selectorPollSeconds":0.1,"cleanupPollSeconds":0.02,"scopeAdmissionSeconds":5,"scopeAdmissionPollSeconds":0.01,"temporaryFilesystemBytes":16777216,"helperInputBytes":262144,"helperGraphNodes":4096,"helperGraphDepth":64,"defaultWallSeconds":15,"captureReadBytes":8192,"waitFloorSeconds":0.001},"analysisIsolation":{"engine":"bubblewrap","namespaces":"unshare-all","capabilities":"none","environment":{"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","TMPDIR":"/tmp","LD_LIBRARY_PATH":"/usr/lib/gcc/x86_64-pc-linux-gnu/16:/usr/lib/llvm/23/lib64"},"readOnlySystemMounts":["/usr","/lib","/lib64"],"readOnlyHelper":"/probe","readOnlyOwnedSourceWork":"/work","sourceArgument":"/work/<relative-source-path>","expectedSourceWork":"separate trusted fixture clone; never mapped into candidate probe","temporaryFilesystem":{"path":"/tmp","bytes":16777216},"hostPathsOutsideMounts":"inaccessible"},"limitSemantics":{"cpuSeconds":"RLIMIT_CPU soft=hard per process; not aggregate cgroup CPU","aggregateCgroupCpuLimit":null,"aggregateCgroupCpuLimitEnforced":false,"resourceLimits":"soft=hard; units are bytes, seconds or descriptor count as named","streamOutput":"independent cap for stdout and stderr; excess makes capture incomplete","cleanup":"wait and subsequent absence-verification each have a distinct 5-second ceiling","helperBuild":"60-second wall supervisor bound; the same 30-second per-process CPU RLIMIT still applies"},"limitAudit":[{"phase":"all-launches","source":"bounded_runtime.py:process_limits","keys":["coreBytes","cpuSeconds","virtualAddressSpaceBytes","openFiles","fileSizeBytes"],"scope":"per-process RLIMITs"},{"phase":"managed-scope","source":"bounded_runtime.py:bounded_run","keys":["tasks","memoryBytes","swapBytes"],"scope":"kernel-verified aggregate cgroup; no aggregate CPU limit"},{"phase":"compiler","source":"evaluate_candidate_v3.py:run","keys":["compilerSeconds","outputBytesPerStream","sourceBytes"],"scope":"preprocess/compile/link/GCC assertions"},{"phase":"probe","source":"interface_gate_v3.py:probe","keys":["probeSeconds","helperOutputBytesPerStream","helperInputBytes","helperGraphNodes","helperGraphDepth"],"scope":"separate expected/candidate input roots"},{"phase":"runtime","source":"evaluate_candidate_v3.py:run","keys":["runtimeSeconds","outputBytesPerStream"],"scope":"one wrapped scenario process"},{"phase":"elf-inspection","source":"interface_gate_v3.py:export_inventory","keys":["elfInspectionSeconds","outputBytesPerStream"],"scope":"each readelf invocation"},{"phase":"caller-build","source":"private preparation coordinator (not in public archive)","keys":["callerBuildSeconds","outputBytesPerStream"],"scope":"trusted caller compiler wall/capture"},{"phase":"helper-build","source":"toolchain-001/build_helper.py","keys":["helperBuildSeconds","helperOutputBytesPerStream"],"scope":"existing helper compiler/link supervisor; not candidate compiler"},{"phase":"toolchain-inspection","source":"toolchain-001/pin_environment.py","keys":["toolchainInspectionSeconds","helperOutputBytesPerStream"],"scope":"each metadata/dependency command"},{"phase":"capture","source":"bounded_runtime.py:bounded_run","keys":["defaultWallSeconds","outputBytesPerStream","stdinBytes","captureReadBytes","selectorPollSeconds","waitFloorSeconds"],"scope":"default15s, bounded stdin before launch, per-stream capture; final wait floor is supervisor policy"},{"phase":"cleanup","source":"bounded_runtime.py:bounded_run","keys":["cleanupWaitSeconds","cleanupVerificationSeconds","cleanupPollSeconds"],"scope":"owned PID-start identity and cgroup/session absence"},{"phase":"scope-admission","source":"scope_gate.py","keys":["scopeAdmissionSeconds","scopeAdmissionPollSeconds"],"scope":"gate timeout/poll; immutable existing supervisor constants"},{"phase":"isolation","source":"evaluate_candidate_v3.py:phase_command/runtime_command; interface_gate_v3.py:probe_command","keys":["temporaryFilesystemBytes"],"scope":"/tmp tmpfs; exact environment/namespaces/mount and writable-work contract below"}]}''')


# F1 monitor/barrier limits remain inside the original per-phase wall/task budgets.
_IMMUTABLE['bounds'].update({'workerProofRecords': 2, 'workerProofRecordBytes': 512, 'workerProofBytes': 1024, 'workerBarrierSeconds': 1, 'workerBarrierPollSeconds': 0.01, 'workerBarrierAttempts': 100, 'workerProcEntries': 256, 'workerFdEntries': 66, 'workerNumericFds': 64, 'workerMetadataBytes': 4096, 'workerMonitorProcesses': 1})
_IMMUTABLE['bounds'].update({'workerLaunchPinEntries': 256, 'workerLaunchPinFileBytes': 16777216})
_IMMUTABLE['analysisIsolation']['readOnlySystemFiles'] = ['/etc/ld.so.cache']
_IMMUTABLE['analysisIsolation']['explicitReadOnlyFileInputs'] = 'exact regular files at original absolute paths, overlaid read-only even within writable work; no parent inference or control-source work tree'
_IMMUTABLE['workerExecProof'] = {'protocolVersion': 1, 'monitorInsidePath': '/_worker_exec_monitor', 'manifestPath': 'toolchain-001/worker-exec-monitor.json', 'receiptRoot': 'exec-proof-receipts', 'receiptFile': 'worker-proof.jsonl', 'reportDescriptor': 4, 'receiptMode': 384, 'receiptDirectoryMode': 448, 'workerPhases': 'all require fresh contained monitor exec/terminal proof', 'taskBudget': 'existing aggregate32 includes reaper and one extra monitor; no extra candidate resources', 'provisioningException': 'fixed public monitor source/compiler command only; channel-free provisioning-only, never candidate acceptance'}
_IMMUTABLE['limitSemantics']['workerExecProof'] = 'barrier and monitor overhead are inside the original phase wall/resource budgets; proof file is independent of untrusted stdout/stderr'
_IMMUTABLE['limitAudit'].append({'phase': 'worker-exec-proof', 'source': 'bounded_runtime.py/scope_gate.py/worker_exec_monitor.c', 'keys': ['workerProofRecords', 'workerProofRecordBytes', 'workerProofBytes', 'workerBarrierSeconds', 'workerBarrierPollSeconds', 'workerBarrierAttempts', 'workerProcEntries', 'workerFdEntries', 'workerNumericFds', 'workerMetadataBytes', 'workerMonitorProcesses', 'workerLaunchPinEntries', 'workerLaunchPinFileBytes'], 'scope': 'closed 2-record proof, bounded pre-worker proc/FD barrier, one monitor inside existing aggregate task budget'})


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate contract key')
        result[key] = value
    return result


def _snapshot_version(metadata):
    return tuple(getattr(metadata, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _directory_version(metadata):
    # Unrelated directory contents may change; the held directory/edge may not.
    return tuple(getattr(metadata, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'))


def _bounded_json_snapshot(path: Path, maximum: int) -> bytes:
    """Finite stable snapshot; no enclosing wall deadline or root authority is implied."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError('invalid contract byte bound')
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('contract parent traversal unsupported')
    if not path.is_absolute():
        path = Path.cwd() / path
    if len(path.parts) > 128 or len(str(path)) > 4096 or path.name == '':
        raise ValueError('contract path bound')
    descriptors = []
    directories = []
    primary = None
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open('/', directory_flags)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError('contract parent must be directory')
        directories.append((descriptor, None, None, _directory_version(metadata)))
        for component in path.parts[1:-1]:
            parent = descriptor
            descriptor = os.open(component, directory_flags, dir_fd=parent)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError('contract parent must be directory')
            version = _directory_version(metadata)
            if _directory_version(os.stat(component, dir_fd=parent, follow_symlinks=False)) != version:
                raise ValueError('contract parent changed during admission')
            directories.append((descriptor, parent, component, version))
        parent = descriptor
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise ValueError('contract regular file byte bound')
        version = _snapshot_version(before)
        if _snapshot_version(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != version:
            raise ValueError('contract file changed before read')
        remaining = before.st_size
        chunks = []
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                raise ValueError('contract file truncated')
            remaining -= len(block)
            chunks.append(block)
        if os.read(descriptor, 1):
            raise ValueError('contract file grew')
        if (_snapshot_version(os.fstat(descriptor)) != version or
                _snapshot_version(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != version):
            raise ValueError('contract file changed during read')
        for held, ancestor, name, expected in directories:
            if _directory_version(os.fstat(held)) != expected:
                raise ValueError('contract held parent changed')
            named = (os.stat('/', follow_symlinks=False) if ancestor is None else
                     os.stat(name, dir_fd=ancestor, follow_symlinks=False))
            if _directory_version(named) != expected:
                raise ValueError('contract named parent changed')
        return b''.join(chunks)
    except BaseException as failure:
        primary = failure
        raise
    finally:
        cleanup_failure = None
        cleanup_count = 0
        for held in reversed(descriptors):
            try:
                os.close(held)
            except BaseException as failure:
                cleanup_count += 1
                if cleanup_failure is None:
                    cleanup_failure = failure
        if cleanup_failure is not None:
            if primary is not None:
                BaseException.add_note(primary, 'contract descriptor cleanup failures: ' + str(cleanup_count))
            else:
                raise cleanup_failure


def _read_json(path: Path, maximum: int):
    raw = _bounded_json_snapshot(path, maximum)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite contract value')))
    except (RecursionError, UnicodeError, json.JSONDecodeError) as failure:
        raise ValueError('invalid contract JSON') from failure
    return value, hashlib.sha256(raw).hexdigest()


def validate_profile(value):
    if not isinstance(value, dict) or set(value) != set(_IMMUTABLE) | {'gccIdentity', 'toolchainEnvironmentPinSha256'}:
        raise ValueError('closed v3 profile keys required')
    for key, expected in _IMMUTABLE.items():
        # Canonical JSON equality distinguishes bool/int and int/float; dictionary order is not policy.
        if json.dumps(value[key], sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
            raise ValueError('immutable profile disagreement: ' + key)
    identity = value['gccIdentity']
    if not isinstance(identity, dict) or set(identity) != {'executable','realpath','sha256','target','version'}:
        raise ValueError('closed GCC identity required')
    if any(not isinstance(v, str) or not 1 <= len(v) <= 4096 for v in identity.values()):
        raise ValueError('invalid GCC identity scalar')
    if identity['executable'] != '/usr/bin/gcc' or identity['target'] != 'x86_64-pc-linux-gnu' or not Path(identity['realpath']).is_absolute():
        raise ValueError('GCC identity target/path disagreement')
    for pin in [identity['sha256'], value['toolchainEnvironmentPinSha256']]:
        if not isinstance(pin, str) or re.fullmatch('[0-9a-f]{64}', pin) is None:
            raise ValueError('invalid toolchain digest')
    return value


def enforced_process_limits():
    b = _IMMUTABLE['bounds']
    return {name: {'soft': b[key], 'hard': b[key], 'unit': unit, 'scope': 'per-process'} for name, key, unit in [
        ('RLIMIT_CORE','coreBytes','bytes'), ('RLIMIT_CPU','cpuSeconds','seconds'),
        ('RLIMIT_AS','virtualAddressSpaceBytes','bytes'), ('RLIMIT_NOFILE','openFiles','descriptors'),
        ('RLIMIT_FSIZE','fileSizeBytes','bytes')]}


def load_profile_with_digest(path=None):
    """Read/validate only the local declared contract; no host tool resolution or policy changes."""
    value, sha256 = _read_json(Path(path) if path is not None else PROFILE_PATH, MAXIMUM_PROFILE_BYTES)
    return validate_profile(value), sha256


def load_profile(path=None):
    return load_profile_with_digest(path)[0]


def profile():
    """Execution-side tool byte revalidation; no subprocess or compiler invocation."""
    value = load_profile()
    identity = value['gccIdentity']
    if str(Path(identity['executable']).resolve()) != identity['realpath'] or digest(Path(identity['realpath'])) != identity['sha256']:
        raise ValueError('GCC executable differs from visible profile identity')
    return value


def _render(value):
    return '\n'.join(['Candidate build contract v3', value['target'],
        *(' '.join(value['commands'][k]) for k in ('preprocess','compile','link')),
        value['exports'], 'Full machine-readable contract:', json.dumps(value, sort_keys=True, indent=2)]) + '\n'


def render():
    return _render(profile())


def _visible_snapshot():
    # One validated byte snapshot binds both visible artifacts; no reread between prompt and manifest.
    value, sha256 = load_profile_with_digest()
    identity = value['gccIdentity']
    if str(Path(identity['executable']).resolve()) != identity['realpath'] or digest(Path(identity['realpath'])) != identity['sha256']:
        raise ValueError('GCC executable differs from visible profile identity')
    return value, sha256


def verify_visible(directory):
    value, sha256 = _visible_snapshot()
    manifest, _ = _read_json(directory / 'visible-manifest.json', MAXIMUM_VISIBLE_BYTES)
    expected = {'schemaVersion': 3, 'profile': value, 'profileSha256': sha256}
    if json.dumps(manifest, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError('visible manifest/profile disagreement')
    prompt = _bounded_json_snapshot(directory / 'prompt.txt', MAXIMUM_VISIBLE_BYTES)
    if prompt != _render(value).encode('utf-8'):
        raise ValueError('visible prompt/profile disagreement')


def write_visible(directory):
    value, sha256 = _visible_snapshot()
    (directory / 'prompt.txt').write_text(_render(value))
    (directory / 'visible-manifest.json').write_text(json.dumps(
        {'schemaVersion': 3, 'profile': value, 'profileSha256': sha256}, sort_keys=True, indent=2) + '\n')
