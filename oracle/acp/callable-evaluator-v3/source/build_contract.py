"""Closed v3 command/limit contract; import and profile loading never launch tools."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import builtins
import sysconfig
from types import ModuleType
from pathlib import Path
import re
from contextlib import contextmanager
from contextvars import ContextVar

BASE = Path(__file__).resolve().parent
PROFILE_PATH = BASE / 'contracts/candidate-build-profile.json'
MAXIMUM_PROFILE_BYTES = 65536
MAXIMUM_VISIBLE_BYTES = 131072

# PyPI fastjsonschema 2.22.2, wheel SHA-256
# 0fb3915616adac85ccfdd737d26be1089845d2019819505b42d39888458f74d4.
# Filled by the independently checked release-source inventory below. These pins
# select executable bytes; installed version text and ambient module caches do not.
_SCHEMA_SOURCES = (
    ('__init__', 13066, 'a8c552ee3f3867050463a59d6bc7394caf7257f5215959487533d126a06c759d'),
    ('__main__', 312, 'e217dddb7a6bcf199073c5632f47d4b1bb2bbef03bde02761c334f80b2c57402'),
    ('draft04', 33750, '04afbc54245971d1da97e47cd67a98e66bbcce20dd93833c37e54fe89a13c01a'),
    ('draft06', 8305, '29b2074e7c22a8fd6f8fc93e38df3ad453e30fac3e35d104ea59bcb3865e31be'),
    ('draft07', 5064, '1290a35007a1a4af57ff0394408a394cd6aea7808d6f13b01eea6ff0e45f7d49'),
    ('draft2019', 541, '28732d8a5b6866e3b86fd9c2a899b328c816d31c28f4f4ce291dd0670ca866a9'),
    ('exceptions', 1859, 'da47b1f76f3b652279afdac7f5e7017d4a5a017a135ced4f8268744b1197eb43'),
    ('generator', 16788, 'bb611052369d3fa5c42b600e0d81efffdb22bad6b05d1a20680896265caf5421'),
    ('indent', 1603, '6c2aaac7022acab03838c691440ee042d8cf93dc1ce2906b804f49bdb2aae31b'),
    ('ref_resolver', 6767, '08f89a3856dd509db520371ac8d7d2ba4c665aa37678170b3f1f8b7fe0850754'),
    ('version', 19, '9460537427fadbc522d10b47be34addba8608635d950d725b288a9eed6515ad1'),
)
_SCHEMA_IMPORT = builtins.__import__
_SCHEMA_STDLIB = frozenset(('functools', 'collections', 'contextlib', 'decimal',
                          're', 'json', 'base64', 'sys', 'urllib', 'urllib.parse'))


def _schema_package_root():
    # A location selects bytes, never their expected identity. No sys.path search.
    location = sysconfig.get_path('purelib')
    if not isinstance(location, str) or not location:
        raise ValueError('schema source location is unavailable')
    return Path(location) / 'fastjsonschema'


class _SchemaSources:
    """One owned source image; no ambient package imports or module-cache writes."""
    def __init__(self):
        root = _schema_package_root()
        raw = {}
        for name, size, expected in _SCHEMA_SOURCES:
            payload = _bounded_json_snapshot(root / (name + '.py'), size)
            if len(payload) != size or hashlib.sha256(payload).hexdigest() != expected:
                raise ValueError('schema executable source identity differs')
            raw[name] = payload
        # Authenticate the complete package before its first compile or body.
        self.code = {name: compile(raw[name], str(root / (name + '.py')), 'exec',
                                   dont_inherit=True, optimize=0)
                     for name, _, _ in _SCHEMA_SOURCES}
        self.modules = {}
        self.loading = set()
        self.ready = set()
        self.prefix = '_v3_schema_' + format(id(self), 'x')
        for name, _, _ in _SCHEMA_SOURCES:
            alias = self.prefix if name == '__init__' else self.prefix + '.' + name
            module = ModuleType(alias)
            module.__file__ = str(root / (name + '.py'))
            module.__package__ = self.prefix
            if name == '__init__':
                module.__path__ = ()
            environment = dict(vars(builtins))
            environment['__import__'] = self.importer
            module.__dict__['__builtins__'] = environment
            self.modules[name] = module

    def load(self, name):
        if name not in self.modules or name in self.loading:
            raise ValueError('unsupported schema source edge or cycle')
        if name not in self.ready:
            self.loading.add(name)
            try:
                exec(self.code[name], self.modules[name].__dict__)
                self.ready.add(name)
                if name != '__init__':
                    setattr(self.modules['__init__'], name, self.modules[name])
            finally:
                self.loading.remove(name)
        return self.modules[name]

    def importer(self, name, globals=None, locals=None, fromlist=(), level=0):
        requested = tuple(fromlist or ())
        if '*' in requested:
            raise ValueError('unsupported schema wildcard import')
        if level:
            if level != 1:
                raise ValueError('unsupported schema relative import')
            return self.load(name or '__init__')
        if name == 'fastjsonschema' or name.startswith('fastjsonschema.'):
            selected = '__init__' if name == 'fastjsonschema' else name[len('fastjsonschema.'):]
            module = self.load(selected)
            return module if requested else self.load('__init__')
        if name not in _SCHEMA_STDLIB or (name == 'urllib' and requested != ('parse',)):
            # Closed local schemas need no remote-ref loader, plugin or file API.
            raise ValueError('unsupported schema external import')
        return _SCHEMA_IMPORT(name, globals, locals, fromlist, level)


def load_schema_validator():
    """Keep actual schema semantics, with all third-party code captured first.

    Interpreter/stdlib/bootstrap identity is a separate qualification boundary.
    No native preparation, model/provider call or release authority follows.
    """
    validator = _SchemaSources().load('__init__')
    if validator.VERSION != '2.22.2':
        raise ValueError('schema source version differs')
    return validator

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


def digest(path: Path, *, maximum=None, deadline=None) -> str:
    # Compatibility default is the existing launch-file domain, not arbitrary host files.
    ceiling = _IMMUTABLE['bounds']['workerLaunchPinFileBytes']
    if maximum is None:
        maximum = ceiling
    if type(maximum) is not int or not 0 <= maximum <= ceiling:
        raise ValueError('invalid digest byte bound')
    _snapshot_timely(deadline)
    raw = _bounded_json_snapshot(path, maximum, deadline=deadline)
    _snapshot_timely(deadline)
    result = hashlib.sha256(raw).hexdigest()
    _snapshot_timely(deadline)
    return result


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


def _snapshot_timely(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('phase expired during contract snapshot')


def _bounded_json_snapshot(path: Path, maximum: int, *, deadline=None) -> bytes:
    """Stable bounded bytes; an optional caller end refuses lateness, not blocking syscalls."""
    _snapshot_timely(deadline)
    if type(maximum) is not int or maximum < 0:
        raise ValueError('invalid contract byte bound')
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('contract parent traversal unsupported')
    if not path.is_absolute():
        path = Path.cwd() / path
    if len(path.parts) > 128 or len(str(path)) > 4096 or path.name == '':
        raise ValueError('contract path bound')
    # Root +at most126 parent components +leaf; own every fd before fallible checks.
    descriptors = [None] * 128
    count = 0
    directories = []
    primary = None
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    def checked(operation, *args, **kwargs):
        _snapshot_timely(deadline)
        value = operation(*args, **kwargs)
        _snapshot_timely(deadline)
        return value
    def opened(name, flags, **kwargs):
        nonlocal count
        _snapshot_timely(deadline)
        descriptor = os.open(name, flags, **kwargs)
        descriptors[count] = descriptor
        count += 1
        _snapshot_timely(deadline)
        return descriptor
    try:
        descriptor = opened('/', directory_flags)
        metadata = checked(os.fstat, descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError('contract parent must be directory')
        directories.append((descriptor, None, None, _directory_version(metadata)))
        for component in path.parts[1:-1]:
            parent = descriptor
            descriptor = opened(component, directory_flags, dir_fd=parent)
            metadata = checked(os.fstat, descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError('contract parent must be directory')
            version = _directory_version(metadata)
            if _directory_version(checked(os.stat, component, dir_fd=parent, follow_symlinks=False)) != version:
                raise ValueError('contract parent changed during admission')
            directories.append((descriptor, parent, component, version))
        parent = descriptor
        descriptor = opened(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=parent)
        before = checked(os.fstat, descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise ValueError('contract regular file byte bound')
        version = _snapshot_version(before)
        if _snapshot_version(checked(os.stat, path.name, dir_fd=parent, follow_symlinks=False)) != version:
            raise ValueError('contract file changed before read')
        remaining = before.st_size
        chunks = []
        while remaining:
            block = checked(os.read, descriptor, min(65536, remaining))
            if not block:
                raise ValueError('contract file truncated')
            remaining -= len(block)
            chunks.append(block)
        if checked(os.read, descriptor, 1):
            raise ValueError('contract file grew')
        if (_snapshot_version(checked(os.fstat, descriptor)) != version or
                _snapshot_version(checked(os.stat, path.name, dir_fd=parent, follow_symlinks=False)) != version):
            raise ValueError('contract file changed during read')
        for held, ancestor, name, expected in directories:
            if _directory_version(checked(os.fstat, held)) != expected:
                raise ValueError('contract held parent changed')
            named = (checked(os.stat, '/', follow_symlinks=False) if ancestor is None else
                     checked(os.stat, name, dir_fd=ancestor, follow_symlinks=False))
            if _directory_version(named) != expected:
                raise ValueError('contract named parent changed')
        raw = b''.join(chunks)
        _snapshot_timely(deadline)
        return raw
    except BaseException as failure:
        primary = failure
        raise
    finally:
        cleanup_failure = None
        cleanup_count = 0
        while count:
            count -= 1
            held = descriptors[count]
            descriptors[count] = None
            try:
                os.close(held)
            except BaseException as failure:
                cleanup_count += 1
                if cleanup_failure is None:
                    cleanup_failure = failure
        if cleanup_failure is not None:
            if primary is None:
                raise cleanup_failure
            try:
                BaseException.add_note(primary, 'contract descriptor cleanup failures: ' + str(cleanup_count))
            except BaseException:
                pass
        if primary is None:
            _snapshot_timely(deadline)


def _decode_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite contract value')))
    except (RecursionError, UnicodeError, json.JSONDecodeError) as failure:
        raise ValueError('invalid contract JSON') from failure
    return value


def _read_json(path: Path, maximum: int):
    raw = _bounded_json_snapshot(path, maximum)
    return _decode_json(raw), hashlib.sha256(raw).hexdigest()


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


class _ProfileSnapshot:
    """Owned original bytes; no returned mutable profile object can retarget this value."""
    __slots__ = ('raw', 'sha256')

    def __init__(self, raw):
        if hasattr(self, 'raw') or hasattr(self, 'sha256'):
            raise AttributeError('profile snapshot is immutable')
        if type(raw) is not bytes or not 0 <= len(raw) <= MAXIMUM_PROFILE_BYTES:
            raise ValueError('profile snapshot byte bound')
        validate_profile(_decode_json(raw))
        object.__setattr__(self, 'raw', raw)
        object.__setattr__(self, 'sha256', hashlib.sha256(raw).hexdigest())

    def __setattr__(self, name, value):
        raise AttributeError('profile snapshot is immutable')

    def __delattr__(self, name):
        raise AttributeError('profile snapshot is immutable')


_PROFILE_SNAPSHOT = ContextVar('verified_candidate_profile', default=None)


def _read_profile_snapshot(path=None):
    # Admission/explicit reads must not inherit an outer evaluation's profile.
    return _ProfileSnapshot(_bounded_json_snapshot(
        Path(path) if path is not None else PROFILE_PATH, MAXIMUM_PROFILE_BYTES))


@contextmanager
def profile_scope(snapshot):
    if type(snapshot) is not _ProfileSnapshot:
        raise ValueError('owned profile snapshot required')
    token = _PROFILE_SNAPSHOT.set(snapshot)
    try:
        yield
    finally:
        _PROFILE_SNAPSHOT.reset(token)


def load_profile_with_digest(path=None):
    """Ordinary aliases share the invocation; explicit paths remain independent reads."""
    snapshot = _PROFILE_SNAPSHOT.get() if path is None else None
    if snapshot is None:
        snapshot = _read_profile_snapshot(path)
    return validate_profile(_decode_json(snapshot.raw)), snapshot.sha256


def load_profile(path=None):
    return load_profile_with_digest(path)[0]


def profile():
    """Execution-side tool byte revalidation; no subprocess or compiler invocation."""
    return _revalidate_gcc(load_profile())


def _revalidate_gcc(value):
    identity = value['gccIdentity']
    if str(Path(identity['executable']).resolve()) != identity['realpath'] or digest(Path(identity['realpath']), maximum=value['bounds']['workerLaunchPinFileBytes'], deadline=None) != identity['sha256']:
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
    snapshot = _read_profile_snapshot()
    return _revalidate_gcc(validate_profile(_decode_json(snapshot.raw))), snapshot.sha256


def verify_visible(directory):
    value, sha256 = _visible_snapshot()
    _verify_visible(directory, value, sha256)


def verified_visible_snapshot(directory):
    """Independently admit the visible contract, including inside an outer profile scope."""
    snapshot = _read_profile_snapshot()
    value = _revalidate_gcc(validate_profile(_decode_json(snapshot.raw)))
    _verify_visible(directory, value, snapshot.sha256)
    return snapshot


def _verify_visible(directory, value, sha256):
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
