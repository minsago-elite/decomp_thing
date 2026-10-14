"""Bounded v3 process runner; declared bounds are separate from observed process facts."""
from __future__ import annotations

import hashlib
import fcntl
import errno
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

BASE = Path(__file__).resolve().parent

from build_contract import load_profile_with_digest, enforced_process_limits


def _canonical_pin_digest(pins: dict) -> str:
    return hashlib.sha256(json.dumps(pins, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _valid_worker_bindings(result: dict) -> bool:
    binding, pins, bounds = result.get('workerProofBindings'), result.get('launchInputPins'), result.get('bounds')
    hashes = {'launchConfigSha256','environmentPinSha256','monitorBinarySha256','monitorSourceSha256',
              'protocolSha256','parserSha256','manifestSha256','targetSha256','launchPinsSha256'}
    def sha(value):
        return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
    if (not isinstance(binding, dict) or set(binding) != hashes | {'protocolVersion','expected'} or
            type(binding['protocolVersion']) is not int or binding['protocolVersion'] != 1 or
            any(not sha(binding[key]) for key in hashes) or not isinstance(pins, dict) or not 1 <= len(pins) <= 256 or
            not isinstance(bounds, dict) or not sha(bounds.get('profileSha256'))):
        return False
    expected = binding['expected']
    identities = {'reportDevice','reportInode','reaperDevice','reaperInode','outerPidNsDevice',
                  'outerPidNsInode','targetDevice','targetInode'}
    phases = {'unspecified','compiler','probe','runtime','elf-inspection','caller-build','helper-build','toolchain-inspection'}
    if (not isinstance(expected, dict) or set(expected) not in (identities | {'attempt','phase'}, identities | {'attempt','phase','library'}) or
            not isinstance(expected['attempt'], str) or len(expected['attempt']) != 32 or
            any(c not in '0123456789abcdef' for c in expected['attempt']) or
            not isinstance(expected['phase'], str) or expected['phase'] not in phases or
            expected['phase'] != bounds.get('phase') or
            any(type(expected[key]) is not int or not 0 <= expected[key] <= (1 << 64) - 1 for key in identities)):
        return False
    for name, item in pins.items():
        if (not isinstance(name, str) or not Path(name).is_absolute() or '\0' in name or '..' in Path(name).parts or
                not isinstance(item, dict) or set(item) != {'device','inode','mode','sha256'} or
                any(type(item[key]) is not int or not 0 <= item[key] <= (1 << 64) - 1 for key in ('device','inode')) or
                type(item['mode']) is not int or not 0 <= item['mode'] <= 0o7777 or not sha(item['sha256'])):
            return False
    if _canonical_pin_digest(pins) != binding['launchPinsSha256']:
        return False
    def matches(prefix, digest=None):
        return any((row['device'], row['inode']) == (expected[prefix+'Device'], expected[prefix+'Inode']) and
                   (digest is None or row['sha256'] == digest) for row in pins.values())
    if not matches('target', binding['targetSha256']) or not matches('reaper'):
        return False
    report = (expected['reportDevice'], expected['reportInode'])
    return report not in ((expected['targetDevice'], expected['targetInode']),
                          (expected['reaperDevice'], expected['reaperInode']))


def worker_execution_complete(result: object) -> bool:
    """Completion is worker proof plus the entire trusted controller chain, never launcher status."""
    if not isinstance(result, dict) or result.get('provisioningOnly') is not False or not _valid_worker_bindings(result):
        return False
    required = ('launcherCreated', 'launcherPidIdentityVerified', 'scopeVerified', 'scopeAdmitted',
                'captureComplete', 'waitComplete', 'cleanupVerified', 'rootReaped',
                'finalAbsenceVerified', 'workerExecVerified', 'workerTerminationVerified')
    if any(result.get(key) is not True for key in required):
        return False
    if any(result.get(key) is not False for key in ('timedOut', 'outputExceeded', 'infrastructureFailure')):
        return False
    if type(result.get('launcherExitCode')) is not int or result['launcherExitCode'] != 0:
        return False
    scope = result.get('kernelScope')
    if not isinstance(scope, dict) or scope.get('finalAbsenceVerified') is not True:
        return False
    proof = result.get('workerProof')
    if not isinstance(proof, dict) or proof.get('protocolVersion') != 1 or type(proof.get('protocolVersion')) is not int:
        return False
    sha = proof.get('proofSha256')
    if (proof.get('status') != 'verified' or proof.get('fileIdentityVerified') is not True or
            proof.get('pinsUnchanged') is not True or not isinstance(sha, str) or len(sha) != 64 or
            any(c not in '0123456789abcdef' for c in sha)):
        return False
    termination = result.get('workerTermination')
    if not isinstance(termination, dict) or set(termination) != {'kind', 'value', 'rawWaitStatus'}:
        return False
    value, raw = termination['value'], termination['rawWaitStatus']
    if type(value) is not int or type(raw) is not int or not 0 <= raw <= 65535:
        return False
    if termination['kind'] == 'exit':
        if not 0 <= value <= 255 or raw != value << 8:
            return False
        normalized = value
    elif termination['kind'] == 'signal':
        if not 1 <= value <= 64 or raw not in (value, value | 128):
            return False
        normalized = -value
    else:
        return False
    if type(result.get('exitCode')) is not int or result['exitCode'] != normalized:
        return False
    for label in ('stdout', 'stderr'):
        if label in result and label + 'Hex' in result:
            return False
        if label in result:
            if not isinstance(result[label], bytes):
                return False
        else:
            text = result.get(label + 'Hex')
            if not isinstance(text, str) or len(text) % 2 or any(c not in '0123456789abcdef' for c in text):
                return False
    if 'workerProofRaw' in result and 'workerProofRawHex' in result:
        return False
    raw = result.get('workerProofRaw')
    if raw is None:
        encoded = result.get('workerProofRawHex')
        if not isinstance(encoded, str) or len(encoded) % 2 or len(encoded) > 2048 or any(c not in '0123456789abcdef' for c in encoded):
            return False
        raw = bytes.fromhex(encoded)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 1024 or hashlib.sha256(raw).hexdigest() != sha:
        return False
    try:
        parser = _fixed_source_module(BASE / 'worker_exec_proof.py', '_v3_completion_proof_parser')
        parsed = parser.parse_proof(raw, result['workerProofBindings']['expected'])
    except Exception:
        return False
    return (parsed['status'] == 'verified' and parsed['workerExecVerified'] is True and
            parsed['workerTerminationVerified'] is True and parsed['workerTermination'] == termination and
            parsed['exitCode'] == result['exitCode'] and parsed['proofSha256'] == sha)


def _repository_root() -> Path:
    for parent in (BASE, *BASE.parents):
        if (parent / '.git').exists():
            return parent.resolve(strict=True)
    raise ValueError('owned repository root is unavailable')


def _work_directory(cwd: Path) -> Path:
    cwd = Path(cwd).resolve(strict=True)
    repository = _repository_root()
    receipt_root = BASE / 'exec-proof-receipts'
    protected = (BASE / 'toolchain-001', BASE / 'contracts', BASE / 'tests', receipt_root)
    if any(cwd.is_relative_to(path) or path.is_relative_to(cwd) for path in protected):
        raise ValueError('protected source/receipt subtree cannot be a worker directory')
    if (not cwd.is_dir() or not cwd.is_relative_to(repository) or cwd == repository or
            BASE.is_relative_to(cwd) or (BASE / 'toolchain-001').is_relative_to(cwd) or
            cwd.is_relative_to(receipt_root) or receipt_root.is_relative_to(cwd) or
            cwd.stat().st_uid != os.getuid()):
        raise ValueError('work must be an explicit owned directory outside protected receipt storage')
    return cwd


def _worker_environment(environment: dict, cwd: Path) -> dict:
    allowed = {'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'TMP', 'TEMP', 'HOME', 'LD_LIBRARY_PATH'}
    if not isinstance(environment, dict) or not set(environment) <= allowed:
        raise ValueError('worker environment has unreviewed keys')
    if any(not isinstance(v, str) or '\0' in v for v in environment.values()):
        raise ValueError('worker environment requires NUL-free strings')
    if any(environment.get(k) != v for k, v in {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}.items()):
        raise ValueError('worker public runtime environment differs')
    for key in ('HOME', 'TMPDIR', 'TMP', 'TEMP'):
        if key in environment and environment[key] not in ('/tmp', str(cwd)):
            raise ValueError('worker state path is outside its declared work/tmp roots')
    if 'LD_LIBRARY_PATH' in environment:
        profile, _ = load_profile_with_digest()
        if environment['LD_LIBRARY_PATH'] != profile['analysisIsolation']['environment']['LD_LIBRARY_PATH']:
            raise ValueError('worker library path differs from the declared runtime')
    return dict(environment)


def contained_command(argv: list[str], cwd: Path, read_only_files=(), *, environment: dict) -> list[str]:
    """Exact-file recipe for formerly direct phases; preserve worker argv and absolute cwd."""
    cwd = _work_directory(cwd)
    if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or '\0' in v for v in argv) or not Path(argv[0]).is_absolute():
        raise ValueError('worker command requires an original absolute executable argv')
    environment = _worker_environment(environment, cwd)
    profile, _ = load_profile_with_digest()
    command = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--die-with-parent', '--new-session',
               '--disable-userns', '--cap-drop', 'ALL', '--clearenv']
    for directory in profile['analysisIsolation']['readOnlySystemMounts']:
        if Path(directory).exists():
            command += ['--ro-bind', directory, directory]
    for path in profile['analysisIsolation']['readOnlySystemFiles']:
        command += ['--ro-bind', path, path]
    command += ['--proc', '/proc', '--dev', '/dev', '--remount-ro', '/dev', '--size',
                str(profile['bounds']['temporaryFilesystemBytes']), '--tmpfs', '/tmp',
                '--bind', str(cwd), str(cwd)]
    seen = set()
    for path in read_only_files:
        path = Path(path)
        if not path.is_absolute() or path != path.resolve(strict=True) or not path.is_file() or path.is_symlink():
            raise ValueError('explicit read-only inputs must be original absolute regular files')
        if path.is_relative_to(BASE / 'exec-proof-receipts'):
            raise ValueError('protected receipt file cannot be a worker input')
        if path.is_relative_to(cwd) and path.stat().st_nlink != 1:
            raise ValueError('read-only work input has an unprotected hard-link alias')
        if path in seen:
            continue
        seen.add(path)
        command += ['--ro-bind', str(path), str(path)]
    command += ['--chdir', str(cwd)]
    for key, value in environment.items():
        command += ['--setenv', key, value]
    return command + ['--', *argv]


def _nonprivileged_executable(path: Path, deadline=None) -> dict:
    path = Path(path).resolve(strict=True)
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('phase expired before executable admission')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o6000 or
                not os.access(path, os.X_OK, effective_ids=True)):
            raise ValueError('worker/monitor executable must be nonprivileged and executable')
        try:
            capability = os.getxattr(descriptor, 'security.capability')
        except OSError as failure:
            if failure.errno != errno.ENODATA:
                raise ValueError('file capability metadata is unknown') from failure
        else:
            if capability:
                raise ValueError('file-capability executable is outside the launch contract')
        if os.read(descriptor, 4) != b'\x7fELF':
            raise ValueError('worker image must be an explicit ELF executable, not a script')
        row = _pin_files([path], deadline)[str(path)]
        after = os.fstat(descriptor)
        if (row['device'], row['inode'], row['mode']) != (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode)) or any(
                getattr(after, key) != getattr(metadata, key) for key in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')):
            raise ValueError('executable identity changed during admission')
        return {'path': str(path), **row}
    finally:
        os.close(descriptor)


def load_worker_monitor_binding() -> dict:
    """Read/revalidate the fixed A3 byte closure; UNQUALIFIED is not production authority."""
    profile, _ = load_profile_with_digest()
    source = BASE / 'toolchain-001/pin_environment.py'
    # Compile the fixed source bytes, not a worker-writable sibling bytecode cache.
    module = type(os)('callable_v3_runtime_monitor_pin')
    module.__file__ = str(source)
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
    binding = module.load_monitor_binding(profile)
    required = {'binaryPath', 'binarySha256', 'sourceSha256', 'protocolSha256', 'parserSha256',
                'dependencies', 'manifestSha256', 'environmentPinSha256'}
    if not isinstance(binding, dict) or not required <= set(binding) or not binding['dependencies']:
        raise ValueError('complete operational monitor byte closure is required')
    for key in required - {'binaryPath', 'dependencies'}:
        value = binding[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('monitor byte closure has invalid hashes')
    if binding['environmentPinSha256'] != profile['toolchainEnvironmentPinSha256']:
        raise ValueError('monitor environment/profile generation differs')
    fixed = [('sourceSha256', BASE / 'worker_exec_monitor.c'),
             ('protocolSha256', BASE / 'contracts/worker-exec-proof-schema.json'),
             ('parserSha256', BASE / 'worker_exec_proof.py')]
    for key, path in fixed:
        if digest(path) != binding[key]:
            raise ValueError('monitor source/protocol/parser pin differs')
    binary = _nonprivileged_executable(Path(binding['binaryPath']))
    if binary['sha256'] != binding['binarySha256']:
        raise ValueError('monitor binary pin differs')
    paths = set()
    for item in binding['dependencies']:
        if (not isinstance(item, dict) or set(item) != {'path', 'sha256'} or
                not Path(item['path']).is_absolute() or item['path'] in paths or
                digest(Path(item['path'])) != item['sha256']):
            raise ValueError('monitor dependency inventory changed')
        paths.add(item['path'])
    return binding



def _recorded_compiler_inputs(recipe, target, deadline=None):
    """Bind only the existing recorded subset for the exact admitted GCC identity."""
    profile, _ = load_profile_with_digest()
    identity = profile['gccIdentity']
    if target['path'] != identity['realpath']:
        return None
    if target['sha256'] != identity['sha256']:
        raise ValueError('recorded compiler executable identity changed')
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('phase expired before compiler recording validation')
    source = BASE / 'toolchain-001/pin_environment.py'
    module = _fixed_source_module(source, '_v3_recorded_compiler_pin')
    binding = module.load_compiler_binding(profile)
    required = {'status', 'scope', 'environmentPinSha256', 'closureSha256', 'driverArgv',
                'workingDirectory', 'environment', 'dependencies', 'closure'}
    if (type(binding) is not dict or set(binding) != required or
            binding['status'] != 'static-recording-unqualified' or
            binding['scope'] != 'recorded-implicit-link-inputs' or
            binding['environmentPinSha256'] != profile['toolchainEnvironmentPinSha256'] or
            not binding['dependencies']):
        raise ValueError('recorded compiler subset binding invalid')
    # Loader is the strict bounded closure validator; verify the consumer's digest too.
    closure_hash = hashlib.sha256(json.dumps(binding['closure'], sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    if closure_hash != binding['closureSha256']:
        raise ValueError('recorded compiler closure digest differs')
    closure = binding['closure']
    try:
        driver = closure['files'][closure['manifest']['tools']['gcc']]
    except (KeyError, TypeError) as failure:
        raise ValueError('recorded compiler driver identity missing') from failure
    if (driver['realpath'] != target['path'] or driver['sha256'] != target['sha256'] or
            driver['realpath'] != identity['realpath'] or driver['sha256'] != identity['sha256']):
        raise ValueError('recorded compiler driver disagrees with admitted profile identity')
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('phase expired during compiler recording validation')
    return {'binding': binding, 'recipe': recipe, 'target': target,
            'invocationMatched': (recipe['worker'] == binding['driverArgv'] and
                                  recipe['chdir'] == binding['workingDirectory'] and
                                  recipe['environment'] == binding['environment'])}


def _check_compiler_input_pins(recording, pins):
    if recording is None:
        return
    seen = set()
    for row in recording['binding']['dependencies']:
        if (type(row) is not dict or set(row) != {'path', 'sha256'} or row['path'] in seen or
                row['path'] not in pins or pins[row['path']]['sha256'] != row['sha256']):
            raise ValueError('recorded compiler input missing or changed in actual launch pins')
        seen.add(row['path'])


def _revalidate_compiler_inputs(launch, deadline=None):
    recording = launch.get('compilerRecording')
    if recording is not None:
        current = _recorded_compiler_inputs(recording['recipe'], recording['target'], deadline)
        if current != recording:
            raise ValueError('recorded compiler directory/selection/input binding changed')
        _check_compiler_input_pins(current, launch['pins'])


def _contained_recipe(argv: list[str], cwd: Path) -> dict:
    """Recognize closed existing recipes, with exact-file RO overlays over the sole RW leaf."""
    if not isinstance(argv, list) or not argv or argv[0] != '/usr/bin/bwrap':
        raise ValueError('host-direct worker execution is forbidden')
    if any(not isinstance(v, str) or '\0' in v for v in argv):
        raise ValueError('containment argv requires NUL-free strings')
    cwd = _work_directory(cwd)
    profile, _ = load_profile_with_digest()
    flags, pairs, mounts, environment, prefix = set(), [], [], {}, []
    zero = {'--unshare-all', '--unshare-user', '--die-with-parent', '--new-session', '--disable-userns', '--clearenv'}
    allowed = {'--cap-drop': {'ALL'}, '--proc': {'/proc'}, '--dev': {'/dev'},
               '--remount-ro': {'/', '/dev'}, '--size': {str(profile['bounds']['temporaryFilesystemBytes'])},
               '--tmpfs': {'/tmp'}, '--dir': {'/workspace'}, '--chdir': {'/work', '/workspace', str(cwd)}}
    index = 1
    while index < len(argv):
        option = argv[index]
        if option == '--':
            index += 1
            break
        if not option.startswith('--'):
            break
        if option in zero:
            if option in flags:
                raise ValueError('duplicate containment flag')
            flags.add(option); prefix.append(option); index += 1
        elif option in ('--ro-bind', '--bind', '--setenv'):
            if index + 2 >= len(argv):
                raise ValueError('truncated containment option')
            a, b = argv[index + 1:index + 3]
            if option == '--setenv':
                if a in environment:
                    raise ValueError('duplicate contained environment key')
                environment[a] = b
            else:
                original, guest = Path(a), Path(b)
                if not original.is_absolute() or not guest.is_absolute() or '..' in guest.parts:
                    raise ValueError('invalid mount path')
                source = original.resolve(strict=True)
                receipt_root = BASE / 'exec-proof-receipts'
                if source.is_relative_to(receipt_root) or receipt_root.is_relative_to(source):
                    raise ValueError('protected receipt storage would be worker-visible')
                if any(m['target'] == guest for m in mounts):
                    raise ValueError('duplicate/shadowed mount target')
                if original.as_posix() in profile['analysisIsolation']['readOnlySystemMounts']:
                    if option != '--ro-bind' or guest != original:
                        raise ValueError('system runtime must retain exact read-only mapping')
                elif source.is_dir():
                    if source != cwd or guest not in (Path('/work'), cwd):
                        raise ValueError('unreviewed parent/tree mount')
                elif not source.is_file():
                    raise ValueError('explicit input must be a regular file')
                elif (guest != original and guest.as_posix() not in ('/probe', '/caller', '/library.so') and
                      not (option == '--ro-bind' and source.is_relative_to(cwd) and
                           guest == Path('/work') / source.relative_to(cwd))):
                    raise ValueError('unreviewed file remapping')
                if option == '--bind' and (source != cwd or guest not in (Path('/work'), cwd)):
                    raise ValueError('only the exact owned work directory may be writable')
                if source.is_file() and source.is_relative_to(cwd) and source.stat().st_nlink != 1:
                    raise ValueError('read-only work input has an unprotected hard-link alias')
                mounts.append({'source': source, 'original': original, 'target': guest, 'writable': option == '--bind'})
            prefix += argv[index:index + 3]; index += 3
        elif option in allowed:
            if index + 1 >= len(argv) or argv[index + 1] not in allowed[option]:
                raise ValueError('containment option differs from the closed recipe')
            value = argv[index + 1]
            if (option, value) in pairs or (option != '--remount-ro' and any(k == option for k, _ in pairs)):
                raise ValueError('duplicate containment option')
            pairs.append((option, value)); prefix += [option, value]; index += 2
        else:
            raise ValueError('unreviewed retention/reuse/containment option')
    required = {('--cap-drop', 'ALL'), ('--proc', '/proc'), ('--dev', '/dev'),
                ('--remount-ro', '/dev'), ('--size', str(profile['bounds']['temporaryFilesystemBytes'])), ('--tmpfs', '/tmp')}
    if not zero <= flags or not required <= set(pairs) or not any(k == '--chdir' for k, _ in pairs):
        raise ValueError('fresh namespace recipe is incomplete')
    for directory in profile['analysisIsolation']['readOnlySystemMounts']:
        if Path(directory).exists() and not any(m['original'] == Path(directory) and m['target'] == Path(directory) and not m['writable'] for m in mounts):
            raise ValueError('declared system runtime mapping is missing')
    # Reject overlays that could replace the trusted runtime or reserved monitor path.
    for mount_index, mount in enumerate(mounts):
        target = mount['target']
        if any(other['writable'] and target.is_relative_to(other['target']) for other in mounts[mount_index + 1:]):
            raise ValueError('later writable bind would hide a read-only input overlay')
        if target == Path('/_worker_exec_monitor') or any(target != Path(d) and target.is_relative_to(Path(d)) for d in ('/usr', '/lib', '/lib64')):
            raise ValueError('input would shadow the trusted runtime')
        if mount['writable'] and any(other['source'].is_relative_to(mount['source']) and other['target'] != mount['target'] / other['source'].relative_to(mount['source']) for other in mounts if other != mount and other['source'].is_relative_to(mount['source'])):
            # /work aliases for existing probe mappings are intentional only on RO work.
            raise ValueError('writable work has an additional aliased mapping')
    worker = argv[index:]
    if not worker or not Path(worker[0]).is_absolute():
        raise ValueError('original worker executable must be absolute')
    _worker_environment(environment, cwd)
    matches = [m for m in mounts if Path(worker[0]).is_relative_to(m['target'])]
    if not matches:
        raise ValueError('worker executable is not explicitly mapped')
    selected = max(matches, key=lambda m: len(m['target'].parts))
    target = selected['source'] / Path(worker[0]).relative_to(selected['target'])
    return {'prefix': prefix, 'worker': worker, 'mounts': mounts, 'target': target,
            'environment': environment, 'chdir': next(v for k, v in pairs if k == '--chdir')}


def _create_worker_receipt() -> dict:
    root = BASE / 'exec-proof-receipts'
    root.mkdir(mode=0o700, exist_ok=True)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid():
        raise ValueError('protected receipt root identity/mode differs')
    root_identity = (metadata.st_dev, metadata.st_ino)
    directory = private_directory(root / uuid.uuid4().hex)
    directory_metadata = directory.lstat()
    path = directory / 'worker-proof.jsonl'
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_RDWR, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size or metadata.st_nlink != 1:
        os.close(descriptor)
        raise ValueError('protected receipt initial identity differs')
    return {'path': path, 'directory': directory, 'fd': descriptor, 'device': metadata.st_dev,
            'inode': metadata.st_ino, 'directoryDevice': directory_metadata.st_dev,
            'directoryInode': directory_metadata.st_ino, 'rootDevice': root_identity[0],
            'rootInode': root_identity[1]}


def _reclaim_worker_receipt(receipt, result, *, provisioning=False):
    """Delete only the stopped, consumed, closed attempt's fixed receipt layout.

    Unknown ownership/absence or unconsumed proof retains all diagnostics. No
    recursive removal, symlink traversal, arbitrary cache tree, or PID authority.
    All deletions are relative to held, independently revalidated directories.
    """
    facts = {'status': 'retained', 'reason': 'absence-proof-or-close-unverified'}
    if receipt is None or receipt.get('fd') is not None:
        return facts
    if (any(result.get(k) is not True for k in ('cleanupVerified', 'rootReaped', 'finalAbsenceVerified')) or
            not isinstance(result.get('kernelScope'), dict) or
            result['kernelScope'].get('finalAbsenceVerified') is not True):
        return facts
    if provisioning:
        consumed = (result.get('provisioningOnly') is True and result.get('infrastructureFailure') is False and
                    all(result.get(k) is True for k in ('launcherCreated', 'launcherPidIdentityVerified',
                        'scopeVerified', 'scopeAdmitted', 'captureComplete', 'waitComplete')) and
                    result.get('timedOut') is False and result.get('outputExceeded') is False and
                    type(result.get('exitCode')) is int and result.get('exitCode') == result.get('launcherExitCode'))
    else:
        consumed = worker_execution_complete(result)
        expected_proof = (result.get('workerProofBindings') or {}).get('expected', {})
        consumed = (consumed and expected_proof.get('attempt') == receipt['directory'].name and
                    (expected_proof.get('reportDevice'), expected_proof.get('reportInode')) ==
                    (receipt['device'], receipt['inode']))
    if not consumed:
        facts['reason'] = 'receipt-not-fully-consumed'
        return facts
    root_fd = directory_fd = cache_fd = None
    removed = []
    try:
        directory = receipt['directory']; root = BASE / 'exec-proof-receipts'
        if (directory.parent != root or len(directory.name) != 32 or
                any(c not in '0123456789abcdef' for c in directory.name)):
            raise ValueError('receipt path is not an owned attempt')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root_fd = os.open(root, flags)
        directory_fd = os.open(directory.name, flags, dir_fd=root_fd)
        def identity(metadata):
            return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
                    metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        def owned_directory(metadata, expected):
            if ((metadata.st_dev, metadata.st_ino) != expected or not stat.S_ISDIR(metadata.st_mode) or
                    stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid()):
                raise ValueError('receipt directory ownership changed')
        root_expected = (receipt['rootDevice'], receipt['rootInode'])
        directory_expected = (receipt['directoryDevice'], receipt['directoryInode'])
        def directories_unchanged():
            owned_directory(os.fstat(root_fd), root_expected)
            owned_directory(root.lstat(), root_expected)
            owned_directory(os.fstat(directory_fd), directory_expected)
            owned_directory(os.stat(directory.name, dir_fd=root_fd, follow_symlinks=False), directory_expected)
        directories_unchanged()
        expected = {'launch.json', 'gate.json', 'python-cache'}
        if not provisioning:
            expected.add('worker-proof.jsonl')
        names = set()
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if len(names) >= len(expected) or entry.name not in expected:
                    raise ValueError('unexpected receipt entry; retain attempt')
                names.add(entry.name)
        if names != expected:
            raise ValueError('receipt inventory incomplete; retain attempt')
        inventory = {}
        for name in sorted(expected - {'python-cache'}):
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or
                    metadata.st_uid != os.getuid() or metadata.st_nlink != 1):
                raise ValueError('receipt entry is not a private owned regular file')
            if name == 'worker-proof.jsonl' and (metadata.st_dev, metadata.st_ino) != (receipt['device'], receipt['inode']):
                raise ValueError('consumed report file was replaced')
            inventory[name] = identity(metadata)
        if not provisioning:
            # Preserve the already-consumed raw proof on the result. Refuse a
            # replacement/modification after proof consumption and FD closure.
            maximum = 1024
            proof_fd = os.open('worker-proof.jsonl', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                               dir_fd=directory_fd)
            try:
                before = os.fstat(proof_fd)
                if identity(before) != inventory['worker-proof.jsonl'] or before.st_size > maximum:
                    raise ValueError('consumed report identity/size differs')
                raw = os.read(proof_fd, maximum + 1)
                if (raw != result['workerProofRaw'] or len(raw) != before.st_size or
                        identity(os.fstat(proof_fd)) != identity(before)):
                    raise ValueError('consumed report bytes changed')
            finally:
                os.close(proof_fd)
        cache_fd = os.open('python-cache', flags, dir_fd=directory_fd)
        cache_metadata = os.fstat(cache_fd)
        cache_expected = (receipt['cacheDevice'], receipt['cacheInode'])
        owned_directory(cache_metadata, cache_expected)
        # Both controller and gate run with -B. An unexpected cache payload is
        # evidence to retain, never authority for recursive deletion.
        with os.scandir(cache_fd) as entries:
            if next(entries, None) is not None:
                raise ValueError('receipt Python cache is not empty')
        for name, expected_identity in inventory.items():
            directories_unchanged()
            if identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) != expected_identity:
                raise ValueError('receipt entry changed before deletion')
            os.unlink(name, dir_fd=directory_fd)
            removed.append(name)
        directories_unchanged()
        owned_directory(os.stat('python-cache', dir_fd=directory_fd, follow_symlinks=False), cache_expected)
        os.close(cache_fd); cache_fd = None
        os.rmdir('python-cache', dir_fd=directory_fd)
        removed.append('python-cache')
        directories_unchanged()
        os.close(directory_fd); directory_fd = None
        owned_directory(os.stat(directory.name, dir_fd=root_fd, follow_symlinks=False), directory_expected)
        os.rmdir(directory.name, dir_fd=root_fd)
        facts = {'status': 'removed', 'reason': 'owned-absence-consumption-and-close-verified',
                 'removedEntries': removed}
    except Exception as failure:
        facts = {'status': 'refused', 'reason': 'receipt-directory-reclamation-failed',
                 'secondaryError': type(failure).__name__ + ':' + str(failure)[:300], 'removedEntries': removed}
    finally:
        for descriptor in (cache_fd, directory_fd, root_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except Exception as failure:
                    facts = {'status': 'refused', 'reason': 'receipt-reclamation-handle-close-failed',
                             'secondaryError': type(failure).__name__ + ':' + str(failure)[:300], 'removedEntries': removed}
    return facts


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_directory(path: Path) -> Path:
    if not path.resolve().is_relative_to(BASE):
        raise ValueError('directory outside owned benchmark root')
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def write_json(path: Path, value: object) -> None:
    if not path.resolve().is_relative_to(BASE):
        raise ValueError('JSON outside owned benchmark root')
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def execution_bounds(timeout=None, output_limit=None, managed_scope=False, phase='unspecified', snapshot=None):
    """Declared limits, not proof of kernel enforcement or application/API execution."""
    profile, profile_sha = snapshot if snapshot is not None else load_profile_with_digest()
    b = profile['bounds']
    phases = {name: {'wallSeconds': b[wall], 'outputBytesPerStream': b[output]} for name, wall, output in [
        ('compiler','compilerSeconds','outputBytesPerStream'), ('probe','probeSeconds','helperOutputBytesPerStream'),
        ('runtime','runtimeSeconds','outputBytesPerStream'), ('elf-inspection','elfInspectionSeconds','outputBytesPerStream'),
        ('caller-build','callerBuildSeconds','outputBytesPerStream'), ('helper-build','helperBuildSeconds','helperOutputBytesPerStream'),
        ('toolchain-inspection','toolchainInspectionSeconds','helperOutputBytesPerStream')]}
    if phase != 'unspecified' and phase not in phases:
        raise ValueError('unknown execution phase')
    ceiling = phases.get(phase, {'wallSeconds': b['helperBuildSeconds'], 'outputBytesPerStream': b['helperOutputBytesPerStream']})
    timeout = (ceiling['wallSeconds'] if phase != 'unspecified' else b['defaultWallSeconds']) if timeout is None else timeout
    output_limit = (ceiling['outputBytesPerStream'] if phase != 'unspecified' else b['outputBytesPerStream']) if output_limit is None else output_limit
    import math
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= ceiling['wallSeconds']:
        raise ValueError('wall deadline outside declared phase bound')
    if type(output_limit) is not int or not 0 < output_limit <= ceiling['outputBytesPerStream']:
        raise ValueError('stream output outside declared phase bound')
    limits = enforced_process_limits()
    return {'schemaVersion': 3, 'profileSha256': profile_sha, 'phase': phase,
        'wallSeconds': timeout, 'outputBytesPerStream': output_limit, 'perProcessRlimits': limits,
        'cgroup': {'requested': bool(managed_scope), 'memoryBytes': b['memoryBytes'], 'swapBytes': b['swapBytes'],
                   'tasks': b['tasks'], 'aggregateCpuLimit': None, 'aggregateCpuLimitEnforced': False},
        'supervisor': {key: b[key] for key in ['stdinBytes','cleanupWaitSeconds','cleanupVerificationSeconds',
            'selectorPollSeconds','cleanupPollSeconds','scopeAdmissionSeconds','scopeAdmissionPollSeconds',
            'captureReadBytes','waitFloorSeconds','temporaryFilesystemBytes']},
        'workerExecProof': profile['workerExecProof'], 'workerLimits': {key: value for key, value in b.items() if key.startswith('worker')},
        'phaseLimits': phases, 'helperGraph': {key: b[key] for key in ['helperInputBytes','helperGraphNodes','helperGraphDepth']}}


def process_limits(limits=None) -> None:
    expected = enforced_process_limits()
    selected = expected if limits is None else limits
    if json.dumps(selected, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError('process limits differ from immutable profile')
    for name in ('RLIMIT_CORE','RLIMIT_CPU','RLIMIT_AS','RLIMIT_NOFILE','RLIMIT_FSIZE'):
        value = selected[name]
        resource.setrlimit(getattr(resource, name), (value['soft'], value['hard']))


def process_identity(pid: int) -> dict | None:
    try:
        value = Path(f'/proc/{pid}/stat').read_text()
        fields = value[value.rfind(')') + 2:].split()
        return {'pid': pid, 'start': int(fields[19]), 'pgid': int(fields[2]), 'sid': int(fields[3])}
    except (FileNotFoundError, ProcessLookupError):
        return None


def owned_processes(leader: int, root_start: int | None) -> list[dict]:
    current = process_identity(leader)
    if root_start is None:
        raise RuntimeError('owned launcher start identity is unknown')
    if current and current['start'] != root_start:
        raise RuntimeError('owned subprocess root PID reused')
    records = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            record = process_identity(int(entry.name))
            if record and (record['sid'] == leader or record['pgid'] == leader):
                records.append(record)
    return records


def kill_exact(record: dict) -> None:
    """Legacy numeric-PID records have no signalling authority, even with a fresh start tick."""
    raise RuntimeError('fresh numeric PID records cannot authorize signalling; acquired handles required')


def _scope_fd(evidence):
    descriptor = evidence.get('_directoryFd')
    if type(descriptor) is not int or descriptor < 0:
        raise RuntimeError('acquired owned cgroup descriptor is unavailable')
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (evidence['device'], evidence['inode']):
        raise RuntimeError('acquired owned cgroup descriptor identity changed')
    return descriptor


def scope_processes(evidence: dict | None) -> list[dict]:
    """Membership is absence evidence only; a cgroup.procs PID is NEVER signal authority."""
    if evidence is None:
        return []
    directory = _scope_fd(evidence)
    try:
        descriptor = os.open('cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    except OSError as failure:
        if failure.errno not in (errno.ENOENT, errno.ENODEV):
            raise
        # A removed cgroup cannot retain live members; do not consult a reused path/PID.
        if Path(evidence['cgroup']).exists():
            raise RuntimeError('cgroup membership is unavailable at a retained path') from failure
        return []
    try:
        raw = os.read(descriptor, 4097)
        if len(raw) > 4096:
            raise RuntimeError('owned cgroup membership byte bound')
    finally:
        os.close(descriptor)
    values = raw.decode('ascii').split()
    if len(values) > 32 or any(not p.isdecimal() or not 0 < int(p) < (1 << 31) for p in values):
        raise RuntimeError('owned cgroup task inventory differs from bound')
    return [{'pid': int(pid)} for pid in values]


def _kill_owned_scope(evidence):
    if evidence is None:
        return
    directory = _scope_fd(evidence)
    try:
        descriptor = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    except OSError as failure:
        if failure.errno in (errno.ENOENT, errno.ENODEV) and not Path(evidence['cgroup']).exists():
            return
        raise RuntimeError('acquisition-bound cgroup kill is unavailable') from failure
    try:
        # Kernel resolves membership from the retained cgroup, not a reused numeric PID.
        if os.write(descriptor, b'1\n') != 2:
            raise RuntimeError('owned cgroup kill write was incomplete')
    finally:
        os.close(descriptor)


def _kill_launcher(descriptor):
    if descriptor is None:
        raise RuntimeError('acquired launcher pidfd is unavailable')
    try:
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _fixed_source_module(path: Path, name: str):
    module = type(os)(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def _pin_files(paths, deadline=None) -> dict:
    """Admit the whole bounded file batch before payload opens; then nofollow/nonblocking reads."""
    limits = load_profile_with_digest()[0]['bounds']
    admitted = {}
    charged_entries = charged_bytes = 0
    fields = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
    def timely():
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('phase expired during input pin validation')
    def identity(metadata):
        return tuple(getattr(metadata, key) for key in fields)
    for item in paths:
        timely()
        charged_entries += 1
        if charged_entries > limits['workerLaunchPinEntries']:
            raise ValueError('launch pin inventory exceeds declared bound')
        path = Path(item).resolve(strict=True)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limits['workerLaunchPinFileBytes']:
            raise ValueError('launch pin is not a bounded regular file')
        if path in admitted:
            if identity(metadata) != identity(admitted[path]):
                raise ValueError('duplicate launch input changed during admission')
            continue
        admitted[path] = metadata
        charged_bytes += metadata.st_size
        # The same existing count x per-file policy bounds the complete batch; no new quota.
        if charged_bytes > limits['workerLaunchPinEntries'] * limits['workerLaunchPinFileBytes']:
            raise ValueError('launch pin batch exceeds declared work bound')
    if not admitted:
        raise ValueError('nonempty launch pin inventory required')
    result = {}
    for path, initial in admitted.items():
        timely()
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or identity(metadata) != identity(initial):
                raise ValueError('launch input changed after pre-open admission')
            digest_value = hashlib.sha256(); count = 0
            while True:
                timely()
                block = os.read(descriptor, min(65536, limits['workerLaunchPinFileBytes'] + 1 - count))
                if not block:
                    break
                count += len(block)
                if count > initial.st_size or count > limits['workerLaunchPinFileBytes']:
                    raise ValueError('launch pin byte bound')
                digest_value.update(block)
            after = os.fstat(descriptor); current = path.lstat()
            if count != initial.st_size or identity(after) != identity(initial) or identity(current) != identity(initial):
                raise ValueError('launch input changed during bounded pin read')
            timely()
            result[str(path)] = {'device': metadata.st_dev, 'inode': metadata.st_ino,
                                 'mode': stat.S_IMODE(metadata.st_mode), 'sha256': digest_value.hexdigest()}
        finally:
            os.close(descriptor)
    timely()
    return result



_SEALED_LIBRARY = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def _snapshot_library(path, receipt, deadline=None):
    """Bounded copy into an owned kernel-sealed object, never a mutable path mount."""
    pin = _pin_files([path], deadline)[str(path)]
    maximum = load_profile_with_digest()[0]['bounds']['workerLaunchPinFileBytes']
    source = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        metadata = os.fstat(source)
        if (not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum or
                (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode)) !=
                (pin['device'], pin['inode'], pin['mode'])):
            raise ValueError('runtime library source identity changed')
        descriptor = os.memfd_create('callable-runtime-library', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        receipt['librarySnapshotFd'] = descriptor  # owner closes even when preparation fails
        count = 0; digest_value = hashlib.sha256()
        while count < metadata.st_size:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('runtime library snapshot deadline')
            block = os.read(source, min(65536, metadata.st_size - count))
            if not block:
                raise ValueError('runtime library snapshot truncated')
            digest_value.update(block); count += len(block)
            view = memoryview(block)
            while view:
                written = os.write(descriptor, view)
                if written <= 0: raise ValueError('runtime library snapshot short write')
                view = view[written:]
        if digest_value.hexdigest() != pin['sha256']:
            raise ValueError('runtime library snapshot bytes differ from admitted input')
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _SEALED_LIBRARY)
        sealed = os.fstat(descriptor)
        if (fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & _SEALED_LIBRARY != _SEALED_LIBRARY or
                sealed.st_size != count):
            raise ValueError('runtime library snapshot not sealed')
        os.lseek(descriptor, 0, os.SEEK_SET)
        return {'device':sealed.st_dev, 'inode':sealed.st_ino, 'size':count,
                'sha256':pin['sha256'], 'sourcePath':str(path)}, pin
    finally:
        os.close(source)



def _committed_config(config):
    raw = (json.dumps(config, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    if not 0 < len(raw) <= 65536:
        raise ValueError('fixed launch configuration exceeds gate byte bound')
    return raw, hashlib.sha256(raw).hexdigest()


def _publish_config(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            if count <= 0: raise ValueError('launch config short write')
            view = view[count:]
    finally:
        os.close(descriptor)


def _lineage_identity(pid):
    with Path('/proc/' + str(pid) + '/stat').open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096: raise ValueError('lineage metadata byte bound')
    fields = raw[raw.rfind(b')') + 2:].split()
    return {'pid':pid, 'start':int(fields[19]), 'ppid':int(fields[1])}


def _acquire_gate_pidfd(gate, launch):
    root = launch.get('launcherIdentity')
    if not root: raise ValueError('owned launcher identity unavailable')
    def chain():
        rows=[];pid=gate['pid'];seen=set()
        for _ in range(load_profile_with_digest()[0]['bounds']['workerProcEntries']):
            if pid in seen or pid <= 0: raise ValueError('gate lineage is not owned')
            seen.add(pid);row=_lineage_identity(pid);rows.append(row)
            if pid == root['pid']:
                if row['start'] != root['start']: raise ValueError('launcher lifetime changed')
                if rows[0]['start'] != gate['start']: raise ValueError('gate lifetime changed')
                return rows
            pid=row['ppid']
        raise ValueError('gate lineage traversal bound')
    before=chain()
    descriptor=os.pidfd_open(gate['pid'])
    try:
        if chain()!=before or process_identity(root['pid'])!=root:
            raise ValueError('gate/launcher lineage changed during acquisition')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise



def _revalidate_scope(evidence, deadline):
    """Final observation of the held acquired cgroup and the exact gate member."""
    def timely():
        if time.monotonic()>=deadline:raise TimeoutError('scope revalidation deadline')
    timely()
    metadata=os.fstat(evidence['_directoryFd'])
    expected=(evidence['device'],evidence['inode'])
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev,metadata.st_ino)!=expected:
        raise ValueError('held scope identity changed before release')
    with Path('/proc/'+str(evidence['gateIdentity']['pid'])+'/cgroup').open('rb') as stream:
        membership=stream.read(4097)
    if len(membership)>4096 or membership.decode().strip()!=evidence['_membership']:
        raise ValueError('gate membership changed before release')
    current=Path(evidence['cgroup']).stat()
    if (current.st_dev,current.st_ino)!=expected:
        raise ValueError('scope pathname identity changed before release')
    for name,wanted in evidence['kernelLimits'].items():
        timely()
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=evidence['_directoryFd'])
        try:
            raw=os.read(fd,65)
            if len(raw)>64 or raw.decode().strip()!=wanted:
                raise ValueError('held scope limit changed before release')
        finally:os.close(fd)
    with Path('/proc/'+str(evidence['gateIdentity']['pid'])+'/cgroup').open('rb') as stream:
        membership=stream.read(4097)
    if len(membership)>4096 or membership.decode().strip()!=evidence['_membership']:
        raise ValueError('gate membership changed during final scope limits')
    timely()


def _release_scope(evidence, launch, deadline):
    if time.monotonic() >= deadline: raise TimeoutError('scope release deadline')
    gate = process_identity(evidence['gateIdentity']['pid'])
    if (process_identity(launch['launcherIdentity']['pid']) != launch['launcherIdentity'] or
            gate is None or gate['start'] != evidence['gateIdentity']['start']):
        raise ValueError('owned scope lifetime changed before release')
    _revalidate_scope(evidence,deadline)
    signal.pidfd_send_signal(evidence['_gatePidfd'], signal.SIGUSR1, None, 0)
    if time.monotonic() >= deadline: raise TimeoutError('scope release returned after deadline')


def _prepare_launch(argv, cwd, bounds, receipt, provisioning, deadline=None, runtime_library=None):
    outer = Path('/proc/self/ns/pid').stat()
    common = [Path(__file__), BASE / 'scope_gate.py', BASE / 'build_contract.py',
              BASE / 'contracts/candidate-build-profile.json', Path('/usr/bin/python3'), Path('/usr/bin/systemd-run')]
    expected = binding = target = compiler_recording = None
    library = library_pin = None
    if provisioning:
        command = list(argv)
        common += [Path('/usr/bin/gcc'), BASE / 'worker_exec_monitor.c']
    else:
        recipe = _contained_recipe(argv, cwd)
        binding = load_worker_monitor_binding()
        target = _nonprivileged_executable(recipe['target'], deadline)
        compiler_recording = _recorded_compiler_inputs(recipe, target, deadline)
        if compiler_recording is not None:
            common += [Path(row['path']) for row in compiler_recording['binding']['dependencies']]
        reaper = _nonprivileged_executable(Path('/usr/bin/bwrap'), deadline)
        monitor = _nonprivileged_executable(Path(binding['binaryPath']), deadline)
        common += [Path(target['path']), Path(reaper['path']), Path(monitor['path']),
                   BASE / 'worker_exec_monitor.c', BASE / 'worker_exec_proof.py',
                   BASE / 'contracts/worker-exec-proof-schema.json', BASE / 'toolchain-001/worker-exec-monitor.json',
                   BASE / 'toolchain-001/environment-pin.json', BASE / 'toolchain-001/pin_environment.py',
                   BASE / 'toolchain-001/link_inputs.py', BASE / 'toolchain-001/monitor_inputs.py']
        common += [Path(item['path']) for item in binding['dependencies']]
        # The closed recipe permits directories only for exact system roots or cwd.
        # Every other mount is an explicit regular input: pin its ACTUAL source, not a claimed row.
        system_roots = set(load_profile_with_digest()[0]['analysisIsolation']['readOnlySystemMounts'])
        common += [mount['source'] for mount in recipe['mounts']
                   if mount['source'] != cwd and str(mount['original']) not in system_roots]
        prefix = list(recipe['prefix'])
        library_mounts = [m for m in recipe['mounts'] if m['target'] == Path('/library.so')]
        if library_mounts:
            if len(library_mounts) != 1 or library_mounts[0]['writable'] or bounds['phase'] != 'runtime':
                raise ValueError('closed runtime library mapping required')
            mount = library_mounts[0]
            if (type(runtime_library) is not dict or set(runtime_library) != {'path','sha256'} or
                    runtime_library['path'] != str(mount['source']) or
                    type(runtime_library['sha256']) is not str or len(runtime_library['sha256']) != 64 or
                    any(c not in '0123456789abcdef' for c in runtime_library['sha256'])):
                raise ValueError('independently admitted runtime library bytes required')
            library, library_pin = _snapshot_library(mount['source'], receipt, deadline)
            if library['sha256'] != runtime_library['sha256']:
                raise ValueError('snapshot differs from admitted runtime library bytes')
            old = ['--ro-bind', str(mount['original']), '/library.so']
            positions = [i for i in range(len(prefix)-2) if prefix[i:i+3] == old]
            if len(positions) != 1: raise ValueError('runtime library mount substitution ambiguous')
            prefix[positions[0]:positions[0]+3] = ['--ro-bind-fd', '5', '/library.so']
        # Mount before root's optional read-only remount, including old immutable recipes.
        additions = ['--ro-bind', monitor['path'], '/_worker_exec_monitor']
        for path in load_profile_with_digest()[0]['analysisIsolation']['readOnlySystemFiles']:
            if not any(m['original'] == Path(path) and m['target'] == Path(path) for m in recipe['mounts']):
                additions += ['--ro-bind', path, path]
        insertion = next((i for i in range(len(prefix) - 1) if prefix[i:i + 2] == ['--remount-ro', '/']), len(prefix))
        prefix[insertion:insertion] = additions
        expected = {'attempt': receipt['directory'].name, 'phase': bounds['phase'],
                    'reportDevice': receipt['device'], 'reportInode': receipt['inode'],
                    'reaperDevice': reaper['device'], 'reaperInode': reaper['inode'],
                    'outerPidNsDevice': outer.st_dev, 'outerPidNsInode': outer.st_ino,
                    'targetDevice': target['device'], 'targetInode': target['inode']}
        if library is not None:
            expected['library'] = library
        monitor_argv = ['/_worker_exec_monitor', '--attempt', expected['attempt'], '--phase', bounds['phase'],
                        '--report-fd', '4', '--report-device', str(receipt['device']), '--report-inode', str(receipt['inode']),
                        '--reaper-device', str(reaper['device']), '--reaper-inode', str(reaper['inode']),
                        '--outer-pidns-device', str(outer.st_dev), '--outer-pidns-inode', str(outer.st_ino), '--', *recipe['worker']]
        if library is not None:
            index = monitor_argv.index('--')
            monitor_argv[index:index] = ['--library-device', str(library['device']), '--library-inode', str(library['inode']), '--library-size', str(library['size'])]
        command = ['/usr/bin/bwrap', *prefix, '--', *monitor_argv]
    pins = _pin_files(common, deadline)
    _check_compiler_input_pins(compiler_recording, pins)
    if library is not None and pins.get(library['sourcePath']) != library_pin:
        raise ValueError('runtime library input changed during preparation')
    unit = 'decomp-acp-efficacy-' + receipt['directory'].name + '.scope'
    config = {'schemaVersion': 1, 'directoryDevice': receipt['directoryDevice'],
              'directoryInode': receipt['directoryInode'], 'mode': 'monitor-provisioning' if provisioning else 'worker',
              'argv': command, 'report': None if provisioning else {'device': receipt['device'], 'inode': receipt['inode']},
              'outerPidNsDevice': outer.st_dev, 'outerPidNsInode': outer.st_ino,
              'scope':{'unit':unit,'limits':{'pids.max':str(bounds['cgroup']['tasks']),
                       'memory.max':str(bounds['cgroup']['memoryBytes']),
                       'memory.swap.max':str(bounds['cgroup']['swapBytes'])}}}
    if library is not None:
        owner = process_identity(os.getpid())
        if owner is None: raise ValueError('snapshot owner lifetime unavailable')
        config['librarySnapshot'] = {'ownerPid':os.getpid(), 'ownerStart':owner['start'],
                                     'descriptor':receipt['librarySnapshotFd'], 'library':library}
    raw_config, config_sha = _committed_config(config)
    _publish_config(receipt['directory'] / 'launch.json', raw_config)
    cache = private_directory(receipt['directory'] / 'python-cache')
    cache_metadata = cache.lstat()
    receipt.update(cacheDevice=cache_metadata.st_dev, cacheInode=cache_metadata.st_ino)
    launcher = ['/usr/bin/systemd-run', '--user', '--scope', '--quiet', '--collect', '--no-ask-password',
                '--unit=' + unit, '--property=TasksMax=' + str(bounds['cgroup']['tasks']),
                '--property=MemoryMax=' + str(bounds['cgroup']['memoryBytes']),
                '--property=MemorySwapMax=' + str(bounds['cgroup']['swapBytes']),
                '/usr/bin/python3', '-I', '-B', '-X', 'pycache_prefix=' + str(cache),
                str(BASE / 'scope_gate.py'), str(receipt['directory']), '--config-sha256', config_sha,
                '--controller', str(os.getpid()), str(process_identity(os.getpid())['start']), str(os.getuid()),
                '--phase-deadline', repr(deadline if deadline is not None else time.monotonic() + bounds['wallSeconds'])]
    proof_binding = None if provisioning else {
        'protocolVersion':1, 'expected':expected, 'launchConfigSha256':config_sha,
        'environmentPinSha256':binding['environmentPinSha256'], 'monitorBinarySha256':binding['binarySha256'],
        'monitorSourceSha256':binding['sourceSha256'], 'protocolSha256':binding['protocolSha256'],
        'parserSha256':binding['parserSha256'], 'manifestSha256':binding['manifestSha256'],
        'targetSha256':target['sha256'], 'launchPinsSha256':_canonical_pin_digest(pins)}
    return {'argv': launcher, 'unit': unit, 'expected': expected, 'pins': pins,
            'command': command, 'cache': cache, 'configSha256': config_sha, 'proofBinding':proof_binding,
            'compilerRecording': compiler_recording}


def _read_private_json(path, maximum=4096):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
                stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
            raise ValueError('private controller file identity differs')
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum:
            raise ValueError('private controller file byte bound')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate controller key')
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=unique)
    finally:
        os.close(descriptor)


def _admit_scope(receipt, launch, bounds):
    path = receipt['directory'] / 'gate.json'
    if not path.exists():
        return None
    gate = _read_private_json(path)
    if (set(gate) != {'pid', 'start'} or any(type(gate[k]) is not int or gate[k] <= 0 for k in gate)):
        raise ValueError('scope gate process identity is invalid')
    child = process_identity(gate['pid'])
    if not child or child['start'] != gate['start']:
        raise ValueError('scope gate process identity changed')
    cgroup_record = Path(f"/proc/{gate['pid']}/cgroup").read_text().strip()
    if not cgroup_record.startswith('0::/') or '\n' in cgroup_record:
        raise ValueError('scope gate cgroup record is invalid')
    cgroup = Path('/sys/fs/cgroup') / cgroup_record[4:]
    if not cgroup.resolve().is_relative_to(Path('/sys/fs/cgroup')) or cgroup.name != launch['unit']:
        raise ValueError('scope gate cgroup path differs')
    values = {name: (cgroup / name).read_text().strip() for name in ('pids.max', 'memory.max', 'memory.swap.max')}
    if values != {'pids.max': str(bounds['cgroup']['tasks']), 'memory.max': str(bounds['cgroup']['memoryBytes']), 'memory.swap.max': str(bounds['cgroup']['swapBytes'])}:
        raise ValueError('scope gate kernel limits differ')
    directory_fd = os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(directory_fd)
        raise ValueError('scope descriptor is not a cgroup directory')
    try:
        gate_pidfd = _acquire_gate_pidfd(gate, launch)
    except BaseException:
        os.close(directory_fd)
        raise
    try:
        evidence = {'unit': launch['unit'], 'cgroup': str(cgroup), 'device': metadata.st_dev,
                    'inode': metadata.st_ino, '_directoryFd': directory_fd, '_gatePidfd':gate_pidfd, '_membership':cgroup_record, 'gateIdentity': gate, 'kernelLimits': values,
                    'systemdRunSha256': launch['pins'][str(Path('/usr/bin/systemd-run').resolve())]['sha256'],
                    'scopeGateSha256': launch['pins'][str(BASE / 'scope_gate.py')]['sha256']}
        # Reread limits via the acquired directory, so pathname substitution cannot authenticate it.
        acquired = {}
        for name in ('pids.max','memory.max','memory.swap.max'):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            try:
                raw = os.read(fd, 65)
                if len(raw) > 64:
                    raise ValueError('scope limit metadata byte bound')
                acquired[name] = raw.decode('ascii').strip()
            finally:
                os.close(fd)
        if acquired != values:
            raise ValueError('acquired scope kernel limits differ')
        current = cgroup.stat()
        if (current.st_dev,current.st_ino) != (metadata.st_dev,metadata.st_ino):
            raise ValueError('scope path changed during acquisition')
        if process_identity(gate['pid']) != child:
            raise ValueError('scope gate identity changed during acquisition')
        if Path(f"/proc/{gate['pid']}/cgroup").read_text().strip() != cgroup_record:
            raise ValueError('scope gate membership changed during acquisition')
        return evidence
    except BaseException:
        os.close(gate_pidfd)
        os.close(directory_fd)
        raise


def _finish_worker_proof(result, receipt, launch, bounds, deadline=None):
    proof = {'protocolVersion': 1, 'status': 'unknown', 'proofSha256': None,
             'fileIdentityVerified': False, 'pinsUnchanged': False, 'reason': 'proof-not-read'}
    result['workerProof'] = proof
    if receipt is None or launch is None:
        proof['reason'] = 'launch-not-prepared'
        return
    try:
        if not result['cleanupVerified'] or not result['finalAbsenceVerified']:
            raise ValueError('owned process absence is unverified')
        directory = receipt['directory'].lstat()
        descriptor = os.fstat(receipt['fd'])
        path = receipt['path'].lstat()
        expected = (receipt['device'], receipt['inode'])
        if ((directory.st_dev, directory.st_ino) != (receipt['directoryDevice'], receipt['directoryInode']) or
                not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode) != 0o700 or directory.st_uid != os.getuid()):
            raise ValueError('receipt directory identity changed')
        for value in (descriptor, path):
            if ((value.st_dev, value.st_ino) != expected or not stat.S_ISREG(value.st_mode) or
                    stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1 or value.st_uid != os.getuid()):
                raise ValueError('receipt file identity changed')
        maximum = bounds['workerLimits']['workerProofBytes']
        raw = os.pread(receipt['fd'], maximum + 1, 0)
        after = os.fstat(receipt['fd'])
        if any(getattr(after, key) != getattr(descriptor, key) for key in ('st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('receipt changed during bounded read')
        result['workerProofRaw'] = raw
        proof['proofSha256'] = hashlib.sha256(raw).hexdigest()
        proof['fileIdentityVerified'] = True
        if descriptor.st_size != len(raw) or len(raw) > maximum:
            raise ValueError('receipt byte bound')
        if _pin_files(launch['pins'], deadline) != launch['pins'] or digest(receipt['directory'] / 'launch.json') != launch['configSha256']:
            raise ValueError('launch source/runtime/input pins changed')
        _revalidate_compiler_inputs(launch, deadline)
        proof['pinsUnchanged'] = True
        parser = _fixed_source_module(BASE / 'worker_exec_proof.py', '_v3_worker_exec_proof')
        parsed = parser.parse_proof(raw, launch['expected'])
        proof.update(status=parsed['status'], proofSha256=parsed['proofSha256'], reason=parsed['reason'])
        result.update(workerExecVerified=parsed['workerExecVerified'],
                      workerTerminationVerified=parsed['workerTerminationVerified'], workerTermination=parsed['workerTermination'])
        if (parsed['status'] == 'verified' and result['launcherExitCode'] == 0 and
                result['captureComplete'] and result['waitComplete'] and result['scopeVerified'] and
                result['scopeAdmitted'] and result['launcherPidIdentityVerified'] and
                not result['timedOut'] and not result['outputExceeded'] and not result['infrastructureFailure']):
            result['exitCode'] = parsed['exitCode']
        else:
            result['infrastructureFailure'] = True
            result['infrastructureReason'] = 'worker-proof-or-controller-chain-incomplete'
    except Exception as failure:
        proof['status'] = 'unknown'
        proof['reason'] = 'receipt-validation-' + type(failure).__name__
        result['infrastructureFailure'] = True
        result['infrastructureReason'] = 'worker-proof-validation-failed'
        result['exitCode'] = None


def bounded_run(argv: list[str], cwd: Path, environment: dict[str, str], stdin: bytes = b'',
                timeout: float | None = None, output_limit: int | None = None,
                managed_scope: bool = False, phase: str = 'unspecified', runtime_library=None) -> dict:
    """Every worker requires contained admission/proof; launcher exit never substitutes."""
    bounds = execution_bounds(timeout, output_limit, managed_scope, phase)
    if type(stdin) is not bytes or len(stdin) > bounds['supervisor']['stdinBytes']:
        raise ValueError('bounded subprocess stdin exceeds profile')
    if managed_scope is not True:
        raise ValueError('unscoped worker execution is forbidden')
    return _run_scoped(argv, cwd, environment, stdin, bounds, provisioning=False, **({'runtime_library':runtime_library} if runtime_library is not None else {}))


def provision_worker_monitor(output: Path) -> dict:
    """The sole channel-free exception: fixed public monitor source, never candidate authority."""
    output = Path(output)
    root = _repository_root() / 'build/acp-decomp-effectiveness/callable-library-v3'
    if (not output.is_absolute() or output != output.resolve() or not output.is_relative_to(root) or
            output.name != 'worker_exec_monitor' or output.exists() or output.is_symlink()):
        raise ValueError('fresh fixed-name public monitor output required')
    cwd = _work_directory(output.parent)
    argv = ['/usr/bin/gcc', '-D_GNU_SOURCE', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-Wl,-z,relro,-z,now,-z,noexecstack', str(BASE / 'worker_exec_monitor.c'), '-o', str(output)]
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': str(cwd)}
    return _run_scoped(argv, cwd, environment, b'', execution_bounds(managed_scope=True, phase='helper-build'), provisioning=True)


def _run_scoped(argv, cwd, environment, stdin, bounds, *, provisioning, runtime_library=None):
    began = time.monotonic()
    supervisor = bounds['supervisor']; timeout = bounds['wallSeconds']; output_limit = bounds['outputBytesPerStream']
    result = {key: False for key in ('launcherCreated', 'launcherPidIdentityVerified', 'scopeVerified', 'scopeAdmitted',
                                    'captureComplete', 'waitComplete', 'cleanupVerified', 'rootReaped', 'finalAbsenceVerified',
                                    'timedOut', 'outputExceeded', 'infrastructureFailure', 'workerExecVerified', 'workerTerminationVerified')}
    result.update(argv=argv, exitCode=None, launcherExitCode=None, workerTermination=None, workerProof=None,
                  workerProofRaw=b'', workerProofBindings=None, launchInputPins=None, provisioningOnly=provisioning, infrastructureReason=None,
                  bounds=bounds, rootPid=None, kernelScope=None, stdout=b'', stderr=b'')
    process = selector = receipt = launch = scope_evidence = root_start = None
    launch_attempted = False
    launcher_pidfd = None
    phase_elapsed = cleanup_began = verification_end = None
    captured = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        cwd = _work_directory(cwd)
        _worker_environment(environment, cwd)
        receipt = _create_worker_receipt()
        if provisioning:
            # No report descriptor/channel exists for this fixed trusted compiler exception.
            os.close(receipt['fd']); receipt['fd'] = None
            receipt['path'].unlink()
        launch = _prepare_launch(argv, cwd, bounds, receipt, provisioning, deadline=began + timeout, **({'runtime_library':runtime_library} if runtime_library is not None else {}))
        result.update(workerProofBindings=launch['proofBinding'], launchInputPins=launch['pins'])
        host_environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                            'HOME': str(receipt['directory']), 'TMPDIR': str(receipt['directory']),
                            'XDG_CACHE_HOME': str(receipt['directory']),
                            'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{os.getuid()}/bus'}
        if time.monotonic() - began >= timeout:
            raise TimeoutError('phase expired before launcher creation')
        launch_attempted = True
        process = subprocess.Popen(launch['argv'], cwd=receipt['directory'], env=host_environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True, start_new_session=True,
                                   preexec_fn=lambda: process_limits(bounds['perProcessRlimits']))
        result.update(launcherCreated=True, rootPid=process.pid)
        # Popen's direct child is not waited/polled/reaped before acquiring this lifetime handle.
        launcher_pidfd = os.pidfd_open(process.pid)
        root = process_identity(process.pid)
        root_start = root['start'] if root else None
        launch['launcherIdentity'] = root
        result['launcherPidIdentityVerified'] = root is not None
        selector = selectors.DefaultSelector()
        process.stdin.write(stdin); process.stdin.close()
        for label, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = timeout - (time.monotonic() - began)
            if remaining <= 0:
                raise TimeoutError('bounded worker phase deadline')
            if scope_evidence is None:
                scope_evidence = _admit_scope(receipt, launch, bounds)
                if scope_evidence is not None:
                    result.update(scopeVerified=True, kernelScope={k:v for k,v in scope_evidence.items() if not k.startswith('_')})
                    # State owns cgroup/gate handles before any authenticated release attempt.
                    _release_scope(scope_evidence, launch, began + timeout)
                    result.update(scopeVerified=True, scopeAdmitted=True, kernelScope={k:v for k,v in scope_evidence.items() if not k.startswith('_')})
            for key, _ in selector.select(min(remaining, supervisor['selectorPollSeconds'])):
                block = os.read(key.fileobj.fileno(), supervisor['captureReadBytes'])
                if not block:
                    selector.unregister(key.fileobj); continue
                available = output_limit - len(captured[key.data])
                captured[key.data].extend(block[:available])
                if len(block) > available:
                    result['outputExceeded'] = True
                    raise ValueError('bounded worker output exceeded limit')
        result['captureComplete'] = True
        remaining = timeout - (time.monotonic() - began)
        if remaining <= 0:
            raise TimeoutError('phase expired before wrapper wait')
        result['launcherExitCode'] = process.wait(timeout=max(supervisor['waitFloorSeconds'], remaining))
        result['waitComplete'] = True
        if scope_evidence is None:
            raise AssertionError('worker scope was never kernel-verified')
    except Exception as failure:
        result['timedOut'] = isinstance(failure, (TimeoutError, subprocess.TimeoutExpired))
        result['infrastructureFailure'] = True
        result['infrastructureReason'] = 'scope-launch-or-worker-controller-failed'
        result.update(failureClass=type(failure).__name__, reason='bounded controller refused or failed')
        failure.bounded_result = result
        raise
    finally:
        primary_failure = sys.exception()
        phase_elapsed = time.monotonic() - began
        cleanup_began = time.monotonic()
        cleanup_failure = None
        if selector is not None:
            try:
                selector.close()
            except Exception as failure:
                cleanup_failure = failure
        try:
            if process is not None:
                wait_end = cleanup_began + supervisor['cleanupWaitSeconds']
                _kill_owned_scope(scope_evidence)
                _kill_launcher(launcher_pidfd)
                remaining = wait_end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('cleanup wait window expired before wait')
                cleanup_code = process.wait(timeout=remaining)
                result['rootReaped'] = True
                if result['launcherExitCode'] is None:
                    result['launcherExitCode'] = cleanup_code
                wait_observed = time.monotonic()
                if wait_observed >= wait_end:
                    raise TimeoutError('cleanup wait returned after its absolute end')
                # One separate subsequent verification window, never renewed by a scan/retry.
                verification_end = wait_observed + supervisor['cleanupVerificationSeconds']
                while True:
                    if time.monotonic() >= verification_end:
                        raise TimeoutError('cleanup absence window expired before observation')
                    scoped = scope_processes(scope_evidence)
                    session = owned_processes(process.pid, root_start)
                    if time.monotonic() >= verification_end:
                        raise TimeoutError('cleanup absence observation returned after its absolute end')
                    if not scoped and not session:
                        break
                    _kill_owned_scope(scope_evidence)
                    remaining = verification_end - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('cleanup absence window expired after owned kill')
                    time.sleep(min(supervisor['cleanupPollSeconds'], remaining))
                if time.monotonic() >= verification_end:
                    raise TimeoutError('final cleanup verification returned late')
                if scope_evidence is not None:
                    scope_evidence['finalAbsenceVerified'] = True
                    result['kernelScope']['finalAbsenceVerified'] = True
                result.update(rootReaped=True, finalAbsenceVerified=True, cleanupVerified=True)
                if result['launcherExitCode'] is None:
                    result['launcherExitCode'] = process.returncode if type(process.returncode) is int else None
            elif not launch_attempted:
                result.update(finalAbsenceVerified=True, cleanupVerified=True)
            else:
                # No process handle means no owned PID/cgroup identity to verify safely.
                result.update(finalAbsenceVerified=False, cleanupVerified=False)
        except Exception as failure:
            cleanup_failure = failure
            result.update(cleanupVerified=False, infrastructureFailure=True, infrastructureReason='owned-cleanup-unverified')
        if process is not None:
            for label, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
                try:
                    # One nonblocking bounded drain retains partial wrapper behavior on failure.
                    block = os.read(stream.fileno(), supervisor['captureReadBytes'])
                    available = max(0, output_limit - len(captured[label]))
                    captured[label].extend(block[:available])
                    if len(block) > available:
                        result['outputExceeded'] = True
                except (BlockingIOError, OSError, ValueError):
                    pass
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    stream.close()
                except Exception as failure:
                    cleanup_failure = cleanup_failure or failure
                    result.update(cleanupVerified=False, infrastructureFailure=True, infrastructureReason='capture-close-failed')
        result.update(stdout=bytes(captured['stdout']), stderr=bytes(captured['stderr']),
                      elapsedSeconds=round(time.monotonic() - began, 6))
        for descriptor in (launcher_pidfd, scope_evidence.get('_directoryFd') if scope_evidence is not None else None,
                           scope_evidence.get('_gatePidfd') if scope_evidence is not None else None):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except Exception as failure:
                    cleanup_failure = cleanup_failure or failure
                    result.update(cleanupVerified=False, infrastructureFailure=True, infrastructureReason='owned-handle-close-failed', exitCode=None)
        if verification_end is not None and time.monotonic() >= verification_end:
            cleanup_failure = cleanup_failure or TimeoutError('cleanup final observations/closures returned after absolute end')
            result.update(cleanupVerified=False, finalAbsenceVerified=False)
            if result['kernelScope'] is not None:
                result['kernelScope']['finalAbsenceVerified'] = False
        if cleanup_failure is not None:
            result.update(cleanupVerified=False, infrastructureFailure=True, infrastructureReason='controller-close-failed')
        proof_began = time.monotonic()
        result['cleanupElapsedSeconds'] = round(proof_began - cleanup_began, 6)
        if provisioning:
            try:
                if launch is not None and _pin_files(launch['pins'], time.monotonic() + max(0, timeout - phase_elapsed)) != launch['pins']:
                    raise ValueError('provisioning pins changed')
            except Exception:
                result.update(infrastructureFailure=True, infrastructureReason='provisioning-input-pins-changed')
            if (not result['infrastructureFailure'] and result['scopeVerified'] and result['scopeAdmitted'] and
                    result['launcherPidIdentityVerified'] and result['captureComplete'] and result['waitComplete'] and
                    result['cleanupVerified'] and not result['outputExceeded'] and not result['timedOut']):
                result['exitCode'] = result['launcherExitCode']
        else:
            _finish_worker_proof(result, receipt, launch, bounds, deadline=time.monotonic() + max(0, timeout - phase_elapsed))
        if receipt is not None and receipt.get('librarySnapshotFd') is not None:
            try:
                os.close(receipt['librarySnapshotFd'])
            except Exception:
                result.update(infrastructureFailure=True, infrastructureReason='library-snapshot-close-failed', exitCode=None)
            finally:
                receipt['librarySnapshotFd'] = None
        if receipt is not None and receipt['fd'] is not None:
            try:
                os.close(receipt['fd'])
                receipt['fd'] = None
            except Exception as failure:
                cleanup_failure = cleanup_failure or failure
                result.update(cleanupVerified=False, infrastructureFailure=True, infrastructureReason='receipt-close-failed', exitCode=None)
        result['phaseElapsedSeconds'] = round(phase_elapsed + time.monotonic() - proof_began, 6)
        if result['phaseElapsedSeconds'] >= timeout:
            result.update(timedOut=True, infrastructureFailure=True, infrastructureReason='phase-budget-exhausted', exitCode=None)
        reclamation_failure = None
        result['_receiptCleanup'] = _reclaim_worker_receipt(receipt, result, provisioning=provisioning)
        if result['_receiptCleanup']['status'] == 'refused':
            reclamation_failure = ValueError('owned receipt directory reclamation failed')
            reclamation_failure.bounded_result = result
            reclamation_failure.receiptCleanup = result['_receiptCleanup']
            result.update(infrastructureFailure=True, infrastructureReason='receipt-directory-reclamation-failed')
            if primary_failure is not None:
                primary_failure.receiptCleanup = result['_receiptCleanup']
        result['phaseElapsedSeconds'] = round(phase_elapsed + time.monotonic() - proof_began, 6)
        if result['phaseElapsedSeconds'] >= timeout:
            result.update(timedOut=True, infrastructureFailure=True, infrastructureReason='phase-budget-exhausted', exitCode=None)
        result['elapsedSeconds'] = round(time.monotonic() - began, 6)
        if cleanup_failure is not None:
            cleanup_failure.bounded_result = result
            cleanup_failure.receiptCleanup = result['_receiptCleanup']
            raise cleanup_failure
        if reclamation_failure is not None and primary_failure is None:
            raise reclamation_failure
    return result


def public_result(result: dict) -> dict:
    return {**{k: v for k, v in result.items() if k not in ('stdout', 'stderr', 'workerProofRaw', '_receiptCleanup')},
            'stdoutHex': result['stdout'].hex(), 'stderrHex': result['stderr'].hex(),
            'workerProofRawHex': result.get('workerProofRaw', b'').hex()}

