"""Bounded v3 process runner; declared bounds are separate from observed process facts."""
from __future__ import annotations

import hashlib
import fcntl
import errno
import json
import math
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
from threading import Lock
import uuid

BASE = Path(__file__).resolve().parent

# Controller census bounds, distinct from sandbox/worker inventory authority.
# The scan budget includes the advance that must observe EOF; exhausting it
# without EOF is unverified, even if the next advance would have ended the scan.
CONTROLLER_PROC_SCAN_ENTRIES = 256
CONTROLLER_PROC_STAT_BYTES = 4096

from build_contract import load_profile_with_digest, enforced_process_limits, digest as _retained_digest


def _canonical_pin_digest(pins: dict) -> str:
    return hashlib.sha256(json.dumps(pins, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


# Independent reviewed parser version, not a result/profile-provided digest.
_WORKER_PROOF_PARSER_BYTES = 10003
_WORKER_PROOF_PARSER_SHA256 = '7174d956dbb2cb69c46b34847dc1a0505e8cd9993e8cbc26377d2889cd863bec'
_WORKER_PROOF_MAX_BYTES = 1024
_WORKER_PROOF_PARSER_VERSION = (_WORKER_PROOF_PARSER_BYTES, _WORKER_PROOF_PARSER_SHA256, _WORKER_PROOF_MAX_BYTES)
_WORKER_PROOF_PARSER_CACHE = None
_WORKER_PROOF_PARSER_LOCK = Lock()


def _worker_proof_parser(deadline=None):
    """Select a private fixed-version callable; busy initialization refuses, never waits."""
    global _WORKER_PROOF_PARSER_CACHE
    _monitor_loader_timely(deadline)
    selected = _WORKER_PROOF_PARSER_CACHE
    published = None
    try:
        if selected is None:
            if not _WORKER_PROOF_PARSER_LOCK.acquire(False):
                raise ValueError('authenticated proof parser initialization is busy')
            try:
                selected = _WORKER_PROOF_PARSER_CACHE
                if selected is None:
                    path = BASE / 'worker_exec_proof.py'
                    raw = _capture_monitor_source(path, _WORKER_PROOF_PARSER_BYTES, deadline)
                    _monitor_loader_timely(deadline)
                    if len(raw) != _WORKER_PROOF_PARSER_BYTES or hashlib.sha256(raw).hexdigest() != _WORKER_PROOF_PARSER_SHA256:
                        raise ValueError('authenticated proof parser source bytes differ')
                    _monitor_loader_timely(deadline)
                    module = type(os)('_v3_authenticated_worker_proof')
                    module.__file__ = str(path)
                    code = compile(raw, str(path), 'exec')
                    _monitor_loader_timely(deadline)
                    exec(code, module.__dict__)
                    _monitor_loader_timely(deadline)
                    parser = module.parse_proof
                    if not callable(parser) or module.MAX_PROOF_BYTES != _WORKER_PROOF_MAX_BYTES:
                        raise ValueError('authenticated proof parser interface differs')
                    selected = (_WORKER_PROOF_PARSER_VERSION, parser)
                    _monitor_loader_timely(deadline)
                    _WORKER_PROOF_PARSER_CACHE = selected
                    published = selected
            finally:
                _WORKER_PROOF_PARSER_LOCK.release()
            _monitor_loader_timely(deadline)
        # Final admission/first callable return remain in this invocation's
        # publication rollback guard; warm refusal owns no publication to clear.
        _monitor_loader_timely(deadline)
        if (type(selected) is not tuple or len(selected) != 2 or selected[0] != _WORKER_PROOF_PARSER_VERSION or
                not callable(selected[1])):
            raise ValueError('authenticated proof parser cache version differs')
        return selected[1]
    except BaseException:
        if published is not None and _WORKER_PROOF_PARSER_CACHE is published:
            _WORKER_PROOF_PARSER_CACHE = None
        raise


def _parse_worker_proof(raw, expected, *, deadline=None):
    parser = _worker_proof_parser(deadline)
    _monitor_loader_timely(deadline)
    parsed = parser(raw, expected)
    _monitor_loader_timely(deadline)
    return parsed


def _helper_execution_pin(result, helper_sha):
    """Historical acquired-H row only; never reopen the serialized coordinate."""
    binding = result.get('workerProofBindings') or {}
    expected = binding.get('expected') or {}
    if expected.get('phase') != 'probe' or result.get('bounds', {}).get('phase') != 'probe':
        return None
    found = []
    for name, row in (result.get('launchInputPins') or {}).items():
        if type(name) is not str or type(row) is not dict:
            return None
        parts = Path(name).parts
        if (len(parts) == 5 and parts[:2] == ('/', 'proc') and parts[3] == 'fd' and
                0 < len(parts[2]) <= 19 and 0 < len(parts[4]) <= 10 and
                parts[2].isascii() and parts[2].isdecimal() and parts[4].isascii() and parts[4].isdecimal() and
                str(int(parts[2])) == parts[2] and 0 < int(parts[2]) <= (1 << 63) - 1 and
                str(int(parts[4])) == parts[4] and 0 <= int(parts[4]) <= (1 << 31) - 1 and
                (row.get('device'), row.get('inode')) == (expected.get('targetDevice'), expected.get('targetInode')) and
                type(row.get('mode')) is int and row['mode'] == 0o500 and row.get('sha256') == helper_sha):
            found.append((name, row))
    return found[0] if len(found) == 1 else None


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
    profile_pin = pins.get(str(BASE / 'contracts/candidate-build-profile.json'))
    if profile_pin is None or profile_pin['sha256'] != bounds['profileSha256']:
        return False
    parser_pin = pins.get(str(BASE / 'worker_exec_proof.py'))
    if (binding['parserSha256'] != _WORKER_PROOF_PARSER_SHA256 or parser_pin is None or
            parser_pin['sha256'] != _WORKER_PROOF_PARSER_SHA256):
        return False
    if _canonical_pin_digest(pins) != binding['launchPinsSha256']:
        return False
    def matches(prefix, digest=None):
        return any((row['device'], row['inode']) == (expected[prefix+'Device'], expected[prefix+'Inode']) and
                   (digest is None or row['sha256'] == digest) for row in pins.values())
    if not matches('target', binding['targetSha256']) or not matches('reaper'):
        return False
    if expected['phase'] == 'probe' and _helper_execution_pin(result, binding['targetSha256']) is None:
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
        parsed = _parse_worker_proof(raw, result['workerProofBindings']['expected'])
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


# Reviewed source expectations, not a mutable manifest or discovered generation.
# pin_environment must be rebound here after any reviewed injection/loader edit.
_MONITOR_LOADER_SOURCES = (
    ('toolchain-001/pin_environment.py', 10310, '3874bc92ba6befb9da9c71a08a21a509ac3c11dc089b3fc1d5ed356dcf7d84a2'),
    ('toolchain-001/link_inputs.py', 38357, '8e36065f38aed067c758cf7e6b0420228aa8074d023e4ebbf57b3b7ffbea7176'),
    ('toolchain-001/monitor_inputs.py', 14964, '0cab347a7874162840bdda8b0dc138782657ddaf592b8e3a51b3c59c731838d1'),
)


def _monitor_loader_timely(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('phase expired during authenticated monitor loader')


def _capture_monitor_source(path, expected_size, deadline=None):
    """Stable finite source bytes; checks refuse late completion, not preempt syscalls."""
    _monitor_loader_timely(deadline)
    path = Path(path)
    if (not path.is_absolute() or '..' in path.parts or len(path.parts) > 128 or
            len(str(path)) > 4096 or not path.name or
            type(expected_size) is not int or not 0 < expected_size <= 16777216):
        raise ValueError('fixed monitor loader source bound')
    # At most root +126 parent components +leaf. Ownership precedes the post-open check.
    descriptors = [None] * 128
    count = 0
    directories = []
    primary = None
    def checked(operation, *args, **kwargs):
        _monitor_loader_timely(deadline)
        value = operation(*args, **kwargs)
        _monitor_loader_timely(deadline)
        return value
    def opened(name, flags, **kwargs):
        nonlocal count
        _monitor_loader_timely(deadline)
        descriptor = os.open(name, flags, **kwargs)
        descriptors[count] = descriptor
        count += 1
        _monitor_loader_timely(deadline)
        return descriptor
    def version(metadata):
        return tuple(getattr(metadata, key) for key in
            ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    def directory_version(metadata):
        return tuple(getattr(metadata, key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid'))
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = opened('/', flags)
        metadata = checked(os.fstat, descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError('loader source parent must be directory')
        directories.append((descriptor, None, None, directory_version(metadata)))
        for component in path.parts[1:-1]:
            parent = descriptor
            descriptor = opened(component, flags, dir_fd=parent)
            metadata = checked(os.fstat, descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError('loader source parent must be directory')
            expected = directory_version(metadata)
            if directory_version(checked(os.stat, component, dir_fd=parent, follow_symlinks=False)) != expected:
                raise ValueError('loader source parent changed during admission')
            directories.append((descriptor, parent, component, expected))
        parent = descriptor
        descriptor = opened(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = checked(os.fstat, descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise ValueError('loader source exact regular byte length differs')
        expected = version(before)
        if version(checked(os.stat, path.name, dir_fd=parent, follow_symlinks=False)) != expected:
            raise ValueError('loader source changed before read')
        remaining = expected_size
        chunks = []
        while remaining:
            block = checked(os.read, descriptor, min(65536, remaining))
            if not block:
                raise ValueError('loader source truncated')
            remaining -= len(block)
            chunks.append(block)
        if checked(os.read, descriptor, 1):
            raise ValueError('loader source grew')
        if (version(checked(os.fstat, descriptor)) != expected or
                version(checked(os.stat, path.name, dir_fd=parent, follow_symlinks=False)) != expected):
            raise ValueError('loader source changed during read')
        for held, ancestor, name, expected in directories:
            if directory_version(checked(os.fstat, held)) != expected:
                raise ValueError('loader source held parent changed')
            named = checked(os.stat, '/', follow_symlinks=False) if ancestor is None else checked(
                os.stat, name, dir_fd=ancestor, follow_symlinks=False)
            if directory_version(named) != expected:
                raise ValueError('loader source named parent changed')
        raw = b''.join(chunks)
        _monitor_loader_timely(deadline)
        return raw
    except BaseException as failure:
        primary = failure
        raise
    finally:
        close_failure = None
        while count:
            count -= 1
            descriptor = descriptors[count]
            descriptors[count] = None
            try:
                os.close(descriptor)
            except BaseException as failure:
                if close_failure is None:
                    close_failure = failure
        if close_failure is not None:
            if primary is None:
                raise close_failure
            if close_failure is not primary:
                try:
                    primary.sourceSnapshotCloseFailure = close_failure
                except BaseException:
                    pass
        if primary is None:
            _monitor_loader_timely(deadline)


def _authenticated_monitor_loader(deadline=None):
    captured = {}
    for relative, size, expected in _MONITOR_LOADER_SOURCES:
        _monitor_loader_timely(deadline)
        raw = _capture_monitor_source(BASE / relative, size, deadline)
        _monitor_loader_timely(deadline)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('authenticated monitor loader source bytes differ')
        _monitor_loader_timely(deadline)
        captured[relative] = raw
    # No module source executes until every expected byte string is authenticated.
    modules = {}
    for key, name in (('link_inputs', '_v3_monitor_link_inputs'), ('monitor_inputs', '_v3_monitor_inputs'),
                      ('pin_environment', '_v3_monitor_pin_environment')):
        _monitor_loader_timely(deadline)
        relative = 'toolchain-001/' + key + '.py'
        module = type(os)(name)
        module.__file__ = str(BASE / relative)
        if key == 'pin_environment':
            module._runtime_dependencies = {'link_inputs':modules['link_inputs'], 'monitor_inputs':modules['monitor_inputs']}
        _monitor_loader_timely(deadline)
        code = compile(captured[relative], module.__file__, 'exec')
        _monitor_loader_timely(deadline)
        exec(code, module.__dict__)
        _monitor_loader_timely(deadline)
        modules[key] = module
    return modules['pin_environment']


def load_worker_monitor_binding(deadline=None) -> dict:
    """Read/revalidate the fixed A3 byte closure; UNQUALIFIED is not production authority."""
    profile, _ = load_profile_with_digest()
    module = _authenticated_monitor_loader(deadline)
    _monitor_loader_timely(deadline)
    binding = module.load_monitor_binding(profile)
    _monitor_loader_timely(deadline)
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
        if digest(path, maximum=profile['bounds']['workerLaunchPinFileBytes'], deadline=deadline) != binding[key]:
            raise ValueError('monitor source/protocol/parser pin differs')
    binary = _nonprivileged_executable(Path(binding['binaryPath']))
    if binary['sha256'] != binding['binarySha256']:
        raise ValueError('monitor binary pin differs')
    paths = set()
    for item in binding['dependencies']:
        if (not isinstance(item, dict) or set(item) != {'path', 'sha256'} or
                not Path(item['path']).is_absolute() or item['path'] in paths or
                digest(Path(item['path']), maximum=profile['bounds']['workerLaunchPinFileBytes'], deadline=deadline) != item['sha256']):
            raise ValueError('monitor dependency inventory changed')
        paths.add(item['path'])
    _monitor_loader_timely(deadline)
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
    module = _authenticated_monitor_loader(deadline)
    _monitor_loader_timely(deadline)
    binding = module.load_compiler_binding(profile)
    _monitor_loader_timely(deadline)
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


class _ReceiptInitializationState:
    """Three local FD obligations, never namespace removal or worker authority."""
    __slots__ = ('fds', 'acquired', 'attempted', 'succeeded', 'transferred',
                 'stage', 'mkdir_returned', 'alias_uncertain')

    def __init__(self):
        self.fds = [None, None, None]  # Storage exists before any open.
        self.acquired = self.attempted = self.succeeded = self.transferred = 0
        self.stage = 0
        self.mkdir_returned = self.alias_uncertain = False

    def admit(self, index):
        self.acquired |= 1 << index
        for other in (0, 1, 2):
            if other != index and self.fds[other] is not None and self.fds[other] == self.fds[index]:
                self.alias_uncertain = True
                raise ValueError('receipt initialization descriptor alias')

    def close(self, index):
        descriptor = self.fds[index]
        if descriptor is None:
            return
        mask = 0
        for other in (0, 1, 2):
            if self.fds[other] == descriptor:
                mask |= 1 << other
                self.fds[other] = None
        self.attempted |= mask  # Terminal BEFORE close; never retry an uncertain integer.
        os.close(descriptor)
        self.succeeded |= mask

    def close_all(self):
        first = None
        for index in (2, 1, 0):
            try:
                self.close(index)
            except BaseException as error:
                if first is None:
                    first = error
        return first

    def discharged(self):
        return (not self.alias_uncertain and self.fds[0] is None and self.fds[1] is None and
                self.fds[2] is None and self.acquired == (self.succeeded | self.transferred))

    def facts(self):
        return {'status': 'retained', 'reason': 'initialization-partial-or-unverified',
                'stage': self.stage, 'acquiredMask': self.acquired, 'closeAttemptedMask': self.attempted,
                'closeSucceededMask': self.succeeded, 'transferredMask': self.transferred,
                'mkdirReturned': self.mkdir_returned,
                'closeUncertain': self.alias_uncertain or bool(self.attempted & ~self.succeeded)}


def _create_worker_receipt(*, deadline=None, initialization=None) -> dict:
    state = _ReceiptInitializationState() if initialization is None else initialization
    if (type(state) is not _ReceiptInitializationState or state.stage != 0 or state.acquired or
            state.attempted or state.succeeded or state.transferred or state.mkdir_returned or
            state.alias_uncertain or state.fds != [None, None, None]):
        raise ValueError('fresh private receipt initialization state required')

    def timely():
        if deadline is not None:
            _controller_metadata_timely(deadline)

    def observe(operation, *args, **kwargs):
        timely()
        value = operation(*args, **kwargs)
        timely()
        return value

    def directory_identity(metadata):
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or
                metadata.st_uid != observe(os.getuid)):
            raise ValueError('protected receipt directory identity/mode differs')
        return metadata.st_dev, metadata.st_ino

    try:
        timely()
        state.stage = 1
        root = BASE / 'exec-proof-receipts'
        observe(root.mkdir, mode=0o700, exist_ok=True)
        state.stage = 2
        root_identity = directory_identity(observe(root.lstat))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        state.stage = 3
        timely()
        state.fds[0] = os.open(root, flags)
        state.admit(0)
        timely()
        if directory_identity(observe(os.fstat, state.fds[0])) != root_identity:
            raise ValueError('protected receipt root binding differs')
        if directory_identity(observe(root.lstat)) != root_identity:
            raise ValueError('protected receipt named root differs')
        state.stage = 4
        component = observe(lambda: uuid.uuid4().hex)
        if (type(component) is not str or len(component) != 32 or
                any(c not in '0123456789abcdef' for c in component)):
            raise ValueError('fixed receipt component required')
        state.stage = 5
        timely()
        os.mkdir(component, mode=0o700, dir_fd=state.fds[0])
        state.mkdir_returned = True  # Returned mkdir is NOT created-inode authentication.
        timely()
        state.stage = 6
        timely()
        state.fds[1] = os.open(component, flags, dir_fd=state.fds[0])
        state.admit(1)
        timely()
        state.stage = 7
        directory_metadata = observe(os.fstat, state.fds[1])
        directory_expected = directory_identity(directory_metadata)
        if directory_identity(observe(os.stat, component, dir_fd=state.fds[0], follow_symlinks=False)) != directory_expected:
            raise ValueError('protected receipt child binding differs')
        state.stage = 8
        timely()
        state.fds[2] = os.open('worker-proof.jsonl', os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_RDWR,
                               0o600, dir_fd=state.fds[1])
        state.admit(2)
        timely()
        state.stage = 9
        metadata = observe(os.fstat, state.fds[2])
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or
                metadata.st_size or metadata.st_nlink != 1 or metadata.st_uid != observe(os.getuid)):
            raise ValueError('protected receipt initial identity differs')
        named = observe(os.stat, 'worker-proof.jsonl', dir_fd=state.fds[1], follow_symlinks=False)
        if ((named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_size, named.st_nlink) !=
                (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_size, metadata.st_nlink)):
            raise ValueError('protected receipt report binding differs')
        state.stage = 10
        timely()
        directory = root / component
        timely()
        receipt = {'path': directory / 'worker-proof.jsonl', 'directory': directory, 'fd': state.fds[2],
                   'device': metadata.st_dev, 'inode': metadata.st_ino,
                   'directoryDevice': directory_metadata.st_dev, 'directoryInode': directory_metadata.st_ino,
                   'rootDevice': root_identity[0], 'rootInode': root_identity[1]}
        timely()
        state.stage = 11
        state.close(1)
        timely()
        state.close(0)
        timely()
        state.stage = 12
        timely()
        state.stage = 13
        state.transferred = 4
        state.fds[2] = None
        return receipt  # No fallible observation/construction after transfer.
    except BaseException as primary:
        state.close_all()
        try:
            primary.receiptInitialization = state.facts()
        except BaseException:
            pass
        raise


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


def digest(path: Path, *, maximum=None, deadline=None) -> str:
    return _retained_digest(path, maximum=maximum, deadline=deadline)


def private_directory(path: Path) -> Path:
    if not path.resolve().is_relative_to(BASE):
        raise ValueError('directory outside owned benchmark root')
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def write_json(path: Path, value: object) -> str:
    """Write/hash one owned encoding; no pathname reread or durability authority.

    The immutable contract's existing RLIMIT_FSIZE supplies the16MiB byte cap
    without loading a profile or creating a new wall-clock allowance. Regular
    nonblocking IO is finite in bytes/progress, not a hard kernel/time bound.
    """
    if not path.resolve().is_relative_to(BASE):
        raise ValueError('JSON outside owned benchmark root')
    maximum = enforced_process_limits()['RLIMIT_FSIZE']['hard']
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size != 0:
            raise ValueError('JSON output requires an empty owned regular file')
        os.fchmod(descriptor, 0o600)
        buffer = bytearray()
        class OwnedEncoding:
            def write(self, text):
                # json.dump's default ensure_ascii remains unchanged. Check
                # characters before allocating encoded bytes, then bytes too.
                if len(text) > maximum - len(buffer):
                    raise ValueError('JSON output exceeds file byte bound')
                encoded = text.encode('utf-8')
                if len(encoded) > maximum - len(buffer):
                    raise ValueError('JSON output exceeds file byte bound')
                buffer.extend(encoded)
                return len(text)
        stream = OwnedEncoding()
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        raw = bytes(buffer)
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            chunk = view[offset:offset + 65536]
            count = os.write(descriptor, chunk)
            if type(count) is not int or not 0 < count <= len(chunk):
                raise ValueError('JSON output short write')
            offset += count
        final = os.fstat(descriptor)
        if (not stat.S_ISREG(final.st_mode) or final.st_size != len(raw) or
                stat.S_IMODE(final.st_mode) != 0o600):
            raise ValueError('JSON output write completion differs')
    finally:
        os.close(descriptor)
    return hashlib.sha256(raw).hexdigest()


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


def _controller_metadata_timely(deadline):
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError('finite absolute controller metadata deadline required')
    if time.monotonic() >= deadline:
        raise TimeoutError('controller metadata absolute deadline expired')


def _cleanup_process_identity(pid: int, deadline) -> dict | None:
    """Bounded absence observation only; never authority to signal a numeric PID."""
    _controller_metadata_timely(deadline)
    if type(pid) is not int or not 0 < pid < (1 << 31):
        raise ValueError('invalid controller census PID')
    try:
        descriptor = os.open(f'/proc/{pid}/stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except (FileNotFoundError, ProcessLookupError):
        _controller_metadata_timely(deadline)
        return None
    raw = None
    try:
        try:
            _controller_metadata_timely(deadline)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError('controller process stat is not a regular file')
            _controller_metadata_timely(deadline)
            raw = os.read(descriptor, CONTROLLER_PROC_STAT_BYTES + 1)
            _controller_metadata_timely(deadline)
            if not raw or len(raw) > CONTROLLER_PROC_STAT_BYTES:
                raise ValueError('controller process stat byte bound')
        except (FileNotFoundError, ProcessLookupError):
            _controller_metadata_timely(deadline)
    finally:
        os.close(descriptor)
    _controller_metadata_timely(deadline)
    if raw is None:
        return None
    value = raw.decode('utf-8')
    end = value.rfind(')')
    if not value.startswith(f'{pid} (') or end < len(f'{pid} ('):
        raise ValueError('malformed controller process stat')
    fields = value[end + 2:].split()
    if end + 1 >= len(value) or value[end + 1] != ' ' or len(fields) < 20:
        raise ValueError('incomplete controller process stat')
    record = {'pid': pid, 'start': int(fields[19]), 'pgid': int(fields[2]), 'sid': int(fields[3])}
    if record['start'] <= 0 or record['pgid'] < 0 or record['sid'] < 0:
        raise ValueError('invalid controller process stat identity')
    _controller_metadata_timely(deadline)
    return record


def owned_processes(leader: int, root_start: int | None, deadline) -> list[dict]:
    _controller_metadata_timely(deadline)
    if root_start is None:
        raise RuntimeError('owned launcher start identity is unknown')
    current = _cleanup_process_identity(leader, deadline)
    if current and current['start'] != root_start:
        raise RuntimeError('owned subprocess root PID reused')
    records = []
    _controller_metadata_timely(deadline)
    with os.scandir('/proc') as entries:
        for _ in range(CONTROLLER_PROC_SCAN_ENTRIES):
            _controller_metadata_timely(deadline)
            try:
                entry = next(entries)
            except StopIteration:
                break
            _controller_metadata_timely(deadline)
            if entry.name.isdecimal():
                record = _cleanup_process_identity(int(entry.name), deadline)
                if record and (record['sid'] == leader or record['pgid'] == leader):
                    records.append(record)
            _controller_metadata_timely(deadline)
        else:
            raise RuntimeError('controller process scan entry budget exhausted without EOF')
    _controller_metadata_timely(deadline)
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



# Fixed Linux UAPI: upstream045958acaa75205b31578cb22c4345e28dd2e4bf.
_HELPER_CREATE_FLAGS = 0x13  # CLOEXEC | ALLOW_SEALING | EXEC
_HELPER_REQUIRED_SEALS = 0x2f  # SEAL | SHRINK | GROW | WRITE | EXEC
_HELPER_KNOWN_SEALS = 0x3f  # additionally FUTURE_WRITE


def _helper_policy():
    for module, values in ((os, {'MFD_CLOEXEC':1, 'MFD_ALLOW_SEALING':2, 'MFD_EXEC':16}),
                           (fcntl, {'F_SEAL_SEAL':1, 'F_SEAL_SHRINK':2, 'F_SEAL_GROW':4,
                                    'F_SEAL_WRITE':8, 'F_SEAL_FUTURE_WRITE':16, 'F_SEAL_EXEC':32})):
        for name, expected in values.items():
            if hasattr(module, name) and (type(getattr(module, name)) is not int or getattr(module, name) != expected):
                raise ValueError('conflicting executable snapshot UAPI')
    if (any(not callable(getattr(os, name, None)) for name in ('memfd_create','fchmod','fstat','pread','read','write','getxattr')) or
            not callable(getattr(fcntl, 'fcntl', None)) or
            any(type(getattr(fcntl, name, None)) is not int for name in ('F_ADD_SEALS','F_GET_SEALS'))):
        raise ValueError('executable snapshot APIs unavailable')


def _helper_no_capability(descriptor):
    try:
        capability = os.getxattr(descriptor, 'security.capability')
    except OSError as failure:
        if failure.errno != errno.ENODATA:
            raise
    else:
        raise ValueError('executable snapshot has capability metadata')


class _OwnedHelperSnapshot:
    """Private phase owner. A serialized proc-FD coordinate is not this handle."""
    __slots__ = ('descriptor','owner_pid','owner_start','source_path','source_pin','helper')

    def __init__(self, descriptor, owner, source_path, source_pin, helper):
        self.descriptor = descriptor
        self.owner_pid, self.owner_start = owner['pid'], owner['start']
        self.source_path, self.source_pin = str(source_path), dict(source_pin)
        self.helper = dict(helper)

    def coordinate(self):
        return '/proc/' + str(self.owner_pid) + '/fd/' + str(self.descriptor)

    def binding(self):
        return {'ownerPid':self.owner_pid, 'ownerStart':self.owner_start, 'descriptor':self.descriptor,
                'helper':{**self.helper, 'sourcePath':self.source_path, 'sourcePin':dict(self.source_pin)}}


def _helper_pin(owner, deadline):
    """Observe only the exact still-owned H descriptor, never a proc pathname."""
    _controller_metadata_timely(deadline)
    _helper_policy()
    _controller_metadata_timely(deadline)
    if type(owner) is not _OwnedHelperSnapshot or type(owner.descriptor) is not int or owner.descriptor < 0:
        raise ValueError('owned executable snapshot unavailable')
    live = process_identity(os.getpid())
    _controller_metadata_timely(deadline)
    if live is None or (live['pid'], live['start']) != (owner.owner_pid, owner.owner_start):
        raise ValueError('executable snapshot owner lifetime changed')
    metadata = os.fstat(owner.descriptor)
    _controller_metadata_timely(deadline)
    seals = fcntl.fcntl(owner.descriptor, fcntl.F_GET_SEALS)
    _controller_metadata_timely(deadline)
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o500 or
            metadata.st_uid != os.getuid() or
            (metadata.st_dev,metadata.st_ino,metadata.st_size) !=
            (owner.helper['device'],owner.helper['inode'],owner.helper['size']) or
            not 0 < metadata.st_size <= load_profile_with_digest()[0]['bounds']['workerLaunchPinFileBytes'] or
            seals & _HELPER_REQUIRED_SEALS != _HELPER_REQUIRED_SEALS or seals & ~_HELPER_KNOWN_SEALS):
        raise ValueError('executable snapshot identity mode size or seals differ')
    _controller_metadata_timely(deadline)
    _helper_no_capability(owner.descriptor)
    _controller_metadata_timely(deadline)
    magic = os.pread(owner.descriptor, 4, 0)
    _controller_metadata_timely(deadline)
    if magic != b'\x7fELF':
        raise ValueError('executable snapshot is not ELF')
    value = hashlib.sha256(); count = 0
    while count < metadata.st_size:
        _controller_metadata_timely(deadline)
        block = os.pread(owner.descriptor, min(65536,metadata.st_size-count), count)
        _controller_metadata_timely(deadline)
        if not block: raise ValueError('executable snapshot truncated')
        value.update(block)
        _controller_metadata_timely(deadline)
        count += len(block)
    after = os.fstat(owner.descriptor)
    _controller_metadata_timely(deadline)
    if (stat.S_IMODE(after.st_mode) != 0o500 or
            (after.st_dev,after.st_ino,after.st_size) != (metadata.st_dev,metadata.st_ino,metadata.st_size)):
        raise ValueError('executable snapshot changed or differs from admitted helper')
    actual_sha = value.hexdigest()
    _controller_metadata_timely(deadline)
    if actual_sha != owner.helper['sha256'] or actual_sha != owner.source_pin['sha256']:
        raise ValueError('executable snapshot changed or differs from admitted helper')
    pin = {'device':metadata.st_dev, 'inode':metadata.st_ino, 'mode':0o500, 'sha256':actual_sha}
    _controller_metadata_timely(deadline)
    return pin


def _close_helper_snapshot(receipt):
    descriptor = receipt.get('helperSnapshotFd')
    if descriptor is None: return
    receipt['helperSnapshotFd'] = None  # A failed close must never be retried.
    owner = receipt.get('helperSnapshot')
    if type(owner) is _OwnedHelperSnapshot: owner.descriptor = None
    try:
        os.close(descriptor)
    except BaseException as failure:
        receipt['helperSnapshotCloseFailed'] = True
        receipt['helperSnapshotCloseFailure'] = failure
        raise


def _snapshot_helper(path, admitted, receipt, deadline):
    _controller_metadata_timely(deadline)
    _helper_policy()
    _controller_metadata_timely(deadline)
    if type(admitted) is not dict or set(admitted) != {str(path)}:
        raise ValueError('one original helper admission required')
    pin = admitted[str(path)]
    if (type(pin) is not dict or set(pin) != {'device','inode','mode','sha256'} or
            any(type(pin[k]) is not int or not 0 <= pin[k] <= (1 << 64)-1 for k in ('device','inode')) or
            type(pin['mode']) is not int or not 0 <= pin['mode'] <= 0o7777 or
            type(pin['sha256']) is not str or len(pin['sha256']) != 64 or any(c not in '0123456789abcdef' for c in pin['sha256'])):
        raise ValueError('invalid original helper admission')
    actual = _pin_files([path], deadline)[str(path)]
    _controller_metadata_timely(deadline)
    if pin != actual:
        raise ValueError('helper snapshot source differs from original admission')
    maximum = load_profile_with_digest()[0]['bounds']['workerLaunchPinFileBytes']
    _controller_metadata_timely(deadline)
    source = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    primary = None; owner = None
    try:
        _controller_metadata_timely(deadline)
        metadata = os.fstat(source)
        _controller_metadata_timely(deadline)
        if (not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum or
                (metadata.st_dev,metadata.st_ino,stat.S_IMODE(metadata.st_mode)) !=
                (actual['device'],actual['inode'],actual['mode'])):
            raise ValueError('helper snapshot source identity differs')
        descriptor = os.memfd_create('callable-probe-helper', _HELPER_CREATE_FLAGS)
        receipt['helperSnapshotFd'] = descriptor
        _controller_metadata_timely(deadline)
        count = 0; value = hashlib.sha256()
        while count < metadata.st_size:
            _controller_metadata_timely(deadline)
            block = os.read(source,min(65536,metadata.st_size-count))
            _controller_metadata_timely(deadline)
            if not block: raise ValueError('helper snapshot source truncated')
            value.update(block)
            _controller_metadata_timely(deadline)
            count += len(block)
            view = memoryview(block)
            while view:
                _controller_metadata_timely(deadline)
                written = os.write(descriptor,view)
                _controller_metadata_timely(deadline)
                if written <= 0: raise ValueError('helper snapshot short write')
                view = view[written:]
        copied_sha = value.hexdigest()
        _controller_metadata_timely(deadline)
        if copied_sha != actual['sha256']: raise ValueError('helper snapshot copy digest differs')
        os.fchmod(descriptor,0o500)
        _controller_metadata_timely(deadline)
        before = os.fstat(descriptor)
        _controller_metadata_timely(deadline)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o500 or before.st_size != count or
                (before.st_dev,before.st_ino) == (actual['device'],actual['inode'])):
            raise ValueError('helper snapshot creation mode or identity differs')
        _helper_no_capability(descriptor)
        _controller_metadata_timely(deadline)
        magic = os.pread(descriptor,4,0)
        _controller_metadata_timely(deadline)
        if magic != b'\x7fELF': raise ValueError('helper snapshot is not ELF')
        fcntl.fcntl(descriptor,fcntl.F_ADD_SEALS,_HELPER_REQUIRED_SEALS)
        _controller_metadata_timely(deadline)
        identity = process_identity(os.getpid())
        _controller_metadata_timely(deadline)
        if identity is None: raise ValueError('helper snapshot owner unavailable')
        owner = _OwnedHelperSnapshot(descriptor,identity,path,actual,
                    {'device':before.st_dev,'inode':before.st_ino,'size':count,'mode':0o500,'sha256':actual['sha256']})
        _helper_pin(owner,deadline)
        receipt['helperSnapshot'] = owner
    except BaseException as failure:
        primary = failure
    try:
        os.close(source)
    except BaseException as cleanup:
        if primary is None: primary = cleanup
        else:
            try: primary.add_note('helper snapshot source cleanup failed')
            except BaseException: pass
    if primary is None:
        try: _controller_metadata_timely(deadline)
        except BaseException as failure: primary = failure
    if primary is not None:
        try: _close_helper_snapshot(receipt)
        except BaseException:
            try: primary.add_note('helper snapshot object cleanup failed')
            except BaseException: pass
        raise primary
    return owner


def _launch_pins(launch, receipt, deadline):
    """Reconstruct the exact ordinary+owned-H union without proc reopening."""
    owner = receipt.get('helperSnapshot')
    if owner is None: return _pin_files(launch['pins'],deadline)
    if type(owner) is not _OwnedHelperSnapshot or owner.descriptor is None:
        raise ValueError('helper snapshot ownership lost before pin validation')
    _controller_metadata_timely(deadline)
    coordinate = owner.coordinate()
    regular = {name:row for name,row in launch['pins'].items() if name != coordinate}
    if len(regular) + 1 != len(launch['pins']): raise ValueError('helper snapshot pin missing')
    _controller_metadata_timely(deadline)
    pins = {**_pin_files(regular,deadline),coordinate:_helper_pin(owner,deadline)}
    _controller_metadata_timely(deadline)
    return pins


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


def _prepare_launch(argv, cwd, bounds, receipt, provisioning, deadline=None, runtime_library=None, helper_admission=None):
    outer = Path('/proc/self/ns/pid').stat()
    common = [Path(__file__), BASE / 'scope_gate.py', BASE / 'build_contract.py',
              BASE / 'contracts/candidate-build-profile.json', Path('/usr/bin/python3'), Path('/usr/bin/systemd-run')]
    expected = binding = target = compiler_recording = None
    library = library_pin = helper = helper_request = None
    if provisioning and helper_admission is not None: raise ValueError('provisioning helper snapshot forbidden')
    if helper_admission is not None and bounds['phase'] != 'probe': raise ValueError('helper snapshot is probe-only')
    if provisioning:
        command = list(argv)
        common += [Path('/usr/bin/gcc'), BASE / 'worker_exec_monitor.c']
    else:
        recipe = _contained_recipe(argv, cwd)
        binding = load_worker_monitor_binding(deadline=deadline)
        target = _nonprivileged_executable(recipe['target'], deadline)
        compiler_recording = _recorded_compiler_inputs(recipe, target, deadline)
        if compiler_recording is not None:
            common += [Path(row['path']) for row in compiler_recording['binding']['dependencies']]
        reaper = _nonprivileged_executable(Path('/usr/bin/bwrap'), deadline)
        monitor = _nonprivileged_executable(Path(binding['binaryPath']), deadline)
        if monitor['sha256'] != binding['binarySha256']:
            raise ValueError('monitor executable differs from validated binding')
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
        if bounds['phase'] == 'probe':
            if runtime_library is not None: raise ValueError('helper and library snapshots are exclusive')
            mappings = [m for m in recipe['mounts'] if m['source'] == Path(target['path']) and m['target'] == Path('/probe')]
            if recipe['worker'][0] != '/probe' or len(mappings) != 1 or mappings[0]['writable'] or '--ro-bind-fd' in prefix:
                raise ValueError('probe requires one explicit read-only helper mapping')
            admitted = helper_admission if helper_admission is not None else {target['path']:{k:target[k] for k in ('device','inode','mode','sha256')}}
            helper_request = (Path(target['path']), admitted)
            old = ['--ro-bind',str(mappings[0]['original']),'/probe']
            positions = [i for i in range(len(prefix)-2) if prefix[i:i+3] == old]
            if len(positions) != 1: raise ValueError('helper snapshot mount substitution ambiguous')
            prefix[positions[0]:positions[0]+3] = ['--ro-bind-fd','5','/probe']
        library_mounts = [m for m in recipe['mounts'] if m['target'] == Path('/library.so')]
        if library_mounts:
            if len(library_mounts) != 1 or library_mounts[0]['writable'] or bounds['phase'] != 'runtime':
                raise ValueError('closed runtime library mapping required')
            if helper_request is not None: raise ValueError('helper and library snapshots are exclusive')
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
    if helper_request is not None:
        limits = load_profile_with_digest()[0]['bounds']
        if len(common) + 1 > limits['workerLaunchPinEntries']:
            raise ValueError('helper snapshot exceeds complete launch pin inventory')
    pins = _pin_files(common, deadline)
    if helper_request is not None:
        helper = _snapshot_helper(helper_request[0],helper_request[1],receipt,deadline)
        coordinate = helper.coordinate()
        if coordinate in pins or len(pins) >= limits['workerLaunchPinEntries']:
            raise ValueError('helper snapshot pin identity aliases an ordinary input')
        # Each ordinary input and H is capped by the same per-file ceiling;
        # len(common)+1 admission bounds their total by the existing product.
        pins[coordinate] = _helper_pin(helper,deadline)
        if pins.get(helper.source_path) != helper.source_pin:
            raise ValueError('helper source changed during preparation')
        expected.update(targetDevice=helper.helper['device'],targetInode=helper.helper['inode'])
    if not provisioning:
        for relative, _, source_sha in _MONITOR_LOADER_SOURCES:
            if pins.get(str(BASE / relative), {}).get('sha256') != source_sha:
                raise ValueError('authenticated monitor loader source launch pin differs')
        monitor_pin = pins.get(monitor['path'])
        if (monitor_pin != {key:monitor[key] for key in ('device','inode','mode','sha256')} or
                monitor_pin.get('sha256') != binding['binarySha256']):
            raise ValueError('monitor launch pin differs from validated executable')
    profile_pin = pins.get(str(BASE / 'contracts/candidate-build-profile.json'))
    if type(profile_pin) is not dict or profile_pin.get('sha256') != bounds['profileSha256']:
        raise ValueError('launch profile pin differs from admitted bounds profile')
    if not provisioning and (binding['parserSha256'] != _WORKER_PROOF_PARSER_SHA256 or
            pins.get(str(BASE / 'worker_exec_proof.py'), {}).get('sha256') != _WORKER_PROOF_PARSER_SHA256):
        raise ValueError('authenticated worker proof parser launch binding differs')
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
    if helper is not None: config['helperSnapshot'] = helper.binding()
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


def _read_private_json(path, maximum=4096, *, deadline):
    _controller_metadata_timely(deadline)
    if type(maximum) is not int or not 0 < maximum <= 4096:
        raise ValueError('private controller JSON byte bound')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _controller_metadata_timely(deadline)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
                stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or
                not 0 <= metadata.st_size <= maximum):
            raise ValueError('private controller file identity differs')
        _controller_metadata_timely(deadline)
        raw = os.read(descriptor, maximum + 1)
        _controller_metadata_timely(deadline)
        if len(raw) > maximum or len(raw) != metadata.st_size:
            raise ValueError('private controller file byte bound')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate controller key')
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique)
        _controller_metadata_timely(deadline)
    finally:
        try:
            os.close(descriptor)
        except OSError as failure:
            # A close error must not masquerade as a missing gate at admission.
            raise RuntimeError('private controller metadata descriptor close failed') from failure
    _controller_metadata_timely(deadline)
    return value


def _admit_scope(receipt, launch, bounds, deadline):
    _controller_metadata_timely(deadline)
    path = receipt['directory'] / 'gate.json'
    try:
        gate = _read_private_json(path, deadline=deadline)
    except FileNotFoundError:
        _controller_metadata_timely(deadline)
        return None
    if (type(gate) is not dict or set(gate) != {'pid', 'start'} or
            any(type(gate[k]) is not int or gate[k] <= 0 for k in gate)):
        raise ValueError('scope gate process identity is invalid')
    child = process_identity(gate['pid'])
    _controller_metadata_timely(deadline)
    if not child or child['start'] != gate['start']:
        raise ValueError('scope gate process identity changed')
    cgroup_record = Path(f"/proc/{gate['pid']}/cgroup").read_text().strip()
    _controller_metadata_timely(deadline)
    if not cgroup_record.startswith('0::/') or '\n' in cgroup_record:
        raise ValueError('scope gate cgroup record is invalid')
    cgroup = Path('/sys/fs/cgroup') / cgroup_record[4:]
    if not cgroup.resolve().is_relative_to(Path('/sys/fs/cgroup')) or cgroup.name != launch['unit']:
        raise ValueError('scope gate cgroup path differs')
    values = {}
    for name in ('pids.max', 'memory.max', 'memory.swap.max'):
        _controller_metadata_timely(deadline)
        values[name] = (cgroup / name).read_text().strip()
        _controller_metadata_timely(deadline)
    if values != {'pids.max': str(bounds['cgroup']['tasks']), 'memory.max': str(bounds['cgroup']['memoryBytes']), 'memory.swap.max': str(bounds['cgroup']['swapBytes'])}:
        raise ValueError('scope gate kernel limits differ')
    _controller_metadata_timely(deadline)
    directory_fd = os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _controller_metadata_timely(deadline)
        metadata = os.fstat(directory_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError('scope descriptor is not a cgroup directory')
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
            _controller_metadata_timely(deadline)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            try:
                _controller_metadata_timely(deadline)
                raw = os.read(fd, 65)
                _controller_metadata_timely(deadline)
                if len(raw) > 64:
                    raise ValueError('scope limit metadata byte bound')
                acquired[name] = raw.decode('ascii').strip()
            finally:
                os.close(fd)
        if acquired != values:
            raise ValueError('acquired scope kernel limits differ')
        _controller_metadata_timely(deadline)
        current = cgroup.stat()
        _controller_metadata_timely(deadline)
        if (current.st_dev,current.st_ino) != (metadata.st_dev,metadata.st_ino):
            raise ValueError('scope path changed during acquisition')
        if process_identity(gate['pid']) != child:
            raise ValueError('scope gate identity changed during acquisition')
        _controller_metadata_timely(deadline)
        if Path(f"/proc/{gate['pid']}/cgroup").read_text().strip() != cgroup_record:
            raise ValueError('scope gate membership changed during acquisition')
        _controller_metadata_timely(deadline)
        return evidence
    except BaseException:
        os.close(gate_pidfd)
        os.close(directory_fd)
        raise


def _launch_config_digest(receipt, *, deadline):
    """Hash only the fixed owned launch file within its existing 64KiB/deadline contract."""
    _controller_metadata_timely(deadline)
    directory_fd = descriptor = None
    primary = None
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    def identity(metadata):
        return tuple(getattr(metadata, key) for key in fields)
    def directory_unchanged():
        _controller_metadata_timely(deadline)
        held = os.fstat(directory_fd)
        _controller_metadata_timely(deadline)
        named = receipt['directory'].lstat()
        _controller_metadata_timely(deadline)
        for metadata in (held, named):
            if ((metadata.st_dev, metadata.st_ino) != (receipt['directoryDevice'], receipt['directoryInode']) or
                    not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or
                    metadata.st_uid != os.getuid()):
                raise ValueError('launch configuration directory identity changed')
    try:
        directory_fd = os.open(receipt['directory'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        directory_unchanged()
        descriptor = os.open('launch.json', os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory_fd)
        _controller_metadata_timely(deadline)
        before = os.fstat(descriptor)
        _controller_metadata_timely(deadline)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or
                not 0 < before.st_size <= 65536):
            raise ValueError('launch configuration is not a bounded private regular file')
        version = identity(before)
        named = os.stat('launch.json', dir_fd=directory_fd, follow_symlinks=False)
        _controller_metadata_timely(deadline)
        if identity(named) != version:
            raise ValueError('launch configuration changed before read')
        digest_value = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            _controller_metadata_timely(deadline)
            block = os.read(descriptor, min(65536, remaining))
            _controller_metadata_timely(deadline)
            if not block or len(block) > remaining:
                raise ValueError('launch configuration exact-size read differs')
            remaining -= len(block)
            digest_value.update(block)
        _controller_metadata_timely(deadline)
        extra = os.read(descriptor, 1)
        _controller_metadata_timely(deadline)
        if extra:
            raise ValueError('launch configuration grew')
        after = os.fstat(descriptor)
        _controller_metadata_timely(deadline)
        named = os.stat('launch.json', dir_fd=directory_fd, follow_symlinks=False)
        _controller_metadata_timely(deadline)
        if identity(after) != version or identity(named) != version:
            raise ValueError('launch configuration changed during read')
        directory_unchanged()
        answer = digest_value.hexdigest()
    except BaseException as failure:
        primary = failure
        raise
    finally:
        cleanup_failure = None
        cleanup_count = 0
        for held in (descriptor, directory_fd):
            if held is not None:
                try:
                    os.close(held)
                except BaseException as failure:
                    cleanup_count += 1
                    if cleanup_failure is None: cleanup_failure = failure
        if cleanup_failure is not None:
            if primary is not None:
                BaseException.add_note(primary, 'launch configuration descriptor cleanup failures: ' + str(cleanup_count))
            else:
                raise cleanup_failure
    _controller_metadata_timely(deadline)
    return answer


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
        if _launch_pins(launch, receipt, deadline) != launch['pins'] or _launch_config_digest(receipt, deadline=deadline) != launch['configSha256']:
            raise ValueError('launch source/runtime/input pins changed')
        _revalidate_compiler_inputs(launch, deadline)
        proof['pinsUnchanged'] = True
        parsed = _parse_worker_proof(raw, launch['expected'], deadline=deadline)
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
                managed_scope: bool = False, phase: str = 'unspecified', runtime_library=None, phase_deadline=None, helper_admission=None) -> dict:
    """Every worker requires contained admission/proof; launcher exit never substitutes."""
    bounds = execution_bounds(timeout, output_limit, managed_scope, phase)
    if phase_deadline is not None:
        _controller_metadata_timely(phase_deadline)
    if type(stdin) is not bytes or len(stdin) > bounds['supervisor']['stdinBytes']:
        raise ValueError('bounded subprocess stdin exceeds profile')
    if managed_scope is not True:
        raise ValueError('unscoped worker execution is forbidden')
    return _run_scoped(argv, cwd, environment, stdin, bounds, provisioning=False, **({'runtime_library':runtime_library} if runtime_library is not None else {}),
                       **({'phase_deadline':phase_deadline} if phase_deadline is not None else {}),
                       **({'helper_admission':helper_admission} if helper_admission is not None else {}))


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


def _run_scoped(argv, cwd, environment, stdin, bounds, *, provisioning, runtime_library=None, phase_deadline=None, helper_admission=None):
    began = time.monotonic()
    supervisor = bounds['supervisor']; timeout = bounds['wallSeconds']; output_limit = bounds['outputBytesPerStream']
    phase_end = began + timeout
    if phase_deadline is not None:
        _controller_metadata_timely(phase_deadline)
        phase_end = min(phase_end,phase_deadline)
        timeout = phase_end - began
        if timeout <= 0: raise TimeoutError('phase expired before controller setup')
        bounds = {**bounds,'wallSeconds':timeout}
    result = {key: False for key in ('launcherCreated', 'launcherPidIdentityVerified', 'scopeVerified', 'scopeAdmitted',
                                    'captureComplete', 'waitComplete', 'cleanupVerified', 'rootReaped', 'finalAbsenceVerified',
                                    'timedOut', 'outputExceeded', 'infrastructureFailure', 'workerExecVerified', 'workerTerminationVerified')}
    result.update(argv=argv, exitCode=None, launcherExitCode=None, workerTermination=None, workerProof=None,
                  workerProofRaw=b'', workerProofBindings=None, launchInputPins=None, provisioningOnly=provisioning, infrastructureReason=None,
                  bounds=bounds, rootPid=None, kernelScope=None, stdout=b'', stderr=b'')
    process = selector = receipt = launch = scope_evidence = root_start = None
    receipt_initialization = _ReceiptInitializationState()
    result['_receiptCleanup'] = {'status': 'retained', 'reason': 'initialization-partial-or-unverified'}
    launch_attempted = False
    launcher_pidfd = None
    phase_elapsed = cleanup_began = verification_end = None
    captured = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        cwd = _work_directory(cwd)
        _worker_environment(environment, cwd)
        receipt = _create_worker_receipt(deadline=phase_end, initialization=receipt_initialization)
        if provisioning:
            # No report descriptor/channel exists for this fixed trusted compiler exception.
            os.close(receipt['fd']); receipt['fd'] = None
            receipt['path'].unlink()
        launch = _prepare_launch(argv, cwd, bounds, receipt, provisioning, deadline=phase_end, **({'runtime_library':runtime_library} if runtime_library is not None else {}),
                                 **({'helper_admission':helper_admission} if helper_admission is not None else {}))
        result.update(workerProofBindings=launch['proofBinding'], launchInputPins=launch['pins'])
        host_environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                            'HOME': str(receipt['directory']), 'TMPDIR': str(receipt['directory']),
                            'XDG_CACHE_HOME': str(receipt['directory']),
                            'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{os.getuid()}/bus'}
        if time.monotonic() >= phase_end:
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
            remaining = phase_end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('bounded worker phase deadline')
            if scope_evidence is None:
                scope_evidence = _admit_scope(receipt, launch, bounds, phase_end)
                if scope_evidence is not None:
                    result.update(scopeVerified=True, kernelScope={k:v for k,v in scope_evidence.items() if not k.startswith('_')})
                    # State owns cgroup/gate handles before any authenticated release attempt.
                    _release_scope(scope_evidence, launch, phase_end)
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
        remaining = phase_end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('phase expired before wrapper wait')
        if phase_deadline is not None and remaining < supervisor['waitFloorSeconds']:
            raise TimeoutError('remaining phase interval below existing wait floor')
        result['launcherExitCode'] = process.wait(timeout=max(supervisor['waitFloorSeconds'], remaining))
        result['waitComplete'] = True
        if scope_evidence is None:
            raise AssertionError('worker scope was never kernel-verified')
    except Exception as failure:
        result['timedOut'] = isinstance(failure, (TimeoutError, subprocess.TimeoutExpired))
        result['infrastructureFailure'] = True
        result['infrastructureReason'] = 'scope-launch-or-worker-controller-failed'
        result.update(failureClass=type(failure).__name__, reason='bounded controller refused or failed')
        try:
            failure.bounded_result = result
        except BaseException:
            pass
        raise
    finally:
        primary_failure = sys.exception()
        phase_elapsed = time.monotonic() - began
        cleanup_began = time.monotonic()
        cleanup_failure = None
        cgroup_kill_failure = launcher_kill_failure = cleanup_block_failure = None
        if selector is not None:
            try:
                selector.close()
            except Exception as failure:
                cleanup_failure = failure
        try:
            if process is not None:
                wait_end = cleanup_began + supervisor['cleanupWaitSeconds']
                try:
                    _kill_owned_scope(scope_evidence)
                except Exception as failure:
                    cgroup_kill_failure = failure
                    if cleanup_failure is None:
                        cleanup_failure = failure
                try:
                    _kill_launcher(launcher_pidfd)
                except Exception as failure:
                    launcher_kill_failure = failure
                    if cleanup_failure is None:
                        cleanup_failure = failure
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
                    session = owned_processes(process.pid, root_start, verification_end)
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
                result.update(rootReaped=True, finalAbsenceVerified=True, cleanupVerified=cleanup_failure is None)
                if result['launcherExitCode'] is None:
                    result['launcherExitCode'] = process.returncode if type(process.returncode) is int else None
            elif not launch_attempted:
                result.update(finalAbsenceVerified=True, cleanupVerified=cleanup_failure is None and receipt_initialization.discharged())
            else:
                # No process handle means no owned PID/cgroup identity to verify safely.
                result.update(finalAbsenceVerified=False, cleanupVerified=False)
        except Exception as failure:
            cleanup_block_failure = failure
            if cleanup_failure is None:
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
                if launch is not None and _pin_files(launch['pins'], phase_end if phase_deadline is not None else time.monotonic() + max(0, timeout - phase_elapsed)) != launch['pins']:
                    raise ValueError('provisioning pins changed')
            except Exception:
                result.update(infrastructureFailure=True, infrastructureReason='provisioning-input-pins-changed')
            if (not result['infrastructureFailure'] and result['scopeVerified'] and result['scopeAdmitted'] and
                    result['launcherPidIdentityVerified'] and result['captureComplete'] and result['waitComplete'] and
                    result['cleanupVerified'] and not result['outputExceeded'] and not result['timedOut']):
                result['exitCode'] = result['launcherExitCode']
        else:
            _finish_worker_proof(result, receipt, launch, bounds, deadline=phase_end if phase_deadline is not None else time.monotonic() + max(0, timeout - phase_elapsed))
        if receipt is not None and ('helperSnapshotFd' in receipt or receipt.get('helperSnapshotCloseFailed')):
            try:
                _close_helper_snapshot(receipt)
                if receipt.get('helperSnapshotCloseFailed'): raise receipt['helperSnapshotCloseFailure']
            except BaseException as failure:
                cleanup_failure = cleanup_failure or failure
                result.update(cleanupVerified=False, infrastructureFailure=True, infrastructureReason='helper-snapshot-close-failed', exitCode=None)
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
        if result['phaseElapsedSeconds'] >= timeout or phase_deadline is not None and time.monotonic() >= phase_end:
            result.update(timedOut=True, infrastructureFailure=True, infrastructureReason='phase-budget-exhausted', exitCode=None)
        reclamation_failure = None
        if receipt is None:
            try:
                result['_receiptCleanup'] = receipt_initialization.facts()
            except BaseException:
                pass  # Preallocated generic retained facts remain; never cleanup authority.
        else:
            result['_receiptCleanup'] = _reclaim_worker_receipt(receipt, result, provisioning=provisioning)
        if result['_receiptCleanup']['status'] == 'refused':
            reclamation_failure = ValueError('owned receipt directory reclamation failed')
            reclamation_failure.bounded_result = result
            reclamation_failure.receiptCleanup = result['_receiptCleanup']
            result.update(infrastructureFailure=True, infrastructureReason='receipt-directory-reclamation-failed')
            if primary_failure is not None:
                primary_failure.receiptCleanup = result['_receiptCleanup']
        result['phaseElapsedSeconds'] = round(phase_elapsed + time.monotonic() - proof_began, 6)
        if result['phaseElapsedSeconds'] >= timeout or phase_deadline is not None and time.monotonic() >= phase_end:
            result.update(timedOut=True, infrastructureFailure=True, infrastructureReason='phase-budget-exhausted', exitCode=None)
        result['elapsedSeconds'] = round(time.monotonic() - began, 6)
        if not receipt_initialization.discharged():
            # Actual caller-owned obligations, independent of optional annotations/facts.
            result.update(cleanupVerified=False, infrastructureFailure=True,
                          infrastructureReason='receipt-initialization-close-unverified', exitCode=None)
        if cleanup_failure is not None:
            # Fixed three-stage secondary metadata only; never serialize exception objects or
            # invoke their equality/formatting. Metadata failure cannot replace the primary.
            try:
                secondary = []
                for failure in (cgroup_kill_failure, launcher_kill_failure, cleanup_block_failure):
                    if (failure is not None and failure is not cleanup_failure and failure is not primary_failure and
                            all(failure is not previous for previous in secondary)):
                        secondary.append(failure)
                cleanup_failure.bounded_result = result
                cleanup_failure.receiptCleanup = result['_receiptCleanup']
                if secondary:
                    cleanup_failure.secondaryCleanupFailures = tuple(secondary)
            except BaseException:
                pass
            if primary_failure is None:
                raise cleanup_failure
            if cleanup_failure is not primary_failure:
                try:
                    primary_failure.cleanupFailure = cleanup_failure
                except BaseException:
                    pass
        if reclamation_failure is not None and primary_failure is None:
            raise reclamation_failure
    return result


def public_result(result: dict) -> dict:
    return {**{k: v for k, v in result.items() if k not in ('stdout', 'stderr', 'workerProofRaw', '_receiptCleanup')},
            'stdoutHex': result['stdout'].hex(), 'stderrHex': result['stderr'].hex(),
            'workerProofRawHex': result.get('workerProofRaw', b'').hex()}

