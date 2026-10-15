"""Explicit, narrowly scoped monitor provisioning; import never launches tools.

The output is NOT a qualified machine pin. Accepted complete compiler/link/header/
loader/runtime input inventory and native public qualification remain independent
mandatory gates. The channel-free compiler cannot prove its own monitored exec.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = ROOT.parents[3]
OUTPUT_ROOT = REPOSITORY / 'build/acp-decomp-effectiveness/callable-library-v3'
MANIFEST = ROOT / 'toolchain-001/worker-exec-monitor.json'
SOURCES = {'sourceSha256': ROOT / 'worker_exec_monitor.c',
           'protocolSha256': ROOT / 'contracts/worker-exec-proof-schema.json',
           'parserSha256': ROOT / 'worker_exec_proof.py'}


def build_command(output):
    return ['/usr/bin/gcc', '-D_GNU_SOURCE', '-std=c11', '-O2', '-Wall',
            '-Wextra', '-Werror', '-Wl,-z,relro,-z,now,-z,noexecstack',
            str(SOURCES['sourceSha256']), '-o', str(output)]


def _input_pin(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ValueError('bounded regular provisioning input required')
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > maximum:
                raise ValueError('provisioning byte bound')
            digest.update(chunk)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if count != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise ValueError('provisioning input changed')
        return {'device': before.st_dev, 'inode': before.st_ino,
                'mode': stat.S_IMODE(before.st_mode), 'sha256': digest.hexdigest()}
    finally:
        os.close(descriptor)


def _hash(path, maximum):
    return _input_pin(path, maximum)['sha256']


def _valid_sha(value):
    return (type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value))


def _canonical_pin_name(value):
    return (type(value) is str and 0 < len(value) <= 4096 and
            value.startswith('/') and not value.startswith('//') and '\x00' not in value and
            str(Path(value)) == value and '..' not in Path(value).parts)


def _valid_pin(value):
    return (type(value) is dict and len(value) == 4 and
            set(value) == {'device', 'inode', 'mode', 'sha256'} and
            all(type(value[k]) is int and 0 <= value[k] < (1 << 64)
                for k in ('device', 'inode')) and
            type(value['mode']) is int and 0 <= value['mode'] <= 0o7777 and
            _valid_sha(value['sha256']))


def _same_bounds(actual, expected):
    # Traversal is driven by the trusted, finite profile-derived tree; reject
    # extra shape before descent. Never serialize a receipt-selected object.
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return (len(actual) == len(expected) and set(actual) == set(expected) and
                all(_same_bounds(actual[k], expected[k]) for k in expected))
    if type(expected) is list:
        return (len(actual) == len(expected) and
                all(_same_bounds(a, b) for a, b in zip(actual, expected)))
    if type(expected) is float:
        return math.isfinite(actual) and math.isfinite(expected) and actual == expected
    return type(expected) in (str, int, bool, type(None)) and actual == expected


def _output(path, *, binary=False):
    path = Path(path)
    # Preserve absolute path semantics; reject traversal/symlink aliases before mkdir.
    if not path.is_absolute() or '..' in path.parts or path != path.resolve():
        raise ValueError('canonical repository output path required')
    if not path.is_relative_to(OUTPUT_ROOT.resolve()):
        raise ValueError('monitor provisioning output outside trusted v3 build root')
    if binary and path.name != 'worker_exec_monitor':
        raise ValueError('fixed monitor binary name required')
    if path.exists() or path.is_symlink():
        raise ValueError('fresh provisioning output required')
    return path


def _complete_provisioning(value, *, source_path, source_pin, expected_bounds, argv):
    required = ('launcherCreated', 'launcherPidIdentityVerified', 'scopeVerified',
                'scopeAdmitted', 'captureComplete', 'waitComplete', 'cleanupVerified',
                'rootReaped', 'finalAbsenceVerified')
    if type(value) is not dict or any(value.get(k) is not True for k in required):
        return False
    if (value.get('provisioningOnly') is not True or
            value.get('workerExecVerified') is not False or
            value.get('workerTerminationVerified') is not False or
            type(value.get('exitCode')) is not int or value['exitCode'] != 0 or
            any(value.get(k) is not False for k in ('timedOut', 'outputExceeded', 'infrastructureFailure')) or
            type(value.get('stdout')) is not bytes or type(value.get('stderr')) is not bytes):
        return False
    scope = value.get('kernelScope')
    if type(scope) is not dict or scope.get('finalAbsenceVerified') is not True:
        return False
    bound_keys = {'schemaVersion', 'profileSha256', 'phase', 'wallSeconds',
                  'outputBytesPerStream', 'perProcessRlimits', 'cgroup', 'supervisor',
                  'workerExecProof', 'workerLimits', 'phaseLimits', 'helperGraph'}
    if (type(expected_bounds) is not dict or set(expected_bounds) != bound_keys or
            expected_bounds.get('phase') != 'helper-build' or
            not _valid_sha(expected_bounds.get('profileSha256')) or
            not _same_bounds(value.get('bounds'), expected_bounds)):
        return False
    actual_argv = value.get('argv')
    if (type(actual_argv) is not list or len(actual_argv) != len(argv) or
            any(type(arg) is not str for arg in actual_argv) or actual_argv != argv):
        return False
    pins = value.get('launchInputPins')
    if (type(pins) is not dict or not 1 <= len(pins) <= 256 or
            any(not _canonical_pin_name(name) or not _valid_pin(row)
                for name, row in pins.items())):
        return False
    if (not _canonical_pin_name(source_path) or not _valid_pin(source_pin) or
            pins.get(source_path) != source_pin):
        return False
    profile_pin = pins.get(str(ROOT / 'contracts/candidate-build-profile.json'))
    return (profile_pin is not None and
            profile_pin['sha256'] == expected_bounds['profileSha256'])


def build(output, receipt=None):
    """Compile exactly public monitor source through the one provisioning runner.

    No runner injection, argv switches, candidate paths, worker-proof flag, or
    native action is available at import. Dependency discovery is NOT simulated.
    The trusted composition must later bind the complete accepted input closure.
    """
    output = _output(output, binary=True)
    receipt = _output(receipt) if receipt is not None else None
    if MANIFEST.exists() or MANIFEST.is_symlink():
        raise ValueError('fixed monitor manifest already exists; preserve generation')
    sys.path.insert(0, str(ROOT))
    from bounded_runtime import provision_worker_monitor, public_result, execution_bounds
    from build_contract import load_profile_with_digest
    profile, profile_sha = load_profile_with_digest()
    expected_bounds = execution_bounds(managed_scope=True, phase='helper-build',
                                       snapshot=(profile, profile_sha))
    argv = build_command(output)
    source_path = str(SOURCES['sourceSha256'])
    if not _canonical_pin_name(source_path):
        raise ValueError('canonical monitor source path required')
    before = {key: _input_pin(path, 262144) for key, path in SOURCES.items()}
    output.parent.mkdir(parents=True, exist_ok=True)
    execution = provision_worker_monitor(output)
    if not _complete_provisioning(execution, source_path=source_path,
                                  source_pin=before['sourceSha256'],
                                  expected_bounds=expected_bounds, argv=argv):
        error = ValueError('incomplete channel-free monitor provisioning')
        error.bounded_result = execution
        raise error
    after = {key: _input_pin(path, 262144) for key, path in SOURCES.items()}
    if before != after:
        error = ValueError('monitor provisioning source changed during build')
        error.bounded_result = execution
        raise error
    value = {'schemaVersion': 1, 'status': 'provisioning-only-unqualified',
             'binaryPath': str(output), 'binarySha256': _hash(output, 16777216),
             **{key: row['sha256'] for key, row in after.items()},
             'dependencies': [], 'buildCommand': argv,
             'execution': public_result(execution)}
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    for destination in ([receipt, MANIFEST] if receipt is not None else [MANIFEST]):
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    value = build(args.output, args.receipt)
    print(json.dumps({'status': value['status'], 'binarySha256': value['binarySha256']}))


if __name__ == '__main__':
    main()
