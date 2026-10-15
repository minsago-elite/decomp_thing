"""Explicit, narrowly scoped monitor provisioning; import never launches tools.

The output is NOT a qualified machine pin. Accepted complete compiler/link/header/
loader/runtime input inventory and native public qualification remain independent
mandatory gates. The channel-free compiler cannot prove its own monitored exec.
"""
from __future__ import annotations

import argparse
import hashlib
import json
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


def _hash(path, maximum):
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
        return digest.hexdigest()
    finally:
        os.close(descriptor)


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


def _complete_provisioning(value):
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
    return type(scope) is dict and scope.get('finalAbsenceVerified') is True


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
    before = {key: _hash(path, 262144) for key, path in SOURCES.items()}
    sys.path.insert(0, str(ROOT))
    from bounded_runtime import provision_worker_monitor, public_result
    output.parent.mkdir(parents=True, exist_ok=True)
    execution = provision_worker_monitor(output)
    if not _complete_provisioning(execution):
        error = ValueError('incomplete channel-free monitor provisioning')
        error.bounded_result = execution
        raise error
    after = {key: _hash(path, 262144) for key, path in SOURCES.items()}
    if before != after:
        raise ValueError('monitor provisioning source changed during build')
    value = {'schemaVersion': 1, 'status': 'provisioning-only-unqualified',
             'binaryPath': str(output), 'binarySha256': _hash(output, 16777216),
             **after, 'dependencies': [], 'buildCommand': build_command(output),
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
