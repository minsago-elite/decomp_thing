"""Trusted host gate: kernel admission first, protected FD4 second, then fixed bwrap."""
import json
import os
from pathlib import Path
import resource
import stat
import sys
import time

BASE = Path(__file__).resolve().parent


def _read_at(directory_fd, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        metadata = os.fstat(fd)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
        assert stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1
        value = os.read(fd, maximum + 1)
        assert len(value) <= maximum
        return value
    finally:
        os.close(fd)


def _contract():
    # -I excludes cwd/PYTHONPATH; compiling the fixed source also excludes sibling .pyc.
    namespace = {'__file__': str(BASE / 'build_contract.py'), '__name__': '_scope_contract'}
    exec(compile((BASE / 'build_contract.py').read_bytes(), str(BASE / 'build_contract.py'), 'exec'), namespace)
    return namespace['load_profile']()


def _close_nonstandard(keep):
    # Include dots in the declared enumeration bound and reject any already-open high FD.
    entries = []
    with os.scandir('/proc/self/fd') as scan:
        for entry in scan:
            assert len(entries) < 64
            entries.append(entry)
    assert len(entries) + 2 <= 66
    for entry in entries:
        assert entry.name.isdecimal() and 0 <= int(entry.name) < 64
        descriptor = int(entry.name)
        if descriptor > 2 and descriptor not in keep:
            try:
                os.close(descriptor)
            except OSError as failure:
                # scandir's own descriptor is already closed by list materialization.
                assert failure.errno == 9


def main():
    assert len(sys.argv) == 2 and sys.flags.isolated and sys.dont_write_bytecode
    gate = Path(sys.argv[1])
    assert gate.is_absolute() and gate.parent == BASE / 'exec-proof-receipts'
    assert sys.pycache_prefix == str(gate / 'python-cache')
    directory_fd = os.open(gate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(directory_fd)
    assert metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700
    config = json.loads(_read_at(directory_fd, 'launch.json', 65536))
    assert set(config) == {'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode'}
    assert config['schemaVersion'] == 1 and type(config['schemaVersion']) is int
    assert (metadata.st_dev, metadata.st_ino) == (config['directoryDevice'], config['directoryInode'])
    assert config['mode'] in ('worker', 'monitor-provisioning')
    command = config['argv']
    assert isinstance(command, list) and command and all(isinstance(a, str) and '\0' not in a for a in command)
    if config['mode'] == 'worker':
        assert command[0] == '/usr/bin/bwrap'
    else:
        assert config['report'] is None
        output = Path(command[-1])
        assert output.name == 'worker_exec_monitor' and output == output.resolve() and not output.exists()
        assert output.is_relative_to(BASE.parents[3] / 'build/acp-decomp-effectiveness/callable-library-v3')
        assert command == ['/usr/bin/gcc', '-D_GNU_SOURCE', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                           '-Wl,-z,relro,-z,now,-z,noexecstack', str(BASE / 'worker_exec_monitor.c'), '-o', str(output)]
    bounds = _contract()['bounds']
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == (bounds['openFiles'], bounds['openFiles'])
    status = Path('/proc/self/status').read_text()
    for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
        assert int(next(line.split(':', 1)[1].strip() for line in status.splitlines() if line.startswith(key + ':')), 16) == 0
    pidns = Path('/proc/self/ns/pid').stat()
    assert (pidns.st_dev, pidns.st_ino) == (config['outerPidNsDevice'], config['outerPidNsInode'])
    value = Path('/proc/self/stat').read_text()
    fields = value[value.rfind(')') + 2:].split()
    record = {'pid': os.getpid(), 'start': int(fields[19])}
    fd = os.open('gate.tmp', os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_WRONLY, 0o600, dir_fd=directory_fd)
    try:
        raw = json.dumps(record, separators=(',', ':')).encode()
        assert os.write(fd, raw) == len(raw)
    finally:
        os.close(fd)
    os.rename('gate.tmp', 'gate.json', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    deadline = time.monotonic() + bounds['scopeAdmissionSeconds']
    while True:
        try:
            admission = _read_at(directory_fd, 'admit', 2)
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise SystemExit(70)
            time.sleep(bounds['scopeAdmissionPollSeconds'])
    assert admission == b'1\n'
    if config['mode'] == 'worker':
        report = config['report']
        assert set(report) == {'device', 'inode'}
        # The first gate-side report open occurs only after the kernel-verified admission.
        fd = os.open('worker-proof.jsonl', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        metadata = os.fstat(fd)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
        assert stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1 and metadata.st_size == 0
        assert (metadata.st_dev, metadata.st_ino) == (report['device'], report['inode'])
        os.dup2(fd, 4, inheritable=True)
        os.set_inheritable(4, True)  # also required when open returned descriptor4 itself
        if fd != 4:
            os.close(fd)
        _close_nonstandard({4})
    else:
        _close_nonstandard(set())
    os.execv(command[0], command)


if __name__ == '__main__':
    main()
