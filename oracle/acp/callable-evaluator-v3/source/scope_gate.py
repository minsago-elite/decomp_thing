"""Trusted host gate: kernel admission first, protected FD4 second, then fixed bwrap."""
import json
import hashlib
import fcntl
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
        if not (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()):
            raise ValueError("scope gate policy refusal at check 17")
        if not (stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1):
            raise ValueError("scope gate policy refusal at check 18")
        value = os.read(fd, maximum + 1)
        if not (len(value) <= maximum):
            raise ValueError("scope gate policy refusal at check 20")
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
            if not (len(entries) < 64):
                raise ValueError("scope gate policy refusal at check 38")
            entries.append(entry)
    if not (len(entries) + 2 <= 66):
        raise ValueError("scope gate policy refusal at check 40")
    for entry in entries:
        if not (entry.name.isdecimal() and 0 <= int(entry.name) < 64):
            raise ValueError("scope gate policy refusal at check 42")
        descriptor = int(entry.name)
        if descriptor > 2 and descriptor not in keep:
            try:
                os.close(descriptor)
            except OSError as failure:
                # scandir's own descriptor is already closed by list materialization.
                if not (failure.errno == 9):
                    raise ValueError("scope gate policy refusal at check 49")



def _acquire_library_snapshot(record, maximum):
    if (type(record) is not dict or set(record) != {'ownerPid','ownerStart','descriptor','library'} or
            any(type(record[k]) is not int or not 0 < record[k] <= (1 << 63) - 1 for k in ('ownerPid','ownerStart')) or
            type(record['descriptor']) is not int or not 0 <= record['descriptor'] <= (1 << 31) - 1):
        raise ValueError('invalid held library owner binding')
    library = record['library']
    if (type(library) is not dict or set(library) != {'device','inode','size','sha256','sourcePath'} or
            any(type(library[k]) is not int or library[k] < 0 for k in ('device','inode','size')) or
            not 0 < library['size'] <= maximum or type(library['sha256']) is not str or
            len(library['sha256']) != 64 or any(c not in '0123456789abcdef' for c in library['sha256'])):
        raise ValueError('invalid sealed library content binding')
    def owner_alive():
        value = Path('/proc/' + str(record['ownerPid']) + '/stat').read_text()
        return int(value[value.rfind(')') + 2:].split()[19]) == record['ownerStart']
    if not owner_alive(): raise ValueError('snapshot owner lifetime changed')
    fd = os.open('/proc/' + str(record['ownerPid']) + '/fd/' + str(record['descriptor']), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    transferred = False
    try:
        metadata = os.fstat(fd)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        if (not stat.S_ISREG(metadata.st_mode) or
                (metadata.st_dev,metadata.st_ino,metadata.st_size) != (library['device'],library['inode'],library['size']) or
                fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals):
            raise ValueError('held snapshot identity or seals differ')
        value = hashlib.sha256(); count = 0
        deadline = time.monotonic() + _contract()['bounds']['scopeAdmissionSeconds']
        while count < library['size']:
            if time.monotonic() >= deadline: raise TimeoutError('snapshot handoff deadline')
            block = os.read(fd, min(65536, library['size'] - count))
            if not block: raise ValueError('snapshot handoff truncated')
            count += len(block); value.update(block)
        if value.hexdigest() != library['sha256'] or not owner_alive():
            raise ValueError('snapshot handoff content or owner differs')
        os.lseek(fd, 0, os.SEEK_SET)
        os.dup2(fd, 5, inheritable=True)
        os.set_inheritable(5, True)
        transferred = True
    finally:
        if fd != 5 or not transferred: os.close(fd)


def main():
    if not (len(sys.argv) == 2 and sys.flags.isolated and sys.dont_write_bytecode):
        raise ValueError("scope gate policy refusal at check 53")
    gate = Path(sys.argv[1])
    if not (gate.is_absolute() and gate.parent == BASE / 'exec-proof-receipts'):
        raise ValueError("scope gate policy refusal at check 55")
    if not (sys.pycache_prefix == str(gate / 'python-cache')):
        raise ValueError("scope gate policy refusal at check 56")
    directory_fd = os.open(gate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(directory_fd)
    if not (metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700):
        raise ValueError("scope gate policy refusal at check 59")
    config = json.loads(_read_at(directory_fd, 'launch.json', 65536))
    if not (set(config) in ({'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode'}, {'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode', 'librarySnapshot'})):
        raise ValueError("scope gate policy refusal at check 61")
    if not (config['schemaVersion'] == 1 and type(config['schemaVersion']) is int):
        raise ValueError("scope gate policy refusal at check 62")
    if not ((metadata.st_dev, metadata.st_ino) == (config['directoryDevice'], config['directoryInode'])):
        raise ValueError("scope gate policy refusal at check 63")
    if not (config['mode'] in ('worker', 'monitor-provisioning')):
        raise ValueError("scope gate policy refusal at check 64")
    command = config['argv']
    if not (isinstance(command, list) and command and all(isinstance(a, str) and '\0' not in a for a in command)):
        raise ValueError("scope gate policy refusal at check 66")
    if config['mode'] == 'worker':
        if not (command[0] == '/usr/bin/bwrap'):
            raise ValueError("scope gate policy refusal at check 68")
    else:
        if not (config['report'] is None):
            raise ValueError("scope gate policy refusal at check 70")
        output = Path(command[-1])
        if not (output.name == 'worker_exec_monitor' and output == output.resolve() and not output.exists()):
            raise ValueError("scope gate policy refusal at check 72")
        if not (output.is_relative_to(BASE.parents[3] / 'build/acp-decomp-effectiveness/callable-library-v3')):
            raise ValueError("scope gate policy refusal at check 73")
        if not (command == ['/usr/bin/gcc', '-D_GNU_SOURCE', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                           '-Wl,-z,relro,-z,now,-z,noexecstack', str(BASE / 'worker_exec_monitor.c'), '-o', str(output)]):
            raise ValueError("scope gate policy refusal at check 74")
    bounds = _contract()['bounds']
    if not (resource.getrlimit(resource.RLIMIT_NOFILE) == (bounds['openFiles'], bounds['openFiles'])):
        raise ValueError("scope gate policy refusal at check 77")
    status = Path('/proc/self/status').read_text()
    for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
        if not (int(next(line.split(':', 1)[1].strip() for line in status.splitlines() if line.startswith(key + ':')), 16) == 0):
            raise ValueError("scope gate policy refusal at check 80")
    pidns = Path('/proc/self/ns/pid').stat()
    if not ((pidns.st_dev, pidns.st_ino) == (config['outerPidNsDevice'], config['outerPidNsInode'])):
        raise ValueError("scope gate policy refusal at check 82")
    value = Path('/proc/self/stat').read_text()
    fields = value[value.rfind(')') + 2:].split()
    record = {'pid': os.getpid(), 'start': int(fields[19])}
    fd = os.open('gate.tmp', os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_WRONLY, 0o600, dir_fd=directory_fd)
    try:
        raw = json.dumps(record, separators=(',', ':')).encode()
        if not (os.write(fd, raw) == len(raw)):
            raise ValueError("scope gate policy refusal at check 89")
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
    if not (admission == b'1\n'):
        raise ValueError("scope gate policy refusal at check 102")
    if config['mode'] == 'worker':
        report = config['report']
        if not (set(report) == {'device', 'inode'}):
            raise ValueError("scope gate policy refusal at check 105")
        # The first gate-side report open occurs only after the kernel-verified admission.
        fd = os.open('worker-proof.jsonl', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        metadata = os.fstat(fd)
        if not (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()):
            raise ValueError("scope gate policy refusal at check 109")
        if not (stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1 and metadata.st_size == 0):
            raise ValueError("scope gate policy refusal at check 110")
        if not ((metadata.st_dev, metadata.st_ino) == (report['device'], report['inode'])):
            raise ValueError("scope gate policy refusal at check 111")
        os.dup2(fd, 4, inheritable=True)
        os.set_inheritable(4, True)  # also required when open returned descriptor4 itself
        if fd != 4:
            os.close(fd)
        if 'librarySnapshot' in config:
            if command.count('--ro-bind-fd') != 1 or command[command.index('--ro-bind-fd') + 1:command.index('--ro-bind-fd') + 3] != ['5','/library.so']:
                raise ValueError('snapshot fd mount missing')
            _acquire_library_snapshot(config['librarySnapshot'], bounds['workerLaunchPinFileBytes'])
            _close_nonstandard({4,5})
        else:
            if '--ro-bind-fd' in command: raise ValueError('unowned snapshot mount')
            _close_nonstandard({4})
    else:
        if 'librarySnapshot' in config: raise ValueError('provisioning snapshot forbidden')
        _close_nonstandard(set())
    os.execv(command[0], command)


if __name__ == '__main__':
    main()
