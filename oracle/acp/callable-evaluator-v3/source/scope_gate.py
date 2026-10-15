"""Trusted host gate: kernel admission first, protected FD4 second, then fixed bwrap."""
import json
import hashlib
import fcntl
import math
import select
import signal
import os
from pathlib import Path
import resource
import stat
import sys
import time

BASE = Path(__file__).resolve().parent


def _read_at(directory_fd, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        metadata = os.fstat(fd)
        if not (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()):
            raise ValueError("scope gate policy refusal at check 17")
        if not (stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1):
            raise ValueError("scope gate policy refusal at check 18")
        chunks=[];size=0
        while True:
            block=os.read(fd,min(65536,maximum+1-size))
            if not block: break
            size+=len(block)
            if size>maximum: raise ValueError('scope gate bounded file overflow')
            chunks.append(block)
        value=b''.join(chunks)
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



def _authenticated_config(directory_fd, expected):
    raw=_read_at(directory_fd,'launch.json',65536)
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('launch config commitment mismatch')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise ValueError('duplicate launch config key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid config number')))


def _controller_identity(controller):
    pid,start,uid=controller
    with Path('/proc/'+str(pid)+'/stat').open('rb') as stream: raw=stream.read(4097)
    if len(raw)>4096 or int(raw[raw.rfind(b')')+2:].split()[19])!=start:
        raise ValueError('controller lifetime changed')
    with Path('/proc/'+str(pid)+'/status').open('rb') as stream: status=stream.read(4097)
    if len(status)>4096: raise ValueError('controller metadata bound')
    real_uid=int(next(line.split()[1] for line in status.splitlines() if line.startswith(b'Uid:')))
    if real_uid!=uid: raise ValueError('controller real UID changed')
    left=Path('/proc/'+str(pid)+'/ns/pid').stat();right=Path('/proc/self/ns/pid').stat()
    if (left.st_dev,left.st_ino)!=(right.st_dev,right.st_ino):raise ValueError('controller PID coordinates differ')


def _live_controller(controller, descriptor):
    _controller_identity(controller)
    poll=select.poll();poll.register(descriptor,select.POLLIN)
    if poll.poll(0):raise ValueError('controller exited')



def _scope_membership():
    with Path('/proc/self/cgroup').open('rb') as stream:raw=stream.read(4097)
    if len(raw)>4096:raise ValueError('gate cgroup membership byte bound')
    record=raw.decode('ascii').strip()
    if not record.startswith('0::/') or '\n' in record or any(p in ('.','..') for p in record[4:].split('/')):
        raise ValueError('invalid gate cgroup membership')
    return record


def _check_scope(scope, deadline):
    def timely():
        if time.monotonic()>=deadline:raise TimeoutError('gate scope deadline')
    timely()
    if _scope_membership()!=scope['membership']:raise ValueError('gate scope membership changed')
    held=os.fstat(scope['fd']);current=Path(scope['path']).stat()
    identity=(scope['device'],scope['inode'])
    if (not stat.S_ISDIR(held.st_mode) or (held.st_dev,held.st_ino)!=identity or
            (current.st_dev,current.st_ino)!=identity):
        raise ValueError('gate acquired scope identity changed')
    for name,wanted in scope['limits'].items():
        timely()
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=scope['fd'])
        try:
            raw=os.read(fd,65)
            if len(raw)>64 or raw.decode('ascii').strip()!=wanted:raise ValueError('gate scope limit changed')
        finally:os.close(fd)
    if _scope_membership()!=scope['membership']:raise ValueError('gate scope membership changed during limits')
    timely()


def _acquire_scope(expected, bounds, unit, deadline):
    limits={'pids.max':str(bounds['tasks']),'memory.max':str(bounds['memoryBytes']),
            'memory.swap.max':str(bounds['swapBytes'])}
    if (type(expected) is not dict or set(expected)!={'unit','limits'} or
            expected['unit']!=unit or expected['limits']!=limits):
        raise ValueError('committed scope unit or limits differ')
    record=_scope_membership();path=Path('/sys/fs/cgroup')/record[4:]
    if path.name!=unit or path.resolve()!=path:raise ValueError('gate is not in committed scope')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        metadata=os.fstat(fd)
        scope={'fd':fd,'path':str(path),'device':metadata.st_dev,'inode':metadata.st_ino,
               'membership':record,'limits':limits}
        _check_scope(scope,deadline)
        if fd!=7:
            os.dup2(fd,7,inheritable=False)
            os.close(fd);fd=7;scope['fd']=7
        return scope
    except BaseException:
        os.close(fd)
        raise


def _wait_release(controller, descriptor, deadline):
    if time.monotonic()>=deadline:raise TimeoutError('gate release deadline')
    _live_controller(controller,descriptor)
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('gate release deadline before wait')
    info=signal.sigtimedwait({signal.SIGUSR1},remaining)
    if time.monotonic()>=deadline:raise TimeoutError('gate release returned after deadline')
    if (info is None or info.si_signo!=signal.SIGUSR1 or info.si_code!=0 or info.si_errno!=0 or
            info.si_pid!=controller[0] or info.si_uid!=controller[2]):
        raise ValueError('unauthenticated controller release')
    _live_controller(controller,descriptor)


def main():
    began=time.monotonic()
    if not all(callable(getattr(module,name,None)) for module,name in
               ((signal,'pthread_sigmask'),(signal,'sigtimedwait'),(os,'pidfd_open'))):
        raise ValueError('required authenticated release APIs unavailable')
    if (len(sys.argv)!=10 or sys.argv[2]!='--config-sha256' or sys.argv[4]!='--controller' or
            sys.argv[8]!='--phase-deadline' or len(sys.argv[3])!=64 or
            any(c not in '0123456789abcdef' for c in sys.argv[3])):
        raise ValueError('closed trusted gate argv required')
    controller=tuple(int(value) for value in sys.argv[5:8])
    if not (0<controller[0]<(1<<31) and 0<controller[1]<(1<<64) and 0<=controller[2]<(1<<32)):
        raise ValueError('invalid controller argv identity')
    phase_end=float(sys.argv[9])
    if not math.isfinite(phase_end):raise ValueError('invalid phase deadline')
    original_handler=signal.getsignal(signal.SIGUSR1)
    original_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1})
    descriptor=None
    try:
        if original_handler!=signal.SIG_DFL or signal.SIGUSR1 in original_mask:
            raise ValueError('unsupported inherited release signal policy')
        deadline=min(phase_end,began+_contract()['bounds']['scopeAdmissionSeconds'])
        if time.monotonic()>=deadline:raise TimeoutError('gate bootstrap deadline')
        _controller_identity(controller)
        descriptor=os.pidfd_open(controller[0])
        if descriptor!=6:
            os.dup2(descriptor,6,inheritable=False)
            os.close(descriptor);descriptor=6
        _live_controller(controller,descriptor)
        command=_main(sys.argv[3],controller,descriptor,deadline)
        _live_controller(controller,descriptor)
        if time.monotonic()>=deadline:raise TimeoutError('gate report handoff deadline')
    finally:
        try:
            if descriptor is not None:os.close(descriptor)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,original_mask)
        # No asynchronous handler is installed; disposition remains original.
    os.execv(command[0],command)


def _main(config_sha, controller, controller_fd, deadline):
    if not (len(sys.argv) == 10 and sys.flags.isolated and sys.dont_write_bytecode):
        raise ValueError("scope gate policy refusal at check 53")
    gate = Path(sys.argv[1])
    if not (gate.is_absolute() and gate.parent == BASE / 'exec-proof-receipts'):
        raise ValueError("scope gate policy refusal at check 55")
    if not (sys.pycache_prefix == str(gate / 'python-cache')):
        raise ValueError("scope gate policy refusal at check 56")
    directory_fd = os.open(gate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    scope=None
    try:
        metadata = os.fstat(directory_fd)
        if not (metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700):
            raise ValueError("scope gate policy refusal at check 59")
        config = _authenticated_config(directory_fd,config_sha)
        if not (set(config) in ({'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode','scope'}, {'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode','scope', 'librarySnapshot'})):
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
        scope=_acquire_scope(config['scope'],bounds,'decomp-acp-efficacy-'+gate.name+'.scope',deadline)
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
        _wait_release(controller,controller_fd,deadline)
        _check_scope(scope,deadline)
        if time.monotonic()>=deadline:raise TimeoutError('gate report release deadline')
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
                _close_nonstandard({4,5,controller_fd,directory_fd,scope['fd']})
            else:
                if '--ro-bind-fd' in command: raise ValueError('unowned snapshot mount')
                _close_nonstandard({4,controller_fd,directory_fd,scope['fd']})
        else:
            if 'librarySnapshot' in config: raise ValueError('provisioning snapshot forbidden')
            _close_nonstandard({controller_fd,directory_fd,scope['fd']})
        _check_scope(scope,deadline)
        return command

    finally:
        try:
            if scope is not None:os.close(scope['fd'])
        finally:
            os.close(directory_fd)


if __name__ == '__main__':
    main()
