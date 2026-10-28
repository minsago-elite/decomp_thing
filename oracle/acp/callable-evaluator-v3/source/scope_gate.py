"""Trusted host gate: kernel admission first, protected FD4 second, then fixed bwrap."""
import json
import hashlib
import fcntl
import errno
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



# Reviewed Linux UAPI045958acaa75205b31578cb22c4345e28dd2e4bf; no reduced-policy fallback.
_HELPER_REQUIRED_SEALS = 0x2f
_HELPER_KNOWN_SEALS = 0x3f


def _helper_policy():
    for module, values in ((os, {'MFD_CLOEXEC':1, 'MFD_ALLOW_SEALING':2, 'MFD_EXEC':16}),
                           (fcntl, {'F_SEAL_SEAL':1, 'F_SEAL_SHRINK':2, 'F_SEAL_GROW':4,
                                    'F_SEAL_WRITE':8, 'F_SEAL_FUTURE_WRITE':16, 'F_SEAL_EXEC':32})):
        for name, expected in values.items():
            if hasattr(module, name) and (type(getattr(module, name)) is not int or getattr(module, name) != expected):
                raise ValueError('conflicting executable snapshot UAPI')
    if (any(not callable(getattr(os,name,None)) for name in ('fstat','read','getxattr','dup2','set_inheritable')) or
            not callable(getattr(fcntl,'fcntl',None)) or
            any(type(getattr(fcntl,name,None)) is not int for name in ('F_ADD_SEALS','F_GET_SEALS'))):
        raise ValueError('executable snapshot APIs unavailable')


def _helper_record(record, maximum, controller):
    if (type(record) is not dict or set(record) != {'ownerPid','ownerStart','descriptor','helper'} or
            any(type(record[k]) is not int or not 0 < record[k] <= (1 << 63)-1 for k in ('ownerPid','ownerStart')) or
            type(record['descriptor']) is not int or not 0 <= record['descriptor'] <= (1 << 31)-1 or
            (record['ownerPid'],record['ownerStart']) != controller[:2]):
        raise ValueError('invalid held helper controller binding')
    helper = record['helper']
    if (type(helper) is not dict or set(helper) != {'device','inode','size','mode','sha256','sourcePath','sourcePin'} or
            any(type(helper[k]) is not int or not 0 <= helper[k] <= (1 << 64)-1 for k in ('device','inode')) or
            type(helper['size']) is not int or not 0 < helper['size'] <= maximum or
            type(helper['mode']) is not int or helper['mode'] != 0o500 or
            type(helper['sha256']) is not str or len(helper['sha256']) != 64 or
            any(c not in '0123456789abcdef' for c in helper['sha256']) or
            type(helper['sourcePath']) is not str or not helper['sourcePath'].startswith('/') or
            '\0' in helper['sourcePath'] or helper['sourcePath'].startswith('//') or len(helper['sourcePath'].encode()) > 4096 or
            '..' in Path(helper['sourcePath']).parts or str(Path(helper['sourcePath'])) != helper['sourcePath']):
        raise ValueError('invalid sealed helper binding')
    pin = helper['sourcePin']
    if (type(pin) is not dict or set(pin) != {'device','inode','mode','sha256'} or
            any(type(pin[k]) is not int or not 0 <= pin[k] <= (1 << 64)-1 for k in ('device','inode')) or
            type(pin['mode']) is not int or not 0 <= pin['mode'] <= 0o7777 or
            type(pin['sha256']) is not str or pin['sha256'] != helper['sha256'] or
            (pin['device'],pin['inode']) == (helper['device'],helper['inode'])):
        raise ValueError('helper source and execution identities differ from admission')
    return helper


def _acquire_helper_snapshot(record, maximum, deadline, controller):
    _helper_policy()
    helper = _helper_record(record,maximum,controller)
    def timely():
        if time.monotonic() >= deadline: raise TimeoutError('helper snapshot handoff deadline')
    def owner_alive():
        value = Path('/proc/' + str(record['ownerPid']) + '/stat').read_text()
        return int(value[value.rfind(')')+2:].split()[19]) == record['ownerStart']
    def metadata_matches(fd):
        metadata = os.fstat(fd); timely()
        seals = fcntl.fcntl(fd,fcntl.F_GET_SEALS); timely()
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o500 or
                metadata.st_uid != controller[2] or
                (metadata.st_dev,metadata.st_ino,metadata.st_size) != (helper['device'],helper['inode'],helper['size']) or
                seals & _HELPER_REQUIRED_SEALS != _HELPER_REQUIRED_SEALS or seals & ~_HELPER_KNOWN_SEALS):
            raise ValueError('held helper identity mode size or seals differ')
        try:
            os.getxattr(fd,'security.capability')
        except OSError as failure:
            if failure.errno != errno.ENODATA: raise
        else: raise ValueError('helper has capability metadata')
        timely()
    fd = None; source_owned = target_owned = False
    try:
        timely()
        alive = owner_alive()
        timely()
        if not alive: raise ValueError('helper snapshot owner lifetime changed')
        fd = os.open('/proc/' + str(record['ownerPid']) + '/fd/' + str(record['descriptor']),
                     os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        if fd == 5: target_owned = True
        else: source_owned = True
        timely(); metadata_matches(fd)
        value = hashlib.sha256(); count = 0; magic = b''
        while count < helper['size']:
            timely()
            block = os.read(fd,min(65536,helper['size']-count)); timely()
            if not block: raise ValueError('helper snapshot handoff truncated')
            if count < 4: magic += block[:4-count]
            count += len(block); value.update(block); timely()
        if magic != b'\x7fELF': raise ValueError('helper snapshot content or owner differs')
        actual_sha = value.hexdigest(); timely()
        if actual_sha != helper['sha256']:
            raise ValueError('helper snapshot content or owner differs')
        alive = owner_alive(); timely()
        if not alive: raise ValueError('helper snapshot content or owner differs')
        metadata_matches(fd)
        os.lseek(fd,0,os.SEEK_SET); timely()
        os.dup2(fd,5,inheritable=True)
        target_owned = True
        timely(); os.set_inheritable(5,True); timely()
        if source_owned:
            source_owned = False
            os.close(fd)
        timely()
        target_owned = False
    except BaseException as primary:
        if source_owned:
            source_owned = False
            try: os.close(fd)
            except BaseException:
                try: primary.add_note('helper snapshot source descriptor cleanup failed')
                except BaseException: pass
        if target_owned:
            target_owned = False
            try: os.close(5)
            except BaseException:
                try: primary.add_note('helper snapshot target descriptor cleanup failed')
                except BaseException: pass
        raise


def _acquire_library_snapshot(record, maximum, deadline):
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
    def timely():
        if time.monotonic() >= deadline: raise TimeoutError('snapshot handoff deadline')
    fd = None
    source_owned = False
    target_owned = False
    try:
        timely()
        if not owner_alive(): raise ValueError('snapshot owner lifetime changed')
        timely()
        fd = os.open('/proc/' + str(record['ownerPid']) + '/fd/' + str(record['descriptor']), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        # Acquire ownership before the first post-open clock or admission operation.
        if fd == 5: target_owned = True
        else: source_owned = True
        timely()
        metadata = os.fstat(fd)
        timely()
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        if (not stat.S_ISREG(metadata.st_mode) or
                (metadata.st_dev,metadata.st_ino,metadata.st_size) != (library['device'],library['inode'],library['size']) or
                fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals):
            raise ValueError('held snapshot identity or seals differ')
        timely()
        value = hashlib.sha256(); count = 0
        timely()
        while count < library['size']:
            timely()
            block = os.read(fd, min(65536, library['size'] - count))
            timely()
            if not block: raise ValueError('snapshot handoff truncated')
            count += len(block); value.update(block)
            timely()
        digest = value.hexdigest()
        timely()
        if digest != library['sha256'] or not owner_alive():
            raise ValueError('snapshot handoff content or owner differs')
        timely()
        os.lseek(fd, 0, os.SEEK_SET)
        timely()
        os.dup2(fd, 5, inheritable=True)
        # From this return onward, refusal owns FD5 even if later setup fails.
        target_owned = True
        timely()
        os.set_inheritable(5, True)
        timely()
        if source_owned:
            source_owned = False  # A failed close must never be retried.
            os.close(fd)
        timely()
        target_owned = False  # Transfer only after every fallible step has completed.
        return
    except BaseException as primary:
        if source_owned:
            source_owned = False
            try:
                os.close(fd)
            except BaseException:
                try: primary.add_note('snapshot source descriptor cleanup failed')
                except BaseException: pass
        if target_owned:
            target_owned = False
            try:
                os.close(5)
            except BaseException:
                try: primary.add_note('snapshot target descriptor cleanup failed')
                except BaseException: pass
        raise


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
        if not (set(config) in ({'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode','scope'}, {'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode','scope', 'librarySnapshot'}, {'schemaVersion', 'directoryDevice', 'directoryInode', 'mode', 'argv', 'report', 'outerPidNsDevice', 'outerPidNsInode','scope', 'helperSnapshot'})):
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
        if 'helperSnapshot' in config:
            marker = command.index('--') if '--' in command else -1
            tail = command[marker+1:] if marker >= 0 else []
            if (config['mode'] != 'worker' or len(tail) < 21 or tail[0] != '/_worker_exec_monitor' or
                    tail[3:5] != ['--phase','probe'] or tail[19:21] != ['--','/probe'] or
                    command[:marker].count('--ro-bind-fd') != 1):
                raise ValueError('helper snapshot requires fixed probe command')
            bind = command.index('--ro-bind-fd')
            if command[bind:bind+3] != ['--ro-bind-fd','5','/probe']:
                raise ValueError('helper snapshot fd mount missing')
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
                if directory_fd == 5: raise ValueError('snapshot fd aliases gate directory')
                _acquire_library_snapshot(config['librarySnapshot'], bounds['workerLaunchPinFileBytes'], deadline)
                _close_nonstandard({4,5,controller_fd,directory_fd,scope['fd']})
            elif 'helperSnapshot' in config:
                if directory_fd == 5: raise ValueError('snapshot fd aliases gate directory')
                _acquire_helper_snapshot(config['helperSnapshot'],bounds['workerLaunchPinFileBytes'],deadline,controller)
                _close_nonstandard({4,5,controller_fd,directory_fd,scope['fd']})
            else:
                if '--ro-bind-fd' in command: raise ValueError('unowned snapshot mount')
                _close_nonstandard({4,controller_fd,directory_fd,scope['fd']})
        else:
            if 'librarySnapshot' in config or 'helperSnapshot' in config: raise ValueError('provisioning snapshot forbidden')
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
