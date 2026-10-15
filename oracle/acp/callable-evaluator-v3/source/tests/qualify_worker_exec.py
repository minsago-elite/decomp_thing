"""Explicit public native qualification source; NEVER test-discovery executed.

Static checkpoint: this source has not been launched or natively qualified.
--allow-native-controls is required, in addition to root's separate Phase B
permission. No candidate/private truth is used. Surrogate observations are
qualificationOnly and cannot enter any candidate/process acceptance denominator.
Production bwrap never accepts --as-pid-1; only this finite fixed fixture does.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1]
REPOSITORY = SOURCE.parents[3]
BUILD_ROOT = REPOSITORY / 'build/acp-decomp-effectiveness/callable-library-v3'
sys.path.insert(0, str(SOURCE))

# Public synthetic code only; no oracle/candidate/API fixture is referenced.
WORKER_SOURCE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
static int emit(int fd,const char *s) {
  size_t left=strlen(s);
  while(left) { ssize_t n=write(fd,s,left); if(n<=0)return -1; s+=n;left-=(size_t)n; }
  return 0;
}
static int denied(int error) { return error==EACCES || error==EPERM || error==ENOENT; }
static int start_time(pid_t pid,unsigned long long *out) {
  char path[80],data[4097]; snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
  int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0)return -1;
  ssize_t n=read(fd,data,sizeof(data)); close(fd);
  if(n<=0 || n>4096)return -1;data[n]=0;
  char *tail=strrchr(data,')'); if(!tail || tail[1]!=' ' || tail[3]!=' ')return -1;
  tail+=4;
  for(int field=4;field<=22;++field) {
    char *end=strchr(tail,' '); if(!end)return -1;
    if(field==22) { *end=0;char *stop;errno=0;*out=strtoull(tail,&stop,10);return errno || *stop || !*out ? -1:0; }
    tail=end+1;
  }
  return -1;
}
static int same(const struct stat *a,const struct stat *b) { return a->st_dev==b->st_dev && a->st_ino==b->st_ino; }
static int channel(pid_t monitor,unsigned long long saved_start) {
  unsigned long long actual;char path[80];
  if(start_time(monitor,&actual)<0 || actual!=saved_start)return 101;
  errno=0;if(fcntl(4,F_GETFD)!=-1 || errno!=EBADF)return 102;
  errno=0;if(write(4,"forged",6)!=-1 || errno!=EBADF)return 103;
  snprintf(path,sizeof(path),"/proc/%ld/fd/4",(long)monitor);
  errno=0;int fd=open(path,O_WRONLY|O_APPEND|O_NONBLOCK|O_CLOEXEC);
  if(fd>=0) { emit(fd,"forged-monitor-channel\n");close(fd);return 104; }
  if(!denied(errno))return 105;
  errno=0;if(ptrace(PTRACE_ATTACH,monitor,0,0)!=-1 || errno!=EPERM)return 106;
  char byte='x';struct iovec local={&byte,1},remote={(void *)1,1};
  errno=0;if(process_vm_writev(monitor,&local,1,&remote,1,0)!=-1 || errno!=EPERM)return 107;
  struct stat stdio[3];for(int n=0;n<3;++n)if(fstat(n,&stdio[n])<0)return 108;
  unsigned events=0;
  /* All64 candidate-visible slots, including renamed aliases4/7 and old-root8.
   * Kernel proc links identify legitimate stdio/eventfd. Do not require allowed
   * stdio/eventfd opens to fail, and never scan processes outside this PIDns. */
  for(int slot=0;slot<64;++slot) {
    char link[4097];snprintf(path,sizeof(path),"/proc/1/fd/%d",slot);
    ssize_t n=readlink(path,link,sizeof(link));
    if(n<0) {
      if(!denied(errno))return 109;
      if(slot<=2)continue; /* Allowed captured stdio need not deny opens. */
      /* A denied link read is not a substituted open result: also try acquire. */
      fd=open(path,O_WRONLY|O_APPEND|O_NONBLOCK|O_CLOEXEC);
      if(fd>=0) { emit(fd,"forged-reaper-channel\n");close(fd);return 110; }
      if(!denied(errno) && errno!=ENXIO)return 111;
      continue;
    }
    if(n>4096)return 112;link[n]=0;
    struct stat object;if(stat(path,&object)<0) { if(denied(errno))continue;return 113; }
    if(slot<=2) { if(!same(&object,&stdio[slot]) || S_ISDIR(object.st_mode))return 114;continue; }
    if(!strcmp(link,"anon_inode:[eventfd]")) { if(++events>1)return 115;continue; }
    /* An unknown extra holder already violates the strict accepted table. Try
     * the actual proc-FD acquisition/write path for regular report aliases;
     * directory acquisition is separate and never traverses host processes. */
    fd=open(path,S_ISDIR(object.st_mode)?(O_RDONLY|O_DIRECTORY|O_NONBLOCK|O_CLOEXEC):(O_WRONLY|O_APPEND|O_NONBLOCK|O_CLOEXEC));
    if(fd>=0) { if(S_ISREG(object.st_mode))emit(fd,"forged-reaper-alias\n");close(fd); }
    return 116;
  }
  /* Visible PID1 root/proc must either deny access or name this sandbox view,
   * never an old host root/proc authority. No host PID census/paths are used. */
  struct stat root,reaper_root,ns,reaper_ns;
  if(stat("/",&root)<0 || stat("/proc/self/ns/pid",&ns)<0)return 117;
  fd=open("/proc/1/root",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
  if(fd<0) { if(!denied(errno))return 118; }
  else {
    if(fstat(fd,&reaper_root)<0 || !same(&root,&reaper_root)) { close(fd);return 119; }
    int view=openat(fd,"proc/self/ns/pid",O_RDONLY|O_CLOEXEC);close(fd);
    if(view<0) { if(!denied(errno))return 120; }
    else { int result=fstat(view,&reaper_ns);close(view);if(result<0 || !same(&ns,&reaper_ns))return 121; }
  }
  if(start_time(monitor,&actual)<0 || actual!=saved_start)return 122;
  return 0;
}
static int descendant(pid_t monitor,unsigned long long saved_start,int hold) {
  int ready[2];if(pipe2(ready,O_CLOEXEC)<0)return 123;
  pid_t child=fork();if(child<0)return 124;
  if(!child) {
    close(ready[0]);int notify=fcntl(ready[1],F_DUPFD_CLOEXEC,10);close(ready[1]);
    if(notify<0)_exit(125);
    /* Preserve monitor identity from before fork: getppid() is now the worker. */
    int result=channel(monitor,saved_start);
    if(!result && emit(1,"DESCENDANT-CHANNEL-DENIED\n")<0)result=126;
    if(write(notify,&result,sizeof(result))!=(ssize_t)sizeof(result))_exit(127);
    close(notify);if(result)_exit(result);
    if(hold)for(;;)pause();
    _exit(0);
  }
  close(ready[1]);int result=-1;ssize_t n=read(ready[0],&result,sizeof(result));close(ready[0]);
  if(n!=(ssize_t)sizeof(result) || result)return 128;
  if(hold) { if(emit(1,"FAULT:descendant\n")<0)return 129;return 0; }
  int status;if(waitpid(child,&status,0)!=child || !WIFEXITED(status))return 130;
  return WEXITSTATUS(status);
}
int main(int argc,char **argv) {
  if(argc<2)return 90;
  pid_t monitor=getppid();unsigned long long saved_start=0;
  if(!strcmp(argv[1],"zero"))return 0;
  if(!strcmp(argv[1],"42"))return 42;
  if(!strcmp(argv[1],"139"))return 139;
  if(!strcmp(argv[1],"signal")) { raise(SIGSEGV);return 91; }
  if(!strcmp(argv[1],"fake")) { puts("__ACP_BEGIN__\n{\"v\":1,\"t\":\"exec\"}\n__ACP_END__");return 42; }
  if(!strcmp(argv[1],"mutant")) { puts("mutant");return 42; }
  if(!strcmp(argv[1],"load") && argc==3) { void *p=dlopen(argv[2],RTLD_NOW);if(!p)return 92;dlclose(p);return 0; }
  if(!strcmp(argv[1],"attack") || !strcmp(argv[1],"descendant-channel") || !strcmp(argv[1],"descendant")) {
    if(start_time(monitor,&saved_start)<0 || monitor<=1)return 131;
    if(!strcmp(argv[1],"attack")) { int r=channel(monitor,saved_start);if(!r && emit(1,"CHANNEL-DENIED\n")<0)return 132;return r; }
    return descendant(monitor,saved_start,!strcmp(argv[1],"descendant"));
  }
  if(!strcmp(argv[1],"kill-monitor")) { if(emit(1,"FAULT:kill-monitor\n")<0 || kill(monitor,SIGKILL)<0)return 133;for(;;)pause(); }
  if(!strcmp(argv[1],"stop-monitor")) { if(emit(1,"FAULT:stop-monitor\n")<0 || kill(monitor,SIGSTOP)<0)return 134;for(;;)pause(); }
  if(!strcmp(argv[1],"timeout")) { if(emit(1,"FAULT:timeout\n")<0)return 135;for(;;)pause(); }
  if(!strcmp(argv[1],"flood")) { if(emit(1,"FAULT:flood\n")<0)return 136;char b[4096];memset(b,'x',sizeof(b));for(;;)if(write(1,b,sizeof(b))<0)return 137; }
  return 100;
}
'''

CONSTRUCTORS = {'exit42': '#include <stdlib.h>\n__attribute__((constructor)) static void c(void){exit(42);}\n',
                'crash': '#include <signal.h>\n__attribute__((constructor)) static void c(void){raise(SIGSEGV);}\n'}


def _read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(fd, min(8192, maximum + 1 - len(data)))
            if not block:
                return bytes(data)
            data.extend(block)
        raise ValueError('qualification metadata byte cap')
    finally:
        os.close(fd)



def _ack_bytes(descriptor):
    try:
        return os.read(descriptor, 3)
    except BlockingIOError:
        return b''  # No acknowledgment yet, never evidence of barrier completion.

def _json(path, maximum=65536):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate qualifier metadata')
            value[key] = item
        return value
    return json.loads(_read(path, maximum), object_pairs_hook=pairs)


def _write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if len(raw) > 262144:
        raise ValueError('qualification receipt byte cap')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def _identity(pid):
    raw = _read(Path('/proc') / str(pid) / 'stat', 4096).decode('ascii')
    first = int(raw.split(' ', 1)[0])
    tail = raw[raw.rfind(')') + 2:].split()
    if first != pid or len(tail) < 20:
        raise ValueError('qualification PID identity')
    return {'pid': pid, 'start': int(tail[19]), 'parent': int(tail[1])}


def _devino(path):
    value = os.stat(path)
    return [value.st_dev, value.st_ino]


def _scope_pids(scope):
    path = Path(scope['path'])
    try:
        if _devino(path) != scope['identity']:
            raise ValueError('qualification cgroup identity drift')
        words = _read(path / 'cgroup.procs', 4096).split()
    except FileNotFoundError:
        if path.exists():
            raise ValueError('unreadable retained qualifier scope')
        return []
    if len(words) > 32 or any(not w.isdigit() for w in words):
        raise ValueError('qualification scope task cap')
    return [int(w) for w in words]


def _verify_scope(record, unit, bounds):
    if set(record) != {'pid', 'start'} or _identity(record['pid'])['start'] != record['start']:
        raise ValueError('qualifier gate PID/start mismatch')
    lines = _read(Path('/proc') / str(record['pid']) / 'cgroup', 4096).decode().splitlines()
    paths = [line[3:] for line in lines if line.startswith('0::')]
    if len(paths) != 1 or not paths[0].startswith('/') or '..' in Path(paths[0]).parts:
        raise ValueError('unified qualifier cgroup required')
    path = Path('/sys/fs/cgroup') / paths[0].lstrip('/')
    if path.name != unit:
        raise ValueError('qualifier gate outside requested scope')
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError('qualifier cgroup directory required')
        scope = {'path': str(path), 'identity': [metadata.st_dev,metadata.st_ino],
                 'directoryFd': descriptor}
        for file, value in [('pids.max', bounds['tasks']), ('memory.max', bounds['memoryBytes']),
                            ('memory.swap.max', bounds['swapBytes'])]:
            if _read(path / file, 64).strip() != str(value).encode():
                raise ValueError('qualifier kernel scope limit mismatch')
        if record['pid'] not in _scope_pids(scope) or _identity(record['pid'])['start'] != record['start']:
            raise ValueError('qualifier gate not in retained scope')
        return scope  # Keep this kernel object FD until all cleanup/proof checks finish.
    except BaseException:
        os.close(descriptor)
        raise


def _kill_scope(scope):
    """Signal the retained kernel cgroup object, never a PID from a stale list.

    cgroup.procs is an absence observation only. A reused PID outside this object
    cannot become kill authority. Missing/unsupported/denied cgroup.kill refuses;
    there is no per-PID fallback. The caller's retained launcher identity is a
    separate authority acquired from its own Popen, never scope enumeration.
    """
    directory = scope['directoryFd']  # Acquired at verified admission, never reopened by path/PID.
    actual = os.fstat(directory)
    if not stat.S_ISDIR(actual.st_mode) or [actual.st_dev, actual.st_ino] != scope['identity']:
        raise ValueError('qualifier retained scope identity mismatch')
    descriptor = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        interface = os.fstat(descriptor)
        after = os.fstat(directory)
        if (not stat.S_ISREG(interface.st_mode) or interface.st_dev != actual.st_dev or
                [after.st_dev, after.st_ino] != scope['identity']):
            raise ValueError('qualifier cgroup kill interface identity mismatch')
        if os.write(descriptor, b'1\n') != 2:
            raise ValueError('qualifier cgroup kill short write')
    finally:
        os.close(descriptor)


def _kill_pid(record):
    try:
        if _identity(record['pid'])['start'] != record['start']:
            raise ValueError('qualifier PID reused')
        descriptor = os.pidfd_open(record['pid'])
    except ProcessLookupError:
        return
    except FileNotFoundError:
        return
    try:
        if _identity(record['pid'])['start'] == record['start']:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except (ProcessLookupError, FileNotFoundError):
        pass
    finally:
        os.close(descriptor)


def _inventory(scope, monitor, worker):
    records, monitors = [], []
    for pid in _scope_pids(scope):
        try:
            record = _identity(pid)
            image = _devino(Path('/proc') / str(pid) / 'exe')
        except FileNotFoundError:
            continue
        record['image'] = image
        if image == worker:
            raise ValueError('worker exists before complete barrier release')
        if image == monitor:
            children = _read(Path('/proc') / str(pid) / 'task' / str(pid) / 'children', 4096).split()
            if len(children) > 32 or children:
                raise ValueError('monitor forked during held descriptor barrier')
            monitors.append(record)
        records.append(record)
    if len(monitors) != 1:
        return None
    return records


def _gate(directory):
    """Qualification-only gate, after kernel admission, never a production mode."""
    from bounded_runtime import process_limits, load_worker_monitor_binding
    from build_contract import load_profile
    directory = Path(directory).resolve(strict=True)
    if not directory.is_relative_to(BUILD_ROOT.resolve()) or directory.parent.name != 'surrogate-gates':
        raise ValueError('fixed qualification gate location required')
    config = _json(directory / 'config.json')
    if set(config) != {'work', 'monitor', 'harness', 'worker', 'mode', 'attempt', 'hashes', 'reportIdentity'} or config['mode'] not in ('release', 'hold', 'deny-trace', 'bind-failure', 'chdir-failure'):
        raise ValueError('closed surrogate configuration')
    binding = load_worker_monitor_binding()
    if config['monitor'] != binding['binaryPath']:
        raise ValueError('surrogate monitor differs from accepted closure')
    for name in ('monitor', 'harness', 'worker'):
        # Hash only bounded regular public binaries, never a target-controlled tree.
        fd = os.open(config[name], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o6000 or not 0 < info.st_size <= 16777216:
                raise ValueError('surrogate binary bounds/mode')
            data = bytearray()
            while len(data) <= info.st_size:
                block = os.read(fd, min(65536, info.st_size + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) != info.st_size or hashlib.sha256(data).hexdigest() != config['hashes'][name]:
                raise ValueError('surrogate binary changed')
        finally:
            os.close(fd)
    bounds = load_profile()['bounds']
    _write(directory / 'gate.json', {k:v for k,v in _identity(os.getpid()).items() if k != 'parent'})
    deadline = time.monotonic() + bounds['scopeAdmissionSeconds']
    while not (directory / 'admit').exists():
        if time.monotonic() >= deadline:
            raise ValueError('qualifier admission timeout')
        time.sleep(bounds['scopeAdmissionPollSeconds'])
    if _read(directory / 'admit', 2) != b'1\n':
        raise ValueError('invalid qualifier admission')
    process_limits()
    # Open only after admission. The host retains its own private file descriptor.
    report = os.open(directory / 'proof', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    info = os.fstat(report)
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
            info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size != 0 or
            [info.st_dev, info.st_ino] != config['reportIdentity']):
        raise ValueError('qualifier protected report metadata')
    # Temporaries avoid overwriting another just-opened descriptor during dup2.
    control = os.open(directory / 'control', os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    ack = os.open(directory / 'ack', os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    saved = [os.dup(fd) for fd in (control, report, ack)]
    for source, destination in zip(saved, (3, 4, 5)):
        os.dup2(source, destination, inheritable=True)
    for fd in range(6, 64):
        try:
            os.close(fd)
        except OSError as error:
            if error.errno != 9:
                raise
    with os.scandir('/proc/self/fd') as entries:
        count = 0
        for entry in entries:
            count += 1
            if count > 64 or not entry.name.isdecimal() or int(entry.name) >= 64:
                raise ValueError('surrogate inherited FD overflow')
    import resource
    if resource.getrlimit(resource.RLIMIT_NOFILE) != (64, 64):
        raise ValueError('qualifier fixed descriptor limit')
    outer = _devino('/proc/self/ns/pid')
    fixture = config['mode'] not in ('bind-failure', 'chdir-failure')
    reaper = _devino(config['harness'] if fixture else '/usr/bin/bwrap')
    monitor_argv = ['/_worker_exec_monitor', '--attempt', config['attempt'], '--phase', 'runtime',
        '--report-fd', '4', '--report-device', str(info.st_dev), '--report-inode', str(info.st_ino),
        '--reaper-device', str(reaper[0]), '--reaper-inode', str(reaper[1]),
        '--outer-pidns-device', str(outer[0]), '--outer-pidns-inode', str(outer[1]),
        '--', config['worker'], 'descendant-channel']
    _write(directory / 'outer.json', {'pidns': outer, 'report': [info.st_dev, info.st_ino]})
    argv = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--die-with-parent', '--new-session',
            '--disable-userns', '--cap-drop', 'ALL', '--clearenv']
    if fixture:
        argv += ['--as-pid-1']
    for system in ('/usr', '/lib', '/lib64'):
        if Path(system).exists():
            argv += ['--ro-bind', system, system]
    argv += ['--proc', '/proc', '--dev', '/dev', '--remount-ro', '/dev', '--size',
             str(bounds['temporaryFilesystemBytes']), '--tmpfs', '/tmp',
             '--bind', config['work'], config['work'], '--chdir', config['work'],
             '--ro-bind', config['monitor'], '/_worker_exec_monitor',
             '--ro-bind', config['harness'], '/_worker_exec_barrier_harness']
    for key, value in {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'TMPDIR':'/tmp'}.items():
        argv += ['--setenv', key, value]
    if fixture:
        argv += ['--', '/_worker_exec_barrier_harness', '--mode', config['mode'], '--', *monitor_argv]
    else:
        # Fixed post-scope-admission setup faults on the ordinary bwrap route.
        # No arbitrary mount/argv injection and no candidate-selected fixture.
        if config['mode'] == 'bind-failure':
            argv += ['--ro-bind', str(directory / 'absent-never-created'), '/_absent']
        else:
            argv += ['--chdir', '/_absent-never-created']
        for fd in (3, 5): os.close(fd)
        argv += ['--', *monitor_argv]
    os.execve('/usr/bin/bwrap', argv, {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C'})


def surrogate(work, output, monitor, harness, worker, mode):
    """Bounded authored schedule fixture, distinct from ordinary production route."""
    from bounded_runtime import process_limits
    from build_contract import load_profile
    from bounded_runtime import _parse_worker_proof
    bounds = load_profile()['bounds']
    directory = output / 'surrogate-gates' / (mode + '-' + uuid.uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    attempt = uuid.uuid4().hex
    paths = {'monitor': str(monitor), 'harness': str(harness), 'worker': str(worker)}
    hashes = {k: hashlib.sha256(_read(Path(v), 16777216)).hexdigest() for k,v in paths.items()}
    report = os.open(directory / 'proof', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    report_id = list((lambda s: (s.st_dev, s.st_ino))(os.fstat(report)))
    _write(directory / 'config.json', {'work': str(work), **paths, 'mode': mode,
             'attempt': attempt, 'hashes': hashes, 'reportIdentity':report_id})
    os.mkfifo(directory / 'control', 0o600); os.mkfifo(directory / 'ack', 0o600)
    control = os.open(directory / 'control', os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
    ack = os.open(directory / 'ack', os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
    unit = 'decomp-exec-surrogate-' + attempt + '.scope'
    argv = ['/usr/bin/systemd-run', '--user', '--scope', '--quiet', '--collect', '--no-ask-password',
            '--unit=' + unit, '--property=TasksMax=32', '--property=MemoryMax=' + str(bounds['memoryBytes']),
            '--property=MemorySwapMax=0', '/usr/bin/python3', '-B', str(Path(__file__).resolve()),
            '--internal-barrier-gate', str(directory)]
    environment = {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'HOME':str(output),
                   'TMPDIR':str(output), 'DBUS_SESSION_BUS_ADDRESS':f'unix:path=/run/user/{os.getuid()}/bus'}
    process = None; scope = None; root = None
    selector = selectors.DefaultSelector()
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    samples = []; actions = []; admitted = False; capture = False; cleanup = False
    complete = False; failure = None; launcher_exit = None
    cleanup_failure = None; cleanup_wait_end = None; cleanup_verification_end = None
    began = time.monotonic(); deadline = began + bounds['runtimeSeconds']
    try:
        process = subprocess.Popen(argv, cwd=work, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=process_limits)
        root = _identity(process.pid)
        for name in streams:
            pipe = getattr(process, name); os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        acknowledgments = bytearray(); last_ack_time = None
        for iteration in range(500):
            now = time.monotonic()
            if now >= deadline:
                raise ValueError('surrogate wall deadline')
            if not admitted and (directory / 'gate.json').exists():
                record = _json(directory / 'gate.json', 4096)
                scope = _verify_scope(record, unit, bounds)
                _write(directory / 'verified-scope.json', scope)
                (directory / 'admit').write_bytes(b'1\n')
                admitted = True
            for key, _ in selector.select(min(.01, deadline-now)):
                block = os.read(key.fileobj.fileno(), 8192)
                if not block:
                    selector.unregister(key.fileobj)
                elif len(streams[key.data]) + len(block) > bounds['outputBytesPerStream']:
                    raise ValueError('surrogate stream cap')
                else:
                    streams[key.data].extend(block)
            acknowledgment = _ack_bytes(ack)
            if acknowledgment:
                acknowledgments.extend(acknowledgment)
                if len(acknowledgments) > 2 or bytes(acknowledgments) not in (b'H', b'HA'):
                    raise ValueError('surrogate acknowledgment protocol')
                last_ack_time = now
            if scope is not None and acknowledgments and actions != ['A','B']:
                # Inspect ONLY this pinned scope, never enumerate host /proc.
                sample = _inventory(scope, _devino(monitor), _devino(worker))
                if sample is not None and len(samples) < 200:
                    samples.append({'ack': acknowledgments.decode(), 'processes': sample,
                                    'elapsed': now-began})
                # Delay each closure stage100ms with observed no-worker inventory.
                if (mode in ('release','deny-trace') and sample is not None and last_ack_time is not None and
                        now-last_ack_time >= .1):
                    if bytes(acknowledgments) == b'H' and not actions:
                        os.write(control, b'A'); actions.append('A')
                    elif bytes(acknowledgments) == b'HA' and actions == ['A']:
                        os.write(control, b'B'); actions.append('B')
            if process.poll() is not None and not selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    raise TimeoutError('surrogate phase wait budget exhausted')
                launcher_exit = process.wait(timeout=remaining)
                if time.monotonic()>=deadline:
                    raise TimeoutError('surrogate phase wait returned after deadline')
                capture = True
                break
        else:
            raise ValueError('surrogate supervisor iteration cap')
        if not capture or not admitted:
            raise ValueError('incomplete surrogate transport/admission')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ':' + str(error)
        proof = {'status':'unknown', 'workerExecVerified':False, 'workerTerminationVerified':False}
    finally:
        # Separate absolute5s wait and subsequent5s verification stages. A late
        # successful call never creates another window or upgrades cleanup.
        try:
            cleanup_wait_end = time.monotonic()+bounds['cleanupWaitSeconds']
            while time.monotonic()<cleanup_wait_end:
                pids = _scope_pids(scope) if scope is not None else []
                if time.monotonic()>=cleanup_wait_end:
                    raise TimeoutError('qualifier cleanup wait inventory exceeded deadline')
                if pids:
                    _kill_scope(scope)  # List contents never become task/signal authority.
                if process is not None and process.poll() is None and root is not None:
                    _kill_pid(root)
                if time.monotonic()>=cleanup_wait_end:
                    raise TimeoutError('qualifier cleanup wait actions exceeded deadline')
                if not pids and (process is None or process.poll() is not None):
                    break
                remaining=cleanup_wait_end-time.monotonic()
                if remaining<=0:
                    raise TimeoutError('qualifier cleanup wait stage exhausted')
                time.sleep(min(.02,remaining))
            remaining=cleanup_wait_end-time.monotonic()
            if remaining<=0:
                raise TimeoutError('qualifier cleanup wait stage exhausted')
            if process is not None:
                process.wait(timeout=remaining)
            wait_observed=time.monotonic()
            if wait_observed>=cleanup_wait_end:
                raise TimeoutError('qualifier cleanup wait returned after deadline')
            # No unused wait budget is transferred to verification; each ceiling
            # remains5s and this end is fixed once after a timely wait only.
            cleanup_verification_end=min(wait_observed+bounds['cleanupVerificationSeconds'],
                                         cleanup_wait_end+bounds['cleanupVerificationSeconds'])
            while time.monotonic()<cleanup_verification_end:
                pids = _scope_pids(scope) if scope is not None else []
                if time.monotonic()>=cleanup_verification_end:
                    raise TimeoutError('qualifier absence observation exceeded deadline')
                if scope is not None and not pids:
                    cleanup=True
                    break
                remaining=cleanup_verification_end-time.monotonic()
                if remaining<=0:
                    break
                time.sleep(min(.02,remaining))
            if not cleanup or time.monotonic()>=cleanup_verification_end:
                raise TimeoutError('qualifier owned absence unverified within deadline')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            cleanup=False
            cleanup_failure='cleanup:'+type(error).__name__+':'+str(error)
            failure=failure or cleanup_failure
        finally:
            closes=[selector.close,lambda:os.close(control),lambda:os.close(ack)]
            if process is not None:
                closes += [process.stdout.close,process.stderr.close]
            for close in closes:
                try:
                    close()
                except (OSError, ValueError) as error:
                    cleanup=False
                    cleanup_failure=cleanup_failure or ('cleanup-close:'+type(error).__name__+':'+str(error))
                    failure=failure or cleanup_failure
    # Parse only after transport completion AND bounded owned-process cleanup.
    # The still-open host descriptor is authenticated again; worker text is never
    # substituted for it. Keep the partial fact if cleanup failed, but never pass.
    try:
        os.lseek(report, 0, os.SEEK_SET)
        raw = os.read(report, 1025)
        after = os.fstat(report)
        if ([after.st_dev, after.st_ino] != report_id or after.st_size != len(raw) or len(raw)>1024 or
                not stat.S_ISREG(after.st_mode) or stat.S_IMODE(after.st_mode)!=0o600 or after.st_nlink!=1):
            raise ValueError('surrogate report identity/byte bound')
        outer = _json(directory / 'outer.json', 4096)
        target = _devino(worker); reaper = _devino('/usr/bin/bwrap' if mode in ('bind-failure','chdir-failure') else harness)
        expected = {'attempt':attempt, 'phase':'runtime', 'reportDevice':report_id[0], 'reportInode':report_id[1],
                    'targetDevice':target[0], 'targetInode':target[1], 'reaperDevice':reaper[0],
                    'reaperInode':reaper[1], 'outerPidNsDevice':outer['pidns'][0], 'outerPidNsInode':outer['pidns'][1]}
        proof = _parse_worker_proof(raw, expected, deadline=cleanup_verification_end if cleanup else None)
        released = actions==['A','B'] and {x['ack'] for x in samples}=={'H','HA'}
        if mode == 'release':
            complete = (proof['status']=='verified' and proof['exitCode']==0 and launcher_exit==0 and released and
                        bytes(streams['stdout'])==b'DESCENDANT-CHANNEL-DENIED\n' and bytes(streams['stderr'])==b'')
        elif mode == 'deny-trace':
            complete = (not proof['workerExecVerified'] and launcher_exit!=0 and released and
                        proof['reason']=='monitor-error:trace')
        elif mode == 'hold':
            complete = (not proof['workerExecVerified'] and launcher_exit!=0 and bool(samples) and
                        not actions and proof['reason']=='monitor-error:barrier')
        else:
            complete = (not proof['workerExecVerified'] and launcher_exit!=0 and admitted and
                        not actions and proof['reason']=='missing-proof')
        if not complete:
            raise ValueError('surrogate expected kernel/barrier observation absent')
    except (OSError, ValueError) as error:
        complete = False
        failure = failure or ('proof:'+type(error).__name__+':'+str(error))
        proof = {'status':'unknown', 'workerExecVerified':False, 'workerTerminationVerified':False}
    finally:
        for descriptor in ([report,scope['directoryFd']] if scope is not None else [report]):
            try:
                os.close(descriptor)
            except (OSError, ValueError) as error:
                cleanup=False
                cleanup_failure=cleanup_failure or ('cleanup-close:'+type(error).__name__+':'+str(error))
                failure=failure or cleanup_failure
    # Include final proof/identity observations and resource closes in the same
    # fixed verification end. Late teardown cannot grant a new cleanup interval.
    if cleanup:
        try:
            if cleanup_verification_end is None or time.monotonic()>=cleanup_verification_end:
                raise TimeoutError('final verification exceeded deadline')
        except (OSError, ValueError) as error:
            cleanup=False
            cleanup_failure=cleanup_failure or ('cleanup:final clock '+type(error).__name__+':'+str(error))
            failure=failure or cleanup_failure
    value = {'qualificationOnly':True, 'candidateAcceptanceAuthority':False,
             'recipe':'delayed-PID1-surrogate-'+mode, 'passed':complete and cleanup and failure is None,
             'failure':failure, 'cleanupFailure':cleanup_failure,
             'cleanupDeadlines':{'wait':cleanup_wait_end,'verification':cleanup_verification_end},
             'captureComplete':capture, 'cleanupVerified':cleanup,
             'launcherExitCode':launcher_exit, 'proof':proof, 'scope':scope,
             'samples':samples, 'actions':actions,
             **{k+'Hex':bytes(v).hex() for k,v in streams.items()}}
    _write(output / ('surrogate-'+mode+'.json'), value)
    return value



def _initial_exec(result):
    """Authenticated partial exec only, with no process/API acceptance authority."""
    from bounded_runtime import _valid_worker_bindings
    from bounded_runtime import _parse_worker_proof
    if type(result) is not dict:
        return None
    raw=result.get('workerProofRaw')
    if type(raw) is not bytes or len(raw)>1024:
        return None  # Refuse before even immutable-binding hash work.
    if result.get('provisioningOnly') is not False or not _valid_worker_bindings(result):
        return None
    required = ('launcherCreated','launcherPidIdentityVerified','scopeVerified','scopeAdmitted',
                'cleanupVerified','rootReaped','finalAbsenceVerified')
    if any(result.get(k) is not True for k in required):
        return None
    scope, proof, raw = result.get('kernelScope'), result.get('workerProof'), result.get('workerProofRaw')
    cap=result['bounds'].get('outputBytesPerStream')
    if (result['bounds'].get('phase')!='runtime' or type(cap) is not int or not 0<cap<=65536 or
            result.get('workerExecVerified') is not True or type(result.get('workerTerminationVerified')) is not bool):
        return None
    if (type(scope) is not dict or scope.get('finalAbsenceVerified') is not True or
            type(proof) is not dict or type(proof.get('protocolVersion')) is not int or proof['protocolVersion']!=1 or
            proof.get('fileIdentityVerified') is not True or proof.get('pinsUnchanged') is not True or
            type(raw) is not bytes or len(raw)>1024 or
            type(result.get('stdout')) is not bytes or type(result.get('stderr')) is not bytes or
            len(result['stdout'])>cap or len(result['stderr'])>cap):
        return None
    actual_term=result.get('workerTermination')
    if actual_term is not None and (type(actual_term) is not dict or set(actual_term)!={'kind','value','rawWaitStatus'} or
            type(actual_term['kind']) is not str or type(actual_term['value']) is not int or type(actual_term['rawWaitStatus']) is not int):
        return None
    parsed = _parse_worker_proof(raw,result['workerProofBindings']['expected'])
    if (parsed['workerExecVerified'] is not True or proof.get('proofSha256')!=parsed['proofSha256'] or
            proof.get('status')!=parsed['status'] or proof.get('reason')!=parsed['reason'] or
            any(result.get(k)!=parsed[k] for k in ('workerExecVerified','workerTerminationVerified','workerTermination'))):
        return None
    return parsed



def channel_control_passed(name,result):
    """Completed public attack fixture with exact denial bytes and unmutated proof."""
    from bounded_runtime import worker_execution_complete
    expected={'protected-channel-attacks':b'CHANNEL-DENIED\n',
              'descendant-channel-attacks':b'DESCENDANT-CHANNEL-DENIED\n'}
    if name not in expected or not worker_execution_complete(result):
        return False
    parsed=_initial_exec(result)
    return (parsed is not None and parsed['status']=='verified' and parsed['exitCode']==0 and
            result['stdout']==expected[name] and result['stderr']==b'')

def postexec_control_passed(name,result):
    """Finite authored-control expectations, never generic 'unknown means pass'.

    Reach bytes are public fixture diagnostics, not exec authority. The protected
    raw report and immutable controller bindings independently prove initial exec.
    Every named fault needs its own actual effect/termination/output/deadline and
    complete owned cleanup. Missing/nonexecutable targets use a separate refusal.
    """
    from bounded_runtime import worker_execution_complete
    parsed = _initial_exec(result)
    if parsed is None or name not in ('kill-monitor','stop-monitor','timeout','flood','descendant'):
        return False
    stdout, stderr = result['stdout'],result['stderr']
    if stderr!=b'':
        return False
    if name=='descendant':
        if stdout!=b'DESCENDANT-CHANNEL-DENIED\nFAULT:descendant\n' or parsed['workerTermination']!={'kind':'exit','value':0,'rawWaitStatus':0}:
            return False
        # PID1 may tear the descendant down immediately when monitor exits. That
        # is a real completed0+cleanup, not a pretend failed candidate process.
        if worker_execution_complete(result):
            return True
    if (result.get('exitCode') is not None or result.get('infrastructureFailure') is not True or
            type(result.get('launcherExitCode')) is not int):
        return False
    if name=='kill-monitor':
        return (stdout==b'FAULT:kill-monitor\n' and not parsed['workerTerminationVerified'] and
                parsed['reason']=='missing-terminal' and result['launcherExitCode']!=0 and
                result.get('captureComplete') is True and result.get('waitComplete') is True and
                result.get('timedOut') is False and result.get('outputExceeded') is False)
    if result.get('captureComplete') is not False or result.get('waitComplete') is not False:
        return False
    termination = parsed['workerTermination']
    partial = (termination is None and parsed['reason'] in ('missing-terminal','invalid-proof-record'))
    if name=='flood':
        cap=result['bounds'].get('outputBytesPerStream')
        prefix=b'FAULT:flood\n'
        term_ok=partial or termination in ({'kind':'signal','value':9,'rawWaitStatus':9},
            {'kind':'signal','value':13,'rawWaitStatus':13},{'kind':'exit','value':137,'rawWaitStatus':137<<8})
        return (type(cap) is int and 0<len(prefix)<cap<=65536 and len(stdout)==cap and
                stdout.startswith(prefix) and stdout[len(prefix):].strip(b'x')==b'' and term_ok and
                result.get('outputExceeded') is True and result.get('timedOut') is False)
    if result.get('timedOut') is not True or result.get('outputExceeded') is not False:
        return False
    if name=='stop-monitor':
        return stdout==b'FAULT:stop-monitor\n' and termination is None and parsed['reason']=='missing-terminal'
    if name=='timeout':
        return stdout==b'FAULT:timeout\n' and (partial or termination=={'kind':'signal','value':9,'rawWaitStatus':9})
    return name=='descendant'  # Verified native0+descendant denial/reach bytes above, capture deadline+cleanup.

def qualify(monitor, output):
    from bounded_runtime import (bounded_run, contained_command, public_result,
                                 worker_execution_complete, load_worker_monitor_binding)
    from build_contract import load_profile
    binding = load_worker_monitor_binding()  # Complete byte closure, not native qualification.
    monitor = Path(monitor).resolve(strict=True)
    if str(monitor) != binding['binaryPath']:
        raise ValueError('monitor must match accepted environment closure')
    output = Path(output)
    if not output.is_absolute(): output = REPOSITORY / output
    if output != output.resolve() or not output.is_relative_to(BUILD_ROOT.resolve()) or output.exists():
        raise ValueError('fresh canonical trusted v3 output required')
    output.mkdir(parents=True, mode=0o700)
    work = output / 'public-work'; work.mkdir(mode=0o700)
    environment = {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'TMPDIR':str(work)}
    load_profile(); results = []
    def run(name, argv, phase, expected=None, unknown=False, files=(), expected_stdout=b'', require_admitted=True, postexec=False):
        try:
            recipe = contained_command(argv, work, read_only_files=files, environment=environment)
            raw = bounded_run(recipe, work, environment, managed_scope=True, phase=phase)
        except (ValueError, OSError) as error:
            raw = getattr(error, 'bounded_result', None)
            if raw is None:
                raw = {'infrastructureFailure':True, 'reason':type(error).__name__}
        observed = worker_execution_complete(raw)
        if name in ('protected-channel-attacks','descendant-channel-attacks'):
            passed = channel_control_passed(name,raw)
        elif postexec:
            passed = postexec_control_passed(name,raw)
        elif unknown:
            controller = (raw.get('scopeAdmitted') is True and raw.get('cleanupVerified') is True and
                          raw.get('kernelScope',{}).get('finalAbsenceVerified') is True)
            passed = not observed and (controller or not require_admitted)
        else:
            passed = (observed and raw['exitCode']==expected and raw['stdout']==expected_stdout and raw['stderr']==b'')
        public = public_result(raw) if type(raw.get('stdout')) is bytes and type(raw.get('stderr')) is bytes else {
            (k+'Hex' if type(v) is bytes else k):(v.hex() if type(v) is bytes else v) for k,v in raw.items()}
        result = {'name':name, 'passed':passed, 'expectedInfrastructureUnknown':unknown,
                  'execution':public}
        _write(output / (name+'.json'), result); results.append(result)
        return raw
    source = work / 'public-worker.c'; source.write_text(WORKER_SOURCE)
    worker = work / 'public-worker'
    built = run('worker-build', ['/usr/bin/gcc','-std=c11','-O2',str(source),'-ldl','-o',str(worker)], 'compiler', 0)
    if not worker_execution_complete(built) or built['exitCode']!=0:
        raise ValueError('actual monitored public worker build must pass')
    harness = work / 'barrier-harness'
    built = run('harness-build', ['/usr/bin/gcc','-D_GNU_SOURCE','-std=c11','-O2','-Wall','-Wextra','-Werror',
                str(SOURCE/'tests/worker_exec_barrier_harness.c'),'-o',str(harness)], 'compiler', 0,
                files=(SOURCE/'tests/worker_exec_barrier_harness.c',))
    if not worker_execution_complete(built) or built['exitCode']!=0:
        raise ValueError('actual monitored harness build must pass')
    # Ordinary unmodified production route is mandatory, separate from surrogate.
    for name, action, code in [('normal0','zero',0),('nonzero42','42',42),('normal139','139',139),
                               ('signal11','signal',-11),('stdout-forged-proof','fake',42),
                               ('protected-channel-attacks','attack',0)]:
        run(name,[str(worker),action],'runtime',code,
            expected_stdout=(b'__ACP_BEGIN__\n{"v":1,"t":"exec"}\n__ACP_END__\n' if action=='fake' else b'CHANNEL-DENIED\n' if action=='attack' else b''))
    run('descendant-channel-attacks',[str(worker),'descendant-channel'],'runtime',0,expected_stdout=b'DESCENDANT-CHANNEL-DENIED\n')
    baseline = run('compatible',[str(worker),'zero'],'runtime',0)
    mutation = run('behavior-mutant',[str(worker),'mutant'],'runtime',42,expected_stdout=b'mutant\n')
    mutant_detected = (worker_execution_complete(baseline) and worker_execution_complete(mutation) and
                       (baseline['exitCode'],baseline['stdout'],baseline['stderr']) !=
                       (mutation['exitCode'],mutation['stdout'],mutation['stderr']))
    for phase in ('probe','elf-inspection','caller-build','helper-build','toolchain-inspection'):
        run('handoff-'+phase,[str(worker),'zero'],phase,0)
    for name, text in CONSTRUCTORS.items():
        c = work / (name+'.c'); library = work / (name+'.so'); c.write_text(text)
        built = run(name+'-build',['/usr/bin/gcc','-shared','-fPIC',str(c),'-o',str(library)],'compiler',0)
        if not worker_execution_complete(built) or built['exitCode']!=0:
            raise ValueError('synthetic constructor build must pass')
        run('constructor-'+name,[str(worker),'load',str(library)],'runtime',42 if name=='exit42' else -11)
    for action in ('kill-monitor','stop-monitor','timeout','flood','descendant'):
        run(action,[str(worker),action],'runtime',postexec=True)
    run('missing-target',[str(work/'absent')],'runtime',unknown=True,require_admitted=False)
    nonexec = work / 'nonexecutable'; nonexec.write_bytes(_read(worker,16777216)); nonexec.chmod(0o600)
    run('nonexecutable-target',[str(nonexec),'zero'],'runtime',unknown=True,require_admitted=False)
    surrogate_results = [surrogate(work,output,monitor,harness,worker,mode) for mode in ('release','hold','deny-trace','bind-failure','chdir-failure')]
    if load_worker_monitor_binding() != binding:
        raise ValueError('monitor/environment closure drift during qualification')
    value = {'schemaVersion':1, 'qualificationOnly':True, 'candidateAcceptanceAuthority':False,
             'productionRoute':'ordinary-unmodified-bwrap', 'mutantDetected':mutant_detected,
             'results':[{'name':r['name'],'passed':r['passed']} for r in results],
             'surrogateResults':[{'recipe':r['recipe'],'passed':r['passed']} for r in surrogate_results],
             'passed':all(r['passed'] for r in results+surrogate_results) and mutant_detected,
             'full24ScenarioAcceptance':False, 'internalApiActivity':None,
             'inputBindings':{'monitorBindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest(), 'publicWorkerSha256':hashlib.sha256(_read(worker,16777216)).hexdigest(),
                 'harnessSourceSha256':hashlib.sha256(_read(SOURCE/'tests/worker_exec_barrier_harness.c',262144)).hexdigest(),
                 'qualifierSourceSha256':hashlib.sha256(_read(Path(__file__).resolve(),262144)).hexdigest()},
             'qualificationScope':'one fixed local public primitive control run; not full24 acceptance',
             'hostedRepeat':None, 'independentNativeReview':None}
    # Local control completion cannot assert hosted qualification/full24 acceptance.
    value['qualificationComplete'] = value['passed']
    _write(output/'qualification.json',value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--monitor',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--allow-native-controls',action='store_true')
    parser.add_argument('--internal-barrier-gate',type=Path,help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.internal_barrier_gate is not None:
        _gate(args.internal_barrier_gate)
        return
    if not args.allow_native_controls or args.monitor is None or args.output is None:
        parser.error('explicit monitor/output and --allow-native-controls required; root Phase B permission also required')
    result = qualify(args.monitor,args.output)
    print(json.dumps({'passed':result['passed'],'qualificationComplete':result['qualificationComplete']}))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
