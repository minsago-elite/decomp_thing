#!/usr/bin/env python3
"""Passive CI diagnostics only. Never an admission, retry or cleanup authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time
import uuid

MAX_TABLE = 1024 * 1024
MAX_ROWS = 4096
MAX_FIELD = 4096
MAX_FIELDS = 64
MAX_ROOTS = 8
MAX_RECORDS = 508  # plus one <=4 KiB lifecycle document, within 512/256 KiB
MAX_OUTPUT = 252 * 1024
RESERVED_BYTES = 4096
MAX_DURATION = 6 * 60 * 60
POLL_MS = 250
STOP_SECONDS = 3
DIRECTORY = 'build/ci-host-mount-observation'
PUBLIC = frozenset(('/', '/proc', '/sys', '/dev', '/dev/pts', '/dev/shm',
                    '/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc', '/run',
                    '/sys/fs/cgroup', '/proc/sys/fs/binfmt_misc'))
FSTYPES = frozenset(('ext4', 'ext3', 'ext2', 'tmpfs', 'devtmpfs', 'proc', 'sysfs',
                     'cgroup', 'cgroup2', 'overlay', 'squashfs', 'binfmt_misc',
                     'devpts', 'securityfs', 'debugfs', 'tracefs', 'mqueue',
                     'hugetlbfs', 'fusectl', 'autofs', 'ramfs', 'bpf', 'nsfs'))


class Unavailable(Exception):
    """Only internally selected closed reason codes may leave this module."""


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def unescape(value):
    # mountinfo's four kernel escapes; malformed/unknown escapes are not guessed.
    if not valid_escapes(value):
        bad('PARSE')
    escapes = {'040': ' ', '011': '\t', '012': '\n', '134': '\\'}
    return re.sub(r'\\([0-7]{3})', lambda match: escapes[match[1]], value)


def valid_escapes(value):
    return re.search(r'\\(?!040|011|012|134)', value) is None


def bad(code):
    raise Unavailable(code)


def canonical_path(value):
    return value.startswith('/') and os.path.normpath(value) == value and not value.startswith('//')


def parse(data):
    if len(data) > MAX_TABLE:
        bad('TABLE_BYTES')
    if not data or not data.endswith(b'\n'):
        bad('TABLE_INCOMPLETE')
    if data.count(b'\n') > MAX_ROWS:
        bad('TABLE_ROWS')
    try:
        lines = data.decode('utf-8', 'strict').split('\n')[:-1]
        rows = {}
        for line in lines:
            fields = line.split(' ')
            if len(fields) > MAX_FIELDS or any(not f or len(f.encode()) > MAX_FIELD for f in fields):
                bad('TABLE_FIELDS')
            if any(re.search(r'[\x00-\x1f\x7f]', f) for f in fields):
                bad('PARSE')
            if '-' not in fields:
                bad('PARSE')
            split = fields.index('-')
            if split < 6 or len(fields) != split + 4:
                bad('PARSE')
            if not all(re.fullmatch(r'[0-9]{1,10}', f) for f in fields[:2]):
                bad('PARSE')
            mid, parent = map(int, fields[:2])
            if mid <= 0 or mid in rows or not re.fullmatch(r'[0-9]{1,10}:[0-9]{1,10}', fields[2]):
                bad('PARSE')
            if any(not item for field in (fields[5], fields[split+3]) for item in field.split(',')):
                bad('PARSE')
            root, target = map(unescape, fields[3:5])
            # Kernel root labels may be namespace handles or deleted/noncanonical paths.
            # They are opaque comparison/hash inputs, never target authority.
            if not canonical_path(target):
                bad('PARSE')
            rows[mid] = dict(mountId=mid, parent=parent, device=fields[2], root=root,
                             target=target, options=tuple(sorted(fields[5].split(','))),
                             optional=tuple(sorted(fields[6:split])), fstype=fields[split+1],
                             source=unescape(fields[split+2]),
                             superoptions=tuple(sorted(fields[split+3].split(','))))
        return rows
    except (ValueError, KeyError, UnicodeError):
        bad('PARSE')


def read_table(fd):
    # Poll acknowledges the namespace event counter on this descriptor.
    # Seek/read captures its bounded current table; no new descriptor is substituted.
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= MAX_TABLE:
        chunk = os.read(fd, min(65536, MAX_TABLE + 1 - len(data)))
        if not chunk:
            return parse(bytes(data))
        data.extend(chunk)
    bad('TABLE_BYTES')


def under(target, root):
    return target == root or target.startswith(root.rstrip('/') + '/')


def relation(target, root):
    return ('AT' if target == root else 'UNDER' if under(target, root)
            else 'ANCESTOR' if under(root, target) else 'DISJOINT')


def target_class(target, workspace):
    # Closed path shapes, no substring-based secrecy inference. ALL other paths hash too.
    if under(target, '/run/credentials'):
        return 'credentials'
    if under(target, '/run/user'):
        return 'user-runtime'
    if under(target, '/snap') or under(target, '/var/lib/snapd') or under(target, '/run/snapd'):
        return 'snap'
    if under(target, '/var/lib/docker') or under(target, '/run/docker'):
        return 'docker'
    if under(target, '/proc/sys/fs/binfmt_misc'):
        return 'binfmt'
    if under(target, workspace + '/build'):
        return 'decomp'
    if under(target, workspace):
        return 'workspace'
    return 'system' if target in PUBLIC else 'other'


def safe_row(row, roots, workspace):
    if row is None:
        return None
    target = row['target']
    optional = row['optional']
    propagation = sorted({f.split(':')[0] for f in optional
                          if re.fullmatch(r'(shared|master|propagate_from):[0-9]{1,10}|unbindable', f)})
    return dict(mountId=row['mountId'], parent=row['parent'], device=row['device'],
                rowHash=digest(row), targetHash=digest(target), rootHash=digest(row['root']),
                sourceHash=digest(row['source']), optionsHash=digest(row['options']),
                superoptionsHash=digest(row['superoptions']), optionalHash=digest(optional),
                target=target if target in PUBLIC else None,
                fstype=row['fstype'] if row['fstype'] in FSTYPES else 'OTHER',
                fstypeHash=digest(row['fstype']), propagation=propagation,
                targetClass=target_class(target, workspace),
                relations=[dict(rootHash=digest(r), relation=relation(target, r)) for r in roots])


def anchor():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return dict(monotonicBeforeNs=before, realtimeNs=realtime, monotonicAfterNs=after)


class Recorder:
    """Complete JSON lines only; reserve START/UNAVAILABLE/OVERFLOW/STOP capacity."""
    def __init__(self, stream):
        self.stream, self.count, self.size, self.overflow = stream, 0, 0, False

    def write(self, kind, **values):
        record = dict(kind=kind, **values)
        data = encoded(record)
        marker = kind in ('START', 'STOP', 'UNAVAILABLE', 'OVERFLOW')
        if not marker and (self.count >= MAX_RECORDS - 3 or
                           self.size + len(data) > MAX_OUTPUT - RESERVED_BYTES):
            if not self.overflow:
                self.overflow = True
                self.write('OVERFLOW', incomplete=True, coalescing='UNKNOWN')
            return False
        if self.count >= MAX_RECORDS or self.size + len(data) > MAX_OUTPUT:
            bad('OUTPUT_BOUND')  # Internal invariant; never slice JSON.
        self.stream.write(data)
        self.stream.flush()
        self.count += 1
        self.size += len(data)
        return True


def observe(recorder, roots, workspace, duration, stopped, *, open_fd=os.open,
            close_fd=os.close, read=read_table, poll_factory=select.poll,
            namespace=lambda: os.stat('/proc/self/ns/mnt').st_ino, on_ready=None):
    fd = None
    reason = 'DEADLINE'
    incomplete = True
    coverage_end = None
    start = time.monotonic()
    recorder.write('START', schema=1, diagnosticOnly=True, qualified=False,
                   clocks={'monotonic': 'Python time.monotonic_ns', 'realtime': 'Unix time.time_ns',
                           'jvmJoin': 'CONDITIONAL_OR_UNKNOWN'}, anchor=anchor(),
                   configuredRoots=[digest(r) for r in roots], authorityProjection='INCOMPLETE',
                   startObserved=True, stopObserved=False, actor='UNKNOWN', benignness='UNKNOWN')
    try:
        ns = namespace()
        fd = open_fd('/proc/self/mountinfo', os.O_RDONLY | os.O_CLOEXEC)
        poller = poll_factory()
        poller.register(fd, select.POLLPRI | select.POLLERR)
        before = anchor()
        previous = read(fd)
        if not recorder.write('BASELINE', namespaceInode=ns, rows=len(previous), tableHash=digest(previous),
                              readStart=before, readEnd=anchor()):
            reason = 'OUTPUT_LIMIT'
            return
        if on_ready is not None and not stopped() and time.monotonic() - start < duration:
            on_ready()
        drain_deadline = None
        drain_polls = 0
        while True:
            now = time.monotonic()
            if now - start >= duration:
                break
            draining = stopped()
            if draining:
                if drain_deadline is None:
                    drain_deadline = now + STOP_SECONDS
                # Time and iteration caps also bound a stream of spurious notifications.
                if now >= drain_deadline or drain_polls >= MAX_RECORDS:
                    reason = 'STOP_DRAIN_LIMIT'
                    break
                drain_polls += 1
            remaining = duration - (now - start)
            poll_start = anchor()
            events = poller.poll(0 if draining else max(0, min(POLL_MS, int(remaining * 1000))))
            if draining and not events:
                if time.monotonic() - start >= duration:
                    break
                if time.monotonic() >= drain_deadline:
                    reason = 'STOP_DRAIN_LIMIT'
                    break
                # Conservatively end coverage at the start of the final quiet poll,
                # not at the later STOP write or descriptor close.
                coverage_end = poll_start
                reason, incomplete = 'SIGNAL', False
                break
            # Drain a reported event even if the stop signal arrived during poll.
            masks = [mask for event_fd, mask in events if event_fd == fd]
            mask = 0
            for value in masks:
                mask |= value
            if mask & (select.POLLNVAL | select.POLLHUP):
                bad('POLL_UNAVAILABLE')
            if not mask & (select.POLLPRI | select.POLLERR):
                continue  # Timeout is not an event or proof of an unchanged table.
            before = anchor()
            current = read(fd)
            if not recorder.write('EVENT', namespaceInode=ns, revents=mask,
                                  readStart=before, readEnd=anchor(), tableHash=digest(current),
                                  rows=len(current), coalescing='UNKNOWN', aba='UNKNOWN'):
                reason, incomplete = 'OUTPUT_LIMIT', True
                break
            changed = [mid for mid in sorted(previous.keys() | current.keys())
                       if previous.get(mid) != current.get(mid)]
            if not changed:
                recorder.write('NO_NET_DELTA', coalescing='UNKNOWN', aba='UNKNOWN', benignness='UNKNOWN')
            for mid in changed:
                old, new = previous.get(mid), current.get(mid)
                if not recorder.write('ADDED' if old is None else 'REMOVED' if new is None else 'CHANGED',
                                      before=safe_row(old, roots, workspace),
                                      after=safe_row(new, roots, workspace)):
                    break
            previous = current
            if recorder.overflow:
                reason, incomplete = 'OUTPUT_LIMIT', True
                break
    except Unavailable as exc:
        reason = str(exc)  # exclusively closed internal codes
        recorder.write('UNAVAILABLE', reason=reason, incomplete=True, coalescing='UNKNOWN')
        incomplete = True
    except (OSError, ValueError):
        reason, incomplete = 'IO_UNAVAILABLE', True
        recorder.write('UNAVAILABLE', reason=reason, incomplete=True, coalescing='UNKNOWN')
    finally:
        if reason == 'DEADLINE':
            incomplete = True  # Also covers unexpected exceptions after the baseline.
        if fd is not None:
            try:
                close_fd(fd)
            except OSError:
                reason, incomplete = 'CLOSE_UNAVAILABLE', True
        recorder.write('STOP', reason=reason, anchor=anchor(), stopObserved=True,
                       incomplete=incomplete, intervalEnded=True, coverageEnd=coverage_end, coalescing='UNKNOWN',
                       qualification='NONE', productCleanup='UNKNOWN')


def identity(path):
    info = os.stat(path, follow_symlinks=False)
    return [info.st_dev, info.st_ino]


def bounded_file(path, limit=16384):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            bad('CONTROL_UNAVAILABLE')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            bad('CONTROL_UNAVAILABLE')
        return data
    finally:
        os.close(fd)


def write_json(path, value):
    data = encoded(value)
    if len(data) > 4096:
        bad('CONTROL_BOUND')
    # Same owned directory; no symlink following, no arbitrary temporary locations.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def process_identity(pid):
    base = Path('/proc') / str(pid)
    raw = bounded_file(base / 'stat')
    end = raw.rfind(b')')
    fields = raw[end+2:].split()
    if end < 0 or len(fields) < 20:
        bad('PROCESS_UNAVAILABLE')
    # This kernel-owned link intentionally identifies the process's directory.
    # Path removes a trailing '/.', so no-follow identity() identifies the
    # procfs symlink itself rather than the workspace it names.
    cwd_info = os.stat(base / 'cwd', follow_symlinks=True)
    if not stat.S_ISDIR(cwd_info.st_mode):
        bad('PROCESS_UNAVAILABLE')
    return dict(pid=pid, ticks=int(fields[19]), commandHash=digest(bounded_file(base / 'cmdline')),
                workspaceIdentity=[cwd_info.st_dev, cwd_info.st_ino], uid=os.stat(base).st_uid)


def paths(workspace):
    root = Path(workspace)
    if not root.is_absolute() or root.resolve() != root or not (root / '.git').exists():
        bad('WORKSPACE_UNAVAILABLE')
    build = root / 'build'
    build.mkdir(exist_ok=True)
    if build.is_symlink() or not build.is_dir():
        bad('WORKSPACE_UNAVAILABLE')
    directory = root / DIRECTORY
    if directory.is_symlink():
        bad('CONTROL_UNAVAILABLE')
    return root, directory


def command(root, token, duration, roots, session):
    return [sys.executable, '-B', str(root / 'scripts/ci-observe-host-mount-events.py'),
            'run', '--workspace', str(root), '--session', session, '--token', token, '--duration', str(duration),
            *[item for r in roots for item in ('--root', r)]]


def load_owned(root, directory, session):
    info = directory.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        bad('CONTROL_UNAVAILABLE')
    control_path = directory / 'control.json'
    control = json.loads(bounded_file(control_path))
    if (control['workspaceIdentity'] != identity(root) or control['uid'] != os.getuid()
            or control['directoryIdentity'] != identity(directory) or control['sessionHash'] != digest(session)):
        bad('OWNERSHIP_MISMATCH')
    return control, identity(control_path)


def start(root, directory, duration, roots, session):
    directory.mkdir(mode=0o700)  # Never adopt an earlier observer/directory.
    token = uuid.uuid4().hex
    argv = command(root, token, duration, roots, session)
    control = dict(token=token, sessionHash=digest(session), workspaceIdentity=identity(root), uid=os.getuid(),
                   directoryIdentity=identity(directory),
                   commandHash=digest(b'\0'.join(os.fsencode(x) for x in argv) + b'\0'))
    write_json(directory / 'control.json', control)
    # Detached pipes cannot keep a CI step open or leak raw stderr into job logs.
    subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    deadline = time.monotonic() + STOP_SECONDS
    while time.monotonic() < deadline:
        if (directory / 'ready.json').exists():
            write_json(directory / 'start.json', dict(kind='START_CONTROL', status='READY',
                                                     diagnosticOnly=True, qualified=False))
            return
        time.sleep(.05)
    write_json(directory / 'start.json', dict(kind='START_CONTROL', status='START_UNCONFIRMED',
                                             incomplete=True, qualified=False))


def run(root, directory, token, duration, roots, session):
    control, control_id = load_owned(root, directory, session)
    own = process_identity(os.getpid())
    if (control['token'] != token or own['commandHash'] != control['commandHash']
            or own['workspaceIdentity'] != control['workspaceIdentity'] or own['uid'] != control['uid']):
        bad('OWNERSHIP_MISMATCH')
    stopping = [False]
    def on_signal(_number, _frame):
        stopping[0] = True
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    ownership = dict(**own, controlIdentity=control_id, token=token)
    write_json(directory / 'owned.json', ownership)
    def on_ready():
        write_json(directory / 'ready.json', dict(**ownership, baselineRecorded=True))
    with (directory / 'observations.jsonl').open('xb') as stream:
        observe(Recorder(stream), roots, str(root), duration, lambda: stopping[0], on_ready=on_ready)


def stop_owned(root, directory, session):
    """A pidfd pins the process across validation/signaling; no PID kill fallback."""
    control, control_id = load_owned(root, directory, session)
    owned = json.loads(bounded_file(directory / 'owned.json'))
    if (owned['controlIdentity'] != control_id or owned['token'] != control['token']
            or owned['workspaceIdentity'] != control['workspaceIdentity']
            or owned['commandHash'] != control['commandHash'] or owned['uid'] != control['uid']
            or type(owned['pid']) is not int or owned['pid'] <= 1):
        bad('OWNERSHIP_MISMATCH')
    try:
        handle = os.pidfd_open(owned['pid'], 0)
    except ProcessLookupError:
        return 'ALREADY_EXITED'
    try:
        current = process_identity(owned['pid'])
        if any(current[k] != owned[k] for k in current):
            bad('OWNERSHIP_MISMATCH')
        # Recheck the control file immediately before signaling the pinned process.
        again, again_id = load_owned(root, directory, session)
        if again != control or again_id != control_id:
            bad('OWNERSHIP_MISMATCH')
        signal.pidfd_send_signal(handle, signal.SIGTERM)
        poller = select.poll()
        poller.register(handle, select.POLLIN)
        deadline = time.monotonic() + STOP_SECONDS
        while time.monotonic() < deadline:
            events = poller.poll(min(POLL_MS, max(0, int((deadline-time.monotonic())*1000))))
            for fd, mask in events:
                if fd == handle and mask & select.POLLIN:
                    return 'EXITED_AFTER_SIGNAL'
                if fd == handle and mask & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                    bad('STOP_POLL_UNAVAILABLE')
        return 'SURVIVOR'  # No escalation, group kill, adoption or cleanup claim.
    finally:
        os.close(handle)


def lifecycle_stop(root, directory, session):
    if not directory.exists():
        directory.mkdir(mode=0o700)
    status = 'UNAVAILABLE'
    try:
        status = stop_owned(root, directory, session)
    except (OSError, ValueError, KeyError, TypeError, Unavailable, AttributeError):
        pass
    start_status = 'ABSENT_START'
    try:
        value = json.loads(bounded_file(directory / 'start.json'))['status']
        if value in ('READY', 'START_UNCONFIRMED'):
            start_status = value
    except (OSError, ValueError, KeyError, TypeError, Unavailable):
        pass
    stop_observed = False
    observation_incomplete = True
    try:
        data = bounded_file(directory / 'observations.jsonl', MAX_OUTPUT)
        records = [json.loads(line) for line in data.splitlines()]
        stop_observed = bool(records and records[-1]['kind'] == 'STOP')
        observation_incomplete = (not stop_observed or records[-1].get('incomplete') is not False
                                  or records[-1].get('reason') != 'SIGNAL')
    except (OSError, ValueError, KeyError, TypeError, Unavailable):
        pass
    write_json(directory / 'lifecycle.json', dict(kind='LIFECYCLE', start=start_status, stop=status,
               stopObserved=stop_observed, incomplete=(start_status != 'READY' or not stop_observed
               or observation_incomplete or status != 'EXITED_AFTER_SIGNAL'),
               diagnosticOnly=True, qualified=False, productCleanup='UNKNOWN'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'run', 'stop'))
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--root', action='append', default=[])
    parser.add_argument('--duration', type=int, default=MAX_DURATION)
    parser.add_argument('--token', default='')
    args = parser.parse_args()
    try:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', args.session) or not 1 <= args.duration <= MAX_DURATION or len(args.root) > MAX_ROOTS or any(
                len(r.encode()) > MAX_FIELD or not canonical_path(r) for r in args.root):
            bad('CONFIG_UNAVAILABLE')
        root, directory = paths(args.workspace)
        if args.action == 'start':
            start(root, directory, args.duration, args.root, args.session)
        elif args.action == 'run':
            run(root, directory, args.token, args.duration, args.root, args.session)
        else:
            lifecycle_stop(root, directory, args.session)
    except (OSError, ValueError, KeyError, TypeError, Unavailable, AttributeError):
        # Fixed text only. A later always-stop records missing start/stop explicitly.
        print('passive mount observation UNAVAILABLE; qualification NONE', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
