#!/usr/bin/python3
"""Fixed-slot administrative ext4 reset. No oracle or operation-release authority.

The installed root-owned profile and manifest are the trust anchor. This module
never adopts caller paths, rebinds/detaches a loop, or walks old filesystem data.
The installer may call register_initial; the public CLI has no bootstrap action.
"""
import contextlib
import copy
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path('/var/lib/decomp-oracle-ext4-reset-ci')
PRIVATE = ROOT / 'private'
PUBLIC = ROOT / 'public'
IMAGE = PRIVATE / 'image'
QUARANTINE = PRIVATE / 'quarantine'
UNIT = 'decomp-oracle-ext4-reset-ci.service'
UNIT_FILE = Path('/etc/systemd/system') / UNIT
RETENTION_UNIT = 'decomp-oracle-ext4-reset-retain.target'
RETENTION_FILE = Path('/etc/systemd/system') / RETENTION_UNIT
INSTALLED = PRIVATE / 'oracle-ext4-reset.py'
PROFILE_FILE = PRIVATE / 'profile.json'
CONFIG_FILE = PRIVATE / 'mke2fs.conf'
IMAGE_BYTES = 67108864
INODES = 4096
MAX_RECORD = 16384
MAX_MANIFEST = 131072
MAX_MOUNTINFO = 4194304
MAX_OUTPUT = 8192
MAX_TRACE = 262144
ZERO = '0' * 64
FLAGS = ['noatime', 'nodev', 'noexec', 'nosuid', 'rw']
LOOP_RE = re.compile(r'/dev/loop([0-9]{1,6})\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
PHASES = ('REGISTERED', 'INTENT', 'FENCED', 'UNMOUNTED', 'FORMAT_STARTED',
          'FORMATTED', 'MOUNT_INTENT', 'READY_PRIVATE', 'EXPOSURE_INTENT', 'PUBLISHED')
BARRIERS = ('INTENT_FSYNC', 'GATE_CLOSED', 'MOUNT_MOVED', 'UNMOUNTED_BEFORE_COMMIT',
            'FORMAT_STARTED', 'FORMAT_FLUSHED', 'READY_RENAMED_BEFORE_FSYNC',
            'CANDIDATE_MOUNTED', 'EXPOSURE_INTENT', 'GATE_OPENED', 'FORMAT_RUNNING')
TOOL_ROLES = frozenset(('mke2fs', 'mount', 'umount', 'systemctl', 'busctl'))
STATE_KEYS = frozenset(('schemaVersion', 'profileSha256', 'manifestSha256', 'slotId',
    'bootId', 'sequence', 'previousHash', 'phase', 'disposition', 'owner', 'anchors',
    'image', 'loop', 'parentMount', 'generation', 'previousGeneration', 'targetGeneration',
    'intentId', 'targetUuid', 'old', 'candidate', 'submission', 'custodian', 'formatter', 'selfHash'))
BASE_PRIVATE = frozenset(('image', 'lock', 'state.json', 'state.next', 'manifest.json',
    'profile.json', 'mke2fs.conf', 'oracle-ext4-reset.py', 'quarantine', 'diagnostic.json', 'diagnostic.next'))
QUAL_PRIVATE = frozenset(('fixture.json', 'fixture.lock', 'case-receipts', 'fault.json',
                         'barrier.json', 'formatter.trace', 'ci-oracle-ext4-reset.py',
                         'oracle-ext4-reset-install.py','oracle-ext4-reset-fixture-mutations.py',
                         'fixture-companion-image',
                         'fixture-old-mount','fixture-alias','fixture-old-image','fixture-old-state','fixture-old-gate',
                         'fixture.json.next','fault.json.next','barrier.json.next'))


class ResetError(RuntimeError):
    pass


def fail(message):
    raise ResetError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('duplicate JSON key')
        result[key] = value
    return result


def parse_canonical(data, maximum=MAX_RECORD):
    if not isinstance(data, bytes) or not 0 < len(data) <= maximum:
        fail('canonical record byte limit')
    try:
        value = json.loads(data, object_pairs_hook=_pairs,
                           parse_constant=lambda _: fail('nonfinite JSON'))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ResetError('invalid JSON') from error
    def bounds(node, depth=0):
        if depth > 8:
            fail('JSON depth limit')
        if isinstance(node, dict):
            if len(node) > 64:
                fail('JSON object limit')
            for item in node.values():
                bounds(item, depth + 1)
        elif isinstance(node, list):
            if len(node) > 64:
                fail('JSON array limit')
            for item in node:
                bounds(item, depth + 1)
        elif isinstance(node, str) and len(node) > 4096:
            fail('JSON string limit')
    bounds(value)
    if canonical(value) != data:
        fail('noncanonical JSON')
    return value


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(label + ' fields differ')


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        fail(label + ' is outside bounds')


def digest(value, label='digest'):
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail(label + ' is invalid')


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    try:
        if str(uuid.UUID(value)) != value:
            fail('noncanonical boot ID')
    except ValueError as error:
        raise ResetError('invalid boot ID') from error
    return value


def profile_document(qualification=False):
    return {'schemaVersion': 1, 'profile': 'oracle-ext4-quarantine-reset-v1',
        'kind': 'qualification' if qualification else 'production', 'slotId': 'slot0',
        'imageBytes': IMAGE_BYTES, 'inodes': INODES, 'blockBytes': 4096,
        'mountFlags': FLAGS, 'systemdMajor': 255, 'machine': 'x86_64',
        'formatterPackages': ['1.47.0-2.4~exp1ubuntu4', '1.47.0-2.4~exp1ubuntu4.1'],
        'metadataBytes': 1048576, 'maximumEntries': 32, 'maximumGenerationDirectories': 2,
        'recordBytes': MAX_RECORD, 'actionSeconds': 45, 'unit': UNIT,'retentionUnit':RETENTION_UNIT}


def fd_identity(fd):
    st = os.fstat(fd)
    info = Path(f'/proc/self/fdinfo/{fd}').read_text()
    ids = re.findall(r'^mnt_id:\s*([0-9]+)$', info, re.M)
    if len(ids) != 1:
        fail('descriptor mount identity absent')
    kind = 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'block' if stat.S_ISBLK(st.st_mode) else 'other'
    result = {'device': st.st_dev, 'inode': st.st_ino, 'mountId': int(ids[0]),
              'uid': st.st_uid, 'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode), 'kind': kind}
    if kind != 'directory':
        result.update({'links': st.st_nlink, 'size': st.st_size, 'rdev': st.st_rdev})
    return result


def file_identity(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        return fd_identity(fd)
    finally:
        os.close(fd)


identity = file_identity


def same_object(actual, expected, *, metadata=True):
    keys = ('device', 'inode', 'mountId', 'kind')
    if metadata:
        keys += ('uid', 'gid', 'mode')
    return all(actual.get(k) == expected.get(k) for k in keys)


def _read_fd(fd, maximum):
    result = bytearray()
    offset = 0
    while len(result) <= maximum:
        part = os.pread(fd, min(65536, maximum + 1 - len(result)), offset)
        if not part:
            return bytes(result)
        result.extend(part)
        offset += len(part)
    fail('file exceeds bound')


def _read_root_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = fd_identity(fd)
        if before['kind'] != 'file' or before['uid'] != 0 or before['links'] != 1 or before['mode'] & 0o022:
            fail('control file is not root-owned private regular data')
        value = _read_fd(fd, maximum)
        if fd_identity(fd) != before or file_identity(path) != before:
            fail('control file changed while read')
        return value
    finally:
        os.close(fd)


def _mount_decode(text):
    def replace(match):
        value = int(match.group(1), 8)
        if value not in (9, 10, 32, 92):
            fail('unsupported mount escape')
        return chr(value)
    result = re.sub(r'\\([0-7]{3})', replace, text)
    if '\x00' in result or re.search(r'\\(?![0-7]{3})', text):
        fail('invalid mount path')
    return result


def parse_mountinfo(text):
    if not isinstance(text, str) or len(text.encode()) > MAX_MOUNTINFO:
        fail('mount inventory bound')
    rows = []
    for line in text.splitlines():
        pieces = line.split(' ')
        try:
            sep = pieces.index('-')
            if sep < 6 or len(pieces) != sep + 4:
                fail('mount row shape')
            row = {'id': int(pieces[0]), 'parent': int(pieces[1]), 'device': pieces[2],
                   'root': _mount_decode(pieces[3]), 'path': _mount_decode(pieces[4]),
                   'options': sorted(pieces[5].split(',')), 'optional': pieces[6:sep],
                   'type': pieces[sep+1], 'source': _mount_decode(pieces[sep+2]),
                   'superOptions': sorted(pieces[sep+3].split(','))}
        except (ValueError, IndexError) as error:
            raise ResetError('invalid mount row') from error
        if row['id'] <= 0 or not re.fullmatch(r'[0-9]+:[0-9]+', row['device']):
            fail('invalid mount identity')
        if not row['path'].startswith('/') or not row['root'].startswith('/'):
            fail('nonabsolute mount path')
        rows.append(row)
        if len(rows) > 16384:
            fail('mount count bound')
    if len({r['id'] for r in rows}) != len(rows):
        fail('duplicate mount identity')
    return rows


def mount_table():
    with open('/proc/self/mountinfo', 'rb') as stream:
        value = stream.read(MAX_MOUNTINFO + 1)
    if len(value) > MAX_MOUNTINFO:
        fail('mount inventory bound')
    return parse_mountinfo(value.decode('utf-8', 'strict'))


def loop_identity(path, owner=None, descriptor=None):
    match = LOOP_RE.fullmatch(str(path))
    if not match:
        fail('loop path outside fixed family')
    owned = descriptor is None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC) if owned else descriptor
    try:
        obj = fd_identity(fd)
        if obj['kind'] != 'block' or os.major(obj['rdev']) != 7 or obj['uid'] != 0:
            fail('loop node identity differs')
        if owner:
            groups = set(owner['groups']) | {owner['gid']}
            if obj['mode'] & 7 or (obj['gid'] in groups and obj['mode'] & 0o070):
                fail('oracle principal can access raw loop device')
            if 'system.posix_acl_access' in os.listxattr(fd):
                fail('loop ACL is outside the profile')
        data = bytearray(232)
        fcntl.ioctl(fd, 0x4C05, data, True)  # LOOP_GET_STATUS64; observation only.
        values = struct.unpack_from('=QQQQQIIII', data)
        if values[3] != 0 or values[4] != IMAGE_BYTES or values[5] != int(match[1]) or any(values[6:9]):
            fail('loop offset, sizing, encryption or flags differ')
        size = bytearray(8)
        fcntl.ioctl(fd, 0x80081272, size, True)  # BLKGETSIZE64.
        if struct.unpack('=Q', size)[0] != IMAGE_BYTES:
            fail('loop capacity differs')
        return {'path': str(path), 'rdev': obj['rdev'], 'node': obj,
                'backingDevice': values[0], 'backingInode': values[1],
                'offset': values[3], 'sizeLimit': values[4], 'number': values[5], 'flags': values[8]}
    finally:
        if owned:
            os.close(fd)


def generation_path(generation):
    integer(generation, 0, 2**64-1, 'generation')
    return PUBLIC / f'g-{generation:016x}'


def formatter_argv(loop_fd, filesystem_uuid):
    integer(loop_fd, 0, 2**31-1, 'loop descriptor')
    canonical_uuid(filesystem_uuid)
    return ['-t', 'ext4', '-q', '-F', '-b', '4096', '-I', '256', '-N', '4096', '-m', '0',
            '-U', filesystem_uuid, '-O', 'none,has_journal,extent,filetype,sparse_super,large_file,dir_index,uninit_bg',
            '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', f'/proc/self/fd/{loop_fd}', '16384']


def run_process(argv, *, timeout=5.0, pass_fds=(), env=None, maximum_output=MAX_OUTPUT,
                capture_pipe=None, capture_sink=None, maximum_capture=MAX_TRACE):
    """Bounded transport, also exercised with real unprivileged test processes."""
    if timeout <= 0:
        if capture_pipe is not None:
            os.close(capture_pipe[0]); os.close(capture_pipe[1])
        fail('command deadline expired')
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, pass_fds=pass_fds, process_group=0,
            env=env or {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    except BaseException:
        if capture_pipe is not None:
            os.close(capture_pipe[0]); os.close(capture_pipe[1])
        raise
    if capture_pipe is not None:
        os.close(capture_pipe[1])
    selector = selectors.DefaultSelector()
    streams = [bytearray(), bytearray()]
    limits = [maximum_output, maximum_output]
    deadline = time.monotonic() + timeout
    reaped = False
    try:
        for index, stream in enumerate((process.stdout, process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        if capture_pipe is not None:
            streams.append(capture_sink)
            limits.append(maximum_capture)
            os.set_blocking(capture_pipe[0], False)
            selector.register(capture_pipe[0], selectors.EVENT_READ, 2)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail('command deadline expired')
            for key, _ in selector.select(min(remaining, 0.05)):
                fd = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
                data = os.read(fd, min(4096, limits[key.data] + 1 - len(streams[key.data])))
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    streams[key.data].extend(data)
                    if len(streams[key.data]) > limits[key.data]:
                        fail('command output exceeds bound')
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            if time.monotonic() >= deadline:
                fail('command deadline expired')
            time.sleep(0.01)
        # Keep leader PID reserved until its owned group has been killed, even on success.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        code = process.wait(timeout=2)
        reaped = True
        if code != 0:
            fail(f'command failed with exit {code}')
        return bytes(streams[0]), bytes(streams[1])
    finally:
        if not reaped:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if capture_pipe is not None:
            os.close(capture_pipe[0])


def canonical_uuid(value):
    try:
        if str(uuid.UUID(value)) != value:
            fail('UUID is not canonical')
    except (ValueError, TypeError, AttributeError) as error:
        raise ResetError('UUID is invalid') from error


def validate_identity(value, kind=None):
    base = ('device', 'inode', 'mountId', 'uid', 'gid', 'mode', 'kind')
    if not isinstance(value, dict) or value.get('kind') not in ('directory', 'file', 'block'):
        fail('invalid object identity')
    exact(value, base if value['kind'] == 'directory' else base + ('links', 'size', 'rdev'), 'identity')
    if kind is not None and value['kind'] != kind:
        fail('identity kind differs')
    for key in set(value) - {'kind'}:
        integer(value[key], 0, 2**64-1, 'identity ' + key)
    integer(value['mode'], 0, 0o7777, 'identity mode')
    if value['inode'] == 0 or value['mountId'] == 0:
        fail('identity is absent')


def validate_mount(value):
    exact(value, ('id', 'parent', 'device', 'root', 'path', 'options', 'optional', 'type', 'source', 'superOptions'), 'mount')
    for key in ('id', 'parent'):
        integer(value[key], 1, 2**63-1, 'mount ' + key)
    if not isinstance(value['device'],str) or not re.fullmatch(r'[0-9]{1,10}:[0-9]{1,10}', value['device']):
        fail('mount device is invalid')
    for key in ('root', 'path', 'type', 'source'):
        if not isinstance(value[key], str) or not 0 < len(value[key]) <= 4096:
            fail('mount string is invalid')
    if not value['root'].startswith('/') or not value['path'].startswith('/'):
        fail('mount path is not absolute')
    for key in ('options', 'optional', 'superOptions'):
        if not isinstance(value[key], list) or len(value[key]) > 32 or any(not isinstance(v, str) or len(v) > 256 for v in value[key]):
            fail('mount options exceed bounds')


def validate_generation(value, *, candidate=False):
    exact(value, ('generation', 'gate', 'underlying', 'mount', 'root', 'uuid'), 'generation record')
    integer(value['generation'], 0, 2**64-1, 'record generation')
    validate_identity(value['gate'], 'directory')
    validate_identity(value['underlying'], 'directory')
    canonical_uuid(value['uuid'])
    if value['mount'] is None or value['root'] is None:
        if not candidate or value['mount'] is not None or value['root'] is not None:
            fail('partial mount identity')
    else:
        validate_mount(value['mount'])
        validate_identity(value['root'], 'directory')


def validate_state(value):
    exact(value, STATE_KEYS, 'state')
    if type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or value['slotId'] != 'slot0' or value['disposition'] != 'RESERVED':
        fail('unsupported state contract')
    if value['phase'] not in PHASES:
        fail('unknown reset phase')
    for name in ('profileSha256', 'manifestSha256', 'previousHash', 'selfHash'):
        digest(value[name], name)
    integer(value['sequence'], 0, 2**63-1, 'sequence')
    for name in ('generation', 'previousGeneration', 'targetGeneration'):
        integer(value[name], 0, 2**64-1, name)
    try:
        if str(uuid.UUID(value['bootId'])) != value['bootId']:
            fail('invalid state boot ID')
    except (ValueError, TypeError, AttributeError) as error:
        raise ResetError('invalid state boot ID') from error
    exact(value['owner'], ('uid', 'gid', 'groups'), 'owner')
    integer(value['owner']['uid'], 1, 2**31-1, 'owner uid')
    integer(value['owner']['gid'], 0, 2**31-1, 'owner gid')
    groups = value['owner']['groups']
    if not isinstance(groups, list) or len(groups) > 32 or any(type(g) is not int for g in groups) or groups != sorted(set(groups)):
        fail('owner groups are not canonical')
    for group in groups:
        integer(group, 0, 2**31-1, 'owner group')
    exact(value['anchors'], ('root', 'private', 'public', 'quarantine', 'underlyingRoot'), 'anchors')
    for entry in value['anchors'].values():
        validate_identity(entry, 'directory')
    validate_identity(value['image'], 'file')
    if value['image']['size'] != IMAGE_BYTES or value['image']['links'] != 1 or value['image']['uid'] != 0 or value['image']['mode'] != 0o600:
        fail('image profile differs')
    exact(value['loop'], ('path', 'rdev', 'node', 'backingDevice', 'backingInode', 'offset', 'sizeLimit', 'number', 'flags'), 'loop')
    if not isinstance(value['loop']['path'], str) or not LOOP_RE.fullmatch(value['loop']['path']):
        fail('loop path differs')
    validate_identity(value['loop']['node'], 'block')
    for key in ('rdev', 'backingDevice', 'backingInode', 'offset', 'sizeLimit', 'number', 'flags'):
        integer(value['loop'][key], 0, 2**64-1, 'loop ' + key)
    if value['loop']['offset'] != 0 or value['loop']['flags'] != 0 or value['loop']['sizeLimit'] != IMAGE_BYTES:
        fail('loop geometry or flags differ')
    if (value['loop']['backingDevice'], value['loop']['backingInode']) != (value['image']['device'], value['image']['inode']):
        fail('loop backing differs')
    validate_mount(value['parentMount'])
    validate_generation(value['old'])
    if value['candidate'] is not None:
        validate_generation(value['candidate'], candidate=True)
        if value['candidate']['generation'] != value['targetGeneration'] or value['candidate']['uuid'] != value['targetUuid']:
            fail('candidate intent differs')
    if value['old']['generation'] != value['previousGeneration']:
        fail('old generation differs')
    if value['custodian'] is not None:
        exact(value['custodian'], ('invocation', 'pid', 'startTicks', 'cgroup', 'cgroupIdentity'), 'custodian')
        if not HEX32.fullmatch(value['custodian']['invocation']):
            fail('custodian invocation differs')
        for key in ('pid', 'startTicks'):
            integer(value['custodian'][key], 1, 2**63-1, 'custodian ' + key)
        if value['custodian']['cgroup'] != '/system.slice/' + UNIT:
            fail('custodian cgroup differs')
        validate_identity(value['custodian']['cgroupIdentity'], 'directory')
    if value['formatter'] is not None:
        exact(value['formatter'], ('exitCode', 'uuid', 'traceSha256', 'traceBytes', 'argvSha256'), 'formatter')
        if type(value['formatter']['exitCode']) is not int or value['formatter']['exitCode'] != 0 or value['formatter']['uuid'] != value['targetUuid']:
            fail('formatter result differs')
        integer(value['formatter']['traceBytes'], 0, MAX_TRACE, 'formatter trace bytes')
        for key in ('traceSha256', 'argvSha256'):
            digest(value['formatter'][key], key)
    exact(value['submission'], ('state', 'job', 'invocation'), 'submission')
    if value['submission']['state'] not in ('NONE', 'PENDING', 'ACKNOWLEDGED', 'ENTERED'):
        fail('invalid submission state')
    job = value['submission']['job']
    if job is not None and (not isinstance(job, str) or not re.fullmatch(r'/org/freedesktop/systemd1/job/[1-9][0-9]{0,15}', job)):
        fail('invalid job handle')
    invocation = value['submission']['invocation']
    if invocation is not None and (not isinstance(invocation, str) or not HEX32.fullmatch(invocation)):
        fail('invalid invocation identity')
    if value['phase'] == 'REGISTERED':
        if value['intentId'] is not None or value['targetUuid'] is not None or value['generation'] != value['targetGeneration']:
            fail('registered state contains reset intent')
        if value['candidate'] is not None or value['custodian'] is not None or value['formatter'] is not None or value['submission']['state'] != 'NONE':
            fail('registered state contains reset result')
    else:
        digest(value['intentId'], 'intent')
        if value['previousGeneration'] == 2**64-1 or value['targetGeneration'] != value['previousGeneration'] + 1:
            fail('reset generation is not monotonic')
        if value['generation'] != (value['targetGeneration'] if value['phase'] == 'PUBLISHED' else value['previousGeneration']):
            fail('current generation differs from phase')
        try:
            if str(uuid.UUID(value['targetUuid'])) != value['targetUuid']:
                fail('invalid target UUID')
        except (ValueError, TypeError, AttributeError) as error:
            raise ResetError('invalid target UUID') from error
        if PHASES.index(value['phase']) >= PHASES.index('FORMATTED') and value['formatter'] is None:
            fail('formatted phase lacks successful result')
        if PHASES.index(value['phase']) >= PHASES.index('MOUNT_INTENT') and value['candidate'] is None:
            fail('mount phase lacks candidate intent')
        if PHASES.index(value['phase']) >= PHASES.index('READY_PRIVATE') and value['candidate']['mount'] is None:
            fail('ready phase lacks mount identity')
    unsigned = dict(value)
    unsigned.pop('selfHash')
    if sha256(canonical(unsigned)) != value['selfHash']:
        fail('state self hash differs')
    if len(canonical(value)) > MAX_RECORD:
        fail('state exceeds byte bound')
    return value


def seal_state(value):
    result = copy.deepcopy(value)
    result.pop('selfHash', None)
    result['selfHash'] = sha256(canonical(result))
    return validate_state(result)


def parse_record(data):
    return validate_state(parse_canonical(data))


def capture_manifest(owner, tool_paths, extra_files=(), package_provenance=None):
    """Trusted install-time snapshot; no invocation path parameters enter the CLI."""
    if not TOOL_ROLES <= set(tool_paths) or len(tool_paths) > 12:
        fail('manifest lacks required fixed tools')
    entries = {}
    paths = set(map(str, extra_files)) | set(map(str, tool_paths.values())) | {
        str(INSTALLED), str(PROFILE_FILE), str(CONFIG_FILE), str(UNIT_FILE),str(RETENTION_FILE)}
    if len(paths) > 64:
        fail('manifest file limit')
    for name in sorted(paths):
        path = Path(name)
        if not path.is_absolute():
            fail('manifest path is not absolute')
        resolved = path.resolve(strict=True)
        obj = file_identity(resolved)
        if obj['kind'] != 'file' or obj['uid'] != 0 or obj['mode'] & 0o022:
            fail('manifest source is not root-controlled')
        data = _read_root_file(resolved, 64 * 1024 * 1024)
        entries[name] = {'resolved': str(resolved), 'identity': obj, 'sha256': sha256(data)}
    result = {'schemaVersion': 1, 'owner': owner, 'tools': {k: str(v) for k,v in tool_paths.items()},
              'files': entries, 'packageProvenance': package_provenance or {}}
    if len(canonical(result)) > MAX_MANIFEST:
        fail('manifest byte limit')
    return result


def _entries(fd, maximum=32):
    with os.scandir(fd) as iterator:
        result = []
        for entry in iterator:
            result.append(entry.name)
            if len(result) > maximum:
                fail('directory population exceeds bound')
    return sorted(result)


class Store:
    def __init__(self):
        self.fds = []
        self.deadline = time.monotonic() + 45
        for ancestor in (*reversed(ROOT.parents), ROOT):
            obj = file_identity(ancestor)
            if obj['kind'] != 'directory' or obj['uid'] != 0 or obj['mode'] & 0o022:
                fail('root namespace ancestry is untrusted')
        self.root = self.open_dir(ROOT)
        self.private = self.open_dir('private', self.root)
        self.public = self.open_dir('public', self.root)
        for fd,mode in ((self.root,0o755),(self.private,0o700),(self.public,0o755)):
            obj = fd_identity(fd)
            if (obj['uid'],obj['gid'],obj['mode']) != (0,0,mode):
                fail('authority directory owner or mode differs')
        raw_profile = self.read('profile.json', MAX_RECORD)
        self.profile = parse_canonical(raw_profile)
        if raw_profile not in (canonical(profile_document(False)), canonical(profile_document(True))):
            fail('installed profile is not supported')
        self.profile_hash = sha256(raw_profile)
        self.qualification = self.profile['kind'] == 'qualification'
        raw_manifest = self.read('manifest.json', MAX_MANIFEST)
        self.manifest = parse_canonical(raw_manifest, MAX_MANIFEST)
        exact(self.manifest, ('schemaVersion', 'owner', 'tools', 'files', 'packageProvenance'), 'manifest')
        self.manifest_hash = sha256(raw_manifest)
        self.verify_manifest()
        allowed = BASE_PRIVATE | (QUAL_PRIVATE if self.qualification else frozenset())
        if not set(_entries(self.private)) <= allowed:
            fail('private authority population differs')
        self.lock = self.open_file('lock', os.O_RDWR)
        lock = fd_identity(self.lock)
        if lock['uid'] != 0 or lock['kind'] != 'file' or lock['links'] != 1 or lock['mode'] != 0o600:
            fail('authority lock identity differs')

    def open_dir(self, name, parent=None):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        self.fds.append(fd)
        return fd

    def open_file(self, name, flags=os.O_RDONLY, parent=None, mode=0o400):
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=self.private if parent is None else parent)
        self.fds.append(fd)
        return fd

    def read(self, name, maximum):
        fd = self.open_file(name)
        try:
            obj = fd_identity(fd)
            if obj['kind'] != 'file' or obj['uid'] != 0 or obj['links'] != 1 or obj['mode'] & 0o022:
                fail('authority member identity differs')
            data = _read_fd(fd, maximum)
            if fd_identity(fd) != obj or file_identity(PRIVATE / name) != obj:
                fail('authority member changed')
            return data
        finally:
            self.drop(fd)

    def verify_manifest(self):
        if type(self.manifest['schemaVersion']) is not int or self.manifest['schemaVersion'] != 1 or not TOOL_ROLES <= set(self.manifest['tools']):
            fail('manifest contract differs')
        if len(self.manifest['files']) > 64:
            fail('manifest entry bound')
        required = set(self.manifest['tools'].values()) | {str(INSTALLED), str(PROFILE_FILE), str(CONFIG_FILE), str(UNIT_FILE),str(RETENTION_FILE)}
        if self.qualification and 'strace' not in self.manifest['tools']:
            fail('qualification tracer absent')
        if not required <= set(self.manifest['files']):
            fail('manifest omitted executable or control source')
        for name, entry in self.manifest['files'].items():
            exact(entry, ('resolved', 'identity', 'sha256'), 'manifest file')
            path = Path(name)
            if str(path.resolve(strict=True)) != entry['resolved'] or file_identity(entry['resolved']) != entry['identity']:
                fail('installed deployment identity changed')
            if sha256(_read_root_file(entry['resolved'], 64*1024*1024)) != entry['sha256']:
                fail('installed deployment bytes changed')

    def acquire(self, wait=0):
        end = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= end:
                    fail('authority lock is held')
                time.sleep(0.02)

    def load(self):
        value = parse_record(self.read('state.json', MAX_RECORD))
        if value['profileSha256'] != self.profile_hash or value['manifestSha256'] != self.manifest_hash:
            fail('state deployment binding differs')
        if value['owner'] != self.manifest['owner']:
            fail('state owner binding differs')
        if value['bootId'] != boot_id():
            fence_old_boot(self,value)
            fail('boot mismatch: slot remains reserved; no recovery permitted')
        if 'state.next' in _entries(self.private):
            candidate = parse_record(self.read('state.next', MAX_RECORD))
            if candidate['previousHash'] != value['selfHash'] or candidate['sequence'] != value['sequence'] + 1:
                fail('unrecognized staged state publication')
            self.validate_transition(value, candidate)
            os.rename('state.next', 'state.json', src_dir_fd=self.private, dst_dir_fd=self.private)
            os.fsync(self.private)
            value = candidate
        self.current_state = value
        return value

    @staticmethod
    def validate_transition(old, new):
        for key in ('schemaVersion','profileSha256','manifestSha256','slotId','bootId','owner','anchors','image','loop','parentMount','disposition'):
            if new[key] != old[key]:
                fail('immutable state field changed')
        if old['phase'] in ('REGISTERED','PUBLISHED') and new['phase'] == 'INTENT':
            if new['previousGeneration'] != old['generation'] or new['targetGeneration'] != old['generation'] + 1:
                fail('new intent generation mismatch')
            return
        if new['intentId'] != old['intentId'] or new['targetGeneration'] != old['targetGeneration'] or new['targetUuid'] != old['targetUuid']:
            fail('in-progress reset intent changed')
        before, after = PHASES.index(old['phase']), PHASES.index(new['phase'])
        if after < before or after > before + 1:
            fail('reset phase transition is not monotonic')

    def publish(self, old, **updates):
        new = copy.deepcopy(old)
        new.update(updates)
        new['previousHash'] = old['selfHash']
        new['sequence'] = old['sequence'] + 1
        new = seal_state(new)
        self.validate_transition(old, new)
        data = canonical(new)
        usage,entries = verify_metadata_budget(self,old)
        if usage + len(data) > self.profile['metadataBytes'] or entries + 1 > 32:
            fail('staged state would exceed metadata reservation')
        fd = self.open_file('state.next', os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            write_all(fd, data)
            os.fsync(fd)
        finally:
            self.drop(fd)
        current = parse_record(self.read('state.json', MAX_RECORD))
        if current != old:
            fail('state changed before publication')
        os.rename('state.next','state.json',src_dir_fd=self.private,dst_dir_fd=self.private)
        if new['phase'] == 'READY_PRIVATE':
            self.barrier('READY_RENAMED_BEFORE_FSYNC', new)
        os.fsync(self.private)
        self.current_state = new
        return new

    def close(self):
        for fd in reversed(self.fds):
            with contextlib.suppress(OSError):
                os.close(fd)
        self.fds.clear()

    def drop(self, fd):
        os.close(fd)
        self.fds.remove(fd)

    def command(self, role, arguments, pass_fds=(), formatter=False):
        self.verify_manifest()
        if role not in TOOL_ROLES:
            fail('unsupported utility role')
        path = self.manifest['tools'][role]
        spec = self.manifest['files'][path]
        fd = self.open_file(spec['resolved'])
        if fd_identity(fd) != spec['identity']:
            fail('utility descriptor differs')
        environment = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}
        if formatter:
            environment.update({'MKE2FS_CONFIG':str(CONFIG_FILE),'E2FSPROGS_UNDO_DIR':'none'})
        try:
            out, err = run_process([str(Path('/proc/self/fd') / str(fd)), *map(str, arguments)],
                timeout=min(35, self.deadline-time.monotonic()), pass_fds=(fd,self.lock,*pass_fds), env=environment)
            self.verify_manifest()
            if getattr(self, 'service', False) and role not in ('systemctl', 'busctl'):
                service_census(self, os.environ.get('INVOCATION_ID'))
            return out, err
        finally:
            self.drop(fd)

    def barrier(self, name, state):
        if name not in BARRIERS:
            fail('unknown internal barrier')
        if not self.qualification or 'fault.json' not in _entries(self.private):
            return
        fault = parse_canonical(self.read('fault.json', 4096))
        exact(fault, ('version','id','generation','barrier'), 'qualification fault')
        digest(fault['id'])
        if type(fault['version']) is not int or fault['version'] != 1 or fault['barrier'] not in BARRIERS:
            fail('qualification fault differs')
        integer(fault['generation'],0,2**64-1,'qualification generation')
        if fault['generation'] != state['previousGeneration'] or fault['barrier'] != name:
            return
        if 'barrier.json' in _entries(self.private):
            prior = parse_canonical(self.read('barrier.json', 4096))
            if prior.get('id') == fault['id']:
                return
            os.unlink('barrier.json', dir_fd=self.private)
        record = {'version':1,'id':fault['id'],'barrier':name,'bootId':boot_id(),
                  'pid':os.getpid(),'startTicks':process_start(os.getpid()),'intentId':state['intentId'],
                  'phase':state['phase'],'stateHash':state['selfHash'],'generation':state['previousGeneration']}
        fd = self.open_file('barrier.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            write_all(fd, canonical(record)); os.fsync(fd); os.fsync(self.private)
        finally:
            self.drop(fd)
        os.kill(os.getpid(), signal.SIGSTOP)


@contextlib.contextmanager
def opened_store(wait=0):
    store = Store.__new__(Store)
    store.fds = []
    try:
        store.__init__()
        store.acquire(wait)
        yield store
    finally:
        store.close()


def process_start(pid):
    data = Path(f'/proc/{pid}/stat').read_text()
    tail = data[data.rfind(')')+2:].split()
    if len(tail) < 20:
        fail('process start identity absent')
    return int(tail[19])


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            fail('short durable write')
        view = view[written:]


def mount_at(rows, path, identity=None):
    matches = [row for row in rows if row['path'] == str(path)]
    if len(matches) != 1:
        fail('mount target is absent, stacked or ambiguous')
    row = matches[0]
    if identity is not None and row['id'] != identity['mountId']:
        fail('mount ID differs from opened root')
    return row


def superblock(loop_fd):
    data = os.pread(loop_fd, 1024, 1024)
    if len(data) != 1024 or struct.unpack_from('<H', data, 56)[0] != 0xef53:
        fail('ext4 superblock is absent')
    inodes, blocks = struct.unpack_from('<II', data, 0)
    if inodes != INODES or blocks != IMAGE_BYTES // 4096 or struct.unpack_from('<I', data, 24)[0] != 2:
        fail('ext4 geometry differs')
    if struct.unpack_from('<H', data, 88)[0] != 256:
        fail('ext4 inode size differs')
    return str(uuid.UUID(bytes=data[104:120]))


def verify_mount(row, root, loop, path):
    expected_dev = f"{os.major(loop['rdev'])}:{os.minor(loop['rdev'])}"
    if row['path'] != str(path) or row['root'] != '/' or row['type'] != 'ext4' or row['device'] != expected_dev:
        fail('scratch mount profile differs')
    if not set(FLAGS) <= set(row['options']) or any(v.startswith(('shared:', 'master:', 'propagate_from:')) for v in row['optional']):
        fail('scratch flags or propagation differ')
    if row['id'] != root['mountId'] or root['device'] != loop['rdev']:
        fail('scratch FD and block device differ')


def current_inventory(state, allowed):
    """Only exact owned parent and finite named child mounts may be visible."""
    rows = mount_table()
    root = str(ROOT)
    owned = [r for r in rows if r['path'] == root or r['path'].startswith(root + '/')]
    expected = {str(ROOT): state['parentMount']['id'], **allowed}
    if len(owned) != len(expected) or any(r['path'] not in expected or
            (expected[r['path']] is not None and r['id'] != expected[r['path']]) for r in owned):
        fail('unexpected mount, alias, replacement or nested mount')
    # A visible alias outside the owned tree is just as disqualifying.
    device = f"{os.major(state['loop']['rdev'])}:{os.minor(state['loop']['rdev'])}"
    if any(r['device'] == device and r['path'] not in allowed for r in rows):
        fail('visible scratch alias outside owned namespace')
    parent = mount_at(rows, ROOT, state['anchors']['root'])
    if parent != state['parentMount'] or any(v.startswith(('shared:', 'master:', 'propagate_from:')) for v in parent['optional']):
        fail('private parent mount identity or propagation differs')
    return rows


def open_gate(store, generation, expected, modes):
    name = generation_path(generation).name
    fd = store.open_dir(name, store.public)
    obj = fd_identity(fd)
    if not same_object(obj, expected, metadata=False) or obj['uid'] != 0 or obj['gid'] != 0 or obj['mode'] not in modes:
        fail('generation gate identity differs')
    if _entries(fd) != ['scratch']:
        fail('generation gate has unknown entries')
    return fd


def verify_base(store, state):
    for name, fd in (('root', store.root), ('private', store.private), ('public', store.public)):
        if fd_identity(fd) != state['anchors'][name] or file_identity({'root': ROOT, 'private': PRIVATE, 'public': PUBLIC}[name]) != state['anchors'][name]:
            fail('persistent namespace anchor changed')
    if file_identity(IMAGE) != state['image']:
        fail('backing image path identity changed')
    image_fd = store.open_file('image', os.O_RDWR)
    if fd_identity(image_fd) != state['image']:
        fail('backing image descriptor changed')
    loop_fd = store.open_file(state['loop']['path'], os.O_RDWR)
    if loop_identity(state['loop']['path'], state['owner'], loop_fd) != state['loop']:
        fail('retained loop association changed')
    generations = _entries(store.public, 2)
    allowed = {generation_path(state['old']['generation']).name}
    if state['candidate'] is not None:
        allowed.add(generation_path(state['candidate']['generation']).name)
    if set(generations) != allowed:
        fail('public generation inventory differs')
    verify_metadata_budget(store,state)
    return image_fd, loop_fd


def verify_metadata_budget(store,state):
    """Finite control namespace only; never descend into old ext4 contents."""
    total = 0
    count = 0
    private_dirs = {'quarantine'}
    if store.qualification:
        private_dirs |= {'case-receipts','fixture-old-mount','fixture-alias','fixture-old-gate'}
    def files(directory, allowed, *, allow_dirs=()):
        nonlocal total,count
        for name in _entries(directory,32):
            if name not in allowed:
                fail('metadata namespace contains unknown member')
            count += 1
            if count > 32:
                fail('aggregate metadata entry limit')
            fd = store.open_file(name,parent=directory)
            try:
                obj = fd_identity(fd)
                if name in allow_dirs:
                    if obj['kind'] != 'directory':
                        fail('metadata directory kind differs')
                    # These exact test targets may intentionally hold an old
                    # mount/gate. Do not recurse into slot contents as metadata.
                    if name != 'quarantine' and name != 'case-receipts':
                        continue
                    if obj['uid'] != 0 or obj['mode'] & 0o077:
                        fail('metadata directory is not root-private')
                    if name == 'case-receipts':
                        files(fd,{'current','summary.json','summary.json.next'},allow_dirs={'current'})
                elif name == 'current' and 'current' in allow_dirs:
                    fail('unreachable metadata directory branch')
                else:
                    if obj['kind'] != 'file' or obj['uid'] != 0 or obj['links'] != 1 or obj['mode'] & 0o022:
                        fail('metadata member is not root-controlled regular data')
                    if (obj['device'],obj['inode']) == (state['image']['device'],state['image']['inode']):
                        if obj != state['image']:
                            fail('original image metadata changed')
                        continue
                    total += obj['size']
                    if name.startswith('summary.json') and obj['size'] > MAX_RECORD:
                        fail('qualification summary exceeds bound')
                    if total > store.profile['metadataBytes']:
                        fail('aggregate metadata byte limit')
            finally:
                store.drop(fd)
    # case-receipts/current is handled separately to keep traversal depth and
    # names fixed even under a qualification installation.
    files(store.private,BASE_PRIVATE | (QUAL_PRIVATE if store.qualification else frozenset()),allow_dirs=private_dirs)
    if store.qualification and 'case-receipts' in _entries(store.private):
        cases = store.open_dir('case-receipts',store.private)
        try:
            if 'current' in _entries(cases):
                current = store.open_dir('current',cases)
                try:
                    obj = fd_identity(current)
                    if obj['uid'] != 0 or obj['mode'] & 0o077:
                        fail('qualification current directory is not root-private')
                    names = {'formatter.trace','events.json','manifest.json','service.properties','receipt.json'}
                    files(current,names | {n+'.next' for n in names})
                finally:
                    store.drop(current)
        finally:
            store.drop(cases)
    for unit in (UNIT_FILE,RETENTION_FILE):
        total += file_identity(unit)['size']
    if total > store.profile['metadataBytes']:
        fail('aggregate metadata byte limit')
    return total,count


def fence_old_boot(store,state):
    """Close only authenticated persistent gates; never repair boot-ambiguous mounts.

    Mount IDs may not survive reboot. For this denial-only action the durable
    host directory dev/inode/owner identity must still match all three anchors.
    No image, loop, scratch root or unknown replacement is changed.
    """
    gates = []
    try:
        for name,path in (('root',ROOT),('private',PRIVATE),('public',PUBLIC)):
            actual = file_identity(path)
            expected = state['anchors'][name]
            keys = ('device','inode','uid','gid','mode','kind')
            if any(actual[key] != expected[key] for key in keys):
                fail('boot mismatch with changed persistent authority anchor')
        records = [state['old']] + ([state['candidate']] if state['candidate'] is not None else [])
        for record in records:
            fd = store.open_dir(generation_path(record['generation']).name,store.public)
            gates.append(fd)
            actual,expected = fd_identity(fd),record['gate']
            keys = ('device','inode','uid','gid','kind')
            if any(actual[key] != expected[key] for key in keys) or actual['uid'] != 0 or actual['gid'] != 0 or actual['mode'] not in (0,0o711) or _entries(fd) != ['scratch']:
                fail('boot mismatch with unknown generation gate')
        for fd in gates:
            os.fchmod(fd,0); os.fsync(fd)
        os.fsync(store.public)
    finally:
        for fd in gates:
            store.drop(fd)


def verify_live_generation(store, state, record, *, gate_modes, root_modes, path=None):
    gate = open_gate(store, record['generation'], record['gate'], gate_modes)
    location = path or generation_path(record['generation']) / 'scratch'
    root_fd = store.open_dir(location)
    obj = fd_identity(root_fd)
    if not same_object(obj, record['root'], metadata=False) or (obj['uid'], obj['gid'], obj['mode']) not in root_modes:
        fail('scratch root identity or owner differs')
    rows = current_inventory(state, {str(location): record['mount']['id']})
    row = mount_at(rows, location, obj)
    for key in ('id','device','root','options','optional','type','source','superOptions'):
        if row[key] != record['mount'][key]:
            fail('scratch mount identity changed')
    verify_mount(row, obj, state['loop'], location)
    return gate, root_fd, row


def register_initial(owner, loop_path, underlying_root, underlying_scratch):
    """Root installer-only API. Never available through broker command parsing."""
    if os.geteuid() != 0:
        fail('root installer required')
    validate_identity(underlying_root, 'directory')
    validate_identity(underlying_scratch, 'directory')
    with opened_store() as store:
        if {'state.json', 'state.next'} & set(_entries(store.private)):
            fail('registration already exists; never adopt residue')
        if owner != store.manifest['owner']:
            fail('installed owner differs')
        image = file_identity(IMAGE)
        loop = loop_identity(loop_path, owner)
        root = file_identity(ROOT)
        parent = mount_at(mount_table(), ROOT, root)
        if (root['device'], root['inode']) != (underlying_root['device'], underlying_root['inode']) or root['mountId'] == underlying_root['mountId']:
            fail('parent is not the recorded nonrecursive self bind')
        path = generation_path(0)
        old_root = file_identity(path / 'scratch')
        gate = file_identity(path)
        row = mount_at(mount_table(), path / 'scratch', old_root)
        fd = store.open_file(loop_path, os.O_RDWR)
        filesystem_uuid = superblock(fd)
        if (gate['uid'], gate['gid'], gate['mode']) != (0,0,0) or (old_root['uid'],old_root['gid'],old_root['mode']) != (owner['uid'],owner['gid'],0o700):
            fail('initial gate or scratch owner profile differs')
        if (underlying_scratch['uid'], underlying_scratch['gid'], underlying_scratch['mode']) != (0,0,0):
            fail('initial underlying scratch is not fenced')
        state = seal_state({'schemaVersion':1,'profileSha256':store.profile_hash,'manifestSha256':store.manifest_hash,
            'slotId':'slot0','bootId':boot_id(),'sequence':0,'previousHash':ZERO,'phase':'REGISTERED','disposition':'RESERVED',
            'owner':owner,'anchors':{'root':root,'private':fd_identity(store.private),'public':fd_identity(store.public),
                'quarantine':file_identity(QUARANTINE),'underlyingRoot':underlying_root},'image':image,'loop':loop,
            'parentMount':parent,'generation':0,'previousGeneration':0,'targetGeneration':0,'intentId':None,'targetUuid':None,
            'old':{'generation':0,'gate':gate,'underlying':underlying_scratch,'mount':row,'root':old_root,'uuid':filesystem_uuid},
            'candidate':None,'submission':{'state':'NONE','job':None,'invocation':None},'custodian':None,'formatter':None})
        verify_base(store,state)
        verify_mount(row,old_root,loop,path/'scratch')
        current_inventory(state,{str(path/'scratch'):row['id']})
        q = store.open_dir('quarantine',store.private)
        if _entries(q) or fd_identity(q)['mode'] != 0:
            fail('initial quarantine is not empty and fenced')
        scratch = store.open_dir(path/'scratch')
        if _entries(scratch):
            fail('initial scratch is not empty')
        fd = store.open_file('state.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        write_all(fd,canonical(state)); os.fsync(fd); os.fsync(store.private)
        gate_fd = open_gate(store,0,gate,(0,))
        os.fchmod(gate_fd,0o711); os.fsync(gate_fd)
        observed_old = dict(state['old'],gate=fd_identity(gate_fd))
        return store.publish(state,old=observed_old)


UNIT_FIXED = {'Type':'exec','ExitType':'cgroup','User':'root','Group':'root',
    'KillMode':'control-group','KillSignal':'9','SendSIGKILL':'no','Restart':'no',
    'RemainAfterExit':'no','TimeoutStartUSec':'5s','TimeoutStopUSec':'5s',
    'RuntimeMaxUSec':'1min','Delegate':'no','FragmentPath':str(UNIT_FILE),'DropInPaths':'',
    'WorkingDirectory':str(PRIVATE),'UMask':'0077','TasksMax':'32','LimitNOFILE':'64',
    'LimitCORE':'0','MemoryMax':'268435456','NoNewPrivileges':'yes','PrivateMounts':'no',
    'PrivateTmp':'no','RootDirectory':'','RootImage':'','Environment':'','EnvironmentFiles':'',
    'PassEnvironment':'','UnsetEnvironment':''}
UNIT_OBSERVED = ('ActiveState','SubState','Job','InvocationID','ControlGroup','ExecMainPID',
                 'MainPID','ExecMainCode','ExecMainStatus','Result','ExecStart','LoadState')
CGROUP = '/system.slice/' + UNIT


def parse_properties(data, expected):
    if not isinstance(data, bytes) or len(data) > MAX_OUTPUT:
        fail('unit observation exceeds bound')
    values = {}
    try:
        for line in data.decode('utf-8', 'strict').splitlines():
            key, separator, value = line.partition('=')
            if not separator or key in values or key not in expected:
                fail('unit observation is ambiguous')
            values[key] = value
    except UnicodeError as error:
        raise ResetError('unit observation is not UTF-8') from error
    if set(values) != set(expected):
        fail('unit observation is incomplete')
    return values


def manager_snapshot(store):
    if not getattr(store, 'platform_checked', False):
        out, _ = store.command('systemctl', ['--version'])
        if not re.match(rb'systemd 255(?:\s|\()', out) or platform.machine() != 'x86_64':
            fail('host is outside reviewed systemd/machine profile')
        store.platform_checked = True
    retention_snapshot(store)
    keys = tuple(UNIT_FIXED) + UNIT_OBSERVED
    out, _ = store.command('systemctl', ['show','--no-pager', '--property=' + ','.join(keys), UNIT])
    values = parse_properties(out, keys)
    if any(values[k] != v for k,v in UNIT_FIXED.items()) or values['LoadState'] != 'loaded':
        fail('effective service settings differ from installed profile')
    command = values['ExecStart']
    expected = f'/usr/bin/python3 -I -S {INSTALLED} service-run'
    if command.count('{') != 1 or not re.search(r'\bpath=/usr/bin/python3\s*;',command) or not re.search(r'\bargv\[\]=' + re.escape(expected) + r'\s*;',command) or 'ignore_errors=no' not in command:
        fail('effective service entrypoint differs')
    if values['ControlGroup'] not in ('', CGROUP):
        fail('effective service cgroup differs')
    return values


def retention_snapshot(store):
    fixed = {'LoadState':'loaded','ActiveState':'active','SubState':'active',
        'FragmentPath':str(RETENTION_FILE),'DropInPaths':'','DefaultDependencies':'no',
        'After':UNIT,'Wants':'','Requires':''}
    keys = tuple(fixed) + ('Job',)
    out,_ = store.command('systemctl',['show','--no-pager','--property='+','.join(keys),RETENTION_UNIT])
    values = parse_properties(out,keys)
    if any(values[k] != v for k,v in fixed.items()) or values['Job'] not in ('','0'):
        fail('fixed service-result retention target differs or is inactive')
    return values


def cgroup_census(path=CGROUP, expected_pid=None):
    if path != CGROUP:
        fail('unknown cgroup namespace')
    root = Path('/sys/fs/cgroup')
    if not any(row['path'] == str(root) and row['type'] == 'cgroup2' for row in mount_table()):
        fail('unified cgroup mount absent')
    location = root / path.lstrip('/')
    try:
        fd = os.open(location, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except FileNotFoundError:
        if expected_pid is not None:
            fail('custodian cgroup disappeared')
        return None
    try:
        obj = fd_identity(fd)
        if obj['uid'] != 0 or obj['mode'] & 0o022:
            fail('service cgroup is delegated or untrusted')
        with os.scandir(fd) as iterator:
            count = 0
            for entry in iterator:
                count += 1
                if count > 256 or entry.is_dir(follow_symlinks=False):
                    fail('service has child cgroup or excessive population')
        procs = os.open('cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            data = _read_fd(procs,4096)
        finally:
            os.close(procs)
        if data and not re.fullmatch(rb'(?:[1-9][0-9]{0,9}\n)+',data):
            fail('invalid cgroup process census')
        pids = [int(v) for v in data.splitlines()]
        expected = [] if expected_pid is None else [expected_pid]
        if pids != expected:
            fail('service cgroup is not empty' if expected_pid is None else 'custodian entry is not self-only')
        if file_identity(location) != obj:
            fail('service cgroup changed during census')
        return obj
    finally:
        os.close(fd)


def service_census(store, invocation):
    if not isinstance(invocation,str) or not HEX32.fullmatch(invocation):
        fail('service invocation absent')
    membership = Path('/proc/self/cgroup').read_text()
    if membership != '0::' + CGROUP + '\n':
        fail('direct custodian entry is forbidden')
    snapshot = manager_snapshot(store)
    if snapshot['InvocationID'] != invocation or snapshot['ControlGroup'] != CGROUP or snapshot['ActiveState'] not in ('activating','active'):
        fail('custodian invocation is not current')
    if snapshot['ExecMainPID'] != str(os.getpid()):
        fail('custodian is not unit main process')
    return cgroup_census(expected_pid=os.getpid())


def inactive_snapshot(store, state, *, successful=False):
    snapshot = manager_snapshot(store)
    if snapshot['ActiveState'] not in ('inactive','failed') or snapshot['SubState'] not in ('dead','failed') or snapshot['Job'] not in ('','0'):
        fail('prior service is active, queued or ambiguous')
    observed = cgroup_census()
    if observed is not None and state['custodian'] is not None and observed != state['custodian']['cgroupIdentity']:
        fail('prior service cgroup was replaced')
    if successful:
        custodian = state['custodian']
        if custodian is None or snapshot['InvocationID'] != custodian['invocation'] or snapshot['Result'] != 'success' or snapshot['ExecMainCode'] != '1' or snapshot['ExecMainStatus'] != '0':
            fail('ready result lacks exact successful service completion')
    return snapshot


def submit(store, state):
    # Root lock is held until the non-waiting StartUnit acknowledgement is durable.
    out, _ = store.command('busctl',['--system','--timeout=4s','call','org.freedesktop.systemd1',
        '/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','StartUnit','ss',UNIT,'fail'])
    match = re.fullmatch(rb'o "(/org/freedesktop/systemd1/job/[1-9][0-9]{0,15})"\n',out)
    if not match:
        fail('StartUnit acknowledgement is ambiguous; pending intent retained')
    return store.publish(state,submission={'state':'ACKNOWLEDGED','job':match[1].decode(),'invocation':None})


def receipt(state):
    record = state['candidate'] if state['phase'] in ('READY_PRIVATE','EXPOSURE_INTENT','PUBLISHED') else state['old']
    return {'schemaVersion':1,'stateHash':state['selfHash'],'intentId':state['intentId'],
        'phase':state['phase'],'generation':state['generation'],'previousGeneration':state['previousGeneration'],
        'targetGeneration':state['targetGeneration'],'scratch':str(generation_path(record['generation'])/'scratch'),
        'oldScratch':str(generation_path(state['old']['generation'])/'scratch'),'filesystemUuid':record['uuid'],
        'disposition':'RESERVED','profileSha256':state['profileSha256'],'manifestSha256':state['manifestSha256']}


def request(store, state, expected_generation):
    if state['phase'] not in ('REGISTERED','PUBLISHED') or state['generation'] != expected_generation:
        fail('stale generation or reset already pending')
    integer(expected_generation,0,2**64-2,'reset generation')
    inactive_snapshot(store,state)
    image_fd, loop_fd = verify_base(store,state)
    old = state['candidate'] if state['phase'] == 'PUBLISHED' else state['old']
    verify_live_generation(store,state,old,gate_modes=(0o711,),root_modes=((state['owner']['uid'],state['owner']['gid'],0o700),))
    if superblock(loop_fd) != old['uuid']:
        fail('current filesystem UUID differs')
    # At most two generations. Remove only the previous already unmounted gate,
    # using exact directory identities and ordinary rmdir, before a new intent.
    if state['phase'] == 'PUBLISHED':
        retired = state['old']
        gate = open_gate(store,retired['generation'],retired['gate'],(0,))
        scratch = store.open_dir('scratch',gate)
        if fd_identity(scratch) != retired['underlying'] or _entries(scratch):
            fail('retired underlying directory differs or is not empty')
        store.drop(scratch)
        os.rmdir('scratch',dir_fd=gate)
        store.drop(gate)
        os.rmdir(generation_path(retired['generation']).name,dir_fd=store.public)
        os.fsync(store.public)
    state = store.publish(state,phase='INTENT',previousGeneration=expected_generation,targetGeneration=expected_generation+1,
        intentId=os.urandom(32).hex(),targetUuid=str(uuid.uuid4()),old=old,candidate=None,custodian=None,formatter=None,
        submission={'state':'PENDING','job':None,'invocation':None})
    return submit(store,state)


def resume(store,state,intent):
    if state['intentId'] != intent or state['phase'] in ('REGISTERED','EXPOSURE_INTENT','PUBLISHED'):
        fail('intent is not destructively resumable')
    snapshot = inactive_snapshot(store,state)
    verify_base(store,state)
    if state['submission']['state'] == 'PENDING':
        # A killed broker could have sent a request that has not yet been observed.
        # Never turn absent acknowledgement into permission for another submission.
        fail('unacknowledged submission remains quarantined')
    if state['submission']['state'] not in ('ACKNOWLEDGED','ENTERED'):
        fail('submission is not recoverable')
    if state['submission']['state'] == 'ENTERED' and snapshot['InvocationID'] != state['submission']['invocation']:
        fail('previous invocation completion is ambiguous')
    if state['phase'] == 'READY_PRIVATE' and snapshot['Result'] == 'success':
        return state
    state = store.publish(state,submission={'state':'PENDING','job':None,'invocation':None})
    return submit(store,state)


def gate_closed(store,state):
    fd = open_gate(store,state['old']['generation'],state['old']['gate'],(0,))
    store.drop(fd)


def old_location(state):
    rows = mount_table()
    matches = [r for r in rows if r['id'] == state['old']['mount']['id']]
    if len(matches) > 1:
        fail('old mount identity is duplicated')
    if not matches:
        current_inventory(state,{})
        return None
    row = matches[0]
    source = generation_path(state['old']['generation'])/'scratch'
    if row['path'] not in (str(source),str(QUARANTINE)):
        fail('old mount moved to unrecognized target')
    current_inventory(state,{row['path']:row['id']})
    return Path(row['path'])


def verify_underlying(store,state):
    old = state['old']
    fd = store.open_dir(generation_path(old['generation'])/'scratch')
    try:
        if fd_identity(fd) != old['underlying'] or _entries(fd):
            fail('old underlying directory changed')
    finally:
        store.drop(fd)
    fd = store.open_dir(QUARANTINE)
    try:
        if fd_identity(fd) != state['anchors']['quarantine'] or _entries(fd):
            fail('quarantine target changed or has residue')
    finally:
        store.drop(fd)


def retire_old(store,state):
    old = state['old']
    owner = state['owner']
    source = generation_path(old['generation'])/'scratch'
    location = old_location(state)
    if state['phase'] == 'INTENT':
        if location != source:
            fail('unfenced intent lost original mount')
        gate, root_fd, _ = verify_live_generation(store,state,old,gate_modes=(0,0o711),
            root_modes=((owner['uid'],owner['gid'],0o700),(0,0,0o700)))
        # The production lease's flock is acquired before either persistent gate
        # or scratch ownership is changed. A live lease can still clean-release.
        try:
            fcntl.flock(root_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            fail('old mount lease is active; generation remains unchanged')
        os.fchmod(gate,0); os.fsync(gate)
        os.fchown(root_fd,0,0); os.fchmod(root_fd,0o700); os.fsync(root_fd)
        store.barrier('GATE_CLOSED',state)
        state = store.publish(state,phase='FENCED')
        store.drop(gate)
        store.drop(root_fd)
    if state['phase'] == 'FENCED':
        gate_closed(store,state)
        location = old_location(state)
        if location is not None:
            gate, root_fd, _ = verify_live_generation(store,state,old,gate_modes=(0,),root_modes=((0,0,0o700),),path=location)
            try:
                fcntl.flock(root_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                fail('fenced mount has unknown active holder')
            store.drop(gate)
            if location == source:
                qfd = store.open_dir(QUARANTINE)
                if fd_identity(qfd) != state['anchors']['quarantine'] or _entries(qfd):
                    fail('quarantine destination differs')
                store.drop(qfd)
                store.command('mount',['--no-canonicalize','--move',str(source),str(QUARANTINE)])
                if old_location(state) != QUARANTINE or file_identity(QUARANTINE) != fd_identity(root_fd):
                    fail('moved mount identity differs')
                store.barrier('MOUNT_MOVED',state)
            # Drop every owned reference to the mounted scratch before normal
            # unmount. A foreign live FD must make the kernel refuse.
            store.drop(root_fd)
            store.command('umount',['--no-canonicalize',str(QUARANTINE)])
            if old_location(state) is not None:
                fail('normal unmount did not retire exact mount')
            verify_underlying(store,state)
            store.barrier('UNMOUNTED_BEFORE_COMMIT',state)
        else:
            verify_underlying(store,state)
        state = store.publish(state,phase='UNMOUNTED')
    return state


def write_diagnostic(store,name,data):
    if name not in ('formatter.trace','diagnostic.json') or len(data) > (MAX_TRACE if name == 'formatter.trace' else MAX_RECORD):
        fail('diagnostic exceeds bound')
    usage,entries = verify_metadata_budget(store,store.current_state)
    if usage + len(data) > store.profile['metadataBytes'] or entries + 1 > 32:
        fail('diagnostic would exceed metadata reservation')
    if name in _entries(store.private):
        prior = store.read(name,MAX_TRACE if name == 'formatter.trace' else MAX_RECORD)
        del prior
        os.unlink(name,dir_fd=store.private)
    fd = store.open_file(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
    try:
        write_all(fd,data); os.fsync(fd); os.fsync(store.private)
    finally:
        store.drop(fd)


def parse_format_attempt(data):
    value = parse_canonical(data)
    exact(value,('schemaVersion','intentId','launchAttempts','invocationId','argvSha256','previousHash','selfHash'),'formatter attempt')
    integer(value['schemaVersion'],1,1,'attempt schema')
    integer(value['launchAttempts'],1,64,'formatter launch attempts')
    for key in ('intentId','argvSha256','previousHash','selfHash'):
        digest(value[key],key)
    if not isinstance(value['invocationId'],str) or not HEX32.fullmatch(value['invocationId']):
        fail('attempt invocation differs')
    unsigned = dict(value); unsigned.pop('selfHash')
    if sha256(canonical(unsigned)) != value['selfHash']:
        fail('attempt checksum differs')
    return value


def format_attempt(store,state,argv):
    """Durable conservative attempts, never claimed as successful exec count.

    An attempt is fsynced before launch. A death before exec may overcount; the
    independent actual execve trace/owned-PID observation establishes execution.
    """
    names = _entries(store.private)
    previous = parse_format_attempt(store.read('diagnostic.json',MAX_RECORD)) if 'diagnostic.json' in names else None
    if 'diagnostic.next' in names:
        staged = parse_format_attempt(store.read('diagnostic.next',MAX_RECORD))
        expected = ZERO if previous is None else previous['selfHash']
        next_count = previous['launchAttempts']+1 if previous is not None and previous['intentId'] == staged['intentId'] else 1
        if staged['previousHash'] != expected or staged['launchAttempts'] != next_count or staged['intentId'] != state['intentId']:
            fail('unrecognized staged formatter attempt')
        os.rename('diagnostic.next','diagnostic.json',src_dir_fd=store.private,dst_dir_fd=store.private)
        os.fsync(store.private)
        previous = staged
    value = {'schemaVersion':1,'intentId':state['intentId'],
        'launchAttempts':previous['launchAttempts']+1 if previous is not None and previous['intentId'] == state['intentId'] else 1,
        'invocationId':state['custodian']['invocation'],'argvSha256':sha256(canonical(argv)),
        'previousHash':ZERO if previous is None else previous['selfHash']}
    value['selfHash'] = sha256(canonical(value))
    data = canonical(value); parse_format_attempt(data)
    usage,entries = verify_metadata_budget(store,state)
    if usage + len(data) > store.profile['metadataBytes'] or entries+1 > 32:
        fail('formatter attempt exceeds metadata reservation')
    fd = store.open_file('diagnostic.next',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
    try:
        write_all(fd,data); os.fsync(fd)
    finally:
        store.drop(fd)
    os.rename('diagnostic.next','diagnostic.json',src_dir_fd=store.private,dst_dir_fd=store.private)
    os.fsync(store.private)
    return value


def format_once(store,state,loop_fd,image_fd):
    gate_closed(store,state)
    current_inventory(state,{})
    verify_underlying(store,state)
    if loop_identity(state['loop']['path'],state['owner'],loop_fd) != state['loop'] or fd_identity(image_fd) != state['image']:
        fail('formatter input association changed')
    argv = formatter_argv(loop_fd,state['targetUuid'])
    format_attempt(store,state,argv)
    trace = bytearray()
    if store.qualification:
        store.verify_manifest()
        formatter = store.manifest['files'][store.manifest['tools']['mke2fs']]
        tracer = store.manifest['files'][store.manifest['tools']['strace']]
        exe = store.open_file(formatter['resolved'])
        tracer_fd = store.open_file(tracer['resolved'])
        if fd_identity(exe) != formatter['identity'] or fd_identity(tracer_fd) != tracer['identity']:
            fail('formatter/tracer descriptor differs')
        injection = []
        if 'fault.json' in _entries(store.private):
            fault = parse_canonical(store.read('fault.json',4096))
            exact(fault,('version','id','generation','barrier'),'qualification fault')
            digest(fault['id'])
            integer(fault['version'],1,1,'qualification version')
            integer(fault['generation'],0,2**64-1,'qualification generation')
            if fault['barrier'] not in BARRIERS:
                fail('qualification barrier differs')
            if fault['barrier'] == 'FORMAT_RUNNING' and fault['generation'] == state['previousGeneration']:
                injection = ['--inject=pwrite64:signal=SIGSTOP:when=1']
        pipe = os.pipe2(os.O_CLOEXEC)
        try:
            run_process([f'/proc/self/fd/{tracer_fd}','-f','-qq','-s','256','-v','-y','-e',
                'trace=execve,stat,newfstatat,fstat,openat,openat2,write,pwrite64,writev,pwritev,ioctl,close','-o',f'/proc/self/fd/{pipe[1]}',
                *injection,'--',f'/proc/self/fd/{exe}',*argv],timeout=min(35,store.deadline-time.monotonic()),
                pass_fds=(loop_fd,exe,tracer_fd,pipe[1],store.lock),capture_pipe=pipe,capture_sink=trace,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C',
                    'MKE2FS_CONFIG':str(CONFIG_FILE),'E2FSPROGS_UNDO_DIR':'none'})
        finally:
            # Even refusal retains the actual bounded trace; overflow never
            # produces a successful formatter record.
            if len(trace) <= MAX_TRACE:
                write_diagnostic(store,'formatter.trace',bytes(trace))
            store.drop(exe); store.drop(tracer_fd)
        store.verify_manifest()
        service_census(store,os.environ.get('INVOCATION_ID'))
    else:
        store.command('mke2fs',argv,pass_fds=(loop_fd,),formatter=True)
    os.fsync(loop_fd); os.fsync(image_fd)
    if loop_identity(state['loop']['path'],state['owner'],loop_fd) != state['loop'] or superblock(loop_fd) != state['targetUuid']:
        fail('formatted filesystem identity differs')
    result = {'exitCode':0,'uuid':state['targetUuid'],'traceSha256':sha256(bytes(trace)),
              'traceBytes':len(trace),'argvSha256':sha256(canonical(argv))}
    store.barrier('FORMAT_FLUSHED',state)
    return result


def prepare_candidate(store,state,loop_fd):
    gate_closed(store,state)
    current_inventory(state,{})
    verify_underlying(store,state)
    if superblock(loop_fd) != state['targetUuid']:
        fail('formatted candidate UUID differs')
    name = generation_path(state['targetGeneration']).name
    # A crash before MOUNT_INTENT leaves an unregistered target. Preserve it and
    # refuse rather than adopting a merely matching directory name.
    os.mkdir(name,0,dir_fd=store.public)
    gate = store.open_dir(name,store.public)
    os.mkdir('scratch',0,dir_fd=gate)
    scratch = store.open_dir('scratch',gate)
    os.fsync(scratch); os.fsync(gate); os.fsync(store.public)
    candidate = {'generation':state['targetGeneration'],'gate':fd_identity(gate),
        'underlying':fd_identity(scratch),'mount':None,'root':None,'uuid':state['targetUuid']}
    store.drop(scratch); store.drop(gate)
    return store.publish(state,phase='MOUNT_INTENT',candidate=candidate)


def mount_candidate(store,state,loop_fd):
    candidate = state['candidate']
    gate = open_gate(store,candidate['generation'],candidate['gate'],(0,))
    path = generation_path(candidate['generation'])/'scratch'
    rows = mount_table()
    matches = [r for r in rows if r['path'] == str(path)]
    if not matches:
        current_inventory(state,{})
        underlying = store.open_dir('scratch',gate)
        if fd_identity(underlying) != candidate['underlying'] or _entries(underlying):
            fail('candidate underlying mount intent changed')
        store.drop(underlying)
        store.command('mount',['--no-canonicalize','-t','ext4','-o',','.join(FLAGS),
            f'/proc/self/fd/{loop_fd}',str(path)],pass_fds=(loop_fd,))
        store.barrier('CANDIDATE_MOUNTED',state)
    root_fd = store.open_dir('scratch',gate)
    root = fd_identity(root_fd)
    rows = current_inventory(state,{str(path):None if candidate['mount'] is None else candidate['mount']['id']})
    row = mount_at(rows,path,root)
    verify_mount(row,root,state['loop'],path)
    if row['parent'] != state['parentMount']['id'] or superblock(loop_fd) != candidate['uuid']:
        fail('candidate mount provenance differs')
    if candidate['mount'] is not None and (row != candidate['mount'] or not same_object(root,candidate['root'],metadata=False)):
        fail('recorded candidate was replaced')
    if root['uid'] not in (0,state['owner']['uid']) or root['gid'] not in (0,state['owner']['gid']):
        fail('private fresh root owner differs')
    entries = _entries(root_fd,2)
    if entries == ['lost+found']:
        lost = store.open_dir('lost+found',root_fd)
        obj = fd_identity(lost)
        if obj['uid'] != 0 or obj['gid'] != 0 or obj['mode'] != 0o700 or obj['mountId'] != root['mountId'] or _entries(lost):
            fail('fresh lost+found is not known empty root directory')
        store.drop(lost)
        os.rmdir('lost+found',dir_fd=root_fd)
    elif entries:
        fail('private candidate contains unknown data')
    os.fchown(root_fd,state['owner']['uid'],state['owner']['gid']); os.fchmod(root_fd,0o700); os.fsync(root_fd)
    root = fd_identity(root_fd)
    if (root['uid'],root['gid'],root['mode']) != (state['owner']['uid'],state['owner']['gid'],0o700):
        fail('fresh candidate owner change failed')
    candidate = dict(candidate,mount=row,root=root)
    store.drop(root_fd); store.drop(gate)
    service_census(store,os.environ.get('INVOCATION_ID'))
    return store.publish(state,phase='READY_PRIVATE',candidate=candidate)


def service_run(store,state):
    invocation = os.environ.get('INVOCATION_ID')
    group = service_census(store,invocation)
    store.service = True
    if state['phase'] in ('REGISTERED','EXPOSURE_INTENT','PUBLISHED') or state['submission']['state'] not in ('PENDING','ACKNOWLEDGED'):
        fail('custodian invocation has no unconsumed pending intent')
    custodian = {'invocation':invocation,'pid':os.getpid(),'startTicks':process_start(os.getpid()),
        'cgroup':CGROUP,'cgroupIdentity':group}
    state = store.publish(state,custodian=custodian,submission={'state':'ENTERED','job':state['submission']['job'],'invocation':invocation})
    if state['phase'] == 'INTENT':
        store.barrier('INTENT_FSYNC',state)
    image_fd, loop_fd = verify_base(store,state)
    state = retire_old(store,state) if state['phase'] in ('INTENT','FENCED') else state
    if state['phase'] == 'UNMOUNTED':
        state = store.publish(state,phase='FORMAT_STARTED')
        store.barrier('FORMAT_STARTED',state)
    if state['phase'] == 'FORMAT_STARTED':
        result = format_once(store,state,loop_fd,image_fd)
        state = store.publish(state,phase='FORMATTED',formatter=result)
    if state['phase'] == 'FORMATTED':
        state = prepare_candidate(store,state,loop_fd)
    if state['phase'] == 'MOUNT_INTENT':
        state = mount_candidate(store,state,loop_fd)
    if state['phase'] != 'READY_PRIVATE':
        fail('custodian did not reach private ready phase')
    verify_live_generation(store,state,state['candidate'],gate_modes=(0,),
        root_modes=((state['owner']['uid'],state['owner']['gid'],0o700),))
    if superblock(loop_fd) != state['targetUuid']:
        fail('ready filesystem UUID differs')
    service_census(store,invocation)
    return state


def finalize(store,state,intent):
    if state['intentId'] != intent or state['phase'] not in ('READY_PRIVATE','EXPOSURE_INTENT','PUBLISHED'):
        fail('intent has no publishable private generation')
    inactive_snapshot(store,state,successful=True)
    image_fd,loop_fd = verify_base(store,state)
    gate_closed(store,state)
    candidate = state['candidate']
    gate,root_fd,_ = verify_live_generation(store,state,candidate,
        gate_modes=(0,) if state['phase'] == 'READY_PRIVATE' else (0,0o711),
        root_modes=((state['owner']['uid'],state['owner']['gid'],0o700),))
    if superblock(loop_fd) != candidate['uuid']:
        fail('publication UUID differs')
    # Do not inspect candidate entries here: EXPOSURE_INTENT may already have
    # admitted a valid lease, whose record and contents must survive finalize.
    if state['phase'] == 'READY_PRIVATE':
        state = store.publish(state,phase='EXPOSURE_INTENT')
        store.barrier('EXPOSURE_INTENT',state)
    if state['phase'] == 'EXPOSURE_INTENT':
        os.fchmod(gate,0o711); os.fsync(gate)
        store.barrier('GATE_OPENED',state)
        state = store.publish(state,phase='PUBLISHED',generation=state['targetGeneration'])
    elif fd_identity(gate)['mode'] != 0o711:
        fail('published generation gate is no longer open')
    return state


def parse_cli(argv):
    if not isinstance(argv,(list,tuple)) or not argv or any(not isinstance(v,str) for v in argv):
        fail('usage: status | request GENERATION | resume INTENT | finalize INTENT | service-run')
    argv = list(argv)
    if argv in (['status'],['service-run']):
        return argv[0],None
    if len(argv) == 2 and argv[0] == 'request' and re.fullmatch(r'0|[1-9][0-9]{0,19}',argv[1]):
        number = int(argv[1]); integer(number,0,2**64-2,'generation'); return argv[0],number
    if len(argv) == 2 and argv[0] in ('resume','finalize') and HEX64.fullmatch(argv[1]):
        return argv[0],argv[1]
    fail('invalid closed action arguments')


def main(argv=None):
    try:
        action,argument = parse_cli(list(sys.argv[1:] if argv is None else argv))
    except (ResetError,ValueError,TypeError) as error:
        print(canonical({'ok':False,'error':str(error)[:512],'disposition':'RESERVED'}).decode())
        return 64
    if os.geteuid() != 0:
        print(canonical({'ok':False,'error':'root controller required','disposition':'RESERVED'}).decode())
        return 77
    try:
        if Path(__file__).resolve() != INSTALLED:
            fail('execute only installed root-owned controller')
        with opened_store(wait=5 if action == 'service-run' else 0) as store:
            state = store.load()
            if action == 'request':
                state = request(store,state,argument)
            elif action == 'resume':
                state = resume(store,state,argument)
            elif action == 'finalize':
                state = finalize(store,state,argument)
            elif action == 'service-run':
                state = service_run(store,state)
            else:
                verify_base(store,state)
            output = {'ok':True,'state':state,'receipt':receipt(state)}
            data = canonical(output)
            if len(data) > MAX_RECORD:
                fail('response exceeds bound')
            print(data.decode())
            return 0
    except (ResetError,OSError,ValueError,KeyError,TypeError) as error:
        print(canonical({'ok':False,'error':str(error)[:512],'disposition':'RESERVED'}).decode())
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
