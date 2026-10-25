#!/usr/bin/python3
"""Trusted hosted bootstrap for the single reviewed ext4 reset qualification slot.

This file is not a reset API. It accepts no caller paths, users, capacities or
commands and refuses all preexisting installation state. No rollback by name is
attempted: interrupted setup remains unavailable for explicit host disposal.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import grp
import re
import stat
import sys
import time
import types
import uuid

ROOT = Path('/var/lib/decomp-oracle-ext4-reset-ci')
PRIVATE = ROOT / 'private'
PUBLIC = ROOT / 'public'
UNIT_NAME = 'decomp-oracle-ext4-reset-ci.service'
UNIT_FILE = Path('/etc/systemd/system') / UNIT_NAME
RETENTION_NAME = 'decomp-oracle-ext4-reset-retain.target'
RETENTION_FILE = UNIT_FILE.parent / RETENTION_NAME
IMAGE_BYTES = 67108864
MAX_SOURCE = 2 * 1024 * 1024
MAX_CAPTURE = 65536
MAX_MANIFEST = 65536
MAX_CLOSURE = 64
OWNER = {'uid': 65534, 'gid': 65534, 'groups': []}
PACKAGES = ('e2fsprogs', 'libext2fs2t64', 'systemd', 'python3-minimal')
FORMATTER_VERSIONS = ('1.47.0-2.4~exp1ubuntu4', '1.47.0-2.4~exp1ubuntu4.1')
TOOL_PATHS = {
    'mke2fs': '/usr/sbin/mke2fs', 'mount': '/usr/bin/mount',
    'umount': '/usr/bin/umount', 'systemctl': '/usr/bin/systemctl',
    'busctl': '/usr/bin/busctl', 'strace': '/usr/bin/strace',
    'losetup': '/usr/sbin/losetup', 'unshare': '/usr/bin/unshare',
    'setpriv': '/usr/bin/setpriv', 'python': '/usr/bin/python3',
}
SOURCE_PATHS = (
    '.github/workflows/ci.yml',
    'scripts/oracle-ext4-reset.py',
    'scripts/oracle-ext4-reset-profile.json',
    'scripts/oracle-ext4-reset-mke2fs.conf',
    'scripts/systemd/decomp-oracle-ext4-reset-ci.service',
    'scripts/systemd/decomp-oracle-ext4-reset-retain.target',
    'scripts/ci-oracle-ext4-reset.py',
    'scripts/oracle-ext4-reset-install.py',
    'scripts/oracle-ext4-reset-fixture-mutations.py',
    'scripts/verify-oracle-ext4-reset.py',
    'src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt',
    'src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchResetMountedTest.kt',
    'src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchResetProbe.kt',
)
INSTALL_FILES = {
    'scripts/oracle-ext4-reset.py': 'oracle-ext4-reset.py',
    'scripts/ci-oracle-ext4-reset.py': 'ci-oracle-ext4-reset.py',
    'scripts/oracle-ext4-reset-install.py': 'oracle-ext4-reset-install.py',
    'scripts/oracle-ext4-reset-fixture-mutations.py': 'oracle-ext4-reset-fixture-mutations.py',
    'scripts/oracle-ext4-reset-mke2fs.conf': 'mke2fs.conf',
}
APT_BOUNDARY = 'requires-successful-signature-enforced-workflow-apt-install'


class InstallError(RuntimeError):
    pass


def fail(message):
    raise InstallError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum, *, trusted=False):
    """No blocking FIFO open, symlink traversal, unstable read or oversized data."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail('expected singly linked regular file')
        if before.st_size > maximum or before.st_size < 0:
            fail('file exceeds capture bound')
        if trusted and (before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o022):
            fail('installed input is not root controlled')
        data = bytearray()
        while len(data) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        if len(data) > maximum or any(getattr(before, k) != getattr(after, k) or
                                     getattr(before, k) != getattr(current, k) for k in keys):
            fail('file changed during bounded capture')
        return bytes(data)
    finally:
        os.close(fd)


def require_root_ancestry(path):
    for member in (*reversed(path.parents), path):
        value = member.lstat()
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or
                stat.S_IMODE(value.st_mode) & 0o022 or member.resolve() != member):
            fail('deployment ancestry is not root controlled')


def trusted_executable(path):
    path = Path(path)
    resolved = path.resolve(strict=True)
    require_root_ancestry(resolved.parent)
    data = read_regular(resolved, 64 * 1024 * 1024, trusted=True)
    if not os.stat(resolved).st_mode & 0o111:
        fail('trusted utility is not executable')
    return resolved, data


def absent(path):
    if os.path.lexists(path):
        fail('installation refuses preexisting state: ' + str(path))


def validate_owner():
    account = pwd.getpwuid(OWNER['uid'])
    group = grp.getgrgid(OWNER['gid'])
    if account.pw_name != 'nobody' or account.pw_gid != OWNER['gid'] or group.gr_name != 'nogroup':
        fail('host does not have the admitted oracle principal')
    if any('nobody' in item.gr_mem and item.gr_gid != OWNER['gid'] for item in grp.getgrall()):
        fail('oracle account has supplementary host groups')
    return dict(OWNER, groups=[])


def parse_package_query(raw, expected):
    try:
        fields = raw.decode('ascii').removesuffix('\n').split('\t')
    except UnicodeError as error:
        raise InstallError('package query is not ASCII') from error
    if len(fields) != 6 or any('\n' in field or '\r' in field for field in fields):
        fail('package query shape differs')
    name, version, source, source_version, architecture, status = fields
    if name != expected or architecture != 'amd64' or status != 'install ok installed':
        fail('package is not the admitted installed amd64 package')
    for value in (name, version, source, source_version):
        if not value or len(value) > 256 or not re.fullmatch(r'[A-Za-z0-9.+:~_-]+', value):
            fail('package identity is malformed')
    if expected in ('e2fsprogs', 'libext2fs2t64') and (
            source != 'e2fsprogs' or source_version not in FORMATTER_VERSIONS or version != source_version):
        fail('formatter package/source version is unreviewed')
    return dict(binaryPackage=name, version=version, sourcePackage=source,
                sourceVersion=source_version, architecture=architecture, status=status)


def parse_apt_metadata(raw, package):
    """Capture a single version-selected APT stanza; no candidate substitution."""
    try:
        text = raw.decode('utf-8')
    except UnicodeError as error:
        raise InstallError('APT metadata encoding differs') from error
    if not text or len(raw) > MAX_CAPTURE or '\x00' in text:
        fail('APT metadata is absent or oversized')
    stanzas = [entry for entry in text.strip().split('\n\n') if entry]
    if len(stanzas) != 1:
        fail('APT metadata does not identify exactly one archive')
    fields = {}
    prior = None
    for line in stanzas[0].splitlines():
        if line.startswith((' ', '\t')):
            if prior is None:
                fail('APT continuation has no field')
            continue
        match = re.fullmatch(r'([A-Za-z0-9-]+): (.*)', line)
        if not match or match[1] in fields:
            fail('APT metadata repeats or corrupts a field')
        prior = match[1]
        fields[prior] = match[2]
    if fields.get('Package') != package['binaryPackage'] or fields.get('Version') != package['version'] or fields.get('Architecture') != 'amd64':
        fail('APT archive identity differs from installed package')
    archive_sha = fields.get('SHA256', '')
    if not re.fullmatch(r'[0-9a-f]{64}', archive_sha):
        fail('APT archive SHA256 is absent')
    return text, archive_sha


def parse_ldd(raw):
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise InstallError('dynamic closure is not ASCII') from error
    paths = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r'linux-vdso\.so\.[0-9]+ \(0x[0-9a-f]+\)', line):
            continue
        match = re.fullmatch(r'(?:[^\s/]+ => )?(/[^\s]+) \(0x[0-9a-f]+\)', line)
        if not match:
            fail('dynamic closure contains an unresolved or unknown entry')
        path = Path(match[1])
        if not str(path).startswith(('/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/')) or '..' in path.parts:
            fail('dynamic closure is outside trusted library roots')
        paths.add(path)
    if not paths or len(paths) > MAX_CLOSURE:
        fail('dynamic closure is absent or exceeds bound')
    return paths


def _run(core, argv, *, deadline, pass_fds=(), maximum=MAX_CAPTURE, env=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        fail('installation deadline expired')
    return core.run_process(list(map(str, argv)), timeout=min(35, remaining),
                            pass_fds=pass_fds, maximum_output=maximum, env=env)[0]


def capture_package_provenance(core, tools, *, deadline):
    for path in ('/usr/bin/dpkg-query', '/usr/bin/dpkg', '/usr/bin/apt-cache'):
        trusted_executable(path)
    packages = {}
    for name in PACKAGES:
        query = _run(core, ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\t${Status}\n', name], deadline=deadline)
        value = parse_package_query(query, name)
        verified = _run(core, ['/usr/bin/dpkg', '--verify', name], deadline=deadline)
        if verified:
            fail('installed package verification reports modifications')
        metadata = _run(core, ['/usr/bin/apt-cache', 'show', name + '=' + value['version']], deadline=deadline)
        metadata_text, archive_sha = parse_apt_metadata(metadata, value)
        policy = _run(core, ['/usr/bin/apt-cache', 'policy', name], deadline=deadline)
        policy_text = policy.decode('utf-8')
        if not policy_text or len(policy) > MAX_CAPTURE or '\x00' in policy_text:
            fail('APT policy capture differs')
        value.update(verifyOutputSha256=digest(verified), aptMetadata=metadata_text,
                     aptMetadataSha256=digest(metadata), aptPolicy=policy_text,
                     aptPolicySha256=digest(policy), aptArchiveSha256=archive_sha)
        packages[name] = value
    systemd = _run(core, [tools['systemctl'], '--version'], deadline=deadline).decode('ascii')
    python = _run(core, [tools['python'], '--version'], deadline=deadline).decode('ascii')
    if not systemd.startswith('systemd 255 ') or not python.startswith('Python 3.') or platform.machine() != 'x86_64':
        fail('host manager/interpreter/machine profile is unreviewed')
    result = {'schemaVersion': 1, 'machine': platform.machine(), 'kernelRelease': platform.release(),
              'systemdVersion': systemd, 'pythonVersion': python, 'packages': packages,
              'formatterSource': {'upstreamCommit': '25ad8a431331b4d1d444a70b6079456cc612ac40',
                  'originalArchiveSha256': '6667afde56eef0c6af26684974400e4d2288ea49e9441bf5e6229195d51a3578',
                  'distributionPatchReview': 'no-reviewed-formatter-files-modified'},
              'aptAuthenticationBoundary': APT_BOUNDARY}
    if len(canonical(result)) > 32768:
        fail('package provenance exceeds its bound')
    return result


def capture_tool_closure(core, tools, *, deadline):
    trusted_executable('/usr/bin/ldd')
    closure = set()
    for path in tools.values():
        resolved, data = trusted_executable(path)
        if data[:5] != b'\x7fELF\x02':
            fail('utility is not the admitted ELF64 executable')
        closure.add(resolved)
        output = _run(core, ['/usr/bin/ldd', str(resolved)], deadline=deadline)
        for library in parse_ldd(output):
            resolved_library = library.resolve(strict=True)
            require_root_ancestry(resolved_library.parent)
            read_regular(resolved_library, 64 * 1024 * 1024, trusted=True)
            closure.add(resolved_library)
        if len(closure) > MAX_CLOSURE:
            fail('tool closure exceeds manifest bound')
    return sorted(closure, key=str)


def source_snapshot(core, repository, *, deadline):
    if repository != Path(__file__).resolve().parent.parent or Path(__file__).name != 'oracle-ext4-reset-install.py':
        fail('bootstrap must run from its checked-in source location')
    files = {name: read_regular(repository / name, MAX_SOURCE) for name in SOURCE_PATHS}
    commit = _run(core, ['/usr/bin/git', '-c', 'safe.directory=' + str(repository), '-C', str(repository), 'rev-parse', '--verify', 'HEAD'], deadline=deadline).decode('ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        fail('checkout source commit is not canonical')
    # A root-owned installed deployment is bound to exact captured source bytes;
    # a checked-out commit name alone never authenticates changed worktree files.
    for name, content in files.items():
        expected = _run(core, ['/usr/bin/git', '-c', 'safe.directory=' + str(repository), '-C', str(repository), 'show', commit + ':' + name], deadline=deadline, maximum=MAX_SOURCE)
        if expected != content:
            fail('bootstrap source differs from checkout commit: ' + name)
    return commit, {name: digest(content) for name, content in files.items()}, files


def _load_core(path):
    data = read_regular(path, MAX_SOURCE)
    module = types.ModuleType('oracle_ext4_reset_install_core')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    module.__loaded_source_sha256__ = digest(data)
    return module


def create_file(directory_fd, name, data, mode=0o400):
    if '/' in name or name in ('', '.', '..'):
        fail('installed file name is not a closed component')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=directory_fd)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail('installed file write made no progress')
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)


def mkdir_exact(path, mode):
    os.mkdir(path, mode)
    os.chown(path, 0, 0)
    os.chmod(path, mode)
    created = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(created)
    finally:
        os.close(created)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def install():
    if os.geteuid() != 0:
        fail('trusted bootstrap requires root')
    absent(ROOT)
    absent(UNIT_FILE)
    absent(RETENTION_FILE)
    require_root_ancestry(ROOT.parent)
    require_root_ancestry(UNIT_FILE.parent)
    owner = validate_owner()
    repository = Path(__file__).resolve().parent.parent
    core = _load_core(repository / 'scripts/oracle-ext4-reset.py')
    deadline = time.monotonic() + 180
    tools = dict(TOOL_PATHS)
    for path in (*tools.values(), '/usr/bin/git'):
        trusted_executable(path)
    commit, source_hashes, source_files = source_snapshot(core, repository, deadline=deadline)
    if source_hashes['scripts/oracle-ext4-reset.py'] != core.__loaded_source_sha256__:
        fail('executed bootstrap core differs from captured source')
    production_profile = json.loads(source_files['scripts/oracle-ext4-reset-profile.json'])
    if production_profile != core.profile_document(False):
        fail('checked profile differs from executable profile')
    provenance = capture_package_provenance(core, tools, deadline=deadline)
    closure = capture_tool_closure(core, tools, deadline=deadline)
    # All prerequisite observations precede the first installation mutation.
    mkdir_exact(ROOT, 0o755)
    underlying_root = core.file_identity(ROOT)
    _run(core, [tools['mount'], '--bind', str(ROOT), str(ROOT)], deadline=deadline)
    _run(core, [tools['mount'], '--make-private', str(ROOT)], deadline=deadline)
    parent_rows = [row for row in core.mount_table() if row['path'] == str(ROOT)]
    if len(parent_rows) != 1 or parent_rows[0]['optional']:
        fail('owned private parent mount was not established')
    mkdir_exact(PRIVATE, 0o700)
    mkdir_exact(PUBLIC, 0o755)
    mkdir_exact(PRIVATE / 'quarantine', 0o000)
    gate = PUBLIC / 'g-0000000000000000'
    mkdir_exact(gate, 0o000)
    scratch = gate / 'scratch'
    mkdir_exact(scratch, 0o000)
    underlying_scratch = core.file_identity(scratch)
    private_fd = os.open(PRIVATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for source, destination in INSTALL_FILES.items():
            create_file(private_fd, destination, source_files[source])
        profile = core.canonical(core.profile_document(True))
        create_file(private_fd, 'profile.json', profile)
        create_file(private_fd, 'lock', b'', 0o600)
        unit_parent = os.open(UNIT_FILE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            create_file(unit_parent, UNIT_NAME, source_files['scripts/systemd/' + UNIT_NAME], 0o644)
            create_file(unit_parent, RETENTION_NAME, source_files['scripts/systemd/' + RETENTION_NAME], 0o644)
        finally:
            os.close(unit_parent)
        image_fd = os.open('image', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=private_fd)
        try:
            os.fchown(image_fd, 0, 0)
            os.fchmod(image_fd, 0o600)
            os.posix_fallocate(image_fd, 0, IMAGE_BYTES)
            os.fsync(image_fd)
            output = _run(core, [tools['losetup'], '--find', '--show', '--nooverlap', '--offset', '0',
                                '--sizelimit', str(IMAGE_BYTES), '--sector-size', '512', f'/proc/self/fd/{image_fd}'],
                          deadline=deadline, pass_fds=(image_fd,))
            loop = output.decode('ascii').removesuffix('\n')
            if not re.fullmatch(r'/dev/loop[0-9]{1,6}', loop):
                fail('loop allocation returned an unrecognized identity')
            loop_identity = core.loop_identity(loop, owner=owner)
            image_identity = core.file_identity(PRIVATE / 'image')
            if (loop_identity['backingDevice'], loop_identity['backingInode']) != (image_identity['device'], image_identity['inode']):
                fail('new loop does not bind the exact private image')
            loop_fd = os.open(loop, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                filesystem_uuid = str(uuid.uuid4())
                env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                       'MKE2FS_CONFIG': str(PRIVATE / 'mke2fs.conf'), 'E2FSPROGS_UNDO_DIR': 'none'}
                _run(core, [tools['mke2fs'], *core.formatter_argv(loop_fd, filesystem_uuid)],
                     deadline=deadline, pass_fds=(loop_fd,), env=env)
                os.fsync(loop_fd)
                os.fsync(image_fd)
                _run(core, [tools['mount'], '-t', 'ext4', '-o', 'rw,nodev,nosuid,noexec,noatime', loop, str(scratch)], deadline=deadline)
                root_fd = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    if sorted(os.listdir(root_fd)) != ['lost+found']:
                        fail('new filesystem has unexpected initial contents')
                    lost_fd = os.open('lost+found', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
                    try:
                        if os.listdir(lost_fd):
                            fail('new lost+found is not empty')
                    finally:
                        os.close(lost_fd)
                    os.rmdir('lost+found', dir_fd=root_fd)
                    os.fchown(root_fd, owner['uid'], owner['gid'])
                    os.fchmod(root_fd, 0o700)
                    os.fsync(root_fd)
                finally:
                    os.close(root_fd)
                installed_extra = [PRIVATE / name for name in INSTALL_FILES.values()] + [RETENTION_FILE]
                manifest = core.capture_manifest(owner, tools, [*closure, *installed_extra], provenance)
                manifest_bytes = core.canonical(manifest)
                if len(manifest_bytes) > MAX_MANIFEST:
                    fail('installed manifest exceeds qualification artifact bound')
                create_file(private_fd, 'manifest.json', manifest_bytes)
                _run(core, [tools['systemctl'], 'daemon-reload'], deadline=deadline)
                _run(core, [tools['systemctl'], 'start', RETENTION_NAME], deadline=deadline)
                # Keep this ordering-only target active through VM disposal.
                # register_initial persists the closed gate before opening it.
                state = core.register_initial(owner, loop, underlying_root, underlying_scratch)
            finally:
                os.close(loop_fd)
        finally:
            os.close(image_fd)
        return {'schemaVersion': 1, 'owner': owner, 'sourceCommit': commit,
                'sourceHashes': source_hashes, 'profileSha256': digest(profile),
                'installedManifestSha256': digest(manifest_bytes), 'initialState': state,
                'loopNode': loop, 'repository': str(repository)}
    finally:
        os.close(private_fd)


def main():
    if sys.argv[1:] != ['install']:
        print('only the fixed install action is supported', file=sys.stderr)
        return 64
    try:
        result = install()
        sys.stdout.buffer.write(canonical(result) + b'\n')
        return 0
    except (InstallError, OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
