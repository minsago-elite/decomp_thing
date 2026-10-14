#!/usr/bin/env python3
"""Offline CI fixture clone of the already selected build JDK. Never installs a JDK."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import uuid
from itertools import islice
from collections import deque

MAX_ENTRIES = 20000
MAX_BYTES = 4 * 1024**3
MAX_DEPTH = 64
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC
# Longest default-java.io.tmpdir bind suffix among the six audited Unix socket fixtures.
# NativeMeasurementFixture uses its separate explicit build/nrm parent.
SOCKET_FIXTURE_SUFFIX = '/pinned-docker-runtime-' + '9' * 20 + '/runtime/docker.sock'
UNIX_SOCKET_PATH_BYTES = 107


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode), value.st_size, value.st_mtime_ns)


def credentials(text, pid):
    require(len(text) <= 65536, 'caller status oversized')
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(':')
        if key in ('Pid', 'Uid', 'Gid'):
            require(key not in fields, 'duplicate caller identity')
            fields[key] = value.split()
    require(fields.get('Pid') == [str(pid)], 'caller PID mismatch')
    result = {}
    for key in ('Uid', 'Gid'):
        values = fields.get(key, [])
        require(len(values) == 4 and all(re.fullmatch(r'[0-9]{1,10}', x) for x in values), 'caller credentials unavailable')
        result[key] = ','.join(values)
    return result


def caller_credentials():
    fd = os.open('/proc/self/status', os.O_RDONLY | os.O_CLOEXEC)
    try:
        data = os.read(fd, 65537)
        require(len(data) <= 65536, 'caller status oversized')
        result = credentials(data.decode('ascii'), os.getpid())
    finally:
        os.close(fd)
    require(list(map(int, result['Uid'].split(',')))[:3] == list(os.getresuid()), 'caller UID authority mismatch')
    require(list(map(int, result['Gid'].split(',')))[:3] == list(os.getresgid()), 'caller GID authority mismatch')
    return result


def secure_directory(path):
    require(path.is_absolute() and path == path.resolve(strict=True), 'noncanonical owned directory')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    value = os.fstat(fd)
    try:
        require(value.st_uid == os.geteuid() and not stat.S_IMODE(value.st_mode) & 0o022, 'unowned or writable directory')
        return fd
    except BaseException:
        os.close(fd); raise


def socket_scratch(repo):
    # The hosted canonical checkout is43bytes; even a one-character child is too long.
    # Temp APIs create fresh independent files/directories here, without any short alias.
    require(len(os.fsencode(repo)) + len(SOCKET_FIXTURE_SUFFIX.encode('ascii')) <= UNIX_SOCKET_PATH_BYTES,
            'repository path exceeds audited Unix socket fixture byte budget')
    fd = secure_directory(repo)
    try:
        value = os.fstat(fd)
        return {'path': str(repo), 'dev': value.st_dev, 'ino': value.st_ino, 'uid': value.st_uid,
                'mode': stat.S_IMODE(value.st_mode), 'maximumSocketSuffix': SOCKET_FIXTURE_SUFFIX,
                'maximumSocketPathBytes': UNIX_SOCKET_PATH_BYTES}
    finally:
        os.close(fd)


def validate_link_graph(entries):
    """Resolve only the closed nofollow inventory, never ambient filesystem paths."""
    work = 0
    for key, entry in entries.items():
        if entry['kind'] != 'link':
            continue
        require(entry['target'] and not entry['target'].startswith('/'), 'JDK absolute symlink refused')
        stack = key.split('/')[:-1]
        pending = deque(entry['target'].split('/'))
        followed = 1
        while pending:
            work += 1
            require(work <= MAX_ENTRIES * MAX_DEPTH, 'JDK symlink work bound')
            if stack:
                require(entries['/'.join(stack)]['kind'] == 'directory', 'JDK symlink non-directory component')
            component = pending.popleft()
            if component in ('', '.'):
                continue
            if component == '..':
                require(stack, 'JDK symlink escapes root')
                stack.pop()
                continue
            candidate = '/'.join([*stack, component])
            require(candidate in entries, 'JDK dangling symlink')
            target = entries[candidate]
            if target['kind'] == 'link':
                followed += 1
                require(followed <= MAX_DEPTH, 'JDK symlink chain/cycle bound')
                link = target['target']
                require(link and not link.startswith('/'), 'JDK absolute symlink refused')
                pending.extendleft(reversed(link.split('/')))
            else:
                stack.append(component)
        # A link to the inventory root is allowed; it is still inside the clone.


def inventory_links(root):
    entries = {}
    def visit(fd, prefix, depth):
        require(depth <= MAX_DEPTH, 'JDK depth bound')
        before = identity(os.fstat(fd))
        with os.scandir(fd) as listing:
            names = [entry.name for entry in islice(listing, MAX_ENTRIES + 1)]
        require(len(names) <= MAX_ENTRIES, 'JDK directory bound')
        for name in sorted(names):
            require(name not in ('.','..') and '/' not in name, 'invalid JDK entry')
            require(len(entries) < MAX_ENTRIES, 'JDK entry bound')
            key = prefix + name
            value = os.stat(name,dir_fd=fd,follow_symlinks=False)
            kind = 'link' if stat.S_ISLNK(value.st_mode) else 'directory' if stat.S_ISDIR(value.st_mode) else 'file' if stat.S_ISREG(value.st_mode) else None
            require(kind is not None, 'JDK special file refused')
            entry = {'kind':kind,'identity':identity(value)}
            entries[key] = entry
            if kind == 'link':
                link = os.readlink(name,dir_fd=fd)
                require(len(os.fsencode(link)) <= 4096, 'JDK symlink bound')
                require(link and not link.startswith('/'), 'JDK absolute symlink refused')
                entry['target'] = link
            elif kind == 'directory':
                child = os.open(name,os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW,dir_fd=fd)
                try:
                    require(identity(os.fstat(child)) == identity(value), 'JDK source directory replaced')
                    visit(child,key+'/',depth+1)
                finally:
                    os.close(child)
            require(identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) == identity(value), 'JDK source entry changed')
        require(identity(os.fstat(fd)) == before, 'JDK source directory changed')
    visit(root,'',0)
    validate_link_graph(entries)
    return entries


def provision(repo: Path, source: Path):
    repo = repo.resolve(strict=True)
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(repo)) is not None, 'CI workspace path is not a safe JVM option path')
    source = source.resolve(strict=True)
    require(source != repo and not repo.is_relative_to(source), 'JDK source contains workspace')
    # Existing build is checked, never chmodded. New state is always repository-local.
    build = repo / 'build'
    if not build.exists():
        build.mkdir(mode=0o700)
    with_fd = secure_directory(build)
    try:
        name = 'ci-jdk-' + str(uuid.uuid4())
        os.mkdir(name, mode=0o700, dir_fd=with_fd)
    finally:
        os.close(with_fd)
    container = build / name
    clone = container / 'jdk'
    clone.mkdir(mode=0o700)
    records = {}
    count = total = 0
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    try:
        target_fd = secure_directory(clone)
    except BaseException:
        os.close(source_fd); raise
    source_root = identity(os.fstat(source_fd))
    target_device = os.fstat(target_fd).st_dev

    def copy_tree(src, dst, relative, depth):
        nonlocal count, total
        require(depth <= MAX_DEPTH, 'JDK depth bound')
        before = identity(os.fstat(src))
        with os.scandir(src) as listing:
            names = [entry.name for entry in islice(listing, MAX_ENTRIES + 1)]
        require(len(names) <= MAX_ENTRIES, 'JDK directory bound')
        for name in sorted(names):
            require(name not in ('.', '..') and '/' not in name, 'invalid JDK entry')
            count += 1
            require(count <= MAX_ENTRIES, 'JDK entry bound')
            key = relative + name
            entry = os.stat(name, dir_fd=src, follow_symlinks=False)
            require(key in inventory and identity(entry) == inventory[key]['identity'], 'JDK preflight inventory changed')
            if stat.S_ISLNK(entry.st_mode):
                link = os.readlink(name, dir_fd=src)
                require(len(os.fsencode(link)) <= 4096, 'JDK symlink bound')
                require(link == inventory[key].get('target'), 'JDK symlink changed after admission')
                os.symlink(link, name, dir_fd=dst)
                records[key] = {'kind': 'link', 'identity': identity(entry), 'target': link}
            elif stat.S_ISDIR(entry.st_mode):
                os.mkdir(name, mode=0o700, dir_fd=dst)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=src)
                try:
                    copied = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=dst)
                except BaseException:
                    os.close(child); raise
                try:
                    require(identity(os.fstat(child)) == identity(entry), 'JDK source directory replaced')
                    require(os.fstat(copied).st_dev == target_device and os.fstat(copied).st_uid == os.geteuid(), 'owned JDK mount/owner changed')
                    copy_tree(child, copied, key + '/', depth + 1)
                    # Only owned copy directories are normalized; symlink data is never followed.
                    os.fchmod(copied, (stat.S_IMODE(entry.st_mode) & ~0o022) | 0o500)
                finally:
                    os.close(child); os.close(copied)
                records[key] = {'kind': 'directory', 'identity': identity(entry)}
            elif stat.S_ISREG(entry.st_mode):
                original = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=src)
                try:
                    copied = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=dst)
                except BaseException:
                    os.close(original); raise
                try:
                    require(not stat.S_IMODE(entry.st_mode) & 0o6000, 'set-id JDK file refused')
                    require(identity(os.fstat(original)) == identity(entry), 'JDK source file replaced')
                    digest = hashlib.sha256()
                    copied_bytes = 0
                    while data := os.read(original, 65536):
                        copied_bytes += len(data); total += len(data)
                        require(total <= MAX_BYTES, 'JDK byte bound')
                        digest.update(data)
                        view = memoryview(data)
                        while view:
                            written = os.write(copied, view); require(written > 0, 'JDK short write'); view = view[written:]
                    require(copied_bytes == entry.st_size and identity(os.fstat(original)) == identity(entry), 'JDK source file changed')
                    own = os.fstat(copied)
                    require(own.st_uid == os.geteuid() and own.st_nlink == 1 and own.st_dev == target_device and
                            (own.st_dev, own.st_ino) != (entry.st_dev, entry.st_ino), 'JDK copy is not independently owned')
                    if key != 'bin/java':
                        os.fchmod(copied, stat.S_IMODE(entry.st_mode))
                    records[key] = {'kind': 'file', 'identity': identity(entry), 'sha256': digest.hexdigest()}
                finally:
                    os.close(original); os.close(copied)
            else:
                raise ValueError('JDK special file refused')
            require(identity(os.stat(name, dir_fd=src, follow_symlinks=False)) == identity(entry), 'JDK source entry changed')
        require(identity(os.fstat(src)) == before, 'JDK source directory changed')

    try:
        inventory = inventory_links(source_fd)
        copy_tree(source_fd, target_fd, '', 0)
        require(set(records) == set(inventory), 'JDK preflight inventory changed')
        require(identity(os.fstat(source_fd)) == source_root, 'JDK source root changed')
        require(records.get('bin/java', {}).get('kind') == 'file' and
                records['bin/java']['identity'][5] <= 16 * 1024**2, 'JDK launcher must be a bounded regular file')
        root = secure_directory(clone)
        try:
            bin_fd = os.open('bin', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=root)
            try:
                bin_stat = os.fstat(bin_fd)
                require(bin_stat.st_uid == os.geteuid() and not stat.S_IMODE(bin_stat.st_mode) & 0o022, 'unsafe owned bin directory')
                launcher = os.open('java', os.O_RDONLY | NOFOLLOW, dir_fd=bin_fd)
                try:
                    own = os.fstat(launcher)
                    original = records['bin/java']['identity']
                    require(stat.S_ISREG(own.st_mode) and own.st_uid == os.geteuid() and own.st_nlink == 1 and
                            (own.st_dev, own.st_ino) != tuple(original[:2]) and own.st_dev == target_device, 'unsafe owned launcher')
                    with os.fdopen(os.dup(launcher), 'rb') as copied_stream:
                        data_hash = hashlib.file_digest(copied_stream, 'sha256').hexdigest()
                    require(data_hash == records['bin/java']['sha256'], 'owned launcher differs from source')
                    os.fchmod(launcher, 0o755)
                    after = os.fstat(launcher)
                    require((after.st_dev, after.st_ino, after.st_uid, after.st_nlink) ==
                            (own.st_dev, own.st_ino, own.st_uid, 1) and stat.S_IMODE(after.st_mode) == 0o755, 'owned launcher normalization failed')
                    require(identity(os.stat('java', dir_fd=bin_fd, follow_symlinks=False)) == identity(after), 'owned launcher path changed')
                finally:
                    os.close(launcher)
            finally:
                os.close(bin_fd)
        finally:
            os.close(root)
    finally:
        os.close(source_fd); os.close(target_fd)
    require(records.get('release', {}).get('kind') == 'file', 'JDK release must be regular')
    with os.fdopen(os.open(clone / 'release', os.O_RDONLY | NOFOLLOW), 'rb') as release_stream:
        release_bytes = release_stream.read(65537)
    require(len(release_bytes) <= 65536, 'JDK release bound')
    release = release_bytes.decode('utf-8')
    require(len(release) <= 65536 and re.search(r'^JAVA_VERSION="21(?:[.\-+][^"]*)?"$', release, re.M), 'selected build JDK must be feature 21')
    for directory in ['home', 'tmp', 'cache', 'gradle', 'preferences', 'receipts', 'selections']:
        (container / directory).mkdir(mode=0o700)
    creds = caller_credentials()
    receipt = {'schema': 1, 'source': str(source), 'home': str(clone), 'container': str(container), 'sourceRoot': source_root,
               'uid': os.geteuid(), 'callerUid': creds['Uid'], 'callerGid': creds['Gid'], 'launcherIdentity': identity(after),
               'launcherSha256': records['bin/java']['sha256'], 'releaseSha256': hashlib.sha256(release_bytes).hexdigest(),
               'vendor': re.search(r'^IMPLEMENTOR="([^"\n]{1,128})"$', release, re.M).group(1) if re.search(r'^IMPLEMENTOR="([^"\n]{1,128})"$', release, re.M) else 'UNAVAILABLE', 'entries': count, 'bytes': total, 'sourceEntries': records}
    write_json(container / 'provision.json', receipt)
    properties = {'home': str(clone), 'java': str(clone / 'bin/java'), 'dev': str(after.st_dev), 'ino': str(after.st_ino),
                  'uid': str(after.st_uid), 'mode': '755', 'sha256': receipt['launcherSha256'],
                  'callerUid': creds['Uid'], 'callerGid': creds['Gid'], 'receipts': str(container / 'receipts')}
    (container / 'provision.properties').write_text(''.join(k + '=' + v + '\n' for k, v in properties.items()), encoding='ascii')
    verify_source(receipt)
    return receipt


def write_json(path, value):
    with path.open('x', encoding='ascii') as handle:
        json.dump(value, handle, sort_keys=True, indent=2); handle.write('\n')


def verify_source(receipt):
    validate_link_graph(receipt['sourceEntries'])
    source = Path(receipt['source'])
    root = os.open(source, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    seen = set()
    def inspect(fd, prefix):
        with os.scandir(fd) as listing:
            names = [entry.name for entry in islice(listing, MAX_ENTRIES + 1)]
        require(len(names) <= MAX_ENTRIES, 'source JDK inventory bound')
        for name in names:
            key = prefix + name
            require(key in receipt['sourceEntries'], 'source JDK acquired extra entry')
            expected = receipt['sourceEntries'][key]; seen.add(key)
            value = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(identity(value) == tuple(expected['identity']), 'source JDK identity/mode changed')
            if expected['kind'] == 'file':
                original = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=fd)
                with os.fdopen(original, 'rb') as stream:
                    require(identity(os.fstat(stream.fileno())) == tuple(expected['identity']) and
                            hashlib.file_digest(stream, 'sha256').hexdigest() == expected['sha256'] and
                            identity(os.fstat(stream.fileno())) == tuple(expected['identity']), 'source JDK content changed')
            elif expected['kind'] == 'link':
                require(os.readlink(name, dir_fd=fd) == expected['target'], 'source JDK link changed')
            else:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
                try:
                    require(identity(os.fstat(child)) == tuple(expected['identity']), 'source JDK directory changed')
                    inspect(child, key + '/')
                finally:
                    os.close(child)
            require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == tuple(expected['identity']), 'source JDK entry replaced')
    try:
        require(identity(os.fstat(root)) == tuple(receipt['sourceRoot']), 'source JDK root changed')
        inspect(root, '')
        require(seen == set(receipt['sourceEntries']), 'source JDK lost entry')
        require(identity(source.lstat()) == tuple(receipt['sourceRoot']), 'source JDK root pathname changed')
    finally:
        os.close(root)
    clone = secure_directory(Path(receipt['home']))
    try:
        bin_fd = os.open('bin', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=clone)
        try:
            java = os.open('java', os.O_RDONLY | NOFOLLOW, dir_fd=bin_fd)
            with os.fdopen(java, 'rb') as stream:
                require(identity(os.fstat(stream.fileno())) == tuple(receipt['launcherIdentity']) and
                        hashlib.file_digest(stream, 'sha256').hexdigest() == receipt['launcherSha256'] and
                        identity(os.fstat(stream.fileno())) == tuple(receipt['launcherIdentity']), 'owned launcher changed')
        finally:
            os.close(bin_fd)
    finally:
        os.close(clone)


def read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1 and
                0 < before.st_size <= maximum, 'unsafe JVM receipt')
        data = os.read(fd, maximum + 1)
        require(len(data) == before.st_size and identity(os.fstat(fd)) == identity(before) and
                identity(path.lstat()) == identity(before), 'JVM receipt changed')
        return data
    finally:
        os.close(fd)


def parse_properties(path):
    fields = {}
    for line in read_regular(path, 16384).decode('ascii').splitlines():
        key, sep, value = line.partition('=')
        require(sep and re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', key) and key not in fields, 'invalid JVM receipt')
        fields[key] = value
    return fields


def verify_jvms(receipt):
    directory = Path(receipt['container']) / 'receipts'
    paths = list(islice(directory.iterdir(), 1025))
    require(0 < len(paths) <= 1024, 'missing/oversized actual Test JVM evidence')
    actual = [p for p in paths if p.suffix == '.properties']
    require(actual and len(paths) == len(actual) * 2, 'incomplete actual Test JVM evidence')
    tasks = set()
    for path in actual:
        props = parse_properties(path)
        require(props == {**{k: str(v) for k, v in {
            'home': receipt['home'], 'command': receipt['home'] + '/bin/java', 'dev': receipt['launcherIdentity'][0],
            'ino': receipt['launcherIdentity'][1], 'uid': receipt['uid'], 'mode': '755', 'sha256': receipt['launcherSha256'],
            'callerUid': receipt['callerUid'], 'callerGid': receipt['callerGid'],
            'scratch': str(Path(receipt['container']).parent.parent)}.items()},
            'pid': props.get('pid'), 'task': props.get('task')}, 'actual Test JVM identity mismatch')
        require(re.fullmatch(r'[1-9][0-9]{0,18}', props['pid']) and re.fullmatch(r':[A-Za-z0-9:_-]{1,160}', props['task']), 'invalid actual Test JVM fields')
        require(read_regular(path.with_suffix('.closed'), 7) == b'closed\n', 'Test JVM session did not close')
        tasks.add(props['task'])
    selections = list(islice((Path(receipt['container']) / 'selections').iterdir(), 257))
    require(0 < len(selections) <= 256, 'missing Test launcher selection')
    for path in selections:
        selected = parse_properties(path)
        require(set(selected) == {'task', 'home', 'java'} and selected['task'] in tasks and selected['home'] == receipt['home'] and
                selected['java'] == receipt['home'] + '/bin/java', 'Test launcher selection lacks matching actual JVM')
    require(tasks == {parse_properties(path)['task'] for path in selections}, 'unexpected Test JVM task')
    return len(actual)


def run(repo, source, command):
    require(command and not (repo / 'gradle/gradle-daemon-jvm.properties').exists(), 'unsupported daemon selector')
    scratch = socket_scratch(repo)
    receipt = provision(repo, source)
    container = Path(receipt['container']); home = receipt['home']
    write_json(container / 'scratch.json', scratch)
    options = ['-XX:-UsePerfData', '-XX:+DisableAttachMechanism', '-Djava.io.tmpdir=' + scratch['path'],
               '-Djna.tmpdir=' + scratch['path'], '-Duser.home=' + str(container / 'home'),
               '-Djava.util.prefs.userRoot=' + str(container / 'preferences'), '-Djava.util.prefs.systemRoot=' + str(container / 'preferences')]
    gradle = ['-Dorg.gradle.daemon=false', '-Dorg.gradle.java.home=' + home,
              '-Dorg.gradle.java.installations.auto-detect=false', '-Dorg.gradle.java.installations.auto-download=false',
              '-Dorg.gradle.java.installations.paths=' + home,
              '-Dorg.gradle.jvmargs=' + ' '.join(['-Xmx2g', *options])]
    env = dict(os.environ)
    for name in ['_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS', 'GRADLE_OPTS', 'JAVA_TOOL_OPTIONS']:
        env.pop(name, None)
    env.update(JAVA_HOME=home, PATH=home + '/bin:' + env.get('PATH', ''), HOME=str(container / 'home'),
               GRADLE_USER_HOME=str(container / 'gradle'), TMPDIR=scratch['path'], TMP=scratch['path'],
               TEMP=scratch['path'], XDG_CACHE_HOME=str(container / 'cache'), JAVA_OPTS=shlex.join(options),
               JAVA_TOOL_OPTIONS=' '.join(options), GRADLE_OPTS=shlex.join(gradle),
               ORG_GRADLE_PROJECT_ciAcpFixtureJvmScratch=scratch['path'], ORG_GRADLE_PROJECT_ciAcpFixtureJdkHome=home, ORG_GRADLE_PROJECT_ciAcpFixtureJdkReceipt=str(container / 'provision.properties'),
               **{'ORG_GRADLE_PROJECT_kotlin.compiler.execution.strategy': 'in-process',
                  'ORG_GRADLE_PROJECT_org.gradle.java.installations.auto-detect': 'false',
                  'ORG_GRADLE_PROJECT_org.gradle.java.installations.auto-download': 'false',
                  'ORG_GRADLE_PROJECT_org.gradle.java.installations.paths': home})
    # Correct dotted Gradle property via JVM options, not an unrecognized underscore property.
    env['GRADLE_OPTS'] += ' ' + shlex.quote('-Dorg.gradle.project.kotlin.compiler.execution.strategy=in-process')
    status = subprocess.run(command, cwd=repo, env=env).returncode
    final = {'exitCode': status, 'sourceUnchanged': False, 'actualTestJvms': 0}
    try:
        require(socket_scratch(repo) == scratch, 'owned JVM scratch identity changed')
        verify_source(receipt); final['sourceUnchanged'] = True
        final['actualTestJvms'] = verify_jvms(receipt)
    finally:
        write_json(container / 'final.json', final)
    require(status == 0, 'CI command failed; owned fixture evidence retained')
    print(json.dumps({'ownedJdk': home, **final}, sort_keys=True))


if __name__ == '__main__':
    require(len(sys.argv) >= 4 and sys.argv[1:3] == ['run', '--'], 'usage: ci-owned-jdk.py run -- command [args]')
    run(Path(__file__).resolve().parents[1], Path(os.environ['JAVA_HOME']), sys.argv[3:])
