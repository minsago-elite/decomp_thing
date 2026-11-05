#!/usr/bin/env python3
"""Static upload membership and downloaded ZIP consistency for the atomic job.

Does not upload, download, build or run product code. Paths in the archive are
relative to build/, the upload selection's common ancestor. Hashes are receipts,
not authentication of the CI service or compiler.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import sys
import secrets
import zipfile

SPEC = importlib.util.spec_from_file_location('atomic_artifact_io', pathlib.Path(__file__).with_name('atomic_install_prepared.py'))
io = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(io)
ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = 'orchestration/atomic-install-ci/artifact-manifest.json'


def rules(repo):
    with io.regular(repo / '.github/workflows/ci.yml', io.MAX_JSON) as (stream, _):
        raw = stream.read(io.MAX_JSON + 1)
        io.require(len(raw) <= io.MAX_JSON, 'workflow selection exceeds bound')
        text = raw.decode()
    job = re.search(r'^  atomic-install:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)', text, re.M | re.S)
    io.require(job is not None, 'atomic-install job missing')
    block = re.search(r'^          path: \|\n((?:            [^\n]+\n)+)', job[1], re.M)
    io.require(block is not None, 'atomic artifact path block missing')
    paths = [p.strip() for p in block[1].splitlines()]
    io.require(all(p.lstrip('!').startswith('build/') and '..' not in p for p in paths), 'artifact pattern escapes build/')
    return paths


MAX_DEPTH = 128
MAX_PATTERNS = 256
MAX_STATE_WORK = 32 * 1024**2


def components(pattern):
    io.require(len(pattern) <= 4096 and not any(c in pattern for c in "\\\0[]{}!()+@#"),
               'unsupported artifact pattern')
    io.require(all(ord(c) >= 32 and ord(c) != 127 for c in pattern), 'unsupported artifact pattern character')
    parts = pattern.split('/')
    io.require(0 < len(parts) <= MAX_DEPTH and all(p and p not in ('.', '..') and
               ('**' not in p or p == '**') for p in parts), 'unsupported artifact pattern components')
    return tuple(parts)


class PatternWork:
    """Shared, fail-closed budget for actual DP cells and NFA state visits."""
    def __init__(self):
        self.used = 0

    def charge(self, count=1):
        io.require(count <= MAX_STATE_WORK - self.used, 'artifact pattern-state work exceeds bound')
        self.used += count


def component_matches(pattern, name, work):
    # Each row is a prefix of the pattern, each column a prefix of the name.
    # Charge the row before allocation/evaluation, including its empty prefix.
    # No regex recursion/backtracking; O(pattern * name) time, O(name) space.
    work.charge(len(name) + 1)
    previous = bytearray(len(name) + 1)
    previous[0] = 1
    for token in pattern:
        work.charge(len(name) + 1)
        current = bytearray(len(name) + 1)
        current[0] = previous[0] if token == '*' else 0
        for j, char in enumerate(name, 1):
            if token == '*': current[j] = previous[j] or current[j - 1]
            else: current[j] = previous[j - 1] and (token == '?' or token == char)
        previous = current
    return bool(previous[-1])


def states(pattern, parts, work=None):
    # Bounded component NFA. ** consumes zero or more whole components.
    if work is None: work = PatternWork()
    io.require(len(parts) <= MAX_DEPTH and all(len(p.encode()) <= 255 for p in parts),
               'artifact depth/name bound')
    def closure(current):
        work.charge(len(current))
        result = set(current)
        for i in range(len(pattern)):
            work.charge()
            if i in result and pattern[i] == '**': result.add(i + 1)
        return result
    active = closure({0})
    for part in parts:
        following = set()
        for i in active:
            work.charge()
            if i < len(pattern):
                if pattern[i] == '**': following.add(i)
                elif component_matches(pattern[i], part, work): following.add(i + 1)
        active = closure(following)
    return active


def matches(pattern, path, work=None):
    pattern = components(pattern)
    return len(pattern) in states(pattern, path.split('/'), work)


def selected(paths, name, work=None):
    if work is None: work = PatternWork()
    io.require(len(paths) <= MAX_PATTERNS, 'artifact pattern count exceeds bound')
    if any(part.startswith('.') for part in name.split('/')):
        return False  # upload-artifact default include-hidden-files=false
    return any(matches(p, name, work) for p in paths if not p.startswith('!')) and not any(
        matches(p[1:], name, work) for p in paths if p.startswith('!'))


def membership_controls(paths, work=None):
    if work is None: work = PatternWork()
    base = 'build/orchestration/atomic-install-remediation/installed-current/'
    kept = ['qualification.json', 'prepared-A.json', 'prepared-retained.json', 'prepared-closure.json', 'prepared-guard.json',
            *[p + s + '.json' for p in ('protected', 'prepared-input') for s in ('-before', '-after', '-diff')],
            *[f'command-{i:02d}' + s for i in range(13) for s in ('.init.gradle', '.init.json', '-events.json')],
            'command-01-plan.json', 'command-02-plan.json', 'barriers/A-none-current/READY',
            'barriers/A-none-current/READY.loaded', 'barriers/A-none-current/RELEASE', 'barriers/A-none-current/launcher.log']
    omitted = ['root-build/install/llm_bin_patch/lib/app.jar', 'prepared-products/000001', 'home/cache', 'tmp/output']
    for name in kept:
        io.require(selected(paths, base + name, work), 'artifact omits ' + name)
    for name in omitted:
        io.require(not selected(paths, base + name, work), 'artifact includes products/cache: ' + name)
    io.require(selected(paths, 'build/' + MANIFEST, work), 'artifact omits manifest')
    return {'retained': len(kept) + 1, 'excluded': len(omitted)}


def seal(repo):
    repo = io.safe_path(repo)
    target = repo / 'build' / MANIFEST
    # Invalidate the previous run before parsing rules or traversing anything.
    # A failed seal cannot leave a previously valid manifest at the current path.
    io.safe_path(target, repo)
    if os.path.lexists(target):
        io.require(stat.S_ISREG(target.lstat().st_mode), 'unsafe artifact manifest')
        target.unlink()
    paths = rules(repo)
    io.require(len(paths) <= MAX_PATTERNS, 'artifact pattern count exceeds bound')
    positives = [components(p) for p in paths if not p.startswith('!')]
    negatives = [components(p[1:]) for p in paths if p.startswith('!')]
    work = PatternWork()
    controls = membership_controls(paths, work)
    budget = [io.MAX_INPUT_BYTES]
    files = {}
    enumerated = 0
    json_work = 0
    def relevance(parts):
        io.require(len(parts) <= MAX_DEPTH and all(len(p.encode()) <= 255 for p in parts),
                   'artifact depth/name bound')
        if any(p.startswith('.') for p in parts): return False, False
        negative = [(p, states(p, parts, work)) for p in negatives]
        # Only a terminal ** proves exclusion of an entire subtree.
        if any(p[-1] == '**' and len(p) - 1 in active for p, active in negative): return False, False
        positive = [(p, states(p, parts, work)) for p in positives]
        member = any(len(p) in active for p, active in positive) and not any(len(p) in a for p, a in negative)
        descend = any(any(i < len(p) for i in active) for p, active in positive)
        return member, descend
    def identity(info):
        return info.st_dev, info.st_ino, info.st_mode
    def walk(fd, path, parts):
        nonlocal enumerated, json_work
        before = os.fstat(fd)
        io.require(stat.S_ISDIR(before.st_mode), 'artifact ancestor is not directory')
        def stable():
            io.require(identity(before) == identity(path.lstat()) == identity(os.fstat(fd)),
                       'artifact directory exchanged')
            io.safe_path(path, repo)
        stable()
        with os.scandir(fd) as children:
            for child in children:
                enumerated += 1
                io.require(enumerated <= io.MAX_INPUT_ENTRIES, 'artifact traversal exceeds entry bound')
                child_parts = (*parts, child.name)
                member, descend = relevance(child_parts)
                if not member and not descend: continue
                stable()
                info = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                child_path = path / child.name
                io.require(not stat.S_ISLNK(info.st_mode), 'selected artifact symlink/ancestor')
                if stat.S_ISDIR(info.st_mode):
                    io.require(descend, 'selected artifact leaf is directory')
                    nested = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        io.require(identity(info) == identity(os.fstat(nested)), 'artifact directory exchanged')
                        walk(nested, child_path, child_parts)
                    finally: os.close(nested)
                elif member:
                    io.require(stat.S_ISREG(info.st_mode), 'selected artifact leaf is not regular')
                    name = '/'.join(child_parts)
                    if name != 'build/' + MANIFEST:
                        io.require(len(files) < io.MAX_INPUT_ENTRIES, 'artifact member count exceeds bound')
                        receipt = io.file_receipt(child_path, budget, dir_fd=fd)
                        json_work += len(json.dumps(name).encode()) + 160
                        io.require(json_work <= io.MAX_JSON, 'artifact manifest member JSON bound')
                        files[name.removeprefix('build/')] = {k: receipt[k] for k in ('sha256', 'bytes')}
                elif stat.S_ISREG(info.st_mode):
                    # Recursive positive patterns can keep a lexical descendant
                    # state after an exact negative pattern excludes this file.
                    # A no-follow regular leaf cannot contain those descendants.
                    pass
                else:
                    # A relevant ancestor must really be a directory (including FIFO/dangling links).
                    raise RuntimeError('artifact possible ancestor is not directory')
                stable()
        stable()
    root_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: walk(root_fd, repo, ())
    finally: os.close(root_fd)
    data = (json.dumps({'schemaVersion': 1, 'members': files, 'patterns': paths,
                       'staticMembership': controls}, sort_keys=True, indent=2) + '\n').encode()
    io.require(len(data) <= io.MAX_JSON, 'artifact manifest exceeds JSON bound')
    # Descriptor-relative creation/publication cannot follow exchanged ancestors.
    # No traversal touches a lexically unselected fixture just to create the manifest.
    fds = [os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    stage_name = '.artifact-manifest-' + secrets.token_hex(16)
    stage_created = False
    published = False
    try:
        for part in target.parent.relative_to(repo).parts:
            try: os.mkdir(part, dir_fd=fds[-1])
            except FileExistsError: pass
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
        io.safe_path(target, repo)
        directory_identity = identity(os.fstat(fds[-1]))
        io.require(directory_identity == identity(target.parent.lstat()), 'artifact publication parent exchanged')
        fd = os.open(stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fds[-1])
        stage_created = True
        with os.fdopen(fd, 'wb') as sink:
            sink.write(data); sink.flush(); os.fsync(sink.fileno())
        io.safe_path(target, repo)
        io.require(directory_identity == identity(target.parent.lstat()), 'artifact publication parent exchanged')
        os.replace(stage_name, target.name, src_dir_fd=fds[-1], dst_dir_fd=fds[-1])
        stage_created = False
        published = True
        os.fsync(fds[-1])
        io.safe_path(target, repo)
        io.require(directory_identity == identity(target.parent.lstat()), 'artifact publication parent exchanged')
        return {'manifest': str(target), 'sha256': io.file_receipt(target, dir_fd=fds[-1])['sha256'], 'members': len(files), **controls}
    except BaseException:
        if published: os.unlink(target.name, dir_fd=fds[-1])
        raise
    finally:
        try:
            if stage_created: os.unlink(stage_name, dir_fd=fds[-1])
        finally:
            for fd in reversed(fds): os.close(fd)


def verify(archive_path, expected_manifest_sha256):
    # The expected manifest digest must come from the originating CI log/receipt,
    # not from another untrusted member in the downloaded artifact.
    with io.regular(archive_path, io.MAX_INPUT_BYTES) as (stream, _):
        with zipfile.ZipFile(stream) as archive:
            entries = archive.infolist()
            io.require(len(entries) <= io.MAX_INPUT_ENTRIES + 1, 'downloaded artifact entry bound')
            for item in entries:
                # ZipInfo.filename silently truncates NUL and can normalize
                # names. Membership must bind the preserved physical spelling.
                io.require(item.orig_filename == item.filename and '\0' not in item.orig_filename,
                           'noncanonical downloaded artifact original path')
            all_names = [i.filename for i in entries]
            io.require(len(all_names) == len(set(all_names)), 'duplicate downloaded artifact path')
            names = [i.filename for i in entries if not i.is_dir()]
            for item in entries:
                path = pathlib.PurePosixPath(item.filename)
                mode = item.external_attr >> 16
                io.require(path.parts and not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename and
                           stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), 'unsafe downloaded artifact path/type')
                io.require(item.filename == path.as_posix() + ('/' if item.is_dir() else ''),
                           'noncanonical downloaded artifact path')
                io.require(stat.S_IFMT(mode) in ((0, stat.S_IFDIR) if item.is_dir() else (0, stat.S_IFREG)) and
                           (not (item.external_attr & 0x10) or item.is_dir()), 'downloaded artifact filename/type mismatch')
                if item.is_dir():
                    # Optional parent records carry no payload at all. ZipFile's
                    # read limit alone trusts the declared uncompressed size.
                    io.require(item.file_size == item.compress_size == item.CRC == 0 and
                               item.compress_type == zipfile.ZIP_STORED,
                               'nonempty/encoded downloaded artifact directory')
                    with archive.open(item) as member:
                        io.require(member.read(1) == b'', 'directory payload differs')
            manifest_info = archive.getinfo(MANIFEST)
            io.require(manifest_info.file_size <= io.MAX_JSON, 'artifact manifest exceeds bound')
            with archive.open(manifest_info) as member: data = member.read(io.MAX_JSON + 1)
            io.require(len(data) <= io.MAX_JSON and hashlib.sha256(data).hexdigest() == expected_manifest_sha256,
                       'downloaded manifest differs from originating run')
            manifest = json.loads(data)
            io.require(manifest['schemaVersion'] == 1 and set(names) == {*manifest['members'], MANIFEST},
                       'downloaded artifact member set differs')
            parents = {str(parent) + '/' for name in names for parent in pathlib.PurePosixPath(name).parents
                       if str(parent) != '.'}
            io.require(all(item.filename in parents for item in entries if item.is_dir()),
                       'unexpected downloaded artifact directory')
            budget = io.MAX_INPUT_BYTES
            for name, claim in manifest['members'].items():
                info = archive.getinfo(name)
                io.require(0 <= info.file_size <= io.MAX_FILE and info.file_size <= budget, 'downloaded member bound')
                h = hashlib.sha256(); total = 0
                with archive.open(info) as member:
                    while block := member.read(min(1024**2, io.MAX_FILE - total + 1)):
                        total += len(block)
                        io.require(total <= io.MAX_FILE and total <= budget, 'expanded member bound')
                        h.update(block)
                io.require(claim == {'sha256': h.hexdigest(), 'bytes': total}, 'downloaded member bytes differ')
                budget -= total
            return {'status': 'passed', 'members': len(manifest['members']), 'manifestSha256': expected_manifest_sha256}


if __name__ == '__main__':
    if sys.argv[1] == 'seal': result = seal(ROOT)
    elif sys.argv[1] == 'check': result = membership_controls(rules(ROOT))
    elif sys.argv[1] == 'verify': result = verify(pathlib.Path(sys.argv[2]).absolute(), sys.argv[3])
    else: raise SystemExit('usage: atomic_install_artifacts.py check|seal|verify ZIP ORIGIN_MANIFEST_SHA256')
    print(json.dumps(result, sort_keys=True))
