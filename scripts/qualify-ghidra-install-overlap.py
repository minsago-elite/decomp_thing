#!/usr/bin/env python3
"""Linux exact-source installed-runtime qualification for #1903 (never historical evidence).

The publisher waits at its entry; the coordinator releases it only after the REAL
HeadlessAnalyzer logs analysis of this fixture. No analysis code is replaced or paused.
Early completion is a failure, never a reason to call shell lifetimes an overlap.
Run --self-test for cheap coordinator/refusal controls, without Gradle or Ghidra.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OWNED = ('build.gradle.kts', '.github/workflows/ci.yml',
         'scripts/qualify-ghidra-install-overlap.py',
         'src/test/kotlin/decompengine/project/InstalledGhidraOverlapProbe.kt')
ARCHIVE_SHA = '93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54'
MFC = {
    'ghidra_12.1.3_PUBLIC/Ghidra/Features/Base/data/symbols/win32/mfc140u.exports':
        '4ae2761e69f8a9a66ead6ac07f378a80b12b6851ba0e6f2d799b5937f2e227b6',
    'ghidra_12.1.3_PUBLIC/Ghidra/Features/Base/data/symbols/win64/mfc140u.exports':
        '0c0dc322c52a2be9d0486f3a2399c42e22f74ae04449060f170d771c6e8cf796',
}
REQUIRED_SUCCESS = {
    'provenance.json', 'commands.json', 'probe-config.json', 'archive-verification.json',
    'build-artifacts.json', 'fixture.json', 'fixture.c', 'fixture',
    'baseline/installed-probe.json', 'baseline/reconstruction.json', 'baseline/source-tree.zip',
    'baseline/analysis/reports/program_model.json', 'baseline-outputs.json',
    'overlap/installed-probe.json', 'overlap/reconstruction.json', 'overlap/source-tree.zip',
    'overlap/analysis/reports/program_model.json', 'overlap-outputs.json',
    'bundle-before.json', 'bundle-after.json', 'bundle-diff.json',
    'application-before.json', 'application-after.json', 'application-diff.json',
    'staged-before.json', 'staged-after.json', 'staged-diff.json',
    'descriptors-before.json', 'descriptors-after.json', 'worker-ready.json', 'worker-observations.json',
    'publication/publisher.jsonl', 'publication/task-outcomes.jsonl',
    'source-after.json', 'source-authority-after.json', 'process-ownership.json', 'budget.json',
}

DEFAULT_DEADLINE_SECONDS = 1500
DEFAULT_CLEANUP_RESERVE_SECONDS = 240


class Budget:
    """One monotonic run bound with a protected process-cleanup/evidence reserve."""

    def __init__(self, total_seconds=DEFAULT_DEADLINE_SECONDS,
                 cleanup_reserve_seconds=DEFAULT_CLEANUP_RESERVE_SECONDS, started_ns=None):
        require(total_seconds > cleanup_reserve_seconds > 0,
                'total deadline must exceed a positive cleanup reserve')
        self.started_ns = started_ns if started_ns is not None else time.monotonic_ns()
        self.total_seconds = total_seconds
        self.cleanup_reserve_seconds = cleanup_reserve_seconds
        self.deadline_ns = self.started_ns + int(total_seconds * 1_000_000_000)
        self.work_deadline_ns = self.deadline_ns - int(cleanup_reserve_seconds * 1_000_000_000)

    def work_timeout(self, phase, maximum):
        remaining = (self.work_deadline_ns - time.monotonic_ns()) / 1_000_000_000
        require(remaining > 0, 'deadline: ' + phase)
        return min(float(maximum), remaining)

    def check_work(self, phase):
        self.work_timeout(phase, float('inf'))

    def check_cleanup(self, phase):
        require(time.monotonic_ns() < self.deadline_ns, 'cleanup deadline: ' + phase)

    def evidence(self):
        return dict(startedMonotonicNs=self.started_ns, workDeadlineMonotonicNs=self.work_deadline_ns,
                    totalDeadlineMonotonicNs=self.deadline_ns, totalSeconds=self.total_seconds,
                    cleanupReserveSeconds=self.cleanup_reserve_seconds)


def seal_evidence(evidence, success, budget=None):
    """Write a content index after owned writers settle, before the terminal receipt.

    Includes failure logs and partial inventories. result.json binds the index digest;
    neither the index nor result includes itself in its digest domain.
    """
    entries = {}
    for base, dirs, files in os.walk(evidence, followlinks=False):
        for name in sorted(dirs + files):
            if budget is not None:
                budget.check_cleanup('evidence index')
            path = Path(base) / name
            relative = path.relative_to(evidence).as_posix()
            if relative in ('evidence-index.json', 'result.json'):
                continue
            if path.is_symlink():
                entries[relative] = dict(type='symlink', target=os.readlink(path))
            elif path.is_file():
                entries[relative] = dict(type='file', size=path.stat().st_size, sha256=digest(path, budget, cleanup=True))
    missing = sorted(REQUIRED_SUCCESS - entries.keys()) if success else []
    write(evidence / 'evidence-index.json', dict(files=entries, requiredEvidenceComplete=not missing,
                                               missing=missing, successRequirementsApplied=success))
    require(not missing, 'incomplete required evidence: ' + ', '.join(missing))
    return digest(evidence / 'evidence-index.json', budget, cleanup=True)


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(path, budget=None, cleanup=False):
    with path.open('rb') as stream:
        h = hashlib.sha256()
        while block := stream.read(1024 * 1024):
            if budget is not None:
                (budget.check_cleanup if cleanup else budget.check_work)('file hashing')
            h.update(block)
        return h.hexdigest()


def fd_digest(fd, budget=None):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while data := os.read(fd, 1024 * 1024):
        if budget is not None:
            budget.check_work('held descriptor hashing')
        h.update(data)
    return h.hexdigest()


def attributes(st):
    return dict(mode=stat.S_IMODE(st.st_mode), size=st.st_size, device=st.st_dev,
                inode=st.st_ino, atimeNs=st.st_atime_ns, mtimeNs=st.st_mtime_ns,
                ctimeNs=st.st_ctime_ns)


def snapshot(root, exclude=None, budget=None, cleanup=False):
    """Every entry, including root and empty directories; never follow links."""
    result = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in ['.'] if Path(base) == root else []:
            result[name] = dict(type='directory', **attributes(root.lstat()))
        for name in sorted(dirs + files):
            if budget is not None:
                (budget.check_cleanup if cleanup else budget.check_work)('inventory snapshot')
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            if exclude and (relative == exclude or relative.startswith(exclude + '/')):
                if name in dirs:
                    dirs.remove(name)
                continue
            st = path.lstat()
            kind = 'file' if stat.S_ISREG(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'unsafe'
            require(kind != 'unsafe', 'unsafe inventory entry: ' + str(path))
            entry = dict(type=kind, **attributes(st))
            if kind == 'file':
                entry['sha256'] = digest(path, budget, cleanup=cleanup)
            result[relative] = entry
    return result


def _safe_archive_path(name):
    require(name and '\\' not in name and '\0' not in name and not name.startswith('/'),
            'unsafe archive member path')
    normalized = name.rstrip('/')
    parts = normalized.split('/')
    require(normalized and all(part not in ('', '.', '..') for part in parts),
            'unsafe archive member path')
    return normalized


def verify_archive_inventory(archive_path, archive_kind, staged, bundle_root, budget=None):
    """Validate raw ZIP/TAR members; synthesize and report unencoded parent directories."""
    expected = snapshot(staged, budget=budget)
    expected_files = {name: value for name, value in expected.items() if value['type'] == 'file'}
    expected_directories = {name: value for name, value in expected.items() if value['type'] == 'directory'}
    explicit = {}
    total_bytes = 0
    member_count = 0
    bundle_prefix = bundle_root.rstrip('/')

    def check_member(name, kind, mode, size, read_content):
        nonlocal total_bytes, member_count
        if budget is not None:
            budget.check_work('archive member inventory')
        member_count += 1
        require(member_count <= 25_000, 'archive member inventory exceeds entry bound')
        path = _safe_archive_path(name)
        require(path.split('/')[0] == bundle_prefix.split('/')[0], 'archive member escaped distribution root')
        require(path not in explicit, 'duplicate archive member path')
        explicit[path] = kind
        parts = path.split('/')
        for index in range(1, len(parts)):
            parent = explicit.get('/'.join(parts[:index]))
            require(parent != 'file' and not (isinstance(parent, dict) and parent['kind'] == 'file'),
                    'archive file/directory path conflict')
        if kind not in ('file', 'directory'):
            raise RuntimeError('unsupported archive member type')
        if path != bundle_prefix and not path.startswith(bundle_prefix + '/'):
            return
        relative = '.' if path == bundle_prefix else path[len(bundle_prefix) + 1:]
        if kind == 'directory':
            require(size == 0, 'archive directory has nonzero payload')
            require(relative in expected_directories, 'unexpected archive directory: ' + relative)
            expected_mode = expected_directories[relative]['mode']
            require(mode == expected_mode, 'archive directory mode mismatch: ' + relative)
            explicit[ path ] = dict(kind=kind, relative=relative, mode=mode, size=size)
            return
        require(relative in expected_files, 'unexpected archive file: ' + relative)
        require(size <= 512 * 1024 * 1024, 'archive member exceeds file byte bound')
        expected_file = expected_files[relative]
        require(mode == expected_file['mode'] and size == expected_file['size'],
                'archive file mode/size mismatch: ' + relative)
        total_bytes += size
        require(total_bytes <= 4 * 1024 * 1024 * 1024, 'archive content exceeds total byte bound')
        h = hashlib.sha256()
        count = 0
        while block := read_content():
            if budget is not None:
                budget.check_work('archive file hashing')
            count += len(block)
            require(count <= size, 'archive member grew while reading')
            h.update(block)
        require(count == size and h.hexdigest() == expected_file['sha256'],
                'archive file content mismatch: ' + relative)
        explicit[path] = dict(kind=kind, relative=relative, mode=mode, size=size, sha256=h.hexdigest())

    if archive_kind == 'zip':
        with zipfile.ZipFile(archive_path, 'r') as archive:
            for info in archive.infolist():
                raw_mode = info.external_attr >> 16
                file_type = stat.S_IFMT(raw_mode)
                is_directory = info.is_dir()
                if is_directory:
                    require(file_type in (0, stat.S_IFDIR), 'unsupported ZIP directory type')
                    require(info.file_size == 0, 'ZIP directory has nonzero payload')
                    member_mode = raw_mode & 0o7777
                    check_member(info.filename, 'directory', member_mode, info.file_size, lambda: b'')
                else:
                    require(file_type in (0, stat.S_IFREG), 'ZIP symlink or special member refused')
                    require(info.file_size <= 512 * 1024 * 1024, 'ZIP member exceeds file byte bound')
                    member_mode = raw_mode & 0o7777
                    with archive.open(info, 'r') as stream:
                        check_member(info.filename, 'file', member_mode, info.file_size,
                                     lambda: stream.read(1024 * 1024))
    elif archive_kind == 'tar':
        with tarfile.open(archive_path, 'r:*') as archive:
            for member in archive.getmembers():
                if member.isdir():
                    check_member(member.name, 'directory', member.mode & 0o7777, member.size, lambda: b'')
                elif member.isreg():
                    require(member.size <= 512 * 1024 * 1024, 'TAR member exceeds file byte bound')
                    stream = archive.extractfile(member)
                    require(stream is not None, 'TAR regular file has no readable contents')
                    with stream:
                        check_member(member.name, 'file', member.mode & 0o7777, member.size,
                                     lambda: stream.read(1024 * 1024))
                else:
                    raise RuntimeError('TAR link or special member refused')
    else:
        raise RuntimeError('unsupported archive kind')

    for path, value in explicit.items():
        parts = path.split('/')
        for index in range(1, len(parts)):
            parent = explicit.get('/'.join(parts[:index]))
            require(parent != 'file' and not (isinstance(parent, dict) and parent['kind'] == 'file'),
                    'archive file/directory path conflict')
    explicit_files = {entry['relative']: entry for entry in explicit.values()
                      if isinstance(entry, dict) and entry['kind'] == 'file'}
    explicit_directories = {entry['relative']: entry for entry in explicit.values()
                            if isinstance(entry, dict) and entry['kind'] == 'directory'}
    expected_file_names = set(expected_files)
    expected_directory_names = set(expected_directories)
    require(set(explicit_files) == expected_file_names, 'archive file inventory differs from staged bundle')
    require(set(explicit_directories).issubset(expected_directory_names),
            'archive contains an unknown directory entry')
    implicit = set()
    for relative in list(explicit_files) + list(explicit_directories):
        if relative == '.':
            continue
        parts = relative.split('/')[:-1]
        for index in range(1, len(parts) + 1):
            parent = '/'.join(parts[:index])
            if parent not in explicit_directories:
                require(parent in expected_directory_names, 'implicit archive directory not in staged bundle')
                require(expected_directories[parent]['mode'] == 0o755,
                        'implicit archive directory mode cannot be proven')
                implicit.add(parent)
    if '.' not in explicit_directories:
        require(expected_directories['.']['mode'] == 0o755,
                'implicit archive root mode cannot be proven')
        implicit.add('.')
    missing_directories = expected_directory_names - set(explicit_directories) - implicit
    require(not missing_directories, 'archive omits empty or otherwise unrepresented directories')
    require(set(explicit_directories) | implicit == expected_directory_names,
            'archive directory inventory differs from staged bundle')

    files = sorted(explicit_files.values(), key=lambda entry: entry['relative'])
    directories = sorted(explicit_directories.values(), key=lambda entry: entry['relative'])
    implicit_directories = sorted((dict(relative=name, mode=expected_directories[name]['mode'],
                                         size=0, implicit=True) for name in implicit),
                                  key=lambda entry: entry['relative'])
    inventory = dict(files=files, directories=directories, implicitDirectories=implicit_directories)
    return dict(kind=archive_kind, path=str(archive_path), sha256=digest(archive_path, budget),
                entryCount=member_count, fileCount=len(files), directoryCount=len(directories),
                implicitDirectoryCount=len(implicit_directories), inventory=inventory,
                inventorySha256=hashlib.sha256(json.dumps(inventory, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest())


def diff(before, after, fields):
    return {name: {'before': before.get(name), 'after': after.get(name)}
            for name in sorted(before.keys() | after.keys())
            if name not in before or name not in after or
            any(before[name].get(k) != after[name].get(k) for k in fields)}


def proc(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        return dict(pid=pid, state=fields[0], ppid=int(fields[1]),
                    startTicks=int(fields[19]), cpuTicks=int(fields[11]) + int(fields[12]),
                    command=Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace'))
    except (OSError, ValueError, IndexError):
        return None


def alive(identity):
    current = proc(identity['pid'])
    return current if current and current['startTicks'] == identity['startTicks'] and current['state'] not in ('Z', 'X') else None


def jsonlines(path):
    if not path.exists():
        return []
    # A writer can be between write and newline; a partial final frame is not an event.
    data = path.read_text()
    return [json.loads(line) for line in data.splitlines(keepends=True) if line.endswith('\n')]


def event(events, name):
    found = [e for e in events if e['event'] == name]
    require(len(found) == 1, 'missing or duplicate ' + name)
    return found[0]


def validate_overlap(events, ready, last_active, outcomes, staged_before, staged_after):
    require(ready is not None, 'missing actual analysis readiness')
    start = event(events, 'publication-start')
    end = event(events, 'publication-end')
    entry = event(events, 'publisher-entry')
    event(events, 'installDist-executing')
    require(entry['monotonicNs'] < start['monotonicNs'] < end['monotonicNs'], 'absent publication interval')
    require(ready['monotonicNs'] < start['monotonicNs'], 'readiness did not precede publication')
    require(last_active is not None and last_active['monotonicNs'] >= end['monotonicNs'], 'early reconstruction exit')
    require(last_active['pid'] == ready['pid'] and last_active['startTicks'] == ready['startTicks'], 'worker identity changed')
    require(last_active['cpuTicks'] > ready['cpuTicks'], 'no actual worker CPU progress')
    install = [r for r in outcomes if r['task'] == ':installDist']
    require(len(install) == 1 and install[0]['didWork'] and not install[0]['skipped'] and not install[0]['failure'],
            'installDist skipped or failed')
    require(staged_before == staged_after, 'changed bundle input')
    require(not any(e['event'] in ('replaced', 'deleted') for e in events), 'unchanged bundle file replaced/deleted')


class Commands:
    """New sessions plus Linux subreaper; retain identities before parents can exit."""
    def __init__(self, evidence, budget):
        self.evidence, self.budget, self.children, self.identities, self.commands = evidence, budget, [], {}, []
        self.reaped = []
        require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, 'cannot become child subreaper')
        self.env = os.environ.copy()
        for key in ('GHIDRA_HOME', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'):
            self.env.pop(key, None)
        for name in ('tmp', 'home', 'cache'):
            (evidence / name).mkdir()
        self.env.update(TMPDIR=str(evidence / 'tmp'), HOME=str(evidence / 'home'),
                        XDG_CACHE_HOME=str(evidence / 'cache'), XDG_CONFIG_HOME=str(evidence / 'home/.config'))

    def census(self):
        all_processes = [p for f in Path('/proc').iterdir() if f.name.isdigit() and (p := proc(int(f.name)))]
        direct = {p.pid for p, _, _ in self.children}
        for p in all_processes:
            if p['ppid'] == os.getpid() and p['pid'] not in direct and p['state'] == 'Z':
                # The real analyzer correctly refuses still-observable descendants. As the
                # subreaper, promptly reap adopted native decompilers, not only at shutdown.
                # Never steal a direct Popen child's status from its poll()/wait().
                try:
                    child, status = os.waitpid(p['pid'], os.WNOHANG)
                    if child:
                        self.reaped.append(dict(pid=child, startTicks=p['startTicks'], status=status,
                                                monotonicNs=time.monotonic_ns()))
                except ChildProcessError:
                    pass
        parents = {os.getpid()} | {p.pid for p, _, _ in self.children}
        for _ in range(20):
            added = False
            for p in all_processes:
                if p['ppid'] in parents:
                    self.identities[(p['pid'], p['startTicks'])] = p
                    if p['pid'] not in parents:
                        parents.add(p['pid'])
                        added = True
            if not added:
                break

    def start(self, args, label, extra_env=None):
        self.budget.check_work('start ' + label)
        args = [str(a) for a in args]
        stdout = (self.evidence / (label + '.stdout.log')).open('wb')
        stderr = (self.evidence / (label + '.stderr.log')).open('wb')
        env = self.env | (extra_env or {})
        p = subprocess.Popen(args, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        self.children.append((p, stdout, stderr))
        self.commands.append(dict(argv=args, label=label, pid=p.pid, startedMonotonicNs=time.monotonic_ns(),
                                  directory=str(ROOT), environmentOverrides={k: env[k] for k in
                                  ('HOME', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'GRADLE_USER_HOME',
                                   'GRADLE_OPTS', 'JAVA_HOME', 'PATH', 'NPM_CONFIG_CACHE') if k in env}))
        write(self.evidence / 'commands.json', self.commands)
        self.census()
        return p

    def wait(self, p, timeout=300):
        phase = next((r['label'] for r in self.commands if r['pid'] == p.pid), 'child process')
        deadline = time.monotonic() + self.budget.work_timeout('command ' + phase, timeout)
        while p.poll() is None:
            self.census()
            self.budget.check_work('command ' + phase)
            require(time.monotonic() < deadline, 'command timeout: ' + str(p.args))
            time.sleep(.05)
        for record in self.commands:
            if record['pid'] == p.pid:
                record.update(returnCode=p.returncode, finishedMonotonicNs=time.monotonic_ns())
        write(self.evidence / 'commands.json', self.commands)
        require(p.returncode == 0, 'command failed: ' + str(p.args))

    def run(self, args, label, timeout=300, extra_env=None):
        self.wait(self.start(args, label, extra_env), timeout)
        return (self.evidence / (label + '.stdout.log')).read_text()

    def run_bytes(self, args, label, timeout=300, extra_env=None):
        self.wait(self.start(args, label, extra_env), timeout)
        return (self.evidence / (label + '.stdout.log')).read_bytes()

    def close(self):
        cleanup_deadline = self.budget.deadline_ns / 1_000_000_000
        self.census()
        for p, _, _ in self.children:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
        for ident in self.identities.values():
            if alive(ident):
                try:
                    os.kill(ident['pid'], signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = min(time.monotonic() + 3, cleanup_deadline)
        while any(alive(p) for p in self.identities.values()) and time.monotonic() < deadline:
            time.sleep(.05)
        for ident in self.identities.values():
            if alive(ident):
                try:
                    os.kill(ident['pid'], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for p, out, err in self.children:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=max(.01, min(10, cleanup_deadline - time.monotonic())))
            out.close()
            err.close()
        deadline = min(time.monotonic() + 10, cleanup_deadline)
        while True:
            try:
                child, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            require(time.monotonic() < deadline, 'owned descendants could not be reaped')
            if child == 0:
                time.sleep(.05)
        write(self.evidence / 'process-ownership.json', list(self.identities.values()))
        write(self.evidence / 'reaped-adopted.json', self.reaped)
        self.budget.check_cleanup('owned process reaping')
        require(not any(alive(p) for p in self.identities.values()), 'owned process survived cleanup')


def wait_for(commands, predicate, processes, timeout, reason):
    deadline = time.monotonic() + commands.budget.work_timeout(reason, timeout)
    while True:
        commands.census()
        commands.budget.check_work(reason)
        value = predicate()
        if value:
            return value
        require(all(p.poll() is None for p in processes), 'early process exit waiting for ' + reason)
        require(time.monotonic() < deadline, 'timeout: ' + reason)
        time.sleep(.02)


def source_inventory(commands, budget):
    paths = commands.run(['git', 'ls-files', '-z'], 'source-inventory-tracked', 20).split('\0')
    # Untracked production/test source can affect compilation in a shared developer checkout.
    paths += commands.run(['git', 'ls-files', '--others', '--exclude-standard', '-z', '--',
                           'src', 'ghidra-bridge/src'], 'source-inventory-untracked', 20).split('\0')
    paths += list(OWNED)
    result = {}
    for path in sorted(set(paths)):
        if path and (ROOT / path).is_file():
            budget.check_work('source inventory')
            result[path] = digest(ROOT / path, budget)
    return result


def parse_source_index(data):
    """Parse the authoritative index including gitlinks, without path quoting."""
    require(len(data) <= 4 * 1024 * 1024 and (not data or data.endswith(b'\0')),
            'malformed or oversized source index')
    entries = []
    seen = set()
    for record in data[:-1].split(b'\0') if data else ():
        match = re.fullmatch(rb'(100644|100755|120000|160000) ([0-9a-f]{40}|[0-9a-f]{64}) 0\t(.+)', record)
        require(match is not None, 'malformed source index mode/stage/record')
        mode, object_id, raw_path = match.groups()
        require(any(byte != ord('0') for byte in object_id), 'invalid source index object')
        require(not raw_path.startswith(b'/') and b'\\' not in raw_path and
                all(byte >= 32 and byte != 127 for byte in raw_path), 'unsafe source index path')
        parts = raw_path.split(b'/')
        require(all(part not in (b'', b'.', b'..') and part.lower() != b'.git' for part in parts),
                'unsafe source index path')
        path = os.fsdecode(raw_path)
        require(path not in seen, 'duplicate source index path')
        seen.add(path)
        entries.append(dict(mode=mode.decode('ascii'), objectId=object_id.decode('ascii'), path=path))
    for entry in entries:
        parents = Path(entry['path']).parents
        require(not any(parent.as_posix() in seen for parent in parents if parent != Path('.')),
                'conflicting source index paths')
    require(len(entries) <= 100_000, 'source index exceeds entry bound')
    return sorted(entries, key=lambda item: item['path'])


def source_authority_snapshot(commands, budget, phase):
    raw_index = commands.run_bytes(['git', 'ls-files', '--stage', '-z'],
                                    'source-index-' + phase, 30)
    entries = parse_source_index(raw_index)
    gitlinks = [entry for entry in entries if entry['mode'] == '160000']
    submodule_status = commands.run(['git', 'submodule', 'status', '--recursive'],
                                    'source-gitlinks-' + phase, 30)
    states = []
    for number, entry in enumerate(gitlinks):
        budget.check_work('source gitlink census')
        path = ROOT / entry['path']
        try:
            st = path.lstat()
        except FileNotFoundError:
            state = 'absent-uninitialized'
        else:
            require(stat.S_ISDIR(st.st_mode), 'gitlink path is linked or non-directory')
            with os.scandir(path) as children:
                empty = next(children, None) is None
            state = 'empty-uninitialized' if empty else 'initialized'
        states.append(dict(path=entry['path'], mode=entry['mode'], indexCommit=entry['objectId'],
                           state=state,
                           identity=None if state == 'absent-uninitialized' else
                           [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid]))
    status_lines = [line for line in submodule_status.splitlines() if line]
    status_by_path = {}
    for line in status_lines:
        match = re.fullmatch(r'([-+ U])([0-9a-f]{40,64})\s+(.+?)(?:\s+\([^)]*\))?', line)
        require(match is not None, 'malformed recursive gitlink status')
        marker, commit, path = match.groups()
        require(marker in (' ', '-'), 'gitlink commit differs or has conflicts')
        require(path not in status_by_path, 'duplicate recursive gitlink status')
        status_by_path[path] = dict(marker=marker, commit=commit)
    for state in states:
        observed = status_by_path.get(state['path'])
        require(observed is not None and observed['commit'] == state['indexCommit'],
                'recursive gitlink status differs from index')
        expected_marker = '-' if state['state'] != 'initialized' else ' '
        require(observed['marker'] == expected_marker, 'recursive gitlink initialization state differs')
    root_status = commands.run(['git', '-c', 'status.submodule=normal', 'status', '--porcelain=v1',
                                '--untracked-files=all', '--ignore-submodules=none'],
                               'source-worktree-status-' + phase, 30)
    budget.check_work('source authority snapshot')
    return dict(indexSha256=hashlib.sha256(raw_index).hexdigest(), entries=entries,
                gitlinks=states, recursiveGitlinkStatus=status_by_path,
                submoduleStatusSha256=hashlib.sha256(submodule_status.encode()).hexdigest(),
                worktreeStatusSha256=hashlib.sha256(root_status.encode()).hexdigest())


def provenance(commands, args):
    def git(*argv):
        return commands.run(['git', *argv], 'git-' + str(len(commands.commands)), 20).strip()
    head = git('rev-parse', 'HEAD')
    requested_head = args.pr_head or os.environ.get('QUALIFICATION_PR_HEAD') or head
    requested_base = args.pr_base or os.environ.get('QUALIFICATION_PR_BASE') or git('rev-parse', 'HEAD^')
    for pin in (requested_head, requested_base):
        require(re.fullmatch('[0-9a-f]{40}', pin), 'full source pin required')
    tracked = git('status', '--porcelain=v1', '--untracked-files=no')
    all_status = git('status', '--porcelain=v1', '--untracked-files=normal')
    source_authority = source_authority_snapshot(commands, commands.budget, 'before')
    result = dict(head=head, tree=git('rev-parse', 'HEAD^{tree}'), parents=git('show', '-s', '--format=%P', 'HEAD'),
                  requestedPrHead=requested_head, requestedPrBase=requested_base,
                  mergeBase=git('merge-base', requested_head, requested_base),
                  headMergeBase=git('merge-base', 'HEAD', requested_head),
                  trackedClean=not tracked, worktreeStatus=all_status,
                  ownedStatus=git('status', '--porcelain=v1', '--', *OWNED),
                  sourceAuthority=source_authority, sourceHashes=source_inventory(commands, commands.budget), ci={k: os.environ.get(k) for k in
                  ('GITHUB_WORKFLOW', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_JOB')},
                  label='current #1903 run; not historical #1841 evidence')
    result['cleanCommittedSource'] = not all_status
    write(commands.evidence / 'provenance.json', result)
    commands.run(['git', 'diff', 'HEAD', '--', *OWNED], 'owned-source-diff', 20)
    require(head == requested_head, 'checked-out HEAD differs from literal requested PR head')
    require(args.allow_dirty or not all_status, 'dirty source requires explicit --allow-dirty; CI must be clean')
    return result


def fixture_source():
    # Fixed generator (192 small functions) keeps genuine analysis/export busy while the
    # publisher hashes the bundle. The coordinator STILL rejects an early worker exit.
    text = ['/* #1903 fixed arithmetic fixture v2; no libc, network, oracle or LLM. */']
    for i in range(192):
        text += [f'__attribute__((noinline)) int f{i}(int x) {{',
                 f'  for (int j=0; j<17; ++j) x = ((x & 32767) ^ ((x & 32767) << {i % 7 + 1})) + j + {i + 3};',
                 '  return x;', '}']
    text += ['int main(void) { int x=7;']
    text += [f'  x = f{i}(x);' for i in range(192)]
    text += ['  return (int)(x & 127); }', '']
    return '\n'.join(text)


def qualify(args, evidence, budget):
    commands = Commands(evidence, budget)
    bundle = ROOT / 'build/install/llm_bin_patch/libexec/ghidra'
    installed = bundle.parent.parent
    staged = ROOT / 'ghidra-bridge/build/bundle'
    fds = []
    result = dict(status='failed', runtimeQualified=False, budget=budget.evidence())
    try:
        write(evidence / 'budget.json', budget.evidence())
        initial = provenance(commands, args)
        # All new Gradle state stays beneath build/. Seed caches by COPY, never linked writes
        # to the user's shared Gradle cache. Reuse this directory across local attempts.
        gradle_home = ROOT / 'build/1903-overlap-gradle-home'
        if not gradle_home.exists():
            gradle_home.mkdir()
            seed = Path(os.environ.get('GRADLE_USER_HOME', str(Path.home() / '.gradle')))
            for name in ('caches', 'wrapper'):
                if (seed / name).exists():
                    commands.run(['cp', '-R', '--reflink=auto', seed / name, gradle_home / name], 'seed-' + name, 180)
        commands.env['GRADLE_USER_HOME'] = str(gradle_home)
        commands.env['GRADLE_OPTS'] = ('-Djava.io.tmpdir=' + str(evidence / 'tmp') +
                                      ' -Duser.home=' + str(evidence / 'home') + ' -XX:-UsePerfData')
        gradle = [ROOT / 'gradlew', '--no-daemon', '--console=plain', '--project-cache-dir',
                  ROOT / 'build/1903-overlap-project-cache', '-PghidraInstallOverlapPrivateCache=true']
        if args.offline:
            gradle += ['--offline']
        commands.run(gradle + ['--version'], 'gradle-version')
        commands.run(['cc', '--version'], 'compiler-version')
        commands.run(gradle + ['installDist', 'verifyGhidraDistributionArchives',
                              'verifyAtomicGhidraBundlePublication', 'prepareGhidraInstallOverlapProbe'], 'prepare', 1200)
        config = json.loads((ROOT / 'build/ghidra-install-overlap-probe.json').read_text())
        write(evidence / 'probe-config.json', config)
        commands.run([config['java'], '-version'], 'jdk-version')
        require(digest(Path(config['archive']), budget) == ARCHIVE_SHA, 'Ghidra release archive pin mismatch')
        archive_report = ROOT / 'build/reports/ghidra-distribution-archives.json'
        archive_data = json.loads(archive_report.read_text())
        require(archive_data['verified'] and {e['archive'] for e in archive_data['entries']} == {'zip', 'tar'}
                and {e['type'] for e in archive_data['entries']} == {'file', 'directory'},
                'complete structured file/directory archive verification missing')
        zip_archive = next((ROOT / 'build/distributions').glob('*.zip'))
        tar_archive = next((ROOT / 'build/distributions').glob('*.tar'))
        zip_root = zip_archive.stem + '/libexec/ghidra'
        tar_root = tar_archive.stem + '/libexec/ghidra'
        archive_inventories = [
            verify_archive_inventory(zip_archive, 'zip', staged, zip_root, budget),
            verify_archive_inventory(tar_archive, 'tar', staged, tar_root, budget),
        ]
        require({item['kind'] for item in archive_inventories} == {'zip', 'tar'},
                'raw ZIP/TAR archive inventory missing')
        write(evidence / 'archive-verification.json', dict(schema='ghidra-1903-archive-inventory-v1',
            verified=True, gradleTreeReportSha256=digest(archive_report, budget),
            archives=archive_inventories))
        artifacts = [Path(config['archive']), staged / 'bundle.sha256', archive_report,
                     *sorted((ROOT / 'build/distributions').glob('*'))]
        write(evidence / 'build-artifacts.json', {str(p): dict(sha256=digest(p, budget), size=p.stat().st_size)
                                                 for p in artifacts if p.is_file()})
        fixture = evidence / 'fixture.c'
        fixture.write_text(fixture_source())
        binary = evidence / 'fixture'
        commands.run(['cc', '-O0', '-g', '-gdwarf-4', '-nostdlib', '-fno-pie', '-no-pie', '-fno-stack-protector',
                      '-Wl,--build-id=none', '-Wl,--entry=main', '-o', binary, fixture], 'compile-fixture', 30)
        write(evidence / 'fixture.json', {p.name: dict(sha256=digest(p, budget), size=p.stat().st_size) for p in (fixture, binary)})
        libraries = sorted(installed.glob('lib/*.jar'))
        require(libraries, 'installed runtime JARs missing')
        classpath = os.pathsep.join(map(str, libraries + [Path(p) for p in config['testClasses']]))

        def launch(label):
            home, tmp = evidence / (label + '-home'), evidence / (label + '-tmp')
            home.mkdir(); tmp.mkdir()
            # Ghidra refuses dot-prefixed project ancestors (e.g. T3's .t3 checkout).
            # A live coordinator cwd alias names the SAME repository directory, without
            # creating a symlink or scratch directory outside build/. Keep this owner alive
            # until the worker has exited. All subprocess cwd values are ROOT.
            output = Path('/proc') / str(os.getpid()) / 'cwd' / (evidence / label).relative_to(ROOT)
            require(output.parent.resolve() == evidence, 'project alias escaped evidence directory')
            java = [config['java'], '-XX:-UsePerfData', '-XX:+ErrorFileToStderr', '-XX:-CreateCoredumpOnCrash',
                    '-XX:-DumpReplayDataOnError', '-Djava.io.tmpdir=' + str(tmp), '-Djna.tmpdir=' + str(tmp),
                    '-Duser.home=' + str(home), '-Ddecompengine.oracle.nativeLibraryDirectory=' +
                    str(installed / 'libexec/oracle-native'), '-cp', classpath,
                    'decompengine.project.InstalledGhidraOverlapProbe', installed, binary, output]
            return commands.start(java, label, dict(HOME=str(home), TMPDIR=str(tmp),
                                  XDG_CONFIG_HOME=str(home / '.config'), XDG_CACHE_HOME=str(home / '.cache')))

        commands.wait(launch('baseline'), 300)
        require((evidence / 'baseline/installed-probe.json').is_file(), 'baseline real reconstruction receipt missing')
        write(evidence / 'baseline-outputs.json', snapshot(evidence / 'baseline', budget=budget))
        before = snapshot(bundle, budget=budget)
        app_before = snapshot(installed, 'libexec/ghidra', budget=budget)
        staged_before = snapshot(staged, budget=budget)
        write(evidence / 'bundle-before.json', before)
        write(evidence / 'application-before.json', app_before)
        write(evidence / 'staged-before.json', staged_before)
        require({p for p in before if p.endswith('/mfc140u.exports')} == set(MFC), 'mfc140u.exports inventory differs')
        for path, expected in MFC.items():
            require(before[path]['sha256'] == expected, 'mfc140u.exports pin differs')
            fd = os.open(bundle / path, os.O_RDONLY | os.O_NOFOLLOW)
            fds.append((path, fd))
        write(evidence / 'descriptors-before.json', {p: dict(fd=fd, sha256=fd_digest(fd, budget), **attributes(os.fstat(fd))) for p, fd in fds})
        publication = evidence / 'publication'
        publication.mkdir()
        installer = commands.start(gradle + ['installDist', '-PghidraInstallOverlapEvidence=' + str(publication)], 'installer')
        log = publication / 'publisher.jsonl'
        wait_for(commands, lambda: any(e['event'] == 'publisher-entry' for e in jsonlines(log)),
                 [installer], 180, 'publisher-entry')
        reconstruction = launch('overlap')
        ready = None
        app_log = evidence / 'overlap-home/.config/ghidra/ghidra_12.1.3_PUBLIC/application.log'
        marker = 'ANALYZING all memory and code: ' + binary.as_uri()

        def readiness():
            nonlocal ready
            if not app_log.exists() or marker not in app_log.read_text(errors='replace'):
                return False
            matches = [p for p in commands.identities.values() if
                       'decompengine.ghidra.BundledGhidraWorker ' in p['command'] and
                       str(binary) in p['command'] and 'archival_reconstruction' in p['command'] and alive(p)]
            require(len(matches) <= 1, 'ambiguous actual analysis worker')
            if not matches:
                return False
            ready = alive(matches[0]) | dict(monotonicNs=time.monotonic_ns(), marker=marker, log=str(app_log))
            return ready

        wait_for(commands, readiness, [installer, reconstruction], 120, 'actual analysis readiness')
        write(evidence / 'worker-ready.json', ready)
        (publication / 'publisher-release').write_text('actual analysis ready\n')
        observations = []
        deadline = time.monotonic() + budget.work_timeout('publication interval', 120)
        while True:
            budget.check_work('publication interval')
            commands.census()
            # Read the end event BEFORE the final live-worker observation. A publisher
            # finishing between a sample and this read must not fabricate an early exit.
            publication_ended = any(e['event'] == 'publication-end' for e in jsonlines(log))
            worker = alive(ready)
            require(worker is not None and reconstruction.poll() is None, 'early reconstruction exit')
            progress = evidence / 'overlap/analysis/reports/program_model.json.progress.json'
            if progress.exists():
                # Progress files may be mid-write; the canonical completion token is sufficient
                # to refuse a completed analysis, even while its parent JVM is still alive.
                require('"phase":"complete"' not in progress.read_text(), 'real analysis completed before publication end observation')
            observation = {k: worker[k] for k in ('pid', 'startTicks', 'cpuTicks', 'state')}
            observation['monotonicNs'] = time.monotonic_ns()
            observations.append(observation)
            write(evidence / 'worker-observations.json', observations)
            if publication_ended:
                break
            require(installer.poll() is None, 'installer exited without publication interval')
            require(time.monotonic() < deadline, 'publication interval timeout')
            time.sleep(.02)
        commands.wait(installer, 120)
        commands.wait(reconstruction, 300)
        after = snapshot(bundle, budget=budget)
        app_after = snapshot(installed, 'libexec/ghidra', budget=budget)
        staged_after = snapshot(staged, budget=budget)
        write(evidence / 'bundle-after.json', after)
        write(evidence / 'application-after.json', app_after)
        write(evidence / 'staged-after.json', staged_after)
        parity = diff(before, after, ('type', 'mode', 'size', 'sha256', 'device', 'inode', 'mtimeNs'))
        write(evidence / 'bundle-diff.json', parity)
        app_diff = diff(app_before, app_after, ('type', 'mode', 'size', 'sha256'))
        write(evidence / 'application-diff.json', dict(changes=app_diff,
              classification='application bytes/modes changed; independent from bundle parity' if app_diff else 'application bytes/modes unchanged'))
        staged_diff = diff(staged_before, staged_after, ('type', 'mode', 'size', 'sha256'))
        write(evidence / 'staged-diff.json', staged_diff)
        require(not parity, 'installed bundle inode/bytes/mode parity failed')
        descriptors = {p: dict(fd=fd, sha256=fd_digest(fd, budget), freshSha256=digest(bundle / p, budget), **attributes(os.fstat(fd))) for p, fd in fds}
        write(evidence / 'descriptors-after.json', descriptors)
        for p, value in descriptors.items():
            require(value['sha256'] == value['freshSha256'] == MFC[p] and
                    value['inode'] == before[p]['inode'] and value['device'] == before[p]['device'], 'descriptor parity failed')
        validate_overlap(jsonlines(log), ready, observations[-1], jsonlines(publication / 'task-outcomes.jsonl'),
                         {}, staged_diff)
        require((evidence / 'overlap/installed-probe.json').is_file(), 'overlap reconstruction receipt missing')
        write(evidence / 'overlap-outputs.json', snapshot(evidence / 'overlap', budget=budget))
        final_sources = source_inventory(commands, budget)
        write(evidence / 'source-after.json', final_sources)
        require(final_sources == initial['sourceHashes'], 'source changed during qualification')
        final_authority = source_authority_snapshot(commands, budget, 'after')
        write(evidence / 'source-authority-after.json', final_authority)
        require(final_authority == initial['sourceAuthority'], 'source index or gitlink state changed during qualification')
        result.update(status='passed', runtimeQualified=True, cleanCommittedSource=initial['cleanCommittedSource'],
                      head=initial['head'], worker=ready, publicationStart=event(jsonlines(log), 'publication-start'),
                      publicationEnd=event(jsonlines(log), 'publication-end'),
                      limitation='Default evidence-stub reconstruction/build; no behavioral equivalence or #1789 JAR reproducibility claim.')
    except BaseException as error:
        result['failure'] = repr(error)
        raise
    finally:
        try:
            commands.close()
        except BaseException as error:
            result.update(status='failed', runtimeQualified=False, cleanupFailure=repr(error))
            raise
        finally:
            for _, fd in fds:
                os.close(fd)
            # Preserve partial installed state even when build/readiness/parity fails.
            for name, path in [('bundle-failure-final.json', bundle), ('staged-failure-final.json', staged)]:
                if result['status'] != 'passed' and path.is_dir():
                    try:
                        write(evidence / name, snapshot(path, budget=budget, cleanup=True))
                    except Exception as error:
                        result[name] = repr(error)
            try:
                result['evidenceIndexSha256'] = seal_evidence(evidence, result['status'] == 'passed', budget)
            except BaseException as error:
                result.update(status='failed', runtimeQualified=False, evidenceFailure=repr(error))
                raise
            finally:
                result['budget'] = budget.evidence() | dict(finishedMonotonicNs=time.monotonic_ns(),
                    elapsedSeconds=(time.monotonic_ns() - budget.started_ns) / 1_000_000_000)
                write(evidence / 'result.json', result)


class Controls(unittest.TestCase):
    def setUp(self):
        self.events = [dict(event=n, monotonicNs=t) for n, t in
                       [('installDist-executing', 1), ('publisher-entry', 2), ('publication-start', 4), ('publication-end', 6)]]
        self.ready = dict(monotonicNs=3, pid=8, startTicks=9, cpuTicks=10)
        self.last = dict(monotonicNs=7, pid=8, startTicks=9, cpuTicks=11)
        self.tasks = [dict(task=':installDist', didWork=True, skipped=False, failure=None)]

    def check(self, **changes):
        values = dict(events=self.events, ready=self.ready, last_active=self.last,
                      outcomes=self.tasks, staged_before='same', staged_after='same') | changes
        validate_overlap(**values)

    def test_positive(self):
        self.check()

    def test_missing_readiness(self):
        with self.assertRaisesRegex(RuntimeError, 'readiness'):
            self.check(ready=None)

    def test_absent_publication_interval(self):
        with self.assertRaisesRegex(RuntimeError, 'publication-end'):
            self.check(events=self.events[:-1])

    def test_early_reconstruction_exit(self):
        with self.assertRaisesRegex(RuntimeError, 'early reconstruction'):
            self.check(last_active=self.last | dict(monotonicNs=5))

    def test_skipped_install(self):
        with self.assertRaisesRegex(RuntimeError, 'installDist skipped'):
            self.check(outcomes=[self.tasks[0] | dict(skipped=True, didWork=False)])

    def test_changed_bundle(self):
        with self.assertRaisesRegex(RuntimeError, 'changed bundle'):
            self.check(staged_after='changed')

    def test_shell_lifetimes_without_cpu_progress_do_not_qualify(self):
        with self.assertRaisesRegex(RuntimeError, 'CPU progress'):
            self.check(last_active=self.last | dict(cpuTicks=10))

    def test_replacement_callback_refuses(self):
        with self.assertRaisesRegex(RuntimeError, 'replaced/deleted'):
            self.check(events=self.events + [dict(event='replaced', monotonicNs=5)])

    def test_missing_evidence_refuses_success_but_seals_failure_diagnostics(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-evidence-control-') as work:
            root = Path(work)
            (root / 'failure.stderr.log').write_text('retained failure')
            with self.assertRaisesRegex(RuntimeError, 'incomplete required evidence'):
                seal_evidence(root, True)
            seal_evidence(root, False)
            self.assertEqual(digest(root / 'failure.stderr.log'),
                             json.loads((root / 'evidence-index.json').read_text())['files']['failure.stderr.log']['sha256'])

    def test_actual_coordinator_missing_readiness_times_out(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-ready-control-') as work:
            owner = Commands(Path(work), Budget())
            try:
                child = owner.start(['sleep', '60'], 'no-readiness')
                with self.assertRaisesRegex(RuntimeError, 'timeout: actual analysis readiness'):
                    wait_for(owner, lambda: None, [child], .1, 'actual analysis readiness')
            finally:
                owner.close()

    def test_snapshot_covers_empty_directories_modes_inodes_and_manifest(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-control-') as work:
            root = Path(work)
            (root / 'empty').mkdir()
            (root / 'bundle.sha256').write_text('manifest')
            before = snapshot(root)
            require(set(before) == {'.', 'empty', 'bundle.sha256'}, 'incomplete inventory')
            temp = root / 'replacement'
            temp.write_text('manifest')
            temp.replace(root / 'bundle.sha256')
            self.assertIn('bundle.sha256', diff(before, snapshot(root), ('inode',)))

    def test_source_index_pins_modes_object_ids_and_gitlinks(self):
        parsed = parse_source_index(b'160000 ' + b'a' * 40 + b' 0\tmodule\0' +
                                    b'100755 ' + b'b' * 40 + b' 0\ttool/run\0')
        self.assertEqual([('160000', 'module'), ('100755', 'tool/run')],
                         [(item['mode'], item['path']) for item in parsed])
        invalid = [b'100644 ' + b'a' * 40 + b' 1\tfile\0',
                   b'100644 ' + b'a' * 40 + b' 0\tfile\0' +
                   b'100644 ' + b'b' * 40 + b' 0\tfile/child\0',
                   b'100644 ' + b'a' * 40 + b' 0\t../escape\0',
                   b'100644 ' + b'a' * 40 + b' 0\tfile\0' +
                   b'100644 ' + b'b' * 40 + b' 0\tfile\0']
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                parse_source_index(value)

    def test_source_index_requires_complete_nul_framing(self):
        with self.assertRaisesRegex(RuntimeError, 'malformed or oversized'):
            parse_source_index(b'100644 ' + b'a' * 40 + b' 0\tfile')

    def archive_fixture(self, root, kind, *, file_mode_override=None, directory_mode_override=None,
                        symlink=False, duplicate=False):
        staged = root / 'staged'
        (staged / 'empty').mkdir(parents=True, exist_ok=True)
        payload = b'bounded archive fixture\n'
        (staged / 'data.bin').write_bytes(payload)
        os.chmod(staged, 0o755)
        os.chmod(staged / 'empty', 0o755)
        os.chmod(staged / 'data.bin', 0o644)
        archive_path = root / ('fixture.zip' if kind == 'zip' else 'fixture.tar')
        prefix = 'fixture/libexec/ghidra'
        if kind == 'zip':
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(archive_path, 'w') as archive:
                    root_info = zipfile.ZipInfo(prefix + '/')
                    root_info.create_system = 3
                    root_info.external_attr = (stat.S_IFDIR | 0o755) << 16
                    archive.writestr(root_info, b'')
                    empty_info = zipfile.ZipInfo(prefix + '/empty/')
                    empty_info.create_system = 3
                    empty_info.external_attr = (stat.S_IFDIR | (directory_mode_override or 0o755)) << 16
                    archive.writestr(empty_info, b'')
                    file_info = zipfile.ZipInfo(prefix + '/data.bin')
                    file_info.create_system = 3
                    file_info.external_attr = (stat.S_IFREG | (file_mode_override if file_mode_override is not None else 0o644)) << 16
                    archive.writestr(file_info, payload)
                    if symlink:
                        link = zipfile.ZipInfo(prefix + '/link')
                        link.create_system = 3
                        link.external_attr = (stat.S_IFLNK | 0o777) << 16
                        archive.writestr(link, b'data.bin')
                    if duplicate:
                        archive.writestr(file_info, payload)
        else:
            with tarfile.open(archive_path, 'w') as archive:
                empty = tarfile.TarInfo(prefix + '/empty')
                empty.type = tarfile.DIRTYPE
                empty.mode = directory_mode_override or 0o755
                archive.addfile(empty)
                data = tarfile.TarInfo(prefix + '/data.bin')
                data.type = tarfile.REGTYPE
                data.mode = file_mode_override if file_mode_override is not None else 0o644
                data.size = len(payload)
                import io
                archive.addfile(data, io.BytesIO(payload))
                if symlink:
                    link = tarfile.TarInfo(prefix + '/link')
                    link.type = tarfile.SYMTYPE
                    link.mode = 0o777
                    link.linkname = 'data.bin'
                    archive.addfile(link)
                if duplicate:
                    duplicate_file = tarfile.TarInfo(prefix + '/data.bin')
                    duplicate_file.type = tarfile.REGTYPE
                    duplicate_file.mode = 0o644
                    duplicate_file.size = len(payload)
                    archive.addfile(duplicate_file, io.BytesIO(payload))
        return staged, archive_path, prefix

    def test_raw_archive_inventory_records_empty_and_implicit_directories(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-archive-inventory-') as work:
            root = Path(work)
            staged, zip_path, zip_prefix = self.archive_fixture(root, 'zip')
            zip_record = verify_archive_inventory(zip_path, 'zip', staged, zip_prefix)
            self.assertEqual(zip_record['fileCount'], 1)
            self.assertEqual({d['relative'] for d in zip_record['inventory']['directories']}, {'.', 'empty'})
            self.assertEqual(zip_record['implicitDirectoryCount'], 0)
            staged, tar_path, tar_prefix = self.archive_fixture(root, 'tar')
            tar_record = verify_archive_inventory(tar_path, 'tar', staged, tar_prefix)
            self.assertEqual(tar_record['fileCount'], 1)
            self.assertEqual({d['relative'] for d in tar_record['inventory']['directories']}, {'empty'})
            self.assertEqual(tar_record['inventory']['implicitDirectories'],
                             [dict(relative='.', mode=0o755, size=0, implicit=True)])

    def test_raw_archive_inventory_rejects_directory_mode_mismatch(self):
        for kind in ('zip', 'tar'):
            with self.subTest(archive=kind), tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-archive-mode-') as work:
                staged, path, prefix = self.archive_fixture(Path(work), kind, directory_mode_override=0o700)
                with self.assertRaisesRegex(RuntimeError, 'directory mode mismatch'):
                    verify_archive_inventory(path, kind, staged, prefix)

    def test_raw_archive_inventory_rejects_file_mode_mismatch(self):
        for kind in ('zip', 'tar'):
            with self.subTest(archive=kind), tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-archive-file-mode-') as work:
                staged, path, prefix = self.archive_fixture(Path(work), kind, file_mode_override=0o600)
                with self.assertRaisesRegex(RuntimeError, 'file mode/size mismatch'):
                    verify_archive_inventory(path, kind, staged, prefix)

    def test_raw_archive_inventory_rejects_symlinks(self):
        for kind in ('zip', 'tar'):
            with self.subTest(archive=kind), tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-archive-link-') as work:
                staged, path, prefix = self.archive_fixture(Path(work), kind, symlink=True)
                with self.assertRaisesRegex(RuntimeError, 'symlink|special'):
                    verify_archive_inventory(path, kind, staged, prefix)

    def test_raw_archive_inventory_rejects_duplicate_members(self):
        for kind in ('zip', 'tar'):
            with self.subTest(archive=kind), tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-archive-duplicate-') as work:
                staged, path, prefix = self.archive_fixture(Path(work), kind, duplicate=True)
                import warnings
                with warnings.catch_warnings(), self.assertRaisesRegex(RuntimeError, 'duplicate archive member'):
                    warnings.simplefilter('ignore', UserWarning)
                    verify_archive_inventory(path, kind, staged, prefix)

    def test_timeout_terminates_and_reaps_owned_grandchild(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-process-control-') as work:
            owner = Commands(Path(work), Budget())
            try:
                child = owner.start([sys.executable, '-c',
                    'import subprocess,time; subprocess.Popen(["sleep","60"]); time.sleep(60)'], 'owned')
                with self.assertRaisesRegex(RuntimeError, 'command timeout'):
                    owner.wait(child, .2)
            finally:
                owner.close()
            self.assertFalse(any(alive(p) for p in owner.identities.values()))

    def test_adopted_zombie_reaped_while_other_commands_are_still_live(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-reap-control-') as work:
            owner = Commands(Path(work), Budget())
            try:
                sleeper = owner.start(['sleep', '60'], 'still-live')
                parent = owner.start([sys.executable, '-c',
                    'import subprocess; subprocess.Popen(["sleep","0.1"])'], 'orphan')
                owner.wait(parent, 5)
                wait_for(owner, lambda: owner.reaped, [sleeper], 5, 'adopted child reaping')
                self.assertIsNone(sleeper.poll())
            finally:
                owner.close()

    def test_global_deadline_keeps_time_for_reaping_and_sealing(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='1903-budget-control-') as work:
            root = Path(work)
            budget = Budget(total_seconds=3, cleanup_reserve_seconds=2)
            owner = Commands(root, budget)
            try:
                child = owner.start([sys.executable, '-c', 'import time; time.sleep(60)'], 'budget-sleeper')
                with self.assertRaisesRegex(RuntimeError, 'deadline: command budget-sleeper'):
                    owner.wait(child, 60)
            finally:
                owner.close()
            self.assertIsNotNone(child.poll())
            self.assertFalse(any(alive(p) for p in owner.identities.values()))
            index_sha = seal_evidence(root, False, budget)
            self.assertEqual(index_sha, digest(root / 'evidence-index.json', budget, cleanup=True))
            self.assertLess(time.monotonic_ns(), budget.deadline_ns)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--allow-dirty', action='store_true', help='developer evidence only; report all unrelated dirty state')
    parser.add_argument('--pr-head')
    parser.add_argument('--pr-base')
    parser.add_argument('--deadline-seconds', type=int, default=DEFAULT_DEADLINE_SECONDS)
    parser.add_argument('--cleanup-reserve-seconds', type=int, default=DEFAULT_CLEANUP_RESERVE_SECONDS)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    (ROOT / 'build').mkdir(exist_ok=True)
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    parent = ROOT / 'build/ghidra-install-overlap'
    parent.mkdir(exist_ok=True)
    evidence = args.evidence.resolve() if args.evidence else Path(tempfile.mkdtemp(prefix='current-', dir=parent))
    require(evidence.is_relative_to(ROOT / 'build'), 'evidence must be beneath repository build/')
    if args.evidence:
        evidence.mkdir(parents=True, exist_ok=False)
    print('Current-run evidence: ' + str(evidence), flush=True)
    budget = Budget(args.deadline_seconds, args.cleanup_reserve_seconds)
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: (_ for _ in ()).throw(InterruptedError('qualification interrupted')))
    try:
        qualify(args, evidence, budget)
    except BaseException as error:
        print('QUALIFICATION FAILED: ' + str(error), file=sys.stderr)
        return 1
    print('Installed-runtime overlap qualified; inspect result.json for source cleanliness and scope.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
