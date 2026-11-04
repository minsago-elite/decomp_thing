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
import zipfile

SPEC = importlib.util.spec_from_file_location('atomic_artifact_io', pathlib.Path(__file__).with_name('atomic_install_prepared.py'))
io = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(io)
ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = 'orchestration/atomic-install-ci/artifact-manifest.json'


def rules(repo):
    text = (repo / '.github/workflows/ci.yml').read_text()
    job = re.search(r'^  atomic-install:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)', text, re.M | re.S)
    io.require(job is not None, 'atomic-install job missing')
    block = re.search(r'^          path: \|\n((?:            [^\n]+\n)+)', job[1], re.M)
    io.require(block is not None, 'atomic artifact path block missing')
    paths = [p.strip() for p in block[1].splitlines()]
    io.require(all(p.lstrip('!').startswith('build/') and '..' not in p for p in paths), 'artifact pattern escapes build/')
    return paths


def matches(pattern, path):
    expression = re.escape(pattern).replace(r'\*\*', '.*').replace(r'\*', '[^/]*').replace(r'\?', '[^/]')
    return re.fullmatch(expression, path) is not None


def selected(paths, name):
    if any(part.startswith('.') for part in pathlib.PurePosixPath(name).parts):
        return False  # upload-artifact default include-hidden-files=false
    return any(matches(p, name) for p in paths if not p.startswith('!')) and not any(
        matches(p[1:], name) for p in paths if p.startswith('!'))


def membership_controls(paths):
    base = 'build/orchestration/atomic-install-remediation/installed-current/'
    kept = ['qualification.json', 'prepared-A.json', 'prepared-retained.json', 'prepared-closure.json', 'prepared-guard.json',
            *[p + s + '.json' for p in ('protected', 'prepared-input') for s in ('-before', '-after', '-diff')],
            *[f'command-{i:02d}' + s for i in range(13) for s in ('.init.gradle', '.init.json', '-events.json')],
            'command-01-plan.json', 'command-02-plan.json', 'barriers/A-none-current/READY',
            'barriers/A-none-current/READY.loaded', 'barriers/A-none-current/RELEASE', 'barriers/A-none-current/launcher.log']
    omitted = ['root-build/install/llm_bin_patch/lib/app.jar', 'prepared-products/000001', 'home/cache', 'tmp/output']
    for name in kept:
        io.require(selected(paths, base + name), 'artifact omits ' + name)
    for name in omitted:
        io.require(not selected(paths, base + name), 'artifact includes products/cache: ' + name)
    io.require(selected(paths, 'build/' + MANIFEST), 'artifact omits manifest')
    return {'retained': len(kept) + 1, 'excluded': len(omitted)}


def seal(repo):
    paths = rules(repo)
    controls = membership_controls(paths)
    budget = [io.MAX_INPUT_BYTES]
    files = {}
    visited = [0]
    roots = set()
    for pattern in paths:
        if pattern.startswith('!'): continue
        parts = pathlib.PurePosixPath(pattern).parts
        plain = []
        for part in parts:
            if '*' in part or '?' in part: break
            plain.append(part)
        roots.add(repo.joinpath(*plain))
    def walk(path):
        visited[0] += 1
        io.require(visited[0] <= io.MAX_INPUT_ENTRIES, 'artifact traversal exceeds entry bound')
        name = path.relative_to(repo).as_posix()
        if any(part.startswith('.') for part in path.relative_to(repo).parts): return
        if any(p.startswith('!') and p.endswith('/**') and matches(p[1:-3], name) for p in paths): return
        io.safe_path(path, repo)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as children:
                for child in children: walk(pathlib.Path(child.path))
        elif selected(paths, name) and name != 'build/' + MANIFEST:
            io.require(len(files) < io.MAX_INPUT_ENTRIES, 'artifact entry count exceeds bound')
            receipt = io.file_receipt(path, budget)
            files[name.removeprefix('build/')] = {k: receipt[k] for k in ('sha256', 'bytes')}
    for root in sorted(roots):
        if root.exists(): walk(root)
    target = repo / 'build' / MANIFEST
    target.parent.mkdir(parents=True, exist_ok=True)
    io.write_json(target, {'schemaVersion': 1, 'members': files, 'patterns': paths, 'staticMembership': controls})
    return {'manifest': str(target), 'sha256': io.file_receipt(target)['sha256'], 'members': len(files), **controls}


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
