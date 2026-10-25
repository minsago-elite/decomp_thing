#!/usr/bin/env python3
"""Provision the separate, disposable generated-C public-factory qualification host.

This operator action installs trusted host tools and finite mounts. It never compiles or
runs candidate code and never changes the provider's availability/assurance policy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

RUNTIME = Path('/opt/decomp-generated-c-validation-ci')
MOUNTS = Path('/var/lib/decomp-generated-c-validation-ci')
MAX_BYTES = 768 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_WORKER_BYTES = 256 * 1024 * 1024
MAX_WORKER_ENTRIES = 512
MAX_WORKER_MANIFEST_BYTES = 256 * 1024
FIXTURE_SOURCE = '''#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
int main(int argc, char **argv) {
    (void)argv;
    printf("args=%d\\n", argc - 1);
    for (int value; (value = getchar()) != EOF;) putchar(value);
    fputs("ordinary fixture stderr\\n", stderr);
    return argc > 2 ? 3 : 0;
}
'''


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('worker classpath manifest has duplicate fields')
        result[key] = value
    return result


def worker_path(value, build_root):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('worker classpath path is invalid')
    path = Path(value)
    if not path.is_absolute() or str(path) != value or path.resolve(strict=True) != path or not path.is_relative_to(build_root):
        raise ValueError('worker classpath must use canonical paths within checkout/build')
    return path


def read_module_worker_classpath(manifest, build_root, expected_uid=None):
    """Admit explicit data only; no classpath discovery, executable command, or user directory copy."""
    build_root = build_root.resolve(strict=True)
    path = worker_path(str(manifest), build_root)
    with open_worker_file(path, MAX_WORKER_MANIFEST_BYTES, expected_uid) as source:
        payload = source.read(MAX_WORKER_MANIFEST_BYTES + 1)
    if len(payload) > MAX_WORKER_MANIFEST_BYTES:
        raise ValueError('worker classpath manifest exceeds its byte bound')
    document = json.loads(payload, object_pairs_hook=no_duplicate_keys)
    if (not isinstance(document, dict) or set(document) != {'schemaVersion', 'entries'} or
            type(document['schemaVersion']) is not int or document['schemaVersion'] != 1):
        raise ValueError('worker classpath manifest differs from schema v1')
    entries = document['entries']
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_WORKER_ENTRIES:
        raise ValueError('worker classpath entry count exceeds its bound')
    admitted = []
    names, identities = set(), set()
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'path', 'bytes', 'sha256'}:
            raise ValueError('worker classpath entry differs from schema v1')
        path = worker_path(entry['path'], build_root)
        if path.suffix != '.jar' or path in names:
            raise ValueError('worker classpath requires distinct regular JAR paths')
        size, digest = entry['bytes'], entry['sha256']
        if (type(size) is not int or not 0 < size <= MAX_WORKER_BYTES or not isinstance(digest, str) or
                not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError('worker classpath entry size or digest is malformed')
        total += size
        if total > MAX_WORKER_BYTES:
            raise ValueError('worker classpath aggregate exceeds its byte bound')
        with open_worker_file(path, size, expected_uid) as source:
            identity = os.fstat(source.fileno())
            key = (identity.st_dev, identity.st_ino)
            if identity.st_size != size or key in identities:
                raise ValueError('worker classpath contains an alias or wrong file size')
            prefix = source.read(4)
            if prefix not in (b'PK\x03\x04', b'PK\x05\x06'):
                raise ValueError('worker classpath entry is not a JAR container')
            source.seek(0)
            digest_state = hashlib.sha256()
            count = 0
            while chunk := source.read(128 * 1024):
                count += len(chunk)
                if count > size:
                    raise ValueError('worker classpath grew during hashing')
                digest_state.update(chunk)
            actual = digest_state.hexdigest()
            if count != size or actual != digest or file_version(os.fstat(source.fileno())) != file_version(identity):
                raise ValueError('worker classpath entry changed or differs from its pin')
            if file_version(path.stat(follow_symlinks=False)) != file_version(identity):
                raise ValueError('worker classpath file name changed during admission')
        names.add(path)
        identities.add(key)
        admitted.append({'path': str(path), 'bytes': size, 'sha256': digest})
    return admitted


def file_version(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_worker_file(path, maximum, expected_uid=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum or
                expected_uid is not None and info.st_uid != expected_uid):
            raise ValueError('worker classpath input must be a bounded single-link regular file')
        return os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise


def copy_module_worker_classpath(entries, destination, expected_uid=None):
    """Copy only admitted exact file bytes; recheck pins at the privileged copy boundary."""
    destination.mkdir(mode=0o755)
    installed = []
    for index, entry in enumerate(entries):
        path = Path(entry['path'])
        target = destination / f'classpath-{index}.jar'
        digest = hashlib.sha256()
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(target_fd, 'wb') as output, open_worker_file(path, entry['bytes'], expected_uid) as source:
            before = os.fstat(source.fileno())
            count = 0
            while chunk := source.read(128 * 1024):
                count += len(chunk)
                if count > entry['bytes']:
                    raise ValueError('worker classpath grew during copy')
                digest.update(chunk)
                output.write(chunk)
            if (count != entry['bytes'] or digest.hexdigest() != entry['sha256'] or
                    file_version(os.fstat(source.fileno())) != file_version(before) or
                    file_version(path.stat(follow_symlinks=False)) != file_version(before) or path.resolve(strict=True) != path):
                raise ValueError('worker classpath changed during privileged copy')
            output.flush()
            os.fsync(output.fileno())
        target.chmod(0o444)
        installed.append({'path': str(target), 'bytes': count, 'sha256': entry['sha256']})
    return {'schemaVersion': 1, 'entries': installed}


def command(args, *, input_text=None):
    result = subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=True)
    if len(result.stdout.encode()) > 4 * 1024 * 1024:
        raise ValueError('operator tool output exceeded its bound')
    return result.stdout.strip()


def trusted(path):
    path = path.resolve(strict=True)
    for item in (path, *path.parents):
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f'operator source is writable or not root owned: {item}')
    return path


class Copier:
    def __init__(self):
        self.entries = 0
        self.bytes = 0

    def copy(self, source, destination, ancestors=frozenset()):
        source = trusted(source)
        info = source.stat()
        self.entries += 1
        if self.entries > MAX_ENTRIES or len(ancestors) > 64:
            raise ValueError('operator runtime copy exceeded entry/depth bounds')
        key = (info.st_dev, info.st_ino)
        if stat.S_ISDIR(info.st_mode):
            if key in ancestors:
                raise ValueError('operator runtime contains a directory cycle')
            destination.mkdir(mode=0o755, parents=True, exist_ok=True)
            for child in sorted(source.iterdir()):
                self.copy(child, destination / child.name, ancestors | {key})
        elif stat.S_ISREG(info.st_mode):
            self.bytes += info.st_size
            if self.bytes > MAX_BYTES:
                raise ValueError('operator runtime copy exceeded byte bound')
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if destination.exists():
                if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
                    raise ValueError(f'conflicting runtime destination: {destination}')
                return
            shutil.copyfile(source, destination)
            destination.chmod(0o555 if info.st_mode & 0o111 else 0o444)
        else:
            raise ValueError(f'operator runtime source is not a regular file/directory: {source}')


def marker(root, run_id):
    if root.is_symlink() or trusted(root) != root:
        raise ValueError('qualification root identity changed')
    record = root / 'qualification-owner.json'
    if record.is_symlink() or record.stat().st_size > 4096:
        raise ValueError('qualification owner record is invalid')
    if json.loads(record.read_text()) != {'runId': run_id, 'purpose': 'generated-c-public-factory-ci'}:
        raise ValueError('qualification root belongs to a different run')


def cleanup(run_id):
    for root in (RUNTIME, MOUNTS):
        if root.exists() or root.is_symlink():
            marker(root, run_id)
    if MOUNTS.exists():
        for name in ('output', 'source'):
            mount = MOUNTS / name
            if subprocess.run(['mountpoint', '--quiet', str(mount)], check=False).returncode == 0:
                fields = command(['findmnt', '--mountpoint', str(mount), '--noheadings', '--output', 'SOURCE,FSTYPE']).split()
                if fields != [f'decomp-generated-c-{name}', 'tmpfs']:
                    raise ValueError('qualification mount identity changed')
                descendants = command(['findmnt', '--submounts', '--mountpoint', str(mount), '--noheadings', '--output', 'TARGET']).splitlines()
                if descendants != [str(mount)]:
                    raise ValueError('qualification mount has unexpected child mounts')
                command(['umount', str(mount)])
        shutil.rmtree(MOUNTS)
    if RUNTIME.exists():
        shutil.rmtree(RUNTIME)


def prepare(args):
    if args.uid <= 0 or args.gid < 0:
        raise ValueError('qualification must run as a distinct non-root application user')
    for root in (RUNTIME, MOUNTS):
        if root.exists() or root.is_symlink():
            raise ValueError(f'refusing to adopt existing qualification target: {root}')
    worker = None
    if args.module_worker_classpath is not None:
        worker = read_module_worker_classpath(Path(args.module_worker_classpath),
                                            Path(__file__).resolve().parents[1] / 'build', args.uid)
    copier = Copier()
    try:
        for root in (RUNTIME, MOUNTS):
            root.mkdir(mode=0o755)
            (root / 'qualification-owner.json').write_text(json.dumps({
                'runId': args.run_id, 'purpose': 'generated-c-public-factory-ci'}))
        if worker is not None:
            worker_manifest = copy_module_worker_classpath(worker, RUNTIME / 'worker', args.uid)
            worker_manifest_path = RUNTIME / 'module-worker-classpath.json'
            worker_manifest_path.write_text(json.dumps(worker_manifest, sort_keys=True) + '\n')
            worker_manifest_path.chmod(0o444)
        tools = {}
        names = {'make': 'make', 'compiler': 'gcc', 'linker': 'ld', 'assembler': 'as',
                 'shell': 'dash', 'find': 'find', 'mkdir': 'mkdir'}
        filenames = {'compiler': 'cc', 'linker': 'ld', 'assembler': 'as', 'shell': 'sh'}
        for role, executable in names.items():
            source = trusted(Path('/usr/bin') / executable)
            destination = RUNTIME / 'tools' / filenames.get(role, role)
            copier.copy(source, destination)
            tools[role] = {'source': str(destination), 'destination': f'/decomp-generated-c-tools/{destination.name}'}
        gcc = trusted(Path('/usr/bin/gcc'))
        gcc_runtime = trusted(Path(command([str(gcc), '-print-libgcc-file-name'])).parent)
        copier.copy(gcc_runtime, RUNTIME / 'gcc')
        build = [{'source': str(RUNTIME / 'gcc'), 'destination': str(gcc_runtime)}]
        # The qualification image intentionally retains only the system headers needed by the
        # fixed benign stdio/stddef/stdint fixture. A general deployment supplies its own reviewed closure.
        dependency_text = command([str(gcc), '-M', '-x', 'c', '-'], input_text=FIXTURE_SOURCE)
        headers = dependency_text.replace('\\\n', ' ').partition(':')[2].split()
        for header in headers:
            path = Path(header)
            if not path.is_absolute():
                raise ValueError('unexpected relative compiler header dependency')
            if path.is_relative_to('/usr/include'):
                copier.copy(path, RUNTIME / 'headers' / path.relative_to('/usr/include'))
            elif not path.resolve().is_relative_to(gcc_runtime):
                raise ValueError(f'unsupported compiler header authority: {path}')
        build.append({'source': str(RUNTIME / 'headers'), 'destination': '/usr/include'})
        link_parent = None
        for name in ('crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'libc.so', 'libc_nonshared.a'):
            path = Path(command([str(gcc), f'-print-file-name={name}'])).absolute().resolve()
            if path.name != name or not path.is_file():
                raise ValueError(f'missing reviewed GCC link input: {name}')
            if link_parent is None:
                link_parent = path.parent
            if path.parent != link_parent:
                raise ValueError('GCC link inputs require different undeclared roots')
            copier.copy(path, RUNTIME / 'link' / name)
        build.append({'source': str(RUNTIME / 'link'), 'destination': str(link_parent)})
        libraries = {}
        # ldd only inspects immutable operator-supplied host tools and compiler internals.
        # Candidate or rebuilt executables are never passed to this provisioning helper.
        elf_inputs = [Path('/usr/bin') / name for name in names.values()] + [gcc_runtime / 'cc1', gcc_runtime / 'collect2']
        for executable in elf_inputs:
            output = command(['/usr/bin/ldd', str(trusted(executable))])
            for line in output.splitlines():
                if 'not found' in line:
                    raise ValueError(f'incomplete operator dynamic runtime: {line}')
                for value in re.findall(r'(?:^|\s)(/[^\s()]+)', line):
                    path = Path(value)
                    libraries[str(path)] = path
        runtime = []
        for index, (destination, source) in enumerate(sorted(libraries.items())):
            copied = RUNTIME / 'libraries' / f'{index:03d}-{source.name}'
            copier.copy(source, copied)
            runtime.append({'source': str(copied), 'destination': destination})
        if len(build) + len(runtime) > 48:
            raise ValueError('qualification runtime exceeds production mount bound')
        helper = Path(args.gate_helper).resolve(strict=True)
        if helper.stat().st_size > 4 * 1024 * 1024 or hashlib.sha256(helper.read_bytes()).hexdigest() != args.gate_sha256:
            raise ValueError('built gate helper differs from its explicit operator pin')
        shutil.copyfile(helper, RUNTIME / 'gate-helper')
        (RUNTIME / 'gate-helper').chmod(0o555)
        # The reference is a fixed trusted qualification fixture, never a candidate input.
        reference_source = RUNTIME / 'reference.c'
        reference_source.write_text(FIXTURE_SOURCE)
        reference_source.chmod(0o444)
        command([str(gcc), '-std=c11', '-O0', '-o', str(RUNTIME / 'reference'), str(reference_source)])
        (RUNTIME / 'reference').chmod(0o555)
        for name in ('source', 'output'):
            target = MOUNTS / name
            target.mkdir(mode=0o700)
            # Captured executable files are admitted from source; output is data only.
            execute = 'exec' if name == 'source' else 'noexec'
            command(['mount', '-t', 'tmpfs', '-o',
                     f'rw,nodev,nosuid,{execute},size=64M,nr_inodes=4096,uid={args.uid},gid={args.gid},mode=0700',
                     f'decomp-generated-c-{name}', str(target)])
        plan = {'schemaVersion': 1, 'profileId': 'generated-c-make-v1',
                'sandboxConfigurationFile': str(RUNTIME / 'sandbox.json'), 'tools': tools,
                'buildRuntimeMounts': build + runtime, 'programRuntimeMounts': runtime,
                'sourceTmpfs': str(MOUNTS / 'source'), 'outputTmpfs': str(MOUNTS / 'output')}
        (RUNTIME / 'runtime-plan.json').write_text(json.dumps(plan, sort_keys=True) + '\n')
        summary = {'runtimePlan': str(RUNTIME / 'runtime-plan.json'), 'runtimeEntries': copier.entries,
                   'runtimeBytes': copier.bytes, 'sourceTmpfs': plan['sourceTmpfs'], 'outputTmpfs': plan['outputTmpfs']}
        if worker is not None:
            summary.update({'moduleWorkerManifest': str(RUNTIME / 'module-worker-classpath.json'),
                            'moduleWorkerEntries': len(worker), 'moduleWorkerBytes': sum(entry['bytes'] for entry in worker)})
        print(json.dumps(summary))
    except BaseException:
        cleanup(args.run_id)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'cleanup'))
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--uid', type=int)
    parser.add_argument('--gid', type=int)
    parser.add_argument('--gate-helper')
    parser.add_argument('--gate-sha256')
    parser.add_argument('--module-worker-classpath', help='optional pinned JAR manifest under checkout/build for contained module qualification')
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', args.run_id):
        parser.error('requires an explicit root operator invocation and portable CI run identity')
    if args.action == 'cleanup':
        cleanup(args.run_id)
    else:
        if any(value is None for value in (args.uid, args.gid, args.gate_helper, args.gate_sha256)):
            parser.error('prepare requires uid, gid, gate-helper and gate-sha256')
        if not re.fullmatch('[0-9a-f]{64}', args.gate_sha256):
            parser.error('gate-sha256 must be the full helper content digest')
        prepare(args)


if __name__ == '__main__':
    main()
