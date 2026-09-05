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
FIXTURE_SOURCE = '''#include <stdio.h>
int main(int argc, char **argv) {
    (void)argv;
    printf("args=%d\\n", argc - 1);
    for (int value; (value = getchar()) != EOF;) putchar(value);
    fputs("ordinary fixture stderr\\n", stderr);
    return argc > 2 ? 3 : 0;
}
'''


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
    copier = Copier()
    try:
        for root in (RUNTIME, MOUNTS):
            root.mkdir(mode=0o755)
            (root / 'qualification-owner.json').write_text(json.dumps({
                'runId': args.run_id, 'purpose': 'generated-c-public-factory-ci'}))
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
        # fixed benign stdio fixture. A general deployment supplies its own reviewed closure.
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
        print(json.dumps({'runtimePlan': str(RUNTIME / 'runtime-plan.json'), 'runtimeEntries': copier.entries,
                          'runtimeBytes': copier.bytes, 'sourceTmpfs': plan['sourceTmpfs'], 'outputTmpfs': plan['outputTmpfs']}))
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
