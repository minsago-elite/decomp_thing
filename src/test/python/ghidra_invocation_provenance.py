#!/usr/bin/env python3
"""Read-only build witness except its two private repo-local manifests.

pin BEFORE a forced compile, seal AFTER installDist, verify in the installed probe.
This is diagnostic build provenance, never oracle authorization. No build is run here.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'build/orchestration'
PIN = OUT / 'ghidra-invocation-source-pin.json'
SEALED = OUT / 'ghidra-invocation-build-provenance.json'
LIMIT = 1024 * 1024


def need(condition):
    if not condition:
        raise ValueError('Invocation qualification proof is missing or inconsistent')


def digest(path, limit=512 * 1024 * 1024):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit)
    value = hashlib.sha256()
    total = 0
    with path.open('rb') as stream:
        while chunk := stream.read(65536):
            total += len(chunk)
            need(total <= limit)
            value.update(chunk)
    return value.hexdigest()


def git(*args):
    # Bounded by repository inventory; no command content or environment is retained.
    process = subprocess.Popen(['git', *args], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        output = process.stdout.read(LIMIT + 1)
        need(len(output) <= LIMIT)
        need(process.wait(timeout=5) == 0)
        return output.decode()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close()


def inventory():
    names = set(git('ls-files', '-z', '--cached', '--others', '--exclude-standard').split('\0'))
    names = sorted(name for name in names if name.startswith(('src/', 'ghidra-bridge/')) or
                   name in ('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties'))
    need(0 < len(names) <= 8192)
    return {name: digest(ROOT / name, 16 * 1024 * 1024) for name in names}


def current():
    return dict(head=git('rev-parse', 'HEAD').strip(),
                dirty=git('status', '--porcelain=v1', '--untracked-files=all').splitlines(), sources=inventory())


def read(path):
    need(path.stat().st_size <= LIMIT)
    return json.loads(path.read_bytes())


def publish(path, value):
    content = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(len(content) <= LIMIT)
    OUT.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.private-' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
        os.replace(temporary, path)
        need(path.stat().st_mode & 0o777 == 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def validate_sources(pin):
    actual = current()
    need(all(pin[key] == actual[key] for key in actual))


def archive_bytes(archive, name):
    entry = archive.getinfo(name)
    need(0 <= entry.file_size <= 16 * 1024 * 1024)
    with archive.open(entry) as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    need(len(data) == entry.file_size)
    return data


HELPER_ROOTS = ('GhidraDotDirectoryInvocationQualificationTest', 'GhidraInstalledInvocationProbe', 'InvocationQualification')
HELPER_PACKAGE = 'decompengine/project/'
HELPER_SOURCES = {
    'GhidraDotDirectoryInvocationQualificationTest': 'GhidraDotDirectoryInvocationQualificationTest.kt',
    'GhidraInstalledInvocationProbe': 'GhidraDotDirectoryInvocationQualificationTest.kt',
    'InvocationQualification': 'GhidraInvocationQualificationSupport.kt',
}
HELPER_DIRECTORIES = ('build/classes/kotlin/test', 'build/classes/java/test')


def helper_name(name):
    return any(name == HELPER_PACKAGE + root + '.class' or
               name.startswith(HELPER_PACKAGE + root + '$') and name.endswith('.class') for root in HELPER_ROOTS)


def class_binding(data):
    """Read only class identity/references/SourceFile, never execute the helper."""
    import struct
    offset = 0
    def take(size):
        nonlocal offset
        need(0 <= size <= len(data) - offset)
        value = data[offset:offset + size]
        offset += size
        return value
    def u2(): return struct.unpack('>H', take(2))[0]
    def u4(): return struct.unpack('>I', take(4))[0]
    need(take(4) == b'\xca\xfe\xba\xbe')
    take(4)
    pool = [None] * u2()
    index = 1
    while index < len(pool):
        tag = take(1)[0]
        if tag == 1:
            # Modified UTF-8 strings unrelated to class identity need not be decoded.
            pool[index] = (tag, take(u2()))
        elif tag in (7, 8, 16, 19, 20): pool[index] = (tag, u2())
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18): take(4)
        elif tag in (5, 6): take(8); index += 1
        elif tag == 15: take(3)
        else: need(False)
        index += 1
    def text(index):
        need(0 < index < len(pool) and pool[index] is not None and pool[index][0] == 1)
        return pool[index][1].decode('ascii')
    def class_name(index):
        need(0 < index < len(pool) and pool[index] is not None and pool[index][0] == 7)
        return text(pool[index][1])
    take(2)
    defining = class_name(u2())
    take(2)
    take(2 * u2())
    def attributes():
        return [(text(u2()), take(u4())) for _ in range(u2())]
    for _ in range(2):
        for _ in range(u2()):
            take(6)
            attributes()
    source_files = [value for name, value in attributes() if name == 'SourceFile']
    need(offset == len(data) and len(source_files) == 1 and len(source_files[0]) == 2)
    source = text(struct.unpack('>H', source_files[0])[0])
    references = {class_name(i) + '.class' for i, entry in enumerate(pool) if entry and entry[0] == 7}
    return defining + '.class', source, {name for name in references if helper_name(name)}


def helper_closure(pin, jars):
    locations = []
    for directory in HELPER_DIRECTORIES:
        root = ROOT / directory
        paths = sorted(p for p in (root / HELPER_PACKAGE).glob('*.class') if helper_name(p.relative_to(root).as_posix()))
        need(len(paths) <= 1024)
        if paths: locations.append((directory, paths))
    need(len(locations) == 1)
    directory, paths = locations[0]
    root = ROOT / directory
    need(root.resolve() == root and not root.is_symlink())
    classes, references = {}, {}
    sources = {}
    for path in paths:
        need(path.resolve() == path and path.stat().st_mtime_ns >= pin['pinnedAtNanos'])
        name = path.relative_to(root).as_posix()
        classes[name] = digest(path, 16 * 1024 * 1024)
        defining, source, refs = class_binding(path.read_bytes())
        need(defining == name)
        owner = name.removeprefix(HELPER_PACKAGE).removesuffix('.class').split('$')[0]
        need(source == HELPER_SOURCES[owner])
        source_path = 'src/test/kotlin/decompengine/project/' + source
        need(pin['sources'].get(source_path) == digest(ROOT / source_path, 16 * 1024 * 1024))
        sources[source_path] = pin['sources'][source_path]
        references[name] = refs
    pending = [HELPER_PACKAGE + name + '.class' for name in HELPER_ROOTS]
    reached = set()
    while pending:
        name = pending.pop()
        if name in reached: continue
        need(name in classes)
        reached.add(name)
        pending.extend(references[name] - reached)
    need(reached == set(classes))
    # Installed application JARs remain first; no helper may hide in any of them.
    for jar in jars:
        with zipfile.ZipFile(jar) as archive:
            need(len(archive.infolist()) <= 65536)
            need(not any(helper_name(name) for name in archive.namelist()))
    return dict(directory=directory, classes=classes, sources=sources,
                closureSha256=hashlib.sha256(json.dumps(classes, sort_keys=True).encode()).hexdigest())


def seal():
    pin = read(PIN)
    validate_sources(pin)
    installed = ROOT / 'build/install/llm_bin_patch'
    jars = sorted((installed / 'lib').glob('*.jar'))
    need(0 < len(jars) <= 256)
    applications = []
    for jar in jars:
        digest(jar)
        with zipfile.ZipFile(jar) as archive:
            need(len(archive.infolist()) <= 65536)
            if 'decompengine/analysis/GhidraJvmAnalyzer.class' in archive.namelist():
                applications.append(jar)
    need(len(applications) == 1)
    application = applications[0]
    classes = {}
    with zipfile.ZipFile(application) as archive:
        for directory in ('build/classes/kotlin/main', 'build/classes/java/main'):
            for compiled in sorted((ROOT / directory).rglob('*.class')):
                name = compiled.relative_to(ROOT / directory).as_posix()
                need(compiled.stat().st_mtime_ns >= pin['pinnedAtNanos'])
                data = archive_bytes(archive, name)
                need(len(data) <= 16 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == digest(compiled))
                classes[name] = hashlib.sha256(data).hexdigest()
        need(all(name in classes for name in (
            'decompengine/analysis/GhidraJvmAnalyzer.class', 'decompengine/analysis/PreparedGhidraCommand.class',
            'decompengine/analysis/GhidraInvocationReceipt.class', 'decompengine/analysis/BundledGhidra.class',
            'decompengine/project/GhidraHeadlessProgramModelAnalyzer.class')))
        for name in ('ExportProgramModelOwned.java', 'ExportProgramModel.java'):
            data = archive_bytes(archive, 'ghidra_scripts/' + name)
            need(hashlib.sha256(data).hexdigest() == digest(ROOT / 'src/main/resources/ghidra_scripts' / name))
    bridge = installed / 'libexec/ghidra/decomp-ghidra-bridge.jar'
    digest(bridge)
    bridge_classes = {}
    script_artifacts = []
    with zipfile.ZipFile(bridge) as archive:
        need(len(archive.infolist()) <= 65536)
        directory = ROOT / 'ghidra-bridge/build/classes/java/main'
        for compiled in sorted(directory.rglob('*.class')):
            name = compiled.relative_to(directory).as_posix()
            need(compiled.stat().st_mtime_ns >= pin['pinnedAtNanos'])
            # Match the explicit root-package exclusions in ghidra-bridge's jar/stageBundle.
            # These classes remain compiled evidence; their installed home is scripts/, not the JAR.
            is_script = name == 'RunBundledExports.class' or (
                '/' not in name and name.startswith('ExportNativeCallsV1') and name.endswith('.class'))
            if is_script:
                need(name not in archive.namelist())
                script = installed / 'libexec/ghidra/scripts' / name
                actual = digest(script, 16 * 1024 * 1024)
                script_artifacts.append(script)
            else:
                actual = hashlib.sha256(archive_bytes(archive, name)).hexdigest()
            need(actual == digest(compiled))
            bridge_classes[name] = actual
        need('decompengine/ghidra/BundledGhidraWorker.class' in bridge_classes)
    pin['compiledBridgeClosureSha256'] = hashlib.sha256(json.dumps(bridge_classes, sort_keys=True).encode()).hexdigest()
    artifacts = jars + [bridge, installed / 'libexec/ghidra/bundle.sha256'] + script_artifacts
    # Class closure digest is bounded even for large application JARs; application bytes are also pinned.
    pin['compiledClassClosureSha256'] = hashlib.sha256(json.dumps(classes, sort_keys=True).encode()).hexdigest()
    pin['artifacts'] = {p.relative_to(ROOT).as_posix(): digest(p) for p in artifacts}
    pin['testHelpers'] = helper_closure(pin, jars)
    pin['sourcePinSha256'] = digest(PIN)
    validate_sources(pin)
    publish(SEALED, pin)


def verify():
    pin = read(SEALED)
    validate_sources(pin)
    need(digest(PIN) == pin['sourcePinSha256'])
    for name, expected in pin['artifacts'].items():
        path = ROOT / name
        need(not Path(name).is_absolute() and path.resolve().is_relative_to(ROOT))
        need(digest(path) == expected)
    jars = sorted((ROOT / 'build/install/llm_bin_patch/lib').glob('*.jar'))
    need(0 < len(jars) <= 256)
    library = Path('build/install/llm_bin_patch/lib')
    sealed_jars = {name for name in pin['artifacts'] if Path(name).parent == library and Path(name).suffix == '.jar'}
    need({path.relative_to(ROOT).as_posix() for path in jars} == sealed_jars)
    need(helper_closure(pin, jars) == pin['testHelpers'])
    print('invocation-build-provenance-verified')


def verify_uploaded(expected, downloaded):
    """Check actual downloaded upload bytes against the completed same-job qualification set."""
    names = ('retained-invocation.json', 'observed-worker.json', 'compiler.json', 'provenance.json')
    for name in names:
        need(digest(expected / name, LIMIT) == digest(downloaded / name, LIMIT))
    provenance = read(downloaded / 'provenance.json')
    need(provenance['schemaVersion'] == 1 and set(provenance['evidence']) == set(names[:-1]))
    for name in names[:-1]:
        need(provenance['evidence'][name] == digest(downloaded / name, LIMIT))
    need(read(downloaded / 'observed-worker.json')['runId'] == provenance['runId'])
    print('invocation-uploaded-evidence-verified')


DIAGNOSTIC_NAMES = frozenset(('observer-failure.json', 'observer-followup.json', 'observer-cleanup.json', 'child-failure.json',
                            'parent-process-failure.json', 'parent-setup-failure.json', 'build-provenance.json'))


def verify_uploaded_diagnostics(expected, downloaded):
    """Failure retention check only. No success manifest or runtime acceptance is inferred."""
    def members(root):
        need(root.is_dir() and not root.is_symlink())
        runs = sorted(root.glob('run-*'))
        need(len(runs) <= 256)
        files = {}
        for directory in [root] + runs:
            need(directory.is_dir() and not directory.is_symlink())
            for name in sorted(DIAGNOSTIC_NAMES):
                path = directory / name
                if path.exists() or path.is_symlink():
                    files[path.relative_to(root).as_posix()] = digest(path, LIMIT if name == 'build-provenance.json' else 4096)
        return files
    original = members(expected)
    need(original and any(Path(name).name.endswith('failure.json') for name in original))
    need(original == members(downloaded))
    print('invocation-uploaded-diagnostics-verified')


if __name__ == '__main__':
    try:
        mode, *arguments = sys.argv[1:]
        need(len(arguments) == (2 if mode in ('verify-uploaded', 'verify-uploaded-diagnostics') else 0))
        if mode == 'pin':
            publish(PIN, dict(schemaVersion=1, pinnedAtNanos=time.time_ns(), **current()))
        elif mode == 'seal':
            seal()
        elif mode == 'verify':
            verify()
        elif mode == 'verify-uploaded':
            verify_uploaded(Path(arguments[0]), Path(arguments[1]))
        elif mode == 'verify-uploaded-diagnostics':
            verify_uploaded_diagnostics(Path(arguments[0]), Path(arguments[1]))
        else:
            need(False)
    except Exception:
        # Do not dump paths, Git output, JVM options, or arbitrary source contents on rejection.
        sys.exit('Invocation qualification proof is missing or inconsistent')
