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


if __name__ == '__main__':
    try:
        mode, *arguments = sys.argv[1:]
        need(len(arguments) == (2 if mode == 'verify-uploaded' else 0))
        if mode == 'pin':
            publish(PIN, dict(schemaVersion=1, pinnedAtNanos=time.time_ns(), **current()))
        elif mode == 'seal':
            seal()
        elif mode == 'verify':
            verify()
        elif mode == 'verify-uploaded':
            verify_uploaded(Path(arguments[0]), Path(arguments[1]))
        else:
            need(False)
    except Exception:
        # Do not dump paths, Git output, JVM options, or arbitrary source contents on rejection.
        sys.exit('Invocation qualification proof is missing or inconsistent')
