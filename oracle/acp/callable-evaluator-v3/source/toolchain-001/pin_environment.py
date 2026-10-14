"""Static v3 toolchain pin API; import and CLI never execute a compiler.

A recorded command is not native qualification. Authorized real driver/link
inventory capture is a separate later gate. Revalidation rebuilds resolutions,
script/response recursion, directories/configuration and symlink identities.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import stat

_spec = importlib.util.spec_from_file_location('callable_v3_link_inputs', Path(__file__).with_name('link_inputs.py'))
link_inputs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(link_inputs)


_monitor_spec = importlib.util.spec_from_file_location('callable_v3_monitor_inputs', Path(__file__).with_name('monitor_inputs.py'))
monitor_inputs = importlib.util.module_from_spec(_monitor_spec)
_monitor_spec.loader.exec_module(monitor_inputs)
BASE = Path(__file__).resolve().parent.parent


def collect_pin(manifest, filesystem_root):
    # Validate every record before any filesystem work; one shared descriptor/IO budget.
    link_inputs.validate_manifest(manifest)
    monitor_inputs.validate_monitor(manifest['monitor'], link_inputs)
    monitor_inputs.validate_inspection(manifest['inspection'], link_inputs)
    resolver = link_inputs.Resolver(filesystem_root)
    closure = link_inputs.collect(manifest, filesystem_root, resolver=resolver)
    monitor = monitor_inputs.collect_monitor(manifest['monitor'], resolver, link_inputs)
    inspection = monitor_inputs.collect_inspection(manifest['inspection'], resolver, link_inputs)
    return {'schemaVersion':3, 'status':'static-recording-unqualified', 'gccTarget':'x86_64-pc-linux-gnu',
            'implicitLinkClosure':closure, 'monitorClosure':monitor, 'inspectionClosure':inspection,
            'dependencies':{name:row['sha256'] for name,row in sorted(resolver.files.items())}}


def revalidate_pin(pin, filesystem_root):
    """Return fully rebuilt equal pin, or raise Refusal; never launches a tool."""
    link_inputs.exact(pin, ('schemaVersion', 'status', 'gccTarget', 'implicitLinkClosure',
                           'monitorClosure', 'inspectionClosure', 'dependencies'))
    if type(pin['schemaVersion']) is not int or pin['schemaVersion'] != 3:
        raise link_inputs.Refusal('v3 toolchain pin required')
    try:
        rebuilt = collect_pin(pin['implicitLinkClosure']['manifest'], filesystem_root)
    except OSError as error:
        raise link_inputs.Refusal('machine closure input unavailable') from error
    if link_inputs.canonical(rebuilt) != link_inputs.canonical(pin):
        raise link_inputs.Refusal('toolchain pin closure/configuration/selection drift')
    return rebuilt


def _read_json(path):
    """Bound descriptor size before parsing; duplicate/float/identity changes refuse."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= link_inputs.MAX_MANIFEST:
                raise link_inputs.Refusal('recording is not bounded regular JSON')
            chunks = []; size = 0
            while size <= before.st_size:
                block = os.read(descriptor, min(link_inputs.BLOCK, before.st_size - size + 1))
                if not block: break
                size += len(block)
                if size > before.st_size: raise link_inputs.Refusal('recording grew beyond reserved bytes')
                chunks.append(block)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            for current in (os.fstat(descriptor), Path(path).stat(follow_symlinks=False)):
                if size != before.st_size or any(getattr(before, key) != getattr(current, key) for key in fields):
                    raise link_inputs.Refusal('recording identity changed during descriptor read')
        finally:
            os.close(descriptor)
    except OSError as error:
        raise link_inputs.Refusal('fixed operational recording unavailable') from error
    raw = b''.join(chunks)
    return monitor_inputs.strict_json(raw, link_inputs), link_inputs.sha(raw)


def load_manifest(path):
    value, _ = _read_json(path)
    link_inputs.validate_manifest(value)
    return value


def _load_operational(profile):
    # Operational byte closure is eligible for the fixed public primitive controls;
    # it remains UNQUALIFIED and cannot satisfy native-qualified/preparation gates.
    digest = profile.get('toolchainEnvironmentPinSha256') if type(profile) is dict else None
    import re
    if type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None:
        raise link_inputs.Refusal('profile-bound environment pin required before worker')
    value, observed = _read_json(BASE / 'toolchain-001/environment-pin.json')
    if observed != digest: raise link_inputs.Refusal('environment pin byte hash mismatch')
    rebuilt = revalidate_pin(value, Path('/'))
    record = rebuilt['monitorClosure']['record']
    fixed = {'sourcePath': BASE / 'worker_exec_monitor.c', 'parserPath': BASE / 'worker_exec_proof.py',
             'protocolPath': BASE / 'contracts/worker-exec-proof-schema.json',
             'buildScriptPath': BASE / 'toolchain-001/build_worker_monitor.py',
             'provisioningManifestPath': BASE / 'toolchain-001/worker-exec-monitor.json'}
    if any(record[key] != str(path) for key, path in fixed.items()):
        raise link_inputs.Refusal('operational pin does not bind fixed public monitor artifacts')
    return rebuilt, observed


def _dependencies(closure, names):
    result = {}
    for name in names:
        row = closure['files'][name]
        previous = result.get(row['realpath'])
        if previous is not None and previous != row['sha256']:
            raise link_inputs.Refusal('conflicting canonical runtime identity')
        result[row['realpath']] = row['sha256']
    if not result: raise link_inputs.Refusal('empty operational runtime dependencies')
    return [{'path': name, 'sha256': digest} for name, digest in sorted(result.items())]


def load_monitor_binding(profile):
    value, digest = _load_operational(profile)
    closure = value['monitorClosure']; record = closure['record']; files = closure['files']
    runtime = set(closure['elfGraph']) - {record['binaryPath']}
    runtime.add(record['cachePath'])
    return {'binaryPath':files[record['binaryPath']]['realpath'], 'binarySha256':files[record['binaryPath']]['sha256'],
            'sourceSha256':files[record['sourcePath']]['sha256'], 'parserSha256':files[record['parserPath']]['sha256'],
            'protocolSha256':files[record['protocolPath']]['sha256'],
            'manifestSha256':files[record['provisioningManifestPath']]['sha256'],
            'environmentPinSha256':digest, 'dependencies':_dependencies(closure, runtime), 'closure':closure}



def load_compiler_binding(profile):
    """Expose every existing recorded implicit-link input, never native qualification.

    This view does not represent unrecorded compiler/header/runtime inputs or bind
    a worker execution. The fixed operational gate rebuilds the whole recording
    under the existing Resolver budget before any view is returned.
    """
    value, digest = _load_operational(profile)
    closure = value['implicitLinkClosure']; manifest = closure['manifest']
    if (value['status'] != 'static-recording-unqualified' or
            closure['status'] != 'static-recording-unqualified' or
            not closure['files'] or not closure['directories'] or not closure['selections']):
        raise link_inputs.Refusal('complete static recorded implicit-link closure required')
    return {'status':'static-recording-unqualified', 'scope':'recorded-implicit-link-inputs',
            'environmentPinSha256':digest,
            'closureSha256':link_inputs.sha(link_inputs.canonical(closure)),
            'driverArgv':manifest['driverArgv'], 'workingDirectory':manifest['workingDirectory'],
            'environment':manifest['environment'],
            'dependencies':_dependencies(closure, closure['files']), 'closure':closure}


def load_inspection_binding(profile):
    value, digest = _load_operational(profile)
    closure = value['inspectionClosure']; record = closure['record']; files = closure['files']
    result = {'environmentPinSha256':digest, 'dependencies':_dependencies(closure, files), 'closure':closure}
    for name, key in [('bash','bashPath'), ('script','scriptPath'), ('cache','cachePath')]:
        result[name + 'Path'] = files[record[key]]['realpath']
        result[name + 'Sha256'] = files[record[key]]['sha256']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--filesystem-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = collect_pin(load_manifest(args.manifest), args.filesystem_root)
    with args.output.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
    print('static-recording-unqualified')


if __name__ == '__main__':
    main()
