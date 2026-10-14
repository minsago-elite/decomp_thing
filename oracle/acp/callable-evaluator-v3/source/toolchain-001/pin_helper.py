"""Pin the explicitly built v3 helper and its compiler/runtime dependencies."""
from pathlib import Path
import importlib.util
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from interface_gate_v3 import _complete_execution, owned_worker_leaf
from bounded_runtime import bounded_run, contained_command, public_result
from build_contract import load_profile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_inspection_binding(profile):
    spec = importlib.util.spec_from_file_location('v3_inspection_pin', Path(__file__).with_name('pin_environment.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_inspection_binding(profile)


def inspection_recipe(binding, tool):
    """One reviewed metadata-only script recipe; monitor proves the actual Bash ELF."""
    paths = {}
    for role in ('bash', 'script', 'cache'):
        path = Path(binding[role + 'Path'])
        if not path.is_absolute() or path != path.resolve(strict=True) or not path.is_file():
            raise ValueError('inspection input is not canonical regular file')
        if digest(path) != binding[role + 'Sha256']:
            raise ValueError('inspection input substitution')
        paths[role] = path
    with paths['bash'].open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise ValueError('inspection interpreter is not ELF')
    with paths['script'].open('rb') as stream:
        if stream.readline(128) != b'#!/bin/bash\n':
            raise ValueError('unsupported inspection shebang')
    for row in binding['dependencies']:
        if digest(Path(row['path'])) != row['sha256']:
            raise ValueError('inspection runtime dependency substitution')
    logical = ['/usr/bin/ldd', str(tool)]
    actual = [str(paths['bash']), str(paths['script']), str(tool)]
    return logical, actual, (Path(tool).resolve(strict=True), paths['script'], paths['cache'])


def pin(output_name, build_receipt_name):
    work = ROOT / 'toolchain-001'
    output, build_receipt = work / output_name, work / build_receipt_name
    if output.parent.resolve() != work.resolve() or build_receipt.parent.resolve() != work.resolve():
        raise ValueError('helper pin path outside owned toolchain root')
    build = json.loads(build_receipt.read_bytes())
    source = ROOT / 'record_identity_probe.cpp'
    schema = ROOT / 'contracts/helper-schema.json'
    if not _complete_execution(build) or build.get('schemaVersion') != 3 or build.get('exitCode') != 0 or build.get('sourceSha256') != digest(source) or build.get('helperSchemaSha256') != digest(schema) or build.get('binarySha256') != digest(work / 'record_identity_probe'):
        raise ValueError('helper build is not bound to current v3 source/schema')
    deps = (work / 'helper-dependencies.d').read_text().replace('\\\n', ' ').split(':', 1)[1].split()
    paths = {Path(path).resolve() for path in deps}
    paths.update([source.resolve(), schema.resolve(), Path(__file__).resolve(), (work / 'build_helper.py').resolve()])
    bounds = load_profile()['bounds']
    inspections = []
    profile = load_profile()
    binding = load_inspection_binding(profile)
    with owned_worker_leaf(ROOT,'helper-inspection-') as leaf:
        inspection_work = leaf.path
        environment = {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(inspection_work)}
        for tool in (work / 'record_identity_probe', Path('/usr/lib/llvm/23/bin/clang')):
            if load_inspection_binding(profile) != binding:
                raise ValueError('inspection admitted closure changed before execution')
            logical, argv, inputs = inspection_recipe(binding, tool)
            execution = leaf.run(bounded_run,contained_command(argv, inspection_work, read_only_files=inputs, environment=environment),
                                    inspection_work, environment, timeout=bounds['elfInspectionSeconds'],
                                    output_limit=bounds['outputBytesPerStream'],
                                    managed_scope=True, phase='elf-inspection')
            if not _complete_execution(execution) or execution['exitCode'] != 0:
                error = ValueError('incomplete helper dependency inspection')
                error.bounded_result = execution
                raise error
            if load_inspection_binding(profile) != binding:
                raise ValueError('inspection admitted closure changed during execution')
            inspection_recipe(binding, tool)  # Revalidate admitted input bytes after execution.
            inspections.append({'logicalArgv':logical,'actualArgv':argv,
                                'environmentPinSha256':binding['environmentPinSha256'],
                                'execution':public_result(execution)})
            listing = execution['stdout'].decode('utf8', errors='strict')
            for entry in re.findall(r'(/[^\s()]+)', listing):
                if Path(entry).is_file():
                    paths.add(Path(entry).resolve())
    for config in Path('/etc/clang').rglob('*.cfg'):
        paths.add(config.resolve())
    paths.update([Path('/usr/lib/llvm/23/bin/clang++').resolve(), Path('/usr/bin/ld').resolve(), Path('/usr/bin/as').resolve()])
    paths.update(Path(binding[role+'Path']) for role in ('bash','script','cache'))
    paths.update(Path(row['path']) for row in binding['dependencies'])
    value = {'schemaVersion':3, 'helperSchemaVersion':3,
             'sourceSha256':digest(source), 'helperSchemaSha256':digest(schema),
             'binarySha256':digest(work / 'record_identity_probe'),
             'inspectionRecipe':binding,'inspections':inspections,
             'buildReceipt':str(build_receipt), 'buildReceiptSha256':digest(build_receipt),
             'dependencies':{str(path):digest(path) for path in sorted(paths)}}
    with output.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    return value


if __name__ == '__main__':
    value = pin(sys.argv[1], sys.argv[2])
    print(value['sourceSha256'], value['binarySha256'], len(value['dependencies']))
