"""Pin the explicitly built v3 helper and its compiler/runtime dependencies."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from interface_gate_v3 import _complete_execution


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    for tool in (work / 'record_identity_probe', Path('/usr/lib/llvm/23/bin/clang')):
        listing = subprocess.check_output(['/usr/bin/ldd', str(tool)], text=True)
        for entry in re.findall(r'(/[^\s()]+)', listing):
            if Path(entry).is_file():
                paths.add(Path(entry).resolve())
    for config in Path('/etc/clang').rglob('*.cfg'):
        paths.add(config.resolve())
    paths.update([Path('/usr/lib/llvm/23/bin/clang++').resolve(), Path('/usr/bin/ld').resolve(), Path('/usr/bin/as').resolve()])
    value = {'schemaVersion':3, 'helperSchemaVersion':3,
             'sourceSha256':digest(source), 'helperSchemaSha256':digest(schema),
             'binarySha256':digest(work / 'record_identity_probe'),
             'buildReceipt':str(build_receipt), 'buildReceiptSha256':digest(build_receipt),
             'dependencies':{str(path):digest(path) for path in sorted(paths)}}
    with output.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    return value


if __name__ == '__main__':
    value = pin(sys.argv[1], sys.argv[2])
    print(value['sourceSha256'], value['binarySha256'], len(value['dependencies']))
