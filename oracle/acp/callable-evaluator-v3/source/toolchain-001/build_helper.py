"""Build the v3 helper only when explicitly invoked; importing is inert."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from bounded_runtime import bounded_run, public_result, digest
from build_contract import load_profile
from interface_gate_v3 import _complete_execution


def build(receipt_name):
    work = ROOT / 'toolchain-001'
    output = work / receipt_name
    if output.parent.resolve() != work.resolve():
        raise ValueError('helper receipt outside owned toolchain root')
    argv = ['/usr/lib/llvm/23/bin/clang++', '-std=c++17', '-MD', '-MF',
            str(work / 'helper-dependencies.d'), '-I/usr/lib/llvm/23/include',
            str(ROOT / 'record_identity_probe.cpp'), '-L/usr/lib/llvm/23/lib64',
            '-Wl,-rpath,/usr/lib/llvm/23/lib64', '-lclang-cpp', '-lLLVM',
            '-o', str(work / 'record_identity_probe')]
    env = {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'TMPDIR':str(work)}
    bounds = load_profile()['bounds']
    execution = bounded_run(argv, work, env,
                           timeout=bounds['helperBuildSeconds'],
                           output_limit=bounds['helperOutputBytesPerStream'],
                           managed_scope=True, phase='helper-build')
    if not _complete_execution(execution):
        error = ValueError('incomplete helper build execution')
        error.bounded_result = execution
        raise error
    result = public_result(execution)
    result.update(schemaVersion=3, sourceSha256=digest(ROOT / 'record_identity_probe.cpp'),
                  helperSchemaSha256=digest(ROOT / 'contracts/helper-schema.json'),
                  binarySha256=digest(work / 'record_identity_probe') if result['exitCode'] == 0 else None)
    with output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return result


if __name__ == '__main__':
    result = build(sys.argv[1])
    print(result.get('exitCode'))
    print(bytes.fromhex(result.get('stderrHex', '')).decode())
