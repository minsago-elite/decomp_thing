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


def collect_pin(manifest, filesystem_root):
    closure = link_inputs.collect(manifest, filesystem_root)
    return {'schemaVersion':3, 'status':'static-recording-unqualified', 'gccTarget':'x86_64-pc-linux-gnu',
            'implicitLinkClosure':closure,
            'dependencies':{name:row['sha256'] for name,row in closure['files'].items()}}


def revalidate_pin(pin, filesystem_root):
    """Return fully rebuilt equal pin, or raise Refusal; no subprocess paths."""
    link_inputs.exact(pin, ('schemaVersion', 'status', 'gccTarget', 'implicitLinkClosure', 'dependencies'))
    if type(pin['schemaVersion']) is not int or pin['schemaVersion'] != 3:
        raise link_inputs.Refusal('v3 toolchain pin required')
    rebuilt = collect_pin(pin['implicitLinkClosure']['manifest'], filesystem_root)
    if link_inputs.canonical(rebuilt) != link_inputs.canonical(pin):
        raise link_inputs.Refusal('toolchain pin closure/configuration/selection drift')
    return rebuilt


def load_manifest(path):
    """Bound raw bytes before JSON parsing; reject duplicate/untyped records."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 <= metadata.st_size <= link_inputs.MAX_MANIFEST:
            raise link_inputs.Refusal('recording is not bounded regular JSON')
        chunks = []
        size = 0
        while size <= metadata.st_size:
            block = os.read(descriptor, min(link_inputs.BLOCK, metadata.st_size - size + 1))
            if not block:
                break
            size += len(block)
            if size > metadata.st_size:
                raise link_inputs.Refusal('recording grew beyond reserved bytes')
            chunks.append(block)
        if size != metadata.st_size:
            raise link_inputs.Refusal('recording changed size')
    finally:
        os.close(descriptor)
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise link_inputs.Refusal('duplicate recording field')
            value[key] = item
        return value
    def invalid(_):
        raise link_inputs.Refusal('noninteger recording number')
    try:
        value = json.loads(b''.join(chunks), object_pairs_hook=pairs,
                           parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise link_inputs.Refusal('invalid bounded recording JSON') from error
    link_inputs.validate_manifest(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--filesystem-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = collect_pin(load_manifest(args.manifest), args.filesystem_root)
    with args.output.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print('static-recording-unqualified')


if __name__ == '__main__':
    main()
