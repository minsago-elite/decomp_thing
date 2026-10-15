"""Build the v3 helper only when explicitly invoked; importing is inert."""
from pathlib import Path
import json
import os
import stat
import struct
import tempfile
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from bounded_runtime import bounded_run, public_result, digest, contained_command, _pin_files
from build_contract import load_profile_with_digest
from interface_gate_v3 import _complete_execution, owned_worker_leaf, MAXIMUM_HELPER_SCHEMA_BYTES


def read_output(path, limit, elf=False):
    """Read only bounded stable regular worker output after verified cleanup."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                or not 0 < before.st_size <= limit):
            raise ValueError('invalid bounded helper output')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(before.st_size + 1)
        after = os.fstat(fd)
        identity = lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if identity(before) != identity(after) or len(data) != before.st_size:
            raise ValueError('helper output changed')
        if elf:
            if (len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01' or
                    struct.unpack_from('<HHI', data, 16) not in ((2,62,1),(3,62,1))):
                raise ValueError('invalid helper ELF')
            phoff = struct.unpack_from('<Q', data, 32)[0]
            ehsize, phsize, phnum = struct.unpack_from('<HHH', data, 52)
            if ehsize != 64 or phsize != 56 or not 1 <= phnum <= 128 or phoff < 64 or phoff + phsize*phnum > len(data):
                raise ValueError('invalid bounded helper ELF headers')
            for offset in range(phoff, phoff+phsize*phnum, phsize):
                segment_offset, filesz = struct.unpack_from('<Q',data,offset+8)[0], struct.unpack_from('<Q',data,offset+32)[0]
                if segment_offset+filesz > len(data):
                    raise ValueError('helper ELF segment outside output')
        return data
    finally:
        os.close(fd)


def publish(path, data, mode):
    """Controller publication; worker never mounts this destination directory."""
    descriptor, temporary = tempfile.mkstemp(prefix='.helper-publish-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(),mode)
        os.replace(temporary,path)
    finally:
        if os.path.lexists(temporary):os.unlink(temporary)


def _require_input_join(execution, name, original, phase, profile_sha):
    """Join an independent ordinary input, never the executable target identity."""
    def valid_row(row):
        return (type(row) is dict and set(row) == {'device','inode','mode','sha256'} and
                all(type(row[key]) is int and 0 <= row[key] <= (1 << 64)-1 for key in ('device','inode')) and
                type(row['mode']) is int and 0 <= row['mode'] <= 0o7777 and
                type(row['sha256']) is str and len(row['sha256']) == 64 and
                all(c in '0123456789abcdef' for c in row['sha256']))
    actual = execution['launchInputPins'].get(name) if type(name) is str else None
    if (type(name) is not str or not name or len(name) > 4096 or '\0' in name or
            not Path(name).is_absolute() or str(Path(name)) != name or '..' in Path(name).parts or
            not valid_row(original) or not valid_row(actual) or actual != original or
            type(profile_sha) is not str or len(profile_sha) != 64 or
            any(c not in '0123456789abcdef' for c in profile_sha) or
            execution['bounds'].get('phase') != phase or execution['bounds'].get('profileSha256') != profile_sha):
        error = ValueError('producer launch input differs from independent admission')
        error.bounded_result = execution
        raise error


def build(receipt_name):
    destination = ROOT / 'toolchain-001'
    output = destination / receipt_name
    if output.parent.resolve() != destination.resolve():
        raise ValueError('helper receipt outside owned toolchain root')
    profile, profile_sha = load_profile_with_digest()
    bounds = profile['bounds']
    source = ROOT / 'record_identity_probe.cpp'
    source_guard = digest(source,maximum=bounds['fileSizeBytes'],deadline=None)
    schema_hash = digest(ROOT/'contracts/helper-schema.json',maximum=MAXIMUM_HELPER_SCHEMA_BYTES,deadline=None)
    source_pins = _pin_files([source], None)
    original_source = source_pins.get(str(source))
    if original_source is None or original_source['sha256'] != source_guard:
        raise ValueError('helper build source admission differs')
    source_hash = original_source['sha256']
    with owned_worker_leaf(ROOT,'helper-build-') as leaf:
        work = leaf.path
        binary = work/'record_identity_probe'
        depfile = work/'helper-dependencies.d'
        argv = ['/usr/lib/llvm/23/bin/clang++', '-std=c++17', '-MD', '-MF',
                str(depfile), '-I/usr/lib/llvm/23/include', str(source),
                '-L/usr/lib/llvm/23/lib64', '-Wl,-rpath,/usr/lib/llvm/23/lib64',
                '-lclang-cpp', '-lLLVM', '-o', str(binary)]
        env = {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'TMPDIR':str(work)}
        execution = leaf.run(bounded_run,contained_command(argv,work,read_only_files=(source,),environment=env),
                                work,env,timeout=bounds['helperBuildSeconds'],
                                output_limit=bounds['helperOutputBytesPerStream'],
                                managed_scope=True,phase='helper-build')
        if not _complete_execution(execution):
            error = ValueError('incomplete helper build execution')
            error.bounded_result = execution
            raise error
        _require_input_join(execution, str(source), original_source, 'helper-build', profile_sha)
        if source_hash != digest(source,maximum=bounds['fileSizeBytes'],deadline=None) or schema_hash != digest(ROOT/'contracts/helper-schema.json',maximum=MAXIMUM_HELPER_SCHEMA_BYTES,deadline=None):
            raise ValueError('helper build source/schema drift')
        if _pin_files([source], None) != source_pins:
            raise ValueError('helper build source/schema drift')
        result = public_result(execution)
        binary_hash = None
        if execution['exitCode'] == 0:
            binary_data = read_output(binary,bounds['fileSizeBytes'],elf=True)
            dependency_data = read_output(depfile,bounds['fileSizeBytes'])
            import hashlib
            binary_hash = hashlib.sha256(binary_data).hexdigest()
            publish(destination/'helper-dependencies.d',dependency_data,0o600)
            publish(destination/'record_identity_probe',binary_data,0o700)
        result.update(schemaVersion=3,sourceSha256=source_hash,helperSchemaSha256=schema_hash,
                      binarySha256=binary_hash,workerArgv=argv,workerCwd=str(work),
                      publication={'binary':str(destination/'record_identity_probe'),
                                   'dependencies':str(destination/'helper-dependencies.d'),
                                   'published':execution['exitCode']==0})
        with output.open('x') as stream:
            json.dump(result,stream,indent=2)
            stream.write('\n')
        return result


if __name__ == '__main__':
    result = build(sys.argv[1])
    print(result.get('exitCode'))
    print(bytes.fromhex(result.get('stderrHex', '')).decode())
