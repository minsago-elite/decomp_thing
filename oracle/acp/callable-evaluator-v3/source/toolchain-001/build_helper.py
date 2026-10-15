"""Build the v3 helper only when explicitly invoked; importing is inert."""
from pathlib import Path
import json
import os
import stat
import struct
from contextlib import contextmanager
import uuid
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


def _receipt_component(name):
    if (type(name) is not str or not 1 <= len(name) <= 255 or
            name in ('.', '..', 'helper-dependencies.d', 'record_identity_probe') or
            '/' in name or '\0' in name):
        raise ValueError('helper receipt must be one bounded unreserved component')
    if not 1 <= len(name.encode('utf-8', errors='strict')) <= 255:
        raise ValueError('helper receipt UTF-8 component byte bound')
    return name


def _directory_version(metadata):
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError('helper publication parent must be directory')
    # Our own worker-work/output creation may change nlink, size and timestamps.
    return (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)


def _file_version(metadata):
    return tuple(getattr(metadata, key) for key in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
         'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class _PublicationDirectory:
    """Confinement to selected A, not original authorization or writer exclusion."""
    def __init__(self, root):
        self.root = Path(root)
        self.fds = [None] * 129  # At most 128 ROOT components, plus fixed child.
        self.count = 0
        self.chain = []
        self.fd = None
        self.uid = None

    def _open(self, name, parent=None):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        self.fds[self.count] = os.open(name, flags, **({} if parent is None else {'dir_fd': parent}))
        self.count += 1  # Acquired FD is already owned before observations/allocations.
        return self.fds[self.count - 1]

    def _close(self, primary):
        failure = None
        while self.count:
            self.count -= 1
            descriptor = self.fds[self.count]
            self.fds[self.count] = None  # A failed close is never retried.
            try:
                os.close(descriptor)
            except BaseException as error:
                if failure is None:
                    failure = error
        if primary is None and failure is not None:
            raise failure

    def __enter__(self):
        try:
            if (not self.root.is_absolute() or '..' in self.root.parts or
                    len(self.root.parts) > 128 or len(str(self.root)) > 4096):
                raise ValueError('helper publication ROOT path bound')
            self.uid = os.getuid()
            descriptor = self._open('/')
            self.chain.append((descriptor, None, '/', _directory_version(os.fstat(descriptor))))
            for component in self.root.parts[1:]:
                parent = descriptor
                descriptor = self._open(component, parent)
                self.chain.append((descriptor, parent, component, _directory_version(os.fstat(descriptor))))
            if os.fstat(descriptor).st_uid != self.uid:
                raise ValueError('helper publication ROOT UID differs')
            parent = descriptor
            descriptor = self._open('toolchain-001', parent)
            metadata = os.fstat(descriptor)
            self.chain.append((descriptor, parent, 'toolchain-001', _directory_version(metadata)))
            if metadata.st_uid != self.uid:
                raise ValueError('helper publication directory UID differs')
            self.fd = descriptor
            self.check()
            return self
        except BaseException as primary:
            self._close(primary)
            raise

    def check(self):
        for descriptor, parent, component, expected in self.chain:
            if _directory_version(os.fstat(descriptor)) != expected:
                raise ValueError('helper held publication parent changed')
            named = os.stat(component, follow_symlinks=False, **({} if parent is None else {'dir_fd': parent}))
            if _directory_version(named) != expected:
                raise ValueError('helper named publication parent changed')

    def __exit__(self, kind, error, traceback):
        primary = error
        if primary is None:
            try:
                self.check()
            except BaseException as failure:
                primary = failure
        self._close(primary)
        if error is None and primary is not None:
            raise primary
        return False

    @contextmanager
    def file(self, component, mode):
        descriptors = [None]
        primary = None
        try:
            self.check()
            descriptors[0] = os.open(component, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode, dir_fd=self.fd)
            descriptor = descriptors[0]
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.uid or
                    metadata.st_nlink != 1 or metadata.st_size != 0):
                raise ValueError('helper publication initial regular file differs')
            self.check()
            yield descriptor
        except BaseException as failure:
            primary = failure
            raise
        finally:
            descriptor = descriptors[0]
            descriptors[0] = None
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException:
                    if primary is None:
                        raise
            # No unlink: a name may now identify another same-UID writer's file.

    def receipt(self, component, result):
        with self.file(component, 0o666) as descriptor:
            with _publication_stream(descriptor, 'w') as stream:
                json.dump(result, stream, indent=2)
                stream.write('\n')
                stream.flush()
            self.check()


@contextmanager
def _publication_stream(descriptor, mode):
    stream = None
    primary = None
    try:
        # The enclosing file owner alone closes the FD, even if stream setup fails.
        stream = os.fdopen(descriptor, mode, closefd=False)
        yield stream
    except BaseException as failure:
        primary = failure
        raise
    finally:
        if stream is not None:
            try:
                stream.close()
            except BaseException:
                if primary is None:
                    raise


def publish(directory, component, data, mode):
    """Same-A lookups; temp-name authenticity against same-UID writers is unproved."""
    if ((component, mode) not in (('helper-dependencies.d', 0o600), ('record_identity_probe', 0o700))
            or type(data) is not bytes):
        raise ValueError('fixed helper publication component and immutable bytes required')
    suffix = uuid.uuid4().hex
    if type(suffix) is not str or len(suffix) != 32 or any(c not in '0123456789abcdef' for c in suffix):
        raise ValueError('fixed helper publication temporary component required')
    temporary = '.helper-publish-' + suffix
    with directory.file(temporary, 0o600) as descriptor:
        before = os.fstat(descriptor)
        with _publication_stream(descriptor, 'wb') as stream:
            offset = 0
            while offset < len(data):
                written = stream.write(data[offset:offset + 65536])
                if type(written) is not int or not 0 < written <= min(65536, len(data) - offset):
                    raise ValueError('helper publication write made invalid progress')
                offset += written
            stream.flush()
            os.fchmod(stream.fileno(),mode)
        after = os.fstat(descriptor)
        if (not stat.S_ISREG(after.st_mode) or stat.S_IMODE(after.st_mode) != mode or
                after.st_uid != directory.uid or after.st_nlink != 1 or after.st_size != len(data) or
                (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)):
            raise ValueError('helper publication output metadata differs')
        directory.check()
        if _file_version(os.stat(temporary, dir_fd=directory.fd, follow_symlinks=False)) != _file_version(after):
            raise ValueError('helper publication temporary entry changed')
        # This is confinement, not atomic compare-inode rename or writer exclusion.
        os.replace(temporary, component, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
        directory.check()
        if _file_version(os.stat(component, dir_fd=directory.fd, follow_symlinks=False)) != _file_version(os.fstat(descriptor)):
            raise ValueError('helper publication final entry differs')


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
    receipt_name = _receipt_component(receipt_name)
    profile, profile_sha = load_profile_with_digest()
    with _PublicationDirectory(ROOT) as publication:
        return _build_admitted(receipt_name, profile, profile_sha, publication)


def _build_admitted(receipt_name, profile, profile_sha, publication):
    destination = ROOT / 'toolchain-001'
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
            publish(publication,'helper-dependencies.d',dependency_data,0o600)
            publish(publication,'record_identity_probe',binary_data,0o700)
        result.update(schemaVersion=3,sourceSha256=source_hash,helperSchemaSha256=schema_hash,
                      binarySha256=binary_hash,workerArgv=argv,workerCwd=str(work),
                      publication={'binary':str(destination/'record_identity_probe'),
                                   'dependencies':str(destination/'helper-dependencies.d'),
                                   'published':execution['exitCode']==0})
        publication.receipt(receipt_name,result)
        return result


if __name__ == '__main__':
    result = build(sys.argv[1])
    print(result.get('exitCode'))
    print(bytes.fromhex(result.get('stderrHex', '')).decode())
