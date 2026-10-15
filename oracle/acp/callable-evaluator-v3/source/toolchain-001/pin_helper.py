"""Pin helper inputs with finite direct work; nested resolver/worker bounds stay separate."""
from pathlib import Path
import importlib.util
import hashlib
import json
import math
import os
import stat
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from interface_gate_v3 import _complete_execution, owned_worker_leaf, MAXIMUM_HELPER_SCHEMA_BYTES
from bounded_runtime import bounded_run, contained_command, public_result
from build_contract import load_profile, load_profile_with_digest, _decode_json

# Explicit caller policy selected from existing link/profile ceilings. This is
# direct pin work, NOT a shared budget for the five nested Resolver invocations.
_INPUT_BYTES = 512 * 1024 * 1024
_FILES = 20000
_WORK = 200000
_TEXT = 1024 * 1024
_SMALL = 16 * 1024 * 1024
_RECEIPT = 8 * 1024 * 1024
_BLOCK = 65536


class _Ledger:
    def __init__(self, deadline=None):
        if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise ValueError('finite original pin deadline required')
        self.deadline = deadline
        self.work = self.bytes = self.tokens = self.advances = self.probes = 0
        self.files = set()
        self.records = {}
        self.config = None

    def timely(self):
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError('helper pin original deadline expired')

    def step(self, amount=1):
        self.timely()
        if amount > _WORK - self.work:
            raise ValueError('helper pin direct work bound')
        self.work += amount

    def call(self, operation, *args, **kwargs):
        self.step()
        value = operation(*args, **kwargs)
        self.timely()
        return value

    def token(self):
        self.step()
        if self.tokens >= _FILES:
            raise ValueError('helper pin path token bound')
        self.tokens += 1

    def advance(self, iterator):
        self.step()
        if self.advances >= _FILES:
            raise ValueError('helper pin scan advance bound')
        self.advances += 1  # Includes the advance that must observe EOF.
        value = next(iterator, None)
        self.timely()
        return value


class _PinInput:
    __slots__ = ('logical', 'canonical', 'role', 'maximum', 'selection', 'version',
                 'size', 'sha256', 'raw', 'prefix', 'aliases')

    def __init__(self, **values):
        for name in self.__slots__:
            object.__setattr__(self, name, values[name])

    def __setattr__(self, name, value):
        raise AttributeError('immutable helper pin input')


def _path(value, ledger):
    ledger.step()
    spelling = str(value)
    if (not spelling or len(spelling) > 4096 or '\0' in spelling or
            len(os.fsencode(spelling)) > 4096 or spelling.startswith('//')):
        raise ValueError('helper pin path bound')
    path = Path(spelling)
    if (not path.is_absolute() or str(path) != spelling or '..' in path.parts or len(path.parts) > 128):
        raise ValueError('canonical absolute helper pin path required')
    return path


def _version(metadata):
    return (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_uid,metadata.st_gid,
            metadata.st_nlink,metadata.st_size,metadata.st_mtime_ns,metadata.st_ctime_ns)


def _directory_version(metadata):
    return (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_uid,metadata.st_gid)


def _open(name, flags, owned, ledger, **kwargs):
    # Reserve both the close token and ownership storage BEFORE acquisition.
    # Builtin-list slot assignment cannot grow storage after open succeeds.
    ledger.step(2)
    index = len(owned)
    owned.append(None)
    descriptor = os.open(name, flags, **kwargs)
    owned[index] = descriptor
    ledger.timely()  # Ownership precedes a fallible post-open clock.
    return descriptor


def _close(owned, index):
    descriptor = owned[index]
    owned[index] = None
    if descriptor is not None:
        os.close(descriptor)


def _close_all(owned, primary, ledger):
    failure = None
    for index in range(len(owned)-1, -1, -1):
        try:
            _close(owned, index)
        except BaseException as error:
            if failure is None:
                failure = error
    if primary is not None:
        if failure is not None and failure is not primary:
            try:
                primary.pinInputCloseFailure = failure
            except BaseException:
                pass
    elif failure is not None:
        raise failure
    else:
        ledger.timely()


def _walk(path, aliases, owned, ledger, *, directory=False):
    """Retain nofollow parents; record bounded explicit host-alias selections."""
    path = _path(path, ledger)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_index = len(owned)
    current = _open('/', flags, owned, ledger)
    metadata = ledger.call(os.fstat, current)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError('helper pin parent is not a directory')
    stack = [(current, root_index)]
    parents = [('/', _directory_version(metadata))]
    observed_parents = list(parents)
    parts = []
    pending = list(path.parts[1:])
    links = []
    while pending:
        ledger.step()
        # Check expansion BEFORE retaining a longer pending/canonical spelling.
        ledger.step(len(pending))
        _path('/' + '/'.join(parts + [p for p in pending if p not in ('','.','..')]), ledger)
        component = pending.pop(0)
        if component in ('', '.'):
            continue
        if component == '..':
            if not parts:
                raise ValueError('helper pin alias escapes root')
            _, index = stack.pop()
            _close(owned, index)
            parts.pop(); parents.pop(); current = stack[-1][0]
            continue
        before = ledger.call(os.stat, component, dir_fd=current, follow_symlinks=False)
        location = '/' + '/'.join(parts + [component])
        if stat.S_ISLNK(before.st_mode):
            if not aliases or len(links) >= 40 or not 0 < before.st_size <= 4096:
                raise ValueError('helper pin symlink policy/bound')
            target = ledger.call(os.readlink, component, dir_fd=current)
            if len(target) > 4096 or len(os.fsencode(target)) > 4096 or '\0' in target:
                raise ValueError('helper pin symlink target bound')
            if _version(ledger.call(os.stat, component, dir_fd=current, follow_symlinks=False)) != _version(before):
                raise ValueError('helper pin symlink changed')
            ledger.step(len(target)+1)
            extra = [value for value in target.split('/') if value]
            if len(extra) + len(pending) + len(parts) > 128:
                raise ValueError('helper pin alias component bound')
            if len(os.fsencode('/'.join(parts + extra + pending))) > 4096:
                raise ValueError('helper pin alias expansion bound')
            links.append((location, target, _version(before)))
            pending = extra + pending
            if target.startswith('/'):
                while len(stack) > 1:
                    _, index = stack.pop(); _close(owned, index)
                parts = []; parents = parents[:1]; current = stack[0][0]
            continue
        is_directory = bool(pending) or directory
        descriptor = _open(component, flags if is_directory else
                           os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                           owned, ledger, dir_fd=current)
        observed = ledger.call(os.fstat, descriptor)
        if _version(observed) != _version(before):
            raise ValueError('helper pin selected input changed before admission')
        if is_directory:
            if not stat.S_ISDIR(observed.st_mode):
                raise ValueError('helper pin parent type differs')
            parts.append(component); parents.append((location, _directory_version(observed)))
            observed_parents.append(parents[-1])
            stack.append((descriptor, len(owned)-1)); current = descriptor
        else:
            return descriptor, observed, (location, tuple(observed_parents), tuple(links))
    if directory:
        return current, ledger.call(os.fstat, current), ('/' + '/'.join(parts), tuple(observed_parents), tuple(links))
    raise ValueError('helper pin regular leaf required')


def _capture(path, *, role, maximum, ledger, retain=False, prefix_bytes=0,
             aliases=False, expected=None, deadline=None):
    if deadline != ledger.deadline:
        raise ValueError('helper pin deadline must be the original ledger end')
    ledger.step()
    if (type(maximum) is not int or not 0 <= maximum <= _INPUT_BYTES or
            type(prefix_bytes) is not int or not 0 <= prefix_bytes <= 128 or type(aliases) is not bool or type(retain) is not bool):
        raise ValueError('helper pin role byte bound')
    logical = str(_path(path, ledger)); key = (logical, role)
    if expected is None:
        expected = ledger.records.get(key)
    owned = []; primary = None
    try:
        descriptor, before, selection = _walk(logical, aliases, owned, ledger)
        size = before.st_size; version = _version(before); canonical = selection[0]
        if not stat.S_ISREG(before.st_mode) or not 0 <= size <= maximum:
            raise ValueError('helper pin requires bounded regular input')
        if expected is not None and (expected.selection != selection or expected.version != version):
            raise ValueError('helper pin original input version changed')
        if canonical not in ledger.files and len(ledger.files) >= _FILES:
            raise ValueError('helper pin distinct input bound')
        if size > _INPUT_BYTES-ledger.bytes:
            raise ValueError('helper pin remaining direct byte bound')
        ledger.files.add(canonical); ledger.bytes += size
        ledger.step()
        digest_value = hashlib.sha256(); raw = bytearray(); prefix = bytearray(); count = 0
        while count < size:
            block = ledger.call(os.read, descriptor, min(_BLOCK,size-count))
            if not block or len(block) > size-count:
                raise ValueError('helper pin input truncated or grew')
            ledger.call(digest_value.update, block); count += len(block)
            if retain:
                ledger.step(); raw.extend(block)
            if len(prefix) < prefix_bytes:
                ledger.step(); prefix.extend(block[:prefix_bytes-len(prefix)])
        ledger.step()
        if ledger.probes >= _WORK:
            raise ValueError('helper pin EOF probe bound')
        ledger.probes += 1
        if ledger.call(os.read, descriptor, 1):
            raise ValueError('helper pin input grew')
        if _version(ledger.call(os.fstat, descriptor)) != version:
            raise ValueError('helper pin input changed during read')
        _, after, named = _walk(logical, aliases, owned, ledger)
        if _version(after) != version or named != selection:
            raise ValueError('helper pin named input/parents changed')
        digest_value = ledger.call(digest_value.hexdigest)
        if expected is not None and digest_value != expected.sha256:
            raise ValueError('helper pin original input digest changed')
        ledger.step(len(_PinInput.__slots__))
        record = _PinInput(logical=logical, canonical=canonical, role=role, maximum=maximum,
                           selection=selection, version=version, size=size, sha256=digest_value,
                           raw=bytes(raw) if retain else None, prefix=bytes(prefix), aliases=aliases)
    except BaseException as error:
        primary = error
        raise
    finally:
        _close_all(owned, primary, ledger)
    # Charge prior lookup/publication and reserve conditional rollback work.
    # A refused new record must not become the original on a later ledger use.
    ledger.step(4)
    previous = ledger.records.get(key)
    try:
        ledger.records.setdefault(key, record)
        ledger.timely()
    except BaseException:
        if previous is None and ledger.records.get(key) is record:
            del ledger.records[key]
        raise
    return record


def _revalidate(record, *, ledger, deadline=None):
    _capture(record.logical, role=record.role, maximum=record.maximum, ledger=ledger,
             aliases=record.aliases, expected=record, deadline=deadline)


def digest(path, *, maximum=None, ledger=None, deadline=None):
    ledger = ledger if ledger is not None else _Ledger(deadline)
    return _capture(path, role='compatibility-hash', maximum=_INPUT_BYTES if maximum is None else maximum,
                    ledger=ledger, aliases=True, deadline=deadline).sha256


def load_inspection_binding(profile):
    spec = importlib.util.spec_from_file_location('v3_inspection_pin', Path(__file__).with_name('pin_environment.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_inspection_binding(profile)


def inspection_recipe(binding, tool, *, ledger=None, deadline=None):
    """One fixed recipe; prefixes and SHA come from the same admitted version."""
    ledger = ledger if ledger is not None else _Ledger(deadline)
    ledger.step()
    if type(binding) is not dict or type(binding.get('dependencies')) is not list or len(binding['dependencies'])>_FILES:
        raise ValueError('bounded inspection dependency list required')
    paths = {}; records = {}
    for role in ('bash', 'script', 'cache'):
        ledger.token()
        record = _capture(binding[role+'Path'], role=role,
                          maximum=_INPUT_BYTES if role=='bash' else _TEXT, ledger=ledger,
                          prefix_bytes=4 if role=='bash' else 128 if role=='script' else 0, deadline=deadline)
        if record.sha256 != binding[role+'Sha256']:
            raise ValueError('inspection input substitution')
        paths[role] = Path(record.canonical); records[role] = record
    if records['bash'].prefix != b'\x7fELF':
        raise ValueError('inspection interpreter is not ELF')
    prefix = records['script'].prefix
    if prefix.split(b'\n',1)[0] + b'\n' != b'#!/bin/bash\n' or b'\n' not in prefix:
        raise ValueError('unsupported inspection shebang')
    for row in binding['dependencies']:
        ledger.token()
        record = _capture(row['path'], role='host-dependency', maximum=_INPUT_BYTES,
                          ledger=ledger, aliases=True, deadline=deadline)
        if record.sha256 != row['sha256']:
            raise ValueError('inspection runtime dependency substitution')
    ledger.token()
    target = _capture(tool, role='helper-binary' if Path(tool)==ROOT/'toolchain-001/record_identity_probe' else 'host-tool',
                      maximum=_SMALL if Path(tool)==ROOT/'toolchain-001/record_identity_probe' else _INPUT_BYTES,
                      ledger=ledger, aliases=True, deadline=deadline)
    ledger.step()  # Complete the bounded return construction before admission.
    logical = ['/usr/bin/ldd',str(tool)]
    actual = [str(paths['bash']),str(paths['script']),str(tool)]
    result = logical, actual, (Path(target.canonical),paths['script'],paths['cache'])
    ledger.timely()
    return result


def _dep_paths(raw, ledger):
    result = []; word = bytearray(); target = False; saw_target = False; index = 0
    def flush():
        nonlocal saw_target
        if word:
            ledger.token(); value = ledger.call(bytes,word).decode('utf8',errors='strict'); word.clear()
            if target:
                result.append(_path(value,ledger))
            else:
                saw_target = True
    while index < len(raw):
        ledger.step(); value = raw[index]; index += 1
        if len(word)>=4096 and value not in b' \t\r\n:':raise ValueError('helper depfile path byte bound')
        if value == 92:
            if index >= len(raw): raise ValueError('truncated helper depfile escape')
            ledger.step(); escaped = raw[index]; index += 1
            if escaped == 10:
                flush(); continue
            if escaped not in b' \t#:\\':raise ValueError('unsupported helper depfile escape')
            word.append(escaped)
        elif value == 58:
            if target:raise ValueError('multiple helper depfile rules')
            flush()
            if not saw_target:raise ValueError('missing helper depfile target')
            target = True
        elif value in b' \t\r\n':flush()
        elif value in b'$#':raise ValueError('unsupported helper depfile variable/comment')
        else:word.append(value)
    flush()
    if not target or not result:raise ValueError('missing helper depfile dependencies')
    return result


def _stdout_paths(raw, ledger):
    if type(raw) is not bytes or len(raw)>65536:
        raise ValueError('helper inspection stdout byte bound')
    ledger.call(raw.decode,'utf8',errors='strict')
    token = bytearray(); result = []
    for value in raw:
        ledger.step()
        if len(token)>=4096 and value not in b' \t\r\n()':raise ValueError('helper inspection path byte bound')
        if token:
            if value in b' \t\r\n()':
                ledger.token(); result.append(_path(bytes(token).decode('utf8'),ledger)); token.clear()
            else:token.append(value)
        elif value == 47:token.append(value)
    if token:
        ledger.token(); result.append(_path(bytes(token).decode('utf8'),ledger))
    return result


def _config_inputs(root, *, ledger, deadline=None):
    pending = [(Path(root),None)]; paths = []; inventory = []
    while pending:
        ledger.step(); path, expected = pending.pop(); owned = []; primary = None; iterator = None
        try:
            try:
                descriptor, metadata, selection = _walk(path,False,owned,ledger,directory=True)
            except FileNotFoundError as error:
                if path != Path(root) or error.filename != path.name or ledger.config not in (None,()):
                    raise
                ledger.config = (); return []
            if expected is not None and _version(metadata) != expected:
                raise ValueError('helper config child changed before traversal')
            entries = []; ledger.step(2)  # Iterator acquisition and reserved terminal close.
            iterator = os.scandir(descriptor); ledger.timely()
            while True:
                entry = ledger.advance(iterator)
                if entry is None:break
                ledger.step(); name = entry.name
                if not name or '/' in name or '\0' in name or name in ('.','..'):
                    raise ValueError('invalid helper config entry')
                child = _path(path/name,ledger)
                observed = ledger.call(os.stat,name,dir_fd=descriptor,follow_symlinks=False)
                entries.append((name,_version(observed)))
                if stat.S_ISDIR(observed.st_mode):
                    pending.append((child,_version(observed)))
                elif stat.S_ISREG(observed.st_mode):
                    if name.endswith('.cfg'):ledger.token(); paths.append(child)
                elif stat.S_ISLNK(observed.st_mode):
                    raise ValueError('unreviewed helper config symlink')
                else:raise ValueError('unsupported helper config entry')
            if _version(ledger.call(os.fstat,descriptor)) != _version(metadata):
                raise ValueError('helper config directory changed')
            _, final, final_selection = _walk(path,False,owned,ledger,directory=True)
            if _version(final)!=_version(metadata) or final_selection!=selection:
                raise ValueError('helper config named directory changed')
            ledger.step(); inventory.append((str(path),selection,_version(metadata),tuple(sorted(entries))))
        except BaseException as error:
            primary = error
            raise
        finally:
            if iterator is not None:
                try:
                    closing = iterator; iterator = None; closing.close()
                except BaseException as error:
                    if primary is None:
                        primary = error
                        try:_close_all(owned,primary,ledger)
                        finally:raise
                    elif error is not primary:
                        try:primary.pinIteratorCloseFailure = error
                        except BaseException:pass
            _close_all(owned,primary,ledger)
    ledger.step(); inventory = tuple(sorted(inventory))
    if ledger.config is not None and inventory != ledger.config:
        raise ValueError('helper configuration inventory changed')
    ledger.config = inventory
    return paths


def _name(name):
    if (type(name) is not str or not name or len(name)>4096 or len(os.fsencode(name))>4096 or
            name in ('.','..') or '/' in name or '\0' in name):
        raise ValueError('helper pin path outside owned toolchain root')
    return name


def _write_pin(output_name,value,*,root,ledger,deadline=None):
    if deadline != ledger.deadline:raise ValueError('helper pin writer end differs')
    ledger.step(); chunks = iter(json.JSONEncoder(indent=2).iterencode(value)); raw = bytearray()
    while True:
        ledger.step(); chunk = next(chunks,None); ledger.timely()
        if chunk is None:break
        if len(chunk)>_SMALL-len(raw):raise ValueError('helper pin output byte bound')
        ledger.step(); encoded=chunk.encode('utf8')
        if len(encoded)>_SMALL-len(raw):raise ValueError('helper pin output byte bound')
        raw.extend(encoded)
    if len(raw)>=_SMALL:raise ValueError('helper pin output newline bound')
    raw.extend(b'\n'); payload=bytes(raw)
    owned=[]; primary=None
    try:
        parent,_,_=_walk(root,False,owned,ledger,directory=True)
        descriptor=_open(_name(output_name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                         owned,ledger,mode=0o600,dir_fd=parent)
        before=ledger.call(os.fstat,descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size!=0:raise ValueError('helper pin output is not empty regular file')
        ledger.call(os.fchmod,descriptor,0o600)
        admitted=ledger.call(os.fstat,descriptor)
        if (not stat.S_ISREG(admitted.st_mode) or stat.S_IMODE(admitted.st_mode)!=0o600 or admitted.st_size!=0 or
                (admitted.st_dev,admitted.st_ino)!=(before.st_dev,before.st_ino)):
            raise ValueError('helper pin output permission/identity differs')
        offset=0
        while offset<len(payload):
            count=ledger.call(os.write,descriptor,payload[offset:offset+_BLOCK])
            if count<=0 or count>min(_BLOCK,len(payload)-offset):raise ValueError('helper pin output short write')
            offset+=count
        result=ledger.call(lambda:hashlib.sha256(payload).hexdigest())
    except BaseException as error:
        primary=error
        raise
    finally:_close_all(owned,primary,ledger)
    return result


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


def pin(output_name,build_receipt_name,*,deadline=None):
    ledger=_Ledger(deadline); work=ROOT/'toolchain-001'
    output_name=_name(output_name); build_receipt=work/_name(build_receipt_name)
    receipt=_capture(build_receipt,role='build-receipt',maximum=_RECEIPT,ledger=ledger,retain=True,deadline=deadline)
    build=ledger.call(_decode_json,receipt.raw)
    source=ROOT/'record_identity_probe.cpp'; schema=ROOT/'contracts/helper-schema.json'; binary=work/'record_identity_probe'
    if not _complete_execution(build) or build.get('schemaVersion')!=3 or build.get('exitCode')!=0:
        raise ValueError('helper build is not bound to current v3 source/schema')
    src=_capture(source,role='source',maximum=_SMALL,ledger=ledger,deadline=deadline)
    sch=_capture(schema,role='schema',maximum=MAXIMUM_HELPER_SCHEMA_BYTES,ledger=ledger,deadline=deadline)
    obj=_capture(binary,role='helper-binary',maximum=_SMALL,ledger=ledger,deadline=deadline)
    if (build.get('sourceSha256')!=src.sha256 or build.get('helperSchemaSha256')!=sch.sha256 or build.get('binarySha256')!=obj.sha256):
        raise ValueError('helper build is not bound to current v3 source/schema')
    dep=_capture(work/'helper-dependencies.d',role='depfile',maximum=_TEXT,ledger=ledger,retain=True,deadline=deadline)
    paths={}
    def add(path,role='host-dependency',maximum=_INPUT_BYTES,aliases=True):
        ledger.token(); record=_capture(path,role=role,maximum=maximum,ledger=ledger,aliases=aliases,deadline=deadline)
        previous=paths.get(record.canonical)
        if previous is not None and (previous.version!=record.version or previous.sha256!=record.sha256):
            raise ValueError('helper dependency aliases disagree')
        paths[record.canonical]=record
    for path in _dep_paths(dep.raw,ledger):add(path)
    bounds=ledger.call(load_profile)['bounds']
    inspections=[]
    profile,profile_sha=ledger.call(load_profile_with_digest)
    binding=ledger.call(load_inspection_binding,profile)
    with owned_worker_leaf(ROOT,'helper-inspection-') as leaf:
        inspection_work=leaf.path
        environment={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(inspection_work)}
        for tool,original in ((binary,obj),(Path('/usr/lib/llvm/23/bin/clang'),None)):
            if original is None:
                original=_capture(tool,role='host-tool',maximum=_INPUT_BYTES,ledger=ledger,aliases=True,deadline=deadline)
            ledger.step()
            original_row={'device':original.version[0],'inode':original.version[1],
                          'mode':stat.S_IMODE(original.version[2]),'sha256':original.sha256}
            if ledger.call(load_inspection_binding,profile)!=binding:raise ValueError('inspection admitted closure changed before execution')
            logical,argv,inputs=inspection_recipe(binding,tool,ledger=ledger,deadline=deadline)
            timeout=bounds['elfInspectionSeconds']
            if deadline is not None:
                ledger.timely();timeout=min(timeout,deadline-time.monotonic())
                ledger.timely()
            execution=leaf.run(bounded_run,contained_command(argv,inspection_work,read_only_files=inputs,environment=environment),
                               inspection_work,environment,timeout=timeout,output_limit=bounds['outputBytesPerStream'],
                               managed_scope=True,phase='elf-inspection',**({'phase_deadline':deadline} if deadline is not None else {}))
            try:
                ledger.timely()
                if not _complete_execution(execution) or execution['exitCode']!=0:
                    error=ValueError('incomplete helper dependency inspection');error.bounded_result=execution;raise error
                ledger.call(_require_input_join,execution,original.canonical,original_row,'elf-inspection',profile_sha)
                if ledger.call(load_inspection_binding,profile)!=binding:raise ValueError('inspection admitted closure changed during execution')
                inspection_recipe(binding,tool,ledger=ledger,deadline=deadline)
                inspections.append({'logicalArgv':logical,'actualArgv':argv,'environmentPinSha256':binding['environmentPinSha256'],'execution':public_result(execution)})
                for path in _stdout_paths(execution['stdout'],ledger):add(path)
            except BaseException as error:
                try:error.bounded_result=execution
                except BaseException:pass
                raise
    for path in _config_inputs(Path('/etc/clang'),ledger=ledger,deadline=deadline):add(path,role='configuration',maximum=_TEXT,aliases=False)
    for path,role,maximum in ((source,'source',_SMALL),(schema,'schema',MAXIMUM_HELPER_SCHEMA_BYTES),(Path(__file__),'pin-script',_SMALL),(work/'build_helper.py','build-script',_SMALL)):
        add(path,role,maximum,False)
    for path in ('/usr/lib/llvm/23/bin/clang++','/usr/bin/ld','/usr/bin/as'):add(Path(path),'host-tool')
    for role in ('bash','script','cache'):add(Path(binding[role+'Path']),role,_INPUT_BYTES if role=='bash' else _TEXT,False)
    for row in binding['dependencies']:add(Path(row['path']))
    _config_inputs(Path('/etc/clang'),ledger=ledger,deadline=deadline)
    ledger.step();originals=tuple(ledger.records.values())
    for record in originals:_revalidate(record,ledger=ledger,deadline=deadline)
    ledger.step(len(paths)+1);dependencies={}
    for name in sorted(paths,key=Path):
        ledger.step();dependencies[name]=paths[name].sha256
    value={'schemaVersion':3,'helperSchemaVersion':3,'sourceSha256':src.sha256,'helperSchemaSha256':sch.sha256,'binarySha256':obj.sha256,
           'inspectionRecipe':binding,'inspections':inspections,'buildReceipt':str(build_receipt),'buildReceiptSha256':receipt.sha256,
           'dependencies':dependencies}
    _write_pin(output_name,value,root=work,ledger=ledger,deadline=deadline)
    return value


if __name__ == '__main__':
    value=pin(sys.argv[1],sys.argv[2])
    print(value['sourceSha256'],value['binarySha256'],len(value['dependencies']))
