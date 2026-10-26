"""Seal a source-bound, independently reviewed preparation; never authorizes a trial."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import stat
from types import CodeType, FunctionType
from inspect import CO_VARARGS, CO_VARKEYWORDS, CO_GENERATOR, CO_COROUTINE, CO_ASYNC_GENERATOR
import builtins
import sys
from types import ModuleType
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock, get_ident

BASE = Path(__file__).resolve().parent


MAX_NODES = 20000
MAX_BYTES = 536870912
MAX_DEPTH = 64
CHUNK_BYTES = 65536


class TreeBudget:
    """Payload reservation, not a cumulative physical-I/O byte counter.

    Every yielded entry, including ignored/unsupported entries and directories,
    consumes one shared node. Hashing, copying and verification are distinct
    fixed passes; each admits at most the reserved payload once per pass.
    """
    def __init__(self, *, nodes=MAX_NODES, directories=MAX_NODES,
                 files=MAX_NODES, bytes=MAX_BYTES, depth=MAX_DEPTH):
        limits={'nodes':nodes,'directories':directories,'files':files,'bytes':bytes,'depth':depth}
        ceilings={'nodes':MAX_NODES,'directories':MAX_NODES,'files':MAX_NODES,'bytes':MAX_BYTES,'depth':MAX_DEPTH}
        if any(type(v) is not int or not 0 <= v <= ceilings[k] for k,v in limits.items()):
            raise ValueError('invalid bounded tree limit')
        self.limits=limits
        self.used={key:0 for key in ('nodes','directories','files','bytes')}

    def node(self, depth):
        if depth > self.limits['depth'] or self.used['nodes'] >= self.limits['nodes']:
            raise ValueError('tree node/depth budget exceeded')
        self.used['nodes']+=1

    def kind(self, mode, size=0):
        key='directories' if stat.S_ISDIR(mode) else 'files' if stat.S_ISREG(mode) else None
        if key is None:raise ValueError('unsupported tree kind (including symlink)')
        if self.used[key] >= self.limits[key]:raise ValueError('tree '+key+' budget exceeded')
        if key=='files' and (size < 0 or size > self.limits['bytes']-self.used['bytes']):
            raise ValueError('tree payload budget exceeded')
        self.used[key]+=1
        if key=='files':self.used['bytes']+=size


def _identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns)


def _absolute(path):
    path=Path(path)
    if '..' in path.parts:raise ValueError('parent traversal unsupported')
    path=path if path.is_absolute() else Path.cwd()/path
    if len(path.parts)>128 or len(str(path))>4096:raise ValueError('path resource bound')
    return path


def _open_directory(path, expected=()):
    """Never resolve or follow a symlink in any directory component."""
    path=_absolute(path)
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    versions=dict(expected);current=Path('/')
    try:
        if str(current) in versions and _identity(os.fstat(fd))[:3]!=versions[str(current)][:3]:raise ValueError('admitted directory changed')
        for component in path.parts[1:]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child;current=current/component
            if str(current) in versions and _identity(os.fstat(fd))[:3]!=versions[str(current)][:3]:raise ValueError('admitted directory changed')
        return fd
    except BaseException:
        os.close(fd);raise


def _open_regular(path, parents=()):
    path=_absolute(path);parent=_open_directory(path.parent,parents)
    fd=None;primary=None
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        closing,parent=parent,None  # Relinquish before close: an error never authorizes retry.
        os.close(closing)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('regular file required')
        result,fd=fd,None
        return result
    except BaseException as failure:
        primary=failure
        raise
    finally:
        cleanup_failure=None;cleanup_count=0
        for held in (fd,parent):
            if held is not None:
                try:os.close(held)
                except BaseException as failure:
                    cleanup_count+=1
                    if cleanup_failure is None:cleanup_failure=failure
        if cleanup_failure is not None:
            if primary is not None:
                try:
                    BaseException.add_note(primary,'regular file descriptor cleanup failures: '+str(cleanup_count))
                except BaseException:
                    pass  # Diagnostics must never replace the already retained primary.
            else:raise cleanup_failure


def _consume(fd, expected, *, sink=None, retain=False):
    """Read only the admitted FD/version in bounded chunks; no path reopen."""
    if _identity(os.fstat(fd)) != expected:raise ValueError('admitted file changed before read')
    remaining=expected[3];hasher=hashlib.sha256();chunks=[] if retain else None
    while remaining:
        chunk=os.read(fd,min(CHUNK_BYTES,remaining))
        if not chunk:raise ValueError('admitted file truncated')
        remaining-=len(chunk);hasher.update(chunk)
        if retain:chunks.append(chunk)
        if sink is not None:
            view=memoryview(chunk)
            while view:
                written=os.write(sink,view)
                if written<=0:raise ValueError('copy write incomplete')
                view=view[written:]
    if _identity(os.fstat(fd)) != expected:raise ValueError('admitted file changed during read')
    return hasher.hexdigest(), b''.join(chunks) if retain else None


def _record(path, relative, metadata, fd, parents=(), *, predicate_capture=None):
    coordinate=str(path) if predicate_capture is not None else None  # Shared admission already made path absolute.
    specification=predicate_capture[0].get(coordinate) if predicate_capture is not None else None
    if specification is not None and metadata.st_size!=specification[0]:
        raise ValueError('predicate source exact byte bound')
    identity=_identity(metadata);sha,raw=_consume(fd,identity,retain=specification is not None)
    record={'path':_absolute(path),'relative':relative,'identity':identity,'sha256':sha,'size':metadata.st_size,'parents':parents}
    if specification is not None:
        if sha!=specification[1]:raise ValueError('unsupported predicate source generation')
        predicate_capture[1][coordinate]=(record,raw)
    return record


def admit_tree(root, budget=None):
    budget=budget or TreeBudget();root=_absolute(root)
    budget.node(0);budget.kind(stat.S_IFDIR)
    rootfd=_open_directory(root);root_identity=_identity(os.fstat(rootfd));records={};directories={}
    def walk(fd, relative, depth, parents=()):
        before=_identity(os.fstat(fd));directories[str(relative)]=before;entries=[]
        parents=parents+((str(root/relative),before[:3]),)
        with os.scandir(fd) as iterator:
            for entry in iterator:
                budget.node(depth+1)  # before stat, collection, recursion, or file open
                metadata=entry.stat(follow_symlinks=False)
                budget.kind(metadata.st_mode,metadata.st_size)
                entries.append((entry.name,metadata))
        # Only the bounded admitted list is sorted/materialized.
        for name,metadata in sorted(entries,key=lambda item:item[0]):
            child_relative=relative/name
            if len(str(root/child_relative))>4096:raise ValueError('tree path resource bound')
            if stat.S_ISDIR(metadata.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    if _identity(os.fstat(child)) != _identity(metadata):raise ValueError('directory changed before traversal')
                    walk(child,child_relative,depth+1,parents)
                finally:os.close(child)
            else:
                child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                try:
                    records[str(child_relative)]=_record(root/child_relative,str(child_relative),metadata,child,parents)
                finally:os.close(child)
        if _identity(os.fstat(fd)) != before:raise ValueError('directory changed during traversal')
    try:walk(rootfd,Path(),0)
    finally:os.close(rootfd)
    check=_open_directory(root)
    try:
        if _identity(os.fstat(check)) != root_identity:raise ValueError('tree root changed during traversal')
    finally:os.close(check)
    return {'root':root,'files':records,'directories':directories,'usage':dict(budget.used)}


def admit_files(paths, budget=None, root=None):
    """Charge files and every parent directory within the explicit input scope.

    Root-to-scope FD resolution separately has a fixed 128-component bound.
    A multi-directory population must supply its common reviewed scope root.
    """
    return _admit_files(paths,budget,root)


def _admit_files(paths, budget=None, root=None, *, predicate_capture=None):
    """Charge files and every parent directory within the explicit input scope.

    Root-to-scope FD resolution separately has a fixed 128-component bound.
    A multi-directory population must supply its common reviewed scope root.
    """
    budget=budget or TreeBudget();records={};directories={};anchor=_absolute(root) if root is not None else None
    for path in paths:
        path=_absolute(path)
        if anchor is None:anchor=path.parent
        if not path.is_relative_to(anchor):raise ValueError('file outside admitted input scope')
        relative=path.relative_to(anchor)
        for index in range(len(relative.parts)):
            directory=anchor/Path(*relative.parts[:index]);name=str(directory)
            if name not in directories:
                budget.node(index);budget.kind(stat.S_IFDIR)
                fd=_open_directory(directory)
                try:directories[name]=_identity(os.fstat(fd))
                finally:os.close(fd)
        budget.node(len(relative.parts))
        if str(path) in records:raise ValueError('duplicate admitted file')
        parents=tuple((str(anchor/Path(*relative.parts[:index])),directories[str(anchor/Path(*relative.parts[:index]))][:3]) for index in range(len(relative.parts)))
        fd=_open_regular(path,parents)
        try:
            metadata=os.fstat(fd);budget.kind(metadata.st_mode,metadata.st_size)
            records[str(path)]=_record(path,str(path),metadata,fd,parents,predicate_capture=predicate_capture)
        finally:os.close(fd)
    return {'files':records,'directories':directories,'usage':dict(budget.used)}


# One reviewed coordinator generation. These hashes do not authenticate its issuer,
# interpreter/bootstrap, machine inputs or any native qualification.
_PREDICATE_MODULES = (
    ('prepare_v3.py',7056,'d7f0f5fc14295a1ce38871b4fd393c83f756662041913f3b1d76c9406e99f6a2'),
    ('generate_controls_v3.py',8873,'e2cdd7593a0e23b5bbd2cbf0d8a0ea5aec2ff1113be710be114e4852f22b4b30'),
    ('evaluate_candidate_v3.py',48323,'852f1a868eceb1932255499a4de4f8e9dcb893da4a7ecb1611f151131ff4612d'),
)


def _admit_execution_predicates(paths):
    # The checkpoint already passed complete charged population equality. Retain
    # only these three fixed coordinates from their ORIGINAL admission interval.
    specification={str(_absolute(BASE/name)):(size,sha) for name,size,sha in _PREDICATE_MODULES}
    if type(paths) is not dict or not specification.keys()<=paths.keys():
        raise ValueError('missing predicate defining source')
    captured={}
    files=_admit_files(paths,root=BASE,predicate_capture=(specification,captured))['files']
    if captured.keys()!=specification.keys():raise ValueError('incomplete predicate source capture')
    return files,captured


def _predicate_code(module, name, arguments, locals):
    selected=None
    for value in module.co_consts:  # Direct module constants only; never recurse.
        if isinstance(value,CodeType) and value.co_name==name:
            if selected is not None:raise ValueError('duplicate predicate definition')
            selected=value
    forbidden=CO_VARARGS|CO_VARKEYWORDS|CO_GENERATOR|CO_COROUTINE|CO_ASYNC_GENERATOR
    if (selected is None or selected.co_qualname!=name or selected.co_argcount!=len(arguments) or
            selected.co_posonlyargcount or selected.co_kwonlyargcount or selected.co_flags&forbidden or
            selected.co_freevars or selected.co_cellvars or selected.co_names or
            selected.co_varnames!=arguments+locals):
        raise ValueError('unsupported pure predicate definition')
    return selected


def _bind_admitted_predicates(sources, captured, checkpoint):
    expected={str(_absolute(BASE/name)) for name,_,_ in _PREDICATE_MODULES}
    if captured.keys()!=expected:raise ValueError('incomplete predicate source capture')
    admitted={}
    for name,maximum,sha in _PREDICATE_MODULES:
        coordinate=str(_absolute(BASE/name));record,raw=captured[coordinate]
        if (sources.get(coordinate) is not record or record['path']!=_absolute(BASE/name) or
                record['size']!=maximum or type(raw) is not bytes or len(raw)!=maximum or
                record['sha256']!=sha or checkpoint.get(coordinate)!=sha or
                hashlib.sha256(raw).hexdigest()!=sha):
            raise ValueError('predicate original capture/checkpoint binding differs')
        admitted[name]=raw
    compiled={name:compile(admitted[name],str(_absolute(BASE/name)),'exec',dont_inherit=True,optimize=0)
              for name,_,_ in _PREDICATE_MODULES}
    # The fixed prepare SHA binds its reviewed reexport to this exact evaluator.
    # Never execute module bodies/imports, use module caches, or reopen source.
    prepare=compiled['prepare_v3.py']
    if any(isinstance(value,CodeType) and value.co_name in ('control_policy','control_passed')
           for value in prepare.co_consts):
        raise ValueError('unsupported predicate reexport generation')
    policy=_predicate_code(compiled['generate_controls_v3.py'],'control_policy',(),())
    passed=_predicate_code(compiled['evaluate_candidate_v3.py'],'control_passed',('control','report'),('kind',))
    # Empty co_names is specific to the reviewed literal/input-only bodies, not
    # a general globals analysis (attribute/method names also occur there).
    return (FunctionType(policy,{'__builtins__':{}},'control_policy'),
            FunctionType(passed,{'__builtins__':{}},'control_passed'))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate contract key')
        result[key] = value
    return result


# Closed source selection only; interpreter/stdlib/coordinator origin remains unqualified.
_FREEZE_DEPENDENCY_SOURCES = (
    ('build_contract',26463,'a54fb8b508ebf85a2f576972f5809095b50763c7ef3ef265ce1864a456ffeb6c'),
    ('bounded_runtime',136314,'1095decb5115e513bcf30973c0543d45e2d5a4aef2ee4e757d14bfe4d33c67a5'),
    ('interface_gate_v3',35287,'caefa9fa3859715dab6a9202f1b0e75280730e8b2bd20b2c8745645336ec8e2e'),
    ('evaluate_candidate_v3',48323,'852f1a868eceb1932255499a4de4f8e9dcb893da4a7ecb1611f151131ff4612d'),
)
_FREEZE_IMPORT_EDGES = {
    'build_contract': {},
    'bounded_runtime': {'build_contract': (
        ('load_profile_with_digest','enforced_process_limits','digest'),)},
    'interface_gate_v3': {
        'bounded_runtime': (('bounded_run','public_result','digest','contained_command',
                            'worker_execution_complete','_helper_execution_pin'),('_pin_files',)),
        'build_contract': (('profile','load_profile','load_profile_with_digest','_bounded_json_snapshot','load_schema_validator'),)},
    'evaluate_candidate_v3': {
        'bounded_runtime': (('bounded_run','digest','private_directory','public_result','write_json',
                            'worker_execution_complete','contained_command'),
                           ('_parse_worker_proof','_WORKER_PROOF_MAX_BYTES'),('_pin_files',)),
        'build_contract': (('profile','load_profile','load_profile_with_digest',
                           'verified_visible_snapshot','profile_scope','_read_json'),),
        'interface_gate_v3': (('compare_descriptors','probe','export_inventory','layout_assertions',
                              'resolve_declaration','phase_remaining','revalidate_handoff','require_handoff_execution'),('fastjsonschema',)),
        'freeze_v3': (('read_regular',),('admit_files','TreeBudget')),},
}
_FREEZE_ORDINARY_IMPORTS = frozenset((
    '__future__','hashlib','json','os','stat','time','pathlib','re','contextlib','contextvars',
    'fcntl','errno','math','resource','selectors','shutil','signal','subprocess','sys','threading',
    'uuid','tempfile','dataclasses','copy','builtins','sysconfig','types'))
_FREEZE_IMPORT = builtins.__import__
_FREEZE_DEPENDENCY_SCOPE = ContextVar('freeze_dependency_owner',default=None)


class _FreezeDependencyOwner:
    """One synchronous invocation's captured graph; never a caller-provided permit."""
    def __init__(self):
        self.root=_absolute(BASE);self.thread=get_ident();self.state='NEW';self.lock=Lock()
        self.modules={};self.aliases={};self.records={};self.ready=set();self.selected=None
        self.facade=ModuleType('_freeze_self')
        self.facade.read_regular=read_regular;self.facade.admit_files=admit_files
        self.facade.TreeBudget=TreeBudget

    def check(self):
        if self.thread!=get_ident() or self.root!=_absolute(BASE) or self.state in ('FAILED','CLOSED'):
            raise ValueError('freeze dependency owner is unavailable or outside its source root')

    def check_aliases(self):
        for alias,module in self.aliases.items():
            if sys.modules.get(alias) is not module:
                raise ValueError('freeze dependency private alias changed')

    def importer(self, source):
        def selected_import(name, globals=None, locals=None, fromlist=(), level=0):
            self.check();self.check_aliases()
            requested=tuple(fromlist or ())
            if level or '*' in requested:
                raise ValueError('unsupported freeze dependency import')
            if name in _FREEZE_IMPORT_EDGES or name=='freeze_v3':
                if requested not in _FREEZE_IMPORT_EDGES[source].get(name,()):
                    raise ValueError('unreviewed freeze dependency edge')
                if name=='freeze_v3':return self.facade
                if name not in self.ready:raise ValueError('forward freeze dependency import')
                return self.modules[name]
            if name not in _FREEZE_ORDINARY_IMPORTS:
                raise ValueError('unreviewed freeze ordinary import')
            return _FREEZE_IMPORT(name,globals,locals,fromlist,level)
        return selected_import

    def validator(self):
        self.check()
        if self.state=='READY':
            self.check_aliases();return self.selected
        if self.state!='NEW' or not self.lock.acquire(False):
            raise ValueError('freeze dependency initialization is busy or unavailable')
        primary=None
        try:
            if self.state!='NEW':raise ValueError('freeze dependency initialized concurrently')
            self.state='INITIALIZING'
            specification={str(self.root/(name+'.py')):(size,sha)
                           for name,size,sha in _FREEZE_DEPENDENCY_SOURCES}
            captured={}
            admission=_admit_files(specification,
                TreeBudget(nodes=5,directories=1,files=4,bytes=sum(size for _,size,_ in _FREEZE_DEPENDENCY_SOURCES),depth=1),root=self.root,
                predicate_capture=(specification,captured))
            if captured.keys()!=specification.keys():raise ValueError('incomplete freeze dependency capture')
            raw={}
            for name,size,sha in _FREEZE_DEPENDENCY_SOURCES:
                coordinate=str(self.root/(name+'.py'));record,payload=captured[coordinate]
                if (record is not admission['files'].get(coordinate) or record['size']!=size or
                        record['path']!=self.root/(name+'.py') or record['sha256']!=sha or
                        type(payload) is not bytes or len(payload)!=size or hashlib.sha256(payload).hexdigest()!=sha):
                    raise ValueError('freeze original dependency bytes differ')
                raw[name]=payload
            # The entire independent catalog is authenticated before ANY compile.
            code={name:compile(raw[name],str(self.root/(name+'.py')),'exec',dont_inherit=True,optimize=0)
                  for name,_,_ in _FREEZE_DEPENDENCY_SOURCES}
            self.records=admission['files']
            for name,_,_ in _FREEZE_DEPENDENCY_SOURCES:
                alias='_v3_freeze_'+format(id(self),'x')+'_'+name
                module=ModuleType(alias);module.__file__=str(self.root/(name+'.py'));module.__package__=''
                if alias in sys.modules:raise ValueError('freeze private alias collision')
                self.modules[name]=module;self.aliases[alias]=module
                if sys.modules.setdefault(alias,module) is not module:
                    raise ValueError('freeze private alias collision')
            # All code has compiled; four owned aliases support real dataclass lookups.
            for name,_,_ in _FREEZE_DEPENDENCY_SOURCES:
                self.check();self.check_aliases()
                module=self.modules[name];environment=dict(vars(builtins))
                environment['__import__']=self.importer(name);module.__dict__['__builtins__']=environment
                exec(code[name],module.__dict__)
                self.check();self.check_aliases()
                if (module.__file__!=str(self.root/(name+'.py')) or
                        sys.modules.get(module.__name__) is not module or
                        (name!='interface_gate_v3' and module.BASE!=self.root) or
                        (name=='build_contract' and module.PROFILE_PATH!=self.root/'contracts/candidate-build-profile.json')):
                    raise ValueError('freeze dependency defining source root differs')
                self.ready.add(name)
            selected=self.modules['evaluate_candidate_v3'].validate_exchange
            if not callable(selected) or selected.__globals__ is not self.modules['evaluate_candidate_v3'].__dict__:
                raise ValueError('freeze validator defining globals differ')
            self.selected=selected
        except BaseException as failure:
            primary=failure;self.state='FAILED';raise
        finally:
            try:self.lock.release()
            except BaseException:
                self.state='FAILED'
                if primary is None:raise
        self.check()
        if self.state!='INITIALIZING':raise ValueError('freeze dependency owner changed during initialization')
        self.state='READY'
        return selected

    def require_sources(self, sources, checkpoint):
        self.validator()
        for name,size,sha in _FREEZE_DEPENDENCY_SOURCES:
            coordinate=str(self.root/(name+'.py'));original=self.records[coordinate];record=sources.get(coordinate)
            if (record is None or record['path']!=original['path'] or record['identity']!=original['identity'] or
                    record['size']!=size or record['sha256']!=sha or checkpoint.get(coordinate)!=sha):
                raise ValueError('freeze dependency original checkpoint join differs')

    def close(self):
        self.state='CLOSED';failure=None
        for alias,module in self.aliases.items():
            try:
                if sys.modules.get(alias) is not module:
                    raise ValueError('freeze private alias cleanup identity unknown')
                del sys.modules[alias]
            except BaseException as error:
                if failure is None:failure=error
        if failure is not None:raise failure


@contextmanager
def _freeze_dependency_scope():
    if _FREEZE_DEPENDENCY_SCOPE.get() is not None:raise ValueError('nested freeze dependency scope refused')
    owner=_FreezeDependencyOwner();token=_FREEZE_DEPENDENCY_SCOPE.set(owner);primary=None
    try:yield owner
    except BaseException as failure:
        primary=failure;raise
    finally:
        cleanup=None
        try:owner.close()
        except BaseException as failure:cleanup=failure
        try:_FREEZE_DEPENDENCY_SCOPE.reset(token)
        except BaseException as failure:
            if cleanup is None:cleanup=failure
        if primary is None and cleanup is not None:raise cleanup


def validate_exchange(name, value):
    owner=_FREEZE_DEPENDENCY_SCOPE.get()
    if owner is None:
        with _freeze_dependency_scope() as selected:
            validator=selected.validator()
            return validator(name,value)
    validator=owner.validator()
    return validator(name,value)


def read_admitted(record, maximum=MAX_BYTES):
    if record['size']>maximum:raise ValueError('admitted read bound')
    fd=_open_regular(record['path'],record['parents'])
    try:sha,raw=_consume(fd,record['identity'],retain=True)
    finally:os.close(fd)
    if sha!=record['sha256']:raise ValueError('admitted bytes changed')
    return raw


def read_regular(path, maximum=8388608):
    snapshot=admit_files([path],TreeBudget(bytes=maximum))
    return read_admitted(next(iter(snapshot['files'].values())),maximum)


def _decode_json(raw, schema=None):
    value=json.loads(raw,object_pairs_hook=_pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    return validate_exchange(schema,value) if schema else value


def read_json(path, schema=None, maximum=8388608):
    return _decode_json(read_regular(path,maximum),schema)


def _read_admitted_json(record, schema=None, maximum=8388608):
    return _decode_json(read_admitted(record,maximum),schema)


def inventory(root, budget=None):
    return {name:record['sha256'] for name,record in admit_tree(root,budget)['files'].items()}


class CopyPlan:
    """Reserve the complete output tree before mkdir/open/write of any output."""
    def __init__(self, budget=None):
        self.budget=budget or TreeBudget(files=10000)
        if self.budget.limits['files']>10000:raise ValueError('copy artifact file limit exceeds schema')
        self.budget.node(0);self.budget.kind(stat.S_IFDIR)
        self.directories={''};self.files={}

    def directory(self,path):
        path=Path(path)
        if path.is_absolute() or '..' in path.parts or len(str(path))>4096:raise ValueError('invalid copy directory')
        for index in range(1,len(path.parts)+1):
            name=str(Path(*path.parts[:index]))
            if name not in self.directories:
                if name in self.files:raise ValueError('copy file/directory collision')
                self.budget.node(index);self.budget.kind(stat.S_IFDIR);self.directories.add(name)

    def add(self, destination, record=None, raw=None):
        path=Path(destination)
        if path.is_absolute() or '..' in path.parts or not path.parts or str(path)=='.':raise ValueError('invalid copy destination')
        if len(str(path))>4096:raise ValueError('copy destination bound')
        self.directory(path.parent)
        name=str(path)
        if name in self.files or name in self.directories:raise ValueError('duplicate copy destination')
        if (record is None)==(raw is None):raise ValueError('one admitted source or immutable byte value required')
        if raw is not None and not isinstance(raw,bytes):raise ValueError('copy bytes required')
        size=len(raw) if raw is not None else record['size']
        self.budget.node(len(path.parts));self.budget.kind(stat.S_IFREG,size)
        self.files[name]={'record':record,'raw':raw,'sha256':hashlib.sha256(raw).hexdigest() if raw is not None else record['sha256']}

    def add_json(self,destination,value):
        # Reserve node/file population before streaming any serialization.
        self.add(destination,raw=b'');row=self.files[str(Path(destination))];row['pending']=True
        remaining=self.budget.limits['bytes']-self.budget.used['bytes'];chunks=[];total=0
        for text in json.JSONEncoder(sort_keys=True,indent=2,allow_nan=False).iterencode(value):
            chunk=text.encode('utf8')
            if len(chunk)>remaining-total:raise ValueError('JSON copy payload budget exceeded')
            total+=len(chunk);chunks.append(chunk)
        if total>=remaining:raise ValueError('JSON newline payload budget exceeded')
        chunks.append(b'\n');total+=1;raw=b''.join(chunks)
        self.budget.used['bytes']+=total;row.update(raw=raw,sha256=hashlib.sha256(raw).hexdigest(),pending=False)

    def add_tree(self,prefix,snapshot):
        self.directory(prefix)
        for name in snapshot['directories']:self.directory(Path(prefix)/name)
        for name,record in snapshot['files'].items():self.add(Path(prefix)/name,record=record)

    def hashes(self):return {name:row['sha256'] for name,row in self.files.items()}

    def execute(self,destination, defer=()):
        if any(row.get('pending') for row in self.files.values()):raise ValueError('unadmitted pending JSON copy')
        deferred=set(defer)
        if not deferred.issubset(self.files) or any(self.files[name]['raw'] is None for name in deferred):raise ValueError('invalid deferred bytes')
        destination=_absolute(destination)
        parent=_open_directory(destination.parent)
        try:os.mkdir(destination.name,mode=0o700,dir_fd=parent)
        finally:os.close(parent)
        rootfd=_open_directory(destination)
        def target_parent(relative):
            fd=os.dup(rootfd)
            try:
                for part in relative.parts[:-1]:
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    os.close(fd);fd=child
                return fd
            except BaseException:os.close(fd);raise
        try:
            for name in sorted(self.directories- {''},key=lambda value:(len(Path(value).parts),value)):
                relative=Path(name);fd=target_parent(relative)
                try:os.mkdir(relative.name,mode=0o700,dir_fd=fd)
                finally:os.close(fd)
            for name,row in sorted(self.files.items()):
                if name in deferred:continue
                record=row['record'];source=None;out=None
                try:
                    if record is not None:
                        source=_open_regular(record['path'],record['parents'])
                        if _identity(os.fstat(source))!=record['identity']:raise ValueError('copy source version changed')
                    relative=Path(name);fd=target_parent(relative)
                    try:out=os.open(relative.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
                    finally:os.close(fd)
                    if source is not None:
                        sha,_=_consume(source,record['identity'],sink=out)
                        if sha!=row['sha256']:raise ValueError('copy source hash changed')
                        os.fchmod(out,0o700 if record['identity'][2]&0o111 else 0o600)
                    else:
                        view=memoryview(row['raw'])
                        while view:
                            count=os.write(out,view[:CHUNK_BYTES])
                            if count<=0:raise ValueError('copy write incomplete')
                            view=view[count:]
                finally:
                    if out is not None:os.close(out)
                    if source is not None:os.close(source)
        finally:os.close(rootfd)
        result=inventory(destination,TreeBudget(**self.budget.limits))
        if result!={name:sha for name,sha in self.hashes().items() if name not in deferred}:raise ValueError('complete admitted copy verification failed')
        return result


def execution_source_paths():
    """Fixed nonrecursive scopes; charge ignored entries before filtering too."""
    budget=TreeBudget();paths=set()
    scopes=((BASE,lambda n:n.endswith('.py') or n in ('record_identity_probe.cpp','preservation-manifest.json','worker_exec_monitor.c')),
            (BASE/'contracts',lambda n:n.endswith('.json')),
            (BASE/'toolchain-001',lambda n:n.endswith('.py')),
            (BASE/'tests',lambda n:(n.startswith('test') and n.endswith('.py')) or n in ('run_static_tests.py','static_test_support.py','qualify_worker_exec.py','worker_exec_barrier_harness.c')),
            (BASE/'tests/fixtures',lambda n:n=='historical_counterexamples.py'),
            (BASE/'private',lambda n:n in ('original.c','original.h','caller.c','cases.json')))
    for directory,select in scopes:
        budget.node(0);budget.kind(stat.S_IFDIR);fd=_open_directory(directory)
        before=_identity(os.fstat(fd))
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    budget.node(1)
                    metadata=entry.stat(follow_symlinks=False);budget.kind(metadata.st_mode,metadata.st_size)
                    if select(entry.name):
                        if not stat.S_ISREG(metadata.st_mode):raise ValueError('regular execution source required')
                        paths.add(str(_absolute(directory/entry.name)))
            if _identity(os.fstat(fd))!=before:raise ValueError('source scope changed during enumeration')
        finally:os.close(fd)
    required={
        'record_identity_probe.cpp','preservation-manifest.json',
        'worker_exec_monitor.c','worker_exec_proof.py',
        'contracts/worker-exec-proof-schema.json',
        'toolchain-001/build_worker_monitor.py','toolchain-001/monitor_inputs.py',
        'tests/qualify_worker_exec.py','tests/worker_exec_barrier_harness.c',
        'tests/run_static_tests.py','tests/static_test_support.py',
        'tests/fixtures/historical_counterexamples.py',
        'tests/test_runtime_worker_proof.py','tests/test_worker_exec_proof.py',
        'tests/test_worker_proof_consumers.py',
    }
    if not required.issubset({str(Path(p).relative_to(BASE)) for p in paths}):
        raise ValueError('missing execution source')
    return paths


def finish_deferred(plan,destination,name):
    # All bytes/nodes were reserved before destination creation.
    row=plan.files[name]
    if row['raw'] is None:raise ValueError('deferred immutable bytes required')
    path=_absolute(destination)/name;parent=_open_directory(path.parent)
    try:fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    finally:os.close(parent)
    try:
        view=memoryview(row['raw'])
        while view:
            count=os.write(fd,view[:CHUNK_BYTES])
            if count<=0:raise ValueError('deferred write incomplete')
            view=view[count:]
    finally:os.close(fd)
    if inventory(destination,TreeBudget(**plan.budget.limits))!=plan.hashes():raise ValueError('deferred copy verification failed')


def seal_readonly(root):
    snapshot=admit_tree(root,TreeBudget(files=10000))
    for record in snapshot['files'].values():
        fd=_open_regular(record['path'],record['parents'])
        try:
            if _identity(os.fstat(fd))!=record['identity']:raise ValueError('seal file changed')
            os.fchmod(fd,0o500 if record['identity'][2]&0o111 else 0o400)
        finally:os.close(fd)
    for relative,identity in sorted(snapshot['directories'].items(),key=lambda row:len(Path(row[0]).parts),reverse=True):
        fd=_open_directory(_absolute(root)/relative)
        try:
            if _identity(os.fstat(fd))!=identity:raise ValueError('seal directory changed')
            os.fchmod(fd,0o500)
        finally:os.close(fd)


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _preservation_repository():
    # Lexical layout identifies only a preservation anchor, never sealing authority.
    base=Path(BASE)
    if not base.is_absolute():raise ValueError('absolute preservation source layout required')
    base=_absolute(base)
    if base.parts[-4:]==('oracle','acp','callable-evaluator-v3','source'):
        return base.parents[3]
    if base.parts[-3:]==('build','acp-decomp-effectiveness','callable-library-v3'):
        return base.parents[2]
    raise ValueError('unsupported preservation source layout')


def verify_preservation(manifest):
    if set(manifest) != {'schemaVersion','files'} or manifest['schemaVersion'] != 3 or not manifest['files']:
        raise ValueError('preservation manifest required')
    repository=_preservation_repository()
    def normalized(path):
        path=Path(path)
        return _absolute(path if path.is_absolute() else repository/path)
    # Lazy normalization preserves the existing charged admission and duplicate checks.
    records=admit_files((normalized(path) for path in manifest['files']),root=repository)['files']
    for path,sha in manifest['files'].items():
        if records[str(normalized(path))]['sha256']!=sha:raise ValueError('historical source changed:'+path)


# Independent reviewed executable expectations, also used by the runtime loader.
# The sealer captures through ORIGINAL source-admission records, never a new path
# admission or a caller-supplied module/cache identity.
_SEAL_TOOLCHAIN_SOURCES = (
    ('toolchain-001/pin_environment.py',10310,'3874bc92ba6befb9da9c71a08a21a509ac3c11dc089b3fc1d5ed356dcf7d84a2'),
    ('toolchain-001/link_inputs.py',38357,'8e36065f38aed067c758cf7e6b0420228aa8074d023e4ebbf57b3b7ffbea7176'),
    ('toolchain-001/monitor_inputs.py',14964,'0cab347a7874162840bdda8b0dc138782657ddaf592b8e3a51b3c59c731838d1'),
)
_SEAL_TOOLCHAIN_IMPORTS = frozenset((
    'pathlib','argparse','importlib.util','json','os','stat','hashlib','io',
    'posixpath','re','shlex','struct'))


def _seal_toolchain_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level or '*' in tuple(fromlist or ()) or name not in _SEAL_TOOLCHAIN_IMPORTS:
        raise ValueError('unreviewed sealer toolchain import')
    return _FREEZE_IMPORT(name,globals,locals,fromlist,level)


def _load_toolchain_revalidator(sources, checkpoint):
    root=_absolute(BASE)
    if type(sources) is not dict or type(checkpoint) is not dict:
        raise ValueError('original toolchain source admission required')
    admitted={}
    # Check the entire fixed metadata catalog before retaining any source body.
    for relative,size,sha in _SEAL_TOOLCHAIN_SOURCES:
        path=root/relative;coordinate=str(path);record=sources.get(coordinate)
        if (type(record) is not dict or record.get('path')!=path or
                record.get('size')!=size or record.get('sha256')!=sha or
                checkpoint.get(coordinate)!=sha):
            raise ValueError('sealer toolchain original source/checkpoint differs')
        admitted[relative]=record
    captured={}
    for relative,size,sha in _SEAL_TOOLCHAIN_SOURCES:
        raw=read_admitted(admitted[relative],size)
        if type(raw) is not bytes or len(raw)!=size or hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError('sealer toolchain captured source differs')
        captured[relative]=raw
    # Every dependency is authenticated before ANY compile or module body.
    code={relative:compile(captured[relative],str(root/relative),'exec',dont_inherit=True,optimize=0)
          for relative,_,_ in _SEAL_TOOLCHAIN_SOURCES}
    modules={}
    for key,alias in (('link_inputs','_v3_monitor_link_inputs'),
                      ('monitor_inputs','_v3_monitor_inputs'),
                      ('pin_environment','_v3_monitor_pin_environment')):
        relative='toolchain-001/'+key+'.py'
        module=ModuleType(alias)
        module.__file__=str(root/relative);module.__package__=''
        environment=dict(vars(builtins));environment['__import__']=_seal_toolchain_import
        module.__dict__['__builtins__']=environment
        if key=='pin_environment':
            module._runtime_dependencies={name:modules[name] for name in ('link_inputs','monitor_inputs')}
        exec(code[relative],module.__dict__)
        if module.__file__!=str(root/relative):
            raise ValueError('sealer toolchain defining source differs')
        modules[key]=module
    selected=modules['pin_environment']
    if (selected.BASE!=root or selected.revalidate_pin.__globals__ is not selected.__dict__ or
            selected.link_inputs is not modules['link_inputs'] or
            selected.monitor_inputs is not modules['monitor_inputs']):
        raise ValueError('sealer toolchain defining dependency graph differs')
    return selected


def revalidate_toolchain(pin, filesystem_root, *, sources, checkpoint):
    module=_load_toolchain_revalidator(sources,checkpoint)
    return module.revalidate_pin(pin,filesystem_root)


def require_qualified_pin(pin):
    # Phase B must add a reviewed typed machine closure and its validation here.
    # A coordinator/reviewer Markdown assertion cannot upgrade a static recording.
    if pin.get('status') == 'static-recording-unqualified':
        raise ValueError('static-only toolchain pin cannot authorize final seal')
    raise ValueError('reviewed typed qualified machine closure not available in this static checkpoint')


def freeze(preflight, review, output, toolchain_pin, acceptance, source_checkpoint, qualification, filesystem_root=Path('/')):
    if 'build/acp-decomp-effectiveness/callable-library-v3' not in str(BASE):
        raise ValueError('seal requires trusted v3 source copy')
    for path in (preflight,output,toolchain_pin,source_checkpoint,qualification,review,acceptance):
        if not _absolute(path).is_relative_to(_absolute(BASE)):raise ValueError('outside trusted v3 namespace')
    if _absolute(output).is_relative_to(_absolute(preflight)):raise ValueError('output must not be inside admitted preflight')
    with _freeze_dependency_scope():
        return _freeze_admitted(preflight,review,output,toolchain_pin,acceptance,source_checkpoint,qualification,filesystem_root)


def _freeze_admitted(preflight, review, output, toolchain_pin, acceptance, source_checkpoint, qualification, filesystem_root=Path('/')):
    # Complete charged admission precedes all preflight reads and copy planning.
    tree=admit_tree(preflight);before={name:r['sha256'] for name,r in tree['files'].items()}
    def record(path):
        path=_absolute(path)
        try:return tree['files'][str(path.relative_to(_absolute(preflight)))]
        except (KeyError,ValueError):raise ValueError('path not in admitted preflight')
    def receipt(path,schema=None,maximum=8388608):
        return _read_admitted_json(record(path),schema,maximum)
    matrix=receipt(preflight/'matrix.json','matrix')
    bindings=receipt(preflight/'execution-bindings.json','execution-bindings')
    if not matrix['allControlsPassed'] or not matrix['executionDependenciesUnchanged']:raise ValueError('preflight not accepted')
    extras=admit_files((source_checkpoint,toolchain_pin,review,acceptance,qualification),root=BASE)['files']
    extra=lambda path:extras[str(_absolute(path))]
    if bindings['sourceCheckpointSha256'] != extra(source_checkpoint)['sha256']:raise ValueError('source checkpoint binding drift')
    checkpoint=_read_admitted_json(extra(source_checkpoint),maximum=8388608)
    if set(checkpoint) != {'schemaVersion','files'} or checkpoint['schemaVersion'] != 3 or checkpoint['files'] != bindings['initialSha256']:
        raise ValueError('preflight must use exact prior source checkpoint')
    if set(checkpoint['files']) != execution_source_paths():raise ValueError('incomplete execution source checkpoint')
    sources,predicate_capture=_admit_execution_predicates(checkpoint['files'])
    owner=_FREEZE_DEPENDENCY_SCOPE.get()
    if owner is None:raise ValueError('freeze dependency scope required')
    owner.require_sources(sources,checkpoint['files'])
    for path,sha in checkpoint['files'].items():
        if sources[str(_absolute(path))]['sha256'] != sha:raise ValueError('source changed after checkpoint:'+path)
    if sources[str(_absolute(BASE/'contracts/helper-schema.json'))]['sha256']!=bindings['helperSchemaSha256']:raise ValueError('helper schema drift')
    if record(preflight/'record_identity_probe')['sha256']!=bindings['helperCopySha256']:raise ValueError('helper binary drift')
    control_policy,control_passed=_bind_admitted_predicates(sources,predicate_capture,checkpoint['files'])
    manifest=receipt(preflight/'controls/manifest.json',maximum=1048576)
    if set(manifest)!={'schemaVersion','controls'} or manifest['schemaVersion']!=3:raise ValueError('closed v3 control manifest required')
    policy=control_policy();controls={}
    for control in manifest['controls']:
        if set(control)!={'name','path','sha256','expected','stage'} or control['name'] in controls:raise ValueError('invalid control identity')
        name=control['name'];path=_absolute(control['path'])
        if name not in policy or control['expected']!=policy[name]['expected'] or control['stage']!=policy[name]['stage']:raise ValueError('control policy drift')
        if not path.is_relative_to(_absolute(preflight/'controls')) or record(path)['sha256']!=control['sha256']:raise ValueError('control source drift')
        controls[name]=control
    names=set(controls)
    if names!=set(policy) or len(matrix['rows']) != len(names) or {r['name'] for r in matrix['rows']} != names:raise ValueError('control coverage mismatch')
    for row in matrix['rows']:
        path=_absolute(row['receipt'])
        if not row['passed'] or record(path)['sha256']!=row['receiptSha256']:raise ValueError('control receipt mismatch')
        report=receipt(path,'report');control=controls[row['name']]
        if row['expected']!=control['expected'] or row['expectedStage']!=control['stage'] or report['candidateSha256']!=control['sha256'] or not control_passed(control,report):raise ValueError('control expectation/result drift')
        for name,sha in report['evidenceFiles'].items():
            if record(path.parent/name)['sha256']!=sha:raise ValueError('process evidence drift')
    inventory_hash=canonical_digest(before)
    pin=_read_admitted_json(extra(toolchain_pin),'toolchain-pin',maximum=8388608)
    require_qualified_pin(pin)  # Currently always refuses; Markdown cannot upgrade it.
    revalidate_toolchain(pin,filesystem_root,sources=sources,checkpoint=checkpoint['files'])
    pins=[extra(toolchain_pin)['sha256'],extra(source_checkpoint)['sha256'],bindings['helperCopySha256'],bindings['helperSchemaSha256'],sources[str(_absolute(BASE/'contracts/candidate-build-profile.json'))]['sha256']]
    qualification_text=read_admitted(extra(qualification),1048576).decode('utf8')
    if 'Native qualification: **QUALIFIED**' not in qualification_text or any(pin not in qualification_text for pin in pins):raise ValueError('native qualification binding missing')
    required=[record(preflight/'matrix.json')['sha256'],inventory_hash,*pins,extra(qualification)['sha256']]
    text=read_admitted(extra(review),1048576).decode('utf8')
    if 'Verdict: **OKAY**' not in text or any(pin not in text for pin in required):raise ValueError('independent review binding missing')
    if _absolute(acceptance)==_absolute(review) or extra(acceptance)['sha256']==extra(review)['sha256']:raise ValueError('distinct acceptance artifact required')
    text=read_admitted(extra(acceptance),1048576).decode('utf8')
    if 'Verdict: **CLEAR**' not in text or any(pin not in text for pin in required):raise ValueError('independent acceptance binding missing')
    preservation=_read_admitted_json(sources[str(_absolute(BASE/'preservation-manifest.json'))],maximum=1048576);verify_preservation(preservation)
    # One reservation covers every destination instance, source duplicates,
    # empty directory and final JSON. <=10000 files agrees with the schema.
    plan=CopyPlan();plan.add_tree('artifacts/preflight',tree)
    for path,name in ((review,'independent-review.md'),(acceptance,'independent-acceptance.md'),(qualification,'native-qualification.md'),(toolchain_pin,'toolchain-pin.json'),(source_checkpoint,'source-checkpoint.json')):
        plan.add('artifacts/'+name,record=extra(path))
    for path,item in sources.items():plan.add(Path('artifacts/execution')/_absolute(path).relative_to(_absolute(BASE)),record=item)
    artifact_hashes={name.removeprefix('artifacts/'):sha for name,sha in plan.hashes().items()}
    report={'schemaVersion':3,'status':'prepared-no-model-call','modelCallCount':0,'authenticationReleased':False,'trialAuthorized':False,'sourceCheckpointSha256':extra(source_checkpoint)['sha256'],'preflightMatrixSha256':record(preflight/'matrix.json')['sha256'],'reviewedPreflightInventorySha256':inventory_hash,'independentReviewSha256':extra(review)['sha256'],'independentAcceptanceSha256':extra(acceptance)['sha256'],'toolchainEnvironmentPinSha256':extra(toolchain_pin)['sha256'],'artifacts':artifact_hashes,'historicalPreservationVerified':True,'preservationScope':'locked-template-inputs-only','externalDependenciesRequireReverification':True,'abiAccuracy':'unassessed','formalStructuralScore':None,'productionFactoryQualified':False,'productionProviderQualified':False,'productionFilesystemQualified':False}
    validate_exchange('preparation',report)
    plan.add_json('freeze.json',report)
    plan.execute(output,defer=('freeze.json',))
    current=admit_tree(preflight)
    if current['directories']!=tree['directories'] or current['files']!=tree['files']:raise ValueError('preflight changed while copying')
    if set(checkpoint['files'])!=execution_source_paths():raise ValueError('source population changed while copying')
    if admit_files(checkpoint['files'],root=BASE)['files']!=sources:raise ValueError('source changed while copying')
    revalidate_toolchain(pin,filesystem_root,sources=sources,checkpoint=checkpoint['files']);verify_preservation(preservation)
    finish_deferred(plan,output,'freeze.json');seal_readonly(output)
    return {'freeze':str(output/'freeze.json'),'sha256':plan.hashes()['freeze.json'],'status':report['status']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('preflight','review','output','toolchain-pin','acceptance','source-checkpoint','qualification'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(json.dumps(freeze(args.preflight,args.review,args.output,args.toolchain_pin,args.acceptance,args.source_checkpoint,args.qualification),indent=2))
