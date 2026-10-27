"""Pure gate/recipe/provisioning controls; no native execution or host policy changes."""
import ast
from contextlib import ExitStack
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
import bounded_runtime as runtime
import build_contract

TEMP = SOURCE.parents[3] / 'build/acp-decomp-effectiveness/callable-library-v3/static-runtime-worker-proof-001/test-tmp'
TEMP.mkdir(parents=True, exist_ok=True)


class RuntimeWorkerProof(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
            self.stack.enter_context(patch('subprocess.' + name, side_effect=AssertionError('pure control forbids subprocess')))
        self.stack.enter_context(patch.object(runtime.resource, 'setrlimit', side_effect=AssertionError('pure control forbids policy')))
        self.stack.enter_context(patch.object(runtime.os, 'pidfd_open', side_effect=AssertionError('pure control forbids pidfd')))
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=TEMP)))
        self.work = self.directory / 'work'; self.work.mkdir(mode=0o700)
        self.env = {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':'/tmp'}
        self.input = self.work / 'input'; self.input.write_bytes(b'authored public file')

    def command(self):
        return runtime.contained_command(['/usr/bin/readelf','-h',str(self.input)],self.work,
                                         read_only_files=(self.input,),environment=self.env)

    def test_explicit_ro_inside_rw_work_is_preserved_and_hardlink_alias_refuses(self):
        recipe=runtime._contained_recipe(self.command(),self.work)
        self.assertEqual([str(self.work)],[str(m['source']) for m in recipe['mounts'] if m['writable']])
        self.assertTrue(any(m['source']==self.input and m['target']==self.input and not m['writable'] for m in recipe['mounts']))
        command=self.command(); ro=command.index(str(self.input))-1; overlay=command[ro:ro+3]
        del command[ro:ro+3]; rw=command.index('--bind');command[rw:rw]=overlay
        with self.assertRaises(ValueError):runtime._contained_recipe(command,self.work)
        os.link(self.input,self.work/'alias')
        with self.assertRaises(ValueError): self.command()

    def test_protected_control_roots_and_hidden_rw_aliases_refuse(self):
        for cwd in (SOURCE,SOURCE/'toolchain-001',SOURCE/'contracts',SOURCE/'tests',SOURCE.parent,SOURCE.parents[3]):
            with self.subTest(cwd=cwd),self.assertRaises(ValueError):
                runtime.contained_command(['/usr/bin/readelf'],cwd,environment=self.env)
        command=self.command(); at=command.index('--chdir')
        for injected in (['--bind',str(self.directory),str(self.directory)],
                         ['--ro-bind',str(self.work),'/elsewhere'],
                         ['--ro-bind',str(self.input),'/usr/bin/readelf'],
                         ['--ro-bind',str(self.input),'/_worker_exec_monitor']):
            with self.subTest(injected=injected),self.assertRaises(ValueError):
                runtime._contained_recipe(command[:at]+injected+command[at:],self.work)

    def test_retention_reuse_missing_flags_and_runtime_shadowing_refuse(self):
        command=self.command(); at=command.index('--chdir')
        for option in ('--as-pid-1','--sync-fd','--lock-file','--json-status-fd','--pidns','--userns','--preserve-fds'):
            with self.subTest(option=option),self.assertRaises(ValueError):
                runtime._contained_recipe(command[:at]+[option,'4']+command[at:],self.work)
        for option in ('--unshare-all','--disable-userns','--clearenv'):
            modified=list(command);modified.remove(option)
            with self.subTest(option=option),self.assertRaises(ValueError):runtime._contained_recipe(modified,self.work)
        modified=list(command);at=modified.index('--size');del modified[at:at+2]
        with self.assertRaises(ValueError):runtime._contained_recipe(modified,self.work)
        modified=list(command);at=modified.index('/usr');modified[at+1]='/wrong'
        with self.assertRaises(ValueError):runtime._contained_recipe(modified,self.work)

    def test_existing_probe_and_runtime_mapping_semantics_are_retained(self):
        from interface_gate_v3 import probe_command
        helper=self.directory/'helper';helper.write_bytes(b'ELF placeholder, never executed')
        with patch('interface_gate_v3.profile',side_effect=build_contract.load_profile) as declared_profile, \
                patch.object(build_contract,'digest',side_effect=AssertionError('pure recipe forbids host tool hashing')):
            recipe=runtime._contained_recipe(probe_command(helper,self.work,['public.c']),self.work)
        declared_profile.assert_called_once_with()
        self.assertEqual(['/probe','public.c'],recipe['worker'])
        self.assertEqual(helper,recipe['target']);self.assertEqual('/work',recipe['chdir'])
        self.assertFalse(any(m['writable'] for m in recipe['mounts']))
        from evaluate_candidate_v3 import runtime_command,phase_command
        library=self.work/'library.so';library.write_bytes(b'public library placeholder')
        recipe=runtime._contained_recipe(runtime_command(helper,library,2),self.work)
        self.assertEqual(['/caller','/library.so','2'],recipe['worker'])
        self.assertEqual('/workspace',recipe['chdir'])
        recipe=runtime._contained_recipe(phase_command(self.work,['/usr/bin/gcc','-v']),self.work)
        self.assertEqual(['/usr/bin/gcc','-v'],recipe['worker'])
        command=phase_command(self.work,['/usr/bin/gcc','/work/input']);at=command.index('--chdir')
        command[at:at]=['--ro-bind',str(self.input),'/work/input']
        recipe=runtime._contained_recipe(command,self.work)
        self.assertTrue(any(m['target']==Path('/work/input') and not m['writable'] for m in recipe['mounts']))

    def test_actual_prepare_refuses_missing_wrong_or_rekeyed_profile_before_publication(self):
        profile,profile_sha=build_contract.load_profile_with_digest()
        bounds=runtime.execution_bounds(managed_scope=True,phase='runtime',snapshot=(profile,profile_sha))
        key=str(runtime.BASE/'contracts/candidate-build-profile.json')
        target=Path('/authored/worker');monitor=Path('/authored/monitor')
        recipe={'target':target,'worker':['/worker'],'prefix':[],'mounts':[]}
        binding={'binaryPath':str(monitor),'dependencies':[],**{name:runtime._WORKER_PROOF_PARSER_SHA256 if name=='parserSha256' else '0'*64 for name in
            ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','parserSha256','manifestSha256')}}
        def executable(path,deadline=None):
            device,inode=(3,4) if str(path)=='/usr/bin/bwrap' else (11,12) if path==monitor else (7,8)
            return {'path':str(path),'device':device,'inode':inode,'mode':0o500,'sha256':'0'*64}
        for provisioning in (False,True):
            for mutation in (None,'missing','wrong','rekeyed'):
                with self.subTest(provisioning=provisioning,mutation=mutation):
                    pins={key:{'device':70,'inode':71,'mode':0o400,'sha256':profile_sha}}
                    pins.update({str(runtime.BASE/relative):{'device':70,'inode':72+i,'mode':0o400,'sha256':sha}
                        for i,(relative,_,sha) in enumerate(runtime._MONITOR_LOADER_SOURCES)})
                    pins[str(runtime.BASE/'worker_exec_proof.py')]={'device':70,'inode':80,'mode':0o400,'sha256':runtime._WORKER_PROOF_PARSER_SHA256}
                    pins[str(monitor)]={key:value for key,value in executable(monitor).items() if key!='path'}
                    if mutation=='missing':pins.pop(key)
                    if mutation=='wrong':pins[key]['sha256']='f'*64
                    if mutation=='rekeyed':pins['/authored/other-profile.json']=pins.pop(key)
                    receipt={'directory':Path('/authored')/('a'*32),'directoryDevice':1,'directoryInode':2,'device':1,'inode':3}
                    with ExitStack() as effects:
                        for target_object,name,effect in ((Path,'stat',lambda *a,**k:types.SimpleNamespace(st_dev=5,st_ino=6)),
                                (Path,'lstat',lambda *a,**k:types.SimpleNamespace(st_dev=1,st_ino=2)),
                                (runtime,'_contained_recipe',lambda *a:recipe),(runtime,'load_worker_monitor_binding',lambda deadline=None:binding),
                                (runtime,'_nonprivileged_executable',executable),(runtime,'_recorded_compiler_inputs',lambda *a:None),
                                (runtime,'load_profile_with_digest',lambda:(profile,profile_sha)),
                                (runtime,'private_directory',lambda path:path),(runtime,'process_identity',lambda pid:{'start':1}),
                                (runtime.os,'getpid',lambda:123),(runtime.os,'getuid',lambda:55)):
                            effects.enter_context(patch.object(target_object,name,side_effect=effect))
                        effects.enter_context(patch.object(runtime,'_pin_files',return_value=pins))
                        published=effects.enter_context(patch.object(runtime,'_publish_config'))
                        effects.enter_context(patch.object(runtime.os,'open',side_effect=AssertionError('authored producer must not open files')))
                        if mutation is None:
                            launch=runtime._prepare_launch(['/authored/worker'],self.work,bounds,receipt,provisioning)
                            self.assertEqual(profile_sha,launch['pins'][key]['sha256']);published.assert_called_once()
                            self.assertEqual(receipt['directory']/'launch.json',published.call_args.args[0])
                        else:
                            with self.assertRaisesRegex(ValueError,'launch profile pin differs'):
                                runtime._prepare_launch(['/authored/worker'],self.work,bounds,receipt,provisioning)
                            published.assert_not_called()

    def test_prepare_inserts_fixed_monitor_and_owned_snapshot_mount_before_root_remount(self):
        from evaluate_candidate_v3 import runtime_command
        helper=self.directory/'helper';helper.write_bytes(b'public ELF placeholder')
        library=self.work/'library.so';library.write_bytes(b'public library placeholder')
        base=self.directory/'trusted';base.mkdir(mode=0o700)
        with patch.object(runtime,'BASE',base):
            receipt=runtime._create_worker_receipt()
            self.addCleanup(os.close,receipt['fd'])
            binding={'binaryPath':str(helper),'dependencies':[{'path':'/etc/ld.so.cache','sha256':'0'*64}],
                     **{key:runtime._WORKER_PROOF_PARSER_SHA256 if key=='parserSha256' else '0'*64 for key in ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','parserSha256','manifestSha256')}}
            identity=lambda p,deadline=None:{'path':str(p),'device':7,'inode':8,'mode':0o755,'sha256':'0'*64}
            receipt['librarySnapshotFd']=5  # mocked descriptor; never opened/closed by this preparation-only control
            snapshot={'device':51,'inode':52,'size':3,'sha256':'0'*64,'sourcePath':str(library)}
            profile_pins={str(base/'contracts/candidate-build-profile.json'):{'device':70,'inode':71,'mode':0o400,'sha256':runtime.load_profile_with_digest()[1]}}
            profile_pins.update({str(base/relative):{'device':70,'inode':72+i,'mode':0o400,'sha256':sha}
                for i,(relative,_,sha) in enumerate(runtime._MONITOR_LOADER_SOURCES)})
            profile_pins[str(base/'worker_exec_proof.py')]={'device':70,'inode':80,'mode':0o400,'sha256':runtime._WORKER_PROOF_PARSER_SHA256}
            profile_pins[str(helper)]={key:value for key,value in identity(helper).items() if key!='path'}
            with patch.object(runtime,'_snapshot_library',return_value=(snapshot,None)),patch.object(runtime,'process_identity',return_value={'start':1}),patch.object(runtime,'load_worker_monitor_binding',return_value=binding),patch.object(runtime,'_nonprivileged_executable',side_effect=identity),patch.object(runtime,'_pin_files',return_value=profile_pins):
                launch=runtime._prepare_launch(runtime_command(helper,library,2),self.work,
                                               runtime.execution_bounds(managed_scope=True,phase='runtime'),receipt,False,runtime_library={'path':str(library),'sha256':'0'*64})
                # Portable actual admission-path controls: no ignored/private template input.
                command_input=runtime_command(helper,library,2)
                for admission in (None, {'path':str(self.work/'other.so'),'sha256':'0'*64},
                                  {'path':str(library),'sha256':'malformed'}):
                    with self.assertRaisesRegex(ValueError,'independently admitted'):
                        runtime._prepare_launch(command_input,self.work,
                            runtime.execution_bounds(managed_scope=True,phase='runtime'),receipt,False,
                            runtime_library=admission)
                # A well-formed admitted SHA still must equal bytes actually copied/sealed.
                with self.assertRaisesRegex(ValueError,'snapshot differs from admitted'):
                    runtime._prepare_launch(command_input,self.work,
                        runtime.execution_bounds(managed_scope=True,phase='runtime'),receipt,False,
                        runtime_library={'path':str(library),'sha256':'1'*64})
            self.assertIn('-I',launch['argv']);self.assertIn('-B',launch['argv'])
            self.assertIn('pycache_prefix='+str(receipt['directory']/'python-cache'),launch['argv'])
            command=launch['command']; monitor_at=command.index('/_worker_exec_monitor')
            root_at=next(i for i in range(len(command)-1) if command[i:i+2]==['--remount-ro','/'])
            self.assertLess(monitor_at,root_at)
            self.assertEqual(['/caller','/library.so','2'],command[-3:])
            self.assertEqual(1,command.count('--report-fd'));self.assertNotIn('--preserve-fds',command)
            fd_at=command.index('--ro-bind-fd')
            self.assertEqual(['5','/library.so'],command[fd_at+1:fd_at+3])
            self.assertNotIn('--sync-fd',command)
            self.assertEqual(snapshot,launch['expected']['library'])
            self.assertFalse(any(str(receipt['directory']) == arg for arg in command))
            self.assertEqual(0,os.fstat(receipt['fd']).st_size)

    def test_pin_reader_is_bounded_and_rejects_identity_drift_or_expired_phase(self):
        before=runtime._pin_files([self.input])
        self.assertEqual(hashlib.sha256(self.input.read_bytes()).hexdigest(),before[str(self.input)]['sha256'])
        with self.assertRaises(ValueError):runtime._pin_files([])
        with self.assertRaises(ValueError):runtime._pin_files([self.input]*257)
        with self.assertRaises(TimeoutError):runtime._pin_files([self.input],deadline=0)
        empty=self.work/'empty';empty.write_bytes(b'')
        with self.assertRaises(ValueError):runtime._pin_files([empty])
        self.input.write_bytes(b'changed authored input')
        self.assertNotEqual(before,runtime._pin_files([self.input]))

    def test_pin_open_is_nonblocking_and_special_replacement_refuses_before_payload(self):
        declared_profile=runtime.load_profile_with_digest()
        fifo=types.SimpleNamespace(st_mode=stat.S_IFIFO|0o600)
        with patch.object(runtime,'load_profile_with_digest',return_value=declared_profile),patch.object(runtime.os,'open',return_value=123) as opened,patch.object(runtime.os,'fstat',return_value=fifo),patch.object(runtime.os,'close'),patch.object(runtime.os,'read',side_effect=AssertionError('special file payload must not be read')):
            with self.assertRaises(ValueError):runtime._pin_files([self.input])
            with self.assertRaises(ValueError):runtime._nonprivileged_executable(self.input)
        flags=opened.call_args.args[1]
        self.assertTrue(flags&os.O_NONBLOCK);self.assertTrue(flags&os.O_NOFOLLOW)
        empty=self.work/'empty';empty.write_bytes(b'')
        with patch.object(runtime,'load_profile_with_digest',return_value=declared_profile),patch.object(runtime.os,'open',side_effect=AssertionError('whole batch must be admitted before any payload open')):
            with self.assertRaises(ValueError):runtime._pin_files([self.input,empty])
        with patch.object(runtime,'load_profile_with_digest',return_value=declared_profile),patch.object(runtime.os,'open',side_effect=AssertionError('expired deadline must refuse before open')):
            with self.assertRaises(TimeoutError):runtime._pin_files([self.input],deadline=0)
        # Existing closed recipe admits an executable in RW work. Its post-exec
        # pathname can change; safe pin opening remains necessary even with proof.
        recipe=runtime._contained_recipe(runtime.contained_command([str(self.input)],self.work,environment=self.env),self.work)
        self.assertEqual(self.input,recipe['target'])
        self.assertTrue(any(m['writable'] for m in recipe['mounts']))

    def test_sealed_runtime_snapshot_survives_path_swap_and_refuses_inplace_mutation(self):
        import fcntl
        source=self.work/'library.so';source.write_bytes(b'authored admitted library bytes')
        expected=runtime.digest(source)
        receipt={}
        library,pin=runtime._snapshot_library(source,receipt)
        self.addCleanup(os.close,receipt['librarySnapshotFd'])
        original=source.with_suffix('.original');source.rename(original)
        source.write_bytes(b'replacement bytes')
        original.write_bytes(b'in-place original mutation')
        fd=receipt['librarySnapshotFd']
        self.assertEqual(expected,library['sha256'])
        self.assertEqual(expected,hashlib.sha256(os.pread(fd,library['size'],0)).hexdigest())
        self.assertEqual(runtime._SEALED_LIBRARY,fcntl.fcntl(fd,fcntl.F_GET_SEALS)&runtime._SEALED_LIBRARY)
        with self.assertRaises(OSError):os.pwrite(fd,b'x',0)
        with self.assertRaises(OSError):os.ftruncate(fd,1)
        self.assertNotEqual(pin['sha256'],runtime.digest(source))
        # Change the held source bytes after admission but before copy: hash comparison refuses.
        source.write_bytes(b'authored admitted library bytes')
        original_open=runtime.os.open
        admitted=runtime._pin_files([source])
        def changed(path,flags,*args,**kwargs):
            if Path(path)==source:source.write_bytes(b'X'*len(b'authored admitted library bytes'))
            return original_open(path,flags,*args,**kwargs)
        failed={}
        with patch.object(runtime,'_pin_files',return_value=admitted),patch.object(runtime.os,'open',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'snapshot bytes differ'):runtime._snapshot_library(source,failed)
        if failed.get('librarySnapshotFd') is not None:self.addCleanup(os.close,failed['librarySnapshotFd'])

    def test_gate_snapshot_handoff_checks_seals_content_and_preserves_only_owned_fd(self):
        spec=importlib.util.spec_from_file_location('snapshot_gate_control',SOURCE/'scope_gate.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        declared_profile=build_contract.load_profile()
        payload=b'authored immutable bytes'
        library={'device':91,'inode':92,'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'sourcePath':'/authored/library.so'}
        record={'ownerPid':123,'ownerStart':77,'descriptor':9,'library':library}
        fields=['0']*20;fields[19]='77'
        metadata=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_dev=91,st_ino=92,st_size=len(payload))
        with patch.object(gate,'_contract',side_effect=AssertionError('snapshot helper must not reload contract')),patch.object(gate.time,'monotonic',return_value=0),patch.object(Path,'read_text',return_value='123 (controller) '+' '.join(fields)),patch.object(gate.os,'open',return_value=10) as opened,patch.object(gate.os,'fstat',return_value=metadata),patch.object(gate.fcntl,'fcntl',return_value=runtime._SEALED_LIBRARY) as seals,patch.object(gate.os,'read',return_value=payload) as read,patch.object(gate.os,'lseek'),patch.object(gate.os,'dup2') as duplicate,patch.object(gate.os,'set_inheritable') as inherit,patch.object(gate.os,'close') as close:
            gate._acquire_library_snapshot(record,1024,10.0)
            opened.assert_called_once_with('/proc/123/fd/9',gate.os.O_RDONLY|gate.os.O_NONBLOCK|gate.os.O_CLOEXEC)
            duplicate.assert_called_once_with(10,5,inheritable=True);inherit.assert_called_once_with(5,True)
            close.assert_called_once_with(10)
            # Parent FD lives in controller table, independent of child FD5/64-FD policy.
            record['descriptor']=4096
            gate._acquire_library_snapshot(record,1024,10.0)
            self.assertEqual('/proc/123/fd/4096',opened.call_args.args[0])
            for invalid in (-1,True,1<<31,'4096'):
                record['descriptor']=invalid
                with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024,10.0)
            record['descriptor']=9
            for wrong in (0,runtime._SEALED_LIBRARY & ~gate.fcntl.F_SEAL_WRITE):
                seals.return_value=wrong
                with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024,10.0)
            seals.return_value=runtime._SEALED_LIBRARY
            read.return_value=b'wrong content'.ljust(len(payload),b'!')
            with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024,10.0)
            record['ownerStart']=78
            with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024,10.0)

    def _library_handoff_control(self, source_fd=10, late=None, failures=None, expire_clock=None, clock_failure=None):
        gate=self.config_gate()
        payload=b'authored sealed handoff'
        real_sha256=hashlib.sha256
        library={'device':91,'inode':92,'size':len(payload),'sha256':real_sha256(payload).hexdigest(),'sourcePath':'/authored/library.so'}
        record={'ownerPid':123,'ownerStart':77,'descriptor':4096,'library':library}
        fields=['0']*20;fields[19]='77'
        metadata=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_dev=91,st_ino=92,st_size=len(payload))
        case=types.SimpleNamespace(gate=gate,record=record,payload=payload,events=[],closes=[],clock_calls=0,
                                   now=10.0 if late=='entry' else 0.0,last=None,owners=0)
        failures={} if failures is None else failures
        def effect(stage, value=None):
            case.events.append(stage);case.last=stage
            if late==stage:case.now=10.0
            if stage in failures:raise failures[stage]
            return value
        def clock():
            case.clock_calls+=1
            if clock_failure is not None and case.last=='dup':raise clock_failure
            if expire_clock is not None and case.clock_calls>=expire_clock:case.now=10.0
            return case.now
        def owner(*args,**kwargs):
            case.owners+=1
            return effect('owner-before' if case.owners==1 else 'owner-after','123 (owner) '+' '.join(fields))
        class Digest:
            def __init__(self):self.value=real_sha256()
            def update(self, block):effect('hash-update');self.value.update(block)
            def hexdigest(self):return effect('digest',self.value.hexdigest())
        def close(fd):
            case.closes.append(fd)
            return effect('source-close' if fd!=5 else 'target-close')
        case.opened=Mock(side_effect=lambda *a,**k:effect('open',source_fd))
        case.duplicate=Mock(side_effect=lambda *a,**k:effect('dup',5))
        case.inherit=Mock(side_effect=lambda *a,**k:effect('inherit'))
        case.read=Mock(side_effect=lambda *a,**k:effect('read',payload))
        case.seek=Mock(side_effect=lambda *a,**k:effect('seek',0))
        case.contract=Mock(side_effect=AssertionError('snapshot helper must not reload contract'))
        def invoke(deadline=10.0):
            with ExitStack() as stack:
                for target,name,value in (
                    (gate,'_contract',case.contract),(gate.time,'monotonic',Mock(side_effect=clock)),
                    (Path,'read_text',Mock(side_effect=owner)),(gate.os,'open',case.opened),
                    (gate.os,'fstat',Mock(side_effect=lambda *a:effect('fstat',metadata))),
                    (gate.fcntl,'fcntl',Mock(side_effect=lambda *a:effect('seals',runtime._SEALED_LIBRARY))),
                    (gate.hashlib,'sha256',Mock(side_effect=lambda:effect('hash-create',Digest()))),
                    (gate.os,'read',case.read),(gate.os,'lseek',case.seek),(gate.os,'dup2',case.duplicate),
                    (gate.os,'set_inheritable',case.inherit),(gate.os,'close',Mock(side_effect=close))):
                    stack.enter_context(patch.object(target,name,value))
                return gate._acquire_library_snapshot(record,1024,deadline)
        case.invoke=invoke
        return case

    def test_gate_library_handoff_timely_aliases_keep_one_original_end_and_transfer_only_fd5(self):
        for descriptor in (5,10):
            with self.subTest(descriptor=descriptor):
                case=self._library_handoff_control(descriptor)
                self.assertIsNone(case.invoke())
                case.contract.assert_not_called()
                case.opened.assert_called_once_with('/proc/123/fd/4096',case.gate.os.O_RDONLY|case.gate.os.O_NONBLOCK|case.gate.os.O_CLOEXEC)
                case.duplicate.assert_called_once_with(descriptor,5,inheritable=True)
                case.inherit.assert_called_once_with(5,True)
                case.seek.assert_called_once_with(descriptor,0,case.gate.os.SEEK_SET)
                self.assertEqual([] if descriptor==5 else [10],case.closes)
                self.assertEqual(['owner-before','open','fstat','seals','hash-create','read','hash-update',
                                  'digest','owner-after','seek','dup','inherit']+
                                 ([] if descriptor==5 else ['source-close']),case.events)

    def test_gate_library_handoff_refuses_late_operations_and_final_transfer_with_owned_cleanup(self):
        for stage in ('entry','owner-before','open','fstat','seals','hash-create','read','hash-update',
                      'digest','owner-after','seek','dup','inherit','source-close'):
            with self.subTest(stage=stage):
                case=self._library_handoff_control(late=stage)
                with self.assertRaisesRegex(TimeoutError,'snapshot handoff deadline'):case.invoke()
                self.assertEqual([] if stage in ('entry','owner-before') else
                                 [10,5] if stage in ('dup','inherit','source-close') else [10],case.closes)
                case.contract.assert_not_called()
                if stage=='entry':case.opened.assert_not_called()
                if stage=='read':self.assertNotIn('hash-update',case.events)
                if stage=='digest':self.assertNotIn('owner-after',case.events)
                if stage not in ('dup','inherit','source-close'):case.duplicate.assert_not_called()
        case=self._library_handoff_control()
        case.record['library']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'snapshot handoff content or owner differs'):case.invoke()
        self.assertNotIn('owner-after',case.events)
        self.assertNotIn('seek',case.events)
        self.assertEqual([10],case.closes)
        for descriptor in (5,10):
            baseline=self._library_handoff_control(descriptor);baseline.invoke()
            case=self._library_handoff_control(descriptor,expire_clock=baseline.clock_calls)
            with self.assertRaises(TimeoutError):case.invoke()
            self.assertEqual([5] if descriptor==5 else [10,5],case.closes)
            self.assertEqual(baseline.clock_calls,case.clock_calls)
            for stage in ('dup','inherit'):
                case=self._library_handoff_control(descriptor,late=stage)
                with self.assertRaises(TimeoutError):case.invoke()
                self.assertEqual([5] if descriptor==5 else [10,5],case.closes)

    def test_gate_library_handoff_setup_and_close_faults_preserve_exact_primary_without_retry(self):
        for descriptor in (5,10):
            for stage in ('open','fstat','read','hash-update','dup','inherit'):
                with self.subTest(descriptor=descriptor,stage=stage):
                    primary=OSError('authored '+stage)
                    case=self._library_handoff_control(descriptor,failures={stage:primary})
                    with self.assertRaises(OSError) as observed:case.invoke()
                    self.assertIs(primary,observed.exception)
                    expected=[] if stage=='open' else [5] if descriptor==5 else [10,5] if stage=='inherit' else [10]
                    self.assertEqual(expected,case.closes)
        for descriptor in (5,10):
            for malformed_notes in (False,True):
                primary=RuntimeError('authored setup failure')
                if malformed_notes:primary.__notes__=object()
                case=self._library_handoff_control(descriptor,failures={'inherit':primary,'source-close':OSError('source cleanup'),
                                                                       'target-close':OSError('target cleanup')})
                with self.assertRaises(RuntimeError) as observed:case.invoke()
                self.assertIs(primary,observed.exception)
                self.assertEqual([5] if descriptor==5 else [10,5],case.closes)
                if not malformed_notes:
                    self.assertEqual(([] if descriptor==5 else ['snapshot source descriptor cleanup failed'])+
                                     ['snapshot target descriptor cleanup failed'],primary.__notes__)
        primary=OSError('authored source-close-only failure')
        case=self._library_handoff_control(failures={'source-close':primary,'target-close':OSError('target cleanup')})
        with self.assertRaises(OSError) as observed:case.invoke()
        self.assertIs(primary,observed.exception)
        self.assertEqual([10,5],case.closes)
        self.assertEqual(['snapshot target descriptor cleanup failed'],primary.__notes__)
        primary=RuntimeError('authored post-dup clock failure')
        case=self._library_handoff_control(clock_failure=primary,failures={'source-close':OSError('source cleanup'),
                                                                        'target-close':OSError('target cleanup')})
        with self.assertRaises(RuntimeError) as observed:case.invoke()
        self.assertIs(primary,observed.exception)
        self.assertEqual([10,5],case.closes)
        case.inherit.assert_not_called()

    def _gate_snapshot_caller_control(self, directory_fd):
        gate=self.config_gate()
        directory=SOURCE/'exec-proof-receipts'/('a'*32)
        snapshot={'authored':'fixed held snapshot'}
        config={'schemaVersion':1,'directoryDevice':10,'directoryInode':11,'mode':'worker',
                'argv':['/usr/bin/bwrap','--ro-bind-fd','5','/library.so'],'report':{'device':20,'inode':21},
                'outerPidNsDevice':30,'outerPidNsInode':31,'scope':{},'librarySnapshot':snapshot}
        directory_stat=types.SimpleNamespace(st_uid=123,st_mode=stat.S_IFDIR|0o700,st_dev=10,st_ino=11)
        report_stat=types.SimpleNamespace(st_uid=123,st_mode=stat.S_IFREG|0o600,st_dev=20,st_ino=21,st_size=0,st_nlink=1)
        case=types.SimpleNamespace(gate=gate,config=config,snapshot=snapshot,handoff=Mock(),sanitize=Mock(),
                                   owned={},events=[],release=Mock(),inherit=Mock())
        def acquire_scope(*args):
            self.assertNotIn(7,case.owned)
            case.owned[7]='scope';case.events.append(('acquire-scope',7))
            return {'fd':7}
        def open_owned(path,*args,**kwargs):
            if path==directory:
                self.assertEqual((gate.os.O_RDONLY|gate.os.O_DIRECTORY|gate.os.O_NOFOLLOW|gate.os.O_CLOEXEC,),args)
                self.assertEqual({},kwargs)
                descriptor,label=directory_fd,'directory'
            elif path=='gate.tmp':
                self.assertEqual((gate.os.O_CREAT|gate.os.O_EXCL|gate.os.O_NOFOLLOW|gate.os.O_CLOEXEC|gate.os.O_WRONLY,0o600),args)
                self.assertEqual({'dir_fd':directory_fd},kwargs)
                self.assertEqual('directory',case.owned.get(directory_fd))
                descriptor,label=11,'ready'
            elif path=='worker-proof.jsonl':
                self.assertEqual((gate.os.O_WRONLY|gate.os.O_APPEND|gate.os.O_NOFOLLOW|gate.os.O_CLOEXEC,),args)
                self.assertEqual({'dir_fd':directory_fd},kwargs)
                self.assertEqual('directory',case.owned.get(directory_fd))
                descriptor,label=12,'report'
            else:self.fail('unexpected gate fixture open')
            self.assertNotIn(descriptor,case.owned,'independent acquired descriptors cannot alias')
            case.owned[descriptor]=label;case.events.append(('open',label,descriptor))
            return descriptor
        def close_owned(descriptor):
            self.assertIn(descriptor,case.owned,'close requires one still-owned acquisition')
            label=case.owned.pop(descriptor);case.events.append(('close',label,descriptor))
        def duplicate_report(source,target,*,inheritable):
            self.assertEqual((12,4,True),(source,target,inheritable))
            self.assertEqual('report',case.owned.get(source))
            self.assertNotIn(target,case.owned)
            case.owned[target]='inherited-report';case.events.append(('dup-report',source,target))
        case.scope=Mock(side_effect=acquire_scope)
        case.opened=Mock(side_effect=open_owned)
        case.closed=Mock(side_effect=close_owned)
        case.duplicate=Mock(side_effect=duplicate_report)
        def proc_text(path,*args,**kwargs):
            if str(path)=='/proc/self/status':return '\n'.join(key+': 00000000' for key in ('CapInh','CapPrm','CapEff','CapAmb'))
            return '12 (gate) S '+' '.join(['1']*19)+' 123 0'
        def invoke(end):
            with ExitStack() as stack:
                for target,name,value in (
                    (gate.sys,'argv',['scope_gate.py',str(directory),'--config-sha256','0'*64,'--controller','1','2','3','--phase-deadline','10']),
                    (gate.sys,'flags',types.SimpleNamespace(isolated=True)),(gate.sys,'dont_write_bytecode',True),
                    (gate.sys,'pycache_prefix',str(directory/'python-cache')),
                    (gate,'_contract',Mock(return_value=build_contract.load_profile())),
                    (gate,'_authenticated_config',Mock(return_value=config)),(gate,'_acquire_scope',case.scope),
                    (gate,'_check_scope',Mock()),(gate,'_wait_release',case.release),(gate.time,'monotonic',Mock(return_value=0)),
                    (gate.os,'open',case.opened),
                    (gate.os,'fstat',Mock(side_effect=[directory_stat,report_stat])),(gate.os,'close',case.closed),
                    (gate.os,'write',Mock(side_effect=lambda fd,raw:len(raw))),(gate.os,'rename',Mock()),
                    (gate.os,'getpid',Mock(return_value=12)),(gate.os,'getuid',Mock(return_value=123)),
                    (gate.resource,'getrlimit',Mock(return_value=(64,64))),
                    (Path,'read_text',proc_text),(Path,'stat',Mock(return_value=types.SimpleNamespace(st_dev=30,st_ino=31))),
                    (gate.os,'dup2',case.duplicate),(gate.os,'set_inheritable',case.inherit),
                    (gate,'_acquire_library_snapshot',case.handoff),(gate,'_close_nonstandard',case.sanitize)):
                    stack.enter_context(patch.object(target,name,value))
                return gate._main('0'*64,(1,2,3),6,end)
        case.invoke=invoke
        return case

    def test_gate_snapshot_caller_passes_same_end_and_refuses_directory_fd5_inside_owned_cleanup(self):
        end=9.25
        case=self._gate_snapshot_caller_control(10)
        self.assertEqual(case.config['argv'],case.invoke(end))
        case.handoff.assert_called_once_with(case.snapshot,build_contract.load_profile()['bounds']['workerLaunchPinFileBytes'],end)
        case.sanitize.assert_called_once_with({4,5,6,10,7})
        self.assertEqual([11,12,7,10],[call.args[0] for call in case.closed.call_args_list])
        self.assertEqual([('open','directory',10),('acquire-scope',7),('open','ready',11),('close','ready',11),
                          ('open','report',12),('dup-report',12,4),('close','report',12),
                          ('close','scope',7),('close','directory',10)],case.events)
        self.assertEqual({4:'inherited-report'},case.owned)
        case.duplicate.assert_called_once_with(12,4,inheritable=True);case.inherit.assert_called_once_with(4,True)
        case.release.assert_called_once_with((1,2,3),6,end)
        case=self._gate_snapshot_caller_control(5)
        with self.assertRaisesRegex(ValueError,'snapshot fd aliases gate directory'):case.invoke(end)
        case.handoff.assert_not_called();case.sanitize.assert_not_called()
        self.assertEqual([11,12,7,5],[call.args[0] for call in case.closed.call_args_list])
        self.assertEqual([('open','directory',5),('acquire-scope',7),('open','ready',11),('close','ready',11),
                          ('open','report',12),('dup-report',12,4),('close','report',12),
                          ('close','scope',7),('close','directory',5)],case.events)
        self.assertEqual({4:'inherited-report'},case.owned)
        case.duplicate.assert_called_once_with(12,4,inheritable=True);case.inherit.assert_called_once_with(4,True)
        case.release.assert_called_once_with((1,2,3),6,end)
        case=self._gate_snapshot_caller_control(5)
        del case.config['librarySnapshot'];case.config['argv']=['/usr/bin/bwrap','authored-no-library']
        self.assertEqual(case.config['argv'],case.invoke(end))
        case.handoff.assert_not_called();case.sanitize.assert_called_once_with({4,6,5,7})
        self.assertEqual([11,12,7,5],[call.args[0] for call in case.closed.call_args_list])
        self.assertEqual([('open','directory',5),('acquire-scope',7),('open','ready',11),('close','ready',11),
                          ('open','report',12),('dup-report',12,4),('close','report',12),
                          ('close','scope',7),('close','directory',5)],case.events)
        self.assertEqual({4:'inherited-report'},case.owned)
        case.duplicate.assert_called_once_with(12,4,inheritable=True);case.inherit.assert_called_once_with(4,True)
        case.release.assert_called_once_with((1,2,3),6,end)

    def test_helper_gate_closed_role_and_directory_fd5_refuse_before_snapshot_acquisition(self):
        helper=self._helper_gate_control().record
        tail=['/_worker_exec_monitor','--attempt','a'*32,'--phase','probe','--report-fd','4',
              '--report-device','20','--report-inode','21','--reaper-device','30','--reaper-inode','31',
              '--outer-pidns-device','40','--outer-pidns-inode','41','--','/probe','/work/input.i']
        command=['/usr/bin/bwrap','--ro-bind-fd','5','/probe','--',*tail]
        case=self._gate_snapshot_caller_control(5)
        del case.config['librarySnapshot'];case.config['helperSnapshot']=helper;case.config['argv']=command
        with patch.object(case.gate,'_acquire_helper_snapshot',side_effect=AssertionError('alias must refuse before acquisition')) as acquired:
            with self.assertRaisesRegex(ValueError,'snapshot fd aliases gate directory'):case.invoke(9.25)
        acquired.assert_not_called();case.handoff.assert_not_called();case.sanitize.assert_not_called()
        self.assertEqual([11,12,7,5],[call.args[0] for call in case.closed.call_args_list])
        for wrong in ('both','phase','mapping'):
            case=self._gate_snapshot_caller_control(10);case.config['helperSnapshot']=helper;case.config['argv']=list(command)
            if wrong!='both':del case.config['librarySnapshot']
            if wrong=='phase':case.config['argv'][case.config['argv'].index('--phase')+1]='runtime'
            if wrong=='mapping':case.config['argv'][3]='/other'
            with self.subTest(wrong=wrong),self.assertRaises(ValueError):case.invoke(9.25)
            self.assertEqual([10],[call.args[0] for call in case.closed.call_args_list])
            case.scope.assert_not_called();case.handoff.assert_not_called();case.sanitize.assert_not_called()

    def test_gate_main_forwards_existing_clamped_admission_end_without_restarting(self):
        for phase_end,wanted in ((4,4),(10,7)):
            gate=self.config_gate()
            argv=['scope_gate.py','/authored','--config-sha256','a'*64,'--controller','12','99','34','--phase-deadline',str(phase_end)]
            with ExitStack() as stack:
                main_call=Mock(return_value=['/authored/no-execution'])
                execute=Mock()
                for target,name,value in (
                    (gate.sys,'argv',argv),(gate.time,'monotonic',Mock(return_value=2)),
                    (gate,'_contract',Mock(return_value={'bounds':{'scopeAdmissionSeconds':5}})),
                    (gate.signal,'getsignal',Mock(return_value=gate.signal.SIG_DFL)),
                    (gate.signal,'pthread_sigmask',Mock(return_value=set())),
                    (gate,'_controller_identity',Mock()),(gate,'_live_controller',Mock()),
                    (gate.os,'pidfd_open',Mock(return_value=6)),(gate.os,'close',Mock()),
                    (gate,'_main',main_call),(gate.os,'execv',execute)):
                    stack.enter_context(patch.object(target,name,value))
                gate.main()
                main_call.assert_called_once_with('a'*64,(12,99,34),6,wanted)
                execute.assert_called_once_with('/authored/no-execution',['/authored/no-execution'])

    def test_runtime_consumer_requires_sealed_namespace_attestation(self):
        import evaluate_candidate_v3 as consumer
        from test_process_results import receipt
        result=consumer.process_observation(receipt())
        inputs={'caller':{'path':'/synthetic/caller','sha256':'a'*64},
                'library':{'path':'/synthetic/libcandidate.so','sha256':'c'*64}}
        self.assertTrue(consumer.observation_complete(result))
        consumer._bound_runtime_inputs(result,inputs,result['profileSha256'])
        import copy
        for field,value in (('sha256','d'*64),('sourcePath','/synthetic/other.so'),('inode',93)):
            changed=copy.deepcopy(result)
            changed['workerProofBindings']['expected']['library'][field]=value
            with self.assertRaises(ValueError):consumer._bound_runtime_inputs(changed,inputs,result['profileSha256'])
        changed=copy.deepcopy(result);del changed['workerProofBindings']['expected']['library']
        with self.assertRaises(ValueError):consumer._bound_runtime_inputs(changed,inputs,result['profileSha256'])

    def test_recorded_compiler_subset_identity_invocation_and_post_drift(self):
        profile=build_contract.load_profile()
        identity=profile['gccIdentity']
        target={'path':identity['realpath'],'sha256':identity['sha256']}
        recipe={'worker':['/usr/bin/gcc','authored-input'], 'chdir':'/work','environment':self.env}
        closure={'files':{'authored':{'realpath':str(self.input),'sha256':runtime.digest(self.input)}},
                 'directories':{'/authored':[]},'selections':[{'selected':'authored'}]}
        closure['manifest']={'tools':{'gcc':'/authored/gcc'}}
        closure['files']['/authored/gcc']={'realpath':identity['realpath'],'sha256':identity['sha256']}
        binding={'status':'static-recording-unqualified','scope':'recorded-implicit-link-inputs',
                 'environmentPinSha256':profile['toolchainEnvironmentPinSha256'],
                 'closureSha256':hashlib.sha256(json.dumps(closure,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                 'driverArgv':recipe['worker'],'workingDirectory':'/work','environment':self.env,
                 'dependencies':[{'path':str(self.input),'sha256':runtime.digest(self.input)}],'closure':closure}
        loader=Mock();loader.load_compiler_binding.return_value=binding
        with patch.object(runtime,'_authenticated_monitor_loader',return_value=loader):
            recording=runtime._recorded_compiler_inputs(recipe,target)
            self.assertTrue(recording['invocationMatched'])
            # Same profile pin and otherwise valid closure must join the actual driver.
            import copy
            for field, value in (('realpath','/authored/other-gcc'),('sha256','0'*64)):
                wrong=copy.deepcopy(binding)
                wrong['closure']['files']['/authored/gcc'][field]=value
                wrong['closureSha256']=hashlib.sha256(json.dumps(wrong['closure'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                loader.load_compiler_binding.return_value=wrong
                with self.assertRaisesRegex(ValueError,'driver disagrees'):
                    runtime._recorded_compiler_inputs(recipe,target)
            loader.load_compiler_binding.return_value=binding
            for changed in ({**recipe,'worker':recipe['worker']+['-other']},
                            {**recipe,'chdir':'/other'}, {**recipe,'environment':{**self.env,'HOME':'/tmp'}}):
                self.assertFalse(runtime._recorded_compiler_inputs(changed,target)['invocationMatched'])
            with self.assertRaises(ValueError):
                runtime._recorded_compiler_inputs(recipe,{**target,'sha256':'0'*64})
            self.assertIsNone(runtime._recorded_compiler_inputs(recipe,{'path':str(self.input),'sha256':runtime.digest(self.input)}))
            pins=runtime._pin_files([self.input])
            launch={'compilerRecording':recording,'pins':pins}
            runtime._revalidate_compiler_inputs(launch)
            with self.assertRaises(ValueError):runtime._check_compiler_input_pins(recording,{})
            changed={str(self.input):{**pins[str(self.input)],'sha256':'0'*64}}
            with self.assertRaises(ValueError):runtime._check_compiler_input_pins(recording,changed)
            # Fresh loader revalidation covers directories/selections/symlinks, not only file pins.
            import copy
            for field in ('directories','selections','files'):
                drift=copy.deepcopy(binding);drift['closure'][field]={'changed':True}
                drift['closureSha256']=hashlib.sha256(json.dumps(drift['closure'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                loader.load_compiler_binding.return_value=drift
                with self.assertRaises(ValueError):runtime._revalidate_compiler_inputs(launch)
            loader.load_compiler_binding.side_effect=ValueError('bounded resolver refuses input drift')
            with self.assertRaises(ValueError):runtime._revalidate_compiler_inputs(launch)
        runtime._revalidate_compiler_inputs({'pins':{}})

    def test_actual_prepare_launch_pins_all_explicit_recipe_files_for_consumer(self):
        """Actual producer hashes authored mounted inputs; no SO/source/header pin injection.

        Only fixed host tool/source-closure selection is mocked, not mounted inputs
        or their admission/hash reader. No fixture byte is executed as an ELF.
        """
        import evaluate_candidate_v3 as consumer
        base=self.directory/'trusted';base.mkdir(mode=0o700)
        for name in ('scope_gate.py','build_contract.py','contracts/candidate-build-profile.json',
                     'worker_exec_monitor.c','worker_exec_proof.py','contracts/worker-exec-proof-schema.json',
                     'toolchain-001/worker-exec-monitor.json','toolchain-001/environment-pin.json',
                     'toolchain-001/pin_environment.py','toolchain-001/link_inputs.py','toolchain-001/monitor_inputs.py'):
            file=base/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(b'authored fixed metadata input')
        # Match the actual admitted profile rather than hashing a generic metadata stub.
        (base/'contracts/candidate-build-profile.json').write_bytes(build_contract.PROFILE_PATH.read_bytes())
        # The fixed loader rows describe the reviewed bytes that its real admission now requires.
        for relative,_,_ in runtime._MONITOR_LOADER_SOURCES:
            (base/relative).write_bytes((SOURCE/relative).read_bytes())
        (base/'worker_exec_proof.py').write_bytes((SOURCE/'worker_exec_proof.py').read_bytes())
        caller=base/'caller';caller.write_bytes(b'authored inert caller');caller.chmod(0o500)
        library=base/'reference/libcandidate.so';library.parent.mkdir();library.write_bytes(b'authored inert shared object');library.chmod(0o400)
        monitor=base/'monitor';monitor.write_bytes(b'authored inert monitor');monitor.chmod(0o500)
        reaper=base/'reaper';reaper.write_bytes(b'authored inert reaper');reaper.chmod(0o500)
        cache=base/'cache';cache.write_bytes(b'authored runtime metadata')
        source=self.work/'candidate.c';source.write_bytes(b'authored source')
        header=self.work/'candidate.h';header.write_bytes(b'authored header')
        real_pin_reader=runtime._pin_files
        received=[]
        fixed_host={Path('/usr/bin/python3'),Path('/usr/bin/systemd-run')}
        def producer_pins(paths,deadline=None):
            paths=list(paths);received.extend(paths)
            # These two fixed host launch tools are outside the input-mount test.
            # Their mock omission cannot add/fabricate a SO/source/header row.
            return real_pin_reader([p for p in paths if Path(p) not in fixed_host],deadline)
        def executable(path,deadline=None):
            path=reaper if Path(path)==Path('/usr/bin/bwrap') else Path(path)
            return {'path':str(path),**real_pin_reader([path],deadline)[str(path)]}
        binding={'binaryPath':str(monitor),'dependencies':[{'path':str(cache),'sha256':runtime.digest(cache)}],
                 **{key:runtime._WORKER_PROOF_PARSER_SHA256 if key=='parserSha256' else '0'*64 for key in ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','parserSha256','manifestSha256')}}
        binding['binarySha256']=runtime.digest(monitor)
        with patch.object(runtime,'BASE',base),patch.object(runtime,'load_worker_monitor_binding',return_value=binding),patch.object(runtime,'_nonprivileged_executable',side_effect=executable),patch.object(runtime,'_pin_files',side_effect=producer_pins):
            receipt=runtime._create_worker_receipt();self.addCleanup(os.close,receipt['fd'])
            launch=runtime._prepare_launch(consumer.runtime_command(caller,library,0),self.work,
                    runtime.execution_bounds(managed_scope=True,phase='runtime'),receipt,False,runtime_library={'path':str(library),'sha256':runtime.digest(library)})
            self.addCleanup(os.close,receipt['librarySnapshotFd'])
            pins=launch['pins'];self.assertIn(library,received)
            self.assertEqual(runtime.digest(library),pins[str(library)]['sha256'])
            inputs={'caller':{'path':str(caller),'sha256':runtime.digest(caller)},'library':{'path':str(library),'sha256':runtime.digest(library)}}
            bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
            process={'profileSha256':bounds['profileSha256'],'launchInputPins':pins,'workerProofBindings':launch['proofBinding']}
            # This control isolates actual input-pin admission, not full process proof replay.
            with patch.object(consumer,'observation_complete',return_value=True):
                consumer._bound_runtime_inputs(process,inputs,bounds['profileSha256'],
                                               admitted_pins=real_pin_reader([caller,library]))
            receipt2=runtime._create_worker_receipt();self.addCleanup(os.close,receipt2['fd'])
            command=runtime.contained_command([str(caller),str(source),str(header)],self.work,
                         read_only_files=(caller,source,header),environment=self.env)
            launch2=runtime._prepare_launch(command,self.work,bounds,receipt2,False)
            for file in (caller,source,header):
                self.assertIn(file,received);self.assertEqual(runtime.digest(file),launch2['pins'][str(file)]['sha256'])
            # Consumer bridge: the actual prepare path must add the recorded subset,
            # compare its hashes, and leave a generated output out of fixed pins.
            fixed=base/'recorded-startup';fixed.write_bytes(b'authored startup input')
            generated=self.work/'generated-output';generated.write_bytes(b'authored mutable output')
            recording={'binding':{'dependencies':[{'path':str(fixed),'sha256':runtime.digest(fixed)}]},
                       'invocationMatched':False}
            with patch.object(runtime,'_recorded_compiler_inputs',return_value=recording):
                receipt3=runtime._create_worker_receipt();self.addCleanup(os.close,receipt3['fd'])
                launch3=runtime._prepare_launch(command,self.work,bounds,receipt3,False)
                self.assertEqual(recording,launch3['compilerRecording'])
                self.assertIn(str(fixed),launch3['pins'])
                self.assertNotIn(str(generated),launch3['pins'])
                recording['binding']['dependencies'][0]['sha256']='0'*64
                receipt4=runtime._create_worker_receipt();self.addCleanup(os.close,receipt4['fd'])
                with self.assertRaisesRegex(ValueError,'actual launch pins'):
                    runtime._prepare_launch(command,self.work,bounds,receipt4,False)
            # Same bytes at a new inode or changed bytes cannot match original admission.
            original=pins[str(library)]
            library.rename(library.with_name('original-libcandidate.so'))
            library.write_bytes(b'authored inert shared object');library.chmod(0o400)
            self.assertNotEqual(original,real_pin_reader([library])[str(library)])
            with self.assertRaises(ValueError):
                consumer._bound_runtime_inputs(process,inputs,bounds['profileSha256'],
                                               admitted_pins=real_pin_reader([caller,library]))
            library.chmod(0o600)
            library.write_bytes(b'changed authored library')
            self.assertNotEqual(original['sha256'],real_pin_reader([library])[str(library)]['sha256'])
            library.unlink()
            with self.assertRaises(FileNotFoundError):real_pin_reader([library])

    def test_stale_membership_never_authorizes_a_replacement_pid_signal(self):
        # PID77 was in a stale cgroup snapshot; its current identity is another process.
        replacement={'pid':77,'start':999,'pgid':77,'sid':77}
        evidence={'cgroup':'/authored/cgroup','device':10,'inode':11,'_directoryFd':40}
        directory=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_dev=10,st_ino=11)
        with patch.object(runtime.os,'fstat',return_value=directory),patch.object(runtime.os,'open',return_value=41) as opened,patch.object(runtime.os,'write',return_value=2) as written,patch.object(runtime.os,'close'),patch.object(runtime,'process_identity',return_value=replacement) as identity,patch.object(runtime.os,'pidfd_open',side_effect=AssertionError('must not acquire stale numeric PID')),patch.object(runtime.signal,'pidfd_send_signal',side_effect=AssertionError('must not signal replacement')):
            runtime._kill_owned_scope(evidence)
            identity.assert_not_called()
            opened.assert_called_once_with('cgroup.kill',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=40)
            written.assert_called_once_with(41,b'1\n')
            with self.assertRaises(RuntimeError):runtime.kill_exact(replacement)
        wrong=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_dev=10,st_ino=999)
        with patch.object(runtime.os,'fstat',return_value=wrong),patch.object(runtime.os,'open') as opened:
            with self.assertRaises(RuntimeError):runtime._kill_owned_scope(evidence)
            opened.assert_not_called()

    def test_named_provisioner_has_fixed_command_and_cannot_select_candidate_source(self):
        # The source-layout fixture may be a staged tree without its own .git.
        # Use its actual owned leaf and explicit synthetic repository context;
        # production repository-root discovery is not part of this pure route test.
        output=self.directory/'worker_exec_monitor'
        with patch.object(runtime,'_repository_root',return_value=SOURCE.parents[3]),patch.object(runtime,'_run_scoped',return_value={'provisioningOnly':True}) as run:
            value=runtime.provision_worker_monitor(output)
        self.assertTrue(value['provisioningOnly'])
        self.assertIs(run.call_args.kwargs['provisioning'],True)
        argv=run.call_args.args[0]
        self.assertEqual(['/usr/bin/gcc','-D_GNU_SOURCE','-std=c11','-O2','-Wall','-Wextra','-Werror',
                          '-Wl,-z,relro,-z,now,-z,noexecstack',str(SOURCE/'worker_exec_monitor.c'),'-o',str(output)],argv)
        with self.assertRaises(ValueError):runtime.provision_worker_monitor(self.work/'candidate')
        signature=ast.parse((SOURCE/'bounded_runtime.py').read_text())
        public=next(node for node in signature.body if isinstance(node,ast.FunctionDef) and node.name=='bounded_run')
        self.assertNotIn('provisioning',[arg.arg for arg in public.args.args+public.args.kwonlyargs])

    def _helper_capture_control(self, *, fail=None, late=None, late_occurrence=None):
        self._helper_case_number=getattr(self,'_helper_case_number',0)+1
        source=self.work/('helper-source-'+str(self._helper_case_number));payload=b'\x7fELF authored inert helper A'
        source.write_bytes(payload);source.chmod(0o500)
        with patch.object(runtime.time,'monotonic',return_value=0.0):
            admitted=runtime._pin_files([source],10.0)
        case=types.SimpleNamespace(source=source,payload=payload,admitted=admitted,receipt={},data=bytearray(),
                                   mode=0o777,seals=0,now=0.0,events=[],counts={},closes=[],failure=OSError('authored helper fault'))
        held=900000
        native={name:getattr(runtime.os,name) for name in ('open','read','write','pread','fstat','fchmod','getxattr','close')}
        def effect(stage):
            case.events.append(stage);case.counts[stage]=case.counts.get(stage,0)+1
            if late==stage and (late_occurrence is None or case.counts[stage]==late_occurrence):case.now=10.0
            if fail==stage:raise case.failure
        def create(name,flags):
            effect('create');self.assertEqual(('callable-probe-helper',0x13),(name,flags));return held
        def metadata(fd):
            if fd!=held:return native['fstat'](fd)
            effect('fstat')
            return types.SimpleNamespace(st_dev=91,st_ino=92,st_uid=123,
                st_mode=stat.S_IFREG|case.mode,st_size=len(case.data))
        def write(fd,data):
            self.assertEqual(held,fd);effect('write')
            count=min(len(data),getattr(case,'write_limit',len(data)))
            case.data.extend(bytes(data[:count]));return count
        def pread(fd,size,offset):
            self.assertEqual(held,fd);effect('pread');return bytes(case.data[offset:offset+size])
        def mode(fd,value):
            self.assertEqual((held,0o500),(fd,value));effect('mode');case.mode=value
        def seals(fd,operation,*args):
            self.assertEqual(held,fd)
            if operation==runtime.fcntl.F_ADD_SEALS:
                effect('seal');self.assertEqual((0x2f,),args);case.seals=0x3f;return 0
            self.assertEqual(runtime.fcntl.F_GET_SEALS,operation);effect('get-seals');return case.seals
        def capability(fd,name):
            self.assertEqual((held,'security.capability'),(fd,name));effect('xattr');raise OSError(runtime.errno.ENODATA,'absent')
        def close(fd):
            if fd==held:
                case.closes.append(fd);effect('object-close');return
            result=native['close'](fd)
            if case.data:effect('source-close')
            return result
        case.created=Mock(side_effect=create)
        def owner_identity(*args):effect('owner');return {'pid':123,'start':77}
        def run(action):
            with ExitStack() as stack:
                for target,name,value in (
                    (runtime.time,'monotonic',Mock(side_effect=lambda:case.now)),
                    (runtime,'process_identity',Mock(side_effect=owner_identity)),
                    (runtime.os,'getpid',Mock(return_value=123)),(runtime.os,'getuid',Mock(return_value=123)),
                    (runtime.os,'memfd_create',case.created),(runtime.os,'fstat',Mock(side_effect=metadata)),
                    (runtime.os,'write',Mock(side_effect=write)),(runtime.os,'pread',Mock(side_effect=pread)),
                    (runtime.os,'fchmod',Mock(side_effect=mode)),(runtime.os,'getxattr',Mock(side_effect=capability)),
                    (runtime.os,'close',Mock(side_effect=close)),(runtime.fcntl,'fcntl',Mock(side_effect=seals))):
                    stack.enter_context(patch.object(target,name,value))
                return action()
        case.run=run
        case.invoke=lambda:run(lambda:runtime._snapshot_helper(source,admitted,case.receipt,10.0))
        return case

    def test_helper_snapshot_measures_original_source_and_owned_sealed_object_without_proc_reopen(self):
        case=self._helper_capture_control();owner=case.invoke()
        self.assertEqual(case.admitted[str(case.source)],owner.source_pin)
        self.assertEqual(0x3f,case.seals);self.assertEqual(0o500,case.mode)
        self.assertLess(case.events.index('mode'),case.events.index('seal'))
        self.assertEqual(case.payload,bytes(case.data))
        self.assertNotEqual((owner.helper['device'],owner.helper['inode']),
                            (owner.source_pin['device'],owner.source_pin['inode']))
        coordinate='/proc/123/fd/900000';row={'device':91,'inode':92,'mode':0o500,'sha256':hashlib.sha256(case.payload).hexdigest()}
        launch={'pins':{**case.admitted,coordinate:row}}
        real=runtime._pin_files
        with patch.object(runtime,'_pin_files',wraps=real) as ordinary:
            self.assertEqual(launch['pins'],case.run(lambda:runtime._launch_pins(launch,case.receipt,10.0)))
        self.assertEqual([(case.admitted,10.0)],[call.args for call in ordinary.call_args_list])
        case.run(lambda:runtime._close_helper_snapshot(case.receipt))
        case.run(lambda:runtime._close_helper_snapshot(case.receipt))
        self.assertEqual([900000],case.closes);self.assertIsNone(owner.descriptor)
        with self.assertRaisesRegex(ValueError,'ownership lost'):
            case.run(lambda:runtime._launch_pins(launch,case.receipt,10.0))

    def test_helper_snapshot_partial_progress_minimum_seals_and_unsupported_APIs_are_closed(self):
        case=self._helper_capture_control();case.write_limit=3;owner=case.invoke()
        self.assertGreater(case.events.count('write'),1);self.assertEqual(case.payload,bytes(case.data))
        case.seals=0x2f;case.run(lambda:runtime._helper_pin(owner,10.0))
        owner.helper['size']+=1
        with self.assertRaises(ValueError):case.run(lambda:runtime._helper_pin(owner,10.0))
        case.run(lambda:runtime._close_helper_snapshot(case.receipt))
        case=self._helper_capture_control();case.write_limit=0
        with self.assertRaisesRegex(ValueError,'short write'):case.invoke()
        self.assertEqual([900000],case.closes)
        for unavailable in ('memfd_create','getxattr'):
            case=self._helper_capture_control()
            def refuse_api():
                with patch.object(runtime.os,unavailable,None):runtime._snapshot_helper(case.source,case.admitted,case.receipt,10.0)
            with self.subTest(api=unavailable),self.assertRaisesRegex(ValueError,'APIs unavailable'):case.run(refuse_api)
            case.created.assert_not_called();self.assertEqual([],case.closes)
        case=self._helper_capture_control();owner=case.invoke()
        def unknown_xattr():
            with patch.object(runtime.os,'getxattr',side_effect=OSError(runtime.errno.ENOTSUP,'authored unsupported')):
                runtime._helper_pin(owner,10.0)
        with self.assertRaises(OSError):case.run(unknown_xattr)
        def changed_controller():
            with patch.object(runtime,'process_identity',return_value={'pid':123,'start':78}):
                runtime._helper_pin(owner,10.0)
        with self.assertRaisesRegex(ValueError,'owner lifetime'):case.run(changed_controller)
        case.run(lambda:runtime._close_helper_snapshot(case.receipt))

    def _helper_clocked_hash(self, case, payload, trace, action, *, late_digest=None, late_update=None):
        # Hash real supplied bytes; only selected terminal-operation timing is authored.
        original=hashlib.sha256
        class ObservedHash:
            def __init__(self,*args,**kwargs):
                self.real=original(*args,**kwargs);self.data=bytearray(args[0] if args else b'')
                if not args:trace['emptyConstructors']+=1
            def update(self,block):
                self.real.update(block);self.data.extend(block)
                if bytes(self.data)==payload:
                    trace['updates']+=1
                    if trace['updates']==late_update:case.now=10.0
            def hexdigest(self):
                value=self.real.hexdigest()
                if bytes(self.data)==payload:
                    trace['digests']+=1
                    if trace['digests']==late_digest:case.now=10.0
                return value
        with patch.object(hashlib,'sha256',side_effect=ObservedHash):return action()

    def test_helper_pin_late_bound_owner_and_final_update_cannot_start_next_fstat(self):
        # Creator observes owner twice; select the third owner in the actual later repin.
        case=self._helper_capture_control(late='owner',late_occurrence=3);owner=case.invoke()
        start=len(case.events)
        with self.assertRaises(TimeoutError):case.run(lambda:runtime._helper_pin(owner,10.0))
        self.assertEqual(3,case.counts['owner']);self.assertNotIn('fstat',case.events[start:])
        case.run(lambda:runtime._close_helper_snapshot(case.receipt));self.assertEqual([900000],case.closes)
        case=self._helper_capture_control();owner=case.invoke();start=len(case.events)
        trace={'updates':0,'digests':0,'emptyConstructors':0}
        with self.assertRaises(TimeoutError):
            case.run(lambda:self._helper_clocked_hash(case,case.payload,trace,
                lambda:runtime._helper_pin(owner,10.0),late_update=1))
        self.assertEqual(1,trace['updates']);self.assertEqual(0,trace['digests'])
        self.assertEqual(1,case.events[start:].count('fstat'))  # initial only, no final metadata call
        case.run(lambda:runtime._close_helper_snapshot(case.receipt));self.assertEqual([900000],case.closes)

    def test_helper_copy_terminal_digest_cannot_start_chmod_and_pin_digest_cannot_return(self):
        case=self._helper_capture_control();trace={'updates':0,'digests':0,'emptyConstructors':0}
        # First matching digest is ordinary source pinning; second is the copied-H digest.
        with self.assertRaises(TimeoutError):
            case.run(lambda:self._helper_clocked_hash(case,case.payload,trace,
                lambda:runtime._snapshot_helper(case.source,case.admitted,case.receipt,10.0),late_digest=2))
        self.assertEqual(2,trace['digests']);self.assertNotIn('mode',case.events)
        self.assertNotIn('seal',case.events);self.assertEqual([900000],case.closes)
        self.assertIsNone(case.receipt.get('helperSnapshotFd'));self.assertEqual(1,case.events.count('source-close'))
        case=self._helper_capture_control(fail='object-close');trace={'updates':0,'digests':0,'emptyConstructors':0}
        with self.assertRaises(TimeoutError) as primary:
            case.run(lambda:self._helper_clocked_hash(case,case.payload,trace,
                lambda:runtime._snapshot_helper(case.source,case.admitted,case.receipt,10.0),late_digest=2))
        self.assertIsNot(case.failure,primary.exception);self.assertEqual(2,trace['digests'])
        self.assertIs(case.failure,case.receipt['helperSnapshotCloseFailure'])
        self.assertIn('helper snapshot object cleanup failed',primary.exception.__notes__)
        self.assertNotIn('mode',case.events);self.assertEqual(1,case.events.count('source-close'))
        case.run(lambda:runtime._close_helper_snapshot(case.receipt));self.assertEqual([900000],case.closes)
        case=self._helper_capture_control();owner=case.invoke();start=len(case.events)
        trace={'updates':0,'digests':0,'emptyConstructors':0};returned=[]
        def repin():returned.append(runtime._helper_pin(owner,10.0))
        with self.assertRaises(TimeoutError):
            case.run(lambda:self._helper_clocked_hash(case,case.payload,trace,repin,late_digest=1))
        self.assertEqual(1,trace['digests']);self.assertEqual([],returned)
        self.assertEqual(2,case.events[start:].count('fstat'))
        case.run(lambda:runtime._close_helper_snapshot(case.receipt));self.assertEqual([900000],case.closes)
        case=self._helper_capture_control();owner=case.invoke();coordinate=owner.coordinate()
        launch={'pins':{**case.admitted,coordinate:{'device':91,'inode':92,'mode':0o500,
                                                  'sha256':case.admitted[str(case.source)]['sha256']}}}
        actual_pin=runtime._helper_pin;returned=[]
        def late_after_pin(held,end):
            row=actual_pin(held,end);case.now=10.0;return row
        def union():
            with patch.object(runtime,'_helper_pin',side_effect=late_after_pin):
                returned.append(runtime._launch_pins(launch,case.receipt,10.0))
        with self.assertRaises(TimeoutError):case.run(union)
        self.assertEqual([],returned)
        case.run(lambda:runtime._close_helper_snapshot(case.receipt));self.assertEqual([900000],case.closes)

    def test_helper_initial_ELF_observation_refuses_before_hash_creation_and_preserves_close(self):
        case=self._helper_capture_control();owner=case.invoke();trace={'updates':0,'digests':0,'emptyConstructors':0}
        def repin():
            reading=runtime.os.pread
            def late_magic(fd,size,offset):
                value=reading(fd,size,offset)
                if size==4 and offset==0:case.now=10.0
                return value
            with patch.object(runtime.os,'pread',side_effect=late_magic):runtime._helper_pin(owner,10.0)
        start=len(case.events)
        with self.assertRaises(TimeoutError):
            case.run(lambda:self._helper_clocked_hash(case,case.payload,trace,repin))
        self.assertEqual(0,trace['emptyConstructors']);self.assertEqual(0,trace['digests'])
        self.assertEqual(1,case.events[start:].count('pread'));self.assertEqual(1,case.events[start:].count('fstat'))
        case.run(lambda:runtime._close_helper_snapshot(case.receipt));self.assertEqual([900000],case.closes)

    def test_helper_gate_late_terminal_digest_omits_final_owner_and_late_final_owner_omits_fstat(self):
        case=self._helper_gate_control();trace={'updates':0,'digests':0,'emptyConstructors':0}
        with self.assertRaises(TimeoutError):
            self._helper_clocked_hash(case,case.payload,trace,case.invoke,late_digest=1)
        self.assertEqual(1,trace['digests']);self.assertEqual(1,case.counts['owner'])
        self.assertEqual(1,case.counts['fstat']);case.duplicate.assert_not_called();self.assertEqual([10],case.closes)
        # Do not expire the first owner check: target its second, terminal observation.
        case=self._helper_gate_control(late='owner',late_occurrence=2)
        with self.assertRaises(TimeoutError):case.invoke()
        self.assertEqual(2,case.counts['owner']);self.assertEqual(1,case.counts['fstat'])
        case.duplicate.assert_not_called();self.assertEqual([10],case.closes)

    def test_helper_actual_prepare_substitutes_only_probe_mount_and_commits_source_plus_owned_H(self):
        case=self._helper_capture_control();profile,profile_sha=build_contract.load_profile_with_digest()
        bounds=runtime.execution_bounds(managed_scope=True,phase='probe')
        recipe={'target':case.source,'worker':['/probe','/work/source.i'],
                'prefix':['--ro-bind',str(case.source),'/probe'],
                'mounts':[{'source':case.source,'original':case.source,'target':Path('/probe'),'writable':False}]}
        binding={'binaryPath':'/authored/monitor','dependencies':[],**{k:'a'*64 for k in
                 ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','manifestSha256')}}
        binding['parserSha256']=runtime._WORKER_PROOF_PARSER_SHA256
        common={**case.admitted,str(runtime.BASE/'contracts/candidate-build-profile.json'):{'device':1,'inode':2,'mode':0o400,'sha256':profile_sha},
                str(runtime.BASE/'worker_exec_proof.py'):{'device':1,'inode':3,'mode':0o400,'sha256':runtime._WORKER_PROOF_PARSER_SHA256}}
        common.update({str(runtime.BASE/name):{'device':2,'inode':index,'mode':0o400,'sha256':sha}
                       for index,(name,_,sha) in enumerate(runtime._MONITOR_LOADER_SOURCES)})
        common['/authored/monitor']={'device':7,'inode':8,'mode':0o500,'sha256':'a'*64}
        case.receipt.update(directory=Path('/authored')/('a'*32),directoryDevice=3,directoryInode=4,device=5,inode=6)
        real_pin=runtime._pin_files;native_stat=Path.stat;native_lstat=Path.lstat;configs=[]
        def pin(paths,deadline=None):
            return real_pin(paths,deadline) if list(paths)==[case.source] else dict(common)
        def executable(path,deadline=None):
            return {'path':str(path),**case.admitted[str(case.source)]} if path==case.source else {'path':str(path),'device':7,'inode':8,'mode':0o500,'sha256':'a'*64}
        def metadata(path,*args,**kwargs):
            if str(path)=='/proc/self/ns/pid' or path==case.receipt['directory']/'python-cache':return types.SimpleNamespace(st_dev=9,st_ino=10)
            return native_stat(path,*args,**kwargs)
        def lmetadata(path,*args,**kwargs):
            if path==case.receipt['directory']/'python-cache':return types.SimpleNamespace(st_dev=9,st_ino=10)
            return native_lstat(path,*args,**kwargs)
        with patch.object(runtime,'_contained_recipe',return_value=recipe),patch.object(runtime,'load_worker_monitor_binding',return_value=binding),                 patch.object(runtime,'_recorded_compiler_inputs',return_value=None),patch.object(runtime,'_nonprivileged_executable',side_effect=executable),                 patch.object(runtime,'_pin_files',side_effect=pin),patch.object(runtime,'private_directory',side_effect=lambda path:path),                 patch.object(Path,'stat',metadata),patch.object(Path,'lstat',lmetadata),                 patch.object(runtime,'_publish_config',side_effect=lambda path,raw:configs.append(json.loads(raw))):
            launch=case.run(lambda:runtime._prepare_launch(['/authored'],self.work,bounds,case.receipt,False,deadline=10.0,helper_admission=case.admitted))
        self.assertEqual(case.admitted[str(case.source)],launch['pins'][str(case.source)])
        self.assertEqual((91,92),(launch['expected']['targetDevice'],launch['expected']['targetInode']))
        self.assertEqual(case.admitted[str(case.source)]['sha256'],launch['proofBinding']['targetSha256'])
        self.assertEqual(0o500,launch['pins']['/proc/123/fd/900000']['mode'])
        self.assertIn(['--ro-bind-fd','5','/probe'],[launch['command'][i:i+3] for i in range(len(launch['command'])-2)])
        self.assertNotIn(['--ro-bind',str(case.source),'/probe'],[launch['command'][i:i+3] for i in range(len(launch['command'])-2)])
        self.assertEqual(case.receipt['helperSnapshot'].binding(),configs[0]['helperSnapshot'])
        self.assertNotIn('librarySnapshot',configs[0]);case.run(lambda:runtime._close_helper_snapshot(case.receipt))

    def test_helper_snapshot_missing_seals_content_mode_and_export_conflicts_refuse(self):
        for bit in (1,2,4,8,32,64):
            case=self._helper_capture_control();owner=case.invoke()
            case.seals=0x3f & ~bit if bit!=64 else 0x7f
            with self.subTest(bit=bit),self.assertRaises(ValueError):
                case.run(lambda:runtime._helper_pin(owner,10.0))
            case.run(lambda:runtime._close_helper_snapshot(case.receipt))
            self.assertEqual([900000],case.closes)
        for change in ('mode','bytes'):
            case=self._helper_capture_control();owner=case.invoke()
            if change=='mode':case.mode=0o700
            else:case.data[-1]^=1
            with self.subTest(change=change),self.assertRaises(ValueError):case.run(lambda:runtime._helper_pin(owner,10.0))
            case.run(lambda:runtime._close_helper_snapshot(case.receipt))
        case=self._helper_capture_control()
        with patch.object(runtime.os,'MFD_EXEC',32,create=True),self.assertRaisesRegex(ValueError,'conflicting'):
            case.invoke()
        case.created.assert_not_called()
        case=self._helper_capture_control();case.admitted[str(case.source)]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'original admission'):case.invoke()
        case.created.assert_not_called()
        case=self._helper_capture_control();case.source.chmod(0o700)
        case.source.write_bytes(b'\x7fELF authored inert helper B');case.source.chmod(0o500)
        with self.assertRaisesRegex(ValueError,'original admission'):case.invoke()
        case.created.assert_not_called()
        case=self._helper_capture_control();case.source.chmod(0o700)
        case.source.write_bytes(b'not an ELF helper');case.source.chmod(0o500)
        with patch.object(runtime.time,'monotonic',return_value=0.0):case.admitted=runtime._pin_files([case.source],10.0)
        # Invoke with the new admission explicitly; the original invoke closure intentionally retains A.
        with self.assertRaisesRegex(ValueError,'not ELF'):
            case.run(lambda:runtime._snapshot_helper(case.source,case.admitted,case.receipt,10.0))
        self.assertNotIn('seal',case.events);self.assertEqual([900000],case.closes)

    def test_helper_snapshot_operation_and_late_refusal_preserve_primary_and_once_cleanup(self):
        for stage in ('create','write','mode','fstat','xattr','seal','get-seals','pread','source-close'):
            for late in (False,True):
                case=self._helper_capture_control(fail=None if late else stage,late=stage if late else None)
                with self.subTest(stage=stage,late=late):
                    with self.assertRaises((TimeoutError,OSError)) as observed:case.invoke()
                    if not late:self.assertIs(case.failure,observed.exception)
                    self.assertEqual([] if stage=='create' and not late else [900000],case.closes)
                    self.assertIsNone(case.receipt.get('helperSnapshotFd'))
        case=self._helper_capture_control(fail='object-close');owner=case.invoke()
        with self.assertRaises(OSError) as observed:case.run(lambda:runtime._close_helper_snapshot(case.receipt))
        self.assertIs(case.failure,observed.exception);self.assertTrue(case.receipt['helperSnapshotCloseFailed'])
        self.assertIs(case.failure,case.receipt['helperSnapshotCloseFailure']);self.assertIsNone(owner.descriptor)
        case.run(lambda:runtime._close_helper_snapshot(case.receipt));self.assertEqual([900000],case.closes)

    def _helper_gate_control(self, descriptor=10, *, late=None, fail=None, late_occurrence=None):
        gate=self.config_gate();payload=b'\x7fELF authored immutable helper'
        helper={'device':91,'inode':92,'size':len(payload),'mode':0o500,'sha256':hashlib.sha256(payload).hexdigest(),
                'sourcePath':'/authored/helper','sourcePin':{'device':81,'inode':82,'mode':0o500,'sha256':hashlib.sha256(payload).hexdigest()}}
        record={'ownerPid':123,'ownerStart':77,'descriptor':900000,'helper':helper}
        fields=['0']*20;fields[19]='77'
        case=types.SimpleNamespace(gate=gate,record=record,payload=payload,now=0.0,closes=[],events=[],counts={},seals=0x3f,mode=0o500,
                                   failure=OSError('authored handoff fault'))
        def effect(stage,value=None):
            case.events.append(stage);case.counts[stage]=case.counts.get(stage,0)+1
            if late==stage and (late_occurrence is None or case.counts[stage]==late_occurrence):case.now=10.0
            if fail==stage:raise case.failure
            return value
        def metadata(fd):
            self.assertEqual(descriptor,fd)
            return effect('fstat',types.SimpleNamespace(st_dev=91,st_ino=92,st_size=len(payload),st_uid=123,st_mode=stat.S_IFREG|case.mode))
        def capability(fd,name):
            self.assertEqual((descriptor,'security.capability'),(fd,name));effect('xattr');raise OSError(gate.errno.ENODATA,'absent')
        def close(fd):case.closes.append(fd);effect('target-close' if fd==5 else 'source-close')
        case.opened=Mock(side_effect=lambda *a,**k:effect('open',descriptor))
        case.duplicate=Mock(side_effect=lambda *a,**k:effect('dup',5));case.inherit=Mock(side_effect=lambda *a,**k:effect('inherit'))
        def invoke():
            with ExitStack() as stack:
                for target,name,value in (
                    (gate.time,'monotonic',Mock(side_effect=lambda:case.now)),
                    (Path,'read_text',Mock(side_effect=lambda *a,**k:effect('owner','123 (owner) '+' '.join(fields)))),
                    (gate.os,'open',case.opened),(gate.os,'fstat',Mock(side_effect=metadata)),
                    (gate.fcntl,'fcntl',Mock(side_effect=lambda *a:effect('seals',case.seals))),
                    (gate.os,'getxattr',Mock(side_effect=capability)),
                    (gate.os,'read',Mock(side_effect=lambda *a:effect('read',payload))),
                    (gate.os,'lseek',Mock(side_effect=lambda *a:effect('seek',0))),
                    (gate.os,'dup2',case.duplicate),(gate.os,'set_inheritable',case.inherit),
                    (gate.os,'close',Mock(side_effect=close))):stack.enter_context(patch.object(target,name,value))
                return gate._acquire_helper_snapshot(record,1024,10.0,(123,77,123))
        case.invoke=invoke;return case

    def test_helper_gate_hashes_real_payload_and_transfers_only_exact_owned_fd5(self):
        for descriptor in (5,10):
            case=self._helper_gate_control(descriptor);self.assertIsNone(case.invoke())
            case.opened.assert_called_once_with('/proc/123/fd/900000',case.gate.os.O_RDONLY|case.gate.os.O_NONBLOCK|case.gate.os.O_CLOEXEC)
            case.duplicate.assert_called_once_with(descriptor,5,inheritable=True);case.inherit.assert_called_once_with(5,True)
            self.assertEqual([] if descriptor==5 else [10],case.closes)
            self.assertEqual(2,case.events.count('fstat'));self.assertEqual(2,case.events.count('seals'))
        for change in ('controller','source','digest','seals','mode'):
            case=self._helper_gate_control()
            if change=='controller':case.record['ownerStart']=78
            elif change=='source':case.record['helper']['sourcePin']['sha256']='0'*64
            elif change=='digest':case.record['helper']['sha256']=case.record['helper']['sourcePin']['sha256']='0'*64
            elif change=='seals':case.seals=0x0f
            else:case.mode=0o700
            with self.subTest(change=change),self.assertRaises(ValueError):case.invoke()
            case.duplicate.assert_not_called()

    def test_helper_gate_refuses_late_and_faulted_handoff_without_new_end_or_duplicate_close(self):
        for stage in ('owner','open','fstat','seals','xattr','read','seek','dup','inherit','source-close'):
            for late in (False,True):
                case=self._helper_gate_control(late=stage if late else None,fail=None if late else stage)
                with self.subTest(stage=stage,late=late),self.assertRaises((TimeoutError,OSError)) as observed:case.invoke()
                if not late:self.assertIs(case.failure,observed.exception)
                expected=[] if stage=='owner' or stage=='open' and not late else [10,5] if stage in ('dup','inherit','source-close') and (stage!='dup' or late) else [10]
                self.assertEqual(expected,case.closes)

    def config_gate(self):
        gate=types.ModuleType('_auth_config_gate_control');gate.__file__=str(SOURCE/'scope_gate.py')
        exec(compile((SOURCE/'scope_gate.py').read_bytes(),gate.__file__,'exec'),gate.__dict__)
        return gate

    def test_gate_config_open_is_nonblocking_and_special_files_refuse_before_read(self):
        gate=self.config_gate()
        for kind in (stat.S_IFIFO,stat.S_IFDIR,stat.S_IFSOCK,stat.S_IFCHR,stat.S_IFBLK):
            metadata=types.SimpleNamespace(st_mode=kind|0o600,st_uid=101,st_nlink=1)
            with self.subTest(kind=kind),patch.object(gate.os,'open',return_value=123) as opened,patch.object(gate.os,'fstat',return_value=metadata),patch.object(gate.os,'getuid',return_value=101),patch.object(gate.os,'read') as read,patch.object(gate.os,'close') as close:
                with self.assertRaisesRegex(ValueError,'check 17'):
                    gate._read_at(39,'launch.json',4)
                opened.assert_called_once_with('launch.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=39)
                read.assert_not_called();close.assert_called_once_with(123)

    def test_gate_config_regular_reader_keeps_exact_bytes_bound_and_error_closure(self):
        gate=self.config_gate()
        metadata=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=101,st_nlink=1)
        cases=(([],b''),( [b'ab',b'cd'],b'abcd'),([b'ab',b'cde'],None))
        for blocks,expected in cases:
            with self.subTest(blocks=blocks),patch.object(gate.os,'open',return_value=123),patch.object(gate.os,'fstat',return_value=metadata),patch.object(gate.os,'getuid',return_value=101),patch.object(gate.os,'read',side_effect=[*blocks,b'']) as read,patch.object(gate.os,'close') as close:
                if expected is None:
                    with self.assertRaisesRegex(ValueError,'bounded file overflow'):
                        gate._read_at(39,'launch.json',4)
                else:self.assertEqual(expected,gate._read_at(39,'launch.json',4))
                self.assertEqual([(123,5),(123,3)] if expected is None else ([(123,5),(123,3),(123,1)] if blocks else [(123,5)]),[call.args for call in read.call_args_list])
                close.assert_called_once_with(123)
        failure=OSError('authored read failure')
        with patch.object(gate.os,'open',return_value=123),patch.object(gate.os,'fstat',return_value=metadata),patch.object(gate.os,'getuid',return_value=101),patch.object(gate.os,'read',side_effect=failure),patch.object(gate.os,'close') as close:
            with self.assertRaises(OSError) as caught:gate._read_at(39,'launch.json',4)
            self.assertIs(failure,caught.exception);close.assert_called_once_with(123)

    def test_config_memory_commitment_and_actual_single_buffer_reader(self):
        gate=self.config_gate();config={'argv':['/usr/bin/bwrap','authored'],'schemaVersion':1}
        raw,sha=runtime._committed_config(config)
        file=self.work/'launch.json';runtime._publish_config(file,raw)
        self.assertEqual(sha,hashlib.sha256(raw).hexdigest())
        directory=os.open(self.work,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,directory)
        self.assertEqual(config,gate._authenticated_config(directory,sha))
        file.write_bytes(raw.replace(b'authored',b'attacker'))
        with self.assertRaisesRegex(ValueError,'commitment'):gate._authenticated_config(directory,sha)
        file.write_bytes(raw)
        self.assertEqual(config,gate._authenticated_config(directory,sha))
        for invalid in (b'{"a":1,"a":2}',b'{} trailing',b'x'*65537):
            file.write_bytes(invalid)
            with self.assertRaises(ValueError):gate._authenticated_config(directory,hashlib.sha256(invalid).hexdigest())
        file.write_bytes(raw)
        real_read=gate.os.read
        with patch.object(gate.os,'read',side_effect=lambda fd,n:real_read(fd,min(n,2))):
            self.assertEqual(config,gate._authenticated_config(directory,sha))

    def test_signal_release_sender_and_original_absolute_clock(self):
        gate=self.config_gate();valid=dict(si_signo=gate.signal.SIGUSR1,si_code=0,si_errno=0,si_pid=12,si_uid=34)
        with patch.object(gate,'_live_controller') as live,patch.object(gate.time,'monotonic',return_value=1),patch.object(gate.signal,'sigtimedwait',return_value=types.SimpleNamespace(**valid)) as wait:
            gate._wait_release((12,99,34),6,10);self.assertEqual(2,live.call_count)
            for key,value in (('si_code',-1),('si_code',-6),('si_pid',13),('si_uid',35),('si_errno',1),('si_signo',gate.signal.SIGUSR2)):
                wait.return_value=types.SimpleNamespace(**{**valid,key:value})
                with self.assertRaises(ValueError):gate._wait_release((12,99,34),6,10)
            wait.return_value=None
            with self.assertRaises(ValueError):gate._wait_release((12,99,34),6,10)
            wait.reset_mock();wait.return_value=types.SimpleNamespace(**valid)
            with patch.object(gate.time,'monotonic',return_value=10):
                with self.assertRaises(TimeoutError):gate._wait_release((12,99,34),6,10)
            wait.assert_not_called()  # even a pending valid signal cannot renew an expired clock
            with patch.object(gate.time,'monotonic',side_effect=[1,2,10]):
                with self.assertRaises(TimeoutError):gate._wait_release((12,99,34),6,10)

    def test_gate_initial_signal_policy_and_controlled_exit_restore_mask_and_close(self):
        gate=self.config_gate();argv=['scope_gate.py','/authored','--config-sha256','a'*64,'--controller','12','99','34','--phase-deadline','10']
        with patch.object(gate.sys,'argv',argv),patch.object(gate.time,'monotonic',return_value=1),patch.object(gate,'_contract',return_value=build_contract.load_profile()),patch.object(gate.signal,'getsignal',return_value=gate.signal.SIG_DFL),patch.object(gate.signal,'pthread_sigmask',return_value=set()) as mask,patch.object(gate,'_controller_identity'),patch.object(gate,'_live_controller'),patch.object(gate.os,'pidfd_open',return_value=6),patch.object(gate.os,'close') as close,patch.object(gate,'_main',side_effect=ValueError('authored refusal')),patch.object(gate.os,'execv') as execute:
            with self.assertRaisesRegex(ValueError,'authored refusal'):gate.main()
            close.assert_called_once_with(6);self.assertEqual((gate.signal.SIG_SETMASK,set()),mask.call_args.args);execute.assert_not_called()
            with patch.object(gate.signal,'getsignal',return_value=gate.signal.SIG_IGN):
                with self.assertRaisesRegex(ValueError,'inherited'):gate.main()
            with patch.object(gate.signal,'pthread_sigmask',return_value={gate.signal.SIGUSR1}):
                with self.assertRaisesRegex(ValueError,'inherited'):gate.main()
            with patch.object(gate.os,'close',side_effect=OSError('close refused')):
                with self.assertRaises(OSError):gate.main()
                self.assertEqual(gate.signal.SIG_SETMASK,mask.call_args.args[0])

    def test_gate_lineage_and_scope_release_use_exact_owned_lifetimes(self):
        root={'pid':10,'start':100};launch={'launcherIdentity':root}
        rows={12:{'pid':12,'start':120,'ppid':10},10:{'pid':10,'start':100,'ppid':1}}
        with patch.object(runtime,'_lineage_identity',side_effect=lambda pid:dict(rows[pid])),patch.object(runtime,'process_identity',return_value=root),patch.object(runtime.os,'pidfd_open',return_value=55) as opened,patch.object(runtime.os,'close'):
            self.assertEqual(55,runtime._acquire_gate_pidfd({'pid':12,'start':120},launch))
            rows[12]['ppid']=12
            with self.assertRaises(ValueError):runtime._acquire_gate_pidfd({'pid':12,'start':120},launch)
        evidence={'_gatePidfd':55,'_directoryFd':56,'gateIdentity':{'pid':12,'start':120}}
        def identity(pid):return root if pid==10 else {'pid':12,'start':120}
        with patch.object(runtime,'process_identity',side_effect=identity),patch.object(runtime,'_revalidate_scope'),patch.object(runtime.time,'monotonic',return_value=1),patch.object(runtime.signal,'pidfd_send_signal') as send:
            runtime._release_scope(evidence,launch,10);send.assert_called_once_with(55,runtime.signal.SIGUSR1,None,0)
            send.side_effect=OSError('authored send failure')
            with self.assertRaises(OSError):runtime._release_scope(evidence,launch,10)
            self.assertEqual(56,evidence['_directoryFd']);self.assertEqual(55,evidence['_gatePidfd'])
            send.reset_mock()
            with patch.object(runtime.time,'monotonic',return_value=10):
                with self.assertRaises(TimeoutError):runtime._release_scope(evidence,launch,10)
            send.assert_not_called()

    def test_controller_final_scope_observation_refuses_each_drift_before_send(self):
        wanted={'pids.max':'32','memory.max':'536870912','memory.swap.max':'0'}
        evidence={'_directoryFd':56,'_gatePidfd':57,'device':91,'inode':92,
                  'cgroup':'/sys/fs/cgroup/owned.scope','_membership':'0::/owned.scope',
                  'gateIdentity':{'pid':12,'start':120},'kernelLimits':wanted}
        root={'pid':10,'start':100};launch={'launcherIdentity':root}
        good=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_dev=91,st_ino=92)
        bad=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_dev=91,st_ino=99)
        for mutation in (None,'membership','held-inode','path-inode','limit'):
            values=dict(wanted)
            if mutation=='limit':values['memory.max']='999'
            descriptors={name:100+i for i,name in enumerate(wanted)}
            def opened(path,*a,**k):return descriptors[str(path)]
            def read(fd,n):return values[next(name for name,value in descriptors.items() if value==fd)].encode()
            member=b'0::/foreign.scope' if mutation=='membership' else b'0::/owned.scope'
            with patch.object(runtime,'process_identity',side_effect=lambda pid:root if pid==10 else {'pid':12,'start':120}),patch.object(runtime.time,'monotonic',return_value=1),patch.object(runtime.os,'fstat',return_value=bad if mutation=='held-inode' else good),patch.object(Path,'stat',return_value=bad if mutation=='path-inode' else good),patch.object(Path,'open',side_effect=lambda *a,**k:io.BytesIO(member)),patch.object(runtime.os,'open',side_effect=opened),patch.object(runtime.os,'read',side_effect=read),patch.object(runtime.os,'close'),patch.object(runtime.signal,'pidfd_send_signal') as send:
                if mutation is None:
                    runtime._release_scope(evidence,launch,10)
                    send.assert_called_once_with(57,runtime.signal.SIGUSR1,None,0)
                else:
                    with self.assertRaises(ValueError):runtime._release_scope(evidence,launch,10)
                    send.assert_not_called()

    def test_gate_holds_scope_before_hello_and_rechecks_scope_after_grant(self):
        gate=self.config_gate();bounds=build_contract.load_profile()['bounds']
        wanted={'pids.max':str(bounds['tasks']),'memory.max':str(bounds['memoryBytes']),
                'memory.swap.max':str(bounds['swapBytes'])}
        expected={'unit':'owned.scope','limits':wanted}
        good=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_dev=91,st_ino=92)
        bad=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_dev=91,st_ino=99)
        for mutation in (None,'pre-membership','membership','held-inode','path-inode','limit'):
            state={'membership':'0::/foreign.scope' if mutation=='pre-membership' else '0::/owned.scope',
                   'held':good,'path':good,'values':dict(wanted)}
            descriptors={name:100+i for i,name in enumerate(wanted)}
            def opened(path,*a,**k):return descriptors.get(str(path),11)
            def read(fd,n):return state['values'][next(name for name,value in descriptors.items() if value==fd)].encode()
            with patch.object(gate,'_scope_membership',side_effect=lambda:state['membership']),patch.object(gate.time,'monotonic',return_value=1),patch.object(Path,'resolve',lambda p,*a,**k:p),patch.object(Path,'stat',side_effect=lambda *a,**k:state['path']),patch.object(gate.os,'fstat',side_effect=lambda fd:state['held']),patch.object(gate.os,'open',side_effect=opened),patch.object(gate.os,'read',side_effect=read),patch.object(gate.os,'dup2') as duplicate,patch.object(gate.os,'close'):
                if mutation=='pre-membership':
                    with self.assertRaises(ValueError):gate._acquire_scope(expected,bounds,'owned.scope',10)
                    duplicate.assert_not_called();continue
                scope=gate._acquire_scope(expected,bounds,'owned.scope',10)
                self.assertEqual(7,scope['fd']);self.assertEqual((91,92),(scope['device'],scope['inode']))
                if mutation=='membership':state['membership']='0::/foreign.scope'
                elif mutation=='held-inode':state['held']=bad
                elif mutation=='path-inode':state['path']=bad
                elif mutation=='limit':state['values']['memory.max']='999'
                if mutation is None:gate._check_scope(scope,10)
                else:
                    with self.assertRaises(ValueError):gate._check_scope(scope,10)
                with patch.object(gate.time,'monotonic',return_value=10):
                    with self.assertRaises(TimeoutError):gate._check_scope(scope,10)

    def test_gate_opens_report_only_after_admission_and_explicitly_hands_fd4(self):
        gate=types.ModuleType('_pure_optimized_scope_gate')
        gate.__file__=str(SOURCE/'scope_gate.py')
        exec(compile((SOURCE/'scope_gate.py').read_bytes(),gate.__file__,'exec',optimize=2),gate.__dict__)
        directory=SOURCE/'exec-proof-receipts'/('a'*32)
        events=[]
        config={'schemaVersion':1,'directoryDevice':10,'directoryInode':11,'mode':'worker',
                'argv':['/usr/bin/bwrap','mock-only'],'report':{'device':20,'inode':21},
                'outerPidNsDevice':30,'outerPidNsInode':31,'scope':{'unit':'decomp-acp-efficacy-'+directory.name+'.scope','limits':{}}}
        dir_stat=types.SimpleNamespace(st_uid=os.getuid(),st_mode=stat.S_IFDIR|0o700,st_dev=10,st_ino=11)
        report_stat=types.SimpleNamespace(st_uid=os.getuid(),st_mode=stat.S_IFREG|0o600,st_dev=20,st_ino=21,st_size=0,st_nlink=1)
        def read_at(fd,name,maximum):
            events.append(('read',name))
            return json.dumps(config).encode() if name=='launch.json' else b'1\n'
        def opened(path,flags,*args,**kwargs):
            events.append(('open',str(path),flags));return 10 if path==directory else 11 if path=='worker-proof.jsonl' else 12
        def proc_text(path,*args,**kwargs):
            if str(path)=='/proc/self/status':return '\n'.join(key+': 00000000' for key in ('CapInh','CapPrm','CapEff','CapAmb'))
            return '12 (gate) S '+ ' '.join(['1']*19)+' 123 0'
        with ExitStack() as gate_effects:
            gate_effects.enter_context(patch.object(gate.sys,'argv',['scope_gate.py',str(directory),'--config-sha256','0'*64,'--controller','1','2','3','--phase-deadline','999999999999']))
            gate_effects.enter_context(patch.object(gate.sys,'flags',types.SimpleNamespace(isolated=True)))
            gate_effects.enter_context(patch.object(gate.sys,'dont_write_bytecode',True))
            gate_effects.enter_context(patch.object(gate.sys,'pycache_prefix',str(directory/'python-cache')))
            gate_effects.enter_context(patch.object(gate,'_contract',return_value=build_contract.load_profile()))
            gate_effects.enter_context(patch.object(gate,'_authenticated_config',return_value=config))
            gate_effects.enter_context(patch.object(gate,'_acquire_scope',return_value={'fd':7}))
            gate_effects.enter_context(patch.object(gate,'_check_scope',side_effect=lambda *a:events.append(('checked-held-scope',))))
            gate_effects.enter_context(patch.object(gate,'_wait_release',side_effect=lambda *a:events.append(('authenticated-release',))))
            gate_effects.enter_context(patch.object(gate.os,'open',side_effect=opened))
            gate_effects.enter_context(patch.object(gate.os,'fstat',side_effect=[dir_stat,report_stat]))
            gate_effects.enter_context(patch.object(gate.os,'close'))
            gate_effects.enter_context(patch.object(gate.os,'write',side_effect=lambda fd,raw:len(raw)))
            gate_effects.enter_context(patch.object(gate.os,'rename'))
            gate_effects.enter_context(patch.object(gate.os,'getpid',return_value=12))
            gate_effects.enter_context(patch.object(gate.resource,'getrlimit',return_value=(64,64)))
            gate_effects.enter_context(patch.object(Path,'read_text',proc_text))
            gate_effects.enter_context(patch.object(Path,'stat',return_value=types.SimpleNamespace(st_dev=30,st_ino=31)))
            duplicate = gate_effects.enter_context(patch.object(gate.os,'dup2'))
            inherit = gate_effects.enter_context(patch.object(gate.os,'set_inheritable'))
            close = gate_effects.enter_context(patch.object(gate,'_close_nonstandard'))
            execute = gate_effects.enter_context(patch.object(gate.os,'execv',side_effect=RuntimeError('mocked exec blocked')))
            self.assertEqual(config['argv'],gate._main('0'*64,(1,2,3),6,float('inf')))
            before_reports=sum(event[:2]==('open','worker-proof.jsonl') for event in events)
            with patch.object(gate.os,'fstat',return_value=dir_stat),patch.object(gate,'_check_scope',side_effect=ValueError('held scope drift after grant')):
                with self.assertRaisesRegex(ValueError,'scope drift'):gate._main('0'*64,(1,2,3),6,float('inf'))
            self.assertEqual(before_reports,sum(event[:2]==('open','worker-proof.jsonl') for event in events))
        report=next(i for i,event in enumerate(events) if event[:2]==('open','worker-proof.jsonl'))
        admitted=events.index(('authenticated-release',))
        self.assertGreater(report,admitted)
        checked=events.index(('checked-held-scope',))
        self.assertLess(admitted,checked);self.assertLess(checked,report)
        flags=events[report][2]
        self.assertTrue(flags & os.O_NOFOLLOW);self.assertTrue(flags & os.O_APPEND)
        duplicate.assert_called_once_with(11,4,inheritable=True);inherit.assert_called_once_with(4,True)
        close.assert_called_once_with({4,6,10,7});execute.assert_not_called()

    def test_optimized_admission_refuses_each_kernel_identity_limit_and_short_write(self):
        # Compile the actual function with assertions removed, without starting
        # another interpreter or reading proc/cgroup data. All effects mocked.
        tree=ast.parse((SOURCE/'bounded_runtime.py').read_text())
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_admit_scope')
        namespace=dict(runtime.__dict__)
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<optimized admission>','exec',optimize=2),namespace)
        admit=namespace['_admit_scope'];bounds=runtime.execution_bounds(managed_scope=True)
        wanted={'pids.max':str(bounds['cgroup']['tasks']),'memory.max':str(bounds['cgroup']['memoryBytes']),
                'memory.swap.max':str(bounds['cgroup']['swapBytes'])}
        metadata=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_dev=77,st_ino=88)
        unit='authored.scope';gate={'pid':12,'start':123};child={'pid':12,'start':123}
        launch={'unit':unit,'pins':{str(Path('/usr/bin/systemd-run')):{'sha256':'0'*64},
                                  str(runtime.BASE/'scope_gate.py'):{'sha256':'0'*64}}}
        cases=(None,'start','record','unit','pids.max','memory.max','memory.swap.max','acquired','membership','gate-pidfd')
        for mutation in cases:
            with self.subTest(mutation=mutation):
                values=dict(wanted)
                if mutation in values:values[mutation]='999'
                seen=0
                def text(path,*args,**kwargs):
                    nonlocal seen
                    if str(path)=='/proc/12/cgroup':
                        seen+=1
                        if mutation=='record':return '1:cpu:/authored.scope'
                        if mutation=='membership' and seen>1:return '0::/changed.scope'
                        return '0::/'+('changed.scope' if mutation=='unit' else unit)
                    return values[path.name]
                descriptors={'pids.max':91,'memory.max':92,'memory.swap.max':93}
                def opened(path,*args,**kwargs):return descriptors.get(str(path),90)
                def read(fd,n):
                    name=next(k for k,v in descriptors.items() if v==fd)
                    return ('999' if mutation=='acquired' and name=='memory.max' else values[name]).encode()
                with patch.dict(namespace,{'_read_private_json':lambda p,**kw:dict(gate),
                                           'process_identity':lambda pid:dict(child,start=999) if mutation=='start' else dict(child),
                                           '_acquire_gate_pidfd':Mock(side_effect=ValueError('gate acquisition') if mutation=='gate-pidfd' else None,return_value=89)}), \
                        patch.object(runtime.time,'monotonic',return_value=1),patch.object(Path,'resolve',lambda p,*a,**k:p), \
                        patch.object(Path,'read_text',text),patch.object(Path,'stat',return_value=metadata), \
                        patch.object(runtime.os,'open',side_effect=opened),patch.object(runtime.os,'fstat',return_value=metadata), \
                        patch.object(runtime.os,'read',side_effect=read),patch.object(runtime.os,'close'), \
                        patch.object(runtime.os,'write') as write, \
                        patch.object(runtime.os,'replace') as publish:
                    if mutation is None:
                        self.assertEqual(unit,admit({'directory':self.work},launch,bounds,10)['unit'])
                        write.assert_not_called();publish.assert_not_called()
                    else:
                        with self.assertRaises(ValueError):admit({'directory':self.work},launch,bounds,10)
                        publish.assert_not_called()

    def test_gate_policy_checks_survive_optimized_compilation(self):
        source=(SOURCE/'scope_gate.py').read_text()
        self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(ast.parse(source))))
        # Runtime directory and JSON containment are also unconditional.
        self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(ast.parse((SOURCE/'bounded_runtime.py').read_text()))))
        gate=types.ModuleType('_optimized_gate_refusals');gate.__file__=str(SOURCE/'scope_gate.py')
        exec(compile(source,gate.__file__,'exec',optimize=2),gate.__dict__)
        with patch.object(gate.sys,'argv',['gate']),patch.object(gate.os,'open') as opened:
            with self.assertRaises(ValueError):gate.main()
            opened.assert_not_called()
        valid=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=os.getuid(),st_nlink=1)
        bad=types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=os.getuid(),st_nlink=1)
        for metadata,payload in ((bad,b'1\n'),(valid,b'123')):
            with patch.object(gate.os,'open',return_value=40),patch.object(gate.os,'fstat',return_value=metadata), \
                    patch.object(gate.os,'read',return_value=payload),patch.object(gate.os,'close'):
                with self.assertRaises(ValueError):gate._read_at(39,'admit',2)
        with patch.object(gate.os,'scandir') as scan,patch.object(gate.os,'close') as closed:
            scan.return_value.__enter__.return_value=iter([types.SimpleNamespace(name='999')])
            with self.assertRaises(ValueError):gate._close_nonstandard(set())
            closed.assert_not_called()
        with patch.object(runtime,'BASE',self.directory):
            with self.assertRaises(ValueError):runtime.private_directory(self.directory.parent/'outside')
            with self.assertRaises(ValueError):runtime.write_json(self.directory.parent/'outside.json',{})

    def test_private_json_nonblocking_descriptor_admission_and_deadline_closure(self):
        cases=(None,'fifo','uid','mode','links','oversize','short','duplicate','malformed','permission','expired','late-open','late-read','late-close','close')
        for mutation in cases:
            with self.subTest(mutation=mutation):
                now=[10 if mutation=='expired' else 1]
                raw=b'{"pid":12,"start":123}'
                if mutation=='duplicate':raw=b'{"pid":12,"pid":13}'
                if mutation=='malformed':raw=b'{bad'
                metadata=types.SimpleNamespace(st_mode=(stat.S_IFIFO if mutation=='fifo' else stat.S_IFREG)|(0o644 if mutation=='mode' else 0o600),
                    st_uid=56 if mutation=='uid' else 55,st_nlink=2 if mutation=='links' else 1,
                    st_size=4097 if mutation=='oversize' else len(raw)+(mutation=='short'))
                def opened(*args,**kwargs):
                    if mutation=='permission':raise PermissionError('authored metadata denial')
                    if mutation=='late-open':now[0]=10
                    return 41
                def read(*args):
                    if mutation=='late-read':now[0]=10
                    return raw
                def close(*args):
                    if mutation=='late-close':now[0]=10
                    if mutation=='close':raise FileNotFoundError('authored close failure is not a missing gate')
                with patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(runtime.os,'getuid',return_value=55), \
                        patch.object(runtime.os,'open',side_effect=opened) as opening, \
                        patch.object(runtime.os,'fstat',return_value=metadata), \
                        patch.object(runtime.os,'read',side_effect=read) as reading, \
                        patch.object(runtime.os,'close',side_effect=close) as closing:
                    if mutation is None:
                        self.assertEqual({'pid':12,'start':123},runtime._read_private_json(self.work/'gate.json',deadline=10))
                    else:
                        with self.assertRaises((ValueError,OSError,RuntimeError)):
                            runtime._read_private_json(self.work/'gate.json',deadline=10)
                    if mutation=='expired':opening.assert_not_called()
                    else:
                        flags=opening.call_args.args[1]
                        for flag in (os.O_NONBLOCK,os.O_NOFOLLOW,os.O_CLOEXEC):self.assertTrue(flags&flag)
                    if mutation in ('fifo','uid','mode','links','oversize','permission','expired','late-open'):reading.assert_not_called()
                    if mutation in ('permission','expired'):closing.assert_not_called()
                    else:closing.assert_called_once_with(41)
                    if reading.called:reading.assert_called_once_with(41,4097)
        with patch.object(runtime.time,'monotonic',return_value=1),patch.object(runtime.os,'open') as opening:
            for maximum in (0,-1,4097,True):
                with self.assertRaises(ValueError):runtime._read_private_json(self.work/'gate.json',maximum,deadline=10)
            for deadline in (None,float('inf'),float('nan'),True):
                with self.assertRaises(ValueError):runtime._read_private_json(self.work/'gate.json',deadline=deadline)
            opening.assert_not_called()

    def test_scope_admission_uses_actual_missing_open_and_rejects_nonclosed_gate_shape(self):
        for gate in (None,[],{'pid':12,'start':123,'extra':1},{'pid':True,'start':123}):
            with self.subTest(gate=gate),patch.object(runtime.time,'monotonic',return_value=1), \
                    patch.object(Path,'exists',side_effect=AssertionError('no existence precheck')), \
                    patch.object(runtime,'_read_private_json',side_effect=FileNotFoundError() if gate is None else None,
                                 return_value=gate) as reading, \
                    patch.object(runtime,'process_identity',side_effect=AssertionError('invalid gate must not inspect processes')):
                if gate is None:self.assertIsNone(runtime._admit_scope({'directory':self.work},{},{},10))
                else:
                    with self.assertRaises(ValueError):runtime._admit_scope({'directory':self.work},{},{},10)
                reading.assert_called_once_with(self.work/'gate.json',deadline=10)

    def test_cleanup_stat_is_bounded_and_all_descriptor_failures_stay_unknown(self):
        fields=['S','1','12','12']+['0']*15+['123']
        valid=('12 (authored name) '+' '.join(fields)+'\n').encode()
        cases=(None,'gone','gone-read','permission','fifo','oversize','malformed','negative','late-open','late-read','close')
        for mutation in cases:
            with self.subTest(mutation=mutation):
                now=[1];raw=valid
                if mutation=='oversize':raw=b'x'*4097
                if mutation=='malformed':raw=b'12 (bad) S'
                if mutation=='negative':raw=valid.replace(b'12 12',b'-1 12',1)
                def opened(*args,**kwargs):
                    if mutation=='gone':raise FileNotFoundError()
                    if mutation=='permission':raise PermissionError('authored proc denial')
                    if mutation=='late-open':now[0]=10
                    return 41
                def read(*args):
                    if mutation=='gone-read':raise ProcessLookupError()
                    if mutation=='late-read':now[0]=10
                    return raw
                with patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(runtime.os,'open',side_effect=opened) as opening, \
                        patch.object(runtime.os,'fstat',return_value=types.SimpleNamespace(
                            st_mode=stat.S_IFIFO if mutation=='fifo' else stat.S_IFREG)), \
                        patch.object(runtime.os,'read',side_effect=read) as reading, \
                        patch.object(runtime.os,'close',side_effect=FileNotFoundError('authored close failure') if mutation=='close' else None) as closing:
                    if mutation is None:
                        self.assertEqual({'pid':12,'start':123,'pgid':12,'sid':12},runtime._cleanup_process_identity(12,10))
                    elif mutation in ('gone','gone-read'):self.assertIsNone(runtime._cleanup_process_identity(12,10))
                    else:
                        with self.assertRaises((ValueError,OSError)):runtime._cleanup_process_identity(12,10)
                    if mutation in ('gone','permission'):closing.assert_not_called()
                    else:closing.assert_called_once_with(41)
                    if mutation in ('gone','permission','fifo','late-open'):reading.assert_not_called()
                    if reading.called:reading.assert_called_once_with(41,4097)
                    self.assertEqual('/proc/12/stat',opening.call_args.args[0])
        with patch.object(runtime.time,'monotonic',return_value=10),patch.object(runtime.os,'open') as opening:
            with self.assertRaises(TimeoutError):runtime._cleanup_process_identity(12,10)
            opening.assert_not_called()

    def test_controller_census_stream_budget_deadline_and_unknown_are_not_absence(self):
        class Entries:
            def __init__(self,names,now,mutation):self.names=iter(names);self.now=now;self.mutation=mutation;self.advances=0;self.closed=False
            def __enter__(self):return self
            def __exit__(self,*args):
                self.closed=True
                if self.mutation=='late-close':self.now[0]=10
            def __next__(self):
                self.advances+=1
                if self.mutation=='permission':raise PermissionError('authored census denial')
                if self.mutation=='late-advance':self.now[0]=10
                return types.SimpleNamespace(name=next(self.names))
        self.assertEqual(256,runtime.CONTROLLER_PROC_SCAN_ENTRIES)
        self.assertEqual(4096,runtime.CONTROLLER_PROC_STAT_BYTES)
        for mutation in (None,'empty','budget','permission','bad-stat','late-advance','late-close','reused'):
            with self.subTest(mutation=mutation):
                now=[1];root={'pid':12,'start':123,'pgid':12,'sid':12}
                names=['self','net','12','99'] if mutation!='budget' else ['not-numeric']*256
                entries=Entries(names,now,mutation)
                def identity(pid,deadline):
                    self.assertEqual(10,deadline)
                    if pid==12:
                        if mutation=='empty':return None
                        return dict(root,start=999) if mutation=='reused' else root
                    if mutation=='bad-stat':raise ValueError('authored malformed stat')
                    return {'pid':pid,'start':9,'pgid':99,'sid':99}
                with patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(runtime.os,'scandir',return_value=entries) as scan, \
                        patch.object(runtime,'_cleanup_process_identity',side_effect=identity) as reading, \
                        patch.object(runtime,'process_identity',side_effect=AssertionError('no unbounded stat reader')), \
                        patch.object(runtime,'kill_exact',side_effect=AssertionError('census is never signal authority')) as killing:
                    if mutation in (None,'empty'):
                        self.assertEqual([] if mutation=='empty' else [root],runtime.owned_processes(12,123,10))
                    else:
                        with self.assertRaises((RuntimeError,ValueError,OSError)):runtime.owned_processes(12,123,10)
                    killing.assert_not_called()
                    if mutation=='reused':scan.assert_not_called()
                    else:
                        scan.assert_called_once_with('/proc');self.assertTrue(entries.closed)
                    if mutation=='budget':
                        self.assertEqual(256,entries.advances)
                        reading.assert_called_once_with(12,10)  # Every nonnumeric entry consumed budget.
                    if mutation=='late-advance':self.assertEqual(1,entries.advances)

    def receipt_fixture(self,*,close=True):
        # Authored protocol bytes only: actual parser/completion predicate, no
        # mocked native qualification and no real worker/process launch.
        from test_identity_graph import completed_result
        base=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=self.directory)))
        (base/'worker_exec_proof.py').write_bytes((SOURCE/'worker_exec_proof.py').read_bytes())
        with patch.object(runtime,'BASE',base):
            receipt=runtime._create_worker_receipt()
            self.addCleanup(lambda:os.close(receipt['fd']) if receipt['fd'] is not None else None)
            cache=runtime.private_directory(receipt['directory']/'python-cache');metadata=cache.lstat()
            receipt.update(cacheDevice=metadata.st_dev,cacheInode=metadata.st_ino)
            for name in ('launch.json','gate.json'):runtime.write_json(receipt['directory']/name,{})
            result=completed_result(stdout=b'preserved behavior',stderr=b'preserved diagnostics')
            expected=result['workerProofBindings']['expected']
            expected.update(attempt=receipt['directory'].name,reportDevice=receipt['device'],reportInode=receipt['inode'])
            rows=[json.loads(row) for row in result['workerProofRaw'].splitlines()]
            for row in rows:row['a']=receipt['directory'].name
            result['workerProofRaw']=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in rows)
            result['workerProof']['proofSha256']=hashlib.sha256(result['workerProofRaw']).hexdigest()
            os.write(receipt['fd'],result['workerProofRaw'])
            if close:os.close(receipt['fd']);receipt['fd']=None
            self.assertTrue(runtime.worker_execution_complete(result))
        return base,receipt,result

    def test_consumed_closed_receipt_is_reclaimed_without_losing_result_bytes(self):
        import copy
        base,receipt,result=self.receipt_fixture();before=copy.deepcopy(result)
        files={p.name:p.read_bytes() for p in receipt['directory'].iterdir() if p.is_file()}
        with patch.object(runtime,'BASE',base):facts=runtime._reclaim_worker_receipt(receipt,result)
        self.assertEqual('retained',facts['status']);self.assertTrue(receipt['directory'].is_dir())
        self.assertEqual('exclusive-deletion-authority-unavailable',facts['reason'])
        self.assertEqual([],facts['removedEntries'])
        self.assertEqual(files,{p.name:p.read_bytes() for p in receipt['directory'].iterdir() if p.is_file()})
        self.assertEqual(before,result);self.assertTrue((base/'exec-proof-receipts').is_dir())
        self.assertEqual(before['workerProofRaw'],result['workerProofRaw'])

    def test_fixed_provisioning_receipt_needs_complete_controller_without_worker_proof(self):
        for complete in (True,False):
            base,receipt,result=self.receipt_fixture();receipt['path'].unlink()
            result.update(provisioningOnly=True,workerProof=None,workerProofRaw=b'',workerProofBindings=None,
                          workerExecVerified=False,workerTerminationVerified=False,captureComplete=complete)
            with patch.object(runtime,'BASE',base):
                facts=runtime._reclaim_worker_receipt(receipt,result,provisioning=True)
            self.assertEqual('retained',facts['status'])
            self.assertTrue(receipt['directory'].is_dir())
            self.assertEqual('exclusive-deletion-authority-unavailable' if complete else
                             'receipt-not-fully-consumed',facts['reason'])
            self.assertFalse(result['workerExecVerified']);self.assertEqual(b'',result['workerProofRaw'])

    def test_unknown_absence_unconsumed_proof_or_open_report_retains_receipt(self):
        for mutation in ('cleanupVerified','rootReaped','finalAbsenceVerified','scope','proof','open'):
            with self.subTest(mutation=mutation):
                base,receipt,result=self.receipt_fixture(close=mutation!='open')
                if mutation in result:result[mutation]=False
                if mutation=='scope':result['kernelScope']['finalAbsenceVerified']=False
                if mutation=='proof':result['workerProofRaw']=b'unconsumed'
                with patch.object(runtime,'BASE',base),patch.object(runtime.os,'unlink',side_effect=AssertionError('must retain')):
                    facts=runtime._reclaim_worker_receipt(receipt,result)
                self.assertEqual('retained',facts['status']);self.assertTrue(receipt['directory'].is_dir())

    def test_receipt_replacements_links_and_unknown_payloads_refuse_before_deletion(self):
        for mutation in ('directory','symlink','report-symlink','report-change','cache-change','cache-payload','unknown'):
            with self.subTest(mutation=mutation):
                base,receipt,result=self.receipt_fixture();directory=receipt['directory']
                protected=base/'protected';protected.write_bytes(b'never remove this')
                if mutation in ('directory','symlink'):
                    original=directory.with_name(directory.name+'-retained');directory.rename(original)
                    if mutation=='directory':directory.mkdir(mode=0o700)
                    else:directory.symlink_to(original,target_is_directory=True)
                elif mutation=='report-symlink':receipt['path'].unlink();receipt['path'].symlink_to(protected)
                elif mutation=='report-change':receipt['path'].write_bytes(b'changed after consumption')
                elif mutation=='cache-change':
                    cache=directory/'python-cache';cache.rename(directory/'previous-cache');cache.mkdir(mode=0o700)
                elif mutation=='cache-payload':(directory/'python-cache/unknown.pyc').write_bytes(b'retain')
                else:(directory/'unexpected').write_bytes(b'retain')
                with patch.object(runtime,'BASE',base),patch.object(runtime.os,'unlink',side_effect=AssertionError('preflight must refuse')):
                    facts=runtime._reclaim_worker_receipt(receipt,result)
                self.assertEqual('refused',facts['status']);self.assertEqual(b'never remove this',protected.read_bytes())
                self.assertTrue(directory.exists());self.assertTrue(result['workerProofRaw'])

    def test_receipt_deletion_error_preserves_primary_proof_and_directory(self):
        base,receipt,result=self.receipt_fixture();raw=result['workerProofRaw']
        with patch.object(runtime,'BASE',base),patch.object(runtime.os,'unlink',side_effect=OSError('authored deletion error')) as unlink:
            facts=runtime._reclaim_worker_receipt(receipt,result)
        unlink.assert_not_called()
        self.assertEqual('retained',facts['status'])
        self.assertEqual('exclusive-deletion-authority-unavailable',facts['reason'])
        self.assertEqual([],facts['removedEntries'])
        self.assertTrue(receipt['directory'].exists());self.assertEqual(raw,result['workerProofRaw'])

    def test_receipt_final_unlink_substitution_boundary_is_unreachable(self):
        # Interpose exactly where the old check-then-unlink could delete a new
        # inode. Retention must never enter this boundary, even for valid proof.
        for name in ('launch.json','gate.json','worker-proof.jsonl'):
            with self.subTest(name=name):
                base,receipt,result=self.receipt_fixture()
                directory=receipt['directory'];original=(directory/name).read_bytes()
                real_unlink=os.unlink;replaced=[]
                def replace_then_unlink(child,*args,**kwargs):
                    if child==name:
                        (directory/name).rename(base/'admitted-entry')
                        (directory/name).write_bytes(b'foreign replacement canary')
                        replaced.append(name)
                    return real_unlink(child,*args,**kwargs)
                with patch.object(runtime,'BASE',base),patch.object(runtime.os,'unlink',side_effect=replace_then_unlink) as unlink:
                    facts=runtime._reclaim_worker_receipt(receipt,result)
                self.assertEqual([],replaced)
                unlink.assert_not_called()
                self.assertEqual('retained',facts['status'])
                self.assertEqual([],facts['removedEntries'])
                self.assertEqual(original,(directory/name).read_bytes())
                self.assertFalse((base/'admitted-entry').exists())

    def test_receipt_final_rmdir_substitution_boundaries_are_unreachable(self):
        for target in ('python-cache','attempt'):
            with self.subTest(target=target):
                base,receipt,result=self.receipt_fixture();directory=receipt['directory']
                name='python-cache' if target=='python-cache' else directory.name
                owned=directory/'python-cache' if target=='python-cache' else directory
                # Old rmdir would also remove an empty foreign replacement. A
                # retained descriptor does not make this namespace entry owned.
                real_rmdir=os.rmdir;replaced=[]
                def replace_then_rmdir(child,*args,**kwargs):
                    if child==name:
                        owned.rename(base/'admitted-directory')
                        owned.mkdir(mode=0o700)
                        replaced.append(name)
                    return real_rmdir(child,*args,**kwargs)
                with patch.object(runtime,'BASE',base),patch.object(runtime.os,'rmdir',side_effect=replace_then_rmdir) as rmdir:
                    facts=runtime._reclaim_worker_receipt(receipt,result)
                self.assertEqual([],replaced)
                rmdir.assert_not_called()
                self.assertEqual('retained',facts['status'])
                self.assertEqual([],facts['removedEntries'])
                self.assertTrue(owned.is_dir())
                self.assertTrue(receipt['path'].is_file())
                self.assertFalse((base/'admitted-directory').exists())

    def test_receipt_retention_closes_all_validation_descriptors(self):
        base,receipt,result=self.receipt_fixture();real_open=os.open;real_close=os.close
        opened=[];closed=[]
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):
            closed.append(fd);return real_close(fd)
        with patch.object(runtime,'BASE',base),patch.object(runtime.os,'open',side_effect=opening),patch.object(runtime.os,'close',side_effect=closing):
            facts=runtime._reclaim_worker_receipt(receipt,result)
        self.assertEqual('retained',facts['status'])
        self.assertCountEqual(opened,closed)
        self.assertGreaterEqual(len(opened),4)

    def test_runner_consumes_proof_and_closes_report_before_reclaim_with_failure_retention(self):
        # Actual runner/final-proof/reclaim functions, authored bytes and mocked
        # process/kernel interfaces. Never asks the OS to create a child or scope.
        for mutation in (None,'absence','report-close','delete','capture','prelaunch','release'):
            with self.subTest(mutation=mutation):
                base,receipt,authored=self.receipt_fixture(close=False)
                report_fd=receipt['fd'];events=[];real_close=os.close;real_read=os.read
                real_reclaim=runtime._reclaim_worker_receipt
                class Pipe:
                    def __init__(self,fd):self.fd=fd
                    def fileno(self):return self.fd
                    def write(self,value):pass
                    def close(self):pass
                process=types.SimpleNamespace(pid=123,stdin=Pipe(900),stdout=Pipe(901),stderr=Pipe(902),
                                              wait=Mock(return_value=0),returncode=0)
                class Selector:
                    def __init__(self):self.entries={}
                    def register(self,stream,event,label):self.entries[stream.fd]=types.SimpleNamespace(fileobj=stream,data=label)
                    def unregister(self,stream):self.entries.pop(stream.fd)
                    def get_map(self):return self.entries
                    def select(self,timeout):
                        if mutation=='capture':raise ValueError('original capture refusal')
                        return [(entry,1) for entry in list(self.entries.values())]
                    def close(self):pass
                pins=authored['launchInputPins']
                # The actual runner bounds must join this authored receipt's profile pin.
                bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
                pins[str(base/'contracts/candidate-build-profile.json')]['sha256']=bounds['profileSha256']
                authored['bounds']=bounds
                authored['workerProofBindings']['launchPinsSha256']=runtime._canonical_pin_digest(pins)
                launch={'argv':['authored never executed'],'unit':'authored.scope',
                        'expected':authored['workerProofBindings']['expected'],'pins':pins,
                        'proofBinding':authored['workerProofBindings'],
                        'configSha256':runtime.digest(receipt['directory']/'launch.json')}
                def closed(fd):
                    events.append(('close',fd))
                    if fd==report_fd and mutation=='report-close':raise OSError('authored report close refusal')
                    if fd not in (111,112,113):real_close(fd)
                def reclaim(*args,**kwargs):
                    self.assertIsNone(receipt['fd'])
                    self.assertIn(('close',report_fd),events)
                    self.assertTrue(args[1]['workerProofRaw'] or mutation=='prelaunch')
                    events.append(('reclaim',None))
                    if mutation=='delete':
                        return {'status':'refused','reason':'authored deletion failure','secondaryError':'OSError:authored'}
                    return real_reclaim(*args,**kwargs)
                def prepare(*args,**kwargs):
                    if mutation=='prelaunch':raise ValueError('original prelaunch refusal')
                    return launch
                scope={'_directoryFd':112,'_gatePidfd':113,'unit':'authored.scope'}
                with ExitStack() as effects:
                    for effect in (
                        patch.object(runtime,'BASE',base),patch.object(runtime,'_work_directory',return_value=self.work),
                        patch.object(runtime,'_worker_environment'),patch.object(runtime,'_create_worker_receipt',return_value=receipt),
                        patch.object(runtime,'_prepare_launch',side_effect=prepare),patch.object(runtime.subprocess,'Popen',return_value=process),
                        patch.object(runtime.os,'pidfd_open',return_value=111),patch.object(runtime,'process_identity',return_value={'start':1}),
                        patch.object(runtime.selectors,'DefaultSelector',side_effect=Selector),patch.object(runtime.os,'set_blocking'),
                        patch.object(runtime,'_admit_scope',return_value=scope),patch.object(runtime,'_release_scope',side_effect=OSError('original release') if mutation=='release' else None),patch.object(runtime,'_kill_owned_scope',side_effect=lambda acquired:events.append(('kill-acquired',acquired))),
                        patch.object(runtime,'_kill_launcher'),patch.object(runtime,'scope_processes',return_value=[]),
                        patch.object(runtime,'owned_processes',side_effect=ValueError('authored absence refusal') if mutation=='absence' else lambda *a:[]),
                        patch.object(runtime,'_pin_files',return_value=pins),patch.object(runtime.os,'close',side_effect=closed),
                        patch.object(runtime.os,'read',side_effect=lambda fd,n:b'' if fd in (901,902) else real_read(fd,n)),
                        patch.object(runtime,'_reclaim_worker_receipt',side_effect=reclaim if mutation not in ('report-close','absence','prelaunch') else real_reclaim)
                    ):effects.enter_context(effect)
                    try:
                        result=runtime._run_scoped(['authored'],self.work,self.env,b'',
                            bounds,provisioning=False)
                    except (ValueError,OSError) as error:
                        result=error.bounded_result
                        if mutation in ('capture','prelaunch','release'):
                            self.assertIn('original '+mutation,str(error))
                        elif mutation=='delete':
                            self.assertEqual('owned receipt directory reclamation failed',str(error))
                        elif mutation not in ('absence','report-close'):raise
                if mutation=='release':
                    self.assertIn(('kill-acquired',scope),events)
                    self.assertIn(('close',112),events);self.assertIn(('close',113),events)
                    self.assertTrue(result['cleanupVerified']);self.assertTrue(result['finalAbsenceVerified'])
                    self.assertTrue(result['kernelScope']['finalAbsenceVerified'])
                    self.assertTrue(result['scopeVerified']);self.assertFalse(result['scopeAdmitted'])
                    self.assertEqual('OSError',result['failureClass'])
                if mutation is None:
                    self.assertEqual('retained',result['_receiptCleanup']['status'])
                    self.assertEqual('receipt-not-fully-consumed',result['_receiptCleanup']['reason'])
                    self.assertEqual([],result['_receiptCleanup'].get('removedEntries',[]))
                    self.assertTrue(receipt['directory'].is_dir())
                    self.assertEqual('exclusive-proof-write-authority-unavailable',result['workerProof']['reason'])
                    with patch.object(runtime,'BASE',base):
                        self.assertFalse(runtime.worker_execution_complete(result))
                else:
                    self.assertTrue(receipt['directory'].exists());self.assertNotEqual('removed',result['_receiptCleanup']['status'])
                if mutation not in ('prelaunch','absence'):
                    self.assertEqual(authored['workerProofRaw'],result['workerProofRaw'])
                elif mutation=='absence':
                    self.assertEqual(b'',result['workerProofRaw'])
                    self.assertEqual(authored['workerProofRaw'],receipt['path'].read_bytes())
                if mutation=='delete':
                    self.assertTrue(result['cleanupVerified']);self.assertFalse(result['workerTerminationVerified'])
                    self.assertTrue(result['infrastructureFailure']);self.assertIn('secondaryError',result['_receiptCleanup'])
                self.assertNotIn('_receiptCleanup',runtime.public_result(result))


    def parser_lock(self, *, available=True, release=None):
        # No thread, wait, retry or scheduler. Test the actual loader's lock calls.
        return types.SimpleNamespace(acquire=Mock(return_value=available),release=Mock(side_effect=release))

    def test_authenticated_parser_executes_captured_bytes_and_reuses_private_success_only_handle(self):
        from test_identity_graph import completed_result
        value=completed_result();raw=value['workerProofRaw'];expected=value['workerProofBindings']['expected']
        base=self.directory/'parser-source';base.mkdir();path=base/'worker_exec_proof.py'
        original=(SOURCE/'worker_exec_proof.py').read_bytes();path.write_bytes(original)
        capture=runtime._capture_monitor_source;lock=self.parser_lock();captured=[]
        ambient=types.ModuleType('_v3_authenticated_worker_proof')
        def admitted(source,size,deadline):
            data=capture(source,size,deadline);captured.append((source,size,deadline))
            path.write_bytes(b'raise AssertionError("mutable parser must not execute")')
            return data
        with patch.object(runtime,'BASE',base),patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None), \
                patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock),patch.object(runtime.time,'monotonic',return_value=0), \
                patch.object(runtime,'_capture_monitor_source',side_effect=admitted), \
                patch.object(runtime,'_fixed_source_module',side_effect=AssertionError('no pathname parser loader')), \
                patch.dict(sys.modules,{'_v3_authenticated_worker_proof':ambient}):
            first=runtime._parse_worker_proof(raw,expected,deadline=10)
            selected=runtime._WORKER_PROOF_PARSER_CACHE
            path.write_bytes(original)  # Restore A only after captured A executed while the path held B.
            second=runtime._parse_worker_proof(raw,expected,deadline=10)
            self.assertEqual(first,second);self.assertEqual('verified',first['status'])
            self.assertIs(selected,runtime._WORKER_PROOF_PARSER_CACHE)
            self.assertEqual(runtime._WORKER_PROOF_PARSER_VERSION,selected[0]);self.assertTrue(callable(selected[1]))
            self.assertIs(ambient,sys.modules['_v3_authenticated_worker_proof'])
            self.assertIsNot(selected[1].__globals__,ambient.__dict__)
        self.assertEqual([(path,10003,10)],captured)
        lock.acquire.assert_called_once_with(False);lock.release.assert_called_once_with()

    def test_authenticated_parser_mismatch_capture_compile_exec_or_release_failure_publishes_nothing(self):
        raw=(SOURCE/'worker_exec_proof.py').read_bytes();real_compile=compile
        for stage in ('short','oversize','hash','capture','compile','exec','release'):
            with self.subTest(stage=stage):
                error=ValueError('authored '+stage);lock=self.parser_lock(release=error if stage=='release' else None)
                data=raw[:-1] if stage=='short' else raw+b'X' if stage=='oversize' else b'X'*len(raw) if stage=='hash' else raw
                with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None),patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock), \
                        patch.object(runtime,'_capture_monitor_source',side_effect=error if stage=='capture' else lambda *a:data), \
                        patch.object(runtime,'compile',create=True,side_effect=error if stage=='compile' else real_compile) as compiling, \
                        patch.object(runtime,'exec',create=True,side_effect=error if stage=='exec' else exec) as executing:
                    with self.assertRaises(ValueError) as caught:runtime._worker_proof_parser()
                    self.assertIsNone(runtime._WORKER_PROOF_PARSER_CACHE)
                    if stage not in ('short','oversize','hash'):self.assertIs(error,caught.exception)
                    if stage in ('short','oversize','hash','capture'):compiling.assert_not_called();executing.assert_not_called()
                lock.acquire.assert_called_once_with(False);lock.release.assert_called_once_with()
        # A separate request can initialize after a refusal; no failed handle is cached.
        lock=self.parser_lock()
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None),patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock), \
                patch.object(runtime,'_capture_monitor_source',side_effect=[b'bad',raw]):
            with self.assertRaises(ValueError):runtime._worker_proof_parser()
            self.assertTrue(callable(runtime._worker_proof_parser()))
            self.assertEqual(2,lock.acquire.call_count);self.assertEqual(2,lock.release.call_count)

    def test_authenticated_parser_busy_refuses_without_capture_or_release_and_rechecks_cache_after_acquire(self):
        lock=self.parser_lock(available=False)
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None),patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock), \
                patch.object(runtime,'_capture_monitor_source',side_effect=AssertionError('busy must not read')) as capture:
            with self.assertRaisesRegex(ValueError,'initialization is busy'):runtime._worker_proof_parser()
            self.assertIsNone(runtime._WORKER_PROOF_PARSER_CACHE)
        lock.acquire.assert_called_once_with(False);lock.release.assert_not_called();capture.assert_not_called()
        # Author an already initialized selected handle through the real loader first.
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None):
            selected=(runtime._WORKER_PROOF_PARSER_VERSION,runtime._worker_proof_parser())
        lock=self.parser_lock()
        def acquired(blocking):runtime._WORKER_PROOF_PARSER_CACHE=selected;return True
        lock.acquire.side_effect=acquired
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None),patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock), \
                patch.object(runtime,'_capture_monitor_source',side_effect=AssertionError('must recheck selected handle')):
            self.assertIs(selected[1],runtime._worker_proof_parser())
        lock.acquire.assert_called_once_with(False);lock.release.assert_called_once_with()

    def test_authenticated_parser_cold_and_warm_deadlines_keep_original_end(self):
        raw=(SOURCE/'worker_exec_proof.py').read_bytes();real_compile=compile;real_exec=exec;real_hash=hashlib.sha256
        for stage in ('before','capture','hash','compile','exec','release'):
            with self.subTest(stage=stage):
                now=[10.0 if stage=='before' else 0.0];lock=self.parser_lock(release=lambda:now.__setitem__(0,10.0) if stage=='release' else None)
                def captured(*args):
                    self.assertEqual(10,args[2])
                    if stage=='capture':now[0]=10.0
                    return raw
                def hashed(*args):
                    value=real_hash(*args)
                    if stage=='hash':now[0]=10.0
                    return value
                def compiling(*args):
                    value=real_compile(*args)
                    if stage=='compile':now[0]=10.0
                    return value
                def executing(*args):
                    real_exec(*args)
                    if stage=='exec':now[0]=10.0
                with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None),patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock), \
                        patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]),patch.object(runtime,'_capture_monitor_source',side_effect=captured), \
                        patch.object(runtime.hashlib,'sha256',side_effect=hashed),patch.object(runtime,'compile',create=True,side_effect=compiling), \
                        patch.object(runtime,'exec',create=True,side_effect=executing):
                    with self.assertRaises(TimeoutError):runtime._worker_proof_parser(10)
                    self.assertIsNone(runtime._WORKER_PROOF_PARSER_CACHE)
                self.assertEqual(0 if stage=='before' else 1,lock.acquire.call_count)
                self.assertEqual(0 if stage=='before' else 1,lock.release.call_count)
        # The post-release check passes, then the EXACT final cold admission
        # expires. Old001 retained its own new tuple at this point.
        released=[False];post_release_checks=[]
        lock=self.parser_lock(release=lambda:released.__setitem__(0,True))
        def last_admission_clock():
            if released[0]:
                value=0.0 if not post_release_checks else 10.0
                post_release_checks.append(value)
                return value
            return 0.0
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None),patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock), \
                patch.object(runtime.time,'monotonic',side_effect=last_admission_clock), \
                patch.object(runtime,'_capture_monitor_source',return_value=raw):
            with self.assertRaises(TimeoutError):runtime._worker_proof_parser(10)
            self.assertIsNone(runtime._WORKER_PROOF_PARSER_CACHE)
        self.assertEqual([0.0,10.0],post_release_checks)
        lock.acquire.assert_called_once_with(False);lock.release.assert_called_once_with()
        from test_identity_graph import completed_result
        value=completed_result();now=[0.0]
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None):
            parser=runtime._worker_proof_parser();selected=runtime._WORKER_PROOF_PARSER_CACHE
            def late(raw,expected):
                parsed=parser(raw,expected);now[0]=10.0;return parsed
            with patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]), \
                    patch.object(runtime,'_capture_monitor_source',side_effect=AssertionError('warm must not capture')):
                now[0]=10.0
                with self.assertRaises(TimeoutError):runtime._worker_proof_parser(10)
                self.assertIs(selected,runtime._WORKER_PROOF_PARSER_CACHE)
                now[0]=0.0;runtime._WORKER_PROOF_PARSER_CACHE=(runtime._WORKER_PROOF_PARSER_VERSION,late)
                with self.assertRaises(TimeoutError):runtime._parse_worker_proof(value['workerProofRaw'],value['workerProofBindings']['expected'],deadline=10)

    def test_authenticated_parser_wrapper_keeps_local_selected_callable_if_cache_reference_changes(self):
        from test_identity_graph import completed_result
        value=completed_result()
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None):
            parser=runtime._worker_proof_parser()
            def selected(raw,expected):
                runtime._WORKER_PROOF_PARSER_CACHE=None
                return parser(raw,expected)
            runtime._WORKER_PROOF_PARSER_CACHE=(runtime._WORKER_PROOF_PARSER_VERSION,selected)
            with patch.object(runtime,'_capture_monitor_source',side_effect=AssertionError('no cold/warm handle mixing')):
                parsed=runtime._parse_worker_proof(value['workerProofRaw'],value['workerProofBindings']['expected'])
            self.assertEqual('verified',parsed['status']);self.assertIsNone(runtime._WORKER_PROOF_PARSER_CACHE)

    def test_parser_binding_requires_independent_sha_and_canonical_row_even_after_forged_aggregate(self):
        import copy
        from test_identity_graph import completed_result
        good=completed_result();self.assertTrue(runtime._valid_worker_bindings(good))
        key=str(runtime.BASE/'worker_exec_proof.py')
        for mutation in ('missing','rekeyed','row','binding','both'):
            with self.subTest(mutation=mutation):
                value=copy.deepcopy(good);pins=value['launchInputPins'];bound=value['workerProofBindings']
                if mutation=='missing':pins.pop(key)
                if mutation=='rekeyed':pins['/authored/other-parser.py']=pins.pop(key)
                if mutation in ('row','both'):pins[key]['sha256']='f'*64
                if mutation in ('binding','both'):bound['parserSha256']='f'*64
                bound['launchPinsSha256']=runtime._canonical_pin_digest(pins)
                with patch.object(runtime,'_parse_worker_proof',side_effect=AssertionError('refuse before parser use')) as parsing, \
                        patch.object(runtime.os,'open',side_effect=AssertionError('bindings are data-only')):
                    self.assertFalse(runtime._valid_worker_bindings(value));self.assertFalse(runtime.worker_execution_complete(value))
                parsing.assert_not_called()

    def test_monitor_replay_requires_original_launch_pin_after_aggregate_resealing(self):
        import copy
        import evaluate_candidate_v3 as evaluator
        from test_identity_graph import completed_result
        for mutation in ('missing','rekeyed','decoy','device','inode','mode','sha256','claim','admission-sha'):
            with self.subTest(mutation=mutation):
                value=completed_result(stdout=b'partial behavior');pins=value['launchInputPins']
                binding=value['workerProofBindings'];name=binding['monitorExecutable']['path']
                if mutation=='missing':pins.pop(name)
                elif mutation=='rekeyed':pins[name+'-replacement']=pins.pop(name)
                elif mutation=='decoy':
                    row=pins.pop(name);pins['/authored/unrelated']={**row,'inode':row['inode']+1}
                elif mutation in ('device','inode','mode'):pins[name][mutation]+=1
                elif mutation=='sha256':pins[name]['sha256']='f'*64
                elif mutation=='claim':binding['monitorBinarySha256']='f'*64
                else:
                    binding['monitorExecutable']['sha256']='f'*64;pins[name]['sha256']='f'*64
                binding['launchPinsSha256']=runtime._canonical_pin_digest(pins)
                original=copy.deepcopy(value)
                with patch.object(runtime,'_parse_worker_proof',side_effect=AssertionError('monitor admission before parser')) as parsing, \
                        patch.object(runtime.os,'open',side_effect=AssertionError('replay never opens a serialized coordinate')):
                    self.assertFalse(runtime._valid_worker_bindings(value))
                    self.assertFalse(runtime.worker_execution_complete(value));self.assertFalse(evaluator._proof_replays(value))
                    observation=evaluator.process_observation(value)
                parsing.assert_not_called();self.assertEqual(original,value)
                self.assertFalse(observation['completed']);self.assertEqual(b'partial behavior'.hex(),observation['stdoutHex'])

    def test_monitor_replay_rejects_malformed_or_aliased_admission_before_parser_use(self):
        import evaluate_candidate_v3 as evaluator
        from test_identity_graph import completed_result
        cases=[('absent',None,None),('null',None,None),('missing','inode',None),('extra','extra',True),
               ('path','path','relative'),('path','path','/'),('path','path','//authored/monitor'),
               ('path','path','/authored/../monitor'),('path','path','/authored/./monitor'),
               ('path','path','/authored/monitor\0'),('path','path','/'+('x'*4096)),
               ('path','path','/\ud800'),('boolean-device','device',True),('negative-inode','inode',-1),
               ('oversized-inode','inode',1<<64),('boolean-mode','mode',True),('nonexec','mode',0o400),
               ('setuid','mode',0o4500),('setgid','mode',0o2500),('bad-sha','sha256','x'*64)]
        cases += [(role,None,None) for role in ('target','reaper','report')]
        for label,field,new in cases:
            with self.subTest(case=label,value=new):
                value=completed_result();binding=value['workerProofBindings'];monitor=binding['monitorExecutable']
                old_name=monitor['path'];pins=value['launchInputPins']
                if label=='absent':del binding['monitorExecutable']
                elif label=='null':binding['monitorExecutable']=None
                elif label=='missing':del monitor[field]
                elif label in ('target','reaper','report'):
                    expected=binding['expected'];monitor.update(device=expected[label+'Device'],inode=expected[label+'Inode'])
                    pins[old_name]={k:monitor[k] for k in ('device','inode','mode','sha256')}
                else:
                    monitor[field]=new
                    if label=='path':pins[new]=pins.pop(old_name)
                    elif field in pins[old_name]:pins[old_name][field]=new
                binding['launchPinsSha256']=runtime._canonical_pin_digest(pins)
                with patch.object(runtime,'_parse_worker_proof',side_effect=AssertionError('malformed monitor before parser')) as parsing, \
                        patch.object(runtime.os,'open',side_effect=AssertionError('data-only replay')):
                    self.assertFalse(runtime.worker_execution_complete(value));self.assertFalse(evaluator._proof_replays(value))
                parsing.assert_not_called()

    def test_actual_finish_completion_and_evaluator_share_authenticated_parser_under_path_replacement(self):
        import evaluate_candidate_v3 as evaluator
        lock=self.parser_lock()
        with patch.object(runtime,'_WORKER_PROOF_PARSER_CACHE',None),patch.object(runtime,'_WORKER_PROOF_PARSER_LOCK',lock):
            base,receipt,result=self.receipt_fixture(close=False)
            launch={'expected':result['workerProofBindings']['expected'],'pins':result['launchInputPins'],
                    'configSha256':runtime.digest(receipt['directory']/'launch.json')}
            # Isolate executable-byte selection from separate ordinary filesystem pin drift.
            (base/'worker_exec_proof.py').write_bytes(b'raise AssertionError("not the selected parser")')
            with patch.object(runtime,'BASE',base),patch.object(runtime.time,'monotonic',return_value=0), \
                    patch.object(runtime,'_pin_files',return_value=launch['pins']), \
                    patch.object(runtime,'_fixed_source_module',side_effect=AssertionError('path loader forbidden')):
                runtime._finish_worker_proof(result,receipt,launch,{'workerLimits':{'workerProofBytes':1024}},deadline=10)
                self.assertEqual('unknown',result['workerProof']['status']);self.assertIsNone(result['exitCode'])
                self.assertEqual('exclusive-proof-write-authority-unavailable',result['workerProof']['reason'])
                self.assertFalse(runtime.worker_execution_complete(result))
                self.assertFalse(evaluator._proof_replays(result));self.assertFalse(evaluator.process_observation(result)['completed'])
            lock.acquire.assert_called_once_with(False);lock.release.assert_called_once_with()

    def test_same_inode_terminal_rewrite_cannot_confer_completion(self):
        import evaluate_candidate_v3 as evaluator
        for exit_code in (0, 7, -9):
            with self.subTest(exit_code=exit_code):
                base,receipt,result=self.receipt_fixture(close=False)
                rows=[json.loads(row) for row in result['workerProofRaw'].splitlines()]
                rows[-1].update(r=exit_code<<8 if exit_code>=0 else -exit_code,
                                k='exit' if exit_code>=0 else 'signal',n=abs(exit_code))
                original=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in rows)
                receipt['path'].write_bytes(original)
                before=receipt['path'].stat()
                # A host peer forges canonical zero-exit bytes after production,
                # preserving the owned inode, mode and link count. Stable reads
                # cannot distinguish this from a genuine producer record.
                forged=result['workerProofRaw']
                with receipt['path'].open('r+b') as writer:
                    writer.write(forged);writer.truncate()
                after=receipt['path'].stat()
                for name in ('st_dev','st_ino','st_mode','st_uid','st_nlink'):
                    self.assertEqual(getattr(before,name),getattr(after,name))
                launch={'expected':result['workerProofBindings']['expected'],'pins':result['launchInputPins'],
                        'configSha256':runtime.digest(receipt['directory']/'launch.json')}
                with patch.object(runtime,'BASE',base),patch.object(runtime.time,'monotonic',return_value=0), \
                        patch.object(runtime,'_pin_files',return_value=launch['pins']):
                    runtime._finish_worker_proof(result,receipt,launch,{'workerLimits':{'workerProofBytes':1024}},deadline=10)
                    self.assertFalse(runtime.worker_execution_complete(result))
                    self.assertFalse(evaluator._proof_replays(runtime.public_result(result)))
                    self.assertFalse(evaluator.process_observation(result)['completed'])
                self.assertEqual(forged,result['workerProofRaw'])
                self.assertEqual(hashlib.sha256(forged).hexdigest(),result['workerProof']['proofSha256'])
                self.assertTrue(result['workerProof']['fileIdentityVerified'])
                self.assertTrue(result['workerProof']['pinsUnchanged'])
                self.assertEqual('unknown',result['workerProof']['status'])
                self.assertEqual('exclusive-proof-write-authority-unavailable',result['workerProof']['reason'])
                self.assertTrue(result['infrastructureFailure']);self.assertIsNone(result['exitCode'])
                self.assertFalse(result['workerExecVerified']);self.assertFalse(result['workerTerminationVerified'])
                self.assertIsNone(result['workerTermination'])
                self.assertEqual(b'preserved behavior',result['stdout'])

    def test_unprepared_finish_clears_stale_completion_claims(self):
        from test_identity_graph import completed_result
        result=completed_result()
        runtime._finish_worker_proof(result,None,None,{})
        self.assertIsNone(result['exitCode']);self.assertIsNone(result['workerTermination'])
        self.assertFalse(result['workerExecVerified']);self.assertFalse(result['workerTerminationVerified'])
        self.assertEqual('launch-not-prepared',result['workerProof']['reason'])
        self.assertFalse(runtime.worker_execution_complete(result))

    def test_evaluator_preserves_strict_hex_subclass_raw_type_ambiguity_and_terminal_replays(self):
        import copy
        import evaluate_candidate_v3 as evaluator
        from test_identity_graph import completed_result
        class Hex(str):pass
        class Raw(bytes):pass
        good=completed_result();self.assertTrue(evaluator._proof_replays(good))
        public=runtime.public_result(good);public['workerProofRawHex']=Hex(public['workerProofRawHex'])
        self.assertTrue(runtime.worker_execution_complete(public));self.assertFalse(evaluator._proof_replays(public))
        for mutation in ('bytes-subclass','ambiguous','overbound','exit','termination','sha','partial'):
            with self.subTest(mutation=mutation):
                value=copy.deepcopy(good)
                if mutation=='bytes-subclass':value['workerProofRaw']=Raw(value['workerProofRaw'])
                if mutation=='ambiguous':value['workerProofRawHex']=value['workerProofRaw'].hex()
                if mutation=='overbound':value['workerProofRaw']=b'x'*1025
                if mutation=='exit':value['exitCode']=1
                if mutation=='termination':value['workerTermination']={'kind':'exit','value':1,'rawWaitStatus':256}
                if mutation=='sha':value['workerProof']['proofSha256']='f'*64
                if mutation=='partial':
                    value['workerProofRaw']=value['workerProofRaw'].splitlines(keepends=True)[0]
                    value['workerProof']['proofSha256']=hashlib.sha256(value['workerProofRaw']).hexdigest()
                self.assertFalse(evaluator._proof_replays(value))
        self.assertEqual(1024,runtime._WORKER_PROOF_MAX_BYTES)
        parsed=runtime._parse_worker_proof(b'x'*1025,good['workerProofBindings']['expected'])
        self.assertFalse(parsed['workerExecVerified']);self.assertFalse(parsed['workerTerminationVerified'])
        for exit_code in (42,-11):self.assertTrue(evaluator._proof_replays(completed_result(exit_code=exit_code)))

    def test_actual_qualifier_partial_consumer_uses_shared_parser_without_completion_authority(self):
        import test_worker_exec_proof as fixtures
        spec=importlib.util.spec_from_file_location('_authored_parser_qualifier',SOURCE/'tests/qualify_worker_exec.py')
        qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualifier)
        value=fixtures.fault_receipt('kill-monitor')
        real_parse=runtime._parse_worker_proof;deadlines=[]
        def parsing(raw,expected,*,deadline=None):deadlines.append(deadline);return real_parse(raw,expected,deadline=deadline)
        with patch.object(runtime,'_parse_worker_proof',side_effect=parsing), \
                patch.object(runtime,'_fixed_source_module',side_effect=AssertionError('no path parser')):
            parsed=qualifier._initial_exec(value)
        self.assertTrue(parsed['workerExecVerified']);self.assertFalse(parsed['workerTerminationVerified'])
        self.assertFalse(runtime.worker_execution_complete(value));self.assertEqual([None],deadlines)

    def test_actual_prepare_preserves_expected_identity_dict_after_all_trusted_source_pins(self):
        profile,profile_sha=build_contract.load_profile_with_digest();bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
        target=Path('/authored/target');monitor=Path('/authored/monitor')
        recipe={'target':target,'worker':['/target'],'prefix':[],'mounts':[]}
        binding={'binaryPath':str(monitor),'dependencies':[],**{name:'a'*64 for name in
            ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','manifestSha256')}}
        binding['parserSha256']=runtime._WORKER_PROOF_PARSER_SHA256
        pins={str(runtime.BASE/'contracts/candidate-build-profile.json'):{'device':70,'inode':71,'mode':0o400,'sha256':profile_sha},
              str(runtime.BASE/'worker_exec_proof.py'):{'device':70,'inode':80,'mode':0o400,'sha256':runtime._WORKER_PROOF_PARSER_SHA256}}
        pins.update({str(runtime.BASE/name):{'device':70,'inode':81+i,'mode':0o400,'sha256':sha}
            for i,(name,_,sha) in enumerate(runtime._MONITOR_LOADER_SOURCES)})
        receipt={'directory':Path('/authored')/('a'*32),'directoryDevice':1,'directoryInode':2,'device':1,'inode':3}
        def executable(path,deadline=None):
            dev,ino=(3,4) if str(path)=='/usr/bin/bwrap' else (11,12) if path==monitor else (7,8)
            return {'path':str(path),'device':dev,'inode':ino,'mode':0o500,'sha256':'a'*64}
        pins[str(monitor)]={key:value for key,value in executable(monitor).items() if key!='path'}
        with patch.object(Path,'stat',return_value=types.SimpleNamespace(st_dev=5,st_ino=6)), \
                patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_dev=1,st_ino=2)), \
                patch.object(runtime.time,'monotonic',return_value=0),patch.object(runtime,'_contained_recipe',return_value=recipe), \
                patch.object(runtime,'load_worker_monitor_binding',return_value=binding), \
                patch.object(runtime,'_recorded_compiler_inputs',return_value=None),patch.object(runtime,'_nonprivileged_executable',side_effect=executable), \
                patch.object(runtime,'_pin_files',return_value=pins),patch.object(runtime,'_publish_config') as published, \
                patch.object(runtime,'private_directory',side_effect=lambda path:path),patch.object(runtime,'process_identity',return_value={'start':1}), \
                patch.object(runtime.os,'getpid',return_value=123),patch.object(runtime.os,'getuid',return_value=55), \
                patch.object(runtime,'load_profile_with_digest',return_value=(profile,profile_sha)), \
                patch.object(runtime.os,'open',side_effect=AssertionError('authored preparation never launches or opens tools')):
            launch=runtime._prepare_launch(['/authored'],self.work,bounds,receipt,False,deadline=10)
        self.assertIs(type(launch['expected']),dict)
        self.assertEqual('a'*32,launch['expected']['attempt'])
        self.assertEqual((7,8),(launch['expected']['targetDevice'],launch['expected']['targetInode']))
        self.assertIs(launch['expected'],launch['proofBinding']['expected'])
        published.assert_called_once()

    def _monitor_launch_control(self):
        # Real bounded pin reads of authored inert bytes; host admission, metadata
        # and publication are controlled. No executable or worker is launched.
        profile,profile_sha=build_contract.load_profile_with_digest()
        bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
        self.monitor_control_count=getattr(self,'monitor_control_count',0)+1
        monitor=self.directory/('monitor-control-'+str(self.monitor_control_count))
        monitor.write_bytes(b'authored trusted monitor');monitor.chmod(0o500)
        real_pin=runtime._pin_files
        trusted=real_pin([monitor])[str(monitor)]
        binding={'binaryPath':str(monitor),'dependencies':[],**{name:'a'*64 for name in
            ('environmentPinSha256','sourceSha256','protocolSha256','manifestSha256')}}
        binding.update(binarySha256=trusted['sha256'],parserSha256=runtime._WORKER_PROOF_PARSER_SHA256)
        receipt={'directory':Path('/authored')/('a'*32),'directoryDevice':1,'directoryInode':2,'device':1,'inode':3}
        recipe={'target':Path('/authored/target'),'worker':['/target'],'prefix':[],'mounts':[]}
        case=types.SimpleNamespace(monitor=monitor,trusted=trusted,binding=binding,events=[],published=Mock(),
            before_admission=lambda:None,before_pin=lambda:None,change_pins=lambda pins:None)
        def load(deadline=None):
            case.events.append(('binding',deadline));case.before_admission();return binding
        def executable(path,deadline=None):
            if path==monitor:
                case.events.append(('monitor-admission',deadline))
                case.admitted=real_pin([monitor],deadline)[str(monitor)]
                return {'path':str(monitor),**case.admitted}
            return {'path':str(path),'device':7,'inode':8,'mode':0o500,'sha256':'a'*64}
        def launch_pins(paths,deadline=None):
            self.assertIn(monitor,paths);case.events.append(('launch-pins',deadline));case.before_pin()
            pins={str(runtime.BASE/'contracts/candidate-build-profile.json'):{'sha256':profile_sha},
                  str(runtime.BASE/'worker_exec_proof.py'):{'sha256':runtime._WORKER_PROOF_PARSER_SHA256}}
            pins.update({str(runtime.BASE/name):{'sha256':sha} for name,_,sha in runtime._MONITOR_LOADER_SOURCES})
            case.retained=real_pin([monitor],deadline)[str(monitor)]
            pins[str(monitor)]=dict(case.retained);case.change_pins(pins);return pins
        real_stat,real_lstat=Path.stat,Path.lstat
        def metadata(path,*args,**kwargs):
            if str(path)=='/proc/self/ns/pid':return types.SimpleNamespace(st_dev=5,st_ino=6)
            return real_stat(path,*args,**kwargs)
        def lmetadata(path,*args,**kwargs):
            if path==receipt['directory']/'python-cache':return types.SimpleNamespace(st_dev=1,st_ino=2)
            return real_lstat(path,*args,**kwargs)
        def invoke():
            with patch.object(Path,'stat',metadata),patch.object(Path,'lstat',lmetadata), \
                    patch.object(runtime.time,'monotonic',return_value=0), \
                    patch.object(runtime,'_contained_recipe',return_value=recipe), \
                    patch.object(runtime,'load_worker_monitor_binding',side_effect=load), \
                    patch.object(runtime,'_nonprivileged_executable',side_effect=executable), \
                    patch.object(runtime,'_recorded_compiler_inputs',return_value=None), \
                    patch.object(runtime,'_pin_files',side_effect=launch_pins), \
                    patch.object(runtime,'_publish_config',case.published), \
                    patch.object(runtime,'private_directory',side_effect=lambda path:path), \
                    patch.object(runtime,'process_identity',return_value={'start':1}):
                return runtime._prepare_launch(['/authored'],self.work,bounds,receipt,False,deadline=10.0)
        def replace():
            replacement=self.directory/'monitor-replacement'
            replacement.write_bytes(b'authored stable replacement');replacement.chmod(0o500);replacement.replace(monitor)
        case.invoke=invoke;case.replace=replace
        return case

    def test_prepare_refuses_monitor_replacement_after_binding_before_executable_admission(self):
        case=self._monitor_launch_control();case.before_admission=case.replace
        with self.assertRaisesRegex(ValueError,'monitor executable differs from validated binding'):case.invoke()
        self.assertNotEqual(case.trusted['sha256'],case.admitted['sha256'])
        self.assertEqual([('binding',10.0),('monitor-admission',10.0)],case.events)
        case.published.assert_not_called()

    def test_prepare_refuses_monitor_replacement_after_admission_before_launch_pin(self):
        case=self._monitor_launch_control();case.before_pin=case.replace
        with self.assertRaisesRegex(ValueError,'monitor launch pin differs from validated executable'):case.invoke()
        self.assertEqual(case.trusted,case.admitted)
        self.assertNotEqual(case.admitted['sha256'],case.retained['sha256'])
        self.assertNotEqual(case.admitted['inode'],case.retained['inode'])
        self.assertEqual([('binding',10.0),('monitor-admission',10.0),('launch-pins',10.0)],case.events)
        case.published.assert_not_called()

    def test_prepare_refuses_missing_rekeyed_or_drifted_monitor_launch_pin(self):
        for mutation in ('missing','rekeyed','sha256','device','inode','mode'):
            with self.subTest(mutation=mutation):
                case=self._monitor_launch_control()
                def change(pins):
                    key=str(case.monitor)
                    if mutation=='missing':pins.pop(key)
                    elif mutation=='rekeyed':pins[key+'-other']=pins.pop(key)
                    elif mutation=='sha256':pins[key][mutation]='f'*64
                    else:pins[key][mutation]+=1
                case.change_pins=change
                with self.assertRaisesRegex(ValueError,'monitor launch pin differs from validated executable'):case.invoke()
                self.assertEqual(case.trusted,case.admitted);self.assertEqual(case.admitted,case.retained)
                case.published.assert_not_called()

    def test_prepare_preserves_trusted_monitor_digest_and_original_admission(self):
        case=self._monitor_launch_control();launch=case.invoke()
        self.assertEqual(case.trusted,launch['pins'][str(case.monitor)])
        self.assertEqual({'path':str(case.monitor),**case.trusted},launch['proofBinding']['monitorExecutable'])
        self.assertEqual(case.binding['binarySha256'],launch['proofBinding']['monitorBinarySha256'])
        self.assertEqual(case.trusted,case.admitted);self.assertEqual(case.admitted,case.retained)
        case.published.assert_called_once()
        self.assertEqual(case.published.call_args.args[0].name,'launch.json')
        command=launch['command'];at=command.index('/_worker_exec_monitor')
        self.assertEqual(['--ro-bind',str(case.monitor),'/_worker_exec_monitor'],command[at-2:at+1])

    def test_actual_monitor_admission_survives_public_record_and_evaluator_replay(self):
        import copy
        import evaluate_candidate_v3 as evaluator
        from test_identity_graph import completed_result
        case=self._monitor_launch_control();launch=case.invoke()
        admitted=launch['proofBinding']['monitorExecutable']
        self.assertEqual({'path':str(case.monitor),**case.admitted},admitted)
        # Exercise the actual monitor admission/public replay bridge. Other proof
        # roles and raw bytes are independently authored, never a launched worker.
        for code in (0,7,-11):
            value=completed_result(exit_code=code);binding=value['workerProofBindings'];pins=value['launchInputPins']
            pins.pop(binding['monitorExecutable']['path']);pins[admitted['path']]=dict(launch['pins'][admitted['path']])
            binding.update(monitorExecutable=copy.deepcopy(admitted),monitorBinarySha256=admitted['sha256'],
                           launchPinsSha256=runtime._canonical_pin_digest(pins))
            self.assertTrue(runtime.worker_execution_complete(value));public=runtime.public_result(value)
            runtime._worker_proof_parser()  # authenticate the parser before denying any further payload opens
            with patch.object(runtime.os,'open',side_effect=AssertionError('replay must not reopen the monitor')):
                self.assertTrue(runtime.worker_execution_complete(public));self.assertTrue(evaluator._proof_replays(public))
            self.assertEqual(admitted,public['workerProofBindings']['monitorExecutable'])

    def test_prepare_launch_refuses_untrusted_monitor_or_canonical_parser_row_before_publication(self):
        profile,sha=build_contract.load_profile_with_digest();bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
        recipe={'target':Path('/authored/target'),'worker':['/target'],'prefix':[],'mounts':[]}
        receipt={'directory':Path('/authored')/('a'*32),'directoryDevice':1,'directoryInode':2,'device':1,'inode':3}
        for mutation in ('binding','missing','rekeyed','row','both'):
            with self.subTest(mutation=mutation):
                binding={'binaryPath':'/authored/monitor','binarySha256':'a'*64,'dependencies':[],'parserSha256':runtime._WORKER_PROOF_PARSER_SHA256}
                pins={str(runtime.BASE/'contracts/candidate-build-profile.json'):{'sha256':sha}}
                pins['/authored/monitor']={'device':1,'inode':2,'mode':0o500,'sha256':'a'*64}
                pins.update({str(runtime.BASE/name):{'sha256':digest} for name,_,digest in runtime._MONITOR_LOADER_SOURCES})
                key=str(runtime.BASE/'worker_exec_proof.py');pins[key]={'sha256':runtime._WORKER_PROOF_PARSER_SHA256}
                if mutation in ('binding','both'):binding['parserSha256']='f'*64
                if mutation=='missing':pins.pop(key)
                if mutation=='rekeyed':pins['/authored/other-parser.py']=pins.pop(key)
                if mutation in ('row','both'):pins[key]['sha256']='f'*64
                with patch.object(Path,'stat',return_value=types.SimpleNamespace(st_dev=1,st_ino=2)), \
                        patch.object(runtime.time,'monotonic',return_value=0),patch.object(runtime,'_contained_recipe',return_value=recipe), \
                        patch.object(runtime,'load_worker_monitor_binding',return_value=binding), \
                        patch.object(runtime,'_recorded_compiler_inputs',return_value=None), \
                        patch.object(runtime,'_nonprivileged_executable',side_effect=lambda p,deadline=None:{'path':str(p),'device':1,'inode':2,'mode':0o500,'sha256':'a'*64}), \
                        patch.object(runtime,'_pin_files',return_value=pins),patch.object(runtime,'_publish_config') as published:
                    with self.assertRaisesRegex(ValueError,'worker proof parser launch binding differs'):
                        runtime._prepare_launch(['/authored'],self.work,bounds,receipt,False,deadline=10)
                published.assert_not_called()

    def test_actual_surrogate_proof_stage_uses_existing_cleanup_end_and_failed_cleanup_cannot_pass(self):
        # Existing definition-only qualifier seam, selecting the ACTUAL proof/final
        # blocks. All process/descriptor effects are inert; no surrogate is run.
        from test_identity_graph import completed_result
        tree=ast.parse((SOURCE/'tests/qualify_worker_exec.py').read_bytes())
        surrogate=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='surrogate')
        proof_stage=next(n for n in surrogate.body if isinstance(n,ast.Try) and any(isinstance(x,ast.For) for x in n.finalbody))
        final=next(n for n in surrogate.body if isinstance(n,ast.If) and isinstance(n.test,ast.Name) and n.test.id=='cleanup')
        result_node=next(n for n in surrogate.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='value' for x in n.targets))
        code=compile(ast.fix_missing_locations(ast.Module(body=[proof_stage,final,result_node],type_ignores=[])),
                     '<actual-surrogate-proof-parser-stage>','exec')
        raw=completed_result()['workerProofRaw'];real_parse=runtime._parse_worker_proof
        for cleanup,late in ((True,False),(False,False),(True,True)):
            with self.subTest(cleanup=cleanup,late=late):
                now=[0.0];deadlines=[];closed=[]
                def parsing(data,expected,*,deadline=None):
                    deadlines.append(deadline);parsed=real_parse(data,expected,deadline=deadline)
                    if late:now[0]=10.0
                    return parsed
                metadata=types.SimpleNamespace(st_dev=1,st_ino=2,st_size=len(raw),st_mode=stat.S_IFREG|0o600,st_nlink=1)
                worker=Path('/authored/worker');harness=Path('/authored/harness')
                namespace={'_parse_worker_proof':parsing,'os':types.SimpleNamespace(lseek=lambda *a:None,SEEK_SET=0,
                    read=lambda fd,count:raw,fstat=lambda fd:metadata,close=lambda fd:closed.append(fd)),
                    'time':types.SimpleNamespace(monotonic=lambda:now[0]),'stat':stat,
                    '_json':lambda *a:{'pidns':[5,6]},'_devino':lambda p:[7,8] if p==worker else [3,4],
                    'directory':self.directory,'report':4,'report_id':[1,2],'scope':{'directoryFd':41},
                    'worker':worker,'harness':harness,'mode':'release','attempt':'a'*32,
                    'cleanup':cleanup,'cleanup_failure':None,'cleanup_wait_end':5,'cleanup_verification_end':10,
                    'failure':None,'launcher_exit':0,'samples':[{'ack':'H'},{'ack':'HA'}],'actions':['A','B'],
                    'admitted':True,'capture':True,'streams':{'stdout':bytearray(b'DESCENDANT-CHANNEL-DENIED\n'),'stderr':bytearray()}}
                with patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(runtime,'_fixed_source_module',side_effect=AssertionError('no path parser')):
                    exec(code,namespace)
                self.assertEqual([10 if cleanup else None],deadlines)
                self.assertEqual([4,41],closed)
                self.assertEqual(cleanup and not late,namespace['value']['passed'])
                self.assertEqual(10,namespace['value']['cleanupDeadlines']['verification'])


    def monitor_source_tree(self):
        base=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=self.directory)))
        (base/'toolchain-001').mkdir()
        for relative,_,_ in runtime._MONITOR_LOADER_SOURCES:
            (base/relative).write_bytes((SOURCE/relative).read_bytes())
        return base

    def capture_source_vector(self, mutation=None, *, primary=None, close_error=None):
        # Actual descriptor reader; authored metadata and bounded read results only.
        events=[];now=[0.0];payload=b'authored';offset=[0];fstats={};stats={};primary_tracebacks=[]
        def metadata(kind,inode,size=0):
            return types.SimpleNamespace(st_dev=7,st_ino=inode,st_mode=kind|0o500,
                st_uid=9,st_gid=9,st_nlink=1,st_size=size,st_mtime_ns=1,st_ctime_ns=1)
        root=metadata(stat.S_IFDIR,1);parent=metadata(stat.S_IFDIR,2)
        leaf=metadata(stat.S_IFREG,3,len(payload))
        if mutation in ('fifo','link','directory'):
            leaf.st_mode={'fifo':stat.S_IFIFO,'link':stat.S_IFLNK,'directory':stat.S_IFDIR}[mutation]|0o500
        if mutation=='empty':leaf.st_size=0
        if mutation=='oversize':leaf.st_size+=1
        def opened(name,flags,**kwargs):
            events.append(('open',name,flags,kwargs))
            if name=='authored' and mutation=='parent-link':raise OSError('authored nofollow refusal')
            fd={'/':101,'authored':102,'source.py':103}[name]
            if name=='/' and mutation=='late-open':now[0]=10.0
            return fd
        def fstat(fd):
            fstats[fd]=fstats.get(fd,0)+1
            if fd==103 and mutation=='descriptor-drift' and fstats[fd]>1:return metadata(stat.S_IFREG,4,len(payload))
            if fd==102 and mutation=='held-parent-drift' and fstats[fd]>1:return metadata(stat.S_IFDIR,4)
            return {101:root,102:parent,103:leaf}[fd]
        def named(name,**kwargs):
            stats[name]=stats.get(name,0)+1
            if name=='source.py' and mutation=='path-drift' and stats[name]>1:return metadata(stat.S_IFREG,4,len(payload))
            if name=='authored' and mutation=='named-parent-drift' and stats[name]>1:return metadata(stat.S_IFDIR,4)
            return {'/':root,'authored':parent,'source.py':leaf}[name]
        def read(fd,count):
            self.assertEqual(103,fd);events.append(('read',count))
            if primary is not None:raise primary
            if mutation=='late-read':now[0]=10.0
            data=payload[:-1] if mutation=='short' else payload+b'X' if mutation=='growth' else payload
            block=data[offset[0]:offset[0]+count];offset[0]+=len(block);return block
        def closed(fd):
            events.append(('close',fd))
            if fd==103 and primary is not None:primary_tracebacks.append(primary.__traceback__)
            if fd==103 and close_error is not None:raise close_error
        caught=raw=None
        with patch.object(runtime.os,'open',side_effect=opened),patch.object(runtime.os,'fstat',side_effect=fstat), \
                patch.object(runtime.os,'stat',side_effect=named),patch.object(runtime.os,'read',side_effect=read), \
                patch.object(runtime.os,'close',side_effect=closed),patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]):
            try:raw=runtime._capture_monitor_source(Path('/authored/source.py'),len(payload),10.0)
            except BaseException as failure:caught=failure
        return types.SimpleNamespace(raw=raw,error=caught,events=events,payload=payload,primary_tracebacks=primary_tracebacks)

    def test_monitor_source_capture_exact_payload_eof_flags_and_owned_closure(self):
        vector=self.capture_source_vector()
        self.assertIsNone(vector.error);self.assertEqual(vector.payload,vector.raw)
        self.assertEqual([8,1],[row[1] for row in vector.events if row[0]=='read'])
        self.assertEqual([103,102,101],[row[1] for row in vector.events if row[0]=='close'])
        opens=[row for row in vector.events if row[0]=='open']
        self.assertTrue(all(row[2]&os.O_NOFOLLOW and row[2]&os.O_CLOEXEC for row in opens))
        self.assertTrue(opens[-1][2]&os.O_NONBLOCK)
        self.assertEqual({'dir_fd':102},opens[-1][3])

    def test_monitor_source_capture_refuses_type_size_and_parent_before_payload(self):
        for mutation in ('fifo','link','directory','empty','oversize','parent-link'):
            with self.subTest(mutation=mutation):
                vector=self.capture_source_vector(mutation)
                self.assertIsNotNone(vector.error);self.assertIsNone(vector.raw)
                self.assertFalse(any(row[0]=='read' for row in vector.events))
                self.assertEqual([101] if mutation=='parent-link' else [103,102,101],
                    [row[1] for row in vector.events if row[0]=='close'])
        with patch.object(runtime.time,'monotonic',return_value=0), \
                patch.object(runtime.os,'open',side_effect=AssertionError('path/size bound must precede open')):
            for path,size in ((Path('relative.py'),1),(Path('/a/../source.py'),1),
                              (Path('/'+('/'.join(['a']*128))+'/source.py'),1),
                              (Path('/'+'a'*4096),1),(Path('/source.py'),0),(Path('/source.py'),16777217)):
                with self.assertRaises(ValueError):runtime._capture_monitor_source(path,size,10)

    def test_monitor_source_capture_refuses_growth_truncation_and_identity_drift(self):
        for mutation in ('short','growth','descriptor-drift','path-drift','held-parent-drift','named-parent-drift'):
            with self.subTest(mutation=mutation):
                vector=self.capture_source_vector(mutation)
                self.assertIsInstance(vector.error,ValueError);self.assertIsNone(vector.raw)
                self.assertEqual([103,102,101],[row[1] for row in vector.events if row[0]=='close'])
                self.assertLessEqual(sum(row[1] for row in vector.events if row[0]=='read'),9)

    def test_monitor_source_capture_keeps_primary_and_closes_once_when_close_fails(self):
        class RefusesDiagnostic(ValueError):
            def __setattr__(self,name,value):
                if name=='sourceSnapshotCloseFailure':raise RuntimeError('authored metadata failure')
                super().__setattr__(name,value)
        for primary in (ValueError('authored read refusal'),RefusesDiagnostic('authored primary')):
            with self.subTest(primary_type=type(primary).__name__):
                close_error=OSError('authored close refusal')
                vector=self.capture_source_vector(primary=primary,close_error=close_error)
                self.assertIs(primary,vector.error)
                self.assertIs(vector.primary_tracebacks[0],vector.error.__traceback__.tb_next)
                self.assertEqual([103,102,101],[row[1] for row in vector.events if row[0]=='close'])
                if type(primary) is ValueError:self.assertIs(close_error,primary.sourceSnapshotCloseFailure)
        close_error=OSError('authored cleanup-only refusal')
        vector=self.capture_source_vector(close_error=close_error)
        self.assertIs(close_error,vector.error);self.assertIsNone(vector.raw)
        self.assertEqual([103,102,101],[row[1] for row in vector.events if row[0]=='close'])

    def test_monitor_source_capture_expiration_closes_even_just_acquired_descriptor(self):
        for mutation in ('late-open','late-read'):
            with self.subTest(mutation=mutation):
                vector=self.capture_source_vector(mutation)
                self.assertIsInstance(vector.error,TimeoutError);self.assertIsNone(vector.raw)
                self.assertEqual([101] if mutation=='late-open' else [103,102,101],
                    [row[1] for row in vector.events if row[0]=='close'])
        with patch.object(runtime.time,'monotonic',return_value=10), \
                patch.object(runtime.os,'open',side_effect=AssertionError('expired must not open')):
            with self.assertRaises(TimeoutError):runtime._capture_monitor_source(Path('/authored.py'),1,10)

    def test_authenticated_loader_captures_all_sources_before_any_compile_or_exec(self):
        for index in range(3):
            for mutation in ('missing','empty','oversize','wrong-hash'):
                with self.subTest(index=index,mutation=mutation):
                    base=self.monitor_source_tree();relative,size,_=runtime._MONITOR_LOADER_SOURCES[index];path=base/relative
                    if mutation=='missing':path.unlink()
                    else:path.write_bytes(b'' if mutation=='empty' else b'X'*(size+1 if mutation=='oversize' else size))
                    with patch.object(runtime,'BASE',base), \
                            patch.object(runtime,'compile',create=True,side_effect=AssertionError('no source may compile')) as compiling, \
                            patch.object(runtime,'exec',create=True,side_effect=AssertionError('no source may execute')) as executing:
                        with self.assertRaises((ValueError,OSError)):runtime._authenticated_monitor_loader()
                    compiling.assert_not_called();executing.assert_not_called()

    def test_authenticated_loader_executes_captured_modules_without_path_cache_or_ambient_modules(self):
        import importlib.util
        base=self.monitor_source_tree();cache=base/'toolchain-001/__pycache__';cache.mkdir()
        for name in ('pin_environment','link_inputs','monitor_inputs'):
            (cache/(name+'.'+sys.implementation.cache_tag+'.pyc')).write_bytes(b'hostile inert cache')
        capture=runtime._capture_monitor_source;captures=[]
        previous=sys.modules.get('_v3_monitor_link_inputs')
        def captured(path,size,deadline):
            raw=capture(path,size,deadline);captures.append(Path(path).name)
            if len(captures)==3:
                (base/'toolchain-001/pin_environment.py').write_bytes(b'raise AssertionError("mutable replacement must not execute")')
            return raw
        ambient={name:types.ModuleType(name) for name in ('_v3_monitor_link_inputs','_v3_monitor_inputs','callable_v3_link_inputs','callable_v3_monitor_inputs')}
        with patch.object(runtime,'BASE',base),patch.object(runtime,'_capture_monitor_source',side_effect=captured), \
                patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('no path/pyc loader')), \
                patch.dict(sys.modules,ambient):
            module=runtime._authenticated_monitor_loader()
        self.assertEqual(['pin_environment.py','link_inputs.py','monitor_inputs.py'],captures)
        self.assertIs(module.link_inputs,module._runtime_dependencies['link_inputs'])
        self.assertIs(module.monitor_inputs,module._runtime_dependencies['monitor_inputs'])
        self.assertIsNot(module.link_inputs,ambient['_v3_monitor_link_inputs'])
        self.assertEqual(hashlib.sha256(b'authored').hexdigest(),module.link_inputs.sha(b'authored'))
        self.assertIs(sys.modules.get('_v3_monitor_link_inputs'),previous)

    def test_authenticated_loader_partial_or_malformed_injection_never_falls_back(self):
        import importlib.util
        raw=(SOURCE/'toolchain-001/pin_environment.py').read_bytes()
        valid_link=types.ModuleType('_v3_monitor_link_inputs');valid_link.__file__=str(SOURCE/'toolchain-001/link_inputs.py')
        valid_monitor=types.ModuleType('_v3_monitor_inputs');valid_monitor.__file__=str(SOURCE/'toolchain-001/monitor_inputs.py')
        for injection in (None,{}, {'link_inputs':valid_link}, {'link_inputs':valid_link,'monitor_inputs':object()},
                          {'link_inputs':valid_link,'monitor_inputs':valid_monitor,'extra':valid_link}):
            module=types.ModuleType('_authored_malformed');module.__file__=str(SOURCE/'toolchain-001/pin_environment.py')
            module._runtime_dependencies=injection
            with patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('no fallback')) as fallback:
                with self.assertRaises(ValueError):exec(compile(raw,module.__file__,'exec'),module.__dict__)
            fallback.assert_not_called()
        valid_monitor.__name__='_wrong_module_name'
        wrong_name=types.ModuleType('_authored_wrong_name');wrong_name.__file__=str(SOURCE/'toolchain-001/pin_environment.py')
        wrong_name._runtime_dependencies={'link_inputs':valid_link,'monitor_inputs':valid_monitor}
        with self.assertRaises(ValueError):exec(compile(raw,wrong_name.__file__,'exec'),wrong_name.__dict__)
        valid_monitor.__name__='_v3_monitor_inputs'
        valid_monitor.__file__='/wrong/monitor_inputs.py'
        module=types.ModuleType('_authored_wrong_path');module.__file__=str(SOURCE/'toolchain-001/pin_environment.py')
        module._runtime_dependencies={'link_inputs':valid_link,'monitor_inputs':valid_monitor}
        with self.assertRaises(ValueError):exec(compile(raw,module.__file__,'exec'),module.__dict__)

    def test_authenticated_loader_expired_capture_hash_compile_and_exec_never_return_module(self):
        real_capture=runtime._capture_monitor_source;real_compile=compile;real_exec=exec;real_sha256=hashlib.sha256
        for stage in ('before','capture','hash','compile','exec'):
            with self.subTest(stage=stage):
                now=[10.0 if stage=='before' else 0.0];events=[]
                def capture(path,size,deadline):
                    events.append(('capture',deadline));raw=real_capture(path,size,deadline)
                    if stage=='capture':now[0]=10.0
                    return raw
                def hashed(*args,**kwargs):
                    value=real_sha256(*args,**kwargs)
                    if stage=='hash':now[0]=10.0
                    return value
                def compiling(*args):
                    events.append(('compile',None));code=real_compile(*args)
                    if stage=='compile':now[0]=10.0
                    return code
                def executing(*args):
                    events.append(('exec',None));real_exec(*args)
                    if stage=='exec':now[0]=10.0
                with patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(runtime,'_capture_monitor_source',side_effect=capture), \
                        patch.object(runtime.hashlib,'sha256',side_effect=hashed), \
                        patch.object(runtime,'compile',create=True,side_effect=compiling), \
                        patch.object(runtime,'exec',create=True,side_effect=executing):
                    with self.assertRaises(TimeoutError):runtime._authenticated_monitor_loader(10.0)
                self.assertTrue(all(value==10.0 for name,value in events if name=='capture'))
                if stage=='before':self.assertEqual([],events)
                if stage=='capture':self.assertEqual([('capture',10.0)],events)
                if stage=='compile':self.assertFalse(any(name=='exec' for name,_ in events))
                if stage=='hash':self.assertFalse(any(name in ('compile','exec') for name,_ in events))

    def test_actual_authenticated_closure_serves_both_binding_consumers_and_revalidation(self):
        profile=build_contract.load_profile();sha='a'*64;driver=profile['gccIdentity']
        monitor_path='/authored/monitor';cache='/authored/cache';library='/authored/lib.so'
        record={'binaryPath':monitor_path,'cachePath':cache,
                'sourcePath':str(runtime.BASE/'worker_exec_monitor.c'),'parserPath':str(runtime.BASE/'worker_exec_proof.py'),
                'protocolPath':str(runtime.BASE/'contracts/worker-exec-proof-schema.json'),
                'provisioningManifestPath':str(runtime.BASE/'toolchain-001/worker-exec-monitor.json')}
        files={path:{'realpath':path,'sha256':sha} for path in set(record.values())|{library}}
        implicit={'status':'static-recording-unqualified','files':{'gcc':{'realpath':driver['realpath'],'sha256':driver['sha256']}},
                  'manifest':{'tools':{'gcc':'gcc'},'driverArgv':['/usr/bin/gcc','-v'],'workingDirectory':'/work','environment':profile['environment']},
                  'directories':{'/authored':{}},'selections':[{'authored':True}]}
        value={'status':'static-recording-unqualified','implicitLinkClosure':implicit,
               'monitorClosure':{'record':record,'files':files,'elfGraph':{monitor_path:[],library:[]}}}
        real_loader=runtime._authenticated_monitor_loader;modules=[];deadlines=[]
        def loaded(deadline=None):
            deadlines.append(deadline);module=real_loader(deadline);modules.append(module)
            module._load_operational=Mock(return_value=(value,profile['toolchainEnvironmentPinSha256']))
            return module
        recipe={'worker':['/usr/bin/gcc','-v'],'chdir':'/work','environment':profile['environment']}
        target={'path':driver['realpath'],'sha256':driver['sha256']}
        with patch.object(runtime,'_authenticated_monitor_loader',side_effect=loaded), \
                patch.object(runtime.time,'monotonic',return_value=0),patch.object(runtime,'digest',return_value=sha), \
                patch.object(runtime,'_nonprivileged_executable',return_value={'sha256':sha}):
            binding=runtime.load_worker_monitor_binding(deadline=10.0)
            recording=runtime._recorded_compiler_inputs(recipe,target,10.0)
            runtime._revalidate_compiler_inputs({'compilerRecording':recording,'pins':{driver['realpath']:{'sha256':driver['sha256']}}},10.0)
        self.assertEqual([10.0,10.0,10.0],deadlines)
        self.assertEqual(3,len(modules));self.assertTrue(recording['invocationMatched'])
        self.assertTrue(all(modules[i] is not modules[j] for i in range(3) for j in range(i)))
        self.assertTrue(all(module.link_inputs is module._runtime_dependencies['link_inputs'] for module in modules))
        self.assertEqual({cache,library},{item['path'] for item in binding['dependencies']})
        self.assertEqual('static-recording-unqualified',recording['binding']['status'])
        # Real loader/consumer with absent environment recording refuses, never native authority.
        base=self.monitor_source_tree()
        with patch.object(runtime,'BASE',base):
            with self.assertRaises(ValueError):runtime.load_worker_monitor_binding()

    def test_monitor_binding_rehashes_actual_retained_files_with_original_cap_and_end(self):
        profile=build_contract.load_profile();base=self.directory/'monitor-binding';base.mkdir();(base/'contracts').mkdir()
        fixed={'sourceSha256':base/'worker_exec_monitor.c','protocolSha256':base/'contracts/worker-exec-proof-schema.json',
               'parserSha256':base/'worker_exec_proof.py'}
        for key,path in fixed.items():path.write_bytes(('authored '+key).encode())
        dependency=base/'dependency';dependency.write_bytes(b'authored dependency')
        binding={key:runtime.digest(path) for key,path in fixed.items()}
        binding.update(binaryPath=str(base/'monitor'),binarySha256='a'*64,manifestSha256='b'*64,
            environmentPinSha256=profile['toolchainEnvironmentPinSha256'],
            dependencies=[{'path':str(dependency),'sha256':runtime.digest(dependency)}])
        module=types.SimpleNamespace(load_monitor_binding=lambda supplied:binding)
        real_digest=runtime.digest;calls=[]
        def hashing(path,**kwargs):calls.append((path,kwargs));return real_digest(path,**kwargs)
        with patch.object(runtime,'BASE',base),patch.object(runtime,'_authenticated_monitor_loader',return_value=module), \
                patch.object(runtime,'_nonprivileged_executable',return_value={'sha256':'a'*64}), \
                patch.object(runtime.time,'monotonic',return_value=0),patch.object(runtime,'digest',side_effect=hashing):
            self.assertIs(binding,runtime.load_worker_monitor_binding(deadline=10.0))
        self.assertEqual([*fixed.values(),dependency],[path for path,_ in calls])
        self.assertTrue(all(kwargs=={'maximum':16777216,'deadline':10.0} for _,kwargs in calls))
        for path in (fixed['sourceSha256'],dependency):
            saved=path.read_bytes()
            for mutation in ('changed','missing','symlink','oversize'):
                if mutation=='changed':path.write_bytes(b'changed')
                elif mutation=='missing':path.unlink()
                elif mutation=='symlink':path.unlink();path.symlink_to(fixed['parserSha256'])
                real_fstat=build_contract.os.fstat;inode=path.stat().st_ino if path.exists() else None
                def fstat(fd):
                    value=real_fstat(fd)
                    if mutation=='oversize' and value.st_ino==inode:
                        return types.SimpleNamespace(**{key:(16777217 if key=='st_size' else getattr(value,key)) for key in
                            ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')})
                    return value
                with self.subTest(path=path,mutation=mutation),patch.object(runtime,'BASE',base), \
                        patch.object(runtime,'_authenticated_monitor_loader',return_value=module), \
                        patch.object(runtime,'_nonprivileged_executable',return_value={'sha256':'a'*64}), \
                        patch.object(runtime.time,'monotonic',return_value=0),patch.object(build_contract.os,'fstat',side_effect=fstat):
                    with self.assertRaises((ValueError,OSError)):runtime.load_worker_monitor_binding(deadline=10.0)
                if path.is_symlink() or path.exists():path.unlink()
                path.write_bytes(saved)

    def test_monitor_binding_late_gate_keeps_same_deadline_and_refuses(self):
        real_loader=runtime._authenticated_monitor_loader;now=[0.0];deadlines=[]
        def loaded(deadline):
            deadlines.append(deadline);module=real_loader(deadline)
            def gate(profile):now[0]=10.0;return {}
            module.load_monitor_binding=gate;module.load_compiler_binding=gate
            return module
        profile=build_contract.load_profile();driver=profile['gccIdentity']
        with patch.object(runtime,'_authenticated_monitor_loader',side_effect=loaded), \
                patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]):
            with self.assertRaises(TimeoutError):runtime.load_worker_monitor_binding(deadline=10.0)
            now[0]=0.0
            with self.assertRaises(TimeoutError):runtime._recorded_compiler_inputs({}, {'path':driver['realpath'],'sha256':driver['sha256']},10.0)
        self.assertEqual([10.0,10.0],deadlines)

    def test_prepare_launch_requires_all_three_trusted_source_pins_before_publication(self):
        profile,profile_sha=build_contract.load_profile_with_digest();bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
        recipe={'target':Path('/authored/target'),'worker':['/target'],'prefix':[],'mounts':[]}
        binding={'binaryPath':'/authored/monitor','dependencies':[],**{name:runtime._WORKER_PROOF_PARSER_SHA256 if name=='parserSha256' else 'a'*64 for name in
            ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','parserSha256','manifestSha256')}}
        receipt={'directory':Path('/authored')/('a'*32),'directoryDevice':1,'directoryInode':2,'device':1,'inode':3}
        for index in range(3):
            for mutation in ('missing','wrong'):
                with self.subTest(index=index,mutation=mutation):
                    pins={str(runtime.BASE/'contracts/candidate-build-profile.json'):{'sha256':profile_sha}}
                    pins['/authored/monitor']={'device':1,'inode':2,'mode':0o500,'sha256':'a'*64}
                    pins.update({str(runtime.BASE/relative):{'sha256':sha} for relative,_,sha in runtime._MONITOR_LOADER_SOURCES})
                    key=str(runtime.BASE/runtime._MONITOR_LOADER_SOURCES[index][0])
                    if mutation=='missing':pins.pop(key)
                    else:pins[key]['sha256']='f'*64
                    with patch.object(Path,'stat',return_value=types.SimpleNamespace(st_dev=1,st_ino=2)), \
                            patch.object(runtime.time,'monotonic',return_value=0),patch.object(runtime,'_contained_recipe',return_value=recipe), \
                            patch.object(runtime,'load_worker_monitor_binding',return_value=binding) as loader, \
                            patch.object(runtime,'_recorded_compiler_inputs',return_value=None), \
                            patch.object(runtime,'_nonprivileged_executable',side_effect=lambda p,deadline=None:{'path':str(p),'device':1,'inode':2,'mode':0o500,'sha256':'a'*64}), \
                            patch.object(runtime,'_pin_files',return_value=pins),patch.object(runtime,'_publish_config') as published:
                        with self.assertRaisesRegex(ValueError,'source launch pin differs'):
                            runtime._prepare_launch(['/authored'],self.work,bounds,receipt,False,deadline=10.0)
                    loader.assert_called_once_with(deadline=10.0);published.assert_not_called()


    def cleanup_runner_vector(self, *, cgroup_error=None, launcher_error=None, primary=None,
                              invalid_scope=False, clock_case=None, helper=False, helper_close_error=None):
        # Actual runner, final-proof refusal and receipt retention; only external
        # process/kernel/clock interfaces are authored. No child, scope or real FD.
        events=[]; now=[100.0]; saved_primary_traceback=[]; cleanup_time=[]
        bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
        receipt={'directory':self.directory/'never-launched-receipt','fd':114}
        if helper:receipt['helperSnapshotFd']=115
        scope={'_directoryFd':112,'_gatePidfd':113,'unit':'authored.scope'}
        launch={'argv':['never executed'],'pins':{},'proofBinding':{}}
        class Pipe:
            def __init__(self,fd):self.fd=fd
            def fileno(self):return self.fd
            def write(self,value):pass
            def close(self):events.append(('close-stream',self.fd))
        class Selector:
            def __init__(self):self.entries={}
            def register(self,stream,event,label):self.entries[stream.fd]=types.SimpleNamespace(fileobj=stream,data=label)
            def unregister(self,stream):self.entries.pop(stream.fd)
            def get_map(self):return self.entries
            def select(self,timeout):
                if primary is not None:raise primary
                return [(entry,1) for entry in list(self.entries.values())]
            def close(self):events.append(('close-selector',None))
        def kill_scope(acquired):
            self.assertIs(scope,acquired);events.append(('kill-scope',acquired))
            cleanup_time.append(now[0])
            if primary is not None:saved_primary_traceback.append(primary.__traceback__)
            if clock_case=='expired-before-wait':now[0]+=bounds['supervisor']['cleanupWaitSeconds']
            if clock_case=='kill-cost':now[0]+=1.0
            if cgroup_error is not None:raise cgroup_error
        def kill_launcher(fd):
            self.assertEqual(111,fd);events.append(('kill-launcher',fd))
            if launcher_error is not None:raise launcher_error
        def wait(*,timeout):
            is_cleanup=bool(cleanup_time)
            events.append(('cleanup-wait' if is_cleanup else 'phase-wait',timeout))
            if is_cleanup:
                if clock_case=='failed-wait':raise TimeoutError('authored wait refusal')
                now[0]+=timeout if clock_case=='late-wait' else 0.25
            return 0
        scope_error=ValueError('authored invalid retained scope')
        def scoped(acquired):
            self.assertIs(scope,acquired);events.append(('scope-absence',None))
            if invalid_scope:raise scope_error
            return []
        def owned(pid,start,end):
            self.assertEqual((123,1),(pid,start));events.append(('session-absence',end))
            return []
        process=types.SimpleNamespace(pid=123,stdin=Pipe(900),stdout=Pipe(901),stderr=Pipe(902),wait=wait,returncode=0)
        caught=None; caught_traceback=None
        def close(fd):
            events.append(('close-fd',fd))
            if fd==115 and helper_close_error is not None:raise helper_close_error
        finish=runtime._finish_worker_proof
        def finish_helper(*args,**kwargs):
            events.append(('proof-consumed',None));return finish(*args,**kwargs)
        with ExitStack() as effects:
            if helper:effects.enter_context(patch.object(runtime,'_finish_worker_proof',side_effect=finish_helper))
            for effect in (
                patch.object(runtime,'_work_directory',return_value=self.work),patch.object(runtime,'_worker_environment'),
                patch.object(runtime,'_create_worker_receipt',return_value=receipt),patch.object(runtime,'_prepare_launch',return_value=launch),
                patch.object(runtime.subprocess,'Popen',return_value=process),patch.object(runtime.os,'pidfd_open',return_value=111),
                patch.object(runtime,'process_identity',return_value={'start':1}),patch.object(runtime.selectors,'DefaultSelector',side_effect=Selector),
                patch.object(runtime.os,'set_blocking'),patch.object(runtime.os,'read',return_value=b''),
                patch.object(runtime.os,'close',side_effect=close),
                patch.object(runtime,'_admit_scope',return_value=scope),patch.object(runtime,'_release_scope'),
                patch.object(runtime,'_kill_owned_scope',side_effect=kill_scope),patch.object(runtime,'_kill_launcher',side_effect=kill_launcher),
                patch.object(runtime,'scope_processes',side_effect=scoped),patch.object(runtime,'owned_processes',side_effect=owned),
                patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]),
                patch.object(runtime.time,'sleep',side_effect=AssertionError('no retry or sleep expected')),
            ):effects.enter_context(effect)
            try:
                runtime._run_scoped(['authored'],self.work,self.env,b'',bounds,provisioning=False)
            except Exception as error:
                caught=error;caught_traceback=error.__traceback__
        self.assertIsNotNone(caught)
        result=caught.bounded_result
        self.assertFalse(result['cleanupVerified']);self.assertTrue(result['infrastructureFailure'])
        self.assertIsNone(result['exitCode']);self.assertFalse(runtime.worker_execution_complete(result))
        self.assertEqual('unknown',result['workerProof']['status'])
        self.assertEqual('retained',result['_receiptCleanup']['status'])
        if helper:
            self.assertEqual([111,112,113,115,114],[value for name,value in events if name=='close-fd'])
            self.assertIsNone(receipt['helperSnapshotFd'])
        else:
            self.assertEqual([111,112,113,114],[value for name,value in events if name=='close-fd'])
        self.assertEqual([900,900,901,902],[value for name,value in events if name=='close-stream'])
        self.assertNotIn('cleanupFailure',runtime.public_result(result))
        self.assertNotIn('secondaryCleanupFailures',runtime.public_result(result))
        return types.SimpleNamespace(error=caught,result=result,events=events,bounds=bounds,scope_error=scope_error,
            traceback=caught_traceback,primary_traceback=saved_primary_traceback,cleanup_time=cleanup_time)

    def test_actual_runner_consumes_proof_before_once_H_close_and_preserves_primary_on_unknown_cleanup(self):
        for close_failure in (None,OSError('authored H close refusal')):
            primary=ValueError('authored phase refusal');kill=OSError('authored scope kill refusal')
            with self.subTest(close_failure=close_failure is not None):
                vector=self.cleanup_runner_vector(primary=primary,cgroup_error=kill,invalid_scope=True,
                                                  helper=True,helper_close_error=close_failure)
                self.assertIs(primary,vector.error);self.assertIs(kill,primary.cleanupFailure)
                self.assertIs(vector.result,primary.bounded_result)
                self.assertEqual(b'',vector.result['workerProofRaw'])
                self.assertFalse(vector.result['cleanupVerified']);self.assertFalse(vector.result['finalAbsenceVerified'])
                self.assertEqual('retained',vector.result['_receiptCleanup']['status'])
                proof=vector.events.index(('proof-consumed',None));closed=vector.events.index(('close-fd',115))
                self.assertLess(proof,closed)
                self.assertEqual(1,vector.events.count(('close-fd',115)))
                self.assertNotIn('helperSnapshot',runtime.public_result(vector.result))

    def test_runner_attempts_each_owned_kill_and_keeps_cleanup_failure_sticky(self):
        for which in ('cgroup','launcher','both'):
            with self.subTest(which=which):
                cgroup=OSError('authored cgroup failure') if which!='launcher' else None
                launcher=RuntimeError('authored pidfd failure') if which!='cgroup' else None
                vector=self.cleanup_runner_vector(cgroup_error=cgroup,launcher_error=launcher)
                self.assertIs(cgroup if cgroup is not None else launcher,vector.error)
                names=[name for name,_ in vector.events]
                self.assertLess(names.index('kill-scope'),names.index('kill-launcher'))
                self.assertLess(names.index('kill-launcher'),names.index('cleanup-wait'))
                self.assertLess(names.index('cleanup-wait'),names.index('scope-absence'))
                self.assertLess(names.index('scope-absence'),names.index('session-absence'))
                self.assertTrue(vector.result['rootReaped']);self.assertTrue(vector.result['finalAbsenceVerified'])
                if which=='both':self.assertIs(launcher,vector.error.secondaryCleanupFailures[0])

    def test_runner_invalid_scope_retains_unknown_absence_after_pidfd_kill_and_reap(self):
        cgroup=ValueError('authored scope handle refusal');launcher=OSError('authored pidfd refusal')
        vector=self.cleanup_runner_vector(cgroup_error=cgroup,launcher_error=launcher,invalid_scope=True)
        self.assertIs(cgroup,vector.error)
        self.assertEqual(2,len(vector.error.secondaryCleanupFailures))
        self.assertIs(launcher,vector.error.secondaryCleanupFailures[0])
        self.assertIs(vector.scope_error,vector.error.secondaryCleanupFailures[1])
        self.assertTrue(vector.result['rootReaped']);self.assertFalse(vector.result['finalAbsenceVerified'])
        self.assertNotIn('session-absence',[name for name,_ in vector.events])

    def test_runner_preserves_active_primary_identity_traceback_and_both_cleanup_errors(self):
        class NoComparisonOrFormatting(ValueError):
            def __eq__(self,other):raise AssertionError('exception equality must not be called')
            def __str__(self):raise AssertionError('exception formatting must not be called')
        primary=NoComparisonOrFormatting();cgroup=NoComparisonOrFormatting();launcher=NoComparisonOrFormatting()
        vector=self.cleanup_runner_vector(primary=primary,cgroup_error=cgroup,launcher_error=launcher)
        self.assertIs(primary,vector.error);self.assertIs(cgroup,primary.cleanupFailure)
        self.assertIs(launcher,cgroup.secondaryCleanupFailures[0])
        self.assertIs(vector.primary_traceback[0],vector.traceback.tb_next)
        self.assertFalse(vector.result['captureComplete']);self.assertFalse(vector.result['waitComplete'])

    def test_runner_diagnostic_attribute_failure_cannot_replace_primary(self):
        class RefusesMetadata(ValueError):
            def __setattr__(self,name,value):
                if name=='cleanupFailure':raise RuntimeError('authored diagnostic attachment failure')
                super().__setattr__(name,value)
        primary=RefusesMetadata('authored primary')
        vector=self.cleanup_runner_vector(primary=primary,cgroup_error=OSError('authored cleanup'))
        self.assertIs(primary,vector.error);self.assertFalse(hasattr(primary,'cleanupFailure'))
        self.assertIs(vector.primary_traceback[0],vector.traceback.tb_next)

    def test_runner_failed_or_expired_wait_never_opens_verification_window(self):
        for clock_case in ('expired-before-wait','failed-wait','late-wait'):
            with self.subTest(clock_case=clock_case):
                cgroup=OSError('authored kill refusal')
                vector=self.cleanup_runner_vector(cgroup_error=cgroup,clock_case=clock_case)
                self.assertIs(cgroup,vector.error)
                self.assertIsInstance(vector.error.secondaryCleanupFailures[0],TimeoutError)
                names=[name for name,_ in vector.events]
                self.assertEqual(0 if clock_case=='expired-before-wait' else 1,names.count('cleanup-wait'))
                self.assertNotIn('scope-absence',names);self.assertNotIn('session-absence',names)
                self.assertFalse(vector.result['finalAbsenceVerified'])
                self.assertEqual(clock_case=='late-wait',vector.result['rootReaped'])

    def test_runner_timely_reap_uses_original_wait_end_then_one_verification_window(self):
        for clock_case,kill_cost in ((None,0.0),('kill-cost',1.0)):
            with self.subTest(clock_case=clock_case):
                vector=self.cleanup_runner_vector(cgroup_error=OSError('authored kill refusal'),clock_case=clock_case)
                supervisor=vector.bounds['supervisor']
                self.assertEqual([supervisor['cleanupWaitSeconds']-kill_cost],
                    [value for name,value in vector.events if name=='cleanup-wait'])
                self.assertEqual([vector.cleanup_time[0]+kill_cost+0.25+supervisor['cleanupVerificationSeconds']],
                    [value for name,value in vector.events if name=='session-absence'])
                self.assertTrue(vector.result['rootReaped']);self.assertTrue(vector.result['finalAbsenceVerified'])
                self.assertFalse(vector.result['cleanupVerified'])

    def test_runner_repeated_identical_errors_do_not_create_self_links_or_duplicate_metadata(self):
        repeated=ValueError('authored repeated cleanup')
        vector=self.cleanup_runner_vector(cgroup_error=repeated,launcher_error=repeated)
        self.assertIs(repeated,vector.error);self.assertFalse(hasattr(repeated,'secondaryCleanupFailures'))
        primary=ValueError('authored same primary and cleanup')
        vector=self.cleanup_runner_vector(primary=primary,cgroup_error=primary,launcher_error=primary)
        self.assertIs(primary,vector.error);self.assertFalse(hasattr(primary,'cleanupFailure'))
        self.assertFalse(hasattr(primary,'secondaryCleanupFailures'))


class LaunchConfigCaptureTests(unittest.TestCase):
    """Authored metadata/bytes only; every filesystem, clock and proof-loading seam is mocked."""
    def vector(self, mutation=None, *, raw=b'{"fixed":true}', deadline=10, finish=False):
        directory = Path('/authored/receipt')
        receipt = {'directory':directory, 'directoryDevice':7, 'directoryInode':8,
                   'fd':51, 'path':directory/'worker-proof.jsonl', 'device':7, 'inode':9}
        def metadata(kind, inode, size, mode):
            return types.SimpleNamespace(st_dev=7, st_ino=inode, st_mode=kind|mode,
                st_uid=55, st_gid=55, st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)
        parent = metadata(stat.S_IFDIR,8,0,0o700)
        config = metadata(stat.S_IFREG,10,len(raw),0o600)
        report = metadata(stat.S_IFREG,9,5,0o600)
        if mutation=='fifo':config.st_mode=stat.S_IFIFO|0o600
        if mutation=='symlink-metadata':config.st_mode=stat.S_IFLNK|0o600
        if mutation=='uid':config.st_uid=56
        if mutation=='mode':config.st_mode=stat.S_IFREG|0o644
        if mutation=='links':config.st_nlink=2
        if mutation=='empty':config.st_size=0
        if mutation=='oversize':config.st_size=65537
        if mutation=='short':config.st_size+=1
        if mutation=='directory-mode':parent.st_mode=stat.S_IFDIR|0o755
        if mutation=='directory-uid':parent.st_uid=56
        if mutation=='directory-kind':parent.st_mode=stat.S_IFREG|0o700
        if mutation=='directory-device':parent.st_dev=8
        if mutation=='directory-inode':parent.st_ino=11
        now=[1]; offset=[0]; fstats={}; stats=[0]
        handles=set(); opened=[]; closed=[]; reads=[]; events=[]
        injected=PermissionError('authored launch configuration operation refusal')
        close_error=OSError('authored launch configuration close refusal')
        def stage(name):
            events.append(name)
            if mutation=='late-'+name:now[0]=10
            if mutation==name+'-error' or mutation=='read-and-close-errors' and name=='read':raise injected
        def changed(value, field='st_ino'):
            result=types.SimpleNamespace(**vars(value));setattr(result,field,getattr(result,field)+1);return result
        def opening(path, flags, *, dir_fd=None):
            if dir_fd is None:
                self.assertEqual(directory,path)
                self.assertEqual(os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,flags)
                number=41; name='open-directory'
            else:
                self.assertEqual((41,'launch.json'),(dir_fd,path))
                self.assertEqual(os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,flags)
                number=42; name='open-file'
                if mutation=='symlink-open':raise OSError(40,'authored nofollow symlink refusal')
            # A late successful open still returns an owned FD which must close.
            stage(name)
            handles.add(number);opened.append(number)
            return number
        def fstat(number):
            if number==51:return report
            self.assertIn(number,handles)
            fstats[number]=fstats.get(number,0)+1
            if number==41:
                name='directory-final' if fstats[number]>1 else 'directory-fstat'
                stage(name)
                return changed(parent) if mutation=='held-directory-drift' and fstats[number]>1 else parent
            self.assertEqual(42,number)
            name='file-final' if fstats[number]>1 else 'file-fstat'
            stage(name)
            return changed(config,'st_mtime_ns') if mutation=='held-file-drift' and fstats[number]>1 else config
        def named_file(name, *, dir_fd, follow_symlinks):
            self.assertEqual(('launch.json',41,False),(name,dir_fd,follow_symlinks))
            self.assertIn(41,handles);stats[0]+=1
            stage('named-file-final' if stats[0]>1 else 'named-file')
            return changed(config) if mutation=='named-file-drift' and stats[0]>1 or mutation=='named-file-before' else config
        def named_path(path):
            if path==receipt['path']:return report
            self.assertEqual(directory,path)
            stage('named-directory-final' if fstats.get(41,0)>1 else 'named-directory')
            return changed(parent) if mutation=='named-directory-drift' and fstats.get(41,0)>1 else parent
        def reading(number, maximum):
            self.assertEqual(42,number);self.assertIn(number,handles)
            self.assertGreater(maximum,0);self.assertLessEqual(maximum,65536)
            reads.append((number,maximum))
            if offset[0]>=len(raw):
                stage('growth')
                return b'x' if mutation=='growth' else b''
            stage('read')
            if mutation=='oversized-read':return b'x'*(maximum+1)
            count=min(maximum,7) if mutation=='partial' else maximum
            value=raw[offset[0]:offset[0]+count];offset[0]+=len(value)
            return value
        def closing(number):
            self.assertIn(number,handles,'owned descriptors close once')
            handles.remove(number);closed.append(number)
            name='close-file' if number==42 else 'close-directory'
            events.append(name)
            if mutation=='late-'+name:now[0]=10
            if mutation in (name+'-error','both-close-errors','read-and-close-errors'):raise close_error
        parsed={'status':'verified','proofSha256':hashlib.sha256(b'proof').hexdigest(),
                'reason':'authored parsed fixture','workerExecVerified':True,'workerTerminationVerified':True,
                'workerTermination':{'kind':'exit','value':0,'rawWaitStatus':0},'exitCode':0}
        parser=types.SimpleNamespace(parse_proof=Mock(return_value=parsed))
        result={'cleanupVerified':True,'finalAbsenceVerified':True,'launcherExitCode':0,
                'captureComplete':True,'waitComplete':True,'scopeVerified':True,'scopeAdmitted':True,
                'launcherPidIdentityVerified':True,'timedOut':False,'outputExceeded':False,
                'infrastructureFailure':False,'workerExecVerified':False,'workerTerminationVerified':False,
                'workerTermination':None,'exitCode':None}
        launch={'expected':{'phase':'runtime'},'pins':{},
                'configSha256':'0'*64 if mutation=='wrong-digest' else hashlib.sha256(raw).hexdigest()}
        answer=error=None
        with ExitStack() as stack:
            for target, name, effect in ((runtime.os,'open',opening),(runtime.os,'fstat',fstat),
                    (runtime.os,'stat',named_file),(runtime.os,'read',reading),(runtime.os,'close',closing)):
                stack.enter_context(patch.object(target,name,side_effect=effect))
            stack.enter_context(patch.object(Path,'lstat',autospec=True,side_effect=named_path))
            stack.enter_context(patch.object(runtime.os,'getuid',return_value=55))
            stack.enter_context(patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]))
            stack.enter_context(patch.object(runtime.os,'pread',return_value=b'proof'))
            stack.enter_context(patch.object(runtime,'_pin_files',return_value={}))
            stack.enter_context(patch.object(runtime,'_revalidate_compiler_inputs'))
            stack.enter_context(patch.object(runtime,'_worker_proof_parser',return_value=parser.parse_proof))
            stack.enter_context(patch.object(runtime,'digest',side_effect=AssertionError('fixed config must not use pathname digest')))
            try:
                if finish:runtime._finish_worker_proof(result,receipt,launch,{'workerLimits':{'workerProofBytes':1024}},deadline=deadline)
                else:answer=runtime._launch_config_digest(receipt,deadline=deadline)
            except BaseException as failure:error=failure
        return types.SimpleNamespace(answer=answer,error=error,result=result,parser=parser,
            opened=opened,closed=closed,handles=handles,reads=reads,events=events,
            injected=injected,close_error=close_error,raw=raw)

    def assert_closed(self, value):
        self.assertEqual(set(),value.handles)
        self.assertEqual(sorted(value.opened),sorted(value.closed))
        self.assertEqual(len(value.closed),len(set(value.closed)))

    def test_fixed_launch_config_exact_cap_partial_reads_and_owned_relative_flags(self):
        for raw,mutation in ((b'x',None),(b'x'*65536,None),(b'{"fixed":true}','partial')):
            with self.subTest(size=len(raw),mutation=mutation):
                value=self.vector(mutation,raw=raw)
                self.assertIsNone(value.error)
                self.assertEqual(hashlib.sha256(raw).hexdigest(),value.answer)
                self.assertEqual(1,value.reads[-1][1]);self.assert_closed(value)
                self.assertEqual([42,41],value.closed)

    def test_fixed_launch_config_rejects_special_unowned_or_oversize_before_read(self):
        for mutation in ('fifo','symlink-metadata','symlink-open','uid','mode','links','empty','oversize',
                         'directory-mode','directory-uid','directory-kind','directory-device','directory-inode','named-file-before'):
            with self.subTest(mutation=mutation):
                value=self.vector(mutation)
                self.assertIsInstance(value.error,(ValueError,OSError));self.assertIsNone(value.answer)
                self.assertEqual([],value.reads);self.assert_closed(value)
        for deadline in (None,True,float('inf'),float('nan'),1):
            with self.subTest(deadline=deadline):
                value=self.vector(deadline=deadline)
                self.assertIsInstance(value.error,(ValueError,TimeoutError))
                self.assertEqual([],value.opened);self.assert_closed(value)

    def test_fixed_launch_config_short_growth_identity_and_late_observations_refuse(self):
        for mutation in ('short','growth','oversized-read','held-file-drift','named-file-drift',
                         'held-directory-drift','named-directory-drift','late-open-directory','late-open-file',
                         'late-directory-fstat','late-file-fstat','late-named-file','late-read','late-growth',
                         'late-file-final','late-named-file-final','late-directory-final','late-named-directory-final',
                         'late-close-file','late-close-directory'):
            with self.subTest(mutation=mutation):
                value=self.vector(mutation)
                self.assertIsInstance(value.error,(ValueError,TimeoutError));self.assertIsNone(value.answer)
                self.assert_closed(value)
                if mutation.startswith('late-open') or mutation in ('late-directory-fstat','late-file-fstat','late-named-file'):
                    self.assertEqual([],value.reads)

    def test_fixed_launch_config_operation_and_cleanup_errors_preserve_primary_and_close_both(self):
        for mutation in ('open-directory-error','open-file-error','directory-fstat-error','file-fstat-error',
                         'named-directory-error','named-file-error','read-error','growth-error','file-final-error',
                         'named-file-final-error','directory-final-error','named-directory-final-error',
                         'close-file-error','close-directory-error','both-close-errors','read-and-close-errors'):
            with self.subTest(mutation=mutation):
                value=self.vector(mutation)
                expected=value.close_error if mutation in ('close-file-error','close-directory-error','both-close-errors') else value.injected
                self.assertIs(value.error,expected);self.assertIsNone(value.answer);self.assert_closed(value)
                if mutation=='read-and-close-errors':
                    self.assertIn('launch configuration descriptor cleanup failures: 2',value.error.__notes__)
                if mutation in ('close-file-error','close-directory-error','both-close-errors','read-and-close-errors'):
                    self.assertEqual([42,41],value.closed)

    def test_actual_finish_uses_fixed_capture_and_never_credits_refused_config(self):
        for mutation in (None,'wrong-digest','fifo','symlink-open','oversize','short','growth',
                         'held-file-drift','named-directory-drift','late-read','late-close-directory','read-and-close-errors'):
            with self.subTest(mutation=mutation):
                value=self.vector(mutation,raw=b'x'*65536 if mutation is None else b'{"fixed":true}',finish=True)
                self.assertIsNone(value.error);self.assert_closed(value)
                self.assertEqual(b'proof',value.result['workerProofRaw'])
                if mutation is None:
                    self.assertEqual('unknown',value.result['workerProof']['status'])
                    self.assertTrue(value.result['workerProof']['pinsUnchanged'])
                    self.assertEqual('exclusive-proof-write-authority-unavailable',value.result['workerProof']['reason'])
                    self.assertIsNone(value.result['exitCode'])
                    self.assertTrue(value.result['infrastructureFailure'])
                    self.assertFalse(value.result['workerExecVerified']);self.assertFalse(value.result['workerTerminationVerified'])
                    value.parser.parse_proof.assert_called_once_with(b'proof',{'phase':'runtime'})
                else:
                    self.assertEqual('unknown',value.result['workerProof']['status'])
                    self.assertFalse(value.result['workerProof']['pinsUnchanged'])
                    self.assertTrue(value.result['infrastructureFailure']);self.assertIsNone(value.result['exitCode'])
                    self.assertFalse(value.result['workerExecVerified']);self.assertFalse(value.result['workerTerminationVerified'])
                    value.parser.parse_proof.assert_not_called()


class _ReceiptInitializationFilesystem:
    """Three authored descriptors; all OS/clock/path effects stay virtual."""
    component = 'a' * 32

    def __init__(self):
        self.base=Path('/authored/receipt-resource');self.root=self.base/'exec-proof-receipts'
        self.state=runtime._ReceiptInitializationState();self.now=0.0;self.counts={};self.events=[]
        self.arguments=[];self.fds={};self.acquired=[];self.closed=[];self.fail=None;self.late=None
        self.error=OSError('authored initialization operation');self.close_errors={};self.alias=None
        self.metadata_changes={};self.clock_count=0;self.expire_clock=None;self.expired_at=None
        self.uuid_component=self.component;self.created=False;self.origin_traceback=None

    def act(self,label,value=None,*,can_fail=True):
        self.counts[label]=self.counts.get(label,0)+1;token=label+'#'+str(self.counts[label])
        self.events.append((token,self.state.stage))
        if can_fail and self.fail==token:
            try:raise self.error
            except BaseException as primary:
                self.origin_traceback=primary.__traceback__;raise
        if self.late==token:self.now=5.0;self.expired_at=len(self.events)
        return value

    def clock(self):
        self.clock_count+=1;self.events.append(('clock#'+str(self.clock_count),self.state.stage))
        if self.expire_clock==self.clock_count:
            self.now=5.0;self.expired_at=len(self.events)
        return self.now

    def metadata(self,role):
        values=dict(st_dev=7,st_ino={'root':11,'child':12,'report':13}[role],
                    st_mode=(stat.S_IFREG|0o600) if role=='report' else (stat.S_IFDIR|0o700),
                    st_uid=1000,st_size=0,st_nlink=1)
        values.update(self.metadata_changes.get(role,{}));return types.SimpleNamespace(**values)

    def mkdir_root(self,path,*,mode,exist_ok):
        self.arguments.append(('root-mkdir',path,mode,exist_ok));return self.act('root-mkdir')

    def lstat(self,path):
        assert path==self.root
        value=self.metadata('root')
        if self.metadata_changes.get('named-root') and self.counts.get('root-lstat',0):
            value=types.SimpleNamespace(**{**vars(value),**self.metadata_changes['named-root']})
        return self.act('root-lstat',value)

    def uuid(self):return self.act('uuid',types.SimpleNamespace(hex=self.uuid_component))

    def mkdir_child(self,name,mode=0o777,*,dir_fd=None):
        self.arguments.append(('child-mkdir',name,mode,dir_fd));self.act('child-mkdir');self.created=True

    def open(self,name,flags,mode=0o777,*,dir_fd=None):
        role='root' if name==self.root else 'child' if name==self.component else 'report'
        assert (role=='root' and dir_fd is None) or (role=='child' and dir_fd==101) or (
            role=='report' and name=='worker-proof.jsonl' and dir_fd==102)
        self.arguments.append(('open',role,name,flags,mode,dir_fd));self.act('open-'+role)
        descriptor={'root':101,'child':102,'report':103}[role]
        if self.alias==role:descriptor=101
        self.fds.setdefault(descriptor,role);self.acquired.append(descriptor)
        self.act('opened-'+role,can_fail=False)
        # An open-entry expiry is observable by the caller only after this call returns.
        if self.late=='open-'+role+'#'+str(self.counts['open-'+role]):
            self.expired_at=len(self.events)
        return descriptor

    def fstat(self,descriptor):
        role=self.fds[descriptor];return self.act('fstat-'+role,self.metadata(role))

    def stat(self,name,*,dir_fd,follow_symlinks):
        role='child' if name==self.component else 'report'
        assert follow_symlinks is False and dir_fd==(101 if role=='child' else 102)
        value=self.metadata(role);value=types.SimpleNamespace(**{**vars(value),**self.metadata_changes.get('named-'+role,{})})
        return self.act('named-'+role,value)

    def close(self,descriptor):
        assert descriptor in self.fds and descriptor not in self.closed
        self.closed.append(descriptor);self.fds.pop(descriptor);self.act('close-'+str(descriptor),can_fail=False)
        if descriptor in self.close_errors:raise self.close_errors[descriptor]

    def effects(self):
        stack=ExitStack();owner=self;divide=Path.__truediv__
        def joined(path,name):
            value=divide(path,name)
            if owner.state.stage==10:
                owner.act('construct-directory' if name==owner.component else 'construct-report')
            return value
        for target,name,effect in ((runtime,'BASE',self.base),(runtime.time,'monotonic',self.clock),
                (runtime.os,'open',self.open),(runtime.os,'fstat',self.fstat),(runtime.os,'stat',self.stat),
                (runtime.os,'mkdir',self.mkdir_child),(runtime.os,'close',self.close),
                (runtime.os,'getuid',lambda:self.act('getuid',1000)),(runtime.uuid,'uuid4',self.uuid),
                (Path,'mkdir',lambda path,**kwargs:self.mkdir_root(path,**kwargs)),
                (Path,'lstat',lambda path:self.lstat(path)),(Path,'__truediv__',joined)):
            stack.enter_context(patch.object(target,name,**({'new':effect} if name=='BASE' or target is Path else {'side_effect':effect})))
        for name in ('read','write','unlink','rmdir','pidfd_open','kill','killpg'):
            stack.enter_context(patch.object(runtime.os,name,side_effect=AssertionError('no extra OS operation')))
        return stack

    def create(self,*,deadline=5.0,direct=False):
        result=error=None
        with self.effects():
            try:
                result=runtime._create_worker_receipt() if direct else runtime._create_worker_receipt(
                    deadline=deadline,initialization=self.state)
            except BaseException as failure:error=failure
        return result,error


class ReceiptInitializationResources(unittest.TestCase):
    def assert_once_closed(self,value):
        self.assertEqual(len(value.closed),len(set(value.closed)))
        self.assertEqual(set(value.acquired),set(value.closed));self.assertFalse(value.fds)

    def test_receipt_factory_transfers_only_report_after_parent_closes_and_retains_none_compatibility(self):
        for deadline,direct in ((5.0,False),(None,False),(None,True)):
            with self.subTest(deadline=deadline,direct=direct):
                value=_ReceiptInitializationFilesystem();receipt,error=value.create(deadline=deadline,direct=direct)
                self.assertIsNone(error);self.assertEqual([102,101],value.closed);self.assertEqual({103:'report'},value.fds)
                self.assertEqual({'path','directory','fd','device','inode','directoryDevice','directoryInode','rootDevice','rootInode'},set(receipt))
                self.assertEqual(103,receipt['fd']);self.assertEqual((7,13),(receipt['device'],receipt['inode']))
                self.assertEqual((7,12),(receipt['directoryDevice'],receipt['directoryInode']))
                self.assertEqual((7,11),(receipt['rootDevice'],receipt['rootInode']))
                self.assertEqual(value.root/value.component/'worker-proof.jsonl',receipt['path'])
                opens=[row for row in value.arguments if row[0]=='open']
                directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
                self.assertEqual([directory_flags,directory_flags,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_RDWR],[row[3]for row in opens])
                self.assertEqual([None,101,102],[row[5]for row in opens]);self.assertEqual(0o600,opens[2][4])
                self.assertIn(('child-mkdir',value.component,0o700,101),value.arguments)
                self.assertIn(('root-mkdir',value.root,0o700,True),value.arguments)
                if not direct:
                    self.assertEqual(7,value.state.acquired);self.assertEqual(3,value.state.succeeded)
                    self.assertEqual(4,value.state.transferred);self.assertTrue(value.state.discharged())
                    self.assertFalse(any(stage==13 for _,stage in value.events))
                if deadline is None:self.assertEqual(0,value.clock_count)
                value.close(103);self.assert_once_closed(value)

    def test_receipt_factory_each_fallible_operation_closes_acquired_only_and_preserves_exact_primary(self):
        baseline=_ReceiptInitializationFilesystem();receipt,error=baseline.create();self.assertIsNone(error)
        tokens=[token for token,_ in baseline.events if not token.startswith(('clock#','opened-','close-'))]
        for token in tokens:
            with self.subTest(operation=token):
                value=_ReceiptInitializationFilesystem();value.fail=token;receipt,error=value.create()
                self.assertIsNone(receipt);self.assertIs(value.error,error);self.assert_once_closed(value)
                self.assertEqual(list(reversed(value.acquired)),value.closed)
                traceback=error.__traceback__
                while traceback.tb_next is not None:traceback=traceback.tb_next
                self.assertEqual('act',traceback.tb_frame.f_code.co_name)
                self.assertIs(value.origin_traceback,traceback)
        for role,changes in (('root',{'st_mode':stat.S_IFLNK|0o700}),('root',{'st_uid':99}),
                ('child',{'st_mode':stat.S_IFDIR|0o755}),('child',{'st_uid':99}),
                ('report',{'st_mode':stat.S_IFIFO|0o600}),('report',{'st_mode':stat.S_IFREG|0o644}),
                ('report',{'st_uid':99}),('report',{'st_size':1}),('report',{'st_nlink':2})):
            with self.subTest(role=role,changes=changes):
                value=_ReceiptInitializationFilesystem();value.metadata_changes[role]=changes
                receipt,error=value.create();self.assertIsNone(receipt);self.assertIsInstance(error,ValueError);self.assert_once_closed(value)
        value=_ReceiptInitializationFilesystem();value.fail='open-report#1';value.error=OSError(24,'authored EMFILE')
        receipt,error=value.create();self.assertIs(value.error,error);self.assertEqual([102,101],value.closed)
        self.assertTrue(value.state.mkdir_returned);self.assertEqual(3,value.state.acquired)
        for component in ('A'*32,'a'*31,'../escape',None):
            value=_ReceiptInitializationFilesystem();value.uuid_component=component
            receipt,error=value.create();self.assertIsNone(receipt);self.assertIsInstance(error,ValueError)
            self.assertFalse(value.created);self.assert_once_closed(value)
        value=_ReceiptInitializationFilesystem();value.fail='child-mkdir#1';value.error=FileExistsError('authored collision')
        receipt,error=value.create();self.assertIs(value.error,error);self.assertFalse(value.state.mkdir_returned)
        self.assertEqual([101],value.acquired);self.assert_once_closed(value)

    def test_receipt_factory_unique_once_close_uncertainty_and_denied_annotations_keep_primary(self):
        class Denied(Exception):
            __notes__=object()
            def __setattr__(self,name,value):raise MemoryError('annotation denied')
            def __eq__(self,other):raise AssertionError('no exception equality')
            def __bool__(self):raise AssertionError('no exception truthiness')
            def __str__(self):raise AssertionError('no exception text')
            def add_note(self,*args):raise MemoryError('notes denied')
        for mask in range(1,8):
            with self.subTest(closeMask=mask):
                value=_ReceiptInitializationFilesystem();primary=Denied();secondary=KeyboardInterrupt()
                value.fail='fstat-report#1';value.error=primary
                value.close_errors={fd:secondary for bit,fd in enumerate((101,102,103))if mask&(1<<bit)}
                receipt,error=value.create();self.assertIsNone(receipt);self.assertIs(primary,error)
                self.assertEqual([103,102,101],value.closed);self.assert_once_closed(value)
                self.assertEqual(7,value.state.attempted);self.assertEqual(7^mask,value.state.succeeded)
                self.assertFalse(value.state.discharged());self.assertTrue(value.state.facts()['closeUncertain'])
        for errors in ((101,),(102,),(101,102),(101,102,103)):
            value=_ReceiptInitializationFilesystem();same=Denied();value.close_errors={fd:same for fd in errors}
            receipt,error=value.create();self.assertIsNone(receipt);self.assertIs(same,error);self.assert_once_closed(value)
            self.assertEqual(0,value.state.transferred);self.assertFalse(value.state.discharged())
        for alias in ('child','report'):
            value=_ReceiptInitializationFilesystem();value.alias=alias
            receipt,error=value.create();self.assertIsNone(receipt);self.assertIsInstance(error,ValueError)
            self.assertTrue(value.state.alias_uncertain);self.assertFalse(value.state.discharged())
            self.assert_once_closed(value)

    def test_receipt_factory_original_end_refuses_each_late_observation_and_still_closes_once(self):
        baseline=_ReceiptInitializationFilesystem();receipt,error=baseline.create();self.assertIsNone(error)
        tokens=[token for token,_ in baseline.events if not token.startswith('clock#')]
        vectors=[('operation',token)for token in tokens]+[('clock',number)for number in range(1,baseline.clock_count+1)]
        for kind,point in vectors:
            with self.subTest(kind=kind,point=point):
                value=_ReceiptInitializationFilesystem()
                if kind=='operation':value.late=point
                else:value.expire_clock=point
                receipt,error=value.create();self.assertIsNone(receipt);self.assertIsInstance(error,TimeoutError)
                self.assertEqual(0,value.state.transferred);self.assert_once_closed(value)
                self.assertEqual(value.state.acquired,value.state.succeeded)
                self.assertTrue(value.state.discharged());self.assertFalse(value.state.facts()['closeUncertain'])
                self.assertTrue(all(token.startswith(('clock#','close-'))for token,_ in value.events[value.expired_at:]))
        for deadline in (True,float('nan'),float('inf'),'5'):
            value=_ReceiptInitializationFilesystem();receipt,error=value.create(deadline=deadline)
            self.assertIsNone(receipt);self.assertIsInstance(error,ValueError);self.assertFalse(value.acquired)

    def test_receipt_factory_namespace_observations_never_authorize_partial_name_deletion(self):
        for role in ('named-root','named-child','named-report'):
            value=_ReceiptInitializationFilesystem();value.metadata_changes[role]={'st_ino':99}
            receipt,error=value.create();self.assertIsNone(receipt);self.assertIsInstance(error,ValueError)
            self.assert_once_closed(value);self.assertEqual('retained',value.state.facts()['status'])
        # Matching replacement/ABA observations are not original mkdir-inode proof.
        # The resource path may return, but grants no removal/creation chronology fact.
        value=_ReceiptInitializationFilesystem();value.metadata_changes['child']={'st_ino':99}
        receipt,error=value.create();self.assertIsNone(error);self.assertEqual(99,receipt['directoryInode'])
        facts=value.state.facts();self.assertEqual('retained',facts['status']);self.assertTrue(facts['mkdirReturned'])
        self.assertNotIn('createdInodeAuthenticated',facts);self.assertNotIn('namespaceRemoved',facts)
        value.close(103);self.assert_once_closed(value)

    def test_actual_runner_reads_owned_initialization_state_despite_denied_facts_and_bounded_result(self):
        class Denied(Exception):
            def __setattr__(self,name,value):raise MemoryError('all annotations denied')
        for close_uncertain,deny_facts,prelaunch in ((True,False,False),(True,True,False),
                (False,False,False),(False,True,False),(False,False,True)):
            with self.subTest(closeUncertain=close_uncertain,denyFacts=deny_facts,prelaunch=prelaunch):
                value=_ReceiptInitializationFilesystem();primary=Denied();observed=[];states=[];ends=[]
                if not prelaunch:value.fail='fstat-report#1';value.error=primary
                if close_uncertain:value.close_errors[103]=OSError('authored uncertain report close')
                factory=runtime._create_worker_receipt;finish=runtime._finish_worker_proof
                def actual_factory(*,deadline,initialization):
                    states.append(initialization);ends.append(deadline);value.state=initialization
                    return factory(deadline=deadline,initialization=initialization)
                def actual_finish(result,*args,**kwargs):
                    observed.append(result);answer=finish(result,*args,**kwargs)
                    if close_uncertain and deny_facts:
                        # Adversarial later mutable observation cannot restore credit;
                        # the REAL early proof body still ran, and no proof is fabricated.
                        result['cleanupVerified']=True
                    return answer
                def refused_prepare(*args,**kwargs):
                    try:raise primary
                    except Denied as error:
                        value.origin_traceback=error.__traceback__;raise
                bounds={'supervisor':{},'wallSeconds':5.0,'outputBytesPerStream':1024}
                with value.effects(),ExitStack() as effects:
                    effects.enter_context(patch.object(runtime,'_work_directory',return_value=Path('/authored/work')))
                    effects.enter_context(patch.object(runtime,'_worker_environment'))
                    effects.enter_context(patch.object(runtime,'_create_worker_receipt',side_effect=actual_factory))
                    effects.enter_context(patch.object(runtime,'_finish_worker_proof',side_effect=actual_finish))
                    prepare=effects.enter_context(patch.object(runtime,'_prepare_launch',side_effect=refused_prepare))
                    for target,name in ((runtime.subprocess,'Popen'),(runtime,'process_identity'),(runtime,'owned_processes'),
                            (runtime,'scope_processes'),(runtime,'_kill_owned_scope'),(runtime,'_kill_launcher'),
                            (runtime.selectors,'DefaultSelector')):
                        effects.enter_context(patch.object(target,name,side_effect=AssertionError('no launch/query/cleanup authority')))
                    if deny_facts:effects.enter_context(patch.object(runtime._ReceiptInitializationState,'facts',side_effect=MemoryError('facts denied')))
                    caught=caught_traceback=None
                    try:runtime._run_scoped(['NOT-EXECUTED'],Path('/authored/work'),{},b'',bounds,provisioning=False)
                    except Denied as error:caught=error;caught_traceback=error.__traceback__
                self.assertIs(primary,caught);self.assertIsNotNone(caught_traceback)
                while caught_traceback.tb_next is not None:caught_traceback=caught_traceback.tb_next
                self.assertIs(value.origin_traceback,caught_traceback)
                self.assertEqual([5.0],ends);self.assertEqual(1,len(states))
                self.assertIs(value.state,states[0]);self.assertEqual(1,len(observed));result=observed[0]
                self.assertEqual(close_uncertain is False,result['cleanupVerified']);self.assertTrue(result['finalAbsenceVerified'])
                self.assertTrue(result['infrastructureFailure']);self.assertFalse(result['rootReaped']);self.assertIsNone(result['kernelScope'])
                self.assertFalse(result['workerExecVerified']);self.assertFalse(result['workerTerminationVerified']);self.assertIsNone(result['exitCode'])
                self.assertEqual('unknown',result['workerProof']['status']);self.assertEqual('launch-not-prepared',result['workerProof']['reason'])
                self.assertEqual('retained',result['_receiptCleanup']['status']);self.assertNotIn('removed',result['_receiptCleanup'])
                self.assert_once_closed(value)
                if close_uncertain:self.assertEqual('receipt-initialization-close-unverified',result['infrastructureReason'])
                if prelaunch:
                    self.assertEqual(4,value.state.transferred);self.assertTrue(value.state.discharged())
                    self.assertEqual([102,101,103],value.closed);prepare.assert_called_once()
                else:
                    self.assertEqual(0,value.state.transferred);self.assertEqual([103,102,101],value.closed);prepare.assert_not_called()


if __name__=='__main__':unittest.main()
