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
        binding={'binaryPath':str(monitor),'dependencies':[],**{name:'0'*64 for name in
            ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','parserSha256','manifestSha256')}}
        def executable(path,deadline=None):
            device,inode=(3,4) if str(path)=='/usr/bin/bwrap' else (11,12) if path==monitor else (7,8)
            return {'path':str(path),'device':device,'inode':inode,'mode':0o500,'sha256':'0'*64}
        for provisioning in (False,True):
            for mutation in (None,'missing','wrong','rekeyed'):
                with self.subTest(provisioning=provisioning,mutation=mutation):
                    pins={key:{'device':70,'inode':71,'mode':0o400,'sha256':profile_sha}}
                    if mutation=='missing':pins.clear()
                    if mutation=='wrong':pins[key]['sha256']='f'*64
                    if mutation=='rekeyed':pins['/authored/other-profile.json']=pins.pop(key)
                    receipt={'directory':Path('/authored')/('a'*32),'directoryDevice':1,'directoryInode':2,'device':1,'inode':3}
                    with ExitStack() as effects:
                        for target_object,name,effect in ((Path,'stat',lambda *a,**k:types.SimpleNamespace(st_dev=5,st_ino=6)),
                                (Path,'lstat',lambda *a,**k:types.SimpleNamespace(st_dev=1,st_ino=2)),
                                (runtime,'_contained_recipe',lambda *a:recipe),(runtime,'load_worker_monitor_binding',lambda:binding),
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
                     **{key:'0'*64 for key in ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','parserSha256','manifestSha256')}}
            identity=lambda p,deadline=None:{'path':str(p),'device':7,'inode':8,'mode':0o755,'sha256':'0'*64}
            receipt['librarySnapshotFd']=5  # mocked descriptor; never opened/closed by this preparation-only control
            snapshot={'device':51,'inode':52,'size':3,'sha256':'0'*64,'sourcePath':str(library)}
            profile_pins={str(base/'contracts/candidate-build-profile.json'):{'device':70,'inode':71,'mode':0o400,'sha256':runtime.load_profile_with_digest()[1]}}
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
        with patch.object(gate,'_contract',return_value=declared_profile),patch.object(Path,'read_text',return_value='123 (controller) '+' '.join(fields)),patch.object(gate.os,'open',return_value=10) as opened,patch.object(gate.os,'fstat',return_value=metadata),patch.object(gate.fcntl,'fcntl',return_value=runtime._SEALED_LIBRARY) as seals,patch.object(gate.os,'read',return_value=payload) as read,patch.object(gate.os,'lseek'),patch.object(gate.os,'dup2') as duplicate,patch.object(gate.os,'set_inheritable') as inherit,patch.object(gate.os,'close') as close:
            gate._acquire_library_snapshot(record,1024)
            opened.assert_called_once_with('/proc/123/fd/9',gate.os.O_RDONLY|gate.os.O_NONBLOCK|gate.os.O_CLOEXEC)
            duplicate.assert_called_once_with(10,5,inheritable=True);inherit.assert_called_once_with(5,True)
            close.assert_called_once_with(10)
            # Parent FD lives in controller table, independent of child FD5/64-FD policy.
            record['descriptor']=4096
            gate._acquire_library_snapshot(record,1024)
            self.assertEqual('/proc/123/fd/4096',opened.call_args.args[0])
            for invalid in (-1,True,1<<31,'4096'):
                record['descriptor']=invalid
                with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024)
            record['descriptor']=9
            for wrong in (0,runtime._SEALED_LIBRARY & ~gate.fcntl.F_SEAL_WRITE):
                seals.return_value=wrong
                with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024)
            seals.return_value=runtime._SEALED_LIBRARY
            read.return_value=b'wrong content'.ljust(len(payload),b'!')
            with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024)
            record['ownerStart']=78
            with self.assertRaises(ValueError):gate._acquire_library_snapshot(record,1024)

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
        with patch.object(runtime,'_fixed_source_module',return_value=loader):
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
                 **{key:'0'*64 for key in ('environmentPinSha256','binarySha256','sourceSha256','protocolSha256','parserSha256','manifestSha256')}}
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
        with patch.object(runtime,'BASE',base):facts=runtime._reclaim_worker_receipt(receipt,result)
        self.assertEqual('removed',facts['status']);self.assertFalse(receipt['directory'].exists())
        self.assertEqual(before,result);self.assertTrue((base/'exec-proof-receipts').is_dir())
        self.assertEqual(before['workerProofRaw'],result['workerProofRaw'])

    def test_fixed_provisioning_receipt_needs_complete_controller_without_worker_proof(self):
        for complete in (True,False):
            base,receipt,result=self.receipt_fixture();receipt['path'].unlink()
            result.update(provisioningOnly=True,workerProof=None,workerProofRaw=b'',workerProofBindings=None,
                          workerExecVerified=False,workerTerminationVerified=False,captureComplete=complete)
            with patch.object(runtime,'BASE',base):
                facts=runtime._reclaim_worker_receipt(receipt,result,provisioning=True)
            self.assertEqual('removed' if complete else 'retained',facts['status'])
            self.assertEqual(not complete,receipt['directory'].exists())
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
        with patch.object(runtime,'BASE',base),patch.object(runtime.os,'unlink',side_effect=OSError('authored deletion error')):
            facts=runtime._reclaim_worker_receipt(receipt,result)
        self.assertEqual('refused',facts['status']);self.assertIn('OSError',facts['secondaryError'])
        self.assertTrue(receipt['directory'].exists());self.assertEqual(raw,result['workerProofRaw'])

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
                    self.assertEqual('removed',result['_receiptCleanup']['status'])
                    self.assertFalse(receipt['directory'].exists())
                    with patch.object(runtime,'BASE',base):
                        self.assertTrue(runtime.worker_execution_complete(result))
                else:
                    self.assertTrue(receipt['directory'].exists());self.assertNotEqual('removed',result['_receiptCleanup']['status'])
                if mutation not in ('prelaunch','absence'):
                    self.assertEqual(authored['workerProofRaw'],result['workerProofRaw'])
                elif mutation=='absence':
                    self.assertEqual(b'',result['workerProofRaw'])
                    self.assertEqual(authored['workerProofRaw'],receipt['path'].read_bytes())
                if mutation=='delete':
                    self.assertTrue(result['cleanupVerified']);self.assertTrue(result['workerTerminationVerified'])
                    self.assertTrue(result['infrastructureFailure']);self.assertIn('secondaryError',result['_receiptCleanup'])
                self.assertNotIn('_receiptCleanup',runtime.public_result(result))


    def cleanup_runner_vector(self, *, cgroup_error=None, launcher_error=None, primary=None,
                              invalid_scope=False, clock_case=None):
        # Actual runner, final-proof refusal and receipt retention; only external
        # process/kernel/clock interfaces are authored. No child, scope or real FD.
        events=[]; now=[100.0]; saved_primary_traceback=[]; cleanup_time=[]
        bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
        receipt={'directory':self.directory/'never-launched-receipt','fd':114}
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
        with ExitStack() as effects:
            for effect in (
                patch.object(runtime,'_work_directory',return_value=self.work),patch.object(runtime,'_worker_environment'),
                patch.object(runtime,'_create_worker_receipt',return_value=receipt),patch.object(runtime,'_prepare_launch',return_value=launch),
                patch.object(runtime.subprocess,'Popen',return_value=process),patch.object(runtime.os,'pidfd_open',return_value=111),
                patch.object(runtime,'process_identity',return_value={'start':1}),patch.object(runtime.selectors,'DefaultSelector',side_effect=Selector),
                patch.object(runtime.os,'set_blocking'),patch.object(runtime.os,'read',return_value=b''),
                patch.object(runtime.os,'close',side_effect=lambda fd:events.append(('close-fd',fd))),
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
        self.assertEqual([111,112,113,114],[value for name,value in events if name=='close-fd'])
        self.assertEqual([900,900,901,902],[value for name,value in events if name=='close-stream'])
        self.assertNotIn('cleanupFailure',runtime.public_result(result))
        self.assertNotIn('secondaryCleanupFailures',runtime.public_result(result))
        return types.SimpleNamespace(error=caught,result=result,events=events,bounds=bounds,scope_error=scope_error,
            traceback=caught_traceback,primary_traceback=saved_primary_traceback,cleanup_time=cleanup_time)

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
            stack.enter_context(patch.object(runtime,'_fixed_source_module',return_value=parser))
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
                    self.assertEqual('verified',value.result['workerProof']['status'])
                    self.assertTrue(value.result['workerProof']['pinsUnchanged'])
                    self.assertEqual(0,value.result['exitCode'])
                    value.parser.parse_proof.assert_called_once_with(b'proof',{'phase':'runtime'})
                else:
                    self.assertEqual('unknown',value.result['workerProof']['status'])
                    self.assertFalse(value.result['workerProof']['pinsUnchanged'])
                    self.assertTrue(value.result['infrastructureFailure']);self.assertIsNone(value.result['exitCode'])
                    self.assertFalse(value.result['workerExecVerified']);self.assertFalse(value.result['workerTerminationVerified'])
                    value.parser.parse_proof.assert_not_called()


if __name__=='__main__':unittest.main()
