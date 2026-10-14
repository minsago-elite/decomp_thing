"""Pure gate/recipe/provisioning controls; no native execution or host policy changes."""
import ast
from contextlib import ExitStack
import hashlib
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
            with patch.object(runtime,'_snapshot_library',return_value=(snapshot,None)),patch.object(runtime,'process_identity',return_value={'start':1}),patch.object(runtime,'load_worker_monitor_binding',return_value=binding),patch.object(runtime,'_nonprivileged_executable',side_effect=identity),patch.object(runtime,'_pin_files',return_value={}):
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
        fifo=types.SimpleNamespace(st_mode=stat.S_IFIFO|0o600)
        with patch.object(runtime.os,'open',return_value=123) as opened,patch.object(runtime.os,'fstat',return_value=fifo),patch.object(runtime.os,'close'),patch.object(runtime.os,'read',side_effect=AssertionError('special file payload must not be read')):
            with self.assertRaises(ValueError):runtime._pin_files([self.input])
            with self.assertRaises(ValueError):runtime._nonprivileged_executable(self.input)
        flags=opened.call_args.args[1]
        self.assertTrue(flags&os.O_NONBLOCK);self.assertTrue(flags&os.O_NOFOLLOW)
        empty=self.work/'empty';empty.write_bytes(b'')
        with patch.object(runtime.os,'open',side_effect=AssertionError('whole batch must be admitted before any payload open')):
            with self.assertRaises(ValueError):runtime._pin_files([self.input,empty])
        with patch.object(runtime.os,'open',side_effect=AssertionError('expired deadline must refuse before open')):
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
        payload=b'authored immutable bytes'
        library={'device':91,'inode':92,'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'sourcePath':'/authored/library.so'}
        record={'ownerPid':123,'ownerStart':77,'descriptor':9,'library':library}
        fields=['0']*20;fields[19]='77'
        metadata=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_dev=91,st_ino=92,st_size=len(payload))
        with patch.object(Path,'read_text',return_value='123 (controller) '+' '.join(fields)),patch.object(gate.os,'open',return_value=10) as opened,patch.object(gate.os,'fstat',return_value=metadata),patch.object(gate.fcntl,'fcntl',return_value=runtime._SEALED_LIBRARY) as seals,patch.object(gate.os,'read',return_value=payload) as read,patch.object(gate.os,'lseek'),patch.object(gate.os,'dup2') as duplicate,patch.object(gate.os,'set_inheritable') as inherit,patch.object(gate.os,'close') as close:
            gate._acquire_library_snapshot(record,1024)
            opened.assert_called_once_with('/proc/123/fd/9',gate.os.O_RDONLY|gate.os.O_NONBLOCK|gate.os.O_CLOEXEC)
            duplicate.assert_called_once_with(10,5,inheritable=True);inherit.assert_called_once_with(5,True)
            close.assert_called_once_with(10)
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

    def test_gate_opens_report_only_after_admission_and_explicitly_hands_fd4(self):
        gate=types.ModuleType('_pure_optimized_scope_gate')
        gate.__file__=str(SOURCE/'scope_gate.py')
        exec(compile((SOURCE/'scope_gate.py').read_bytes(),gate.__file__,'exec',optimize=2),gate.__dict__)
        directory=SOURCE/'exec-proof-receipts'/('a'*32)
        events=[]
        config={'schemaVersion':1,'directoryDevice':10,'directoryInode':11,'mode':'worker',
                'argv':['/usr/bin/bwrap','mock-only'],'report':{'device':20,'inode':21},
                'outerPidNsDevice':30,'outerPidNsInode':31}
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
        with patch.object(gate.sys,'argv',['scope_gate.py',str(directory)]),patch.object(gate.sys,'flags',types.SimpleNamespace(isolated=True)),patch.object(gate.sys,'dont_write_bytecode',True),patch.object(gate.sys,'pycache_prefix',str(directory/'python-cache')),patch.object(gate,'_contract',return_value=build_contract.load_profile()),patch.object(gate,'_read_at',side_effect=read_at),patch.object(gate.os,'open',side_effect=opened),patch.object(gate.os,'fstat',side_effect=[dir_stat,report_stat]),patch.object(gate.os,'close'),patch.object(gate.os,'write',side_effect=lambda fd,raw:len(raw)),patch.object(gate.os,'rename'),patch.object(gate.os,'getpid',return_value=12),patch.object(gate.resource,'getrlimit',return_value=(64,64)),patch.object(Path,'read_text',proc_text),patch.object(Path,'stat',return_value=types.SimpleNamespace(st_dev=30,st_ino=31)),patch.object(gate.os,'dup2') as duplicate,patch.object(gate.os,'set_inheritable') as inherit,patch.object(gate,'_close_nonstandard') as close,patch.object(gate.os,'execv',side_effect=RuntimeError('mocked exec blocked')) as execute:
            with self.assertRaisesRegex(RuntimeError,'mocked exec blocked'):gate.main()
        report=next(i for i,event in enumerate(events) if event[:2]==('open','worker-proof.jsonl'))
        admitted=events.index(('read','admit'))
        self.assertGreater(report,admitted)
        flags=events[report][2]
        self.assertTrue(flags & os.O_NOFOLLOW);self.assertTrue(flags & os.O_APPEND)
        duplicate.assert_called_once_with(11,4,inheritable=True);inherit.assert_called_once_with(4,True)
        close.assert_called_once_with({4});execute.assert_called_once_with('/usr/bin/bwrap',config['argv'])

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
        cases=(None,'start','record','unit','pids.max','memory.max','memory.swap.max','acquired','membership','short-write')
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
                with patch.dict(namespace,{'_read_private_json':lambda p:dict(gate),
                                           'process_identity':lambda pid:dict(child,start=999) if mutation=='start' else dict(child)}), \
                        patch.object(Path,'exists',return_value=True),patch.object(Path,'resolve',lambda p,*a,**k:p), \
                        patch.object(Path,'read_text',text),patch.object(Path,'stat',return_value=metadata), \
                        patch.object(runtime.os,'open',side_effect=opened),patch.object(runtime.os,'fstat',return_value=metadata), \
                        patch.object(runtime.os,'read',side_effect=read),patch.object(runtime.os,'close'), \
                        patch.object(runtime.os,'write',return_value=1 if mutation=='short-write' else 2) as write, \
                        patch.object(runtime.os,'replace') as publish:
                    if mutation is None:
                        self.assertEqual(unit,admit({'directory':self.work},launch,bounds)['unit'])
                        write.assert_called_once();publish.assert_called_once()
                    else:
                        with self.assertRaises(ValueError):admit({'directory':self.work},launch,bounds)
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
            for name in ('launch.json','gate.json','admit'):runtime.write_json(receipt['directory']/name,{})
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
        for mutation in (None,'absence','report-close','delete','capture','prelaunch'):
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
                launch={'argv':['authored never executed'],'unit':'authored.scope',
                        'expected':authored['workerProofBindings']['expected'],'pins':pins,
                        'proofBinding':authored['workerProofBindings'],
                        'configSha256':runtime.digest(receipt['directory']/'launch.json')}
                def closed(fd):
                    events.append(('close',fd))
                    if fd==report_fd and mutation=='report-close':raise OSError('authored report close refusal')
                    if fd not in (111,112):real_close(fd)
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
                scope={'_directoryFd':112,'unit':'authored.scope'}
                with ExitStack() as effects:
                    for effect in (
                        patch.object(runtime,'BASE',base),patch.object(runtime,'_work_directory',return_value=self.work),
                        patch.object(runtime,'_worker_environment'),patch.object(runtime,'_create_worker_receipt',return_value=receipt),
                        patch.object(runtime,'_prepare_launch',side_effect=prepare),patch.object(runtime.subprocess,'Popen',return_value=process),
                        patch.object(runtime.os,'pidfd_open',return_value=111),patch.object(runtime,'process_identity',return_value={'start':1}),
                        patch.object(runtime.selectors,'DefaultSelector',side_effect=Selector),patch.object(runtime.os,'set_blocking'),
                        patch.object(runtime,'_admit_scope',return_value=scope),patch.object(runtime,'_kill_owned_scope'),
                        patch.object(runtime,'_kill_launcher'),patch.object(runtime,'scope_processes',return_value=[]),
                        patch.object(runtime,'owned_processes',side_effect=ValueError('authored absence refusal') if mutation=='absence' else lambda *a:[]),
                        patch.object(runtime,'_pin_files',return_value=pins),patch.object(runtime.os,'close',side_effect=closed),
                        patch.object(runtime.os,'read',side_effect=lambda fd,n:b'' if fd in (901,902) else real_read(fd,n)),
                        patch.object(runtime,'_reclaim_worker_receipt',side_effect=reclaim if mutation not in ('report-close','absence','prelaunch') else real_reclaim)
                    ):effects.enter_context(effect)
                    try:
                        result=runtime._run_scoped(['authored'],self.work,self.env,b'',
                            runtime.execution_bounds(managed_scope=True,phase='runtime'),provisioning=False)
                    except (ValueError,OSError) as error:
                        result=error.bounded_result
                        if mutation in ('capture','prelaunch'):
                            self.assertIn('original '+mutation,str(error))
                        elif mutation=='delete':
                            self.assertEqual('owned receipt directory reclamation failed',str(error))
                        elif mutation not in ('absence','report-close'):raise
                if mutation is None:
                    self.assertEqual('removed',result['_receiptCleanup']['status'])
                    self.assertFalse(receipt['directory'].exists());self.assertTrue(runtime.worker_execution_complete(result))
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


if __name__=='__main__':unittest.main()
