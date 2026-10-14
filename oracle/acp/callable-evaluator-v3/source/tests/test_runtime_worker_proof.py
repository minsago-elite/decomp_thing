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

    def test_prepare_inserts_only_fixed_monitor_before_root_remount_and_no_fd_forwarding(self):
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
            with patch.object(runtime,'load_worker_monitor_binding',return_value=binding),patch.object(runtime,'_nonprivileged_executable',side_effect=identity),patch.object(runtime,'_pin_files',return_value={}):
                launch=runtime._prepare_launch(runtime_command(helper,library,2),self.work,
                                               runtime.execution_bounds(managed_scope=True,phase='runtime'),receipt,False)
            self.assertIn('-I',launch['argv']);self.assertIn('-B',launch['argv'])
            self.assertIn('pycache_prefix='+str(receipt['directory']/'python-cache'),launch['argv'])
            command=launch['command']; monitor_at=command.index('/_worker_exec_monitor')
            root_at=next(i for i in range(len(command)-1) if command[i:i+2]==['--remount-ro','/'])
            self.assertLess(monitor_at,root_at)
            self.assertEqual(['/caller','/library.so','2'],command[-3:])
            self.assertEqual(1,command.count('--report-fd'));self.assertNotIn('--preserve-fds',command)
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
                    runtime.execution_bounds(managed_scope=True,phase='runtime'),receipt,False)
            pins=launch['pins'];self.assertIn(library,received)
            self.assertEqual(runtime.digest(library),pins[str(library)]['sha256'])
            inputs={'caller':{'path':str(caller),'sha256':runtime.digest(caller)},'library':{'path':str(library),'sha256':runtime.digest(library)}}
            bounds=runtime.execution_bounds(managed_scope=True,phase='runtime')
            process={'profileSha256':bounds['profileSha256'],'launchInputPins':pins,'workerProofBindings':launch['proofBinding']}
            consumer._bound_runtime_inputs(process,inputs,bounds['profileSha256'],
                                           admitted_pins=real_pin_reader([caller,library]))
            receipt2=runtime._create_worker_receipt();self.addCleanup(os.close,receipt2['fd'])
            command=runtime.contained_command([str(caller),str(source),str(header)],self.work,
                         read_only_files=(caller,source,header),environment=self.env)
            launch2=runtime._prepare_launch(command,self.work,bounds,receipt2,False)
            for file in (caller,source,header):
                self.assertIn(file,received);self.assertEqual(runtime.digest(file),launch2['pins'][str(file)]['sha256'])
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
        gate=runtime._fixed_source_module(SOURCE/'scope_gate.py','_pure_scope_gate')
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


if __name__=='__main__':unittest.main()
