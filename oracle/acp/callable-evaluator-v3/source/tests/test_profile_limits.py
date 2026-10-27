"""Static/mock-only profile/runtime controls. Never launch tools or change host resource limits."""
import ast
import copy
import io
import hashlib
import os
import stat
import json
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, Mock

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
import build_contract as contract
import bounded_runtime as runtime

_READ_OWNED_FILE = os.read

TEMP = SOURCE.parents[3] / 'build/acp-decomp-effectiveness/callable-library-v3/static-profile/test-tmp'
TEMP.mkdir(parents=True, exist_ok=True)


class Stream(io.BytesIO):
    def __init__(self, descriptor):
        super().__init__(); self.descriptor = descriptor
    def fileno(self):
        return self.descriptor


class Process:
    pid = 123
    def __init__(self, code=7):
        # Synthetic stream labels cannot collide with descriptors opened for
        # actual repository-owned receipt files during final consumption.
        self.stdin = Stream(100012); self.stdout = Stream(100010); self.stderr = Stream(100011)
        self.code = code; self.waits = []; self.returncode = None; self.wait_hook = None
    def wait(self, timeout):
        self.waits.append(timeout)
        if self.wait_hook is not None:self.wait_hook(len(self.waits),timeout)
        self.returncode = self.code; return self.code


class Selector:
    def __init__(self):
        self.keys = {}
    def register(self, stream, events, data):
        self.keys[stream.fileno()] = types.SimpleNamespace(fileobj=stream, data=data)
    def get_map(self):
        return self.keys
    def select(self, timeout):
        return [(key, 0) for key in list(self.keys.values())]
    def unregister(self, stream):
        self.keys.pop(stream.fileno())
    def close(self):
        pass


class ProfileLimits(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack(); self.addCleanup(self.guards.close)
        for name in ['Popen','run','call','check_call','check_output']:
            self.guards.enter_context(patch('subprocess.' + name, side_effect=AssertionError('static test forbids subprocess')))
        self.guards.enter_context(patch.object(runtime.resource, 'setrlimit', side_effect=AssertionError('static test forbids host policy')))
        self.guards.enter_context(patch.object(runtime.os, 'pidfd_open', side_effect=AssertionError('static test forbids pidfd')))
        self.guards.enter_context(patch.object(runtime, 'kill_exact', side_effect=AssertionError('static test forbids signals')))

    def retained_digest_vector(self, mutation=None, *, primary=None, close_error=None, deadline=10.0):
        # Actual shared reader/hash, with only metadata/FD/clock operations modeled.
        events=[];now=[0.0];payload=b'authored';offset=[0];fstats={};stats={};tracebacks=[]
        def metadata(kind,inode,size=0,stamp=1):
            return types.SimpleNamespace(st_dev=7,st_ino=inode,st_mode=kind|0o500,
                st_uid=9,st_gid=9,st_nlink=1,st_size=size,st_mtime_ns=stamp,st_ctime_ns=stamp)
        if mutation=='empty':payload=b''
        root=metadata(stat.S_IFDIR,1);parent=metadata(stat.S_IFDIR,2)
        leaf=metadata(stat.S_IFREG,3,len(payload))
        if mutation in ('fifo','device','directory','link'):
            leaf.st_mode={'fifo':stat.S_IFIFO,'device':stat.S_IFCHR,'directory':stat.S_IFDIR,'link':stat.S_IFLNK}[mutation]|0o500
        if mutation=='oversize':leaf.st_size+=1
        def opened(name,flags,**kwargs):
            events.append(('open',name,flags,kwargs))
            if mutation=='open-'+name:raise OSError('authored nofollow open refusal')
            fd={'/':101,'authored':102,'input':103}[name]
            if mutation=='late-open' and name=='/':now[0]=10.0
            return fd
        def fstat(fd):
            events.append(('fstat',fd));fstats[fd]=fstats.get(fd,0)+1
            if mutation=='fstat-error' and fd==103:raise primary
            if mutation=='descriptor-drift' and fd==103 and fstats[fd]>1:return metadata(stat.S_IFREG,4,len(payload))
            if mutation=='overwrite' and fd==103 and fstats[fd]>1:return metadata(stat.S_IFREG,3,len(payload),2)
            if mutation=='held-parent' and fd==102 and fstats[fd]>1:return metadata(stat.S_IFDIR,4)
            return {101:root,102:parent,103:leaf}[fd]
        def named(name,**kwargs):
            events.append(('stat',name,kwargs));stats[name]=stats.get(name,0)+1
            if mutation=='stat-error' and name=='input':raise primary
            if mutation=='path-drift' and name=='input' and stats[name]>1:return metadata(stat.S_IFREG,4,len(payload))
            if mutation=='named-parent' and name=='authored' and stats[name]>1:return metadata(stat.S_IFDIR,4)
            return {'/':root,'authored':parent,'input':leaf}[name]
        def read(fd,count):
            events.append(('read',fd,count));self.assertEqual(103,fd)
            if primary is not None and mutation not in ('fstat-error','stat-error'):raise primary
            if mutation=='late-read':now[0]=10.0
            data=payload[:-1] if mutation=='short' else payload+b'X' if mutation=='growth' else payload
            take=min(count,3) if mutation=='partial' else count
            result=data[offset[0]:offset[0]+take];offset[0]+=len(result);return result
        def closed(fd):
            events.append(('close',fd))
            if fd==103 and primary is not None:tracebacks.append(primary.__traceback__)
            if mutation=='late-close':now[0]=10.0
            if fd==103 and close_error is not None:raise close_error
        original_hash=hashlib.sha256
        def hashed(raw):
            events.append(('hash',raw))
            if mutation=='late-hash':now[0]=10.0
            return original_hash(raw)
        answer=caught=None
        with patch.object(contract.os,'open',side_effect=opened),patch.object(contract.os,'fstat',side_effect=fstat), \
                patch.object(contract.os,'stat',side_effect=named),patch.object(contract.os,'read',side_effect=read), \
                patch.object(contract.os,'close',side_effect=closed),patch.object(contract.time,'monotonic',side_effect=lambda:now[0]), \
                patch.object(contract.hashlib,'sha256',side_effect=hashed):
            try:answer=runtime.digest(Path('/authored/input'),maximum=len(payload),deadline=deadline)
            except BaseException as failure:caught=failure
        return types.SimpleNamespace(answer=answer,error=caught,events=events,payload=payload,tracebacks=tracebacks)

    def test_retained_digest_exact_empty_partial_payload_and_nofollow_owned_closure(self):
        for mutation,reads in ((None,[8,1]),('empty',[1]),('partial',[8,5,2,1])):
            with self.subTest(mutation=mutation):
                vector=self.retained_digest_vector(mutation)
                self.assertIsNone(vector.error)
                self.assertEqual(hashlib.sha256(vector.payload).hexdigest(),vector.answer)
                self.assertEqual(reads,[row[2] for row in vector.events if row[0]=='read'])
                self.assertEqual([103,102,101],[row[1] for row in vector.events if row[0]=='close'])
                opens=[row for row in vector.events if row[0]=='open']
                for row in opens:self.assertTrue(row[2]&os.O_NOFOLLOW);self.assertTrue(row[2]&os.O_CLOEXEC)
                self.assertTrue(opens[-1][2]&os.O_NONBLOCK);self.assertEqual({'dir_fd':102},opens[-1][3])
                self.assertTrue(all(not row[2]['follow_symlinks'] for row in vector.events if row[0]=='stat'))
                self.assertLess(max(i for i,row in enumerate(vector.events) if row[0]=='close'),
                                next(i for i,row in enumerate(vector.events) if row[0]=='hash'))

    def test_retained_digest_refuses_special_size_path_and_identity_changes(self):
        for mutation in ('fifo','device','directory','link','oversize','open-authored','open-input',
                         'short','growth','descriptor-drift','overwrite','path-drift','held-parent','named-parent'):
            with self.subTest(mutation=mutation):
                vector=self.retained_digest_vector(mutation)
                self.assertIsInstance(vector.error,(ValueError,OSError));self.assertIsNone(vector.answer)
                self.assertFalse(any(row[0]=='hash' for row in vector.events))
                acquired=[{'/':101,'authored':102,'input':103}[row[1]] for row in vector.events
                          if row[0]=='open' and mutation!='open-'+row[1]]
                self.assertEqual(list(reversed(acquired)),[row[1] for row in vector.events if row[0]=='close'])
                if mutation in ('fifo','device','directory','link','oversize','open-authored','open-input'):
                    self.assertFalse(any(row[0]=='read' for row in vector.events))
        with patch.object(contract.os,'open',side_effect=AssertionError('invalid admission must not open')):
            for maximum in (-1,True,16777217,1.0):
                with self.subTest(maximum=maximum),self.assertRaises(ValueError):runtime.digest(Path('/authored/input'),maximum=maximum)
            for path in (Path('/authored/../input'),Path('/'+'/'.join(['x']*128)),Path('/'+'x'*4096)):
                with self.subTest(path=path),self.assertRaises(ValueError):runtime.digest(path)

    def test_retained_digest_exact_primary_survives_cleanup_and_diagnostic_faults(self):
        class NoDiagnostics(ValueError):
            def __setattr__(self,name,value):raise RuntimeError('authored diagnostic refusal')
        for mutation in (None,'fstat-error','stat-error'):
            malformed=ValueError('authored malformed notes');malformed.__notes__=()
            for primary in (ValueError('authored primary'),NoDiagnostics('authored primary'),malformed):
                cleanup=OSError('authored cleanup')
                vector=self.retained_digest_vector(mutation,primary=primary,close_error=cleanup)
                self.assertIs(vector.error,primary);self.assertIsNone(vector.answer)
                self.assertEqual([103,102,101],[row[1] for row in vector.events if row[0]=='close'])
                tail=primary.__traceback__
                while tail is not None and tail is not vector.tracebacks[0]:tail=tail.tb_next
                self.assertIs(tail,vector.tracebacks[0])
                if type(primary) is ValueError and primary is not malformed:
                    self.assertEqual(['contract descriptor cleanup failures: 1'],primary.__notes__)
                if primary is malformed:self.assertEqual((),primary.__notes__)
        cleanup=OSError('cleanup only')
        vector=self.retained_digest_vector(close_error=cleanup)
        self.assertIs(vector.error,cleanup);self.assertIsNone(vector.answer)
        self.assertEqual([103,102,101],[row[1] for row in vector.events if row[0]=='close'])

    def test_retained_digest_original_deadline_closes_late_acquisition_and_final_operations(self):
        for mutation in ('late-open','late-read','late-close','late-hash'):
            with self.subTest(mutation=mutation):
                vector=self.retained_digest_vector(mutation)
                self.assertIsInstance(vector.error,TimeoutError);self.assertIsNone(vector.answer)
                expected=[101] if mutation=='late-open' else [103,102,101]
                self.assertEqual(expected,[row[1] for row in vector.events if row[0]=='close'])
        with patch.object(contract.time,'monotonic',return_value=10), \
                patch.object(contract.os,'open',side_effect=AssertionError('expired end before open')):
            with self.assertRaises(TimeoutError):runtime.digest(Path('/authored/input'),deadline=10)
        vector=self.retained_digest_vector('late-read',deadline=None)
        self.assertIsNone(vector.error);self.assertEqual(hashlib.sha256(vector.payload).hexdigest(),vector.answer)

    def test_retained_digest_hashes_capture_not_later_path_and_gcc_keeps_exact_realpath(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as temporary:
            path=Path(temporary)/'gcc';path.write_bytes(b'authored A')
            original=contract._bounded_json_snapshot
            def captured(name,maximum,*,deadline=None):
                raw=original(name,maximum,deadline=deadline)
                path.write_bytes(b'authored B')
                return raw
            with patch.object(contract,'_bounded_json_snapshot',side_effect=captured):
                self.assertEqual(hashlib.sha256(b'authored A').hexdigest(),contract.digest(path,maximum=10))
            value=contract.load_profile();value['gccIdentity'].update(executable=str(path),realpath=str(path),sha256=hashlib.sha256(b'authored B').hexdigest())
            with patch.object(contract,'digest',wraps=contract.digest) as hashed:
                self.assertIs(value,contract._revalidate_gcc(value))
                hashed.assert_called_once_with(path,maximum=16777216,deadline=None)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'GCC executable differs'):contract._revalidate_gcc(value)
            value['gccIdentity']['realpath']=str(path.with_name('other'))
            with patch.object(contract,'digest',side_effect=AssertionError('realpath disagreement before hash')):
                with self.assertRaisesRegex(ValueError,'GCC executable differs'):contract._revalidate_gcc(value)

    def test_complete_rlimits_are_disclosed_and_applied_exactly_without_host_policy(self):
        p = contract.load_profile(); bounds = runtime.execution_bounds(phase='runtime')
        self.assertEqual({'coreBytes':0,'openFiles':64,'fileSizeBytes':16777216,'cpuSeconds':30,
                          'virtualAddressSpaceBytes':2147483648},
                         {k:p['bounds'][k] for k in ['coreBytes','openFiles','fileSizeBytes','cpuSeconds','virtualAddressSpaceBytes']})
        with patch.object(runtime.resource, 'setrlimit') as set_limit:
            runtime.process_limits(bounds['perProcessRlimits'])
        self.assertEqual([(runtime.resource.RLIMIT_CORE,(0,0)), (runtime.resource.RLIMIT_CPU,(30,30)),
                          (runtime.resource.RLIMIT_AS,(2147483648,2147483648)),
                          (runtime.resource.RLIMIT_NOFILE,(64,64)), (runtime.resource.RLIMIT_FSIZE,(16777216,16777216))],
                         [call.args for call in set_limit.call_args_list])
        self.assertIsNone(bounds['cgroup']['aggregateCpuLimit'])
        self.assertFalse(bounds['cgroup']['aggregateCpuLimitEnforced'])
        self.assertEqual('per-process', bounds['perProcessRlimits']['RLIMIT_CPU']['scope'])
        altered = copy.deepcopy(bounds['perProcessRlimits']); altered['RLIMIT_CORE']['soft'] = 1
        with self.assertRaises(ValueError): runtime.process_limits(altered)

    def test_every_bound_mutation_unknown_key_and_v2_refuse_before_any_execution(self):
        p = contract.load_profile()
        for key, value in p['bounds'].items():
            altered = copy.deepcopy(p); altered['bounds'][key] = value + 1
            with self.subTest(key=key), self.assertRaises(ValueError): contract.validate_profile(altered)
        for field in ['schemaVersion','commands','environment','analysisIsolation','limitAudit','limitSemantics']:
            altered = copy.deepcopy(p)
            if field == 'schemaVersion': altered[field] = 2
            elif field == 'commands': altered[field]['compile'].append('-DCHANGED=1')
            elif field == 'environment': altered[field]['LD_PRELOAD'] = '/injected'
            elif field == 'analysisIsolation': altered[field]['readOnlyOwnedSourceWork'] = '/other'
            else: altered[field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError): contract.validate_profile(altered)
        altered = copy.deepcopy(p); altered['bounds']['swapBytes'] = False
        with self.assertRaises(ValueError): contract.validate_profile(altered)
        altered = copy.deepcopy(p); altered['unexpected'] = 1
        with self.assertRaises(ValueError): contract.validate_profile(altered)

    def test_loader_has_no_host_identity_resolution_and_rejects_duplicate_or_oversize_json(self):
        with patch.object(contract, 'digest', side_effect=AssertionError('host identity access')), patch.object(Path, 'resolve', side_effect=AssertionError('host resolution')):
            self.assertEqual(3, contract.load_profile()['schemaVersion'])
        with tempfile.TemporaryDirectory(dir=TEMP) as temporary:
            path = Path(temporary)/'profile.json'
            path.write_text('{"schemaVersion":3,"schemaVersion":3}')
            with self.assertRaises(ValueError): contract.load_profile(path)
            path.write_bytes(b' '*(contract.MAXIMUM_PROFILE_BYTES+1))
            with self.assertRaises(ValueError): contract.load_profile(path)

    def test_visible_manifest_and_renderer_bind_all_limits_and_immutable_commands(self):
        value, digest = contract.load_profile_with_digest()
        with tempfile.TemporaryDirectory(dir=TEMP) as temporary, patch.object(contract, '_visible_snapshot', return_value=(value,digest)):
            root = Path(temporary); contract.write_visible(root); contract.verify_visible(root)
            prompt = (root/'prompt.txt').read_text()
            self.assertTrue(prompt.startswith('Candidate build contract v3\n'))
            self.assertIn('"coreBytes": 0',prompt); self.assertIn('"openFiles": 64',prompt)
            self.assertIn('"fileSizeBytes": 16777216',prompt)
            for key in value['bounds']: self.assertIn('"'+key+'":',prompt)
            manifest = json.loads((root/'visible-manifest.json').read_text()); manifest['profile']['bounds']['openFiles'] = 65
            (root/'visible-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError): contract.verify_visible(root)
            contract.write_visible(root); (root/'prompt.txt').write_text(prompt.replace('-fPIC','-fpic'))
            with self.assertRaises(ValueError): contract.verify_visible(root)
            contract.write_visible(root); manifest = json.loads((root/'visible-manifest.json').read_text()); manifest['schemaVersion'] = 2
            (root/'visible-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError): contract.verify_visible(root)

    def test_phase_defaults_and_one_over_reject_without_resource_or_subprocess_calls(self):
        for phase, seconds, output in [('compiler',30,65536),('probe',30,1048576),('runtime',5,65536),
            ('elf-inspection',10,65536),('caller-build',30,65536),('helper-build',60,1048576),('toolchain-inspection',10,1048576)]:
            with self.subTest(phase=phase):
                b = runtime.execution_bounds(phase=phase)
                self.assertEqual(seconds,b['wallSeconds']); self.assertEqual(output,b['outputBytesPerStream'])
                with self.assertRaises(ValueError): runtime.execution_bounds(seconds+1,phase=phase)
                with self.assertRaises(ValueError): runtime.execution_bounds(output_limit=output+1,phase=phase)
        for value in [True,0,-1,float('nan'),float('inf')]:
            with self.assertRaises(ValueError): runtime.execution_bounds(timeout=value)
        with self.assertRaises(ValueError): runtime.execution_bounds(phase='invented')
        with self.assertRaises(ValueError): runtime.bounded_run(['forbidden'],TEMP,{},stdin=b'x'*4097)

    def test_finite_audit_accounts_for_all_bounds_and_unchanged_supervisor_constants(self):
        p = contract.load_profile()
        self.assertEqual(set(p['bounds']),{key for row in p['limitAudit'] for key in row['keys']} |
            {'memoryBytes','swapBytes','tasks','coreBytes','cpuSeconds','virtualAddressSpaceBytes','openFiles','fileSizeBytes'})
        # Poll interval remains an immutable disclosed compatibility field; the
        # authenticated signal wait now enforces the absolute admission deadline.
        self.assertEqual(5,p['bounds']['scopeAdmissionSeconds'])
        self.assertEqual(0.01,p['bounds']['scopeAdmissionPollSeconds'])
        gate=types.ModuleType('_profile_admission_signal_control')
        gate.__file__=str(SOURCE/'scope_gate.py')
        exec(compile((SOURCE/'scope_gate.py').read_bytes(),gate.__file__,'exec'),gate.__dict__)
        deadline=p['bounds']['scopeAdmissionSeconds']
        pending=types.SimpleNamespace(si_signo=gate.signal.SIGUSR1,si_code=0,si_errno=0,si_pid=1,si_uid=2)
        with patch.object(gate,'_live_controller'),patch.object(gate.time,'monotonic',side_effect=[0,1,deadline]),patch.object(gate.signal,'sigtimedwait',return_value=pending) as wait:
            with self.assertRaises(TimeoutError):gate._wait_release((1,9,2),6,deadline)
            wait.assert_called_once_with({gate.signal.SIGUSR1},deadline-1)
        with patch.object(gate.time,'monotonic',return_value=deadline),patch.object(gate.signal,'sigtimedwait',return_value=pending) as wait:
            with self.assertRaises(TimeoutError):gate._wait_release((1,9,2),6,deadline)
            wait.assert_not_called()
        helper = ast.parse((SOURCE/'toolchain-001/build_helper.py').read_text())
        calls = [n for n in ast.walk(helper) if isinstance(n,ast.Call) and
                 ((isinstance(n.func,ast.Name) and n.func.id=='bounded_run') or
                  (isinstance(n.func,ast.Attribute) and n.func.attr=='run' and n.args and
                   isinstance(n.args[0],ast.Name) and n.args[0].id=='bounded_run'))]
        self.assertEqual(1,len(calls)); keywords={k.arg:k.value for k in calls[0].keywords}
        for argument, key in [('timeout','helperBuildSeconds'),('output_limit','helperOutputBytesPerStream')]:
            node = keywords[argument]
            self.assertIsInstance(node, ast.Subscript)
            self.assertEqual('bounds', node.value.id); self.assertEqual(key, node.slice.value)
        self.assertEqual(60,p['bounds']['helperBuildSeconds'])
        self.assertEqual(1048576,p['bounds']['helperOutputBytesPerStream'])

    def simulate(self, *, output=b'ok', limit=None, clock=None, cleanup_failure=False,
                 wrapper=0, proof_kind='complete', admission=True, setup_failure=False, provisioning=False, late_cleanup_wait=False, late_absence=False, cleanup_prework=0.0,
                 metadata_failure=None, census_failure=None, synthetic_completion=False, pidfd_failure=None,
                 cleanup_wait_failure=None, nonblocking_failure=None):
        import worker_exec_proof as parser
        declared_profile_sha=contract.load_profile_with_digest()[1]
        stack = ExitStack(); self.addCleanup(stack.close)
        temporary = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=TEMP)))
        base = temporary / 'trusted'; base.mkdir(mode=0o700)
        work = temporary / 'work'; work.mkdir(mode=0o700)
        stack.enter_context(patch.object(runtime, 'BASE', base))
        process = Process(wrapper); self.last_process=process; now=[100.0]
        if late_cleanup_wait:
            process.wait_hook=lambda count,timeout: now.__setitem__(0,now[0]+6.0) if count==2 else None
        if cleanup_wait_failure is not None:
            def wait_failure(count,timeout):raise cleanup_wait_failure
            process.wait_hook=wait_failure
        blocks = {process.stdout.fileno():[output,b''],process.stderr.fileno():[b'err',b'']}
        popen = stack.enter_context(patch.object(runtime.subprocess,'Popen',return_value=process))
        self.last_popen = popen
        lifetime=work/'authored-launcher-handle';lifetime.write_bytes(b'public mocked lifetime')
        stack.enter_context(patch.object(runtime.os,'pidfd_open',side_effect=pidfd_failure if pidfd_failure is not None
            else lambda pid:os.open(lifetime,os.O_RDONLY)))
        if pidfd_failure is None:
            stack.enter_context(patch.object(runtime,'_kill_launcher',side_effect=lambda fd:now.__setitem__(0,now[0]+cleanup_prework)))
        stack.enter_context(patch.object(runtime,'_kill_owned_scope'))
        if setup_failure:
            popen.side_effect = OSError('mocked launch refusal')
        stack.enter_context(patch.object(runtime,'process_identity',return_value={'pid':123,'start':9,'pgid':123,'sid':123}))
        def scoped(evidence):
            if late_absence:now[0]+=6.0
            return []
        stack.enter_context(patch.object(runtime,'scope_processes',side_effect=scoped))
        self.last_census_deadlines=[]
        def census(leader,start,deadline):
            self.last_census_deadlines.append(deadline)
            if start is None:raise RuntimeError('owned launcher start identity is unknown')
            if census_failure is not None:raise census_failure
            return [{'pid':123}] if cleanup_failure else []
        stack.enter_context(patch.object(runtime,'owned_processes',side_effect=census))
        if cleanup_failure:
            stack.enter_context(patch.object(runtime,'kill_exact'))
            stack.enter_context(patch.object(runtime.time,'sleep'))
        stack.enter_context(patch.object(runtime.selectors,'DefaultSelector',return_value=Selector()))
        self.last_pipe_nonblocking={};self.last_pipe_reads=[];self.last_pipe_mode_attempts=[]
        def nonblocking(fd,blocking):
            self.last_pipe_mode_attempts.append((fd,blocking))
            if nonblocking_failure is not None:raise nonblocking_failure
            self.last_pipe_nonblocking[fd]=blocking
        stack.enter_context(patch.object(runtime.os,'set_blocking',side_effect=nonblocking))
        def read(fd,size):
            if fd in blocks:
                self.assertIs(self.last_pipe_nonblocking.get(fd),False,'never read a blocking capture pipe')
                self.last_pipe_reads.append((fd,size))
                return blocks[fd].pop(0) if blocks[fd] else b''
            return _READ_OWNED_FILE(fd,size)
        stack.enter_context(patch.object(runtime.os,'read',side_effect=read))
        stack.enter_context(patch.object(runtime.time,'monotonic',side_effect=clock if clock is not None else lambda:now[0]))
        stack.enter_context(patch.object(runtime,'_worker_proof_parser',return_value=parser.parse_proof))
        if synthetic_completion:
            # Isolate reclamation/controller predicates from the unavailable proof
            # producer channel. Only explicit authored metadata tests opt in; this
            # is not runner completion or native authority qualification.
            finish=runtime._finish_worker_proof
            def authored_completion(result,receipt,launch,bounds,deadline=None):
                finish(result,receipt,launch,bounds,deadline=deadline)
                self.assertEqual('exclusive-proof-write-authority-unavailable',result['workerProof']['reason'])
                parsed=parser.parse_proof(result['workerProofRaw'],launch['expected'])
                self.assertEqual('verified',parsed['status'])
                result['workerProof'].update(status=parsed['status'],reason=parsed['reason'])
                result.update(exitCode=parsed['exitCode'],workerExecVerified=parsed['workerExecVerified'],
                    workerTerminationVerified=parsed['workerTerminationVerified'],workerTermination=parsed['workerTermination'],
                    infrastructureFailure=False,infrastructureReason=None)
            stack.enter_context(patch.object(runtime,'_finish_worker_proof',side_effect=authored_completion))
        pins={'/authored/worker':{'device':7,'inode':8,'mode':0o755,'sha256':'0'*64},
              '/authored/bwrap':{'device':3,'inode':4,'mode':0o755,'sha256':'0'*64},
              '/authored/monitor':{'device':13,'inode':14,'mode':0o500,'sha256':'9'*64},
              str(base/'contracts/candidate-build-profile.json'):{'device':70,'inode':71,'mode':0o400,'sha256':declared_profile_sha}}
        pins[str(base/'worker_exec_proof.py')]={'device':70,'inode':72,'mode':0o400,'sha256':runtime._WORKER_PROOF_PARSER_SHA256}
        stack.enter_context(patch.object(runtime,'_pin_files',return_value=pins))
        def prepare(argv,cwd,bounds,receipt,provisioning,deadline=None):
            self.last_receipt=receipt
            runtime.write_json(receipt['directory']/'launch.json', {'mock':True})
            cache=runtime.private_directory(receipt['directory']/'python-cache')
            metadata=cache.lstat()
            receipt.update(cacheDevice=metadata.st_dev,cacheInode=metadata.st_ino)
            expected = {'attempt':receipt['directory'].name,'phase':'runtime','reportDevice':receipt['device'],
                        'reportInode':receipt['inode'],'reaperDevice':3,'reaperInode':4,
                        'outerPidNsDevice':5,'outerPidNsInode':6,'targetDevice':7,'targetInode':8}
            config_sha=runtime.digest(receipt['directory']/'launch.json')
            binding={'protocolVersion':1,'expected':expected,'launchConfigSha256':config_sha,
                     **{key:'0'*64 for key in ('environmentPinSha256','monitorBinarySha256','monitorSourceSha256',
                                               'protocolSha256','parserSha256','manifestSha256','targetSha256')},
                     'launchPinsSha256':runtime._canonical_pin_digest(pins)}
            binding['parserSha256']=runtime._WORKER_PROOF_PARSER_SHA256
            binding['monitorBinarySha256']='9'*64
            binding['monitorExecutable']={'path':'/authored/monitor',**pins['/authored/monitor']}
            return {'argv':['mock-no-execution'],'unit':'mock.scope','expected':expected,'pins':pins,
                    'configSha256':config_sha,'proofBinding':None if provisioning else binding}
        stack.enter_context(patch.object(runtime,'_prepare_launch',side_effect=prepare))
        # This simulator already mocks kernel acquisition. Explicitly isolate
        # authenticated release here; actual sender/scope helpers have separate controls.
        self.last_scope_evidence=None
        def acquired_scope():
            scope={'finalAbsenceVerified':False}
            self.last_scope_evidence=scope
            return scope
        def release(scope,launch,deadline):
            self.assertIs(scope,self.last_scope_evidence)
            self.assertIsInstance(deadline,(int,float))
            self.assertGreater(deadline,0)
        release_mock=stack.enter_context(patch.object(runtime,'_release_scope',side_effect=release))
        self.last_release=release_mock
        self.last_admission_deadlines=[]
        def admit(receipt,launch,bounds,deadline):
            self.last_admission_deadlines.append(deadline)
            if metadata_failure is not None:raise metadata_failure
            if not admission:
                return None
            runtime.write_json(receipt['directory']/'gate.json',{'pid':123,'start':9})
            if provisioning:
                self.assertIsNone(receipt['fd'])  # No compiler report channel.
                metadata=receipt['path'].lstat()
                self.assertEqual((receipt['device'],receipt['inode']),(metadata.st_dev,metadata.st_ino))
                self.assertEqual(b'',receipt['path'].read_bytes())  # Retained, never unlinked.
                return acquired_scope()
            e = {'v':1,'t':'exec','s':1,'a':launch['expected']['attempt'],'p':'runtime','c':3,
                 'ed':7,'ei':8,'od':7,'oi':8,'w':parser.EXEC_WAIT_STATUS,'cf':1,'dp':0,
                 'rd':3,'ri':4,'b':[1,100,5,9,1,3]}
            term = {'v':1,'t':'term','s':2,'a':e['a'],'p':'runtime','c':3,'r':139<<8,'k':'exit','n':139}
            if proof_kind == 'signal': term.update(r=11,k='signal',n=11)
            records = [e,term] if proof_kind in ('complete','signal') else [e] if proof_kind == 'exec-only' else []
            if proof_kind == 'terminal-only': records=[term]
            raw = b''.join((json.dumps(record,separators=(',',':'))+'\n').encode() for record in records)
            if proof_kind == 'overflow': raw=b'x'*1025
            os.pwrite(receipt['fd'],raw,0)
            if proof_kind == 'replaced':
                receipt['path'].unlink(); receipt['path'].write_bytes(raw); receipt['path'].chmod(0o600)
            return acquired_scope()
        stack.enter_context(patch.object(runtime,'_admit_scope',side_effect=admit))
        try:
            if provisioning:
                return runtime._run_scoped(['mock-fixed-provisioner'],work,{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},b'',
                                           runtime.execution_bounds(output_limit=limit,managed_scope=True,phase='runtime'),provisioning=True)
            return runtime.bounded_run(['mock-only'],work,{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},
                                       phase='runtime',output_limit=limit,managed_scope=True)
        finally:
            if self.last_scope_evidence is None:
                release_mock.assert_not_called()
            else:
                release_mock.assert_called_once()
                self.assertIs(self.last_scope_evidence,release_mock.call_args.args[0])

    def test_controller_metadata_refusals_preserve_original_deadlines_and_unknown_results(self):
        result=self.simulate()
        self.assertFalse(runtime.worker_execution_complete(result))
        self.assertEqual('exclusive-proof-write-authority-unavailable',result['workerProof']['reason'])
        self.assertTrue(self.last_admission_deadlines)
        self.assertEqual({100+runtime.execution_bounds(phase='runtime')['wallSeconds']},set(self.last_admission_deadlines))
        self.assertEqual([105],self.last_census_deadlines)
        for kind in ('metadata','census'):
            for failure in (TimeoutError('authored original deadline'),ValueError('authored metadata refusal'),
                            PermissionError('authored inspection denial'),RuntimeError('authored census cap')):
                with self.subTest(kind=kind,failure=type(failure).__name__):
                    with self.assertRaises(type(failure)) as caught:
                        self.simulate(**{kind+'_failure':failure})
                    result=caught.exception.bounded_result
                    self.assertTrue(result['infrastructureFailure'])
                    self.assertFalse(runtime.worker_execution_complete(result))
                    self.assertIsNone(result['exitCode'])
                    if kind=='census':
                        self.assertFalse(result['cleanupVerified']);self.assertFalse(result['finalAbsenceVerified'])
                        self.assertEqual([105],self.last_census_deadlines)
                    else:
                        self.assertFalse(result['scopeAdmitted'])
                        self.assertEqual(isinstance(failure,TimeoutError),result['timedOut'])
                        self.last_release.assert_not_called()

    def test_mock_complete_proof_separates_worker_from_launcher_and_public_bytes(self):
        result = self.simulate()
        self.assertFalse(runtime.worker_execution_complete(result))
        self.assertEqual(0,result['launcherExitCode']); self.assertIsNone(result['exitCode'])
        self.assertEqual('exclusive-proof-write-authority-unavailable',result['workerProof']['reason'])
        self.assertEqual(b'err',result['stderr']); self.assertTrue(result['workerProofRaw'])
        public = runtime.public_result(result)
        self.assertNotIn('workerProofRaw',public)
        self.assertEqual(result['workerProofRaw'].hex(),public['workerProofRawHex'])
        self.assertFalse(runtime.worker_execution_complete(public))
        self.assertIs(self.last_popen.call_args.kwargs['close_fds'], True)
        self.assertFalse('pass_fds' in self.last_popen.call_args.kwargs)
        result = self.simulate(proof_kind='signal')
        self.assertIsNone(result['exitCode']); self.assertFalse(runtime.worker_execution_complete(result))
        self.assertFalse(result['workerTerminationVerified']);self.assertIsNone(result['workerTermination'])

    def test_mock_provisioning_is_channel_free_and_never_worker_completion(self):
        result=self.simulate(provisioning=True,wrapper=7)
        self.assertTrue(result['provisioningOnly']);self.assertEqual(7,result['exitCode'])
        self.assertFalse(result['workerExecVerified']);self.assertFalse(result['workerTerminationVerified'])
        self.assertIsNone(result['workerProof']);self.assertEqual(b'',result['workerProofRaw'])
        self.assertFalse(runtime.worker_execution_complete(result))
        self.assertTrue(result['cleanupVerified']);self.assertTrue(result['scopeAdmitted'])

    def test_mock_complete_receipt_layout_is_actually_consumed_closed_and_reclaimed(self):
        for provisioning in (False,True):
            with self.subTest(provisioning=provisioning):
                result=self.simulate(provisioning=provisioning,synthetic_completion=not provisioning)
                self.assertIsNone(self.last_receipt['fd'])
                self.assertEqual('retained',result['_receiptCleanup']['status'])
                self.assertEqual('exclusive-deletion-authority-unavailable',result['_receiptCleanup']['reason'])
                self.assertEqual([],result['_receiptCleanup']['removedEntries'])
                self.assertTrue(self.last_receipt['directory'].is_dir())
                self.assertEqual(not provisioning,runtime.worker_execution_complete(result))
                self.assertEqual(not provisioning,bool(result['workerProofRaw']))
                self.assertNotIn('_receiptCleanup',runtime.public_result(result))

    def test_mock_missing_receipt_entry_still_refuses_without_changing_worker_facts(self):
        reclaim=runtime._reclaim_worker_receipt
        def missing(receipt,result,**kwargs):
            (receipt['directory']/'gate.json').unlink()
            return reclaim(receipt,result,**kwargs)
        with patch.object(runtime,'_reclaim_worker_receipt',side_effect=missing):
            with self.assertRaisesRegex(ValueError,'owned receipt directory reclamation failed') as caught:
                self.simulate(synthetic_completion=True)
        result=caught.exception.bounded_result
        self.assertEqual('refused',result['_receiptCleanup']['status'])
        self.assertEqual([],result['_receiptCleanup']['removedEntries'])
        self.assertIn('inventory incomplete',result['_receiptCleanup']['secondaryError'])
        self.assertTrue(self.last_receipt['directory'].is_dir())
        self.assertTrue(result['cleanupVerified']);self.assertTrue(result['workerTerminationVerified'])
        self.assertTrue(result['workerProofRaw']);self.assertTrue(result['infrastructureFailure'])

    def test_unexpected_legacy_admit_marker_retains_worker_and_provisioning_receipts(self):
        reclaim=runtime._reclaim_worker_receipt
        def injected(receipt,result,**kwargs):
            marker=receipt['directory']/'admit';marker.write_bytes(b'1\n');marker.chmod(0o600)
            return reclaim(receipt,result,**kwargs)
        for provisioning in (False,True):
            with self.subTest(provisioning=provisioning),patch.object(runtime,'_reclaim_worker_receipt',side_effect=injected):
                with self.assertRaisesRegex(ValueError,'owned receipt directory reclamation failed') as caught:
                    self.simulate(provisioning=provisioning,synthetic_completion=not provisioning)
            result=caught.exception.bounded_result
            self.assertEqual('refused',result['_receiptCleanup']['status'])
            self.assertEqual([],result['_receiptCleanup']['removedEntries'])
            self.assertIn('unexpected receipt entry',result['_receiptCleanup']['secondaryError'])
            self.assertTrue(self.last_receipt['directory'].is_dir())
            self.assertEqual(b'1\n',(self.last_receipt['directory']/'admit').read_bytes())
            self.assertTrue(result['cleanupVerified']);self.assertTrue(result['finalAbsenceVerified'])
            self.assertEqual(not provisioning,result['workerTerminationVerified'])

    def test_wrapper_status_without_both_proofs_never_becomes_worker_exit(self):
        for wrapper in (0,1,137):
            for kind in ('missing','exec-only','terminal-only','overflow','replaced'):
                with self.subTest(wrapper=wrapper,kind=kind):
                    result=self.simulate(wrapper=wrapper,proof_kind=kind)
                    self.assertEqual(wrapper,result['launcherExitCode']); self.assertIsNone(result['exitCode'])
                    self.assertFalse(runtime.worker_execution_complete(result))
                    self.assertTrue(result['infrastructureFailure'])
                    self.assertFalse(result['workerExecVerified'])
        # Complete canonical bytes cannot repair missing producer authority or transport.
        result=self.simulate(wrapper=1)
        self.assertFalse(result['workerTerminationVerified']); self.assertIsNone(result['exitCode'])

    def test_mock_prelaunch_and_no_admission_retain_raw_refusal_and_cleanup(self):
        with self.assertRaises(OSError) as caught: self.simulate(setup_failure=True)
        result=caught.exception.bounded_result
        self.assertFalse(result['launcherCreated']); self.assertIsNone(result['exitCode'])
        self.assertEqual(b'',result['stdout']); self.assertFalse(result['cleanupVerified'])
        self.assertFalse(result['finalAbsenceVerified'])
        with self.assertRaises(AssertionError) as caught: self.simulate(admission=False)
        result=caught.exception.bounded_result
        self.assertTrue(result['captureComplete']); self.assertTrue(result['waitComplete'])
        self.assertFalse(result['scopeVerified']); self.assertFalse(result['scopeAdmitted'])
        self.assertTrue(result['infrastructureFailure']); self.assertTrue(result['cleanupVerified'])
        self.assertEqual(b'err',result['stderr']); self.assertIsNone(result['exitCode'])

    def test_mock_partial_output_retains_limit_and_cleanup_without_completion(self):
        with self.assertRaises(ValueError) as caught: self.simulate(output=b'overflow',limit=1)
        result=caught.exception.bounded_result
        self.assertEqual(b'o',result['stdout']); self.assertTrue(result['outputExceeded'])
        self.assertFalse(result['captureComplete']); self.assertFalse(result['waitComplete']); self.assertTrue(result['cleanupVerified'])
        self.assertIsNone(result['exitCode']); self.assertFalse(runtime.worker_execution_complete(result))

    def test_mock_timeout_and_cleanup_failure_remain_partial_or_unknown(self):
        import itertools
        with self.assertRaises(TimeoutError) as caught:
            self.simulate(clock=itertools.chain([0,0,0,0,100],itertools.repeat(100)))
        self.assertTrue(caught.exception.bounded_result['timedOut'])
        create_receipt=runtime._create_worker_receipt
        def initialize_receipt(*args,**kwargs):
            # Keep the actual factory within the existing phase end, then advance
            # the same simulated clock to exercise the intended cleanup refusal.
            with patch.object(runtime.time,'monotonic',return_value=0):
                return create_receipt(*args,**kwargs)
        with patch.object(runtime,'_create_worker_receipt',side_effect=initialize_receipt):
            with self.assertRaises(TimeoutError) as caught:
                self.simulate(cleanup_failure=True,clock=itertools.count(0,0.2))
        self.last_popen.assert_called_once()
        self.assertTrue(self.last_census_deadlines)
        result=caught.exception.bounded_result
        self.assertFalse(result['cleanupVerified']); self.assertIsNone(result['exitCode'])
        self.assertFalse(result['workerExecVerified'])

    def test_pidfd_acquisition_failure_still_waits_for_direct_child_without_numeric_signal(self):
        for failure in (OSError(24,'authored descriptor exhaustion'),OSError(38,'authored unsupported pidfd')):
            with self.subTest(errno=failure.errno):
                # Exercise the real unavailable-handle refusal, not the simulator's
                # successful kill seam. No numeric PID or session kill is allowed.
                with patch.object(runtime.os,'kill',side_effect=AssertionError('no numeric PID signal')), \
                        patch.object(runtime.os,'killpg',side_effect=AssertionError('no numeric session signal')), \
                        patch.object(runtime,'_kill_launcher',wraps=runtime._kill_launcher) as killing, \
                        self.assertRaises(OSError) as caught:
                    self.simulate(pidfd_failure=failure)
                killing.assert_called_once_with(None)
                self.assertIs(failure,caught.exception)
                result=failure.bounded_result
                self.assertTrue(result['launcherCreated']);self.assertFalse(result['launcherPidIdentityVerified'])
                self.assertEqual([5.0],self.last_process.waits)
                self.assertTrue(result['rootReaped'])
                self.assertFalse(result['scopeAdmitted']);self.assertFalse(result['finalAbsenceVerified'])
                self.assertFalse(result['cleanupVerified']);self.assertTrue(result['infrastructureFailure'])
                self.assertIsNone(result['exitCode']);self.assertFalse(runtime.worker_execution_complete(result))

    def test_pidfd_failure_and_timed_out_wait_never_drain_blocking_pipes(self):
        failure=OSError(24,'authored pidfd exhaustion')
        wait_failure=runtime.subprocess.TimeoutExpired('authored launcher',5)
        with self.assertRaises(OSError) as caught:
            self.simulate(pidfd_failure=failure,cleanup_wait_failure=wait_failure)
        self.assertIs(failure,caught.exception)
        self.assertEqual([5.0],self.last_process.waits)
        self.assertEqual([(100010,False),(100011,False)],self.last_pipe_mode_attempts)
        self.assertEqual([100010,100011],[fd for fd,_ in self.last_pipe_reads])
        result=failure.bounded_result
        self.assertFalse(result['rootReaped']);self.assertFalse(result['cleanupVerified'])
        self.assertFalse(result['finalAbsenceVerified']);self.assertTrue(result['infrastructureFailure'])
        self.assertIsNone(result['exitCode']);self.assertFalse(runtime.worker_execution_complete(result))
        self.assertEqual(b'ok',result['stdout']);self.assertEqual(b'err',result['stderr'])

    def test_early_drain_skips_reads_when_nonblocking_setup_refuses(self):
        for mode_failure in (OSError(9,'authored invalid pipe'),ValueError('authored closed pipe')):
            with self.subTest(error=type(mode_failure).__name__):
                failure=OSError(38,'authored unsupported pidfd')
                with self.assertRaises(OSError) as caught:
                    self.simulate(pidfd_failure=failure,
                        cleanup_wait_failure=runtime.subprocess.TimeoutExpired('authored launcher',5),
                        nonblocking_failure=mode_failure)
                self.assertIs(failure,caught.exception)
                self.assertEqual([(100010,False),(100011,False)],self.last_pipe_mode_attempts)
                self.assertEqual([],self.last_pipe_reads)
                result=failure.bounded_result
                self.assertEqual(b'',result['stdout']);self.assertEqual(b'',result['stderr'])
                self.assertFalse(result['cleanupVerified']);self.assertIsNone(result['exitCode'])
                self.assertFalse(runtime.worker_execution_complete(result))

    def test_cleanup_wait_receives_only_remaining_absolute_window(self):
        result=self.simulate(cleanup_prework=2.0)
        self.assertEqual(3.0,self.last_process.waits[-1])
        self.assertTrue(result['cleanupVerified']);self.assertEqual(2.0,result['cleanupElapsedSeconds'])
        with self.assertRaises(TimeoutError) as caught:self.simulate(cleanup_prework=5.0)
        self.assertFalse(caught.exception.bounded_result['cleanupVerified'])
        self.assertEqual(1,len(self.last_process.waits))  # original wrapper wait only; no renewed cleanup budget

    def test_late_successful_cleanup_wait_and_final_absence_never_verify(self):
        for kind in ('wait','absence'):
            with self.subTest(kind=kind),self.assertRaises(TimeoutError) as caught:
                self.simulate(late_cleanup_wait=kind=='wait',late_absence=kind=='absence')
            result=caught.exception.bounded_result
            self.assertEqual(0,result['launcherExitCode']);self.assertEqual(b'ok',result['stdout'])
            self.assertEqual(b'err',result['stderr']);self.assertTrue(result['waitComplete'])
            self.assertFalse(result['cleanupVerified']);self.assertFalse(result['finalAbsenceVerified'])
            self.assertIsNone(result['exitCode']);self.assertFalse(runtime.worker_execution_complete(result))
            self.assertTrue(result['infrastructureFailure'])

    def test_host_direct_and_unscoped_requests_refuse_before_subprocess(self):
        env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
        with self.assertRaises(ValueError): runtime.bounded_run(['/usr/bin/true'],TEMP,env)
        with self.assertRaises(ValueError) as caught:
            runtime.bounded_run(['/usr/bin/true'],TEMP,env,managed_scope=True)
        self.assertFalse(caught.exception.bounded_result['launcherCreated'])

    def test_completion_requires_all_controller_facts_and_exact_streams(self):
        value=self.simulate(synthetic_completion=True)
        self.assertTrue(runtime.worker_execution_complete(value))
        for key in ('launcherCreated','launcherPidIdentityVerified','scopeVerified','scopeAdmitted','captureComplete',
                    'waitComplete','cleanupVerified','rootReaped','finalAbsenceVerified','workerExecVerified','workerTerminationVerified'):
            changed=copy.deepcopy(value);changed[key]=False
            with self.subTest(key=key): self.assertFalse(runtime.worker_execution_complete(changed))
        for key in ('timedOut','outputExceeded','infrastructureFailure','provisioningOnly'):
            changed=copy.deepcopy(value);changed[key]=True
            with self.subTest(key=key): self.assertFalse(runtime.worker_execution_complete(changed))
        for mutate in (lambda v:v['kernelScope'].update(finalAbsenceVerified=False),
                       lambda v:v.update(stdout='text'),lambda v:v.update(stdoutHex='00'),
                       lambda v:v['workerProof'].update(pinsUnchanged=False),
                       lambda v:v.update(workerProofRaw=b'forged'),
                       lambda v:v['workerProofBindings']['expected'].update(targetInode=999),
                       lambda v:v['launchInputPins']['/authored/worker'].update(inode=999),
                       lambda v:v['bounds'].update(phase='compiler'),
                       lambda v:v['workerProof'].update(fileIdentityVerified=False),
                       lambda v:v['workerTermination'].update(rawWaitStatus=11)):
            changed=copy.deepcopy(value);mutate(changed);self.assertFalse(runtime.worker_execution_complete(changed))
        public=runtime.public_result(value); public['stdoutHex']='GG'
        self.assertFalse(runtime.worker_execution_complete(public))


if __name__ == '__main__':
    unittest.main()
