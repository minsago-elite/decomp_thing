"""Static/mock-only profile/runtime controls. Never launch tools or change host resource limits."""
import ast
import copy
import io
import hashlib
import os
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
                 metadata_failure=None, census_failure=None):
        import worker_exec_proof as parser
        stack = ExitStack(); self.addCleanup(stack.close)
        temporary = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=TEMP)))
        base = temporary / 'trusted'; base.mkdir(mode=0o700)
        work = temporary / 'work'; work.mkdir(mode=0o700)
        stack.enter_context(patch.object(runtime, 'BASE', base))
        process = Process(wrapper); self.last_process=process; now=[100.0]
        if late_cleanup_wait:
            process.wait_hook=lambda count,timeout: now.__setitem__(0,now[0]+6.0) if count==2 else None
        blocks = {process.stdout.fileno():[output,b''],process.stderr.fileno():[b'err',b'']}
        popen = stack.enter_context(patch.object(runtime.subprocess,'Popen',return_value=process))
        self.last_popen = popen
        lifetime=work/'authored-launcher-handle';lifetime.write_bytes(b'public mocked lifetime')
        stack.enter_context(patch.object(runtime.os,'pidfd_open',side_effect=lambda pid:os.open(lifetime,os.O_RDONLY)))
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
            if census_failure is not None:raise census_failure
            return [{'pid':123}] if cleanup_failure else []
        stack.enter_context(patch.object(runtime,'owned_processes',side_effect=census))
        if cleanup_failure:
            stack.enter_context(patch.object(runtime,'kill_exact'))
            stack.enter_context(patch.object(runtime.time,'sleep'))
        stack.enter_context(patch.object(runtime.selectors,'DefaultSelector',return_value=Selector()))
        stack.enter_context(patch.object(runtime.os,'set_blocking'))
        def read(fd,size):
            if fd in blocks:
                return blocks[fd].pop(0) if blocks[fd] else b''
            return _READ_OWNED_FILE(fd,size)
        stack.enter_context(patch.object(runtime.os,'read',side_effect=read))
        stack.enter_context(patch.object(runtime.time,'monotonic',side_effect=clock if clock is not None else lambda:now[0]))
        stack.enter_context(patch.object(runtime,'_fixed_source_module',return_value=parser))
        pins={'/authored/worker':{'device':7,'inode':8,'mode':0o755,'sha256':'0'*64},
              '/authored/bwrap':{'device':3,'inode':4,'mode':0o755,'sha256':'0'*64}}
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
                self.assertIsNone(receipt['fd']); self.assertFalse(receipt['path'].exists())
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
        self.assertTrue(runtime.worker_execution_complete(result))
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
        self.assertTrue(runtime.worker_execution_complete(result))
        self.assertEqual(0,result['launcherExitCode']); self.assertEqual(139,result['exitCode'])
        self.assertEqual(b'err',result['stderr']); self.assertTrue(result['workerProofRaw'])
        public = runtime.public_result(result)
        self.assertNotIn('workerProofRaw',public)
        self.assertEqual(result['workerProofRaw'].hex(),public['workerProofRawHex'])
        self.assertTrue(runtime.worker_execution_complete(public))
        self.assertIs(self.last_popen.call_args.kwargs['close_fds'], True)
        self.assertFalse('pass_fds' in self.last_popen.call_args.kwargs)
        result = self.simulate(proof_kind='signal')
        self.assertEqual(-11,result['exitCode']); self.assertTrue(runtime.worker_execution_complete(result))

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
                result=self.simulate(provisioning=provisioning)
                self.assertIsNone(self.last_receipt['fd'])
                self.assertEqual('removed',result['_receiptCleanup']['status'])
                self.assertFalse(self.last_receipt['directory'].exists())
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
                self.simulate()
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
                    self.simulate(provisioning=provisioning)
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
                    self.assertEqual(kind=='exec-only',result['workerExecVerified'])
        # Even an authenticated complete terminal cannot repair a failed wrapper transport.
        result=self.simulate(wrapper=1)
        self.assertTrue(result['workerTerminationVerified']); self.assertIsNone(result['exitCode'])

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
        with self.assertRaises(TimeoutError) as caught:
            self.simulate(cleanup_failure=True,clock=itertools.count(0,0.2))
        result=caught.exception.bounded_result
        self.assertFalse(result['cleanupVerified']); self.assertIsNone(result['exitCode'])
        self.assertFalse(result['workerExecVerified'])

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
        value=self.simulate()
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
