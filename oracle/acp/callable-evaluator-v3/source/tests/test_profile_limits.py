"""Static/mock-only profile/runtime controls. Never launch tools or change host resource limits."""
import ast
import copy
import io
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
        self.stdin = Stream(12); self.stdout = Stream(10); self.stderr = Stream(11)
        self.code = code; self.waits = []
    def wait(self, timeout):
        self.waits.append(timeout); return self.code


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
        gate = ast.parse((SOURCE/'scope_gate.py').read_text())
        gate_keys = {n.slice.value for n in ast.walk(gate) if isinstance(n,ast.Subscript) and isinstance(n.value,ast.Name) and n.value.id == 'bounds' and isinstance(n.slice,ast.Constant)}
        self.assertTrue({'scopeAdmissionSeconds','scopeAdmissionPollSeconds'} <= gate_keys)
        helper = ast.parse((SOURCE/'toolchain-001/build_helper.py').read_text())
        calls = [n for n in ast.walk(helper) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='bounded_run']
        self.assertEqual(1,len(calls)); keywords={k.arg:k.value for k in calls[0].keywords}
        for argument, key in [('timeout','helperBuildSeconds'),('output_limit','helperOutputBytesPerStream')]:
            node = keywords[argument]
            self.assertIsInstance(node, ast.Subscript)
            self.assertEqual('bounds', node.value.id); self.assertEqual(key, node.slice.value)
        self.assertEqual(60,p['bounds']['helperBuildSeconds'])
        self.assertEqual(1048576,p['bounds']['helperOutputBytesPerStream'])

    def simulate(self, *, output=b'ok', limit=None, clock=None, cleanup_failure=False, managed_scope=False):
        stack = ExitStack(); self.addCleanup(stack.close)
        process = Process(); blocks = {10:[output,b''],11:[b'err',b'']}
        stack.enter_context(patch.object(runtime.subprocess,'Popen',return_value=process))
        stack.enter_context(patch.object(runtime,'private_directory',return_value=TEMP))
        stack.enter_context(patch.object(runtime,'process_identity',return_value={'pid':123,'start':9,'pgid':123,'sid':123}))
        stack.enter_context(patch.object(runtime,'scope_processes',return_value=[]))
        owned = [[],[],[{'pid':123}]] if cleanup_failure else None
        stack.enter_context(patch.object(runtime,'owned_processes',side_effect=owned,return_value=[]))
        stack.enter_context(patch.object(runtime.selectors,'DefaultSelector',return_value=Selector()))
        stack.enter_context(patch.object(runtime.os,'set_blocking'))
        stack.enter_context(patch.object(runtime.os,'read',side_effect=lambda fd,size:blocks[fd].pop(0) if blocks[fd] else b''))
        stack.enter_context(patch.object(runtime.time,'monotonic',side_effect=clock,return_value=100.0))
        return runtime.bounded_run(['mock-only'],TEMP,{},phase='runtime',output_limit=limit,managed_scope=managed_scope)

    def test_mock_success_separates_launcher_scope_capture_wait_and_cleanup(self):
        result = self.simulate()
        for key in ['launcherCreated','launcherPidIdentityVerified','captureComplete','waitComplete','cleanupVerified']:
            self.assertTrue(result[key],key)
        self.assertFalse(result['scopeVerified']); self.assertFalse(result['scopeAdmitted'])
        self.assertEqual(7,result['exitCode']); self.assertEqual(b'err',result['stderr'])
        self.assertEqual(3,result['bounds']['schemaVersion'])

    def test_mock_completed_launcher_without_scope_proof_is_infrastructure_failure(self):
        with self.assertRaises(AssertionError) as caught: self.simulate(managed_scope=True)
        result = caught.exception.bounded_result
        self.assertTrue(result['captureComplete']); self.assertTrue(result['waitComplete'])
        self.assertFalse(result['scopeVerified']); self.assertFalse(result['scopeAdmitted'])
        self.assertTrue(result['infrastructureFailure']); self.assertTrue(result['cleanupVerified'])
        self.assertEqual(b'err', result['stderr'])

    def test_mock_partial_output_retains_limit_and_cleanup_without_completion(self):
        with self.assertRaises(ValueError) as caught: self.simulate(output=b'overflow',limit=1)
        result=caught.exception.bounded_result
        self.assertEqual(b'o',result['stdout']); self.assertTrue(result['outputExceeded'])
        self.assertFalse(result['captureComplete']); self.assertFalse(result['waitComplete']); self.assertTrue(result['cleanupVerified'])

    def test_mock_timeout_and_cleanup_failure_remain_partial_or_unknown(self):
        import itertools
        with self.assertRaises(TimeoutError) as caught: self.simulate(clock=itertools.chain([0,100],itertools.repeat(100)))
        self.assertTrue(caught.exception.bounded_result['timedOut']); self.assertTrue(caught.exception.bounded_result['cleanupVerified'])
        with self.assertRaises(AssertionError) as caught: self.simulate(cleanup_failure=True)
        self.assertFalse(caught.exception.bounded_result['cleanupVerified'])


if __name__ == '__main__':
    unittest.main()
