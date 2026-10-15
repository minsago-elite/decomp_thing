"""Pure protocol/source controls. These do NOT execute or qualify the C monitor."""
import ast
import copy
import hashlib
import stat
from types import SimpleNamespace
import worker_exec_proof as proof_parser
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

import fastjsonschema

from worker_exec_proof import (EXEC_WAIT_STATUS, ERROR_STAGES, MAX_PROOF_BYTES,
                               MAX_RECORD_BYTES, PHASES, parse_proof)

ROOT = Path(__file__).resolve().parents[1]


def binding():
    return {'attempt': 'a' * 32, 'phase': 'runtime', 'reportDevice': 1, 'reportInode': 2,
            'reaperDevice': 3, 'reaperInode': 4, 'outerPidNsDevice': 5,
            'outerPidNsInode': 6, 'targetDevice': 7, 'targetInode': 8}


def exec_record():
    return {'v': 1, 't': 'exec', 's': 1, 'a': 'a' * 32, 'p': 'runtime', 'c': 3,
            'ed': 7, 'ei': 8, 'od': 7, 'oi': 8, 'w': EXEC_WAIT_STATUS,
            'cf': 1, 'dp': 0, 'rd': 3, 'ri': 4, 'b': [1, 100, 5, 9, 1, 3]}


def terminal(kind='exit', value=0):
    return {'v': 1, 't': 'term', 's': 2, 'a': 'a' * 32, 'p': 'runtime', 'c': 3,
            'r': value << 8 if kind == 'exit' else value, 'k': kind, 'n': value}


def wire(*records):
    return b''.join((json.dumps(x, separators=(',', ':')) + '\n').encode('ascii') for x in records)


def parsed(*records):
    return parse_proof(wire(*records), binding())


def barrier_plan(scans, *, metadata_bytes=4096, proc_entries=256,
                 pid_set=(1, 2), identity_stable=True, fresh=True,
                 deadline_ns=0):
    """Test-only finite schedule oracle, not production monitor/FD authority.

    Models the reviewed plan's release condition to make old FD4-only/partial-
    scan counterexamples explicit. C source checks below are separate; native
    qualification must prove the actual compiled routine on actual proc/bwrap.
    Each item: (numericFD -> (role, identity), completeEOF, denied, elapsed_ns).
    """
    if (metadata_bytes > 4096 or proc_entries > 256 or not fresh or
            not identity_stable or set(pid_set) != {1, 2}):
        return {'forks': 0, 'reason': 'visibility'}
    attempts = 0
    for descriptors, complete, denied, elapsed in scans:
        attempts += 1
        if attempts > 100 or elapsed >= 1000000000 or elapsed < deadline_ns:
            return {'forks': 0, 'reason': 'bound'}
        if denied or len(descriptors) > 64 or any(type(fd) is not int or not 0 <= fd < 64 for fd in descriptors):
            return {'forks': 0, 'reason': 'scan'}
        if not complete:
            continue
        allowed = {0: ('stdio', (10, 0)), 1: ('stdio', (10, 1)), 2: ('stdio', (10, 2))}
        safe = all(descriptors.get(k) == v for k, v in allowed.items())
        events = 0
        for fd, (role, physical) in descriptors.items():
            if physical == (1, 2):
                safe = False
            elif fd > 2:
                if role != 'eventfd':
                    safe = False
                events += role == 'eventfd'
        if safe and events <= 1 and 3 <= len(descriptors) <= 4:
            return {'forks': 1, 'reason': 'stable-complete-allowlist'}
    return {'forks': 0, 'reason': 'pending'}



class SealedRuntimeLibraryProof(unittest.TestCase):
    def test_exact_sealed_object_attestation_and_old_nonlibrary_records(self):
        expected=binding(); expected['library']={'device':91,'inode':92,'size':8,'sha256':'c'*64,'sourcePath':'/authored/lib.so'}
        event=exec_record();event['l']=[91,92,8]
        self.assertEqual('verified',parse_proof(wire(event,terminal()),expected)['status'])
        self.assertEqual('verified',parse_proof(wire(exec_record(),terminal()),binding())['status'])
        for value in (None,[91,93,8],[91,92,7],[True,92,8]):
            bad=exec_record()
            if value is not None:bad['l']=value
            self.assertFalse(parse_proof(wire(bad,terminal()),expected)['workerExecVerified'])
        self.assertFalse(parse_proof(wire(event,terminal()),binding())['workerExecVerified'])


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads((ROOT / 'contracts/worker-exec-proof-schema.json').read_bytes())
        cls.validate = staticmethod(fastjsonschema.compile(cls.schema))

    def test_complete_normal_and_nonzero_are_worker_results(self):
        for n in (0, 1, 42, 137, 139, 255):
            with self.subTest(n=n):
                out = parsed(exec_record(), terminal(value=n))
                self.assertEqual((out['status'], out['exitCode']), ('verified', n))
                self.assertEqual(out['workerTermination'], {'kind': 'exit', 'value': n, 'rawWaitStatus': n << 8})

    def test_normal_139_is_not_sigsegv(self):
        signal = parsed(exec_record(), terminal('signal', 11))
        normal = parsed(exec_record(), terminal(value=139))
        self.assertEqual(signal['exitCode'], -11)
        self.assertEqual(normal['exitCode'], 139)
        self.assertNotEqual(signal['workerTermination'], normal['workerTermination'])
        core = terminal('signal', 11)
        core['r'] |= 128
        self.assertEqual(parsed(exec_record(), core)['workerTermination']['rawWaitStatus'], 139)

    def test_no_proof_never_uses_wrapper_status(self):
        for wrapper in (0, 1, 137, 139, -11):
            out = parse_proof(b'', binding())
            self.assertIsNone(out['exitCode'], wrapper)
            self.assertFalse(out['workerExecVerified'])
            self.assertFalse(out['workerTerminationVerified'])

    def test_partial_exec_retained_without_completion(self):
        out = parsed(exec_record())
        self.assertTrue(out['workerExecVerified'])
        self.assertFalse(out['workerTerminationVerified'])
        self.assertIsNone(out['exitCode'])
        self.assertEqual(out['reason'], 'missing-terminal')

    def test_error_before_and_after_exec(self):
        for stage in ERROR_STAGES:
            for error in (None, 1, 2147483647):
                record = {'v': 1, 't': 'error', 's': 1, 'a': 'a'*32, 'p': 'runtime', 'g': stage, 'e': error}
                self.validate(record)
                self.assertFalse(parsed(record)['workerExecVerified'])
                record['s'] = 2
                self.assertTrue(parsed(exec_record(), record)['workerExecVerified'])
                self.assertFalse(parsed(exec_record(), record)['workerTerminationVerified'])

    def test_terminal_requires_exec_and_same_child(self):
        self.assertFalse(parsed(terminal())['workerExecVerified'])
        t = terminal(); t['c'] = 4
        self.assertFalse(parsed(exec_record(), t)['workerTerminationVerified'])
        self.assertFalse(parsed(terminal(), exec_record())['workerExecVerified'])

    def test_raw_wait_semantics_not_only_claimed_fields(self):
        for key, value in [('r', 11), ('n', 256), ('n', True), ('k', 'stopped'), ('r', True), ('r', 65536)]:
            with self.subTest(key=key, value=value):
                t = terminal(); t[key] = value
                self.assertFalse(parsed(exec_record(), t)['workerTerminationVerified'])
        for raw in (0, 127, 255, 0xffff, 0x1000b, 65):
            t = terminal('signal', 11); t['r'] = raw
            self.assertFalse(parsed(exec_record(), t)['workerTerminationVerified'])

    def test_binding_and_kernel_event_counterexamples(self):
        alterations = [('a', 'b'*32), ('p', 'probe'), ('c', 0), ('c', True),
                       ('ed', 99), ('ei', 99), ('od', 99), ('oi', 99),
                       ('rd', 99), ('ri', 99), ('w', (5 << 8) | 127),
                       ('w', (1 << 16) | (5 << 8) | 127), ('cf', 0), ('dp', 1),
                       ('cf', True), ('v', True), ('s', True)]
        for key, value in alterations:
            with self.subTest(key=key, value=value):
                e = exec_record(); e[key] = value
                self.assertFalse(parsed(e, terminal())['workerExecVerified'])

    def test_barrier_tuple_identity_and_bounds(self):
        for b in ([1, 100, 5, 6, 1, 3], [0, 100, 5, 9, 1, 3], [1, 0, 5, 9, 1, 3],
                  [1, 100, 5, 9, 0, 3], [1, 100, 5, 9, 101, 3],
                  [1, 100, 5, 9, 1, 2], [1, 100, 5, 9, 1, 5],
                  [True, 100, 5, 9, 1, 3], [1, 100, 5, 9, 1, 3, 1]):
            e = exec_record(); e['b'] = b
            self.assertFalse(parsed(e, terminal())['workerExecVerified'])

    def test_closed_records_and_duplicate_keys(self):
        good = wire(exec_record(), terminal())
        for raw in (good.replace(b'"v":1', b'"v":1,"v":1', 1),
                    good.replace(b'"cf":1', b'"cf":1,"forged":true', 1),
                    good.replace(b'"cf":1', b'"cf":true', 1),
                    good.replace(b'"v":1', b'"v":1.0', 1),
                    good.replace(b'"c":3', b'"c":NaN', 1),
                    good.replace(b'"c":3', b'"c":-0', 1),
                    b' {"v":1}\n', b'null\n', b'[]\n', b'"fake"\n'):
            self.assertFalse(parse_proof(raw, binding())['workerExecVerified'])

    def test_truncation_trailing_order_and_stream_type(self):
        for raw in (wire(exec_record(), terminal())[:-1], wire(exec_record(), terminal()) + b'junk',
                    wire(exec_record(), terminal(), terminal()), wire(exec_record()) + b'\n',
                    wire(exec_record()).replace(b'\n', b'\r\n'), b'\xff\n', b'{', b'x'*1025):
            self.assertFalse(parse_proof(raw, binding())['workerTerminationVerified'])
        for raw in (None, '', bytearray(wire(exec_record(), terminal())), {}):
            self.assertIsNone(parse_proof(raw, binding())['exitCode'])

    def test_noncanonical_key_order_whitespace_and_escaped_text(self):
        raw = wire(exec_record(), terminal())
        for changed in (raw.replace(b'"v":1,"t":"exec"', b'"t":"exec","v":1', 1),
                        raw.replace(b'"v":1', b'"v": 1', 1),
                        raw.replace(b'runtime', b'run\\u0074ime', 1)):
            self.assertFalse(parse_proof(changed, binding())['workerExecVerified'])

    def test_exact_maximum_wire_lengths_and_schema(self):
        u64 = 2**64-1
        e = exec_record()
        e.update(a='f'*32, p='toolchain-inspection', c=2**31-1,
                 ed=u64, ei=u64, od=u64, oi=u64, rd=u64, ri=u64,
                 b=[1, u64, u64, u64, 100, 4])
        t = terminal('exit', 255)
        t.update(a='f'*32, p='toolchain-inspection', c=2**31-1)
        error = {'v': 1, 't': 'error', 's': 2, 'a': 'f'*32,
                 'p': 'toolchain-inspection', 'g': 'protection', 'e': 2147483647}
        for record in (e, t, error):
            self.validate(record)
            self.assertLessEqual(len(wire(record)), MAX_RECORD_BYTES)
        self.assertEqual(len(wire(e)), 364)
        self.assertEqual(len(wire(t)), 135)
        self.assertLessEqual(len(wire(e, t)), MAX_PROOF_BYTES)
        ex = binding()
        for key in ('targetDevice', 'targetInode', 'reaperDevice', 'reaperInode'):
            ex[key] = u64
        ex.update(attempt='f'*32, phase='toolchain-inspection')
        self.assertTrue(parse_proof(wire(e, t), ex)['workerTerminationVerified'])

    def test_schema_rejects_hostile_fields(self):
        for record in (exec_record(), terminal()):
            self.validate(record)
            for mutation in ({**record, 'unknown': 1}, {k:v for k,v in record.items() if k!='a'},
                             {**record, 'v': 2}):
                with self.assertRaises(fastjsonschema.JsonSchemaException):
                    self.validate(mutation)

    def test_expectations_are_closed_and_never_worker_selected(self):
        for ex in ({}, {**binding(), 'extra': True}, {**binding(), 'targetDevice': True},
                   {**binding(), 'attempt': 'A'*32}, {**binding(), 'reportDevice': 7, 'reportInode': 8}):
            with self.assertRaises(ValueError):
                parse_proof(wire(exec_record(), terminal()), ex)


class BarrierPlanAndSourceTests(unittest.TestCase):
    def setUp(self):
        self.safe = {0: ('stdio', (10, 0)), 1: ('stdio', (10, 1)), 2: ('stdio', (10, 2))}

    def test_fd4_closed_but_renumbered_report_alias_blocks(self):
        for fd in (4, 7, 63):
            held = {**self.safe, fd: ('regular', (1, 2))}
            out = barrier_plan([(held, True, False, 0)])
            self.assertEqual(out['forks'], 0)
        self.assertEqual(barrier_plan([(self.safe, True, False, 0)])['forks'], 1)

    def test_old_fd4_only_rule_would_release_unsafely(self):
        held = {**self.safe, 7: ('regular', (1, 2))}
        old_release = 4 not in held
        self.assertTrue(old_release)
        self.assertEqual(barrier_plan([(held, True, False, 0)])['forks'], 0)

    def test_host_directory_control_and_namespace_handles_block(self):
        for role in ('directory', 'namespace', 'pipe', 'socket', 'regular'):
            held = {**self.safe, 7: (role, (20, 1))}
            self.assertEqual(barrier_plan([(held, True, False, 0)])['forks'], 0)
        self.assertEqual(barrier_plan([({**self.safe, 7: ('eventfd', (20, 1))}, True, False, 0)])['forks'], 1)

    def test_delayed_closure_and_full_retry_after_enoent(self):
        held = {**self.safe, 7: ('regular', (1, 2)), 8: ('directory', (20, 1))}
        scans = [(held, True, False, 0), (self.safe, False, False, 10000000),
                 (self.safe, True, False, 20000000)]
        self.assertEqual(barrier_plan(scans)['forks'], 1)
        self.assertEqual(barrier_plan(scans[:2])['forks'], 0)

    def test_denial_identity_or_proc_visibility_never_means_absence(self):
        for kwargs in ({'fresh': False}, {'identity_stable': False}, {'pid_set': (1, 2, 3)},
                       {'metadata_bytes': 4097}, {'proc_entries': 257}):
            self.assertEqual(barrier_plan([(self.safe, True, False, 0)], **kwargs)['forks'], 0)
        self.assertEqual(barrier_plan([(self.safe, True, True, 0)])['forks'], 0)

    def test_attempt_deadline_and_descriptor_limits(self):
        pending = {**self.safe, 7: ('directory', (20, 1))}
        self.assertEqual(barrier_plan([(pending, True, False, 0)]*99 + [(self.safe, True, False, 999999999)])['forks'], 1)
        self.assertEqual(barrier_plan([(pending, True, False, 0)]*100 + [(self.safe, True, False, 0)])['forks'], 0)
        self.assertEqual(barrier_plan([(self.safe, True, False, 1000000000)])['forks'], 0)
        self.assertEqual(barrier_plan([({**self.safe, 64: ('eventfd', (20, 1))}, True, False, 0)])['forks'], 0)

    def test_c_only_worker_fork_is_after_barrier_and_parent_recheck(self):
        source = (ROOT / 'worker_exec_monitor.c').read_text()
        self.assertEqual(source.count('owned_child=fork();'), 1)
        main = source[source.index('int main('):]
        self.assertLess(main.index('barrier_wait(&barrier)'), main.index('owned_child=fork();'))
        self.assertLess(main.index('stable_parent(&barrier)'), main.index('owned_child=fork();'))
        self.assertLess(main.index('child_fds(owned_child)'), main.index('exec_record(owned_child'))
        self.assertIn('PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL', source)
        self.assertIn('execve(cfg.worker[0],cfg.worker,environ)', source)
        self.assertIn('same(identity(&st),cfg.report)', source)
        self.assertNotIn('execvp(', source)
        self.assertNotIn('as-pid-1', source)
        self.assertNotIn('test-mode', source)

    def test_c_charged_bounds_and_scope_source_only(self):
        source = (ROOT / 'worker_exec_monitor.c').read_text()
        for text in ('#define META_LIMIT 4096', '#define FD_LIMIT 64', '#define PROC_ENTRIES 256',
                     '#define FD_ENTRIES 66', '#define BARRIER_ATTEMPTS 100',
                     '#define RECORD_LIMIT 512', '#define PROOF_LIMIT 1024',
                     '++entries>PROC_ENTRIES', '++entries>FD_ENTRIES',
                     'if (errno==ENOENT) { pending=true; continue; }'):
            self.assertIn(text, source)
        self.assertLess(source.index('if (++entries>PROC_ENTRIES)'), source.index('number(de->d_name,&pid)'))


class ProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'toolchain-001/build_worker_monitor.py'
        spec = importlib.util.spec_from_file_location('worker_monitor_builder_for_tests', path)
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)

    def test_imports_inert_and_fixed_command_source_only(self):
        command = self.builder.build_command(Path('/trusted/worker_exec_monitor'))
        self.assertEqual(command[:8], ['/usr/bin/gcc', '-D_GNU_SOURCE', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wl,-z,relro,-z,now,-z,noexecstack'])
        self.assertEqual(command[8], str(ROOT / 'worker_exec_monitor.c'))
        self.assertEqual(command[-2:], ['-o', '/trusted/worker_exec_monitor'])

    def test_provisioning_cannot_claim_candidate_completion(self):
        good = {k: True for k in ('launcherCreated', 'launcherPidIdentityVerified', 'scopeVerified',
                'scopeAdmitted', 'captureComplete', 'waitComplete', 'cleanupVerified',
                'rootReaped', 'finalAbsenceVerified')}
        good.update(provisioningOnly=True, workerExecVerified=False, workerTerminationVerified=False,
                    exitCode=0, timedOut=False, outputExceeded=False, infrastructureFailure=False,
                    stdout=b'', stderr=b'', kernelScope={'finalAbsenceVerified': True})
        self.assertTrue(self.builder._complete_provisioning(good))
        for key, value in (('workerExecVerified', True), ('workerTerminationVerified', True),
                           ('provisioningOnly', False), ('stdout', None), ('stderr', None),
                           ('cleanupVerified', False), ('exitCode', 1)):
            self.assertFalse(self.builder._complete_provisioning({**good, key: value}))

    def test_provisioning_paths_do_not_accept_candidate_or_existing_outputs(self):
        for path in (Path('/tmp/worker_exec_monitor'), ROOT / 'worker_exec_monitor.c',
                     self.builder.OUTPUT_ROOT / '../worker_exec_monitor'):
            with self.assertRaises(ValueError):
                self.builder._output(path, binary=True)

    def test_python_sources_parse_without_compilation(self):
        for relative in ('worker_exec_proof.py', 'toolchain-001/build_worker_monitor.py',
                         'tests/qualify_worker_exec.py'):
            ast.parse((ROOT / relative).read_bytes(), filename=relative)


class QualificationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'tests/qualify_worker_exec.py'
        spec = importlib.util.spec_from_file_location('worker_qualifier_source_test', path)
        cls.qualifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.qualifier)  # Audit guard forbids native side effects.

    def test_qualifier_import_has_no_native_action(self):
        self.assertTrue(callable(self.qualifier.qualify))
        self.assertTrue(callable(self.qualifier.surrogate))
        tree = ast.parse((ROOT / 'tests/qualify_worker_exec.py').read_bytes())
        calls = [n for n in tree.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)]
        # Only repository-local import path setup at module scope; no native call.
        self.assertEqual(len(calls), 1)
        self.assertIsInstance(calls[0].value.func, ast.Attribute)
        self.assertEqual(calls[0].value.func.attr, 'insert')

    def test_tiny_reader_cap_stops_without_unbounded_materialization(self):
        temporary = ROOT.parents[3] / 'build/acp-decomp-effectiveness/callable-library-v3/static-worker-exec-test-tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary) as name:
            path = Path(name) / 'bounded'; path.write_bytes(b'abcd')
            self.assertEqual(self.qualifier._read(path, 4), b'abcd')
            with self.assertRaises(ValueError): self.qualifier._read(path, 3)
            link = Path(name) / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): self.qualifier._read(link, 4)

    def test_empty_nonblocking_ack_is_pending_and_denial_is_error(self):
        with patch.object(self.qualifier.os, 'read', side_effect=BlockingIOError()):
            self.assertEqual(self.qualifier._ack_bytes(9), b'')
        with patch.object(self.qualifier.os, 'read', side_effect=PermissionError()):
            with self.assertRaises(PermissionError): self.qualifier._ack_bytes(9)

    def test_harness_real_delay_schedule_and_no_proof_authority(self):
        source = (ROOT / 'tests/worker_exec_barrier_harness.c').read_text()
        for text in ('getpid()!=1', 'dup2(4,7)', 'dup2(root,8)', "request('A',begin+750)",
                     "request('B',begin+900)", 'close(7)', 'close(8)', 'close(3)', 'close(5)',
                     'now-begin>=1200', 'SECCOMP_RET_ERRNO|EPERM', '__NR_ptrace'):
            self.assertIn(text, source)
        self.assertNotIn('"t":"exec"', source)
        self.assertNotIn('write(4,', source)
        self.assertLess(source.index('dup2(4,7)'), source.index('pid_t monitor=fork()'))
        self.assertLess(source.index("request('B',begin+900)"), source.index('close(7)'))

    def test_qualifier_separates_surrogate_from_required_production_route(self):
        source = (ROOT / 'tests/qualify_worker_exec.py').read_text()
        self.assertIn("argv += ['--as-pid-1']", source)
        self.assertIn("if fixture:", source)
        self.assertIn("'productionRoute':'ordinary-unmodified-bwrap'", source)
        self.assertIn("'candidateAcceptanceAuthority':False", source)
        self.assertIn("'full24ScenarioAcceptance':False", source)
        self.assertIn("'internalApiActivity':None", source)
        self.assertIn("scope = _verify_scope(record, unit, bounds)", source)
        self.assertIn("actions != ['A','B']", source)
        self.assertIn("'deny-trace','bind-failure','chdir-failure'", source)
        self.assertIn("'scopeAdmitted') is True", source)
        self.assertIn("load_worker_monitor_binding()", source)
        self.assertLess(source.index('cleanup=True'), source.index('proof = _parse_worker_proof(raw, expected, deadline=cleanup_verification_end if cleanup else None)'))
        self.assertNotIn("qualificationComplete'] = False", source)

    def test_native_entrypoints_require_explicit_invocation(self):
        source = (ROOT / 'tests/qualify_worker_exec.py').read_text()
        self.assertIn("if not args.allow_native_controls", source)
        self.assertIn("if __name__ == '__main__':", source)
        self.assertNotIn('pytest', source)
        for name in ('worker_exec_monitor.c', 'tests/worker_exec_barrier_harness.c'):
            text = (ROOT / name).read_text()
            self.assertNotIn('system(', text)
            self.assertNotIn('popen(', text)


def fault_receipt(name, *, descendant_complete=False):
    """Public synthetic receipt only; no actual execution or qualification."""
    raw=wire(exec_record(),terminal()) if name=='descendant' else wire(exec_record())
    parsed_proof=parse_proof(raw,binding())
    import bounded_runtime as runtime
    pins={'/public/worker':{'device':7,'inode':8,'mode':0o755,'sha256':'c'*64},
          '/public/reaper':{'device':3,'inode':4,'mode':0o755,'sha256':'d'*64},
          str(runtime.BASE/'contracts/candidate-build-profile.json'):{'device':70,'inode':71,'mode':0o400,'sha256':'b'*64}}
    pins[str(runtime.BASE/'worker_exec_proof.py')]={'device':70,'inode':72,'mode':0o400,'sha256':runtime._WORKER_PROOF_PARSER_SHA256}
    bound={key:'b'*64 for key in ('launchConfigSha256','environmentPinSha256','monitorBinarySha256',
        'monitorSourceSha256','protocolSha256','parserSha256','manifestSha256','targetSha256','launchPinsSha256')}
    bound.update(protocolVersion=1,expected=binding(),targetSha256='c'*64,parserSha256=runtime._WORKER_PROOF_PARSER_SHA256,
        launchPinsSha256=hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    result={k:True for k in ('launcherCreated','launcherPidIdentityVerified','scopeVerified','scopeAdmitted',
                             'cleanupVerified','rootReaped','finalAbsenceVerified')}
    result.update(provisioningOnly=False,workerProofRaw=raw,workerProofBindings=bound,launchInputPins=pins,
        bounds={'phase':'runtime','profileSha256':'b'*64,'wallSeconds':5,'outputBytesPerStream':65536},
        workerProof={'protocolVersion':1,'status':parsed_proof['status'],'proofSha256':parsed_proof['proofSha256'],
                     'fileIdentityVerified':True,'pinsUnchanged':True,'reason':parsed_proof['reason']},
        workerExecVerified=parsed_proof['workerExecVerified'],workerTerminationVerified=parsed_proof['workerTerminationVerified'],
        workerTermination=parsed_proof['workerTermination'],exitCode=None,launcherExitCode=-9,
        captureComplete=False,waitComplete=False,timedOut=name in ('stop-monitor','timeout','descendant'),
        outputExceeded=name=='flood',infrastructureFailure=True,
        kernelScope={'finalAbsenceVerified':True},stdout=('FAULT:'+name+'\n').encode(),stderr=b'')
    if name=='kill-monitor':result.update(captureComplete=True,waitComplete=True)
    if name=='flood':
        result['bounds']['outputBytesPerStream']=32
        result['stdout']=b'FAULT:flood\n'+b'x'*(32-len(b'FAULT:flood\n'))
    if name=='descendant':
        result['stdout']=b'DESCENDANT-CHANNEL-DENIED\nFAULT:descendant\n'
        if descendant_complete:
            result.update(exitCode=0,launcherExitCode=0,captureComplete=True,waitComplete=True,
                          timedOut=False,outputExceeded=False,infrastructureFailure=False)
    return result


class ReviewCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=ROOT/'tests/qualify_worker_exec.py'
        spec=importlib.util.spec_from_file_location('qualifier_review_corrections',path)
        cls.qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.qualifier)

    def test_replay_requires_canonical_profile_pin_even_after_aggregate_resealing(self):
        import bounded_runtime as runtime
        good=fault_receipt('descendant',descendant_complete=True)
        key=str(runtime.BASE/'contracts/candidate-build-profile.json')
        with patch.object(runtime,'load_profile_with_digest',side_effect=AssertionError('replay must not read profile')),patch.object(runtime.os,'open',side_effect=AssertionError('replay must not open files')):
            self.assertTrue(runtime._valid_worker_bindings(good))
            self.assertTrue(runtime.worker_execution_complete(good))
            for mutation in ('missing','wrong','rekeyed'):
                with self.subTest(mutation=mutation):
                    bad=copy.deepcopy(good)
                    row=bad['launchInputPins'].pop(key)
                    if mutation=='wrong':row['sha256']='f'*64;bad['launchInputPins'][key]=row
                    if mutation=='rekeyed':bad['launchInputPins']['/authored/other-profile.json']=row
                    bad['workerProofBindings']['launchPinsSha256']=runtime._canonical_pin_digest(bad['launchInputPins'])
                    self.assertFalse(runtime._valid_worker_bindings(bad))
                    self.assertFalse(runtime.worker_execution_complete(bad))

    def test_one_over_proof_cap_does_no_hash_or_record_parse(self):
        with patch.object(proof_parser.hashlib,'sha256') as hashed, patch.object(proof_parser,'_record') as decoded:
            value=proof_parser.parse_proof(b'x'*1025,binding())
        self.assertEqual(value['reason'],'proof-byte-bound')
        self.assertIsNone(value['proofSha256']);hashed.assert_not_called();decoded.assert_not_called()

    def test_qualifier_overbound_raw_refuses_before_binding_hash_work(self):
        import bounded_runtime
        value=fault_receipt('kill-monitor');value['workerProofRaw']=b'x'*1025
        with patch.object(bounded_runtime,'_valid_worker_bindings') as validation:
            self.assertIsNone(self.qualifier._initial_exec(value))
        validation.assert_not_called()

    def test_exact_proof_cap_admits_only_bounded_hash_and_then_refuses_bad_record(self):
        original=hashlib.sha256
        raw=b'x'*1023+b'\n'
        with patch.object(proof_parser.hashlib,'sha256',wraps=original) as hashed, patch.object(proof_parser.json,'loads') as decoded:
            value=proof_parser.parse_proof(raw,binding())
        hashed.assert_called_once_with(raw);decoded.assert_not_called()
        self.assertEqual(value['proofSha256'],original(raw).hexdigest())
        self.assertFalse(value['workerTerminationVerified'])

    def test_old_hash_order_counterexample_current_refuses_before_work(self):
        calls=[]
        def old_order(raw):
            calls.append(len(raw))  # Old sha256-before-length work order from review.
            return len(raw)<=1024
        self.assertFalse(old_order(b'x'*1025));self.assertEqual(calls,[1025])
        with patch.object(proof_parser.hashlib,'sha256',side_effect=AssertionError('over-bound hash')):
            self.assertEqual(parse_proof(b'x'*1025,binding())['reason'],'proof-byte-bound')

    def test_stale_scope_pid_cannot_become_replacement_signal_authority(self):
        # Old list12345 has exited; any new identity at12345 is an unrelated
        # replacement. Kernel cgroup.kill targets the admitted object instead.
        scope={'path':'/owned.scope','identity':[8,10],'directoryFd':41}
        directory=SimpleNamespace(st_dev=8,st_ino=10,st_mode=stat.S_IFDIR|0o700)
        interface=SimpleNamespace(st_dev=8,st_ino=11,st_mode=stat.S_IFREG|0o200)
        metadata=lambda fd: directory if fd==41 else interface
        with patch.object(self.qualifier,'_identity',side_effect=AssertionError('fresh stale-PID identity')), \
             patch.object(self.qualifier.os,'pidfd_open') as pidfd, \
             patch.object(self.qualifier.signal,'pidfd_send_signal') as signalled, \
             patch.object(self.qualifier.os,'fstat',side_effect=metadata), \
             patch.object(self.qualifier.os,'open',return_value=42) as opened, \
             patch.object(self.qualifier.os,'write',return_value=2) as written, \
             patch.object(self.qualifier.os,'close') as closed:
            self.qualifier._kill_scope(scope)
        pidfd.assert_not_called();signalled.assert_not_called()
        self.assertEqual(opened.call_args.args[0],'cgroup.kill')
        self.assertEqual(opened.call_args.kwargs,{'dir_fd':41})
        self.assertTrue(opened.call_args.args[1]&self.qualifier.os.O_NOFOLLOW)
        written.assert_called_once_with(42,b'1\n');closed.assert_called_once_with(42)

    def test_scope_identity_replacement_refuses_before_interface_open_or_write(self):
        scope={'path':'/owned.scope','identity':[8,10],'directoryFd':41}
        wrong=SimpleNamespace(st_dev=8,st_ino=99,st_mode=stat.S_IFDIR|0o700)
        with patch.object(self.qualifier.os,'fstat',return_value=wrong), \
             patch.object(self.qualifier.os,'open') as opened, patch.object(self.qualifier.os,'write') as written:
            with self.assertRaises(ValueError):self.qualifier._kill_scope(scope)
        opened.assert_not_called();written.assert_not_called()

    def test_cgroup_interface_denial_has_no_pid_fallback(self):
        scope={'path':'/owned.scope','identity':[8,10],'directoryFd':41}
        directory=SimpleNamespace(st_dev=8,st_ino=10,st_mode=stat.S_IFDIR|0o700)
        with patch.object(self.qualifier.os,'fstat',return_value=directory), \
             patch.object(self.qualifier.os,'open',side_effect=PermissionError()), \
             patch.object(self.qualifier.os,'write') as written, patch.object(self.qualifier,'_kill_pid') as fallback:
            with self.assertRaises(PermissionError):self.qualifier._kill_scope(scope)
        written.assert_not_called();fallback.assert_not_called()

    def test_scope_source_retains_admission_fd_and_never_refreshes_list_to_signal(self):
        source=(ROOT/'tests/qualify_worker_exec.py').read_text()
        self.assertIn("'directoryFd': descriptor",source)
        self.assertIn("directory = scope['directoryFd']",source)
        self.assertIn('_kill_scope(scope)',source)
        self.assertNotIn('_kill_pid(_identity(pid))',source)
        self.assertIn("[report,scope['directoryFd']]",source)

    def test_each_named_postexec_fault_needs_its_actual_exec_and_effect(self):
        for name in ('kill-monitor','stop-monitor','timeout','flood','descendant'):
            with self.subTest(name=name):
                intended=fault_receipt(name)
                self.assertTrue(self.qualifier.postexec_control_passed(name,intended))
                wrong=copy.deepcopy(intended)
                wrong.update(workerExecVerified=False,workerTerminationVerified=False,
                             workerTermination=None,workerProofRaw=b'')
                # Exactly the review's previous insufficient setup-error facts.
                wrong['reason']='unrelated-pre-exec-wrapper-failure'
                old_pass=(wrong['scopeAdmitted'] and wrong['cleanupVerified'] and wrong['kernelScope']['finalAbsenceVerified'])
                self.assertTrue(old_pass)
                self.assertFalse(self.qualifier.postexec_control_passed(name,wrong))
                effect=copy.deepcopy(intended);effect['stdout']=b''
                self.assertFalse(self.qualifier.postexec_control_passed(name,effect))

    def test_flood_and_deadline_controls_require_the_expected_flags(self):
        for name,key in [('stop-monitor','timedOut'),('timeout','timedOut'),('flood','outputExceeded')]:
            value=fault_receipt(name);value[key]=False
            self.assertFalse(self.qualifier.postexec_control_passed(name,value))
        flood=fault_receipt('flood');flood['stdout']=flood['stdout'][:-1]
        self.assertFalse(self.qualifier.postexec_control_passed('flood',flood))
        self.assertFalse(self.qualifier.postexec_control_passed('timeout',fault_receipt('stop-monitor')))

    def test_authentication_cleanup_and_raw_exec_claims_are_mandatory(self):
        for mutate in (lambda v:v.update(cleanupVerified=False),
                       lambda v:v.update(workerExecVerified=1),
                       lambda v:v['workerProof'].update(fileIdentityVerified=False),
                       lambda v:v['workerProof'].update(pinsUnchanged=False),
                       lambda v:v['workerProof'].update(proofSha256='f'*64),
                       lambda v:v['workerProofBindings'].update(launchPinsSha256='f'*64),
                       lambda v:v.update(workerProofRaw=wire({**exec_record(),'w':127})),
                       lambda v:v.update(provisioningOnly=True)):
            value=fault_receipt('kill-monitor');mutate(value)
            self.assertFalse(self.qualifier.postexec_control_passed('kill-monitor',value))

    def test_descendant_requires_real_denial_bytes_term0_and_full_cleanup(self):
        self.assertTrue(self.qualifier.postexec_control_passed('descendant',fault_receipt('descendant',descendant_complete=True)))
        value=fault_receipt('descendant');value['stdout']=b'FAULT:descendant\n'
        self.assertFalse(self.qualifier.postexec_control_passed('descendant',value))
        value=fault_receipt('descendant');value['workerTermination']=None
        self.assertFalse(self.qualifier.postexec_control_passed('descendant',value))
        self.assertFalse(self.qualifier.postexec_control_passed('missing-target',fault_receipt('timeout')))

    def test_real_channel_control_needs_exact_denial_and_unmutated_authenticated_report(self):
        for name,stdout in [('protected-channel-attacks',b'CHANNEL-DENIED\n'),
                            ('descendant-channel-attacks',b'DESCENDANT-CHANNEL-DENIED\n')]:
            with self.subTest(name=name):
                value=fault_receipt('descendant',descendant_complete=True);value['stdout']=stdout
                self.assertTrue(self.qualifier.channel_control_passed(name,value))
                forged=copy.deepcopy(value);forged['workerProofRaw']+=b'forged-report-mutation\n'
                self.assertFalse(self.qualifier.channel_control_passed(name,forged))
                wrong=copy.deepcopy(value);wrong['stdout']=b''
                self.assertFalse(self.qualifier.channel_control_passed(name,wrong))
                missing=copy.deepcopy(value);missing['workerExecVerified']=False
                self.assertFalse(self.qualifier.channel_control_passed(name,missing))

    def test_channel_source_covers_pid1_alias_root_and_saved_monitor_descendant(self):
        text=self.qualifier.WORKER_SOURCE
        for fragment in ('for(int slot=0;slot<64;', '"/proc/1/fd/%d"', '"anon_inode:[eventfd]"',
                         'if(slot<=2)', 'open("/proc/1/root"', 'openat(fd,"proc/self/ns/pid"',
                         'forged-reaper-alias', 'int result=channel(monitor,saved_start)',
                         'DESCENDANT-CHANNEL-DENIED', 'F_DUPFD_CLOEXEC,10', 'start_time(monitor,&actual)'):
            self.assertIn(fragment,text)
        self.assertEqual(text.count('monitor=getppid()'),1)
        source=(ROOT/'tests/qualify_worker_exec.py').read_text()
        self.assertIn("run('descendant-channel-attacks'",source)
        self.assertIn("'--', config['worker'], 'descendant-channel'",source)
        self.assertIn("bytes(streams['stdout'])==b'DESCENDANT-CHANNEL-DENIED\\n'",source)
        self.assertIn("postexec=True",source)


class CleanupDeadlineCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Execute the actual narrow cleanup/final-verdict AST, not a model of it.
        # All OS/process/time effects below are inert test doubles. The real C,
        # compiler, qualifier launcher and proc/cgroup functions are never called.
        tree=ast.parse((ROOT/'tests/qualify_worker_exec.py').read_bytes())
        surrogate=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='surrogate')
        execution=next(n for n in surrogate.body if isinstance(n,ast.Try) and
                       any(isinstance(x,ast.Try) for x in n.finalbody))
        cleanup=next(n for n in execution.finalbody if isinstance(n,ast.Try))
        proof_stage=next(n for n in surrogate.body if isinstance(n,ast.Try) and
                         any(isinstance(x,ast.For) for x in n.finalbody))
        final=next(n for n in surrogate.body if isinstance(n,ast.If) and isinstance(n.test,ast.Name) and n.test.id=='cleanup')
        result=next(n for n in surrogate.body if isinstance(n,ast.Assign) and
                    any(isinstance(x,ast.Name) and x.id=='value' for x in n.targets))
        parameters=('process','root','scope','bounds','failure','selector','control','ack','report',
                    'mode','complete','capture','launcher_exit','proof','samples','actions','streams')
        function=ast.FunctionDef(name='cleanup_probe',args=ast.arguments(posonlyargs=[],
            args=[ast.arg(arg=x) for x in parameters],kwonlyargs=[],kw_defaults=[],defaults=[]),
            body=ast.parse('cleanup=False;cleanup_failure=None;cleanup_wait_end=None;cleanup_verification_end=None').body+
                 [copy.deepcopy(cleanup)]+copy.deepcopy(proof_stage.finalbody)+[copy.deepcopy(final),copy.deepcopy(result),ast.Return(value=ast.Name(id='value',ctx=ast.Load()))],
            decorator_list=[])
        cls.module=ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[]))

    def probe(self,*,wait_returns_at=.25,inventory_returns_at=None,close_returns_at=None,primary=None,close_clock_unknown=False):
        clock=SimpleNamespace(now=0.0)
        def sleep(seconds):clock.now+=seconds
        inventory_calls=[]
        def inventory(scope):
            inventory_calls.append(clock.now)
            if len(inventory_calls)==2 and inventory_returns_at is not None:
                clock.now=inventory_returns_at
            return []
        def wait(*,timeout):
            self.assertGreater(timeout,0)
            self.assertLessEqual(timeout,5)
            clock.now=wait_returns_at
            return 0
        def close_selector():
            if close_returns_at is not None:clock.now=close_returns_at
            if close_clock_unknown:clock.unknown=True
        def monotonic():
            if getattr(clock,'unknown',False):raise OSError('clock unavailable')
            return clock.now
        namespace={'time':SimpleNamespace(monotonic=monotonic,sleep=sleep),
                   '_scope_pids':inventory,'_kill_scope':lambda _:self.fail('unexpected scope signal'),
                   '_kill_pid':lambda _:self.fail('unexpected PID signal'),
                   'os':SimpleNamespace(close=lambda _:None),
                   'subprocess':SimpleNamespace(SubprocessError=RuntimeError)}
        exec(compile(self.module,'<actual-surrogate-cleanup-static-only>','exec'),namespace)
        process=SimpleNamespace(poll=lambda:0,wait=wait,
                 stdout=SimpleNamespace(close=lambda:None),stderr=SimpleNamespace(close=lambda:None))
        proof=parse_proof(wire(exec_record(),terminal()),binding())
        stdout=b'DESCENDANT-CHANNEL-DENIED\n'
        result=namespace['cleanup_probe'](process,{'pid':123,'start':100},{'directoryFd':41},
            {'cleanupWaitSeconds':5,'cleanupVerificationSeconds':5},primary,
            SimpleNamespace(close=close_selector),3,5,4,'release',True,True,0,proof,
            [{'ack':'H'},{'ack':'HA'}],['A','B'],{'stdout':stdout,'stderr':b''})
        self.assertIs(result['proof'],proof)
        self.assertEqual(result['stdoutHex'],stdout.hex())
        self.assertEqual(result['stderrHex'],'')
        return result,inventory_calls

    def test_timely_wait_absence_and_final_observations_pass_same_five_plus_five(self):
        result,calls=self.probe()
        self.assertTrue(result['passed']);self.assertTrue(result['cleanupVerified'])
        self.assertEqual(result['cleanupDeadlines'],{'wait':5.0,'verification':5.25})
        self.assertIsNone(result['cleanupFailure']);self.assertEqual(len(calls),2)

    def test_successful_but_late_wait_does_not_start_a_new_verification_window(self):
        for observed in (5.0,5.001,8.0):
            with self.subTest(observed=observed):
                result,calls=self.probe(wait_returns_at=observed)
                self.assertFalse(result['passed']);self.assertFalse(result['cleanupVerified'])
                self.assertIsNone(result['cleanupDeadlines']['verification'])
                self.assertIn('wait returned after deadline',result['cleanupFailure'])
                self.assertEqual(len(calls),1)

    def test_empty_inventory_returning_after_verification_end_is_not_cleanup_proof(self):
        for observed in (5.25,5.251,9.0):
            with self.subTest(observed=observed):
                result,_=self.probe(inventory_returns_at=observed)
                self.assertFalse(result['passed']);self.assertFalse(result['cleanupVerified'])
                self.assertEqual(result['cleanupDeadlines']['verification'],5.25)
                self.assertIn('absence observation exceeded deadline',result['cleanupFailure'])

    def test_final_close_or_proof_observation_cannot_upgrade_after_same_stage_end(self):
        result,_=self.probe(close_returns_at=5.251)
        self.assertFalse(result['passed']);self.assertFalse(result['cleanupVerified'])
        self.assertIn('final verification exceeded deadline',result['cleanupFailure'])
        self.assertEqual(result['cleanupDeadlines']['verification'],5.25)

    def test_primary_failure_and_valid_proof_bytes_survive_secondary_late_cleanup(self):
        for options in ({'wait_returns_at':5.001},{'inventory_returns_at':5.251},{'close_returns_at':5.251}):
            result,_=self.probe(primary='original-primary-failure',**options)
            self.assertEqual(result['failure'],'original-primary-failure')
            self.assertIsNotNone(result['cleanupFailure'])
            self.assertFalse(result['passed']);self.assertEqual(result['proof']['status'],'verified')

    def test_unknown_final_clock_keeps_cleanup_unverified_and_primary_preserved(self):
        result,_=self.probe(close_clock_unknown=True,primary='original-primary-failure')
        self.assertFalse(result['passed']);self.assertFalse(result['cleanupVerified'])
        self.assertEqual(result['failure'],'original-primary-failure')
        self.assertIn('clock unavailable',result['cleanupFailure'])
        self.assertEqual(result['proof']['status'],'verified')

    def test_initial_phase_wait_also_refuses_success_after_its_absolute_end(self):
        tree=ast.parse((ROOT/'tests/qualify_worker_exec.py').read_bytes())
        surrogate=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='surrogate')
        branch=next(n for n in ast.walk(surrogate) if isinstance(n,ast.If) and
                    any(isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='launcher_exit' for t in x.targets)
                        for x in n.body))
        for observed in (4.999,5.0,5.001):
            clock=SimpleNamespace(now=0.0)
            def wait(*,timeout):
                self.assertGreater(timeout,0);self.assertLessEqual(timeout,5)
                clock.now=observed;return 0
            namespace={'process':SimpleNamespace(poll=lambda:0,wait=wait),
                       'selector':SimpleNamespace(get_map=lambda:{}),'deadline':5.0,
                       'time':SimpleNamespace(monotonic=lambda:clock.now),'capture':False}
            loop=ast.While(test=ast.Constant(value=True),body=[copy.deepcopy(branch)],orelse=[])
            code=compile(ast.fix_missing_locations(ast.Module(body=[loop],type_ignores=[])),
                         '<actual-surrogate-phase-wait-static-only>','exec')
            if observed>=5:
                with self.assertRaises(TimeoutError):exec(code,namespace)
                self.assertFalse(namespace['capture'])
            else:
                exec(code,namespace);self.assertTrue(namespace['capture'])

    def test_old_pre_call_only_deadline_control_would_accept_the_late_empty_result(self):
        old_before=0.25;end=old_before+5
        self.assertTrue(old_before<end)
        returned_at=end+.001;empty=[]
        old_cleanup=not empty  # Old branch did not sample returned_at.
        self.assertTrue(old_cleanup)
        corrected,_=self.probe(inventory_returns_at=returned_at)
        self.assertFalse(corrected['cleanupVerified'])


if __name__ == '__main__':
    unittest.main()
